#!/usr/bin/env node
/**
 * Agent-facing `open-ssl` command, assembled with `@wae/commander`.
 *
 * Contract:
 * - non-interactive, always exits with a stable code
 * - `--json` returns `{ ok, data }` or `{ ok: false, error }` under `wae.cli-result/v0`
 * - inspection and issuance are separate capabilities, and inspection never writes
 * - every mutating command supports `--dry-run`
 * - every command configures the audit actor before calling the native layer
 *
 * The command tree owns presentation only. Every operation goes through
 * `new OpenSSL(options)`, which forwards to the N-API exports.
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { createCli, type CommandContext, type ParsedOptions } from '@wae/commander';

import {
    AppError,
    OpenSSL,
    fromNativeError,
    type AcmeIssueOutcome,
    type AcmePlan,
    type AcmeTargetOptions,
    type CapabilityItem,
} from './index.js';
import { loadRuntimeContract, type ActorChannel } from './runtime.js';

const ENVELOPE_SCHEMA = 'wae.cli-result/v0';

const EXIT = { OK: 0, FAILURE: 1, USAGE: 2, CAPABILITY: 3, CANCELED: 4 } as const;

const here = path.dirname(fileURLToPath(import.meta.url));
const localesDir = path.join(here, '..', 'locales');

const cli = createCli('open-ssl')
    .locales(localesDir)
    .intro('cli.intro')
    .option('--actor <id>', 'cli.opt.actor')
    .option('--actor-kind <kind>', 'cli.opt.actor-kind')
    .option('--actor-source <source>', 'cli.opt.actor-source')
    .option('--json', 'cli.opt.json');

const ssl = new OpenSSL();

function stringOption(options: ParsedOptions, key: string): string | undefined {
    const value = options[key];
    return typeof value === 'string' && value.trim() ? value : undefined;
}

function flag(options: ParsedOptions, key: string): boolean {
    return options[key] === true;
}

function stringArrayOption(options: ParsedOptions, key: string): string[] {
    const value = options[key];
    if (value === undefined) return [];
    if (Array.isArray(value)) return value.map((item) => String(item));
    if (typeof value === 'string') return [value];
    throw new AppError({ code: 'invalid_argument', message: `\`--${key}\` accepts values only` });
}

function integerOption(options: ParsedOptions, key: string): number | undefined {
    const raw = stringOption(options, key);
    if (raw === undefined) return undefined;
    const value = Number(raw);
    if (!Number.isInteger(value) || value < 0) {
        throw new AppError({ code: 'invalid_argument', message: `\`--${key}\` must be a non-negative integer` });
    }
    return value;
}

const runtime = loadRuntimeContract();

/** Resolve one actor field from the channel declared in `audit.actor`. */
function actorValue(channel: ActorChannel | undefined, fromFlag: string | undefined, envKey: string, hostDefault: string): string {
    switch (channel) {
        case 'env':
            return process.env[envKey]?.trim() || hostDefault;
        case 'host':
        case 'session':
            return hostDefault;
        case 'flag':
        default:
            return fromFlag ?? hostDefault;
    }
}

/** Configure the audit actor before any capability call. */
function bootstrap(options: ParsedOptions): void {
    const mapping = runtime.audit?.actor;
    const kind = actorValue(mapping?.kind, stringOption(options, 'actor-kind'), 'WAE_ACTOR_KIND', 'user');
    if (kind !== 'user' && kind !== 'agent') {
        throw new AppError({ code: 'invalid_argument', message: '`--actor-kind` must be `user` or `agent`' });
    }
    ssl.configureAudit({
        actorKind: kind,
        actorId: actorValue(mapping?.id, stringOption(options, 'actor'), 'WAE_ACTOR_ID', 'unknown'),
        actorSource: actorValue(mapping?.source, stringOption(options, 'actor-source'), 'WAE_ACTOR_SOURCE', 'cli'),
    });
}

function emit(options: ParsedOptions, ctx: CommandContext, data: unknown, human: string): void {
    if (flag(options, 'json')) {
        ctx.stdout(JSON.stringify({ schema: ENVELOPE_SCHEMA, ok: true, data }, null, 2));
        return;
    }
    if (human) ctx.stdout(human);
}

function exitFor(code: string | undefined): number {
    switch (code) {
        case 'unsupported_platform':
        case 'not_implemented':
        case 'dependency_blocked':
            return EXIT.CAPABILITY;
        case 'invalid_argument':
        case 'unknown_command':
            return EXIT.USAGE;
        case 'canceled':
            return EXIT.CANCELED;
        default:
            return EXIT.FAILURE;
    }
}

function fail(options: ParsedOptions, ctx: CommandContext, error: unknown): number {
    const appError = fromNativeError(error);
    if (flag(options, 'json')) {
        ctx.stdout(JSON.stringify({ schema: ENVELOPE_SCHEMA, ok: false, error: appError.toJSON() }, null, 2));
    }
    else {
        ctx.stderr(`${appError.code}: ${appError.message}`);
    }
    return exitFor(appError.code);
}

function formatCapabilities(items: CapabilityItem[], notes: string[]): string {
    const rows = items.map((item) => [item.id, item.state ?? 'supported', item.reason].join('\t'));
    const lines = [['capability', 'state', 'reason'].join('\t'), ...rows];
    if (notes.length) lines.push('', ...notes.map((note) => `note: ${note}`));
    return lines.join('\n');
}

/** Resolve one domain capability. The skeleton refuses before any side effect. */
function resolve(options: ParsedOptions, ctx: CommandContext, capability: string, mutating: boolean): number {
    try {
        if (mutating && flag(options, 'dry-run')) {
            // The dry-run flag is part of the contract even while the capability
            // refuses. The plan itself cannot exist before implementation, so the
            // refusal still decides the exit code.
            ctx.stderr('dry-run: plan unavailable because the capability is not implemented');
        }
        bootstrap(options);
        const data = ssl.invoke(capability);
        emit(options, ctx, data, String(data));
        return EXIT.OK;
    }
    catch (error) {
        return fail(options, ctx, error);
    }
}

cli.command('capabilities', 'cli.cmd.capabilities').actionCtx(async (options, _args, ctx) => {
    try {
        bootstrap(options);
        const report = ssl.capabilities();
        emit(options, ctx, report, formatCapabilities(report.items, report.notes));
        return EXIT.OK;
    }
    catch (error) {
        return fail(options, ctx, error);
    }
});

cli.command('version', 'cli.cmd.version').actionCtx(async (options, _args, ctx) => {
    try {
        bootstrap(options);
        const current = ssl.version();
        emit(options, ctx, { version: current }, current);
        return EXIT.OK;
    }
    catch (error) {
        return fail(options, ctx, error);
    }
});

cli.command('audit', 'cli.cmd.audit')
    .option('--kind <kind>', 'cli.opt.kind', { enum: ['user', 'agent'] })
    .option('--id <id>', 'cli.opt.id')
    .option('--capability <name>', 'cli.opt.capability')
    .option('--from-ms <n>', 'cli.opt.from-ms')
    .option('--to-ms <n>', 'cli.opt.to-ms')
    .option('--limit <n>', 'cli.opt.limit')
    .actionCtx(async (options, _args, ctx) => {
        try {
            bootstrap(options);
            const entries = ssl.auditQuery({
                kind: stringOption(options, 'kind') === 'agent' ? 'agent' : stringOption(options, 'kind') === 'user' ? 'user' : undefined,
                id: stringOption(options, 'id'),
                capability: stringOption(options, 'capability'),
                fromMs: integerOption(options, 'from-ms'),
                toMs: integerOption(options, 'to-ms'),
                limit: integerOption(options, 'limit'),
            });
            emit(options, ctx, entries, JSON.stringify(entries, null, 2));
            return EXIT.OK;
        }
        catch (error) {
            return fail(options, ctx, error);
        }
    });

cli.command('gui', 'cli.cmd.gui')
    .option('--content-dir <path>', 'cli.opt.content-dir')
    .actionCtx(async (options, _args, ctx) => {
        try {
            bootstrap(options);
            const backend = await ssl.runGui({ contentDir: stringOption(options, 'content-dir') });
            emit(options, ctx, { backend }, `closed (${backend})`);
            return EXIT.OK;
        }
        catch (error) {
            return fail(options, ctx, error);
        }
    });

/** Shared target parsing for `acme-plan` and `acme-issue`. */
function acmeTarget(options: ParsedOptions): AcmeTargetOptions {
    const kind = stringOption(options, 'kind');
    if (kind !== 'staging' && kind !== 'production') {
        throw new AppError({ code: 'invalid_argument', message: '`--kind` must be `staging` or `production`' });
    }
    const dnsProvider = stringOption(options, 'dns-provider');
    if (!dnsProvider) {
        throw new AppError({ code: 'invalid_argument', message: '`--dns-provider` is required' });
    }
    const identifiers = stringArrayOption(options, 'identifier');
    if (!identifiers.length) {
        throw new AppError({ code: 'invalid_argument', message: 'at least one `--identifier` is required' });
    }
    const projectRoot = stringOption(options, 'project');
    return projectRoot ? { kind, dnsProvider, identifiers, projectRoot } : { kind, dnsProvider, identifiers };
}

function formatPlan(plan: AcmePlan): string {
    const lines = [
        `${plan.identifiers.join(', ')} via ${plan.dnsProvider} against the ${plan.kind} directory`,
        `secrets file: ${plan.secretsFile} (${plan.secretsAvailable ? 'valid' : 'missing or invalid'})`,
        `dns token: ${plan.dnsTokenAvailable ? 'available' : 'missing'}`,
        `account: ${plan.existingAccount ? 'reusable' : 'will be created'}`,
    ];
    if (plan.pendingOrder) lines.push(`pending order: ${plan.pendingOrder}`);
    lines.push(...plan.requiredSansNote.map((note) => `note: ${note}`));
    return lines.join('\n');
}

function formatIssue(outcome: AcmeIssueOutcome): string {
    if (outcome.dryRun) return `dry run\n${outcome.plan ? formatPlan(outcome.plan) : ''}`;
    const report = outcome.report;
    if (!report) return 'no outcome';
    return [
        `delivered generation ${report.generation}`,
        `sans: ${report.sans.join(', ')}`,
        `fingerprint sha256: ${report.certificateSha256}`,
        `valid from ${new Date(report.notBeforeUnix * 1000).toISOString()} until ${new Date(report.notAfterUnix * 1000).toISOString()}`,
        `certificate: ${report.paths.certificate}`,
        `chain: ${report.paths.chain}`,
        `private key: ${report.paths.privateKey}`,
        `account: ${report.accountUrl}`,
        `order: ${report.orderUrl}`,
        `dns records removed: ${report.dnsRecordsRemoved}`,
    ].join('\n');
}

cli.command('acme-plan', 'cli.cmd.acme-plan')
    .option('--kind <kind>', 'cli.opt.acme-kind')
    .option('--dns-provider <id>', 'cli.opt.dns-provider')
    .option('--identifier <domain>...', 'cli.opt.identifier')
    .option('--project <path>', 'cli.opt.project')
    .actionCtx(async (options, _args, ctx) => {
        try {
            bootstrap(options);
            const plan = ssl.acmePlan(acmeTarget(options));
            emit(options, ctx, plan, formatPlan(plan));
            return EXIT.OK;
        }
        catch (error) {
            return fail(options, ctx, error);
        }
    });

cli.command('acme-issue', 'cli.cmd.acme-issue')
    .option('--kind <kind>', 'cli.opt.acme-kind')
    .option('--dns-provider <id>', 'cli.opt.dns-provider')
    .option('--identifier <domain>...', 'cli.opt.identifier')
    .option('--contact <uri>...', 'cli.opt.contact')
    .option('--dns-zone-id <id>', 'cli.opt.dns-zone-id')
    .option('--dns-zone-name <name>', 'cli.opt.dns-zone-name')
    .option('--project <path>', 'cli.opt.project')
    .option('--dry-run', 'cli.opt.dry-run')
    .actionCtx(async (options, _args, ctx) => {
        try {
            bootstrap(options);
            const outcome = ssl.acmeIssue({
                ...acmeTarget(options),
                dryRun: flag(options, 'dry-run'),
                dnsZoneId: stringOption(options, 'dns-zone-id'),
                dnsZoneName: stringOption(options, 'dns-zone-name'),
                contact: stringArrayOption(options, 'contact'),
            });
            emit(options, ctx, outcome, formatIssue(outcome));
            return EXIT.OK;
        }
        catch (error) {
            return fail(options, ctx, error);
        }
    });

for (const [id, mutating] of [
    ['certificate-inspect', false],
    ['certificate-issue', true],
    ['certificate-renew', true],
    ['certificate-revoke', true],
    ['ca-create', true],
    ['csr-create', true],
    ['private-key-store', true],
    ['certificate-store', true],
    ['remote-agent', true],
    ['host-install', true],
    ['host-uninstall', true],
] as const) {
    const command = cli.command(id, `cli.cmd.${id}`);
    if (mutating) command.option('--dry-run', 'cli.opt.dry-run');
    command.actionCtx(async (options, _args, ctx) => resolve(options, ctx, id, mutating));
}

/** Exported for build tooling, which reads the command tree without running `--help`. */
export { cli };

/** Nearest `package.json` name above a file or directory, if any. */
function nearestPackageName(target: string): string | undefined {
    let dir = path.dirname(target);
    while (true) {
        const manifest = path.join(dir, 'package.json');
        if (fs.existsSync(manifest)) {
            try {
                const parsed = JSON.parse(fs.readFileSync(manifest, 'utf8')) as { name?: unknown };
                return typeof parsed.name === 'string' ? parsed.name : undefined;
            }
            catch {
                return undefined;
            }
        }
        const parent = path.dirname(dir);
        if (parent === dir) return undefined;
        dir = parent;
    }
}

/** True when `invoked` resolves to this module, following package-manager symlinks and junctions. */
function relationToEntry(invoked: string): 'main' | 'imported' | 'unresolved' {
    const self = fileURLToPath(import.meta.url);
    try {
        if (fs.realpathSync(invoked) === fs.realpathSync(self)) return 'main';
    }
    catch {
        // A dangling link or removed file still counts as a launch attempt when
        // it carries this entry's name.
    }
    if (path.basename(invoked) !== path.basename(self)) return 'imported';
    return nearestPackageName(invoked) === nearestPackageName(self) ? 'unresolved' : 'imported';
}

const entry = process.argv[1];
if (entry !== undefined) {
    const relation = relationToEntry(entry);
    if (relation === 'main') {
        process.exitCode = await cli.parse(process.argv);
    }
    else if (relation === 'unresolved') {
        console.error(`[open-ssl] cannot resolve entry "${entry}" to "${fileURLToPath(import.meta.url)}"`);
        process.exitCode = 1;
    }
}
