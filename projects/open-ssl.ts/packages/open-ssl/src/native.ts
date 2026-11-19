/**
 * Lazy loader for the platform-native addon.
 *
 * The addon is an optional dependency. It is loaded only when a native
 * capability is called, so `--help`, `version`, and locale resolution work on
 * machines without the binary.
 */
import { createRequire } from 'node:module';
import { AppError } from './errors.js';

const require = createRequire(import.meta.url);
const PLATFORM_PACKAGE = '@wae/open-ssl-win32-x64';

/** Raw surface exported by the Rust `napi` crate. */
export interface NativeBindings {
    version(): string;
    capabilities(): unknown;
    invoke(capability: string, params?: unknown): unknown;
    openGui(options?: { contentDir?: string; title?: string }): unknown;
    pumpEvents(): boolean;
    closeGui(): boolean;
    isGuiOpen(): boolean;
    configureAudit(options: {
        actorKind?: string;
        actorId?: string;
        actorSource?: string;
        session?: string;
        host?: string;
    }): unknown;
    auditQuery(filter?: {
        kind?: string;
        id?: string;
        fromMs?: number;
        toMs?: number;
        capability?: string;
        limit?: number;
    }): string;
    acmePlan(options: AcmeTargetOptions): unknown;
    acmeIssue(options: AcmeIssueOptions): unknown;
}

/**
 * Non-secret issuance target shared by plan and issue.
 *
 * Everything except `identifiers` may be omitted: the project's
 * `open-ssl.json` supplies `kind`, `dnsProvider`, zone and contacts, and the
 * final defaults are `staging` plus the interactive `manual` provider. A
 * value passed here always wins over the configuration.
 */
export interface AcmeTargetOptions {
    kind?: 'staging' | 'production';
    dnsProvider?: string;
    identifiers: string[];
    projectRoot?: string;
}

/** Full issuance options; a real `cloudflare` run demands a zone from flags or `open-ssl.json`. */
export interface AcmeIssueOptions extends AcmeTargetOptions {
    dryRun: boolean;
    dnsZoneId?: string;
    dnsZoneName?: string;
    contact?: string[];
}

let cached: NativeBindings | null = null;

/** Load the native addon once. */
export function loadNative(): NativeBindings {
    if (cached) return cached;
    try {
        cached = require(PLATFORM_PACKAGE) as NativeBindings;
        return cached;
    }
    catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        throw new AppError({
            code: 'native_unavailable',
            platform: `${process.platform}-${process.arch}`,
            message:
                `cannot load ${PLATFORM_PACKAGE}: ${message}\n` +
                'Run `pnpm run build:napi` from the repository root, ' +
                'or install the matching platform package.',
        });
    }
}
