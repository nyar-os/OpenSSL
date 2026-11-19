/**
 * Typed library and command surface over the N-API boundary.
 *
 * One class owns every capability. `new OpenSSL(options)` supplies the issuance
 * defaults and each method accepts overrides, so callers never rebuild an
 * options object per call. The `open-ssl` `bin` in `cli.ts` is a thin
 * `@wae/commander` assembly over this class, and it owns no protocol logic.
 */
import { AppError, fromNativeError } from './errors.js';
import { loadNative, type AcmeIssueOptions, type AcmeTargetOptions } from './native.js';

export type { AcmeIssueOptions, AcmeTargetOptions } from './native.js';

/** Local-only issuance plan returned by `acmePlan` and by a dry run. */
export interface AcmePlan {
    projectRoot: string;
    kind: 'staging' | 'production';
    dnsProvider: string;
    identifiers: string[];
    secretsFile: string;
    secretsAvailable: boolean;
    dnsTokenAvailable: boolean;
    existingAccount: boolean;
    pendingOrder: string | null;
    requiredSansNote: string[];
}

/** Managed file locations of a delivered generation; never the key body. */
export interface AcmeGenerationPaths {
    certificate: string;
    chain: string;
    privateKey: string;
}

/** Delivered certificate produced by a real issuance run. */
export interface AcmeIssueReport {
    accountUrl: string;
    orderUrl: string;
    generation: string;
    dnsRecordsRemoved: number;
    /** Manual-path records the operator must still delete after delivery. */
    manualRecordsToRemove?: AcmeTxtInstruction[];
    sans: string[];
    certificateSha256: string;
    notBeforeUnix: number;
    notAfterUnix: number;
    paths: AcmeGenerationPaths;
}

/** One TXT record the operator has to place in the DNS console. */
export interface AcmeTxtInstruction {
    fqdn: string;
    value: string;
}

/** Manual dns-01 prepare result: persisted action plus resume instruction. */
export interface AcmeActionRequired {
    actionId: string;
    statusRef: string;
    expiresUnix: number;
    records: AcmeTxtInstruction[];
    nextAction: { command: string; argv: string[] };
}

/** Outcome of `acmeIssue`: a dry run carries the plan, a manual prepare run the action. */
export interface AcmeIssueOutcome {
    dryRun: boolean;
    plan?: AcmePlan;
    report?: AcmeIssueReport;
    actionRequired?: AcmeActionRequired;
}

/** Capability availability states. `null` means available. */
export type CapabilityState = 'unsupported_platform' | 'not_implemented' | 'dependency_blocked';

/** One capability row. */
export interface CapabilityItem {
    id: string;
    state: CapabilityState | null;
    code: string | null;
    reason: string;
    detail: string;
}

/** Capability report, including the `gui` row added by the native boundary. */
export interface CapabilitiesReport {
    app: string;
    platform: string;
    arch: string;
    version: string;
    items: CapabilityItem[];
    notes: string[];
}

/** GUI open options. */
export interface GuiOptions {
    contentDir?: string;
    title?: string;
}

/** Caller identity used by the shared audit facility. */
export interface AuditActor {
    actorKind?: 'user' | 'agent';
    actorId?: string;
    actorSource?: string;
    session?: string;
    host?: string;
}

/** Audit query filter. */
export interface AuditQuery {
    kind?: 'user' | 'agent';
    id?: string;
    fromMs?: number;
    toMs?: number;
    capability?: string;
    limit?: number;
}

/** One audit record as stored by the shared facility. */
export type AuditRecord = Record<string, unknown>;

/** Success payload shared by the meta capabilities. */
export interface OkResult {
    ok: true;
}

/**
 * Issuance defaults shared by every capability call.
 *
 * The constructor takes the same shape, and each method accepts a partial
 * override. Domain capabilities added by later rounds (ACME issuance, CSR,
 * keystore) read their defaults from here, so callers configure once.
 */
export interface OpenSSLOptions {
    /** Default audit actor applied by `configureAudit()`. */
    actor?: AuditActor;
    /** ACME directory URL for issuance capabilities. */
    acmeDirectoryUrl?: string;
    /** ACME account contact email. */
    accountEmail?: string;
    /** DNS names the issuance capabilities default to. */
    domains?: string[];
    /** Per-call timeout in milliseconds. */
    timeoutMs?: number;
}

/** Per-call overrides accepted by `invoke`. */
export interface InvokeOverrides extends Partial<Omit<OpenSSLOptions, 'actor'>> {}

/**
 * A client for one set of issuance defaults.
 *
 * ```ts
 * const ssl = new OpenSSL({
 *     acmeDirectoryUrl: 'https://acme-staging-v02.api.letsencrypt.org/directory',
 *     accountEmail: 'me@example.com',
 *     domains: ['*.example.com'],
 * });
 * const report = ssl.capabilities();
 * ```
 */
export class OpenSSL {
    readonly #defaults: OpenSSLOptions;

    constructor(options: OpenSSLOptions = {}) {
        this.#defaults = { ...options };
    }

    /** Native addon version. */
    version(): string {
        return this.#invoke(() => loadNative().version());
    }

    /** Capability report, including rows owned by the upstream facade. */
    capabilities(): CapabilitiesReport {
        return this.#invoke(() => loadNative().capabilities() as CapabilitiesReport);
    }

    /**
     * Resolve one domain capability by its stable id.
     *
     * Available capabilities have dedicated methods, so this raises their
     * refusal instead of silently doing nothing. The constructor defaults are
     * forwarded as the call parameters.
     */
    invoke<T = unknown>(capability: string, overrides: InvokeOverrides = {}): T {
        const { actor: _actor, ...defaults } = this.#defaults;
        const params = { ...defaults, ...overrides };
        return this.#invoke(() => loadNative().invoke(capability, params) as T);
    }

    /**
     * Read the local-only issuance plan.
     *
     * Inspects project state and provider-token availability without creating
     * an account or order, writing files, touching DNS, or generating keys.
     */
    acmePlan(options: AcmeTargetOptions): AcmePlan {
        return this.#invoke(() => loadNative().acmePlan({ ...options }) as AcmePlan);
    }

    /**
     * Drive certificate issuance to a delivered generation, or plan only.
     *
     * `dryRun: true` is exactly `acmePlan`. A real run reads the provider token
     * from the calling project's `.secrets/open-ssl.json`, publishes the DNS
     * challenges, and returns the delivered report; any failure is a structured
     * `AppError`, never a silent blocked result.
     */
    acmeIssue(options: AcmeIssueOptions): AcmeIssueOutcome {
        return this.#invoke(() => loadNative().acmeIssue({ ...options }) as AcmeIssueOutcome);
    }

    /** Configure the shared audit facility, defaulting to the constructor actor. */
    configureAudit(actor: AuditActor = this.#defaults.actor ?? {}): OkResult {
        return this.#invoke(() => loadNative().configureAudit({ ...actor }) as OkResult);
    }

    /** Read audit entries for the current actor as structured records. */
    auditQuery(filter: AuditQuery = {}): AuditRecord[] {
        const json = this.#invoke(() => loadNative().auditQuery({ ...filter }));
        return this.#invoke(() => JSON.parse(json) as AuditRecord[]);
    }

    /** Open the GUI window. */
    openGui(options: GuiOptions = {}): { backend: string } {
        return this.#invoke(() => loadNative().openGui({ ...options }) as { backend: string });
    }

    /** Pump one GUI event batch. */
    pumpEvents(): boolean {
        return this.#invoke(() => loadNative().pumpEvents());
    }

    /** Request GUI close. */
    closeGui(): boolean {
        return this.#invoke(() => loadNative().closeGui());
    }

    /** Whether the GUI window is still open. */
    isGuiOpen(): boolean {
        return this.#invoke(() => loadNative().isGuiOpen());
    }

    /**
     * Open the GUI and pump until the window closes.
     *
     * The host owns the event loop, so the process stays alive without spawning
     * a second runtime.
     */
    async runGui(options: GuiOptions = {}): Promise<string> {
        const opened = this.openGui(options);
        while (this.pumpEvents()) {
            await new Promise((resolve) => setTimeout(resolve, 16));
        }
        this.closeGui();
        return opened.backend;
    }

    /** Convert native boundary failures into `AppError`. */
    #invoke<T>(run: () => T): T {
        try {
            return run();
        }
        catch (error) {
            throw fromNativeError(error);
        }
    }
}

export { AppError, fromNativeError } from './errors.js';
