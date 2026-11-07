# OpenSSL

Certificate generation and management. In this skeleton round every domain
capability refuses with `not_implemented`, and no external `openssl`, `certutil`,
`certreq`, `makecert`, or PowerShell certificate command is ever started.

The product name does not imply affiliation with, endorsement of, or use of
the OpenSSL project or its library.

## Capabilities

| Capability | Target behaviour |
|------------|------------------|
| `certificate-inspect` | Parse X.509, ASN.1, DER, and PEM input and display a normalized certificate view |
| `certificate-issue` | Sign a CSR with a CA and write the issued certificate without external tools |
| `certificate-renew` | Reissue a certificate with an idempotent renewal policy |
| `certificate-revoke` | Revoke a certificate and publish a CRL with an explicit reason code |
| `ca-create` | Create and manage a root or intermediate CA |
| `csr-create` | Build and validate a certificate signing request with key usage and extensions |
| `private-key-store` | Generate, protect, import, and export private keys through CNG or a DPAPI container |
| `certificate-store` | Enumerate, import, and export certificates in the local Windows store |
| `remote-agent` | Manage certificates on a remote computer through the first-party agent channel |
| `host-install` | Install the host integration and desktop entry |
| `host-uninstall` | Remove the host integration and clean residual state |

Inspection and issuance are separate capabilities. Inspection never writes. A
remote write requires the first-party agent channel and never falls back to a
system tool.

## Layout

| Path | Responsibility |
|------|----------------|
| `projects/open-ssl.rs/crates/core` | Portable domain model, capability matrix, audit fields |
| `projects/open-ssl.rs/crates/napi` | Platform-neutral N-API surface over the `wae` facade |
| `projects/open-ssl.rs/crates/cli` | Command ids, exit codes, and the machine-readable contract |
| `projects/open-ssl.ts/packages/open-ssl` | Typed library over the native boundary. Owns no `bin` |
| `projects/open-ssl.ts/packages/open-ssl-cli` | The `open-ssl` command entry and locales |
| `projects/open-ssl.ts/packages/open-ssl-ui` | VMZ page and design tokens. Staged into the CLI `dist/gui` |
| `projects/open-ssl.ts/packages/open-ssl-skills` | Agent skills with frontmatter and safety prerequisites |
| `projects/open-ssl.ts/packages/open-ssl-win32-x64` | First native platform package |
| `wae.config.ts` | Native targets, platform packages, TS/UI/skills steps, staging and release set |

## First run

```sh
npm install --global @wae/wae
pnpm install
```

Commit `pnpm-lock.yaml` and `Cargo.lock` before enabling CI. `check-typescript.yml`
runs `pnpm install --frozen-lockfile`, so a missing lockfile fails the job by
design.

## Commands

```sh
pnpm run build         # wae build: native → TS → UI → skills → staging
pnpm run build:napi    # build one configured native target and stage it
pnpm run stage:napi    # restage an already built native artifact
pnpm run smoke:napi    # load the staged addon and verify capabilities
pnpm run check:rust    # fmt + clippy -D warnings + test
```

CLI surface:

```sh
open-ssl capabilities --json
open-ssl version
open-ssl certificate-inspect --json
open-ssl certificate-issue --dry-run --json
open-ssl private-key-store --dry-run --json
open-ssl remote-agent --dry-run --json
open-ssl audit --kind agent --limit 20 --json
```

Exit codes: `0` success, `1` failure, `2` usage, `3` capability unavailable,
`4` canceled. `--json` emits `wae.cli-result/v0` envelopes.

## Audit

Every exported N-API capability is wrapped at the boundary through `wae::audit`
(`wae.audit/v0`). The domain supplies the capability id, the target count, the
redacted target summary, and a stable error code. Actor, host, session, schema,
timestamps, duration, and sanitisation stay in the shared facility. Do not add a
second audit schema.

## License

Apache-2.0. See the single repository-level `License.md`.
