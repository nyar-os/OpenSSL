---
name: workflow
description: Drive the OpenSSL CLI to read capabilities, inspect a certificate, and issue or export only after explicit confirmation.
---

# OpenSSL agent workflow

This skill drives the `open-ssl` CLI. The CLI is non-interactive and every
command returns a stable exit code:

- `0` success
- `1` runtime failure
- `2` usage or validation failure
- `3` structured capability failure (`unsupported_platform`, `not_implemented`,
  `dependency_blocked`)
- `4` canceled

Prefer `--json`. Every result is a `wae.cli-result/v0` envelope:
`{ "schema", "ok": true, "data": ... }` or
`{ "schema", "ok": false, "error": { "code", "capability", "platform", "message" } }`.
Do not parse human prose.

## Read before write

`certificate-inspect` is read-only. Issuance, renewal, revocation, and private
key export are separate capabilities with their own confirmation.

1. Read the capability table. Rows with a non-null `state` are refusals and must
   not be attempted.

   `open-ssl capabilities --json`

2. Inspect a certificate without writing anything. The report carries a
   normalized view of subject, issuer, serial, validity, and key usage.

   `open-ssl certificate-inspect --json`

## Certificate lifecycle

3. Preview issuance. Show subject, key type, validity range, and the CA identity
   to the user before applying.

   `open-ssl certificate-issue --dry-run --json`

4. Issue only after explicit confirmation.

   `open-ssl certificate-issue --json`

5. Renew with the same idempotent policy. A renewal must not silently replace a
   certificate whose identity changed.

   `open-ssl certificate-renew --dry-run --json`

6. Revoke with an explicit reason category. Revocation is never implied by a
   renewal.

   `open-ssl certificate-revoke --dry-run --json`

## Private keys and the local store

7. Generate or import a private key only through CNG or a DPAPI-protected
   container. Export is an explicit high-risk action and is disabled by default.

   `open-ssl private-key-store --dry-run --json`

8. Enumerate or write the local Windows certificate store. Machine scope requires
   additional confirmation.

   `open-ssl certificate-store --dry-run --json`

## Audit

Every domain call is recorded with the capability id, the target count, and a
redacted target summary. Use a stable `--actor` id so records are attributable.

   `open-ssl audit --kind <user|agent> --capability <id> --limit <n> --json`

## Safety

- In this skeleton round every domain capability refuses with `not_implemented`.
  A refusal is not a success. Do not fall back to an external `openssl`,
  `certutil`, `certreq`, `makecert`, or PowerShell certificate command.
- Never place private keys or passphrases in command output, logs, or audit
  records. Audit only records the action and the key type.
- Do not execute a mutating command without explicit confirmation（确认）from the
  user after the dry-run preview.
- Do not retry a structured capability failure with elevated privileges. Report
  the `code`, `capability`, and `platform` fields instead.
- Treat `--json` output as the contract. Exit code `3` means the capability is
  unavailable on this platform or is not implemented.
