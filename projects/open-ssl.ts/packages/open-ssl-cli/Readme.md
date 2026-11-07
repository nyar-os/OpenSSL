# @wae/open-ssl-cli

`open-ssl` command line entry.

- Non-interactive. Decisions are made by exit code, not by prose.
- `--json` emits `wae.cli-result/v0` envelopes on stdout.
- `certificate-inspect` never writes. Issuance, renewal, and revocation are separate capabilities.
- Mutating commands accept `--dry-run`.

Exit codes: `0` success, `1` failure, `2` usage, `3` capability unavailable, `4` canceled.

In this skeleton round every domain capability refuses with `not_implemented`.
