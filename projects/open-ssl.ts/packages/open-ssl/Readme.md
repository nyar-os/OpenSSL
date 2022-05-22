# `@wae/open-ssl`

Library and `open-ssl` command over native capabilities.

- loads the platform native addon lazily
- exposes one `OpenSSL` class whose constructor carries the issuance defaults
  and whose methods forward to the N-API exports
- owns the `open-ssl` `bin`, assembled with `@wae/commander`, and its locale
  catalogs
- owns the structured `AppError` used by every consumer

```js
import { OpenSSL } from '@wae/open-ssl';

const ssl = new OpenSSL({
    acmeDirectoryUrl: 'https://acme-staging-v02.api.letsencrypt.org/directory',
    accountEmail: 'me@example.com',
    domains: ['*.example.com'],
});

const report = ssl.capabilities();
console.log(report.items.map((item) => [item.id, item.state]));

// Skeleton round: every domain capability refuses with `not_implemented`.
ssl.invoke('certificate-inspect');
```

The command tree owns presentation only. Every operation goes through
`new OpenSSL(options)`, which forwards to the N-API exports, so the CLI, the
GUI, and agents share one capability contract.

See the repository `Readme.md` for build and test commands.
