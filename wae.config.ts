/**
 * OpenSSL build configuration.
 *
 * Plain literal data: `wae` parses this file without executing it, so a config
 * cannot run commands, spawn processes, or branch on `process.env`. Every
 * relative path resolves against this directory.
 *
 * `wae build` runs `native → ts → ui → skills → staging` in that order and
 * fails with a stable `build_*` code instead of skipping a missing artifact.
 */
import { defineConfig } from '@wae/wae';

export default defineConfig({
    native: {
        crate: 'open-ssl-napi',
        cdylib: 'open_ssl_napi',
        profile: 'release',
        targets: [
            {
                platform: 'win32',
                arch: 'x64',
                triple: 'x86_64-pc-windows-msvc',
                package: '@wae/open-ssl-win32-x64',
                nodeFile: 'open-ssl.win32-x64.node',
                dir: 'projects/open-ssl.ts/packages/open-ssl-win32-x64',
            },
        ],
    },
    packages: [
        {
            name: '@wae/open-ssl-win32-x64',
            dir: 'projects/open-ssl.ts/packages/open-ssl-win32-x64',
            os: ['win32'],
            cpu: ['x64'],
            main: 'open-ssl.win32-x64.node',
        },
    ],
    build: {
        ts: { packages: ['@wae/open-ssl', '@wae/open-ssl-cli'] },
        ui: { package: '@wae/open-ssl-ui' },
        stage: [
            {
                from: 'projects/open-ssl.ts/packages/open-ssl-ui/dist/static',
                to: 'projects/open-ssl.ts/packages/open-ssl-cli/dist/gui',
                clean: true,
            },
        ],
        outputs: ['projects/open-ssl.ts/packages/open-ssl-cli/dist/gui/index.html'],
    },
    skills: {
        packages: [
            {
                dir: 'projects/open-ssl.ts/packages/open-ssl-skills/skills',
                packageJson: 'projects/open-ssl.ts/packages/open-ssl-skills/package.json',
                appPackageJson: 'projects/open-ssl.ts/packages/open-ssl/package.json',
                cliEntry: 'projects/open-ssl.ts/packages/open-ssl-cli/dist/cli.js',
                commandName: 'open-ssl',
            },
        ],
    },
    // The publishable set is the non-private platform package, the TypeScript
    // packages under `build.ts`, and any non-private UI package. Skills is
    // `private` in this round, so it is not part of the release set.
    release: {
        registry: 'https://registry.npmjs.org',
        tagPattern: '^v(\\d+\\.\\d+\\.\\d+)$',
        packages: [
            { dir: 'projects/open-ssl.ts/packages/open-ssl-win32-x64' },
            { dir: 'projects/open-ssl.ts/packages/open-ssl' },
            { dir: 'projects/open-ssl.ts/packages/open-ssl-cli' },
        ],
    },
    // `wae build` validates this CI contract: the declared workflow files must
    // exist, `requiredJobs` must be real job ids, and `repo` must match
    // `Cargo.toml#repository`. Claim `shaBinding` only when a workflow actually
    // binds `GITHUB_SHA` to the release tag.
    ci: {
        repo: 'nyar-os/OpenSSL',
        workflows: ['check-rust.yml', 'check-typescript.yml'],
        shaBinding: false,
    },
    // `wae build` writes these into the app CLI as `dist/wae-runtime.json`.
    // `shortcutDefault` is the install command's default (a desktop shortcut is
    // created unless `--no-shortcut` is passed), and every capability call
    // resolves the audit actor from the channels declared here.
    install: { shortcutDefault: true },
    audit: { actor: { kind: 'flag', id: 'flag', source: 'env' } },
});
