# Contributing

Thanks for looking. Issues and pull requests are welcome.

## Setup

Node.js 22 or later and pnpm (the version in `package.json` `packageManager`;
`corepack enable` picks it up).

```bash
pnpm install
pnpm run build
pnpm test            # offline; cargo-dependent tests skip without cargo
pnpm run check       # repository gates
pnpm run contract    # the desktop app's schema contract (see contract/README.md)
```

`pnpm run inspect` opens the server in the MCP Inspector.

## Pull requests

- One change per PR, with a test that fails without it.
- CI must be green: tests on Linux, Windows and macOS, the gates, the
  dependency audit, the package-contents check and the app-schema contract.
- New source files start with `// SPDX-License-Identifier: Apache-2.0`.
- A new tool needs an `inputSchema` on its `xxxTool` definition, a registry
  entry, a dispatch entry, and a `schema-contract.test.ts` SOURCES entry.
- SQL against the desktop app's tables must match `contract/app-schema.sql`.
  Guard columns the app added recently with `hasColumn()`: users run the app
  and this server at independent versions.

## Releases

Maintainers only: `node scripts/release.mjs <patch|minor|major>`, merge the
release PR, then tag the merge commit `mcp-v<version>`. See the header of
`scripts/release.mjs`.

## Licence

By contributing you agree that your contribution is licensed under the
Apache License 2.0, the licence of this repository.
