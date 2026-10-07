# @4da/mcp-server — instructions for coding agents

Local stdio MCP server (TypeScript, Node >= 22) giving coding agents upgrade intelligence:
`upgrade_impact`, `dependency_check`, `vulnerability_scan`, `dependency_health`,
`upgrade_planner` and more. It works standalone and also reads the 4DA desktop app's
database (`4da.db`) when the app is installed. The app is a separate repository:
github.com/4DA-Systems/4DA (until 2026-10-04 this server was its `mcp-4da-server/` folder).

## Commands

```bash
pnpm install --frozen-lockfile   # pnpm pinned in package.json packageManager (10.x)
pnpm run build                   # tsc -> dist/
pnpm test                        # vitest, offline
pnpm run check                   # SPDX, retired claims, REMOVE BY, pnpm pin
pnpm run contract                # app-schema contract (see contract/README.md)
pnpm run inspect                 # MCP Inspector
```

## Rules that bite

- **The desktop app's schema is a contract, not a guess.** SQL against app tables must match
  `contract/app-schema.sql`. Users run the app and this server at independent versions, so
  guard newer columns with `db.hasColumn()`. `pnpm run contract` must pass; CI also checks
  against the app's current `main`, and the app's merge queue checks this repo's `main`.
- **pnpm settings live in pnpm-workspace.yaml** (overrides, onlyBuiltDependencies), never in a
  `pnpm` field of package.json: pnpm 11 ignores that field and dropped every security override
  (issue #9). `pnpm run check` enforces it. Install with the pinned pnpm 10 (`packageManager`);
  pnpm 11 is used for `audit` only (`npx -y pnpm@11.13.1 audit --audit-level=high`).
- **Every source file starts with `// SPDX-License-Identifier: Apache-2.0`.** The app is FSL;
  this package is Apache-2.0.
- **No tool counts in static listing text** (npm description, server.json, directory copy):
  every count written there went stale.
- **Five manifests carry the version** (package.json, server.json x2, .claude-plugin/plugin.json
  incl. the npx pin, .claude-plugin/marketplace.json, gemini-extension.json).
  `manifest-versions.test.ts` holds them together; `scripts/release.mjs` bumps them together.
- **A new tool** needs an `inputSchema` on its `xxxTool`, a registry entry with `definition:`,
  a dispatch entry in `tool-dispatch.ts`, and a `schema-contract.test.ts` SOURCES entry.

## Releasing

`node scripts/release.mjs <patch|minor|major>` (needs a `## X.Y.Z — unreleased` changelog
entry first) -> PR -> merge -> tag the merge commit `mcp-v<version>` -> approve the `release`
environment. `release.yml` publishes to npm through trusted publishing (provenance required;
no token exists), then the MCP Registry, then a GitHub release with the `.mcpb` bundles.
`main` is protected: every change goes through a PR with green CI.
