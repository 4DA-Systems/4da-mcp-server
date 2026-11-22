# App-mode arm

The same project must get the same dependency answers whether or not the 4DA desktop app's
database is attached (DESIGN: one inventory, the disk). `run.mjs` scans (concise and
detailed) and plans one project three ways, each from a server started **in** the project with
no `project_path`, which is how 4DA's own `.mcp.json` and every app user's configuration start
it:

| run | database |
|---|---|
| A | none (the server's own store) |
| B | an app database built from `contract/app-schema.sql` whose `project_dependencies` rows cover every sub-project, as the app writes them after a full index |
| C | B with one sub-project's rows removed (an app index that has not seen that directory) |

It fails unless B and C give A's vulnerable packages, counts (`total_dependencies_scanned`,
`total_vulnerable_packages`, `by_severity`, `by_advisory_severity`), advisory rows and plan
rows, and unless every scan answer carries a `coverage` object. It says which field differs and
how. The three runs share one server data folder, so their lookups share one cache.

```bash
pnpm run build
node bench/app-mode/run.mjs --server dist/index.js                     # the fixture below
node bench/app-mode/run.mjs --server dist/index.js --project ~/code/app --drop services/api
node bench/app-mode/run.mjs --server <dir with node_modules/@4da/mcp-server> --out /tmp/app-mode
```

Options: `--project <dir>` (read only; at least two lockfile directories), `--drop <dir>` (the
sub-project C leaves out; default the first one below the root), `--work <dir>` (a new folder is
made inside it), `--out <dir>` (writes `app-mode.json`), `--offline` (nothing is sent: use it for
a project with made-up or private names), `--keep`. Exit 1 when the three disagree, 2 when the
harness cannot run.

`fixture.json` is the default project: an npm project at the root (lodash 4.17.20, minimist
1.2.5) and a Cargo project in `svc/` (smallvec 1.6.0, time 0.1.43), public names at versions
with published advisories. It is kept as JSON and written to a temp folder at run time, so this
repository holds no lockfile with known advisories for scanners to report, and no run writes
beside the repository's files.

`.github/workflows/plan-exec.yml` runs it weekly (job `app-mode`) and on demand.

## 6.4.0

The audit (2026-11-23, L1 and C2-F1) found that with the app's database attached, 6.4.0 took
its list of sub-projects from `project_dependencies` instead of the disk, returned no
`coverage` block, and dropped a sub-project the app had not indexed without a word.

This arm on 6.4.0 (the published package, the fixture, 2026-11-23) exits 1 with 12 violations:

- A and B agree (4 dependencies, 4 vulnerable packages, 7 advisory rows, 4 plan rows).
- C drops `svc/` silently: 2 dependencies, 2 vulnerable packages (smallvec 1.6.0 and time 0.1.43
  gone, with their advisories and their two plan rows), `by_severity` critical 1 instead of 2.
- No answer in any of the three carries `coverage`: 6.4.0 writes the block only when a scan is
  partial (`vulnerability-scan-format.ts`, "Present only when the scan is partial"), so a
  complete scan and one that skipped a sub-project look the same.
