# Plan execution harness

Does running the plan work? `upgrade_planner` is checked here by doing what it says. For each
project of a pinned public corpus, the harness:

1. clones it at its tag (the commit is checked against `corpus.json`);
2. asks the server for a detailed `vulnerability_scan` and the whole plan
   (`upgrade_planner`, `max_recommendations: 1000`), retried while lookups are NOT CHECKED;
3. runs the plan's steps top to bottom in a copy, with package-manager scripts disabled;
4. rescans the copy from a fresh server process.

It reports, per project and in total: steps run, steps that failed, steps that named a command
the harness does not run, steps without effect, steps that lowered a version an earlier step set
or that was installed, advisories before and after, and the plan's own prediction (which
vulnerable copies it gave something to run for) against the copies left. Then it applies the gate
in `thresholds.json`.

- Copies are counted per lockfile entry, so a step that moves the hoisted copy of a version while
  a bundled copy of the same version stays has moved it.
- Without effect: some copy the step was for was still there before it, it moved none, and it
  either changed nothing or no later step serves the same rows (a Cargo pre-update that frees the
  crates a later `--precise` moves has done its part when it changes the lockfile). A step whose
  copies an earlier step already moved had nothing left to do and is not counted.
- Lowered: the step removed a version, added only lower ones, and left no version at or above it
  on its release line (the major, or `0.minor`). Copies of one package on several lines that each
  move up their own line onto versions the lockfile already held are not a lowering, nor is a step
  whose every added version moves up a line the lockfile already held (the removed copies left with
  what required them). The cost: a copy that drops onto the top of a line already held is not seen.
- Each step records `moved` (its copies it moved) and `changes` (per lockfile, the versions of the
  packages it serves that went and came).

This checks a sequence, not single steps. The 2026-11-23 audit found single steps mostly right
and the sequence not: later steps undid earlier ones (Go `go get` downgrades, three npm rows
naming three `mocha` majors), one major bump broke the npm peer tree and the next 8 commands
failed, and some targets brought in new vulnerable copies.

## Run it

```bash
pnpm run build
# against this checkout's build
node bench/plan-exec/run.mjs --server dist/index.js
# against an installed package (a directory holding node_modules/@4da/mcp-server, or the package itself)
node bench/plan-exec/run.mjs --server /tmp/pub
# two projects only, results somewhere known
node bench/plan-exec/run.mjs --server dist/index.js --only fd,fastapi-frontend --out /tmp/plan-exec
```

Options: `--corpus <file>`, `--only id,id`, `--work <dir>` (copies, caches and the server's
data folder; must be outside this repository; default a new temp folder, removed afterwards),
`--out <dir>` (results; default a new temp folder), `--thresholds <file>`, `--keep` (leave the
work folder), `--shared-caches` (use your own npm, cargo, Go and uv caches instead of fresh
ones under `--work`), `--no-gate`.

Output: `plan-exec-result.json` (totals, gate findings, and per project every step with the
commands as given and as run, exit codes, output tails, versions lowered), `plan-exec-summary.md`
(a readable table and every step that did not simply work), and `raw/` (the scans and the plan
the server gave). Exit 0 when the gate passes, 1 when it fails, 2 when the harness cannot start.

Needs: git, Node 22 (npm and corepack bundled), cargo, Go (any release from 1.21: a plan that
raises the go directive has the go command download that toolchain), uv, and the network
(GitHub, the registries, OSV.dev). pnpm and Yarn classic come through `npx` at the versions
`corpus.json` names; Yarn berry through corepack at the project's version.

## What it runs, and what it never runs

- Only lockfile and manifest changes: `npm install|update|uninstall|dedupe|pkg set`,
  `pnpm install|up|add|remove|dedupe`, `yarn [install]|upgrade|up|add|remove|dedupe`,
  `bun install|update|add|remove`, `cargo update|add|remove`, `uv lock|add|remove`,
  `go get`, `go mod tidy`. Anything else is refused and counted (`pip`, `poetry`, `npx`,
  `npm run`, builds, tests).
- Scripts off: npm `--package-lock-only --ignore-scripts`, pnpm `--lockfile-only
  --ignore-scripts --ignore-pnpmfile`, Yarn classic `--ignore-scripts --ignore-engines`, Yarn
  berry `--mode update-lockfile` with `YARN_ENABLE_SCRIPTS=false`, uv `UV_NO_BUILD=1` (and
  `--no-sync`), Go `GOFLAGS=-mod=mod`. Cargo's update and add build nothing.
- A project's own package-manager code is removed from the copy first: `yarnPath` / `yarn-path`
  and `plugins` in `.yarnrc.yml` / `.yarnrc`, `.yarn/releases`, `.yarn/plugins`, `.pnpmfile.cjs`.
- Every command is split into tokens; a shell operator outside quotes, or a token with a
  character a shell would expand, refuses the step. Each argument is passed double-quoted.
- The server runs with its data folder and every place it looks for the desktop app's database
  under `--work`: it never reads or writes your real stores.

## Where the steps come from

| `order_source` | When | Steps |
|---|---|---|
| `run_order` | the plan has `run_order` (6.5.0) | `run_order[]` in order: `{ n, dir, run, fixes }` |
| `row_commands` | no `run_order`, rows carry `commands[]` | each row's commands, in row order |
| `legacy_rows` | neither (6.4.0 and older): **baseline mode** | the audit's extraction from the vulnerable rows' `upgradeCommands`, `refreshCommands`, `parentUpgrades` levers and override snippets, in row order |

The gate requires `run_order` (`require_order_source`), so a plan without one fails it whatever
else it scores; baseline mode exists so the same harness measures 6.4.0.

## The gate (`thresholds.json`)

A scan whose only gap is private dependencies counts as complete (`scanComplete` in `lib.mjs`):
the server never looks up a dependency a lockfile takes from a private index, on any attempt, so
there is nothing a retry could add. The corpus has one such project (an example lockfile of
mcp-python-sdk names an internal index for three packages); the summary names it and the number.

Fails when a project cannot be run or a scan stays NOT CHECKED, when any step fails, lowers a
version, or is refused, when the plan has no `run_order`, or when the corpus's net share of
advisories cleared, `(before - after) / before`, is below `min_net_cleared_ratio` (0.75: just under what the
6.5.0 candidate measured, 0.7595; raise it to what a release measures, in the change that records that
run). Advisory counts drift as OSV.dev adds records for these old versions, so the gate reads a
ratio, never a count.

This is not a pull-request job: it clones 13 repositories, resolves their trees against the
live registries and takes about an hour of runner time. `.github/workflows/plan-exec.yml` runs
it weekly and on demand (`workflow_dispatch`, optionally for a published version).

## Baseline: 6.4.0

The audit's Track B (2026-11-23) ran 6.4.0's full plans on these 14 projects by hand-built
scripts that this harness ports:

- 438 plan rows; 362 steps came with something to run, of which **328 worked**, **13 cleared
  their advisory but did harm** (a downgrade, new vulnerable copies, a broken peer tree),
  **10 failed** and **11 ran with the advisory left in place**.
- Advisory rows **1,198 -> 273** (77% cleared). The plan's rows predicted 66 vulnerable copies
  would be left; 86 were.

| project | pm | advisories before -> after (audit) |
|---|---|---|
| http-server v14.1.1 | npm | 82 -> 31 |
| nodemon v2.0.20 | npm | 109 -> 52 |
| fastapi-frontend 0.7.1 | npm | 89 -> 6 |
| ni v0.18.8 | pnpm 7 | 96 -> 0 |
| eslint-config v0.34.0 | pnpm 7 workspace | 98 -> 1 |
| h3 v1.12.0 | pnpm 9 workspace | 201 -> 42 |
| zustand v4.1.4 | yarn classic | 224 -> 29 |
| reselect v4.1.8 | yarn berry | 116 -> 17 |
| fd v8.4.0 | cargo | 5 -> 3 |
| bat v0.22.1 | cargo | 11 -> 7 |
| fastapi-backend 0.7.1 | uv | 84 -> 36 |
| mcp-python-sdk v1.1.0 | uv workspace | 24 -> 17 |
| glow v1.5.0 | go | 55 -> 32 |
| fzf 0.35.1 | go | 4 -> 0 |

This harness on 6.4.0 (`legacy_rows`), two projects, 2026-11-23: **fd** 6 steps, step 3
`cargo update -p chrono@0.4.19 --precise 0.4.30` fails with exit 101 (step 2 had already moved
chrono), advisories 5 -> 3; **fastapi-frontend** 16 steps, steps 8 to 15 fail (`peer
vite@"^4 || ^5" from @vitejs/plugin-react-swc@3.5.0`, left by step 7's `vite@^6.4.5`),
advisories 89 -> 6. Both match the audit's runs.

Where this harness differs from the audit's scripts, so its 6.4.0 totals will not match the
table above exactly:

- The audit ran `uv lock --upgrade-package X==<target>` for PyPI direct rows that named no
  command; this harness runs only what the plan says, so those rows are `nothing_to_run` and
  fastapi-backend and mcp-python-sdk end with more advisories.
- The audit also rescanned with osv-scanner; this harness uses the server's own detailed scan
  (the audit's 1,198 -> 273 are the server's own rows too).
- Go inventories come from `go.mod` (the audit used `go list -m all`), so no module download is
  needed to see a lowered version.
- A Yarn classic "delete the entries, then yarn install" step installs at once instead of being
  deferred to the end.
