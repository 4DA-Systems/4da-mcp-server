# Environment harnesses

What happens to the server's data folder when real hosts use it: several processes at once,
an editor killing a server while it creates its store, a fleet starting on a fresh folder.
Each harness takes the server entry point, works only in temp folders, runs **offline**
(`FOURDA_OFFLINE=1` and a proxy on a port nothing listens on, so nothing leaves the machine),
compares every answer with a single-process baseline taken by the same server, and exits 1 on
a violation. The projects (`lib.mjs`) are four small ones with distinct stacks (npm, Python,
Cargo, Go) and public package names.

```bash
pnpm run build
node bench/env/concurrency.mjs       --server dist/index.js [--seconds 60]
node bench/env/firstrun-kill.mjs     --server dist/index.js [--delays 0,5,...,300] [--reps 2] [--modes list,call]
node bench/env/firstrun-together.mjs --server dist/index.js [--reps 5] [--extra 2]
# any of them: --work <dir> (a new folder is made inside it), --out <dir> (writes <harness>.json), --keep
# against an installed package: --server <dir with node_modules/@4da/mcp-server>
```

| harness | what runs | violation |
|---|---|---|
| `concurrency.mjs` | one server started in each project and as many in an empty directory, one data folder (created by one session first; `--cold` skips that), all at once, looping scans of every project, `dependency_health`, `get_context`, decisions and memories for `--seconds` | an error answer; "database is locked", a missing table or an unreadable store; an answer about the wrong project or differing from the baseline; a write answered as kept that a fresh server cannot read back; a store failing `PRAGMA integrity_check` |
| `firstrun-kill.mjs` | on a new empty data folder each time: `initialize` + `tools/list` (mode `list`) or `initialize` + a scan (mode `call`), then a hard kill `<delay>` ms later; then a normal session on that folder | the next session lists other tools than a fresh folder gives, cannot scan the project as the baseline does, says the store or lockfile is broken, or loses a decision |
| `firstrun-together.mjs` | one server in each project and `--extra` in an empty directory started at the same instant on one empty data folder | a server that lists other tools than a fresh folder gives (before or after the others start), returns another stack from `get_context`, scans another project or another dependency count, or loses its decision |

Kill windows depend on the machine: a clean sweep on one runner is not proof for another, and a
broken folder on any machine is a real defect. `.github/workflows/plan-exec.yml` runs the three
weekly (job `env`) and on demand.

## 6.4.0

Ported from the 2026-11-23 audit's Track E scripts. What the audit found on 6.4.0, Windows:

- E1: a hard kill 55 to 70 ms into the first start of a data folder (6 of 28 kill points) left
  a zero-table `standalone.db`; every later session in every project then listed 16 tools and
  failed to read its lockfile, permanently.
- E2: servers started together on a fresh folder took their own store for the desktop app's
  database (39 of 60 sessions); `get_context` returned another project's stack in 4 of 10
  repetitions.
- Steady state held: 8 processes on one folder for 4 minutes, 16,380 calls, no error, no lost
  write, integrity ok.

This port on 6.4.0 (the published package, Windows, 2026-11-23, on a loaded machine):

- `firstrun-kill.mjs` (defaults: 19 delays x 2 modes x 2 repetitions): **19 of 76** kill points
  left a broken folder. `list` mode broke at 65, 70, 75, 80 and 90 ms (8 of 38), `call` mode
  at 5, 10 and 20 ms and from 65 to 150 ms (11 of 38). Every broken folder's next session listed
  16 tools instead of 11, could not read its lockfile ("scan read null dependencies") or failed
  to open the store, and lost the decision written to it. Exit 1.
- `firstrun-together.mjs` (5 repetitions, 6 servers): **3 of 5** repetitions wrong; 7 sessions
  went from 11 to 16 tools mid-session, and `get_context` returned another project's stack in
  5 sessions (the Rust project answered `flask,go,javascript,python`). Exit 1.
- `concurrency.mjs` (60 s, 8 processes, a folder one session created first): 8,056 calls, 0
  errors, 0 lock or wrong-project answers, 4,024 writes answered as kept and all of them read
  back and in the store, integrity ok. Exit 0, as in the audit. With `--cold` the same run
  meets the first-start race above.
