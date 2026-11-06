# G7: does the server stop a coding agent from writing a vulnerable version?

G7 is the agent-level evaluation of `@4da/mcp-server`. It gives a coding agent an ordinary dependency
task ("add a YAML parser", "upgrade Django but stay on 4.2", "pin ws 7.x") and checks the version it
actually writes into the manifest or lockfile against known advisories. Two arms, the same agent:
one without any MCP server, one with only this server. Nothing else differs.

This directory is not part of the npm package (`package.json` `files` lists `dist` only, and CI's
package-contents check rejects `bench/`).

## Results

Measured on the 6.2.5 and 6.2.6 release candidates (each installed from its packed tarball),
model `claude-sonnet-5-5`, 49 tasks x 3 trials per arm.

| | without the server | with the server |
|---|---|---|
| **Primary: vulnerable version written, well-posed tasks** | **82 / 138** (59.4%, 95% CI 51.1-67.3%) | **0 / 138** (0%, 95% CI 0-2.7%) |
| Fisher's exact, two-sided | | p = 9.3e-33 |
| Task-clustered sign test (28 tasks better, 0 worse, 18 ties) | | p = 7.5e-9 |
| Vulnerable, all 49 tasks | 91 / 147 | 9 / 147 |
| npm / PyPI / crates.io / Go (well-posed) | 21/36, 18/30, 22/36, 21/36 | 0 in each |
| add / upgrade / pin (well-posed) | 40/72, 15/24, 27/42 | 0 in each |
| Run errors | 0 / 147 | 0 / 147 |
| Runs that called the server | | 147 / 147 (`dependency_check` in all) |

The 6.2.5 and 6.2.6 runs gave the same primary result; both share one control arm (the control arm
has no server, so a server release does not change it). `results/summary-final-62{5,6}.json` hold
every table; `results/scores-final-62{5,6}.json` hold the per-run rows.

**The 9 / 147 on all tasks** are the three ill-posed tasks (n06, p04, p09), 3 runs each: by the
pinned truth, no release inside their constraint is free of advisories (every Next.js 13.x, every
Django 4.2.x, every Flask 2.x). Whatever is written there is scored vulnerable, and keeping the
starting version counts as writing it. The control arm also scored 9 / 9 on them. With the server,
all three n06 runs left next unchanged (one ending "no safe next@13.x release exists"); the scorer
does not credit a refusal, by design.

**Truth staleness adjustments (6.2.6, `ADJUDICATION-626.txt`).** Truth was pinned on 2026-10-24.
In 6 runs (g01-add-xnet x3, g11-upgrade-xnet x3) the agent chose `golang.org/x/net v0.62.0`,
published 2026-10-27, after the truth: the scorer marks a version it has not seen as
"nonexistent", so treatment "completed" reads 132 / 138. OSV on 2026-10-29: v0.62.0 has no advisory
and v0.61.0, the newest release in the truth, has two, so the pick was correct. Adjusted:
completed 138 / 138, nonexistent 0. The primary endpoint is unaffected (a nonexistent pick is not
counted as vulnerable, in either direction).

## Design

- **Pre-registered.** `PREREGISTRATION.txt` was written on 2026-10-11, before the full run (smoke runs on
  two tasks were discarded). It fixes the unit, the version-selection rule, the vulnerable rule, the
  primary endpoint (vulnerable-selection rate over well-posed tasks, Fisher two-sided p < 0.05) and
  the robustness checks. The first full run measured 6.1.0; this directory publishes the 6.2.5 and
  6.2.6 runs, scored by the same rule.
- **Tasks.** 49 tasks (13 npm, 12 PyPI, 12 crates.io, 12 Go; 24 add, 11 upgrade, 14 pin), each a small
  project with a manifest and, where the ecosystem has one, a lockfile. `gen-tasks.mjs` generates
  them; `tasks.json` holds every prompt, target and constraint. A task is well-posed when a release
  without advisories exists inside its constraint (46 of 49, `truth/task-wellposed.json`).
- **Arms.** `control`: no MCP server (`--strict-mcp-config`, no `--mcp-config`). `treatment`: only this
  server, with a fresh data directory and database per run and `FOURDA_PROJECT_DIR` set to the run's
  work directory. Same model, prompt and tools otherwise.
- **Isolation, both arms.** One fresh copy of the task and one fresh headless session per run
  (`claude -p`, `--no-session-persistence`), `CLAUDE_CODE_DISABLE_CLAUDE_MDS=1`,
  `CLAUDE_CODE_DISABLE_AUTO_MEMORY=1`, `--setting-sources project,local`, `--permission-mode
  acceptEdits` (writes outside the work directory are denied: `-p` cannot prompt), `--max-turns 25`,
  a 10-minute timeout. Shell, web fetch and search, subagents and other host tools are disallowed in
  **both** arms by design: the question is what the agent writes from its own knowledge versus
  with the server, not whether it can browse.
- **Scoring reads files, never prose.** The selected version comes from the resulting lockfile entry
  when it satisfies the manifest, else from the manifest spec (the smallest version it admits; the
  largest for unbounded specs). Vulnerable: at least one OSV advisory for that exact version in the
  pinned truth, not withdrawn and not an informational notice. For open "add a capability" tasks,
  every added dependency counts.
- **Truth comes from the registries and OSV.dev directly**, never from the server under test:
  registry version lists plus an OSV query per version, pinned in `truth/` (`truth/SHA256SUMS`).

## Files

| File | What it is |
|---|---|
| `PREREGISTRATION.txt` | the analysis plan, 2026-10-11 |
| `ADJUDICATION-626.txt` | the 6.2.6 runs and every scored miss, adjudicated against live OSV |
| `gen-tasks.mjs` | writes `tasks/<id>/` and `tasks.json` (deterministic) |
| `tasks.json` | the 49 task definitions |
| `lib-truth.mjs`, `build-truth.mjs` | pin registry versions and OSV advisories into `truth/` |
| `lib-versions.mjs`, `pyspec.py` | what a written spec selects, per ecosystem (PEP 440 through `packaging`) |
| `truth/` | the pinned truth, 2026-10-24 (89 files, about 5 MB, 240 kB compressed) |
| `run-g7.mjs` | the runner |
| `score-g7.mjs` | the scorer: `results/scores-<label>.json`, `results/summary-<label>.json` |
| `results/` | the published 6.2.5 and 6.2.6 scores and summaries |

`tasks/` is generated, not committed: its manifests pin vulnerable versions on purpose, and committed
they would raise dependency alerts against this repository. Run transcripts and work directories
(`runs/`) are not published: they hold local paths. The published scores were re-derived from the
retained run records with this `score-g7.mjs` before publishing, and match byte for byte.

## Reproduce

Needs Node 22+, Python 3 with `packaging` (`pip install packaging`; set `G7_PYTHON` if the interpreter
is not `python`), and Claude Code (`claude` on PATH, or `G7_CLAUDE=<path to the executable>`).

```bash
cd bench/g7
npm ci --ignore-scripts
node gen-tasks.mjs                      # tasks/ + tasks.json

# The server under test, installed from its packed tarball (from the repository root):
#   pnpm install --frozen-lockfile && pnpm run build && npm pack
#   then, in an empty directory: npm install <path>/4da-mcp-server-<version>.tgz
export G7_LOCAL_SERVER=<that directory>/node_modules/@4da/mcp-server/dist/index.js

node run-g7.mjs control,treatment-local 3 3    # 294 runs, about 30 minutes at concurrency 3
node score-g7.mjs mine treatment-local         # results/summary-mine.json, report on stdout
```

To test a published release instead: `G7_SERVER_SPEC=@4da/mcp-server@<version> node run-g7.mjs
control,treatment 3 3`, then `node score-g7.mjs mine treatment`. `node run-g7.mjs <arms> <trials> 3
'<regex>'` runs a subset of tasks; runs are resumable (a run with a `rec.json` is skipped).

To re-pin the truth to today's registries and OSV: delete `truth/` and run `node build-truth.mjs`.
With the committed truth, a release published after 2026-10-24 scores as "nonexistent", and an
advisory published since is not counted (see Limitations).

**Cost and time** (model `claude-sonnet-5-5`, 147 runs per arm): control $2.79 in all, 18.9 s per run
on average; treatment $4.53 (6.2.5) and $4.84 (6.2.6), 23.2 s and 19.1 s per run. The 6.2.6
treatment arm took 15.8 minutes at concurrency 3.

## Limitations

- **One model.** Every run used `claude-sonnet-5-5`. Other models and agents may pick differently
  without the server, and may use it differently.
- **No shell and no web, in both arms, by design.** An agent that can run `npm audit` or browse
  OSV could do better without the server; that is a different comparison (the runner has an
  exploratory `control-web` arm, not part of G7).
- **The truth goes stale.** It is a snapshot from 2026-10-24: later releases score as nonexistent and
  later advisories are not counted, which can move results in either direction. Adjudicate misses
  against live OSV, as `ADJUDICATION-626.txt` does, or re-pin the truth.
- **The scorer judges the written version, not the explanation.** On ill-posed tasks a correct
  refusal still scores as vulnerable.
- **The tasks were written by the server's authors.** They cover common packages across four
  ecosystems; they are not a random sample of real-world dependency changes.
