# Mutation check

Does the test suite notice when the code it guards is wrong? `mutations.mjs` lists mutants: one exact text replacement each, in a named file, with the wrong behaviour it introduces (`intent`) and the test files most likely to kill it (`tests`).

- `node scripts/mutation/run.mjs --check`: every mutant still applies (its text is found exactly once, its tests exist); changes nothing.
- `node scripts/mutation/run.mjs [--only R01,S05] [--out DIR]`: baseline first (build + full suite must pass on pristine source), then each mutant in turn: build, its `tests`, then the full suite if those pass. The file is restored after each one.
- Exit 0: every mutant killed or listed `equivalent` (with its reason). Exit 1: a mutant survived or does not compile; `survivors.txt` and `summary.md` in `--out` name them. Exit 2: the list or the baseline is broken (nothing was judged).
- A survivor is a test gap: add a test that fails with the mutant, then add that file to its `tests`. When code a mutant targets changes, update its `find` and `replace` in the same change.
- Fetch the conformance corpus first (`node scripts/fetch-conformance.mjs`) and set `FOURDA_REQUIRE_CONFORMANCE=1`, as CI does: some mutants only the corpus suites kill.
- CI: `.github/workflows/mutation.yml`, weekly and on demand (`workflow_dispatch`, optional `only`); a scheduled failure opens or updates an issue. The full list takes about an hour; run a few locally with `--only`.
