# Dependency-engine conformance

This server's dependency engine (lockfile discovery, the readers, advisory matching) is
scored against the conformance corpus of the 4DA desktop app:
[`src-tauri/tests/conformance`](https://github.com/4DA-Systems/4DA/tree/main/src-tauri/tests/conformance)
in 4DA-Systems/4DA. The corpus holds vendored public lockfiles, the OSV records that name
their packages (pinned as api.osv.dev served them), and the adjudicated truth per case.
Its README defines the format, the key normalisation and the scoring. The desktop app's
Rust engine is scored against the same truth, so the two engines are held to one answer.

The corpus is **fetched, never vendored**. `../conformance.lock` pins the 4DA commit.

```bash
node scripts/fetch-conformance.mjs                      # into conformance/corpus/ (gitignored)
pnpm exec vitest run src/__tests__/conformance.test.ts  # report + ratchet, offline, a few seconds
FOURDA_CONFORMANCE_DUMP=<dir> pnpm exec vitest run src/__tests__/conformance.test.ts
                                                         # also writes each case's engine output and diff.tsv
```

Without a fetched corpus the test skips and says how to fetch it; with
`FOURDA_REQUIRE_CONFORMANCE=1` (CI) a missing corpus fails.

How a case runs: the project-tree walk over the case directory, the readers through
`LiveIntelligence`, and a scan whose advisory source is `PinnedRecordsSource`
(`src/live/pinned-advisories.ts`): only the pinned records, membership decided locally by
`osv-ranges.ts`, no network. Scoring mirrors the reference harness,
`src-tauri/src/osv/conformance_tests.rs`, line for line (`src/__tests__/helpers/conformance.ts`).

## Files here

- `thresholds.json`: this engine's ratchet per OSV ecosystem (findings and inventory
  precision/recall, max silent drops), truncated to 4 decimals. It never falls; raise it in
  the PR that improves it (the run prints `ratchet can rise`). `unsupported_by_engine` names
  ecosystems this engine has no reader for (RubyGems, Packagist): they are printed on every
  run and not asserted.
- `engine-disagreements.json`: every difference from the truth in a ratcheted ecosystem,
  grouped by verdict with a reason. A difference listed nowhere fails the test.

## CI

- `conformance (pinned)`: every PR and push, ubuntu, corpus cached by the pinned commit.
- `conformance (4DA main)`: nightly, against 4DA's current main; a failure opens the
  nightly issue.

## When it fails

1. Read the printed diff lines: `case  inventory|finding  MISSED|EXTRA  ecosystem|dir|name|version[|advisory]`.
2. A reader defect here: fix it with a unit test (see `src/__tests__/conformance-drift.test.ts`).
3. A truth error: never edit the corpus or lower a threshold. Fix it in 4DA through
   `adjudications.json` `truth_overrides`, then bump `conformance.lock`.
4. A disagreement that is right for this engine and stays: list it in
   `engine-disagreements.json` with its verdict and reason.
5. Moving the pin: set `conformance.lock` to the new 4DA commit, re-fetch, run, and adjust
   in the same PR.
