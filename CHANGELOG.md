# Changelog

## 6.2.5 — unreleased

### An incomplete scan is never a clean one (audit A1/B-1/B-2, critical)

6.2.4 turned an OSV.dev outage, a 503, a timeout or its own rate limit into a
clean report. Reproduced 2026-10-12 with an empty cache: the 4DA app's `src-tauri`
(10,568 dependencies) came back `total_vulnerable_packages: 0`,
`dependency_health` scored it 75/100 and `upgrade_planner` said
`vulnerabilityDataAvailable: true`; the only trace was `_meta.offline`.

- **Large trees are answered in full.** querybatch requests (1,000
  dependencies each) go out as the query budget allows, waiting for it to
  refill (60 s at most), instead of failing the whole scan past 10 batches.
  The budget is 60 batches a minute. A failed batch is retried once. The same
  tree, cold, now reports 11,203 dependencies and 431 vulnerable packages
  (with `include_test_fixtures`; see below).
- **What OSV did not answer is counted, and leads the answer.** Dependencies
  with no answer (and no earlier cached one) are `unchecked`, never clean.
  `vulnerability_scan` then starts with `summary: "NOT CHECKED: OSV.dev
  unreachable (...) — N of M dependencies have no vulnerability answer"`,
  `coverage.unchecked_dependencies` counts them, and `total_vulnerable_packages`,
  `by_severity` and `clean_dependencies` are null (findings in the checked part
  are under `found_in_checked_dependencies`).
- `dependency_health` withholds `healthScore` and `vulnerableCount` (null) and
  adds `vulnerabilityCoverage`; `upgrade_planner` sets
  `vulnerabilityDataAvailable: false` and adds `vulnerabilityCoverage`. Both
  summaries start with "NOT CHECKED". The tool descriptions and the server
  instructions say an incomplete result is not a clean one.

### dependency_health says what each number counts

navcal read "Health: 19/100. 18 dependencies scanned, 26 vulnerable" (6.2.4
too): 18 was the direct runtime dependencies checked against their registry
(25 devDependencies left out), 26 the vulnerable packages among the 633
installed. The summary now names both populations ("18 direct dependencies
checked against their registries (25 devDependencies left out ...); 26
vulnerable packages in the full tree of 633 installed (1 direct, 25
transitive); 14 outdated (direct)"), the answer adds `treeDeps` and
`vulnerableDirectCount`, and the score states its penalties ("100 minus 55 for
vulnerabilities, 26 for outdated, 0 for deprecated") with `healthScoreBasis`.
`ecosystem_filter` now narrows the vulnerability counts too, and a project with
no direct dependencies reports 0, not 1.

### Coverage stated, not implied

- **Ruby and PHP are read** (audit A2): `Gemfile.lock` (RubyGems; git and path
  gems are local code and are skipped, as the desktop app does) and
  `composer.lock` (Packagist; `packages-dev` marked dev). Both are ratcheted at
  1.0 in the conformance corpus (RubyGems 143/143 findings, Packagist 44/44).
- **Ecosystems not read are listed.** Maven (`pom.xml`), Gradle, .NET
  (`*.csproj`, `packages.lock.json`, ...), Pub, Hex, SwiftPM, CocoaPods and a
  `Gemfile` / `composer.json` with no lockfile are reported in
  `coverage.not_covered`, in mixed repositories too. A project made only of
  them is told "NOT COVERED: ... Nothing was checked" instead of "No manifest
  files found ... Run this tool from your project root directory".
- **Test fixtures are not the project** (audit A3). Lockfiles under `tests/`,
  `test/`, `fixtures/`, `testdata/`, `__fixtures__/`, `conformance/` and the like
  are left out by default and counted in `coverage.not_scanned`;
  `include_test_fixtures: true` scans them. The 4DA app's `src-tauri` is 905
  dependencies of its own, not 10,568.
- **An unreadable lockfile is named** (audit B-9): merge-conflict markers,
  invalid JSON or a damaged file is listed in `coverage.unreadable_lockfiles`
  with the reason, instead of falling through to "no lockfile".

### Fix advice

- **No deprecated or yanked release as a fix target** (audit B-8): lodash
  4.17.15 is sent to 4.18.1, not the deprecated 4.18.0 ("Bad release"), and
  the note says why. See the readiness section below for what counts as
  withdrawn.
- **`last_affected`-only advisories** get the first published release above the
  installed version that no known advisory affects as a candidate, labelled as
  such, instead of "no fix" (audit A6), in `vulnerability_scan` and
  `upgrade_planner`.
- **A parent that will not move** (deprecated, or already at its latest
  release) turns "waiting on upstream" into `override_or_replace`, with the
  syntax for npm `overrides`, pnpm `pnpm.overrides`, yarn `resolutions`, or
  Cargo `[patch]` (audit A4).
- npm `-security` placeholder packages (`fs@0.0.1-security`) are no longer
  reported as malware (audit A5), as in the desktop app, under any advisory id
  (see the readiness section below).
- `vulnerability_scan` includes direct devDependencies by default, labelled
  `is_dev` and graded one level down, as the desktop app does (audit A8);
  `include_dev: false` leaves out every dev-only copy (see the final audit
  section below).
- `dependency_check` counts a vulnerability once across its alias records
  (GHSA + RUSTSEC), keeping the most severe grade. tokio 1.18.0's "6
  advisories" are 3, all moderate or low, so its `review` verdict was right
  (audit A9).

### Found in the pre-release readiness audit (2026-10-16 to 10-18)

6.2.5 was held back after an adversarial audit of the release candidate found
5 high, 7 medium and 8 low findings, and each fix below was reviewed again
before it was accepted. Every rule shared with the desktop app is pinned by
the shared rule vectors, which both engines run.

**Fix targets and versions**

- **Packagist and RubyGems are ordered as Composer and Gem::Version order
  them** (H2). Two-part OSV bounds such as `6.4` are padded, so targets stay on
  the installed line: symfony/process 5.1.0 goes to 5.4.51 and rack 2.0.6 to
  2.2.23, not 8.0.5 and 3.2.6. A two-part `fixed` bound no longer makes a
  vulnerable version look clean, and a Packagist lower bound with no stability
  suffix admits that release's prereleases (`>=8.0` admits 8.0.0-RC1, as
  Composer reads it). An advisory's enumerated `versions` list is honoured too.
  A RubyGems beta is never offered as a stable target.
- **A release its registry withdrew is never the target** (FX-H5, with the
  app): crates.io and PyPI yanked releases, and npm deprecated releases when a
  later, non-deprecated stable release exists on the same caret line. A
  whole-major npm notice is not a withdrawal: glob 10.4.5 goes to 10.5.0, not
  12.0.0. When every way out is withdrawn there is no target, `withheld` names
  the withdrawn releases, and the answer says "No installable fix", never "No
  fix published". The same rule applies to each advisory's own fix, in
  vulnerability_scan, upgrade_planner, dependency_check and
  what_should_i_know. If the registry cannot be read, the earlier answer stands
  and the answer says the withdrawal check did not run.
- **A deprecated or yanked release is excluded even when OSV's per-package
  query fails** (H5): lodash 4.17.20 goes to 4.18.1, labelled
  `installed_advisories_only`.

**upgrade_planner**

- **A transitive pinned by a parent that has a newer release is
  `upgrade_parent`, not "waiting on upstream"** (H1). `parentUpgrades` names
  the smallest parent release whose own requirement admits a clean version,
  and every declared dependency it arrives through (`levers`). That release is
  clear of the parent's own advisories (one with no published fix is named
  instead: "remains affected by ... (no fix published)"), and a dependency gets
  the same release on every row: NodeGoat's express goes to 4.22.3, on its own row and as the
  lever for path-to-regexp. When the parent's new requirement still admits the
  installed copy, the step names the refresh to run after the install, because
  npm keeps the copy (`refreshCommands`). A parent the lockfile cannot tie to a
  declared dependency gets no command (`leverUnknown`) and is
  `upgrade_parent_unverified`, not counted as fixed; a move across a major is
  flagged `breaking`.
- **A direct bump is raised to the release that also clears the vulnerable
  transitives it pins**, never onto a release its own advisories affect, and
  across a major only when a row's only fix is across it (then `breaking`):
  express 4.20.0 goes to 4.22.3.
- **Commands keep how a dependency is declared** (E8, with the app): an exact
  npm pin gets `--save-exact`, and `^`/`~` are kept and quoted (`npm install
  "x@~1.2.6"`, also pnpm, yarn 1 and yarn berry; Cargo `cargo add` with
  `--dev`/`--build`/`--target`/`--rename`; Go `go get`). No command is named
  for a spec it cannot carry (`>=`, `||`, tags, git, `workspace:`), for a yarn
  workspace member, or when the declaration does not admit the installed copy.
  Commands run in the directory that declares the dependency.
- **Dev-only vulnerable packages are planned by default**, labelled `isDev`,
  and rows rank on the scan's scope-adjusted severity with runtime rows first
  (H4). `include_dev: false` says what it left out.
- Advisories are counted once per alias group (M1). An advisory with only
  `last_affected` below the target is reported as resolved by it (M2).
- **API:** a new `upgrade_parent` action; `parentUpgrades[]` with `levers[]`
  (each with `commands`, `instructions` and `breaking`), `breaking`, `peer`,
  `moreLevers`, `leverUnknown` and `refreshCommands`; direct rows can carry
  `upgradeCommands` / `upgradeInstructions`.

**Severity**

- **One grade per advisory in every tool** (M6). An alias group no record of
  which grades it takes the highest grade among all of its GHSA aliases: GO-2024-3333
  is high, through GHSA-w32m-9786-jp63, in dependency_check,
  vulnerability_scan, dependency_health and upgrade_planner alike.
  `severity_from` names the alias the grade came from, and an alias that could
  not be read within the 5 s budget or the cap is listed, never guessed. The
  lookup uses the injected advisory source and makes no network call offline.

**Coverage and dependency_health**

- **Started inside a Maven, Gradle or fixtures-only project**, every tool says
  NOT COVERED or "only test-fixture lockfiles" instead of "no manifest found"
  (H3).
- dependency_health counts advisories, not OSV records, so its counts match
  vulnerability_scan's (pygoat 187, not 348). It counts the same population in
  its registry and vulnerable figures and says whether dev-only copies are
  included (L2).
- **An unreadable lockfile withholds the health score**, with
  `withheldReason` (M5). A refused requirements include, or a yarn.lock or
  requirements entry over the length cap, is named under `refused_includes` /
  `partial_lockfiles`. The score then covers the checked part only and says so
  (`scoreCoverage`, "at least" counts) (M4, L5).
- `--hash` options no longer push a requirements entry past the length cap.
  Hashed `pip-compile` pins with many wheels were dropped silently before.
- A `v`-prefixed version in an installed package.json is not install drift
  (L1).

**dependency_check and the rest**

- **An unmaintained-package notice never moves the verdict** (L3). It is
  listed in `maintenance_notices`, no longer counted in `affecting_to`, and no
  longer turns `proceed` into `review`.
- **npm security holding placeholders** (`0.0.<n>-security`) are not installed
  code under ANY advisory id (L4). crossenv 0.0.2-security under
  GHSA-c2m4-w5hm-vqjw read as malware when only MAL- ids were held. A
  publisher's own `1.0.0-security` prerelease stays affected.
- upgrade_impact reads every Cargo workspace member's features (M3).
- Fix paths read a parent's registry requirements without peerDependencies
  (L7).
- In standalone mode, `resources/list` lists only the tools it serves, and the
  startup line no longer claims working tools when the database is refused
  (L6).

### Found in the final release audit (2026-10-18)

A last audit of the release candidate found 1 high, 5 medium and 7 low
findings; the 4DA app's review of the same rules added three more. Each fix
was checked live on NodeGoat, pygoat, xsv, navcal and victauri, and the rules
shared with the app are pinned by the shared vectors.

- **No tool offers a release an advisory affects** (H1). upgrade_planner sent
  crossenv 0.0.2-security, npm's placeholder for removed malware, to 1.0.1, the
  malware itself (GHSA-c2m4-w5hm-vqjw, last_affected 1.0.1); cross-env.js,
  mongose, babelcli, d3.js, jquery.js, ffmepg, nodesass and nodefabric the
  same. Every release a tool offers (the planner's newest-release target,
  dependency_health's `latestStableVersion`, what_should_i_know's `latest`) now
  passes the advisory check dependency_check decides `proceed` by, and the
  registry's withdrawals. A placeholder whose newer releases are all malware is
  `remove_dependency` ("remove it"); otherwise the newest release that is
  neither affected nor withdrawn is offered, or `hold_current` when none is.
- **No release brings in an advisory the installed version does not have**,
  fixed or not (the 4DA lead's rule for both engines): not a fix target, a
  parent or lever release, or a newest-release offer. An advisory with no
  published fix is skipped only when the installed version already has it.
  When nothing qualifies, no release is named and the answer says "every
  fixing release brings in <id>". A parent or lever whose only admitting
  release carries such an advisory reports the outcome `introduces` (shared
  vector pr-010), not "no release admits".
  dependency_health adds `latestSafeVersion` and `latestStableNote` and
  measures `versionsBehind` to the safe release; what_should_i_know's `latest`
  adds `registry_latest` and `note`.
- **One clean-release rule everywhere, with the app** (#981). A malicious
  advisory is never skipped:
  a release it affects is never clean, never a target and never "newest", and
  an installed copy it affects names no release ("... is flagged malicious:
  remove or replace ..."). An advisory whose ranges cannot be read leaves the
  decision undecided: no release, no command, and the reason. An advisory with
  no published fix never blocks a move that fixes the rest, and the named
  release says it "remains affected by ... (no fix published)". A parent's or
  lever's newest release is the highest stable, non-withdrawn release no
  malicious advisory affects, not its `latest` tag, which decides only the
  "already its latest release" wording.
- **One malware predicate** (the 4DA lead): a MAL- id, a MAL- alias, CWE-506
  in `database_specific.cwe_ids`, or GitHub's fixed advisory title ("Malicious
  Package in ..." / "Malicious code in ..." at the start, after leading
  whitespace; ids and CWEs trimmed, any case: the app's is_malware exactly); no
  other summary wording. GitHub's GHSA-c2m4-w5hm-vqjw ("crossenv is malware") has no MAL- id
  and is malware by CWE-506; GHSA-28f8-hqmc-7ph8 ("Malicious Package in
  ember-power-timepicker") has neither, and is malware by its title. It decides the offered release, the clean-release rule, parent
  standing and the placeholder note, and an installed malicious copy is
  critical in every tool. Scan rows carry `malware`; the advisory cache key
  moved so rows cached without it are not reused.
- **One grade per advisory, in every tool** (M2). vulnerability_scan kept the
  grade of the record with the most detail; the other tools kept the most
  severe. An alias group now takes the most severe own grade of its records,
  each read by its curated label first and its CVSS band second (as the app
  does: on the conformance corpus the label follows a CVSS v4 score neither
  engine computes); a grade inherited from a GHSA alias applies only when no
  record of the group has one. CVE-2026-4277 (GHSA-pwjp-ccjc-ghwg LOW,
  PYSEC-2026-52 CVSS 9.8) is critical everywhere, and `severity_from` names the
  record or alias the grade came from. dependency_health's
  `vulnerabilitySummary` adds `unknown`, so it equals vulnerability_scan's
  `advisory_by_severity`. upgrade_planner ranks by the scan's scope-adjusted
  grade: a dev-only medium is low, an ungraded advisory medium, a MAL- record
  high. The shared severity vectors run in the TypeScript runner.
- **devDependencies are declarations** (M3). The lever walk read only
  dependencies, optionalDependencies and peerDependencies, so a dev-only
  transitive had "no declared dependency above" it; navcal's @vitest/mocker
  and tinypool now name vitest. A workspace member's own dependency
  (packages/a devDependencies minimist ^1.2.5) is declared there, and its
  command runs in the member's directory.
- **One release per dependency across all rows** (M4). NodeGoat named
  express-session 1.18.1, 1.18.2 and 1.19.0 on three rows (1.18.1 still pins a
  vulnerable on-headers); xsv crossbeam-channel 0.4.4 and 0.5.0. Each
  dependency now gets the highest release its rows NEED (each lever's release,
  and its own row's target when that row is a fix) that crosses no further
  major and that its own advisories leave clean, on every row, with one
  command; a freshness row follows that release and keeps the newest as
  `latestVersion` (express-session 1.18.2 everywhere). The requirement,
  `resolvesTo` and refresh are recomputed at that release. A release lifted
  above its own smallest one records it (`smallest`); a lever through a
  transitive parent records the parent's smallest admitting release (`floor`)
  and the one it brings in (`brings`): NodeGoat's send copy reads "express
  4.21.0 is the smallest express release that brings in a serve-static that
  admits it, and express 4.22.3, the release express's own upgrade moves to,
  also brings in serve-static 1.16.3".
- **A declared bump that drops the package from the path comes before an
  override** (M5). xsv's memoffset 0.2.1 and lock_api 0.1.3 go away with
  crossbeam-channel, which no longer depends on crossbeam-epoch or
  parking_lot: the step says "goes away" and names the command, instead of
  pointing `[patch.crates-io]` at a fork (`goesAway`).
- **`include_dev: false` means one thing** (M6): every dev-only copy (every
  path to it is a dev one) is left out, in vulnerability_scan,
  dependency_health and upgrade_planner, and each states the same population
  ("N dev-only copies left out"; the scan's `dev_scope`). NodeGoat: 34
  vulnerable packages in all three, where health said 82 and the planner
  dropped 90 copies.
- Smaller fixes: with OSV's per-package query and the registry both down, the
  target says the withdrawal check did not run (7a); a lifted parent release
  whose requirement no longer admits the installed copy names no refresh, and
  none is named while another parent keeps the copy below the target (7b); a
  parent upgrade whose levers name no release is `upgrade_parent_unverified`,
  not "fixed by upgrading the parent" (7c); "admits" is said only of a
  requirement that admits the target (7d); Go versions keep their `v` in
  every target field (7e); a target with a whole-line npm deprecation notice
  (glob 10.5.0) stays the target and says it is deprecated, as
  dependency_check's `review` does (7f); a pin in a file included with `-r` is
  declared, and its edit names that file (7g).
- Parent and lever candidates follow the fix-target withdrawal rule (8a), and a
  parent stands as the app's does: deprecated (its latest release is), then
  already its latest release (the `latest` tag), then the walk. A vulnerable
  row with no fix names no release.
- **A declaration that already admits the fix is refreshed, not bumped** (with
  the app). navcal's sharp, next and vite rows named `npm install "pkg@^x"` for
  a `^` range that already admitted the target. The step is now the tool's
  in-range refresh, each run live with the manifest left unchanged: `npm update
  <pkg>`, `pnpm update <pkg> --no-save` (plain `pnpm update` rewrote the
  range), `yarn upgrade <pkg>`, `yarn up -R <pkg>`, `cargo update -p
  <crate>@<installed> --precise <target>`. Any readable range qualifies,
  `>=` and `||` included. A row of refreshes reads "Fixable now with a lockfile
  refresh (the declared range already admits the fix)"; a refresh among other
  commands is labelled. An npm workspace member is refreshed in its own
  directory, and a workspace-inherited, git, path or registry crate is never
  refreshed this way.
- The shared rule vectors `severity` (sv-001..sv-019) and `parent_release`
  (pr-001..pr-008, with the graph lines run through the whole planner, and
  Cargo lines) run in the TypeScript runner.
- **A row's only fix across a major raises the row**, flagged `breaking`,
  with the reason "the only release of <parent> that fixes <child> is <ver>, a
  major upgrade" (the 4DA lead): xsv's crossbeam-channel row goes to 0.5.0,
  the only release whose requirement admits a clean crossbeam-utils.
- **API:** new actions `upgrade_parent_unverified`, `remove_dependency` and
  `hold_current`; `parentUpgrades[].goesAway` and `smallest`;
  `levers[].smallest`, `floor` and `brings`; `upgradeCommands[].refresh` and
  `levers[].commands[].refresh`; local lockfile edges carry `dir` and
  `section`.

### Security: the working directory is never trusted (audit B-3/B-4/B-5/B-11)

- A `data/settings.json` or `data/4da.db` in (or beside) the directory the
  server starts in is no longer read. A cloned repository could use them to
  send stored memory and decisions to a host of its choosing, or to plant
  "decisions". Settings come from `FOURDA_SETTINGS_PATH`, the `settings.json`
  beside `FOURDA_DB_PATH`, or the desktop app's data directory; the database
  from `FOURDA_DB_PATH`, the desktop app's data directory, or the server's own.
- A RELATIVE `FOURDA_DB_PATH` that names no file is refused with a clear error
  instead of silently creating a database inside whatever directory the server
  started in (`./data/4da.db`). An existing file still opens through a relative
  path (4DA's own `.mcp.json` keeps working). An ABSOLUTE path that names no
  file is created as a standalone database when its directory exists, as
  before, and now says so: one stderr line and `_meta.database_note` in the
  first tool answer; its directory missing is refused. The server used to pass
  `FOURDA_DB_PATH` to the database as an explicit path, which skipped these
  rules.
- Requirements `-r` / `-c` includes stay inside the project: absolute, UNC,
  drive-letter, or outside (also through a symlink) targets are not read.

### Robustness

- Hostile input no longer blocks the server (audit B-10): changelog headings and
  yarn.lock version and dependency lines are parsed in linear time, and lines
  over 4 KB are skipped (requirements files too). A crafted CHANGELOG or lockfile
  line took 5–20 s or more.
- `+build` metadata is not a prerelease (audit B-12): toml_edit's latest stable
  is 0.25.17, not 0.23.9. PyPI `rc` / `a` / `b` / `.dev` versions now count as
  prereleases in the latest-stable pick.

### upgrade_impact (audit B-6/B-7)

- A breaking entry that names a Cargo feature your manifest enables (reqwest
  0.13's `rustls-tls` / `macos-system-configuration`) counts as touching your
  code; the features are listed in `your_code.cargo_features`.
- A GitHub PR line ("... by @user in <url>") is no longer a second change, and
  replacement syntax after "use" / "instead" / ";" is no longer read as old
  syntax (thiserror 2 flagged every `{name}` format string; `r#` raw
  identifiers no longer match).
- When the changelog is missing or partial, the answer says how to turn on the
  opt-in GitHub fallback (`FOURDA_GITHUB_CHANGELOG=true`).

### Protocol and docs (audit B-13 to B-19)

- An unknown tool or prompt name is a JSON-RPC -32602 error, and an unknown
  resource is resource-not-found, as the MCP spec says. `4da://schema/__proto__`
  (and other names inherited from Object) no longer reach Object internals.
  `4da://skills`, which never existed, is no longer advertised.
- `get_context` marks dependency names read from repository lockfiles as
  untrusted data.
- README: the network-host list is complete (api.npmjs.org, index.crates.io,
  hn.algolia.com and the opt-in hosts), and HTTP mode is documented as
  single-tenant.
- The conformance fetch works with Windows long paths, and a missing corpus
  prints a visible warning (the suites used to skip silently).
## 6.2.4 — 2026-10-12

### Fix paths held to the 4DA rule vectors

The fix-path rules (version order, OSV range evaluation, the fix target, the
refresh-or-parent verdict, the refresh command, `range_check`) now run in CI
against the shared rule vectors of the 4DA desktop app, the same 333 vectors
its Rust engine runs (see `conformance/README.md`). All pass. The first run
found these defects:

- **pnpm workspaces: the refresh command missed members.** At a pnpm workspace
  root, `pnpm update <pkg>` touches only the root project, so a member's
  vulnerable transitive copy stayed (measured with pnpm 10.34.6). The command
  is now `pnpm update -r <pkg> --depth Infinity` there, and
  `pnpm update <pkg> --depth Infinity` elsewhere (vectors fc-005..fc-008).
- **A blocking parent was not named when another parent's requirement could
  not be read.** `upgrade_planner` gave up on the whole copy and kept a
  generic "waiting on upstream". A requirement that excludes the target now
  decides on its own, and the reason names it (rv-048).
- **Unread requirements fall back to semver, and say so.** When not every
  parent's requirement can be read (the registry did not answer) and none read
  excludes the target, the verdict comes from semver compatibility: a target
  in the installed version's caret range is a `lockfile_refresh` with
  `refreshInferred: true` and a reason that says it was inferred; any other
  target stays `waiting_on_upstream` (AD-055 ¶1; rv-002..rv-032 even ids,
  rv-049, rv-050).
- **npm aliases were unreadable requirements.** `"npm:string-width@^4.2.0"`,
  how package-lock records cliui's `string-width-cjs`, is now read as `^4.2.0`
  on string-width (rv-047).
- **PEP 440 local labels did not order.** `1.0`, `1.0+abc.5`, `1.0+abc.7` and
  `1.0+5` compared equal; they now order as PEP 440 says (vo-013..vo-015), so a
  `last_affected` bound equal to a local-labelled install is read correctly.
- Yarn 1 and bun have no command that moves one transitive copy in place, so
  none is named; the manual steps (delete the lockfile entries, reinstall) are
  unchanged.

## 6.2.3 — 2026-10-11

### Yarn 1 refresh instruction covers alias entries

The yarn 1 refresh step said "delete the `<name>@` entries from yarn.lock". A
yarn 1 block is keyed by every spec that resolved to it, and an alias block's
first key names the alias (`"string-width-cjs@npm:string-width@^4.2.0"`), so
following the step left those blocks and kept the vulnerable version. It now
names both forms: keys `"<name>@…"` and alias keys `"…@npm:<name>@…"`.

### Fix-path parents name the real package

The parent reader behind the fix-path rule ("a lockfile refresh is enough"
vs "the parent must move") parsed lockfiles with its own code and still had
the two naming defects 6.2.2 fixed in the package readers. It now names
packages with the readers' helpers.

- **yarn (v1 and berry): npm aliases.** A parent installed under an alias was
  reported by the alias: on hono's benchmarks/routers lockfile, string-width
  4.2.3 and wrap-ansi 7.0.0 were named `string-width-cjs` and `wrap-ansi-cjs`.
  An aliased dependency edge (`string-width-cjs: "npm:string-width@^4.2.0"`)
  was never matched, so @isaacs/cliui was missing from string-width 4.2.3's
  parents, and its range is now the real package's `^4.2.0`.
- **pnpm 5: entries keyed by a tarball URL.** Such an entry was dropped as a
  parent and as a dependency: trpc's tarball-keyed @prisma/client 4.7.1 was
  missing from prisma 4.7.1's parents, and the four workspace projects that
  depend on it were missing from @prisma/client's. A dependency value that
  points at another entry (that tarball key, or a pnpm alias's
  `/real/1.2.3`) is now an edge to the package it installs.

## 6.2.2 — 2026-10-11

### Lockfile readers agree with the 4DA conformance corpus

The dependency engine is now scored in CI against the conformance corpus of
the 4DA desktop app (35 public repositories and synthetic cases, pinned OSV
records, adjudicated truth; see `conformance/README.md`), the same truth the
app's own engine is held to. The first run found five reader defects, all
fixed. On the corpus, findings and inventory precision and recall are now
1.0 in npm, crates.io, PyPI and Go, with no silent drops.

- **Go modules before go 1.17 report what is built.** go.sum records the
  go.mod hash of every module version the graph walk visits, but the source
  only of modules the build compiles. A module with only a `/go.mod` line at
  its selected version was reported as installed: 728 never-built modules on
  hugo, node_exporter and traefik, with 182 advisory findings that did not apply. A
  module now counts when go.sum hashes its source at the version minimal
  version selection picks, and `replace` applies to these modules as it does
  to go.mod's own requirements (including `old v1.2.3 => new v1.3.0`).
- **Versions an advisory lists match by value, not spelling.** OSV lists
  certifi `2020.12.05` (from the git tag) and pip installs `2020.12.5`, the
  same PEP 440 version. The local range check (fix targets, `range_check`,
  `dependency_check`) did not see it as affected by PYSEC-2024-230.
- **uv and poetry: a git, URL or local source is not a PyPI release.**
  pydantic's uv.lock pins pydantic-extra-types 2.10.0 from git `main`; it was
  scanned as the PyPI release of that number. poetry `[package.source]` types
  `git`, `url`, `file` and `directory` are skipped too; `legacy` (a private
  index) still counts.
- **yarn: an npm alias is scanned as the package it installs.**
  `"string-width-cjs@npm:string-width@^4.2.0"` was read as a package named
  `string-width-cjs`, which OSV does not know, so string-width 4.2.3 was never
  checked. berry's `resolution:` and v1's alias spec now name the package.
- **pnpm 5: entries keyed by a tarball URL are read.** pnpm writes `name:`
  and `version:` fields under such a key; trpc's lockfile installs
  @prisma/client 4.7.1 four times that way and none was read. A tarball that
  is not a registry artifact (codeload, a git archive) is still skipped.

## 6.2.1 — 2026-10-11

### Feed tools leave out sources you turned off in the 4DA app

Since app schema 126, social and editorial sources (Hacker News, Reddit, RSS
and the rest) are opt-in "interests", off until turned on in Settings →
Sources, and every app reader skips their items. The server still returned
them. `get_relevant_content`, `get_actionable_signals`, `knowledge_gaps` and
`what_should_i_know` now apply the app's own rule
(`source_type NOT IN (SELECT source_type FROM sources WHERE enabled = 0)`), and
say so in a `sources_note` when any source is off. A source with no `sources`
row counts as on, as in the app; a database without `sources.enabled` is read
unfiltered, as before. `developer_dna` is unchanged: like the app's own, it
reports reading history. The vendored app-schema contract moves to schema 127.

## 6.2.0 — 2026-10-11

### `dependency_check`: the release-age hold no longer leaves only vulnerable choices

The 3-day hold on new releases is waived for a clean version when every safe
release on its line is inside the hold too and every older release on that line
has a known advisory: holding back would leave only vulnerable releases to
write. The `release_age` signal then says `proceed` with
`hold_waived: "no_settled_safe_release"`, names the line and the count of
vulnerable older releases, and asks the agent to tell the user the version's
age. A package whose only releases are new keeps the hold (that is the
supply-chain case it exists for). Found by G7 (golang.org/x/net on 2026-10-11:
the only safe releases were 1.8 and 2.8 days old, 59 of 61 v0 releases were
vulnerable, and every run left go.mod unchanged).

### `dependency_check`: PyPI and Go, safe versions in a constraint, and instructions that make agents call it

The G7 agent evaluation (49 dependency tasks x 3 trials, 2026-10-11) found that
when an agent called a 4DA tool, 0 of 60 runs wrote a vulnerable version, and
when it did not, 41 of 78 did. The misses were runs that never called one:
PyPI and Go adds (`dependency_check` took npm and crates.io only), pin tasks
("pin ws 7.x" wrote 7.5.10 from memory; body-parser 1.20.3), and agents told
they could not browse concluding they could not check versions at all.

- **PyPI.** Releases, upload times and yanks from the PyPI JSON API (a release
  is yanked when every file is; one with no files is not installable), PEP 440
  ordering, OSV.dev for the exact version.
- **Go.** Versions from proxy.golang.org, each judged version's date from its
  `.info` (the list has none), `retract` directives in the latest go.mod
  reported like a yank, `+incompatible` releases matched (`v2.0.0` finds
  `v2.0.0+incompatible`), pseudo-versions dated and judged, and a major 2+
  without its `/vN` path named as the different module it is.
- Signals the registry cannot supply (publisher trust, install scripts, new
  transitive dependencies on PyPI and Go) say "not applicable" with the
  reason, never a made-up value or an `unknown` that blocks the verdict.
- **Constraints.** `to` may be the constraint the agent was given: `"7.x"`,
  `"^1.20"`, `"=0.17"`, `"~=3.1"`, `"3.1.*"`, `">=2,<3"`, `"v1"`. The item then
  returns `range_check` (`smallest_safe_in_range`, `newest_safe_in_range`,
  `safe_versions`, `smallest_safe_upgrade` above `from`), from every advisory
  OSV.dev lists for the package evaluated against each release the constraint
  admits, and the verdict is given for the version it picks: the smallest safe
  upgrade above `from`, else the newest safe release past the 3-day hold. An
  exact `to` an advisory affects gets the same `range_check` over its own line,
  so "is ws 7.5.10 safe?" answers avoid and names 7.5.11. Withdrawn and
  deprecated releases are never picked; maintenance notices do not make a
  release unsafe. When nothing in the constraint is safe, the advisories that
  affect all of it and the newest safe release outside it are named. A test
  holds the local range evaluation to OSV.dev's own per-version answers on
  recorded data (ws, Jinja2, golang.org/x/net).
- **Instructions and descriptions.** The server instructions now open with
  the rule "before writing any dependency version into a manifest or
  lockfile, call dependency_check on that exact version, or on the constraint
  you were given", name add / pin / upgrade / bump / downgrade / choose a
  version for all four ecosystems, and say the server reads the registries
  for the agent (so "I cannot browse" is not a reason to skip it).
  `vulnerability_scan` says it judges installed versions and points at
  `dependency_check` for a version about to be written.
- The manifest-edit hook names a `dependency_check` call for PyPI and Go edits
  too, and passes a range edit (`^7.0.0`) as a constraint instead of dropping it.
- `ecosystem` is matched case-insensitively (`pypi`, `go`).

### `upgrade_impact` reads PyPI and Go

Until 6.1 it answered for npm and crates.io only, and pointed Python and Go
upgrades at the briefing.

- **PyPI.** Versions, publish dates and yanks from the PyPI JSON API, ordered
  by PEP 440 (`2.0`, `3.0.0rc1` and `1.0.post1` are releases, not unreadable
  semver); a two-part version such as pydantic `2.0` is that release, not a
  line. The changelog is read from the target release's sdist on
  files.pythonhosted.org (`CHANGES.rst`, `HISTORY.md`, ...); a release with
  wheels only says so. Import sites are matched on the MODULE the
  distribution installs, established from the project's virtualenv metadata
  (`.venv` / `venv` / `env`: `top_level.txt`, else `RECORD`), else a table of
  well-known differences (`PyYAML` -> `yaml`, `beautifulsoup4` -> `bs4`,
  `Pillow` -> `PIL`), else the distribution name, which the answer labels an
  assumption (`your_code.import_name_source`, `import_name_note`) instead of
  guessing silently.
- **Go.** Versions from proxy.golang.org (`/@v/list`, dates from `.info`), the
  changelog from the module zip. A major version 2+ is a different module
  path: `github.com/jackc/pgx/v4` -> `v5.0.0` reads the `/v5` module, lists
  the rest of the v4 line and the v5 releases crossed, and reports
  `module_path_change` with the files that import the old path. An up-to-date
  module whose next major exists says so (`newer_major_module`). Import sites
  come from `import "module/..."` specs, never counting another major's path.
- The parser reads reStructuredText changelogs: titles underlined (or over-
  and underlined) with any RST adornment, their `Released <date>` lines, and
  non-release setext/RST titles as sub-headings. `CHANGELOG_PARSER_VERSION` is
  4 (with the classifier changes below), so changelogs cached by 6.1 are re-read.
- A zip reader (central directory only, stored and deflate entries, every
  inflate capped) for Go module zips and zip sdists.

### GitHub release notes, opt-in (`FOURDA_GITHUB_CHANGELOG`)

Off by default: the default contract is unchanged, and only the package's
own registry and OSV.dev are contacted. With `FOURDA_GITHUB_CHANGELOG=true`,
when the archive has no changelog for the range, `upgrade_impact` reads the
repository's GitHub releases (for PyPI, first a changelog file the project
links on GitHub in `project_urls`), with the same parser and classifier.

- The repository comes from registry metadata; for Go from the proxy's
  recorded VCS origin, so vanity paths (`google.golang.org/grpc`) and
  multi-module repositories (`service/s3/v1.50.0` tags) resolve. Monorepo tags
  for other packages are skipped.
- Unauthenticated REST API, or `GITHUB_TOKEN` when set. A rate limit is
  reported with its reset time and how to raise it, and is not cached.
  Results are cached under a key that carries `CHANGELOG_PARSER_VERSION`.
- With the fallback off and no usable changelog, the answer says the
  changelog is unavailable and gives `github_fallback.how_to_enable` (or says
  enabling it would not help: no GitHub repository). `_meta.sources` and
  `_meta.privacy` name GitHub whenever it was contacted.

### Breaking-entry precision gate (G3)

A held-out panel, re-measured by the test suite on every run
(`src/__tests__/g3-breaking-precision.test.ts`, fixtures in
`src/__tests__/fixtures/g3/`): 40 real upgrade pairs, 10 each from npm,
crates.io, PyPI and Go, none of them a package the 6.1 rules were built on.
Each pair records the changelog source the tool read live (registry archive or
GitHub releases), trimmed to the range and checked to parse identically. Gold
for each of the 1,618 entries shown is the majority of three blind raters
working to a written rubric (`rubric.txt`), each label backed by a verbatim
quote from the entry (Fleiss kappa 0.984; the raters were model instances,
so agreement may be higher than independent human raters would reach). The
test fails below 90% precision, overall or on the held-out half, and on any
entry without a label.

| | flagged | precision | recall |
|---|---|---|---|
| 6.1 rules, all 40 pairs | 246 | 94.7% | 55.0% |
| 6.1 rules, 20 held-out pairs | 108 | 95.4% | 67.8% |
| 6.2 rules, all 40 pairs | 326 | 97.2% (95% CI 94.8-98.5) | 74.8% |
| 6.2 rules, 20 held-out pairs | 115 | 94.8% (95% CI 89.1-97.6) | 71.7% |

The 6.2 rule changes were made from the 20 dev pairs' errors only:

- An API change is read under any heading but a fix one. Covered: a leading
  removal or rename of something API-shaped ("remove UMD build"), a changed
  default, a type made private, a move or replacement, keyword-only
  arguments, "now ... instead of", and "no longer comparable / usable /
  subclasses".
- Dropped runtimes and raised minimums break whatever the reason given
  ("drop node 10.x to upgrade dev dependencies", "Replace go 1.21 with go 1.22
  in go mod").
- "Other Changes" / "Misc" headings are neutral, not additive: pgx 5 filed its
  type removals there.
- Fix headings are their own context.
- "Previously-deprecated APIs have been removed" is a removal list.
- `*Backwards-incompatible*` is an explicit marker.
- Link targets, bare URLs and GitHub's "by @user in <PR>" are dropped before
  classifying (a `go.dev/doc/...` link read "Drop support for Go 1.21" as a
  docs change); RST ``literals`` read as code.
- No longer breaking: entries that say they still work or have no effect on
  users, private modules and `_names`, removing a deprecation notice,
  restoring an API, relaxing a bound, renaming the repository, swapping a
  dependency crate, and changes scoped to an example, docs or CI.

Per ecosystem over all 40 pairs: npm 99.0% / 84.2%, crates.io 99.0% /
81.3%, PyPI 95.7% / 72.5%, Go 92.0% / 54.1% (Go's GitHub release notes are
largely PR titles and prose). `CHANGELOG_PARSER_VERSION` is 4.

### Hook and briefing

- The manifest-edit hook names the exact `upgrade_impact` call for
  `pyproject.toml`, `requirements.txt` and `go.mod` edits (`ecosystem: "PyPI"`
  / `"Go"`); `what_should_i_know`'s next step for a PyPI or Go package is
  `upgrade_impact`.

## 6.1.0 — 2026-10-10

Fixes from an agent eval over stdio JSON-RPC against real projects (2026-10-07)
and an engine-generalization test on 19 public repositories against
osv-scanner, pip-audit and a fix-path oracle (2026-10-10): precision 1.00 over
19,115 findings and recall 19,115 of 19,116 on the lockfiles the server reads
(was 0.74 overall, with 44 langchain lockfiles dropped silently); the median
`vulnerability_scan` over the corpus went from 27 s to 8.6 s.

### Install: runs under npm 12 with no install scripts

npm 12 blocks dependency install scripts unless allowed, so a default
`npx @4da/mcp-server` or `npm install` left better-sqlite3's native module
unbuilt and every tool failed (6.0.x documented an `allow-scripts` workaround).

- The server uses Node's built-in `node:sqlite` when the runtime has it
  (Node 22.13.0 and later; npm 12 itself requires 22.22.2+). No install
  script, no native download. better-sqlite3 moved to `optionalDependencies`
  and is used only where `node:sqlite` is missing (Node 22.0-22.12), if its
  native module opens a database.
- One driver interface (`src/sqlite-driver.ts`) covers what the server uses;
  node:sqlite is adapted to match better-sqlite3: plain-object rows, BLOBs as
  Buffers, error codes (`SQLITE_BUSY`, `SQLITE_NOTADB`, ...), the 5 s busy
  timeout, savepoint-nested transactions, `readonly` / `fileMustExist`.
  Read-only connections also set `PRAGMA query_only`.
- With no usable driver at all the server no longer exits at import: it
  starts, `vulnerability_scan`, `dependency_health`, `dependency_check` and
  `upgrade_impact` run without a database (in-memory cache), and the other
  tools return the fix (upgrade Node, or allow better-sqlite3's build).
- `--doctor` reports the driver in use. `FOURDA_SQLITE_DRIVER=node|better|none`
  forces one (tests, diagnostics). node:sqlite's one-time ExperimentalWarning
  is filtered; other warnings pass.
- Tests: the suite passes on each driver (CI runs it on both, and on Node
  22.12, which has no node:sqlite); driver parity tests; the built server over
  stdio with better-sqlite3's native module missing (fails on 6.0.2: every
  tool answered "Could not locate the bindings file").

### The server never changes the desktop app's schema

The server opened the 4DA app's live `4da.db` read-write, created a
`live_cache` table in it (2,774 rows on one machine) that the app's
migrations do not own, and added `embedding` columns to app tables when an
embedding provider was set.

- Reads go through a `{ readonly: true, fileMustExist: true }` connection.
  Nothing is created or altered in the app's database: no tables, columns
  or indexes.
- The response cache moved to `cache.db` in the server's own folder
  (`%LOCALAPPDATA%\4da-mcp`, `~/Library/Application Support/4da-mcp`,
  `~/.local/share/4da-mcp`; `FOURDA_MCP_HOME` moves it).
- Decisions, agent memory and feedback still go into the app's own
  `developer_decisions`, `agent_memory`, `interactions` and `feedback`
  tables, so the app's decision UI and calibration see them. They go through a
  separate write connection (busy timeout 3 s, one short transaction per
  record). If the app's table or a column a record needs is missing (schema
  drift), the record goes to the server's `standalone.db` and the response
  says so in `_meta`; the server never creates it.
- Semantic-recall embeddings are cached in the app's tables only when they
  already have `embedding` / `embedding_model` columns; otherwise they are
  computed per call.
- Tests: the app's `sqlite_master` is identical after every tool ran, and
  only those four tables gain rows; caching alone leaves the file
  byte-for-byte unchanged.
- The `live_cache` table already inside existing app databases is left
  alone; the app owns that file and can drop it.

### `upgrade_impact`

- Reads changelog headings with inline HTML before the version (stripe:
  `## <a id="23-0-0"></a>23.0.0 - 2026-09-30`). stripe 22.3.0 -> 23.0.0 went
  from "no changelog" to 8 releases with 11 entries flagged breaking.
- Bullets nested under an entry are that entry's `details`, not entries of
  their own; a breaking detail makes the entry breaking. sqlx 0.8.6 -> 0.9.0
  went from "83 entries flagged breaking" to 24 (its Breaking section's 23
  bullets plus the MSRV statement).
- "`Cargo.lock` Removed from Tracking" is no longer read as a Removed
  category.
- The parsed-changelog cache key carries the parser version
  (`upgrade-impact:changelog:p2:...`). Parsed changelogs are cached for 7
  days, so before this a parser fix in a release stayed invisible for a week
  on every machine that had already read that package.

### Breaking version ranges

- `dependency_health` and `upgrade_planner` label a 0.x minor bump (and a
  0.0.x patch bump) "major", as `upgrade_impact` and `dependency_check`
  already did: under caret rules 0.12 -> 0.13 is breaking.
- `dependency_check` returns `review` for a breaking range (a major, a 0.x
  minor) with "breaking version range, run upgrade_impact". It returned
  `proceed` for vitest 3 -> 5, reqwest 0.12 -> 0.13 and stripe 22 -> 23.
- `what_should_i_know` counts a 0.x minor bump as a major one in
  `majors_crossed` and the delegation verdict. It compared plain major
  numbers, so "upgrade reqwest from 0.12 to 0.13" crossed 0 majors and came
  back `safe_to_delegate`; it is now `review_needed`. Without a stated
  "from", the furthest installed copy sets the distance.

### Project scope

- `upgrade_planner` and `what_should_i_know` take `project_path`. Default:
  the project the server was started in; `"*"` for every project. Called
  from 4DA, the app's plan led with navcal, verax and 4da-ledger steps; it
  is now narrowed to the project's steps, lines and sites, and says how
  many steps only touch other projects.

### `what_should_i_know`

- Expands the package families a task names ("all tauri plugins", "tauri
  and its plugins", "@tauri-apps packages", "tauri-plugin-*") to the
  project's direct dependencies in them. It matched only `tauri`.
- For a task asking for the latest release, each package gets `latest`
  (newest stable, installed vs latest major line, `on_latest_major`) and the
  summary says which are already on the latest major.

### `vulnerability_scan`

- One recommendation per installed version, each advisory counted once.
  "rsa 0.9.10 — 2 known vulnerabilities" was one advisory on two versions.

### `vulnerability_scan` latency

A cold scan (empty cache) through the server's own modules, same machine,
same network, two runs each (2026-10-10):

| Project | Dependencies | Before | After |
|---|---|---|---|
| superset | 4,516 | 71 s, 143 s | 9.4 s, 9.2 s |
| proshop-mern | 1,545 | 34 s, 34 s | 6.5 s, 6.5 s |
| nushell | 531 | 20 s, 17 s | 4.5 s, 4.4 s |

- **Cache writes in one transaction.** A scan caches one row per dependency
  and one per advisory, and each was its own autocommit: on superset the
  network part of a cold scan ended at 12 s and the remaining ~40 s were
  4,516 WAL commits. They are now one transaction per batch, and the cache
  file runs `synchronous = NORMAL` (a cache: in WAL mode a crash can lose
  only the last writes, never corrupt the file).
- **Advisory details in a pool of 24, not rounds of 8.** OSV has no batch
  endpoint for advisory records; rounds of 8 each waited for their slowest
  request. A throttled (429), failed or timed-out detail request is retried
  once instead of leaving the advisory without severity or summary.
- **querybatch chunks (1,000 dependencies each) are sent 4 at a time**
  instead of one after another; every chunk must answer or the scan fails, so
  an unanswered chunk can never read as clean.
- **No duplicate work beside the warm-up.** The startup warm-up scan and the
  first tool call's scan ran side by side and both fetched every advisory
  before either could cache it. An identical scan already running is now
  awaited (a forced refresh still runs its own), and a detail request in
  flight is shared by every scanner in the process.

### What the standalone scan reads

From the same 19-repository corpus, checked against osv-scanner and
pip-audit.

- **The project-tree walk is wider, and never silent about its bounds.**
  langchain keeps 108 lockfiles up to three levels down; the walk (depth 2,
  64 projects) read 64 and dropped 44 (4,852 advisory findings) without a
  word in any answer. Bounds are now 4 levels and 256 projects (langchain:
  about 2 s for the walk and every project scan). Past a bound the walk keeps
  counting without scanning (up to 20,000 directories), and
  `vulnerability_scan` returns a `coverage` block (concise and detailed:
  `complete: false`, a note, `lockfiles_not_scanned`; detailed also lists
  each skipped lockfile and why). `dependency_health` and `upgrade_planner`
  say "Partial scan: ..." in their summaries.
- **Python reads every source in a directory, merged:** poetry.lock, uv.lock,
  pdm.lock (new), Pipfile.lock and every requirements file:
  `*requirements*.txt` (requirements-dev.txt, _test_minimum_requirements.txt)
  and the `.txt` files of a `requirements/` folder (superset keeps its 100
  runtime pins in requirements/base.txt, which nothing read), plus a
  `.txt` that `-r`-includes a requirements file and pins packages itself
  (CTFd's development.txt). It read one source per directory, so langchain's
  libs/community poetry.lock hid the _test_minimum_requirements.txt beside
  it. `-r` includes are followed; a `-c` constraints file only gives a
  version to a name a requirements file lists (it installs nothing by
  itself). Against pip-audit on the newly read files: superset 149/152 rows
  agree (the 3 others are advisories OSV lists and pip-audit's data does not
  yet) and 262/262 of pip-audit's advisories are found; CTFd 6/6; langchain
  libs 38/38 rows, 64/65 advisories (the miss is a langchainjs CVE pip-audit
  files under the Python package).
- A `dir/*/` .gitignore rule hid the files beside the ignored
  subdirectories: `docs/api_reference/*/` made langchain's
  docs/api_reference/requirements.txt look ignored. A directory-only rule now
  ignores a file only through a directory above it.
- **Dev scope from a requirements file's name, and only from it:**
  requirements-dev.txt, requirements/testing.txt, docs-requirements.txt and
  the like mark their packages dev. A package any other file lists keeps an
  unknown scope (never "dev"), so a runtime package is never graded down by
  a dev file that includes the runtime one.
- **No lockfile: declared ranges are labelled, never scanned as installs.**
  A package.json or Cargo.toml with no lockfile used to have its range
  floors scanned as installed versions (nushell samples/wasm: 2 false
  findings). Ranged dependencies now carry `declaredRange` ("^1.2.0") in
  `dependency_health` and `upgrade_planner` and are not sent to OSV; exact
  pins still are. `vulnerability_scan` lists each such manifest under
  `coverage.unresolved_manifests` with the command that writes its lockfile.
- A Cargo.toml read without Cargo.lock took `[package]`'s own `version =
  "0.1.0"` and `edition = "2021"` for crates named "version" and "edition";
  only dependency tables are read now.

### Fix paths (`upgrade_planner`)

From a fix-path oracle on 19 public repositories (2026-10-10): each
recommended step was applied to a copy, the lockfile re-resolved and the
project re-scanned with osv-scanner.

- **A target is checked against every advisory of the package, not only the
  ones the installed version has.** openssl 0.10.38 was sent to 0.10.79,
  which GHSA-phqj-4mhp-q6mq affects (0.10.50 up to 0.10.80): the upgrade
  traded old advisories for a new one. The target is now the smallest
  published version at or above every per-advisory fix that no advisory
  affects (0.10.80). The package's advisories come from one OSV `/v1/query`
  per vulnerable package; versions from its registry (npm, crates.io sparse
  index, PyPI, Go proxy), else from the advisories' own fix events. An
  advisory no release fixes (braces GHSA-vfj7-8cjw-p6xm, last affected
  3.0.3, the newest release) does not disqualify a target and is named in
  the step. OSV `last_affected` events are read as closed ranges.
- **"Waiting on upstream" only when a parent really blocks the fix.** Every
  transitive finding used to be `waiting_on_upstream`; for minimist 1.2.5
  (npm), braces 3.0.2 (pnpm) and mio 0.8.0 (Cargo) that was wrong: each
  parent's declared requirement already admitted the fix, and a lockfile
  refresh fixed all three. The planner now reads the parents of the
  installed copy (package-lock v1-v3, yarn v1 and berry and bun.lock record
  the ranges; pnpm and Cargo.lock do not, so the parent's requirement comes
  from registry.npmjs.org or the crates.io sparse index) and returns
  `action: "lockfile_refresh"` with `refreshCommands` (`npm update
  minimist`, `pnpm update braces`, `yarn up -R`, `cargo update -p
  mio@0.8.0 --precise 0.8.11`) when every requirement admits a clean
  version. A step still waiting on upstream names the requirement that
  blocks it (`left-pad 1.0.0 requires "1.2.5"`). Summary and
  `lockfileRefreshes` count them.
- A Cargo refresh names the locked crates `--precise` cannot move by itself.
  `cargo update -p openssl@0.10.38 --precise 0.10.80` fails on nushell:
  0.10.80 pulls syn 2, which needs quote ^1.0.25, and quote 1.0.15 is held
  by rstest. The step is now `cargo update -p bytemuck@1.8.0 -p
  proc-macro2@1.0.36 -p quote@1.0.15 && cargo update -p openssl@0.10.38
  --precise 0.10.80`, found by walking the target's dependency requirements
  against the lockfile.
- Checked by applying every `lockfile_refresh` step of four plans to a copy
  and re-scanning with osv-scanner: 104 of 104 steps cleared their
  advisories (proshop-mern npm 45, taxonomy pnpm 21, chatgpt-tauri pnpm and
  Cargo 26, nushell Cargo 12).
- **`vulnerability_scan` and `what_should_i_know` run the same check** on
  the targets they recommend. "Upgrade openssl 0.10.38 → 0.10.79" is now
  "→ 0.10.80 (... 0.10.79, the highest per-advisory fix, is itself affected
  by GHSA-phqj-4mhp-q6mq)". Concise rows carry `fix_checked`; detailed
  output adds `fix_targets` per vulnerable package version, while each
  advisory row keeps its own `fixed_version`. The check is cached and
  bounded (5 s per call, most severe first); what it could not reach in time
  says `installed_advisories_only`. On nushell, cold: 33 of 39 package
  versions checked in the first call.
- The test suite is offline by construction: `fetch` throws unless a test
  stubs it (`FOURDA_TEST_NETWORK=1` lifts that), so no assertion can depend
  on live OSV or registry data.
- Each vulnerable step says how its target was checked: `fixPathChecked`
  is `all_advisories`, or `installed_advisories_only` when OSV or the
  registry did not answer (offline, or past the 25 s budget), and the
  summary counts those.

### Build

- pnpm settings (overrides, onlyBuiltDependencies) moved from package.json
  to pnpm-workspace.yaml: pnpm 11 ignores package.json's `pnpm` field, so
  the CI audit ran without the security overrides. New override
  source-map-js >= 1.2.2 (GHSA-68fv-2mgg-jv7q, high). Fixes the nightly CI
  (#9).

## 6.0.2 — 2026-10-04

### `--setup` writes the files editors actually read

Three of the four editors `--setup` reported as configured were configured in
files those editors never read, so nothing happened:

| Editor | Before | Now |
|---|---|---|
| VS Code | `~/.vscode/mcp.json` | the user profile's `mcp.json`: `%APPDATA%\Code\User\` (Windows), `~/Library/Application Support/Code/User/` (macOS), `$XDG_CONFIG_HOME/Code/User/` (Linux, default `~/.config`), key `servers`, `"type": "stdio"` |
| Windsurf | `~/.windsurf/mcp.json` | `~/.codeium/windsurf/mcp_config.json`, key `mcpServers` |
| Claude Code | `mcpServers` in the project's `.claude/settings.json` (or, outside a project, rewrote `~/.claude.json`) | prints `claude mcp add --scope user 4da -- npx @4da/mcp-server`; `~/.claude.json` is never edited |

Added: VS Code Insiders, Claude Desktop (`claude_desktop_config.json`) and
Devin Desktop / Devin CLI (`~/.config/devin/mcp_config.json`,
`%APPDATA%\devin\` on Windows), Windsurf's successor. Cursor
(`~/.cursor/mcp.json`) was already right.

- **A config file setup cannot parse is left untouched.** It used to be read
  as `{}`, so a VS Code `mcp.json` with a comment or a trailing comma (both
  legal there) was replaced by our entry alone, deleting every other server.
  Files are now parsed as JSONC and edited in place with `jsonc-parser`
  (Microsoft's, the parser VS Code uses; no dependencies of its own), which
  keeps comments, formatting, other servers and other keys. A file that does
  not parse is reported with the entry to add by hand.
- An existing `4da` entry is updated, not duplicated, and keeps its other
  fields (`env`); an identical one is left alone, so a second run writes
  nothing.
- Every modified file is backed up first (`<file>.bak`; an earlier backup is
  never overwritten) and replaced atomically (temp file, then rename).
- `--setup --dry-run` wrote anyway when run through `npx @4da/mcp-server`
  (only the `4da-mcp-setup` entry honoured the flag). It now writes nothing on
  either, and prints each file and the exact entry it would add.

### Clearer answers when the database cannot help

- A desktop-only tool (`get_relevant_content`, `get_actionable_signals`,
  `knowledge_gaps`, `record_feedback`, `developer_dna`) called without the
  desktop app's database answered `[]`, which reads as "nothing relevant". It
  now carries a `desktop_app_note` saying it needs the app.
- A database file that is damaged or not SQLite answered every call with
  SQLite's bare "file is not a database". The message now names the file and
  what to do, and never advises deleting it (`--doctor`'s integrity check used
  to say "Try deleting data/4da.db"). The handle a failed open left behind is
  closed, so on Windows the file can be moved aside while the server runs.
- The database lookup no longer checks `data/4da.db` two directories above the
  server's own files, a leftover from when the server was a folder of the app
  repository; installed, it pointed into `node_modules/@4da/`.

- Dependencies: `@modelcontextprotocol/server` ^2.2.0, `hono` ^4.13.12; dev: `@types/node` ^26.6.3, `vitest` ^5.0.3 (#2).

## 6.0.1 — 2026-10-04

### The server has its own repository

`@4da/mcp-server` now lives at
[github.com/4DA-Systems/4da-mcp-server](https://github.com/4DA-Systems/4da-mcp-server),
with its full history, instead of a folder of the 4DA desktop app's monorepo.
Issues, releases and the Claude Code plugin marketplace move with it:

```bash
claude plugin marketplace add 4DA-Systems/4da-mcp-server
claude plugin install 4da@4da
```

The package, its name in the MCP Registry (`io.github.4DA-Systems/4da-mcp-server`)
and every tool are unchanged.

- **Published with provenance.** Releases are built and published from this
  repository's `release.yml` through npm trusted publishing, so each version
  carries a SLSA provenance attestation tying it to the commit it was built from.
- **App-schema contract.** The server reads the desktop app's database, which
  is now maintained in a different repository. `pnpm run contract` checks every
  statement the server issues, and every column it probes for, against the
  schema the app's migrations produce (`contract/app-schema.sql`, generated in
  the app's CI). The app's CI runs the same check before a migration merges.
- **Removed dead code.** `explainRelevance`, `getSourceItem`,
  `recordAgentFeedback` and `getAgentFeedbackStats` had no callers since their
  tools were removed; the standalone schema no longer creates the unused
  `agent_feedback` table.
- The Claude Code plugin pins the exact server version it was released with.

## 6.0.0 — 2026-10-02

### New: `upgrade_impact`

What changes between the version you run and the one you want, for one npm
or crates.io dependency: the releases in between (publish dates, npm
deprecations, crates yanks), the changelog shipped inside the target
version's own registry archive with every entry classified breaking /
deprecation / security, the breaking entries that mention symbols your code
imports from the package (`touches_your_code`), the files that import it, and
the advisories the upgrade fixes or leaves. Only the package's registry and
OSV.dev are contacted; when the archive ships no changelog (fastembed, vite and
zod do not) the answer says so and gives the release-notes URL instead of
guessing.

Breaking changes in string literals are found too: the old syntax a breaking
entry names (axum 0.8's `/:single` -> `/{single}`) is matched in the
importing files' route and pattern strings, with file and line
(`matched_literals`).

Every entry carries the heading or parent bullet it sits under (`under`):
"`rt::{Arbiter}` re-exports." means nothing until you see it sits under
"Removed". Concise output keeps up to 20 plain changes per release under API
or neutral headings ("Changed", "Methods", "Types") and 3 under additive ones,
and says how many it left out.

How far the "breaking" flags go, measured: five corpora of real upgrades,
each rated blind by three independent raters. The last, 47 upgrades never
used to build the rules, rated by raters who saw each entry's heading
(Fleiss kappa 0.982), is the release measurement: 98.6% of entries flagged
breaking were breaking (95% CI 94.9-99.6%) and about 65% of breaking entries
were flagged. Earlier fresh corpora, before the last parser fixes, measured
73-87%, so the summary says "flagged", every answer states the measurement in
`_meta.classification`, and the agent is told to read every entry of a major
upgrade. Counts are `null` when the changelog has no entry for the releases
crossed, and labelled lower bounds when it covers only some. Changelog formats
read: keep-a-changelog and changesets headings, category headings at the
release's own level (date-fns), plain and bold label lines, releases as
bullets (indexmap), History.md label lists (express), day-first dates (knex),
RELEASE-NOTES.md (base64); layout markup (`<details>`) is skipped.

### New: `dependency_check` — a verdict before you add or bump a dependency

An agent calls it with up to 25 `{ ecosystem, package, to, from? }` items (npm
and crates.io) before it edits a manifest; `to: "latest"` checks the newest
stable release and reports which version that was (`to_requested`). Each item gets `proceed`, `wait`,
`review`, `avoid` or `unknown`, a one-line reason, and the signals behind it,
each with evidence: known OSV advisories on the target (and the ones the change
fixes), release age (under 3 days is `wait`, unless the release fixes an
advisory affecting the installed version), a drop in publish trust (trusted
publisher > provenance attestation > neither), npm install scripts the target
adds, runtime dependencies the target adds that were themselves first published
under 30 days earlier, yanked / deprecated / unpublished targets, and the
upgrade type. Against the axios 1.14.0 -> 1.14.1 compromise shape (token
publish replacing a trusted publisher, plus a dependency created the day
before) it answers `review` on both counts. A registry or OSV that cannot be
reached gives `unknown`, never `proceed`; a name missing from the public
registry says it may be private, misspelled or hallucinated.

Registry requests carry the package name only. The installed and target
versions are picked out of the full release list locally: npm's full packument
(cached on disk with its ETag and revalidated with `If-None-Match`) and the
crates.io versions API (spaced one request per second, with a descriptive
User-Agent) plus the sparse index for per-version dependencies.

### New: the `deps` prompt

The server now declares the MCP `prompts` capability. `deps` is a user-invoked
workflow: plan with `upgrade_planner`, vet each bump with `dependency_check`,
apply only `proceed` items in small batches with the project's tests after
each, report everything else with its evidence, and re-run
`vulnerability_scan` at the end.

### New: a Claude Code plugin, with a hook on dependency edits

Install with `claude plugin marketplace add 4DA-Systems/4DA --sparse
.claude-plugin mcp-4da-server` and `claude plugin install 4da@4da` (the
repository now carries the marketplace manifest the plugin needed to be
installable at all). After an Edit or MultiEdit that changes a dependency's
version in `package.json`, `Cargo.toml`, `pyproject.toml`, `requirements.txt`
or `go.mod`, the agent is told which packages moved and given the exact
`dependency_check` and `upgrade_impact` calls. A tool is called when the agent
thinks to; a hook fires on the edit itself. Plain Node, no network, silent for
every other edit, and it can never fail the edit. Verified end to end in a real
Claude Code session: the hook's context reaches the agent on the edit.

### Fixed: the vulnerability scan read lockfiles losslessly

Measured against osv-scanner on 12 projects, the matching was exact but the
lockfile reading lost findings (precision 0.74, recall 0.48 per advisory). Now
precision 1.00, recall 0.995:
- every installed copy is scanned, not one version per package name (nested
  npm copies, two versions of a crate: 4DA's own `rsa 0.9.10` was missed);
- npm/pnpm/Pipfile/poetry dev flags make a transitive's dev scope known;
- Go: full pseudo-versions and `+incompatible`, `replace` directives, Go's build
  list from `go.mod` (and `go.sum` before go 1.17);
- `requirements.txt` extras, dotted names, markers, comments and `--hash`
  options; `poetry.lock` of any vintage, `uv.lock`, Poetry and PEP 621 manifests;
- Cargo virtual workspaces, and standalone mode scans every independently
  locked project under the root, honouring `.gitignore`;
- `bun.lock` (Bun 1.2+), with dev scope from the workspaces;
- PEP 440 version order and PEP 503 names when choosing the fix version.

Before release the scan was re-run, from the packed tarball installed fresh,
on those 12 projects and on 11 more never used to build the readers (npm,
yarn v1, pnpm, bun, Cargo, Go, uv, Pipfile, Poetry): every project matches
osv-scanner or an independent oracle (OSV queried directly; Go's own
`go list -m all` build list, where the server reports modules osv-scanner
misses). The only misses are transitives of a `requirements.txt` without a
lockfile, documented below. Eight projects locked at current releases report
zero findings.

### Changed: answers only confirmed evidence can raise

- `what_should_i_know` is built from the task: the dependencies it names,
  their installed versions, version-confirmed vulnerabilities, majors crossed.
  Feed headlines no longer drive the delegation verdict (a security keyword
  in an arXiv paper or in OpenAI company news forced `human_only` for any task).
- `get_actionable_signals` no longer classifies items by keyword; it shows the
  desktop app's classifications only when its relevance judge accepted the item,
  and a headline is never above medium unless it comes from an advisory database.
- `get_relevant_content` and `knowledge_gaps` leave out judge-rejected items.
- `upgrade_planner` targets the smallest version that fixes the advisories, not
  the newest major; unmaintained-package notices are not counted as CVEs. It
  and `dependency_health` run the OSV scan themselves when none has run (they
  answered "run vulnerability_scan first", leaving the first answer of a
  session CVE-blind),
  and `package` finds a vulnerable transitive instead of calling it "not a
  dependency".
- `vulnerability_scan` takes `package`: one dependency's findings across every
  installed copy, with a `package_note` saying what the lockfiles hold for it.
  An agent asked about one transitive otherwise read the whole report.
- A scan that finishes late no longer replaces a newer one: the startup scan
  (devDependencies left out) could overwrite an agent's `include_dev` scan, and
  the planner then sent the devDependency node-fetch 2.6.0 to the ESM-only 3.3.2
  with no advisories (2 runs in 6). A plan or briefing that needs
  devDependencies covered scans at that scope instead of reading a narrower scan.
- Desktop mode finds the app's database on Linux (`$XDG_DATA_HOME/4da/data`, as
  the app writes it) and honours the app's `FOURDA_DATA_DIR`.

### Changed: the protocol surface

- Every tool now lists all its parameters in `tools/list` (most were hidden).
- Server `instructions` for hosts with tool search; argument errors come back as
  `isError` with the fix; `structuredContent` beside the text; compact JSON;
  invisible and control characters stripped from third-party text.
- `tools/list` no longer waits for the project scan (6.6 s measured).
- `agent_memory` and `decision_memory` match their published schemas (recall
  takes `query`, store takes `subject`; the old schema could not be followed).

### Breaking

- Node.js 22 or later. better-sqlite3 publishes no Node 20 binary from 12.10,
  so a Node 20 install compiled from source and failed on any machine without
  Python and a C++ toolchain (every slim container); Node 20 reached end of
  life in April 2026. Verified installs: Node 20 (with a toolchain), 22 and 24
  on Windows; Node 22 on Debian and Alpine Linux; Node 24 on Debian.
- npm 12 blocks dependency install scripts unless allowed, so better-sqlite3
  is left unbuilt by both `npx` and `npm install`. `--doctor` now opens a
  database instead of trusting the import; it had reported the bindings as
  loaded while every tool failed with "Could not locate the bindings file".
  That error now carries the fix: `npm config set
  allow-scripts=better-sqlite3 --location=user` and `npx clear-npx-cache`, or
  `npm install-scripts approve better-sqlite3` and `npm rebuild
  better-sqlite3`. Each was verified on npm 12.2.0. npm 10 and 11, which every
  current Node release ships, are not affected.
- `upgrade_impact`'s summary says "N entries flagged breaking", not "N
  breaking changes": the flags are a pre-sort, and every entry now carries its
  heading (`under`).
- `vulnerability_scan` answers in a concise form by default: `vulnerable_packages`
  has one row per vulnerable package version (worst severity, the version that
  fixes all its advisories, advisory count and first ids), the 40 most severe,
  with 25 recommendations and a count of anything left out. `by_severity` still
  counts every advisory. Pass `response_format: "detailed"` for the previous
  full report, one row per advisory. One row per advisory came to about 25k
  tokens on large projects, the size at which Claude Code cuts a tool answer
  off.
- `get_actionable_signals` returns fewer items: unclassified and judge-rejected
  ones are gone by design.
- Tool schemas are no longer separate JSON files (`dist/schemas/`); the
  `4da://schema/<tool>` resources serve them from the tool definitions.
- A standalone database is created in the user data folder, not in
  `<cwd>/data/4da.db`. An existing one there is still found and used.
- Hacker News is contacted only when `ecosystem_pulse` is called, never at startup.

### Changed: `upgrade_planner` returns the 4DA app's plan when there is one

The tool used to compute its own plan from the lockfiles in the current
directory, even on a machine where the 4DA app had already computed one. An
agent could be told a different target than the app showed for the same
install. When the app's database holds its persisted Upgrade Plan (schema 4),
the tool now returns that plan's work order with `provenance.mode: "app_plan"`:
one step per package, keyed by the app's item id, with the ecosystem, each
installed version and its minimum clean target, the upgrade type
(patch/minor/major), the projects holding it (direct or transitive, dev or
not) and the mechanism. `manifest_bump` means edit the manifest;
`lockfile_or_parent_update` means the package is only transitive, so update its
parent or refresh the lockfile rather than adding it as a direct dependency.
Past the plan's `expires_at` the result says `stale: true` and is still the
app's plan. Without a usable plan (no app database, nothing computed yet, or a
snapshot from another app version) the tool runs the standalone heuristic as
before and says why in `appPlanUnavailable`. The server reads the plan; it
does not reimplement the app's matching. `package` narrows either plan to one
package.

## 5.1.0 — 2026-09-11

### Fixed: scoped packages in pnpm and yarn lockfiles were never scanned

`vulnerability_scan` asked OSV about `'@humanfs/node`, with a leading quote,
instead of `@humanfs/node`. So GHSA-p498-v437-472g never appeared, although it
was open as Dependabot alert 340 on this repository and the app showed it. The
pnpm reader matched package keys with a pattern whose `\s` crossed the blank
line pnpm writes between entries, and so kept the next key's quote. Every
scoped package outside the importer blocks was affected: 525 names across five
lockfiles in this repository (measured 2026-09-11). The test fixture had no
blank lines, so it passed. The reader now matches keys by column on whole
lines, reads pnpm lockfile v5, v6 and v9, and drops keys that pin no registry
version (git, tarball, file) instead of querying them as names. The yarn
reader could not match a header that starts with `@`, so it dropped every
scoped package, and it never read yarn berry's `version: x` lines. Both are
fixed. Expect more findings on a pnpm or yarn project after upgrading; they
were always there.

### Fixed: a patched lockfile no longer hides a vulnerable node_modules

`mcp-4da-server/pnpm-lock.yaml` pinned hono 4.13.5 (the fix for
CVE-2026-84363/-84364/-84365) while `mcp-4da-server/node_modules` held 4.13.1
for 25 days, because activation ran `pnpm install` only at the repo root.
Every 4DA surface reads the lockfile, so every surface reported hono fixed
while the vulnerable copy was the one that ran (measured 2026-09-10). For npm
direct dependencies resolved from a lockfile, the server now reads
`node_modules/<name>/package.json` (scoped names included; hoisted workspaces
by walking up to the repository root, at most six levels). A directory with
no `node_modules` of its own is skipped, and a manifest-only resolution is
never compared, because a specifier floor is not a pin. When the installed
version differs, OSV is asked about the installed version too, so the answer
is OSV's, not a guess.

`vulnerability_scan` gains `install_drift: [{ package, dir, lockfile_version,
installed_version, vulnerable_installed, lockfile_version_vulnerable, fix,
note }]`, where `fix` is `pnpm install`, `npm ci` or `yarn install` according
to the lockfile that pinned the version. Each affected vulnerability carries
`installed_version`, `lockfile_version` and an `install_note` ("the lockfile
is patched but node_modules still has 4.13.1 — run `pnpm install`"), and the
recommendation is the reinstall, not an upgrade the lockfile is already past.
`what_should_i_know` names a vulnerable installed copy with its reinstall
command whatever the task, so the verdict is at least `review_needed` and
never clean. That advisory is graded the way the app grades its install-drift
row: high when the reinstall clears an advisory the running copy has (the
hono case, though its three advisories are medium on their own), medium when
the lockfile's pinned version is exposed too. `dependency_health` and `upgrade_planner` show `installedVersion`
beside `currentVersion`, and `upgrade_planner` turns a drift-only row into a
`reinstall` step. Expect `install_drift: []` on a healthy checkout.

### Fixed: a long-running server answered for the dependency set it saw at startup

Three server processes were live on the founder machine. Two had started
before the pull that brought hono 4.13.5, and `vulnerability_scan` from one
of them reported hono 4.13.3 (the lockfile at its start) with
`_meta.cached: false`: versions were resolved once at init and never again,
and `cached` only ever described the OSV lookup. Each resolution group now
records the files it read as stat signatures (every lockfile candidate,
present or absent; the manifest when the resolver fell back to it; for npm,
the node_modules install state). `vulnerability_scan`, `what_should_i_know`,
`dependency_health`, `upgrade_planner` and the briefing's scan wait re-run the
same resolution when one changes, and drop the stored scan and the warmup so
no answer describes a dependency set that no longer exists. Stat calls only:
no timers, no watchers. The cargo host-platform memo is keyed on
`Cargo.lock`/`Cargo.toml` too, so a re-resolution cannot mark newly added
crates as not built on this host.

### Added: resolution provenance

`vulnerability_scan`'s `_meta` gains `resolution: { resolved_at, lockfiles:
[{ path, kind, mtime }], re_resolved_this_call, note }` and `osv_cached` (the
same value as `cached`, which stays for compatibility). The tool description
now says that `cached` refers to the OSV advisory lookup, not to dependency
resolution. `what_should_i_know` gains a `scan` block (`status`,
`scanned_at`, `resolved_at`, `re_resolved_this_call`); `scan_status` stays.

### Changed: one severity rule with the desktop app (AD-046)

`vulnerability_scan` graded `sandbox@3.1.2`, a transitive of paddle-webhook
whose dev/runtime scope is unknown, critical (`by_severity.critical: 1`; the
briefing said "CRITICAL: Sandbox Breakout"), while the app graded the same
advisory High. Every surface now presents one grade, the rule the app uses
(`osv::identity::scope_adjusted_urgency`): a transitive-only dependency caps
critical at high, then a dev-only dependency drops one level (critical to
high, high to medium, medium to low; low and unknown stay). Unknown dev scope
gets no discount. Applied in `vulnerability_scan`, `what_should_i_know` and
`get_actionable_signals`; `severity_filter` and sorting use the presented
grade. Nothing is hidden: every entry keeps the advisory's own tier as
`advisory_severity` (with a `severity_note` when the two differ),
`by_severity` counts the presented grade, and the new `advisory_by_severity`
counts the raw tiers.

In full-database mode a transitive's dev scope comes from the app's
`dependency_instances` table. Only a real determination counts (`is_dev = 1`,
or a `scope` of runtime, dev or build); the app's placeholder rows
(`is_dev = 0, scope = 'unknown'`) stay unknown. Without `include_dev`, only
direct devDependencies are left out of the scan: a transitive of known dev
scope is graded down, not dropped, and one of unknown scope is no longer
hidden because a direct devDependency shares its name.

### Added: the database-recovery voice in data_freshness

When the headless refresh engine restores `4da.db` from a backup, or
quarantines it and starts a fresh empty one, it leaves `data/.db-recovered`
beside it. A fresh database looks fresh by every other freshness field.
`data_freshness` now surfaces the marker the way it surfaces `.engine-blocked`:
`db_recovered_at`, `db_recovery_kind`, `db_recovery_detail`, and a note ("The
database was restored from a backup / replaced with a fresh empty database by
the background refresh at … — results may be incomplete or empty; the
preserved file is …"). Read-only: the desktop app shows the marker once and
deletes it.

### Changed: ranked reads break ties by id

`get_relevant_content` orders by `COALESCE(rank_score, relevance_score) DESC,
id DESC`, mirroring the app's `RANKED_ORDER_EXPR`. 100 of 651 surfaced items
sat at exactly 0.5000 (a hard score cap), and their order was whatever SQLite
emitted.

### Changed: dependency_health says when it has no CVE data

`dependency_health` no longer says "all healthy" without a vulnerability scan
behind it, and says so when CVE data is not loaded (no scan yet, or the
dependencies changed since the last one).

### Fixed: the briefing never answers "safe" without a vulnerability scan

`what_should_i_know` awaited nothing. In full-database mode the live layer was
initialised without a vulnerability scan, so the first call after start read
an empty cache and reported `safe_to_delegate` for a task that named a package
with an open advisory (verified live 2026-09-07: 0 advisories at t+0, 11 at
t+7 min). The scan now warms at server start, the briefing awaits it (bounded,
8 s), and the result carries `scan_status` (`ready` | `unavailable` |
`disabled`). Without a ready scan the delegation level is the new `"unknown"`
— treat the task as unreviewed, never as safe; `safe_to_delegate` is only
emitted over a ready scan. Existing `human_only` evidence still wins.

Security signals now also come through a 30-day feed pass (`since_hours` max
raised from 168 to 720; windows past 7 days keep the current-pipeline-version
guard), so a three-day-old advisory is no longer cut by the 72-hour window. A
relevant security or breaking-change advisory yields at least `review_needed`.

### Fixed: one signal per vulnerability

`get_actionable_signals` injected one live signal per OSV record, so a
GHSA/RUSTSEC pair for one bug read as two problems. Alias-connected records
are clustered (union-find, scoped to package + version) and emitted once,
every id in `triggers`. Platform-inactive advisories and maintenance notices
drop to `low` with an explanatory action, and the briefing does not read them.

A `signal_type` filter is now pushed into the database read: the general read
is capped at the top 200 ranked items across every type, and on the live
corpus that cap starved a security-only pass (both in-window stored security
alerts ranked 299th and 582nd). The pipeline's stored priority vocabulary
(`critical` / `alert` / `advisory` / `watch`) is mapped onto the tool's tiers
instead of cast through unchanged — 92 of 93 stamped rows carried a priority
no filter, sort, or briefing rule recognised.

### Fixed: knowledge_gaps coverage and grading

- Every direct dependency is scanned (a `LIMIT 100` left 43 of 143 live
  dependencies unexamined); candidate items are loaded once.
- Registry rows (`crates_io`, `npm_registry`, `pypi`, `go_modules`) are version
  updates and grade `medium` regardless of title words — when the row is newer
  than the installed version (the row for the version you run is not a gap).
- An advisory names a dependency when the dependency is its subject package
  (`[ID] package: …`), not when the title merely contains the word: `url` was
  graded critical on a SurrealDB advisory ("via URL path"), `hmac` on a
  Phalcon one.
- An advisory the installed version is positively inside survives the 90-day
  publish-date cut; unknown exposure does not exempt.
- `osv_advisories` is consulted for the dependency's own ecosystem (the npm
  and crates.io `jsonwebtoken` were being conflated).

### Fixed: dependency_health counts vulnerable packages the way vulnerability_scan does

`vulnerableCount` is the actionable set (built on this host, not a maintenance
notice); `advisoryCount` reports every row so nothing is hidden. The health
penalty and severity breakdown follow the same set.

## 5.0.4 (2026-08-24)

### Fixed: vulnerability_scan could recommend a downgrade

`fixed_version` selection took the first OSV range's fix regardless of which
range contains the installed version — live consequence: "Upgrade undici to
6.28.0" while on 7.28.0. Selection is now branch-aware (the fix comes from the
range containing the installed version), with a hard guard that a
recommendation is never below the installed version — if no fix at or above it
exists, the honest "no fix version published" line is emitted instead.

### Changed: ranked reads follow the app's evidence/rank split

`get_relevant_content` orders by `COALESCE(rank_score, relevance_score)`
(schema 110, guarded for older databases); membership thresholds stay on the
evidence score.

## 5.0.3 (2026-08-23)

### Fixed: standalone mode broke on its second session (critical)

The minimal standalone schema created `dependencies` without the `is_direct`
column, while the live-intelligence init queried it. Session 1 of a standalone
install worked (fresh scan); session 2+ threw on init, the error was swallowed,
and `vulnerability_scan` / `dependency_health` / `upgrade_planner` silently
reported "no project detected" — blaming the user's setup. The column is now in
the minimal schema and an `ensureColumn` upgrade heals existing standalone DBs
on open.

### Fixed: grounded tool output

- `knowledge_gaps`: word-boundary matching with relevance/recency guards and
  honest severity (previously substring matches like "invite" → vite, and
  everything reported "critical").
- `ecosystem_pulse`: returns headlines again (dependency prefetch + on-demand
  fetch + 14-day recency window; previously reproducibly empty).
- `what_should_i_know`: the decision-windows section was dead (ordered by a
  column that does not exist on that table — `created_at` vs `opened_at`).
- Version logic: no more prerelease "upgrades" (rsa 0.10.0-rc downgrade) or
  phantom stable versions (React "19.0.8") — stable-semver comparison
  throughout.
- `dependency_health`: healthScore is proportional instead of collapsing to
  0/100; feed output deduplicated (title similarity).

### Changed: tools/list serves real schemas for required-param tools (AD-032)

Tools whose schema declares required parameters (`record_feedback`,
`decision_memory`, `agent_memory`, `check_decision_alignment`,
`what_should_i_know`) now serve their real `inputSchema` in `tools/list` —
the slim `{"type":"object"}` made them uncallable for clients that never read
MCP Resources. All-optional tools stay slim; full schemas remain available at
`4da://schema/{tool}`.

## 5.0.2 (2026-08-17)

### Docs: republish so npm serves the corrected README

No code changes. 5.0.1 was published to npm on 2026-08-16 minutes before the
AD-030 copy retirement (#469) landed the corrected README, so the npm package
page still described "Compound intelligence (learns over time)" and content that "compounds over time" — claims the product retired. <!-- retired-ok: quotes the retired claims verbatim to document exactly what this republish removed from npm -->
This release exists to put the current README (and the corrected app-vs-MCP
comparison) on npm.

## 5.0.1 (2026-08-16)

### Security: HTTP transport accepted forged authentication tokens

**Affects `--http` only. The default stdio transport was never exposed.**

`extractAuthClaims` decoded the JWT payload and validated the claims inside it
but never read the signature segment — no HMAC was ever computed, despite the
function's own docstring claiming "HMAC-SHA256 verification against the shared
relay secret". Any request could present
`Authorization: Bearer x.<base64url({"team_id":"x","client_id":"y","role":"admin","exp":9999999999})>.x`
and be accepted as a team admin.

Three defects compounded it:

- The transport's header claimed "Binds to 127.0.0.1 only", but `--host`
  accepted any address, so `--http --host 0.0.0.0` served all 14 tools to the
  network.
- The DNS rebinding guard was written as `if (origin) { ...check... }`, so a
  request with **no** `Origin` header — every non-browser client, and any
  attacker — skipped it entirely.
- `hasPermission()` existed but was never called, so even legitimate tokens got
  no role enforcement: a `viewer` could invoke every write tool.

Fixed:

- **Real signature verification.** HMAC-SHA256 over
  `base64url(header).base64url(payload)`, constant-time compared
  (`crypto.timingSafeEqual`) against the shared secret, **before** any claim is
  read. The algorithm is pinned to `HS256`, so `alg: none`, other HMAC widths,
  and asymmetric-algorithm confusion are all refused. `exp` is now mandatory
  (a signed token with no expiry is a permanent credential) and `nbf` is
  honoured, both with the issuer's 60s leeway. No new dependency — Node's
  built-in `node:crypto`.
- **Fail closed.** With no secret configured (`MCP_AUTH_SECRET`, falling back
  to `JWT_SECRET` for parity with a co-deployed relay), *every* token is
  rejected. A server that cannot verify a signature must not trust claims.
- **Host-header DNS rebinding guard on every request**, using the SDK's
  `validateHostHeader`/`validateOriginHeader`. `Host` is mandatory, so the
  check can no longer be skipped by omitting a header; a foreign `Origin` is
  still refused when present.
- **Safe `--host`.** 127.0.0.1 remains the default. A non-loopback bind is
  **refused at startup** unless a secret is configured, prints a warning
  banner, and forces authentication on for every request regardless of
  `MCP_AUTH_REQUIRED`.
- **Role enforcement wired up.** Every tool call is checked against the
  verified role via the registry's existing `readOnlyHint` annotation:
  `viewer` = read-only, `member`/`admin` = read + write. Unknown tools fail
  closed as writes.
- Removed `isNetworkTierAllowed()` — dead code with no tier data anywhere in
  this package.

**Behaviour change:** an existing `--http --host 0.0.0.0` deployment will now
refuse to start until `MCP_AUTH_SECRET` is set, and only accepts localhost-class
`Host` headers unless `MCP_ALLOWED_HOSTS` names the address clients use. This is
deliberate: that deployment was previously reachable by anyone with forgeable
admin credentials.

## 5.0.0 (2026-08-11)

### Breaking: Node.js 20+ required

The server now requires Node.js >= 20 (previously >= 18; Node 18 has been EOL
since April 2025). No tool behavior changes.

### Changed: migrated to MCP TypeScript SDK v2 + 2026-07-28 protocol support

Replaced the discontinued `@modelcontextprotocol/sdk` v1 with the v2 packages
(`@modelcontextprotocol/server` + `@modelcontextprotocol/node`) and moved both
transports onto the v2 serving entries:

- **stdio** now goes through `serveStdio`, which negotiates the protocol era
  per connection: 2025-era hosts (Claude Code, Claude Desktop, Cursor — the
  classic `initialize` handshake) are served exactly as before, and hosts
  speaking the new stateless 2026-07-28 revision (`server/discover`) are now
  supported on the same endpoint.
- **--http** now goes through `createMcpHandler` + `toNodeHandler`: stateless
  serving for both eras from one factory — the previous per-request transport
  wiring is gone. Health endpoint, localhost binding, Origin-header DNS
  rebinding protection, and the optional JWT auth gate are unchanged.

Existing clients need no changes — protocol version negotiation is untouched
for 2025-era hosts and verified against a v1-SDK client.

### Fixed: startup log reported a stale version

The stdio startup line hardcoded "v4.6.3" regardless of the installed version;
it now derives from package.json like `--version` and `serverInfo`.

## 4.6.2 (2026-06-17)

### Fixed: vulnerability_scan returned empty severity, fix versions, and summaries

The scanner enumerated advisories via OSV's `/v1/querybatch` endpoint, which returns
only `{ id, modified }` per vulnerability — but it then mapped that index-only object
as if it were the full record. Every rich field collapsed to a default: `summary`
became the bare advisory ID, `fixed_version` was always `null` (so every
recommendation read "no fix version published"), `references` was always empty,
`published` actually carried the *modified* timestamp, and severity was hardcoded
(`medium` for any GHSA, `unknown` for anything else) rather than derived.

The scanner now hydrates each matched advisory via `/v1/vulns/{id}` (cache-first,
24h TTL, bounded concurrency over the vulnerable subset only) and derives severity
honestly: a CVSS base score — computed from the vector string when OSV provides one
(new `cvss.ts`, CVSS v3.0/3.1) — wins, then the GitHub-advisory severity label, then
`unknown`. No more fabricated default buckets. Real fix versions, CVE aliases,
summaries, and reference links now flow through.

## 4.6.1 (2026-06-11)

### Improved: prescriptive tool descriptions

All 14 tool descriptions now state WHEN to call the tool, not just what it does
(e.g. "Call when the user asks about security, vulnerabilities, or CVEs"). Both the
slim tool list and the full schemas carry explicit triggers, so calling models select
the right tool more reliably. A regression test enforces this going forward.

### Changed: license

Relicensed to Apache-2.0 (from MIT). The 4DA desktop app remains under
FSL-1.1-Apache-2.0; this MCP connector is intentionally permissive to maximize adoption.

## 4.6.0 (2026-04-24)

### Breaking: Tool consolidation — 39 → 14 tools

Removed 25 tools that returned empty, broken, or low-value data through MCP.
Every remaining tool reliably returns useful, actionable information.

**Kept (14):**
- `vulnerability_scan` — live CVE scanning (standalone)
- `dependency_health` — health score + version freshness (standalone)
- `upgrade_planner` — ranked upgrade recommendations (standalone)
- `what_should_i_know` — pre-task intelligence briefing (standalone)
- `ecosystem_pulse` — filtered ecosystem news (standalone)
- `get_context` — tech stack + interests (standalone)
- `get_relevant_content` — scored content feed (full mode)
- `get_actionable_signals` — classified alerts (full mode)
- `knowledge_gaps` — dependency blind spots (full mode)
<!-- retired-ok: historical release notes — describes that release's tool list verbatim -->
- `record_feedback` — save/dismiss to teach the system (full mode)
- `decision_memory` — persistent architectural decisions (standalone)
- `check_decision_alignment` — verify tech choices (standalone)
- `agent_memory` — cross-session persistent memory (standalone)
- `developer_dna` — tech identity profile (full mode)

**Removed:** explain_relevance, score_autopsy, trend_analysis, daily_briefing,
context_analysis, topic_connections, signal_chains, semantic_shifts,
attention_report, source_health, config_validator, llm_status,
export_context_packet, reverse_mentions, project_health, tech_radar,
agent_session_brief, delegation_score, autophagy_status, decision_windows,
compound_advantage, record_agent_feedback, get_agent_feedback_stats,
trust_summary, preemption_feed

**Fixed:**
- `get_relevant_content` now uses Rust-computed PASIFA scores when the desktop
  app database is present, instead of the simplified TypeScript keyword scorer.
  Results are dramatically more accurate.

## 1.0.0 (2026-02-27)

Initial public release.

### Tools (27)

**Content & Scoring**
- `get_relevant_content` — Query filtered content by relevance, source, time
- `explain_relevance` — Understand why an item scored the way it did
- `record_feedback` — Teach 4DA what you like/dislike (click, save, dismiss)
- `score_autopsy` — Deep forensic analysis of relevance scores

**Intelligence & Analysis**
- `daily_briefing` — Executive summary of discoveries
- `trend_analysis` — Statistical patterns, anomalies, and predictions
- `get_actionable_signals` — Classify content into actionable signals with priority levels
- `signal_chains` — Get causal signal chains connecting related events over time
- `semantic_shifts` — Detect narrative shifts in topics you follow
- `topic_connections` — Build knowledge graphs from content

**Developer Context**
- `get_context` — Get user's interests, tech stack, learned affinities
- `context_analysis` — Optimize your context for better relevance
- `knowledge_gaps` — Detect knowledge gaps in your project dependencies
- `project_health` — Project health radar for dependency freshness and security
- `reverse_mentions` — Find where your projects are mentioned in sources
- `attention_report` — Analyze attention allocation vs codebase needs
- `developer_dna` — Export your Developer DNA — tech identity, dependencies, engagement, blind spots

**Decision & Memory**
- `decision_memory` — Manage developer decisions (record, list, check, update, supersede)
- `tech_radar` — Generate tech radar from decisions and content signals
- `check_decision_alignment` — Check if a technology aligns with active decisions
- `decision_windows` — View time-bounded opportunities requiring attention
- `compound_advantage` — Measures intelligence leverage for decisions

**Agent Integration**
- `agent_memory` — Cross-agent persistent memory — store and recall across sessions
- `agent_session_brief` — Tailored session startup context for AI agents
- `delegation_score` — Should the agent proceed or ask the human?
- `export_context_packet` — Generate portable context packet for session handoff

**System**
- `source_health` — Diagnose source fetching and data quality issues
- `config_validator` — Validate configuration and detect issues
- `llm_status` — Check LLM/Ollama configuration and availability
- `autophagy_status` — Intelligence metabolism status — calibration accuracy, anti-patterns

### Features

- 11 content sources: Hacker News, Reddit, Twitter/X, GitHub, RSS, YouTube, arXiv, Dev.to, Lobsters, Product Hunt, custom feeds
- PASIFA scoring algorithm — 5-axis codebase-aware relevance with confidence calibration
- Privacy-first — local SQLite reads; the only outbound call is vulnerability_scan (package names + versions to OSV.dev), zero telemetry
- BYOK — bring your own API keys, never stored remotely
- Works offline with Ollama fallback for embeddings
- Dual transport: stdio (default) and Streamable HTTP
- SQLite storage with automatic migrations
- Compatible with Claude Code, Cursor, Windsurf, VS Code Copilot, and any MCP client
