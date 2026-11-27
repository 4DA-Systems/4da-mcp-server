# Changelog

## 6.6.0 — unreleased

### Behaviour changes to know before upgrading

- The guard hook counts a `proceed` or `review` answer, and a private record, only from a 4da server at 6.6.0 or later (each ledger line now records the server's version); `avoid` and `wait` count from any version. The plugin pins the server, so they move together; with an older server kept by hand, every install is held until the server is updated.
- Moving a dependency into another section of a manifest (for example from `devDependencies` or optional-dependencies into the runtime dependencies) is judged like adding it.
- A package name withheld only because the project's default registry, index or proxy is a host 4DA does not know as public (Artifactory, Nexus, Verdaccio, a member's or a requirements file's index) is no longer treated as your own package: `dependency_check` says the registry was not recognised, and the guard hook holds installs of those names until the host is added to `FOURDA_PUBLIC_MIRRORS` (when it proxies the public registry) or the names to `FOURDA_PRIVATE_PACKAGES`. A scope or `GOPRIVATE` rule releases its packages only in the folder whose configuration holds it, or everywhere when it is set in the environment.
- The guard hook honours a `latest` answer for 1 hour (24 before), so `npm install x` more than an hour after its check is held until `dependency_check` answers for `latest` again; exact versions and bounded ranges keep 24 hours. Which private records release an install is in the next bullet.
- `dependency_check` answers `wait` where 6.5.1 answered `review` for a release still inside the age hold that also carries a review note. The guard hook holds `wait`, so an install of a release published in the last three days is now stopped in that case too.
- `what_should_i_know` takes two new arguments, `packages` and `not_packages`, and has a fifth level, `confirmation_needed`: the agent acts next, no person is needed yet. A call without `packages` never ends `safe_to_delegate`: it ends `confirmation_needed`, or `human_only` when something the briefing looked up on its own is malicious or critical. A caller that reads `delegation_assessment.level` must handle the new value. `unverified_words` and `withheld_from_task`, which no published release had, are folded into one section, `task_packages`. See The briefing.
- `what_should_i_know` reads a command written inside a sentence to the end of that sentence, so the English words after it are its operands: "Use npm install msw for tests" holds msw, for and tests, each waits in `task_packages.to_confirm` like any operand, and putting for and tests in `not_packages` keeps the level at `review_needed`: the reason says this is not an error, and to check what the command installs with `dependency_check`. A command written on its own line, in a code span (`` `npm install msw` ``) or in parentheses ("(npm install msw)") holds only the words up to its end.
- `not_packages` is your statement of which words of the task are not packages, as `packages` is your statement of what the task adds, and a `safe_to_delegate` reason ends by saying it rests on both. A word you dismiss keeps `review_needed` only where the briefing itself read it as a package: an operand of a command it reads, an entry of a snippet it reads, a name with a version written on it, or a near miss of a popular name.
- `what_should_i_know` sends every name you declare `public: true` to its public registry: declare `public: false` for anything the task or the project takes from a private registry, an index of its own, git or a path. The briefing notices a package source the task names only through a fixed list of spellings (The briefing), so that declaration is what keeps a private name off the public registries.
- `what_should_i_know` makes one promise. The level rests on your declaration and on your statement of which words are not packages: each package you declare public is checked at the `version` you state. Declare the version the task writes. Without `version` the package is still checked, but the answer is never `safe_to_delegate`: it is `confirmation_needed`, or a stricter level another rule sets, and `next_step` asks for the version. Apart from that promise, the briefing also checks versions it happens to read in the task (on a command's operand, in a snippet, beside a name). That reading is best effort and promises nothing: a version written in a spelling it does not read is not checked.
- The guard hook holds an install command that names a package without a version (`npm install x`, `pip install x`, `cargo add x`, `go get x`), a tool install from a registry (`cargo install x`, `go install x@v`, `yarn global add x`, `uv tool install x`, `poetry self add x`) and a tool's own upgrade (`python -m pip install --upgrade pip`, `npm i -g npm`) until `dependency_check`, or a `what_should_i_know` call that declared the package `public: true`, has answered for that package at that version in the last 24 hours, or at `latest` for a bare name in the last hour. 6.5.1 let all of these through with no verdict. A dist-tag other than `latest` (`x@next`) is held until the command names the version.
- The guard hook lets a command that holds a package manager's install word through only when it reads that command whole. A command it cannot read whole is held, and the denial names the part it did not read: a variable or a substitution on the line, beside a named package any option that is not on the manager's allow list, a manager's own setting named at or before the install (`npm_config_registry=...`), operands `xargs` reads from its input, `sed`, `awk` or `make` with an install on their line, a PowerShell comma list or `--%`. 6.5.1 let these through without comment. Text that only mentions an install (`echo`, `grep`, `git commit -m`) still goes ahead.
- Where a ledger exists, a hook that fails or runs out of time holds every Bash and PowerShell call and every edit of a manifest or of the ledger, and a payload under 8 MB that does not parse is held. 6.5.1 let such calls through. Any call that names the check ledger, other than one plain read command, is held.
- `--http` refuses to start when the `@hono/node-server` it would serve through is older than 2.1.6. The stdio server is not affected.
- Below Node.js 22 the server stops at once, with one line and exit code 1. 6.5.1 started and served.
- More answers are words or NOT CHECKED where 6.5.1 gave a command or a clean result: an `upgrade_planner` step whose precondition the plan could not establish, a `cargo add` whose old and new lines link one native library, a uv pin that installs an affected release on the project's lowest supported Python, and the scans, the health score, the briefing and the plan beside a lockfile read only in part.
- `--setup` leaves a config that holds any key twice untouched and exits 1, and for a Claude Code entry that pins another release it prints the remove and add commands instead of "Already configured".
- Inside a workspace (a `pnpm-workspace.yaml`, `lerna.json`, `nx.json`, a `package.json` with `workspaces`, a `go.work`, a pyproject or Cargo workspace, up to 12 folders above), with a workspace option, or when a project file already mentions the package, the guard hook holds a package named without a version or with a range until the command names the exact version (`x@1.2.3`, `x==1.2.3`). 6.5.1 let these through.
- A registry or index on a host that is not plainly internal (anything but localhost, a name without a dot, a name ending in .internal, .local, .lan, .corp, .home.arpa, .test, .example, .invalid or .localhost, or a private or loopback address) is no longer taken as the project's own source: the packages installed from it are judged on the ledger like registry names, and the denial says how to mark a private name (`FOURDA_PRIVATE_PACKAGES`). 6.5.1 let every non-public host through.
- The guard hook holds every change to a `pnpm-workspace.yaml` in which any line is not plain (a `key:` header, a `- 'entry'` item or `key: value`), a comment or quote-style change included, until the file is rewritten as plain `name: version` lines.
- An edit of `package.yaml` or `package.json5` (which pnpm reads as manifests) is held with the advice to write the manifest as `package.json`, and a NotebookEdit of any manifest is held with the advice to use Edit or Write.

### What is scanned

- A `Gemfile.lock` (or `gems.locked`), `composer.lock`, `Pipfile.lock`, `poetry.lock` or `pdm.lock` is compared with the manifest beside it (`Gemfile` or `gems.rb`, `composer.json`, `Pipfile`, `pyproject.toml`): a package the manifest declares and the lockfile has no entry for makes the lockfile PARTIAL, as npm, pnpm, Yarn, Bun, Cargo and uv lockfiles already were. 6.5.1 read such a lockfile as complete in every format: a `Gemfile.lock` written before a gem was added to the `Gemfile` answered `coverage.complete: true`, 0 vulnerable, and `dependency_health` 100/100, and the added gem was checked nowhere. Not compared, because a lockfile may leave them out: platform packages, names a package provides or replaces, gems declared behind a condition or for some platforms only, requirements restricted by a marker, a Python version or a platform, path, git and URL sources, setuptools, pip and wheel, and the project itself. PDM's `[tool.pdm.dev-dependencies]` and its optional-dependencies and dependency groups are compared when the lock's `[metadata] groups` names the group, Poetry 2's `[project.optional-dependencies]` and `[dependency-groups]` are compared, and a Pipfile category is compared when the lock has a section for it; a group or category the lock does not record, and a `require-dev` beside a `composer.lock` with no dev package, are named as not compared. A manifest the server cannot read or follow is named as not compared (NOT CROSS-CHECKED, a note), never as damage. The `Gemfile` is followed through block assignments (`x = if`, `x = case`, `x = begin`), `;` statements, heredocs, percent literals and a `gem` line continued on the next line.
- A `Gemfile.lock`, `composer.lock`, `poetry.lock` or `pdm.lock` in which an entry depends on a package that has no entry of its own is PARTIAL, worded "an entry another package needs is missing ... The whole file was read and what it holds was checked"; a file that stops short is still "read up to the damage". So is a `Gemfile.lock` whose `DEPENDENCIES` lists a gem with no spec (except a gem the `Gemfile` declares for some platforms only or behind a condition, and `bundler`), and one beside a `Gemfile` that moved a gem between a path, git and the registry. 6.5.1 read these as complete.
- A lockfile read only in part (older than its manifest, cut short, entries skipped), a refused requirements include, or a second lockfile that disagrees with the one read now leads `vulnerability_scan`'s summary with NOT CHECKED, sets `total_vulnerable_packages` and `by_severity` to null and puts what was found under `found_in_checked_dependencies`, as an unreadable lockfile already did. 6.5.1 listed the file under `coverage.partial_lockfiles` and still answered "0 vulnerable". A lockfile read whole that could only not be compared with its manifest (NOT CROSS-CHECKED) is a note: the totals stay numbers.
- A lockfile whose only problem is a missing entry for a declared dependency is named as older than its manifest ("PARTIAL: 1 lockfile is older than its manifest: Gemfile.lock (Gemfile declares carrierwave, but this lockfile has no entry for it ..."), not as "NOT read to the end"; NOT CROSS-CHECKED says "against the manifests that declare its dependencies", since a `Gemfile`, `composer.json`, `Pipfile` or `pyproject.toml` can be that manifest.
- A `Gemfile.lock` `GEM` section that lists a private remote beside rubygems.org is private as a whole: none of its gems is sent. 6.5.1 sent to OSV.dev the private gems of a section that named a private remote first and rubygems.org second. Gems from a `GIT` section and Composer branch checkouts (`dev-master`) are listed under `coverage.not_checkable` (6.5.1 left them out without a word), and a `pdm.lock` package from git, a URL or a path is no index release (6.5.1 called a GitHub one private).
- A `gems.locked` beside a byte-identical `Gemfile.lock` (line endings aside) is no conflict. 6.5.1 listed the `Gemfile.lock` under `conflicting_lockfiles`.
- A repository directory whose name is not a plain path (for example `packages/a$(x)` or `c;x;`) is named only escaped, in every answer that names it (`[unsafe directory name, escaped: a$(x)]`): `vulnerability_scan` (where a finding is locked, the lockfiles and manifests it lists, its recommendations), `dependency_health`, `upgrade_impact`, `what_should_i_know` (`advisories[].action`) and `upgrade_planner`. `vulnerability_scan` gives no fix command in such a directory; the step's `action_note` says why. 6.5.1 put the name raw into `fix_targets.*.commands[].dir`, `run_order` and the prose an agent pastes. `project_root` and `upgrade_impact`'s `your_code.files[].path` stay verbatim. Which characters count is under The plan.
- A Cargo target that is not built on this host is quoted only as a plain `cfg(...)` or target triple; one holding a string literal (`cfg(target_os = "linux")`) is described without its text. 6.5.1 quoted the header from `Cargo.toml` as written, so a hostile header reached `appliesWhenBuiltFor`, the reasons and the summary.
- `dependency_health` withholds its score when a lockfile was read only in part (older than its manifest, cut short, entries skipped) or disagrees with the one read: `healthScore` and the counts are null, `withheldReason` is `"lockfile_partial"`, and the summary leads with NOT CHECKED and what was not read. 6.5.1 answered "Health: 100/100 ... over the checked part only" beside a `Gemfile.lock` or `Pipfile.lock` older than its manifest. A refused requirements include still scores the checked part, and a lockfile that could not be compared with its manifest is a note beside a full score.
- A directory walk that stopped early (20,000 directories, or `FOURDA_WALK_BUDGET_MS`) makes `what_should_i_know` lead with NOT CHECKED naming the walk and never say `safe_to_delegate`, `upgrade_planner` say `vulnerabilityDataAvailable: false` with a NOT CHECKED summary, and `dependency_health` lead with it, score the part that was read and never say all healthy. 6.5.1 answered `safe_to_delegate` and "No dependency of this project is named in the task" for a package in the part never read.

### The plan

- A step in a directory whose name a shell would read as code gets no command, no `run_order` step and no `dir`: its reasons name the directory escaped and say to handle it by hand, and the row is not counted as fixed. Only the steps in such a directory are withheld; a row's steps in other directories stay in `run_order`, in order, and the summary and `run_order_note` say how many were withheld. Refused anywhere in the path: `$`, the backquote, `"`, `'`, the curly quotes U+2018 to U+201F, `\`, `%`, `!`, `;`, `&`, `|`, `<`, `>`, `(`, `)`, `{`, `}`, `*`, `?`, `[`, `]`, `^`, `:` after a drive letter, a control, format or invisible character, and any space other than U+0020; at the start of the path, `-`, a Unicode dash, `~` and `#`; a path that is a bare `@name`; an empty segment; a path over 1,024 characters. Allowed inside a name: letters, marks, digits, the space, and `. _ - + @ # ~ , =`, so `packages/@scope/pkg` keeps its commands. 6.5.1 named every directory as the repository spelled it, in `run_order[].dir`, `commands[].dir` and "run X in <dir>".
- A requirements line's trailing comment, an environment marker holding anything but a plain comparison, an extras name outside PEP 508 and a Cargo feature name outside Cargo's shape are never put into the plan's instructions: the requirement and a plain marker are quoted as written (blanks before the `;` kept), anything else is refused or counted in words, and a requirements file whose name is not a plain path is named escaped. 6.5.1 spliced them raw into `upgradeInstructions`.
- `project_path: "*"` when no app plan can be read (no app attached, no plan stored, a plan format this server does not read) leads with "NOT CHECKED: project_path "*" asks for every project, and only the 4DA app's stored plan covers more than one ...", names the reason, sets `vulnerabilityDataAvailable: false` and carries `allProjects: { covered: false, reason }`; the rows are still the plan for the server's own project. 6.5.1 returned that plan as if it covered every project. A call without `project_path` is unchanged.
- An app plan step returned for `"*"` no longer calls its target "the fixed release" (it is not checked against the lockfiles), and no longer prints a move to the same version ("0.18.2 -> 0.18.2").
- `upgrade_planner` keeps `vulnerabilityDataAvailable: true` beside a lockfile that was read whole and only could not be compared with its manifest (NOT CROSS-CHECKED). 6.5.1 said NOT CHECKED for it.
- `upgrade_planner`'s tool description says the plan is this server's, computed from the project's lockfiles, and when the app's stored plan is returned instead; 6.5.1's still called it the app's work order.
- Every `run_order` step of Cargo, Go, `uv lock`, Poetry, `pip-compile` or `uv pip compile` with an output file, npm, pnpm, Yarn and Bun names the files it changes, relative to the project (`changes`: `["Cargo.toml", "Cargo.lock"]` for a `cargo add` at the root, the workspace's lockfile for a member's step). A step whose failure can leave a file edited says how to put exactly that back (`if_it_fails`): a `cargo add` writes `Cargo.toml` before it resolves, and `npm install x@v`, `pnpm up` or `pnpm add`, `yarn upgrade`, `yarn up`, `yarn add` and `yarn workspace <member> add` write `package.json`; the requirement or entry the plan read is quoted when it is a plain one ("if this command fails, check package.json: set dependencies.lodash back to "4.17.20" if it changed"), otherwise the words say to put it back as it was, and never a blanket `git checkout`. `npm pkg set` names `package.json` and says to remove the key it added. Every plan ends with `after_run`: call `vulnerability_scan` again when the steps have run, and what the plan cannot promise (the package manager picks the copies no step names, a release can need a newer toolchain, and after a failed step the rest run on a tree the plan did not expect: stop there, put it back and scan again). 6.5.1's steps carried none of these.
- A `cargo update -p <crate> --precise <release>` step carries the pre-update its target needs, read from the crates.io sparse index with the optional dependencies the release's default features turn on: chrono 0.4.30 needs core-foundation-sys ^0.8.3, so with 0.8.2 locked the step is `cargo update -p core-foundation-sys@0.8.2 && cargo update -p chrono@0.4.19 --precise 0.4.30`. Cargo's moves run a crate before the crates that depend on it, and before the upgrades of their directory, and `run_order_note` says so. A `cargo add` whose new release would link the same native library (`links`) as an old line another locked crate keeps (git2 0.21 beside shadow-rs's git2 0.13) is words naming the crate to move first, not a command. In 6.5.1 starship v1.0.0's `cargo update -p chrono@0.4.19 --precise 0.4.30` failed on core-foundation-sys, and its `cargo add git2@0.21.0` failed and left `Cargo.toml` edited.
- A check the plan needs before it can give a step as a command (the `links` check, the pre-update's requirements, a uv target's own requirements, the Python floor below, whether the target clears the row's advisories) has three outcomes: pass, fail, or not established. When it could not finish (a slow or failing index, OSV.dev not answering, the walk's bound, the time running out), the step is words with the reason, never the command, and the row is not counted as fixed.
- Every uv upgrade of one lockfile runs as one `uv lock` with all its `--upgrade-package` pins (of two pins of one package the higher stays), so no pin lowers another; a refresh with no pin inside it says the resolver decides where it lands and that `vulnerability_scan` after the run says where. A uv target that requires the project itself at another version (crewai-tools 1.15.1 requires crewai==1.15.1 in crewai 0.86.0) is words. A uv pin whose requirement resolves, on the project's lowest supported Python, to a release with an advisory is held: NOT a clean fix, out of `run_order`, not counted as fixed, saying what it would clear, what it would install there, the first clean release and the Python it needs, and the two ways out (raise `requires-python` and plan again, or write the requirement knowingly). A dependency group named outside the group grammar is said escaped and gets words. A target that clears none of the row's advisories gets no step and is not counted as fixed.
- On Yarn Berry, an upgrade of a dev dependency the manifest also lists as a peer carries `--dev`; a dependency or optional dependency that is also a peer gets no command, since Berry refuses `yarn add` for it. 6.5.1's `yarn workspace <member> add` failed there.
- At a pnpm workspace root and on Yarn Berry, a copy another package keeps for its own requirement is refreshed after the step (`pnpm update -r <name> --depth Infinity --no-save`, `yarn up -R <name>`) when each such requirement resolves to a clean release at or above the target; when one does not, or that could not be read, the row names the copy that stays and is a hand edit, not counted as fixed. 6.5.1 counted such a row as fixed while the other copy stayed (vue core's minimist through json5).
- A row's steps on different npm-family lockfiles are no longer chained; a row whose fix on a lockfile is an override or resolution alone runs it before the other rows' version-setting steps on that lockfile; on one lockfile the npm refreshes run before an npm override scoped to a parent, which would stop `npm update` inside that parent; and a Yarn classic exact resolution forces the release the row says a refresh resolves to, raised to any release another step sets on that line, never the smallest fix below it. In 6.5.1 formik 2.2.9's run lowered minimatch again after an earlier step raised it.

### The pre-write check

- `dependency_check` refuses a package that is no name its registry can have, in every ecosystem, before anything is sent: PEP 508 names for PyPI, crates.io's crate-name rule, a Go module path whose first element is a domain, npm's name rule. A local path, a URL, a git source, a whole requirement line, a Cargo inline table, `requests[socks]` (extras) or `lodash@4.17.21` (a version in the name: the answer suggests `"lodash"` and says the version goes in `to`) is `unknown` with `not_checked: "input"` and "Nothing was sent to <the registry> or OSV.dev". 6.5.1 screened npm names only, and sent a PyPI, crates.io or Go item whole to pypi.org, crates.io, proxy.golang.org and OSV.dev, home directory and private host included.
- An item with a field `dependency_check` does not define (`registry`, `index_url`) is refused as written, item by item: the tool reads only the public registry. 6.5.1 ignored the field and looked the name up on the public registry and OSV.dev.
- A clean answer from OSV.dev's batch endpoint is read as clean only when the package's own advisory list (`/v1/query`) could be read to confirm it; otherwise the item is NOT CHECKED and the batch answer is not cached. With the batch endpoint answering empty and `/v1/query` failing, 6.5.1 answered `proceed` for 11 of 12 items, lodash 4.17.20 among them, and cached that for an hour.
- An advisory with no grade of its own whose GHSA alias could not be read counts as high, and the reason says the grade was not read. 6.5.1 counted it as ungraded: golang.org/x/net v0.17.0 went from `avoid` to `review` when that read failed, and the guard hook lets a `review` through. An alias OSV.dev holds no record for (it answers 404) grades nothing, as before.
- This server's own request limit for npm, PyPI and crates.io is named as such, with `retry_after_seconds` and a NOT CHECKED lead, as the Go proxy's has been since 6.5.0. 6.5.1 worded it as the registry being unreachable.
- `dependency_check` refuses a `to` or `from` whose label is shaped like a credential (a token prefix, an AWS key, a long mixed run): it is not sent, not shown (`to: "(withheld: shaped like a credential)"`) and not recorded in the ledger. Pre-release words, Go pseudo-versions and abbreviated commit hashes are versions; a build label holding a full 40-digit commit is refused. 6.5.1 sent such a label to the registry and OSV.dev.
- When no item could be checked, the summary leads with "NOT CHECKED: the item could not be checked" (one item) or "NOT CHECKED: none of the N items could be checked" (several) and `_meta.offline_note` says whether `FOURDA_OFFLINE` is set or the network, a proxy or OSV.dev failed. 6.5.1's summary read "N checked: N unknown". A bare crate version no longer names a newest release it never read. When every item was refused as written, the summary ends "No item was checked." instead of an empty count.
- A release inside the age hold now answers `wait` even when another signal asks for review, and the review findings are listed beside it; 6.5.1 answered `review` (for example a release 0.2 days old in a project whose `requires-python` raised a support note), which the guard hook lets through. Verdicts rank avoid, review, unknown, wait, proceed, except that with a wait among the signals the order is avoid, unknown, wait, review.
- A ledger answer counts only for the reading it judged. An exact-version verdict no longer clears a Cargo bare requirement (`cargo add clap@4.6.9`, `clap = "4.6.9"`), which Cargo reads as `^4.6.9` and may lock at a newer release; a bare crates.io version needs the answer for that caret range, `=1.2.3` and `cargo install x@1.2.3` the answer for the release.
- A `latest` verdict clears a name alone, or a spec that bounds nothing, for 1 hour, not 24: a release published after the verdict is inside the age hold and was not what it judged.
- With a well-known public mirror as the default index (Tsinghua, Aliyun, Tencent, Huawei Cloud, USTC, rsproxy, goproxy.cn, goproxy.io), names are checked as public; 6.5.1 recorded every name private there, and the guard hook released any version of it in every project.
- A private record no longer releases an install by itself. A name on `FOURDA_PRIVATE_PACKAGES` is released everywhere; a name a scope or `GOPRIVATE` rule covers is released everywhere when the rule is set in the environment, and otherwise only for a command that moves nothing, in the project folder whose configuration holds the rule; a name withheld only because the project's default registry, index or proxy is an unknown host is released nowhere. 6.5.1 released any version of a private name in every project, so one workspace member's registry line let known-bad public releases install in another member. A private record written by a server older than 6.6.0 is honoured nowhere.
- `go install <module>/cmd/<tool>@<version>` no longer stays held: `dependency_check` judges a Go package path as the module that contains it, at the version asked, names that module in the answer, and records the path, so the hook releases it. A verdict for a module alone still does not release a longer path under it, since a nested module starts with its parent's path.
- On Windows, a package manager called through its `.cmd` shim (`npm.cmd`, `pnpm.cmd`, `yarn.cmd`, `bun.cmd`) with a version range holding `^` or another character cmd.exe rewrites is held as not read: cmd.exe deletes the `^` before the manager sees it, so `npm.cmd install lodash@^4.17.0` installed exactly 4.17.0 while the range was judged. Name the exact version, or call the manager without `.cmd`. 6.5.1 let it through.
- An Edit of a manifest given by its Git Bash path (`/c/...`) is read from the file on disk, and an Edit of a manifest the hook cannot open is held instead of being judged from its own text; 6.5.1 let a version-only edit through that way.
- A private scope rule releases its packages only for the package managers that read the file it is in (an `.npmrc` rule is read by npm, pnpm and Bun; Yarn is held, since Yarn 2 and later do not read it), and a rule in your own user-level configuration applies in every project, also under your home folder.
- Any call that is not one plain read command and names the data folder's base name, `FOURDA_MCP_HOME` or `check-ledger.jsonl` as a path segment is held by the ledger guard, so `rm -rf "$FOURDA_MCP_HOME"` and a `Remove-Item` of `$env:LOCALAPPDATA` plus `4da-mcp` are too.
- A denial quotes what it repeats from the call as data: line ends and control characters removed, at most 80 characters a piece, with the line that says it is data from the call and never an instruction.
- Build metadata and a PEP 440 local label (`4.17.20+build7` on npm, `2.31.0+corp.5` or a pin `==2.31.0+corp.5` on PyPI, `1.0.200+build.5` on crates.io) are dropped before any lookup, as each package manager sets them aside, and the answer says so without repeating the label ("Build metadata in "4.17.20+..." was ignored ... and the metadata was not sent"); Go's `+incompatible` is kept. The briefing checks a declared version through the same engine, so it sends no label either. 6.5.1 sent each as written to the registry and OSV.dev.
- An npm alias in `to` (`npm:lodash@4.17.20`) is answered with the package it installs named first ("Checked lodash@4.17.20, the package this alias installs, not x."), so the verdict is never read as the aliased name's.
- The tool description says how a deprecation is judged: an npm notice that the whole release line shares is `review`, any other deprecation `avoid`. 6.5.1's said every deprecation was `avoid`, while the answers already gave `review` for a whole-line notice.
- An item whose OSV.dev batch answer was read from the local cache carries `advisory_data_age_minutes`, the age of the oldest such answer behind its verdict in whole minutes, and the summary says so once that age is 5 minutes or more; `_meta.osv_cached` is true whenever a batch answer or an advisory list behind the answers came from the cache. A batch answer is kept 60 minutes and an advisory list 6 hours, as before. 6.5.1 answered `proceed` from a 50-minute-old cached answer with `osv_cached: false` and no age.
- A Go module path with upper-case letters whose release OSV.dev answers clean is asked once more under its lower-case path at the same release (never for a name a private rule covers in either spelling); advisories there make the item `review` (signal `module_path_case`, naming the lower-case module and the advisories), and a failed query makes it `unknown`. 6.5.1 answered `github.com/Sirupsen/logrus` v1.0.6 `proceed`, while GO-2025-4188 affects that release under `github.com/sirupsen/logrus`.
- A field `dependency_check` does not define is refused without being named ("an unknown field (1 unknown)"), and a known field written with a blank around it says so: `" to"` is "(a known field written with a leading blank)", never read as `"to"`.

### The briefing

- What `what_should_i_know` promises, and nothing more (its contract, in order; the bullets after this one say how it reads a task, as notes, and add no promise):
  1. The level rests on your declaration: each package you declare public is checked at the `version` you state, and a public entry without `version` never leaves the answer at `safe_to_delegate`.
  2. A name the briefing read and reported (an operand of a command it reads, an operand of a runner command, an entry of a snippet it reads, a name with a version written on it, a line of a requirements file the task names) that you put in `not_packages` keeps the answer from `safe_to_delegate`, with a reason that names it; where you declared a name one edit from it instead, the reason says "you said lodahs is not a package and declared lodash instead: the task names lodahs; say so to the user, and make sure nothing installs lodahs".
  3. A name you dismiss or declare private, whatever its spelling (letter case, full-width letters, invisible characters, a version or extras written on it, PyPI's separators), and for a path any shorter path it starts with at a `/`, is never in a request the call makes: one guard that every registry, proxy, OSV.dev and GitHub request passes refuses it, and a `public: true` entry for such a name, or under such a path, is refused.
  4. A value of a credential shape this server knows is never, whole, in any response the server returns (every tool's result and error, and the replies to every other request, over stdio and HTTP), except the `task` field of a `what_should_i_know` answer.
  5. That `task` field is the reading copy of your task: markup dropped, line continuations joined, full-width and look-alike letters folded and invisible characters removed (NFKC), each run of blanks one space, a line over 2,000 characters left out; where it differs from your task in more than blanks, `task_note` says "the task held characters this briefing folded or removed (full-width or look-alike letters, invisible characters, markup): the echoed task is the reading copy".
  6. The check ledger line for a declared package is the line `dependency_check` writes for the same item, also for one the project's configuration makes private.
  7. The briefing also checks versions it happens to read in the task, for example on a command's operand, in a snippet or beside a name; that reading is best effort, and a version written in a spelling it does not read is not checked.
  8. The level is raised, for example, by a finding on a checked package, a version-confirmed vulnerability of the project, running install drift, a decision conflict, a name waiting in `to_confirm`, or something the briefing noticed it could not read.
  9. When the briefing notices it cannot read a command or a snippet whole (for example a quote problem, a source option, a line over 2,000 characters), it says so and the answer is not `safe_to_delegate`.
  10. When the briefing notices a command of a manager it does not read (for example gem, brew or composer at a command position with its own install verb), it says so, its words are not offered or looked up, and the answer is not `safe_to_delegate`; it does not promise to notice each such command.
  11. With one of the listed package-source spellings in the task, the names the task adds are not looked up; the answer is kept from `safe_to_delegate` when that held a name, and a task that only mentions such a spelling can be safe.
  12. A call reads at most 100 snippets and checks at most 4000 distinct words of its own for near-miss names, and checks its deadline between stages and lines; past a bound the answer says which and is not `safe_to_delegate`.
  13. The cost bounds are measured, not enforced: the CPU tests keep each generated input of up to 200,000 characters under 3 s of child CPU (measured this round: 2.14 s at worst on the reviewer's sets, 1.94 s on the sweep).
  14. Each fixed sentence of the answer is said only where it belongs: the "rests on your declaration" sentence ends a `safe_to_delegate` reason, the best-effort sentence comes right before it in a call that declared a package, the coverage sentence of 18 comes right before the "rests on your declaration" sentence, and a sentence that keeps the answer from `safe_to_delegate` is never said with `safe_to_delegate`.
  15. `to_confirm` lists the names the briefing noticed: a prompt for you, not a complete reading.
  16. The project's own scan reads the installed dependencies and sends their names unless the project's configuration marks them private; a declaration does not change that (a name you dismiss that is an installed dependency is still sent by that scan), and no task text goes to an embedding provider.
  17. A value of a credential shape this server knows in an argument of any tool is not sent to any host and not stored: a package name, version, ecosystem or path holding one is refused before any lookup ("refused: a value of a credential's shape is not a package name; nothing was sent or stored"; in `dependency_check` the one item, with no ledger line), and in the free text `decision_memory`, `check_decision_alignment` and `agent_memory` store it is replaced by its first four characters and its length, which `_meta.credential_masked` says. 6.5.1 sent such a name to the npm registry and OSV.dev and wrote it to the check ledger.
  18. The briefing checks npm, PyPI, crates.io and Go packages: what a task installs through any other manager or tool is outside what its answer covers, whatever the level, and every `safe_to_delegate` reason says so ("This briefing checks npm, PyPI, crates.io and Go packages: what the task installs through any other manager or tool is outside what this answer covers.").
- The one promise: The level rests on your declaration and on your statement of which words are not packages: each package you declare public is checked at the `version` you state. Declare the version the task writes. An entry's `version` is an exact version, a range in the ecosystem's grammar, or `latest` (refused where `dependency_check` refuses it: a dist-tag other than `latest`, and for PyPI a Poetry `^` or `~`). An entry without `version` is still checked in that call, at the versions the briefing read on it, else at `latest` (and at `latest` too where the task also names it without a version), and its verdict is shown, but the declaration is not complete: the answer is never `safe_to_delegate`, the level is `confirmation_needed` or a stricter one another rule sets (`human_only` stays `human_only`; a listed source spelling in the task gives `review_needed`), and `next_step` says "State `version` for each package you declared public: the version or range you will write, or "latest" for the newest release (checked so far: <name> at <version>, ...)." No task text decides this.
- Second, and apart from the promise: The briefing also checks versions it happens to read in the task (on a command's operand, in a snippet, beside a name). That reading is best effort and promises nothing: a version written in a spelling it does not read is not checked. What it reads is checked in addition to the declared `version`, and the worst answer sets the level (a task that writes lodash@4.17.20 is not safe because 4.18.1 was declared). It reads, for example: a command operand's spec; a snippet entry's spec; and forms beside the name written right before them, in prose or a code span, such as name@spec (bare or quoted, `name@">=1 <2"` included), `alias@npm:name@spec` (tied to name), name==spec and PEP 440's other operators (`zqx >= 1.4` for a declared name included), `name = "spec"`, `"name": "spec"` and `"alias": "npm:name@spec"`. A version in prose without such a form ("pin lodash to 4.17.20") is read only for a name the briefing knows on its own (a dependency of the project, a bundled-list name), never for a declared one: the declaration carries it. Where a form decides the ecosystem (a PEP 440 operator: PyPI; `"name": "..."`: npm) the name also waits in `to_confirm`, seen as "a name with a version written in the task". A version is never moved to another package or ecosystem (`pip install x==1.0.0 && npm install x` checks npm's x at `latest`). In a call that declared at least one package, every `safe_to_delegate` reason says, right before its last sentence, whatever the task holds: "The versions this briefing read in the task's commands and snippets are best effort: a version written in a spelling it does not read was not checked, so declare the version the task writes."
- `what_should_i_know` works with the agent's own statement about the task's packages. `packages: [{ ecosystem, name, version?, public }]` (at most 100 entries; `ecosystem` is npm, PyPI, crates.io or Go) names every package the task adds, pins, bumps, downgrades or swaps in, and `packages: []` says it changes none. `public: true` is a package on the public registry: its name is sent there and it is checked in that call with `dependency_check`'s engine, in batches of at most 25 within the call's time, as the two bullets above say. Each (package, release) is one row of `checked` and one reason clause (PyPI's `==2022.12.7` is the release 2022.12.7), and only a row the declaration produced says "confirmed public by you". "checked so far" names each package and says its ecosystem when the name is declared in more than one ("zqx (npm) at latest, zqx (PyPI) at latest"); a name declared private in two ecosystems is two `private` rows. When the task holds one of the source spellings listed below, nothing it adds is looked up. Each answer for what was declared public is recorded in the check ledger as the line `dependency_check` writes for that item, so the guard hook lets the install through, or holds it, the same way. `public: false` is a package from a private registry, git, a path or the workspace: the briefing never looks it up for the task, lists it under `task_packages.private`, and counts it as unchecked (`review_needed` at least). A declaration does not change this project's own vulnerability scan, which reads the installed dependencies and sends their names unless the project's configuration marks them private (`FOURDA_PRIVATE_PACKAGES`, an `.npmrc` scope or registry, a pip index, `GOPRIVATE`): a name the project already depends on is still sent by that scan, and the answer says so. `not_packages: [word]` (at most 100) drops words of the task that are not packages. A declared package the task does not mention is checked too, at its `version`, else at `latest`. 6.5.1 had neither argument.
- On its own the briefing looks a name of the task up only when the project already depends on it in that same ecosystem (a Go module by its full path), or it is exactly a name on one of its bundled lists (popular npm and PyPI names; names with a known malicious or hijacked release, such as crossenv, event-stream and node-ipc) for an ecosystem the project uses, one an install command in the task installs from, or one whose manifest file the task names (`package.json`, `requirements.txt`, `pyproject.toml`, `Cargo.toml`, `go.mod`). A language or manager word in prose decides no ecosystem, and nothing is looked up in an ecosystem other than the one that let it through. Every other name the task may mean as a package is looked up nowhere and listed in `task_packages.to_confirm`. 6.5.1 looked up any name an adding verb or an install command stood before, published or not, and took a dependency of any ecosystem, or the last segment of a Go module path, as one the project already has.
- `task_packages` holds every package-like word of the task once: `status` (`complete` or `confirmation_needed`); `to_confirm`, each entry with its `name`, the `ecosystems` it could be in, how it was `seen` (the operand of an install command, an entry of a manifest snippet, a name with a version written in the task, a line of the requirements file the task names, a word after an adding verb) and no version, one entry per name with its ecosystems merged, and two helps for the agent, `hint` for a near miss of a popular name ("one edit from lodash: if you mean lodash, confirm lodash instead") and `caution` when the task calls the word a key, a secret, a password or a token, or calls it internal; at most 25 entries, with `to_confirm_total` counting all; `checked` (name, ecosystem, version, verdict, and the `basis`: a project dependency, a well-known name, or confirmed public by you); `private`; `not_read` (what the screen or the argument check kept from being read, shown without its value, and why); `dismissed` (the `not_packages` words that matched); and `next_step` while the status is `confirmation_needed`. Nothing in it is shaped as the `packages` argument or as any tool's arguments, so it cannot be pasted back.
- The level. While a name waits in `to_confirm`, the level is `confirmation_needed` (unless what is already known makes the task `human_only`, whose reason then counts the waiting names), and `next_step` says to call again with the same task and `packages`: one entry for each waiting name that is a package, `public: true` or `public: false`, and a word that is no package in `not_packages`; a name left out stays waiting. A call with no `packages` argument and nothing waiting is `confirmation_needed` as well ("This call declared no packages ..."). With every name settled, the level follows from the verdicts. In a clean npm project, "npm install lodahs" answers `confirmation_needed` with lodahs in `to_confirm`; declared `public: true`, lodahs is checked in that call (`avoid`: npm took it down as malware) and the level is `human_only`. A reason reached after a declaration says what it rests on ("You declared 1 package." or "You declared that the task adds or changes no package."), and a `safe_to_delegate` reason ends "This rests on your declaration of what the task adds and on your statement of which words are not packages: a package you did not declare may not have been checked."; `next_step` says that `to_confirm` can miss names and ecosystems, so every package the task adds or changes is declared, listed or not.
- Commands are read, best effort, by a small grammar: a command it recognises is read, and where it notices a shape it cannot read it says the command is not read whole; a command it does not recognise as one is not read, and that silence says nothing. A command it recognises is a package manager's word (npm, pnpm, yarn, bun, pip or `python -m pip` / `py -m pip`, uv, poetry, cargo, go, pipx; with a `.cmd`, `.exe`, `.bat` or `.ps1` ending, or a version suffix such as `pip3.12`) and one of its adding verbs (npm's own aliases of install, such as `isntall`, its `it` and `install-test`, and bun's `a` included; npm's `cit` and `install-ci-test` install the lockfile and are named but not read whole), with only options on that manager's list between them (`npm -w web install x`, `npm --workspace web install x`; also `uv pip install`, `yarn global add`, `yarn workspace <name> add` and `cargo +<toolchain> install`), followed by: switches on that manager's list, compared with their letter case (`-F` is not `-f`); options of fixed arity whose value is never offered (`-w <workspace>`, `--filter <f>`, `--group <g>`, `-F` / `--features <list>`, `--optional <group>`); a requirements file after `-r`; and operands that are each a plain package name with an optional version in that ecosystem's grammar. It ends only at `;`, `&&`, `||`, `|`, a lone `&`, a new line without a continuation, the close of its own code span or of the parenthesis it opens ("(npm install pino)"), or the end of its sentence (a word ending in a run of `.`, `!` or `?`, or an ellipsis, before a blank, whatever the next word's case); a shell comment (`#`) does not end it, and every word up to there is an option or an operand: "Please npm install x and then run the tests" holds x, and, then, run, the and tests. When a word of a command written inside a sentence is put in `not_packages`, or a command is not read whole for a comma, a word that is no plain name or a redirection, the reason adds "This command, as the task writes it, keeps the answer from safe_to_delegate: it is not an error. Check what the command installs with dependency_check before running it." No remedy is offered. A word the grammar consumed (the manager's program, its verb, a switch, an option and its value) is no package of the task at that occurrence: it is not offered, looked up or weighed there, so "Use npm install ms@2.1.3" no longer looks up a package named install; the same word elsewhere in the task is read as before ("cargo add -p x y. Then add x to the docs" offers x).
- Where the briefing reads a name in the task, it holds the caller to it. Each operand of a command it read, and each entry of a manifest snippet it read (for example a `package.json` dependencies object, inline or fenced; requirements lines after a requirements file is named, in a ```txt or ~~~ fence or a `cat > requirements.txt <<EOF` heredoc; a pyproject `dependencies = [...]`, `[project.optional-dependencies]` or `[dependency-groups]`; a Poetry or Cargo dependencies table, `[target.'cfg(...)'.dependencies]`, `[workspace.dependencies]`, `[dependencies.name]` and inline tables included, where `package = "real"` names the crate real; go.mod requires; a requirements file the task installs with `-r`, and a `-r` or `-c` file it names, seen as "a line of the requirements file the task names"). Such a file is read only when its real path (symlinks and junctions resolved) is inside the project; otherwise the briefing says "a requirements file outside the project is not read", and for a missing file or one over 256 KB "the requirements file it names could not be read" (`review_needed` either way). A credential-shaped word in such a file is never offered, repeated or looked up, and the file is said not read whole ("a line of a requirements file it cannot read"; earlier builds of 6.6.0 could repeat such a word). A requirements file the briefing says it did not read whole offers none of its entries, is a (name as written, ecosystem) pair that waits in `to_confirm` until a declaration of exactly that pair settles it: a declaration in another ecosystem or in other letter case does not, so `pip install colorsx && npm install colorsx` is one entry with the ecosystems PyPI and npm that needs a declaration in each, and `pip install Colorsx` still waits beside a declaration of `colorsx`. Put in `not_packages`, such a pair keeps `review_needed`. A word that only follows an adding verb in prose ("add papaparse to package.json", "install papaparse (npm)") is offered once with every ecosystem the project uses, and any declaration of the name settles it.
- When the briefing notices it cannot read a command, it says the command is not read whole. It notices, for example: an option not on its manager's list, a registry, index, source, git or path option, a substitution, a quote problem, a redirection among its words (`>`, `>>`, `<`, `<<<`, `2>`, `2>&1`, `&>`, `|&`, spaced or attached: the words after its target are still its arguments), a comma in its list of packages (`pip install requests, x`), a word that is no plain name (a path, a URL, an alias, a tag, a credential's shape), a Poetry `^` or `~` operand (`poetry add x@^1.2`, said "a Poetry ^ or ~ constraint, which is no PEP 440 spec: write the PEP 440 range it means (for example >=1.2,<2.0) or an exact version; the level stays review_needed for this command as written"; `poetry add "x>=1.2,<2.0"` is read), and every command that fetches and runs a package (`npx`, `pnpx`, `bunx`, `uvx`, `deno`, `npm exec`, `npm x`, `pnpm dlx`, `yarn dlx`, `bun x`, `uv run`, `uv tool run`, `pipx run`, `go run`) or a scaffold (`npm init <x>`, `npm create`, `yarn create`, `pnpm create`, `bun create`: "it fetches and runs a package named create-<name> (or <scope>/create), which this briefing does not check"), and every command of pipenv, pdm, rye, hatch, conda, mamba or pixi ("it is a package manager this briefing does not read"). Such a command is said by its manager and verb only (it is a thing the briefing says when it notices, never a promise that what it did not flag was read in full) ("This task holds a command (pip install) this briefing could not read whole (a comma in its list of packages): check what it installs with dependency_check."), none of its words is offered in `to_confirm` or looked up, at any length, and the level is at most `review_needed` whatever is declared. A name that is malware in every release on the bundled list (crossenv) written in such a command is `human_only` without the network, whether or not a lookup answered; a name with a hijacked release (event-stream) there is not looked up, so `npm install x@npm:event-stream, y` ends `review_needed`. When a snippet reader notices a line or entry it cannot read (a value that is no version, an unknown key, a nested object in `package.json` dependencies, a requirements line it cannot parse, a direct reference `name @ url` in a `-r` file, an unreadable tail of "Add to requirements.txt: ..."), it says the snippet is not read whole ("a line it cannot read", "an entry it cannot read"): none of its entries is offered, repeated or looked up, and the level is at most `review_needed`. Silence says nothing about what was missed. A requirements line it reads can hold, for example, blanks around PEP 440 operators and in comma lists, extras (with blanks), a marker after `;` and `--hash` options; a comment or an option line such as `-r file` is no package. A requirements snippet is, for example, the fenced block after the file's name, a ```requirements, ```pip or ```txt fence, a ~~~ fence, or the lines right after the name up to a blank line. A marker word (`python_version`), an alias key (`"x": "npm:..."`), a dependency-group name (`cli = [...]`) or a PEP 735 `{include-group = "cli"}` entry and a package manager's own name where it is no command's operand ("use brew to set it up") are not offered. Pipfile and setup.cfg snippets are not read. Every reader works on a reading copy in which each run of blanks and tabs is one space (requirements files on disk too). A line of the task longer than 2,000 characters after that is not read: "a line longer than this briefing reads (2,000 characters)" (`review_needed`). More than 8 requirements files named with `-r` or `-c`: "the requirements files it names are more than this briefing reads (8)" (`review_needed`). At most 100 snippets are read per call: past that, "This task holds more manifest snippets than one call reads (100): split the task and ask for each part." (`review_needed` at least). An npm tilde range in a snippet (`"~9.6.0"`) is a range and is read. The key of a snippet entry (an alias key `x = { package = "real" }` included) is never offered as a prose word. An entry with a git, path, registry or workspace key is a source of the task's own, listed under `task_packages.private` with the basis "the manifest snippet in the task takes it from git, a path, a registry or the workspace, not the public registry"; the rest of such a snippet is read as usual, and its registry entries wait in `to_confirm`.
- A courtesy check on a list of spellings, not a promise about sources. When the task holds one of these, no name the task adds is looked up, also when declared `public: true`: `--registry`, `--config.registry=`, `--userconfig`, `registry=`, `:registry`, `--index-url`, `--extra-index-url`, `--default-index`, `--index`, `--find-links`, pip's `-i` and `-f` inside a pip command, `--source`, `--git`, `--path`, `npmRegistryServer`, `[[tool.uv.index]]`, `[[index]]` (uv.toml), `[tool.uv.sources]`, `[[tool.poetry.source]]`, `[install.scopes]` (bunfig.toml), `[registries]`, `[registries.<name>]`, `[registry]`, `[source.<name>]`, `[patch.<name>]`, a go.mod replace directive with `=>`, single-line or block, and the environment variables `npm_config_registry`, `NPM_CONFIG_USERCONFIG`, `YARN_REGISTRY`, `YARN_NPM_REGISTRY_SERVER`, `PIP_INDEX_URL`, `PIP_EXTRA_INDEX_URL`, `PIP_FIND_LINKS`, `UV_INDEX`, `UV_INDEX_URL`, `UV_DEFAULT_INDEX`, `UV_EXTRA_INDEX_URL`, `CARGO_REGISTRIES_<NAME>_INDEX`, `CARGO_REGISTRY_DEFAULT`, `GOPRIVATE`, `GOPROXY`, `GONOSUMDB` and `GONOPROXY` (in any letter case; options and tables are matched in their own case, and for the manager they belong to: Cargo's `-F derive` and npm's `-f` are no source). Any other way a task names a source ("from our Artifactory", "point npm at https://npm.acme.internal") is not noticed, and a name declared public there is sent: the declaration decides, so declare `public: false` for anything from a private registry, an index of its own, git or a path. The project's own private rules still override a public declaration. Each name held by the list is listed in `task_packages.not_read` as "not looked up: the task names a package source of its own; if it is on the public registry, check it with dependency_check" (or, when its own command names the source, "not looked up: the task takes it from a registry named in its command", or from "a package index" or "a find-links location named in its command"), the answer is kept from `safe_to_delegate` when the list held a name, and nothing is written to the check ledger for it. A task that only mentions such a spelling, with no name to hold ("Document the --registry option in the README"), can be `safe_to_delegate`. Dependencies the project already has are read by the scan as before.
- A declaration only adds checks: what the briefing looks up and concludes on its own is looked up and weighed the same whatever the caller declares, and the versions it reads in the task are checked beside a declared version (best effort, as above). A name the caller marks `public: false` or puts in `not_packages` is not looked up for the task even where the briefing would have looked it up, and then counts as unchecked; a name with a known malicious release on the bundled list stays `human_only` whatever the caller says. A name declared both public and private, in any order and any spelling (letter case, PEP 503, crates' `-` and `_`, a Go path's `!` escape or major-version suffix, an `npm:` prefix in `not_packages`), is never looked up for the task: private wins. A `public: false` entry that is refused still keeps its name from being looked up.
- A `packages` entry is validated as `dependency_check` validates an item: a field the tool does not define, a missing or non-boolean `public`, an unknown ecosystem, a name its registry cannot have, or a version `dependency_check` refuses (a dist-tag other than `latest` among them) is refused in its place, named in `task_packages.not_read` by its position and never by its value, and the briefing sends nothing in it; the other entries stand, and a refused entry holds the level at `review_needed` at least. An entry that is null, a number or an array is refused in its place, not the call, and `public: "false"` (a string) is refused and still keeps its name from being looked up. No refusal repeats the refused value, and the error for a `task` over 200,000 characters repeats nothing of the task. A Go module path in the proxy's `!`-escaped form (`github.com/!sirupsen/logrus`) is refused in a declaration, as `dependency_check` refuses the same item: neither tool looks it up or writes a ledger line for it (`dependency_check` records no item it refuses as written; the guard hook holds an unanswered item the same way). Declare a Go module as the go command writes it (`github.com/Sirupsen/logrus`). A `public: true` entry that this project's private rules cover is reported private, not looked up, and recorded in the check ledger as `dependency_check` records it (`not_checked: "private"`, with the rule that made it private); its basis is "your FOURDA_PRIVATE_PACKAGES list" when that list names it, else "this project's registry configuration"; an entry whose name is shaped as a credential (a known token prefix, a JWT, a PEM block, a UUID, twelve or more hex digits) is refused whatever `public` says and its name is never repeated (a `public: false` one still keeps its name from being looked up), and one whose version carries a label with a credential's shape is refused, not sent and not recorded.
- A value of a known credential shape (a token prefix such as `ghp_`, `AKIA`, `sk_live_`, `xoxb-` or `npm_`, a JWT, a PEM block, a UUID and the other shapes the task screen knows) is shown as its first four characters and its length ("ghp_... (39 characters)") in every result and error of every tool of the server, wherever it came from (a task word, a `not_packages` word, a name, a version, an ecosystem, a line of a requirements file); only the `task` field of a `what_should_i_know` answer keeps it, and that field is the reading copy of the task. Only known shapes are masked: a long random-looking folder name, a sha512 integrity string or a 64-hex digest is shown as it is (an earlier build of 6.6.0 masked such ordinary long words, a macOS temporary folder in `project_path` among them). A refusal no longer names an unknown field or parameter: "an unknown parameter (1 unknown)", "an unknown field (1 unknown)". A credential in the task is never read as a package name: a known token shape (`ghp_...`, `AKIA...`, `sk_live_...`, `xoxb-...`, `npm_...`), a UUID, a password shape (a capital, small letters and a run of digits inside letters, such as `Winter2026sgkr`), twelve or more hex digits, a high-entropy word, a word with a shell expansion in it (`P4ss$w0rd`, `${SECRET}`, `%TOKEN%`), a URL's user info, a git remote and an email address. A setting is not a package: a key that is, or ends in `_` plus, password, passwd, pwd, secret, token, apikey, api_key, auth, credential(s) or key (or `-` plus one of those but auth and key), that is no bundled-list name and no dependency of the project, and whose value is no version or constraint (`password==hunter2` in a pasted requirements block, `DB_PASSWORD=...`). A word that starts with `-` is an option. Inside a command, an option not on its manager's list is said only as the command not read whole ("an option this briefing does not read"): none of its words is offered or listed, and the level is at most `review_needed` (the "the word after <option>" entry is given only for a command of a tool the grammar does not read, such as `pipenv install --auth <value> x`); the value of a fixed-arity option on the list (`--workspace web`, `--features derive`) is read as a value and weighs nothing. Where such a word stands it is listed in `task_packages.not_read` by how the screen shows it, never by its value: "a setting named <key>", "the word after --auth", "a word with a shell expansion in it", "a word with a colon inside", "(user info withheld)", a token as its first four characters and its length. A withheld word weighs on the level only when it stands where a package stands (an install command's operand, a name the task takes from a registry named in its command, a name that could not be read whole): then the task is `review_needed` at least, and the reason says "if one is a package after all, call dependency_check on it"; a setting, an environment assignment or a credential in prose weighs nothing. A backtick is markdown, not an expansion, so a code span such as **`minimist@1.2.5`** is read as ordinary text, and a scoped npm name with capitals is no package name and is never lower-cased into one. 6.5.1 sent such a token to registry.npmjs.org or pypi.org and to api.osv.dev as a package name.
- A name put in `not_packages` that stands where a package stands (an install command's operand, a manifest entry), or that is one edit from a popular name, keeps the task at `review_needed` at least, with a reason that names it ("You said lodahs is not a package; it stands where a package name stands in the task's command: make sure nothing installs it").
- A package the task's own command takes from elsewhere by one of the listed spellings (an install command that names a registry, index, source, git or path option, or a registry setting in front of the command, such as `YARN_REGISTRY=...`) is not looked up, even when declared `public: true`: it is listed under `task_packages.private` and in `not_read`, and the task is `review_needed`. 6.5.1 looked such names up and sent the private registry's host name as a package ("npm.acme.internal (proceed)").
- A version in prose tied to no package ("pin it to 6.5.4", "support versions 1.2 and 2.0 of the config format") and words such as python or proxy hold nothing: with `packages: []` such a task can be `safe_to_delegate`.
- A word the caller lists in `not_packages` is the caller's statement and holds nothing by itself, wherever it stands. It keeps the level at `review_needed` only where the briefing itself read and reported it as a package: an operand of a command it reads, an entry of a snippet it reads, a name with a version written on it, or a near miss of a popular name ("you said lodahs is not a package; it is one edit from lodash: make sure nothing installs it"). The dismissal is compared after Unicode folding (NFKC, letter case, and with soft hyphens, zero-width characters, variation selectors and bidi marks removed, so full-width `ｚｑｘ`, or zqx with a soft hyphen inside, is `zqx`), by its bare name (`x@1.0.0`, `x==1`, `x[extra]`, `"x@1"`, and `@s/n@1` as `@s/n`) and by each ecosystem's own rule (PEP 503: `ZQX.fold` dismisses `zqx_fold`). Earlier builds of 6.6.0 also held a dismissed word that only stood after a package manager's name anywhere earlier in the task; that rule is gone. A number or null in `not_packages` refuses that entry only, as in `packages`, and a refused entry is named by its cause ("in not_packages that are not strings", "that are no word of the task", "past the 100-word limit").
- "A package manager's name", in every rule that names one, is one of this list (MANAGER_NAMES): npm, pnpm, yarn, bun, pip, pip3 (and pipX.Y), pipx, uv, poetry, cargo, go, npx, pnpx, bunx, uvx, deno, pipenv, pdm, rye, hatch, conda, mamba, micromamba, pixi, yarnpkg, cargo-binstall, easy_install, gem, bundle, composer, dotnet, nuget, brew, apt, apt-get, ni, nci, nr, nlx, corepack, volta, mise, asdf.
- A command of a tool the briefing does not read is said, and holds `review_needed`, in two cases, each only at a command position (the start of a line or a code span, after `;`, `&&`, `||` or `|`, after `$ ` or "Run", or after `xargs` and its options): `xargs` followed by a manager's name ("This task holds a command this briefing does not read (npm (through xargs)): check what it installs with dependency_check."), and a manager the grammar does not read (gem, bundle, composer, dotnet, nuget, brew, apt, apt-get, pipenv, pdm, rye, conda, mamba, micromamba, pixi) written bare and followed directly by its own install verb ("This task holds a command this briefing does not read (brew): check what it installs with dependency_check."). "Go add a test", "the npm package", "yarn lock", "go up", "use brew to set it up", "For the docs bundle, add hono", "a hidden gem: install dayjs", "Let it brew; install ky" and "users can brew install jq" are no command. A package of such a command is not listed as "NOT CHECKED: 1 more package".
- The near-miss check runs once per distinct word (it ran once per occurrence: 99.7 s of CPU for 199 KB of "require ("), on at most 4000 distinct words a call has not seen, and on none in the last 4 s of the call's budget; every snippet reader is one pass over the task. Measured, not promised: 2.19 s of child CPU at worst on the reviewers' sets, for tasks up to the 200,000-character limit. A task of 199,990 new lines now costs 0.2 to 0.4 s; earlier builds of 6.6.0 took 32.7 s, and 67.8 s with a `not_packages` word (no reader's multi-line pattern lets a blank run across lines now). The published 6.5.1 answered the same task offline in under 0.2 s. A call that runs out of its budget while reading says "This briefing did not finish reading the task within its time budget: split the task and ask for each part." (`review_needed` at least).
- A task with more than 100 names that may be packages, whichever reader found them, is `review_needed` (no longer counted as "1 more package"): "The task holds more than 100 names that may be packages, more than one call can declare: split the task into smaller ones."
- The tool description and the `task` argument ask for the request in the user's words: an agent is not to correct spellings or drop names, since a misspelt package name may be the finding.
- `what_should_i_know` sends no task text to an embedding provider: the recorded decisions and memories it returns, and its check for a conflict with a recorded decision, are ranked on this machine, and with a provider configured `wisdom_recall_note` says that the task text was not sent. 6.5.1 sent the task as written.
- A task is read in time that grows with its length (measured, as above): a word longer than any package name (300 characters) is not read, and a task is read for at most 100 packages (the rest are said NOT CHECKED). 6.5.1 took 89 s on a task of 199,000 characters.

### With the desktop app

- An app database that has not finished setting up (schema version 1, before the app's first migration) is never adopted as the server's own store: it is left byte-identical, the server runs on its own `standalone.db`, and the first answer (`_meta.database_note`), stderr and `--doctor` (a warning) say why. 6.5.1 took such a database for its own, wrote its tables and rows into it, and the five tools that need the app disappeared. An app database set up past that point is read as the app's even when 6.5.1 left its marker table in it.
- The app's dependency rows never lower a severity and never turn a copy the lockfile knows as runtime into dev: a scope the lockfile on disk states is kept, and where the lockfile does not say, only an app row that says runtime is used. 6.5.1 let a stale dev row lower severities, and `dependency_health` counted 3 vulnerable packages where the lockfile gives 6.
- `knowledge_gaps` judges a project's install by its lockfile on disk first, and uses the app's recorded version only where the disk has none for that project. 6.5.1 preferred the app's record.
- A time ahead of this machine's clock by more than 5 minutes is not read as fresh: a feed last fetched "in the future" is stale with the reason, the app's advisory data verified in the future has an unknown age and makes `app_plan_check` `not_comparable`, and a plan generated in the future makes one project's comparison `not_comparable` and the all-projects plan `stale`. 6.5.1 clamped such an age to 0.

### Data folder

- `FOURDA_DB_PATH` naming a database of this server's own format at a path other than its own `standalone.db` is not used, and nothing in it is changed: the server runs on its own store, and `_meta.database_note`, stderr and `--doctor` (a warning) say "Point FOURDA_DB_PATH at the 4DA desktop app's database, or unset it". 6.5.1 used it as its own store.
- `agent_memory` `store` asks a busy database once more before it answers "Failed to store memory: database is locked". The tool answers its own errors, so the server's one retry of a busy database, which acts on an error a tool throws, never saw a lock here: one such answer in 17,595 calls of the 6.5.1 concurrency run on a loaded machine. The quota count and the insert are one statement each, so a write that met a lock stored nothing and is safe to run again. A database still busy on the second try answers as before.
- A `cache.db` whose write lock another process holds no longer makes a tool fail: a statement that meets the lock runs again on an in-memory stand-in, the file is left alone for 30 s, and stderr says so once, with the file's name. A cache statement now waits 1 s for the lock (5 s in 6.5.1, each wait holding the server), an open 250 ms. In 6.5.1 every tool, the memory tools included, answered "database is locked" after about 11 s for as long as the lock lasted.
- A data folder the server cannot write to is found once per process, by creating and removing an empty file there (`.write-check-<pid>-<ms>.tmp`) and asking SQLite to create one (`.write-check-<pid>-<ms>.db`): the server's own store then answers "the data folder <dir> is not writable (<code>)" with the remedy, the cache stays in memory without trying the file, the dependency tools answer at their normal speed, and `--doctor`'s Data folder line fails with the same words. A folder made writable afterwards is used after a restart. 6.5.1 spent about 3 s on every call and answered "Failed to open 4DA database ... unable to open database file", and its `--doctor` passed the Data folder line.
- Several servers started together on a new data folder no longer answer "database is locked" and lose what a call was storing: SQLite refuses the switch to WAL mode at once while another server creates the file, and the open now retries it for up to 5 s, the wait every other statement already has; a lock that never goes is said plainly ("nothing was read or stored: call again"). This was in 6.5.1 too.

### Plugin hook and install

- The guard hook reads a `pnpm-workspace.yaml` override keyed by a selector (`"lodash@<4.17.21": 4.17.21`, what `pnpm audit --fix` writes) or a parent path (`express>lodash`) as the version of the package the key ends in, as it reads `pnpm.overrides` in `package.json`; the `>` of a range (`lodash@>=4.0.0 <4.17.21`) stays in the selector, in both files. 6.5.1 skipped such keys, so a version `dependency_check` had answered `avoid` for went ahead.
- It reads a `catalog:`, `catalogs:` or `overrides:` section with a comment after its key (`catalog: # shared versions`) or a quoted key (`"catalog":`), a catalog entry that is an `npm:` alias as the package and version it names, a file whose lines end in a lone CR (as YAML does), and a section after a byte order mark. 6.5.1 skipped the whole section.
- It reads Bun's catalogs in a workspace root's `package.json`: `workspaces.catalog`, `workspaces.catalogs.<name>`, and the top-level `catalog` and `catalogs.<name>` beside a `workspaces` field (a top-level `catalog` in a `package.json` with no `workspaces` is another tool's field and is not read). 6.5.1 read none of them. A byte order mark before the JSON no longer turns the file into one it could not parse.
- A `pnpm-workspace.yaml` that holds `{` or `}` on a line that is not a `#` comment line (an exact `{}` aside) is not read: an edit that changes any of its non-blank lines is held as could not be read, no verdict releases it, and the denial says how to make the file readable (each flow mapping as block lines, one `name: version` per line; a brace glob as separate entries; a brace in a trailing comment moved to a comment line of its own; any other brace taken out). A re-save, or a change of blank lines only, goes ahead. 6.5.1 did not read flow mappings and let a version in one go ahead.
- An override keyed by a selector, a parent path, a parent it is nested under, or an alias is judged as a target, but no longer counts as declaring that version for the whole tree, in `pnpm-workspace.yaml` and in `package.json` (`pnpm.overrides`, `overrides`, `resolutions`). With `"lodash@<4": 3.10.1` on disk, 6.5.1 let `"lodash": "3.10.1"` through elsewhere with no verdict; that edit is now judged on its own. A plain key still declares its version.
- The hook reads an install after npm's `--option false` (`npm --audit false install x@1`), after uv's global options (`uv -q pip install`), after pip's general options that take a value (`--cert`, `--client-cert`, `--exists-action`, `--use-feature`, `--use-deprecated`, `--resume-retries`) and after pnpm's `--prefix`, `--global-dir`, `--cache-dir` and `--state-dir`. 6.5.1 took the option's value for the command and let the install through.
- A `go get` of a path the ledger has no verdict for says that the path may be a package inside a module, that `dependency_check` reads modules and answers `unknown` for a package path, and to check the module that contains it and name the module in the command (`go get <module>@<version>`). A verdict for a module never releases a longer path. 6.5.1 said only that no verdict was recorded, which no call could change.
- The guard hook lets a command through only on positive evidence. A command goes ahead when no line of it holds a package manager's word (npm, pnpm, Yarn, Bun, pip or `python -m pip`, uv, Poetry, Cargo, Go) followed later on that line by one of its words that can add or move a dependency (install, add, up, update, upgrade, link, get, sync, lock, `npm pkg set`, `go mod edit`), read again with the shell's quote and escape characters taken out, continued lines joined. A line that holds one goes ahead only when every simple command in it that holds a hit is the text of a data program, or is read whole. A data program's words are text when its options are on its own short list, no setting for it stands in the call (only `GIT_AUTHOR_*`, `GIT_COMMITTER_*`, `TZ`, `LANG`, `LC_ALL`, `NO_COLOR`, `FORCE_COLOR` and `CI` may), and its output runs nowhere: echo, printf, cat, the grep family, rg, Select-String, findstr, Set-Content and Add-Content into a file that is no manifest or lockfile, `git commit` / `log` / `show` / `diff` / `status` / `grep` / `tag`, the text options of `gh pr`, `issue`, `release` and `gist`, `node -e` and `python -c` with nothing after the code and not fed from a pipe, and `docker` or `podman` `run` / `exec` / `build`; not sed, awk or make, which can run a command from their script or their line. Read whole means its program and prefixes known, beside a named package only options on that manager's allow list, and every operand one of: a public name with an exact version or a range, judged on its verdict; a name alone or `@latest`, judged on the verdict for `latest`; a requirements file named with `-r`; or a form that names no public release (a path, a local archive, git, a URL on a host that is private by its shape (localhost, a name with no dot, a name ending in .internal, .local, .lan, .corp, .home.arpa, .test, .example, .invalid or .localhost, or a loopback, private or link-local address)). One option that replaces the public index (`-i`, `--index-url`, `--default-index`, `--registry`, Cargo's `--index`), with nothing else naming a source and a host that is private by its shape (localhost, a name with no dot, a name ending in .internal, .local, .lan, .corp, .home.arpa, .test, .example, .invalid or .localhost, or a loopback, private or link-local address), lets the install go ahead unjudged as the project's own source; a package from any other host is judged on the ledger like a registry name, and the denial says how to mark a private name (`FOURDA_PRIVATE_PACKAGES`). 6.5.1 and earlier builds of this release took every host that is not a public registry as private, public mirrors included. 6.5.1 let a command through unless its reader found an install it could read: any `$`, backquote, backslash or heredoc left the whole command unread, and it went ahead.
- Held as not read, beside a named package: every option that is not on that manager's allow list. The list (`NAMED_OPTIONS` in the hook, one reason beside each entry) holds only options that cannot change which release is installed, where it is fetched from or which config is read: placement (`--save-dev`, `-g`, `-w`, `--prefix`), output, `--ignore-scripts`, `--dry-run`, and a few more such as npm's `--omit`, `--no-package-lock`, `--strict-peer-deps` and `--engine-strict`, Yarn's `--ignore-engines` and pip's `--no-cache-dir`, `--no-deps` and `--upgrade`. Everything else is held, an abbreviation (`--offl`) and an unlisted `--no-` form included, and the denial names the option alone ("Run the same command without the option `--before`; if that option takes a value, remove its value too"). Among the held: `--force`, `--package-lock-only`, `--require-hashes`, `go get -u` with a module, an option that can change which release is installed or where it is fetched from (npm, pnpm and Yarn `--offline` and `--prefer-offline`, `--frozen-lockfile`, Yarn's `--immutable` and `--cached`, pip's `--upgrade-strategy`, `--only-binary`, `--platform` and `--python-version`, uv's `--offline`, `--frozen`, `--locked` and `--python-version`, `cargo add --locked`, Go's `-mod`, and more), a constraints or overrides file (`-c`, `--constraint`, `--override`), and `--tag`, `--before`, `--pre`, `--resolution` and uv's `--upgrade` on `uv add`, `uv lock` and `uv sync`. Also held: a manager's own setting as a prefix or made earlier in the call (`npm_config_*`, `PIP_*`, `UV_*`, `POETRY_*`, `YARN_*`, `BUN_CONFIG*`, Cargo's registry and source settings, `GOPROXY`, `GOFLAGS`, `GOPRIVATE`, `GONOPROXY`, `GONOSUMDB`, `GOINSECURE`, `GOTOOLCHAIN`), operands a command reads from its input (`xargs`, `-r -`), an alias or a function defined beside a package manager's name, a blank or control character other than space, tab, CR and LF on an install line ("retype it with plain spaces"), a version spec outside its registry's grammar ("write an exact version"), a program, prefix or wrapper the hook does not read (`start`, `mise exec`, `gsudo`, `concurrently`, `git submodule foreach`), a data program with an option off its list or piped into anything else (`| sh`, `| python`), more than three wrappers deep, `sed`, `awk` and `make` with an install on their line, and a line the hook cannot take apart (a variable, a substitution, an escape, a PowerShell here-string, a PowerShell comma list or `--%`). The denial names the first part of the line it did not read, as written, and says "Run the same command without `<that>`" or "with `<that>` written as" the form it reads (an exact version or the name alone, a variable's value written out, an npm placement setting as its option); where no single part can be named (a heredoc, `xargs`) it says to run the install as a plain command of its own. It prints no command the user did not write. Ordinary commands that only mention an install (`echo`, `grep`, `git commit -m`, a heredoc into `tee`, `gh pr review --body`) go ahead.
- A command run through a shell's `-c`, `eval`, `pwsh -Command`, `Invoke-Expression`, `npx`, `bunx`, `pnpx`, `npm exec`, `pnpm exec` or `dlx`, `yarn exec`, `dlx` or `run`, `bun run` or `x`, `uv run`, `uv tool run` or `uvx`, `poetry run`, `pipenv`, `pdm`, `rye`, `pixi` or `hatch run`, `python -m uv` or `poetry`, `node <path>/npm-cli.js` or corepack is read as the command it runs, at most three wrappers deep, and so is one after a prefix (sudo, env, timeout, nice, nohup, time, command, exec, busybox, wsl), a shell keyword, or inside a subshell, a group or a script block. 6.5.1 read this list in part and let the rest through.
- An install that names a package without a version or with `@latest` (also as a version-less `npm:` alias), `pnpm up -L x`, Berry's `yarn up x`, `yarn upgrade x --latest` and a link of a registry name (`npm link x`) write the registry's newest release: each is held until `dependency_check` has answered for that package at `latest` (`to: "latest"`) in the last hour, and goes ahead on `proceed` or `review`. A tool installed from a registry is read as an add (`cargo install x`, `go install x@v`, `yarn global add x`, `uv tool install x`, `poetry self add x`), and so is a tool's own upgrade (`python -m pip install --upgrade pip`, `npm i -g npm`). A dist-tag other than `latest` (`x@next`) or a Go branch is held with "name the version": no call clears a tag. `pnpm up x` and `yarn upgrade x` without `--latest` stay inside the manifest's range and are not read. 6.5.1 let a package without a version through with no verdict, and `cargo install`, `go install`, `yarn global add`, `uv tool install` and `poetry self add` at any version.
- A package confirmed with `public: true` in a `what_should_i_know` call is recorded in the ledger as `dependency_check` records it, so its verdict releases or holds an install the same way; `public: false` records nothing and releases nothing, and the denial says so.
- Any call that names the check ledger (its file name or the data folder's path, normalised) is held unless it is one plain read command alone on its line: an Edit, MultiEdit, Write or NotebookEdit of it, a redirection, `tee`, `Set-Content`, `sed -i`, a copy, a move or a delete. Only the server writes it. The hook now also runs before NotebookEdit. 6.5.1 let an agent write the ledger it reads.
- The two ledger files are read as one snapshot (each stat'ed, read and stat'ed again, at most three times, as the server may be moving one over the other): a ledger still changing holds the call, and so does a ledger file that exists but cannot be read (EACCES, EPERM, a deny-read ACL). A package whose newest ledger line is cut short, dated ahead of the clock or not fully valid has an unknown verdict, so an older `proceed` for it does not let it through.
- When anything goes wrong while the hook reads a call (an error of its own, a worker that stops without an answer, the 5 s wall clock for a payload over 8 KB, a spent read budget), one rule decides on the raw text, where a ledger exists and the guard blocks: it holds every Bash and PowerShell call (the denial says the hook could not finish reading the command, and to run it in smaller parts), every Edit, MultiEdit, Write and NotebookEdit whose path names a manifest or the ledger or cannot be read, and a payload that does not parse; any other call goes ahead. A payload whose stdin is still open after 8 s is judged from the text that arrived when that parses whole, and held by that rule when it does not. 6.5.1 let through a payload that is not JSON, and a call it failed on that wrote no manifest and named no install in plain sight.
- On an Edit, MultiEdit or Write the path is resolved as text first, as Windows opens it (`\` read as `/`, empty and `.` parts dropped, `name/..` resolved, each part's trailing dots and blanks dropped, an NTFS stream suffix such as `::$DATA` taken off), and the file name is matched without regard to case on every platform, so `PACKAGE.JSON`, `Cargo.TOML`, `package.json::$DATA` and `package.json/.` are read as the manifests they are. 6.5.1 let `PACKAGE.JSON` and `package.json::$DATA` through.
- More manifest forms are read: Cargo root dotted keys and root inline dependency tables (also under `[target.'cfg(...)']` and `[workspace]`), the `[dev_dependencies]` and `[build_dependencies]` spellings, a `Cargo.toml` that starts with a byte order mark, a Poetry dependencies inline table, PEP 621 and PEP 735 tables and uv's inline tables, `project` as an inline table at the root, and a requirement continued with a backslash. A TOML escape or a multi-line string in a dependency context is held as not read. In a command, a requirement with more than eight version clauses, one whose extras are over 200 characters and a Poetry constraint whose clauses a blank separates are held as not read. `go install <path>@<version>` is read as `go get` is. 6.5.1 let each of these through without comment.
- `name@<URL>` is the URL: the public registry's own file form (an npm tarball, a PyPI wheel or sdist) is read as that name and version and judged; another form on a public registry host is held as not read; a URL on another host is held as a source the hook cannot judge until the name is recorded private, unless the host is private by its shape (localhost, a name with no dot, a name ending in .internal, .local, .lan, .corp, .home.arpa, .test, .example, .invalid or .localhost, or a loopback, private or link-local address). pip's `--extra-index-url`, `--find-links` and `--no-index` follow the one source rule: the named packages are judged on the ledger, and `--no-index` with only local files reads no index and goes ahead. PowerShell's typographic quotes are read as quotes. A redirection to a quoted target no longer leaves the line unread (`npm i x@1 > "out file.txt"` is judged).
- `FOURDA_GUARD=advise` never denies, the ledger guard included, and its advice after a manifest edit compares the whole file before and after, as a denial reads it: an Edit that changes only the version string is advised on.

### HTTP mode

- Only `localhost`, `::1` and an IPv4 address in 127.0.0.0/8 are loopback. `--host 127.evil.example` is a host name, so it now needs `MCP_AUTH_SECRET` and every request a token; 6.5.1 read any `--host` starting with `127.` as loopback and required no authentication there.
- Each token segment must be base64url (`A-Z`, `a-z`, `0-9`, `-`, `_`, no padding) and the signature its canonical spelling. 6.5.1 decoded junk after a valid signature away and accepted the token.
- A token whose header `alg` or `typ` is refused is logged with that value JSON-quoted and at most 40 characters long, so a newline in it cannot forge a line of the server's log; a value that is not a string is refused with 401. 6.5.1 printed the value raw before the signature was checked, and a header `{"alg":{"toString":1}}` answered 500.
- `--http` reads the version of the `@hono/node-server` copy that `@modelcontextprotocol/node` will load, and refuses to start when it is below 2.1.6 (every 1.x release and every 2.x release below 2.1.6 has a known advisory): the message names the version, says the folder the server was installed into already held that older copy and npm kept it, and gives the ways out (run the server with npx, or install `@hono/node-server@^2.1.6` in that folder). A fresh install resolves a clean release; nothing this package declares changes which copy is loaded where an older one is already installed. A version that cannot be read is not a refusal. The stdio server never loads it. 6.5.1 served HTTP through whatever copy the folder held.

### Setup and the command line

- `--setup` and `--setup --update` say which release each Claude Code `4da` server runs (user, local and project scope, and the 4DA plugin) and, for another release, print `claude mcp remove 4da -s <scope>` and the matching `claude mcp add`; a plugin user is told that the plugin provides the server and how it updates (a `claude plugin update` command only for plain plugin and marketplace names, Claude Code's `/plugin` menu otherwise), never to add a second server. Setup still edits none of Claude Code's files. 6.5.1 printed "Already configured" for any Claude Code `4da` entry, whatever release it pinned.
- A config that holds any key twice, at any depth, is left untouched, the key is named, and the exit code is 1. In 6.5.1 a duplicated `args` in the `4da` entry made `--update` rewrite the first copy while editors read the last, and setup printed "Written".
- A config that is a symbolic link is written where the link points, link by link, and created there when the file does not exist yet but its folder does (otherwise it is not written, and setup says why); a hard-linked config is written in place after its backup, so every name keeps the new content. Setup says which it did, and removes a `<config>.4da-<pid>.tmp` that a run stopped mid-write left, once that process is gone. 6.5.1 replaced a link to a file not made yet by a plain file with no backup, and gave a hard-linked config a new file.
- With no usable SQLite driver, the message gives each driver's whole cause, then one remedy in words: a Node.js line with the built-in driver (22.13 or later, 23.4 or later), or reinstalling the package with the Node.js that runs it. It prints no command that runs a third-party package. 6.5.1 told users to run `npx clear-npx-cache`, printed its remedy twice and cut the cause short.
- Below Node.js 22 the server stops before anything else loads, with "[4DA] Node.js 22 or newer is needed; this is Node.js <version>. Install Node.js 22.13 or later (its built-in SQLite driver needs nothing built), then start the server again." and exit code 1, when serving and for `--doctor`, `--setup` and `--http`; `--version` and `--help` still answer. 6.5.1 started and served on Node.js 20 with no word of its own (npm's engine warning is hidden by MCP clients).
- `--doctor` prints colour only on a terminal, and never with `NO_COLOR` set. A UTF-8 byte order mark before the first message on stdin is dropped (one, at the start of the stream only); in 6.5.1 it made `initialize` fail with -32700. `--help` names what `--doctor` checks.

### Performance

- `cargo tree` runs as a child process the server never waits on synchronously: a scan waits for it at most 5 s (less in a call with little time left) while other calls are answered, and without its answer every crate is counted and the scan says "Not platform-filtered". A `cargo tree` stopped at that bound keeps new ones from starting for a minute (each would wait on the same lock), and closing stdin ends it at once. 6.5.1 ran it synchronously for up to 30 s while another cargo held the package cache, and every call of the server waited.
- Each `package-lock.json` is parsed once per resolution, and every pass over a lockfile's entries pauses every 2,048 entries, so other calls are answered while very large lockfiles are read; the directories of a dependency's sources are judged once each. A tool call waits for the project's first read no longer than its own time budget: past it the call answers "NOT CHECKED: this project's lockfiles (<size> of lockfiles in <n> projects) were still being read when this call's 20 s ran out ... call again in a minute", and the read goes on. In 6.5.1 the first call on 20 lockfiles of 62 MB took over a minute.

### Tests and gates

- A CI run whose only failures are jobs that never got a runner (cancelled with no runner and no step, in practice macOS install smokes: three times on 2026-11-24) is run again by `rerun-unstarted.yml`, at most twice; a job that ran a step and failed is left for a person. The release workflow's "CI passed on the tagged commit" check now looks again for two minutes before it believes a failure, so such a re-run no longer stops a release.
- The guard hook's timing rows are judged on the hook's own CPU time when the wall clock is over its bound: a row passes inside 500 ms of wall clock (1,000 ms for the two rows that read 8 MB of ledger), or with the hook's CPU time inside twice that. The wall-clock bound failed twice on loaded CI runners with nothing wrong in the hook (1,095 ms, then 1,418 ms, against 1,000), the second time through a bound scaled by how long a trivial call took at that moment. With 32 busy processes on 16 cores a ledger row went from 390 ms to 4,600 ms of wall clock and from 450 ms to 660 ms of CPU time; all 91 tests of that file passed under that load, and failed when the hook was made to burn 2.5 s. The inputs these rows were written for took 1.5 s to 21 s.

### Changed behaviour

- `what_should_i_know` called without `packages` answers `confirmation_needed` (or `human_only`), never `safe_to_delegate`, and a name it does not look up waits in `task_packages.to_confirm` instead of being looked up by the briefing. In 6.5.1 "npm install lodahs" was looked up by the briefing itself and answered `human_only`; now the first call answers `confirmation_needed` with lodahs in `to_confirm`, and the call that declares it `public: true` checks it and answers `human_only`. A caller that stops at the first answer, or reads `review_needed` as the worst level short of `human_only`, must follow `task_packages.next_step` and handle `confirmation_needed`. A private dependency of one ecosystem is no longer looked up under another manager's name. crossenv, event-stream and node-ipc, names with a known malicious release, are still looked up and judged on a bare call.
- A dependency the project has that its own public registry does not know (a private package with no registry configuration) is no longer looked up on the other ecosystems' registries when a task names it. In 6.5.1, with `zqx_tools` in `requirements.txt` and pypi.org answering not found, "add zqx_tools", "use zqx_tools for parsing" and "npm install zqx_tools" sent `zqx_tools` to registry.npmjs.org and crates.io as well; now nothing is looked up in an ecosystem other than the one that let the name through. Set `FOURDA_PRIVATE_PACKAGES` to keep such a name from its own registry too.
- More answers say NOT CHECKED: `dependency_check` for an item whose clean OSV.dev batch answer the package's own advisory list could not confirm, and when no item could be checked; `vulnerability_scan` with a lockfile read only in part (older than its manifest, cut short, entries skipped), a refused include or a conflicting lockfile, which now leads the answer with `total_vulnerable_packages` and `by_severity` null and the counts under `found_in_checked_dependencies`; `dependency_health`, which withholds its score there (`healthScore: null`, `withheldReason: "lockfile_partial"`); the briefing, the plan and the health answer after a directory walk that was cut short; and `upgrade_planner` with `project_path: "*"` and no readable app plan (`vulnerabilityDataAvailable: false`, `allProjects.covered: false`). Lockfiles older than their manifest are now found for Ruby, PHP, Pipfile, Poetry and PDM, so projects that read as complete in 6.5.1 can now read as PARTIAL.
- `upgrade_planner` gives words instead of a command, leaves the step out of `run_order` and does not count the row as fixed in more cases: a check before the step that could not finish, a `cargo add` whose old and new lines link one native library, a uv target that requires the project itself at another version, a uv pin that installs an affected release on the project's lowest supported Python, a Yarn Berry dependency or optional dependency that is also a peer, a pnpm or Berry copy another package keeps that the refresh cannot reach, and a target that clears none of the row's advisories. A plan that 6.5.1 offered as one script can now leave more of the work as named hand steps. Its uv upgrades of one lockfile are one `uv lock`, and `cargo --precise` steps can carry a pre-update joined with `&&`.
- `dependency_check` refuses, with `not_checked: "input"` and nothing sent: a PyPI, crates.io or Go package that is no name its registry can have (a path, a URL, a git source, a requirement line); `name[extras]` for PyPI; `name@version` as an npm package (the version goes in `to`); and an item with a field other than `ecosystem`, `package`, `to` and `from`. 6.5.1 looked the first three up and ignored the extra field.
- `dependency_check`'s `_meta.osv_cached` is true far more often on a warm cache (an advisory list is kept 6 hours), and an item can carry `advisory_data_age_minutes`; a Go module path with upper-case letters can now be `review` (`module_path_case`) or `unknown` where 6.5.1 said `proceed`.
- A directory whose name holds a character a shell reads as code gets words instead of commands, in `upgrade_planner` (`commands`, `run_order`, `dir`) and in `vulnerability_scan`'s fix commands. The refused characters are `$`, the backquote, `"`, `'`, the curly quotes U+2018 to U+201F, `\`, `%`, `!`, `;`, `&`, `|`, `<`, `>`, `(`, `)`, `{`, `}`, `*`, `?`, `[`, `]`, `^`, `:` after a drive letter, control, format and invisible characters, and any space other than U+0020; `-`, a Unicode dash, `~` and `#` at the start; and a bare `@name`. A project under `Program Files (x86)`, `web (old)` or `web[1]` now gets no command for that directory.
- `FOURDA_DB_PATH` naming a database of this server's own format at a path other than its own `standalone.db` is no longer used: the server runs on its own store, with a note. Point it at the desktop app's database, or unset it.
- The desktop app's dependency rows no longer lower a severity or mark a copy dev that the lockfile on disk does not; scores and vulnerable counts that the app's rows lowered in 6.5.1 go back up to what the lockfile says.
- The guard hook holds every change to a `pnpm-workspace.yaml` in which any line is not plain (a `key:` header, a `- 'entry'` item, or `key: value` with a plain or simply quoted value), a quote-style or comment change included, until the file is rewritten as plain `name: version` lines, and a change under a top-level key that is neither read (catalog, catalogs, overrides, packageExtensions, configDependencies) nor known to install nothing; it now reads pnpm's `packageExtensions` (in `pnpm-workspace.yaml` and in `package.json`) as declarations, selector and parent-path overrides, catalog sections after a comment or under a quoted key, `npm:` alias entries and Bun catalogs beside `workspaces`, so a version in those places now needs a verdict; a selector, parent-path, nested or alias override (in `package.json` as well) no longer counts as declaring the version elsewhere; and a `go get` of a package path is denied with the advice to name its module.
- The guard hook holds what it cannot read whole where 6.5.1 let it through: `cd "$HOME/app" && npm i x@1` (the denial says to write `$HOME` out), `npm i x@1 --before 2020-01-01` ("Run the same command without the option `--before`; if that option takes a value, remove its value too"), `npm_config_registry=... npm i x@1`, `echo x | xargs npm i`, `sed`, `awk` or `make` with an install on their line, a PowerShell comma list. It holds a package named without a version, a tool install from a registry and a tool's own upgrade until there is a verdict for `latest` or the version named. It holds every Bash and PowerShell call, and every edit of a manifest or the ledger, when it fails or runs out of time, and a payload that does not parse. It holds any call that names the check ledger, other than one plain read command. Each denial says what to do. `FOURDA_GUARD=advise` still never denies. Beside a server older than 6.5.0, which starts no ledger, only a call that names the check ledger is held.
- HTTP mode: a `--host` that is a name starting with `127.` is no longer loopback, so it is refused without `MCP_AUTH_SECRET` and requires a token on every request; a token with any character outside base64url in a segment, padding included, or a non-canonical signature is refused with 401.
- `--http` refuses to start beside an `@hono/node-server` below 2.1.6 (see HTTP mode), and below Node.js 22 the server does not start at all.
- `--setup` exits 1 and writes nothing to a config that holds any key twice, where 6.5.1 wrote it with exit 0 (or printed "Written" while editors kept the old pin); a symbolically linked config is now written where the link points.
- A cache statement waits 1 s for another process's lock (5 s in 6.5.1), then the cache runs in memory for 30 s; a data folder found unwritable stays so until the server restarts; a `cargo tree` slower than 5 s means no platform filter on that scan ("Not platform-filtered"), and no new `cargo tree` for a minute after one is stopped at that bound; and a first call on a project whose lockfiles are still being read can answer the still-reading NOT CHECKED error (`isError`) instead of waiting past its budget.

### Known limits

- A version changed only in the manifest while the lockfile still holds the old one is not detected, in any format: `package.json` declaring `"ms": "2.1.3"` beside a `package-lock.json` that installs 2.1.2 scans 2.1.2 as complete, and so does a `Pipfile` pin beside an older `Pipfile.lock`. A dependency added to the manifest is detected; reinstall after editing a version by hand.
- A transitive package dropped from a `Pipfile.lock` cannot be detected: the file records no dependency graph, so a lock that lists `requests` without what `requests` needs reads as complete.
- The briefing reads commands of npm, pnpm, yarn, bun, pip, pipx, uv, poetry, cargo and go in English task text, by the grammar above; a command with an option off its manager's list is said not read whole (`review_needed` at most). A command of pipenv, pdm, rye, hatch, conda, mamba or pixi is named as a package manager the briefing does not read, and `xargs` before a manager or such a manager with its own install verb (`gem install`, `brew install`, `apt-get install`) is said as a command the briefing does not read (`review_needed` at most); what any of them installs is covered only by your declaration, and a listed name with no install verb after it (`ni x`, `nci`, "use brew") holds nothing. The cost: a task that writes such a command at a command position, even as advice ("run brew install jq first"), holds `review_needed`; written in the middle of a sentence ("users can brew install jq") it holds nothing. A word after "and" in an adding verb's list is a prose candidate ("Add zod and ship on Friday" offers ship, so that "add zod and valibot" offers valibot); putting it in `not_packages` settles it.
- The briefing reads candidate names from the task text in their plain forms only (commands the grammar reads, manifest snippets, a word after an adding verb), and in English. It does not read a package a task only bumps or swaps out when the project does not have it ("bump typescript to 5.6" in a project without typescript; moment in "swap moment for dayjs"), nor a noun after a preposition ("set up tests with jsdom"): such a package is covered only by the caller's declaration, which is why a call without `packages` never ends complete.
- A word in `to_confirm` is whatever the task wrote where a package name would be: a credential that looks like an ordinary word (a bare operand such as `npm install lodash pwzqx234 typescript`, or "add Zqx2026! as the admin password", which offers zqx2026) can be listed there, since the briefing cannot tell it from a package name. Nothing about it is sent unless the caller declares it `public: true`; `caution` marks a word the task calls a key, a secret, a password or a token, and it is a help, never a gate.
- A setting is read as a package name, and offered in `to_confirm` (by its name, with no version), when its value is shaped like a version (`db_password==88419273`) or its name does not end in one of the listed words (`db_pass==4417`). It is never looked up unless the caller declares it `public: true`.
- A private registry named in prose rather than by a source word the briefing reads ("point npm at https://npm.acme.internal") is not read as one: declaring a package of the task `public: true` sends its name to the public registry. Declare such a package `public: false`.
- Marking an installed dependency `public: false`, or listing it in `not_packages`, keeps the briefing from looking it up for the task; this project's own vulnerability scan, which every dependency tool runs, still sends that installed dependency's name, as for every package no private rule covers. To keep it off the public registries, name it in `FOURDA_PRIVATE_PACKAGES` or configure its private registry (an `.npmrc` scope, a pip index, `GOPRIVATE`). For a name the project does not have installed, `public: false` and `not_packages` keep it from being sent by any tool of this server.
- The guard hook reads a `pnpm-workspace.yaml` only when every line of it is plain. A file with a value that carries an anchor (`lodash: &v 4.17.20`) or a tag (`lodash: !!str 4.17.20`), a value on the line after its key, a block scalar (`lodash: >-`), a merge key (`<<: *base`), an explicit key (`? lodash`) or an unquoted `{` or `}` is held on every change, a change of quote style or of a comment line included, until it is rewritten as plain `name: version` lines. A declaration that bounds nothing by its meaning (`*`, `""`, `x`, `x.x`, `*.*`, `=*`, `^*`, `v*`, any `||` alternative that is empty or only wildcards, a name alone in a requirements file or a pyproject array, the same wildcards in Poetry and in every Cargo form (`"x"`, `{ version = "x" }`, `[dependencies.x]`, target and workspace tables)) needs an answer for `latest`; a dist-tag other than `latest` is held until it names a version. The ledger guard names the ledger file and the data folder it is in, not a folder above it. `package.yaml` and `package.json5`, which pnpm reads as manifests, are held with the advice to write the manifest as `package.json`, whatever their spelling (`package.yaml::$DATA`, a trailing dot or space); a NotebookEdit of any manifest is held with the advice to use Edit or Write. A `go.work` is read for its `replace` directives as `go.mod` is. A URL dependency in any manifest (a `package.json` value, `name @ URL` in any pyproject array or a requirements file, a `[tool.uv.sources]` or Poetry `url`) follows one rule: a public registry's own file is read as that name and version and judged, a host private by its shape goes ahead, and any other host is held as a source the hook cannot judge until the name is recorded private. In `go.mod` and `go.work`, `latest` needs an answer for latest, and a branch, `upgrade`, `patch` or a comparison is held until the exact version is named. A range of exclusions only (`!=1.0`) counts as latest. Index, registry and source options follow one rule: exactly one option that replaces the public index (`--registry`, `-i`, `--index-url`, `--default-index`, Cargo's `--index`) on a host private by its shape (localhost, a name with no dot, a name ending in .internal, .local, .lan, .corp, .home.arpa, .test, .example, .invalid or .localhost, or a loopback, private or link-local address) goes ahead unjudged as the project's own source; `--no-index` with only local or private `--find-links` goes ahead (no index is read); in every other case and combination (`--extra-index-url`, uv's `--index`, two sources, a registry on any other host) the named packages are judged on the ledger: a proceed or review for the release named, or a private record, lets the install through, and the denial says how to mark a private name (`FOURDA_PRIVATE_PACKAGES`). A denial for such an option never says to leave it out. A URL operand follows the same URL rule as a manifest value, whatever stands before it (`name@URL`, `alias@npm:URL`, `name @ URL`): a registry's own file (any letter case, with or without the default port, a percent-encoded scope, a query or fragment) is that name and version and is judged; a git or `file:` URL, or a host private by its shape, goes ahead; any other URL is held. An archive is local only when it has no scheme. A `file:` location in `--find-links` or an index option is local. A UNC path (`//host/share`, `\hostshare`) or a `file://host/` URL follows the host rule. Overrides, resolutions, catalogs, `[patch]` and workspace pins in the project can make the manager install another release than the one the command names; the hook judges those entries when they are edited, not when a command meets them. After a Bash or PowerShell command in which a package manager ran an install, add, update, sync or ci, package named or not (`npm ci`, `pnpm install --frozen-lockfile`, `yarn`, `pip install -r`, `uv sync`, `poetry install`, `cargo fetch`, `cargo build` / `b`, `cargo run` / `r`, `cargo test` / `t`, `go mod download`), also when npx, bunx or pnpx runs the manager, with or without a version (`npx pnpm@9 install`), and after `npm`, `pnpm`, `yarn` or `bun link`, the hook adds one line of advice, never a denial: "The package manager decides the releases actually installed. Run vulnerability_scan to check them."
- A package named without a version is judged at the registry's newest release. As a further guard, with npm, pnpm, Yarn, Bun, `uv add`, `poetry add` and `cargo add` a name alone is held, with the version to name in the manager's syntax (`x@1.2.3`, `x==1.2.3`), when the hook sees a reason the manager may pick another release: a change of folder before it that the hook does not follow (popd, `cd ~`, `cd -`, a folder that does not exist, a cd after `&&` or `||` or in a pipeline, a drive change, a wrapper or prefix with a directory option such as `pwsh -WorkingDirectory`, `pnpm -C … exec`, `uv --directory … run`, `env -C`, or a directory option given twice); a workspace option (`-w`, `--workspace`, `--filter`, `-F`, `-r`, `-p`, `--package`, `yarn workspace`); a workspace root at that folder or up to 12 above (`pnpm-workspace.yaml`, `lerna.json`, `nx.json`, `rush.json`, a `package.json` with `workspaces`, a `pyproject.toml` or `Cargo.toml` that mentions `workspace`, a `go.work`); or a project file there or above that mentions the name. The same guard holds a range (`x@^1`, `'x>=2'`), with "name the exact version". So every name alone inside a workspace is held until the version is named. This guard is not a guarantee: see the limits below. `bun update x` is read as an add of x. With npm, pnpm, Yarn and Bun, `x@latest` is judged at the newest release even beside a declared version, which those managers replace. Not checked: a range is judged as the release its verdict was recorded for; a lockfile or an installed copy that already holds another release in that range is kept by pnpm, Bun, uv, Cargo and pip (npm and Yarn 1 moved to the newest): that release is not checked. Name the exact version, or run `vulnerability_scan` after the install (the advice line says so); and a name alone can install a release the project already pins where the hook does not look: a folder reached in a way it does not follow (a wrapper's directory option it does not know, a cd that did not run, a directory set in config, a function, alias or script), a workspace root it does not recognise, a sibling member, a lockfile; the manager then keeps or reuses that release. A name alone judged at the newest may also install a release published after the verdict was recorded (within the hour a `latest` verdict is honoured), which is not checked; it may also install the newest that fits this Node, Python or Rust (`engines`, `requires-python`, `rust-version`), the release `latest` names when it is not the highest, or the copy pip finds installed. After an install the advice line recognises, it says to run `vulnerability_scan`, which reads the releases actually installed. Not seen either: a change of folder the hook cannot see: a shell function or alias named `cd`, a profile or a script sourced in an earlier call, a PowerShell script or function that calls Set-Location; and settings and pins in files it does not read (`.npmrc`, `.yarnrc.yml`, `bunfig.toml`, `.pnpmfile.cjs`, `pip.conf`, `uv.toml`, `Pipfile`, `deno.json`, `requirements.in`, `constraints.txt`). The hook's allow lists of options are lists, not proofs: each option was tested not to change the named release in the tool versions tested.
- The guard hook is a guard-rail against an agent's mistakes and shortcuts, not a sandbox: an agent that sets out to defeat it can (a script file that runs the install, a variable, a path that reaches the data folder through `cd`, `pushd` or `Set-Location` in an earlier call, a junction or symbolic link made earlier, a name the shell assembles from pieces, a wildcard). It reads no network: a registry host it cannot classify is not looked up; a package from it is judged on the ledger like a registry name (a proceed, review or private record lets it through). Removing the ledger turns every denial but the ledger guard's off until the server starts again.
- Not read or not judged by the hook, so each goes ahead: commands that let the manager choose versions without naming a package (`npm audit fix`, also with `--force`; `pnpm audit --fix`; `npm update`, `pnpm up` and `yarn upgrade` with or without a name (measured: a name the project does not declare is not added), `bun update` with no name (`bun update x` is read as an add of x); `cargo update`, `cargo upgrade`, `cargo install-update`, `poetry update`, `uv tool upgrade`, `go mod tidy`, `go get` with no module, `go get -u ./...`), after which run `vulnerability_scan`; a manifest, requirements file or lockfile changed by a shell command (a redirection, `sed -i`, `tee`, a script) rather than the Edit, MultiEdit or Write tool, so `echo x==1 > r.txt && pip install -r r.txt` goes ahead; a registry or index on a host that is private by its shape (localhost, a name with no dot, a name ending in .internal, .local, .lan, .corp, .home.arpa, .test, .example, .invalid or .localhost, or a loopback, private or link-local address), named by exactly one option that replaces the public index, which is taken as the project's own source and not judged; installs through pipenv, pdm, rye, pixi, hatch and conda, `pipx inject`, gem, composer and dotnet, and commands run inside a container; a program or script that runs an install (a make target, `npm run x`, `pwsh -File`, code given to `node -e` or `python -c`); a manager name the shell assembles or decodes (`$'\x6epm'`, `powershell -EncodedCommand`).
- Runners that fetch a package and run it are not checked: `npx pkg@v`, `pnpx pkg`, `npm exec` / `npm x pkg`, `pnpm dlx pkg`, `yarn dlx pkg`, `bunx pkg`, `bun x pkg`, `uvx pkg`, `uv tool run pkg`, `uv run --with pkg`, `pipx run`, `npm init`, `npm create`, `yarn create`, `pnpm create`, `bun create`, `go run mod@v` and `cargo binstall`. A runner that runs a package manager (`npx pnpm add x@1`) is read as the command it runs. `what_should_i_know` says such a runner command is not read whole: it offers none of its words and the level is at most `review_needed`.
- Settings that change what a name resolves to are not read when they live in files (`.npmrc`, `pip.conf`, `uv.toml` or pyproject's `[tool.uv]`, a lockfile written by hand and then installed with `npm ci`), when a manager's own config-writing verb writes them before an install in the same call (`npm`, `pnpm`, `yarn` or `pip config set`, `poetry config`, `poetry source add`, `go env -w`, `git config url.<x>.insteadOf`), or when a variable outside the managers' own names points a manager at other config files (`HOME`, `USERPROFILE`, `XDG_CONFIG_HOME`, `APPDATA`, `CARGO_HOME`, `GOENV`), and Go's checksum settings before `go get` (`GOSUMDB`, `GONOSUMCHECK`): an install under them is read as if they were not there. A manager's own setting before the install (`npm_config_*`, `PIP_*`, `UV_*`, `GOPROXY` and the rest) is held.
- A hook payload over 8 MB that does not parse, or one over 64 MB, is not read whole and is held like a failure of the hook: every Bash and PowerShell call, every manifest edit, and any payload whose tool cannot be found in its first 64 KB. A pip requirement with more than eight version clauses goes ahead unread in a `pyproject.toml` array and is judged on its first eight clauses in a requirements file; one whose extras are over 200 characters is read as naming no version in a requirements file.
- The plan cannot promise what the package manager's resolver picks for the copies no step names, and `yarn up -R` and pnpm's `-r` refresh move every copy of that name. On a project whose lowest supported Python excludes a dependency's clean release, the plan holds the upgrade and says what would unlock it. uv's universal resolve can pick a different release for a higher Python than the one the plan checked. Check each step's result before running the next (its `if_it_fails` says how to put back what it changed), and scan again after the run, as `after_run` says.
- One very large `package-lock.json` is still parsed in one step, during which the server answers nothing else, and one OSV.dev batch request can be sent a second time in a call, after a 500 or a closed connection.
- `--setup` reads whether the 4DA plugin is disabled in the user settings only; a project's own settings, and the local-scope entries of other projects, are not read.

## 6.5.1 — 2026-11-24

### What is scanned

- A `package-lock.json` or `npm-shrinkwrap.json` with no entry for a dependency `package.json` declares (written before that dependency was added, the usual state after `package.json` is edited by hand) is read as a partial lockfile, as pnpm, Yarn and Bun lockfiles already were. 6.5.0 called such a project complete in every tool: `dependency_health` "Health: 100/100 ... all healthy", `vulnerability_scan` `coverage.complete: true`, `upgrade_planner` `vulnerabilityDataAvailable: true`, and the missing dependency was checked by none of them. Now the lockfile is listed under `coverage.partial_lockfiles` with the names it lacks, the health score is for the checked part only and says so (`scoreCoverage`, "over the checked part only"), and the plan says NOT CHECKED. A peerDependency and a `link:` / `portal:` / `workspace:` dependency are owed no entry. A `file:` dependency is owed one (npm writes a link entry for a directory and a `resolved: file:` entry for an archive), so a lockfile without it is listed as partial too.
- An npm dependency that is not a registry release is never looked up by its name, in any tool. Specs are read as npm reads them (npm-package-arg's order): `file:`, `link:`, `workspace:` and `portal:`; a bare relative, home or absolute path (`../libs/x`, `./libs/x`, `~/x`, `/opt/x`, `C:\x`); a tarball file (`vendor/x-1.0.0.tgz`, `x-1.0.0.tgz`); GitHub shorthand (`org/repo`, `org/repo#ref`) and every other git spelling; a URL, unless it is the public npm registry's tarball of that same package; and any other protocol (`jsr:`). So is a name the lockfile installs only as a link (a workspace member, `link: true`), from git, a URL or a local archive whatever spec `package.json` gives it, and a workspace member's own name (npm, pnpm, Yarn and Bun). Membership is read from the enclosing workspace root's manifests (`workspaces`, `pnpm-workspace.yaml`, a Cargo `[workspace]`) whether or not a lockfile exists, inside the git repository and never at or above the home directory: started in a member with no lockfile, or asked about a member's path, 6.5.0 sent the sibling members' names, and a crate the member inherits with `{ workspace = true }` from a root path entry went to index.crates.io. `dependency_health` and `upgrade_planner` made a registry row for every declared dependency, so these names went to registry.npmjs.org and api.npmjs.org, and through `ecosystem_pulse` to hn.algolia.com; `dependency_check`, `upgrade_impact` and `what_should_i_know` looked them up when asked. Now they get no registry row, `dependency_check` answers them `unknown` with `not_checked: "private"` and the file and spec that make them so, `upgrade_impact` refuses them, the briefing and the pulse never send them; what they install is listed under `coverage.not_checkable` as before. So is a dependency an override forces to such a source: npm `overrides` (the nested form included), Yarn `resolutions`, `pnpm.overrides` and the `overrides:` of `pnpm-workspace.yaml` (with no lockfile, 6.5.0 sent a `^1.0.0` dependency overridden to `file:`, `portal:` or `link:`). A registry copy of the same name elsewhere in the tree is still checked. Python: a requirement installed from a local path (`-e ./libs/x`, `./libs/x`, a local wheel or archive, the same inside an `-r` include) is withheld when asked about directly (6.5.0 looked it up on pypi.org and OSV), a bare URL line is no longer read as a package named `https` (nor `vendor/x.whl` as `vendor`), and a git checkout or archive on a public code host (`requests @ git+https://github.com/...`, a `[tool.uv.sources]` git entry, a uv.lock git source) is not taken for the PyPI release of its name: it gets no registry row and is withheld, as it was only for private hosts. Also withheld: Cargo dotted keys, a quoted crate name included (`"x".path = ...`), read as the inline table they spell (`name.workspace = true` was read as a crate named `name.workspace`, and `name.path` / `name.git` were not read), a uv `{ workspace = true }` source, a Python project's own `[project]` or Poetry name, an npm workspace member linked by a symlink or junction, and a member's own name asked about at a workspace root that has no dependencies and no lockfile; a server started in a folder with no manifest below a project, below a folder that holds `.git` (a `.git` file counts; `GIT_DIR` is not read) (`src/lib`, `crates/a/src/bin`; at most three levels, never above that folder) reads that project, where nothing was known before, so the first call there does that project's scan; with no `.git` above it, nothing above the start folder is read, as in 6.5.0. A Cargo dependency renamed with `package =` from a path, git or another registry withholds its key as well as its package name (6.5.0 sent the key to index.crates.io and hn.algolia.com). Such a name (and a Cargo `path`/`git` crate, a go.work module, a Python local package or git checkout) is also withheld when another project is asked about it (6.5.0 sent it when another project's briefing or `dependency_check` named it), but only while a scanned project still declares it so (the list is read again with the dependency set), and never in a project that itself declares the name as a registry dependency, with or without a lockfile. An alias key is withheld only inside the project that aliases it. Such an answer says `NOT CHECKED (not a registry release)` and where the name comes from; it does not call it a private package or point at private-registry tooling. In the project whose `package.json` declares an `npm:` alias only the target is sent, never the key it is installed under, whatever the lockfile (in another project the same word is an ordinary package name and is looked up as one): the key is mapped to its target from `package.json` itself (with a pnpm, Yarn or Bun lockfile 6.5.0 sent the key to registry.npmjs.org, api.npmjs.org and hn.algolia.com and gave it a row of its own), and `dependency_check`, `upgrade_impact` and the briefing asked about the key, in any letter case, answer it not checked and name the target to ask about. Still checked as registry releases: versions, ranges (`^1.2.3`, `1.x`, `>=1 <2`, `*`, an empty spec), dist-tags (`latest`, `next`: npm installs the registry's release under that tag), Yarn's `npm:<range>` and a `patch:` of a registry release. Inside `patch:` Yarn's rule applies: `patch:lodash@npm%3A4.17.21#...` patches lodash 4.17.21, `npm:other@1` is other's, and a patch of a path, git or a URL is withheld as that source is. `npm:<x>` with no `@<range>` is a package named x to npm and the key's own release to Yarn, so: when the whole of x is a semver range no package could be named (`^1.2.0`, `>=1 <2`, `^1 || ^2`) or a full version (`"ms": "npm:2.1.3"`), it is the key's own release; when x is a package name and no range (`npm:v8-compile-cache`, `npm:7zip-bin`), it is an alias to x and the key is never sent; when x is the key itself (`"next": "npm:next"`), npm and Yarn agree and it is that package from the registry; when x is both a range and a name (`npm:1`, `npm:1.x`, `npm:2048`, `npm:x`) or a common dist-tag (`npm:latest`), it is withheld, since which one is meant depends on the package manager, unless a `package-lock.json` records which package it installed, and the answer names both readings (`NOT CHECKED (ambiguous npm: spec)`). An alias npm refuses to install (an alias of an alias such as `npm:npm:x@1`, `npm:x@<a URL>`, `npm:x@patch:...`, `npm:x-1.0.0.tgz`, an empty `npm:`) is withheld under its key, as is a dependency an override replaces with an alias; the package named inside a URL or `patch:` alias, or in a spec with whitespace around it, is withheld too (npm does not trim a spec, so ` npm:x@1` is not an alias to npm); for `npm:npm:x@1` and `npm:x-1.0.0.tgz`, x is looked up if asked about directly; and an alias whose range npm cannot read (`npm:x@=~7`, `npm:x@1.0.0 junk`) is read as an alias to x, and x is sent like any alias target. A `catalog:` dependency is what its catalog entry says, read from `pnpm-workspace.yaml` (`catalog` and `catalogs.<name>`, in the project or the nearest directory above it that has one) or Bun's root `package.json` (`catalog` / `catalogs`, top level or under `workspaces`): an entry that is a path, `link:`, `workspace:`, git or a URL is withheld like the same spec in `package.json`, a registry range is checked with the catalog's range as the declared range, and an entry that cannot be found, or a catalog that cannot be read (one that repeats a key, which pnpm refuses, included; YAML anchors and aliases are read in file order, and an alias before its anchor, an alias to an anchor defined twice, or `catalog` given together with `catalogs.default` makes the catalog unreadable rather than guessed at (an anchor defined twice that no entry uses is harmless)), withholds the name, names the catalog file and why under `unreadable_lockfiles`, makes `coverage.complete` false and the plan NOT CHECKED, and is answered "declared through a catalog that could not be read", never as private (6.5.0 sent `"x": "catalog:"` with `x: link:../x` in the catalog to registry.npmjs.org, api.npmjs.org, api.osv.dev and hn.algolia.com). An edit to the catalog file is read on the next call.
- A dependency added to or removed from a manifest while the server runs is a row, or is gone, on the next call. When a file changed, the dependency set was read again with the dependency names read at startup: the versions and the advisory set followed the files, the direct dependencies did not. In 6.5.0, `package.json` with `ms` and no lockfile, then `lodash` added: `vulnerability_scan` scanned 2 pins while `dependency_health` listed `ms` alone (`totalDeps: 1`) on every call until a restart, and a removed dependency stayed a row. It held for every ecosystem (`package.json` with or without a lockfile, `Cargo.toml`, requirements files, `pyproject.toml`, `go.mod`) and for every tool that reads the direct dependencies: `dependency_health`, `upgrade_planner`, `upgrade_impact`, `what_should_i_know`, `get_context`, `knowledge_gaps`, `ecosystem_pulse` and `dependency_check`'s installed versions. `dependency_check`, `get_context`, `knowledge_gaps` and `ecosystem_pulse` now also re-read a changed set before they answer; they never did, and answered from whatever set the last tool had read. That includes a manifest edited beside a lockfile that was read (`package-lock.json`, `Cargo.lock` and the rest): the added dependency is a row and the lockfile is listed as partial, a removed one is gone; and a manifest or requirements file created while the server runs. Editing anything else in `package.json` (a script) re-resolves nothing. An unchanged project is still only checked with file stat calls, and fewer of them: a lockfile or rule file that is not there is covered by one stat of its directory, so on 200 independent npm projects an unchanged `dependency_check` makes about 1,900 stat calls (about the same as 6.5.0), `vulnerability_scan` about 1,900 (about 5,200 in 6.5.0) and `dependency_health` about 3,100 (about 8,500 in 6.5.0); the figures move by a few with the depth of the project's path. The first scan reads more files than 6.5.0 did (about 1,000 against about 800 on the same projects: the workspace, catalog and manifest checks above), with each manifest read once per change however many of them use it.
- A manifest that cannot be parsed is never read as "nothing declared". In 6.5.0 a `package.json` that is not valid JSON beside a readable `package-lock.json` read as complete and healthy ("0 direct dependencies checked", `coverage.complete: true`, `vulnerabilityDataAvailable: true`) and the lockfile was not cross-checked against it; the same held for `Cargo.toml` beside `Cargo.lock`, a `Cargo.toml` with no lockfile made invalid while the server ran, an unparseable `package.json` or `pyproject.toml` in a subdirectory, and a `pnpm-lock.yaml` cut off mid-value beside a `package-lock.json`. Now the file is named (under `unreadable_lockfiles`, `manifests_without_lockfile` with `unreadable`, or `conflicting_lockfiles`), `coverage.complete` is false and the plan says NOT CHECKED. `Cargo.toml` and `pyproject.toml` are checked for what a hand edit breaks (a table header or an array left open, a line that is no `key = value`), not by a full TOML parser; valid TOML is never rejected (45 real and edge-case shapes are a test corpus, multi-line strings closed by a run of four or five quotes or holding an escaped quote included), and what it cannot tell is accepted.

### The plan

- `upgrade_planner` says `vulnerabilityDataAvailable: false`, and its summary starts with NOT CHECKED, whenever a lockfile problem makes `vulnerability_scan`'s `coverage.complete` false, in any ecosystem: merge-conflict markers (a `go.sum` included), a file that could not be parsed or was read only in part, a requirements include that was refused, a second lockfile that disagrees with the one read, one not cross-checked against its manifests. Both answers read one list of lockfile problems, so on a lockfile problem they agree; and a manifest below the root with no lockfile (`manifests_without_lockfile`), which the scan already called incomplete while the plan said `true`, now makes the plan say NOT CHECKED too. They still differ, by design, where the scan is incomplete for something outside what the plan covers (see Known limits). 6.5.0 said `true` while the scan of the same project said `coverage.complete: false`: beside a conflicted `Cargo.lock` once an npm lockfile next to it was read, a conflicted `go.sum` (alone or beside an npm lockfile), a refused requirements include, a `yarn.lock` that disagrees with the `package-lock.json` read, a `bun.lockb` beside a `package-lock.json`, and a `Cargo.lock` or `pnpm-lock.yaml` older than its manifest.
- A fix target that installs an affected copy two levels down is not a clean fix. `@hey-api/openapi-ts` 0.97.3 clears its own advisory but exact-pins `@hey-api/json-schema-ref-parser` 1.4.2, which exact-pins `js-yaml` 4.1.1 (four advisories); 6.5.0's plan gave it as the target with a command and `fixPathChecked: "all_advisories"`, the scan named it `fixed_version`, and `dependency_check` said proceed. Now the exact pins of what a target holds are checked too: the row names the copy and the dependency that pins it (several copies pinned through one dependency are named under it once), a later release clean at both levels is taken when there is one, otherwise the row is NOT a clean fix with no target or command, the scan gives no fixed version, and `dependency_check` names the copy. A parent upgrade's lever is judged the same way: the handlebars row of the same project named openapi-ts 0.97.3 as the release that drops handlebars and ran it first, after which the plan's own js-yaml refresh could not move the pinned copy; that row now says the release is NOT a clean fix, leaves it out of `run_order`, and names no command, target or run_order step for it anywhere (the lever rows, their reasons and `parentUpgrades`, whose `to` is null, and the package's own row when the one-release rule set it to that release), and no `fixPathChecked: "all_advisories"`. "Safe" is said only of a release judged at every level: a fix target that installs an affected copy is "the smallest release its own advisories leave clean ... but it is NOT a clean fix", and the newest release is "the newest release its own advisories leave clean (what it installs was not judged)" (the openapi-ts row called 0.97.3 and 0.99.0 safe while `dependency_check` answered avoid for both). Where what a held dependency pins cannot be read in time, the target is NOT CHECKED, never clean.
- A Cargo step that installs a crate release needing a newer Rust than your `rust-version` says so. The row carries `needsNewerRust` (the crate, the Rust it needs, the `rust-version` and the manifest that declares it) and a reason; the summary counts such rows and `run_order_note` names the steps. A project declaring `rust-version = "1.64"` is told that time 0.3.47, the first release past RUSTSEC-2026-0009, needs Rust 1.88: `cargo update --precise` installs it anyway, and the build then fails on 1.64. `rust-version` is read from `[package]`, from `[workspace.package]` when inherited, and at a virtual workspace root.
- An `upgrade_planner` call reads its rows and the lockfile problems, notes and lockfile state from one dependency set. When another call re-reads the set while a plan is being computed (a lockfile changed meanwhile), the plan says "NOT CHECKED: the dependency set changed while this plan was computed ... plan again" with `vulnerabilityDataAvailable: false`, rather than mixing rows from one set with notes from the other.

### The pre-write check

- `dependency_check` on a name it withholds never reads as checked. A name withheld because a lockfile could not be read is answered "NOT CHECKED (unreadable lockfile): <file> could not be read ... repair or regenerate the lockfile (reinstall), then call dependency_check again", with `unreadable_file` on the item and `_meta.unreadable_lockfile`; 6.5.0 called lodash "a private package" beside an unparseable `package-lock.json` and pointed at a private registry. An answer in which nothing was checked starts with "NOT CHECKED:". `_meta.sources_note` no longer says "every answer was read from the local cache" when items were withheld: it says how many were not looked up and how many were answered from the cache. `not_checked` stays `"private"` for both in the answer; the check ledger records the second as `"unreadable_lockfile"`, and the guard hook holds it and names the file to repair (see Plugin hook).
- `dependency_check` on a crate release that needs a newer Rust than the project's `rust-version` says so, as the plan's `needsNewerRust` does: the item carries `needs_newer_rust` (the Rust it needs, the declared `rust-version` and the manifest) and its reason ends with the caveat. The verdict is unchanged: the release has no advisory, and the build failure is the caveat. It answered time 0.3.47 `proceed` in a project declaring `rust-version = "1.64"` with no mention, while the plan flagged it.

### Plugin hook and install

- The guard hook reads an install command run through a shell or a runner: `bash -c "npm install x@1"`, `sh -c`, `bash -lc`, `fish -c`, `eval '...'`, `pwsh -Command` (a script block `& { ... }` included) or `-CommandWithArgs` / `-cwa`, `Invoke-Expression`, `npx pnpm add`, `npx -y pnpm@9 add`, `npm exec`, `bunx`, `pnpx`, `pnpm dlx`, `pnpm -c exec '...'`, `yarn dlx`, `corepack pnpm@9 add`, up to three wrappers deep; after a prefix (`sudo` and `env` with their options, `timeout 600`, `nice -n 5`, `nohup`, `time -p`, `command -p`, `exec`, `xargs -n1`, `busybox`, `wsl`) or a shell keyword (`! cmd`, `if ...; then cmd; fi`, `for/while ...; do cmd; done`); and inside a subshell `( ... )` or a group `{ ...; }`. npm's subcommand is resolved with npm's own table (npm 10's `cmd-list.js`): every alias, typo and unique prefix of `install` and `install-test` (`inst`, `isntall`, `it`, `install-t`, `installTest`). It also reads `bun install x@1` / `bun i` / `bun a`, `yarn workspace <name> add`, `yarn workspaces foreach ... add`, `pnpm up` / `yarn up` with a version, `python -u -m pip install`, `cargo +nightly add`, a PowerShell path to `npm.cmd` in double quotes (`& "C:\Program Files\nodejs\npm.cmd" i x@1`), and a `--registry` that names the public registry (`npx --registry https://registry.npmjs.org pnpm add x@1`, `npm i x@1 --registry=https://registry.npmjs.org/`). In 6.5.0 most of these went ahead unchecked; it already read a bare `sudo`, `env VAR=value`, `nohup`, `corepack pnpm add`, and npm's `add` and `in`. It now also reads a scoped package from PowerShell (`npm i @types/node@20.0.0`: PowerShell passes `@scope/name@1` as written, only a bare `@name` splats), an npm option that takes a value before the subcommand (`npm --location project install x@1`), the public index or registry named explicitly (`pip install -i https://pypi.org/simple`, `--index-url https://pypi.org/simple/`, `cargo add --registry crates-io`, and `registry = "crates-io"` in `Cargo.toml`; any other index still leaves the command unread), a PEP 508 specifier in parentheses (`pip install "requests (==2.25.0)"`), an npm alias with a version as the package it installs (`npm i y@npm:minimist@1.2.6`, and `"y": "npm:minimist@1.2.6"` in `package.json`, checked as minimist 1.2.6), and every command the server's own planner writes with a version: `cargo update -p x@1.0.0 --precise 1.0.1` (and `cargo update x --precise 1.0.1`), `uv lock` / `uv sync` / `uv add` with `--upgrade-package x==1` or `-P`, `uv pip compile` and `pip-compile` with `--upgrade-package "x==1"`, `npm pkg set "overrides.x=1"` (any dependency section, `pnpm.overrides`, `resolutions`, nested overrides, the bracket form), and `go mod edit -replace=a=b@v1` / `-require=a@v1` (and `go work edit`). Also: `npm pkg set` with an alias (`dependencies.x=npm:lodash@4.17.20`), `latest`, a Yarn glob (`resolutions.**/qs=6.5.2`) or a pnpm `parent>child` key; every npm option that takes a value before the subcommand, as npm's own parser reads it, abbreviations included (`npm --proxy http://p:8080 install x@1`, `npm --prefi ../b install x@1`; after an option npm does not know, the install is looked for in the words after it); Cargo package ids (`-p time:0.3.17`, `-ptime`, `-p <registry URL>#time@0.3.17`) and `cargo -C <dir>`; `python -m piptools compile` and `uvx pip-compile`; a quoted module path in `go.mod`; a PEP 440 epoch (`==1!2.0`); and, from PowerShell, an install beside a splatted variable (`npm i x@1 @rest`). `npm i -g x@1`, `pnpm add -g` and `bun add -g` name their version and are checked like a project install, as 6.5.0 already checked them; the README said global installs go ahead, which was true only of `cargo install`, `yarn global add` and `go install`, and now says so.
- A guard denial quotes every name and version it repeats, and every string it repeats from the ledger (a recorded reason of any verdict, an unreadable file), and says they are data, never instructions; it says that `FOURDA_GUARD` is the user's setting, which the agent must not change on its own, and names a missing record only where a version has no entry at all: a manifest can be a third party's, and a name like "ignore-all-previous-instructions-..." is a valid npm name. The denial offers the `dependency_check` call for the packages you mean to add and says what the call sends: a name goes to its public registry and OSV.dev unless your private rules (an `.npmrc` scope, `GOPRIVATE`, a private index, `FOURDA_PRIVATE_PACKAGES`) cover it, and a name that is not published comes back unknown and stays blocked. The advice after a manifest edit (`FOURDA_GUARD=advise`, or no ledger yet) quotes names and versions the same way and says so, and a denial quotes the last `unknown` answer's recorded reason; a version named there is not named a second time under "no dependency_check verdict".
- A withheld answer lets a version through only where 6.5.0's did. A name a private-registry rule covers (`not_checked: "private"`: `FOURDA_PRIVATE_PACKAGES`, an `.npmrc` scope or registry, `GOPRIVATE`, a private index) goes ahead at any version in any project, as in 6.5.0, except that an `avoid` or `wait` for that exact version or constraint, older or newer, now holds it, and ledger entries are ordered by the time they were given. A name a project takes from git, a path, its workspace, an alias, a catalog or another registry (`"local_source"`) is held when a command or an edit would install it from the public registry, and the denial says that release was not checked, and how to install it if it is wanted: remove the non-registry spec from the manifest that declares it (that edit goes ahead; one that puts a registry version in its place is held like the command), or repair an unreadable catalog, then check the version, and the install is judged on its verdict: an unchecked public release of a name a project takes from elsewhere is dependency confusion (`"acme-utils": "github:acme/acme-utils"`, then `npm i acme-utils@9.9.9`). An edit that keeps such a name's non-registry spec installs nothing from the registry and goes ahead. A name withheld because a lockfile or manifest could not be read is `"unreadable_lockfile"` with `unreadable_file`, and the hook holds it, naming the file to repair. In 6.5.0 a private entry beat a later `avoid`, and a name withheld beside an unreadable `package-lock.json` went ahead. A ledger line is, for example: `{"t":"2026-11-24T10:21:00.000Z","ecosystem":"npm","package":"acme-utils","version":"9.9.9","verdict":"unknown","reason":"NOT CHECKED (not a registry release): ...","not_checked":"local_source"}`.
- A range or constraint goes ahead on a `proceed` or `review` answered for that same constraint, or, without one, on a `proceed` or `review` for exactly the release its inclusive ceiling names (`<=V`, `A - V`, with only lower bounds beside it and no `!=`, which can exclude the ceiling), the release a fresh resolve picks from it (a lockfile that already holds a release in the range keeps that one); an `avoid` or `wait` for either holds it. In 6.5.0 any verdict for the package let every range through: with `avoid` for lodash 4.17.20, `npm i 'lodash@<=4.17.20'` went ahead. PyPI `==2.0.0+cpu` and `==5.0.0-rc1` are read as exact pins (compared in PEP 440 normal form), `==3.2.*` as a range, and npm's `lodash@ ^4.17.0` as the range after the blank. `"latest"` in `package.json` is held with a call for `latest`.
- A `go.mod` `replace` that points at a module version (`replace golang.org/x/net => golang.org/x/net v0.17.0`, `replace a v1 => b v0.0.1`) is held until that module version is checked, as an npm override is; a replace to a directory still goes ahead. No longer stopped: a PowerShell block comment `<# ... #>`, a PEP 503 spelling-only rename (`requests_toolbelt` to `requests-toolbelt`), and an edit of a `syntax_test_*` file, which the server does not read as a requirements file.
- `--help`, the message for a database that cannot be read, the better-sqlite3 remedy, `--setup`'s closing `--doctor` line and the update notice's `--setup --update` command print `npx -y --prefer-offline @4da/mcp-server@<this version>` (the remedy with `--allow-scripts=better-sqlite3` among npx's options); they printed unpinned `npx @4da/mcp-server` lines, which start whatever npx cached first. `--help` also says `FOURDA_OFFLINE` turns off the package registries and Hacker News as well as OSV.dev.
- The MCP Registry entry (`server.json`) carries `runtimeHint: "npx"` with `-y` and `--prefer-offline` as runtime arguments, so a client that builds its command from the registry starts a cached pinned version without asking the registry first, as the plugin, the Gemini extension, `--setup` and 4da.ai's install pages already do.

### Changed behaviour

- `upgrade_planner` says `vulnerabilityDataAvailable: false` in more projects: any lockfile problem that makes the scan incomplete, of any ecosystem, including an npm lockfile older than its `package.json`, a conflicted `go.sum`, a second lockfile that disagrees with the one read and a refused requirements include. A caller that waits for `true` before acting gets the NOT CHECKED summary instead, which names the file to fix.
- `dependency_check` verdicts change for a release whose held dependencies exact-pin an affected copy (now `avoid` or `review` with the copy named). The guard hook holds an `avoid`; a `review` goes ahead, as every `review` does (the README's rule: `proceed` or `review` passes), so read its reason before writing the version.
- The check ledger records a withheld name as `not_checked: "private"` only when the server's rule code says a private-registry rule covers it: a `FOURDA_PRIVATE_PACKAGES` pattern, an npm scope or registry in `.npmrc`, `GOPRIVATE` / `GONOPROXY` / `GONOSUMDB`, `GOPROXY`, a Cargo source replacement, a pip or uv index (a requirements `--index-url` included), a Pipfile `[[source]]`. It is never decided from the answer's wording, which quotes repository text. Every other withheld name is `"local_source"` (git, GitHub shorthand, a path, `file:`, a tarball, `link:`, a workspace member, an alias key, a catalog, a Cargo `path`, `git`, named registry or `[patch]`, a uv source, a go.mod `replace` to a directory, and a name a `package-lock.json` installs from a private host), unless a registry or index setting covers the whole ecosystem (an `.npmrc` `registry=`, a default pip or uv index, a requirements `--index-url`, `--extra-index-url` or `--find-links`), in which case every name of that ecosystem is recorded private, as 6.5.0 did; and a name withheld beside an unreadable lockfile is `"unreadable_lockfile"`. Both hooks hold those two. 6.5.0 recorded Cargo `git`, `path` and named-registry dependencies, uv sources and a go.mod `replace` to a directory as private, so its hook let any version of those names through in every project; they are held now, which is stricter.
- Version skew, measured with the published 6.5.0 server and hook against this release's (`npm i` / `cargo add` / `pip install` of the name, in the declaring project and in another one). With a 6.5.1 server, both hooks hold every `local_source` and `unreadable_lockfile` name, and both let a private-registry name through, as 6.5.0 does. With a 6.5.0 server, both hooks behave as the 6.5.0 hook: its ledger records an unreadable lockfile and Cargo `git` / `path` dependencies as `private`, and both hooks let those names through, as 6.5.0 did; a git or workspace name, which 6.5.0 did not withhold, is held when the 6.5.0 server answered offline; online that server looks the name up, and its verdict decides. No pairing lets through anything that 6.5.0 with 6.5.0 holds. A range needs an answer for itself (or for its inclusive ceiling), where any verdict for the package used to do.
- For a version, the last decisive answer (`proceed`, `review`, `avoid`, `wait`) decides, whatever `unknown` answers came after it, and entries are ordered by the time they were given, not by their place in the ledger files (several servers append to one ledger): an `avoid` holds until a later `proceed` or `review`, and a `proceed` is no longer undone by a later time-budget `unknown`.
- The hook honours any server's ledger verdict for 24 hours: a `proceed` that a 6.5.0 server recorded for a release 6.5.1 now answers `avoid` (a two-level pin, for example) keeps passing until it is 24 hours old or the version is checked again.
- `dependency_check`'s `_meta.private_packages` counts only private names; names withheld beside an unreadable lockfile are counted in `_meta.unreadable_lockfile`. An all-withheld summary starts with "NOT CHECKED:" (it started with "N not checked (private)").
- `dependency_health` lists no row for an npm dependency that is not a registry release (a path, an archive, git, a URL other than the public registry's own tarball, a link or workspace member), so "N direct dependencies checked against their registries" counts registry dependencies only; `dependency_check` on such a name in that project is `unknown` (`not_checked: "private"`).

### Known limits

- A name is withheld only when a manifest or lockfile the scan reads says it is local code, git or a URL. Not covered: a manifest the scan does not read (a project in a subdirectory with no lockfile, listed under `manifests_without_lockfile`: a name declared only there is looked up if you ask about it directly); the project's own root package name in npm, pnpm, Yarn v1 and Bun, asked about directly; a crate in a folder the Cargo workspace `exclude`s that nothing depends on, asked about directly; a Go module replaced by a `GOPRIVATE` fork, asked about directly, which is looked up by its original path; and the repository path of an npm git dependency asked about as a Go module; an alias only the lockfile records (a `package-lock.json` root that still lists `"x": "npm:y@1"` after `package.json` dropped it, a lockfile out of step with its manifest) has its key sent when that package is found vulnerable, as in 6.5.0; for `npm:npm:x@1` and `npm:x-1.0.0.tgz`, x is looked up if asked about directly; and an alias whose range npm cannot read (`npm:x@=~7`, `npm:x@1.0.0 junk`) is read as an alias to x, and x is sent like any alias target. A requirement given as a URL on PyPI's own file host is checked by name by `dependency_check` but listed by the scan under `not_checkable`.
- `vulnerabilityDataAvailable: true` means OSV.dev answered for every dependency of every lockfile read, with no lockfile problem and no manifest below the root left without a lockfile. It stays true while `vulnerability_scan`'s `coverage.complete` is false for: a lockfile left out on purpose (in a gitignored directory, or a test fixture: pass `project_path` or `include_test_fixtures`), a manifest of an ecosystem this server does not read (`pom.xml`, Gradle, .NET), a git, URL or local-archive dependency (`not_checkable`: no registry advisory describes it), the unpinned dependencies of a requirements file that lists only direct pins, and Go's standard library and toolchain (run govulncheck). The scan's `coverage.note` names each.
- A file change is noticed by its stat signature (mtime, size, inode) and, for a file that was not there, by its directory's: an in-place edit that keeps a file's mtime, size and inode is not seen until a restart, nor is a file created on a file system that does not update a directory's mtime when an entry is added. A manifest's text is also kept by that signature, so a rewrite of the same size within the file system's mtime resolution can be read stale once (6 of 2,000 back-to-back same-size rewrites on NTFS in a check).
- A pnpm catalog written with YAML tags (`!!str`), block scalars (`>-`), merge keys (`<<: *base`), an anchor on a mapping, `catalog: &c`, or a value on the line after its anchor, all of which pnpm reads, is reported as a catalog that could not be read, and the names declared through it are withheld. They are withheld in other projects too until the project that declares them is scanned again with a readable catalog: repairing the catalog releases them only on a rescan of that project.
- One unreadable lockfile in a scanned project keeps the names its manifest declares from being looked up in other projects until the server restarts, unless that other project installs them itself (as in 6.5.0), and the answer there still says "private".
- The `dependency_check` summary counts ambiguous `npm:` items under "not a registry release", while each item says "ambiguous npm: spec".
- A project that itself declares a name as a registry dependency has that name looked up, even when another scanned project takes the same name from a path, git or its workspace.
- `dependency_health` still scores the checked part of a project beside a lockfile read only in part (`scoreCoverage`, "over the checked part only"), where `what_should_i_know` treats the same file as not read; an unreadable or merge-conflicted lockfile withholds the score.
- Two levels down only exact pins are judged: a range two levels down, anything deeper, and a copy bundled inside a package's tarball (`tap`) are not checked, so a plan can still bring in a vulnerable copy it did not name (`@actions/github` 6.0.0 brings undici 5.x through `@actions/http-client`). Scan again after running a plan (`run_order_note` says so).
- The planner flags a Cargo release that needs a newer Rust than your `rust-version` and keeps it as the target; it does not look for an older release that fits (for a security fix the smallest clean release is already the target). A release that declares no `rust-version` is not judged.
- The guard hook cannot tell a made-up name from a real one by itself (it runs offline with no registry); the server's answer decides, and an unknown answer keeps the version held. It does not read: `cmd /c`, `pwsh -EncodedCommand`, `Start-Process ... -ArgumentList`; a tool that runs commands given as its arguments (`npx concurrently 'npm i x@1'`); what `xargs` reads from its input (`echo x@1 | xargs npm i`); more than three shells or runners deep; a prefix option it does not know (`env -S`, `command -v`) or a prefix it does not know at all (`stdbuf`, `ionice`, `flock`, `su -c`, `doas`); a command piped into a shell (`echo "npm i x@1" | bash`); `uv run pip install`, `poetry run pip install`, `pdm add`, `pipenv install`, `npx expo install` and `yarn set resolution`; an `npm:` alias without a version; `npm install-ci-test` (`cit`), which installs the lockfile as `npm ci` does; a registry or index other than the public one; global tool installs that are not a package manager's add (`cargo install`, `yarn global add`, `go install`, `npx some-tool@1.2.3`), which add no dependency to the project; `npm pkg set --json` with an object value; a package.json dist-tag other than `latest` (`"next"`); `constraints.txt` and `requirements.in` (neither is a requirements file the server reads); a TOML unicode escape (`\u0041`) in a dependency name or in a pyproject requirement string; manifests written by the shell (`echo "x==1" >> requirements.txt`, `sed -i`). Any `$`, backquote, backslash (other than a line continuation) or `<<` anywhere in a Bash command, and any `$`, backtick, or parenthesis or brace outside a script block `& { ... }` in a PowerShell command, leaves the WHOLE command unread: `cd "$HOME/app" && npm i x@1` and, from PowerShell, `npm i x@1 2>$null` go ahead. Each of these goes ahead without comment. So do `yarnpkg add` (the full reader does not know `yarnpkg`; past 64 KB the pre-check does), a package manager run as a script (`node pnpm.cjs add x@1`; past 64 KB the pre-check sees it), and, on Windows, a manifest written as `PACKAGE.JSON` or `package.json::$DATA` (the same file: requirements file names are matched without regard to case, the other manifest names exactly). A command over 64 KB whose install names its package manager through a variable, a substitution or an escape (`$PM i x@1`, `n\pm i x@1`) is not seen as an install, and goes ahead; so does one that installs inside a quoted argument (`bash -c "npm i x@1"`, `sh -c`, `eval`, `pwsh -Command`, `Invoke-Expression`), after a prefix option that takes an argument (`sudo -u root npm i`, `env -u X npm i`, `timeout -s KILL 600 npm i`, `wsl -d Ubuntu npm i`), after `if`, `while` or `until`, after a leading redirection (`2>/dev/null npm i x@1`), or with a line continuation that ends in a carriage return (each of these is read and judged when the command is under 64 KB); and so does a payload over 8 MB that does not parse as JSON or is over 64 MB, unless its first 64 KB show the call. A pip requirement with more than eight version clauses (`x>=1,>=1,...`) is read by its first eight only, in a command or a file, so a ninth clause that excludes or caps a release is not seen (as in 6.5.0), and `npm i x@x` or `x@x.x.x` goes ahead like a bare `npm i x`. Held, though they may be harmless: a manifest write or install command with any part past the hook's bounds (the README lists them), held as "could not be read", among them a command over 64 KB that starts with a package manager's name and has one of its install words anywhere after it (`cargo test install ...`), a `git commit -m "$(cat <<'EOF' ... EOF)"` message over 64 KB that has an odd number of double quotes and a line reading like an install (`npm install x`), a PowerShell here-string over 64 KB with Windows line endings and such a line, a command over 8 MB whose pre-check takes longer than about 2.5 s (tens of megabytes of very short commands), a large formatting MultiEdit (200 edits on a 220 KB requirements file passes the edit-work bound: make the edit as a Write); a ledger with more than 5,000 entries for one package, which holds installs of every package until those entries are 24 hours old or the ledger rotates (empty `check-ledger.jsonl` and `check-ledger.1.jsonl` in the server's data folder, keeping the files, and check again the versions you need); a `--dry-run` install and a versioned global install, like any other install with that version; and deleting a `go.mod` `replace` to a directory, which makes the `require` install its version from the registry. A name covered by a private-registry rule (`FOURDA_PRIVATE_PACKAGES`, an `.npmrc` scope or registry, `.yarnrc.yml` `npmScopes` / `npmRegistryServer`, `bunfig.toml`, `GOPRIVATE`, a pip, uv or Poetry index, a requirements `--index-url`) is never looked up, so the guard lets any version of it through in any project for 24 hours after the server has said so, as 6.5.0 did. These files are read from the repository: a repository that points an ecosystem at its own registry (an `.npmrc` `registry=`, a `.yarnrc.yml` `npmRegistryServer`, a Poetry source, an `--index-url` in a requirements file) has every name of that ecosystem recorded private, and the guard lets every version of those names through for 24 hours, as in 6.5.0; a name the project takes from git, a path, its workspace or an alias is held when a command would install it from the registry. A 6.5.0 server records an unreadable lockfile and Cargo `git` and `path` dependencies as private, and beside one the 6.5.1 hook lets those names through, as the 6.5.0 hook does.
- An upgrade can lower another package through the new release's own exact pin (cypress 15 pins `cli-table3` 0.6.1 where 0.6.3 was installed). The plan does not warn about it.
- uv's universal resolve can pick a different release for a higher Python than the one the plan checked.
- A direct upgrade that would leave other packages' copies affected is not offered as a command at all, so the project's own copy also stays until the hand step is done.
- A cold batch of 25 crates can need a second call: crates.io allows one request a second.
- In the `"*"` scope one app plan step can cover copies with different routes.

## 6.5.0 — 2026-11-23

### What is scanned

- `build/`, `dist/`, `out/`, `coverage/`, `.vscode/` and `.idea/` are ordinary directories: their lockfiles are read unless the repository ignores the directory, and listed lockfile by lockfile (`gitignored_directory`) when it does. Directories never scanned by their name (installed code, a tool's build output or cache, editor or agent state: `node_modules`, `target`, `.venv`, `.claude` ...) that the repository does not ignore are searched within their own bound of 2,000 directories, and every lockfile in them is listed under `coverage.not_scanned.lockfiles` with reason `excluded_directory`.
- A junction or directory symlink whose real path is inside the project is walked (each directory once, never looping); one that leads outside it is not scanned, and the lockfiles behind it are listed with reason `symlink_outside_root`. A directory the walk cannot list is named (reason `unreadable`, its path ending in `/`) instead of read as empty.
- A lockfile or manifest with git merge-conflict markers is not read at all, neither side of it: it is listed with reason `merge_conflict`, `coverage.complete` is false, and every tool says `NOT CHECKED (merge conflict)` for it.
- Started in a workspace member with no lockfile of its own, the server reads the workspace root whose lockfile holds it (npm, pnpm, Yarn and Bun workspaces, Cargo, uv, Poetry, PDM, `go.work`) and says so (`workspace_note`; `dependency_health`'s summary). The search stays inside the enclosing git repository (at most 6 levels with none, never at or above the home directory); an ancestor lockfile that cannot be confirmed to hold the directory is named, not read.
- With no lockfile read, no tool scores or clears the project: `dependency_health` gives `healthScore: null` with `withheldReason: "no_lockfile"` and a NOT CHECKED summary, a declared range's floor is shown as `currentVersion: null` beside `declaredRange`, `upgrade_planner` sets `vulnerabilityDataAvailable: false`, and `what_should_i_know` never says `safe_to_delegate` on that basis. `vulnerability_scan` starts its answer with NOT CHECKED and gives null totals (a `package.json` of 126 dependencies and no lockfile used to answer "4 scanned, 0 vulnerable" with no summary; what is found among its exact pins is now a lower bound under `found_in_checked_dependencies`). A folder holding nothing the server reads, an empty one or the wrong one, is answered the same way instead of `coverage.complete: true` with zero findings, and a scan that read nothing beside an ecosystem it does not cover leads with that.
- A lockfile that exists and could not be read (not valid JSON, garbage, a merge conflict) is never passed over. Every tool names the file: the scan leads with NOT CHECKED and gives null totals even when a second ecosystem beside it was read (what was found there is a lower bound under `found_in_checked_dependencies`), and `what_should_i_know` is never `safe_to_delegate` while a lockfile was not read or read only partly (`lockfiles_not_read` lists each). It used to say "safe to delegate" beside an unparseable `package-lock.json`. The dependencies under such a file are still never sent, and are said as "NOT CHECKED (unreadable lockfile)", no longer as "private". A go.sum that holds no valid line in a project older than go 1.17 is reported, not read as empty.
- In a `what_should_i_know` task that names several packages with versions, each package gets the version from its own clause ("upgrade minimist to 1.2.8 and install react 18.3.1" gave minimist 18.3.1).
- Cargo dependencies declared as tables (`[dependencies.git2]`), dotted keys (`git2.version = "0.15"`), target tables and quoted names are read as the inline form is.
- A Sublime Text syntax test (`syntax_test_*`, the name that convention requires) is never read as a requirements file. bat's `syntax_test_requirements.txt` used to turn the scan of that Cargo project into "NOT CHECKED (private)" and put PyPI rows in its plan.
- A package-lock v1 dependency installed from a tarball URL is kept: a registry-shaped URL is the release it names (and a private host makes it NOT CHECKED (private), never sent); one that names no release is listed as not checkable.
- `vulnerability_scan` shows the advisory's own grade beside the scope-adjusted one: `by_advisory_severity` beside `by_severity` (the detailed answer also keeps `advisory_by_severity`), `advisory_severity` on a concise row whose own grade differs, and the summary says first (after any NOT CHECKED headline) how many advisories are critical by their own grade and how many are presented lower. Every recommendation names the own grade where it differs.
- Scan rows have one order, whatever was answered from the cache, so detailed pages never lose or repeat a row; a concise row carries its ecosystem.
- `vulnerability_scan` always returns `coverage`, in both formats: a scan that left nothing out says `complete: true` with `lockfiles_read` and `lockfiles_not_scanned: 0`; an incomplete scan is unchanged (`complete: false`).

### The plan

- `upgrade_planner` for one project is always this server's plan from that project's lockfiles, with or without the desktop app (`provenance.mode: "lockfile_engine"`). With the app attached, `app_plan_check` says how the app's stored plan compares: `agrees`, `differs` (up to 10 `differences`), `not_comparable` (plan format not read, advisory data over 24 hours old, a lockfile changed after the plan, this server's scan incomplete) or `no_plan`. A stored step whose sites all lie in a directory this server does not scan is counted apart and never reported as a difference.
- A command installs the release the plan checked. A command written with the manifest's range (`npm install "mssql@~10.0.3"`) makes the package manager install the newest release that range admits, which the plan had never looked at: mssql 10.0.6 goes back to `tedious ^16`, so the advisory the step named stayed. The plan now works out which release the command installs (`installs` on the command) and checks it as it checked the target: its advisories, that a parent upgrade still brings the fix in, and what it pins. If it fails a check or cannot be established, the command names the checked release exactly (`npm install mssql@10.0.3 --save-exact`, `pnpm up x@T`, `yarn upgrade|up x@T`, `cargo add "x@=T"`) and the row says why. npm, pnpm, Yarn and Cargo; `vulnerability_scan`'s `fix_targets` carry the same command. This was also wrong in 6.4.0 and earlier.
- A direct upgrade after which other packages keep an affected copy on the old line (tar moved to 7.x while four packages require `^6`) says which packages, which copy they keep, whether a clean release exists inside their range, and the hand step. It is a hand edit, counted apart and not in `run_order`, and no longer counted as fixed.
- The plan's `summary` starts with NOT CHECKED whenever its vulnerability data is incomplete or no lockfile was read, and `run_order_note` words its claim as one about order and says to scan again after the run.
- `project_path: "*"` with the app attached still returns the app's stored plan across every project, labelled `provenance.mode: "app_plan"` with `app_plan_check.status: "unverified"` (or `"not_comparable"`), and `stale` when it is past its expiry, its advisory data is over 24 hours old, or a lockfile of a project it covers changed after it (up to 5 named).
- Every row carries `commands` (`{ dir, run }`); the plan carries `run_order` (`{ n, dir, run, fixes }`), the rows shown as one script that is safe to run top to bottom, and `run_order_note`, which says what it covers and what it leaves out and why, and counts and names the rows that are hand edits and not in the script. Tied rows are ordered the same way every time.
- Every direct upgrade with no command says why in its reasons. A freshness upgrade (no advisory against the installed version) says it is not a security fix, is left out of `run_order`, and names the hand step that takes it; a row whose fix starts with a manifest edit says nothing runs before that edit (`upgradeInstructions` names it).
- In `run_order`, upgrades run before in-range refreshes, so a refresh is never undone by a later upgrade. A target that breaks an installed package's peer range installs in one command with that package's release when the plan moves it. On pnpm, the peer step after a parent's upgrade names the release the upgrade leaves, never a lower one.
- An override within its parents' major runs as commands: `npm pkg set "overrides.<name>=<version>"` (or `pnpm.overrides` / `resolutions`, scope kept), then the install, in the lockfile's directory. An override that crosses a major of what its parents declare, a key `npm pkg set` cannot write as a path, an entry `package.json` already has, or a Yarn Berry or Bun override that would force other copies stays a hand step.
- Yarn classic: a package the lockfile holds on one release line, every copy at or below the target, gets an exact resolution (`npm pkg set "resolutions.<name>=<target>"`, then `yarn install`; the resolution stays). A declared package whose `yarn.lock` entry is also keyed by transitive ranges gets the hand step that moves every range.
- uv: a pin whose release needs a newer Python than the project supports is a hand step that says to raise `requires-python` first. In a uv workspace each command runs once, at the root, and a copy only a member's leftover `uv.lock` lists is a hand step (delete the file), named in `run_order_note`. A package a uv, npm/pnpm/Yarn or Cargo workspace member defines is taken from the workspace and never upgraded from the registry.
- A row is `waiting_on_upstream` only when no command you can run today fixes that copy. A Python parent the project does not declare is moved by its own refresh when what requires it admits a fixing release (`upgrade_parent_unverified` when something holds it below that release, NOT DETERMINED when the releases could not be read). A uv project's vulnerable direct dependency gets `uv lock --upgrade-package <name>==<target>`, or the widening of its requirement first; a uv refresh that would stop below the fix because of a co-dependency the lock holds lower names the fix itself.
- A version installed both bundled inside another package and on its own gets the refresh for the copies that are not bundled, with `bundledCopies` naming each owner whose copy stays; the summary counts that row in `lockfileRefreshes` and in `waitingOnUpstream`, and says a bundled copy remains.
- A Cargo upgrade into a release that drops a feature the manifest enables is an instruction naming the feature, not a command cargo refuses; `upgrade_impact` lists such features in `your_code.cargo_features_removed`.
- A parent upgrade never names a release of a declared dependency that brings in a new vulnerable copy. Overrides are scoped to the vulnerable copy's parents where the lockfile holds other versions; a Yarn classic refresh that would move only one of several entries gives the hand steps instead. On pnpm, a parent move whose new release takes the package as a peer names the step that moves the peer.
- Upgrade targets past the per-call requirement cap are examined after the call returns, so the next call answers every one.
- The app plan's `lockfile_refresh` is worded for a direct dependency whose declared range already admits the fix as well as for a transitive copy, and the plan summary no longer calls every refresh transitive.

### The pre-write check

- One refused item no longer fails a `dependency_check` batch: it is `unknown` with `not_checked: "input"` and its reason, and the others are answered. An npm scope written without its `@` is named as such, and nothing is sent.
- Go: a retraction list that could not be read makes the item `unknown` (never `proceed`) and nothing is cached for it. A read held back by this server's own Go request limit says so, never blames the proxy, and carries `retry_after_seconds`. The limit is 300 requests a minute and an item reserves every read it needs up front, so a 25-item batch fits.
- A constraint's smallest safe release is never above a release in the range that was not judged.

### Signals and the briefing

- `get_actionable_signals` starts the project's scan and waits for it when none has run in the session (`scan: { status, scanned_at }`; `note` starts NOT CHECKED when it is missing or incomplete), and gives the scan's own instruction for each finding, as `vulnerability_scan` and `what_should_i_know` do. A call filtered to a non-security signal type starts no scan.
- `get_relevant_content` and `get_actionable_signals` never widen a `since_hours` you pass; the default window is still widened when empty, and `window: { requested_hours, used_hours, widened }` says so. They give one item per advisory, keeping the better-grounded source.
- A feed advisory reaches a briefing package only on its ecosystem and exact name; the briefing keys packages by ecosystem and name; a signal's priority follows the presented grade; maintenance notices read as notices (`maintenance_notices` on a briefing row), never as advisories with a missing fix.
- `ecosystem_pulse` takes its search terms from the project on disk (its frameworks and direct dependencies), with or without the desktop app; the app's stored rows are used only to keep a name another project installs privately from being sent.

### With the desktop app

- The dependency tools read every lockfile under the project root from disk, exactly as without the app, with the same `coverage`; the app's database is never the inventory and a scan never writes to it.
- The supported app range is declared: 4DA v1.0.3 (schema 124, plan format 4) through the app's main of 2026-11-22 (schema 131, plan format 5). Outside it, `get_context` and every answer that reads or writes the app's data carry `_meta.app_compatibility` with a note saying which side to update. The server keeps serving; when such a database lacks a table a tool reads, the error itself carries the note (it used to fail with "no such table" and nothing else).

### Data folder

- `FOURDA_DB_PATH` naming a missing file, or a file with no tables, leaves `vulnerability_scan`, `dependency_health`, `dependency_check`, `upgrade_impact`, `upgrade_planner`, `what_should_i_know` and `ecosystem_pulse` answering from the project's files, each with `_meta.database_note`; the briefing has no stored decisions, memories or feed rows then and says so in `stored_data_note`. Every other tool returns the error, which names the path. Nothing is created or changed at that path.
- The server's own store is known by its path and completed on every open, so a first start killed mid-way, or several servers started together on a fresh folder, no longer leave a file taken for the app's database.
- The disk cache retries a lock before falling back to memory.
- `--doctor` names the data folder, the server's own database, the cache and the app database, each with its path and state, and exits 1 when the own store cannot be used or `FOURDA_DB_PATH` names no file or a file with no tables. When it finds its own database empty (0 bytes) or without tables and completes it in place, it says so as a warning, not a plain pass.
- `record_feedback` that recorded nothing is an error (`isError`), with a retry hint when the app holds its write lock.

### Plugin hook and install

- The plugin hook runs before the edit or install command (PreToolUse) and denies a dependency version that has no `dependency_check` verdict of `proceed` or `review` from the last 24 hours, or whose verdict is `avoid` or `wait`, naming the call to make. `dependency_check` records each verdict in a local ledger in the data folder (`check-ledger.jsonl`, never sent), and the server finishes writing it before it exits, so a checked version goes through even when the host closes the session straight after the answer. The hook reads install commands and `pnpm-workspace.yaml`, `requirements-*.txt` and `requirements/*.txt` too, and fails open. `FOURDA_GUARD=advise` restores advice after the edit; `FOURDA_GUARD=off` turns it off.
- The hook and the server can be of different releases (the hook comes with the plugin, the server with npm), and a server before 6.5.0 records no verdict, so a denied edit could never pass beside one. The hook therefore denies only where a ledger file exists, and the server starts one, empty, when it starts serving. With none, the hook denies nothing and advises after a manifest edit, as it did before 6.5.0. A denial for a version with no entry also says what a second stop after `dependency_check` has answered means (an older server, or a different data folder) and not to retry.
- The hook judges the package a manifest line installs, in the forms manifests really use. A renamed Cargo dependency (`alias = { package = "real", ... }`) is judged as the real crate. A dependency taken from a path, git, a URL or a non-public source goes ahead and its name is never repeated in a denial. In `pyproject.toml` only dependency declarations count: a comment or a `description` with requirement-shaped text is not denied, and a comment naming a package no longer hides a changed pin. The same name in two sections has each section's change held on its own; npm nested overrides, Yarn glob and parent-path resolutions, pnpm `parent>child` overrides, and Cargo dotted keys and quoted names are held. go.mod `exclude` and `retract` never count as versions being introduced. `dev-requirements.txt` and every `*requirements*.txt` the server reads are guarded. A version the manifest already declared for that name in another section is not treated as new.
- Every configuration `--setup` writes, the printed Claude Code command, the plugin and the Gemini extension run `npx -y --prefer-offline @4da/mcp-server@<version>`, so a cached pinned version starts without asking the registry first.
- `get_context` carries `update_notice` and `--doctor` a "Server version" warning when a newer release is published. The newest version is read only after a tool call of the session has already contacted a registry, never at start-up or with `FOURDA_OFFLINE`, at most once a day.
- The server instructions name `by_advisory_severity` and say that with the app attached the dependency tools still read the project from disk; `vulnerability_scan`'s description says build directories are read unless ignored.

### Tests and gates

- The conformance corpus is pinned to 4DA f99b6fa0c: 91 more rule vectors (malware vectors now scored) and one more OSV record (3,929); the runner fails when the corpus ships a vector file no check runs.
- Every released app schema is tested (`contract/released/v1.0.3.sql` beside the vendored current schema): every tool runs against each without an SQL error.
- New release harnesses, run weekly and on demand: plan execution (each corpus project's plan run top to bottom on a copy and rescanned), concurrent and killed first starts on one data folder, and an app-mode arm that must agree with standalone mode.

### Changed behaviour

- `upgrade_planner` no longer relays the app's stored plan for one project, and `appPlanUnavailable` is gone: read `app_plan_check` instead.
- `provenance.mode` is `"lockfile_engine"` for every plan of one project (it was `standalone_heuristic` or `app_plan`); `"app_plan"` now means only the app's stored plan for `project_path: "*"`.
- `FOURDA_DB_PATH` naming no file is refused and nothing is created there (before, an absolute path whose directory existed was created as a new standalone database), except at the server's own `standalone.db` path.
- The plugin hook now denies an unchecked or `avoid` version before the edit; set `FOURDA_GUARD=advise` for the old advice.
- A feed window is never widened when `since_hours` is passed: a call that relied on the silent widening to 168 or 720 hours gets an empty answer that says nothing matched in its window.
- `record_feedback` that records nothing returns `isError: true` with `error`, where it returned `success: false` alone.
- `lockfileRefreshes` and `waitingOnUpstream` can now both count one row (a refresh that leaves a bundled copy).
- `vulnerability_scan`'s `coverage` is never absent: a reader that took a missing `coverage` to mean a complete scan should read `coverage.complete` instead.

### Known limits

- `run_order` is the part of the plan that is safe to run as commands. Rows that need a hand edit (an override that crosses a major of what its parents declare, Yarn classic lockfile entries with copies on several release lines, a requirement edit the manager has no command for) are counted and named in `run_order_note`; running the script alone does not finish them. Measured on 14 public projects (`bench/plan-exec`), the script ran 0 failing steps where 6.4.0's plan had 10, and on Yarn classic projects it leaves most of the work as named hand steps.
- A target is checked for vulnerable dependencies it pins one level deep; a copy pinned two levels down or bundled inside the target's tarball is not detected (`@hey-api/openapi-ts` pinning `js-yaml` through another package; `tap` bundling its own copies).
- So a plan can still bring in a vulnerable package it did not name (upgrading `@actions/github` to 6.0.0 brings undici 5.x through `@actions/http-client`). `run_order_note` says to scan again after the run; over the 15 projects of `bench/plan-exec` the run brought in 26 such copies and left 24 it had a step for, against 1,208 advisories cleared of 1,548.
- An upgrade can lower another package through the new release's own exact pin (cypress 15 pins `cli-table3` 0.6.1 where 0.6.3 was installed). The plan does not warn about it.
- Cargo plans do not read `rust-version`: a target can need a newer compiler than the project declares.
- uv's universal resolve can pick a different release for a higher Python than the one the plan checked.
- A direct upgrade that would leave other packages' copies affected is not offered as a command at all, so the project's own copy also stays until the hand step is done.
- `upgrade_planner` can say `vulnerabilityDataAvailable: true` beside an unreadable lockfile of another ecosystem (the scan and the briefing say NOT CHECKED there), and `dependency_health` scores "the checked part" beside a partly read lockfile.
- A cold batch of 25 crates can need a second call: crates.io allows one request a second.
- In the `"*"` scope one app plan step can cover copies with different routes.

## 6.4.0 — 2026-11-19

### Behaviour changes

- `project_path` refuses a home directory (like a drive root) and a network path on another machine, before anything is opened. The same holds when the server itself is started in the home directory and a tool is called without `project_path`: nothing is scanned at startup and the tool asks for `project_path` (before, the server scanned every project under the home directory as one and sent each dependency name to OSV.dev and the registries).
- `vulnerability_scan` detailed answers are a page: at most 200 advisory rows by default, `limit` (up to 1,000) and `offset` for the rest, with a `truncated` block; totals still describe the whole result.
- Concise `upgrade_impact` answers list at most 150 changelog entries.
- `--setup` writes a pinned `npx @4da/mcp-server@<version>`, keeps an existing 4da entry that differs (`--update` replaces it), refuses unknown arguments (exit 2) and exits 1 when a config was not written.
- Exact `==` pins in `pyproject.toml` with no lockfile are checked (the answer says NO LOCKFILE), and a pin with other clauses (`idna>=2.5,==2.8`) is an exact pin.
- Redirects are followed only over https to the same host or its own download host, and never for a request with a body; any other redirect is refused.
- A workspace member's dependencies, and the root's optional and peer dependencies, are direct: graded, labelled and planned as direct, with the fix run where they are declared.
- Every pin in any requirements file is a direct dependency; it is dev-only only when every file that brings it in is a dev file.
- A copy is dev-only only when no runtime root reaches it; where that cannot be read whole, the scope is unknown (treated as runtime).
- A project's own packages (Cargo workspace and `path =` crates, go.work modules, uv and Poetry local packages) are not dependencies and no longer make a scan NOT CHECKED (private); the scan counts them in `own_packages`.
- npm security placeholders (`0.0.N-security`) are listed under `security_placeholders` with `remove_dependency`, never counted clean.
- `dependency_check` gives `review` when a Go, crates.io or PyPI release's own requirements carry advisories, or when a PyPI release's `requires_python` lower bound excludes a Python the project declares; `unknown` when those cannot be read. An upper cap on `requires_python` (scipy 1.11.3, `<3.13,>=3.9`) is a note in `python_support` and the release stays a pick (uv ignores it; pip judges only the running interpreter).
- PyPI requirements are judged by their environment markers against the Python versions the project declares: one no declared Python installs is dropped (botocore 1.40.0's `urllib3<1.27; python_version < "3.10"` in a `>=3.10` project), one that applies on some says on which, and one that depends on the platform, or on a project that declares no Python, is a caveat (review at most, never by itself avoid). `x; sys_platform == "win32" and extra != "y"` is no longer read as extras-only.
- The project's Python is read from more declarations: `>3.9` keeps the 3.9 series, Poetry `python = "3.11.*"` and space-separated clauses (`">=3.9 <4.0"`); a declaration that cannot be read gives an info `python_support` signal saying so.
- `dependency_check` judges held dependencies and requirements until the call's remaining budget (less a reserve for writing the answer), not a fixed 10 s, so a cold batch no longer leaves a release NOT CHECKED it had time to judge.
- A Go minimum whose clearing release was not looked up in the call (the per-call cap, the deadline, a failed lookup) says so (`fixed_in_not_looked_up`), apart from "no later release clears it".
- `dependency_check` flags a PyPI name one or two edits from a popular project: `review` ("did you mean"), `avoid` when under 30 days old with at most 3 releases.
- `vulnerability_scan` and `upgrade_planner` judge a Go, crates.io or PyPI direct upgrade by what the target release itself requires. On crates.io and PyPI, a target whose requirements carry advisories or could not be read is not a clean fix (withheld from `targetVersion` and `fixed_version`). On Go, whose requirements are minimums the project raises afterwards, the target is kept and the step and the recommendation carry the minimums, the advisories they carry and the `go get` that raises them (or that the go.mod was not examined). At most 10 targets are examined per call, and `requirements_note` and the plan summary count the rest.
- A transitive fix path that could not be read is `not_determined` (NOT DETERMINED), not "waiting on upstream"; a PyPI copy blocked by a parent the project declares is an upgrade of that parent.
- A parent upgrade is a fix only when every holder of that parent moves; `parentUpgrades[].paths` counts them.
- An npm parent release that fixes a copy and carries over only affected dependencies the installed parent already holds is named, with what it carries over.
- A vulnerable copy this host does not build carries its fix, under `whenBuilt` and `appliesWhenBuiltFor`.
- `severity_filter` also keeps a row whose advisory's own severity meets the floor, and the answer counts what it hid.
- `force_refresh` asks again only for what the call needs and never empties the cache first; when OSV.dev does not answer, the cached answers stand in, marked STALE.
- npm-shrinkwrap.json is read in preference to package-lock.json, as npm does.
- deno.lock is listed under NOT COVERED.
- `what_should_i_know` leaves `newer_releases` out when the desktop feed has no answer for a package, instead of `[]`.
- A file that decides private names and cannot be read makes the names of its ecosystem under its folder private.
- pnpm tarball locations and yarn aliases mark the package they belong to, so a neighbouring package is no longer made private.
- A semantic-recall query that names a private package is not sent to a remote embedding provider: recall is skipped for that call and the answer says so.
- `_meta.privacy` and `_meta.sources` of `vulnerability_scan`, `dependency_check` and `upgrade_impact` name the hosts the call actually sent requests to, redirect hops included, and say when nothing was sent.
- `dependency_check` asks PyPI for a judged release's own document by version when it is not the latest release (the only place its requirements are served); never for the installed (`from`) version unless it is also `to`.
- A Python prefix-match pin such as `requests==2.32.*` is listed as unpinned. It was checked as the version "2.32.*", which matched every advisory OSV.dev holds for the package.
- `severity_filter` never hides an advisory whose severity is unknown, and maintenance notices and advisories on packages not built on this host are always listed in full.
- A yarn.lock entry whose header line is longer than the reader accepts makes that lockfile's npm names private (not sent, NOT CHECKED), as an overlong line inside an entry already did.
- `vulnerability_scan` of a large project answers within one call. Advisory records it runs out of time for are marked NOT CHECKED and read in a bounded background queue, so the next call is complete from the cache. Measured on a 2,084-dependency tree with an empty cache: complete in one call at 18 to 20 s.
- A dependency a Yarn workspace member declares is fixed in that member: the step names its directory and `yarn workspace <name> add <version>`, keeping its section and operator. At the root of a Yarn berry workspace the step is `yarn add <version>`, which does not rewrite the members' declarations.
- In a Yarn project (classic or berry), a vulnerable transitive dependency's fix names the dependency your package.json (or a workspace member's) declares and the command that upgrades it, when the lockfile proves the link; otherwise the step stays unverified.
- `dependency_check`, `upgrade_planner` and `vulnerability_scan` judge a Python package against the Python declared by the project that declares it, not only the repository root, and name the folder where a release is unsupported.
- A Poetry project with no poetry.lock has its exact versions checked. Ranges are listed as unpinned, git and url entries as not checkable, and path or private-source entries are never sent. Before, `requests = "2.31.0"` was listed as unpinned and never scanned.
- When a yarn or pnpm lockfile cannot be checked against package.json because the workspace member list could not be read whole, the answer says so (NOT CROSS-CHECKED) and why, without calling the lockfile damaged. A lockfile that is both damaged and not cross-checked shows both notes.

### Fixed

- A CRLF go.mod's `retract` directives are read.
- yarn berry: a lockfile key listing several descriptors resolves the direct dependency to the copy its range names.
- An OSV.dev batch answer is attributed to its own batch only.
- Advisory ranges: an unreadable bound decides nothing, events are evaluated in version order, and OSV.dev's answer for an exact version is never contradicted.
- PEP 440: `>V`, `<V` and `==V+local` admit what pip admits, and PyPI's latest stable release is the highest final release in PEP 440 order.
- A Cargo wildcard requirement (`1.0.*`) is the line it writes, not `^1.0`.
- An unlabelled advisory is graded by the highest valid CVSS score it carries.
- A merge-conflicted npm or bun lockfile whose blocks are all closed is judged by the locations it holds.
- Damaged or truncated lockfiles and manifests (JavaScript, Python, Go, Cargo, Ruby, PHP) and an unparseable package.json are reported UNREADABLE or PARTIAL, never read as complete or absent.
- gems.locked, go.work `replace` directives and pyproject.toml exact pins are read.
- A direct Go upgrade says when the fixed release needs a newer Go than go.mod states, for the final target when the plan raises it.
- The Go requirement caveat claims the minimum only for modules the project's build uses.
- PyPI answers say what holds a release back: no release that supports the project's Python, or none clear of the advisories on it.
- A proceed beside an unmaintained-package notice names the notice.
- The concise scan summary states advisories on dependencies not built on this host.
- Changelogs: "BREAK CHANGES" headings and PyYAML's release titles are read, and a denied "breaking change" is not flagged.
- An npm parent's requirement is read from its whole-package document, so the installed version is not sent to the registry.
- Text that names a private package is never sent to a remote embedding provider, and remote embedding requests use the proxy settings.
- `--doctor` reports the semantic recall provider the server will actually use; `ecosystem_pulse` offline says Hacker News was not searched.
- `developer_dna` reads only the rows it uses.
- `--setup` accepts a config with a UTF-8 BOM, refuses one that is not UTF-8 or has duplicate or second 4da entries, keeps file permissions, and removes its backup after a failed write.
- A cold scan reads advisory records 48 at a time instead of 24.
- A range check's "not examined" reason no longer repeats itself.
- A release blocked because CI on the tagged commit was cancelled says to re-run CI on that commit, not "Fix main".
- The README, SECURITY.md, the Gemini extension and the .mcpb description state what the code does (the .mcpb text no longer says only package names and versions leave the machine, and carries no tool count; `dependency_check`'s privacy note and README say which per-release documents are requested): pinned versions, which tools send which versions to a registry, that ecosystem pulse sends dependency names to Hacker News search, model-instance raters, `gems.locked`, and the concise scan's size (about 10k tokens for about 290 advisories).
- An unreadable manifest is called a file, not a lockfile.
- A yarn.lock or bun.lock in which a package's dependency has no entry (a truncated or damaged file) marks no package dev-only: scope is unknown, so advisories keep their full severity.
- pnpm lockfiles are not reported partial for optional dependencies named in `ignoredOptionalDependencies`, or for workspace members left out under `excludeLinksFromLockfile`.
- Yarn workspaces written with braces (`packages/{a,b}`) are recognised; when the member list cannot be read in full, a dependency missing from the lockfile is not reported as damage.
- A uv.lock is not called damaged for a dependency that a `[tool.uv]` override or constraint removes.
- Cargo: `1.0.0-alpha.x` is a prerelease, not a wildcard requirement.
- When an archive holds more changelog-named files than are read, the answer says so instead of blaming the file it read.
- Upgrade-target checks stay within the call's time budget. They could run past it, which replaced the whole scan answer with "did not finish".
- Repeat scans no longer ask OSV.dev again for advisory records it does not hold (remembered for one hour; `force_refresh` asks again).
- Changing a package.json in a Yarn project is picked up by the next plan even when yarn.lock is unchanged.

### Hardening

- Manifest patterns are matched without regular expressions, member walks and import scans are bounded, and archives are read to at most 32 files and 8 MB of text; an archive path is shown plain or as its basename.
- Changelogs are parsed under a time allowance; a cut-off parse is labelled.
- Registry-supplied names, versions, dates and licences, and crate dependency names from the sparse index, are held to their shapes.
- Response bodies have a per-host size limit, and rows over 24 MB are not cached.
- Advisory record requests are capped per scan (2,000 records, none started after 60 s); what was not read is NOT CHECKED and counted in `coverage.details_unchecked`.
- Files that decide private names go through one decoding reader under one size cap; private patterns are matched by a bounded matcher.
- The pyproject.toml array reader and the Cargo.toml dependency reader run in linear time.
- The plugin hook bounds what it reads and repeats only shaped names and version specifiers.
- The plugin hook repeats only a dependency's version specifier, read clause by clause; words placed after a version are not repeated.
- GitHub release pages and raw changelog files up to 64 MB are read, and are parsed under the same time allowance as archive changelogs.
- An oversized answer is never written to the cache, batch writes included.
- Requests to a local Ollama never go through a configured proxy.
- The background queue that finishes advisory reads is bounded (16 at once, 2,000 waiting), holds ids only, stops when the server shuts down, and reads each record under the private-name rules of the project that queued it. An OSV.dev answer naming tens of thousands of ids still costs no more than the per-scan limit of requests.
- The OSV.dev dependency query goes out as up to 8 smaller requests at once, and a slow advisory request is retried in parallel (at most 8 per scan).

### Tooling and tests

- A release requires green CI on the tagged commit, with the conformance suites run and required; CI runs every corpus-gated test, and the nightly report names every failed job.
- `pnpm run lint` (ESLint, correctness rules only) and `pnpm run typecheck` (the test suite type-checked) run in CI and pass with no warnings.
- A weekly mutation check runs 90 mutants and fails on any survivor outside the equivalent list.
- `scripts/release.mjs` bumps every version pin, and a test holds them to package.json.
- New tests hold rules that had none (HTTP rules, PEP 440 ordering, name folding, malware, control characters, fail-closed verdicts, batch attribution, private-name casing, README statements; only the two HTTP helpers may call the global fetch); tests that could not fail now can, and none depends on machine speed or a random port.
- `pnpm run check` fails when a mutation-check mutant no longer applies to the code. Two had gone stale unnoticed; all 90 apply and were run on the merged tree.
- `checkPass` in `dependency_check` (548 lines) is split into named stages in nine modules; the function is 46 lines. Behaviour is unchanged and no existing test was edited.

## 6.3.0 — 2026-11-15

- **Pre-publish fixes (round 10).**
  - *Privacy, one rule.* A name the project does not install yet is private
    only for a registry-wide reason: the package manager would fetch any name
    from a source that is not public. That covers a default registry, index or
    proxy; a requirements file's `--index-url`, `--extra-index-url` or
    `--find-links`; `registry`/`registries` in `pnpm-workspace.yaml`; a Cargo
    source replacement; GOPROXY; and a lockfile that installs everything from
    one private host. The request guard, dependency_check, upgrade_impact and
    the briefing now share this rule. dependency_check and upgrade_impact sent
    a new name to OSV.dev and pypi.org when the private index was set only in
    requirements.txt; they no longer do. Round 9's rule also made "add lodash"
    private in a project whose only npm packages are a privately scoped
    `@acme/*`; that is checked again. A `pyproject.toml` in a subfolder with no
    lockfile now applies its own index settings. Each private answer names the
    setting that makes it private and the `FOURDA_PUBLIC_MIRRORS` escape.
    Behaviour to know: under a private pip index, extra index or find-links,
    public names such as `requests` are NOT CHECKED (private), because pip may
    take any name from that index. One subfolder with a private index makes new
    names in that ecosystem private for the whole project.
  - *Versions as the package manager reads them.* A bare crates.io version
    ("1.6.0") is what Cargo reads as `^1.6.0`. It is now judged both as that
    release (a Cargo.lock already holding it keeps it) and as the range (a
    fresh resolve installs the newest 1.x), and the worse answer stands. When
    that newest release is under 3 days old, the answer is `wait`, with an
    exact `=X` pin given as the safe alternative. An npm range is judged at
    npm's own pick (the `latest` tag when the range admits it and it is not
    deprecated, else the highest non-deprecated release) and at the highest
    release Yarn or pnpm may install; both are named when they differ.
    `serde-json` is checked as `serde_json`, the spelling crates.io publishes.
  - *Briefing.* Ranges are read the way dependency_check reads them, so
    "add minimist >= 1.2.0, < 1.2.6" is avoid. An unreadable range no longer
    turns every other package in the call to unknown, which had hidden ctx's
    malware. A TOML entry (`smallvec = { version = ">=1.6.0, <1.6.1" }`) is
    filed under its own ecosystem and gives one verdict. Tasks with no verb are
    checked: "chalk 5.6.1/debug 4.4.2", "chalk@5.6.1, debug@4.4.2" and
    "pin chalk 5.6.1 and debug 4.4.2" are avoid. " / " separates items.
    "add debug, chalk and ms" checks all three. A loose word ("use blueprints")
    is checked by name only, with one lookup instead of two.
  - *upgrade_impact names what the target installs.* express 4.17.1 → 4.21.2
    said 2 advisories fixed and nothing remaining. 4.21.2 exact-pins
    vulnerable qs, body-parser and path-to-regexp; they are now listed in
    `held_dependencies_affected`. The answer gives `first_clean_release`
    (4.22.3, confirmed with OSV.dev). If the registry or OSV.dev can't be
    read, the answer is NOT CHECKED, never clean.
  - *Fix-path wording.* "no 3.x release clears every advisory" for
    event-stream 3.3.6 was false: 3.3.5 is clean. Scan and planner now say
    "No 3.x release after 3.3.6 exists; 3.3.5 (a downgrade) is clean; 4.0.0 is
    the smallest safe upgrade". A downgrade is only named after OSV.dev and its
    pinned dependencies confirm it. "No published version clears every
    advisory" now names the range that was checked.
  - *Offline answers from the cache.* With `FOURDA_OFFLINE=1` (or no
    network), vulnerability_scan, upgrade_planner and dependency_health answer
    from cached OSV.dev results, kept for 7 days past their 1-hour life. They
    name the oldest answer's age and keep NOT CHECKED for everything not in
    the cache. dependency_check names cached advisories for an exact version
    and leaves the verdict `unknown`. `force_refresh` offline no longer wipes
    the cache.
  - *upgrade_planner counts.* A dependency OSV.dev gave no answer for, with
    no newer release to offer, was counted as "vulnerable with no fixed
    release yet". It now has the action `not_checked` and is counted only as
    NOT CHECKED, never as vulnerable or clean. Clients that read `action`
    should handle the new value.
  - *Review fixes.* A `pnpm-workspace.yaml` whose `registries` map spans
    several lines was not read, so new names were sent; registry values are
    now read in every YAML shape, and one the reader cannot follow makes npm
    private for that folder (fail closed). A bare Cargo requirement "1.6" or
    "1" is read as Cargo reads it, a caret range; a release in that range
    held by the project's Cargo.lock is judged too, and the worse answer
    stands. A renamed crate is explained by the difference that applies
    (letter case, "-"/"_", or both). Offline, a fix release that was not
    checked says live lookups are off, not that a check did not finish.
  - *A wide range no release of which is clean is held.* A dependency spec
    is now judged at the newest release it admits, the one a fresh install
    or refresh gets. A range whose newest admitted release is affected makes
    the parent release affected; one that can't be read is NOT CHECKED. Until
    now any wide range counted as "not held", even when no release it admits
    is clean. mocha 10.6.0-10.8.2 require `serialize-javascript ^6.0.2`, every
    6.x of which is affected (an RCE among them), and 10.6.0 was named a clean
    target. It is now avoid, and upgrade_impact names no clean release in
    that line. An npm alias (`npm:event-stream@3.3.6`) is judged as the
    package it aliases. A safe pick is never a release the same answer calls
    avoid: react-native's deprecated 1000.0.0 placeholder is no longer offered.
    The shared rule vector ft-086 is amended in the 4DA corpus to match.
  - *Final review fixes.* A pip-style comparator on a name the task did not
    tie to PyPI ("add event-stream==3.3.6" in an npm project) is also judged
    on npm, and the worst answer stands, so event-stream 3.3.6 is human_only.
    In a project with both npm and PyPI, an ecosystem with no such release,
    or only a near-miss namesake, no longer outranks a real answer:
    "add rsa 4.7" and "add pandas 2.2.3" are judged on PyPI. When the guess and the
    project's own ecosystem give the same answer, the project's is reported. Planner rows say
    which dependencies a parent release holds (exact pin or range), never
    say "could not be read" for releases that were read, and say how many
    releases were checked when not all were. The planner's
    pinned-dependency checks now run within its time budget, and a row whose
    check did not finish is NOT CHECKED with no target named.
  - *uv's find-links.* `find-links` and `no-index` (`UV_FIND_LINKS`,
    `UV_NO_INDEX`, `uv.toml`, `[tool.uv]`, `[tool.uv.pip]`) were not read, so
    private names in a project that installs private wheels through uv were
    sent. They are now treated like pip's find-links.
  - *Briefing commands and specifiers.* `poetry add`, `uv add`, `pdm add`,
    `pipenv install`, `pipx`, `rye`, `cargo add` and `go get` fix the
    ecosystem for everything they name. "poetry add pyyaml@5.3" in an npm
    project is now checked on PyPI and comes back human_only. `gem`,
    `bundle`, `composer` and `conda` arguments are NOT CHECKED, never looked
    up on npm. A comparator glued to a name (`requests~=2.31`,
    `flask<2.2.5`) reads as PyPI, and a name checked in several ecosystems
    reports its worst answer once. A release carrying a crypto-miner (e.g.
    PYSEC-2024-154, ultralytics 8.3.41) counts as malware and is human_only.
    A Cargo `=1.6.0` pin keeps its `=`. "add a retry with backoff" and "add a
    progress bar" no longer read `retry` or `progress` as packages.
  - *Startup.* The first tool call no longer holds up a concurrent `ping`
    (242-2,905 ms before, 4-5 ms after, measured on the built server); the
    database schema is created in one transaction. Resolving a very large
    lockfile pauses every 15 ms. On a 150,000-entry pnpm lockfile the worst
    ping during the first call went from 2.4 s to about 150 ms, with
    identical findings. The lockfile is read with less heap (peak 316 to
    243 MB). Known limit: the process peak on that lockfile is still about
    440 MB.
  - *Protocol.* In a 2025-03-26 session, a JSON-RPC batch with a cancelled
    request is answered without it, over stdio and Streamable HTTP. Before,
    the batch waited forever, and a later request reusing the id was folded
    into it. A repeated id in a batch is refused with -32600. An open stdio
    batch is written at the tool-call budget plus 10 s at the latest.
- **Pre-publish fix (round 9).** In a project whose every dependency comes
  from a private index or registry (pip behind `PIP_INDEX_URL` or a
  requirements file's `--index-url`, Cargo with crates.io replaced), a briefing
  task naming a new package with no ecosystem ("add zqxpy-new") guessed npm
  and sent the name to OSV.dev and registry.npmjs.org. The guess now counts
  the private dependencies, and a name that would be looked up in an
  ecosystem whose registry is not public, or whose installed packages are all
  private, is reported NOT CHECKED (private) and never sent. The
  malicious-package check across other ecosystems skips those ecosystems too.
- **Pre-publish fixes (round 8).**
  - *Briefing.* A list no longer stops at a common or standard-library word:
    "add uuid and electorn", "add ms, crossenv" and "add json and ctx" said
    `safe_to_delegate` with the malware unchecked. A version constraint in the
    task ("add minimist <1.2.6", `">=1.2.5 <1.2.6"`, "django>=2,<3") is read
    whole and checked as one constraint. Each version binds to its own package
    ("A, B to X and Y", "/" between items, "depend on X 1.2.3"), the summary
    shows the worst verdict of everything checked, and names past the check
    cap are listed as NOT CHECKED. OSV advisory text moved out of
    `advisories[].action` into `advisories[].quoted_from_osv`, named in
    `_meta.untrusted_text`. "install the git hooks" names no package. The
    round-7 entry said a `[dependencies.serde] version` edit counted when
    `[package]` also has a version line; it did not, and does now. One bad edit
    in a MultiEdit no longer hides the others.
  - *Verdicts.* A constraint is judged at the release the package manager would
    install, the highest one it admits ("minimist <1.2.6" installs 1.2.5, which
    is critical, and said proceed); the safe exact pins are still given.
    RustSec's `malicious` category and "removed from crates.io for malicious
    code" count as malware, so `evm-units` is avoid again (6.2.7 had it; 6.3.0
    candidates lost it). A batch answer that contradicts the advisories already
    known for a package no longer wins, is not cached, and names no safe
    release. The OSV cache moved to `osv:v9`. With the npm registry failing
    for express's own dependencies, vulnerability_scan and upgrade_planner
    said `npm install express@4.20.0` and `express@4.22.0`, releases that
    install a vulnerable qs or body-parser: a parent upgrade now names only
    the first release whose pinned and narrowly ranged dependencies were
    confirmed clean (4.22.3 here), or NOT CHECKED with no release and no
    command, and `parentUpgrades[].smallest` never names a release that
    installs an affected dependency. An advisory whose grade could not be read
    keeps a package at avoid. When the whole OSV scan did not finish within
    the call, upgrade_planner rated rows "low" and `risk_threshold: "high"`
    dropped them; their risk is now unknown, listed under every threshold.
    The PyPI range check's release bucketing never matched (its pattern had
    lost its backslashes), so every release was compared with every listed
    version; a cold django check spends about half as long there.
  - *Privacy.* Private Python names stayed private in more layouts: PDM sources
    with `pdm.lock`, Pipfile `[[source]]`, pip config values on a continuation
    line, `-i<url>`, `--index`, `--extra-index`, `--find-links`/`-f` and
    `PIP_FIND_LINKS`, and uv.lock git sources on a private host. Under a private
    GOPROXY a sub-package path of a private module is private. Twice
    percent-encoded names, Cargo path members, Go `replace => ../local` modules
    and `!`-escaped Go spellings are refused. Under a private registry, index or
    proxy, a name that is not installed is private when the lookup names its
    ecosystem. A project's own workspace crates and Go module count as local.
  - *Protocol and process.* An over-10 MB stdio line is discarded whole; its
    tail ran as a request. Closing stdin, SIGINT or SIGTERM cancels requests in
    flight and exits (it kept working for up to a minute). stdio serves batches
    for 2025-03-26 sessions like HTTP. `--doctor` tests OSV.dev and the
    registries through the configured proxy. An offline scan starts with
    "NOT CHECKED (offline)". Conflicting modes (`--setup`, `--doctor`, `--http`)
    exit 2; an absolute-form HTTP target is served or refused with 400, never
    500. Reading a 150k-entry pnpm lockfile peaks at about half the memory.

- **Pre-publish fixes (briefing, round 7).** what_should_i_know left a package
  or a version unchecked in common wordings. "bring in rustdecimal" in an npm
  project said `safe_to_delegate`: npm has no such name, so it was dropped as
  prose, and crates.io's rustdecimal is malware (GHSA-7pwq-f4pq-78gm). "pull in
  node-ipc 10.1.1", "we need node-ipc 10.1.1", "bring in ua-parser-js 0.7.29"
  and "pull in event-stream 3.3.6" never tied the version to the name, so the
  malicious releases were not flagged. "add express, ctx", "add lodash 4.17.21
  and crossenv" and "add chalk 5.6.2 and electorn" never checked the second
  package: a comma, or a version after the first name, ended the list. "replace
  request with axios 0.21.0" (and swap / migrate) said "Task adds axios
  (proceed)": the version was dropped and latest judged. `add "dbg":
  "npm:debug@4.4.2" to package.json` said "Task adds dbg (proceed), npm
  (proceed)" and missed the malicious debug 4.4.2. The task is now read clause
  by clause (a sentence break, ";", "then" or a new verb ends one): after the
  verb (add, install, need, use, include, require, bring in, pull in, replace
  A with, swap A for, migrate / switch from A to) comes a list of items, each
  `name [version]`, separated by commas, "and", "&", "+" or "plus", and each
  version is bound to the item just before it ("upgrade lodash to 4.17.21 and
  add express 4.x" gives 4.x to express). A package the task names a version
  for is checked at that version, in new_packages as in requested_versions, and
  the summary names it ("Task adds axios 0.21.0 (avoid)"); the version of what
  a swap takes out is not judged. Manifest entries written into a task read as
  the dependency they declare: `"name": "npm:real@1.2.3"` is real 1.2.3 (never
  a package called `npm`), `"name": "^1.2.3"`, Cargo's `name = "1.2"` and
  `name = { version = "1.2" }`, and pip's `name==1.2`; a manifest's own fields
  (`"version"`, engines' `"node"`, `edition`, `rust-version`,
  `requires-python`) are not packages. A name the task gives no ecosystem for
  that none of the project's ecosystems has is also looked up, for malware
  only, in the other ecosystems (npm, crates.io, PyPI); private names are still
  sent nowhere. Up to eight packages a task adds are checked (was three, and
  the rest were dropped without a word); past eight the rest are named as
  "NOT CHECKED: N more packages named in the task (...)" and the briefing is
  never `safe_to_delegate`.
  Everyday work still names nothing ("add tests", "add logging to the
  handler", "add tests, logging and retries"). The plugin's manifest-edit hook
  counted `"version"` and engines' `"node"` in package.json, and `version`,
  `edition` and `rust-version` in Cargo.toml or pyproject.toml, as dependency
  changes: only dependency sections count now (the edited lines' own section,
  or the manifest on disk when they do not show it).
- **Pre-publish fixes (verdicts, round 7).** With OSV.dev failing only for
  express's own dependencies, `dependency_check {express, "4.x"}` said
  `unknown` and still named 4.20.0 the smallest safe release, which a healthy
  run calls avoid (it pins a vulnerable qs, cookie and body-parser), and the
  summary told the agent to write a safe version the item names; "add express
  4.x" in what_should_i_know did the same, as did a failed second page of a
  querybatch or a hanging advisory record. A release whose held dependencies
  could not be checked is now never named safe: the answer says NOT CHECKED
  (`range_check.held_not_checked`), offers no release outside the range in its
  place, and is never wider than the healthy answer. upgrade_planner no longer
  puts an unconfirmed release in `targetVersion` when the batch query fails,
  and a row OSV.dev gave no answer for has risk `"unknown"` (ranked and
  filtered with critical) instead of `"low"`. A call that runs out of time
  keeps what it already read: chalk 5.6.1 is avoid on npm's "unpublished" and
  its MAL- record instead of `unknown`, and one hanging `/v1/vulns/{id}`
  request (now 4 s per attempt) no longer eats the whole call. Registry
  deprecation and yank messages are no longer inside this server's sentences
  (`recommendations`, fix notes, planner reasons, the briefing's actions): they
  are in a top-level `quoted_from_registry`, which `_meta.untrusted_text`
  names. Repository and changelog URLs from a registry are held to http(s), at
  most 300 characters, with no whitespace or control character (a
  5,000-character one came back whole). An advisory id or alias with a line
  break inside is dropped, not glued into one id. upgrade_impact reads
  `to_version: "latest"` as the newest stable release, says when a refused
  target is vulnerable, unpublished or malware, and reads `"lodash"` (quoted)
  as dependency_check does. A version that is not a release number ("latest"
  for a package the registry does not have, a range) is never sent to OSV.dev
  from any tool. upgrade_planner names one upgrade command once, however many
  parents lead to it (`sameCommandsAs`). Cache keys change: the OSV answer
  cache moves to `osv:v8`, fix-path facts to `fixpath:v16`, and
  upgrade_impact's registry index to `upgrade-impact:index:v2`.

- **Pre-publish fixes (robustness and protocol, round 7).** A lockfile of
  130,000 or more entries whose lookups went unanswered (OSV.dev down, or the
  query budget spent) came back NOT CHECKED "the scan failed (Maximum call
  stack size exceeded)": a list was spread into a function call. No array is
  spread into a call any more, and `pnpm run check` refuses a new one; 200,000
  npm, Yarn, pnpm and Bun entries with the network blocked are 200,000
  unchecked, for the network's reason. One unauthenticated `--http` request
  (`GET http://[`) ended the server; a request target that is not a URL is now
  answered 400, anything a request handler throws is answered 500 without
  stopping the server, and an error no request handled is logged on stderr in
  either mode instead of ending the process (a closed stdout still ends it).
  On stdio `{"jsonrpc":"2.0"}` and `{"jsonrpc":"2.0","id":77}` got no reply;
  each now gets -32600, under its id when it has one. `FOURDA_OFFLINE=1` left
  the server online (463 requests): every yes/no variable (`FOURDA_OFFLINE`,
  `MCP_AUTH_REQUIRED`, `FOURDA_GITHUB_CHANGELOG`) is on for 1, true, yes or on
  and off for 0, false, no or off, in any case; any other value is read as its
  safe side (offline, authentication required, GitHub not asked) and said once
  on stderr. The first call on a large lockfile blocked longer than 6.2.7: a
  100,000-entry npm lockfile spent 6.2 s building a requested-by list that was
  copied on every entry, and a 150,000-entry bun.lock 3.7 s dropping trailing
  commas one character at a time. Both are linear now: npm 100,000 entries,
  first call 12.9 s / 729 MB peak to 3.1 s / 503 MB; Bun 150,000 entries 10.8 s
  / 1,725 MB to 4.3 s / 608 MB (`bench/lockfile-scale`). The fix-path rows a
  call's time budget left unstarted are worked out after the call returns, so
  a second scan of an unchanged project asks nothing (js-nest-npm3: 49
  requests, then 0). `constructor`, `__proto__` and `toString` were accepted as
  tool parameters ("the limit is function toString() { [native code] }"); only
  a tool's own parameters are. Invalid params on `initialize`, `resources/read`
  and `prompts/get` were answered -32603 Internal error; they are -32602.
  HTTP served JSON-RPC batches that stdio refuses: a batch is refused the same
  way (-32600) unless the request speaks 2025-03-26 or earlier, the revisions
  that require a server to accept one. `--port 80abc` bound port 80 and
  `--bogus` started the server: a port is a whole number from 1 to 65535 and an
  unknown argument exits with the usage and code 2. A scan served from the
  cache said `_meta.offline: null`; it is `false` (a boolean always), with
  `osv_contacted: false` saying OSV.dev was not asked.
- **Pre-publish fixes (privacy, round 7).** An audit of 5d709ff found
  configuration layouts in which a private package or module name still
  reached OSV.dev, a public registry or HN; each was confirmed with a dead
  proxy, and each now has a test that runs every tool and asserts no request
  names the private package while a public one is still checked. A pip
  requirements file whose `-r base.txt` or `-c constraints.txt` (nested, each
  relative to the file naming it, loops and depth bounded) set
  `--index-url` / `--extra-index-url`: the included file's options now apply
  to the whole install, as in pip. uv and Poetry projects with no lockfile:
  a `[[tool.uv.index]]` that is the default or not `explicit`, `[tool.uv]`
  `index-url` / `extra-index-url`, `uv.toml` (the project's or above it, the
  user's, the system's, `UV_CONFIG_FILE`), `UV_DEFAULT_INDEX`, `UV_INDEX_URL`,
  `UV_INDEX` and `UV_EXTRA_INDEX_URL`, and a Poetry source that is not
  `priority = "explicit"` (primary, default, supplemental, legacy
  `default = true` / `secondary = true`) or a PDM source now make every
  package the project declares private, ranged and unpinned ones included; the
  public wheel indexes (PyTorch, NVIDIA, PyG) are still allowed as extra
  indexes. A PEP 508 direct reference (`name @ https://...`, `git+https://`,
  `file:`) or a uv / Poetry `git`, `url` or `path` source on a host that is not
  public makes that name private (pypi.org's files, the public wheel indexes
  and GitHub, GitLab and Bitbucket are public). Cargo: every workspace
  member's Cargo.toml is read (`members` globs, `exclude` respected), a `git =`
  dependency and a `[patch]` entry count like `registry =`, and
  `.cargo/config.toml` is read in the project, every directory above it and
  `CARGO_HOME` (`[patch]`, and `[source.crates-io] replace-with` a registry).
  npm: the global npmrc (`npm_config_globalconfig`, `<prefix>/etc/npmrc`,
  `%APPDATA%\npm\etc\npmrc`), a quoted `"@scope:registry"` key,
  `npm_config_@scope:registry` and every other `npm_config_*` in any case, the
  user's `~/.yarnrc.yml`, `YARN_RC_FILENAME`, `YARN_NPM_SCOPES` and
  `YARN_NPM_REGISTRY_SERVER` are read. The request guard reads a GOPRIVATE
  module in every git spelling: `https://github.com/org/mod.git`,
  `git+ssh://git@github.com/org/mod`, `git@github.com:org/mod.git`,
  `...#v1.2.3`, `.../tree/main`, a bare `mod.git`.
- **One mirror policy for npm, PyPI, Go and Cargo (behaviour change).** A
  default registry, index or proxy that is not public, consulted for any name,
  now makes that ecosystem's packages in the project private (never sent,
  reported as not checked, the setting named), as a pip `--index-url` already
  did. Until now an npm `registry=` host (and bun's `[install] registry`) was
  read as a mirror and unscoped names were looked up publicly with only a
  notice, and a `GOPROXY` pointing at a private proxy with no GOPRIVATE sent
  every module path to proxy.golang.org and OSV.dev. A server that only
  mirrors the public registry is declared with `FOURDA_PUBLIC_MIRRORS` (hosts),
  and its packages, lockfile hosts included, are checked again in every
  ecosystem. `registry_notice` for npm now says the packages were treated as
  private and names the setting.
- **Pre-publish fixes (scan speed, round 6).** On a 1,889-dependency npm
  project a vulnerability_scan with every answer cached took 3.7 s, and the
  server did not answer `ping` until it was done (6.2.7: 0.3 s); at 107,000
  lockfile entries `ping` waited 20.8 s. Every parent lookup re-read, re-parsed
  and re-walked the whole lockfile. Each lockfile is now read once, indexed
  child-to-parents once (kept while its size and modification time stay the
  same), and every lookup is a map read; npm, pnpm, Yarn classic and berry, Bun
  and Cargo lockfiles alike, and Python lockfiles are read once per call. Long
  work gives the event loop back every 15 ms, so `ping` answers in tens of
  milliseconds during a scan. A second scan in the same process re-sent about
  90 querybatch and 90 `/v1/query` requests: the fix confirmations went out one
  release per request, used up the 60-a-minute OSV.dev query budget, ran out of
  time waiting for it, and were asked again by the next scan. Small queries
  made at the same moment now share one request, concurrent checks of one
  release or one package's advisory list ask once, and an npm document still
  being fetched is no longer dropped and fetched again. The fix-target check and
  the fix-path verdicts run side by side. A transitive finding whose fix path
  was not worked out within the call now says so (`fix_action: "not_checked"`
  with `fix_action_note`, `action`/`action_note` in `fix_targets`) instead of
  carrying no action at all. A version that is not a release number ("latest"
  for a package the registry does not have) is never sent to OSV.dev and never
  confirmed. No cache key changes: what is cached, and its shape, is the same.
- **Pre-publish fixes (briefing, round 6).** In a project with package.json,
  package-lock.json and requirements.txt, what_should_i_know said
  `safe_to_delegate` for "add ctx", "add ctx, then refactor the handler",
  "install the ctx module" and "add `ctx`": it looked up npm's `ctx` (clean)
  and never PyPI's, which is malware (PYSEC-2022-199). A package the task names
  without saying where it comes from is now checked in every ecosystem the
  project uses, at once and within the same budget, and the worst answer
  stands (`also_checked` lists the others); "pip install ctx", "add ctx to
  requirements.txt", "npm i ctx" and "cargo add" still check only the one
  named. "we need X", "we'll need X", "bring in X" and "pull in X" read like
  "add X" ("we need electorn for the desktop build" is electron's malware
  typo-squat), by name only: a version written after X, or a second package
  after a comma, was not read until round 7. A bare name one or two edits from a popular PyPI project is a
  package in a project that installs from PyPI ("add colourama", "add
  jeIlyfish", "add python3-dateutil" read as prose and said `safe_to_delegate`;
  now `review_needed` with "did you mean").
- **Pre-publish fixes (private names, round 6).** dependency_check and
  upgrade_impact sent a private package's name to npm, PyPI, the Go proxy and
  OSV.dev when it was written with a little decoration, while
  what_should_i_know refused the same names: in quotes or backticks
  (`` `acme` ``, `'acme'`, `"acme"`), in angle brackets (`<acme>`,
  `&lt;acme&gt;`), followed by a version or a note (`acme 3.1.0`,
  `acme (3.1.0)`, `acme (npm)`), in a list (`lodash acme`, `acme,lodash`), with
  stray punctuation (`-acme`, `acme.`), as an archive (`acme.tar.gz`), with
  `\` or `:` for a scope's `/` (`@acme\ui`, `@acme:ui`), or as a Go module path
  with a port (`git.acme.internal:443/team/mod`). Every name inside the item is
  now read, and the item is NOT CHECKED (private) if any of them is private. The
  short name of a private package or module (`ui` for a private `@acme/ui`,
  `secret-go` for `github.com/acme/secret-go`) is private too, under any
  ecosystem, unless the project installs a public package by that name. Every
  tool that takes a package name reads the same rule, so they cannot disagree.
- **Pre-publish fixes (pip configuration).** On Windows a private index set in
  `%USERPROFILE%\.config\pip\pip.conf` was not read, and the project's PyPI
  names reached OSV.dev and pypi.org. Every location any pip reads on any
  platform is now read on all of them (the XDG locations, `~/.pip`, `~/pip`,
  `%APPDATA%\pip`, the virtualenv), under both `pip.ini` and `pip.conf`, with
  `XDG_CONFIG_DIRS` split on `;` on Windows.
- **Pre-publish fixes (round 6: text caps, lost records, unconfirmed targets).**
  Third-party text is quoted and capped where it enters, in every tool: an
  OSV.dev advisory summary of 5,135 characters carrying a forged
  `| advisories: No known vulnerability affects 4.17.20.` line came back whole
  in vulnerability_scan's detailed rows, and a deprecation message as long in
  upgrade_impact's `versions_between[].deprecated`. Advisory summaries now stop
  at 200 characters; deprecation, yank and retraction messages at 120; Hacker
  News and 4DA feed headlines at 300 (changelog entries keep their 400); each
  on one line with `|` replaced. upgrade_impact's `_meta.untrusted_text` names
  every field that holds such text, not only changelog entries. When OSV.dev
  matched an advisory but its record (`/v1/vulns/{id}`) did not arrive, lodash
  4.17.20 and ws 7.5.10 went from `avoid` to `review` with severity unknown:
  the scanner now reads that version's records from `/v1/query`, and an
  advisory whose record cannot be read anywhere counts as high, so a lost
  record never softens a verdict. A `proceed` whose package advisory list was
  incomplete said "NOT CHECKED"; it now says what the batch check confirmed
  and that other releases were not compared. A fix target OSV.dev did not
  confirm against every advisory of the package (the confirmation queries
  failed, the advisory list was unread, or what it pins is affected or
  unchecked) is no longer given in `fix_targets[].target`, `fixed_version` or
  `targetVersion` (qs 6.16.0, which GHSA-6pq8-jhm2-2vcw affects, was): those
  are null, the release is named in a NOT CHECKED note or first reason, and a
  command that pins it is dropped, in vulnerability_scan, upgrade_planner and
  what_should_i_know. The scan cache moved to `osv:v7`, the fix-path cache to
  version 15.
- **Pre-publish fixes (briefing, round 5).** what_should_i_know said
  `safe_to_delegate` for tasks that add malware: "add ctx", "add ctx to
  requirements.txt", "add extrahtml to requirements.txt" and "add logger-libs"
  in a Python project, "replace lodash with lodahs", "swap express for expres"
  and "add flatmap-stream". A bare "add X" now checks any plausible name, a
  name put in a manifest or the dependency list is always a package, and
  "replace/swap/switch/migrate A with/for/to B" checks B (at latest: a
  version written after B was dropped until round 7). Everyday English is
  not looked up ("install steps", "add routes to the app"), and a bare name no
  registry has and no malware record covers is read as prose. Quoted versions
  (`lodash@"4.17.20"`) and npm aliases (`lodash@npm:event-stream@3.3.6`) are
  judged at the version written; anything else after `name@` that cannot be
  read is unread, which keeps the briefing from `safe_to_delegate`. "lodash in
  package.json to 4.17.20" ties the version to lodash in a project without it.
- **Pre-publish fixes (verdicts).** A Go module path the go command would not
  accept as written (`github.com/gin-gonic/gin/`, `github.com//gin-gonic/gin`,
  `github.com/x/y/../../gin-gonic/gin`, `@v1.6.0` inside the path, or a case
  the module's own go.mod does not declare, such as `github.com/Labstack/Echo/v4`)
  said `proceed` for vulnerable versions: OSV.dev matches the exact path and
  matched nothing. dependency_check, upgrade_impact and what_should_i_know now
  answer NOT CHECKED (`not_checked: "module_path"`) with the canonical path.
  dependency_check of `{PyPI, django, 4.2.0}` took 25-30 s of CPU that blocked
  every other call; parsed versions are now kept, an advisory's listed versions
  indexed, and each release's advisories computed once (about 0.3 s warm;
  litellm 1.82.7 from 20 s to under 1 s warm). The typo-squat name check runs
  whenever the project's lockfiles do not hold the package, with `from` or
  without. upgrade_planner reads go.mod `replace`: it says to move or drop the
  replace (`go mod edit -replace=...`), or that a fork or local replacement
  blocks the fix, instead of a `go get` that changes nothing built. An npm
  alias in `to` (`npm:lodash@4.17.20`) is judged as the package it installs.
  dependency_check no longer names a maintainer-flagged "bad release"
  (lodash.template 4.18.0) as the safe release; a malicious name lists every
  record covering it (GO-2025-3451 beside MAL-2025-2545); and a "newest safe
  release" is one no advisory affects at all.

- **Pre-publish fixes (privacy and protocol).** `what_should_i_know` now
  recognises a private package the task names (installed, or covered by the
  private rules): it leads with `NOT CHECKED (private)`, lists
  `private_dependencies`, and never answers `safe_to_delegate` for it (a task
  upgrading `@acme/vault-core` came back "No dependency of this project is
  named in the task", safe). A private PyPI index named by `--index-url` / `-i`
  in a requirements file, `PIP_INDEX_URL` or pip's config file makes the pins
  it serves private (`omega-internal-risk==3.1.0` reached OSV.dev and
  pypi.org); `--extra-index-url` keeps names public and says so. A name a task
  mentions is never looked up under a guessed ecosystem when the project marks
  it private in any ecosystem ("bump omega-internal-risk to 3.2.0", private by
  a pip `--index-url`, was guessed npm and sent to OSV.dev and the npm registry;
  black-box re-run 2026-11-14). A private name is also recognised in every form
  an agent may write it: `npm:acme-x`, `acme-x@1.0.0`, percent-encoded, with an
  invisible character, as a registry URL, `omega[extra]`, `omega==3.2.0`, and a
  GOPRIVATE module with a capitalised host (each reached the network; blind
  audit 2026-11-14). Deciding which names are private is now linear: a
  40,000-dependency tree took 34 s with the server unresponsive, now under
  0.1 s. The briefing reads "add event-stream version 3.3.6", "set lodash
  version to 4.17.20" and "version X of name", and a task that writes a release
  a critical advisory affects is `human_only` (event-stream 3.3.6 came back
  `safe_to_delegate`). `reason` carries every review finding beside an avoid
  (time 0.3.8 named the yank but not RUSTSEC-2026-0009), and no longer says no
  release in a range is clean while answering `proceed` on one. A JSON-RPC batch
  array, or a line that is not a JSON object, gets `-32600` instead of silence.
  The README says the Go proxy is asked for `.mod` as well as `.info`. No `_meta.privacy`
  says private names are sent any more (vulnerability_scan still said
  "private names included"), and a test holds every one to the README. One
  shared cleaning for third-party text (changelogs, OSV summaries, deprecation
  and yank messages, Go retraction rationales, HN titles) now removes Unicode
  tag characters and invisible operators too: an instruction hidden in tag
  characters survived the changelog parser. A malformed JSON-RPC line gets a
  `-32700` Parse error, a request before `initialize` is refused with
  `-32600`, and every tool error is one compact `{"error": ...}`.
- **what_should_i_know judges the version a task names.** "add lodash
  4.17.20" was judged at latest and came back safe_to_delegate; "pin axios
  to 0.21.1" did not see axios. `name@v`, `name==v`, "name to v", "name from
  a to b", "pin name v" are read and judged by dependency_check at exactly
  that version or constraint (`requested_versions`); one that is not proceed
  is never safe_to_delegate.
- **Every lookup goes through HTTPS_PROXY / HTTP_PROXY**, with NO_PROXY
  honoured, on every supported Node (undici's EnvHttpProxyAgent; `undici`
  7.30.1, MIT, pinned). A proxy that cannot be reached makes the answer NOT
  CHECKED, never a direct connection.

- **dependency_check says avoid for a name that is malware itself.** `{npm,
  lodahs, latest}` said proceed: `latest` is 0.0.1-security, the empty
  placeholder npm publishes after taking a malicious package down, and the
  scanner rightly drops findings on an installed placeholder (it holds no
  code). `electorn`, `loadyaml`, `axois` and others read the same. A name npm
  holds with a security placeholder, or that a malicious-package record covers
  as a whole (open from the first version, every listed release, or a name the
  registry no longer has), is now `avoid`, with the records and the popular
  package it imitates when one is close ("Did you mean lodash?"). Hijacked
  releases of real packages (chalk 5.6.1, nx 21.5.0, ua-parser-js 0.7.29) stay
  avoid release by release, and the rest of those packages is judged as before;
  vulnerability_scan still reports no malware for an installed placeholder. On
  43 taken-down names checked live, all are avoid (6.2.7: 7 proceed); none of
  the 1,822 bundled popular names is flagged. The suggestion list is bundled
  (`src/live/popular-npm.ts`, from npm-high-impact 1.13.0), so it works offline.
  A name the registry does not have also gets the suggestion in its `unknown`.
- **dependency_check no longer says proceed for a name one slip from a popular
  package.** `expres`, `reactt` and `expresss` each said proceed: they are on
  the registry, no advisory names them, and the near-miss the server computed
  (express, react) was printed only beside names npm had already taken down.
  A NEW npm dependency (no `from`) whose name is one edit, a dropped `.js` /
  `-js` / `js` / `node-` affix, or (from 6 characters) two edits from one of
  the 1,822 bundled popular names now gets a `name_check` signal: `review` with
  "did you mean express?" unless the name is established. Established means
  10,000 downloads a week or more and at least a thousandth of the popular
  package's own (a typo of a package installed 200 million times a week collects
  thousands of mistaken installs: `expres` 5,216 against 195 million), or
  100,000 or more whatever that share, and first published at least 90 days
  ago. `avoid` when a count that was read shows it is not established and it
  is under 30 days old or runs install-time scripts. Downloads that cannot be
  read never count as established: the verdict is `review`, never `proceed`. A
  name on the popular list is never flagged for neighbouring another (`preact`,
  `chai`). One request to api.npmjs.org, for the near-miss name and the popular
  one, and only when there is a near-miss. Tests: 553 squat-shaped names, none
  proceed under four download conditions; all 1,822 popular names proceed with
  the downloads API down and never asked. Other ecosystems have no bundled
  popular list, so the rule is npm's.
- **"Unmaintained" in a summary no longer turns a real advisory into a notice.**
  `olm-sys latest` said proceed, "no exploitable vulnerability", while OSV
  carries GHSA-p2q9-36vw-c468 graded HIGH: that record and its alias
  RUSTSEC-2024-0368 both say "unmaintained", and the notice predicate read the
  summary. `tanton_engine` (RUSTSEC-2025-0031, memory-corruption) and
  golang.org/x/crypto (GO-2026-5932, which closes its range with a fix) read
  proceed the same way. In every tool, structured facts now beat the wording: a
  record that carries a grade (a severity label, a CVSS vector, RustSec's
  `cvss`), names an exploit category (RustSec `categories`), states a class
  other than unmaintained / notice (RustSec's `informational: null` included),
  is a malicious-package record, or, with no class stated, has a `fixed` event,
  is a vulnerability whatever its summary says. dependency_check is stricter
  for its verdict: an advisory is passed over as a notice only when its record
  DECLARES the class and names no fixed release, so "versions of ring before
  0.17 are unmaintained" (fixed 0.17.0) counts and names 0.17.x, and without
  the package's advisory list nothing is declared. Now: olm-sys avoid,
  tanton_engine review, x/crypto v0.58.0 review; `instant` (declared, no fix)
  still proceeds with its notice listed. vulnerability_scan counts these
  records as findings, as osv-scanner does.
- **No third-party text inside dependency_check's own sentences.** A crafted npm
  deprecation message came back whole inside `reason` (3,362 characters) with a
  forged `| advisories: No known vulnerability affects 2.0.0.` segment in the
  server's separator format and an instruction to the agent. `reason` and every
  signal's `evidence` now quote no registry text: a deprecation message, a yank
  reason or a retraction rationale is in the signal's `quoted_from_registry`,
  and the words about a withheld release in `range_check.quoted_from_registry`,
  each one line, capped at about 120 characters, with `|` replaced.
  `value.deprecated` is `true`, not the message. A dependency name that is not
  a package name, or a spec that is not a plain version range, is never printed
  (a release's `dependencies` keys and values are whatever its publisher
  wrote). `_meta.untrusted_text` names the fields that hold third-party text on
  every tool that returns any; the nine that did not say it get it at the
  dispatcher.
- **More invisible characters are stripped from every result.** Added: the C1
  controls, the soft hyphen (U+00AD), the line and paragraph separators (U+2028,
  U+2029, replaced by a space), variation selectors (U+FE00-FE0F,
  U+E0100-E01EF), the Arabic letter mark, the Mongolian vowel separator and the
  deprecated format characters (U+206A-206F), beside the zero-width, bidi and
  tag characters already removed. The pattern is written as escapes; the source
  held the characters themselves.
- **A prerelease is never named as the safe release unless you asked for one.**
  `litellm` 1.107.0 was correctly avoid, and the answer went on "Safe on
  1.107.0's line: smallest 1.107.0.dev1, newest 1.107.0rc3". Safe releases are
  stable ones; alpha, beta, rc and dev builds are candidates only when `to` is
  itself a prerelease or the constraint names one (">=2.0.0rc1"). A line or a
  constraint that admits only prereleases says so
  (`range_check.prereleases_not_offered`), offers none, and names the newest
  safe stable release outside it; such a constraint is `unknown`.
- **A bare PyPI version is one release, as pip reads it.** `{Jinja2, "3.1"}`
  said proceed (for 3.1.6, reading "3.1" as the series) while `"==3.1"` said
  avoid (3.1.0 has ten OSV ids); an agent then wrote `Jinja2==3.1`. "3.1" is
  now 3.1.0, the same answer as "==3.1". For the series ask "3.1.*" or "~=3.1.0".
  npm, Cargo and Go read a bare "7" / "7.5", "1" / "0.17" and "v1" as ranges
  themselves, and those are unchanged. Every item now says how `to` was read
  (`to_read_as`).
- **An avoid over a held dependency now says what clears it.** Every Next.js 15
  release exact-pins postcss 8.4.31, and `{next, "^15.0"}` said avoid and "No
  release in ^15.0 is free of known advisories", nothing more. Whatever the
  held advisory's grade, `range_check.held_advice` now names the dependency,
  its advisories and the release of it that clears them (the override): review
  for a low or moderate one, as before, and avoid for a high or critical one
  with the override said. A release outside the range that was "not known safe"
  only because none had been judged (every release holds something) is judged
  and offered: 16.4.5 for next. When nothing in a range is safe, the answer is
  about the newest release whose only issue is a low or moderate held
  dependency, when there is one.
- **what_should_i_know checks the packages a task adds.** "add the lodahs
  package" came back safe_to_delegate: the briefing asked only which of the
  project's own dependencies the task names. It now reads the names a task adds
  (a package-manager command, "add the X package", "install X", a code-quoted
  name) and runs each through dependency_check at `latest`: a malware name is
  human_only, a near-miss name or one the registry does not have is
  review_needed, and a check that could not run is never safe. `new_packages`
  lists them with the verdict.
- **No more steering to a release years old over a moderate advisory a
  dependency holds.** `{npm, nx, latest}` said review and "Newest safe release
  outside it: 13.2.4" (December 2021) because every 24.x exact-pins minimatch
  10.2.5 (GHSA-g3hv-75wg-m249, moderate). When no release in range is safe, the
  newest safe release outside it is offered only when it is at most one major
  below the requested one and under about 18 months old. When a low or moderate
  advisory on a held dependency is what stands in the way, the answer names
  the dependency, its advisories and the release of it that clears them, with
  the override that installs it ("override minimatch to 11.0.1, a new major of
  minimatch: check that nx works with it"), in `range_check.held_advice`. A
  release that is itself vulnerable (nx 21.5.0) is pointed at the newest
  release clear of the package's own advisories, with the same advice, not at
  13.2.4. High and critical held advisories are unchanged: avoid.
- **vulnerability_scan and dependency_check read a malformed range bound the
  same way, OSV's.** GHSA-92cp-5422-2mw7 (go-redis v9) opens a range at
  `9.6.0b1`. vulnerability_scan treated the record as unreadable and said no
  release clears it ("9.6.3 is still affected"); dependency_check read the bound
  as 0. Both now read it as OSV.dev does (`9.6.0-b1`: missing parts are 0, a bare
  suffix is a prerelease), and both name v9.6.3 for an installed v9.5.1.
- **CVSS v4.0 vectors are scored.** A record with only a `CVSS:4.0/` vector and
  no label (RUSTSEC-2026-0459, libsqlite3-sys) was graded `unknown`; it is now
  medium (6.8). The score is a port of the FIRST reference calculator, checked
  against it on 100,000 random vectors with no difference. A curated label still
  wins, and a v3.x vector still wins over a v4.0 one.
- **upgrade_planner reads the app's plan schema 5 as well as 4.** The 4DA app
  now writes the mechanisms `lockfile_refresh`, `parent_update` and
  `blocked_upstream` (`lockfile_or_parent_update` now means the route is
  undecided or differs between copies) and `blocked_upstream` holds on a step.
  Each step gets a `next_step` sentence in its schema's terms; a blocked step
  names no upgrade, says what holds each copy and lists the options. Holds are
  narrowed by `project_path` with the lines. Any other schema still falls back
  to the standalone plan, saying why.
- **The first scan after updating fetches again, once.** The scan cache moves to
  `osv:v4` and the fix-path cache to version 12, since entries written by 6.2.7
  hold the old grades and range readings.
- **A lockfile `.gitignore` lists is scanned, and what is not scanned is
  listed.** A project whose `.gitignore` named `package-lock.json` read "5
  dependencies, 0 vulnerable" with no `coverage` block while
  `backend/package-lock.json` held 750 packages and 171 advisories; lockfiles
  in dot-directories (`.github/actions/*`, `.design-system`) were skipped the
  same way. A lockfile is what is installed, so it is read whether or not it is
  committed, and a dot-directory is a directory like any other. A directory
  `.gitignore` excludes is still not scanned (it is as often a scratch clone as
  the project's own code), and installed code, build output, caches and tool
  state (`node_modules`, `target`, `dist`, `.venv`, `.tox`, `.git`, `.claude`
  ...) are never entered; every lockfile found in an ignored directory, or
  sitting directly in a `build/`-style one, is listed by path under
  `coverage.not_scanned.lockfiles` with `coverage.complete: false`.
  `_meta.resolution.lockfiles` marks a file read although gitignored.
- **A manifest with no lockfile is never a clean result.** Exact pins in a
  `package.json` or `Cargo.toml` with no lockfile were checked and the answer
  said nothing more: `next 15.5.29` alone read "3 dependencies, 0 vulnerable"
  while the postcss it installs has four advisories. The answer now says the
  transitive tree was not resolved (`coverage.unresolved_manifests`). A
  manifest in a subdirectory that no lockfile above holds as a workspace
  member is listed (`coverage.manifests_without_lockfile`), a binary
  `bun.lockb` is named as unreadable, and `environment.yml`, a `setup.py` with
  `install_requires`, a `pylock.toml` and a `Pipfile` with no `Pipfile.lock`
  are named under `coverage.not_covered`. A `pyproject.toml` with no lockfile
  lists its dependencies as not checked instead of advising `poetry install`.
- **A requirement with no pinned version reads NOT CHECKED.** `pydantic>=2.0.0`
  gave "pydantic unknown (direct): no known advisories", and a requirements
  file that pins nothing was said to "pin only the packages listed". Such
  requirements are listed in `coverage.unpinned_requirements`; when nothing at
  all was scanned the totals are null, not 0.
- **Two lockfiles in one directory: the answer says which was read.** With a
  `package-lock.json` and a `yarn.lock` (or pnpm, Bun) side by side, the first
  by rank was read without a word. The other is now compared and, when it pins
  a different set, named in `coverage.conflicting_lockfiles` with the packages
  that differ.
- **npm aliases in package-lock.json are scanned as the package they install.**
  `"my-lodash": "npm:lodash@4.17.20"` was sent to OSV as `my-lodash` and read
  "no known advisories", in lockfile versions 1, 2 and 3. The entry's real name
  (v2, v3) or its `npm:` spec (v1) is used, and the dependency stays direct.
- **Git and URL dependencies are not matched as registry packages.** A
  `bignumber.js@2.0.7` resolved from `git+ssh://` was checked as npm's
  `bignumber.js 2.0.7`. Dependencies installed from git, a URL or a local
  archive (package-lock.json, yarn.lock, pnpm, Bun, uv, Poetry, Pipfile.lock,
  requirements files) are listed in `coverage.not_checkable` and never sent to
  OSV under the registry name. Their location is not echoed. Cargo git sources
  are unchanged (the shared conformance truth counts them).
- **Damaged and oddly encoded files are not read as less, silently.** A UTF-16
  `requirements.txt` (what Windows PowerShell 5 writes for `pip freeze >`) gave
  0 dependencies, and a UTF-8 byte-order mark made a valid `package-lock.json`
  "invalid JSON": both are decoded. A truncated `Cargo.lock` read as 14 of 85
  packages and a truncated `pnpm-lock.yaml` as 17 of 93 with no notice: a
  lockfile that is cut short or damaged (also `yarn.lock`, `poetry.lock`,
  `uv.lock`, `pdm.lock`) is reported in `coverage.partial_lockfiles` with what
  gives it away. On about 200 whole lockfiles (the conformance corpus and
  local repositories) the checks flag none.
- **The stored scan is at most one hour old.** The server lives as long as the
  IDE, and the scan `what_should_i_know`, `upgrade_planner` and
  `dependency_health` reuse never aged. Past an hour it is taken again; if that
  fails the answer is NOT CHECKED, never the old scan.
- **An advisory whose record could not be fetched is NOT CHECKED, not
  "unknown, no fix".** One failed detail fetch turned a critical into
  `unknown` with no fix version and cached that for an hour. Such a row now
  carries `details: "NOT CHECKED"`, is never dropped by `severity_filter`, is
  not worded as "no fix version published", makes the answer incomplete
  (`coverage.details_unchecked`, in every tool), and is not cached.
- **Every page of an OSV answer is read.** `next_page_token` from querybatch
  was ignored. It is followed; a dependency whose later pages cannot be had is
  unanswered, not recorded with its first page.
- **A cloned repository can no longer hang the server.** Two lines of
  `.gitignore` (`a*a*...*b`, 20 stars) beside a 40-character directory name made
  6.2.7 stop answering: `dependency_check`, then `tools/list`, for as long as
  the process lived. Patterns were translated to regular expressions and
  matched during the synchronous startup walk. They are now matched without
  backtracking (each `*`-separated piece is located once, left to right; a
  path is one forward pass over its segments), `**` is read as git reads it
  (`src/**/fixtures` no longer matches `src/notfixtures`), and a file's size,
  its rule count and each pattern's length are capped. Anything over a cap is
  not applied as an ignore rule, and a negation that cannot be applied
  re-includes everything below its file, so a cap can only make the walk scan
  more. The walk itself has a time budget (10 s, `FOURDA_WALK_BUDGET_MS`):
  past it the answer is a partial scan that says so ("the directory walk
  stopped at its 10 s time budget"), with `coverage.complete: false`. A lockfile
  or manifest over 64 MB is not read and is reported as UNREADABLE, "its
  dependencies were not checked". A 200 KB `Cargo.toml` of repeated `[package]`
  headers, which took 3.8 s to read, takes under a millisecond.
- **An over-long argument is refused, and a long constraint no longer blocks
  the server.** A `to` of 8 KB (`>=` and 4,000 one-digit tokens) took 7 s and
  held up a concurrent `tools/list`; 40 KB never answered. A version or
  constraint is limited to 256 characters and a package name to 512, with an
  error that says which argument, how long it was and how it starts. The range
  parser is one pass and each constraint is parsed once, not once per
  published release.
- **Every tool call has a time budget of 20 s** (`FOURDA_CALL_BUDGET_MS`),
  counted from the moment the request arrives. A cold `dependency_check` for
  litellm or Django took 21 to 37 s, and with OSV.dev stalled 49 s, after which
  it said OSV "did not answer within 15 s". `vulnerability_scan`,
  `dependency_health` and `upgrade_planner` size their own waits from what is
  left and answer with what they have, the rest NOT CHECKED. A call still
  running at its budget is answered in its place: every `dependency_check` item
  `unknown` ("did not finish within 20 s ... This is not a proceed"), any other
  tool an error that starts NOT CHECKED. Nothing is aborted: the lookups run on
  and are cached, so the same call made again answers from them. OSV's own
  message now says "did not answer within 15 s on either of 2 attempts".
- **A fix target must exist for that exact package or module path.**
  `go.etcd.io/etcd` was sent to "v3.4.44", a fixed version OSV names for the
  import path that the Go proxy does not serve for that module (Go major 3 is
  `go.etcd.io/etcd/v3`). A target above every release the registry listed is
  now asked for by name (the proxy's `.info`, the npm registry, PyPI, the
  crates.io index). Served: it is the target, without the "confirm it is
  published" caveat. Not served: no release is named, the step is
  `no_fix_available`, and the reason says "No installable fix on this module
  path" and where the fix lives ("Go major 3 is a different module,
  go.etcd.io/etcd/v3 (the proxy serves it, ...), and moving to it changes the
  import path"). The advisory's own row says the same. Unanswered: the caveat
  stands.
- **A release its maintainer deprecated by itself is never the target.**
  lodash.template 4.5.0 was sent to 4.18.0 ("Bad release. Please use
  lodash.template@4.5.0 instead.") past 4.18.1, because the package is retired
  and every release is deprecated, which the rule read as one line-wide notice.
  A release whose `deprecated` message is not the notice the rest of its line
  carries is now withdrawn like any other: the target is 4.18.1, with 4.18.0
  named as passed and 4.18.1's own retirement notice still said. A line whose
  releases all say one thing is unchanged (glob 10.x keeps 10.5.0).
- **No parent upgrade when a lockfile refresh is enough.** "tailwindcss 3.4.19
  is the smallest tailwindcss release that brings in sucrase 3.35.1" was said of
  a project whose installed tailwindcss 3.4.18 already requires `sucrase
  ^3.35.0` (2 of 9 sampled claims; the same for `@azure/identity` under
  `@vscode/vsce`, which was told to cross a major). When every installed parent
  of the blocking parent already admits a release of it that fixes the package,
  the step is `lockfile_refresh` with the exact command (`npm update sucrase`),
  names no upgrade of anything the project declares, and carries no
  `parentUpgrades`. A parent that does not admit it is still named, as before.
- **An override the project already has is read.** With `"overrides": { "qs":
  "^6.16.0" }` the plan read request's own `~6.5.2`, called the parent stuck
  and said to add an override. npm `overrides`, pnpm `pnpm.overrides` (and
  `overrides:` in pnpm-workspace.yaml) and Yarn `resolutions` are now the
  effective requirement, each for its own tool: an entry that admits the fix
  makes the step `npm update qs`; one that excludes it makes the step "change
  that entry", with no parent blamed and no second override suggested.
- **vulnerability_scan and upgrade_planner give one answer per finding.** On
  4DA's own src-tauri the scan said "Upgrade zip 8.6.0 → 9.0.5" while the
  planner said, correctly, that docx-rs 0.4.22 (its newest release) requires
  `^8.6.0`. The scan now runs the planner's fix-path verification on every
  vulnerable copy it lists, and a transitive copy's recommendation is that
  verdict in the planner's words: "Refresh ... with a lockfile refresh",
  "Upgrade the parent that pins ...", "Blocked upstream: ... it takes an
  override or replacing the parent", or "Waiting on upstream". A copy whose fix
  path could not be read in time says so (NOT CHECKED) instead of naming a bare
  version. `fix_targets` carries the planner's `action`, `breaking` and
  `commands`; a concise row carries `fix_action` and `fix_breaking` for a
  transitive copy.
- **A yanked release is never named for code this host does not build.** The
  plan named crypto-bigint 0.7.6 (yanked on crates.io) for a crate not built on
  Windows: those rows were never checked. They are now checked like any other
  (after the findings that count): the target is 0.7.9, with 0.7.6 to 0.7.8
  named as yanked, in the plan and in the scan's platform-inactive rows.
- **"breaking" is honest about forced versions.** "Force uuid to 11.1.1" under
  request 2.88.2 (`^3.3.2`) said `breaking: false`; request does
  `require('uuid/v4')` and uuid 11 removed that export. A forced override,
  resolution or Cargo `[patch]` that crosses a major version of what the parent
  declares is now `breaking: true`, and the step says why (zip 8 → 9 under
  docx-rs is one). A transitive step whose only move is a major upgrade of what
  the project declares is breaking too.
- **A dead installed line names the smallest safe release and the newest.**
  "No 8.x release clears every advisory: 9.0.0 is the smallest safe release, on
  the nearest later line that has one; 9.0.3 is the newest safe release"
  (jsonwebtoken 8.5.1; Django 3.2 → 5.2.17, newest 6.1.3), in the plan's
  reasons (with `latestVersion`) and in the scan's recommendation and
  `fix_targets.newest_safe`. Only where the project picks the release (a direct
  copy, or one it must force).
- **Python and Go transitive fixes say the step.** Every one was "waiting on
  upstream" with no command. PyPI: the parents' requirements are read from
  poetry.lock, or from each parent release's `requires_dist` on PyPI (uv.lock,
  compiled requirements files); when every parent admits the fix and the newest
  release they admit is clean, the step is `lockfile_refresh` with `poetry update
  certifi`, `uv lock --upgrade-package certifi` or the `--upgrade-package`
  re-compile; when one excludes it, "blocked upstream" names the parent and
  whether its newest release admits the fix (requests 2.25.0 requires
  `idna<3`; 2.34.2 admits 3.15). A fix that drops the project's lowest Python
  is said as that: sqlparse 0.6.0 requires Python >= 3.10, so a `^3.8` lock
  keeps 0.5.x whatever Django declares. Go: no requirement sets an upper bound,
  so an `// indirect` module is raised with `go get module@vX`, then `go mod
  tidy` (two command entries: `&&` does not chain commands in Windows
  PowerShell 5.1; not when go.mod replaces or excludes the module). A
  requirement that cannot be read leaves the old label: never a refresh on a
  guess. Nor is one decided when a uv.lock `[manifest]` constraint or override
  names the package, or when a parent's requirements on it are gated by
  environment markers (`python_version`) and do not all admit the fix. The
  dead-line wording is not used for calendar (certifi 2020.12.5) or epoch
  versions.
- **Platform activity is tracked per lockfile.** One lockfile that cargo cannot
  resolve (a stale example) made every crate it shares with the project's real
  lockfile count as built on this host. A finding now carries
  `platform_inactive_in`: the directories that lock that copy without building
  it here, and `upgrade_planner` aims its commands at the others and says which
  lockfile the step is not about. Nothing a lockfile may build is hidden.
- **Operating-system directories are not scanned.** `project_path` (and the
  directory a host starts the server in) was unconfined: a scan of
  `C:\Windows\System32` read the clones that had landed there and sent 2,122
  package pairs. Drive and filesystem roots, the Windows directory and
  everything below it, the roots of Program Files, ProgramData and Users, and
  on Linux and macOS the system's own directories (`/usr`, `/etc`, `/System`,
  ...) are refused with an error that says why and asks for the project's
  root; a server started in one scans nothing and each tool says so.
- **Three answers that read as fine when nothing was checked.**
  `dependency_health` with an `ecosystem_filter` that matches nothing returned
  100/100 over 0 dependencies; it now returns no score and says what the
  project does hold. A `vulnerability_scan` served whole from the advisory
  cache said `_meta.offline: false` with the network dead; `offline` is now
  `null` there, with `osv_contacted: false` and a note. `HTTPS_PROXY` /
  `HTTP_PROXY` / `NO_PROXY` were ignored in silence: they are honoured on Node
  24.14 and later, and on Node 22.21 and later when the server is started with
  `NODE_USE_ENV_PROXY=1`; otherwise the startup log and `--doctor` say that the
  proxy is not used and what to set. Older Node cannot use a proxy.
- **The fix-path cache moves to version 13**, since entries written before hold
  the releases a maintainer flagged as candidates.
- **Nothing leaves the machine until a tool needs it.** With no tool called,
  `initialize` and `tools/list` already sent every dependency name in the
  project to OSV.dev: listing the tools started the background init, and the
  init started the vulnerability scan. The init now only reads the project;
  the first tool that needs the scan starts it (a briefing still waits for it,
  never reading an empty cache).
- **Private package names are never sent.** Every name, private ones included,
  went to OSV.dev and the registries; `FOURDA_OFFLINE` was the only off switch.
  With nothing to configure, a package is private when the machine says so: an
  npm scope mapped to a non-public registry in the project's or the user's
  `.npmrc` (or `.yarnrc.yml` `npmScopes`), a Go module matching `GOPRIVATE`,
  `GONOPROXY` or `GONOSUMDB` (environment or `go env -w`), a crate `Cargo.lock`
  installs from another registry or from git, a PyPI package `uv.lock`,
  `poetry.lock` or `Pipfile.lock` installs from an index other than pypi.org.
  `FOURDA_PRIVATE_PACKAGES` adds globs (`npm:@acme/*, Go:github.com/acme/*`).
  The scope rule reads `.yarnrc.yml` at any indentation and in flow style; a
  bare `@acme` covers the scope; PyPI names compare PEP 503-normalised; an
  empty `GOPRIVATE` falls back to `go env -w`; an npm lockfile `resolved` /
  `tarball` host other than the public registry (or the `.npmrc` default, read
  as a mirror) makes a package private; the rules are re-read when their files
  or the environment change. A private PARENT is never looked up either:
  `upgrade_planner` named `@acme/api` to registry.npmjs.org while planning the
  public `qs` beneath it; its fix-path lookups now refuse private names, the
  step says `NOT CHECKED (private)` with `privateParents`, and every OSV.dev,
  registry and search request passes one check that refuses a request naming
  a private package (a test fails on any request that bypasses it). Every
  spelling counts (`acme_core` and `Acme-Core` are the private `acme-core`);
  Gemfile.lock gems from a non-rubygems.org `remote:` and composer.lock
  packages from a private host or a declared non-Packagist repository are
  private too. With an `.npmrc` default `registry=` that is not public (read
  as a mirror), answers say that unscoped names are still looked up publicly
  (`registry_notice`).
  Such a package is read but never looked up: scans, health and plans lead
  with `NOT CHECKED (private)` and list why each is private
  (`coverage.private_dependency_list`), `dependency_check` answers `unknown`
  with `not_checked: "private"`, `upgrade_impact` refuses it, and
  `ecosystem_pulse` never searches for it.
- **The embedding provider never receives file paths.** The README said no
  file paths leave the machine, but `what_should_i_know` embedded its task
  together with every path in `files`. The provider now gets the task text;
  the paths still rank results locally. The README says exactly what an
  embedding provider receives.
- **dependency_check is faster, and answers concisely by default.** On 25
  public packages a check took 32 s cold: the advisory lists started only
  after every registry read, what npm releases hold was read one package at a
  time, and crates.io was paged 100 versions a request at one request a second
  (clap: five pages) while PyPI and Go waited behind it. Lookups that depend
  only on the names now start together and later phases reuse them, each
  registry has its own pool, and a whole crates.io version list is one
  request. Same 25 packages: 12 s cold. The default answer keeps the verdict,
  the reason (the evidence of every avoid, review, unknown and wait finding),
  the safe versions (`safe`), advisory ids, a malicious package's records,
  notices and every registry quote: 42 KB became 10 KB.
  `response_format: "detailed"` returns every signal as before.
- **dependency_check no longer reports a publish-trust drop against a later
  release.** `react@19.2.0` read "Publish trust dropped" against 19.1.10, a
  backport published a year later. The baseline is now the previous release
  on the line by version AND by publish time.
- **The cache is in `cache.db` in standalone mode too**, as the README says;
  it was inside `standalone.db`, beside your decisions and memories. The old
  table is dropped once.
- **README:** every install command pins the version, with how to update it;
  the Windows paths for Devin and VS Code show their backslashes again; a
  factual comparison with GitHub's `check_dependency_vulnerabilities`.

## 6.2.7 — 2026-11-08

- **dependency_check's prose no longer undercounts advisories.** With high or
  critical advisories present, the advisories signal named three of them and
  added "and N more", where N counted only the high and critical ones: axios
  1.7.4 read "... and 10 more" (13 in all) while `affecting_to` held 33 ids.
  It now states the total and the serious share: "1.7.4 is affected by 33
  known advisories, 13 of them high or critical: GHSA-35jp-ww65-95wh (high),
  GHSA-3g43-6gmg-66jw (high), GHSA-43fc-jf86-j433 (high) and 10 more high or
  critical."
- **"No release ... is free of known advisories" counts each advisory once,
  and all of them.** The count came from `range_check.affecting_all`, which
  names at most 10 ids, and a GHSA record and its PYSEC twin were counted as
  two: pyjwt 2.9.* read "... and 7 more affect every one", naming 10 of its 17
  advisories; it now reads "... and 14 more".
  Aliases are now grouped as everywhere else, and the new
  `range_check.affecting_all_total` carries the uncapped count.
- **The first scan after updating fetches its fix-path data again, once.** The
  cache behind fix targets (OSV package records and the npm, crates.io, PyPI and
  Go facts) moves to version 11 with the count change above, so entries written
  by 6.2.6 are not reused.
- **Dependencies:** the MCP SDK moves to `@modelcontextprotocol/server` and
  `core` 2.4.0, and `@modelcontextprotocol/node` 2.1.2; hono moves to 4.13.14
  (#50). What 2.4.0 changes (tool `outputSchema` handling, `$id`/`$ref` URI
  checks, `x-mcp-header` parameters) touches nothing this server declares.
- **Release pipeline:** the package is published from the exact tarball CI
  verified. `verify` packs it once and records its SHA-256. `install-smoke`
  installs that file on Linux, macOS and Windows with npm 10 and npm 12 (#47).
  The `.mcpb` bundles are built from `pnpm-lock.yaml` with a pinned mcpb CLI
  (#48). The publish job, the only one holding the publish identity, builds
  nothing and uploads that file (#49) with `--provenance`, so npm refuses before
  the upload if it cannot attest. Release jobs restore no dependency cache, and
  the GitHub release attaches exactly the three bundles the run built.
- **`bench/g7`** publishes the agent-level evaluation: 49 dependency tasks, run
  with and without the server, with its pre-registration, pinned truth, scorer
  and the 6.2.5 and 6.2.6 results (#53). It is not part of the npm package.
- The conformance corpus and shared rule vectors are pinned at 4DA `807e0a35c`.
  Since `511ba1cda`, only the Rust engine's skip list changed there, and every
  vector still passes here.

## 6.2.6 — 2026-10-30

Parity with the 4DA app's engine after its D-4, A-1 and F-7 changes. The
shared rule vectors are pinned at 4DA `511ba1cda` (schema 130); every one of
them passes, the conformance corpus too.

- **A transitive row's fix target is judged by what it installs, too.**
  upgrade_planner checked held dependencies on direct rows only, so it named
  serve-static 1.16.0, which exact-pins an affected send 0.18.0; it now names
  1.16.1, as vulnerability_scan does (shared vector pr-007).
- **A release whose held dependencies could not be judged is named, not
  counted.** When no release on a target's line cleared what it holds, the note
  said "no release up to X clears them" even if some of those releases were
  never checked. It now says "of the releases that could be checked (... NOT
  CHECKED)" (4DA #1039).
- **A fix version the registry does not list, below one it does, is no longer
  offered as a step.** node-ipc's GHSA-97m3-w2cp-4xx6 is "fixed" in 10.1.3,
  which npm does not serve. The package target already moved past it (12.0.0),
  but the advisory's own row still said `fixed_version: 10.1.3`; it now says
  11.0.0, with "10.1.3 is not a release the registry lists" (shared vector
  ft-078, audit A-1, the app's `installable_fix`). A Go pseudo-version is never
  called unlisted.
- **A fix newer than every release the registry listed** stays the target, as
  the app keeps it, and is now said: "confirm it is published before pinning
  it", in vulnerability_scan and upgrade_planner. For npm, what such a release
  pins cannot be read, so it is NOT CHECKED, never a clean fix.
- **upgrade_planner's summary** counts a target that pins an affected dependency
  (or whose pins could not be checked) as "NOT a clean fix", never as
  upgradable, fixed by a lockfile refresh or by a parent upgrade, nor as an
  answer OSV did not give in time.
- The held check on transitive rows costs one OSV lookup per npm row (a
  40-row plan took about twice as long in a synthetic test, still within the
  plan's budget and failing closed). Batching the rows' lookups was tried and
  dropped: one failed batch marked every row in it NOT CHECKED.
- The shared vectors' new `held` line kind (ft-079..ft-092) runs through the
  scan's own target path, and plain fix-target lines through `cleanFixTarget`,
  the scan's entry point (ft-076, a last_affected-only advisory, already
  passed there). The severity runner checks the optional `expect.notices`, and
  fix-target lines' `malicious[]` is now checked too.
- Two independent reviews of this change ran before release. The first found an
  unlisted fix named as "no installable fix" in place of the real reason
  (malware, or an advisory every fix brings in); the second found its fix too
  broad, and the batching above. Both are fixed, each with a regression test.
- `contract/app-schema.sql` follows the app to schema 130 (version lines only).

## 6.2.5 — 2026-10-26

### Pre-publish adversarial audit fixes (2026-10-26)

An independent six-track audit of the 6.2.5 candidate (oracle parity, fault
injection, security, honesty, install/release, cross-engine parity) found the
following. Each fix has a regression test that fails on the old code.

- **Suggested commands never carry text a repository controls.** `cargo add`
  put a Cargo.toml `[target.'cfg(...)']` header inside `--target "..."` and a
  renamed key after `--rename`, where a shell would expand it. Every command
  builder now checks every value it splices; anything else gets words, not a command.
- **cargo runs from the server's own data directory**, not a fixed folder in
  the shared temp directory where another account could plant a cargo config.
- **An unchecked fix target is never said to "resolve" anything.** When the
  target check runs out of time the line says NOT CHECKED; an alias group's fix
  is the highest any of its records names (netmask: 2.0.1, not 1.1.0).
- **A fix target is judged by what it installs.** A release that exact-pins (or
  narrowly pins) an affected dependency is not offered: express 4.22.3, not
  4.20.0, in vulnerability_scan, dependency_check and upgrade_planner.
- **One OSV record no longer blinds the scan.** An `affected[]` entry with no
  `package` (EEF-CVE-2026-56812, npm phoenix) made every dependency NOT CHECKED.
- **Desktop mode reads a project the app does not track** from its own
  lockfiles; the planner no longer answers "0 steps" for it.
- **Fail-closed, further:** an answer from an expired cache, a cache row
  fetched "in the future", a malformed querybatch entry, a stalled response
  body or a registry outage is never presented as a current, complete answer.
- **Malware** is critical in every tool, scan rows carry `malware`, and a copy
  with a clean later release is an upgrade, not a removal.
- **Honesty:** unsound RustSec advisories are never hidden as notices; Maven /
  Gradle / .NET tasks are never `safe_to_delegate`; a Maven-only scan has null
  totals; a Go scan says the standard library is not checked; a flat
  requirements.txt says its dependencies were not checked; aliases are counted
  once; two-part versions (Django 4.2 -> 5.2) are majors; a clean stable release
  comes before a prerelease fix; recalled memories are labelled untrusted data;
  the privacy wording names private package names, HN search and opt-ins.
- **PyPI advice:** a compiled requirements file is re-compiled
  (`--upgrade-package`), never hand-edited; pins of a fully pinned file are
  re-resolved together.
- **Paths:** symlinked requirements files and Cargo workspace members outside
  the project are not read; `[build-dependencies]` are normal dependencies.
- **Install:** `4da-mcp-setup` works on macOS and Linux (it was a no-op through
  npm's symlinked bin); CI now installs the packed tarball on all three OSes;
  the release verifies provenance on every run and pins npm.
- **Performance:** a large pnpm-lock.yaml is read in linear time (200k entries:
  409 s -> 0.6 s).

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
  dependency_health's `latestSafeVersion`, what_should_i_know's `latest`) now
  passes the advisory check dependency_check decides `proceed` by, and the
  registry's withdrawals. A placeholder whose newer releases are all malware is
  `remove_dependency` ("remove it"); otherwise the newest release that is
  neither affected nor withdrawn is offered, or `hold_current` when none is.
  dependency_health's `latestStableVersion` stays the registry's newest stable
  release as published; when that release is affected or withdrawn,
  `latestStableNote` says so and `latestSafeVersion` names the one offered.
- **No release brings in an advisory the installed version does not have**,
  fixed or not (the 4DA lead's rule for both engines): not a fix target, a
  parent or lever release, or a newest-release offer. An advisory with no
  published fix is skipped only when the installed version already has it.
  When nothing qualifies, no release is named and the answer says "every
  fixing release brings in <ids>", naming every such advisory across all the
  releases blocked this way, sorted, not only the smallest one's. A parent or
  lever whose only admitting release carries such an advisory reports the
  outcome `introduces` (shared vector pr-010), not "no release admits".
- **A maintenance notice never blocks a release** (both engines, the #994
  review). An unmaintained or deprecated-package notice (the maintenance
  predicate: OSV `informational`, or unmaintained wording) never makes a
  release unclean, never leaves a row with no fix, and never produces
  `introduces`. The copy's own fix-target walk and the clean-copy checks
  behind parent moves and refreshes counted them before; a release affected
  only by a notice is now the target.
- **A fix that lands on malware says so.** When every release a fix could land
  on is flagged malicious, the row names no release and reads "<pkg> is
  flagged malicious (<id>): remove or replace <pkg>", not "still affected by
  MAL-x".
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
  <crate>@<installed> --precise <target>`. Only an npm range bounded below the
  next major (`^`, `~`, also on a prerelease base such as `^2.0.0-rc.4`) is
  refreshed: a refresh installs the newest release in
  range, so a `>=`, `||`, `*` or x-range could jump a major, and names nothing
  (shared vector fc-059). A Cargo requirement is refreshed with `--precise`,
  which pins the exact target. A row of refreshes reads "Fixable now with a lockfile
  refresh (the declared range already admits the fix)"; a refresh among other
  commands is labelled. An npm workspace member is refreshed in its own
  directory, and a workspace-inherited, git, path or registry crate is never
  refreshed this way.
- The shared rule vectors `severity` (sv-001..sv-022) and `parent_release`
  (pr-001..pr-012, with the graph lines run through the whole planner, and
  Cargo lines) run in the TypeScript runner.
- The conformance pin moves to 4DA 9450d1613 (#972, #976, #981, #986, #992,
  #993, #994, #998, #1008, #1025): every shared vector line (435, nine files)
  and the corpus suite pass at it. #1008's new lines hold the Rust engine to this
  server's rules: a malware landing is named as malware (ft-070, ft-072), a
  maintenance notice never blocks a target and is never one, even at its own
  fixed bound (ft-071, ft-073, ring RUSTSEC-2025-0010), and a notice with a
  published fix is still not graded from an alias (sv-023).
- **An unmaintained-crate notice is a notice wherever RustSec puts the flag.**
  RustSec writes `informational` on each `affected[]` entry, never on the
  record, so RUSTSEC-2018-0017 (`tempdir` crate has been deprecated), net2 and
  structopt were graded vulnerabilities. A record is now a notice for a package
  when its summary says unmaintained, or `informational` is `unmaintained` or
  `notice` on the record or on that package's affected entry; `unsound` stays
  a vulnerability (smallvec). The same predicate as the 4DA app (#1025),
  pinned by ft-074, ft-075, sv-024 and sv-025.
- **A row's only fix across a major raises the row**, flagged `breaking`,
  with the reason "the only release of <parent> that fixes <child> is <ver>, a
  major upgrade" (the 4DA lead): xsv's crossbeam-channel row goes to 0.5.0,
  the only release whose requirement admits a clean crossbeam-utils.
- **Known difference from the desktop app:** the app's live path raises a
  row across a major only for npm. For Cargo the app holds the rule in its
  shared vector (pr-009) but not yet on live data, because a live Cargo raise
  needs per-version dependency data it does not read yet. Until that lands,
  this server and the app can give different answers for a live Cargo row
  whose only fix is across a major.
- **A lever that cannot move no longer hides its parent's release** (with the
  app, shared vector pr-011). When a parent arrives through a declared
  dependency that names no release (it is flagged malicious, every release
  that would bring the fix in brings in an advisory it lacks, none does, or it
  is at its latest), the parent's release is still named and that lever
  carries `levers[].outcome` with its own reason ("no <lever> release is
  named: ...", "replace <lever>"). The step stays `override_or_replace`,
  with the override that forces the copy.
- **API:** new actions `upgrade_parent_unverified`, `remove_dependency` and
  `hold_current`; `parentUpgrades[].goesAway` and `smallest`;
  `levers[].smallest`, `floor`, `brings` and `outcome`; `upgradeCommands[].refresh` and
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
