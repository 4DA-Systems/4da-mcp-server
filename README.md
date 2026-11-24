# @4da/mcp-server

[![npm version](https://img.shields.io/npm/v/@4da/mcp-server?color=gold)](https://www.npmjs.com/package/@4da/mcp-server)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Node](https://img.shields.io/badge/Node-%3E%3D22-brightgreen)](https://nodejs.org/)
[![CI](https://github.com/4DA-Systems/4da-mcp-server/actions/workflows/ci.yml/badge.svg)](https://github.com/4DA-Systems/4da-mcp-server/actions/workflows/ci.yml)

**Upgrade intelligence for AI coding agents.** Before your agent bumps a dependency it learns what changes between the version you run and the one you want, which of your files that touches, and which vulnerabilities the move fixes, from your own lockfiles, on your machine. Plus vulnerability scanning at osv-scanner parity on the lockfiles it reads ([what that covers, and how it is measured](#how-it-works)), ranked upgrade plans and decision memory. Zero config, no account.

```
You:     "Upgrade axum to 0.8"
Agent →  upgrade_impact { package: "axum", to_version: "0.8.4" }

         axum 0.7.9 -> 0.8.4: 5 releases (0.8.2 yanked), changelog from the 0.8.4 crate.
         12 breaking entries, 8 touch your code (Path, Query, Router, extract, serve):
           breaking  Remove OptionalFromRequestParts impl for `Query`        (you use Query)
           breaking  Require `Sync` for all handlers added to `Router`       (you use Router)
           ...
         Your code: 10 files import axum.
```

*(Output of version 6.0.0, abridged, from 2026-10-02 on the 4DA desktop app's repository, where this server lived until 2026-10-04. Later releases word the same answer a little differently (6.3.0 counts 11 breaking entries for this upgrade), and the files and symbols an answer names are your project's.)*

One command to install. No API keys. No accounts. Your code never leaves your machine.

## Install

Requires Node.js 22 or later. CI runs the suite on Node 22 (the newest 22.x on Linux, Windows and macOS, and 22.12, where the server falls back to `better-sqlite3`) and on Node 24 (Linux); other versions are not tested.

The server uses Node's built-in `node:sqlite` (Node 22.13 and later), so it needs no install script and works with npm 12's default of blocking them. On Node 22.0-22.12 it uses the optional `better-sqlite3`, whose native module npm 10 and 11 build on install. `npx @4da/mcp-server@6.5.0 --doctor` shows which one is in use.

```bash
claude mcp add --scope user 4da -- npx -y --prefer-offline @4da/mcp-server@6.5.0
```

Every command and config on this page pins the version, and so do the plugin, the Gemini extension and the entry `--setup` writes, so what runs changes only when you change it. Each configuration starts the server with `npx -y --prefer-offline`: with `--prefer-offline` a cached copy of the pinned version starts without asking the registry first, which matters behind a slow or dead proxy. npx's own options go before the package name; written after it they are passed to the server, which exits with `unknown argument`. Without a version, npx runs whatever it has cached or the newest release, which you did not review.

To update, replace the version with the newest one on npm (`npm view @4da/mcp-server version`, or run `--setup --update` from the newer version); the [changelog](CHANGELOG.md) says what changed. A pinned install never updates itself, so the server says when a newer release is published: `get_context` carries `update_notice` (both versions and the command that moves the pin) and `--doctor` prints it as a "Server version" warning. The server reads the newest version from the npm registry only after a tool call of the session has already contacted a package registry, never at start-up and never with `FOURDA_OFFLINE`, at most once a day per data folder.

**As a Claude Code plugin** (the MCP server plus a hook):

```bash
claude plugin marketplace add 4DA-Systems/4da-mcp-server
claude plugin install 4da@4da
```

The hook runs before the edit or command (PreToolUse on Edit, MultiEdit, Write, Bash and PowerShell), so it can stop a dependency version from being written or installed before it was checked. Every `dependency_check` verdict is recorded in a local ledger in the server's data folder (`check-ledger.jsonl`, never sent anywhere), and the server finishes writing it before it exits, so a host that closes the session straight after the answer still leaves the verdict the hook reads. For each version the call would introduce (in `package.json`, `Cargo.toml`, `pyproject.toml`, any `*requirements*.txt` (`requirements-dev.txt`, `dev-requirements.txt`) or `requirements/*.txt`, `go.mod` or `pnpm-workspace.yaml`, or in an install command: `npm install` (and every alias, typo and abbreviation npm itself accepts for `install` and `install-test`: `i`, `add`, `inst`, `isntall`, `it` ...), `pnpm add`, `yarn add` (also `yarn workspace <name> add` and `yarn workspaces foreach ... add`), `bun add` or `bun install` with a package, `pnpm up` or `yarn up` with a version, `cargo add`, `uv add`, `uv pip install`, `pip install`, `poetry add`, `go get`, also when run through `bash -c`, `sh -c`, `fish -c`, `eval`, `pwsh -Command` or `-CommandWithArgs`, `Invoke-Expression`, `npx`, `bunx`, `pnpx`, `npm exec`, `pnpm dlx`, `pnpm -c exec`, `yarn dlx` or `corepack`, up to three such wrappers deep, after a prefix (`sudo`, `env`, `timeout`, `nice`, `nohup`, `time`, `command`, `exec`, `xargs`, `busybox`, `wsl`) or a shell keyword (`!`, `if ...; then`, `do`), or inside a subshell `( ... )`, a group `{ ...; }` or a PowerShell script block `& { ... }`) it reads the verdicts of the last 24 hours: `proceed` or `review` goes ahead silently; `avoid` or `wait` is denied with that verdict's reason; no verdict, or only `unknown`, is denied with the exact `dependency_check` call to make, and the call goes through once it answers `proceed`. A denial quotes every name and version it repeats (they come from the edit or command, which may be a third party's, and are data, never instructions) and says what the call sends: a name goes to its public registry and OSV.dev unless the project's private rules cover it, and a name that is not published comes back `unknown` and stays blocked. A range or constraint is denied only when the package has no verdict at all, or when that same constraint's last verdict was `avoid` or `wait`; a package the server recorded as private goes ahead. A bare install, `npm ci` (and `npm install-ci-test`, which installs the lockfile), a registry or index other than the public one (a `--registry` naming registry.npmjs.org is the public one and is read), a git or path source (in a command or in a manifest: Cargo `path`, `git` or `registry`, `[tool.uv.sources]`, Poetry `path`, `git`, `url` or a named source, a PEP 508 direct reference, a go.mod `replace` to a directory), or a command line with variables, substitutions or heredocs goes ahead without comment, as does a global tool install that names no version the hook reads (`cargo install`, `yarn global add`, `go install`, `npx some-tool@1.2.3`), which is no dependency of the project. A global install through `npm i -g`, `pnpm add -g` or `bun add -g` names its version as a project install does, and is checked like one. What the hook does not read is listed in the CHANGELOG's known limits. `FOURDA_GUARD=advise` never denies and advises after a manifest edit instead (the behaviour before 6.5.0); `FOURDA_GUARD=off` turns the hook off. The hook denies only where that ledger exists: a server from 6.5.0 on starts it, empty, when it starts serving. Beside an older server, which records no verdict, a denied edit could never pass, so there the hook denies nothing and advises after a manifest edit as it did before 6.5.0. The hook is plain Node, contacts nothing, and fails open: its own error, a payload it does not read, a missing data folder or its 8 s self-limit lets the call through.

<details>
<summary><b>Cursor / Windsurf / Devin Desktop</b></summary>

Add to `~/.cursor/mcp.json` (Cursor), `~/.codeium/windsurf/mcp_config.json` (Windsurf), or `~/.config/devin/mcp_config.json` (Devin Desktop and Devin CLI; `%APPDATA%\devin\mcp_config.json` on Windows):
```json
{
  "mcpServers": {
    "4da": {
      "command": "npx",
      "args": ["-y", "--prefer-offline", "@4da/mcp-server@6.5.0"]
    }
  }
}
```
</details>

<details>
<summary><b>VS Code (Copilot)</b></summary>

Run **MCP: Open User Configuration** and add the entry, or edit the file directly: `%APPDATA%\Code\User\mcp.json` (Windows), `~/Library/Application Support/Code/User/mcp.json` (macOS), `~/.config/Code/User/mcp.json` (Linux). VS Code uses `servers`, not `mcpServers`:
```json
{
  "servers": {
    "4da": {
      "type": "stdio",
      "command": "npx",
      "args": ["-y", "--prefer-offline", "@4da/mcp-server@6.5.0"]
    }
  }
}
```
</details>

<details>
<summary><b>Claude Desktop</b></summary>

Add to `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):
```json
{
  "mcpServers": {
    "4da": {
      "command": "npx",
      "args": ["-y", "--prefer-offline", "@4da/mcp-server@6.5.0"]
    }
  }
}
```
</details>

<details>
<summary><b>Auto-setup</b> (detects all installed editors)</summary>

```bash
npx @4da/mcp-server@6.5.0 --setup --dry-run   # show each file and entry, write nothing
npx @4da/mcp-server@6.5.0 --setup
npx @4da/mcp-server@6.5.0 --setup --update    # also replace a 4da entry that is already there
```

Writes the entry, pinned to the version you ran it from, into the Cursor, VS Code (and Insiders), Windsurf, Devin Desktop and Claude Desktop configs it finds, merging into what is there: other servers, settings and comments are kept, and a backup (`.bak`) is written first. A `4da` entry that is already there and differs (another version, a local build, a wrapper command) is kept and reported; `--update` replaces its command and keeps its `env` and other fields. A file it cannot read exactly (invalid JSON, not UTF-8, the same key twice) is left untouched with the entry to add by hand, and the exit code is then 1. For Claude Code it prints the `claude mcp add` command instead of editing `~/.claude.json`.
</details>

Then ask your AI: **"What changes if I upgrade X to Y?"**, **"Scan for vulnerabilities"** or **"What should I upgrade first?"**

## How It Works

The server reads every lockfile of the project it is started in, including independently-locked projects below the root (a repo with `src-tauri/Cargo.lock` beside a root `pnpm-lock.yaml` is scanned whole): `package-lock.json` / `npm-shrinkwrap.json`, `pnpm-lock.yaml` (v5–v9), `yarn.lock` (v1 and berry), `bun.lock`, `Cargo.lock` (Cargo workspaces included), `poetry.lock`, `uv.lock`, `pdm.lock`, `Pipfile.lock`, requirements pins (`*requirements*.txt`, `requirements/*.txt`, with `-r` and `-c`), `go.mod` / `go.sum` (Go's build list), `Gemfile.lock` (RubyGems; git and path gems are local code, not releases) and `composer.lock` (Packagist). Every Python source in a folder is read, not only the first. Every installed copy is scanned, not one version per name, with the lockfile's own dev flags. It re-reads them whenever a lockfile changes, and for npm it also checks what `node_modules` actually holds. A lockfile is what is installed, so it is read whether or not `.gitignore` lists it, and a dot-directory (`.github/actions/*`) is a directory like any other; so are `build/`, `dist/`, `out/`, `coverage/`, `.vscode/` and `.idea/`, which are read unless the repository ignores them. What is not scanned is said, lockfile by lockfile, under `coverage.not_scanned.lockfiles` with a `reason`: a directory `.gitignore` excludes is left out (it is as often a scratch clone as the project's own code: `gitignored_directory`); installed code, a tool's build output or cache, and editor or agent state (`node_modules`, `target`, `.venv`, `.next`, `.claude` ...) are never scanned, and when the repository does not ignore such a directory the lockfiles in it are listed (`excluded_directory`; it is searched within 2,000 directories, and the answer says when that bound stopped it); a lockfile sitting directly in an ignored `vendor/`, `target/` or `venv/` is listed too (`output_directory`); version-control data is never entered. A junction or symbolic link whose real path is inside the project is followed, each directory walked once; one that leads outside it is not, and the lockfiles behind it are listed (`symlink_outside_root`); a directory the walk cannot list is named (`unreadable`, its path ending in `/`). A lockfile or manifest holding git merge-conflict markers is not read at all, neither side of it: it is listed with reason `merge_conflict`, `coverage.complete` is false and every tool says `NOT CHECKED (merge conflict)` for it. The walk goes 4 levels down and up to 256 projects; whatever it leaves out is listed the same way (`depth`, `project_limit`). So is every manifest with no lockfile: its declared ranges are not installs and are not scanned, its exact pins are checked but the packages they pull in are resolved nowhere (`coverage.unresolved_manifests`, and `coverage.manifests_without_lockfile` for a manifest in a subdirectory that no lockfile above holds as a workspace member). `vulnerability_scan` always returns a `coverage` block: a scan that left nothing out says `complete: true` with `lockfiles_read` (and `lockfiles_not_scanned: 0`), one that left something out says `complete: false` and lists it; nothing is dropped silently. A lockfile problem that makes the scan's coverage incomplete (any of those listed below, a conflicted `go.sum` included) also makes `upgrade_planner` say `vulnerabilityDataAvailable: false`: both read the same list. So are manifests of ecosystems it does not read (Maven `pom.xml`, Gradle, .NET `*.csproj` / `packages.lock.json`, Pub, Hex, SwiftPM, CocoaPods: `coverage.not_covered`), lockfiles that exist but cannot be read (invalid JSON, Bun's binary `bun.lockb`: `coverage.unreadable_lockfiles`), lockfiles that are truncated or damaged and were read only up to the damage, or are older than their manifest (a dependency `package.json` or `Cargo.toml` declares has no entry; npm, pnpm, Yarn and Bun lockfiles alike) (`coverage.partial_lockfiles`), a second lockfile in a directory that disagrees with the one that was read (`coverage.conflicting_lockfiles`), requirements with no pinned version such as `pydantic>=2.0.0` (`coverage.unpinned_requirements`: there is no installed version to check), dependencies installed from git or a URL (`coverage.not_checkable`: they are not the registry package of that name, so they are never matched against it), files of a supported ecosystem in a form that is not read (`environment.yml`, `setup.py`, `pylock.toml`), and lockfiles under test-fixture directories (`tests/`, `test/`, `fixtures/`, `testdata/`, `__fixtures__/`, `conformance/` ...), which are not scanned as the project's own unless you pass `include_test_fixtures: true` (`coverage.not_scanned`).

Started in a workspace member that has no lockfile of its own, whose manifest an ancestor's lockfile holds as a member (npm, pnpm, Yarn and Bun workspaces, a Cargo workspace, a uv, Poetry or PDM workspace, a `go.work`), the server reads that workspace root and says so (`project_root` is the root; `vulnerability_scan`'s `workspace_note` and `dependency_health`'s summary name the member it was started in). The search stays inside the enclosing git repository, or at most 6 levels up with none, never at or above your home directory; an ancestor lockfile that cannot be confirmed to hold the directory is named in the coverage note, not read. When no lockfile was read for the project at all, no tool scores or clears it: `dependency_health` gives `healthScore: null` with `withheldReason: "no_lockfile"` and a NOT CHECKED summary (never "0 vulnerable"), a dependency known only by its declared range shows `currentVersion: null` beside `declaredRange`, `upgrade_planner` sets `vulnerabilityDataAvailable: false`, `what_should_i_know` never says `safe_to_delegate` on that basis, and `vulnerability_scan` starts its answer with NOT CHECKED and gives null totals (what it found among a manifest's exact pins is a lower bound, under `found_in_checked_dependencies`). A folder that holds nothing the server reads, an empty one or the wrong one, is answered the same way, never as a complete scan with zero findings.

**An incomplete answer is never a clean one.** When OSV.dev cannot answer for some dependencies (outage, HTTP error, timeout, the query budget), `vulnerability_scan` starts with `summary: "NOT CHECKED: ... N of M dependencies have no vulnerability answer"`, counts them in `coverage.unchecked_dependencies`, and sets `total_vulnerable_packages` and `by_severity` to null (what the checked part found is under `found_in_checked_dependencies`); `dependency_health` withholds its score and vulnerable count, and `upgrade_planner` sets `vulnerabilityDataAvailable: false`. Large trees are queried in batches of 1,000 as OSV's budget allows, so a tree past 10,000 dependencies is answered in full, and a long answer is read to its last page. An advisory OSV matched whose record it then failed to return is listed as `details: "NOT CHECKED"`: its severity is unknown, not low, no `severity_filter` drops it, and it is asked for again on the next scan instead of being cached. The scan the other tools reuse is at most one hour old; past that it is taken again.

**Two grades for one advisory.** `severity` and `by_severity` are the grade the 4DA app presents, adjusted for scope (a transitive copy caps critical at high, a dev-only copy drops a level); the advisory's own grade is always visible beside it: `advisory_severity` on a package row whose own grade differs, and `by_advisory_severity` beside `by_severity` (the detailed answer also keeps it as `advisory_by_severity`). When any advisory is critical by its own grade, the `summary` says so first (after any NOT CHECKED headline): how many, on which package versions, and how many are presented lower because they are transitive or dev-only. Every recommendation names the own grade where it differs ("3 high (2 critical by the advisory)").

**What "osv-scanner parity" covers, and how it is measured.** Two things: reading the same installed packages out of a lockfile (inventory), and matching them to the same advisories (findings). It is not feature parity: osv-scanner reads ecosystems this server does not (Maven and Gradle among them). The measurement is the conformance corpus in the 4DA repository, fetched at a pinned commit: 36 cases (32 public repositories at pinned commits, 4 synthetic), scored for npm, crates.io, PyPI, Go, RubyGems and Packagist, with 3,929 OSV records pinned as OSV.dev served them (and 6 synthetic rule records). The expected inventory comes from osv-scanner 2.6.0 and the expected findings from OSV.dev's own evaluation of each installed version, with every correction recorded in the corpus; the corpus is kept by the same maintainers as this server. Against it this engine reads 20,458 inventory entries with none missing and none extra, and reports 4,785 findings with 0 false positives and 0 false negatives. That run is offline, on the pinned records, with this server's own range matcher: it measures the readers and the matching, not the live requests to OSV.dev, and not a lockfile damaged in a way the corpus does not hold. CI runs it on every change (`conformance (pinned)`) and a release requires it; to run it yourself: `node scripts/fetch-conformance.mjs && pnpm exec vitest run src/__tests__/conformance.test.ts --reporter=verbose`, which prints the table per ecosystem (see [conformance/README.md](conformance/README.md)).

Measured with a coding agent on the 6.2.5, 6.2.6 and 6.2.7 release candidates (pre-registered, 49 dependency tasks x 3 trials, one model, `claude-sonnet-5-5`, tasks written by the authors, shell and web off in both arms): it wrote a vulnerable version in 82 of 138 well-posed runs without the server and 0 of 138 with it. No result for a later release is published here. Harness, tasks, pinned truth and results: [`bench/g7`](bench/g7/).

- **OSV.dev** for known vulnerabilities, matched to exact installed versions
- **npm registry, crates.io, PyPI, Go module proxy** (registry.npmjs.org, crates.io and index.crates.io, pypi.org, proxy.golang.org) for versions, deprecations and yanks
- **npm download counts** (api.npmjs.org), for `dependency_health`'s weekly-downloads figure (`upgrade_planner` and `what_should_i_know` make the same request when they read registry data for npm packages), and for `dependency_check` when a new dependency's name is a near-miss of a popular package (that name and the popular one, nothing else)
- **The package's own registry archive** (registry.npmjs.org, static.crates.io, files.pythonhosted.org, proxy.golang.org) for the changelog `upgrade_impact` reads; GitHub only if you opt in with `FOURDA_GITHUB_CHANGELOG=true` (below)
- **npm full packument**, the **crates.io versions API**, the **PyPI JSON API** and the **Go proxy's version list** for `dependency_check` (publish times, yanks and retractions; on npm and crates.io also publishers, install scripts, per-version dependencies). These requests carry the package name only. Besides them, `dependency_check` requests per-release documents of the releases it is judging (`to`, a constraint's candidates, the safe releases it names): the Go proxy's `.info` and `.mod` (its list has no dates; the same requests `go get` makes, and `.mod` lists what the release requires), and on PyPI the release's own document (`pypi.org/pypi/<name>/<version>/json`, the only place a release that is not the latest lists its requirements); and it looks up, by name, the release lists of the packages those releases require (crates.io, PyPI) and their advisories at OSV.dev. The version you have installed (`from`) is named only to the Go proxy (its `.info`) and, on PyPI, only when it is also `to`. `upgrade_planner` names a version to a registry in two cases: on PyPI, a parent that uv.lock or a compiled requirements file names without its requirement is asked for by its own release (`pypi.org/pypi/<name>/<version>/json`, the installed version); and on npm, PyPI and Go a fix version is asked for by name. OSV.dev's advisory list for the package lets `dependency_check` name the safe releases in a constraint. Packuments are cached on disk and revalidated with `If-None-Match`; crates.io API reads are spaced one per second.
- **Hacker News Algolia API** (hn.algolia.com), only when you call `ecosystem_pulse`
- **GitHub** (api.github.com, raw.githubusercontent.com), only with `FOURDA_GITHUB_CHANGELOG=true`
- **Your embedding provider**, only if you configure one for semantic recall (a local Ollama URL, or api.openai.com; see below)

Those are all the hosts the server contacts.

Results are cached (24h for registry data, 1h for vulnerabilities, 30min for news) and rate-limited per source.

**What's sent over the network, and when:** nothing when your editor starts the server and lists its tools; the project is read locally, and the first request goes out when a tool that needs it is called (`vulnerability_scan`, `what_should_i_know`, `dependency_check` ...). Then: package names and versions (the same data visible in your lockfile), and, only for `ecosystem_pulse`, the names of a few of your dependencies as search terms. Never a private package's name (below). No source code, no file paths, no personal data. The call-site scan of `upgrade_impact` runs locally. Set `FOURDA_OFFLINE=true` to disable all network calls.

**Private packages are never sent.** A package is private, with nothing to configure, when your machine already says so:

- **npm:** its scope is mapped to a registry other than the public one in the project's `.npmrc` (or a parent directory's, or any member directory's the project walk finds, lockfile or not), your user `.npmrc` (or `npm_config_userconfig` in any case), the global npmrc (`npm_config_globalconfig`, else `<prefix>/etc/npmrc` with the prefix from `npm_config_prefix` / `PREFIX`, `%APPDATA%\npm` or node's own), a quoted key (`"@acme:registry"=...`), the environment (`npm_config_@acme:registry`, any case), `.yarnrc.yml` `npmScopes` at any indentation or in flow style (`@acme:registry=https://npm.acme.dev/`; the project's and those above it, `~/.yarnrc.yml`, under the name `YARN_RC_FILENAME` gives, and `YARN_NPM_SCOPES`), or `bunfig.toml` `[install.scopes]` (a URL, `{ url = ... }`, or an `[install.scopes.<scope>]` table; the project's, `~/.bunfig.toml` or `$XDG_CONFIG_HOME/.bunfig.toml`); or your lockfile installs it from another host: the `resolved` location in `package-lock.json` / `npm-shrinkwrap.json` and yarn v1 `yarn.lock`, a yarn berry `resolution` URL (or `__archiveUrl`), the `tarball` in `pnpm-lock.yaml` (GitHub Packages included), the registry URL of a `bun.lock` entry. A default registry that is not public (`registry=` in any of those `.npmrc` files, `npm_config_registry`, yarn's `npmRegistryServer` or `YARN_NPM_REGISTRY_SERVER`, bun's `[install] registry`) makes every npm package of the project private (see "Mirrors" below); registry.npmjs.org, registry.yarnpkg.com and registry.npmmirror.com are public.
- **Go:** its module path matches `GOPRIVATE`, `GONOPROXY` or `GONOSUMDB`, from the environment or from `go env -w` (the `GOENV` file; as go does, an empty variable falls back to it), whatever spelling a tool is given (`https://github.com/acme/mod.git`, `git+ssh://git@github.com/acme/mod`, `git@github.com:acme/mod.git`, `...#v1.2.3`, `.../tree/main`); or `GOPROXY` names a proxy that is not public (see "Mirrors" below).
- **Cargo:** `Cargo.lock` installs it from a registry other than crates.io, or from git (path dependencies are local code and were never sent); or `Cargo.toml` (the root's and every workspace member's, `members` globs and `exclude` respected) takes it from another registry (`registry = "acme"` other than `crates-io`, or `registry-index`) or from git, in any dependency table or `[patch]`, with or without a lockfile; or a `.cargo/config.toml` (in the project, any directory above it, or `CARGO_HOME`) patches it from git or another registry, or replaces crates.io with a registry that is not crates.io (see "Mirrors" below; a vendored directory is crates.io's own crates).
- **PyPI:** `uv.lock`, `poetry.lock` or `Pipfile.lock` installs it from an index other than pypi.org; or a requirements file pins it under `--index-url` / `-i` naming another index (set in the file or in any file it includes with `-r` or `-c`, nested); or `pyproject.toml` takes it from another index (uv `[tool.uv.sources] name = { index = "acme" }` naming a `[[tool.uv.index]]` that is not pypi.org; Poetry `name = { version = ..., source = "acme" }` naming a `[[tool.poetry.source]]` that is not pypi.org), with or without a lockfile; or a direct reference installs it from a location that is not public (`name @ https://pkgs.acme.dev/...`, `name @ git+https://git.acme.dev/...`, `name @ file:...`, uv or Poetry `git` / `url` / `path` sources; pypi.org's files, the public wheel indexes and GitHub, GitLab and Bitbucket are public); or, with no lockfile, uv, Poetry or PDM consults an index that is not pypi.org for any name (a `[[tool.uv.index]]` that is the default or not `explicit`, `[tool.uv]` `index-url` / `extra-index-url`, `uv.toml` in the project or above it, the user's or the system's, `UV_DEFAULT_INDEX`, `UV_INDEX_URL`, `UV_INDEX`, `UV_EXTRA_INDEX_URL`, a Poetry source that is not `priority = "explicit"`, a PDM source): then every package the project declares is private; or pip is configured with another index (`PIP_INDEX_URL`, or `index-url` in any pip config file pip reads: site-wide `%ProgramData%\pip\pip.ini`, `/etc/pip.conf`, `$XDG_CONFIG_DIRS/pip/pip.conf`, `/Library/Application Support/pip/pip.conf`; per-user `%USERPROFILE%\pip\pip.ini`, `%APPDATA%\pip\pip.ini`, `~/.pip/pip.conf`, `~/.config/pip/pip.conf`, `~/Library/Application Support/pip/pip.conf`; the virtualenv's `$VIRTUAL_ENV/pip.ini` or `pip.conf`; `PIP_CONFIG_FILE`) and a requirements file installs it. A company mirror of PyPI named there counts as private too: list nothing, and its packages are reported as not checked. An `--extra-index-url` (in a requirements file, `PIP_EXTRA_INDEX_URL` or pip config) that is not pypi.org counts the same way: pip takes each package from whichever index has the newest release, so any name it installs may come from that index, and the packages a requirements file installs are private (not sent, reported as not checked); the answer names the index (`registry_notice`). A lockfile that records each package's index (`uv.lock`, `poetry.lock`, `Pipfile.lock`) lets the public ones be checked.
- **RubyGems:** `Gemfile.lock` lists it under a `GEM` section whose `remote:` is not rubygems.org.
- **Packagist:** `composer.lock` installs it from a host other than Packagist and the public code hosts (a Satis or Private Packagist server), or from a repository `composer.json` declares that is not Packagist (`vcs`, even on GitHub; `composer`; `path`; `artifact`).

**Mirrors: one policy for every ecosystem.** A registry, index or proxy that is not the public one, and that the package manager consults for any name (an `.npmrc` `registry=`, a pip `--index-url` or extra index, a uv or Poetry default index, `GOPROXY`, a Cargo source replacement), can serve packages published nowhere else, so every package of that ecosystem the project installs is private: never sent, reported as not checked, with the reason and the setting named (`registry_notice` for npm and pip). If such a server only mirrors the public registry (Artifactory, Nexus, devpi, Athens as a pure proxy), say so with `FOURDA_PUBLIC_MIRRORS=artifactory.acme.dev,athens.acme.dev` (hosts, comma- or space-separated) and its packages are checked again; its lockfile hosts count as public too. Until 6.3.0 an npm `registry=` host and `GOPROXY` were read as mirrors and unscoped names were sent. Go needs no proxy for a module on your own host: one that neither `GOPRIVATE` (or `GONOPROXY` / `GONOSUMDB`) names nor a private `GOPROXY` covers is fetched by go through the public proxy too, and is looked up here the same way; name it in `GOPRIVATE`.

A dependency taken from a path, git or a URL is not the registry package of its name, and is never looked up by that name, in any ecosystem. npm specs are read as npm reads them: `file:`, `link:`, `workspace:`, a bare path (`../libs/x`, `./x`, `~/x`, `/opt/x`, `C:\x`), a tarball file (`vendor/x-1.0.0.tgz`), GitHub shorthand (`org/repo#ref`) or any git spelling, a URL other than the public registry's own tarball of that package, or another protocol; so is a name the lockfile installs only as a link (a workspace member), from git, a URL or a local archive, and a workspace member's own name. Such a dependency gets no registry row in `dependency_health` or `upgrade_planner`, `dependency_check` answers it `unknown` with `not_checked: "private"`, `upgrade_impact` refuses it, and neither the briefing nor `ecosystem_pulse` sends it (until 6.5.0 the first two asked the npm registry about it by name); what it installs is listed under `coverage.not_checkable`. Versions, ranges, dist-tags (`latest`, `next`), pnpm `catalog:` and an `npm:` alias's target are registry releases and are checked; an alias's own key is never sent.

Names are compared the way each registry compares them: a crate is the same whatever its case and whether it is written with `_` or `-` (`acme_core`, `Acme-Core`), PyPI names are PEP 503-normalised, npm, RubyGems and Packagist names are case-insensitive. Look-alike spellings are folded first (NFKC, so fullwidth `＠acme／ui` is `@acme/ui`; every Unicode dash or hyphen is `-`), and `acme/ui` or `github:acme/ui` is read as a form of `@acme/ui`.

Add your own with `FOURDA_PRIVATE_PACKAGES`: comma- or space-separated globs, `*` matching anything (`/` included), each optionally prefixed with its ecosystem: `FOURDA_PRIVATE_PACKAGES="npm:@acme/*, crates.io:acme-*, PyPI:acme-*, Go:github.com/acme/*"`. A bare scope (`@acme`) covers the whole scope; PyPI names are compared PEP 503-normalised (`Acme_Auth` is `acme-auth`). The rules are read again whenever one of those files or variables changes. A name your project also installs from the public registry is public (asking about it reveals nothing). A private package is still read from your lockfiles, and is never looked up anywhere, as itself or as the parent of a public one: `vulnerability_scan`, `dependency_health`, `upgrade_planner` and `what_should_i_know` lead with `NOT CHECKED (private)` (the briefing also for a private package the task only names, installed or not, and never calls such a task `safe_to_delegate`) and list each one with the file or setting that made it private (`coverage.private_dependency_list`), so the answer is never a clean one for it; `dependency_check` answers it `unknown` with `not_checked: "private"` (a name withheld only because a lockfile or manifest of the project could not be read is said as that, `NOT CHECKED (unreadable lockfile)` with `unreadable_file`, and the remedy is to repair the file); `upgrade_impact` refuses it; `upgrade_planner` never looks up a private parent's releases, and a step that arrives through one leads with `NOT CHECKED (private)` and names it in `privateParents` (never an inferred refresh); `ecosystem_pulse` never uses its name as a search term (its terms come only from the project the server runs for, never from other projects in the same data folder, and a name another of those projects installs privately is never one). As a second line of defence, every OSV.dev, registry and search request passes one check that refuses it when its URL or body names a private package; a refused request reads as not checked, never clean. Registry URLs are shown without credentials.

**GitHub release notes (opt-in, off by default).** Many packages ship no changelog in their registry archive (vite, zod, cobra, most Go modules). With `FOURDA_GITHUB_CHANGELOG=true` in the server's environment, `upgrade_impact` reads the repository's GitHub releases when the archive has no changelog for the range (for PyPI, first a changelog file the project links on GitHub from its `project_urls`). GitHub then receives the repository name and the versions, nothing else. It uses the unauthenticated REST API (60 requests an hour) or `GITHUB_TOKEN` when set (5,000); a rate limit is reported with its reset time, never retried in a loop, and results are cached. With it off, an answer without a changelog says so and names the setting; nothing is guessed.

**What's written to disk, and where:** only files the server owns, in its folder in your user data directory (`%LOCALAPPDATA%\4da-mcp`, `~/Library/Application Support/4da-mcp` or `~/.local/share/4da-mcp`; `FOURDA_MCP_HOME` moves it): `cache.db` (registry, OSV and changelog responses, in every mode; safe to delete, it costs refetches only), `standalone.db` (without the desktop app: your project scan and the decisions, agent memory and feedback you record; no cache) and `check-ledger.jsonl` (each `dependency_check` verdict, for the plugin hook; started empty when the server starts serving; moved to `check-ledger.1.jsonl` past 512 KB, so the two hold about 1 MB at most). Nothing is written inside your repository. `standalone.db` is known by its path: a file there that a killed first start left empty or half-made is completed in place, and a table that exists is never touched. (Until 6.3.0 standalone mode kept the cache inside `standalone.db`; that table is dropped the first time 6.3.0 opens it.)

When the 4DA desktop app is installed, the server reads the app's database (`4da.db`) through a **read-only** connection and never creates or alters anything in it: no tables, no columns, no cache. It is never the dependency inventory either, and a scan never writes to it: the dependency tools read every lockfile under the project root from disk, exactly as without the app, with the same `coverage` (see "Standalone vs. Full Mode"). The only writes are rows in the four app-owned tables the tools exist to fill, so the app sees them: decisions (`decision_memory` -> `developer_decisions`), agent memory (`agent_memory`), and feedback (`record_feedback` -> `interactions` and `feedback`, which the app's calibration reads). Those go through a separate write connection that waits briefly for the app's lock. If your app version lacks the table or a column a record needs, the record goes to `standalone.db` instead and the response says so in `_meta`. (Before 6.1 the server also created a `live_cache` table inside the app's database; it now keeps that cache in `cache.db`.)

**Where configuration and the database come from:** `FOURDA_DB_PATH` if set, else the desktop app's database in its data directory, else the server's own `standalone.db`. `FOURDA_DB_PATH` must name an existing file (a relative path resolves against the server's working directory); one that names no file is refused and nothing is created there, except when it names the server's own `standalone.db`. A file with no tables is not taken for the app's database either. Then the tools that answer from the project's files (`vulnerability_scan`, `dependency_health`, `dependency_check`, `upgrade_impact`, `upgrade_planner`, `what_should_i_know`, `ecosystem_pulse`) still answer, each answer carrying `_meta.database_note` with the reason (the briefing has no stored decisions, memories or feed rows, and says so in `stored_data_note`); every other tool returns the error, which names the path. A fresh clone whose committed `.mcp.json` names `./data/4da.db` therefore still gets dependency answers. Embedding settings come from `FOURDA_SETTINGS_PATH`, else the `settings.json` beside `FOURDA_DB_PATH`, else the desktop app's data directory. Nothing is picked up from the directory the server is started in: until 6.2.5 a `data/settings.json` or `data/4da.db` inside (or beside) the working directory was adopted, so a cloned repository could redirect semantic recall to a host of its choosing or plant "decisions".

> The one exception: if you *explicitly* configure an OpenAI embedding provider (`FOURDA_EMBED_PROVIDER=openai`) for semantic recall, OpenAI receives exactly this, to be embedded: the text of the decisions and memories you stored (subject, decision or content, rationale, rejected alternatives), and the text being searched for: a `what_should_i_know` task, an `agent_memory` recall query, or a `check_decision_alignment` technology and pattern. Never the file paths you pass in `files` (they rank results locally), never source code. The default — no embedding provider, or a local Ollama one — keeps everything on your machine, and `FOURDA_OFFLINE=true` overrides it regardless.

**Ecosystems supported:** npm, crates.io (Rust), PyPI (Python), Go; `vulnerability_scan` also reads RubyGems (`Gemfile.lock`) and Packagist (`composer.lock`). Maven, Gradle and .NET are not read, and are listed as not covered. `upgrade_impact` reads npm, crates.io, PyPI and Go. PyPI: versions and dates from the PyPI JSON API, the changelog from the release's sdist, and import sites matched on the module the distribution installs: read from your virtualenv's metadata (`.venv`, `venv`, `env`: `top_level.txt` or `RECORD`), else a table of well-known differences (`PyYAML` -> `yaml`, `Pillow` -> `PIL`), else the distribution name, which the answer then labels an assumption. Go: versions and dates from proxy.golang.org, the changelog from the module zip, and a major version 2+ reported as the module path change it is (`github.com/jackc/pgx/v4` -> `/v5`), with the files that import the old path. `dependency_check` reads all four too; on PyPI and Go, where the registry exposes no publisher identity or install hooks, those signals say "not applicable".

**Known limits, stated plainly:** a `requirements.txt` without a lockfile names only your direct pins, so their transitive dependencies are not scanned (use `uv lock`, `poetry lock` or `pip-compile`). Many packages ship no changelog in their registry archive (fastembed, vite, zod among them); `upgrade_impact` then says so and gives the release-notes URL instead of guessing. Breaking entries are flagged from the changelog's headings and wording, and every entry carries the heading it sits under (`under`). Measured on a panel of 40 real upgrades across npm, crates.io, PyPI and Go (1,618 entries; gold is the majority of three blind raters, each a model instance working to a written rubric, with a verbatim quote for every label; the panel and the measurement are in the test suite): on the 20 upgrades held out from rule-making, 95% of entries flagged breaking were breaking (95% CI 89-98%) and about 72% of breaking entries were flagged; Go release notes written as prose are the weakest (about 54% recall). Treat the flags as a pre-sort: read every entry of a major upgrade. Each answer says this in `_meta.classification`.

The plan has limits of its own. `run_order` is the part of the plan that is safe to run as commands. Rows that need a hand edit (an override that crosses a major of what its parents declare, Yarn classic lockfile entries with copies on several release lines, a requirement edit the manager has no command for) are counted and named in `run_order_note`; running the script alone does not finish them. Measured on 14 public projects (`bench/plan-exec`: each project's plan run top to bottom on a copy, then rescanned), the script ran 0 failing steps where 6.4.0's plan had 10, and on Yarn classic projects it leaves most of the work as named hand steps. A target is checked for vulnerable dependencies it holds one level down and, on npm, for the exact pins of those dependencies two levels down (`@hey-api/openapi-ts` 0.97.3 pins `@hey-api/json-schema-ref-parser` 1.4.2, which pins an affected `js-yaml` 4.1.1: the plan says so and gives no command for it, and `dependency_check` names the copy); a range two levels down, anything deeper, and a copy bundled inside the target's tarball (`tap` bundling its own copies) are not detected. A first plan or check of many crates can need a second call: crates.io allows one request a second, so a cold batch of 25 crates may not finish within one call's time, and what it did not reach is answered NOT CHECKED, never clean (the lookups run on, and the next call answers from them). With `project_path: "*"`, the app's plan has one step per package, which can still cover copies whose routes differ between projects; `upgrade_planner` for one project gives each copy its own row.

## What You Can Ask

```
"What changes if I upgrade axum to 0.8?"      -> upgrade_impact
"Check my dependency health"                  -> dependency_health
"Scan for vulnerabilities"                    -> vulnerability_scan
"Which deps should I upgrade first?"          -> upgrade_planner
"Is it safe to bump axios to 1.14.1?"         -> dependency_check
"Pin ws to a 7.x version"                     -> dependency_check (to: "7.x")
"I'm about to bump fastembed 5 -> 7"          -> what_should_i_know
"What's happening in the ecosystem?"          -> ecosystem_pulse
"What's my tech stack?"                       -> get_context
"Record a decision: we chose Postgres"        -> decision_memory
"Does switching to MySQL align?"              -> check_decision_alignment
"Remember: never use ORM for batch inserts"   -> agent_memory
```

## Tools

### Dependency Security

| Tool | What it does |
|------|-------------|
| `upgrade_impact` | What changes between the installed and a target version of one dependency (npm, crates.io, PyPI, Go): releases in between, changelog entries classified breaking / deprecation / security, the breaking ones that touch your code (symbols you import, and route or pattern syntax in your string literals, e.g. axum 0.8's `/:id` -> `/{id}`), the files that import it, advisories fixed. |
| `vulnerability_scan` | Every installed copy in every lockfile matched against OSV.dev. Scope-adjusted `severity` with the advisory's own grade beside it (`advisory_severity`, `by_advisory_severity`; see "Two grades for one advisory"), an upgrade target checked against every advisory of the package (the highest per-advisory fix can itself be affected by another), where each version is pinned, and a `coverage` block on every answer (`complete: true` with `lockfiles_read` when nothing was left out, `complete: false` with what was left out otherwise). Rows come in one fixed order, so detailed pages never lose or repeat a row. Concise by default (one row per vulnerable package version, the 40 most severe; about 10k tokens on a project with about 290 advisories); `package` for one dependency; `response_format: "detailed"` for every advisory. |
| `dependency_health` | Version freshness, deprecation (of the version you run) and vulnerability counts per dependency. With no lockfile read it withholds the score (`healthScore: null`, `withheldReason: "no_lockfile"`). |
| `upgrade_planner` | The smallest version no advisory affects for each vulnerable package, majors flagged (a 0.x minor counts as a major). Direct steps (`upgrade_direct`) carry `upgradeCommands`, the command per declaring project directory, keeping how the dependency is declared (`npm install x@v --save-exact` for an exact pin, `npm install "x@^v"`, `pnpm up`, `yarn upgrade` / `yarn up`, `cargo add` with `--dev` / `--build` / `--target` / `--rename`, `go get`; none for a `>=` / `||` / tag / git spec or a yarn workspace member), and a direct target is raised when a slightly newer release also clears a vulnerable transitive it pins. Transitive fixes: `lockfile_refresh` with the exact command (`npm update`, `pnpm update`, `yarn up -R`, `cargo update -p ... --precise`) when every parent's declared requirement already admits a clean version; `upgrade_parent` when a parent pins it but a newer release of that parent admits one, with `parentUpgrades` naming the smallest such release that is itself clear of the parent's advisories (read from the registry), the declared dependencies to bump (`levers`, with their commands; none when the lockfile cannot tie the parent to a declaration) and, when the new requirement still admits the installed copy, the refresh to run after the install (`refreshCommands`); `override_or_replace` with the override syntax (npm `overrides`, pnpm `pnpm.overrides`, yarn `resolutions`, Cargo `[patch]`) when the parent will not move (deprecated, already its latest release, or no release admits a clean version); `waiting_on_upstream` when the parent's releases could not be read, and for a copy bundled inside its owner's package, which only a new owner release (or replacing the owner) can move. `waiting_on_upstream` means no command you can run today fixes that copy; a Python parent the project does not declare is moved by its own refresh (`uv lock --upgrade-package <parent>`) when what requires it admits a release of it that admits the fix. When one version is installed both bundled inside another package and on its own, the row is the `lockfile_refresh` for the copies that are not bundled and `bundledCopies` names each owner whose bundled copy stays; the summary counts that row as a refresh and as waiting on upstream, never as fully fixed. A Cargo upgrade into a release that no longer offers a feature your `Cargo.toml` enables is an instruction naming the feature, not a command cargo would refuse (`upgrade_impact` lists such features in `your_code.cargo_features_removed`). Every row carries `commands` (`{ dir, run }`, `dir` relative to the project, `"."` for the root; empty when its reasons say why nothing is run, such as a hand edit of a lockfile entry or a manifest; a direct upgrade with no command always says why in its reasons, and a freshness upgrade, which no advisory against the installed version makes a security fix, says so, is left out of `run_order` and names the hand step that takes it), and the plan carries `run_order`: the rows shown as one script (`{ n, dir, run, fixes }`) that is safe to run from the first step to the last: one version-setting command per package per directory at the highest release any row needs, nothing set below a version that is installed or that an earlier step sets, every `go get` of one module directory in one command, upgrades before in-range refreshes and a parent upgrade before the refreshes that follow it, and a target that breaks an installed package's peer range run in one command with that package's release when the plan moves it, or left out with the reason. On pnpm the peer step after a parent's upgrade names the release that upgrade leaves, never a lower one. An override within its parents' major is written as commands (`npm pkg set "overrides.<name>=<version>"`, or `pnpm.overrides` / `resolutions`, then the install, in the lockfile's directory), and on Yarn classic a package the lockfile holds on one release line, every copy at or below the target, is refreshed with an exact resolution (`npm pkg set "resolutions.<name>=<target>"`, then `yarn install`; the resolution stays). In a uv workspace each command runs once, at the root, and a copy only a member's leftover `uv.lock` lists is a hand step (delete the file); a uv pin whose release needs a newer Python than the project supports is a hand step that says to raise `requires-python` first; a Cargo row whose release needs a newer Rust than the `rust-version` its `Cargo.toml` declares (inherited from `[workspace.package]` too) carries `needsNewerRust` (`{ crate, version, needs, declared, manifest }`) and a reason, and the step stays, since `cargo update --precise` and `cargo add` install it anyway and only the build on the declared Rust fails (the summary and `run_order_note` count such rows); a package a uv, npm/pnpm/Yarn or Cargo workspace member defines is taken from the workspace and never upgraded from the registry. `run_order_note` says what it covers and what it leaves out, and why, and counts and names the rows that are hand edits and not in the script. Dev-only packages are included and labelled `isDev`, as in `vulnerability_scan`. `package` for a one-package plan.<br><br>**Which plan.** For one project (the default, the project the server was started in, or `project_path`) the plan is always computed by this server from that project's lockfiles, with or without the desktop app (`provenance.mode: "lockfile_engine"`). With the app attached, `app_plan_check` says how the app's stored plan compares, by ecosystem, package and installed version: `agrees`, `differs` (up to 10 `differences`), `not_comparable` (a plan format this server does not read, the app's advisory data more than 24 hours old, a lockfile changed after the plan was generated, or this server's own scan incomplete) or `no_plan`, with `plan_generated_at` and `advisory_data_age_hours`; the app's plan never replaces this one. `project_path: "*"` with the app attached returns the app's stored plan across every project it tracks, labelled as such (`provenance.mode: "app_plan"`, `app_plan_check.status: "unverified"`, or `"not_comparable"` on old advisory data): it is not checked against the lockfiles on disk, and `stale` is true when it is past its expiry, when its advisory data is more than 24 hours old, or when a lockfile of a project it covers changed after it was generated (up to 5 named). Without the app, `"*"` plans the project the server was started in. A command written with a range carries `installs`, the release it installs when that is not the target, checked as the target was; otherwise the command names the checked release exactly. A direct upgrade that would leave other packages on an affected copy is a hand edit, not in `run_order`. Scan again after running a plan: what an upgraded package brings in deeper than that (a range two levels down, anything below, a bundled copy) is not checked. |
| `dependency_check` | Call before writing any dependency version into a manifest: adding, pinning, upgrading, bumping, downgrading. `to` is the exact version, or the constraint you were given (`"7.x"`, `"^1.20"`, `"~=3.1"`, `"v1"`): then `safe` names the smallest and newest release in it that no known advisory affects, and the verdict is for the one it picks. The answer is concise by default (verdict, a reason carrying the evidence of every avoid / review / unknown / wait finding, `safe`, advisory ids and any registry quotes: about 10 KB for 25 items); `response_format: "detailed"` adds every signal with its evidence, `to_read_as` and the full `range_check`. An exact version an advisory affects gets the safe releases on its line. Verdict per item (`proceed` / `wait` / `review` / `avoid` / `unknown`) with evidence: advisories on the target, release age (holds releases under 3 days unless they fix an advisory you have), publish-trust drop, new install scripts, brand-new transitive dependencies, yanked or deprecated, and a breaking version range (a major, or a 0.x minor) is `review` with a pointer to `upgrade_impact`. A name that is malware itself is `avoid`; a new npm dependency one or two edits from a popular package (`expres`) is `review` with "did you mean" unless its downloads and age show it is established, and a new PyPI name one or two edits from a popular project is `review` with "did you mean" too (`avoid` when under 30 days old with at most 3 releases; PyPI publishes no download counts). A release is also judged by what it requires: an npm release's exact pins and ranges, a crate's dependencies and a PyPI release's `requires_dist` (an environment marker is judged against the Python versions the project declares): one whose newest admitted release, or pin, has an advisory counts against the release; a Go release's go.mod minimums with advisories are a caveat naming the `go get` that raises them. On PyPI, `python_support` says whether the release supports every Python the project declares (`requires-python`, Poetry, uv.lock, Pipfile, `.python-version`, `runtime.txt`): a release whose lower bound excludes one is `review` and never a safe pick; an upper cap is a note. `to_read_as` (in every answer to a constraint or "latest", and in the detailed form) says how `to` was read: a bare PyPI `"3.1"` is the release 3.1.0, as pip reads `==3.1`, never the series. A prerelease is never named as the safe release unless you ask for one. A registry's own words (a deprecation message) are quoted in `quoted_from_registry`, capped, never inside `reason`. A private package is `unknown` and never looked up (see "Private packages are never sent"). npm, crates.io, PyPI and Go (publisher trust, install scripts and new transitive dependencies are npm/crates.io signals and say "not applicable" elsewhere). One item refused as written (an npm dist-tag other than `latest`, a Poetry caret, an unknown ecosystem, an npm scope written without its `@`) is `unknown` with `not_checked: "input"` and its reason, and the rest of the batch is answered. Go: a release is judged against the module's retractions, and when the list of retractions could not be read the item is `unknown`, never `proceed`, and nothing is cached for it; an item this server's own Go request limit held back says so (the proxy was not asked) and carries `retry_after_seconds`. |

### Intelligence

| Tool | What it does |
|------|-------------|
| `what_should_i_know` | Pre-task briefing built from the task: the dependencies it names (and the families it names: "all tauri plugins" adds the project's tauri-*, tauri-plugin-* and @tauri-apps/* packages; for "latest", whether each is already on the newest major), their versions and confirmed vulnerabilities, majors crossed, your recorded decisions, and a delegation verdict only confirmed evidence can raise. A version the task names (`lodash@4.17.20`, `Django==3.2`, "pin axios to 0.21.1", "add lodash 4.17.20", "bump X from A to B") is judged by `dependency_check` at exactly that version or constraint (`requested_versions`); one that is not `proceed` means the task is not `safe_to_delegate`. A package the task adds ("add the X package", `npm install X`) is run through `dependency_check`: a name that is malware is `human_only`, a near-miss of a popular package or a name the registry does not have is `review_needed`. |
| `ecosystem_pulse` | Hacker News headlines that name your dependencies, then your languages (labelled as such). Fetched only when called; the search terms are the frameworks and direct dependencies of the project on disk (with or without the desktop app), never a private name. |
| `get_context` | Your tech stack, resolved dependency versions, interests, detected topics. |
| `get_relevant_content`* | Scored content feed that passed the desktop app's relevance judge, one item per advisory. A `since_hours` you pass is never widened; the default 24 hours is widened to 168 and then 720 hours when it holds nothing, and `window` (`requested_hours`, `used_hours`, `widened`) and `summary` say so. |
| `get_actionable_signals`* | Judge-accepted feed items the app classified (advisories, breaking changes), plus this project's own vulnerabilities, with the scan's instruction for each. It starts the project's scan and waits for it when none has run in the session (`scan`: `status`, `scanned_at`; `note` starts NOT CHECKED when the scan is missing or incomplete). The same window rule as `get_relevant_content` (default 48 hours; `window` and `note`). |
| `knowledge_gaps`* | Dependencies with judge-accepted advisories or releases you have not looked at. |
| `record_feedback`* | Save or dismiss items; recorded in the app's own feedback tables, which its calibration reads. A record that could not be written (the app holding its write lock) is an error, never a success. |

### Decisions & Memory

| Tool | What it does |
|------|-------------|
| `decision_memory` | Record, query, and manage architectural decisions across sessions. |
| `check_decision_alignment` | Verify if a proposed technology change aligns with recorded decisions. |
| `agent_memory` | Persistent memory that survives across sessions, agents, and editors. |

### Identity

| Tool | What it does |
|------|-------------|
| `developer_dna`* | Your tech identity: primary stack, top dependencies, blind spots. |

*\* Requires the [4DA desktop app](https://4da.ai) for full data.*

### Prompt: `deps`

A user-invoked workflow (shown as a slash command by hosts that surface MCP prompts). It tells the agent to run `upgrade_planner`, check every proposed bump with `dependency_check`, apply only `proceed` items in small batches with the project's own tests after each batch, stop and report every `review` / `avoid` / `wait` / `unknown` item with its evidence, and re-run `vulnerability_scan` at the end. Optional argument `scope` (e.g. `security only`).

## Standalone vs. Full Mode

The MCP server works without the desktop app. It keeps a small local database in your user data folder (`%LOCALAPPDATA%\4da-mcp`, `~/Library/Application Support/4da-mcp` or `~/.local/share/4da-mcp`, never inside your repository) and scans your project on every start:

| Capability | Standalone | With 4DA Desktop |
|------------|-----------|-------------------|
| Upgrade impact (changelog, breaking changes, your call sites) | Yes | Yes |
| Vulnerability scanning (OSV.dev) | Yes | Yes |
| Dependency health (4 registries) | Yes | Yes |
| Upgrade planner | Yes | Yes |
| Pre-install dependency check | Yes | Yes |
| Ecosystem news (Hacker News, on request) | Yes | Yes |
| Pre-task intelligence briefing | Yes | Yes |
| Tech stack detection + resolved versions | Yes | Yes |
| Decision memory + alignment checking | Yes | Yes |
| Agent memory (cross-session) | Yes | Yes |
| Developer news judged against your stack (the app's feed) | -- | Yes |
| Actionable signals + knowledge gaps | -- | Yes |
| The analysis layer (Signal Chains, Knowledge Gaps, temporal analysis) | -- | Yes |

**With the desktop app attached** the dependency tools still read every lockfile under the project root from disk, with the same `coverage`: the same project gives the same packages, counts and coverage either way, and a sub-project the app has not indexed is not lost. The app's database supplies the app-backed tools (marked * above), decisions and memory, and the app's stored plan for `upgrade_planner` with `project_path: "*"`; a scan never writes to it.

**Supported app versions.** This server is tested against 4DA v1.0.3 (schema 124, plan format 4) through the app's main branch of 2026-11-22 (schema 131, plan format 5). With an app outside that range attached the server keeps serving (an answer it cannot serve from that database says which side to update, it does not just fail), and `get_context` and every answer that reads or writes the app's data carry `_meta.app_compatibility` (`status`: `app_older_than_supported` or `app_newer_than_tested`, the app's schema and plan format, the supported range, and a `note` saying whether to update the app or this server).

> **[Download 4DA](https://github.com/4DA-Systems/4DA/releases/latest)** for the full experience.

## Transports

**stdio** (default) -- works with all MCP hosts:
```bash
npx @4da/mcp-server@6.5.0
```

**Streamable HTTP** -- for remote or multi-client setups:
```bash
npx @4da/mcp-server@6.5.0 --http --port 4840
```

The HTTP transport binds to `127.0.0.1` by default and applies a `Host`-header
DNS rebinding guard to every request. Exposing it beyond this machine requires
a shared secret:

```bash
MCP_AUTH_SECRET=<same value as the relay's JWT_SECRET> \
MCP_ALLOWED_HOSTS=mcp.internal \
  npx @4da/mcp-server@6.5.0 --http --host 0.0.0.0
```

Without `MCP_AUTH_SECRET` a non-loopback bind is refused at startup. With it,
every request must carry a Bearer token whose HMAC-SHA256 signature verifies
against that secret, and the token's role is enforced per tool (`viewer` is
read-only; `member` and `admin` may write). Put TLS in front of it.

JSON-RPC batches are refused with `-32600`, as on stdio: MCP removed them in
protocol revision 2025-06-18. A request that speaks 2025-03-26 or earlier (its
`MCP-Protocol-Version` header, an `initialize` in the batch, or no version at
all, which the transport spec reads as 2025-03-26) is still served, because
that revision requires a server to accept batches.

**HTTP mode is single-tenant.** A token's `team_id` is verified but not used to
separate data: every authenticated client shares one database, one agent memory
and one set of decisions, and `project_path` lets any authenticated client scan
any directory on the host the server can read. Run one server per team (or per
trust boundary), and only behind clients you would give that access.

## CLI Reference

```
npx @4da/mcp-server@6.5.0              # Start server (stdio)
npx @4da/mcp-server@6.5.0 --http       # Start server (Streamable HTTP)
npx @4da/mcp-server@6.5.0 --setup      # Auto-configure your editors
npx @4da/mcp-server@6.5.0 --doctor     # Check the install (exit code 1 when a check fails)
npx @4da/mcp-server@6.5.0 --version    # Print version
```

`--doctor` prints one line per check: the Node.js version, the SQLite driver, the data folder, the server's own database, the cache (on disk or in memory, and why) and the app database, each with its path and state; build freshness in a repository checkout; the semantic recall provider; the proxy when one is set; whether OSV.dev and each registry answer; and a "Server version" warning when a session has seen a newer release. When it finds the server's own database empty (0 bytes) or without tables, it completes it in place, as a tool call would, and says so as a warning: anything that file was meant to hold is not in it. It exits 1 when any check fails, among them a server's own database it cannot open or complete, and a `FOURDA_DB_PATH` that names no file or a file with no tables. The app database is only read.

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `FOURDA_DB_PATH` | Path to 4DA's SQLite database. An existing file with tables is used (a relative path resolves against the working directory). A path that names no file, or a file with no tables, is refused and nothing is created there (except at the server's own `standalone.db` path): the tools that answer from the project's files still do, with `_meta.database_note`, and the others return the error. See "Where configuration and the database come from". | The desktop app's database, else the server's own |
| `FOURDA_DATA_DIR` | Folder searched before the desktop app's own data directory for its `4da.db` and `settings.json` (`FOURDA_DB_PATH` and `FOURDA_SETTINGS_PATH` take precedence) | Unset |
| `FOURDA_SETTINGS_PATH` | `settings.json` holding the optional `embedding` block for semantic recall | Beside `FOURDA_DB_PATH`, else the desktop app's data directory |
| `FOURDA_EMBED_PROVIDER` | Turns semantic recall on with an embedding provider: `ollama` (local) or `openai`. Takes precedence over the `embedding` block of `settings.json`. What the provider receives is in the note on embeddings above. | Unset: no embedding provider |
| `FOURDA_EMBED_MODEL` | The embedding model, with `FOURDA_EMBED_PROVIDER` | `nomic-embed-text` (Ollama), `text-embedding-3-small` (OpenAI) |
| `OLLAMA_URL` | The Ollama endpoint, with `FOURDA_EMBED_PROVIDER=ollama`. An endpoint on another machine receives the text the note above says OpenAI receives. | `http://localhost:11434` |
| `OPENAI_API_KEY` | The API key, with `FOURDA_EMBED_PROVIDER=openai`. Without a key the provider is not used. | Unset |
| `FOURDA_OFFLINE` | Disable all network calls (`1` / `true` / `yes` / `on`, any case; any value other than those and `0` / `false` / `no` / `off` is read as on, and said on stderr) | Off |
| `FOURDA_PRIVATE_PACKAGES` | Package names never sent anywhere, in addition to what `.npmrc`, `GOPRIVATE` and your lockfiles already mark private: globs, `*` matching anything, optionally `npm:` / `crates.io:` / `PyPI:` / `Go:` prefixed. See "Private packages are never sent". | Unset |
| `FOURDA_PUBLIC_MIRRORS` | Hosts of registries, indexes or Go proxies that only mirror the public ones (comma- or space-separated). Without it, a default registry, index or proxy that is not public makes that ecosystem's packages private. See "Mirrors". | Unset |
| `FOURDA_PROJECT_DIR` | The project the server scans and answers for, in place of the directory it was started in (for hosts that start servers from their own directory; the `.mcpb` bundle sets it from its folder picker). A value that still holds an unfilled `${...}` template is ignored. | The working directory |
| `FOURDA_CALL_BUDGET_MS` | The time one tool call may take, counted from the request. A call still running then is answered NOT CHECKED (`dependency_check`: every item `unknown`); its lookups run on and are cached, so the same call made again answers from them. | `20000` |
| `FOURDA_WALK_BUDGET_MS` | The time the startup walk of the project tree may take. Past it the scan is partial and says so. | `10000` |
| `HTTPS_PROXY`, `HTTP_PROXY`, `NO_PROXY` | Every lookup goes through the proxy (NO_PROXY honoured); an unreachable proxy means NOT CHECKED, never a direct connection. See "Behind a proxy". | Unset |
| `FOURDA_GUARD` | The plugin hook: `advise` advises after a manifest edit and never denies; `off` turns the hook off. | Unset: the hook denies an unchecked version |
| `FOURDA_GITHUB_CHANGELOG` | `upgrade_impact`: read GitHub release notes when the registry archive has no changelog for the range (`true` / `1` / `yes` / `on`) | Off |
| `GITHUB_TOKEN` | Used only with `FOURDA_GITHUB_CHANGELOG`: raises GitHub's rate limit from 60 to 5,000 requests an hour | Unset |
| `FOURDA_MCP_HOME` | Folder for the files the server writes (`cache.db`, `standalone.db`) | Your user data folder + `4da-mcp` |
| `MCP_AUTH_SECRET` | Shared secret for verifying Bearer tokens on `--http` (HMAC-SHA256). Falls back to `JWT_SECRET`. Unset means no token is accepted. | Unset |
| `MCP_AUTH_REQUIRED` | Require auth on a **loopback** `--http` bind (`1` / `true` / `yes` / `on`; an unreadable value is read as on). Always required on a non-loopback bind. | Off |
| `MCP_ALLOWED_HOSTS` | Extra comma-separated hostnames accepted in `Host`/`Origin` (needed when binding to `0.0.0.0`). | localhost only |

## Limits

The server reads repositories it did not write, so everything it reads is bounded, and a bound that is hit is reported, never passed off as a clean result.

- **Time.** A tool call has 20 s (`FOURDA_CALL_BUDGET_MS`); the walk that finds a project's lockfiles has 10 s (`FOURDA_WALK_BUDGET_MS`), 20,000 directories, 4 levels and 256 projects. Past a walk bound the answer is a partial scan (`coverage.complete: false`).
- **Size.** A lockfile or manifest over 64 MB is not read and is reported as UNREADABLE. A `.gitignore` over 1 MB, its rules past 5,000, and a pattern over 1,024 characters are not applied; a negation that cannot be applied re-includes everything below its file, so a limit can only make the scan cover more.
- **Arguments.** A version or constraint is at most 256 characters, a package name 512.
- **Place.** A drive or filesystem root and the operating system's own directories (`C:\Windows` and below, `/usr`, `/etc`, `/System` and the like) are not scanned: pass `project_path` with your project's root, or set `FOURDA_PROJECT_DIR`.

## Behind a proxy

Set `HTTPS_PROXY` (and `HTTP_PROXY`, `NO_PROXY`, in upper or lower case) in the server's environment (the `env` block of the MCP server entry) and every OSV.dev, registry and search lookup goes through that proxy, on every supported Node; nothing else to set. Hosts `NO_PROXY` names are reached directly. A proxy that cannot be reached, or refuses a request, makes the lookup fail, and the answer says NOT CHECKED: nothing is ever retried around the proxy. The server uses undici's `EnvHttpProxyAgent` for this (`undici`, MIT, pinned). An embedding provider you configure is the exception: it uses Node's own `fetch`, which honours the proxy on Node 24.14+, or on 22.21+ started with `NODE_USE_ENV_PROXY=1`.

The first lines of the server's stderr, and `npx @4da/mcp-server@6.5.0 --doctor`, say so whenever a proxy variable is set.

## FAQ

**Does this send my code anywhere?**
No. When a tool needs them (never at startup), the server sends public package names and versions to public APIs ([OSV.dev](https://osv.dev), npm registry, crates.io, PyPI, Go proxy), never a private package's name, downloads the target version's archive from the package's own registry for `upgrade_impact` (and reads GitHub release notes only if you set `FOURDA_GITHUB_CHANGELOG=true`), and, only when you call `ecosystem_pulse`, sends a few dependency names as search terms to [HN Algolia](https://hn.algolia.com/api). No source code, no file paths, no personal data: the call-site scan runs locally. Set `FOURDA_OFFLINE=true` to disable all network calls. (The sole exception is opt-in OpenAI embeddings — see the network note above.)

**How does this compare with GitHub's dependency tool for agents?**
GitHub's hosted MCP server has `check_dependency_vulnerabilities` (dependabot toolset). It needs a GitHub token and reports high and critical advisories and malware. In one comparison on 2026-11-11 (216 identical cases, ground truth from OSV.dev, this server at 6.2.7) it was faster (median 1.2 s against 2.5 s) and covers Maven and .NET, which this server does not read; it missed 102 of 178 known-bad versions, mostly medium and low advisories and RustSec / PyPA / Go-only records, which this server reports, and it does not judge nonexistent, yanked, deprecated or days-old releases. The cases and results of that comparison are not published in this repository, so it cannot be re-run from here: read it as one dated measurement of 6.2.7. This server needs no account and runs on your machine.

**Do I need the 4DA desktop app?**
No. These work standalone: upgrade impact, pre-install dependency checks, vulnerability scanning, dependency health, upgrade planning, ecosystem news, pre-task briefings, project context, decision memory, alignment checking, and agent memory. The desktop app is where the same engine runs day to day: one worklist across every project on the machine, a morning Brief of what changed in your stack, and an Upgrade Plan. With it installed, your agent also gets signals, knowledge gaps, developer news judged against your stack, Developer DNA and feedback.

**Which AI tools does this work with?**
Any tool that supports [MCP](https://modelcontextprotocol.io): Claude Code, Claude Desktop, Cursor, Windsurf, VS Code (Copilot), and any custom MCP client.

## Build from Source

```bash
git clone https://github.com/4DA-Systems/4da-mcp-server.git
cd 4da-mcp-server
pnpm install
pnpm build
pnpm test    # offline
```

## License

Apache License 2.0 (`Apache-2.0`). See [LICENSE](LICENSE).

---

Built by [4DA](https://4da.ai)
