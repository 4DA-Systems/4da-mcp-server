# @4da/mcp-server

[![npm version](https://img.shields.io/npm/v/@4da/mcp-server?color=gold)](https://www.npmjs.com/package/@4da/mcp-server)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Node](https://img.shields.io/badge/Node-%3E%3D22-brightgreen)](https://nodejs.org/)
[![CI](https://github.com/4DA-Systems/4da-mcp-server/actions/workflows/ci.yml/badge.svg)](https://github.com/4DA-Systems/4da-mcp-server/actions/workflows/ci.yml)

**Upgrade intelligence for AI coding agents.** Before your agent bumps a dependency it learns what changes between the version you run and the one you want, which of your files that touches, and which vulnerabilities the move fixes, from your own lockfiles, on your machine. Plus vulnerability scanning at osv-scanner parity, ranked upgrade plans and decision memory. Zero config, no account.

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

*(Real output, abridged, run on this repository, 2026-10-02.)*

One command to install. No API keys. No accounts. Your code never leaves your machine.

## Install

Requires Node.js 22 or later.

The server uses Node's built-in `node:sqlite` (Node 22.13 and later), so it needs no install script and works with npm 12's default of blocking them. On Node 22.0-22.12 it uses the optional `better-sqlite3`, whose native module npm 10 and 11 build on install. `npx @4da/mcp-server@6.2.7 --doctor` shows which one is in use.

```bash
claude mcp add 4da -- npx @4da/mcp-server@6.2.7
```

Every command and config on this page pins the version (`@6.2.7`), so what runs changes only when you change it. To update, replace the version with the newest one on npm (`npm view @4da/mcp-server version`); the [changelog](CHANGELOG.md) says what changed. Without a version, npx runs whatever it has cached or the newest release, which you did not review.

**As a Claude Code plugin** (the MCP server plus a hook):

```bash
claude plugin marketplace add 4DA-Systems/4da-mcp-server
claude plugin install 4da@4da
```

The hook: when your agent edits a dependency's version in `package.json`, `Cargo.toml`, `pyproject.toml`, `requirements.txt` or `go.mod`, it is told which packages moved and given the exact `dependency_check` and `upgrade_impact` calls to make before it installs and builds. The hook is plain Node, contacts nothing, and stays silent for every other edit.

<details>
<summary><b>Cursor / Windsurf / Devin Desktop</b></summary>

Add to `~/.cursor/mcp.json` (Cursor), `~/.codeium/windsurf/mcp_config.json` (Windsurf), or `~/.config/devin/mcp_config.json` (Devin Desktop and Devin CLI; `%APPDATA%\devin\mcp_config.json` on Windows):
```json
{
  "mcpServers": {
    "4da": {
      "command": "npx",
      "args": ["@4da/mcp-server@6.2.7"]
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
      "args": ["@4da/mcp-server@6.2.7"]
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
      "args": ["@4da/mcp-server@6.2.7"]
    }
  }
}
```
</details>

<details>
<summary><b>Auto-setup</b> (detects all installed editors)</summary>

```bash
npx @4da/mcp-server@6.2.7 --setup --dry-run   # show each file and entry, write nothing
npx @4da/mcp-server@6.2.7 --setup
```

Writes Cursor, VS Code (and Insiders), Windsurf, Devin Desktop and Claude Desktop configs it finds, merging into what is there: other servers, settings and comments are kept, a backup (`.bak`) is written first, and a file it cannot parse is left untouched with the entry to add by hand. For Claude Code it prints the `claude mcp add` command instead of editing `~/.claude.json`.
</details>

Then ask your AI: **"What changes if I upgrade X to Y?"**, **"Scan for vulnerabilities"** or **"What should I upgrade first?"**

## How It Works

The server reads every lockfile of the project it is started in, including independently-locked projects below the root (a repo with `src-tauri/Cargo.lock` beside a root `pnpm-lock.yaml` is scanned whole): `package-lock.json` / `npm-shrinkwrap.json`, `pnpm-lock.yaml` (v5–v9), `yarn.lock` (v1 and berry), `bun.lock`, `Cargo.lock` (Cargo workspaces included), `poetry.lock`, `uv.lock`, `pdm.lock`, `Pipfile.lock`, requirements pins (`*requirements*.txt`, `requirements/*.txt`, with `-r` and `-c`), `go.mod` / `go.sum` (Go's build list), `Gemfile.lock` (RubyGems; git and path gems are local code, not releases) and `composer.lock` (Packagist). Every Python source in a folder is read, not only the first. Every installed copy is scanned, not one version per name, with the lockfile's own dev flags. It re-reads them whenever a lockfile changes, and for npm it also checks what `node_modules` actually holds. A lockfile is what is installed, so it is read whether or not `.gitignore` lists it, and a dot-directory (`.github/actions/*`) is a directory like any other. What is not scanned is said: a directory `.gitignore` excludes is left out (it is as often a scratch clone as the project's own code), and installed code, build output and caches (`node_modules`, `target`, `dist`, `.venv`, `.git` ...) are never entered, but every lockfile found in an ignored directory, or sitting directly in a `build/`-style one, is listed by path under `coverage.not_scanned.lockfiles`. The walk goes 4 levels down and up to 256 projects; whatever it leaves out is listed the same way. So is every manifest with no lockfile: its declared ranges are not installs and are not scanned, its exact pins are checked but the packages they pull in are resolved nowhere (`coverage.unresolved_manifests`, and `coverage.manifests_without_lockfile` for a manifest in a subdirectory that no lockfile above holds as a workspace member). The `coverage` block is present only when something was left out, and then always says `complete: false`; nothing is dropped silently. So are manifests of ecosystems it does not read (Maven `pom.xml`, Gradle, .NET `*.csproj` / `packages.lock.json`, Pub, Hex, SwiftPM, CocoaPods: `coverage.not_covered`), lockfiles that exist but cannot be read (merge-conflict markers, invalid JSON, Bun's binary `bun.lockb`: `coverage.unreadable_lockfiles`), lockfiles that are truncated or damaged and were read only up to the damage (`coverage.partial_lockfiles`), a second lockfile in a directory that disagrees with the one that was read (`coverage.conflicting_lockfiles`), requirements with no pinned version such as `pydantic>=2.0.0` (`coverage.unpinned_requirements`: there is no installed version to check), dependencies installed from git or a URL (`coverage.not_checkable`: they are not the registry package of that name, so they are never matched against it), files of a supported ecosystem in a form that is not read (`environment.yml`, `setup.py`, `pylock.toml`), and lockfiles under test-fixture directories (`tests/`, `test/`, `fixtures/`, `testdata/`, `__fixtures__/`, `conformance/` ...), which are not scanned as the project's own unless you pass `include_test_fixtures: true` (`coverage.not_scanned`).

**An incomplete answer is never a clean one.** When OSV.dev cannot answer for some dependencies (outage, HTTP error, timeout, the query budget), `vulnerability_scan` starts with `summary: "NOT CHECKED: ... N of M dependencies have no vulnerability answer"`, counts them in `coverage.unchecked_dependencies`, and sets `total_vulnerable_packages` and `by_severity` to null (what the checked part found is under `found_in_checked_dependencies`); `dependency_health` withholds its score and vulnerable count, and `upgrade_planner` sets `vulnerabilityDataAvailable: false`. Large trees are queried in batches of 1,000 as OSV's budget allows, so a tree past 10,000 dependencies is answered in full, and a long answer is read to its last page. An advisory OSV matched whose record it then failed to return is listed as `details: "NOT CHECKED"`: its severity is unknown, not low, no `severity_filter` drops it, and it is asked for again on the next scan instead of being cached. The scan the other tools reuse is at most one hour old; past that it is taken again.

Measured against osv-scanner on 19 public repositories (npm, pnpm v5-v9, yarn v1 and berry, bun, Cargo, Poetry, uv, Pipfile, requirements, Go; 2026-10-10), every difference settled by OSV's own API: precision 1.00 over 19,115 findings, recall 19,115 of 19,116 on the lockfiles it reads (Maven/Gradle are not read). Newly read requirement files were also checked against pip-audit.

Measured with a coding agent (pre-registered, 49 dependency tasks x 3 trials, `claude-sonnet-5-5`, shell and web off in both arms): it wrote a vulnerable version in 82 of 138 well-posed runs without the server and 0 of 138 with it. Harness, tasks, pinned truth and results: [`bench/g7`](bench/g7/).

- **OSV.dev** for known vulnerabilities, matched to exact installed versions
- **npm registry, crates.io, PyPI, Go module proxy** (registry.npmjs.org, crates.io and index.crates.io, pypi.org, proxy.golang.org) for versions, deprecations and yanks
- **npm download counts** (api.npmjs.org), for `dependency_health`'s weekly-downloads figure, and for `dependency_check` when a new dependency's name is a near-miss of a popular package (that name and the popular one, nothing else)
- **The package's own registry archive** (registry.npmjs.org, static.crates.io, files.pythonhosted.org, proxy.golang.org) for the changelog `upgrade_impact` reads; GitHub only if you opt in with `FOURDA_GITHUB_CHANGELOG=true` (below)
- **npm full packument**, the **crates.io versions API**, the **PyPI JSON API** and the **Go proxy's version list** for `dependency_check` (publish times, yanks and retractions; on npm and crates.io also publishers, install scripts, per-version dependencies). These requests carry the package name only; the version you have installed is never sent to a registry, except that the Go proxy's list has no dates, so it is asked for the `.info` of the versions being judged (the same request `go get` makes). OSV.dev's advisory list for the package lets `dependency_check` name the safe releases in a constraint. Packuments are cached on disk and revalidated with `If-None-Match`; crates.io API reads are spaced one per second.
- **Hacker News Algolia API** (hn.algolia.com), only when you call `ecosystem_pulse`
- **GitHub** (api.github.com, raw.githubusercontent.com), only with `FOURDA_GITHUB_CHANGELOG=true`
- **Your embedding provider**, only if you configure one for semantic recall (a local Ollama URL, or api.openai.com; see below)

Those are all the hosts the server contacts.

Results are cached (24h for registry data, 1h for vulnerabilities, 30min for news) and rate-limited per source.

**What's sent over the network, and when:** nothing when your editor starts the server and lists its tools; the project is read locally, and the first request goes out when a tool that needs it is called (`vulnerability_scan`, `what_should_i_know`, `dependency_check` ...). Then: package names and versions (the same data visible in your lockfile), and, only for `ecosystem_pulse`, the names of a few of your dependencies as search terms. Never a private package's name (below). No source code, no file paths, no personal data. The call-site scan of `upgrade_impact` runs locally. Set `FOURDA_OFFLINE=true` to disable all network calls.

**Private packages are never sent.** A package is private, with nothing to configure, when your machine already says so:

- **npm:** its scope is mapped to a registry other than the public one in the project's `.npmrc`, your user `.npmrc` (or `NPM_CONFIG_USERCONFIG`), or `.yarnrc.yml` `npmScopes` at any indentation or in flow style (`@acme:registry=https://npm.acme.dev/`); or your lockfile installs it from another host: the `resolved` location in `package-lock.json` / `npm-shrinkwrap.json` and `yarn.lock`, the `tarball` in `pnpm-lock.yaml` (GitHub Packages included). A global `registry=` setting, and a lockfile host that matches it, is read as a mirror of the public registry, not as making every package private; registry.npmjs.org, registry.yarnpkg.com and registry.npmmirror.com are public. **That has a consequence you should know:** with `registry=https://artifactory.example/...`, an unscoped package published only on that server is still looked up on the public registry by its name. Every coverage note and `dependency_check` answer says so (`registry_notice`): list such packages in `FOURDA_PRIVATE_PACKAGES`, or publish them under a scope, to keep them private.
- **Go:** its module path matches `GOPRIVATE`, `GONOPROXY` or `GONOSUMDB`, from the environment or from `go env -w` (the `GOENV` file; as go does, an empty variable falls back to it).
- **Cargo:** `Cargo.lock` installs it from a registry other than crates.io, or from git (path dependencies are local code and were never sent).
- **PyPI:** `uv.lock`, `poetry.lock` or `Pipfile.lock` installs it from an index other than pypi.org. A company mirror of PyPI named there counts as private too: list nothing, and its packages are reported as not checked.
- **RubyGems:** `Gemfile.lock` lists it under a `GEM` section whose `remote:` is not rubygems.org.
- **Packagist:** `composer.lock` installs it from a host other than Packagist and the public code hosts (a Satis or Private Packagist server), or from a repository `composer.json` declares that is not Packagist (`vcs`, even on GitHub; `composer`; `path`; `artifact`).

Names are compared the way each registry compares them: a crate is the same whatever its case and whether it is written with `_` or `-` (`acme_core`, `Acme-Core`), PyPI names are PEP 503-normalised, npm, RubyGems and Packagist names are case-insensitive.

Add your own with `FOURDA_PRIVATE_PACKAGES`: comma- or space-separated globs, `*` matching anything (`/` included), each optionally prefixed with its ecosystem: `FOURDA_PRIVATE_PACKAGES="npm:@acme/*, crates.io:acme-*, PyPI:acme-*, Go:github.com/acme/*"`. A bare scope (`@acme`) covers the whole scope; PyPI names are compared PEP 503-normalised (`Acme_Auth` is `acme-auth`). The rules are read again whenever one of those files or variables changes. A name your project also installs from the public registry is public (asking about it reveals nothing). A private package is still read from your lockfiles, and is never looked up anywhere, as itself or as the parent of a public one: `vulnerability_scan`, `dependency_health`, `upgrade_planner` and `what_should_i_know` lead with `NOT CHECKED (private)` and list each one with the file or setting that made it private (`coverage.private_dependency_list`), so the answer is never a clean one for it; `dependency_check` answers it `unknown` with `not_checked: "private"`; `upgrade_impact` refuses it; `upgrade_planner` never looks up a private parent's releases, and a step that arrives through one leads with `NOT CHECKED (private)` and names it in `privateParents` (never an inferred refresh); `ecosystem_pulse` never uses its name as a search term. As a second line of defence, every OSV.dev, registry and search request passes one check that refuses it when its URL or body names a private package; a refused request reads as not checked, never clean. Registry URLs are shown without credentials.

**GitHub release notes (opt-in, off by default).** Many packages ship no changelog in their registry archive (vite, zod, cobra, most Go modules). With `FOURDA_GITHUB_CHANGELOG=true` in the server's environment, `upgrade_impact` reads the repository's GitHub releases when the archive has no changelog for the range (for PyPI, first a changelog file the project links on GitHub from its `project_urls`). GitHub then receives the repository name and the versions, nothing else. It uses the unauthenticated REST API (60 requests an hour) or `GITHUB_TOKEN` when set (5,000); a rate limit is reported with its reset time, never retried in a loop, and results are cached. With it off, an answer without a changelog says so and names the setting; nothing is guessed.

**What's written to disk, and where:** only files the server owns, in its folder in your user data directory (`%LOCALAPPDATA%\4da-mcp`, `~/Library/Application Support/4da-mcp` or `~/.local/share/4da-mcp`; `FOURDA_MCP_HOME` moves it): `cache.db` (registry, OSV and changelog responses, in every mode; safe to delete, it costs refetches only) and `standalone.db` (without the desktop app: your project scan and the decisions, agent memory and feedback you record; no cache). Nothing is written inside your repository. (Until 6.3.0 standalone mode kept the cache inside `standalone.db`; that table is dropped the first time 6.3.0 opens it.)

When the 4DA desktop app is installed, the server reads the app's database (`4da.db`) through a **read-only** connection and never creates or alters anything in it: no tables, no columns, no cache. The only writes are rows in the four app-owned tables the tools exist to fill, so the app sees them: decisions (`decision_memory` -> `developer_decisions`), agent memory (`agent_memory`), and feedback (`record_feedback` -> `interactions` and `feedback`, which the app's calibration reads). Those go through a separate write connection that waits briefly for the app's lock. If your app version lacks the table or a column a record needs, the record goes to `standalone.db` instead and the response says so in `_meta`. (Before 6.1 the server also created a `live_cache` table inside the app's database; it now keeps that cache in `cache.db`.)

**Where configuration and the database come from:** `FOURDA_DB_PATH` if set (a relative path resolves against the server's working directory and must name an existing file; an absolute path that names no file is created as a new standalone database when its directory exists, and the first tool answer says so in `_meta.database_note`; otherwise it is refused with an error), else the desktop app's database in its data directory, else the server's own `standalone.db`. Embedding settings come from `FOURDA_SETTINGS_PATH`, else the `settings.json` beside `FOURDA_DB_PATH`, else the desktop app's data directory. Nothing is picked up from the directory the server is started in: until 6.2.5 a `data/settings.json` or `data/4da.db` inside (or beside) the working directory was adopted, so a cloned repository could redirect semantic recall to a host of its choosing or plant "decisions".

> The one exception: if you *explicitly* configure an OpenAI embedding provider (`FOURDA_EMBED_PROVIDER=openai`) for semantic recall, OpenAI receives exactly this, to be embedded: the text of the decisions and memories you stored (subject, decision or content, rationale, rejected alternatives), and the text being searched for: a `what_should_i_know` task, an `agent_memory` recall query, or a `check_decision_alignment` technology and pattern. Never the file paths you pass in `files` (they rank results locally), never source code. The default — no embedding provider, or a local Ollama one — keeps everything on your machine, and `FOURDA_OFFLINE=true` overrides it regardless.

**Ecosystems supported:** npm, crates.io (Rust), PyPI (Python), Go; `vulnerability_scan` also reads RubyGems (`Gemfile.lock`) and Packagist (`composer.lock`). Maven, Gradle and .NET are not read, and are listed as not covered. `upgrade_impact` reads npm, crates.io, PyPI and Go. PyPI: versions and dates from the PyPI JSON API, the changelog from the release's sdist, and import sites matched on the module the distribution installs: read from your virtualenv's metadata (`.venv`, `venv`, `env`: `top_level.txt` or `RECORD`), else a table of well-known differences (`PyYAML` -> `yaml`, `Pillow` -> `PIL`), else the distribution name, which the answer then labels an assumption. Go: versions and dates from proxy.golang.org, the changelog from the module zip, and a major version 2+ reported as the module path change it is (`github.com/jackc/pgx/v4` -> `/v5`), with the files that import the old path. `dependency_check` reads all four too; on PyPI and Go, where the registry exposes no publisher identity or install hooks, those signals say "not applicable".

**Known limits, stated plainly:** a `requirements.txt` without a lockfile names only your direct pins, so their transitive dependencies are not scanned (use `uv lock`, `poetry lock` or `pip-compile`). Many packages ship no changelog in their registry archive (fastembed, vite, zod among them); `upgrade_impact` then says so and gives the release-notes URL instead of guessing. Breaking entries are flagged from the changelog's headings and wording, and every entry carries the heading it sits under (`under`). Measured on a panel of 40 real upgrades across npm, crates.io, PyPI and Go (1,618 entries, gold from three blind raters with verbatim evidence; the panel and the measurement are in the test suite): on the 20 upgrades held out from rule-making, 95% of entries flagged breaking were breaking (95% CI 89-98%) and about 72% of breaking entries were flagged; Go release notes written as prose are the weakest (about 54% recall). Treat the flags as a pre-sort: read every entry of a major upgrade. Each answer says this in `_meta.classification`.

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

## All 16 Tools

### Dependency Security

| Tool | What it does |
|------|-------------|
| `upgrade_impact` | What changes between the installed and a target version of one dependency (npm, crates.io, PyPI, Go): releases in between, changelog entries classified breaking / deprecation / security, the breaking ones that touch your code (symbols you import, and route or pattern syntax in your string literals, e.g. axum 0.8's `/:id` -> `/{id}`), the files that import it, advisories fixed. |
| `vulnerability_scan` | Every installed copy in every lockfile matched against OSV.dev. Scope-adjusted severity, an upgrade target checked against every advisory of the package (the highest per-advisory fix can itself be affected by another), where each version is pinned, and a `coverage` block whenever the scan is partial. Concise by default (one row per vulnerable package version, the 40 most severe, about 4k tokens on a 290-advisory project); `package` for one dependency; `response_format: "detailed"` for every advisory. |
| `dependency_health` | Version freshness, deprecation (of the version you run) and vulnerability counts per dependency. |
| `upgrade_planner` | The smallest version no advisory affects for each vulnerable package, majors flagged (a 0.x minor counts as a major). Direct steps (`upgrade_direct`) carry `upgradeCommands`, the command per declaring project directory, keeping how the dependency is declared (`npm install x@v --save-exact` for an exact pin, `npm install "x@^v"`, `pnpm up`, `yarn upgrade` / `yarn up`, `cargo add` with `--dev` / `--build` / `--target` / `--rename`, `go get`; none for a `>=` / `||` / tag / git spec or a yarn workspace member), and a direct target is raised when a slightly newer release also clears a vulnerable transitive it pins. Transitive fixes: `lockfile_refresh` with the exact command (`npm update`, `pnpm update`, `yarn up -R`, `cargo update -p ... --precise`) when every parent's declared requirement already admits a clean version; `upgrade_parent` when a parent pins it but a newer release of that parent admits one, with `parentUpgrades` naming the smallest such release that is itself clear of the parent's advisories (read from the registry), the declared dependencies to bump (`levers`, with their commands; none when the lockfile cannot tie the parent to a declaration) and, when the new requirement still admits the installed copy, the refresh to run after the install (`refreshCommands`); `override_or_replace` with the override syntax (npm `overrides`, pnpm `pnpm.overrides`, yarn `resolutions`, Cargo `[patch]`) when the parent will not move (deprecated, already its latest release, or no release admits a clean version); `waiting_on_upstream` when the parent's releases could not be read, and for a copy bundled inside its owner's package, which only a new owner release (or replacing the owner) can move. Dev-only packages are included and labelled `isDev`, as in `vulnerability_scan`. For one project: `project_path` (default: the project the server was started in; `"*"` for every project the desktop app tracks). `package` for a one-package plan. |
| `dependency_check` | Call before writing any dependency version into a manifest: adding, pinning, upgrading, bumping, downgrading. `to` is the exact version, or the constraint you were given (`"7.x"`, `"^1.20"`, `"~=3.1"`, `"v1"`): then `safe` names the smallest and newest release in it that no known advisory affects, and the verdict is for the one it picks. The answer is concise by default (verdict, a reason carrying the evidence of every avoid / review / unknown / wait finding, `safe`, advisory ids and any registry quotes: about 10 KB for 25 items); `response_format: "detailed"` adds every signal with its evidence, `to_read_as` and the full `range_check`. An exact version an advisory affects gets the safe releases on its line. Verdict per item (`proceed` / `wait` / `review` / `avoid` / `unknown`) with evidence: advisories on the target, release age (holds releases under 3 days unless they fix an advisory you have), publish-trust drop, new install scripts, brand-new transitive dependencies, yanked or deprecated, and a breaking version range (a major, or a 0.x minor) is `review` with a pointer to `upgrade_impact`. A name that is malware itself is `avoid`; a new npm dependency one or two edits from a popular package (`expres`) is `review` with "did you mean" unless its downloads and age show it is established. `to_read_as` (in every answer to a constraint or "latest", and in the detailed form) says how `to` was read: a bare PyPI `"3.1"` is the release 3.1.0, as pip reads `==3.1`, never the series. A prerelease is never named as the safe release unless you ask for one. A registry's own words (a deprecation message) are quoted in `quoted_from_registry`, capped, never inside `reason`. A private package is `unknown` and never looked up (see "Private packages are never sent"). npm, crates.io, PyPI and Go (publisher trust, install scripts and new transitive dependencies are npm/crates.io signals and say "not applicable" elsewhere). |

### Intelligence

| Tool | What it does |
|------|-------------|
| `what_should_i_know` | Pre-task briefing built from the task: the dependencies it names (and the families it names: "all tauri plugins" adds the project's tauri-*, tauri-plugin-* and @tauri-apps/* packages; for "latest", whether each is already on the newest major), their versions and confirmed vulnerabilities, majors crossed, your recorded decisions, and a delegation verdict only confirmed evidence can raise. A package the task adds ("add the X package", `npm install X`) is run through `dependency_check`: a name that is malware is `human_only`, a near-miss of a popular package or a name the registry does not have is `review_needed`. |
| `ecosystem_pulse` | Hacker News headlines that name your dependencies, then your languages (labelled as such). Fetched only when called. |
| `get_context` | Your tech stack, resolved dependency versions, interests, detected topics. |
| `get_relevant_content`* | Scored content feed that passed the desktop app's relevance judge. |
| `get_actionable_signals`* | Judge-accepted feed items the app classified (advisories, breaking changes), plus your live vulnerabilities. |
| `knowledge_gaps`* | Dependencies with judge-accepted advisories or releases you have not looked at. |
| `record_feedback`* | Save or dismiss items; recorded in the app's own feedback tables, which its calibration reads. |

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

> **[Download 4DA](https://github.com/4DA-Systems/4DA/releases/latest)** for the full experience.

## Transports

**stdio** (default) -- works with all MCP hosts:
```bash
npx @4da/mcp-server@6.2.7
```

**Streamable HTTP** -- for remote or multi-client setups:
```bash
npx @4da/mcp-server@6.2.7 --http --port 4840
```

The HTTP transport binds to `127.0.0.1` by default and applies a `Host`-header
DNS rebinding guard to every request. Exposing it beyond this machine requires
a shared secret:

```bash
MCP_AUTH_SECRET=<same value as the relay's JWT_SECRET> \
MCP_ALLOWED_HOSTS=mcp.internal \
  npx @4da/mcp-server@6.2.7 --http --host 0.0.0.0
```

Without `MCP_AUTH_SECRET` a non-loopback bind is refused at startup. With it,
every request must carry a Bearer token whose HMAC-SHA256 signature verifies
against that secret, and the token's role is enforced per tool (`viewer` is
read-only; `member` and `admin` may write). Put TLS in front of it.

**HTTP mode is single-tenant.** A token's `team_id` is verified but not used to
separate data: every authenticated client shares one database, one agent memory
and one set of decisions, and `project_path` lets any authenticated client scan
any directory on the host the server can read. Run one server per team (or per
trust boundary), and only behind clients you would give that access.

## CLI Reference

```
npx @4da/mcp-server@6.2.7              # Start server (stdio)
npx @4da/mcp-server@6.2.7 --http       # Start server (Streamable HTTP)
npx @4da/mcp-server@6.2.7 --setup      # Auto-configure your editors
npx @4da/mcp-server@6.2.7 --doctor     # Verify installation health
npx @4da/mcp-server@6.2.7 --version    # Print version
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `FOURDA_DB_PATH` | Path to 4DA's SQLite database. An existing file is used. A relative path (resolved against the working directory) that names no file is refused. An absolute path that names no file is created as a standalone database if its directory exists (one stderr line and `_meta.database_note` in the first tool answer say so), and refused if the directory does not exist. | The desktop app's database, else the server's own |
| `FOURDA_SETTINGS_PATH` | `settings.json` holding the optional `embedding` block for semantic recall | Beside `FOURDA_DB_PATH`, else the desktop app's data directory |
| `FOURDA_OFFLINE` | Disable all network calls | `false` |
| `FOURDA_PRIVATE_PACKAGES` | Package names never sent anywhere, in addition to what `.npmrc`, `GOPRIVATE` and your lockfiles already mark private: globs, `*` matching anything, optionally `npm:` / `crates.io:` / `PyPI:` / `Go:` prefixed. See "Private packages are never sent". | Unset |
| `FOURDA_CALL_BUDGET_MS` | The time one tool call may take, counted from the request. A call still running then is answered NOT CHECKED (`dependency_check`: every item `unknown`); its lookups run on and are cached, so the same call made again answers from them. | `20000` |
| `FOURDA_WALK_BUDGET_MS` | The time the startup walk of the project tree may take. Past it the scan is partial and says so. | `10000` |
| `HTTPS_PROXY`, `HTTP_PROXY`, `NO_PROXY` | Used on Node 24.14+; on Node 22.21+ only when the server is started with `NODE_USE_ENV_PROXY=1`. See "Behind a proxy". | Unset |
| `FOURDA_GITHUB_CHANGELOG` | `upgrade_impact`: read GitHub release notes when the registry archive has no changelog for the range (`true` / `1` / `yes` / `on`) | Off |
| `GITHUB_TOKEN` | Used only with `FOURDA_GITHUB_CHANGELOG`: raises GitHub's rate limit from 60 to 5,000 requests an hour | Unset |
| `FOURDA_MCP_HOME` | Folder for the files the server writes (`cache.db`, `standalone.db`) | Your user data folder + `4da-mcp` |
| `MCP_AUTH_SECRET` | Shared secret for verifying Bearer tokens on `--http` (HMAC-SHA256). Falls back to `JWT_SECRET`. Unset means no token is accepted. | Unset |
| `MCP_AUTH_REQUIRED` | Require auth on a **loopback** `--http` bind. Always required on a non-loopback bind. | `false` |
| `MCP_ALLOWED_HOSTS` | Extra comma-separated hostnames accepted in `Host`/`Origin` (needed when binding to `0.0.0.0`). | localhost only |

## Limits

The server reads repositories it did not write, so everything it reads is bounded, and a bound that is hit is reported, never passed off as a clean result.

- **Time.** A tool call has 20 s (`FOURDA_CALL_BUDGET_MS`); the walk that finds a project's lockfiles has 10 s (`FOURDA_WALK_BUDGET_MS`), 20,000 directories, 4 levels and 256 projects. Past a walk bound the answer is a partial scan (`coverage.complete: false`).
- **Size.** A lockfile or manifest over 64 MB is not read and is reported as UNREADABLE. A `.gitignore` over 1 MB, its rules past 5,000, and a pattern over 1,024 characters are not applied; a negation that cannot be applied re-includes everything below its file, so a limit can only make the scan cover more.
- **Arguments.** A version or constraint is at most 256 characters, a package name 512.
- **Place.** A drive or filesystem root and the operating system's own directories (`C:\Windows` and below, `/usr`, `/etc`, `/System` and the like) are not scanned: pass `project_path` with your project's root, or set `FOURDA_PROJECT_DIR`.

## Behind a proxy

Every lookup uses Node's own `fetch`, and no proxy library is bundled, so whether `HTTPS_PROXY` / `HTTP_PROXY` / `NO_PROXY` are used depends on the Node that runs the server:

- **Node 24.14 or later:** used, nothing else to set.
- **Node 22.21 or later:** used when Node itself is started with them, which takes `NODE_USE_ENV_PROXY=1` in the server's environment (the `env` block of the MCP server entry).
- **Older Node:** not supported; lookups go direct and, where the proxy is required, every answer is NOT CHECKED.

The first lines of the server's stderr, and `npx @4da/mcp-server@6.2.7 --doctor`, say which case applies whenever a proxy variable is set.

## FAQ

**Does this send my code anywhere?**
No. When a tool needs them (never at startup), the server sends public package names and versions to public APIs ([OSV.dev](https://osv.dev), npm registry, crates.io, PyPI, Go proxy), never a private package's name, downloads the target version's archive from the package's own registry for `upgrade_impact` (and reads GitHub release notes only if you set `FOURDA_GITHUB_CHANGELOG=true`), and, only when you call `ecosystem_pulse`, sends a few dependency names as search terms to [HN Algolia](https://hn.algolia.com/api). No source code, no file paths, no personal data: the call-site scan runs locally. Set `FOURDA_OFFLINE=true` to disable all network calls. (The sole exception is opt-in OpenAI embeddings — see the network note above.)

**How does this compare with GitHub's dependency tool for agents?**
GitHub's hosted MCP server has `check_dependency_vulnerabilities` (dependabot toolset). It needs a GitHub token and reports high and critical advisories and malware. On 216 identical cases (2026-11-11, ground truth from OSV.dev) it was faster (median 1.2 s against 2.5 s for this server's 6.2.7) and covers Maven and .NET, which this server does not read; it missed 102 of 178 known-bad versions, mostly medium and low advisories and RustSec / PyPA / Go-only records, which this server reports, and it does not judge nonexistent, yanked, deprecated or days-old releases. This server needs no account and runs on your machine.

**Do I need the 4DA desktop app?**
No. 11 tools work standalone: upgrade impact, pre-install dependency checks, vulnerability scanning, dependency health, upgrade planning, ecosystem news, pre-task briefings, project context, decision memory, alignment checking, and agent memory. The desktop app is where the same engine runs day to day: one worklist across every project on the machine, a morning Brief of what changed in your stack, and an Upgrade Plan. With it installed, your agent also gets 5 more tools: signals, knowledge gaps, developer news judged against your stack, Developer DNA and feedback.

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
