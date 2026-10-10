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

The server uses Node's built-in `node:sqlite` (Node 22.13 and later), so it needs no install script and works with npm 12's default of blocking them. On Node 22.0-22.12 it uses the optional `better-sqlite3`, whose native module npm 10 and 11 build on install. `npx @4da/mcp-server --doctor` shows which one is in use.

```bash
claude mcp add 4da -- npx @4da/mcp-server
```

**As a Claude Code plugin** (the MCP server plus a hook):

```bash
claude plugin marketplace add 4DA-Systems/4da-mcp-server
claude plugin install 4da@4da
```

The hook: when your agent edits a dependency's version in `package.json`, `Cargo.toml`, `pyproject.toml`, `requirements.txt` or `go.mod`, it is told which packages moved and given the exact `dependency_check` and `upgrade_impact` calls to make before it installs and builds. The hook is plain Node, contacts nothing, and stays silent for every other edit.

<details>
<summary><b>Cursor / Windsurf / Devin Desktop</b></summary>

Add to `~/.cursor/mcp.json` (Cursor), `~/.codeium/windsurf/mcp_config.json` (Windsurf), or `~/.config/devin/mcp_config.json` (Devin Desktop and Devin CLI; `%APPDATA%devinmcp_config.json` on Windows):
```json
{
  "mcpServers": {
    "4da": {
      "command": "npx",
      "args": ["@4da/mcp-server"]
    }
  }
}
```
</details>

<details>
<summary><b>VS Code (Copilot)</b></summary>

Run **MCP: Open User Configuration** and add the entry, or edit the file directly: `%APPDATA%CodeUsermcp.json` (Windows), `~/Library/Application Support/Code/User/mcp.json` (macOS), `~/.config/Code/User/mcp.json` (Linux). VS Code uses `servers`, not `mcpServers`:
```json
{
  "servers": {
    "4da": {
      "type": "stdio",
      "command": "npx",
      "args": ["@4da/mcp-server"]
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
      "args": ["@4da/mcp-server"]
    }
  }
}
```
</details>

<details>
<summary><b>Auto-setup</b> (detects all installed editors)</summary>

```bash
npx @4da/mcp-server --setup --dry-run   # show each file and entry, write nothing
npx @4da/mcp-server --setup
```

Writes Cursor, VS Code (and Insiders), Windsurf, Devin Desktop and Claude Desktop configs it finds, merging into what is there: other servers, settings and comments are kept, a backup (`.bak`) is written first, and a file it cannot parse is left untouched with the entry to add by hand. For Claude Code it prints the `claude mcp add` command instead of editing `~/.claude.json`.
</details>

Then ask your AI: **"What changes if I upgrade X to Y?"**, **"Scan for vulnerabilities"** or **"What should I upgrade first?"**

## How It Works

The server reads every lockfile of the project it is started in, including independently-locked projects below the root (a repo with `src-tauri/Cargo.lock` beside a root `pnpm-lock.yaml` is scanned whole) and skipping what `.gitignore` excludes: `package-lock.json` / `npm-shrinkwrap.json`, `pnpm-lock.yaml` (v5–v9), `yarn.lock` (v1 and berry), `bun.lock`, `Cargo.lock` (Cargo workspaces included), `poetry.lock`, `uv.lock`, `pdm.lock`, `Pipfile.lock`, requirements pins (`*requirements*.txt`, `requirements/*.txt`, with `-r` and `-c`), and `go.mod` / `go.sum` (Go's build list). Every Python source in a folder is read, not only the first. Every installed copy is scanned, not one version per name, with the lockfile's own dev flags. It re-reads them whenever a lockfile changes, and for npm it also checks what `node_modules` actually holds. The walk goes 4 levels down and up to 256 projects; whatever it leaves out, and every manifest with no lockfile (its declared ranges are not installs and are not scanned), is listed in the answer's `coverage` block, never dropped silently.

Measured against osv-scanner on 19 public repositories (npm, pnpm v5-v9, yarn v1 and berry, bun, Cargo, Poetry, uv, Pipfile, requirements, Go; 2026-10-10), every difference settled by OSV's own API: precision 1.00 over 19,115 findings, recall 19,115 of 19,116 on the lockfiles it reads (Maven/Gradle are not read). Newly read requirement files were also checked against pip-audit.

- **OSV.dev** for known vulnerabilities, matched to exact installed versions
- **npm registry, crates.io, PyPI, Go module proxy** for versions, deprecations and yanks
- **The package's own registry archive** (registry.npmjs.org, static.crates.io) for the changelog `upgrade_impact` reads; never GitHub
- **npm full packument** and the **crates.io versions API** for `dependency_check` (publish times, publishers, install scripts, per-version dependencies). These requests carry the package name only; the version you have installed is never sent to a registry. Packuments are cached on disk and revalidated with `If-None-Match`; crates.io API reads are spaced one per second.
- **Hacker News Algolia API**, only when you call `ecosystem_pulse`

Results are cached (24h for registry data, 1h for vulnerabilities, 30min for news) and rate-limited per source.

**What's sent over the network:** package names and versions (the same data visible in your lockfile), and, only for `ecosystem_pulse`, the names of a few of your dependencies as search terms. No source code, no file paths, no personal data. The call-site scan of `upgrade_impact` runs locally. Set `FOURDA_OFFLINE=true` to disable all network calls.

**What's written to disk, and where:** only files the server owns, in its folder in your user data directory (`%LOCALAPPDATA%\4da-mcp`, `~/Library/Application Support/4da-mcp` or `~/.local/share/4da-mcp`; `FOURDA_MCP_HOME` moves it): `cache.db` (registry, OSV and changelog responses; safe to delete) and `standalone.db` (without the desktop app: your project scan and the decisions, agent memory and feedback you record). Nothing is written inside your repository.

When the 4DA desktop app is installed, the server reads the app's database (`4da.db`) through a **read-only** connection and never creates or alters anything in it: no tables, no columns, no cache. The only writes are rows in the four app-owned tables the tools exist to fill, so the app sees them: decisions (`decision_memory` -> `developer_decisions`), agent memory (`agent_memory`), and feedback (`record_feedback` -> `interactions` and `feedback`, which the app's calibration reads). Those go through a separate write connection that waits briefly for the app's lock. If your app version lacks the table or a column a record needs, the record goes to `standalone.db` instead and the response says so in `_meta`. (Before 6.1 the server also created a `live_cache` table inside the app's database; it now keeps that cache in `cache.db`.)

> The one exception: if you *explicitly* configure an OpenAI embedding provider (`FOURDA_EMBED_PROVIDER=openai`) for semantic recall, the decision/memory text you store is sent to OpenAI to be embedded. The default — no embedding provider, or a local Ollama one — keeps everything on your machine, and `FOURDA_OFFLINE=true` overrides it regardless.

**Ecosystems supported:** npm, crates.io (Rust), PyPI (Python), Go. `upgrade_impact`: npm and crates.io.

**Known limits, stated plainly:** a `requirements.txt` without a lockfile names only your direct pins, so their transitive dependencies are not scanned (use `uv lock`, `poetry lock` or `pip-compile`). Many packages ship no changelog in their registry archive (fastembed, vite, zod among them); `upgrade_impact` then says so and gives the release-notes URL instead of guessing. Breaking entries are flagged from the changelog's headings and wording, and every entry carries the heading it sits under (`under`). Measured on 47 upgrades never used to build the rules, against three blind raters who saw each entry's heading: 99% of entries flagged breaking were breaking (95% CI 95-100%) and about 65% of breaking entries were flagged. Earlier corpora, before the last parser fixes, measured 73-87%, so treat the flags as a pre-sort: read every entry of a major upgrade. Each answer says this in `_meta.classification`.

## What You Can Ask

```
"What changes if I upgrade axum to 0.8?"      -> upgrade_impact
"Check my dependency health"                  -> dependency_health
"Scan for vulnerabilities"                    -> vulnerability_scan
"Which deps should I upgrade first?"          -> upgrade_planner
"Is it safe to bump axios to 1.14.1?"         -> dependency_check
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
| `upgrade_impact` | What changes between the installed and a target version of one dependency: releases in between, changelog entries classified breaking / deprecation / security, the breaking ones that touch your code (symbols you import, and route or pattern syntax in your string literals, e.g. axum 0.8's `/:id` -> `/{id}`), the files that import it, advisories fixed. |
| `vulnerability_scan` | Every installed copy in every lockfile matched against OSV.dev. Scope-adjusted severity, an upgrade target checked against every advisory of the package (the highest per-advisory fix can itself be affected by another), where each version is pinned, and a `coverage` block whenever the scan is partial. Concise by default (one row per vulnerable package version, the 40 most severe, about 4k tokens on a 290-advisory project); `package` for one dependency; `response_format: "detailed"` for every advisory. |
| `dependency_health` | Version freshness, deprecation (of the version you run) and vulnerability counts per dependency. |
| `upgrade_planner` | The smallest version no advisory affects for each vulnerable package, majors flagged (a 0.x minor counts as a major). Transitive fixes: `lockfile_refresh` with the exact command (`npm update`, `pnpm update`, `yarn up -R`, `cargo update -p ... --precise`) when every parent's declared requirement already admits a clean version, else `waiting_on_upstream` naming the requirement that blocks it. For one project: `project_path` (default: the project the server was started in; `"*"` for every project the desktop app tracks). `package` for a one-package plan. |
| `dependency_check` | Call before adding a dependency or applying a bump. Verdict per item (`proceed` / `wait` / `review` / `avoid` / `unknown`) with evidence: advisories on the target, release age (holds releases under 3 days unless they fix an advisory you have), publish-trust drop, new install scripts, brand-new transitive dependencies, yanked or deprecated, and a breaking version range (a major, or a 0.x minor) is `review` with a pointer to `upgrade_impact`. npm and crates.io. |

### Intelligence

| Tool | What it does |
|------|-------------|
| `what_should_i_know` | Pre-task briefing built from the task: the dependencies it names (and the families it names: "all tauri plugins" adds the project's tauri-*, tauri-plugin-* and @tauri-apps/* packages; for "latest", whether each is already on the newest major), their versions and confirmed vulnerabilities, majors crossed, your recorded decisions, and a delegation verdict only confirmed evidence can raise. |
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
| Scored content feed (20+ sources) | -- | Yes |
| Actionable signals + knowledge gaps | -- | Yes |
| The analysis layer (Signal Chains, Knowledge Gaps, temporal analysis) | -- | Yes |

> **[Download 4DA](https://github.com/4DA-Systems/4DA/releases/latest)** for the full experience.

## Transports

**stdio** (default) -- works with all MCP hosts:
```bash
npx @4da/mcp-server
```

**Streamable HTTP** -- for remote or multi-client setups:
```bash
npx @4da/mcp-server --http --port 4840
```

The HTTP transport binds to `127.0.0.1` by default and applies a `Host`-header
DNS rebinding guard to every request. Exposing it beyond this machine requires
a shared secret:

```bash
MCP_AUTH_SECRET=<same value as the relay's JWT_SECRET> \
MCP_ALLOWED_HOSTS=mcp.internal \
  npx @4da/mcp-server --http --host 0.0.0.0
```

Without `MCP_AUTH_SECRET` a non-loopback bind is refused at startup. With it,
every request must carry a Bearer token whose HMAC-SHA256 signature verifies
against that secret, and the token's role is enforced per tool (`viewer` is
read-only; `member` and `admin` may write). Put TLS in front of it.

## CLI Reference

```
npx @4da/mcp-server              # Start server (stdio)
npx @4da/mcp-server --http       # Start server (Streamable HTTP)
npx @4da/mcp-server --setup      # Auto-configure your editors
npx @4da/mcp-server --doctor     # Verify installation health
npx @4da/mcp-server --version    # Print version
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `FOURDA_DB_PATH` | Path to 4DA's SQLite database | Auto-detected |
| `FOURDA_OFFLINE` | Disable all network calls | `false` |
| `FOURDA_MCP_HOME` | Folder for the files the server writes (`cache.db`, `standalone.db`) | Your user data folder + `4da-mcp` |
| `MCP_AUTH_SECRET` | Shared secret for verifying Bearer tokens on `--http` (HMAC-SHA256). Falls back to `JWT_SECRET`. Unset means no token is accepted. | Unset |
| `MCP_AUTH_REQUIRED` | Require auth on a **loopback** `--http` bind. Always required on a non-loopback bind. | `false` |
| `MCP_ALLOWED_HOSTS` | Extra comma-separated hostnames accepted in `Host`/`Origin` (needed when binding to `0.0.0.0`). | localhost only |

## FAQ

**Does this send my code anywhere?**
No. The server sends package names and versions to public APIs ([OSV.dev](https://osv.dev), npm registry, crates.io, PyPI, Go proxy), downloads the target version's archive from the package's own registry for `upgrade_impact`, and, only when you call `ecosystem_pulse`, sends a few dependency names as search terms to [HN Algolia](https://hn.algolia.com/api). No source code, no file paths, no personal data: the call-site scan runs locally. Set `FOURDA_OFFLINE=true` to disable all network calls. (The sole exception is opt-in OpenAI embeddings — see the network note above.)

**Do I need the 4DA desktop app?**
No. 11 tools work standalone: upgrade impact, pre-install dependency checks, vulnerability scanning, dependency health, upgrade planning, ecosystem news, pre-task briefings, project context, decision memory, alignment checking, and agent memory. The desktop app adds a scored content feed from 20+ sources, judged against your actual stack.

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
