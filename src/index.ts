#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
/**
 * 4DA MCP Server
 *
 * Provides dependency-intelligence tools (CVE scanning, dependency health,
 * upgrade planning, ecosystem news, decision/agent memory) to Claude Code,
 * Claude Desktop, and other MCP hosts. Runs locally; the only data leaving the
 * machine is public package names/versions sent to registries (OSV, npm, etc.).
 *
 * SECURITY: stdio serving is unauthenticated by design — the MCP host launches
 * this process and already holds local process rights. The optional --http
 * transport defaults to 127.0.0.1 and applies a Host-header DNS rebinding
 * guard to every request. Binding it anywhere else requires a shared auth
 * secret (MCP_AUTH_SECRET) and then verifies an HMAC-SHA256-signed Bearer
 * token on every request, enforcing the token's role at tool dispatch.
 *
 * 16 tools across 5 categories, plus the `deps` prompt. Upgrade impact,
 * live vulnerability scanning (OSV.dev), pre-install dependency checks,
 * ecosystem news, persistent memory, and tech stack awareness for any MCP host.
 *
 * Categories (canonical — matches schema-registry.ts `ToolCategory`):
 *   Security (5)      — vulnerability scanning, dependency health, upgrade planning,
 *                       upgrade impact, dependency check
 *   Intelligence (7)  — briefing, ecosystem pulse, context, content feed,
 *                       actionable signals, knowledge gaps, feedback
 *   Decisions (2)     — decision memory, alignment checking
 *   Agent (1)         — cross-session persistent memory
 *   Identity (1)      — developer DNA profile
 *
 * Protocol: MCP TypeScript SDK v2. stdio serving goes through `serveStdio`,
 * HTTP through `createMcpHandler` — both entries negotiate the era per
 * connection/request, so 2025-era hosts (classic `initialize` handshake) and
 * 2026-07-28 hosts (stateless `server/discover`) are both supported.
 */
// First, before any other module runs: below Node.js 22 the process stops here with one line (node-gate.ts).
import "./node-gate.js";
import { screenJsonRpc, screenText, screenToolResult, screenWireText } from "./output-screen.js";
import { serveStdio, StdioServerTransport } from "@modelcontextprotocol/server/stdio";
import { StdioGate } from "./stdio-gate.js";
import { BRIEFING_FAILED } from "./tools/briefing-confirm.js";
import type { Server } from "@modelcontextprotocol/server";
import { FourDAServer, ownHandler } from "./mcp-server.js";
import { parseCliArgs } from "./cli-args.js";
import { installProcessGuards } from "./process-guards.js";
import { warnUnreadableEnvFlags } from "./env-flags.js";
import { readFileSync, statSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import { startHttpServer } from "./http-transport.js";
import { runSetup } from "./setup.js";
import { pinnedNpx, serverUsage } from "./usage.js";
import { runDoctor } from "./doctor.js";
import { exclusionNotes, scanProjectTree, treeResolutionGroups, type TreeDiscovery } from "./project-tree.js";
import { LiveIntelligence } from "./live/index.js";
import { setLiveIntelligence } from "./live-singleton.js";
import { SERVER_INSTRUCTIONS } from "./server-instructions.js";
import { validateToolArgs } from "./tool-args.js";

// Tool registry: listing, schema resources, category metadata
import {
  getSlimToolList,
  listResources,
  readResource,
  startupToolsLine,
  toolEntry,
  unknownPromptError,
  unknownToolError,
} from "./schema-registry.js";

// Map-based tool dispatch (replaces per-tool imports + switch statement)
import { DATABASE_FREE_TOOLS, dispatchTool } from "./tool-dispatch.js";
import { SqliteUnavailableError, sqliteDriverStatus } from "./sqlite-driver.js";
import { getPrompt, listPrompts } from "./prompts.js";
import { checkBuildStaleness } from "./build-staleness.js";
import { configureProxy } from "./proxy.js";
import { shutdown } from "./shutdown.js";
import { closeServerCacheDb } from "./live/cache.js";
import { lockfileCandidates } from "./live/lockfile-parsers.js";
import { mapEcosystem } from "./live/version-resolver.js";
import { callBudgetMs, secondsText, settleWithin } from "./call-budget.js";
import { ledgerWritesSettled, startLedger } from "./check-ledger.js";
import { systemDirectoryProblem } from "./tools/project-scope.js";
import { MAX_DEPTH, MAX_PROJECTS } from "./project-tree.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Single source of truth for the server version — read from package.json so
// serverInfo and --version can never drift from the published version again
// (drift shipped in 4.6.1: serverInfo reported 4.6.0).
const SERVER_VERSION: string = (() => {
  try {
    const pkg = JSON.parse(readFileSync(join(__dirname, "..", "package.json"), "utf8")) as { version?: string };
    return pkg.version ?? "0.0.0";
  } catch {
    return "0.0.0";
  }
})();

import {
  createDatabase,
  DatabaseUnavailableError,
  FourDADatabase,
  isUnreadableDbError,
  unreadableDbMessage,
  type DatabaseValidationResult,
} from "./db.js";

// =============================================================================
// Server Setup
// =============================================================================

/**
 * Project root for scanning/scoping. FOURDA_PROJECT_DIR overrides cwd for
 * hosts where cwd is meaningless (Claude Desktop launches extension servers
 * from an app directory) — the .mcpb bundle wires its directory picker to it.
 * A value still containing "${" is an unsubstituted host template; ignore it.
 */
function resolveProjectDir(): string {
  const dir = process.env.FOURDA_PROJECT_DIR?.trim();
  if (dir && !dir.includes("${")) return dir;
  return process.cwd();
}

// Database instance (lazy initialized)
let db: FourDADatabase | null = null;
let liveIntel: LiveIntelligence | null = null;

/**
 * Get or create database connection.
 * In standalone mode (no existing 4DA database), creates a minimal database
 * and populates it from the current working directory's project files.
 */
function getDatabase(): FourDADatabase {
  if (!db) finishInit(openInit());
  return db!;
}

/**
 * The database and live layer, opened but not yet given the project: the first of the two steps
 * of the init (pre-publish round 10, W9). Kept here until `finishInit` takes it, so the step is
 * never done twice.
 */
let opened: { db: FourDADatabase; live: LiveIntelligence } | null = null;

function openInit(): { db: FourDADatabase; live: LiveIntelligence } {
  if (!opened) {
    // No argument: the constructor resolves FOURDA_DB_PATH itself and applies
    // its rules (a relative path must exist). Passing the env value as an
    // explicit path bypassed them.
    const database = createDatabase();
    opened = { db: database, live: new LiveIntelligence(database.getRawDb()) };
  }
  return opened;
}

/** One turn of the event loop: a request read meanwhile (a `ping`) is answered before more init runs. */
function yieldToEventLoop(): Promise<void> {
  return new Promise((resolve) => setImmediate(resolve));
}

/**
 * The init, with the event loop given a turn before it and between its two steps (pre-publish
 * round 10, W9). The SDK runs a request's handler in a microtask, and the `ping` read with the
 * first `tools/call` queues behind it: with the whole init synchronous in that handler, the ping
 * waited for all of it (240 ms on a 41-dependency project, 2.6 s on a 150,000-entry
 * pnpm-lock.yaml). The work and its result are the same as `getDatabase`'s, which still finishes
 * it from either step when a caller needs it now.
 */
async function prepareDatabase(): Promise<void> {
  if (db) return;
  // One init in flight, shared by every caller that arrives while it runs.
  preparing ??= prepareInSteps().finally(() => {
    preparing = null;
  });
  return preparing;
}

let preparing: Promise<void> | null = null;

async function prepareInSteps(): Promise<void> {
  await yieldToEventLoop();
  if (db) return;
  const step = openInit();
  await yieldToEventLoop();
  if (db) return;
  const prepared = await resolveInSteps(step);
  if (!db) finishInit(step, prepared);
}

/** The project tree of an init, and whether the live layer already resolved it (resolveInSteps). */
interface PreparedTree {
  cwd: string;
  tree: ReturnType<typeof projectTreeFor>;
  resolved: boolean;
}

/**
 * The project tree, and its lockfiles resolved into `step.live` in steps
 * (initFromProjectTreeYielding), before the init is finished, with or without the app's database.
 * The resolution was one synchronous step of 2.3 s on a 150,000-entry pnpm-lock.yaml, and a `ping`
 * sent during the first tool call waited for all of it (pre-publish round 10, W11). A caller that
 * needs the database meanwhile (getDatabase) finishes the init synchronously; this one then stops
 * at its next pause and leaves the set to it (`db` is set, so prepareInSteps does not finish again).
 */
async function resolveInSteps(step: { db: FourDADatabase; live: LiveIntelligence }): Promise<PreparedTree | null> {
  const cwd = resolveProjectDir();
  const tree = projectTreeFor(cwd);
  if (tree.entries.length === 0) return { cwd, tree, resolved: false };
  const groups = treeResolutionGroups(tree.entries);
  loading = { projects: groups.length, bytes: lockfileBytes(groups) };
  const resolved = await step.live.initFromProjectTreeYielding(cwd, groups, tree.discovery);
  return { cwd, tree, resolved };
}

/** What the init in steps is reading, for the answer of a call whose budget ended first. */
let loading: { projects: number; bytes: number } | null = null;

/** The size of the lockfiles the groups resolve from (stat calls only). */
function lockfileBytes(groups: ReturnType<typeof treeResolutionGroups>): number {
  let bytes = 0;
  for (const file of new Set(groups.flatMap((g) => lockfileCandidates(g.dir, mapEcosystem(g.language))))) {
    try {
      bytes += statSync(file).size;
    } catch {
      // Not there.
    }
  }
  return bytes;
}

/** A call whose budget ended while the project's lockfiles were still being read (the init goes on). */
function stillReadingAnswer(): { content: Array<{ type: "text"; text: string }>; isError: true } {
  const what = loading ? ` (${Math.max(1, Math.round(loading.bytes / 1048576)).toLocaleString("en-US")} MB in ${loading.projects} project${loading.projects === 1 ? "" : "s"})` : "";
  const error =
    `NOT CHECKED: this project's lockfiles${what} were still being read when this call's ${secondsText(callBudgetMs())} ran out, ` +
    "so nothing was checked and nothing was stored. The server goes on reading them and answers pings meanwhile: call again in a minute for the full answer.";
  return { content: [{ type: "text", text: JSON.stringify({ error }) }], isError: true };
}

function finishInit(step: { db: FourDADatabase; live: LiveIntelligence }, prepared: PreparedTree | null = null): void {
  opened = null;
  db = step.db;

  // Initialize live intelligence layer
  liveIntel = step.live;
  setLiveIntelligence(liveIntel);

  // The dependency inventory is the project on disk, with or without the desktop app's database:
  // the root and every independently-locked project below it (project-tree.ts), and the walk's
  // record of what it left out, which every tool's coverage note is built from. The app's
  // `project_dependencies` rows are never the inventory: a sub-project it had not indexed vanished
  // from every answer with no note, and a scan with the app attached carried no coverage at all.
  // FOURDA_PROJECT_DIR overrides cwd for hosts where cwd is meaningless (Claude Desktop launches
  // extension servers from an app directory, not the user's code); the .mcpb bundle wires its
  // directory picker to it.
  const cwd = prepared?.cwd ?? resolveProjectDir();
  const { entries: tree, discovery } = prepared?.tree ?? projectTreeFor(cwd);
  if (tree.length === 0) {
    // A system directory: nothing is scanned (projectTreeFor). The tools say so and ask for project_path.
    liveIntel.initFromProjectTree(cwd, [], discovery);
    return;
  }
  const scan = tree[0].scan;
  // The standalone store keeps the project's stack for get_context. The app's database is the
  // user's own profile and is never written here.
  if (db.isStandalone) db.populateFromScan(scan);
  const groups = treeResolutionGroups(tree);

  const detected = [
    ...scan.languages,
    ...scan.frameworks,
  ].filter(Boolean);

  const mode = db.isStandalone ? "Standalone mode" : "4DA app database attached; dependencies are read from disk";
  console.error(`[4DA] ${mode}: scanned ${scan.projectPath} (${tree.length} project${tree.length === 1 ? "" : "s"})`);
  // Also with NO groups: the walk's report of what it found but does not read (pom.xml,
  // build.gradle, test-fixture lockfiles) is what every tool's coverage note is built from
  // (readiness audit H3). Already done, in steps, when the init came from a tool call (resolveInSteps).
  if (!prepared?.resolved) liveIntel.initFromProjectTree(cwd, groups, discovery);
  if (groups.length > 0) {
    console.error(
      `[4DA]   Detected: ${detected.join(", ") || "lockfiles"} | ${scan.dependencies.length} deps, ${scan.devDependencies.length} dev deps at the root`
    );

    if (liveIntel.isEnabled()) {
      // Nothing is sent at startup (audit 2026-11-11 A1 #7: `initialize` + `tools/list` alone
      // sent every dependency name to OSV.dev). The first tool that needs the scan starts it.
      console.error(`[4DA]   Live intelligence: enabled (OSV.dev); no lookup is made until a tool needs one.`);
    }
  } else {
    console.error(`[4DA]   ${noSupportedProjectNote(cwd, discovery)}`);
  }
}

/**
 * No SQLite driver is usable (Node < 22.13 and better-sqlite3's native module
 * unbuilt): the live layer alone, from a project scan and an in-memory cache,
 * so the dependency tools (DATABASE_FREE_TOOLS) still answer. Every other
 * tool returns the driver error, which says how to fix it.
 */
function initWithoutDatabase(why: string): void {
  if (liveIntel) return;
  liveIntel = new LiveIntelligence(null);
  setLiveIntelligence(liveIntel);
  const cwd = resolveProjectDir();
  const { entries, discovery } = projectTreeFor(cwd);
  const groups = treeResolutionGroups(entries);
  console.error(`[4DA] ${why}: the dependency tools run without a database (${cwd}).`);
  // Kept with no groups too: the coverage notes come from the walk (H3).
  liveIntel.initFromProjectTree(cwd, groups, discovery);
  if (groups.length === 0) {
    console.error(`[4DA]   ${noSupportedProjectNote(cwd, discovery)}`);
    return;
  }
}

/** The startup line for a directory with no lockfile this server reads: what it did find, never just "nothing". */
function noSupportedProjectNote(cwd: string, discovery: TreeDiscovery): string {
  const notes = exclusionNotes(discovery);
  return notes.length > 0
    ? `No lockfile of a supported ecosystem in ${cwd}. ${notes.join(" ")}`
    : `No project manifests found in ${cwd} — tools will return empty results`;
}

/**
 * The database for a tool call. Null only for a database-free tool when there is none to use: no
 * SQLite driver, or the selected database is unavailable (FOURDA_DB_PATH names no file, a file
 * with no tables, one that cannot be opened); `note` then says which, for the answer.
 */
function databaseFor(tool: string): { database: FourDADatabase | null; note: string | null } {
  try {
    return { database: getDatabase(), note: null };
  } catch (error) {
    const unavailable = error instanceof DatabaseUnavailableError ? error : null;
    if (!(unavailable || error instanceof SqliteUnavailableError) || !DATABASE_FREE_TOOLS.has(tool)) throw error;
    initWithoutDatabase(unavailable ? "The database is unavailable" : "No SQLite driver");
    return { database: null, note: unavailable?.note ?? null };
  }
}

/**
 * The project tree under `dir`, or nothing when `dir` is an operating-system directory. Hosts
 * start servers wherever they happen to be: `C:\Windows\System32`, `/`. Walking one read every
 * lockfile below it and sent each package to OSV.dev and the registries (audit 2026-11-11, M15:
 * 2,122 package pairs from System32). Nothing is scanned there; the tools say why and ask for
 * `project_path`.
 */
function projectTreeFor(dir: string): ReturnType<typeof scanProjectTree> {
  const refused = systemDirectoryProblem(dir);
  if (!refused) return scanProjectTree(dir);
  console.error(`[4DA] ${refused}`);
  return { entries: [], discovery: { projects: 0, maxDepth: MAX_DEPTH, maxProjects: MAX_PROJECTS, skipped: [], skippedCount: 0, walkTruncated: false } };
}

/** Standalone vs desktop-app database, decided once by the cheap probe (no scan, no resolution). */
let standaloneMode: boolean | null = null;

function isStandaloneMode(): boolean {
  if (db) return db.isStandalone;
  if (standaloneMode === null) {
    const probe = FourDADatabase.validateDatabase(process.env.FOURDA_DB_PATH || undefined);
    standaloneMode = probe.standalone === true;
  }
  return standaloneMode;
}

let backgroundInitScheduled = false;

/**
 * Start the full init (database, project scan, lockfile resolution, scan
 * warmup) after the current response has been written. It is synchronous
 * work, so it runs on a later tick; a tool call that arrives first simply
 * performs it itself, exactly as before.
 */
function scheduleBackgroundInit(): void {
  if (backgroundInitScheduled || db) return;
  backgroundInitScheduled = true;
  setTimeout(() => {
    // In steps, as a tool call's init is (prepareDatabase, pre-publish round 10, W9).
    prepareDatabase().catch((err: unknown) => {
      console.error(`[4DA] Background init failed (tools will retry on first call): ${err instanceof Error ? err.message : String(err)}`);
    });
  }, 50).unref?.();
}

// =============================================================================
// Server Factory
// =============================================================================

/**
 * Build a Server instance with every handler registered.
 *
 * The v2 serving entries take a factory: `serveStdio` pins one instance per
 * connection; stateless HTTP (`createMcpHandler`) builds one per request.
 * Handlers close over the module-level database singleton, so every instance
 * shares the same lazily-initialized database and live-intelligence layer.
 */
export function buildServer(): Server {
  // FourDAServer: params the SDK rejects are answered -32602, not -32603 (mcp-server.ts).
  const server = new FourDAServer(
    {
      name: "4da-server",
      version: SERVER_VERSION,
    },
    {
      // `listChanged` was advertised and never sent: the tool set is fixed for
      // the life of the process, so the honest capability is none.
      capabilities: {
        tools: {},
        resources: {},
        prompts: {},
      },
      instructions: SERVER_INSTRUCTIONS,
    }
  );

  // tools/list answers from a cheap mode probe, never from the full init. It
  // used to open the database AND resolve every lockfile synchronously first
  // (measured 6.6 s on a 2,063-dependency tree), stalling the host's handshake.
  // The full init is started right after the first listing is sent.
  server.setRequestHandler("tools/list", ownHandler(async () => {
    scheduleBackgroundInit();
    return {
      tools: getSlimToolList(isStandaloneMode() ? true : undefined),
    };
  }));

  // Resources: every tool's full schema (lazy loading), and the category
  // manifest. An unknown URI is a resource-not-found protocol error.
  // Filtered as tools/list is: standalone mode advertised the 5 desktop-only schemas (audit L6).
  server.setRequestHandler("resources/list", ownHandler(async () => ({ resources: listResources(isStandaloneMode() ? true : undefined) })));

  server.setRequestHandler("resources/read", ownHandler(async (request) => readResource(request.params.uri, isStandaloneMode() ? true : undefined)));

  // Prompts: user-invoked workflows (surfaced as slash commands by some hosts).
  server.setRequestHandler("prompts/list", ownHandler(async () => ({ prompts: listPrompts() })));

  server.setRequestHandler("prompts/get", ownHandler(async (request) => {
    const prompt = getPrompt(request.params.name, request.params.arguments);
    if (!prompt) throw unknownPromptError(request.params.name);
    return prompt;
  }));

  // Execute a tool
  server.setRequestHandler("tools/call", ownHandler(async (request) => {
    // The call's time budget counts from here: the first call of a session also pays for the project scan.
    const startedAt = Date.now();
    const { name, arguments: args } = request.params;

    // An unknown tool NAME is a JSON-RPC Invalid Params error (MCP spec), not
    // a tool result: it used to come back as `isError` content like a tool
    // that ran and failed.
    const entry = toolEntry(name);
    // Round 14, X1: the name is the caller's; an error names it by shape where it has a credential's.
    if (!entry) throw unknownToolError(screenText(name));

    // Arguments are checked against the published schema before anything
    // runs, so a wrong type or a misspelled parameter comes back as a
    // correctable error rather than a Node exception or a silent no-op.
    const problem = validateToolArgs(name, entry.definition.inputSchema, (args ?? {}) as Record<string, unknown>);
    if (problem) {
      return screenToolResult(name, {
        content: [{ type: "text" as const, text: JSON.stringify({ error: problem }) }],
        isError: true,
      });
    }

    try {
      // The first call's init gives the event loop a turn before and inside it (prepareDatabase),
      // so a ping sent with it is answered first (pre-publish round 10, W9). An error it meets is
      // met again, and answered, by databaseFor.
      // An init still running when the call's budget ends (20 lockfiles of 62 MB took over a minute,
      // audit 2026-11-25, F-M1) is not finished synchronously here: the call says so plainly and the
      // init goes on, so a later call gets the whole answer.
      const prepared = (async () => {
        await prepareDatabase().catch(() => undefined);
        return true;
      })();
      const ready = await settleWithin(prepared, startedAt + callBudgetMs() - Date.now(), () => false);
      if (!ready) return stillReadingAnswer();
      const { database, note: unavailableNote } = databaseFor(name);
      // A changed .npmrc, .yarnrc.yml, go env file or environment re-reads which names are private (stat calls only).
      liveIntel?.refreshPrivateRules();
      const result = await dispatchTool(name, database, args as Record<string, unknown> | undefined, { startedAt });
      const note = database?.takeCreationNote() ?? unavailableNote;
      // Round 14, X1: every result leaves through the output screen (output-screen.ts).
      return screenToolResult(name, note ? withDatabaseNote(result, note) : result);
    } catch (error) {
      // A database that turns out damaged mid-session (SQLITE_CORRUPT on a
      // page the open did not touch) gets the same guidance as one that
      // fails to open, instead of the bare SQLite text.
      const errorMessage =
        db && isUnreadableDbError(error)
          ? unreadableDbMessage(db.dbPath, error)
          : error instanceof Error
            ? error.message
            : String(error);
      return screenToolResult(name, {
        content: [
          {
            type: "text" as const,
            // One shape for every tool error: `{"error": "..."}`, compact, as the argument check writes it.
            // Round 18b: a briefing that failed is said to be no assessment, never read as a level.
            text: JSON.stringify({ error: name === "what_should_i_know" ? `${BRIEFING_FAILED} ${errorMessage}` : errorMessage }),
          },
        ],
        isError: true,
      });
    }
  }));

  return server;
}

/** Attach a one-time database note to a tool result, in `_meta.database_note` of both its forms. */
type ToolResult = Awaited<ReturnType<typeof dispatchTool>>;

function withDatabaseNote(result: ToolResult, note: string): ToolResult {
  const r = result as { content: Array<{ type: "text"; text: string }>; structuredContent?: Record<string, unknown> };
  if (r.structuredContent) {
    const payload = r.structuredContent;
    const structuredContent = { ...payload, _meta: { ...((payload._meta as Record<string, unknown> | undefined) ?? {}), database_note: note } };
    return { ...result, structuredContent, content: [{ type: "text" as const, text: JSON.stringify(structuredContent) }] } as ToolResult;
  }
  return { ...result, content: [...r.content, { type: "text" as const, text: JSON.stringify({ _meta: { database_note: note } }) }] } as ToolResult;
}

// =============================================================================
// Server Lifecycle
// =============================================================================

/**
 * Stop the server promptly: abort every lookup in flight, close the transport (`first`), the
 * database and the lookup cache, and exit 0 (shutdown.ts).
 */
function stopServer(reason: string, first?: () => Promise<void>): void {
  shutdown(reason, {
    close: [
      ...(first ? [first] : []),
      () => {
        if (db) db.close();
        db = null;
        // A database opened by an init that has not finished yet (prepareDatabase).
        opened?.db.close();
        opened = null;
      },
      () => closeServerCacheDb(),
      // A verdict already answered reaches the ledger the guard hook reads (check-ledger.ts).
      () => ledgerWritesSettled(),
    ],
    exit: (code) => process.exit(code),
    log: (line) => console.error(line),
  });
}

/** --help, and the text an unknown argument exits with (cli-args.ts): every command pinned to this version (usage.ts). */
const USAGE = serverUsage(SERVER_VERSION);

/**
 * Start the MCP server
 *
 * Supports three modes:
 *   (default)  stdio transport — serves 2025-era and 2026-07-28 hosts
 *   --http     Streamable HTTP transport — stateless, both eras
 *   --setup    Configure editors for 4DA MCP
 */
async function main() {
  const parsed = parseCliArgs(process.argv.slice(2));
  if (!parsed.ok) {
    console.error(`[4DA] ${parsed.error}`);
    console.error(USAGE);
    process.exit(2);
  }
  const command = parsed.command;

  // Say it before anything else: a stale dist answers with code the repo has
  // already replaced (the 2026-08-30 server was two days behind its src and
  // its already-fixed bugs were nearly re-diagnosed as live). stderr only —
  // stdout is the MCP protocol.
  try {
    const staleness = checkBuildStaleness();
    if (staleness?.stale && staleness.note) {
      console.error(`[4DA] WARNING: ${staleness.note}`);
    }
  } catch {
    // The self-check must never block startup.
  }

  if (command.kind === "version") {
    console.log(`@4da/mcp-server ${SERVER_VERSION}`);
    return;
  }

  if (command.kind === "help") {
    console.log(USAGE);
    return;
  }

  // Setup command: configure editors
  if (command.kind === "setup") {
    // Non-zero when a config that was found could not be written (setup.ts).
    process.exitCode = runSetup({ dryRun: command.dryRun, update: command.update }).exitCode;
    return;
  }

  // Doctor command: validate installation health
  if (command.kind === "doctor") {
    await runDoctor();
    return;
  }

  // A FOURDA_OFFLINE or MCP_AUTH_REQUIRED value that is not a yes or a no is said once (env-flags.ts).
  warnUnreadableEnvFlags();
  // An error no request handled is logged and the server keeps serving (process-guards.ts).
  installProcessGuards();

  // HTTPS_PROXY / HTTP_PROXY: every lookup goes through it (live/http-utils.ts); said here (proxy.ts).
  const proxy = configureProxy();
  if (proxy.note) console.error(`[4DA] ${proxy.note}`);

  // The guard hook denies only where a ledger exists (check-ledger.ts): this server keeps one.
  void startLedger();

  // HTTP transport mode
  if (command.kind === "http") {
    try {
      const http = await startHttpServer(buildServer, { port: command.port, host: command.host, handleSignals: false });
      // SIGINT / SIGTERM: stop accepting, abort every lookup, close the databases, exit (shutdown.ts).
      process.once("SIGINT", () => stopServer("received SIGINT", () => http.close()));
      process.once("SIGTERM", () => stopServer("received SIGTERM", () => http.close()));
    } catch (error) {
      // Bind-policy refusals carry an actionable message; print it plainly
      // rather than as an unhandled stack trace.
      console.error(`[4DA] ${error instanceof Error ? error.message : String(error)}`);
      process.exit(1);
    }
    return;
  }

  // -------------------------------------------------------------------------
  // Pre-flight: validate the database before accepting tool calls
  // -------------------------------------------------------------------------
  const dbPath = process.env.FOURDA_DB_PATH || undefined;
  const validation: DatabaseValidationResult = FourDADatabase.validateDatabase(dbPath);
  const sqlite = sqliteDriverStatus();
  if (!sqlite.driver) {
    console.error(`[4DA] ${sqlite.problem}`);
    console.error(`  Dependency tools (${[...DATABASE_FREE_TOOLS].join(", ")}) still run, without a database.`);
  }

  if (validation.valid && validation.standalone) {
    // The own store's schema is completed by the first open, whatever a killed or concurrent first start left.
    if (validation.note) console.error(`[4DA] ${validation.note}`);
    console.error(`[4DA] Standalone mode: the server's own database is ${validation.path}.`);
  } else if (validation.valid) {
    console.error(`[4DA] The 4DA app's database: ${validation.path} (${validation.tables?.length ?? 0} tables, read-only).`);
  } else if (validation.standalone) {
    // No existing DB — standalone mode will create one on first tool call
    console.error(`[4DA] No existing database found — standalone mode enabled.`);
    console.error(`  Will scan your project and create a local database on first tool call.`);
    console.error(`  For full features, install the 4DA desktop app: https://4da.ai`);
    console.error(``);
  } else {
    // Database exists but is corrupt or unreadable
    console.error(`[4DA] Database issue: ${validation.error}`);
    console.error(`  Or run: ${pinnedNpx(SERVER_VERSION)} --doctor  for diagnostics`);
    console.error(``);
  }

  // Default: stdio serving. `serveStdio` owns the era decision per connection —
  // a 2025-era `initialize` opening is served exactly as before; a 2026-07-28
  // `server/discover` opening gets the stateless modern protocol.
  // Parse errors and requests before initialize are answered here, per JSON-RPC and MCP (stdio-gate.ts).
  // A JSON-RPC batch is served on a 2025-03-26 connection and answered as one array (stdio-gate.ts).
  // Round 15, A2: every JSON-RPC message the server writes (any method's result or error) passes the output screen.
  const gate = new StdioGate((message) => {
    process.stdout.write(`${JSON.stringify(screenJsonRpc(message))}\n`);
  });
  const output = gate.output((text) => {
    process.stdout.write(screenWireText(text));
  });
  output.on("error", () => undefined);
  process.stdin.pipe(gate);
  serveStdio(buildServer, {
    transport: new StdioServerTransport(gate, output),
    onerror: (error) => {
      console.error(`[4DA] stdio serving error: ${error.message}`);
    },
  });

  // The host closing stdin is MCP's stdio shutdown: abort every lookup, close the databases, exit
  // (shutdown.ts). Until 6.3.0 the server worked on for up to a minute after it (blind audit of e3aba98).
  process.stdin.once("end", () => stopServer("stdin closed"));
  process.stdin.once("close", () => stopServer("stdin closed"));
  process.once("SIGINT", () => stopServer("received SIGINT"));
  process.once("SIGTERM", () => stopServer("received SIGTERM"));

  // What this start will serve: with the database refused, every call returns that error (audit L6).
  console.error(`4DA MCP Server v${SERVER_VERSION} started — ${startupToolsLine(validation, Boolean(sqlite.driver), DATABASE_FREE_TOOLS.size)}, stdio transport`);
  console.error("  Use --http for Streamable HTTP, --setup to configure editors, --doctor to check health");
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
