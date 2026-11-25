// SPDX-License-Identifier: Apache-2.0
/**
 * 4DA MCP Doctor — Installation health checker
 *
 * Validates that the MCP server can run correctly:
 * 1. Node.js version is sufficient
 * 2. A SQLite driver opens a database (node:sqlite, else better-sqlite3)
 * 3. The data folder, the server's own database, the cache and the app's
 *    database, each named by its path with its state (dataFolderChecks)
 * 4. LLM providers are configured (optional)
 * 5. OSV.dev and the registries answer, through the configured proxy
 *
 * Usage:
 *   npx @4da/mcp-server --doctor
 *   4da-mcp --doctor
 */

import * as fs from "node:fs";
import * as path from "node:path";
import {
  desktopAppDbPaths,
  explicitDbPathProblem,
  FourDADatabase,
  getDefaultDbPath,
  isOwnStorePath,
  missingOwnTables,
  serverCacheDbPath,
  serverDataDir,
  standaloneDbPath,
} from "./db.js";
import { closeServerCacheDb, getServerCacheDb, serverCacheState } from "./live/cache.js";
import { openDatabase, sqliteDriverStatus } from "./sqlite-driver.js";
import { checkBuildStaleness } from "./build-staleness.js";
import { configureProxy } from "./proxy.js";
import { checkLookupReachability } from "./doctor-network.js";
import { pushAll } from "./array-utils.js";
import { embeddingEndpoint, getEmbeddingConfig, isLocalProvider, isOfflineMode, modelTag } from "./embeddings.js";
import { doctorUpdateCheck } from "./update-notice.js";

interface Check {
  name: string;
  status: "pass" | "warn" | "fail";
  detail: string;
}

/**
 * The semantic recall line: the provider the server will use (getEmbeddingConfig), never which
 * variables happen to be set. Off, it says why, and names a variable that is set but not read.
 */
export function semanticRecallCheck(): Check {
  const env = process.env;
  const name = "Semantic recall provider";
  const config = getEmbeddingConfig();
  if (config) {
    let host: string = config.provider;
    try {
      host = new URL(embeddingEndpoint(config)).host;
    } catch {
      // an Ollama URL that does not parse: named by provider
    }
    const where = isLocalProvider(config) ? "on this machine" : "not on this machine: text that names a private package is never sent to it";
    return { name, status: "pass", detail: `${modelTag(config)} at ${host} (${where})` };
  }
  const named = (env.FOURDA_EMBED_PROVIDER ?? "").trim();
  const why = isOfflineMode()
    ? "FOURDA_OFFLINE is set, so no provider is asked"
    : named.toLowerCase() === "openai" && !env.OPENAI_API_KEY
      ? "FOURDA_EMBED_PROVIDER=openai, but OPENAI_API_KEY is not set"
      : named && !["ollama", "openai"].includes(named.toLowerCase())
        ? `FOURDA_EMBED_PROVIDER=${named} is not a provider this server knows (ollama, openai)`
        : "no usable provider is configured (FOURDA_EMBED_PROVIDER, or the embedding block of settings.json; OpenAI needs an API key)";
  const unread = [
    ...(env.OPENAI_API_KEY && !named ? ["OPENAI_API_KEY alone does not turn it on (set FOURDA_EMBED_PROVIDER=openai)"] : []),
    ...["OLLAMA_HOST", "OLLAMA_BASE_URL"].filter((k) => env[k]).map((k) => `${k} is not read (set FOURDA_EMBED_PROVIDER=ollama and OLLAMA_URL)`),
  ];
  return { name, status: "warn", detail: `Off: ${why}. Keyword recall is used.${unread.length > 0 ? ` ${unread.join("; ")}.` : ""}` };
}

const message = (error: unknown) => (error instanceof Error ? error.message : String(error));

/**
 * The data folder and every database the tools use, each named by its path with its state. The
 * own store is opened the way a tool call opens it (which creates it, or completes a schema a
 * killed first start left half-made) and fails when it still cannot serve the tools: --doctor
 * never passes a store every tool would answer wrongly from. The cache is opened as a starting
 * server opens it. The app's database is only read.
 */
export function dataFolderChecks(): Check[] {
  const dir = path.resolve(serverDataDir());
  const existed = fs.existsSync(dir);
  const notFolder = existed && !fs.statSync(dir).isDirectory();
  // The database the tools use: FOURDA_DB_PATH, else the desktop app's, else the own store.
  const selected = getDefaultDbPath();
  const standaloneMode = isOwnStorePath(selected);
  // An app database is in use only when it is there, readable and the desktop app's own (not set up, or
  // this server's own format, and the server runs on its own store).
  const app = standaloneMode ? null : FourDADatabase.validateDatabase(selected);
  const appInUse = Boolean(app?.valid && !app.standalone);
  const rest = [ownStoreCheck(standaloneMode, appInUse), cacheCheck(), appDatabaseCheck(selected, standaloneMode)];
  const made = existed ? "" : fs.existsSync(dir) ? " (created by this check)" : " (created on first use)";
  const folder: Check = {
    name: "Data folder",
    status: notFolder ? "fail" : "pass",
    detail: notFolder ? `${dir} exists but is not a folder: the server cannot keep its files there` : `${dir}${made}`,
  };
  return [folder, ...rest];
}

function ownStoreCheck(standaloneMode: boolean, appInUse: boolean): Check {
  const name = "Own database";
  const own = standaloneDbPath();
  // Made only when the tools use it: in standalone mode, or beside the app's database for a record its schema cannot hold.
  if (!standaloneMode && !fs.existsSync(own)) {
    return { name, status: "pass", detail: `${own}: not created (the database in use is another; this one is made only for a record the app's schema cannot hold)` };
  }
  // What was there before the open completes it: said, so a repair is never silent.
  const before = emptyStoreState(own);
  let db: FourDADatabase | null = null;
  try {
    db = new FourDADatabase(own);
    const missing = missingOwnTables(db.getRawDb());
    if (missing.length > 0) {
      return {
        name,
        status: "fail",
        detail: `${own} has no ${missing.join(", ")} after the open, so the tools cannot use it. Move it aside (keep it if it holds decisions or agent memory you want); the next call creates a new one.`,
      };
    }
  } catch (error) {
    return { name, status: "fail", detail: `${own} cannot be opened: ${message(error)}` };
  } finally {
    db?.close();
  }
  // Deep integrity_check: --doctor is an explicit diagnostic where a slow full scan is expected.
  const deep = FourDADatabase.validateDatabase(own, { deep: true });
  if (!deep.valid) return { name, status: "fail", detail: `${own}: ${deep.error ?? "cannot be read"}` };
  // "Beside the app's database" only when one is in use; otherwise this is the database the tools use.
  const role = appInUse ? " (beside the app's database, for records its schema cannot hold)" : "";
  const ready = `${deep.tables?.length ?? 0} tables, ready${role}`;
  if (before) {
    return {
      name,
      status: "warn",
      detail:
        `${own} ${before} when this check started (a first start stopped while it created the file, or a file put there by hand); ` +
        `this check completed it in place, as a tool call would: ${ready}. Anything that file was meant to hold is not in it.`,
    };
  }
  return { name, status: "pass", detail: `${own}: ${ready}` };
}

/**
 * "was empty (0 bytes)" or "had no tables" for an existing own store with nothing in it; null
 * when it is missing (a first start creates it), has tables, or cannot be read (the open reports that).
 */
function emptyStoreState(file: string): string | null {
  let size: number;
  try {
    size = fs.statSync(file).size;
  } catch {
    return null;
  }
  if (size === 0) return "was empty (0 bytes)";
  let raw: ReturnType<typeof openDatabase> | null = null;
  try {
    raw = openDatabase(file, { readonly: true, fileMustExist: true });
    const row = raw.prepare("SELECT COUNT(*) AS c FROM sqlite_master WHERE type = 'table'").get() as { c: number | bigint } | undefined;
    return row && Number(row.c) === 0 ? "had no tables" : null;
  } catch {
    return null;
  } finally {
    raw?.close();
  }
}

function cacheCheck(): Check {
  const name = "Cache";
  const file = serverCacheDbPath();
  getServerCacheDb();
  const state = serverCacheState();
  closeServerCacheDb();
  if (!state) return { name, status: "warn", detail: `${file}: not opened (no SQLite driver); each session caches its lookups in memory` };
  if (state.kind === "disk") {
    const waited = state.attempts > 1 ? `; opened at attempt ${state.attempts}, another process held a lock` : "";
    return { name, status: "pass", detail: `${file} (on disk${waited})` };
  }
  return {
    name,
    status: "warn",
    detail:
      `${file} cannot be opened (${state.reason}): a server started now caches in memory for its session, so its ` +
      `lookups are not shared or kept, and an offline scan has no cached answers to fall back on`,
  };
}

function appDatabaseCheck(selected: string, standaloneMode: boolean): Check {
  const name = "App database";
  const configured = Boolean(process.env.FOURDA_DB_PATH?.trim());
  const problem = explicitDbPathProblem();
  if (problem) return { name, status: "fail", detail: problem };
  if (standaloneMode) {
    return {
      name,
      status: "pass",
      detail: configured
        ? `none attached (FOURDA_DB_PATH names this server's own database, ${selected})`
        : `none attached (no desktop app database at ${desktopAppDbPaths().join(", ")}); the tools use the server's own database`,
    };
  }
  // Read only, with the deep integrity_check (the startup path uses the cheap probe).
  const v = FourDADatabase.validateDatabase(selected, { deep: true });
  if (!v.valid) return { name, status: configured ? "fail" : "warn", detail: v.error ?? `${selected} cannot be read` };
  // An app database that is not set up (or another server's store) is not used: the server runs on
  // its own store, and the note says why (audit 2026-11-25, G-1).
  if (v.standalone && v.note) return { name, status: "warn", detail: v.note };
  if (v.standalone) {
    return { name, status: "pass", detail: `${selected}: a database of this server's own format, not the desktop app's (${v.tables?.length ?? 0} tables)` };
  }
  const leftover = v.tables?.includes("live_cache")
    ? " It holds a live_cache table an old version of this server (before 6.1) created there; nothing reads it now, and the server never removes anything from the app's database."
    : "";
  return { name, status: "pass", detail: `${selected}: ${v.tables?.length ?? 0} tables, read-only${leftover}` };
}

export async function runDoctor(): Promise<void> {
  console.log("\n  4DA MCP Server — Doctor\n");

  const checks: Check[] = [];

  // 1. Node.js version
  const nodeVersion = process.version;
  const major = parseInt(nodeVersion.slice(1).split(".")[0], 10);
  // 22, matching package.json engines: better-sqlite3 >= 12.10 ships no Node 20
  // prebuild, so a Node 20 install compiles from source and fails without a
  // C++ toolchain (measured 2026-10-03 on node:20-bookworm-slim and alpine).
  const nodeRequired = 22;
  checks.push({
    name: "Node.js version",
    status: major >= nodeRequired ? "pass" : "fail",
    detail: major >= nodeRequired
      ? `${nodeVersion} (>= ${nodeRequired} required)`
      : `${nodeVersion} — Node.js ${nodeRequired}+ required`,
  });

  // 2. SQLite driver — opening a database, not just importing a package:
  // better-sqlite3's import succeeds without its compiled module (npm 12
  // blocking its install script left none, and this check used to say "loaded").
  const sqlite = sqliteDriverStatus();
  const passedOver = sqlite.rejected.map((r) => `${r.name} not used: ${r.reason}`).join("; ");
  checks.push({
    name: "SQLite driver",
    status: sqlite.driver ? "pass" : "fail",
    detail: !sqlite.driver
      ? (sqlite.problem ?? "no SQLite driver")
      : sqlite.driver.name === "node:sqlite"
        ? `node:sqlite (built into Node ${process.versions.node}) opened an in-memory database`
        : `better-sqlite3 opened an in-memory database (${passedOver || "node:sqlite needs Node 22.13+ or 23.4+"})`,
  });

  // 3. The data folder and every database the tools use, by path. Opening them needs a driver.
  if (sqlite.driver) {
    pushAll(checks, dataFolderChecks());
  } else {
    checks.push({
      name: "Data folder",
      status: "warn",
      detail: `${serverDataDir()}: its databases (${standaloneDbPath()}, ${serverCacheDbPath()}) cannot be opened without a SQLite driver`,
    });
  }

  // 5. Build freshness — repo checkouts only. `.mcp.json` runs dist/, and
  // nothing rebuilds it on a merge; a stale dist served two-day-old behavior
  // on 2026-08-30 with zero symptoms. The published npm package ships no src/
  // (check returns null there) so users never see a false alarm.
  const staleness = checkBuildStaleness();
  if (staleness) {
    checks.push({
      name: "Server build freshness",
      status: staleness.stale ? "fail" : "pass",
      detail: staleness.stale
        ? staleness.note ?? "dist/ is older than src/ — rebuild"
        : "dist/ is at least as new as src/",
    });
  }

  // 6. Semantic recall provider (optional)
  checks.push(semanticRecallCheck());

  // Proxy: said only when a proxy is configured; a proxy this process does not use fails every lookup.
  const proxy = configureProxy();
  if (proxy.note) checks.push({ name: "Proxy", status: proxy.state === "invalid" ? "fail" : "pass", detail: proxy.note.replace(/^Proxy: /, "") });

  // 7. Lookups: OSV.dev and each registry asked once, through the proxy when one is set. A proxy
  // that parses but does not answer used to pass here (blind audit of e3aba98).
  pushAll(checks, await checkLookupReachability());

  // 8. A newer release than this one, as a server session last read it (update-notice.ts; asks nothing itself).
  const update = doctorUpdateCheck();
  if (update) checks.push(update);

  // Print results
  const icons = { pass: "\u2713", warn: "!", fail: "\u2717" };
  const colors = { pass: "\x1b[32m", warn: "\x1b[33m", fail: "\x1b[31m" };
  const reset = "\x1b[0m";

  for (const check of checks) {
    const icon = icons[check.status];
    const color = colors[check.status];
    console.log(`  ${color}${icon}${reset} ${check.name}: ${check.detail}`);
  }

  const failures = checks.filter((c) => c.status === "fail");
  const warnings = checks.filter((c) => c.status === "warn");

  console.log("");

  // If the app's database has issues (standalone is fine), show guidance
  const dbCheck = checks.find((c) => c.name === "App database");
  if (dbCheck && dbCheck.status === "warn") {
    console.log("  The MCP server can work standalone or with the 4DA desktop app.");
    console.log("  Standalone: scans your dependencies for known CVEs and provides project context.");
    console.log("  Full app: adds content scoring, source monitoring, and more.");
    console.log("");
    console.log("  Desktop app: https://github.com/4DA-Systems/4DA/releases/latest");
    console.log("  Learn more: https://4da.ai");
    console.log("");
  }

  if (failures.length > 0) {
    console.log(`  ${failures.length} issue(s) need attention.\n`);
    process.exit(1);
  } else if (warnings.length > 0) {
    console.log(`  All clear with ${warnings.length} optional warning(s).\n`);
  } else {
    console.log("  All checks passed.\n");
  }
}
