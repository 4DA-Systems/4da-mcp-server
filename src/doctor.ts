// SPDX-License-Identifier: Apache-2.0
/**
 * 4DA MCP Doctor — Installation health checker
 *
 * Validates that the MCP server can run correctly:
 * 1. Node.js version is sufficient
 * 2. A SQLite driver opens a database (node:sqlite, else better-sqlite3)
 * 3. Database is found and readable
 * 4. LLM providers are configured (optional)
 * 5. OSV.dev and the registries answer, through the configured proxy
 *
 * Usage:
 *   npx @4da/mcp-server --doctor
 *   4da-mcp --doctor
 */

import { existsSync } from "node:fs";
import { explicitDbPathProblem, FourDADatabase } from "./db.js";
import { NODE_SQLITE_MIN, sqliteDriverStatus } from "./sqlite-driver.js";
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
        : `better-sqlite3 opened an in-memory database (${passedOver || `node:sqlite needs Node ${NODE_SQLITE_MIN}+`})`,
  });

  // 3. Database discovery — deep integrity_check is appropriate here: --doctor is
  // an explicit, user-invoked diagnostic where a slow full scan is expected. The
  // startup path uses the cheap default to keep the MCP handshake responsive.
  const validation = FourDADatabase.validateDatabase(undefined, { deep: true });
  if (validation.valid) {
    checks.push({
      name: "4DA database",
      status: "pass",
      detail: `Found with ${validation.tables?.length ?? 0} tables`,
    });
  } else if (validation.standalone) {
    checks.push({
      name: "4DA database",
      status: "pass",
      detail: "No existing database — standalone mode will create one (scans your project)",
    });
  } else {
    checks.push({
      name: "4DA database",
      status: "warn",
      detail: validation.error ?? "Database not found",
    });
  }

  // 4. Environment variables
  const envDb = process.env.FOURDA_DB_PATH;
  if (envDb) {
    const envExists = existsSync(envDb);
    const problem = explicitDbPathProblem();
    checks.push({
      name: "FOURDA_DB_PATH",
      status: envExists ? "pass" : problem ? "fail" : "warn",
      detail: envExists
        ? envDb
        : problem ?? `Set to ${envDb}, which does not exist yet: the server creates a new standalone database there on first use.`,
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

  // If database has issues (not standalone — standalone is fine), show guidance
  const dbCheck = checks.find((c) => c.name === "4DA database");
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
