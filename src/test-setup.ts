// SPDX-License-Identifier: Apache-2.0
/**
 * Vitest setup: make config resolution HERMETIC.
 *
 * getEmbeddingConfig()/getLLMConfig() otherwise walk up to the operator's real
 * data/settings.json, so enabling a provider there would silently flip test
 * behaviour (e.g. agent_memory.recall going async). Point FOURDA_SETTINGS_PATH at
 * an empty settings file so tests depend only on the env they set themselves.
 * Tests that exercise the semantic path set FOURDA_EMBED_PROVIDER explicitly,
 * which takes precedence over the settings file.
 */
import { writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

// Fixed name, not per-pid: the content is always "{}", so concurrent runs overwrite each other
// harmlessly — and %TEMP% holds one file forever instead of one per test process (554 had accumulated).
const emptySettings = join(tmpdir(), "4da-test-empty-settings.json");
writeFileSync(emptySettings, "{}");
process.env.FOURDA_SETTINGS_PATH = emptySettings;

// Every file the server writes (cache.db, and standalone.db as the memory
// store beside the desktop app's read-only database) goes under FOURDA_MCP_HOME:
// a per-worker temp directory, never the operator's real data directory.
if (!process.env.FOURDA_MCP_HOME) {
  const { mkdtempSync, rmSync } = await import("node:fs");
  const { afterAll } = await import("vitest");
  const home = mkdtempSync(join(tmpdir(), "4da-mcp-home-"));
  process.env.FOURDA_MCP_HOME = home;
  afterAll(async () => {
    const { closeServerCacheDb } = await import("./live/cache.js");
    closeServerCacheDb();
    try {
      rmSync(home, { recursive: true, force: true });
    } catch {
      // A handle a test left open (Windows): the OS temp cleaner gets it.
    }
    delete process.env.FOURDA_MCP_HOME;
  });
}

// ---------------------------------------------------------------------------
// App-schema contract recording (scripts/app-schema-contract.mjs).
//
// With FOURDA_SQL_CORPUS set to a directory, every SQL statement that SERVER
// code (src/, not src/__tests__/) prepares during the run is appended there,
// with the function that issued it, and so is every hasColumn() probe. The
// contract script then re-prepares those statements against the desktop app's
// real schema. Off by default: plain `pnpm test` records nothing.
// ---------------------------------------------------------------------------
if (process.env.FOURDA_SQL_CORPUS) {
  const { appendFileSync, mkdirSync } = await import("node:fs");
  const { threadId } = await import("node:worker_threads");
  const corpusDir = process.env.FOURDA_SQL_CORPUS;
  mkdirSync(corpusDir, { recursive: true });
  const out = join(corpusDir, `corpus-${process.pid}-${threadId}.jsonl`);
  const seen = new Set<string>();
  const g = globalThis as { __fourdaCorpusPatched?: boolean };

  /**
   * The innermost stack frame in server code, or null when no server code is
   * on the stack (a test building its fixture tables). Test frames are passed
   * over rather than decisive, because a test may wrap `prepare` itself (the
   * app-schema contract test does) and its wrapper then sits between the
   * server call and this one.
   */
  const serverCallsite = (): { fn: string; file: string; line: string } | null => {
    const limit = Error.stackTraceLimit;
    Error.stackTraceLimit = 60;
    const stack = new Error().stack?.split("\n").slice(2) ?? [];
    Error.stackTraceLimit = limit;
    for (const line of stack) {
      const norm = line.replaceAll("\\", "/");
      if (!norm.includes("/src/") || norm.includes("/node_modules/") || norm.includes("/src/test-setup")) continue;
      // The driver adapter (pragma() prepares PRAGMA ...): the caller is the server code.
      if (norm.includes("/src/sqlite-driver")) continue;
      if (norm.includes("/src/__tests__/")) continue;
      const m =
        norm.match(/at (?:async )?([^\s(]+) \(.*?(\/src\/[^:)]+):(\d+)/) ?? norm.match(/at ()(?:.*?)(\/src\/[^:)]+):(\d+)/);
      if (m) return { fn: m[1] || "<anonymous>", file: m[2].replace(/^\//, ""), line: m[3] };
    }
    return null;
  };
  const record = (entry: Record<string, string>) => {
    const key = JSON.stringify(entry);
    if (seen.has(key)) return;
    seen.add(key);
    appendFileSync(out, key + "\n");
  };

  if (!g.__fourdaCorpusPatched) {
    g.__fourdaCorpusPatched = true;
    // Both drivers (sqlite-driver.ts): better-sqlite3's Database, and the
    // node:sqlite adapter the server uses when the runtime has node:sqlite.
    const BetterSqlite3 = (await import("better-sqlite3")).default;
    const { NodeSqliteDatabase } = await import("./sqlite-driver.js");
    for (const Ctor of [BetterSqlite3, NodeSqliteDatabase]) {
      const proto = Ctor.prototype as unknown as {
        prepare: (sql: string) => unknown;
        exec: (sql: string) => unknown;
      };
      const prepare = proto.prepare;
      proto.prepare = function (this: unknown, sql: string) {
        const site = serverCallsite();
        if (site) record({ kind: "prepare", sql, ...site });
        return prepare.call(this, sql);
      };
      const exec = proto.exec;
      proto.exec = function (this: unknown, sql: string) {
        const site = serverCallsite();
        if (site) record({ kind: "exec", sql, ...site });
        return exec.call(this, sql);
      };
    }
  }
  // hasColumn() probes: the columns server code expects on a current database.
  const { FourDADatabase } = await import("./db.js");
  const dbProto = FourDADatabase.prototype as unknown as {
    hasColumn: (table: string, column: string) => boolean;
    __fourdaCorpusPatched?: boolean;
  };
  if (!dbProto.__fourdaCorpusPatched) {
    dbProto.__fourdaCorpusPatched = true;
    const hasColumn = dbProto.hasColumn;
    dbProto.hasColumn = function (this: unknown, table: string, column: string) {
      const site = serverCallsite();
      if (site) record({ kind: "hasColumn", table, column, ...site });
      return hasColumn.call(this, table, column);
    };
  }
}
