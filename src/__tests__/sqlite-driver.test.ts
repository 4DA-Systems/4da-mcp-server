// SPDX-License-Identifier: Apache-2.0
/**
 * The SQLite driver (sqlite-driver.ts): node:sqlite and better-sqlite3 must
 * behave the same for everything the server does with a database, and the
 * selection must never leave the server without a working driver when one
 * exists.
 *
 * Origin: npm 12 blocks dependency install scripts, so better-sqlite3's native
 * module was never built and every tool failed (2026-10-03, npm 12.2.0). The
 * server now prefers node:sqlite, which ships inside Node.
 */
import { describe, it, expect, afterEach } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import {
  NodeSqliteDatabase,
  loadBetterSqlite3,
  loadNodeSqlite,
  resolveSqliteDriver,
  sqliteCodeName,
  type SqliteDatabase,
  type SqliteDriver,
} from "../sqlite-driver.js";
import { isUnreadableDbError } from "../db.js";

const dirs: string[] = [];
function tempFile(name = "t.db"): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "4da-sqlite-driver-"));
  dirs.push(dir);
  return path.join(dir, name);
}
afterEach(() => {
  for (const dir of dirs.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
});

/** node:sqlite exists from Node 22.13; CI also runs Node 22.12, where only better-sqlite3 does. */
const [major, minor] = process.versions.node.split(".").map(Number);
const HAS_NODE_SQLITE = major > 22 || (major === 22 && minor >= 13);

describe("node:sqlite availability", () => {
  it("matches the documented minimum (22.13.0 on the 22 line)", () => {
    expect(resolveSqliteDriver(undefined, { FOURDA_SQLITE_DRIVER: "node" }).driver !== null).toBe(HAS_NODE_SQLITE);
  });
});

const drivers: SqliteDriver[] = (HAS_NODE_SQLITE ? (["node", "better"] as const) : (["better"] as const)).map((force) => {
  const { driver, problem } = resolveSqliteDriver(undefined, { FOURDA_SQLITE_DRIVER: force });
  if (!driver) throw new Error(`driver ${force} unavailable in the test environment: ${problem}`);
  return driver;
});

function catchError(fn: () => unknown): { code?: string; message: string } {
  try {
    fn();
  } catch (error) {
    return error as { code?: string; message: string };
  }
  throw new Error("expected an error");
}

describe.each(drivers.map((d) => [d.name, d] as const))("%s", (_name, driver) => {
  function memory(): SqliteDatabase {
    const db = driver.open(":memory:");
    db.exec("CREATE TABLE t (id INTEGER PRIMARY KEY, name TEXT NOT NULL, score REAL, data BLOB, big INTEGER)");
    return db;
  }

  it("binds positional parameters, flattens arrays, and reports changes and rowids", () => {
    const db = memory();
    const insert = db.prepare("INSERT INTO t (name, score) VALUES (?, ?)");
    expect(insert.run("a", 1.5)).toEqual({ changes: 1, lastInsertRowid: 1 });
    expect(insert.run(["b", 2])).toEqual({ changes: 1, lastInsertRowid: 2 });
    expect(db.prepare("SELECT name FROM t WHERE id IN (?, ?) ORDER BY id").all(...[1, 2])).toEqual([{ name: "a" }, { name: "b" }]);
    expect(db.prepare("UPDATE t SET score = 0").run().changes).toBe(2);
    expect(db.prepare("SELECT * FROM t WHERE id = ?").get(99)).toBeUndefined();
    db.close();
  });

  it("binds named parameters given without their prefix, for @, : and $", () => {
    const db = memory();
    db.prepare("INSERT INTO t (name, score) VALUES (@name, :score)").run({ name: "n", score: 3 });
    expect(db.prepare("SELECT name, score FROM t WHERE name = $name").get({ name: "n" })).toEqual({ name: "n", score: 3 });
    db.close();
  });

  it("returns plain objects, BLOBs as Buffers, and integers past 2^53 as numbers", () => {
    const db = memory();
    db.prepare("INSERT INTO t (name, data, big) VALUES (?, ?, ?)").run("x", Buffer.from([1, 2, 3]), 9007199254740993n);
    const row = db.prepare("SELECT data, big FROM t").get() as { data: Buffer; big: number };
    expect(Object.getPrototypeOf(row)).toBe(Object.prototype);
    expect(Buffer.isBuffer(row.data)).toBe(true);
    expect([...row.data]).toEqual([1, 2, 3]);
    expect(typeof row.big).toBe("number");
    expect(row.big).toBe(Number(9007199254740993n));
    // Normal reads still come back as numbers after a BigInt re-read.
    expect(db.prepare("SELECT 1 AS one").get()).toEqual({ one: 1 });
    db.close();
  });

  it("commits a transaction, rolls one back on throw, and nests as savepoints", () => {
    const db = memory();
    const insert = db.prepare("INSERT INTO t (name) VALUES (?)");
    const count = () => (db.prepare("SELECT COUNT(*) AS n FROM t").get() as { n: number }).n;

    expect(db.transaction((a: string, b: string) => (insert.run(a), insert.run(b), "done"))("a", "b")).toBe("done");
    expect(count()).toBe(2);

    expect(() =>
      db.transaction(() => {
        insert.run("c");
        throw new Error("boom");
      })(),
    ).toThrow("boom");
    expect(count()).toBe(2);

    const outer = db.transaction(() => {
      insert.run("d");
      try {
        db.transaction(() => {
          insert.run("e");
          throw new Error("inner");
        })();
      } catch {
        // The inner failure rolls back only the inner work.
      }
      insert.run("f");
    });
    outer();
    expect((db.prepare("SELECT name FROM t ORDER BY id").all() as { name: string }[]).map((r) => r.name)).toEqual(["a", "b", "d", "f"]);
    db.close();
  });

  it("answers pragmas as rows, or as one value with { simple: true }", () => {
    const db = memory();
    expect(db.pragma("table_info(t)")).toEqual(expect.arrayContaining([expect.objectContaining({ name: "name", notnull: 1 })]));
    expect(db.pragma("user_version", { simple: true })).toBe(0);
    db.pragma("user_version = 7");
    expect(db.pragma("user_version", { simple: true })).toBe(7);
    expect(db.pragma("foreign_keys", { simple: true })).toBe(1);
    db.close();
  });

  it("waits 5 s for a lock by default, like better-sqlite3", () => {
    const db = memory();
    expect(db.pragma("busy_timeout", { simple: true })).toBe(5000);
    db.close();
  });

  it("exposes open, readonly and name", () => {
    const file = tempFile();
    const db = driver.open(file);
    expect([db.open, db.readonly, db.name]).toEqual([true, false, file]);
    db.close();
    expect(db.open).toBe(false);
    const ro = driver.open(file, { readonly: true, fileMustExist: true });
    expect(ro.readonly).toBe(true);
    ro.close();
  });

  it("refuses writes on a read-only connection with SQLITE_READONLY", () => {
    const file = tempFile();
    const rw = driver.open(file);
    rw.exec("CREATE TABLE k (v TEXT)");
    rw.close();
    const ro = driver.open(file, { readonly: true });
    expect(catchError(() => ro.prepare("INSERT INTO k VALUES ('x')").run()).code).toMatch(/^SQLITE_READONLY/);
    expect(ro.prepare("SELECT COUNT(*) AS n FROM k").get()).toEqual({ n: 0 });
    ro.close();
  });

  it("fails with SQLITE_CANTOPEN for a missing file under fileMustExist or readonly, and creates nothing", () => {
    const file = tempFile("missing.db");
    expect(catchError(() => driver.open(file, { fileMustExist: true })).code).toBe("SQLITE_CANTOPEN");
    expect(catchError(() => driver.open(file, { readonly: true })).code).toBe("SQLITE_CANTOPEN");
    expect(fs.existsSync(file)).toBe(false);
  });

  it("reports a file that is not a database as SQLITE_NOTADB, which the server recognises", () => {
    const file = tempFile("garbage.db");
    fs.writeFileSync(file, "this is not a SQLite database, just text padded out to more than one header ".repeat(4));
    const error = catchError(() => {
      const db = driver.open(file, { readonly: true, fileMustExist: true });
      try {
        db.prepare("SELECT name FROM sqlite_master").all();
      } finally {
        db.close();
      }
    });
    expect(error.code).toBe("SQLITE_NOTADB");
    expect(isUnreadableDbError(error)).toBe(true);
  });

  it("names constraint violations as better-sqlite3 does", () => {
    const db = memory();
    db.prepare("INSERT INTO t (id, name) VALUES (1, 'a')").run();
    expect(catchError(() => db.prepare("INSERT INTO t (id, name) VALUES (1, 'b')").run()).code).toBe("SQLITE_CONSTRAINT_PRIMARYKEY");
    expect(catchError(() => db.prepare("INSERT INTO t (name) VALUES (NULL)").run()).code).toBe("SQLITE_CONSTRAINT_NOTNULL");
    db.close();
  });

  it("reports a write lock held by another connection as SQLITE_BUSY", () => {
    const file = tempFile();
    const a = driver.open(file);
    a.exec("CREATE TABLE k (v TEXT)");
    const b = driver.open(file);
    b.pragma("busy_timeout = 0");
    a.exec("BEGIN IMMEDIATE");
    try {
      expect(catchError(() => b.prepare("INSERT INTO k VALUES ('x')").run()).code).toBe("SQLITE_BUSY");
    } finally {
      a.exec("ROLLBACK");
      a.close();
      b.close();
    }
  });
});

describe("sqliteCodeName", () => {
  it("maps extended codes when known and falls back to the primary code", () => {
    expect(sqliteCodeName(5)).toBe("SQLITE_BUSY");
    expect(sqliteCodeName(26)).toBe("SQLITE_NOTADB");
    expect(sqliteCodeName(2067)).toBe("SQLITE_CONSTRAINT_UNIQUE");
    expect(sqliteCodeName(5 | (99 << 8))).toBe("SQLITE_BUSY");
  });
});

describe("driver selection", () => {
  const missingBindings = () =>
    class {
      constructor() {
        throw new Error("Could not locate the bindings file. Tried:\n → build/better_sqlite3.node");
      }
    } as never;
  const noNodeSqlite = () => {
    throw Object.assign(new Error("No such built-in module: node:sqlite"), { code: "ERR_UNKNOWN_BUILTIN_MODULE" });
  };

  it.runIf(HAS_NODE_SQLITE)("prefers node:sqlite", () => {
    const r = resolveSqliteDriver({ node: loadNodeSqlite, better: missingBindings }, {});
    expect(r.driver?.name).toBe("node:sqlite");
    expect(r.problem).toBeNull();
  });

  it.runIf(HAS_NODE_SQLITE)("uses node:sqlite when better-sqlite3's native module was never built (npm 12, scripts blocked)", () => {
    const r = resolveSqliteDriver({ node: loadNodeSqlite, better: missingBindings }, { FOURDA_SQLITE_DRIVER: "" });
    const db = r.driver!.open(":memory:");
    expect(db.prepare("SELECT sqlite_version() AS v").get()).toEqual({ v: expect.any(String) });
    db.close();
  });

  it("falls back to better-sqlite3 when the runtime has no node:sqlite", () => {
    const r = resolveSqliteDriver({ node: noNodeSqlite, better: loadBetterSqlite3 }, {});
    expect(r.driver?.name).toBe("better-sqlite3");
    expect(r.rejected.map((x) => x.name)).toEqual(["node:sqlite"]);
  });

  it("rejects a better-sqlite3 whose import succeeds but whose native module is missing", () => {
    const r = resolveSqliteDriver({ node: noNodeSqlite, better: missingBindings }, {});
    expect(r.driver).toBeNull();
    expect(r.problem).toContain("upgrade Node.js to 22.13.0 or later");
    expect(r.problem).toContain("Could not locate the bindings file");
    expect(r.problem).toContain("npm install-scripts approve better-sqlite3");
  });

  it("reports better-sqlite3 as not installed when it is absent (an optional dependency)", () => {
    const absent = () => {
      throw new Error("Cannot find module 'better-sqlite3'");
    };
    const r = resolveSqliteDriver({ node: noNodeSqlite, better: absent }, {});
    expect(r.driver).toBeNull();
    expect(r.rejected[1].reason).toMatch(/^not installed/);
  });

  it.runIf(HAS_NODE_SQLITE)("honours FOURDA_SQLITE_DRIVER and never silently replaces a forced driver", () => {
    expect(resolveSqliteDriver(undefined, { FOURDA_SQLITE_DRIVER: "better" }).driver?.name).toBe("better-sqlite3");
    expect(resolveSqliteDriver(undefined, { FOURDA_SQLITE_DRIVER: "node:sqlite" }).driver?.name).toBe("node:sqlite");
    const forced = resolveSqliteDriver({ node: loadNodeSqlite, better: missingBindings }, { FOURDA_SQLITE_DRIVER: "better" });
    expect(forced.driver).toBeNull();
    expect(forced.problem).toContain("FOURDA_SQLITE_DRIVER=better");
    const none = resolveSqliteDriver(undefined, { FOURDA_SQLITE_DRIVER: "none" });
    expect(none.driver).toBeNull();
    expect(none.problem).toContain("FOURDA_SQLITE_DRIVER=none");
  });

  it.runIf(HAS_NODE_SQLITE)("NodeSqliteDatabase closes idempotently and refuses use after close", () => {
    const db = new NodeSqliteDatabase(loadNodeSqlite(), ":memory:");
    db.close();
    db.close();
    expect(() => db.prepare("SELECT 1")).toThrow(/not open/);
  });
});
