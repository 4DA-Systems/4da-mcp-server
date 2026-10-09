// SPDX-License-Identifier: Apache-2.0
/**
 * The SQLite driver: Node's built-in `node:sqlite` when the runtime has it,
 * otherwise better-sqlite3, behind one interface.
 *
 * Why: npm 12 blocks dependency install scripts unless allowed, so a default
 * `npx @4da/mcp-server` or `npm install` left better-sqlite3's native module
 * unbuilt and every tool failed (measured 2026-10-03 on npm 12.2.0, see
 * native-bindings.ts). `node:sqlite` ships inside Node: no install script, no
 * native download. It is available without a flag from Node 22.13.0 (and
 * 23.4.0); npm 12 itself requires Node ^22.22.2 || ^24.15.0 || >=26, so every
 * npm 12 install has it. better-sqlite3 is an optional dependency now, used on
 * Node 22.0-22.12 where it builds (npm 10 and 11 run its install script).
 *
 * The interface is the subset of better-sqlite3 this server uses: open
 * options `readonly` / `fileMustExist`, prepare().get/all/run (positional
 * parameters, arrays flattened, or one object of named parameters), exec,
 * pragma (incl. `{ simple: true }`), transaction (nested calls become
 * savepoints), close, and the `open` / `readonly` / `name` properties.
 * better-sqlite3's Database satisfies it as is; node:sqlite is adapted
 * (NodeSqliteDatabase) so that rows, BLOBs, error codes and the 5 s busy
 * timeout match what the server's code already expects.
 *
 * `FOURDA_SQLITE_DRIVER=node|better` forces one driver (tests, diagnostics):
 * a forced driver that cannot load is reported, never silently replaced.
 * `none` simulates a host where neither works.
 */

import * as fs from "node:fs";
import { createRequire } from "node:module";

import { checkNativeBindings, NATIVE_BINDING_FIX } from "./native-bindings.js";

export interface SqliteRunResult {
  changes: number;
  lastInsertRowid: number | bigint;
}

export interface SqliteStatement {
  run(...params: unknown[]): SqliteRunResult;
  get(...params: unknown[]): unknown;
  all(...params: unknown[]): unknown[];
}

export interface SqliteOpenOptions {
  readonly?: boolean;
  fileMustExist?: boolean;
}

/** The subset of better-sqlite3's Database the server uses; both drivers provide it. */
export interface SqliteDatabase {
  prepare(source: string): SqliteStatement;
  exec(source: string): unknown;
  pragma(source: string, options?: { simple?: boolean }): unknown;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  transaction<F extends (...args: any[]) => unknown>(fn: F): (...args: Parameters<F>) => ReturnType<F>;
  close(): unknown;
  readonly open: boolean;
  readonly readonly: boolean;
  readonly name: string;
}

export type SqliteDriverName = "node:sqlite" | "better-sqlite3";

export interface SqliteDriver {
  name: SqliteDriverName;
  open(file: string, options?: SqliteOpenOptions): SqliteDatabase;
}

/** Thrown by sqliteDriver() when neither driver can open a database here. */
export class SqliteUnavailableError extends Error {
  readonly code = "FOURDA_NO_SQLITE";
}

/** The first Node release with `node:sqlite` unflagged on the 22 line. */
export const NODE_SQLITE_MIN = "22.13.0";

// ---------------------------------------------------------------------------
// node:sqlite adapter
// ---------------------------------------------------------------------------

/** Primary and extended SQLite result codes, by number, as better-sqlite3 names them. */
const SQLITE_CODES: Record<number, string> = {
  1: "SQLITE_ERROR", 2: "SQLITE_INTERNAL", 3: "SQLITE_PERM", 4: "SQLITE_ABORT", 5: "SQLITE_BUSY",
  6: "SQLITE_LOCKED", 7: "SQLITE_NOMEM", 8: "SQLITE_READONLY", 9: "SQLITE_INTERRUPT", 10: "SQLITE_IOERR",
  11: "SQLITE_CORRUPT", 12: "SQLITE_NOTFOUND", 13: "SQLITE_FULL", 14: "SQLITE_CANTOPEN", 15: "SQLITE_PROTOCOL",
  16: "SQLITE_EMPTY", 17: "SQLITE_SCHEMA", 18: "SQLITE_TOOBIG", 19: "SQLITE_CONSTRAINT", 20: "SQLITE_MISMATCH",
  21: "SQLITE_MISUSE", 22: "SQLITE_NOLFS", 23: "SQLITE_AUTH", 24: "SQLITE_FORMAT", 25: "SQLITE_RANGE",
  26: "SQLITE_NOTADB",
  261: "SQLITE_BUSY_RECOVERY", 517: "SQLITE_BUSY_SNAPSHOT", 773: "SQLITE_BUSY_TIMEOUT",
  262: "SQLITE_LOCKED_SHAREDCACHE", 264: "SQLITE_READONLY_RECOVERY", 520: "SQLITE_READONLY_CANTLOCK",
  776: "SQLITE_READONLY_ROLLBACK", 1032: "SQLITE_READONLY_DBMOVED", 267: "SQLITE_CORRUPT_VTAB",
  275: "SQLITE_CONSTRAINT_CHECK", 787: "SQLITE_CONSTRAINT_FOREIGNKEY", 1299: "SQLITE_CONSTRAINT_NOTNULL",
  1555: "SQLITE_CONSTRAINT_PRIMARYKEY", 2067: "SQLITE_CONSTRAINT_UNIQUE", 2579: "SQLITE_CONSTRAINT_ROWID",
};

/** better-sqlite3's error code for a SQLite result code (extended when known, else primary). */
export function sqliteCodeName(errcode: number): string {
  return SQLITE_CODES[errcode] ?? SQLITE_CODES[errcode & 0xff] ?? `SQLITE_UNKNOWN_${errcode}`;
}

/**
 * node:sqlite errors carry `code: "ERR_SQLITE_ERROR"` and the SQLite result
 * code in `errcode`; the server's checks (unreadable database, BUSY/LOCKED
 * retry) read better-sqlite3's `code: "SQLITE_BUSY"` form. Rewrite it in place.
 */
function normaliseError(error: unknown): unknown {
  const e = error as { code?: unknown; errcode?: unknown } | null;
  if (e && typeof e === "object" && typeof e.errcode === "number") {
    try {
      Object.defineProperty(e, "code", { value: sqliteCodeName(e.errcode), writable: true, enumerable: true, configurable: true });
    } catch {
      // A frozen error keeps its own code.
    }
  }
  return error;
}

function guarded<T>(fn: () => T): T {
  try {
    return fn();
  } catch (error) {
    throw normaliseError(error);
  }
}

// node:sqlite's types are taken from the runtime module, not imported
// statically: on Node < 22.13 a static `import "node:sqlite"` would fail the
// whole module graph.
interface NativeStatement {
  run(...params: unknown[]): { changes: number | bigint; lastInsertRowid: number | bigint };
  get(...params: unknown[]): unknown;
  all(...params: unknown[]): unknown[];
  setReadBigInts(enabled: boolean): void;
}
interface NativeDatabase {
  prepare(sql: string): NativeStatement;
  exec(sql: string): void;
  close(): void;
}
type NativeDatabaseCtor = new (path: string, options?: Record<string, unknown>) => NativeDatabase;

function isPlainParamObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value) && !ArrayBuffer.isView(value) && !(value instanceof ArrayBuffer);
}

/** better-sqlite3's argument forms -> node:sqlite's (named object first, then positionals). */
function bindArgs(params: unknown[]): unknown[] {
  let named: Record<string, unknown> | null = null;
  const positional: unknown[] = [];
  const add = (value: unknown) => {
    if (Array.isArray(value)) value.forEach(add);
    else if (isPlainParamObject(value)) named = { ...(named ?? {}), ...value };
    else positional.push(value);
  };
  params.forEach(add);
  return named ? [named, ...positional] : positional;
}

function toNumber(value: unknown): unknown {
  // better-sqlite3 returns integers past 2^53 as (inexact) numbers; so do we.
  return typeof value === "bigint" ? Number(value) : value;
}

/** A row as better-sqlite3 returns it: a plain object, BLOBs as Buffers. */
function plainRow(row: unknown, bigints: boolean): unknown {
  if (row === undefined || row === null || typeof row !== "object") return row;
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(row as Record<string, unknown>)) {
    out[key] =
      value instanceof Uint8Array && !Buffer.isBuffer(value)
        ? Buffer.from(value.buffer, value.byteOffset, value.byteLength)
        : bigints
          ? toNumber(value)
          : value;
  }
  return out;
}

function isOutOfRange(error: unknown): boolean {
  return (error as { code?: unknown } | null)?.code === "ERR_OUT_OF_RANGE";
}

class NodeSqliteStatement implements SqliteStatement {
  constructor(private readonly stmt: NativeStatement) {}

  /** Read once as numbers; an integer past 2^53 makes node:sqlite throw, so re-read as BigInts and convert. */
  private read<T>(fn: (args: unknown[]) => T, args: unknown[]): { value: T; bigints: boolean } {
    const bound = bindArgs(args);
    try {
      return { value: fn(bound), bigints: false };
    } catch (error) {
      if (!isOutOfRange(error)) throw normaliseError(error);
      this.stmt.setReadBigInts(true);
      try {
        return { value: guarded(() => fn(bound)), bigints: true };
      } finally {
        this.stmt.setReadBigInts(false);
      }
    }
  }

  run(...params: unknown[]): SqliteRunResult {
    const result = guarded(() => this.stmt.run(...bindArgs(params)));
    return { changes: Number(result.changes), lastInsertRowid: result.lastInsertRowid };
  }

  get(...params: unknown[]): unknown {
    const { value, bigints } = this.read((a) => this.stmt.get(...a), params);
    return plainRow(value, bigints);
  }

  all(...params: unknown[]): unknown[] {
    const { value, bigints } = this.read((a) => this.stmt.all(...a), params);
    return value.map((row) => plainRow(row, bigints));
  }
}

/** better-sqlite3's default busy timeout, which the server's retry logic assumes. */
const BUSY_TIMEOUT_MS = 5000;

export class NodeSqliteDatabase implements SqliteDatabase {
  readonly name: string;
  readonly readonly: boolean;
  private db: NativeDatabase;
  private isOpen = true;
  private depth = 0;
  private savepoints = 0;

  constructor(Ctor: NativeDatabaseCtor, file: string, options: SqliteOpenOptions = {}) {
    this.name = file;
    this.readonly = options.readonly === true;
    const inMemory = file === ":memory:" || file === "";
    if (!inMemory && (options.fileMustExist || this.readonly) && !fs.existsSync(file)) {
      // better-sqlite3's error for the same case.
      throw Object.assign(new Error("unable to open database file"), { code: "SQLITE_CANTOPEN", errcode: 14 });
    }
    this.db = guarded(() => new Ctor(file, { readOnly: this.readonly }));
    try {
      this.db.exec(`PRAGMA busy_timeout = ${BUSY_TIMEOUT_MS}`);
      // Belt and braces for the read-only contract on the desktop app's
      // database: refused writes even if a runtime ignored `readOnly`.
      if (this.readonly) this.db.exec("PRAGMA query_only = ON");
    } catch (error) {
      this.db.close();
      throw normaliseError(error);
    }
  }

  get open(): boolean {
    return this.isOpen;
  }

  private assertOpen(): void {
    if (!this.isOpen) throw new TypeError("The database connection is not open");
  }

  prepare(source: string): SqliteStatement {
    this.assertOpen();
    return new NodeSqliteStatement(guarded(() => this.db.prepare(source)));
  }

  exec(source: string): this {
    this.assertOpen();
    guarded(() => this.db.exec(source));
    return this;
  }

  pragma(source: string, options?: { simple?: boolean }): unknown {
    const rows = this.prepare(`PRAGMA ${source}`).all() as Record<string, unknown>[];
    if (options?.simple) {
      const first = rows[0];
      return first ? Object.values(first)[0] : undefined;
    }
    return rows;
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  transaction<F extends (...args: any[]) => unknown>(fn: F): (...args: Parameters<F>) => ReturnType<F> {
    return (...args: Parameters<F>): ReturnType<F> => {
      this.assertOpen();
      const nested = this.depth > 0;
      const savepoint = nested ? `fourda_sp_${++this.savepoints}` : null;
      this.exec(savepoint ? `SAVEPOINT ${savepoint}` : "BEGIN");
      this.depth++;
      try {
        const result = fn(...args) as ReturnType<F>;
        this.exec(savepoint ? `RELEASE ${savepoint}` : "COMMIT");
        return result;
      } catch (error) {
        try {
          this.exec(savepoint ? `ROLLBACK TO ${savepoint}; RELEASE ${savepoint}` : "ROLLBACK");
        } catch {
          // SQLite already rolled back (e.g. after SQLITE_FULL); the original error matters.
        }
        throw error;
      } finally {
        this.depth--;
      }
    };
  }

  close(): this {
    if (this.isOpen) {
      this.isOpen = false;
      this.db.close();
    }
    return this;
  }
}

// ---------------------------------------------------------------------------
// Selection
// ---------------------------------------------------------------------------

const require = createRequire(import.meta.url);

/** Load node:sqlite without its one-time "SQLite is an experimental feature" warning; every other warning passes. */
export function loadNodeSqlite(): NativeDatabaseCtor {
  const original = process.emitWarning;
  process.emitWarning = function (this: unknown, warning: string | Error, ...rest: unknown[]) {
    const message = typeof warning === "string" ? warning : warning?.message;
    const opt = rest[0];
    const type = typeof opt === "string" ? opt : (opt as { type?: string } | undefined)?.type ?? (warning as Error)?.name;
    if (type === "ExperimentalWarning" && /^SQLite is an experimental feature/.test(String(message))) return;
    return (original as (...a: unknown[]) => void).call(process, warning, ...rest);
  } as typeof process.emitWarning;
  try {
    const mod = require("node:sqlite") as { DatabaseSync?: NativeDatabaseCtor };
    if (typeof mod.DatabaseSync !== "function") throw new Error("node:sqlite has no DatabaseSync");
    return mod.DatabaseSync;
  } finally {
    process.emitWarning = original;
  }
}

type BetterCtor = new (file: string, options?: { readonly?: boolean; fileMustExist?: boolean }) => SqliteDatabase;

export function loadBetterSqlite3(): BetterCtor {
  const mod = require("better-sqlite3") as BetterCtor | { default: BetterCtor };
  return typeof mod === "function" ? mod : mod.default;
}

export interface DriverLoaders {
  node: () => NativeDatabaseCtor;
  better: () => BetterCtor;
}

export interface DriverResolution {
  driver: SqliteDriver | null;
  /** Why each driver tried was not used (empty when the first one worked). */
  rejected: { name: SqliteDriverName; reason: string }[];
  /** The actionable message when no driver is usable. */
  problem: string | null;
}

function firstLine(error: unknown): string {
  return (error instanceof Error ? error.message : String(error)).split("\n")[0].trim();
}

function forcedDriver(env: NodeJS.ProcessEnv): SqliteDriverName | "none" | null {
  const raw = env.FOURDA_SQLITE_DRIVER?.trim().toLowerCase();
  if (!raw) return null;
  if (raw === "node" || raw === "node:sqlite") return "node:sqlite";
  if (raw === "better" || raw === "better-sqlite3") return "better-sqlite3";
  if (raw === "none") return "none";
  return null;
}

/**
 * Pick the driver: node:sqlite, then better-sqlite3 if its native module
 * actually opens a database (importing it succeeds without one). Pure apart
 * from the loaders, so tests can make either one fail.
 */
export function resolveSqliteDriver(
  loaders: DriverLoaders = { node: loadNodeSqlite, better: loadBetterSqlite3 },
  env: NodeJS.ProcessEnv = process.env,
): DriverResolution {
  const forced = forcedDriver(env);
  // "none" simulates a host where neither driver works (tests, diagnostics).
  const order: SqliteDriverName[] = forced === "none" ? [] : forced ? [forced] : ["node:sqlite", "better-sqlite3"];
  const rejected: DriverResolution["rejected"] = [];
  for (const name of order) {
    if (name === "node:sqlite") {
      try {
        const Ctor = loaders.node();
        new NodeSqliteDatabase(Ctor, ":memory:").close();
        return { driver: { name, open: (file, options) => new NodeSqliteDatabase(Ctor, file, options) }, rejected, problem: null };
      } catch (error) {
        rejected.push({ name, reason: `not available in Node ${process.versions.node} (${firstLine(error)})` });
      }
    } else {
      let Ctor: BetterCtor;
      try {
        Ctor = loaders.better();
      } catch (error) {
        rejected.push({ name, reason: `not installed (${firstLine(error)})` });
        continue;
      }
      const problem = checkNativeBindings(Ctor);
      if (problem) {
        rejected.push({ name, reason: problem });
        continue;
      }
      return { driver: { name, open: (file, options) => new Ctor(file, options) }, rejected, problem: null };
    }
  }
  const tried = rejected.map((r) => `${r.name}: ${r.reason}`).join("; ");
  const problem = forced === "none"
    ? "FOURDA_SQLITE_DRIVER=none disables SQLite: the database tools are unavailable. Unset it to let the server choose a driver."
    : forced
    ? `FOURDA_SQLITE_DRIVER=${env.FOURDA_SQLITE_DRIVER} forces ${forced}, which cannot be used here (${tried}). Unset it to let the server choose.`
    : `No SQLite driver is usable (${tried}). Fix either one: upgrade Node.js to ${NODE_SQLITE_MIN} or later ` +
      `(its built-in node:sqlite needs no install step), or let better-sqlite3 build: ${NATIVE_BINDING_FIX}`;
  return { driver: null, rejected, problem };
}

let resolved: DriverResolution | null = null;

/** The resolution for this process (computed once). */
export function sqliteDriverStatus(): DriverResolution {
  resolved ??= resolveSqliteDriver();
  return resolved;
}

/** The driver in use; throws SqliteUnavailableError with the fix when there is none. */
export function sqliteDriver(): SqliteDriver {
  const status = sqliteDriverStatus();
  if (!status.driver) throw new SqliteUnavailableError(status.problem ?? "No SQLite driver is usable.");
  return status.driver;
}

/** Open a database with the driver in use. */
export function openDatabase(file: string, options?: SqliteOpenOptions): SqliteDatabase {
  return sqliteDriver().open(file, options);
}

/** Forget the cached resolution (tests that change FOURDA_SQLITE_DRIVER). */
export function resetSqliteDriver(): void {
  resolved = null;
}
