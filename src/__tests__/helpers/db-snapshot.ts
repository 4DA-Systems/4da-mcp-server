// SPDX-License-Identifier: Apache-2.0
/**
 * A comparable picture of a SQLite file: its schema (sqlite_master, every
 * row) and, per table, a row count and a hash of every row. Used to prove the
 * server changed nothing in the desktop app's database beyond rows in the
 * app-owned tables its tools are designed to write.
 */
import { createHash } from "node:crypto";
import Database from "better-sqlite3";

export interface DbSnapshot {
  schema: string[];
  tables: Record<string, { rows: number; hash: string }>;
}

export function snapshotDb(file: string): DbSnapshot {
  const db = new Database(file, { readonly: true, fileMustExist: true });
  try {
    const master = db
      .prepare("SELECT type, name, tbl_name, sql FROM sqlite_master ORDER BY type, name")
      .all() as Array<{ type: string; name: string; tbl_name: string; sql: string | null }>;
    const tables: DbSnapshot["tables"] = {};
    for (const t of master) {
      if (t.type !== "table" || t.name.startsWith("sqlite_")) continue;
      try {
        const rows = db.prepare(`SELECT * FROM "${t.name}"`).raw().all();
        const hash = createHash("sha256")
          .update(JSON.stringify(rows, (_k, v) => (Buffer.isBuffer(v) ? v.toString("base64") : typeof v === "bigint" ? String(v) : v)))
          .digest("hex");
        tables[t.name] = { rows: rows.length, hash };
      } catch {
        // Virtual tables whose module this build does not load (sqlite-vec): schema-checked only.
      }
    }
    return { schema: master.map((m) => JSON.stringify(m)), tables };
  } finally {
    db.close();
  }
}

/** Tables whose rows changed between two snapshots. */
export function changedTables(before: DbSnapshot, after: DbSnapshot): string[] {
  const names = new Set([...Object.keys(before.tables), ...Object.keys(after.tables)]);
  return [...names].filter((n) => before.tables[n]?.hash !== after.tables[n]?.hash).sort();
}
