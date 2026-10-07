// SPDX-License-Identifier: Apache-2.0
/**
 * Where a decision, agent memory or feedback record is written.
 *
 * Reads go through the database's main connection (read-only for the desktop
 * app's database). A write into one of the app-owned tables the tools exist to
 * write goes through FourDADatabase.writerFor: the app's own table via a
 * separate write connection, or, when the app's schema lacks the table or a
 * column, the server's store with a note. A stand-in object without writerFor
 * (some tests hand tools a minimal double) writes to its own connection.
 */
import type { AppWritableTable, FourDADatabase, WriteTarget } from "./db.js";

export function writerOf(db: FourDADatabase, table: AppWritableTable, columns: readonly string[]): WriteTarget {
  const writerFor = (db as Partial<Pick<FourDADatabase, "writerFor">>).writerFor;
  return typeof writerFor === "function" ? writerFor.call(db, table, columns) : { raw: db.getRawDb(), target: "database" };
}

/** `_meta` for a tool result when the record could not go where it normally goes. */
export function writeMeta(target: WriteTarget): { _meta?: { written_to: string; note: string } } {
  return target.note ? { _meta: { written_to: target.target, note: target.note } } : {};
}
