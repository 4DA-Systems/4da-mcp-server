// SPDX-License-Identifier: Apache-2.0
/**
 * Load the desktop app's schema (contract/app-schema.sql) into a SQLite handle.
 *
 * Shared by the contract test (src/__tests__/app-schema-contract.test.ts) and
 * the contract runner (scripts/app-schema-contract.mjs) so both read the file
 * the same way.
 *
 * sqlite-vec's `vec0` module is not available to better-sqlite3, and the
 * server never queries vector tables, so each vec0 table becomes a plain stub
 * with the same name. FTS5 is compiled into better-sqlite3 and loads as is.
 */

/** Matches one `CREATE VIRTUAL TABLE ... USING vec0(...);` statement. */
const VEC0 = /CREATE VIRTUAL TABLE (?:IF NOT EXISTS )?("?)(\w+)\1 USING vec0\([\s\S]*?\);/g;

/**
 * @param {import("better-sqlite3").Database} db an empty database
 * @param {string} sql the contents of app-schema.sql
 * @returns {{ vecTables: string[], schemaVersion: number | null }}
 */
export function loadAppSchema(db, sql) {
  const vecTables = [];
  const rewritten = sql.replace(VEC0, (_match, _quote, name) => {
    vecTables.push(name);
    return `CREATE TABLE ${name} (rowid INTEGER PRIMARY KEY, embedding BLOB);`;
  });
  db.exec(rewritten);
  const header = sql.match(/^-- schema_version: (\d+)/m);
  return { vecTables, schemaVersion: header ? Number(header[1]) : null };
}

/** SQLite errors that mean the server and the app disagree about the schema. */
export const SCHEMA_ERROR = /no such (table|column)|has no column named|no such function/i;
