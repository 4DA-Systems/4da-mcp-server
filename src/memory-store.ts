// SPDX-License-Identifier: Apache-2.0
/**
 * The database the memory tools (agent_memory, decision_memory,
 * check_decision_alignment, the briefing's wisdom section) read and write.
 *
 * With the desktop app's database, which this server opens read-only, that is
 * the server's own store (FourDADatabase.getMemoryStore()); a standalone
 * database is its own store. A stand-in object without getMemoryStore (some
 * tests hand tools a minimal double) is used as is.
 */
import type { FourDADatabase } from "./db.js";

export function memoryStoreOf(db: FourDADatabase): FourDADatabase {
  const store = (db as Partial<Pick<FourDADatabase, "getMemoryStore">>).getMemoryStore;
  return typeof store === "function" ? store.call(db) : db;
}
