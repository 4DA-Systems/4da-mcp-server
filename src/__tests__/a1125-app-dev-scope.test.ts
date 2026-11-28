// SPDX-License-Identifier: Apache-2.0
/**
 * Audit 2026-11-25, G-2: the desktop app's `dependency_instances` rows never lower a grade. A stale
 * app row saying dev turned runtime copies the npm lockfile knew into dev (severities lowered,
 * vulnerable packages dropped from the health count, 6 -> 3). The rule now: the lockfile's own
 * determination stands; where it does not say, only an app row determining RUNTIME is used (it
 * changes no grade, it only makes `dev_scope_known` true); a dev row changes nothing.
 */
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import Database from "better-sqlite3";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { applyInstanceDevScope, canonicalStoragePath } from "../live/dev-scope.js";
import type { ResolvedDependency } from "../live/types.js";
import type { SqliteDatabase } from "../sqlite-driver.js";

let root: string;
let dir: string;

beforeAll(() => {
  root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "a1125-dev-scope-")));
  dir = path.join(root, "proj");
  fs.mkdirSync(dir);
});
afterAll(() => fs.rmSync(root, { recursive: true, force: true }));

function appDb(rows: Array<{ name: string; isDev: number; scope: string }>): SqliteDatabase {
  const db = new Database(":memory:");
  db.exec(`CREATE TABLE dependency_instances (
    id INTEGER PRIMARY KEY, project_path TEXT NOT NULL, ecosystem TEXT NOT NULL,
    package_name TEXT NOT NULL, version TEXT NOT NULL, is_direct INTEGER NOT NULL DEFAULT 0,
    is_dev INTEGER NOT NULL DEFAULT 0, scope TEXT NOT NULL DEFAULT 'unknown',
    detected_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(project_path, ecosystem, package_name, version))`);
  const insert = db.prepare(
    "INSERT INTO dependency_instances (project_path, ecosystem, package_name, version, is_dev, scope, detected_at) VALUES (?, 'npm', ?, '1.0.0', ?, ?, '2099-01-01 00:00:00')",
  );
  for (const r of rows) insert.run(canonicalStoragePath(dir), r.name, r.isDev, r.scope);
  return db as unknown as SqliteDatabase;
}

function dep(name: string, over: Partial<ResolvedDependency>): ResolvedDependency {
  return { name, version: "1.0.0", ecosystem: "npm", isDev: false, isDirect: false, devScopeKnown: false, target: null, platformActive: true, sourceDirs: [dir], ...over } as ResolvedDependency;
}

describe("G-2: the app's dev rows never lower a grade", () => {
  it("a runtime copy the lockfile knows stays runtime, even when a fresh app row says dev", () => {
    const db = appDb([{ name: "runtime-known", isDev: 1, scope: "dev" }]);
    const [out] = applyInstanceDevScope(db, [dep("runtime-known", { devScopeKnown: true, isDev: false })]);
    expect(out).toMatchObject({ devScopeKnown: true, isDev: false });
  });

  it("a dev copy the lockfile knows stays dev, even when an app row says runtime", () => {
    const db = appDb([{ name: "dev-known", isDev: 0, scope: "runtime" }]);
    const [out] = applyInstanceDevScope(db, [dep("dev-known", { devScopeKnown: true, isDev: true })]);
    expect(out).toMatchObject({ devScopeKnown: true, isDev: true });
  });

  it("where the lockfile does not say, an app dev row changes nothing (scope stays unknown, no discount)", () => {
    const db = appDb([{ name: "unknown", isDev: 1, scope: "dev" }]);
    const [out] = applyInstanceDevScope(db, [dep("unknown", {})]);
    expect(out).toMatchObject({ devScopeKnown: false, isDev: false });
  });

  it("where the lockfile does not say, an app runtime row makes the scope known runtime (no grade changes)", () => {
    const db = appDb([{ name: "unknown", isDev: 0, scope: "runtime" }]);
    const [out] = applyInstanceDevScope(db, [dep("unknown", {})]);
    expect(out).toMatchObject({ devScopeKnown: true, isDev: false });
  });

  it("a copy pinned in two workspaces, one app row runtime and one dev: unchanged", () => {
    const other = path.join(root, "other");
    fs.mkdirSync(other, { recursive: true });
    const db = appDb([{ name: "split", isDev: 0, scope: "runtime" }]);
    (db as unknown as Database.Database)
      .prepare("INSERT INTO dependency_instances (project_path, ecosystem, package_name, version, is_dev, scope) VALUES (?, 'npm', 'split', '1.0.0', 1, 'dev')")
      .run(canonicalStoragePath(other));
    const [out] = applyInstanceDevScope(db, [dep("split", { sourceDirs: [dir, other] })]);
    expect(out).toMatchObject({ devScopeKnown: false, isDev: false });
  });
});
