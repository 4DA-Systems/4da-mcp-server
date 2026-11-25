// SPDX-License-Identifier: Apache-2.0
/**
 * Audit 2026-11-25, G-4: knowledge_gaps judged a project's install by the version the desktop app
 * had recorded (project_dependencies / user_dependencies), ahead of the version the server itself
 * resolved from the lockfile on disk for that project. The app's record can be older than the
 * lockfile; the disk now comes first, and the app's record is used only where the disk has none.
 */
import * as path from "node:path";
import * as os from "node:os";
import Database from "better-sqlite3";
import { describe, expect, it } from "vitest";

import { InstallResolver } from "../tools/knowledge-gap-installs.js";
import type { FourDADatabase } from "../db.js";
import type { ResolvedDependency } from "../live/types.js";

const project = path.join(os.tmpdir(), "a1125-gap-installs", "proj");

function appDb(lockVersion: string | null): FourDADatabase {
  const raw = new Database(":memory:");
  raw.exec("CREATE TABLE user_dependencies (project_path TEXT, package_name TEXT, version TEXT, ecosystem TEXT, is_direct INTEGER, last_seen_at TEXT)");
  if (lockVersion) {
    raw.prepare("INSERT INTO user_dependencies VALUES (?, 'lodash', ?, 'npm', 1, '2026-01-01')").run(project, lockVersion);
  }
  const columns = new Set(["project_path", "package_name", "version", "ecosystem", "is_direct", "last_seen_at"]);
  return { hasColumn: (_t: string, c: string) => columns.has(c), getRawDb: () => raw } as unknown as FourDADatabase;
}

function live(version: string | null, dirs = [project]) {
  const deps = version
    ? [{ name: "lodash", version, ecosystem: "npm", isDev: false, isDirect: true, devScopeKnown: true, target: null, platformActive: true, sourceDirs: dirs } as ResolvedDependency]
    : [];
  return { isInitialized: () => true, getResolvedDeps: () => deps };
}

const row = (version: string | null) => ({ package_name: "lodash", version, project_path: project, language: "javascript" });

describe("G-4: the install a knowledge gap judges is the disk's, ahead of the app's record", () => {
  it("prefers the server's resolution for this project over the app's exact project_dependencies version", () => {
    const r = new InstallResolver(appDb(null), live("4.17.21"), [path.dirname(project)]);
    expect(r.installsFor([row("4.17.10")])[0].version).toBe("4.17.21");
  });

  it("prefers the server's resolution for this project over the app's user_dependencies lock row", () => {
    const r = new InstallResolver(appDb("4.17.10"), live("4.17.21"), [path.dirname(project)]);
    expect(r.installsFor([row("^4.17.0")])[0].version).toBe("4.17.21");
  });

  it("falls back to the app's record when the disk has no resolution for this project", () => {
    expect(new InstallResolver(appDb(null), live(null), []).installsFor([row("4.17.10")])[0].version).toBe("4.17.10");
    expect(new InstallResolver(appDb("4.17.10"), live(null), [path.dirname(project)]).installsFor([row("^4.17.0")])[0].version).toBe("4.17.10");
  });

  it("never takes another project's resolution from disk over this project's app record", () => {
    const other = path.join(path.dirname(project), "other");
    const r = new InstallResolver(appDb("4.17.10"), live("4.17.21", [other]), [path.dirname(project)]);
    expect(r.installsFor([row("^4.17.0")])[0].version).toBe("4.17.10");
  });
});
