// SPDX-License-Identifier: Apache-2.0
/**
 * With the desktop app's database attached, the dependency tools read the project from disk, exactly
 * as without it: the app's `project_dependencies` rows are never the inventory. A sub-project the app
 * has not indexed is still scanned, a directory the repository's .gitignore excludes is named in
 * `coverage` and not scanned even when the app lists it, and the same tree gives the same answer
 * with and without the app database. The scan is never written into the app's database.
 *
 * The built server runs over stdio in the fixture project, OSV.dev answered from records held in a
 * file (helpers/a1123-appmode.ts).
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { appDependency, appModeSession, buildAppDb, npmProject, osvRecord, serverEntry, VENDORED_APP_SCHEMA, type AppModeSession } from "./helpers/a1123-appmode.js";
import { changedTables, snapshotDb, type DbSnapshot } from "./helpers/db-snapshot.js";

const OSV = [
  osvRecord("GHSA-35jh-r3h4-6jhm", "lodash", "npm", { fixed: "4.17.21" }),
  osvRecord("GHSA-xvch-5gv4-984h", "minimist", "npm", { fixed: "1.2.6" }, "CRITICAL"),
  osvRecord("GHSA-hrpp-h998-j3pp", "qs", "npm", { fixed: "6.5.3" }),
];

const CALLS: Array<[string, Record<string, unknown>]> = [
  ["vulnerability_scan", {}],
  ["vulnerability_scan", { response_format: "detailed" }],
  ["vulnerability_scan", { package: "minimist" }],
  ["what_should_i_know", { task: "upgrade minimist in svc" }],
  // An explicit project_path naming the start directory (C2-F1 found it did not help).
  ["vulnerability_scan", { project_path: "<project>", package: "minimist" }],
];

type Row = { package: string; current_version: string; severity: string; ids: string[]; source_dirs?: string[] };

/** The parts of a concise scan that say what was scanned and found. */
function scanFacts(scan: Record<string, unknown>) {
  const rows = (scan.vulnerable_packages as Row[] | undefined) ?? [];
  return {
    ecosystems_scanned: scan.ecosystems_scanned,
    total_dependencies_scanned: scan.total_dependencies_scanned,
    total_vulnerable_packages: scan.total_vulnerable_packages,
    by_severity: scan.by_severity,
    coverage: scan.coverage,
    vulnerable_packages: rows.map((r) => ({ package: r.package, current_version: r.current_version, severity: r.severity, ids: r.ids, source_dirs: r.source_dirs })),
  };
}

describe.skipIf(!fs.existsSync(serverEntry) || !fs.existsSync(VENDORED_APP_SCHEMA))("app mode: the inventory is the disk", () => {
  let root: string;
  let project: string;
  let appDbFile: string;
  let before: DbSnapshot;
  let app: AppModeSession;
  let standalone: AppModeSession;

  beforeAll(async () => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), "4da-a1123-inventory-"));
    project = path.join(root, "proj-mono");
    npmProject(project, { lodash: "4.17.20" });
    npmProject(path.join(project, "svc"), { minimist: "1.2.5" });
    npmProject(path.join(project, "ignored"), { qs: "6.5.2" });
    fs.writeFileSync(path.join(project, ".gitignore"), "ignored/\n");
    appDbFile = path.join(root, "4da.db");
    // The app indexed the root and the ignored directory, never svc/.
    buildAppDb(appDbFile, VENDORED_APP_SCHEMA, (raw) => {
      appDependency(raw, project, "lodash", "4.17.20");
      appDependency(raw, path.join(project, "ignored"), "qs", "6.5.2");
    });
    before = snapshotDb(appDbFile);
    const calls = CALLS.map(([name, args]): [string, Record<string, unknown>] => [name, args.project_path === "<project>" ? { ...args, project_path: project } : args]);
    [app, standalone] = await Promise.all([appModeSession(project, appDbFile, calls, OSV), appModeSession(project, null, calls, OSV)]);
  }, 120_000);

  afterAll(() => {
    fs.rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
  });

  it("runs against the app's database (not a standalone store)", () => {
    expect(app.stderr).toContain("Database validated");
    expect(app.stderr).not.toContain("standalone mode enabled");
  });

  it("scans the sub-project the app never indexed, and says what it left out", () => {
    const [concise, detailed] = app.results;
    const packages = ((concise.vulnerable_packages as Row[]) ?? []).map((r) => `${r.package}@${r.current_version}`).sort();
    expect(packages).toEqual(["lodash@4.17.20", "minimist@1.2.5"]);
    expect(concise.coverage).toBeTypeOf("object");
    expect(concise.coverage).not.toBeNull();
    expect(detailed.coverage).toBeTypeOf("object");
    expect(detailed.coverage).not.toBeNull();
  });

  it("asked about the sub-project's package, it reports it, never 'not in this project's lockfiles'", () => {
    const one = app.results[2];
    expect(JSON.stringify(one)).not.toMatch(/not in this project's lockfiles/);
    expect(((one.vulnerable_packages as Row[]) ?? []).map((r) => r.package)).toEqual(["minimist"]);
  });

  it("an explicit project_path naming the start directory reads the disk too", () => {
    const one = app.results[4];
    expect(((one.vulnerable_packages as Row[]) ?? []).map((r) => `${r.package}@${r.current_version}`)).toEqual(["minimist@1.2.5"]);
    expect(scanFacts(one)).toEqual(scanFacts(standalone.results[4]));
  });

  it("the briefing for a task on the sub-project's package is not safe to delegate", () => {
    const briefing = JSON.stringify(app.results[3]);
    expect(briefing).toContain("minimist");
    expect(briefing).not.toMatch(/safe_to_delegate/);
  });

  it("a directory .gitignore excludes is not scanned even though the app lists it, and coverage names it", () => {
    const [concise] = app.results;
    expect(((concise.vulnerable_packages as Row[]) ?? []).map((r) => r.package)).not.toContain("qs");
    const coverage = concise.coverage as { complete: boolean; not_scanned?: { lockfiles?: Array<{ path: string; reason: string }> } };
    expect(coverage.complete).toBe(false);
    expect(coverage.not_scanned?.lockfiles).toContainEqual({ path: "ignored/package-lock.json", reason: "gitignored_directory" });
  });

  it("gives the same packages, counts and coverage as the same tree without the app database", () => {
    expect(scanFacts(app.results[0])).toEqual(scanFacts(standalone.results[0]));
    expect(scanFacts(app.results[2])).toEqual(scanFacts(standalone.results[2]));
    expect((app.results[1] as { coverage?: unknown }).coverage).toEqual((standalone.results[1] as { coverage?: unknown }).coverage);
  });

  it("never writes the scan into the app's database", () => {
    const after = snapshotDb(appDbFile);
    expect(after.schema).toEqual(before.schema);
    expect(changedTables(before, after)).toEqual([]);
  });
});
