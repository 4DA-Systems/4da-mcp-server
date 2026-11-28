// SPDX-License-Identifier: Apache-2.0
/**
 * Round 20 (polish, no new promise): folders that could not be listed are counted apart from lockfiles; a scan that ran
 * and answered nothing names its cause (every installed name private, an unreadable .npmrc, an unreadable lockfile).
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { executeWhatShouldIKnow } from "../tools/what-should-i-know.js";
import { SCAN_ALL_PRIVATE, SCAN_INCOMPLETE, SCAN_LOCKFILE_UNREADABLE, SCAN_NPMRC_UNREADABLE, UNLISTED_FOLDERS } from "../tools/briefing-confirm.js";
import { createHarness, type Harness } from "./helpers/a1119-planner-harness.js";
import { brokenTextRules } from "./helpers/a1137-text-rules.js";

let h: Harness;
beforeEach(() => {
  h = createHarness();
  h.NPM.zod = { latest: "3.24.1", versions: { "3.24.1": {} } };
  h.npmProject({ zod: "3.24.1" }, {}, { zod: { version: "3.24.1" } });
});
afterEach(() => h.dispose());
const args = { task: "Refactor the logger module.", packages: [] };

describe("1: a folder that could not be listed is no lockfile found", () => {
  it.each([1, 3])("%i unlisted folder(s), no lockfile: said as folders, the level unknown", async (n) => {
    const live = await h.live();
    const base = live.getDiscovery?.() ?? null;
    const discovery = { ...(base ?? {}), skipped: Array.from({ length: n }, (_, i) => ({ path: `locked${i}/`, reason: "unreadable" })), skippedCount: n, skippedByReason: { unreadable: n } };
    const r = (await executeWhatShouldIKnow(null, { ...args, project_path: h.dir } as never, Object.assign(Object.create(live), { getDiscovery: () => discovery }))) as Record<string, any>;
    expect(r.delegation_assessment.level).toBe("unknown");
    expect(r.delegation_assessment.reason).toContain(SCAN_INCOMPLETE);
    expect(r.delegation_assessment.reason).toContain(UNLISTED_FOLDERS(n));
    expect(r.delegation_assessment.reason).not.toMatch(/lockfiles? (?:was|were) found/);
    expect(r.folders_not_listed).toBe(n);
    expect(r.lockfiles_not_scanned).toBeUndefined();
    expect(brokenTextRules(r, args)).toEqual([]);
  });
});

describe("2: a scan that ran and answered nothing names its cause", () => {
  const withScan = async (privateExcluded: Record<string, unknown>) => {
    const live = await h.live();
    const scan = { scannedAt: "2026-11-28T00:00:00Z", projectPath: h.dir, ecosystemsScanned: ["npm"], totalScanned: 0, totalVulnerable: 0, platformInactiveVulnerable: 0, bySeverity: { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 }, vulnerabilities: [], cleanCount: 0, scanDurationMs: 1, cached: false, offline: false, privateExcluded };
    const patched = Object.assign(Object.create(live), { ensureVulnerabilities: async () => scan, getVulnerabilities: () => scan });
    return (await executeWhatShouldIKnow(null, { ...args, project_path: h.dir } as never, patched)) as Record<string, any>;
  };
  it("every installed dependency private by configuration", async () => {
    const r = await withScan({ count: 2, dependencies: [] });
    expect(r.delegation_assessment.level).toBe("unknown");
    expect(r.delegation_assessment.reason).toContain(SCAN_ALL_PRIVATE(2));
    expect(r.private_installed).toBe(2);
    expect(brokenTextRules(r, args)).toEqual([]);
  });
  it("an unreadable .npmrc", async () => {
    const r = await withScan({ count: 2, dependencies: [], unreadable: { count: 2, names: ["zod"], files: [".npmrc"] } });
    expect(r.delegation_assessment.reason).toContain(SCAN_NPMRC_UNREADABLE(2));
    expect(r.delegation_assessment.level).toBe("unknown");
    expect(brokenTextRules(r, args)).toEqual([]);
  });
  it("an unreadable lockfile of a sub-project", async () => {
    const r = await withScan({ count: 1, dependencies: [], unreadable: { count: 1, names: ["zod"], files: ["web/package-lock.json"] } });
    expect(r.delegation_assessment.reason).toContain(SCAN_LOCKFILE_UNREADABLE(["web/package-lock.json"]));
    expect(r.delegation_assessment.level).toBe("unknown");
    expect(brokenTextRules(r, args)).toEqual([]);
  });
});

describe("20b: the unreadable .npmrc is named before the all-private cause; one text for an unreadable lockfile", () => {
  const scanWith = async (privateExcluded: Record<string, unknown>) => {
    const live = await h.live();
    const scan = { scannedAt: "2026-11-28T00:00:00Z", projectPath: h.dir, ecosystemsScanned: ["npm"], totalScanned: 0, totalVulnerable: 0, platformInactiveVulnerable: 0, bySeverity: { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 }, vulnerabilities: [], cleanCount: 0, scanDurationMs: 1, cached: false, offline: false, privateExcluded };
    return (await executeWhatShouldIKnow(null, { ...args, project_path: h.dir } as never, Object.assign(Object.create(live), { ensureVulnerabilities: async () => scan, getVulnerabilities: () => scan }))) as Record<string, any>;
  };
  it("an injected .npmrc read failure (the reason each withheld name carries): SCAN_NPMRC_UNREADABLE, not SCAN_ALL_PRIVATE", async () => {
    const why = ".npmrc could not be read (EACCES): it may name a private registry or source for any npm package here, so none is treated as public";
    const r = await scanWith({ count: 1, dependencies: [{ ecosystem: "npm", name: "zod", version: "3.24.1", why, kind: "name" }] });
    expect(r.delegation_assessment.reason).toContain(SCAN_NPMRC_UNREADABLE(1));
    expect(r.delegation_assessment.reason).not.toContain("every installed dependency is private");
    expect(brokenTextRules(r, args)).toEqual([]);
  });
  it.skipIf(process.platform !== "win32")("a real .npmrc the process cannot read (a deny-read ACL), where the platform enforces it", async () => {
    const { execFileSync } = await import("node:child_process");
    const fs = await import("node:fs");
    const path = await import("node:path");
    const file = path.join(h.dir, ".npmrc");
    fs.writeFileSync(file, "save-exact=true\n");
    try {
      execFileSync("icacls", [file, "/deny", "*S-1-1-0:(R)"], { stdio: "ignore" });
    } catch {
      return; // no icacls here: the injected case above stands for it
    }
    let enforced = false;
    try {
      fs.readFileSync(file, "utf8");
    } catch {
      enforced = true;
    }
    try {
      // A process holding the backup privilege reads past a deny ACL (Git Bash on this machine does): nothing to test then.
      if (!enforced) return;
      const r = (await executeWhatShouldIKnow(null, { ...args, project_path: h.dir } as never, await h.live())) as Record<string, any>;
      expect(r.delegation_assessment.level).not.toBe("safe_to_delegate");
      expect(r.delegation_assessment.reason).toContain("the project's .npmrc could not be read");
    } finally {
      execFileSync("icacls", [file, "/remove:d", "*S-1-1-0"], { stdio: "ignore" });
    }
  });
  it("a package-lock.json that is a directory: the lockfile text with its path and error, not the older UNREADABLE note", async () => {
    const fs = await import("node:fs");
    const path = await import("node:path");
    fs.rmSync(path.join(h.dir, "package-lock.json"), { force: true });
    fs.mkdirSync(path.join(h.dir, "package-lock.json"));
    const r = (await executeWhatShouldIKnow(null, { ...args, project_path: h.dir } as never, await h.live())) as Record<string, any>;
    expect(r.delegation_assessment.level).not.toBe("safe_to_delegate");
    expect(r.delegation_assessment.reason).toMatch(/The lockfile package-lock\.json \(EISDIR[^)]*\) could not be read, so its dependencies were not checked\./);
    expect(r.delegation_assessment.reason).not.toMatch(/UNREADABLE: \d+ lockfile/);
    expect(brokenTextRules(r, args)).toEqual([]);
  });
});
