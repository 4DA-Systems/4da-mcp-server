// SPDX-License-Identifier: Apache-2.0
/**
 * The first call's lockfile resolution runs in steps (pre-publish round 10, W11): it was one
 * synchronous stretch of 2.3 s on a 150,000-entry pnpm-lock.yaml, and a `ping` sent meanwhile
 * waited for all of it. These check that the stepped run gives the event loop turns, that it
 * resolves exactly what the synchronous run does (an unchecked dependency stays unchecked, a
 * damaged lockfile stays reported), and that a synchronous init meanwhile supersedes it.
 */
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { LiveIntelligence } from "../live/index.js";
import { emptyReadReport, pnpmLockDamage, pnpmLockDamageSteps, readPnpmLock, readPnpmLockSteps } from "../live/js-lockfile-readers.js";
import { InstanceSet } from "../live/lockfile-types.js";
import { runSteps, runStepsYielding } from "../live/yield-point.js";
import { scanProjectTree, treeResolutionGroups } from "../project-tree.js";

function lockOf(n: number, { truncate = false, git = false } = {}): string {
  const lines = ["lockfileVersion: '9.0'", "", "importers:", "  .:", "    dependencies:", "      pkg0:", "        specifier: ^1.0.0", "        version: 1.0.0", "      gone:", "        specifier: ^2.0.0", "        version: 2.0.0", "", "packages:"];
  for (let i = 0; i < n; i++) lines.push(`  pkg${i}@1.0.${i === 0 ? 0 : i % 50}:`, "    resolution: {integrity: sha512-AAAA}");
  if (git) lines.push("  from-git@https://codeload.github.com/acme/x/tar.gz/abc:", "    resolution: {tarball: https://codeload.github.com/acme/x/tar.gz/abc}", "    version: 1.0.0");
  lines.push("", "snapshots:");
  for (let i = 0; i < (truncate ? n / 2 : n); i++) lines.push(`  pkg${i}@1.0.${i === 0 ? 0 : i % 50}:`, "    dependencies:", `      pkg${(i + 1) % n}: 1.0.${(i + 1) % 50}`);
  return lines.join("\n") + "\n";
}

const dirs: string[] = [];
function project(lock: string): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "w11-steps-"));
  dirs.push(dir);
  fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ name: "w11", dependencies: { pkg0: "^1.0.0", gone: "^2.0.0" } }));
  fs.writeFileSync(path.join(dir, "pnpm-lock.yaml"), lock);
  return dir;
}
afterAll(() => {
  for (const dir of dirs) fs.rmSync(dir, { recursive: true, force: true });
});

/** What a live layer resolved, with the times taken out. */
function state(live: LiveIntelligence): string {
  const l = live as unknown as Record<string, unknown>;
  return JSON.stringify(
    {
      resolved: l.resolvedDeps,
      audit: l.auditDeps,
      privateDeps: l.privateDeps,
      problems: live.getLockfileProblems(),
      uncheckable: live.getUncheckableDependencies(),
      unresolved: live.getUnresolvedManifests(),
      sources: live.getResolutionProvenance()?.sources.map((s) => s.path),
    },
    (key, value) => (key === "resolvedAt" || key === "mtimeMs" ? undefined : value),
  );
}

describe("lockfile resolution in steps (W11)", () => {
  it("the stepped readers return what the synchronous ones do", () => {
    for (const text of [lockOf(5000), lockOf(5000, { truncate: true, git: true })]) {
      const a = { versions: new Map<string, string>(), instances: new InstanceSet(), report: emptyReadReport() };
      const b = { versions: new Map<string, string>(), instances: new InstanceSet(), report: emptyReadReport() };
      const seenA = readPnpmLock(text, a.versions, a.instances, a.report);
      const seenB = runSteps(readPnpmLockSteps(text, b.versions, b.instances, b.report));
      expect([...seenB]).toEqual([...seenA]);
      expect([...b.versions]).toEqual([...a.versions]);
      expect(b.instances.toArray()).toEqual(a.instances.toArray());
      expect(b.report).toEqual(a.report);
      expect(runSteps(pnpmLockDamageSteps(text, b.report.missingDirect, seenB))).toEqual(pnpmLockDamage(text, a.report.missingDirect, seenA));
    }
  });

  it("gives the event loop turns while a large lockfile resolves, and resolves the same set", async () => {
    const dir = project(lockOf(60_000));
    const tree = scanProjectTree(dir);
    const sync = new LiveIntelligence(null);
    sync.initFromProjectTree(dir, treeResolutionGroups(tree.entries), tree.discovery);

    const stepped = new LiveIntelligence(null);
    let turns = 0;
    let more = true;
    const tick = () => {
      turns++;
      if (more) setImmediate(tick);
    };
    setImmediate(tick);
    const done = await stepped.initFromProjectTreeYielding(dir, treeResolutionGroups(tree.entries), tree.discovery);
    more = false;
    expect(done).toBe(true);
    expect(turns).toBeGreaterThan(1);
    expect(state(stepped)).toBe(state(sync));
  });

  it("keeps a damaged lockfile reported, and its unreadable entries unchecked, when run in steps", async () => {
    const dir = project(lockOf(4000, { truncate: true, git: true }));
    const tree = scanProjectTree(dir);
    const sync = new LiveIntelligence(null);
    sync.initFromProjectTree(dir, treeResolutionGroups(tree.entries), tree.discovery);
    const stepped = new LiveIntelligence(null);
    await stepped.initFromProjectTreeYielding(dir, treeResolutionGroups(tree.entries), tree.discovery);
    expect(stepped.getLockfileProblems().length).toBeGreaterThan(0);
    expect(stepped.getUncheckableDependencies().map((u) => u.name)).toContain("from-git");
    expect(state(stepped)).toBe(state(sync));
  });

  it("stops, and leaves the set alone, when a synchronous init runs meanwhile", async () => {
    const big = project(lockOf(60_000));
    const small = project(lockOf(10));
    const bigTree = scanProjectTree(big);
    const smallTree = scanProjectTree(small);
    const live = new LiveIntelligence(null);
    const running = live.initFromProjectTreeYielding(big, treeResolutionGroups(bigTree.entries), bigTree.discovery);
    // A caller that cannot wait (getDatabase) finishes an init synchronously at the first turn given.
    await new Promise((resolve) => setImmediate(resolve));
    live.initFromProjectTree(small, treeResolutionGroups(smallTree.entries), smallTree.discovery);
    const expected = state(live);
    expect(await running).toBe(false);
    expect(state(live)).toBe(expected);
    expect(live.getResolutionProvenance()?.sources.map((s) => path.dirname(s.path))).toEqual([small]);
  });

  it("a superseded run reports it rather than a result", async () => {
    let current = true;
    function* work() {
      yield;
      current = false;
      for (let i = 0; i < 1e7; i++) if ((i & 1023) === 0) yield;
      return "done";
    }
    const out = await runStepsYielding(work(), () => current, "superseded");
    expect(out).toBe("superseded");
  });
});
