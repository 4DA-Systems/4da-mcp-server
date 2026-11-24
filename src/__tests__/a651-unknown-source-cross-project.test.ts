// SPDX-License-Identifier: Apache-2.0
/**
 * A name withheld in one project because where it comes from could not be determined is withheld
 * in another project too, as a non-registry name is. Check of round 2 (2026-11-24, cases xp2, xp):
 * a name declared through a catalog that could not be read (`!!str` tag, a repeated key) was left out
 * of the cross-project list, so a briefing for project B sent it to OSV and the registry. Also a
 * name beside a lockfile that could not be read. Stubbed fetch: nothing leaves the machine.
 */

import * as path from "node:path";
import Database from "better-sqlite3";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { LiveIntelligence } from "../live/index.js";
import { resetPrivateGuard } from "../live/private-guard.js";
import { scanProjectTree, treeResolutionGroups } from "../project-tree.js";
import { executeDependencyCheck } from "../tools/dependency-check.js";
import { executeDependencyHealth } from "../tools/dependency-health.js";
import { executeWhatShouldIKnow } from "../tools/what-should-i-know.js";
import { createHarness, type Harness } from "./helpers/a1119-planner-harness.js";

let h: Harness;
let bodies: string[];
const INVENTED = /acme/i;
const sent = () => [...h.requests, ...bodies].map((s) => decodeURIComponent(s));
const leaked = () => sent().filter((s) => INVENTED.test(s));

beforeEach(() => {
  resetPrivateGuard();
  h = createHarness();
  bodies = [];
  const inner = globalThis.fetch;
  vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
    if (init?.body) bodies.push(String(init.body));
    return inner(input, init);
  });
  h.NPM = { ms: { latest: "2.1.3", versions: { "2.1.3": {} } } };
  for (const p of ["a", "b"]) h.write(`${p}/.git/HEAD`, "ref: refs/heads/main\n");
  h.write("b/package.json", JSON.stringify({ name: "b", version: "1.0.0", dependencies: { ms: "2.1.3" } }));
});
afterEach(() => {
  h.dispose();
  resetPrivateGuard();
});

function liveIn(dir: string): LiveIntelligence {
  const li = new LiveIntelligence(new Database(":memory:"));
  const { entries, discovery } = scanProjectTree(dir);
  li.initFromProjectTree(dir, treeResolutionGroups(entries), discovery);
  return li;
}

async function askFromB(names: string[]) {
  const b = path.join(h.dir, "b");
  const a = liveIn(path.join(h.dir, "a"));
  await executeDependencyHealth(null, {}, a);
  await executeWhatShouldIKnow(null, { task: `add ${names.join(" and ")}`, project_path: b }, a);
  await executeDependencyCheck(null, { items: names.map((p) => ({ ecosystem: "npm", package: p, to: "1.0.1" })) }, liveIn(b));
}

describe("withheld in another project too", () => {
  it("a name declared through a catalog that could not be read (a !!str tag)", async () => {
    h.write("a/package.json", JSON.stringify({ name: "a", version: "1.0.0", dependencies: { "acme-tag": "catalog:", ms: "2.1.3" } }));
    h.write("a/pnpm-workspace.yaml", "packages:\n  - '.'\ncatalog:\n  acme-tag: !!str link:../acme-tag\n");
    await askFromB(["acme-tag"]);
    expect(leaked()).toEqual([]);
    // Worded as what it is in the other project (final check: "comes from declared through ...").
    const r = (await executeDependencyCheck(null, { items: [{ ecosystem: "npm", package: "acme-tag", to: "1.0.1" }] }, liveIn(path.join(h.dir, "b")))) as { results: Array<{ reason: string }> };
    expect(r.results[0].reason).toContain(`in ${path.join(h.dir, "a")}, acme-tag is declared through a catalog that could not be read (`);
    expect(r.results[0].reason).not.toMatch(/comes from declared|not a registry release/);
  });

  it("every name of a catalog that repeats a key", async () => {
    h.write("a/package.json", JSON.stringify({ name: "a", version: "1.0.0", dependencies: { "acme-one": "catalog:", "acme-two": "catalog:", ms: "2.1.3" } }));
    h.write("a/pnpm-workspace.yaml", "catalog:\n  acme-one: link:../one\n  acme-one: ^1.0.0\n  acme-two: link:../two\n");
    await askFromB(["acme-one", "acme-two"]);
    expect(leaked()).toEqual([]);
  });

  it("a name beside a lockfile that could not be read", async () => {
    h.write("a/package.json", JSON.stringify({ name: "a", version: "1.0.0", dependencies: { "acme-unread": "^1.0.0", ms: "2.1.3" } }));
    h.write("a/package-lock.json", '{"name":"a","lockfileVersion":3,"packages":{');
    await askFromB(["acme-unread"]);
    expect(leaked()).toEqual([]);
  });
});
