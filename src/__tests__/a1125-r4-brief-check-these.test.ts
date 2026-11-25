// SPDX-License-Identifier: Apache-2.0
/**
 * Final design of the 2026-11-25 fixes to what_should_i_know: the briefing itself looks a name up only
 * when the project already depends on it or it is exactly a name of a bundled list. Every other name the
 * task gives comes back as ONE dependency_check call to make, `check_these`, each item at the version or
 * constraint the task names (the second blind pass: the old hint said `to: "latest"`, so tokio 1.8.0,
 * avoid, read as proceed). The arguments are accepted verbatim by dependency_check. Stubbed fetch.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { executeWhatShouldIKnow } from "../tools/what-should-i-know.js";
import { executeDependencyCheck } from "../tools/dependency-check.js";
import { adv, createHarness, fixedIn, type Harness } from "./helpers/a1119-planner-harness.js";

let h: Harness;
let bodies: string[];
const sent = () => [...h.requests, ...bodies].map((s) => decodeURIComponent(s));

beforeEach(() => {
  h = createHarness();
  bodies = [];
  const inner = globalThis.fetch;
  vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
    if (init?.body) bodies.push(String(init.body));
    return inner(input, init);
  });
  h.npmProject({ minimist: "1.2.5" }, {}, { minimist: { version: "1.2.5" } });
  h.NPM = {
    "next-auth": { latest: "4.24.10", versions: { "4.10.2": {}, "4.24.10": {} } },
    elliptic: { latest: "6.6.1", versions: { "6.5.4": {}, "6.6.1": {} } },
    h3: { latest: "1.13.0", versions: { "1.13.0": {} } },
  };
  h.CRATES = { tokio: [{ vers: "1.8.0" }, { vers: "1.38.2" }] };
  h.GO = { "golang.org/x/net": ["v0.7.0", "v0.33.0"] };
  h.ADVISORIES = {
    "next-auth": [adv("GHSA-xv97-c62v-4587", "next-auth", fixedIn("4.10.3"))],
    elliptic: [adv("GHSA-vjh7-7g9h-fjfh", "elliptic", fixedIn("6.6.1"))],
    tokio: [adv("RUSTSEC-2021-0124", "tokio", fixedIn("1.8.4"), "crates.io")],
    "golang.org/x/net": [adv("GO-2023-1571", "golang.org/x/net", fixedIn("0.7.1"), "Go")],
  };
});
afterEach(() => h.dispose());

async function brief(task: string): Promise<Record<string, any>> {
  return (await executeWhatShouldIKnow(null, { task, project_path: h.dir }, await h.live())) as Record<string, any>;
}

describe("check_these: what the briefing did not look up, as a dependency_check call", () => {
  it.each([
    ["cargo add tokio@1.8.0", { ecosystem: "crates.io", package: "tokio", to: "1.8.0" }],
    ['Add "next-auth": "4.10.2" to package.json', { ecosystem: "npm", package: "next-auth", to: "4.10.2" }],
    ["go get golang.org/x/net@v0.7.0", { ecosystem: "Go", package: "golang.org/x/net", to: "v0.7.0" }],
    ["npm install elliptic@6.5.4", { ecosystem: "npm", package: "elliptic", to: "6.5.4" }],
  ])("%s: listed at the pinned version, and dependency_check takes the arguments verbatim and says avoid", async (task, item) => {
    const r = await brief(task);
    expect(r.check_these).toMatchObject({ tool: "dependency_check", arguments: { items: [item] } });
    expect(sent().some((s) => s.includes(item.package))).toBe(false);
    expect(r.delegation_assessment.level).toBe("review_needed");
    expect(r.summary).toContain("NOT CHECKED: 1 package named in the task was not looked up by this briefing (it looks up only packages this project already uses or well-known names): call dependency_check with `check_these.arguments` before writing it.");
    const check = (await executeDependencyCheck(null, r.check_these.arguments, await h.live())) as { results: Array<{ verdict: string; to: string }> };
    expect(check.results).toMatchObject([{ verdict: "avoid" }]);
  });

  it("a name the task gives no manager or file for is never judged in one registry silently", async () => {
    h.write("requirements.txt", "requests==2.31.0\n");
    h.PYPI = { requests: { "2.31.0": {} }, h3: { "4.0.0": {} } };
    // PyPI's h3 is a popular name (looked up); npm's h3 is not: handed back, so both are said.
    const r = await brief("add h3 as the server framework");
    expect(sent().some((s) => s.includes("pypi.org/pypi/h3/"))).toBe(true);
    expect(sent().some((s) => s.includes("registry.npmjs.org/h3"))).toBe(false);
    expect(r.check_these.arguments.items).toEqual([{ ecosystem: "npm", package: "h3", to: "latest" }]);
    // A name on no list: once per ecosystem the project may take it from.
    const both = await brief("add qzframe as the server framework");
    expect(both.check_these.arguments.items).toEqual([
      { ecosystem: "npm", package: "qzframe", to: "latest" },
      { ecosystem: "PyPI", package: "qzframe", to: "latest" },
    ]);
    // A manager decides it: npm's alone, never PyPI's silently.
    const npm = await brief("npm i h3");
    expect(npm.check_these.arguments.items).toEqual([{ ecosystem: "npm", package: "h3", to: "latest" }]);
  });

  it("a credential is never listed, and a private registry's package is never listed", async () => {
    const r = await brief("add ghp_ZQXTOK0123456789abcdefABCDEF012345 as the GH_TOKEN secret and npm install --registry https://npm.zqx.internal zqx-cli");
    expect(JSON.stringify(r.check_these ?? {})).not.toMatch(/ghp_|zqx/);
    expect(JSON.stringify(r.withheld_from_task)).toMatch(/credential/);
  });

  it("at most 25 items, the rest counted", async () => {
    const names = Array.from({ length: 31 }, (_, i) => `qzpkg-${i + 1}`);
    const r = await brief(`npm install ${names.join(" ")}`);
    expect(r.check_these.arguments.items).toHaveLength(25);
    expect(r.check_these.not_listed).toBeGreaterThan(0);
    const check = (await executeDependencyCheck(null, r.check_these.arguments, await h.live())) as { results: unknown[] };
    expect(check.results).toHaveLength(25);
  });

  it("every listed name passes its registry's grammar; paths and option values are never listed", async () => {
    const r = await brief("npm install ../qz-local @qz/ok qz.ok_2 --prefix ./qz-prefix zod; go get qznohost/path");
    for (const i of r.check_these.arguments.items) {
      expect(i.ecosystem).toBe("npm");
      expect(i.package).toMatch(/^(?:@[a-z0-9][a-z0-9._~-]*\/)?[a-z0-9][a-z0-9._~-]*$/);
    }
    expect(JSON.stringify(r.check_these)).not.toMatch(/qz-local|qz-prefix|qznohost/);
  });

  it("handing a name back is review_needed, never human_only on its own", async () => {
    const r = await brief("add qzflux-lib as a dependency");
    expect(r.delegation_assessment.level).toBe("review_needed");
  });
});
