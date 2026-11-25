// SPDX-License-Identifier: Apache-2.0
/**
 * Fifth blind check of the 2026-11-25 fixes, item 1 (a blocker, also in 6.5.1): a name the gate allowed
 * because the project depends on it, answered "not found" by its own public registry (what a private
 * dependency gets), was looked up in every other ecosystem: a Python-only project with zqx_tools==1.0.0
 * in requirements.txt sent zqx_tools to registry.npmjs.org, crates.io and OSV.dev as npm and crates.io.
 * No lookup happens outside the gate now, and the project's own dependency is asked about once, in its
 * own ecosystem only. The registries here answer 404 for an unknown name, as the real ones do.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { executeWhatShouldIKnow } from "../tools/what-should-i-know.js";
import { createHarness, type Harness } from "./helpers/a1119-planner-harness.js";

let h: Harness;
let sent: Array<{ url: string; body: string }>;

beforeEach(() => {
  h = createHarness();
  sent = [];
  const inner = globalThis.fetch;
  vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
    sent.push({ url: decodeURIComponent(String(input)), body: init?.body ? String(init.body) : "" });
    return inner(input, init);
  });
  h.write("requirements.txt", "requests==2.25.0\nzqx_tools==1.0.0\n");
  h.PYPI = { requests: { "2.25.0": {} } };
});
afterEach(() => h.dispose());

async function brief(task: string): Promise<Record<string, any>> {
  return (await executeWhatShouldIKnow(null, { task, project_path: h.dir }, await h.live())) as Record<string, any>;
}

const about = (name: string) => sent.filter((s) => `${s.url} ${s.body}`.toLowerCase().includes(name));

describe("no lookup outside the gate", () => {
  it.each(["add zqx_tools", "use zqx_tools for parsing", "add zqx_tools 1.0.0", "bring in zqx_tools"])("%s: never asked about as npm or crates.io", async (task) => {
    await brief(task);
    const asked = about("zqx_tools").concat(about("zqx-tools"));
    expect(asked.filter((s) => /registry\.npmjs\.org|crates\.io/.test(s.url))).toEqual([]);
    expect(asked.filter((s) => /"ecosystem":"(?:npm|crates\.io)"/.test(s.body))).toEqual([]);
  });

  it("the project's own dependency is asked about once per call, on PyPI only", async () => {
    await brief("add zqx_tools 1.0.0 for parsing");
    const registry = sent.filter((s) => /pypi\.org\/pypi\/zqx[-_]tools\//i.test(s.url));
    expect(new Set(registry.map((s) => s.url)).size).toBe(registry.length);
    const osv = sent.filter((s) => /api\.osv\.dev/.test(s.url) && /zqx[-_]tools/i.test(s.body));
    expect(osv.every((s) => /"ecosystem":"PyPI"/.test(s.body))).toBe(true);
  });
});
