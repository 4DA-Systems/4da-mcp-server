// SPDX-License-Identifier: Apache-2.0
/**
 * Third blind check of the 2026-11-25 fixes, item 3 (also in 6.5.1): "the project already depends on it"
 * matched a dependency of ANY ecosystem, and a Go module by its last path segment. With a PyPI
 * dependency `zqx-pyonly`, "npm install zqx_pyonly" sent npm:zqx_pyonly; with a go.mod requiring
 * git.zqxcorp.net/team/zqx-pay-engine, "npm install zqx-pay-engine" and "pip install zqx-pay-engine" were
 * looked up, and "npm install core" sent npm:core. The rule holds only inside the dependency's own
 * ecosystem, with its own name rule, and for Go only for the full module path; another manager's
 * operand is listed in unverified_words for THAT ecosystem. Stubbed fetch: nothing leaves the machine.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { executeWhatShouldIKnow } from "../tools/what-should-i-know.js";
import { createHarness, type Harness } from "./helpers/a1119-planner-harness.js";

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
  h.write("requirements.txt", "zqx-pyonly==1.0.0\n");
  h.write("go.mod", "module example.com/app\n\ngo 1.22\n\nrequire git.zqxcorp.net/team/zqx-pay-engine v1.0.0\n");
  h.write("go.sum", "git.zqxcorp.net/team/zqx-pay-engine v1.0.0 h1:aaaa=\ngit.zqxcorp.net/team/zqx-pay-engine v1.0.0/go.mod h1:bbbb=\n");
});
afterEach(() => h.dispose());

async function brief(task: string): Promise<Record<string, any>> {
  return (await executeWhatShouldIKnow(null, { task, project_path: h.dir }, await h.live())) as Record<string, any>;
}

/** Requests that ask an ecosystem's registry or OSV.dev about `name` under that ecosystem. */
const askedIn = (ecosystem: "npm" | "PyPI", name: string) =>
  sent().filter((s) =>
    ecosystem === "npm"
      ? s.startsWith(`https://registry.npmjs.org/${name}`) || new RegExp(`"name":"${name}","ecosystem":"npm"|"ecosystem":"npm","name":"${name}"`, "i").test(s)
      : s.startsWith(`https://pypi.org/pypi/${name}/`) || new RegExp(`"name":"${name}","ecosystem":"PyPI"|"ecosystem":"PyPI","name":"${name}"`, "i").test(s),
  );

describe("a dependency of one ecosystem is not evidence in another", () => {
  it.each([
    ["npm install zqx_pyonly", "npm", "zqx_pyonly"],
    ["npm install zqx-pay-engine", "npm", "zqx-pay-engine"],
    ["pip install zqx-pay-engine", "PyPI", "zqx-pay-engine"],
    ["npm install core", "npm", "core"],
  ] as const)("%s is not looked up; it is listed for %s", async (task, ecosystem, name) => {
    const r = await brief(task);
    expect(askedIn(ecosystem, name)).toEqual([]);
    expect(r.unverified_words).toMatchObject([{ word: name, read_as: ecosystem }]);
  });

  it("inside its own ecosystem, with its name rule, a dependency is still looked up", async () => {
    await brief("pip install zqx_pyonly==1.0.1");
    expect(askedIn("PyPI", "zqx-pyonly").length + askedIn("PyPI", "zqx_pyonly").length).toBeGreaterThan(0);
  });
});
