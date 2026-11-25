// SPDX-License-Identifier: Apache-2.0
/**
 * Fourth blind check of the 2026-11-25 fixes, item 2: the command reader read past the end of a command.
 * `npm install lodash && git push origin feature-x` listed git, push, origin, feature-x; `npm install pg
 * && psql -U admin -W pw` listed psql and pw; `npm install lodash --auth admin:hunter2` listed hunter2;
 * abbreviated private-registry options (`-ihttps://...`, `--reg URL`, `YARN_REGISTRY=`) left the private
 * package readable. A shell or sentence separator now ends the operands; a shell variable or expansion
 * and a word with a colon inside are never names, and a value is never repeated. Stubbed fetch.
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
  h.NPM = { lodash: { latest: "4.17.21", versions: { "4.17.21": {} } }, pg: { latest: "8.13.0", versions: { "8.13.0": {} } } };
});
afterEach(() => h.dispose());

async function brief(task: string): Promise<Record<string, any>> {
  return (await executeWhatShouldIKnow(null, { task, project_path: h.dir }, await h.live())) as Record<string, any>;
}

/** Every word the answer names as a package, looked up or not. */
const named = (r: Record<string, any>) => [
  ...(r.unverified_words ?? []).map((w: { word: string }) => w.word),
  ...(r.new_packages ?? []).map((p: { name: string }) => p.name),
  ...(r.requested_versions ?? []).map((p: { name: string }) => p.name),
];

describe("a separator ends the command's operands", () => {
  it.each([
    "npm install lodash && git push origin feature-x",
    "npm install lodash; cargo build",
    "npm install lodash || npx tsc",
    "npm install lodash | tee log.txt",
    "npm install lodash & npm run dev",
    "npm install lodash > out.txt",
    "npm install lodash < in.txt",
    "npm install lodash # then commit",
    "npm install lodash // the util",
    "npm install lodash\ngit push origin main",
    "npm install lodash, then build it",
    "npm install lodash (the util) and test",
    "npm install lodash — the util",
    "run `npm install lodash` then `git push`",
  ])("%s", async (task) => {
    const r = await brief(task);
    expect(named(r)).toEqual(["lodash"]);
  });

  it("npm install pg && psql -U admin -W pw: psql and pw are no packages", async () => {
    const r = await brief("npm install pg && psql -U admin -W pw");
    expect(named(r)).toEqual(["pg"]);
    expect(sent().some((s) => /\bpw\b|psql/.test(s))).toBe(false);
  });
});

describe("shell expansions and colon words are never names, and never repeated", () => {
  it.each(["npm install $(cat pkgs.txt)", "npm install $PKG", "npm install %PKG%", "npm install ${PKG}"])("%s: not read, and not safe", async (task) => {
    const r = await brief(task);
    expect(named(r)).toEqual([]);
    expect(r.delegation_assessment.level).not.toBe("safe_to_delegate");
  });

  it.each(["npm install lodash --auth admin:hunter2", "npm install lodash user:hunter2"])("%s", async (task) => {
    const r = await brief(task);
    expect(named(r)).toEqual(["lodash"]);
    expect(JSON.stringify({ ...r, task: undefined })).not.toContain("hunter2");
    expect(sent().some((s) => s.includes("hunter2"))).toBe(false);
  });
});

describe("an abbreviated or glued private registry is a private source", () => {
  it.each([
    "npm install -ihttps://npm.zqx.internal zqx-cli",
    "npm install --reg https://npm.zqx.internal zqx-cli",
    "YARN_REGISTRY=https://npm.zqx.internal yarn add zqx-cli",
  ])("%s", async (task) => {
    const r = await brief(task);
    expect(named(r)).toEqual([]);
    expect(sent().some((s) => s.includes("zqx"))).toBe(false);
    expect(r.delegation_assessment.level).not.toBe("safe_to_delegate");
  });
});
