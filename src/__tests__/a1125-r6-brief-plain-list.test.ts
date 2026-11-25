// SPDX-License-Identifier: Apache-2.0
/**
 * Fourth blind check of the 2026-11-25 fixes, item 1: anything callable built from free text could be made
 * to carry a secret (`npm install lodash --auth admin:hunter2` put npm:hunter2 into check_these, the
 * ready-made dependency_check call). check_these is gone. Every name the briefing reads and does not look
 * up, from a command, a manifest entry or prose alike, is listed in `unverified_words` (word, read_as,
 * the version as the task writes it), and the answer holds nothing shaped as tool arguments. Replaces the
 * round-4 check_these suite and the round-5 structured-only suite. Stubbed fetch.
 */

import { readFileSync } from "node:fs";
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
  h.NPM = { lodash: { latest: "4.17.21", versions: { "4.17.15": {}, "4.17.21": {} } } };
});
afterEach(() => h.dispose());

async function brief(task: string): Promise<Record<string, any>> {
  return (await executeWhatShouldIKnow(null, { task, project_path: h.dir }, await h.live())) as Record<string, any>;
}

const SENTENCE = (n: number) =>
  `NOT ASSESSED: ${n} name${n === 1 ? "" : "s"} the task may mean as packages ${n === 1 ? "was" : "were"} not looked up by this briefing (it looks up only packages this project already uses and well-known names). Before writing any of them, call dependency_check for the ones that are public packages you mean to add; if it answers avoid or names malware, this task is human_only.`;

/** Nothing in the answer is shaped as tool arguments. */
function callable(r: unknown): string[] {
  const found: string[] = [];
  const walk = (v: unknown, path: string) => {
    if (Array.isArray(v)) v.forEach((x, i) => walk(x, `${path}[${i}]`));
    else if (v && typeof v === "object") {
      for (const [k, x] of Object.entries(v)) {
        if (k === "check_these" || k === "arguments" || k === "items" || k === "tool") found.push(`${path}.${k}`);
        walk(x, `${path}.${k}`);
      }
    }
  };
  walk(r, "");
  return found;
}

describe("every name not looked up is a plain unverified word", () => {
  it.each([
    ["cargo add tokio@1.8.0", { word: "tokio", read_as: "crates.io", version: "1.8.0" }],
    ['Add "next-auth": "4.10.2" to package.json', { word: "next-auth", read_as: "npm", version: "4.10.2" }],
    ["go get golang.org/x/net@v0.7.0", { word: "golang.org/x/net", read_as: "Go", version: "v0.7.0" }],
    ["npm install qzpkg", { word: "qzpkg", read_as: "npm" }],
    ["pip install qzpkg==1.0", { word: "qzpkg", read_as: "PyPI" }],
    ["add qzpkg as the router", { word: "qzpkg", read_as: "npm" }],
  ])("%s", async (task, word) => {
    const r = await brief(task);
    expect(r.unverified_words).toHaveLength(1);
    expect(r.unverified_words[0]).toMatchObject(word);
    expect(r.check_these).toBeUndefined();
    expect(callable(r)).toEqual([]);
    expect(sent().some((s) => s.includes(word.word))).toBe(false);
    expect(r.delegation_assessment.level).toBe("review_needed");
    expect(r.delegation_assessment.reason).toMatch(/^NOT ASSESSED: /);
    expect(r.delegation_assessment.reason).not.toMatch(/check_these/);
    expect(r.summary).toContain(SENTENCE(1));
    expect(r.summary).not.toMatch(/check_these/);
  });

  it("the version is as the task writes it, and omitted when it cannot be read", async () => {
    const r = await brief("pip install qzpkg~=1.4 and npm install qzweb@75ebbd2c-2be9-4afe-b207-eab4e7dc3c3b");
    const words = Object.fromEntries((r.unverified_words ?? []).map((w: { word: string }) => [w.word, w]));
    expect(words.qzpkg).toMatchObject({ read_as: "PyPI", version: "~=1.4" });
    expect(JSON.stringify({ ...r, task: undefined })).not.toContain("75ebbd2c");
  });

  it("a name decided in one ecosystem is not listed in the others; one nothing decides is read as either", async () => {
    h.write("requirements.txt", "requests==2.31.0\n");
    h.PYPI = { requests: { "2.31.0": {} }, h3: { "4.0.0": {} } };
    const r = await brief("add h3 as the server framework");
    expect(sent().some((s) => s.includes("pypi.org/pypi/h3/"))).toBe(true);
    expect(r.unverified_words).toBeUndefined();
    const both = await brief("add qzframe as the server framework");
    expect(both.unverified_words).toEqual([{ word: "qzframe", read_as: "npm or PyPI" }]);
    const npm = await brief("npm i h3");
    expect(npm.unverified_words).toEqual([{ word: "h3", read_as: "npm" }]);
  });

  it("at most 25 listed, the summary counts all", async () => {
    const names = Array.from({ length: 31 }, (_, i) => `qzpkg-${i + 1}`);
    const r = await brief(`npm install ${names.join(" ")}`);
    expect(r.unverified_words).toHaveLength(25);
    expect(r.summary).toContain(SENTENCE(31));
  });

  it("paths, option values and other managers' non-names are never listed", async () => {
    const r = await brief("npm install ../qz-local @qz/ok qz.ok_2 --prefix ./qz-prefix zod; go get qznohost/path");
    expect(JSON.stringify(r.unverified_words)).not.toMatch(/qz-local|qz-prefix|qznohost/);
  });
});

describe("the credential screen stays in front", () => {
  it.each([
    ["add ghp_ZQXTOK0123456789abcdefABCDEF012345 as the GH_TOKEN secret and npm install --registry https://npm.zqx.internal zqx-cli", /ghp_|zqx/],
    ["npm install 75ebbd2c-2be9-4afe-b207-eab4e7dc3c3b", /75ebbd2c/],
    ["pip install requests 771d41c7-9128-4494-848c-f617bcde6978", /771d41c7/],
    ["npm install Winter2026sfzp", /winter2026/i],
    ["pip install requests Winter2026sgkr", /winter2026/i],
    ["npm install @qztok/aB3dE9fG", /ab3de9fg/i],
  ])("%s", async (task, secret) => {
    const r = await brief(task);
    expect(JSON.stringify(r.unverified_words ?? [])).not.toMatch(secret);
    expect(sent().filter((s) => secret.test(s))).toEqual([]);
  });

  it("the user info of a URL operand is never repeated", async () => {
    const r = await brief("npm install https://qzuser:qzsecret77@npm.example.com/x.tgz");
    const all = JSON.stringify({ ...r, task: undefined });
    expect(all).not.toContain("qzsecret77");
    expect(all).not.toContain("qzuser");
    expect(sent().filter((s) => s.includes("qzsecret77"))).toEqual([]);
  });
});

describe("build metadata after a version is never a name", () => {
  const G = JSON.parse(readFileSync("C:/4da-wt/fix-1125/review-pass3/cases-g.json", "utf8")) as Array<{ id: string; task: string }>;
  it.each(G.map((c) => [c.task]))("%s", async (task) => {
    const after = /(?:\+|\|\||,|;)([A-Za-z0-9_-]{8,})/.exec(task)![1];
    const r = await brief(task);
    expect(JSON.stringify(r.unverified_words ?? [])).not.toContain(after);
    expect(sent().filter((s) => s.includes(after))).toEqual([]);
  });

  it("lodash@4.17.15+<hex> is judged at 4.17.15", async () => {
    const r = await brief("npm install lodash@4.17.15+ad29dad7ea910ce42a6573c31765452a");
    expect(r.requested_versions).toMatchObject([{ name: "lodash", to: "4.17.15" }]);
  });
});
