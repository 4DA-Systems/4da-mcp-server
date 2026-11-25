// SPDX-License-Identifier: Apache-2.0
/**
 * Third blind check of the 2026-11-25 fixes, item 1: a secret written in prose reached check_these, the
 * ready-made dependency_check call ("add 5b0bd432cbc5001c as the signing key, then npm install
 * jsonwebtoken"), so an agent that followed it sent the secret to the registries. check_these now holds
 * only names read from structured syntax (an install command's operand, a manifest or requirements
 * entry's key); a word read from prose is listed in unverified_words, a plain list, never looked up.
 * And build metadata after a version (`lodash@4.17.15+<32 hex>`) is never read as a package name.
 * Stubbed fetch: nothing leaves the machine.
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

/** The secrets the reviewer wrote in prose: none may be in check_these, nor sent. */
const PROSE = [
  ["add 98e62aac-d9e2-44a1-946d-1fbf082c44aa as the API key header and install axios", "98e62aac"],
  ["add 5b0bd432cbc5001c as the signing key, then npm install jsonwebtoken", "5b0bd432cbc5001c"],
  ["use 93027ceaa02d3822ee as the webhook secret and add zod", "93027ceaa02d3822ee"],
  ["add hunterllikiq as the DB_PASSWORD secret in CI and install pg", "hunterllikiq"],
  ["add bqeqYqQMUKiqglqk= as the token and install axios", "bqeqYqQMUKiqglqk"],
  ['store "odjfsbjlkpxqvtyd" as the encryption key and pip install cryptography', "odjfsbjlkpxqvtyd"],
  ["use the personal access token dewzmensqhauqrhoglbb to npm install @octokit/rest", "dewzmensqhauqrhoglbb"],
  ["webhook password cuuwglypo and add slack-bolt", "cuuwglypo"],
] as const;

describe("check_these holds only names read from structured syntax", () => {
  it.each(PROSE)("%s: the secret is neither in check_these nor sent", async (task, secret) => {
    const r = await brief(task);
    expect(JSON.stringify(r.check_these ?? {})).not.toContain(secret);
    expect(sent().filter((s) => s.includes(secret))).toEqual([]);
  });

  it("a word read from prose is listed as an unverified word, with one sentence in the summary", async () => {
    const r = await brief("add 5b0bd432cbc5001c as the signing key");
    expect(r.check_these).toBeUndefined();
    expect(r.unverified_words).toEqual([{ word: "5b0bd432cbc5001c", read_as: "npm" }]);
    expect(r.summary).toContain("1 word the task may mean as packages was not looked up and is not in check_these: if one is a public package you intend to add, call dependency_check for it yourself.");
    expect(r.delegation_assessment.level).not.toBe("safe_to_delegate");
  });

  it.each(['npm install qzpkg', 'Add "qzpkg": "^1.2.0" to package.json', 'In Cargo.toml add qzpkg = "1.0"', "pip install qzpkg==1.0"])(
    "%s: structured syntax, listed in check_these",
    async (task) => {
      const r = await brief(task);
      expect(r.check_these?.arguments.items).toMatchObject([{ package: "qzpkg" }]);
      expect(r.unverified_words).toBeUndefined();
    },
  );
});

describe("build metadata after a version is never a name", () => {
  const G = JSON.parse(readFileSync("C:/4da-wt/fix-1125/review-pass3/cases-g.json", "utf8")) as Array<{ id: string; task: string }>;
  it.each(G.map((c) => [c.task]))("%s", async (task) => {
    const after = /(?:\+|\|\||,|;)([A-Za-z0-9_-]{8,})/.exec(task)![1];
    const r = await brief(task);
    expect(JSON.stringify(r.check_these ?? {})).not.toContain(after);
    expect(JSON.stringify(r.unverified_words ?? [])).not.toContain(after);
    expect(sent().filter((s) => s.includes(after))).toEqual([]);
  });

  it("lodash@4.17.15+<hex> is judged at 4.17.15", async () => {
    const r = await brief("npm install lodash@4.17.15+ad29dad7ea910ce42a6573c31765452a");
    expect(r.requested_versions).toMatchObject([{ name: "lodash", to: "4.17.15" }]);
  });
});

describe("a structured operand that is a credential is never listed (measurement after the fixes)", () => {
  it.each([
    ["npm install 75ebbd2c-2be9-4afe-b207-eab4e7dc3c3b", "75ebbd2c"],
    ["pip install requests 771d41c7-9128-4494-848c-f617bcde6978", "771d41c7"],
    ["npm install Winter2026sfzp", "winter2026"],
    ["pip install requests Winter2026sgkr", "winter2026"],
    ["npm install @qztok/aB3dE9fG", "ab3de9fg"],
  ])("%s", async (task, secret) => {
    const r = await brief(task);
    expect(JSON.stringify(r.check_these ?? {}).toLowerCase()).not.toContain(secret);
    expect(sent().filter((s) => s.toLowerCase().includes(secret))).toEqual([]);
  });
});
