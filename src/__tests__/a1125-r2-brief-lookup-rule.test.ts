// SPDX-License-Identifier: Apache-2.0
/**
 * Re-check of the 2026-11-25 fixes to what_should_i_know (the blind check of the integrated build):
 * 1. a requirement or manifest entry whose NAME holds auth / token / secret / passw (`oauthlib==3.2.0`,
 *    `"jsonwebtoken": "8.5.1"`) was read as a credential setting, its version blanked, and the package
 *    judged at latest: 6.5.1's review_needed became safe_to_delegate. An entry is never a credential, and
 *    a package a withheld span touches is held, never judged at a version the task did not write.
 * 2. the block-list of secret and private-source spellings failed as a block-list does. A word of the task
 *    is now looked up only on positive evidence that it is a public package: installed, popular or a
 *    near-miss of a popular name, or an install command's operand / a manifest entry's key in a task
 *    with no private-source signal for that ecosystem. Everything else is held, said, and never sent.
 * 3. bounded: every 199,000-character shape the reviewer used answers within 2 s of CPU.
 * Stubbed fetch: nothing leaves the machine.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { executeWhatShouldIKnow } from "../tools/what-should-i-know.js";
import { adv, createHarness, fixedIn, type Harness } from "./helpers/a1119-planner-harness.js";
import { waitingWords, notReadWords } from "./helpers/a1127-task-packages.js";

let h: Harness;
let bodies: string[];
const sent = () => [...h.requests, ...bodies].map((s) => decodeURIComponent(s));
const leaked = (pattern: RegExp) => sent().filter((s) => pattern.test(s));
const looked = (name: string) => sent().filter((s) => s.includes(`registry.npmjs.org/${name}`) || s.includes(`pypi.org/pypi/${name}/`) || s.includes(`"name":"${name}"`));

beforeEach(() => {
  h = createHarness();
  bodies = [];
  const inner = globalThis.fetch;
  vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
    if (init?.body) bodies.push(String(init.body));
    return inner(input, init);
  });
  h.npmProject({ minimist: "1.2.5" }, {}, { minimist: { version: "1.2.5" } });
  h.write("requirements.txt", "requests==2.31.0\n");
  h.NPM = {
    lodash: { latest: "4.17.21", versions: { "4.17.21": {} } },
    express: { latest: "4.21.2", versions: { "4.21.2": {} } },
    typescript: { latest: "5.6.3", versions: { "5.6.3": {} } },
    jsonwebtoken: { latest: "9.0.2", versions: { "8.5.1": {}, "9.0.2": {} } },
    "next-auth": { latest: "4.24.10", versions: { "4.10.2": {}, "4.24.10": {} } },
  };
  h.PYPI = { requests: { "2.31.0": {}, "2.32.3": {} }, oauthlib: { "3.2.0": {}, "3.2.2": {} } };
  h.ADVISORIES = {
    oauthlib: [adv("GHSA-3pgj-pg6c-r5p7", "oauthlib", fixedIn("3.2.1"), "PyPI")],
    jsonwebtoken: [adv("GHSA-27h2-hvpr-p74q", "jsonwebtoken", fixedIn("9.0.0"))],
    "next-auth": [adv("GHSA-xv97-c62v-4587", "next-auth", fixedIn("4.10.3"))],
  };
});
afterEach(() => h.dispose());

async function brief(task: string): Promise<Record<string, any>> {
  return (await executeWhatShouldIKnow(null, { task, project_path: h.dir }, await h.live())) as Record<string, any>;
}

describe("1. an entry is never a credential, and a version is never replaced by latest", () => {
  it.each([
    ["pip install oauthlib==3.2.0", "oauthlib", "3.2.0"],
    ['Add "jsonwebtoken": "8.5.1" to package.json', "jsonwebtoken", "8.5.1"],
    ['Add "next-auth": "4.10.2" to package.json', "next-auth", "4.10.2"],
    ["npm install jsonwebtoken@8.5.1", "jsonwebtoken", "8.5.1"],
  ])("%s is judged at the version written", async (task, name, version) => {
    const r = await brief(task);
    expect(r.delegation_assessment.level).not.toBe("safe_to_delegate");
    expect(JSON.stringify(notReadWords(r) ?? [])).not.toContain(name);
    // A listed name is judged by the briefing; any other is listed at the version the task writes (fourth
    // blind check: a plain list, never tool arguments).
    if (r.requested_versions) {
      expect(r.requested_versions).toMatchObject([{ name, to: version, verdict: "avoid" }]);
    } else {
      // Round 7, C7: the entry carries no version; it is checked at that version once declared (C4).
      expect(waitingWords(r)).toContainEqual({ word: name, read_as: "npm" });
    }
  });

  it("a credential-shaped value beside a package name holds the package whole, never judged at latest", async () => {
    const r = await brief('Add "jsonwebtoken": "Zq9xK2Lm8PqR4s" to package.json');
    expect(r.new_packages ?? []).toEqual([]);
    expect(r.requested_versions ?? []).toEqual([]);
    expect(JSON.stringify(notReadWords(r))).toMatch(/jsonwebtoken.*not read whole/);
    expect(r.delegation_assessment.level).not.toBe("safe_to_delegate");
    expect(leaked(/Zq9xK2Lm8PqR4s/)).toEqual([]);
  });
});

describe("2. a word is looked up only on evidence that it is a public package", () => {
  it.each([
    "add hunter2zqx as the DB_PASSWORD secret in CI and install pg",
    "add 550e8400-e29b-41d4-a716-446655440000 as the API key header and install axios",
    "add 9f86d081884c7d65 as the signing key, then npm install jsonwebtoken",
    "add dGhpcyBpcyBzZWNyZXQ= as the token and install axios",
    "add eyJhbGciOiJIUzI1NiJ9 . eyJzdWIiOiJ6cXgifQ . zqxsigpart4242 as the JWT and install jsonwebtoken",
    "add ghp_zqx123 as GH_TOKEN and install octokit",
    "ajoute zqx-fr-lib au projet",
    "NPM_CONFIG_REGISTRY=https://npm.zqxcorp.internal npm i zqx-envreg-a",
    '$env:NPM_CONFIG_REGISTRY = "https://npm.zqxcorp.internal"; npm install zqx-envreg-b',
    "YARN_NPM_REGISTRY_SERVER=https://npm.zqxcorp.internal yarn add zqx-yarnenv",
    "BUN_CONFIG_REGISTRY=https://npm.zqxcorp.internal bun add zqx-bunenv",
    "npm install --config.registry=https://npm.zqxcorp.internal zqx-cfgreg",
    "Our registry is https://npm.zqxcorp.internal. Install zqx-prose-c with npm.",
    'Paste this into .yarnrc.yml:\nnpmScopes:\n  zqxs:\n    npmRegistryServer: "https://npm.zqxcorp.internal"\nthen yarn add @zqxs/yarn-d',
    'In bunfig.toml:\n[install.scopes]\nzqxb = "https://npm.zqxcorp.internal/"\nthen bun add @zqxb/core',
    'In pyproject.toml:\n[[tool.uv.index]]\nname = "zqx"\nurl = "https://pypi.zqxcorp.internal/simple"\n\n[tool.uv.sources]\nzqx-uvsrc = { index = "zqx" }\nthen uv add zqx-uvsrc',
    "requirements.txt:\n--index-url https://pypi.zqxcorp.internal/simple\nzqx-req-lib==1.0.0\nrequests==2.31.0",
    'Pipfile:\n[[source]]\nurl = "https://pypi.zqxcorp.internal/simple"\nname = "zqx"\n\n[packages]\nzqx-pipfile-lib = {version="==1.0", index="zqx"}',
    'pipx install zqx-pipx-cli --pip-args="--index-url https://pypi.zqxcorp.internal/simple"',
    "install zqx-pip-from with pip from https://pypi.zqxcorp.internal/simple",
    "go.mod:\nreplace github.com/zqxorg/zqx-fence-f => ../zqx-fence-f\nrequire github.com/zqxorg/zqx-fence-f v1.0.0",
    "npm install --userconfig ./zqx.npmrc zqx-ucfg",
    "npm install --prefix ./zqx-prefix lodash",
    "npm install --cache ./zqx-cache --globalconfig ./zqx-global lodash",
    "pnpm -C ./zqx-dir add lodash",
    "pip install -t ./zqx-target requests",
    "cargo install --root ./zqx-root --bin zqx-binname ripgrep",
    "pip install zqxsecretpkg123 --password zqxpwflag99",
    "pnpm add zqx-catalog@catalog:zqx",
  ])("%s sends no made-up name, secret or private host", async (task) => {
    await brief(task);
    expect(leaked(/zqx|550e8400|9f86d081884c7d65|dGhpcyBpcyBzZWNyZXQ|eyJ[A-Za-z0-9]{8}/i)).toEqual([]);
  });

  it.each([
    ["add lodash", "lodash"],
    ["npm i -D typescript", "typescript"],
    ["pip install -U requests", "requests"],
    ["npm install --save-exact express", "express"],
  ])("%s still looks the package up", async (task, name) => {
    await brief(task);
    expect(looked(name).length).toBeGreaterThan(0);
  });

  it("a name on no bundled list is handed back, never looked up, and the task is review_needed", async () => {
    const r = await brief("add left-pad-ng to the project");
    expect(looked("left-pad-ng")).toEqual([]);
    // Fourth blind check of the 2026-11-25 fixes: a name not looked up is listed in task_packages.to_confirm.
    expect(waitingWords(r)).toMatchObject([{ word: "left-pad-ng" }]);
    expect(r.delegation_assessment.level).toBe("confirmation_needed");
  });
});

describe("3. every reviewer shape of 199,000 characters answers within 2 s of CPU", () => {
  const N = 199_000;
  const fill = (u: string) => u.repeat(Math.floor(N / u.length));
  const gen = (f: (i: number) => string) => {
    let s = "";
    for (let i = 0; s.length < N - 40; i++) s += f(i);
    return s;
  };
  const SHAPES: Record<string, () => string> = {
    secretVersions: () => gen((i) => `AbCd${String(i).padStart(5, "0")}EfGh==1.0 `),
    secretVersionsAt: () => gen((i) => `AbCd${String(i).padStart(5, "0")}EfGh@1.0.0 `),
    secretAdd: () => gen((i) => `add AbCd${String(i).padStart(5, "0")}EfGh `),
    emailsVersions: () => gen((i) => `p${i}@x.io==1.0 `),
    urlsVersions: () => gen((i) => `p${i}==1.0 //h/p${i} `),
    npmPkgs: () => gen((i) => (i === 0 ? "npm install " : `p${i} `)),
    npmPkgsVer: () => gen((i) => (i === 0 ? "npm install " : `p${i}@1.0.${i} `)),
    pipPkgs: () => gen((i) => (i === 0 ? "pip install " : `p${i}==1.0 `)),
    managers: () => fill("npm "),
    pemHeaders: () => fill("-----BEGIN -----"),
    dotted: () => fill("1.1"),
    listToVersions: () => `upgrade ${gen((i) => `p${i}, `)} to ${gen((i) => `1.${i}, `)}`.slice(0, N),
  };
  it.each(Object.keys(SHAPES))("%s", async (key) => {
    const task = SHAPES[key]();
    const live = await h.live();
    let best = Number.POSITIVE_INFINITY;
    let size = 0;
    for (let i = 0; i < 3 && best > 2_000; i++) {
      const start = process.cpuUsage();
      const r = await executeWhatShouldIKnow(null, { task, project_path: h.dir }, live);
      const used = process.cpuUsage(start);
      best = Math.min(best, (used.user + used.system) / 1000);
      // The answer holds the task itself; past it, it stays small (it was 0.66 MB).
      size = JSON.stringify(r).length - task.length;
    }
    expect(best).toBeLessThan(2_000);
    expect(size).toBeLessThan(60_000);
  });
});
