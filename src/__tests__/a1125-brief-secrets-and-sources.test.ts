// SPDX-License-Identifier: Apache-2.0
/**
 * what_should_i_know never sends a credential written in the task, and never looks up publicly what
 * the task's own command takes from a private registry, an index, a source, git, a path, a file or a
 * URL (pre-publish audit 2026-11-25, E1 and E2: both reached registry.npmjs.org, pypi.org and
 * api.osv.dev as package names; the private registry's host went out as "npm.x.internal (proceed)").
 * Each withheld word is named NOT CHECKED with its reason (a credential redacted). Stubbed fetch:
 * nothing leaves the machine.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { executeWhatShouldIKnow } from "../tools/what-should-i-know.js";
import { looksLikeSecret, screenTask } from "../tools/briefing-task-screen.js";
import { createHarness, type Harness } from "./helpers/a1119-planner-harness.js";
import { waitingWords } from "./helpers/a1127-task-packages.js";

let h: Harness;
let bodies: string[];
const sent = () => [...h.requests, ...bodies].map((s) => decodeURIComponent(s));
/** What a request names, for a check against a word that must never leave. */
const leaked = (pattern: RegExp) => sent().filter((s) => pattern.test(s));
/** Registry and OSV lookups of `name` as a package. */
const looked = (name: string) =>
  sent().filter((s) => s.includes(`registry.npmjs.org/${name}`) || s.includes(`pypi.org/pypi/${name}/`) || s.includes(`"name":"${name}"`) || s.includes(`crates.io/`) && s.endsWith(`/${name}`));

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
    lodash: { latest: "4.17.21", versions: { "4.17.21": {} } },
    express: { latest: "4.21.2", versions: { "4.21.2": {} } },
    axios: { latest: "1.7.9", versions: { "1.7.9": {} } },
  };
  h.PYPI = { requests: { "2.32.3": {} } };
});
afterEach(() => h.dispose());

async function brief(task: string): Promise<Record<string, any>> {
  return (await executeWhatShouldIKnow(null, { task, project_path: h.dir }, await h.live())) as Record<string, any>;
}

describe("E1: a credential in the task is never sent", () => {
  it.each([
    ["Add ghp_ZQXTOK0123456789abcdefABCDEF012345 as the GH_TOKEN secret", "ghp_"],
    ["add the key sk-proj-zqxtok9f8e7d6c5b4a3 to .env and install openai", null],
    ["add AKIAZQXTOK1234567890 to the aws credentials file", "AKIA"],
    ["install stripe and add sk_live_ZQXTOK51HxyzAbc to the config", "sk_l"],
    ["add xoxb-ZQXTOK-123-abc to the slack config", "xoxb"],
    ["add npm_ZQXTOK0123456789abcdefghij0123456789 to .npmrc", "npm_"],
    ["add OPENAI_API_KEY=sk-proj-zqxtokEQ12345 to .env", null],
    ["use the token npm_ZQXTOKuse0123456789 to publish", null],
    ["set GITHUB_TOKEN=ghp_TOKZQXgh0024 then add express", null],
    ["add TOKZQXbare0026 to the env file and install dotenv", "TOKZ"],
    ["install the token TOKZQXafterverb0027", "TOKZ"],
    ["export NPM_TOKEN=TOKZQXexport0023 and install axios", null],
    ["Add this to .npmrc: //npm.zqxcorp.internal/:_authToken=TOKZQXpasted0021 then npm install lodash", null],
    ["npm install lodash --registry https://deploybot:TOKZQXpasswd0022@npm.zqxcorp.internal/", null],
    ["pip install requests --extra-index-url https://__token__:TOKZQXpypi0025@pypi.zqxcorp.internal/simple", null],
    ["npm install jsmith-zqx --registry https://jsmith:hunter2zqx@npm.zqxcorp.internal/", null],
    ["add https://jsmithzqx:pw0rdzqx@github.com/zqxorg/zqxrepo to the deps", null],
    ["add jsmithzqx@mail.example.com as a reviewer and install lodash", null],
  ])("%s", async (task, redacted) => {
    const r = await brief(task);
    expect(leaked(/zqx|tokzqx|jsmith|hunter2|deploybot|__token__|ghp_|sk_live|sk-proj|akia|xoxb|npm_zqx/i)).toEqual([]);
    if (redacted) {
      expect(r.summary).toContain(`${redacted}...`);
      expect(r.summary).toMatch(/credential/);
      expect(r.delegation_assessment.level).not.toBe("safe_to_delegate");
    }
  });

  it("names the credential by four characters and its length, never in full", async () => {
    const r = await brief("Add ghp_ZQXTOK0123456789abcdefABCDEF012345 as the GH_TOKEN secret");
    expect(r.summary).toContain("ghp_... (38 characters)");
    expect(r.summary).not.toContain("ZQXTOK0123456789");
  });

  it("a package next to a credential is still checked", async () => {
    await brief("set GITHUB_TOKEN=ghp_TOKZQXgh0024 then add express");
    expect(looked("express").length).toBeGreaterThan(0);
  });

  it("package names are not credentials", () => {
    for (const name of ["event-stream", "crossenv", "lodash", "@types/node", "PyYAML", "Flask-SQLAlchemy", "python-dateutil", "es5-ext", "base64-js", "github.com/gin-gonic/gin", "sqlalchemy2-stubs", "PyQt5-sip"]) {
      expect(looksLikeSecret(name), name).toBe(false);
    }
  });
});

describe("E2: what the task's own command takes from elsewhere is never looked up publicly", () => {
  it.each([
    ["Run npm install --registry https://npm.zqxcorp.internal zqx-cli-tool", "zqx-cli-tool"],
    ["npm install --registry=https://npm.zqxcorp.internal zqx-eq-tool", "zqx-eq-tool"],
    ["pip install -i https://pypi.zqxcorp.internal/simple zqx-pip-tool2==1.0", "zqx-pip-tool2"],
    ["pip install --extra-index-url https://pypi.zqxcorp.internal/simple zqx-extra", "zqx-extra"],
    ["cargo add zqx-cg-thing --registry zqxreg", "zqx-cg-thing"],
    ["cargo add zqx-cargo-git --git https://git.zqxcorp.internal/x", "zqx-cargo-git"],
    ["cargo add zqx-cargo-path --path ../zqx-cargo-path", "zqx-cargo-path"],
    ["uv add zqx-uv-thing --index https://pypi.zqxcorp.internal/simple", "zqx-uv-thing"],
    ["uv add zqx-uv-named --index zqxidx=https://pypi.zqxcorp.internal/simple", "zqx-uv-named"],
    ["poetry add zqx-poetry-thing --source zqxsrc", "zqx-poetry-thing"],
    ["npm i file:../zqx-local-dir", "file:../zqx-local-dir"],
    ["pip install ./libs/zqx-local-py", "./libs/zqx-local-py"],
    ["npm install zqxuser/zqxrepo", "zqxuser/zqxrepo"],
    ['pip install "zqx-urlpkg @ https://pkgs.zqxcorp.internal/zqx-urlpkg-1.0.tar.gz"', "zqx-urlpkg"],
    ['Add "zqx-json-dep": "git+ssh://git@git.zqxcorp.internal/zqx/json-dep.git" to package.json', "zqx-json-dep"],
    ['In Cargo.toml add zqx-toml-git = { git = "https://git.zqxcorp.internal/zqx-toml-git" }', "zqx-toml-git"],
    ['In pyproject.toml add "zqx-pep508 @ git+https://git.zqxcorp.internal/zqx-pep508.git"', "zqx-pep508"],
    ["npm config set @zqxscope:registry https://npm.zqxcorp.internal and add @zqxscope/ui", "@zqxscope/ui"],
    ["npm config set registry https://npm.zqxcorp.internal then add zqxglobal-thing", "zqxglobal-thing"],
    ["PIP_INDEX_URL=https://pypi.zqxcorp.internal/simple pip install zqx-env-pip", "zqx-env-pip"],
  ])("%s", async (task, withheld) => {
    const r = await brief(task);
    expect(leaked(/zqx/i)).toEqual([]);
    // No option value (the host, "https", "file", "simple") is looked up as a package.
    for (const word of ["https", "http", "file", "simple", "git", "ssh", "internal"]) expect(looked(word), word).toEqual([]);
    expect(r.summary).toContain(withheld);
    expect(r.summary).toMatch(/not looked up/);
    expect(r.delegation_assessment.level).not.toBe("safe_to_delegate");
  });

  // Round 7, C3: a registry or index option anywhere in the task is the evidence, whichever it names: no name the task
  // adds is looked up by the briefing (dependency_check checks the public one when asked).
  it("a registry or index named in the task, the public one included, holds every name the task adds", async () => {
    const r = await brief("npm install --registry https://registry.npmjs.org lodash");
    expect(looked("lodash")).toEqual([]);
    expect(r.delegation_assessment.level).not.toBe("safe_to_delegate");
    await brief("pip install -i https://pypi.org/simple requests");
    expect(looked("requests")).toEqual([]);
  });

  it("an option's value is never a package, and the operands after it are still read", async () => {
    await brief("npm install --tag zqxtagvalue lodash");
    expect(leaked(/zqx/i)).toEqual([]);
    expect(looked("lodash").length).toBeGreaterThan(0);
  });

  it("a private command does not hide the next clause's popular package, and its own package is never listed (final design)", async () => {
    const r = await brief("npm install --registry https://npm.zqxcorp.internal zqx-cli-tool; then add express");
    expect(leaked(/zqx/i)).toEqual([]);
    // Round 7, C3: the source word holds the next clause's name too (it is said, not looked up).
    expect(looked("express")).toEqual([]);
    expect(JSON.stringify(waitingWords(r) ?? [])).not.toMatch(/zqx/);
    expect(r.delegation_assessment.level).not.toBe("safe_to_delegate");
  });

  it("screenTask blanks spans in place", () => {
    const task = "npm i --registry https://npm.zqx.internal zqx-a and add lodash";
    const s = screenTask(task);
    expect(s.text.length).toBe(task.length);
    expect(s.text).not.toMatch(/zqx/);
    expect(s.text).toContain("add lodash");
  });
});
