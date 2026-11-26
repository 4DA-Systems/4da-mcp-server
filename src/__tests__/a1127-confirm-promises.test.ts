// SPDX-License-Identifier: Apache-2.0
/**
 * Wave 2, package confirmation: the promises P1-P6 of the design (2026-11-27, section 1), each proved with a
 * stubbed fetch whose registries answer 404 for a name they do not have, as the real ones do (an always-200
 * stub hides a fallback: the fifth blind check found one that way). Nothing leaves the machine.
 *
 * - P1: without `packages`, a name is sent only when the project depends on it in that ecosystem or it is
 *   exactly a bundled-list name (the gate).
 * - P2: with `packages`, the only additional names sent are `public: true` entries that passed the name
 *   grammar, the project's private rules and the credential shapes; a `public: false` entry and a
 *   `not_packages` word are never sent, by any path.
 * - P3: no answer field is shaped as the `packages` argument or as any tool's arguments.
 * - P4: no answer is safe_to_delegate while a name waits in to_confirm.
 * - P5 (offline part): after the confirm call a typosquat that is malware and a critical pin are human_only.
 * - P6: the secret-in-task cases of the earlier reviews: nothing of a secret is sent on the first call, and
 *   nothing in to_confirm repeats a value the screen withheld.
 * And: only declared packages go to the check ledger.
 */

import { readFileSync } from "node:fs";
import * as fs from "node:fs";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { executeWhatShouldIKnow } from "../tools/what-should-i-know.js";
import { knownPublicName, screenTask } from "../tools/briefing-task-screen.js";
import { LEDGER_FILE, ledgerWritesSettled } from "../check-ledger.js";
import { serverDataDir } from "../db.js";
import { adv, createHarness, fixedIn, type Harness } from "./helpers/a1119-planner-harness.js";

const rev = (s: string) => [...s].reverse().join("");
const FIXTURE = JSON.parse(readFileSync(path.join(__dirname, "fixtures", "a1127-confirm", "secret-tasks.json"), "utf8")) as { cases: Array<{ set: string; task: string; canaries: string[] }> };
const SECRET_CASES = FIXTURE.cases.map((c) => ({ set: c.set, task: rev(c.task), canaries: c.canaries.map(rev) }));

const ORDINARY = [
  "add lodahs and elliptic 6.5.4",
  "npm install zqxprivate-ui and express",
  "use pydantic v2 for the settings",
  "add the left-pad package",
  "swap moment for dayjs",
  "bump typescript to 5.6",
  "replace request with axios 0.21.0",
  "add ctx",
  "npm install flatmap-stream event-stream@3.3.6",
  "pip install reqeusts==2.0.0",
  'add "json-web-token": "3.0.1" to package.json',
  "cargo add rustdecimal",
];

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
  h.npmProject({ minimist: "1.2.5" }, {}, { minimist: { version: "1.2.5" } });
  h.NPM = {
    lodahs: { latest: "0.0.1-security", versions: { "0.0.1-security": {} } },
    elliptic: { latest: "6.6.1", versions: { "6.5.4": {}, "6.6.1": {} } },
    express: { latest: "4.21.2", versions: { "4.21.2": {} } },
  };
  h.ADVISORIES = {
    lodahs: [adv("MAL-2025-25502", "lodahs", [{ introduced: "0" }], "npm", "CRITICAL")],
    elliptic: [adv("GHSA-vjh7-7g9h-fjfh", "elliptic", fixedIn("6.6.1"), "npm", "CRITICAL")],
  };
});
afterEach(() => h.dispose());

async function brief(task: string, more: Record<string, unknown> = {}): Promise<Record<string, any>> {
  return (await executeWhatShouldIKnow(null, { task, project_path: h.dir, ...more } as never, await h.live())) as Record<string, any>;
}

/** Every (ecosystem, name) a request asked about: registry paths and OSV.dev query bodies. */
function namesSent(): Array<{ ecosystem: string; name: string }> {
  const out: Array<{ ecosystem: string; name: string }> = [];
  for (const s of sent) {
    const npm = /^https:\/\/registry\.npmjs\.org\/((?:@[^/]+\/)?[^/?#]+)/.exec(s.url);
    if (npm) out.push({ ecosystem: "npm", name: npm[1] });
    const npmDl = /^https:\/\/api\.npmjs\.org\/downloads\/point\/[^/]+\/((?:@[^/]+\/)?[^/?#]+)/.exec(s.url);
    if (npmDl) out.push({ ecosystem: "npm", name: npmDl[1] });
    const pypi = /^https:\/\/pypi\.org\/pypi\/([^/]+)/.exec(s.url);
    if (pypi) out.push({ ecosystem: "PyPI", name: pypi[1] });
    const crates = /^https:\/\/(?:crates\.io\/api\/v1\/crates|index\.crates\.io\/[^/]+(?:\/[^/]+)?)\/([^/?#]+)/.exec(s.url);
    if (crates) out.push({ ecosystem: "crates.io", name: crates[1] });
    for (const m of s.body.matchAll(/"package":\{"name":"([^"]+)","ecosystem":"([^"]+)"/g)) out.push({ ecosystem: m[2], name: m[1] });
  }
  return out;
}

const DEPS = new Set(["npm\0minimist"]);
/** P1's rule: a project dependency in that ecosystem, or exactly a bundled-list name. */
const gateAllows = (n: { ecosystem: string; name: string }) => DEPS.has(`${n.ecosystem}\0${n.name.toLowerCase()}`) || knownPublicName(n.name, n.ecosystem as never);

/** Objects in the answer shaped as the `packages` argument, or as any tool's arguments. */
function callableShapes(answer: unknown): string[] {
  const found: string[] = [];
  const walk = (v: unknown, at: string) => {
    if (Array.isArray(v)) v.forEach((x, i) => walk(x, `${at}[${i}]`));
    else if (v && typeof v === "object") {
      const keys = Object.keys(v);
      if (keys.includes("public") && keys.includes("name")) found.push(`${at}: a packages entry`);
      for (const k of ["check_these", "arguments", "items", "tool"]) if (keys.includes(k)) found.push(`${at}.${k}`);
      for (const [k, x] of Object.entries(v)) walk(x, `${at}.${k}`);
    }
  };
  walk(answer, "");
  return found;
}

describe("P1: without packages, nothing is sent outside the gate", () => {
  it.each([...ORDINARY, ...SECRET_CASES.map((c) => c.task)])("%s", async (task) => {
    await brief(task);
    expect(namesSent().filter((n) => !gateAllows(n))).toEqual([]);
  });
});

describe("P2: only public, screened declarations are sent", () => {
  it("public: false and not_packages are never sent, in any ecosystem, even a name the gate would look up", async () => {
    const r = await brief("add zqxprivate-ui, ctx and zqxword, then npm install lodahs", {
      packages: [
        { ecosystem: "npm", name: "zqxprivate-ui", public: false },
        { ecosystem: "npm", name: "ctx", public: false },
      ],
      not_packages: ["zqxword", "lodahs"],
    });
    const names = namesSent().map((n) => n.name.toLowerCase());
    for (const off of ["zqxprivate-ui", "ctx", "zqxword", "lodahs"]) expect(names).not.toContain(off);
    expect(r.task_packages.private.map((p: { name: string }) => p.name)).toEqual(expect.arrayContaining(["zqxprivate-ui", "ctx"]));
    expect(r.task_packages.dismissed).toEqual(expect.arrayContaining(["zqxword", "lodahs"]));
    expect(r.task_packages.to_confirm).toEqual([]);
  });

  it("a public: true entry the project's rules mark private is not sent, and is reported private", async () => {
    vi.stubEnv("FOURDA_PRIVATE_PACKAGES", "npm:zqxcorp-*");
    try {
      const r = await brief("add zqxcorp-auth", { packages: [{ ecosystem: "npm", name: "zqxcorp-auth", public: true }] });
      expect(namesSent().map((n) => n.name)).not.toContain("zqxcorp-auth");
      expect(r.task_packages.private).toContainEqual(expect.objectContaining({ name: "zqxcorp-auth", basis: "this project's registry configuration" }));
    } finally {
      vi.unstubAllEnvs();
    }
  });

  it("a public: true entry shaped as a credential is not sent, nor repeated", async () => {
    const token = ["gh", "p_", "ZQXTOK0123456789abcdefABCDEF012345"].join("");
    const uuid = "98e62aac-d9e2-44a1-946d-1fbf082c44aa";
    const r = await brief("add the token", { packages: [{ ecosystem: "npm", name: token, public: true }, { ecosystem: "npm", name: uuid, public: true }] });
    expect(sent.some((s) => s.url.includes("ZQXTOK") || s.body.includes("ZQXTOK") || s.url.includes(uuid) || s.body.includes(uuid))).toBe(false);
    expect(JSON.stringify({ ...r, task: undefined })).not.toMatch(/ZQXTOK|98e62aac/);
  });

  it("an entry with a field this tool does not define, or no `public`, is refused and never sent", async () => {
    const r = await brief("add things", {
      packages: [
        { ecosystem: "npm", name: "zqxreg-one", public: true, registry: "https://npm.zqx.internal" },
        { ecosystem: "npm", name: "zqxreg-two" },
        { ecosystem: "npm", name: "../zqx-local", public: true },
      ],
    });
    expect(namesSent().map((n) => n.name)).not.toEqual(expect.arrayContaining([expect.stringMatching(/zqx/)]));
    expect(r.task_packages.not_read.map((x: { shown: string }) => x.shown)).toEqual(["packages[0]", "packages[1]", "packages[2]"]);
    expect(JSON.stringify(r.task_packages.not_read)).not.toContain("zqx");
  });

  it("the only additional names sent are the confirmed public ones, in their ecosystem only", async () => {
    await brief("add zqxcandidate and lodahs");
    const before = new Set(namesSent().map((n) => `${n.ecosystem}:${n.name}`));
    sent.length = 0;
    await brief("add zqxcandidate and lodahs", { packages: [{ ecosystem: "npm", name: "lodahs", public: true }], not_packages: ["zqxcandidate"] });
    const added = namesSent().filter((n) => !before.has(`${n.ecosystem}:${n.name}`));
    expect([...new Set(added.map((n) => `${n.ecosystem}:${n.name}`))]).toEqual(["npm:lodahs"]);
  });
});

describe("P3: nothing in the answer is shaped as tool arguments", () => {
  it.each(ORDINARY)("%s", async (task) => {
    expect(callableShapes(await brief(task))).toEqual([]);
    expect(callableShapes(await brief(task, { packages: [{ ecosystem: "npm", name: "lodahs", public: true }], not_packages: ["zqx"] }))).toEqual([]);
  });
});

describe("P4: never safe_to_delegate while a name waits, nor on a call that declared nothing", () => {
  it.each([...ORDINARY, ...SECRET_CASES.map((c) => c.task)])("%s", async (task) => {
    const r = await brief(task);
    if (r.task_packages.to_confirm.length > 0) {
      expect(r.delegation_assessment.level).not.toBe("safe_to_delegate");
      expect(r.task_packages.status).toBe("confirmation_needed");
      expect(r.task_packages.next_step).toContain("a name left out stays in to_confirm");
    } else {
      // A bare call never ends complete: it asks for a declaration (wave 2, change A).
      expect(r.task_packages.status).toBe("confirmation_needed");
      expect(r.delegation_assessment.level).not.toBe("safe_to_delegate");
      expect(r.task_packages.next_step).toContain("This call declared no packages.");
    }
    // With the declaration that the task changes no package, the names it read still wait.
    const declared = await brief(task, { packages: [] });
    if (declared.task_packages.to_confirm.length > 0) expect(declared.delegation_assessment.level).not.toBe("safe_to_delegate");
    else expect(declared.task_packages.status).toBe("complete");
  });

  it("a name left out of the answer stays waiting: omission is never dismissal", async () => {
    const r = await brief("add lodahs and elliptic 6.5.4", { packages: [{ ecosystem: "npm", name: "elliptic", version: "6.5.4", public: true }] });
    expect(r.task_packages.to_confirm.map((t: { name: string }) => t.name)).toEqual(["lodahs"]);
    // Known already: the critical pin makes it human_only, and the reason says a name waits.
    expect(r.delegation_assessment.level).toBe("human_only");
    expect(r.delegation_assessment.reason).toContain("1 name also waits for confirmation");
  });
});

describe("P5 (offline): after the confirm call, a malware typosquat and a critical pin are human_only again", () => {
  it.each([
    ["add lodahs", [{ ecosystem: "npm", name: "lodahs", public: true }]],
    ["add elliptic 6.5.4", [{ ecosystem: "npm", name: "elliptic", version: "6.5.4", public: true }]],
    // Round 7, C4: a version in prose attaches to no pair: the agent declares the version it will write.
    ["pin elliptic to 6.5.4", [{ ecosystem: "npm", name: "elliptic", version: "6.5.4", public: true }]],
  ])("%s", async (task, packages) => {
    const first = await brief(task);
    expect(first.delegation_assessment.level).toBe("confirmation_needed");
    const second = await brief(task, { packages });
    expect(second.task_packages.status).toBe("complete");
    expect(second.delegation_assessment.level).toBe("human_only");
    expect(second.task_packages.checked).toContainEqual(expect.objectContaining({ basis: "confirmed public by you", verdict: "avoid" }));
  });
});

describe("P6: the secret-in-task cases of the earlier reviews", () => {
  it.each(SECRET_CASES.map((c) => [c.set, c.task, c.canaries] as const))("%s: %s", async (_set, task, canaries) => {
    const r = await brief(task);
    for (const c of canaries) expect(sent.filter((s) => `${s.url} ${s.body}`.includes(c)), c).toEqual([]);
    const withheld = screenTask(task).withheld.map((w) => task.slice(w.start, w.end)).filter((v) => v.length >= 4);
    for (const t of r.task_packages.to_confirm as Array<{ name: string; version?: string }>) {
      for (const v of withheld) {
        expect(t.name.includes(v) || v.includes(t.name) && t.name.length >= 8, `${t.name} repeats a withheld value ${v}`).toBe(false);
        if (t.version) expect(t.version.includes(v), `${t.version} repeats a withheld value`).toBe(false);
      }
    }
  });
});

describe("the check ledger records only what the caller confirmed", () => {
  it("a confirmed public package is recorded; the briefing's own lookups and private ones are not", async () => {
    await brief("add lodahs, ctx and zqxprivate-ui", {
      packages: [
        { ecosystem: "npm", name: "lodahs", public: true },
        { ecosystem: "npm", name: "zqxprivate-ui", public: false },
      ],
      not_packages: ["ctx"],
    });
    await brief("npm install express");
    await ledgerWritesSettled();
    const file = path.join(serverDataDir(), LEDGER_FILE);
    const lines = fs.existsSync(file) ? fs.readFileSync(file, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l) as { package: string; verdict: string }) : [];
    expect(lines.map((l) => l.package)).toContain("lodahs");
    expect(lines.find((l) => l.package === "lodahs")?.verdict).toBe("avoid");
    expect(lines.map((l) => l.package)).not.toEqual(expect.arrayContaining(["zqxprivate-ui"]));
    expect(lines.map((l) => l.package)).not.toContain("express");
    expect(lines.map((l) => l.package)).not.toContain("minimist");
  });
});
