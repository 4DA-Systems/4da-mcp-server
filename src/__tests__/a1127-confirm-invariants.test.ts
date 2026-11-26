// SPDX-License-Identifier: Apache-2.0
/**
 * Wave 2, package confirmation: the invariants I1-I8 (lead, after the first independent check of b0316d3, whose
 * blockers B1-B3 and P1 were one design error: a declaration was allowed to REMOVE a check). Each invariant is
 * proved over generated cases, with a stubbed fetch whose registries answer 404 for names they do not have.
 *
 *  I1 a declaration only adds checks (privacy is the one exception, and then the name stands as unchecked);
 *  I2 the version the task writes is always checked, a declared one in addition;
 *  I3 a waiting name is settled only by a declaration in an ecosystem it was read in;
 *  I4 a dismissal of a name standing where a package stands keeps review_needed (incl. one edit from a declared name);
 *  I5 one forbidden set, folded for every ecosystem: private wins over public, whatever the order or spelling;
 *  I7 runner commands' operands are candidates;
 *  I8 every declared public entry is checked; more than 25 waiting names end for a literal agent.
 * (I6, the embedding cut, is proved in a1125-r8-brief-embed-screened.test.ts.)
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { executeWhatShouldIKnow } from "../tools/what-should-i-know.js";
import { adv, createHarness, fixedIn, type Harness } from "./helpers/a1119-planner-harness.js";

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
  h.npmProject({ undici: "6.21.0" }, {}, { undici: { version: "6.21.0" } });
  h.NPM = {
    lodash: { latest: "4.17.21", versions: { "4.17.20": {}, "4.17.21": {} } },
    "node-forge": { latest: "1.3.1", versions: { "0.10.0": {}, "1.3.1": {} } },
    undici: { latest: "6.21.0", versions: { "5.8.0": {}, "6.21.0": {} } },
    fastify: { latest: "5.2.0", versions: { "5.2.0": {} } },
    crossenv: { latest: "6.1.1", versions: { "6.1.1": {} } },
    "event-stream": { latest: "4.0.1", versions: { "3.3.6": {}, "4.0.1": {} } },
    lodahs: { latest: "0.0.1-security", versions: { "0.0.1-security": {} } },
  };
  h.ADVISORIES = {
    lodash: [adv("GHSA-35jh-r3h4-6jhm", "lodash", fixedIn("4.17.21"), "npm", "HIGH")],
    "node-forge": [adv("GHSA-x4jg-mjrx-434g", "node-forge", fixedIn("1.0.0"), "npm", "CRITICAL")],
    undici: [adv("GHSA-3787-6prv-h9w3", "undici", fixedIn("5.8.2"), "npm", "CRITICAL")],
    crossenv: [adv("MAL-2017-1", "crossenv", [{ introduced: "0" }], "npm", "CRITICAL")],
    "event-stream": [adv("GHSA-mh6f-8j2x-4483", "event-stream", fixedIn("4.0.0"), "npm", "CRITICAL")],
    lodahs: [adv("MAL-2025-25502", "lodahs", [{ introduced: "0" }], "npm", "CRITICAL")],
  };
});
afterEach(() => h.dispose());

async function brief(task: string, more: Record<string, unknown> = {}): Promise<Record<string, any>> {
  sent.length = 0;
  return (await executeWhatShouldIKnow(null, { task, project_path: h.dir, ...more } as never, await h.live())) as Record<string, any>;
}
/** Every lower-cased name a request asked about (registry paths and OSV.dev bodies). */
const namesSent = () =>
  new Set(
    sent.flatMap((s) => [
      ...[...s.url.matchAll(/registry\.npmjs\.org\/((?:@[^/]+\/)?[^/?#]+)|pypi\.org\/pypi\/([^/]+)/g)].map((m) => (m[1] ?? m[2]).toLowerCase()),
      ...[...s.body.matchAll(/"name":"([^"]+)"/g)].map((m) => m[1].toLowerCase()),
    ]),
  );
const RANK: Record<string, number> = { safe_to_delegate: 1, confirmation_needed: 2, review_needed: 3, unknown: 3, human_only: 4 };

/** Tasks a bare call already looks up (bundled names, a project dependency, the versions written). */
const KNOWN_TASKS = ["npm install crossenv", "npm install event-stream@3.3.6", "npm install lodash@4.17.20", "upgrade undici to 5.8.0", "npm install node-forge@0.10.0"];

describe("I1: a declaration only adds checks", () => {
  const extras = [
    [],
    [{ ecosystem: "npm", name: "fastify", public: true }],
    [{ ecosystem: "npm", name: "zqx-extra", public: true }],
    [{ ecosystem: "PyPI", name: "requests", public: true }],
  ];
  it.each(KNOWN_TASKS.flatMap((t) => extras.map((e) => [t, e] as const)))("%s with %j: the bare call's lookups and conclusion stand", async (task, packages) => {
    const bare = await brief(task, { packages: [] });
    const bareSent = namesSent();
    const declared = await brief(task, { packages });
    const declaredSent = namesSent();
    for (const n of bareSent) expect(declaredSent.has(n), `${n} was looked up without the declaration`).toBe(true);
    if (bare.delegation_assessment.level === "human_only") expect(declared.delegation_assessment.level).toBe("human_only");
    expect(RANK[declared.delegation_assessment.level]).toBeGreaterThanOrEqual(Math.min(RANK[bare.delegation_assessment.level], 3));
  });

  it.each(KNOWN_TASKS.flatMap((t) => (["private", "not_packages"] as const).map((how) => [t, how] as const)))("%s, the name forbidden as %s: never sent, never safe; malware stays human_only", async (task, how) => {
    const name = /install ([a-z-]+)|upgrade ([a-z-]+)/.exec(task)!.slice(1).find(Boolean)!;
    const r = await brief(task, how === "private" ? { packages: [{ ecosystem: "npm", name, public: false }] } : { packages: [], not_packages: [name] });
    // The project's own vulnerability scan asks about an installed dependency by name, as every tool does (the
    // documented limit: FOURDA_PRIVATE_PACKAGES or a registry config keeps it off): the briefing itself sends nothing.
    const own = sent.filter((x) => (x.url.includes(`registry.npmjs.org/${name}`) || (x.url.endsWith("/v1/query") && x.body.includes(`"name":"${name}"`))));
    expect(name === "undici" ? own : [...namesSent()].filter((n) => n === name)).toEqual([]);
    expect(r.delegation_assessment.level).not.toBe("safe_to_delegate");
    if (name === "crossenv") expect(r.delegation_assessment.level).toBe("human_only");
  });
});

// Round 7, C4: a declared entry is checked at its declared version if it gives one; else at every spec written on
// that exact pair (a canonical operand, a manifest entry), and at latest where the pair is named without one. A
// version in prose ("pin zqxpin to 1.0.0") attaches to no pair.
describe("C4 (was I2): which versions a declared entry is checked at", () => {
  it.each([
    ["npm install node-forge@0.10.0", "node-forge", undefined, ["node-forge@0.10.0"]],
    ["npm install node-forge@0.10.0", "node-forge", "1.3.1", ["node-forge@1.3.1"]],
    ["npm install lodash@4.17.20", "lodash", undefined, ["lodash@4.17.20"]],
    ["pin zqxpin to 1.0.0", "zqxpin", undefined, ["zqxpin@latest"]],
  ])("%s, declared at %s %s", async (task, name, declaredVersion, expected) => {
    const r = await brief(task, { packages: [{ ecosystem: "npm", name, ...(declaredVersion ? { version: declaredVersion } : {}), public: true }] });
    // Round 7c, R3: one row per (pair, version), in new_packages or requested_versions.
    const rows = [...(r.new_packages ?? []).map((x: { name: string; version?: string }) => `${x.name}@${x.version ?? "latest"}`), ...(r.requested_versions ?? []).map((x: { name: string; to: string }) => `${x.name}@${x.to}`)];
    for (const e of expected) expect(rows, JSON.stringify(rows)).toContain(e);
    if (name === "node-forge" && !declaredVersion) expect(r.delegation_assessment.level).toBe("human_only");
  });
});

describe("I3: a declaration in another ecosystem does not settle a waiting name", () => {
  it.each([["npm install colorsx", "PyPI"], ["pip install zqxpylib", "npm"], ["cargo add zqxcrate", "PyPI"]])("%s, declared in %s", async (task, other) => {
    const name = task.split(" ").pop()!;
    const r = await brief(task, { packages: [{ ecosystem: other, name, public: true }] });
    expect(r.task_packages.to_confirm.map((t: { name: string }) => t.name)).toContain(name);
    expect(r.delegation_assessment.level).not.toBe("safe_to_delegate");
  });
});

describe("I4: a dismissed name standing where a package stands keeps review_needed", () => {
  it.each([
    ["npm install zqxcmd", "zqxcmd", []],
    ["npx zqxrunner init", "zqxrunner", []],
    ['add "zqxmanifest": "1.0.0" to package.json', "zqxmanifest", []],
    ["add lodahs", "lodahs", []],
    ["Add fastifyy for the new HTTP layer", "fastifyy", [{ ecosystem: "npm", name: "fastify", public: true }]],
    ["npm install crossenv", "crossenv", []],
    ["npm install lodash@4.17.20", "lodash", []],
  ])("%s, %s dismissed", async (task, word, packages) => {
    const r = await brief(task, { packages, not_packages: [word] });
    expect(r.delegation_assessment.level).not.toBe("safe_to_delegate");
    expect(namesSent().has(word)).toBe(false);
  });
});

describe("I5: one forbidden set, folded for every ecosystem; private wins", () => {
  const variants: Array<[string, Array<Record<string, unknown>>, string[]]> = [
    ["npm install zqxboth", [{ ecosystem: "npm", name: "zqxboth", public: true }, { ecosystem: "npm", name: "zqxboth", public: false }], []],
    ["npm install zqxboth", [{ ecosystem: "npm", name: "zqxboth", public: false }, { ecosystem: "npm", name: "zqxboth", public: true }], []],
    ["npm install ZqxBoth", [{ ecosystem: "npm", name: "zqxboth", public: true }, { ecosystem: "npm", name: "ZQXBOTH", public: false }], []],
    ["pip install zqx.py_lib", [{ ecosystem: "PyPI", name: "zqx.py_lib", public: true }, { ecosystem: "PyPI", name: "Zqx-Py-Lib", public: false }], []],
    ["cargo add zqx_crate", [{ ecosystem: "crates.io", name: "zqx_crate", public: true }, { ecosystem: "crates.io", name: "zqx-crate", public: false }], []],
    ["npm install zqxnotpkg", [{ ecosystem: "npm", name: "zqxnotpkg", public: true }], ["zqxnotpkg"]],
    ["npm install lodash", [{ ecosystem: "npm", name: "lodash", public: true }], ["LODASH"]],
  ];
  it.each(variants)("%s %j %j", async (task, packages, notPackages) => {
    const r = await brief(task, { packages, ...(notPackages.length > 0 ? { not_packages: notPackages } : {}) });
    const forbidden = [...packages.filter((p) => p.public === false).map((p) => String(p.name)), ...notPackages].map((n) => n.toLowerCase().replace(/[-_.]+/g, "-"));
    for (const n of namesSent()) expect(forbidden, `${n} was sent`).not.toContain(n.replace(/[-_.]+/g, "-"));
    expect(r.delegation_assessment.level).not.toBe("safe_to_delegate");
  });
});

// Round 7, C1/C2: a runner or scaffold command fetches and runs a package this briefing does not check: it is not read
// whole, nothing of it is offered, and the level is at most review_needed.
describe("C1 (was I7): a runner command is never read whole", () => {
  it.each([
    ["npx zqxrun init", "zqxrun"],
    ["npx --yes zqxrun", "zqxrun"],
    ["pnpm dlx zqxrun", "zqxrun"],
    ["yarn dlx zqxrun", "zqxrun"],
    ["bunx zqxrun", "zqxrun"],
    ["npm exec zqxrun", "zqxrun"],
    ["uvx zqxpyrun", "zqxpyrun"],
    ["pipx run zqxpyrun", "zqxpyrun"],
    ["uv tool run zqxpyrun", "zqxpyrun"],
  ])("%s", async (task, name) => {
    const r = await brief(task, { packages: [] });
    expect(JSON.stringify(r.task_packages.to_confirm)).not.toContain(name);
    expect(r.delegation_assessment.level).not.toBe("safe_to_delegate");
    expect(r.delegation_assessment.reason).toMatch(/could not read whole \(it fetches and runs a package/);
  });

  it("npx crossenv: a known-malicious name, looked up and human_only on a bare call", async () => {
    expect((await brief("npx crossenv")).delegation_assessment.level).toBe("human_only");
  });
});

describe("I8: every declared public entry is checked; many waiting names end", () => {
  it("25 declared packages, malware at the 25th: checked, human_only", async () => {
    const names = [...Array.from({ length: 24 }, (_, i) => `zqxdecl${i}`), "lodahs"];
    const r = await brief(`npm install ${names.join(" ")}`, { packages: names.map((name) => ({ ecosystem: "npm", name, public: true })) });
    expect(r.delegation_assessment.level).toBe("human_only");
    expect(r.task_packages.checked.filter((c: { basis: string }) => c.basis === "confirmed public by you")).toHaveLength(25);
  });

  it("60 waiting names: a literal agent that answers what it is shown, keeping its earlier answers, finishes", async () => {
    const task = `npm install ${Array.from({ length: 60 }, (_, i) => `zqxmany${i}`).join(" ")}`;
    let args: Record<string, any> = {};
    let r = await brief(task);
    let calls = 1;
    while (r.task_packages.status === "confirmation_needed" && calls < 6) {
      const answered = [...(args.not_packages ?? []), ...r.task_packages.to_confirm.map((t: { name: string }) => t.name)];
      args = { packages: [], not_packages: answered };
      r = await brief(task, args);
      calls++;
    }
    expect(r.task_packages.status).toBe("complete");
    expect(calls).toBeLessThanOrEqual(4);
  });

  it("more than 25 waiting: to_confirm shows 25, counts all, and next_step says to call again for the rest", async () => {
    const r = await brief(`npm install ${Array.from({ length: 30 }, (_, i) => `zqxmany${i}`).join(" ")}`);
    expect(r.task_packages.to_confirm).toHaveLength(25);
    expect(r.task_packages.to_confirm_total).toBe(30);
    expect(r.task_packages.next_step).toContain("call again for the next ones");
  });
});
