// SPDX-License-Identifier: Apache-2.0
/**
 * Round 17: the fifteenth independent check (review-confirm15). C1 installed malware or a security placeholder
 * anywhere in the full scan (dev, optional, peer, transitive, sub-project, the copy on disk) holds every briefing at
 * human_only; C2 a declared or read name touches its installed copy; C4 the reading copy's dashes, slashes and
 * markup; C5 a credential-shaped request id, masking to a fixed point, trailers, line breaks.
 */
import * as fs from "node:fs";
import { createServer, request as httpRequest } from "node:http";
import type { AddressInfo } from "node:net";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { executeWhatShouldIKnow, readingCopy } from "../tools/what-should-i-know.js";
import { INSTALLED_MALWARE, INSTALLED_PLACEHOLDER, TASK_FOLDED } from "../tools/briefing-confirm.js";
import { DASH_EXTRAS, SLASH_LOOKALIKES, foldName } from "../live/private-guard.js";
import { hasCredentialShape, screenText } from "../output-screen.js";
import { screenResponse } from "../http-transport.js";
import { CREDENTIAL_ID_REFUSED, StdioGate } from "../stdio-gate.js";
import { adv, createHarness, type Harness } from "./helpers/a1119-planner-harness.js";
import { SHAPES } from "./helpers/credential-samples.js";
import { brokenTextRules } from "./helpers/a1137-text-rules.js";

type Kind = "prod" | "dev" | "optional" | "peer" | "transitive" | "sub-project" | "drift";
type Eco = "npm" | "PyPI" | "crates.io" | "Go";
const NPM_LOCK = (entries: Record<string, Record<string, unknown>>, root: Record<string, unknown>) => JSON.stringify({ name: "svc", version: "1.0.0", lockfileVersion: 3, requires: true, packages: { "": root, ...entries } });

/** A project holding one bad copy (`bad`@`version`) of the given kind next to a clean zod (or flask, serde, errors). */
function writeProject(h: Harness, eco: Eco, kind: Kind, bad: string, version: string): void {
  if (eco === "npm") {
    const root: Record<string, unknown> = { name: "svc", version: "1.0.0", dependencies: { zod: "3.24.1" } };
    const entries: Record<string, Record<string, unknown>> = { "node_modules/zod": { version: "3.24.1" } };
    if (kind === "prod" || kind === "drift") {
      (root.dependencies as Record<string, string>)[bad] = kind === "drift" ? "0.7.29" : version;
      entries[`node_modules/${bad}`] = { version: kind === "drift" ? "0.7.29" : version };
    }
    if (kind === "dev") {
      root.devDependencies = { [bad]: version };
      entries[`node_modules/${bad}`] = { version, dev: true };
    }
    if (kind === "optional") {
      root.optionalDependencies = { [bad]: version };
      entries[`node_modules/${bad}`] = { version, optional: true };
    }
    if (kind === "peer") {
      root.peerDependencies = { [bad]: version };
      entries[`node_modules/${bad}`] = { version, peer: true };
    }
    if (kind === "transitive") entries[`node_modules/zod/node_modules/${bad}`] = { version };
    const pj = { name: "svc", version: "1.0.0", private: true, dependencies: root.dependencies, ...(root.devDependencies ? { devDependencies: root.devDependencies } : {}), ...(root.optionalDependencies ? { optionalDependencies: root.optionalDependencies } : {}), ...(root.peerDependencies ? { peerDependencies: root.peerDependencies } : {}) };
    h.write("package.json", JSON.stringify(pj));
    h.write("package-lock.json", NPM_LOCK(entries, root));
    if (kind === "drift") {
      h.write(`node_modules/${bad}/package.json`, JSON.stringify({ name: bad, version }));
      h.write("node_modules/zod/package.json", JSON.stringify({ name: "zod", version: "3.24.1" }));
    }
    if (kind === "sub-project") {
      const subRoot = { name: "web", version: "1.0.0", dependencies: { [bad]: version } };
      h.write("packages/web/package.json", JSON.stringify({ ...subRoot, private: true }));
      h.write("packages/web/package-lock.json", NPM_LOCK({ [`node_modules/${bad}`]: { version } }, subRoot));
    }
    return;
  }
  if (eco === "PyPI") {
    if (kind === "prod") h.write("requirements.txt", `flask==3.0.3\n${bad}==${version}\n`);
    if (kind === "dev") {
      h.write("requirements.txt", "flask==3.0.3\n");
      h.write("requirements-dev.txt", `${bad}==${version}\n`);
    }
    if (kind === "sub-project") {
      h.write("requirements.txt", "flask==3.0.3\n");
      h.write("svc/requirements.txt", `${bad}==${version}\n`);
    }
    return;
  }
  if (eco === "crates.io") {
    const pkg = (n: string, v: string) => `[[package]]\nname = "${n}"\nversion = "${v}"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\nchecksum = "${"1".repeat(64)}"\n`;
    const deps = kind === "prod" ? `serde = "1.0.210"\n${bad} = "${version}"\n` : `serde = "1.0.210"\n`;
    const dev = kind === "dev" ? `\n[dev-dependencies]\n${bad} = "${version}"\n` : "";
    h.write("Cargo.toml", `[package]\nname = "ingest"\nversion = "0.3.0"\nedition = "2021"\n\n[dependencies]\n${deps}${dev}`);
    const rootDeps = kind === "transitive" ? ["serde"] : ["serde", bad];
    h.write("Cargo.lock", `version = 3\n\n[[package]]\nname = "ingest"\nversion = "0.3.0"\ndependencies = [\n${rootDeps.sort().map((n) => ` "${n}",`).join("\n")}\n]\n\n${pkg("serde", "1.0.210")}${kind === "transitive" ? `dependencies = [\n "${bad}",\n]\n` : ""}\n${pkg(bad, version)}`);
    return;
  }
  const indirect = kind === "transitive" ? " // indirect" : "";
  h.write("go.mod", `module example.com/svc\n\ngo 1.22\n\nrequire (\n\tgithub.com/pkg/errors v0.9.1\n\t${bad} ${version}${indirect}\n)\n`);
  h.write("go.sum", `github.com/pkg/errors v0.9.1 h1:x=\ngithub.com/pkg/errors v0.9.1/go.mod h1:y=\n${bad} ${version} h1:z=\n${bad} ${version}/go.mod h1:w=\n`);
  h.write("main.go", "package main\nfunc main() {}\n");
}

const MALWARE: Record<Eco, { name: string; version: string; kinds: Kind[] }> = {
  npm: { name: "crossenvq", version: "1.0.1", kinds: ["prod", "dev", "optional", "peer", "transitive", "sub-project"] },
  PyPI: { name: "requestssq", version: "2.32.4", kinds: ["prod", "dev", "sub-project"] },
  "crates.io": { name: "rustdecimallq", version: "1.23.1", kinds: ["prod", "dev", "transitive"] },
  Go: { name: "github.com/evilq/modd", version: "v1.0.0", kinds: ["prod", "transitive"] },
};
const TASKS: Array<[string, Record<string, unknown>]> = [
  ["an unrelated task", { task: "Fix the typo in the README.", packages: [] }],
  ["a bare call", { task: "Fix the typo in the README." }],
];

describe("C1: installed malware or a placeholder anywhere in the full scan holds human_only (generated)", () => {
  let h: Harness;
  beforeEach(() => {
    h = createHarness();
    h.NPM.zod = { latest: "3.24.1", versions: { "3.24.1": {} } };
    h.PYPI.flask = { "3.0.3": {} };
    h.CRATES.serde = [{ vers: "1.0.210" }];
    h.GO["github.com/pkg/errors"] = ["v0.9.1"];
    h.NPM.crossenvq = { latest: "1.0.1", versions: { "1.0.1": {} } };
    h.NPM.uaparserjsq = { latest: "0.7.29", versions: { "0.7.28": {}, "0.7.29": {} } };
    h.NPM.flatmapstreammq = { latest: "0.0.1-security", versions: { "0.0.1-security": {} } };
    h.ADVISORIES.crossenvq = [adv("MAL-2026-91003", "crossenvq", [{ introduced: "0" }], "npm", "CRITICAL")];
    h.ADVISORIES.uaparserjsq = [adv("MAL-2026-91001", "uaparserjsq", [{ introduced: "0" }, { fixed: "0.7.29" }], "npm", "CRITICAL")];
    h.ADVISORIES.flatmapstreammq = [adv("MAL-2026-91002", "flatmapstreammq", [{ introduced: "0" }], "npm", "CRITICAL")];
    h.ADVISORIES.requestssq = [adv("MAL-2026-91031", "requestssq", [{ introduced: "0" }], "PyPI", "CRITICAL")];
    h.ADVISORIES.rustdecimallq = [adv("MAL-2026-91011", "rustdecimallq", [{ introduced: "0" }], "crates.io", "CRITICAL")];
    h.ADVISORIES["github.com/evilq/modd"] = [adv("MAL-2026-91021", "github.com/evilq/modd", [{ introduced: "0" }], "Go", "CRITICAL")];
  });
  afterEach(() => h.dispose());
  const brief = async (args: Record<string, unknown>) => (await executeWhatShouldIKnow(null, { ...args, project_path: h.dir } as never, await h.live())) as Record<string, any>;
  const CASES: Array<[string, Eco, Kind, string, string, "malware" | "placeholder", Record<string, unknown>]> = [];
  for (const [eco, m] of Object.entries(MALWARE) as Array<[Eco, (typeof MALWARE)[Eco]]>) for (const kind of m.kinds) for (const [t, args] of TASKS) CASES.push([`malware ${eco} ${kind}, ${t}`, eco, kind, m.name, m.version, "malware", args]);
  for (const [t, args] of TASKS) CASES.push([`malware npm drift-on-disk, ${t}`, "npm", "drift", "uaparserjsq", "0.7.28", "malware", args]);
  for (const kind of ["prod", "dev", "optional", "peer", "transitive", "sub-project"] as Kind[]) for (const [t, args] of TASKS) CASES.push([`placeholder npm ${kind}, ${t}`, "npm", kind, "flatmapstreammq", "0.0.1-security", "placeholder", args]);
  it.each(CASES)("%s", async (_l, eco, kind, name, version, what, args) => {
    writeProject(h, eco, kind, name, version);
    const r = await brief(args);
    expect(r.delegation_assessment.level, r.delegation_assessment.reason).toBe("human_only");
    const reason = String(r.delegation_assessment.reason);
    if (what === "placeholder") expect(reason).toContain(INSTALLED_PLACEHOLDER([`${name}@${version}`]));
    else expect(reason).toMatch(new RegExp(`^This project has ${name.replace(/[.]/g, "\\.")}@${version.replace(/[.]/g, "\\.")}${kind === "drift" ? " \\(in node_modules; the lockfile pins 0\\.7\\.29\\)" : ""} installed, which is recorded as malware`));
    expect(reason).not.toMatch(/nothing version-confirmed|node_modules runs a vulnerable copy/);
    expect(brokenTextRules(r, args)).toEqual([]);
  }, 60_000);
  it("INSTALLED_MALWARE names the copy on disk", () => {
    expect(INSTALLED_MALWARE(["uaparserjsq@0.7.28 (in node_modules; the lockfile pins 0.7.29)"])).toBe("This project has uaparserjsq@0.7.28 (in node_modules; the lockfile pins 0.7.29) installed, which is recorded as malware: a person must deal with that before any task is delegated.");
  });
});

describe("C2: a declared or read name touches its installed copy", () => {
  let h: Harness;
  beforeEach(() => {
    h = createHarness();
    h.NPM.zod = { latest: "3.24.1", versions: { "3.24.1": {} } };
    h.NPM.undici = { latest: "6.21.0", versions: { "5.8.0": {}, "6.21.0": {} } };
    h.ADVISORIES.undici = [adv("GHSA-g7c0-hhhh-0001", "undici", [{ introduced: "0" }, { fixed: "5.8.2" }], "npm", "HIGH")];
    h.npmProject({ zod: "3.24.1", undici: "5.8.0" }, {}, { zod: { version: "3.24.1" }, undici: { version: "5.8.0" } });
  });
  afterEach(() => h.dispose());
  const brief = async (args: Record<string, unknown>) => (await executeWhatShouldIKnow(null, { ...args, project_path: h.dir } as never, await h.live())) as Record<string, any>;
  it.each([
    ["declared public, the task text not naming it", { task: "Bump the HTTP client to the patched release.", packages: [{ ecosystem: "npm", name: "undici", version: "6.21.0", public: true }] }],
    ["declared in another case", { task: "Bump the HTTP client to the patched release.", packages: [{ ecosystem: "npm", name: "Undici", version: "6.21.0", public: true }] }],
  ])("%s: review_needed, the installed copy named as the vulnerable one, never 'Not about this task'", async (_l, args) => {
    const r = await brief(args);
    expect(r.delegation_assessment.level).toBe("review_needed");
    expect(r.delegation_assessment.reason).toMatch(/the installed undici 5\.8\.0 has a confirmed vulnerability \(GHSA-g7c0-hhhh-0001\); the declared [Uu]ndici 6\.21\.0 was checked: the installed copy is the vulnerable one/);
    expect(JSON.stringify(r.advisories)).not.toContain("Not about this task");
    expect(brokenTextRules(r, args)).toEqual([]);
  });
  it("a dependency the call does not touch is still 'Not about this task', level untouched", async () => {
    const r = await brief({ task: "Fix the typo in the README.", packages: [] });
    expect(r.delegation_assessment.level).toBe("safe_to_delegate");
    expect(JSON.stringify(r.advisories)).toContain("Not about this task");
  });
});

describe("C4: the reading copy folds dashes and slashes, and drops markup by its exact rule", () => {
  it("each Dash_Punctuation character and DASH_EXTRAS fold to - (generated from the property)", () => {
    let n = 0;
    for (let cp = 0; cp <= 0x10ffff; cp++) {
      if (cp >= 0xd800 && cp <= 0xdfff) continue;
      const ch = String.fromCodePoint(cp);
      if (!/^\p{Pd}$/u.test(ch) && !DASH_EXTRAS.includes(ch)) continue;
      n++;
      expect(foldName(`a${ch}b`), cp.toString(16)).toBe("a-b");
    }
    expect(n).toBeGreaterThan(25);
    for (const ch of SLASH_LOOKALIKES) expect(foldName(`a${ch}b`), ch.codePointAt(0)!.toString(16)).toBe("a/b");
    for (const cp of [0x2e3a, 0x2e3b, 0x058a, 0x05be, 0x1806, 0x2e17, 0x301c, 0x30a0, 0x02d7, 0x1400]) expect(readingCopy(`a${String.fromCodePoint(cp)}b`)).toBe("a-b");
    for (const cp of [0x29f8, 0x2571, 0x1735, 0x3033, 0x27cb]) expect(readingCopy(`a${String.fromCodePoint(cp)}b`)).toBe("a/b");
  });
  it.each([
    ["Fix __init__.py", "Fix __init__.py"],
    ["Run __main__ once", "Run __main__ once"],
    ["rename snake__case", "rename snake__case"],
    ["**bold** text", "bold text"],
    ["__bold__ stays", "__bold__ stays"],
    ["__two words__ go", "two words go"],
    ["run **npm i x**.", "run npm i x."],
  ])("%j", (input, out) => {
    expect(readingCopy(input)).toBe(out);
  });
});

describe("C5: request ids, masking to a fixed point, trailers, line breaks", () => {
  const tok = SHAPES[0];
  it("a request whose id has a credential's shape is not run: one -32600 with id null (stdio gate)", async () => {
    const replies: unknown[] = [];
    const gate = new StdioGate((m) => replies.push(m));
    const passed: string[] = [];
    gate.on("data", (d) => passed.push(String(d)));
    gate.write(`${JSON.stringify({ jsonrpc: "2.0", id: tok, method: "tools/list" })}\n`);
    await new Promise((r) => setTimeout(r, 50));
    expect(passed.join("")).toBe("");
    expect(replies).toEqual([{ jsonrpc: "2.0", id: null, error: { code: -32600, message: CREDENTIAL_ID_REFUSED } }]);
    expect(JSON.stringify(replies).includes(tok)).toBe(false);
  });
  it("masking reaches a fixed point: two shapes glued are both masked (each pair, generated)", () => {
    for (const a of SHAPES) for (const b of SHAPES) {
      const out = screenText(`x ${a}${b} y`);
      expect(hasCredentialShape(out), `${a.slice(0, 6)}+${b.slice(0, 6)}`).toBe(false);
    }
  });
  it("trailers are screened", async () => {
    const server = createServer((_req, res) => {
      screenResponse(res);
      res.writeHead(200, { "content-type": "text/plain", trailer: "x-echo" });
      res.write("ok\n");
      res.addTrailers({ "x-echo": `bad ${tok}` });
      res.end();
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
    const port = (server.address() as AddressInfo).port;
    const trailers = await new Promise<Record<string, unknown>>((resolve, reject) => {
      const req = httpRequest({ host: "127.0.0.1", port, path: "/" }, (res) => {
        res.on("data", () => undefined);
        res.on("end", () => resolve(res.trailers));
      });
      req.on("error", reject);
      req.end();
    });
    server.close();
    expect(JSON.stringify(trailers).includes(tok)).toBe(false);
    expect(JSON.stringify(trailers)).toContain(`${tok.slice(0, 4)}...`);
  });
  describe("TASK_FOLDED ignores line breaks U+2028, U+2029 and NEL", () => {
    let h: Harness;
    beforeEach(() => {
      h = createHarness();
      h.NPM.hono = { latest: "4.6.14", versions: { "4.6.14": {} } };
      h.npmProject({ hono: "4.6.14" }, {}, { hono: { version: "4.6.14" } });
    });
    afterEach(() => h.dispose());
    it.each(["\u2028", "\u2029", "\u0085"])("%j between words is no fold", async (br) => {
      const r = (await executeWhatShouldIKnow(null, { task: `Refactor the routes.${br}Keep hono.`, packages: [], project_path: h.dir } as never, await h.live())) as Record<string, any>;
      expect(r.task_note).toBeUndefined();
      expect(TASK_FOLDED.length).toBeGreaterThan(0);
    });
  });
});

describe("C3: the fixed sentences of the briefing are listed with their rules", () => {
  it("the sentence table names each sentence-shaped literal of the briefing's modules", async () => {
    const { literalsOf, SENTENCES } = await import("./helpers/a1140-sentence-table.js");
    const listed = new Set(SENTENCES.map(([t]) => t));
    const lits = literalsOf(path.join(__dirname, "..", "tools"));
    expect(lits.length).toBeGreaterThan(150);
    expect(lits.filter((l) => !listed.has(l.text)).map((l) => `${l.file}:${l.line} ${l.text.slice(0, 80)}`)).toEqual([]);
    const present = new Set(lits.map((l) => l.text));
    expect(SENTENCES.filter(([t]) => !present.has(t)).map(([t]) => t.slice(0, 80))).toEqual([]);
    expect(fs.existsSync(path.join(__dirname, "helpers", "a1140-sentence-table.ts"))).toBe(true);
  });
});
