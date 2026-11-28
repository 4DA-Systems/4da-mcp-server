// SPDX-License-Identifier: Apache-2.0
/**
 * Round 8: the sixth independent check's rules, one block per rule (D1-D5, m1-m11). Stubbed fetch over a canned
 * world: zqxcrit4 1.0.0 critical (fixed 2.0.0), zqx-vuln-py 1.0.0 critical, zqx-vuln-rs 1.0.0 critical, node-forge
 * 0.10.0 high, smallvec 1.6.0 high. The reviewer's own cases are vendored apart (a1131-confirm-review6).
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { executeWhatShouldIKnow } from "../tools/what-should-i-know.js";
import { executeDependencyCheck } from "../tools/dependency-check.js";
import { RAW_SOURCE, SOURCE_SPELLINGS, STAYS_REVIEW } from "../tools/briefing-command-check.js";
import { POETRY_SPEC } from "../tools/briefing-canonical.js";
import { validateToolArgs } from "../tool-args.js";
import { TOOL_REGISTRY } from "../schema-registry.js";
import { adv, createHarness, fixedIn, type Harness } from "./helpers/a1119-planner-harness.js";

let h: Harness;
let live: Awaited<ReturnType<Harness["live"]>> | null = null;
beforeEach(() => {
  h = createHarness();
  for (const n of ["zqxok", "pino", "ky", "rmp-serde", "winston", "ms"]) h.NPM[n] = { latest: "9.6.0", versions: { "1.0.0": {}, "9.6.0": {} } };
  h.NPM.zqxcrit4 = { latest: "2.0.0", versions: { "1.0.0": {}, "2.0.0": {} } };
  h.NPM["node-forge"] = { latest: "1.3.1", versions: { "0.10.0": {}, "1.3.1": {} } };
  h.PYPI["zqx-vuln-py"] = { "1.0.0": {}, "2.0.0": {} };
  h.PYPI.requests = { "2.32.3": {} };
  h.CRATES["zqx-vuln-rs"] = [{ vers: "1.0.0" }, { vers: "2.0.0" }];
  h.CRATES.smallvec = [{ vers: "1.6.0" }, { vers: "1.13.2" }];
  h.CRATES["rmp-serde"] = [{ vers: "1.3.0" }];
  h.CRATES.serde = [{ vers: "1.0.210" }];
  h.CRATES.thiserror = [{ vers: "2.0.9" }];
  h.ADVISORIES.zqxcrit4 = [adv("GHSA-zq8c-0000-0001", "zqxcrit4", fixedIn("2.0.0"), "npm", "CRITICAL")];
  h.ADVISORIES["node-forge"] = [adv("GHSA-zq8c-0000-0002", "node-forge", fixedIn("1.3.1"), "npm", "HIGH")];
  h.ADVISORIES["zqx-vuln-py"] = [adv("PYSEC-2026-8001", "zqx-vuln-py", fixedIn("2.0.0"), "PyPI", "CRITICAL")];
  h.ADVISORIES["zqx-vuln-rs"] = [adv("RUSTSEC-2026-8001", "zqx-vuln-rs", fixedIn("2.0.0"), "crates.io", "CRITICAL")];
  h.ADVISORIES.smallvec = [adv("RUSTSEC-2026-8002", "smallvec", fixedIn("1.6.1"), "crates.io", "HIGH")];
});
afterEach(() => {
  live = null;
  h.dispose();
});
const brief = async (args: Record<string, unknown>) => {
  live ??= await h.live();
  return (await executeWhatShouldIKnow(null, { ...args, project_path: h.dir } as never, live)) as Record<string, any>;
};
const npm = () => h.npmProject({}, {}, {});
const cargo = (deps = "") => h.write("Cargo.toml", `[package]\nname = "app"\nversion = "0.1.0"\n\n[dependencies]\n${deps}`);
const py = () => h.write("requirements.txt", "flask==3.0.3\n");
const level = (r: Record<string, any>) => r.delegation_assessment.level as string;

describe("D1: a version the task writes is checked, or holds review_needed", () => {
  it.each([
    ["Pin zqxcrit4 to 1.0.0 in package.json.", "npm", "zqxcrit4"],
    ["Add zqxcrit4 version 1.0.0", "npm", "zqxcrit4"],
    ["Downgrade node-forge to 0.10.0", "npm", "node-forge"],
  ])("(round 9, E1) %s with no declared version is confirmation_needed: the declaration is incomplete", async (task, ecosystem, name) => {
    npm();
    const r = await brief({ task, packages: [{ ecosystem, name, public: true }] });
    expect(level(r)).toBe("confirmation_needed");
    expect(r.task_packages.status).toBe("confirmation_needed");
    expect(r.delegation_assessment.reason).toContain('State `version` for each package you declared public: the version or range you will write, or "latest" for the newest release');
    expect(r.task_packages.next_step).toContain(`(checked so far: ${name} at latest)`);
  });

  it("(b) the declared version is checked: Pin zqxcrit4 to 1.0.0 declared 1.0.0 is human_only; declared latest is the caller's statement", async () => {
    npm();
    expect(level(await brief({ task: "Pin zqxcrit4 to 1.0.0 in package.json.", packages: [{ ecosystem: "npm", name: "zqxcrit4", version: "1.0.0", public: true }] }))).toBe("human_only");
    const r = await brief({ task: "Pin zqxcrit4 to 1.0.0 in package.json.", packages: [{ ecosystem: "npm", name: "zqxcrit4", version: "latest", public: true }] });
    expect(r.delegation_assessment.reason).not.toContain("State `version`");
  });

  it.each([
    ["Add zqxcrit4@1.0.0 to the dependencies.", "npm", "zqxcrit4", npm],
    ["Install `zqxcrit4@1.0.0` with npm.", "npm", "zqxcrit4", npm],
    ["Add zqx-vuln-py==1.0.0 to requirements.txt.", "PyPI", "zqx-vuln-py", py],
    ['Add zqx-vuln-rs = "1.0.0" under [dependencies] in Cargo.toml.', "crates.io", "zqx-vuln-rs", () => cargo()],
    ['Add "zqxcrit4": "1.0.0" to package.json.', "npm", "zqxcrit4", npm],
  ] as const)("(a) %s: the form ties the spec to the name, checked: human_only", async (task, ecosystem, name, project) => {
    project();
    const r = await brief({ task, packages: [{ ecosystem, name, public: true }] });
    expect(level(r)).toBe("human_only");
  });

  it("(a) the form never moves a spec to another ecosystem: zqx-vuln-py==1.0.0 is no npm spec", async () => {
    npm();
    const r = await brief({ task: "Add zqx-vuln-py==1.0.0", packages: [{ ecosystem: "npm", name: "zqx-vuln-py", version: "2.0.0", public: true }] });
    expect(JSON.stringify(r.requested_versions ?? [])).not.toContain("1.0.0");
  });

  it("(c, round 9) the schema says `version` is needed for a complete answer, first", () => {
    const schema = JSON.stringify(TOOL_REGISTRY.what_should_i_know.definition);
    expect(schema).not.toContain("default: the version the task writes");
    expect(schema).not.toContain("no form ties to a package");
    expect(schema).toContain("Needed for a complete answer: the version or range you will write");
  });
});

describe("D2: C3 is a courtesy check on an exact list", () => {
  const FORMS = [(x: string) => x, (x: string) => `Use \`${x}\` here.`, (x: string) => `Set it with ${x} today.`, (x: string) => `(see ${x})`];
  const EXAMPLES: Record<string, string> = {
    "--registry": "npm install --registry https://n.corp zqxok", "--config.registry=": "pnpm add --config.registry=https://n.corp zqxok", "--userconfig": "npm install --userconfig ./corp.npmrc zqxok",
    "registry=": "registry=https://n.corp", ":registry": "@corp:registry=https://n.corp", "--index-url": "pip install --index-url https://p.corp zqxok", "--extra-index-url": "pip install --extra-index-url https://p.corp zqxok",
    "--default-index": "uv add --default-index https://p.corp zqxok", "--index": "uv add --index https://p.corp zqxok", "--find-links": "pip install --find-links ./wheels zqxok", "pip -i <index>": "pip install -i https://p.corp zqxok",
    "pip -f <links>": "pip install -f ./wheels zqxok", "--source": "poetry add --source corp zqxok", "--git": "cargo install --git https://g.corp/x zqxok", "--path": "cargo install --path ../x", "npmRegistryServer": "npmRegistryServer: https://n.corp",
    "[[tool.uv.index]]": "[[tool.uv.index]]", "[[index]] (uv.toml)": "[[index]]", "[tool.uv.sources]": "[tool.uv.sources]", "[[tool.poetry.source]]": "[[tool.poetry.source]]", "[install.scopes] (bunfig.toml)": "[install.scopes]",
    "[registries]": "[registries]", "[registries.<name>]": "[registries.corp]", "[registry]": "[registry]", "[source.<name>]": "[source.crates-io]", "[patch.<name>]": "[patch.crates-io]", "a go.mod replace directive with =>, single-line or block": "replace corp.example/x => ../x",
    npm_config_registry: "npm_config_registry=https://n.corp", NPM_CONFIG_USERCONFIG: "NPM_CONFIG_USERCONFIG=./x", YARN_REGISTRY: "YARN_REGISTRY=https://n.corp", YARN_NPM_REGISTRY_SERVER: "YARN_NPM_REGISTRY_SERVER=https://n.corp",
    PIP_INDEX_URL: "PIP_INDEX_URL=https://p.corp", PIP_EXTRA_INDEX_URL: "PIP_EXTRA_INDEX_URL=https://p.corp", PIP_FIND_LINKS: "PIP_FIND_LINKS=./w", UV_INDEX: "UV_INDEX=https://p.corp", UV_INDEX_URL: "UV_INDEX_URL=https://p.corp",
    UV_DEFAULT_INDEX: "UV_DEFAULT_INDEX=https://p.corp", UV_EXTRA_INDEX_URL: "UV_EXTRA_INDEX_URL=https://p.corp", "CARGO_REGISTRIES_<NAME>_INDEX": "CARGO_REGISTRIES_CORP_INDEX=https://c.corp", CARGO_REGISTRY_DEFAULT: "CARGO_REGISTRY_DEFAULT=corp",
    GOPRIVATE: "GOPRIVATE=corp.example", GOPROXY: "GOPROXY=https://g.corp", GONOSUMDB: "GONOSUMDB=corp.example", GONOPROXY: "GONOPROXY=corp.example",
  };
  it("every listed spelling has an example", () => {
    expect(SOURCE_SPELLINGS.filter((s) => !(s in EXAMPLES))).toEqual([]);
  });
  it.each(Object.entries(EXAMPLES).flatMap(([k, ex]) => FORMS.map((f, i) => [`${k} #${i}`, f(ex)] as const)))("%s triggers", (_k, task) => {
    expect(RAW_SOURCE.test(task)).toBe(true);
  });
  it.each(["goprivate=corp.example go get x", "Pip_Index_Url=https://p.corp pip install x"])("environment names in any case: %s", (task) => {
    expect(RAW_SOURCE.test(task)).toBe(true);
  });
  it("the tool and `public` descriptions say first: public: false for private sources; public: true is sent", () => {
    const def = TOOL_REGISTRY.what_should_i_know.definition as unknown as { description: string; inputSchema: { properties: { packages: { items: { properties: { public: { description: string } } } } } } };
    expect(def.description).toContain("Declare public: false for anything the task or the project takes from a private registry, an index of its own, git or a path");
    expect(def.description).toContain("a name declared public: true is sent to the public registry");
    expect(def.inputSchema.properties.packages.items.properties.public.description).toMatch(/^false for anything from a private registry/);
  });
});

// Round 13, U1: the raw-text dismissed-word rule (D3) and its tests are removed.
describe("D4: consumption is by occurrence", () => {
  it.each([
    ["Keep smallvec at 1.6.0 and add rmp-serde:\n```\ncargo add rmp-serde -F smallvec\n```", "smallvec"],
    ["Keep smallvec at 1.6.0 and add rmp-serde:\n```\ncargo add -p smallvec rmp-serde\n```", "smallvec"],
  ])("%s: the prose mention is read as before", async (task, dep) => {
    cargo('smallvec = "1.6.0"\n');
    h.write("Cargo.lock", 'version = 3\n\n[[package]]\nname = "smallvec"\nversion = "1.6.0"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n');
    const r = await brief({ task, packages: [{ ecosystem: "crates.io", name: "rmp-serde", public: true }] });
    expect((r.task_dependencies ?? []).map((d: { package: string }) => d.package)).toContain(dep);
  });
  it.each(["-w", "--filter"])("npm/pnpm %s value that is also named in prose", async (flag) => {
    h.npmProject({ ky: "1.0.0" }, {}, { ky: { version: "1.0.0" } });
    const r = await brief({ task: `Bump ky in the web workspace:\n\`\`\`\npnpm add ${flag} ky zqxok\n\`\`\``, packages: [{ ecosystem: "npm", name: "zqxok", public: true }] });
    expect((r.task_dependencies ?? []).map((d: { package: string }) => d.package)).toContain("ky");
  });
});

describe("D5: Poetry's ^ / ~ in a command", () => {
  it("says what to write, and that the command as written stays review_needed", async () => {
    py();
    const r = await brief({ task: "poetry add zqx-vuln-py@^2.0", packages: [{ ecosystem: "PyPI", name: "zqx-vuln-py", version: ">=2.0,<3.0", public: true }] });
    expect(level(r)).toBe("review_needed");
    expect(r.delegation_assessment.reason).toContain(POETRY_SPEC);
  });
  it("following the remedy literally ends clean", async () => {
    py();
    const r = await brief({ task: 'poetry add "zqx-vuln-py>=2.0,<3.0"', packages: [{ ecosystem: "PyPI", name: "zqx-vuln-py", version: ">=2.0,<3.0", public: true }] });
    expect(r.delegation_assessment.reason).not.toMatch(/could not read whole/);
  });
  it("the `version` schema lists what is accepted per ecosystem, and says Poetry's ^ and ~ are not", () => {
    expect(JSON.stringify(TOOL_REGISTRY.what_should_i_know.definition)).toContain("PyPI: PEP 440, not Poetry's ^ or ~");
  });
});

describe("minors", () => {
  it('m1: an npm tilde range in a snippet is a range, checked, never a path source', async () => {
    npm();
    const r = await brief({ task: 'package.json:\n```\n"dependencies": { "zqxcrit4": "~1.0.0" }\n```', packages: [{ ecosystem: "npm", name: "zqxcrit4", public: true }] });
    expect(JSON.stringify(r.task_packages.private)).not.toContain("zqxcrit4");
    expect(level(r)).toBe("human_only");
  });
  it("m2: a snippet's git entry declared public says the snippet's own source", async () => {
    npm();
    const r = await brief({ task: 'package.json:\n```\n"dependencies": { "zqxgitdep": "github:corp/x#main" }\n```', packages: [{ ecosystem: "npm", name: "zqxgitdep", public: true }] });
    const row = (r.task_packages.private as Array<{ name: string; basis: string }>).find((p) => p.name === "zqxgitdep");
    expect(row?.basis).toBe("the manifest snippet in the task takes it from git, a path, a registry or the workspace, not the public registry");
  });
  it("m3: a word ending in a period ends the command, whatever the next word's case", async () => {
    npm();
    const r = await brief({ task: "Run npm install pino. zqxprivafter is our service name.", packages: [{ ecosystem: "npm", name: "pino", public: true }] });
    expect(JSON.stringify(r.task_packages.to_confirm)).not.toMatch(/zqxprivafter|"is"|"our"/);
  });
  it("m4: a word past the 120th character of a command not read whole is not offered", async () => {
    npm();
    const r = await brief({ task: `npm install --prefer-online ${Array.from({ length: 20 }, (_, i) => `zqxfill${i}`).join(" ")} zqxlastword` });
    expect(JSON.stringify(r.task_packages.to_confirm)).not.toContain("zqxlastword");
  });
  // A git entry is positively read as the snippet's own source (C5), so this snippet IS read whole: its two registry
  // entries are strict pairs that wait, the git one is private.
  it("m4: a snippet with a git entry is read whole: its registry entries wait, the git one is private", async () => {
    npm();
    const r = await brief({ task: 'package.json:\n```\n"dependencies": { "zqxprivsn1": "1.0.0", "zqxprivsn2": "github:corp/x#main", "zqxprivsn3": "^2" }\n```' });
    expect((r.task_packages.to_confirm as Array<{ name: string }>).map((e) => e.name).sort()).toEqual(["zqxprivsn1", "zqxprivsn3"]);
    expect((r.task_packages.private as Array<{ name: string }>).map((e) => e.name)).toEqual(["zqxprivsn2"]);
  });
  it.each(['package.json:\n```\n"dependencies": { "zqxprivsn4": "1.0.0", "x": { "y": 1 } }\n```', 'Add to package.json: "dependencies": { "zqxprivsn5": "1.0.0", "zqxbad": 12 }'])("m4: a snippet not read whole offers nothing: %s", async (task) => {
    npm();
    const r = await brief({ task });
    expect(JSON.stringify(r.task_packages), JSON.stringify(r.task_packages)).not.toMatch(/zqxprivsn/);
  });
  it("m5: a version never moves to another pair (Cargo snippet with serde and thiserror)", async () => {
    cargo('serde = "1.0.210"\n');
    h.write("Cargo.lock", 'version = 3\n\n[[package]]\nname = "serde"\nversion = "1.0.210"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n');
    const r = await brief({ task: 'Cargo.toml:\n```\n[dependencies]\nserde = "1.0.210"\nthiserror = "2.0.9"\n```', packages: [{ ecosystem: "crates.io", name: "thiserror", version: "2.0.9", public: true }] });
    expect(JSON.stringify(r)).not.toMatch(/crosses 1 major version of serde/);
  });
  it("m6: a number in not_packages refuses that entry only", async () => {
    expect(validateToolArgs("what_should_i_know", TOOL_REGISTRY.what_should_i_know.definition.inputSchema, { task: "npm install zqxok", not_packages: [5, "x"] })).toBeNull();
    npm();
    const r = await brief({ task: "npm install zqxok", packages: [{ ecosystem: "npm", name: "zqxok", public: true }], not_packages: [5, "x"] });
    expect(JSON.stringify(r.task_packages.not_read)).toContain("not_packages[0]");
  });
  it("m7: 110 operands: review_needed with the fixed reason, never an unanswerable confirmation_needed", async () => {
    npm();
    const names = Array.from({ length: 110 }, (_, i) => `zqxbulk${i}`);
    const r = await brief({ task: `\`\`\`\nnpm install ${names.join(" ")}\n\`\`\``, packages: names.slice(0, 100).map((name) => ({ ecosystem: "npm", name, version: "latest", public: true })) });
    expect(level(r)).toBe("review_needed");
    expect(r.delegation_assessment.reason).toContain("more than 100 names that may be packages");
  });
  // Round 9, E3: no remedy; the truth for a command inside a sentence, a comma or a non-plain word.
  it("E3: a dismissed word of a command inside a sentence says it stays review_needed, without a remedy", async () => {
    npm();
    const s = await brief({ task: "Please npm install zqxok and wire it in", packages: [{ ecosystem: "npm", name: "zqxok", version: "latest", public: true }], not_packages: ["and", "wire", "it", "in"] });
    expect(s.delegation_assessment.reason).toContain(STAYS_REVIEW);
    expect(s.delegation_assessment.reason).not.toMatch(/clean answer/);
  });
  it.each(["npm ins zqxok", "npm isntall zqxok", "npm instal zqxok", "bun a zqxok"])("m9: %s is a command", async (task) => {
    npm();
    const r = await brief({ task, packages: [] });
    expect((r.task_packages.to_confirm as Array<{ name: string; seen: string }>).find((e) => e.name === "zqxok")?.seen).toMatch(/operand of an install command/);
  });
  it("m10: words of a command not read whole are looked up by no reader", async () => {
    py();
    await brief({ task: "pip install requests, zqxdualpy", packages: [] });
    expect(h.requests.filter((u) => /pypi\.org\/pypi\/requests/.test(u))).toEqual([]);
  });
  it("m11: dependency_check with every item refused says so without an empty count", async () => {
    live ??= await h.live();
    const r = (await executeDependencyCheck(null, { items: [{ ecosystem: "npm", package: "zqxok", to: "1.0.0" }, { ecosystem: "Go", package: "github.com/!zqx/mod", to: "v1.0.0" }] }, live)) as { summary: string };
    expect(r.summary).not.toMatch(/0 checked: \./);
  });
});
