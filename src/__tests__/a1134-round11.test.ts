// SPDX-License-Identifier: Apache-2.0
/**
 * Round 11: the ninth independent check. P1 the contract promises one thing (the level rests on the declaration);
 * task-text reading is best effort. P2 everyday spellings read. P3 a dismissed word is compared by its bare name. P4
 * every reader is one pass, capped, and checks the deadline. P5 "a command this briefing does not read" in two exact
 * cases only. P7 the "split the task" text is reachable over stdio. Stubbed fetch over a canned world.
 */
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import * as path from "node:path";
import { pathToFileURL } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { executeWhatShouldIKnow, whatShouldIKnowTool } from "../tools/what-should-i-know.js";
import { bareName, manifestPairs, pep508, requirementsPairs, strictEvidence, unreadCommandLines, wordsAfterManager } from "../tools/briefing-command-check.js";
import { MANAGER_NAMES } from "../tools/briefing-canonical.js";
import { MAX_SNIPPETS } from "../tools/briefing-snippets.js";
import { TOOL_REGISTRY } from "../schema-registry.js";
import { adv, createHarness, fixedIn, type Harness } from "./helpers/a1119-planner-harness.js";
import { resultText, serverEntry, stdioSession } from "./helpers/stdio-session.js";

let h: Harness;
let live: Awaited<ReturnType<Harness["live"]>> | null = null;
beforeEach(() => {
  h = createHarness();
  h.NPM.zqxcrit4 = { latest: "2.0.0", versions: { "1.0.0": {}, "1.0.1": {}, "2.0.0": {} } };
  h.NPM.zqxok = { latest: "1.0.0", versions: { "1.0.0": {} } };
  h.PYPI["zqx-vuln-py"] = { "1.0.0": {}, "2.0.0": {} };
  h.PYPI.flask = { "3.0.3": {} };
  h.CRATES["zqx-vuln-rs"] = [{ vers: "1.0.0" }, { vers: "2.0.0" }];
  h.ADVISORIES.zqxcrit4 = [adv("GHSA-zq11-0000-0001", "zqxcrit4", fixedIn("2.0.0"), "npm", "CRITICAL")];
  h.ADVISORIES["zqx-vuln-py"] = [adv("PYSEC-2026-1101", "zqx-vuln-py", fixedIn("2.0.0"), "PyPI", "CRITICAL")];
  h.ADVISORIES["zqx-vuln-rs"] = [adv("RUSTSEC-2026-1101", "zqx-vuln-rs", fixedIn("2.0.0"), "crates.io", "CRITICAL")];
});
afterEach(() => {
  live = null;
  h.dispose();
});
const brief = async (args: Record<string, unknown>) => {
  live ??= await h.live();
  return (await executeWhatShouldIKnow(null, { ...args, project_path: h.dir } as never, live)) as Record<string, any>;
};
const level = (r: Record<string, any>) => r.delegation_assessment.level as string;
const py = () => h.write("requirements.txt", "flask==3.0.3\n");
const npm = () => h.npmProject({}, {}, {});
const rs = () => h.write("Cargo.toml", '[package]\nname = "app"\nversion = "0.1.0"\n\n[dependencies]\n');
const atLatest = (ecosystem: string, name: string) => [{ ecosystem, name, version: "latest", public: true }];

describe("P1: one promise, then best effort", () => {
  it("the description states the promise first and promises no complete reading", () => {
    const d = whatShouldIKnowTool.description;
    expect(d.indexOf("The level rests on your declaration")).toBeLessThan(d.indexOf("best effort"));
    expect(d).toContain("Declare the version the task writes.");
    const texts = [d, TOOL_REGISTRY.what_should_i_know.summary, JSON.stringify(whatShouldIKnowTool.inputSchema)];
    for (const t of texts) for (const banned of [/\bexactly these\b/i, /three outcomes/i, /in silence/i, /bare or spaced/i, /every line/i]) expect(t).not.toMatch(banned);
  });
  it("property: no safe_to_delegate while a public entry lacks `version`", async () => {
    npm();
    for (const task of ["add zqxok", "npm install zqxok", "Refactor the router.", "requirements.txt\nflask==3.0.3", "```\nnpm i zqxok\n```"]) {
      const r = await brief({ task, packages: [{ ecosystem: "npm", name: "zqxok", public: true }] });
      expect(level(r), task).not.toBe("safe_to_delegate");
    }
  });
});

describe("P2: everyday spellings (improvements, not promises)", () => {
  it.each([
    ["Add zqx-vuln-py == 1.0.0 to the project.", "PyPI", "zqx-vuln-py"],
    ["Add zqx-vuln-py < 2 to the project.", "PyPI", "zqx-vuln-py"],
    ["Add zqx-vuln-py >= 1.0, < 2 to the project.", "PyPI", "zqx-vuln-py"],
    ["Add zqx-vuln-py[cli, http]==1.0.0 to the project.", "PyPI", "zqx-vuln-py"],
    ['Run: echo "zqx-vuln-py == 1.0.0" >> requirements.txt', "PyPI", "zqx-vuln-py"],
    ['Add zqxcrit4@">=1 <2" to the project.', "npm", "zqxcrit4"],
    ["Add zqxcrit4@'~1.0.0 || ~1.0.1' to the project.", "npm", "zqxcrit4"],
    ["Use these requirements:\n```txt\nzqx-vuln-py <2\nflask==3.0.3\n```", "PyPI", "zqx-vuln-py"],
    ["Write this to requirements.txt:\n\n```\nzqx-vuln-py <2\nflask==3.0.3\n```", "PyPI", "zqx-vuln-py"],
    ["requirements.txt:\n~~~\nzqx-vuln-py <2\n~~~", "PyPI", "zqx-vuln-py"],
    ["Update requirements.txt:\n# security pins\nzqx-vuln-py <2\nflask==3.0.3", "PyPI", "zqx-vuln-py"],
    ["Add to requirements.txt: zqx-vuln-py ~= 1.0 (we need the old API).", "PyPI", "zqx-vuln-py"],
    ["cat > requirements.txt <<EOF\nzqx-vuln-py <2\nEOF", "PyPI", "zqx-vuln-py"],
    ['In pyproject.toml:\n```toml\n[project.optional-dependencies]\ndev = ["zqx-vuln-py < 2"]\n```', "PyPI", "zqx-vuln-py"],
    ['pyproject.toml:\n```toml\n[dependency-groups]\ntest = [\n  "zqx-vuln-py<2",\n  {include-group = "lint"},\n]\n```', "PyPI", "zqx-vuln-py"],
    ["Cargo.toml:\n```toml\n[target.'cfg(windows)'.dependencies]\nzqx-vuln-rs = { version = \"1.0.0\" }\n```", "crates.io", "zqx-vuln-rs"],
    ['Cargo.toml:\n```toml\n[workspace.dependencies]\nzqx-vuln-rs = { version = "1.0.0" }\n```', "crates.io", "zqx-vuln-rs"],
    ['Cargo.toml:\n```toml\n[ dependencies ]\nzqx-vuln-rs = { version = "1.0.0" }\n```', "crates.io", "zqx-vuln-rs"],
    ['Cargo.toml:\n```toml\n[dependencies.zqx-vuln-rs]\nversion = "1.0.0"\n```', "crates.io", "zqx-vuln-rs"],
    ['Cargo.toml:\n```toml\n[dev-dependencies]\nzqx-vuln-rs = { version = "1.0.0", features = ["x"] }\n```', "crates.io", "zqx-vuln-rs"],
    ['Cargo.toml:\n```toml\n[build-dependencies]\nzqx-vuln-rs = "1.0.0"\n```', "crates.io", "zqx-vuln-rs"],
  ])("%s: declared at latest, the bad release it writes is read (never safe)", async (task, ecosystem, name) => {
    if (ecosystem === "PyPI") py();
    else if (ecosystem === "npm") npm();
    else rs();
    const r = await brief({ task, packages: atLatest(ecosystem, name) });
    expect(level(r)).not.toBe("safe_to_delegate");
  });
  it("ledger equality: npm's blank-separated range is not cut into a PEP 440 spec (add lodash >=4.17.0 <4.17.21)", () => {
    expect(strictEvidence("add lodash >=4.17.0 <4.17.21").formPairs).toEqual([]);
    expect(strictEvidence("Add zqx-vuln-py >= 1.0, < 2 to the project.").formPairs.map((f) => f.spec)).toEqual([">=1.0,<2"]);
  });
  it("#82: a one-line tail it cannot read says the snippet is not read whole", () => {
    expect(manifestPairs("Add to requirements.txt: the usual web stack, pinned").unreadable.length).toBeGreaterThan(0);
    expect(manifestPairs("Add to requirements.txt: zqx-vuln-py ~= 1.0 (we need the old API).").pairs.map((p) => `${p.name}${p.version}`)).toEqual(["zqx-vuln-py~=1.0"]);
  });
  it("#72: the -r file reader reads (<2), spaced == and a -c file; a direct reference makes the file not read whole", () => {
    const files: Record<string, string> = { "r.txt": "zqx-vuln-py (<2)\nflask == 3.0.3\n-c c.txt\n", "c.txt": "zqx-vuln-py<2\n", "u.txt": "zqx-vuln-py @ https://files.example/zqx_vuln_py-1.0.0.whl\n" };
    const read = (f: string) => files[f] ?? null;
    const r = requirementsPairs("/p", ["r.txt"], read);
    expect(r.map((p) => `${p.name}${p.version ?? ""}`)).toEqual(["zqx-vuln-py<2", "flask==3.0.3", "zqx-vuln-py<2"]);
    expect(r.notWhole).toBeUndefined();
    expect(requirementsPairs("/p", ["u.txt"], read).notWhole).toBe(true);
  });
  it("pep508 reads blanks, extras with blanks, parentheses, markers and --hash", () => {
    for (const [line, spec] of [["zqx-vuln-py == 1.0.0", "==1.0.0"], ["zqx-vuln-py >= 1.0, < 2", ">=1.0,<2"], ["zqx-vuln-py[cli, http]==1.0.0", "==1.0.0"], ["zqx-vuln-py (<2)", "<2"], ['zqx-vuln-py == 1.0.0 ; python_version >= "3.8"', "==1.0.0"], ["zqx-vuln-py==1.0.0 --hash=sha256:0f0e", "==1.0.0"]] as const) {
      const d = pep508(line);
      expect(d !== null && d !== "skip" && d.spec, line).toBe(spec);
    }
  });
  it("docs lane: a marker word and an alias key are not offered", async () => {
    py();
    const a = await brief({ task: '```requirements\nzqx-vuln-py <2 ; python_version >= "3.8"\n```', packages: [] });
    expect(JSON.stringify(a.task_packages.to_confirm ?? [])).not.toContain("python_version");
    npm();
    const b = await brief({ task: 'Set "zqxal2": "npm:zqxcrit4@2.0.0" in package.json.', packages: [] });
    expect(JSON.stringify(b.task_packages.to_confirm ?? [])).not.toContain("zqxal2");
    expect(strictEvidence('Set "zqxal2": "npm:zqxcrit4@2.0.0".').consumedHere("zqxal2")).toBe(true);
  });
});

describe("P3: a dismissed word is compared by its bare name", () => {
  const DECORATIONS = ["@1.0.0", "@^1.0.0", "==1.0.0", ">=1,<2", "[extra]", "~=1.0", "."];
  const QUOTED = (w: string) => `"${w}"`;
  const PLACE = [(m: string, w: string) => `With ${m}, use ${w} here.`, (m: string, w: string) => `With ${m} \\\n  use ${w}.`, (m: string, w: string) => "```\n" + `${m}\n${w}\n` + "```"];
  const sample = MANAGER_NAMES.filter((_, i) => i % 3 === 0);
  it.each(sample.flatMap((m) => [...DECORATIONS.map((d) => `zqxcrit4${d}`), QUOTED("zqxcrit4@1.0.0")].flatMap((w) => PLACE.map((p, i) => [`${m} ${w} #${i}`, p(m, w)] as const))))("%s", (_label, task) => {
    expect(wordsAfterManager(task)("zqxcrit4")).toBe(true);
  });
  it("a scoped name compares as @s/n", () => {
    expect(bareName("@zqxs/core@1.0.0")).toBe("@zqxs/core");
    expect(wordsAfterManager("With pnpm, use @zqxs/core@1.0.0 here.")("@zqxs/core")).toBe(true);
  });
  it.each(["With pnpm, use zqxcrit4@1.0.0 here.", "In this pnpm workspace, pin zqxcrit4@^1.0.0.", "pnpm: zqxcrit4@1.0.0", 'With npm, use "zqxcrit4@1.0.0" here.', "With pnpm \\\n  use zqxcrit4@1.0.0.", "```\npnpm\nzqxcrit4@1.0.0\n```"])("%s with zqxcrit4 dismissed: never safe", async (task) => {
    npm();
    const r = await brief({ task, packages: [], not_packages: ["zqxcrit4"] });
    expect(level(r)).not.toBe("safe_to_delegate");
  });
});

describe("P5: a command this briefing does not read, two cases only", () => {
  it.each(["Make the counter go up by one when the button is clicked.", "Go add a unit test for the date parser.", "Publish the npm package after the release notes.", "The go package docs need an example.", "Commit the yarn lock with the change.", "Explain how pip resolves extras."])("%s: no command", (task) => {
    expect(unreadCommandLines(task)).toEqual([]);
  });
  it.each([["echo zqxx | xargs npm install", "npm (through xargs)"], ["find . | xargs -0 pnpm add", "pnpm (through xargs)"], ["gem install rails", "gem"], ["composer require monolog/monolog", "composer"], ["brew install jq", "brew"], ["apt-get -y install curl", "apt-get"], ["dotnet add package Newtonsoft.Json", "dotnet"]])("%s: %s", (task, said) => {
    expect(unreadCommandLines(task)).toEqual([said]);
  });
});

describe("P4: CPU bounded on the reviewer's slow inputs and on every reader's trigger token", () => {
  const dist = path.resolve(__dirname, "../../dist/tools/what-should-i-know.js");
  const childCpu = (task: string) => {
    const script = `
      import { readFileSync } from "node:fs";
      const { executeWhatShouldIKnow } = await import(${JSON.stringify(pathToFileURL(dist).href)});
      process.env.FOURDA_OFFLINE = "true";
      const task = readFileSync(0, "utf8");
      const t0 = process.cpuUsage();
      await executeWhatShouldIKnow(null, { task, packages: [] }, null);
      const u = process.cpuUsage(t0);
      console.log((u.user + u.system) / 1000);`;
    return Number(execFileSync(process.execPath, ["--input-type=module", "-e", script], { encoding: "utf8", input: task, maxBuffer: 1 << 24 }).trim().split("\n").pop());
  };
  const recipes = JSON.parse(readFileSync(path.join(__dirname, "fixtures", "a1134-confirm", "slow-recipes.json"), "utf8")) as Array<{ id: string; unit: string; head?: string; length: number }>;
  const grow = (unit: string, length: number, head = "") => `${head}${unit.repeat(Math.ceil(length / unit.length)).slice(0, length)}`;
  it.skipIf(!existsSync(dist))("the ninth check's slow recipes: each under 3 s of child CPU (task on stdin)", () => {
    for (const r of recipes) expect(childCpu(grow(r.unit, r.length, r.head)), r.id).toBeLessThan(3000);
  }, 600_000);
  const TRIGGERS = ["requirements.txt\n", "requirements.in %\n", "cat > requirements.txt <<EOF\n", "```\n", "~~~\n", "```txt\n", "[dependencies]\n", "[target.'cfg(x)'.dependencies]\n", "[project.optional-dependencies]\n", "dependencies = [\n", '"dependencies": {\n', "require (\n", "npm install ", "pip install ", "xargs npm ", "gem install ", "a == ", "a@", "a <2\n"];
  it.skipIf(!existsSync(dist))("each reader's trigger token repeated to 199 KB, alone and between one-character lines: under 3 s", () => {
    for (const t of TRIGGERS) {
      expect(childCpu(grow(t, 199_000)), JSON.stringify(t)).toBeLessThan(3000);
      expect(childCpu(grow(`${t}a\n`, 199_000)), `${JSON.stringify(t)} + a`).toBeLessThan(3000);
    }
  }, 900_000);
});

describe("P7: the 'split the task' text is reachable over stdio", () => {
  it.skipIf(!existsSync(serverEntry))(`more than ${MAX_SNIPPETS} snippets in one task: review_needed at least, and the answer says split the task`, async () => {
    npm();
    const task = Array.from({ length: MAX_SNIPPETS + 5 }, (_, i) => `requirements-${i}.txt\nzqxok${i}==1.0.0\n`).join("\n");
    const s = await stdioSession(h.dir, [["what_should_i_know", { task, packages: [] }]], {}, { requestTimeoutMs: 120_000 });
    const text = resultText(s.results[0]);
    expect(text).toContain("split the task");
    expect(text).not.toContain('"level":"safe_to_delegate"');
  }, 180_000);
});
