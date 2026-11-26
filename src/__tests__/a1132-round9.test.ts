// SPDX-License-Identifier: Apache-2.0
/**
 * Round 9: the seventh independent check's rules. E1 the leftover-version heuristic is gone: a public entry states its
 * version, and without one the call is confirmation_needed (no task text consulted); E2 a redirection makes a command
 * not read whole; E3 no remedy, the truth; E4 the minors. Stubbed fetch over a canned world (zqxcrit4 1.0.0 critical,
 * zqx-vuln-py 1.0.0 critical, certifi 2022.12.7 critical). The reviewer's own cases are vendored apart (a1132-confirm-review7).
 */
import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { executeWhatShouldIKnow } from "../tools/what-should-i-know.js";
import { RAW_SOURCE, STAYS_REVIEW } from "../tools/briefing-command-check.js";
import { canonicalCommands } from "../tools/briefing-canonical.js";
import { adv, createHarness, fixedIn, type Harness } from "./helpers/a1119-planner-harness.js";

let h: Harness;
let live: Awaited<ReturnType<Harness["live"]>> | null = null;
beforeEach(() => {
  h = createHarness();
  for (const n of ["zqxok", "pino", "ky", "lodash"]) h.NPM[n] = { latest: "9.6.0", versions: { "1.0.0": {}, "9.6.0": {} } };
  h.NPM.zqxcrit4 = { latest: "2.0.0", versions: { "1.0.0": {}, "2.0.0": {} } };
  h.PYPI["zqx-vuln-py"] = { "1.0.0": {}, "2.0.0": {} };
  h.PYPI.certifi = { "2022.12.7": {}, "2024.8.30": {} };
  h.ADVISORIES.zqxcrit4 = [adv("GHSA-zq9c-0000-0001", "zqxcrit4", fixedIn("2.0.0"), "npm", "CRITICAL")];
  h.ADVISORIES["zqx-vuln-py"] = [adv("PYSEC-2026-9001", "zqx-vuln-py", fixedIn("2.0.0"), "PyPI", "CRITICAL")];
  h.ADVISORIES.certifi = [adv("PYSEC-2026-9002", "certifi", fixedIn("2024.8.30"), "PyPI", "CRITICAL")];
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
const py = () => h.write("requirements.txt", "flask==3.0.3\n");
const level = (r: Record<string, any>) => r.delegation_assessment.level as string;
const STATE = 'State `version` for each package you declared public: the version or range you will write, or "latest" for the newest release';

describe("E1: a public entry states its version; without one the call is confirmation_needed", () => {
  const CASES: Array<[string, string, string, string, () => void]> = [
    ["Pin zqxcrit4 to 1.0.0 in package.json.", "npm", "zqxcrit4", "1.0.0", npm],
    ["Add zqxcrit4 version 1.0.0 to the project.", "npm", "zqxcrit4", "1.0.0", npm],
    ["zqxok@1.0.0 and zqxcrit4 1.0.0", "npm", "zqxcrit4", "1.0.0", npm],
    ["Pin certifi to 2022.12.7 in requirements.txt.", "PyPI", "certifi", "2022.12.7", py],
    ["Add zqx-vuln-py<2 to requirements.txt.", "PyPI", "zqx-vuln-py", "1.0.0", py],
  ];
  it.each(CASES)("%s: no version declared -> confirmation_needed, never safe", async (task, ecosystem, name, _bad, project) => {
    project();
    const r = await brief({ task, packages: [{ ecosystem, name, public: true }] });
    expect(level(r)).toMatch(/^(?:confirmation_needed|human_only)$/);
    expect(r.task_packages.status).toBe("confirmation_needed");
    expect(r.task_packages.next_step).toContain(STATE);
    expect(r.task_packages.next_step).toContain(`checked so far: ${name} at `);
  });
  it.each(CASES)("%s: the bad version declared -> human_only", async (task, ecosystem, name, bad, project) => {
    project();
    expect(level(await brief({ task, packages: [{ ecosystem, name, version: bad, public: true }] }))).toBe("human_only");
  });
  it.each(CASES.filter(([task]) => !/<2|==|@1\.0\.0/.test(task)))("%s: latest declared -> the level of latest, the caller's statement", async (task, ecosystem, name, _bad, project) => {
    project();
    const r = await brief({ task, packages: [{ ecosystem, name, version: "latest", public: true }] });
    expect(r.delegation_assessment.reason).not.toContain(STATE);
    expect(level(r)).not.toBe("confirmation_needed");
  });
  it("B3: the bare PEP 440 `<` ties the range to its own name: zqx-vuln-py<2 is checked at <2 too", async () => {
    py();
    const r = await brief({ task: "Add zqx-vuln-py<2 to requirements.txt.", packages: [{ ecosystem: "PyPI", name: "zqx-vuln-py", version: "2.0.0", public: true }] });
    expect(level(r)).toBe("human_only");
  });
  it("B2: nothing moves by position: zqxok@1.0.0 never gives zqxcrit4 a version", async () => {
    npm();
    const r = await brief({ task: "zqxok@1.0.0 and zqxcrit4 1.0.0", packages: [{ ecosystem: "npm", name: "zqxok", version: "1.0.0", public: true }, { ecosystem: "npm", name: "zqxcrit4", version: "2.0.0", public: true }] });
    expect(JSON.stringify([...(r.requested_versions ?? []), ...(r.new_packages ?? [])].filter((x: { name: string }) => x.name === "zqxcrit4"))).not.toContain('"1.0.0"');
  });
  it("property: over random task texts, no level is safe while a public entry has no version", async () => {
    npm();
    let seed = 20261128;
    const rnd = () => ((seed = (seed * 1103515245 + 12345) % 2 ** 31) / 2 ** 31);
    const WORDS = ["add", "pin", "zqxok", "zqxcrit4", "to", "1.0.0", "npm", "install", "```", "\n", "and", "lodash", "4.17.21", "the", "fix", "test", "v2", "==1.0", "@", ">"];
    for (let n = 0; n < 60; n++) {
      const task = Array.from({ length: 3 + Math.floor(rnd() * 12) }, () => WORDS[Math.floor(rnd() * WORDS.length)]).join(" ");
      const r = await brief({ task, packages: [{ ecosystem: "npm", name: "zqxok", public: true }] });
      expect(level(r), task).not.toBe("safe_to_delegate");
    }
  });
});

describe("E2: a redirection makes the command not read whole", () => {
  it.each([
    "npm install zqxok > install.log zqxevil",
    "npm install zqxok >install.log zqxevil",
    "npm install zqxok >> install.log zqxevil",
    "npm install zqxok 2>&1 zqxevil",
    "npm install zqxok 2> err.log zqxevil",
    "npm install zqxok &> out.log zqxevil",
    "npm install zqxok |& tee zqxevil",
    "npm install zqxok <<< zqxevil",
    "npm install zqxok < in.txt zqxevil",
  ])("%s", (task) => {
    for (const form of [task, `\`${task}\``, `\`\`\`\n${task}\n\`\`\``]) {
      const c = canonicalCommands(form)[0]!;
      expect(c.canonical, form).toBe(false);
      expect(c.why).toBe("a redirection among its words");
    }
  });
  it("only ;, &&, ||, |, a lone & end a command", () => {
    for (const t of ["npm install zqxok; echo", "npm install zqxok && echo", "npm install zqxok || echo", "npm install zqxok | tee", "npm install zqxok & echo"]) {
      expect(canonicalCommands(t)[0]!.canonical, t).toBe(true);
    }
  });
});

describe("E3: no remedy, the truth", () => {
  it("a comma in a command's list says it stays review_needed", async () => {
    npm();
    const r = await brief({ task: "npm install zqxok, ky", packages: [{ ecosystem: "npm", name: "zqxok", version: "latest", public: true }, { ecosystem: "npm", name: "ky", version: "latest", public: true }] });
    expect(r.delegation_assessment.reason).toContain(STAYS_REVIEW);
    expect(r.delegation_assessment.reason).not.toMatch(/clean answer/);
  });
  it("a command substitution is not mistaken for a comma", async () => {
    npm();
    const r = await brief({ task: "npm install $(cat pkgs)", packages: [] });
    expect(r.delegation_assessment.reason).not.toContain(STAYS_REVIEW);
  });
});

describe("E4: minors", () => {
  it("#20/#69: 131 names in prose: review_needed with the split sentence, no '1 more package'", async () => {
    npm();
    const r = await brief({ task: `Add ${Array.from({ length: 131 }, (_, i) => `zqxprose${i}`).join(", ")}.`, packages: [] });
    // Never the unanswerable confirmation_needed (unknown here: the empty test project has no ready scan).
    expect(level(r)).toMatch(/^(?:review_needed|unknown)$/);
    expect(r.delegation_assessment.reason).toContain("split the task");
    expect(JSON.stringify(r)).not.toContain("1 more package");
  });
  it("#29: one to_confirm entry per name, ecosystems merged", async () => {
    npm();
    py();
    const r = await brief({ task: "Add zqxprivc2==1.0.0 and add zqxprivc2 to the web app" });
    expect((r.task_packages.to_confirm as Array<{ name: string }>).filter((e) => e.name === "zqxprivc2")).toHaveLength(1);
  });
  it.each(["Run npm install pino! zqxafter is ours.", "Run npm install pino... zqxafter is ours.", "Run npm install pino… zqxafter is ours."])("#36: %s ends at the marks", (task) => {
    expect(canonicalCommands(task)[0]!.operands.map((o) => o.name)).toEqual(["pino"]);
  });
  it.each(["replace corp.example/x => ../x", "replace (\n\tcorp.example/x => ../x\n)"])("#39/#47: go.mod replace, single or block: %s", (task) => {
    expect(RAW_SOURCE.test(task)).toBe(true);
  });
  it("#82: one checked row per release (certifi 2022.12.7 and ==2022.12.7)", async () => {
    py();
    const r = await brief({ task: "Add certifi==2022.12.7 to requirements.txt.", packages: [{ ecosystem: "PyPI", name: "certifi", version: "2022.12.7", public: true }] });
    expect((r.task_packages.checked as Array<{ name: string; version: string }>).filter((c) => c.name === "certifi")).toHaveLength(1);
  });
  // Child CPU time on the built server (skipped where the suite runs unbuilt, as the MCP stdio tests are).
  it.skipIf(!existsSync(path.resolve(__dirname, "../../dist/tools/what-should-i-know.js")))("time: 45,000 lines of 'npm' with 100 dismissed words stays under 1.5 s of CPU (child process)", () => {
    const script = `
      const { executeWhatShouldIKnow } = await import(${JSON.stringify("file:///" + path.resolve(__dirname, "../../dist/tools/what-should-i-know.js").replace(/\\/g, "/"))});
      process.env.FOURDA_OFFLINE = "true";
      const task = Array(45000).fill("npm").join("\\n").slice(0, 199000);
      const t0 = process.cpuUsage();
      await executeWhatShouldIKnow(null, { task, packages: [], not_packages: Array.from({ length: 100 }, (_, i) => "w" + i) }, null);
      const u = process.cpuUsage(t0);
      console.log((u.user + u.system) / 1000);`;
    const ms = Number(execFileSync(process.execPath, ["--input-type=module", "-e", script], { encoding: "utf8" }).trim().split("\n").pop());
    expect(ms).toBeLessThan(1500);
  }, 120_000);
  it.each(["npm it zqxok", "npm install-test zqxok"])("npm's %s is an install verb", (task) => {
    expect(canonicalCommands(task)[0]!.operands.map((o) => o.name)).toEqual(["zqxok"]);
  });
  it.each(["npm cit", "npm install-ci-test"])("%s installs the lockfile: not read whole", (task) => {
    expect(canonicalCommands(task)[0]!.canonical).toBe(false);
  });
  it("docs 1: a prose form is seen as a name with a version written in the task", async () => {
    py();
    const r = await brief({ task: "we pin zqxd2==1.2.3 there" });
    expect((r.task_packages.to_confirm as Array<{ name: string; seen: string }>).find((e) => e.name === "zqxd2")?.seen).toBe("a name with a version written in the task");
  });
  it("docs 4: a number in not_packages is named as not a string", async () => {
    npm();
    const r = await brief({ task: "npm install zqxok", packages: [{ ecosystem: "npm", name: "zqxok", version: "latest", public: true }], not_packages: [3, "x"] });
    expect(r.delegation_assessment.reason).toContain("in not_packages that are not strings");
  });
  it("docs 5: a bundled malicious name in a command not read whole is human_only offline", async () => {
    npm();
    process.env.FOURDA_OFFLINE = "true";
    try {
      const r = (await executeWhatShouldIKnow(null, { task: "npm install crossenv, lodash", packages: [], project_path: h.dir } as never, null)) as Record<string, any>;
      expect(level(r)).toBe("human_only");
    } finally {
      delete process.env.FOURDA_OFFLINE;
    }
  });
  it("docs 6: a pipenv command is a tool this briefing does not read: nothing of it is offered", async () => {
    py();
    const r = await brief({ task: "Run pipenv install zqxc1 today", packages: [] });
    expect(JSON.stringify(r.task_packages.to_confirm)).not.toMatch(/today|zqxc1/);
    expect(r.delegation_assessment.reason).toContain("(it is a package manager this briefing does not read)");
  });
});
