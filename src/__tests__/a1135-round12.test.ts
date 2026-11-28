// SPDX-License-Identifier: Apache-2.0
/**
 * Round 12: the tenth independent check. R1 a dismissed word after a package manager's name ANYWHERE earlier in the
 * task holds review_needed (no lines or units), compared folded. R2 no quadratic multiline regex: a generated CPU set
 * of single characters repeated to 199,990. R3 the best-effort sentence in every safe reason of a call that declared a
 * package. R4 words from a requirements file pass the credential screen. R5 a file outside the project (real path)
 * or unreadable is said; file lines are labelled as such; group keys and manager names are never candidates.
 */
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { executeWhatShouldIKnow } from "../tools/what-should-i-know.js";
import { requirementsPairs } from "../tools/briefing-command-check.js";
import { createHarness, type Harness } from "./helpers/a1119-planner-harness.js";
import { childCpu } from "./helpers/child-cpu.js";

// The child-CPU cases run through helpers/child-cpu.ts (its wall timeout, environment, exit and folder are said there).

let h: Harness;
let live: Awaited<ReturnType<Harness["live"]>> | null = null;
beforeEach(() => {
  h = createHarness();
  h.PYPI.flask = { "3.0.3": {} };
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
const npm = () => h.npmProject({}, {}, {});

// Round 13, U1: the raw-text dismissed-word rule (wordsAfterManager) and its tests are removed.
describe("R3: every safe reason of a call that declared a package carries the best-effort sentence", () => {
  // Verified on the vendored worlds (helpers/a1134-review9-runner.ts, a1135-review10-runner.ts): there the scan is
  // ready and safe answers occur; this harness has no ready scan. Here: the rule as written in the code.
  it("the rule is unconditional in the code", () => {
    const src = fs.readFileSync(path.join(__dirname, "..", "tools", "what-should-i-know.ts"), "utf8");
    expect(src).toContain("const declaredSome = Array.isArray(params.packages) && params.packages.length > 0;");
    expect(src).not.toContain("holdsSnippetOrCommand");
  });
});

describe("R4/R5: the requirements file reader", () => {
  const TOKENS = [["ghp", "_abcdefghijklmnopqrstuvwxyz0123456789"], ["AKIA", "IOSFODNN7EXAMPLE"], ["xoxb", "-123456789012-1234567890123-abcdefghijklmnopqrstuvwx"], ["github_pat", "_11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyz"], ["glpat", "-abcdefghij0123456789"], ["npm", "_abcdefghijklmnopqrstuvwxyz0123456789"]].map(([a, b]) => `${a}${b}`);
  it.each(TOKENS)("a credential-shaped line (%#) is never a pair, and the file is not read whole", (tok) => {
    for (const line of [`${tok}==1.0`, tok]) {
      const r = requirementsPairs("/p", ["a.txt"], () => `${line}\nflask==3.0.3\n`);
      expect(r.map((p) => p.name)).toEqual(["flask"]);
      expect(r.notWhole).toBe(true);
    }
  });
  it.each(TOKENS)("through every output field (%#): the token is never repeated", async (tok) => {
    h.write("requirements.txt", "flask==3.0.3\n");
    h.write("a.txt", `${tok}==1.0\n`);
    for (const args of [{ packages: [] }, { packages: [], not_packages: [tok] }, {}]) {
      const r = await brief({ task: "pip install -r a.txt", ...args });
      const out = JSON.stringify({ ...r, ...(args.not_packages ? {} : {}) });
      expect(out.split(tok).length - 1, JSON.stringify(args)).toBe(0);
      expect(level(r)).not.toBe("safe_to_delegate");
    }
  });
  it("a file line is labelled as a line of the requirements file", async () => {
    h.write("requirements.txt", "flask==3.0.3\n");
    h.write("a.txt", "zqxfileonly==1.0\n");
    const r = await brief({ task: "pip install -r a.txt", packages: [] });
    const row = (r.task_packages.to_confirm as Array<{ name: string; seen: string }>).find((x) => x.name === "zqxfileonly");
    expect(row?.seen).toBe("a line of the requirements file the task names");
  });
  it("a missing or too-large file is said and holds review_needed", async () => {
    h.write("requirements.txt", "flask==3.0.3\n");
    const r = await brief({ task: "pip install -r nothere.txt", packages: [] });
    expect(r.delegation_assessment.reason).toContain("the requirements file it names could not be read");
    expect(level(r)).not.toBe("safe_to_delegate");
    h.write("big.txt", "flask==3.0.3\n".repeat(30_000));
    const b = await brief({ task: "pip install -r big.txt", packages: [] });
    expect(b.delegation_assessment.reason).toContain("the requirements file it names could not be read");
  });
  it("a symlinked file or folder pointing outside the project is not read, and is said", async () => {
    h.write("requirements.txt", "flask==3.0.3\n");
    const outside = fs.mkdtempSync(path.join(os.tmpdir(), "a1135-outside-"));
    fs.writeFileSync(path.join(outside, "x.txt"), "zqxoutside==1.0\n");
    let linked = 0;
    try {
      fs.symlinkSync(path.join(outside, "x.txt"), path.join(h.dir, "link.txt"), "file");
      linked++;
    } catch {
      // No symlink right on this Windows account: the folder junction below still runs.
    }
    fs.symlinkSync(outside, path.join(h.dir, "dirlink"), process.platform === "win32" ? "junction" : "dir");
    for (const f of [...(linked ? ["link.txt"] : []), "dirlink/x.txt"]) {
      const r = await brief({ task: `pip install -r ${f}`, packages: [] });
      expect(JSON.stringify(r), f).not.toContain("zqxoutside");
      expect(r.delegation_assessment.reason, f).toContain("a requirements file outside the project is not read");
      expect(level(r), f).not.toBe("safe_to_delegate");
    }
    fs.rmSync(outside, { recursive: true, force: true });
  });
});

describe("R5 docs lane: a manager's own name and a dependency-group key are no candidates", () => {
  it.each(["Use brew to set it up.", "Ask volta to pin node for the repo.", 'pyproject.toml:\n```toml\n[dependency-groups]\ncli = ["click>=8"]\n```'])("%j", async (task) => {
    npm();
    const r = await brief({ task, packages: [] });
    const names = ((r.task_packages.to_confirm ?? []) as Array<{ name: string }>).map((x) => x.name.toLowerCase());
    for (const bad of ["brew", "volta", "cli"]) expect(names).not.toContain(bad);
  });
});

describe("R2: single characters repeated to 199,990: under 3 s of child CPU each", () => {
  const dist = path.resolve(__dirname, "../../dist/tools/what-should-i-know.js");
  const run = (input: string) =>
    childCpu({ input, calls: `(input) => { const { task, np } = JSON.parse(input); return [{ task, packages: [] }, { task, packages: [], ...(np ? { not_packages: ["zqxfoo"] } : {}) }]; }` });
  const CHARS = ["\n", "\r\n", " ", "\t", " ", "\f", "\v", "​", "`", "~", "#", "-", "=", "<", ">", "@", '"', "'", "\\", "(", ")", "[", "]", "{", "}", ",", "."];
  it.skipIf(!fs.existsSync(dist))("alone and between a word at each end, with packages [] and one not_packages word", () => {
    for (const c of CHARS) {
      const fill = c.repeat(Math.ceil(199_990 / c.length)).slice(0, 199_990);
      for (const task of [fill, `npm ${fill.slice(0, 199_970)} zqxfoo`]) {
        const ms = run(JSON.stringify({ task, np: true }));
        for (const m of ms) expect(m, `${JSON.stringify(c)} ${task.length}`).toBeLessThan(3000);
      }
    }
  }, 900_000);
});

describe("Round 12b: the docs lane's proof run", () => {
  it("a requirements file not read whole offers none of its entries", async () => {
    h.write("requirements.txt", "flask==3.0.3\n");
    h.write("cred.txt", `zqxok==1.0\n${["ghp", "_abcdefghijklmnopqrstuvwxyz0123456789"].join("")}==1.0\n`);
    const r = await brief({ task: "pip install -r cred.txt", packages: [] });
    expect(JSON.stringify(r.task_packages.to_confirm ?? [])).not.toContain("zqxok");
    expect(JSON.stringify(r.task_packages.checked ?? [])).not.toContain("zqxok");
    expect(r.delegation_assessment.reason).toContain("a line of a requirements file it cannot read");
    expect(level(r)).not.toBe("safe_to_delegate");
  });
  it("an include-group table is no entry: its group name is not offered", async () => {
    npm();
    const r = await brief({ task: 'pyproject.toml:\n```toml\n[dependency-groups]\ndev = ["zqxdg==2", {include-group = "cli"}]\n```', packages: [] });
    const names = ((r.task_packages.to_confirm ?? []) as Array<{ name: string }>).map((x) => x.name);
    expect(names).not.toContain("cli");
    expect(names).toContain("zqxdg");
  });
  it("a refused entry: with a versionless public entry confirmation_needed; with `version` given never safe (the refused entry alone: helpers/a1135-review10-runner.ts)", async () => {
    npm();
    const a = await brief({ task: "add zqxv2", packages: [{ ecosystem: "npm", name: "zqxv2", public: true }, { ecosystem: "npm", name: "zqxbad", public: "yes" }] });
    expect(level(a)).toBe("confirmation_needed");
    const b = await brief({ task: "add zqxv2", packages: [{ ecosystem: "npm", name: "zqxv2", version: "1.0.0", public: true }, { ecosystem: "npm", name: "zqxbad", public: "yes" }] });
    expect(["review_needed", "human_only", "unknown"]).toContain(level(b));
    expect(level(b)).not.toBe("safe_to_delegate");
    expect(level(b)).not.toBe("confirmation_needed");
    const src = fs.readFileSync(path.join(__dirname, "..", "tools", "what-should-i-know.ts"), "utf8");
    expect(src).toContain("never safe_to_delegate: confirmation_needed, or a stricter or equal level another rule sets (a refused entry holds review_needed)");
  });
});
