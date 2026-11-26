// SPDX-License-Identifier: Apache-2.0
/**
 * Round 10: the eighth independent check's rules. G1 every snippet line is a pair, a known non-package line, or it
 * makes the snippet not read whole; G2 the tying forms are one exact list; G3 one list of manager names for every rule
 * that names one; G4 CPU is bounded (once per distinct word); G5 the minors. Stubbed fetch over a canned world:
 * zqx-vuln-py 1.0.0 critical, zqxcrit4 1.0.0 critical, zqx-vuln-rs 1.0.0 critical, github.com/zqxevil/mod v1.0.0 critical.
 */
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { executeWhatShouldIKnow } from "../tools/what-should-i-know.js";
import { manifestPairs, pep508, unreadCommandLines, wordsAfterManager } from "../tools/briefing-command-check.js";
import { MANAGER_NAMES } from "../tools/briefing-canonical.js";
import { adv, createHarness, fixedIn, type Harness } from "./helpers/a1119-planner-harness.js";

let h: Harness;
let live: Awaited<ReturnType<Harness["live"]>> | null = null;
beforeEach(() => {
  h = createHarness();
  for (const n of ["zqxok", "lodash"]) h.NPM[n] = { latest: "9.6.0", versions: { "1.0.0": {}, "9.6.0": {} } };
  h.NPM.zqxcrit4 = { latest: "2.0.0", versions: { "1.0.0": {}, "2.0.0": {} } };
  h.PYPI["zqx-vuln-py"] = { "1.0.0": {}, "2.0.0": {} };
  h.PYPI.flask = { "3.0.3": {} };
  h.PYPI.requests = { "2.32.3": {} };
  h.ADVISORIES.zqxcrit4 = [adv("GHSA-zq10-0000-0001", "zqxcrit4", fixedIn("2.0.0"), "npm", "CRITICAL")];
  h.ADVISORIES["zqx-vuln-py"] = [adv("PYSEC-2026-1001", "zqx-vuln-py", fixedIn("2.0.0"), "PyPI", "CRITICAL")];
});
afterEach(() => {
  live = null;
  h.dispose();
});
const brief = async (args: Record<string, unknown>) => {
  live ??= await h.live();
  return (await executeWhatShouldIKnow(null, { ...args, project_path: h.dir } as never, live)) as Record<string, any>;
};
const py = () => h.write("requirements.txt", "flask==3.0.3\n");
const npm = () => h.npmProject({}, {}, {});
const level = (r: Record<string, any>) => r.delegation_assessment.level as string;

describe("G1: every requirements line is a pair, a known non-package line, or the snippet is not read whole", () => {
  it.each(["zqx-vuln-py <2", "zqx-vuln-py < 2.0.0", "zqx-vuln-py >0.5, <2", 'zqx-vuln-py == 1.0.0 ; python_version >= "3.8"', "zqx-vuln-py == 1.0.0 --hash=sha256:0f0e", "zqx-vuln-py[fast] ~= 1.0", "zqx-vuln-py===1.0.0", "zqx-vuln-py!=2.0.0"])(
    "requirements.txt with %s and zqx-vuln-py declared at latest: never safe",
    async (line) => {
      py();
      const r = await brief({ task: `requirements.txt\nflask==3.0.3\n${line}`, packages: [{ ecosystem: "PyPI", name: "zqx-vuln-py", version: "latest", public: true }, { ecosystem: "PyPI", name: "flask", version: "3.0.3", public: true }] });
      expect(level(r)).not.toBe("safe_to_delegate");
    },
  );

  it("property: generated valid lines are pairs, mutated lines are never silently dropped", () => {
    let seed = 20261210;
    const rnd = (n: number) => ((seed = (seed * 1103515245 + 12345) % 2 ** 31) % n);
    const OPS = ["==", "===", "~=", "!=", ">=", "<=", "<", ">"];
    const ver = () => `${rnd(9)}.${rnd(20)}${rnd(2) ? `.${rnd(30)}` : ""}`;
    const valid = () => {
      const name = ["flask", "zqx-vuln-py", "requests", "a_b.c"][rnd(4)];
      const extras = rnd(4) === 0 ? "[socks, security]" : "";
      const clauses = Array.from({ length: 1 + rnd(2) }, () => `${OPS[rnd(OPS.length)]}${rnd(2) ? " " : ""}${ver()}`).join(rnd(2) ? ", " : ",");
      const marker = rnd(4) === 0 ? ' ; python_version >= "3.8"' : "";
      const hash = rnd(5) === 0 ? " --hash=sha256:0123abcd" : "";
      return `${name}${extras}${rnd(2) ? " " : ""}${rnd(5) === 0 ? "" : clauses}${marker}${hash}`;
    };
    const mutate = (l: string) => [`${l} and then`, l.replace(/[<>=~!]+/, "=>"), `@@${l}`, `${l}(`][rnd(4)];
    for (let i = 0; i < 400; i++) {
      const l = valid();
      const d = pep508(l);
      expect(d, l).not.toBeNull();
      expect(d, l).not.toBe("skip");
      const bad = mutate(l);
      const block = manifestPairs(`requirements.txt\n${l}\n${bad}`);
      // The mutated line is a pair (still valid by the grammar) or the snippet is not read whole: never a third way.
      const parsed = pep508(bad);
      if (parsed === null) expect(block.unreadable.length, bad).toBeGreaterThan(0);
    }
  });

  it.each([
    ['package.json:\n```\n"dependencies": { "zqxcrit4": "1.0.0", "x": 1 }\n```', "npm"],
    ['go.mod:\n```\nrequire (\n\tgithub.com/zqxevil/mod v1.0.0\n\tnot a module line\n)\n```', "Go"],
    ['pyproject.toml:\n```\ndependencies = ["zqx-vuln-py>=1", unquoted]\n```', "PyPI"],
    ['Cargo.toml:\n```\n[dependencies]\nzqx-vuln-rs = { version = "1.0", weird = 3 }\n```', "crates.io"],
  ])("other readers: a line they cannot read makes the snippet not read whole (%s)", (task) => {
    expect(manifestPairs(task).unreadable.length).toBeGreaterThan(0);
  });

  it("an option line (-r other.txt) and a comment are known non-package lines", () => {
    expect(pep508("-r other.txt")).toBe("skip");
    expect(pep508("# pinned for CI")).toBe("skip");
    expect(manifestPairs("requirements.txt\nflask==3.0.3\n-r dev.txt\n# c\nrequests>=2").unreadable).toEqual([]);
  });
});

describe("G2: the tying forms, exactly", () => {
  it.each(['Pin zqxcrit4@"1.0.0" in the app.', "Pin zqxcrit4@'1.0.0' in the app.", "Use mylib@npm:zqxcrit4@1.0.0 for the parser.", 'Set "mylib": "npm:zqxcrit4@1.0.0" in package.json.'])("%s: the spec is checked for zqxcrit4", async (task) => {
    npm();
    const r = await brief({ task, packages: [{ ecosystem: "npm", name: "zqxcrit4", version: "2.0.0", public: true }] });
    expect(level(r)).toBe("human_only");
  });
});

describe("G3: one list of manager names", () => {
  const FORMS = [(m: string) => `${m} add zqxcrit4`, (m: string) => `${m} add \\\n  zqxcrit4`, (m: string) => "```\n" + `${m} add\nzqxcrit4\n` + "```"];
  it.each(MANAGER_NAMES.flatMap((m) => FORMS.map((f, i) => [`${m} #${i}`, f(m)] as const)))("%s: a dismissed word after it is held", (_label, task) => {
    expect(wordsAfterManager(task)("zqxcrit4")).toBe(true);
  });
  it("the reviewer's forms end review_needed", async () => {
    npm();
    for (const task of ["With hatch, add zqxcrit4 to the project.", "Run mamba install zqxcrit4", "pixi add zqxcrit4", "deno add npm:zqxcrit4", "yarnpkg add zqxcrit4", "cargo-binstall zqxcrit4", "rye add zqxcrit4"]) {
      const r = await brief({ task, packages: [], not_packages: ["zqxcrit4"] });
      expect(level(r), task).not.toBe("safe_to_delegate");
    }
  });
});

describe("G4: CPU is bounded", () => {
  const dist = path.resolve(__dirname, "../../dist/tools/what-should-i-know.js");
  // His slow inputs (e8, e8b), stored as the unit each repeats and the length (a 199 KB string is not vendored).
  const recipes = JSON.parse(readFileSync(path.join(__dirname, "fixtures", "a1133-confirm", "slow-recipes.json"), "utf8")) as Array<{ id: string; unit?: string; head?: string; length?: number }>;
  const cases = recipes.filter((r) => r.unit).map((r) => ({ id: r.id, task: `${r.head ?? ""}${r.unit!.repeat(Math.ceil(r.length! / r.unit!.length)).slice(0, r.length)}` }));
  it.skipIf(!existsSync(dist))("the reviewer's slow inputs each cost under 3 s of child CPU", () => {
    for (const c of cases) {
      const script = `
        const { executeWhatShouldIKnow } = await import(${JSON.stringify("file:///" + dist.replace(/\\/g, "/"))});
        process.env.FOURDA_OFFLINE = "true";
        const t0 = process.cpuUsage();
        await executeWhatShouldIKnow(null, { task: process.env.TASK }, null);
        const u = process.cpuUsage(t0);
        console.log((u.user + u.system) / 1000);`;
      const ms = Number(execFileSync(process.execPath, ["--input-type=module", "-e", script], { encoding: "utf8", env: { ...process.env, TASK: c.task }, maxBuffer: 1 << 24 }).trim().split("\n").pop());
      expect(ms, c.id).toBeLessThan(3000);
    }
  }, 300_000);
});

describe("G5: minors", () => {
  it("docs B: xargs before a manager name, and a tool the grammar does not read, are said as such", async () => {
    expect(unreadCommandLines("echo zqxx | xargs npm install")).toEqual(["npm (through xargs)"]);
    expect(unreadCommandLines("gem install rails")).toEqual(["gem"]);
    expect(unreadCommandLines("npm install lodash")).toEqual([]);
    expect(unreadCommandLines("Add caching to the go service")).toEqual([]);
    npm();
    const r = await brief({ task: "echo zqxx | xargs npm install", packages: [] });
    expect(r.delegation_assessment.reason).toContain("This task holds a command this briefing does not read (npm (through xargs))");
  });
  it("#72: checked so far is per (ecosystem, name)", async () => {
    npm();
    py();
    const r = await brief({ task: "add zqxdual", packages: [{ ecosystem: "npm", name: "zqxdual", public: true }, { ecosystem: "PyPI", name: "zqxdual", public: true }] });
    expect(r.task_packages.next_step).toContain("zqxdual (npm) at latest");
    expect(r.task_packages.next_step).toContain("zqxdual (PyPI) at latest");
  });
  it("#71: a row that exists because of the declaration says so", async () => {
    py();
    const r = await brief({ task: "pip install requests==2.32.3", packages: [{ ecosystem: "PyPI", name: "requests", public: true }] });
    const rows = (r.task_packages.checked as Array<{ name: string; basis: string }>).filter((c) => c.name === "requests");
    expect(rows.length).toBeGreaterThan(0);
    for (const row of rows) expect(row.basis).toBe("confirmed public by you");
  });
  it("docs A: the same name private in two ecosystems is two rows", async () => {
    npm();
    py();
    const r = await brief({ task: "add zqxpriv2", packages: [{ ecosystem: "npm", name: "zqxpriv2", public: false }, { ecosystem: "PyPI", name: "zqxpriv2", public: false }] });
    expect((r.task_packages.private as Array<{ name: string; ecosystem: string }>).filter((p) => p.name === "zqxpriv2").map((p) => p.ecosystem).sort()).toEqual(["PyPI", "npm"]);
  });
});
