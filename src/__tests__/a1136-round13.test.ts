// SPDX-License-Identifier: Apache-2.0
/**
 * Round 13: the eleventh independent check. U1 the raw-text dismissed-word rule is gone; a name the briefing read
 * (operand, snippet entry) and the caller dismissed still holds, compared by dismissedBy. U2 a credential-shaped
 * value supplied anywhere is never repeated in an answer (only the echoed `task`). U3 a declared public package the
 * project's configuration makes private gets dependency_check's own ledger record. U4 blanks are collapsed: a run of
 * blanks costs nothing. U5 the minors.
 */
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { executeWhatShouldIKnow, whatShouldIKnowTool } from "../tools/what-should-i-know.js";
import { foldForNames, requirementsPairs, unreadCommandLines } from "../tools/briefing-command-check.js";
import { dismissedBy, RESTS_ON_DECLARATION } from "../tools/briefing-confirm.js";
import { pep508 } from "../tools/briefing-snippets.js";
import { LEDGER_FILE, ledgerWritesSettled } from "../check-ledger.js";
import { runDependencyCheck } from "../tools/dependency-check.js";
import { screenValue } from "../output-screen.js";
import { createHarness, type Harness } from "./helpers/a1119-planner-harness.js";
import { childCpu as childCpuFigures } from "./helpers/child-cpu.js";

let h: Harness;
let live: Awaited<ReturnType<Harness["live"]>> | null = null;
const saved = new Map<string, string | undefined>();
const setEnv = (k: string, v: string | undefined) => {
  if (!saved.has(k)) saved.set(k, process.env[k]);
  if (v === undefined) delete process.env[k];
  else process.env[k] = v;
};
beforeEach(() => {
  h = createHarness();
  h.PYPI.flask = { "3.0.3": {} };
});
afterEach(() => {
  live = null;
  h.dispose();
  for (const [k, v] of saved) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  saved.clear();
});
const brief = async (args: Record<string, unknown>) => {
  live ??= await h.live();
  return (await executeWhatShouldIKnow(null, { ...args, project_path: h.dir } as never, live)) as Record<string, any>;
};
const level = (r: Record<string, any>) => r.delegation_assessment.level as string;
const npm = () => h.npmProject({}, {}, {});
const py = () => h.write("requirements.txt", "flask==3.0.3\n");

describe("U1: dismissals hold only for what the briefing read", () => {
  it("a dismissed word in prose after an incidental manager name no longer holds by itself", async () => {
    npm();
    const r = await brief({ task: "We use go for the CLI; add a retry to the fetcher.", packages: [], not_packages: ["retry"] });
    expect(r.delegation_assessment.reason).not.toContain("after a package manager's name");
  });
  it.each([
    ["npm install zqxfoo", "zqxfoo"],
    ["pip install zqx.foo", "zqx-foo"],
    ["pip install zqx_foo==1.0", "ZQX-FOO"],
    ['requirements.txt:\n```\nzqx.foo==1.0\n```', "zqx-foo"],
  ])("%j with %s dismissed: the name it read keeps review_needed", async (task, word) => {
    py();
    npm();
    const r = await brief({ task, packages: [], not_packages: [word] });
    expect(level(r)).not.toBe("safe_to_delegate");
  });
  it("dismissedBy folds NFKC, default-ignorables (by the Unicode property), case, the bare name and PEP 503", () => {
    expect(dismissedBy("zqx.foo", ["PyPI"], ["ZQX_FOO"])).toBe("ZQX_FOO");
    expect(dismissedBy("zqx­foo", ["npm"], ["zqxfoo"])).toBe("zqxfoo");
    expect(dismissedBy("zqxfoo@1.0.0", ["npm"], ["zqxfoo"])).toBe("zqxfoo");
    expect(foldForNames("zqx￰fo￸o‍")).toBe("zqxfoo");
  });
  it("the description and the safe reason say not_packages is the caller's statement", () => {
    expect(whatShouldIKnowTool.description).toContain("The level rests on your declaration and on your statement of which words are not packages");
    expect(RESTS_ON_DECLARATION).toContain("on your statement of which words are not packages");
    expect(RESTS_ON_DECLARATION).toContain("may not have been checked");
  });
});

describe("U2: a credential-shaped value is never repeated, from any argument position", () => {
  const SHAPES = [["ghp", "_Q9wE7rT5yU3iO1pA8sD6fG4hJ2kL0zX5cV7bN9m"], ["AKIA", "QWERQWERQWERQWER"], ["xoxb", "-123456789012-1234567890123-abcdefghijklmnopqrstuvwx"], ["github_pat", "_11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyz"], ["glpat", "-abcdefghij0123456789"], ["npm", "_abcdefghijklmnopqrstuvwxyz0123456789"], ["sk", "-proj-abcdefghij0123456789ABCDEFGH"], ["eyJ", "hbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123"]].map(([a, b]) => `${a}${b}`);
  const POSITIONS: Array<[string, (t: string) => Record<string, unknown>]> = [
    ["task word", (t) => ({ task: `npm install zqxok --token ${t}`, packages: [] })],
    ["not_packages", (t) => ({ task: `With go, add ${t} to the notes.`, packages: [], not_packages: [t] })],
    ["package name (public)", (t) => ({ task: "add it", packages: [{ ecosystem: "npm", name: t, version: "1.0.0", public: true }] })],
    ["package name (private)", (t) => ({ task: "add it", packages: [{ ecosystem: "npm", name: t, public: false }] })],
    ["version", (t) => ({ task: "add zqxok", packages: [{ ecosystem: "npm", name: "zqxok", version: t, public: true }] })],
    ["unknown field key", (t) => ({ task: "add zqxok", packages: [{ ecosystem: "npm", name: "zqxok", version: "1.0.0", public: true, [t]: "x" }] })],
    ["ecosystem", (t) => ({ task: "add zqxok", packages: [{ ecosystem: t, name: "zqxok", version: "1.0.0", public: true }] })],
    ["files", (t) => ({ task: "edit it", packages: [], files: [t] })],
    ["requirements file", () => ({ task: "pip install -r cred.txt", packages: [] })],
  ];
  it.each(SHAPES.flatMap((t, i) => POSITIONS.map(([where, args]) => [`shape ${i} as ${where}`, t, args] as const)))("%s", async (_label, tok, args) => {
    npm();
    py();
    h.write("cred.txt", `zqxok==1.0\n${tok}==1.0\n`);
    // Round 14, X1: the screen is the server's, on what it returns (output-screen.ts), as here.
    const r = screenValue(await brief(args(tok)), "task") as Record<string, any>;
    const out = JSON.stringify({ ...r, task: undefined });
    expect(out.includes(tok)).toBe(false);
  });
});

describe("U3: a declared public package the configuration makes private gets dependency_check's own record", () => {
  it("FOURDA_PRIVATE_PACKAGES: the briefing's ledger line equals dependency_check's", async () => {
    npm();
    setEnv("FOURDA_PRIVATE_PACKAGES", "zqx-priv-x");
    const strip = (text: string) => text.split("\n").filter(Boolean).map((l) => { const { t: _t, ...rest } = JSON.parse(l); return JSON.stringify(rest); });
    const homeA = fs.mkdtempSync(path.join(os.tmpdir(), "a1136-dc-"));
    const homeB = fs.mkdtempSync(path.join(os.tmpdir(), "a1136-wsik-"));
    live = await h.live();
    setEnv("FOURDA_MCP_HOME", homeA);
    await runDependencyCheck(null, { items: [{ ecosystem: "npm", package: "zqx-priv-x", to: "1.0.0" }] } as never, live as never);
    await ledgerWritesSettled();
    setEnv("FOURDA_MCP_HOME", homeB);
    const r = await brief({ task: "npm install zqx-priv-x@1.0.0", packages: [{ ecosystem: "npm", name: "zqx-priv-x", version: "1.0.0", public: true }] });
    await ledgerWritesSettled();
    const a = strip(fs.readFileSync(path.join(homeA, LEDGER_FILE), "utf8"));
    const b = strip(fs.readFileSync(path.join(homeB, LEDGER_FILE), "utf8"));
    expect(a.length).toBeGreaterThan(0);
    expect(a.some((l) => l.includes('"not_checked":"private"'))).toBe(true);
    expect(b).toEqual(a);
    // #62: the basis names the user's own list, and one row per declared ecosystem.
    const rows = r.task_packages.private as Array<{ name: string; ecosystem: string; basis: string }>;
    expect(rows.filter((x) => x.name === "zqx-priv-x")).toEqual([{ name: "zqx-priv-x", ecosystem: "npm", basis: "your FOURDA_PRIVATE_PACKAGES list" }]);
    fs.rmSync(homeA, { recursive: true, force: true });
    fs.rmSync(homeB, { recursive: true, force: true });
  });
});

describe("U4: blanks are collapsed; a run of blanks costs nothing", () => {
  it("pep508 reads a line with blanks at each token boundary, and a line over 2,000 characters is not read", () => {
    for (const n of [3, 3000, 50_000]) {
      const b = " ".repeat(n);
      const d = pep508(`zqx-vuln-py${b}[${b}cli${b},${b}http${b}]${b}==${b}1.0.0${b},${b}<${b}2${b};${b}python_version${b}>${b}"3"`);
      expect(d !== null && d !== "skip" && d.spec, String(n)).toBe("==1.0.0,<2");
    }
    expect(pep508(`zqx${"a".repeat(2_100)}==1`)).toBeNull();
  });
  const dist = path.resolve(__dirname, "../../dist/tools/what-should-i-know.js");
  // The project_path is given on purpose here (the harness's project).
  const childCpu = (input: string, root: string) =>
    childCpuFigures({ input, calls: `(input) => { const { task } = JSON.parse(input); return [{ task, packages: [], project_path: ${JSON.stringify(root)} }]; }` })[0];
  const SHAPES = [(b: string) => `requirements.txt\na${b}b`, (b: string) => `requirements.txt\nzqx-vuln-py${b}==${b}1.0.0${b};${b}python_version${b}>${b}"3"`, (b: string) => `Cargo.toml:\n\`\`\`toml\n[${b}dependencies${b}]\nzqx${b}=${b}"1.0"\n\`\`\``, (b: string) => `pyproject.toml:\n\`\`\`toml\n[project]\ndependencies${b}=${b}[${b}"zqx${b}>=${b}1"${b}]\n\`\`\``, (b: string) => `npm${b}install${b}zqx@1.0.0`, (b: string) => `Add zqx-vuln-py${b}==${b}1.0.0${b}to it.`];
  it.skipIf(!fs.existsSync(dist))("each reader's line shape with 3,000 / 6,000 / 50,000 blanks or tabs at each boundary: under 3 s of child CPU", () => {
    for (const shape of SHAPES)
      for (const n of [3000, 6000, 50_000])
        for (const c of [" ", "\t"]) {
          const task = shape(c.repeat(n));
          expect(childCpu(JSON.stringify({ task }), h.dir), `${shape(" ").slice(0, 30)} ${n} ${JSON.stringify(c)}`).toBeLessThan(3000);
        }
  }, 900_000);
  it.skipIf(!fs.existsSync(dist))("the same in a requirements file on disk", () => {
    for (const n of [3000, 6000, 50_000]) {
      const b = " ".repeat(n);
      h.write("big.txt", `zqx-vuln-py${b}==${b}1.0.0${b};${b}python_version${b}>${b}"3"\na${b}b\n`);
      expect(childCpu(JSON.stringify({ task: "pip install -r big.txt" }), h.dir), String(n)).toBeLessThan(3000);
    }
  }, 300_000);
});

describe("U5: minors", () => {
  it("#11, #16: the description does not promise a closed list", () => {
    const d = whatShouldIKnowTool.description;
    expect(d).toContain("or human_only when something it looked up on its own is malicious or critical");
    expect(d).toContain("it is raised, for example, by");
    expect(d).not.toContain("only version-confirmed evidence");
  });
  it.each(["For the docs bundle, add hono", "a hidden gem: install dayjs", "Let it brew; install ky later", "Mention that users can brew install jq"])("#45: %j names no command", (task) => {
    expect(unreadCommandLines(task)).toEqual([]);
  });
  it.each([["gem install rails", "gem"], ["make && brew install jq", "brew"], ["Run `bundle add hono` now", "bundle"], ["$ composer require x/y", "composer"]])("#45: %j is a command (%s)", (task, said) => {
    expect(unreadCommandLines(task)).toEqual([said]);
  });
  it("#112: a 9th requirements file is said, and holds review_needed", async () => {
    py();
    for (let i = 1; i <= 9; i++) h.write(`r${i}.txt`, i < 9 ? `-r r${i + 1}.txt\n` : "zqx-vuln-py==1.0.0\n");
    const pairs = requirementsPairs(h.dir, ["r1.txt"], (f) => fs.readFileSync(path.join(h.dir, f), "utf8"));
    expect(pairs.capped).toBe(true);
    const r = await brief({ task: "pip install -r r1.txt", packages: [] });
    expect(r.delegation_assessment.reason).toContain("the requirements files it names are more than this briefing reads (8)");
    expect(level(r)).not.toBe("safe_to_delegate");
  });
});
