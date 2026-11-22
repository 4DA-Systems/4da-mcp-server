// SPDX-License-Identifier: Apache-2.0
/**
 * The plan-execution harness (bench/plan-exec): which commands it runs and how, which steps it
 * reads from a plan, how it inventories lockfiles, and when it calls a step harmful. Offline:
 * nothing here starts a process.
 */
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  advisoryDelta,
  compareLoose,
  extractSteps,
  gateFindings,
  inventory,
  lockfileVersions,
  lowerings,
  predictionCheck,
  prepareCommand,
  shellLine,
  tokenize,
  totals,
  yarn1DeleteEntries,
  type Inventory,
  type ProjectResult,
} from "../../bench/plan-exec/lib.mjs";

const dirs: string[] = [];
afterEach(() => {
  for (const d of dirs.splice(0)) fs.rmSync(d, { recursive: true, force: true });
});
const tmp = () => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), "plan-exec-"));
  dirs.push(d);
  return d;
};
const inv = (entries: Record<string, string[]>): Inventory => new Map(Object.entries(entries).map(([k, v]) => [k, new Set(v)]));

describe("commands the harness runs", () => {
  it("splits && parts and keeps quoted specs whole", () => {
    expect(tokenize('npm install "mocha@^3.0.0"')).toEqual({ parts: [["npm", "install", "mocha@^3.0.0"]] });
    expect(tokenize("go get golang.org/x/text@v0.41.0 && go mod tidy")).toEqual({ parts: [["go", "get", "golang.org/x/text@v0.41.0"], ["go", "mod", "tidy"]] });
    expect(tokenize(`npm install "vite@^4 || ^5"`)).toEqual({ parts: [["npm", "install", "vite@^4 || ^5"]] });
  });

  it("refuses anything a shell would read as another command", () => {
    for (const line of ["npm install a; rm -rf /", "npm install a | sh", "npm install $(curl x)", "npm install `id`", "npm install a > out", 'npm install "a$HOME"', "npm install a & b", 'npm install "unclosed']) {
      expect(tokenize(line), line).toHaveProperty("refused");
    }
  });

  it("adds the flags that keep scripts from running, per package manager", () => {
    expect(prepareCommand(["npm", "update", "minimist"])).toMatchObject({ argv: ["npm", "update", "minimist", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund"] });
    expect(prepareCommand(["pnpm", "up", "vitest@^4"])).toMatchObject({ argv: ["pnpm", "up", "vitest@^4", "--lockfile-only", "--ignore-scripts", "--ignore-pnpmfile"] });
    expect(prepareCommand(["yarn", "upgrade", "ws"], { yarnFlavor: "classic" })).toMatchObject({ argv: ["yarn", "upgrade", "ws", "--ignore-scripts", "--ignore-engines", "--non-interactive"] });
    const berry = prepareCommand(["yarn", "up", "-R", "ws"], { yarnFlavor: "berry" });
    expect(berry).toMatchObject({ argv: ["yarn", "up", "-R", "ws", "--mode", "update-lockfile"], env: { YARN_ENABLE_SCRIPTS: "false" } });
    expect(prepareCommand(["uv", "add", "httpx>=0.28"])).toMatchObject({ argv: ["uv", "add", "httpx>=0.28", "--no-sync"], env: { UV_NO_BUILD: "1" } });
    expect(prepareCommand(["cargo", "update", "-p", "url@2.2.2", "--precise", "2.5.9"])).toMatchObject({ argv: ["cargo", "update", "-p", "url@2.2.2", "--precise", "2.5.9"], added: [] });
    expect(prepareCommand(["go", "get", "golang.org/x/net@v0.62.0"])).toMatchObject({ env: { GOFLAGS: "-mod=mod" } });
  });

  it("refuses commands that run a package's own code or are not lockfile changes", () => {
    for (const argv of [["pip", "install", "x"], ["poetry", "lock"], ["npx", "x"], ["npm", "run", "build"], ["npm", "exec", "x"], ["npm", "pkg", "get"], ["cargo", "build"], ["go", "run", "."], ["go", "mod", "download"], ["make"], ["sh", "-c", "x"]]) {
      expect(prepareCommand(argv), argv.join(" ")).toHaveProperty("refused");
    }
  });

  it("quotes every argument for the shell and leaves the program bare", () => {
    expect(shellLine(["npm", "install", "vite@^4 || ^5"])).toBe('npm "install" "vite@^4 || ^5"');
    expect(() => shellLine(["./npm", "install"])).toThrow(/plain program name/);
  });
});

describe("the steps a plan gives", () => {
  const row = (pkg: string, version: string, extra: Record<string, unknown> = {}) => ({ package: pkg, ecosystem: "npm", currentVersion: version, reasons: ["1 known vulnerability (GHSA-x)"], ...extra });

  it("runs run_order top to bottom when the plan has it", () => {
    const plan = {
      recommendations: [row("minimist", "0.0.8"), row("mocha", "2.5.3")],
      run_order: [
        { n: 1, dir: ".", run: 'npm install "mocha@^7.1.2"', fixes: ["npm:mocha", "npm:minimist"] },
        { n: 2, dir: "examples/demo", run: "npm update minimist", fixes: ["npm:minimist"] },
      ],
      run_order_note: "the rows shown",
    };
    const got = extractSteps(plan);
    expect(got.source).toBe("run_order");
    expect(got.note).toBe("the rows shown");
    expect(got.steps.map((s) => s.actions)).toEqual([[{ type: "run", dir: ".", run: 'npm install "mocha@^7.1.2"' }], [{ type: "run", dir: "examples/demo", run: "npm update minimist" }]]);
    expect(got.steps[0].rows.map((r) => r.package)).toEqual(["mocha", "minimist"]);
  });

  it("falls back to row commands, then to the marked 6.4.0 extraction", () => {
    const withCommands = extractSteps({ recommendations: [row("ws", "7.4.5", { commands: [{ dir: ".", run: "npm update ws" }] }), row("qs", "6.5.2", { commands: [] })] });
    expect(withCommands.source).toBe("row_commands");
    expect(withCommands.steps).toHaveLength(1);

    const legacy = extractSteps({
      recommendations: [
        row("x", "1.0.0", { action: "upgrade_direct", upgradeCommands: [{ dir: ".", command: "npm install x@1.0.1" }] }),
        row("y", "2.0.0", { action: "lockfile_refresh", refreshCommands: [{ dir: "examples/demo", command: "delete every yarn.lock entry that resolves to y 2.0.0, then run yarn install" }] }),
        row("z", "3.0.0", { action: "override_or_replace", reasons: ['1 known vulnerability (GHSA-z)', 'add "overrides": { "z": "3.0.1" } to package.json (npm 8.3+), then npm install'] }),
        row("w", "4.0.0", { action: "waiting_on_upstream" }),
        { ...row("lodash", "4.17.21"), reasons: ["3 minor versions behind"], action: "upgrade_direct" },
      ],
    });
    expect(legacy.source).toBe("legacy_rows");
    expect(legacy.note).toMatch(/BASELINE MODE/);
    expect(legacy.steps.map((s) => s.actions)).toEqual([
      [{ type: "run", dir: ".", run: "npm install x@1.0.1" }],
      [{ type: "yarn1-delete", dir: "examples/demo", name: "y" }],
      [{ type: "override", dir: ".", file: "package.json", snippet: '"overrides": { "z": "3.0.1" }', then: "npm install" }],
      [],
    ]);
  });
});

describe("lockfile inventory", () => {
  it("reads every lockfile format the corpus uses", () => {
    const v = (base: string, text: string) => Object.fromEntries([...lockfileVersions(base, text)].map(([n, s]) => [n, [...s].sort()]));
    expect(v("package-lock.json", JSON.stringify({ lockfileVersion: 3, packages: { "": {}, "node_modules/a": { version: "1.0.0" }, "node_modules/b/node_modules/a": { version: "0.9.0" }, "node_modules/l": { link: true } } }))).toEqual({ a: ["0.9.0", "1.0.0"] });
    expect(v("package-lock.json", JSON.stringify({ lockfileVersion: 1, dependencies: { a: { version: "1.0.0", dependencies: { c: { version: "2.0.0" } } } } }))).toEqual({ a: ["1.0.0"], c: ["2.0.0"] });
    expect(v("pnpm-lock.yaml", "lockfileVersion: '9.0'\n\npackages:\n\n  '@babel/core@7.24.0':\n    resolution: {}\n  vite@5.3.1:\n    resolution: {}\n")).toEqual({ "@babel/core": ["7.24.0"], vite: ["5.3.1"] });
    expect(v("pnpm-lock.yaml", "lockfileVersion: 5.4\n\npackages:\n\n  /minimist/1.2.5:\n    resolution: {}\n  /@types/node/18.0.0_abc:\n    resolution: {}\n")).toEqual({ minimist: ["1.2.5"], "@types/node": ["18.0.0"] });
    expect(v("yarn.lock", '# yarn lockfile v1\n\n\n"ws@^7.0.0", ws@^7.4.0:\n  version "7.4.5"\n  resolved "x"\n\nstring-width-cjs@npm:string-width@^4.2.0:\n  version "4.2.3"\n')).toEqual({ ws: ["7.4.5"], "string-width": ["4.2.3"] });
    expect(v("yarn.lock", '__metadata:\n  version: 6\n\n"ws@npm:^7.0.0":\n  version: 7.4.5\n  resolution: "ws@npm:7.4.5"\n')).toEqual({ ws: ["7.4.5"] });
    expect(v("Cargo.lock", 'version = 3\n\n[[package]]\nname = "own"\nversion = "0.1.0"\n\n[[package]]\nname = "url"\nversion = "2.2.2"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n')).toEqual({ url: ["2.2.2"] });
    expect(v("uv.lock", 'version = 1\n\n[[package]]\nname = "app"\nversion = "0.1.0"\nsource = { editable = "." }\n\n[[package]]\nname = "Python_Multipart"\nversion = "0.0.9"\nsource = { registry = "https://pypi.org/simple" }\n')).toEqual({ "python-multipart": ["0.0.9"] });
    expect(v("go.mod", "module m\n\ngo 1.17\n\nrequire (\n\tgolang.org/x/net v0.54.0 // indirect\n\tgithub.com/a/b v1.2.3\n)\n\nrequire golang.org/x/sys v0.44.0\n")).toEqual({ "golang.org/x/net": ["v0.54.0"], "github.com/a/b": ["v1.2.3"], "golang.org/x/sys": ["v0.44.0"] });
  });

  it("keys every lockfile by its directory and skips installed trees", () => {
    const root = tmp();
    fs.mkdirSync(path.join(root, "examples", "demo"), { recursive: true });
    fs.mkdirSync(path.join(root, "node_modules", "x"), { recursive: true });
    const lock = (v: string) => JSON.stringify({ lockfileVersion: 3, packages: { "node_modules/a": { version: v } } });
    fs.writeFileSync(path.join(root, "package-lock.json"), lock("1.0.0"));
    fs.writeFileSync(path.join(root, "examples", "demo", "package-lock.json"), lock("2.0.0"));
    fs.writeFileSync(path.join(root, "node_modules", "x", "package-lock.json"), lock("9.9.9"));
    expect(Object.fromEntries([...inventory(root)].map(([k, s]) => [k, [...s]]))).toEqual({
      "npm|.|a": ["1.0.0"],
      "npm|examples/demo|a": ["2.0.0"],
    });
  });

  it("removes a yarn classic package's entries, aliases included", () => {
    const f = path.join(tmp(), "yarn.lock");
    fs.writeFileSync(f, '# yarn lockfile v1\n\n\npostcss@^8.0.0:\n  version "8.4.0"\n\n"p2@npm:postcss@^8.1.0":\n  version "8.4.1"\n\nws@^7:\n  version "7.4.5"\n');
    expect(yarn1DeleteEntries(f, "postcss")).toBe(2);
    expect(fs.readFileSync(f, "utf8")).toContain("ws@^7");
    expect(fs.readFileSync(f, "utf8")).not.toContain("postcss@");
  });
});

describe("harmful steps", () => {
  it("orders versions across ecosystems", () => {
    expect(compareLoose("v0.0.0-20220811171246-fbc7d0a398ab", "v0.44.0")).toBe(-1);
    expect(compareLoose("1.0.0-rc.1", "1.0.0")).toBe(-1);
    expect(compareLoose("1.0.post1", "1.0")).toBe(1);
    expect(compareLoose("7.2.0", "4.1.0")).toBe(1);
    expect(compareLoose("2.0.0+build", "2.0.0")).toBe(0);
  });

  it("names a step that lowers what an earlier step set, and one that lowers an installed version (Go: x/sys after x/crypto)", () => {
    const initial = inv({ "Go|.|golang.org/x/crypto": ["v0.0.0-2021"], "Go|.|golang.org/x/sys": ["v0.0.0-2022"] });
    const afterCrypto = inv({ "Go|.|golang.org/x/crypto": ["v0.59.0"], "Go|.|golang.org/x/sys": ["v0.50.0"] });
    const earlier = inv({ "Go|.|golang.org/x/crypto": ["v0.59.0"], "Go|.|golang.org/x/sys": ["v0.50.0"] });
    const afterSys = inv({ "Go|.|golang.org/x/crypto": ["v0.51.0"], "Go|.|golang.org/x/sys": ["v0.44.0"] });
    expect(lowerings(afterCrypto, afterSys, earlier, initial)).toEqual([
      { key: "Go|.|golang.org/x/crypto", from: "v0.59.0", to: "v0.51.0", set_by: "earlier_step" },
      { key: "Go|.|golang.org/x/sys", from: "v0.50.0", to: "v0.44.0", set_by: "earlier_step" },
    ]);
    // nodemon: mocha 7.2.0 (installed) -> 4.1.0
    expect(lowerings(inv({ "npm|.|mocha": ["7.2.0"] }), inv({ "npm|.|mocha": ["4.1.0"] }), new Map(), inv({ "npm|.|mocha": ["7.2.0"] }))).toEqual([{ key: "npm|.|mocha", from: "7.2.0", to: "4.1.0", set_by: "installed" }]);
  });

  it("does not call a dedupe or an upgrade a lowering", () => {
    const before = inv({ "npm|.|a": ["1.5.0", "2.0.0"], "npm|.|b": ["1.0.0"] });
    const after = inv({ "npm|.|a": ["1.5.0"], "npm|.|b": ["1.0.1"] });
    expect(lowerings(before, after, new Map(), before)).toEqual([]);
  });
});

describe("scoring and the gate", () => {
  const r = (pkg: string, version: string, id: string, aliases: string[] = []) => ({ package: pkg, ecosystem: "npm", current_version: version, vuln_id: id, aliases });

  it("counts an advisory cleared only when no copy of the package carries it, by id or alias", () => {
    const before = [r("a", "1.0.0", "GHSA-1", ["CVE-1"]), r("b", "1.0.0", "GHSA-2")];
    const after = [r("a", "1.0.1", "CVE-1"), r("c", "1.0.0", "GHSA-3")];
    expect(advisoryDelta(before, after)).toEqual({ cleared: ["npm|b|1.0.0|GHSA-2"], introduced: ["npm|c|1.0.0|GHSA-3"] });
  });

  it("holds the plan's prediction against the copies left", () => {
    const step = (pkg: string, version: string, actions: number) => ({ n: 1, fixes: [`npm:${pkg}`], rows: [{ package: pkg, ecosystem: "npm", currentVersion: version }], actions: Array.from({ length: actions }, () => ({ type: "run" as const, dir: ".", run: "npm update" })) });
    const got = predictionCheck({
      beforeRows: [r("a", "1.0.0", "G1"), r("b", "1.0.0", "G2"), r("c", "1.0.0", "G3")],
      afterRows: [r("a", "1.0.0", "G1"), r("d", "2.0.0", "G4")],
      steps: [step("a", "1.0.0", 1), step("b", "1.0.0", 1), step("c", "1.0.0", 0)],
    });
    expect(got).toMatchObject({ vulnerable_copies_before: 3, predicted_remaining: 1, remaining: 1, new_vulnerable_copies: 1, planned_but_remained: ["npm|a|1.0.0"], not_planned_but_cleared: ["npm|c|1.0.0"] });
  });

  it("fails on a failed step, a lowering, a refused command, too few cleared, a missing run_order or a project that did not run", () => {
    const project = (over: Partial<Omit<ProjectResult, "counts">> & { counts?: Partial<ProjectResult["counts"]> } = {}): ProjectResult => ({
      id: "p",
      order_source: "run_order",
      ...over,
      counts: { steps: 10, steps_run: 10, steps_failed: 0, steps_refused: 0, steps_without_effect: 0, steps_lowering: 0, steps_lowering_earlier: 0, ...over.counts },
      advisories: over.advisories ?? { before: 100, after: 10 },
      prediction: { vulnerable_copies_before: 10, predicted_remaining: 1, remaining: 1, vulnerable_copies_after: 1 },
    });
    const thresholds = { max_failed_steps: 0, max_lowering_steps: 0, max_refused_steps: 0, min_net_cleared_ratio: 0.772, require_order_source: "run_order" };
    const gate = (ps: ProjectResult[]) => gateFindings(totals(ps), thresholds, ps);
    expect(gate([project()])).toEqual([]);
    expect(gate([project({ counts: { steps_failed: 1 } })])).toEqual([expect.stringMatching(/1 step\(s\) failed/)]);
    expect(gate([project({ counts: { steps_lowering: 1 } })])).toEqual([expect.stringMatching(/lowered a version/)]);
    expect(gate([project({ counts: { steps_refused: 2 } })])).toEqual([expect.stringMatching(/does not run/)]);
    expect(gate([project({ advisories: { before: 100, after: 30 } })])).toEqual([expect.stringMatching(/0\.7 cleared, below 0\.772/)]);
    expect(gate([project({ order_source: "legacy_rows" })])).toEqual([expect.stringMatching(/without run_order: 1 from legacy_rows/)]);
    expect(gate([project(), { ...project(), id: "q", error: "clone failed" }])).toEqual([expect.stringMatching(/1 project\(s\) could not be run: q \(clone failed\)/)]);
    expect(gate([project({ scan_incomplete: true })])).toEqual([expect.stringMatching(/NOT CHECKED/)]);
  });
});
