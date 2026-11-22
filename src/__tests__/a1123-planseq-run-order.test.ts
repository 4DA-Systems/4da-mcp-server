// SPDX-License-Identifier: Apache-2.0
/**
 * run_order: the rows shown as one script that is safe to run from the first step to the last
 * (DESIGN 3, rules a-f), on small synthetic row sets. The planner-level cases are in
 * a1123-planseq-run-order-plan.test.ts.
 */

import { describe, expect, it } from "vitest";
import { overrideHint } from "../tools/upgrade-planner-fixpaths.js";
import { buildRunOrder, parseCommand, type SequencedRow } from "../tools/upgrade-plan-sequence.js";

type Lever = NonNullable<SequencedRow["parentUpgrades"]>[number]["levers"][number];
const cmd = (run: string, dir = ".") => ({ dir, run });

function row(pkg: string, action: string, runs: Array<string | { dir: string; run: string }>, fields: Partial<SequencedRow> = {}): SequencedRow {
  const commands = runs.map((r) => (typeof r === "string" ? cmd(r) : r));
  return { package: pkg, ecosystem: "npm", currentVersion: "1.0.0", targetVersion: "2.0.0", action, reasons: [], commands, refreshCommands: action === "lockfile_refresh" ? commands.map((c) => ({ dir: c.dir, command: c.run })) : undefined, ...fields };
}
/** An upgrade_parent row whose one lever is `lever@version` moved by `run`. */
function parentRow(pkg: string, lever: string, version: string, run: string, extra: string[] = []): SequencedRow {
  const l: Lever = { name: lever, version, to: run.replace(/^.*@[\^~]?([^"\s]+)"?.*$/, "$1"), commands: [{ dir: ".", command: run }] };
  return row(pkg, "upgrade_parent", [run, ...extra], { parentUpgrades: [{ levers: [l], refreshCommands: extra.map((e) => ({ dir: ".", command: e })) }] });
}
const plan = (rows: SequencedRow[], extra: Partial<Parameters<typeof buildRunOrder>[0]> = {}) =>
  buildRunOrder({ rows, totalRows: rows.length, heldUnclean: (r) => r.reasons.some((x) => /NOT a clean fix/.test(x)), ...extra });
const runs = (rows: SequencedRow[], extra: Partial<Parameters<typeof buildRunOrder>[0]> = {}) => plan(rows, extra).run_order.map((s) => s.run);

describe("(a) one command per package per directory, at the highest target any row needs", () => {
  it("nodemon: three rows naming mocha ^3, ^7 and ^4 become one install of ^7.1.2, serving all three", () => {
    const rows = [
      parentRow("debug", "mocha", "2.5.3", 'npm install "mocha@^3.0.0"'),
      parentRow("minimist", "mocha", "2.5.3", 'npm install "mocha@^7.1.2"'),
      parentRow("ms", "mocha", "2.5.3", 'npm install "mocha@^4.0.0"'),
    ];
    const out = plan(rows);
    expect(out.run_order).toEqual([{ n: 1, dir: ".", run: 'npm install "mocha@^7.1.2"', fixes: ["npm:debug", "npm:minimist", "npm:ms"] }]);
    expect(out.run_order_note).toMatch(/mocha is set once in the project root, at 7\.1\.2, for rows that named 3\.0\.0, 4\.0\.0 and 7\.1\.2/);
    expect(out.run_order_note).toMatch(/was not confirmed \(re-scan after running\)/);
  });

  it("two different refreshes of one package both run (they move different copies); an identical one runs once", () => {
    const rows = [
      row("vite", "upgrade_direct", ["pnpm update vite --no-save"]),
      row("vite", "lockfile_refresh", ["pnpm update vite --depth Infinity"], { currentVersion: "5.0.0" }),
      row("vite", "lockfile_refresh", ["pnpm update vite --depth Infinity"], { currentVersion: "5.1.0" }),
    ];
    expect(runs(rows)).toEqual(["pnpm update vite --depth Infinity", "pnpm update vite --no-save"]);
  });

  it("the same package in two directories is two commands", () => {
    const rows = [row("lodash", "upgrade_direct", [cmd("npm install lodash@4.17.21 --save-exact", "web")]), row("lodash", "upgrade_direct", [cmd("npm install lodash@4.17.21 --save-exact", "api")])];
    expect(plan(rows).run_order.map((s) => [s.dir, s.run])).toEqual([
      ["api", "npm install lodash@4.17.21 --save-exact"],
      ["web", "npm install lodash@4.17.21 --save-exact"],
    ]);
  });

  it("Cargo: a --precise move two rows name is run once (the second found the crate gone: exit 101)", () => {
    const precise = "cargo update -p chrono@0.4.19 --precise 0.4.30";
    const rows = [row("chrono", "upgrade_direct", [precise], { ecosystem: "crates.io" }), row("time", "upgrade_parent", [precise], { ecosystem: "crates.io" })];
    expect(plan(rows).run_order).toEqual([{ n: 1, dir: ".", run: precise, fixes: ["crates.io:chrono", "crates.io:time"] }]);
  });

  it("Cargo: a repeated pre-update and --precise pair is one of each, pre-update first", () => {
    const pair = ["cargo update -p either@1.6.1 -p log@0.4.14", "cargo update -p url@2.2.2 --precise 2.5.9"];
    const rows = [row("url", "lockfile_refresh", pair, { ecosystem: "crates.io" }), row("idna", "lockfile_refresh", pair, { ecosystem: "crates.io" })];
    expect(runs(rows)).toEqual(pair);
  });
});

describe("(b) no command lowers a version that is installed or that an earlier step sets", () => {
  it("a lever release below the installed one is not run, and the note says why", () => {
    const r = parentRow("ms", "mocha", "7.2.0", 'npm install "mocha@^4.0.0"');
    const out = plan([r]);
    expect(out.run_order).toEqual([]);
    expect(out.run_order_note).toMatch(/mocha 4\.0\.0 is not run in the project root: a newer mocha is installed there/);
  });
});

describe("(c) every go get of one module directory is one command", () => {
  const glow = () => [
    row("golang.org/x/crypto", "lockfile_refresh", ["go get golang.org/x/crypto@v0.59.0", "go mod tidy"], { ecosystem: "Go", scope: "transitive" } as Partial<SequencedRow>),
    row("golang.org/x/net", "lockfile_refresh", ["go get golang.org/x/net@v0.62.0", "go mod tidy"], { ecosystem: "Go" }),
    row("golang.org/x/sys", "upgrade_direct", ["go get golang.org/x/sys@v0.44.0"], { ecosystem: "Go", targetVersion: "v0.44.0" }),
    row("golang.org/x/text", "upgrade_direct", ["go get golang.org/x/text@v0.41.0"], { ecosystem: "Go", targetVersion: "v0.41.0" }),
  ];
  const requires: Record<string, Record<string, string>> = {
    "golang.org/x/crypto@v0.59.0": { "golang.org/x/net": "v0.61.0", "golang.org/x/sys": "v0.50.0", "golang.org/x/text": "v0.42.0" },
    "golang.org/x/net@v0.62.0": { "golang.org/x/crypto": "v0.58.0", "golang.org/x/sys": "v0.50.0", "golang.org/x/text": "v0.44.0" },
    "golang.org/x/sys@v0.44.0": {},
    "golang.org/x/text@v0.41.0": {},
  };
  const goRequires = (m: string, v: string) => (requires[`${m}@${v}`] ? new Map(Object.entries(requires[`${m}@${v}`])) : undefined);

  it("glow: one go get, and no module named below what another target's go.mod requires of it", () => {
    const out = plan(glow(), { goRequires });
    expect(out.run_order).toEqual([
      { n: 1, dir: ".", run: "go get golang.org/x/crypto@v0.59.0 golang.org/x/net@v0.62.0", fixes: ["Go:golang.org/x/crypto", "Go:golang.org/x/net", "Go:golang.org/x/sys", "Go:golang.org/x/text"] },
      { n: 2, dir: ".", run: "go mod tidy", fixes: ["Go:golang.org/x/crypto", "Go:golang.org/x/net"] },
    ]);
    expect(out.run_order_note).toMatch(/golang\.org\/x\/sys is not named in the project root's go get: golang\.org\/x\/crypto v0\.59\.0's go\.mod requires v0\.50\.0, at or above its target v0\.44\.0/);
  });

  it("without the go.mod reads every target is named in the one command, and the note says the combination was not checked", () => {
    const out = plan(glow(), { goRequires: () => null });
    expect(out.run_order[0].run).toBe("go get golang.org/x/crypto@v0.59.0 golang.org/x/net@v0.62.0 golang.org/x/sys@v0.44.0 golang.org/x/text@v0.41.0");
    expect(out.run_order_note).toMatch(/could not be read, so whether they require another named module above its target was not checked/);
  });

  it("two module directories are two go get commands", () => {
    const rows = [
      row("golang.org/x/net", "upgrade_direct", [cmd("go get golang.org/x/net@v0.62.0", "svc/a")], { ecosystem: "Go" }),
      row("golang.org/x/net", "upgrade_direct", [cmd("go get golang.org/x/net@v0.60.0", "svc/b")], { ecosystem: "Go" }),
    ];
    expect(plan(rows).run_order.map((s) => [s.dir, s.run])).toEqual([
      ["svc/a", "go get golang.org/x/net@v0.62.0"],
      ["svc/b", "go get golang.org/x/net@v0.60.0"],
    ]);
  });
});

describe("(d) a parent upgrade comes before the refreshes of the children it carries", () => {
  it("a row's own order holds across rows that share the refresh", () => {
    const rows = [
      row("minimist", "lockfile_refresh", ["npm update minimist"]),
      parentRow("minimist", "mkdirp", "0.5.1", "npm install mkdirp@0.5.5 --save-exact", ["npm update minimist"]),
      row("postcss", "lockfile_refresh", ["npm update postcss"]),
    ];
    expect(runs(rows)).toEqual(["npm install mkdirp@0.5.5 --save-exact", "npm update minimist", "npm update postcss"]);
  });

  it("with no tie between them, upgrades run before in-range refreshes (a refresh never lowers what an upgrade set), and a reinstall last", () => {
    const rows = [
      row("vite", "upgrade_direct", ['npm install "vite@^6.4.5"']),
      row("hono", "reinstall", ["npm ci"]),
      row("nanoid", "lockfile_refresh", ["npm update nanoid"]),
    ];
    expect(runs(rows)).toEqual(['npm install "vite@^6.4.5"', "npm update nanoid", "npm ci"]);
  });
});

describe("(e) a target that breaks a peer range never runs alone", () => {
  it("the step and every row it serves are left out, and the reason is returned for the row", () => {
    const vite = row("vite", "upgrade_direct", ['npm install "vite@^6.4.5"'], { targetVersion: "6.4.5" });
    const esbuild = parentRow("esbuild", "vite", "5.0.0", 'npm install "vite@^6.4.5"');
    const nanoid = row("nanoid", "lockfile_refresh", ["npm update nanoid"]);
    const peerConflict = (_dir: string, pkg: string, version: string) =>
      pkg === "vite" && version === "6.4.5" ? { holders: ["@vitejs/plugin-react-swc"], who: '@vitejs/plugin-react-swc 3.5.0 declares "^4 || ^5"', text: "vite 6.4.5 leaves the peer range" } : null;
    const out = plan([vite, esbuild, nanoid], { peerConflict });
    expect(out.run_order.map((s) => s.run)).toEqual(["npm update nanoid"]);
    expect([...out.peerBlocked.keys()]).toEqual([vite, esbuild]);
    expect(out.peerBlocked.get(vite)).toBe("vite 6.4.5 leaves the peer range");
    expect(out.run_order_note).toMatch(/2 that break a peer range an installed dependency declares .*: vite 1\.0\.0, esbuild 1\.0\.0/);
  });

  it("when the script upgrades the holder too, both run in one command (h3: vitest 4 against @vitest/coverage-v8 1.6.0's exact peer)", () => {
    const vite = row("vite", "upgrade_parent", ['pnpm up "vitest@^4.1.12"', 'pnpm up "@vitest/coverage-v8@^4.1.11"'], {
      parentUpgrades: [
        {
          levers: [
            { name: "vitest", version: "1.6.0", to: "4.1.12", commands: [{ dir: ".", command: 'pnpm up "vitest@^4.1.12"' }] },
            { name: "@vitest/coverage-v8", version: "1.6.0", to: "4.1.11", commands: [{ dir: ".", command: 'pnpm up "@vitest/coverage-v8@^4.1.11"' }] },
          ],
        },
      ],
    });
    const nanoid = row("nanoid", "lockfile_refresh", ["pnpm update nanoid --depth Infinity"]);
    const peerConflict = (_dir: string, pkg: string) =>
      pkg === "vitest" ? { holders: ["@vitest/coverage-v8"], who: '@vitest/coverage-v8 1.6.0 declares "1.6.0"', text: "vitest 4.1.12 leaves the peer range" } : null;
    for (const rows of [[vite, nanoid], [nanoid, vite]]) {
      const out = plan(rows, { peerConflict });
      expect(out.peerBlocked.size).toBe(0);
      expect(out.run_order.map((s) => s.run)).toEqual(['pnpm up "@vitest/coverage-v8@^4.1.11" "vitest@^4.1.12"', "pnpm update nanoid --depth Infinity"]);
      expect(out.run_order_note).toMatch(/vitest 4\.1\.12 runs in one command with @vitest\/coverage-v8 in the project root, which the script upgrades too: installed, @vitest\/coverage-v8 1\.6\.0 declares "1\.6\.0"/);
    }
  });

  it("a holder whose command differs in more than its spec cannot share one: the step is left out", () => {
    const a = row("a", "upgrade_direct", ["npm install a@2.0.0 --save-exact"]);
    const b = row("b", "upgrade_direct", ['npm install "b@^3.0.0"']);
    const peerConflict = (_dir: string, pkg: string) => (pkg === "a" ? { holders: ["b"], who: 'b 1.0.0 declares "^1"', text: "a 2.0.0 leaves the peer range" } : null);
    const out = plan([a, b], { peerConflict });
    expect([...out.peerBlocked.keys()]).toEqual([a]);
    expect(out.run_order.map((s) => s.run)).toEqual(['npm install "b@^3.0.0"']);
  });
});

describe("(f) every step names its directory", () => {
  it("each step carries the directory its command runs in", () => {
    const rows = [row("postcss", "lockfile_refresh", [cmd("yarn up -R postcss", "examples/demo")]), row("lodash", "upgrade_direct", ["yarn up lodash@4.17.21"])];
    for (const s of plan(rows).run_order) expect(s.dir).toMatch(/^(\.|examples\/demo)$/);
  });

  it("an override snippet in a nested project names its package.json and where to install", () => {
    expect(overrideHint("yarn", "postcss", "8.5.23", "examples/demo")).toBe('yarn: add "resolutions": { "postcss": "8.5.23" } to examples/demo/package.json, then yarn install in examples/demo');
    expect(overrideHint("package-lock", "qs", "6.14.1", "web")).toBe('npm: add "overrides": { "qs": "6.14.1" } to web/package.json (npm 8.3+), then npm install in web');
    // At the root the snippet reads as it always did.
    expect(overrideHint("package-lock", "qs", "6.14.1")).toBe('npm: add "overrides": { "qs": "6.14.1" } to package.json (npm 8.3+), then npm install');
  });
});

describe("what run_order leaves out, and the note", () => {
  it("rows that are not a fix by command are named by why, and the script covers only the rows shown", () => {
    const rows = [
      row("a", "lockfile_refresh", ["npm update a"]),
      row("b", "waiting_on_upstream", []),
      row("c", "override_or_replace", []),
      row("d", "lockfile_refresh", [], { refreshCommands: [{ dir: ".", command: "delete every yarn.lock entry that resolves to d (keys \"d@…\"), then run yarn install" }] }),
      row("e", "upgrade_direct", ["npm install e@2.0.0 --save-exact"], { reasons: ["2.0.0 exact-pins x 1.0.0 (GHSA-1): installing 2.0.0 installs them, so 2.0.0 is NOT a clean fix"] }),
      row("f", "not_built_on_this_host", ["npm update f"]),
    ];
    const out = buildRunOrder({ rows, totalRows: 40, heldUnclean: (r) => r.reasons.some((x) => /NOT a clean fix/.test(x)) });
    expect(out.run_order.map((s) => s.run)).toEqual(["npm update a"]);
    const note = out.run_order_note;
    expect(note).toMatch(/^run_order is 1 step for 1 of the 6 rows shown/);
    expect(note).toMatch(/it covers only the rows shown, not the other 34/);
    expect(note).toMatch(/1 row is a hand edit and is not in this script: d 1\.0\.0/);
    expect(note).toMatch(/1 that have a target that is NOT a clean fix .*: e 1\.0\.0/);
    expect(note).toMatch(/1 that are not counted as fixed by their commands .*: c 1\.0\.0/);
    expect(note).toMatch(/1 that apply where the code is built, not on this host .*: f 1\.0\.0/);
    expect(note).toMatch(/1 that have nothing to run .*: b 1\.0\.0/);
  });

  it("a row whose lever has no command is not claimed by the script", () => {
    const r = row("minimist", "upgrade_parent", ["npm install mkdirp@0.5.5 --save-exact"], {
      parentUpgrades: [{ levers: [{ name: "mkdirp", version: "0.5.1", to: "0.5.5", commands: [{ dir: ".", command: "npm install mkdirp@0.5.5 --save-exact" }] }, { name: "mocha", version: "7.1.0", to: "7.1.2", instructions: [{}] }] }],
    });
    expect(plan([r]).run_order).toEqual([]);
  });

  it("the same rows in another order give the same script", () => {
    const rows = [
      row("a", "lockfile_refresh", ["npm update a"]),
      row("b", "upgrade_direct", ["npm install b@2.0.0 --save-exact"]),
      parentRow("c", "mocha", "2.5.3", 'npm install "mocha@^7.1.2"', ["npm update c"]),
      row("d", "lockfile_refresh", [cmd("pnpm update d --depth Infinity", "web")]),
    ];
    const once = plan(rows);
    const again = plan([...rows].reverse());
    expect(again.run_order).toEqual(once.run_order);
    expect(again.run_order_note).toBe(once.run_order_note);
  });
});

describe("parseCommand reads every form the planner writes", () => {
  it.each([
    ["npm install a@1.2.3 --save-exact", { kind: "set", tool: "npm", pkg: "a", version: "1.2.3" }],
    ['npm install "@scope/a@^1.2.3"', { kind: "set", tool: "npm", pkg: "@scope/a", version: "1.2.3" }],
    ['pnpm up "vitest@^4.1.12"', { kind: "set", tool: "pnpm", pkg: "vitest", version: "4.1.12" }],
    ['yarn upgrade "a@~1.2.3"', { kind: "set", tool: "yarn", pkg: "a", version: "1.2.3" }],
    ['yarn workspace web add "a@^1.2.3" --dev', { kind: "set", tool: "yarn", pkg: "a", version: "1.2.3" }],
    ['cargo add "git2@^0.21.0" --dev', { kind: "set", tool: "cargo", pkg: "git2", version: "0.21.0", flags: "--dev" }],
    ["yarn upgrade @babel/core", { kind: "refresh", tool: "yarn", pkg: "@babel/core" }],
    ["pnpm update -r vite --depth Infinity", { kind: "refresh", tool: "pnpm", pkg: "vite" }],
    ["uv lock --upgrade-package h11", { kind: "refresh", tool: "uv", pkg: "h11" }],
    ["cargo update -p url@2.2.2 --precise 2.5.9", { kind: "precise", pkg: "url", from: "2.2.2", to: "2.5.9" }],
    ["go get golang.org/x/net@v0.62.0", { kind: "goget" }],
    ['uv pip compile requirements.in -o requirements.txt --upgrade-package "django==4.2.30"', { kind: "compile" }],
    ["npm ci", { kind: "reinstall" }],
  ])("%s", (run, want) => {
    expect(parseCommand(run)).toMatchObject(want);
  });
});
