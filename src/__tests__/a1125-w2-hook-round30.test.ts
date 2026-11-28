// SPDX-License-Identifier: Apache-2.0
/**
 * Round 30 of the hook lane (sentence check 26): a dependency name the hook does not read is denied
 * as not read, never dropped (J1); the .yarnrc reader takes one key and one value per line (J2);
 * `latest` is compared exactly in the npm family (J3); CRLF comment lines are comments; the ledger
 * mention exemption needs the source extension to end the word.
 */

import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { sandbox, type Sandbox } from "./helpers/a1123-hookfix-run.js";

let s: Sandbox;
beforeEach(() => {
  s = sandbox();
  s.ledger([
    { ecosystem: "npm", package: "lodash", version: "4.17.20", verdict: "avoid", reason: "test avoid" },
    { ecosystem: "npm", package: "lodash", version: "4.18.1", verdict: "proceed" },
    { ecosystem: "PyPI", package: "requests", version: "2.19.0", verdict: "avoid", reason: "test avoid" },
    { ecosystem: "crates.io", package: "regex", version: "1.5.4", requested: "=1.5.4", verdict: "avoid", reason: "test avoid" },
  ]);
});
afterEach(() => s.dispose());

const bash = (command: string, tool = "Bash") => s.run({ session_id: "s", cwd: s.project, hook_event_name: "PreToolUse", tool_name: tool, tool_input: { command } });

describe("J1: an entry whose name the hook does not read is denied, never dropped", () => {
  const names = [" lodash", "lodash ", "lo dash", "a'b", 'a"b', "a!b", "-a", ".a", "_a", "lоdash" /* Cyrillic o */, "lo​dash", "", "x".repeat(215), "@/x", "@ s/x", "@s /x"];
  // [manifest, before, the text with an entry of name n and an avoided version]
  const readers: Array<[string, string, (n: string) => string]> = [
    ["package.json dependencies", '{"name":"p"}', (n) => JSON.stringify({ name: "p", dependencies: { [n]: "4.17.20" } })],
    ["package.json devDependencies", '{"name":"p"}', (n) => JSON.stringify({ name: "p", devDependencies: { [n]: "4.17.20" } })],
    ["package.json peerDependencies", '{"name":"p"}', (n) => JSON.stringify({ name: "p", peerDependencies: { [n]: "4.17.20" } })],
    ["package.json optionalDependencies", '{"name":"p"}', (n) => JSON.stringify({ name: "p", optionalDependencies: { [n]: "4.17.20" } })],
    ["package.json overrides", '{"name":"p"}', (n) => JSON.stringify({ name: "p", overrides: { [n]: "4.17.20" } })],
    ["package.json pnpm.overrides", '{"name":"p"}', (n) => JSON.stringify({ name: "p", pnpm: { overrides: { [n]: "4.17.20" } } })],
    ["package.json resolutions", '{"name":"p"}', (n) => JSON.stringify({ name: "p", resolutions: { [n]: "4.17.20" } })],
    ["Cargo.toml", '[package]\nname = "a"\nversion = "0.1.0"\n', (n) => `[package]\nname = "a"\nversion = "0.1.0"\n\n[dependencies]\n${JSON.stringify(n)} = "=1.5.4"\n`],
    ["Poetry", '[tool.poetry]\nname = "t"\n', (n) => `[tool.poetry]\nname = "t"\n[tool.poetry.dependencies]\n${JSON.stringify(n)} = "2.19.0"\n`],
    ["pnpm catalog", "packages:\n  - .\n", (n) => `packages:\n  - .\ncatalog:\n  ${JSON.stringify(n)}: 4.17.20\n`],
  ];
  for (const [label, before, make] of readers) {
    const file = label.startsWith("package.json") ? "package.json" : label === "Cargo.toml" ? "Cargo.toml" : label === "Poetry" ? "pyproject.toml" : "pnpm-workspace.yaml";
    for (const n of names) {
      it(`${label}: ${JSON.stringify(n.length > 20 ? `${n.slice(0, 8)}...(${n.length})` : n)}`, () => {
        const r = s.write(s.file(file, before), make(n));
        expect(r.decision, r.text).toBe("deny");
      });
    }
  }
  it("the denial names the part not read", () => {
    expect(s.write(s.file("package.json", '{"name":"p"}'), JSON.stringify({ name: "p", dependencies: { " lodash": "4.17.20" } })).text).toContain("a dependency name this hook does not read");
  });
  it("ordinary names still go ahead or are judged", () => {
    expect(s.write(s.file("package.json", '{"name":"p"}'), JSON.stringify({ name: "p", dependencies: { lodash: "4.18.1", "@types/node": "workspace:*" } })).decision).toBe("allow");
  });
});

describe("J2: .yarnrc takes one key and one value per line", () => {
  it.each([
    'email foo registry "http://127.0.0.1:9/"',
    'save-exact true registry "http://127.0.0.1:9/"',
    'email "foo" registry "http://127.0.0.1:9/"',
    'email "foo"registry "http://127.0.0.1:9/"',
    'email foo, registry "http://127.0.0.1:9/"',
    'registry: "http://127.0.0.1:9/"',
    'email:foo',
    "email",
    'email foo\n  registry "http://127.0.0.1:9/"',
    '"email" foo bar',
  ])("%j: held", (line) => {
    const r = s.write(s.file(".yarnrc", 'save-prefix "~"\n'), `save-prefix "~"\n${line}\n`);
    expect(r.decision, r.text).toBe("deny");
  });
  it.each(['email foo', 'email "foo@example.com"', '"email" foo', "email foo # a note", "# a comment"])("%j: inert, goes ahead", (line) => {
    expect(s.write(s.file(".yarnrc", 'save-prefix "~"\n'), `save-prefix "~"\n${line}\n`).decision).toBe("allow");
  });
});

describe("J3: latest is compared exactly in the npm family", () => {
  for (const tool of ["Bash", "PowerShell"]) {
    it.each(["npm i lodash@LATEST", "pnpm add lodash@Latest", "yarn add lodash@LATEST", "bun add lodash@LATEST", "npx lodash@LATEST"])(`${tool} %s: a dist-tag, held`, (command) => {
      const r = bash(command, tool);
      expect(r.decision).toBe("deny");
      expect(r.text).toContain("a dist-tag or branch");
    });
  }
  it("a package.json value LATEST is a tag", () => {
    expect(s.write(s.file("package.json", '{"name":"p"}'), '{"name":"p","dependencies":{"lodash":"LATEST"}}').decision).toBe("deny");
  });
});

describe("CRLF line ends are ordinary in the line readers", () => {
  it("a requirements comment line", () => {
    const f = s.file("requirements.txt", "requests==2.31.0\r\n");
    expect(s.write(f, "# pinned\r\nrequests==2.31.0\r\n").text).not.toContain("could not be read");
  });
  it("a go.mod comment line", () => {
    const g = "module example.com/x\r\n\r\ngo 1.22\r\n";
    expect(s.write(s.file("go.mod", g), `${g}// a note\r\n`).decision).toBe("allow");
  });
  it("a requirements include with CRLF", () => {
    s.file("base.txt", "# c\r\nrequests==2.19.0\r\n");
    expect(bash("pip install -r base.txt").text).toContain("answered avoid");
  });
});

describe("P5: the source extension must end the word", () => {
  it.each(["cp a check-ledger.mjs.bak", "cp a check-ledger.ts.orig"])("%s names the ledger", (command) => {
    expect(bash(command).text).toContain("check ledger");
  });
  it.each(["cat src/check-ledger.ts", "node scripts/check-ledger.mjs", "cat src/check-ledger.test.ts"])("%s does not", (command) => {
    expect(bash(command).decision).toBe("allow");
  });
});

void join;
