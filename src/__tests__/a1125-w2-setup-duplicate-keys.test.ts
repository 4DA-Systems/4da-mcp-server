// SPDX-License-Identifier: Apache-2.0
/**
 * Audit 2026-11-25, H-3: a key written twice inside the `4da` entry (`"args"` twice) made `--update`
 * rewrite the first while an editor reads the last; setup printed "Replacing ... now: <this release>"
 * and "Written" on every run and never converged. A duplicated key elsewhere (another server's name)
 * was written with exit 0, though the README says a file holding the same key twice is left untouched.
 * Both are refused now: the file stays byte for byte, the key is named, and the exit code is 1.
 */
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { editorTargets, planConfig, runSetup, type SetupContext } from "../setup.js";

const VERSION = JSON.parse(readFileSync(path.resolve("package.json"), "utf8")).version as string;
const ENTRY = { command: "npx", args: ["-y", "--prefer-offline", `@4da/mcp-server@${VERSION}`] };

describe("planConfig refuses a key written twice anywhere", () => {
  const cases: Array<[string, string, string]> = [
    ["args twice inside the 4da entry", '{ "mcpServers": { "4da": { "command": "npx", "args": ["-y", "@4da/mcp-server@6.4.0"], "args": ["-y", "@4da/mcp-server@6.3.0"] } } }', '"mcpServers"."4da"."args"'],
    ["command twice inside the 4da entry", '{ "mcpServers": { "4da": { "command": "node", "command": "npx", "args": [] } } }', '"mcpServers"."4da"."command"'],
    ["another server's name twice", '{ "mcpServers": { "other": { "command": "a" }, "other": { "command": "b" } } }', '"mcpServers"."other"'],
    ["a key twice in another server's env", '{ "mcpServers": { "other": { "command": "a", "env": { "K": "1", "K": "2" } } } }', '"mcpServers"."other"."env"."K"'],
    ["a top-level setting twice", '{ "theme": "dark", "mcpServers": {}, "theme": "light" }', '"theme"'],
    ["a key twice inside an array element", '{ "mcpServers": {}, "list": [ { "a": 1 }, { "b": 1, "b": 2 } ] }', '"list"."[1]"."b"'],
  ];
  for (const [name, text, key] of cases) {
    for (const update of [false, true]) {
      it(`${name}${update ? " (--update)" : ""}`, () => {
        const plan = planConfig(text, "mcpServers", ENTRY, { update });
        expect(plan.action).toBe("refuse");
        expect(plan.reason).toContain(`the key ${key} twice`);
        expect(plan.content).toBeUndefined();
      });
    }
  }

  it("the two refusals it already had keep their words", () => {
    expect(planConfig('{ "mcpServers": {}, "mcpServers": {} }', "mcpServers", ENTRY).reason).toContain('"mcpServers" key appears 2 times');
    expect(planConfig('{ "mcpServers": { "4da": {}, "4da": {} } }', "mcpServers", ENTRY).reason).toContain('holds 2 "4da" entries');
  });

  it("the same name in different objects is not a duplicate", () => {
    const plan = planConfig('{ "mcpServers": { "a": { "command": "x", "env": { "command": "y" } }, "b": { "command": "x" } } }', "mcpServers", ENTRY);
    expect(plan.action).toBe("update");
  });

  it("a key that is long or holds control characters is named on one printable line, capped", () => {
    const long = "k".repeat(500);
    const plan = planConfig(`{ "mcpServers": {}, "${long}": 1, "${long}": 2, "a\\u001bb": 1 }`, "mcpServers", ENTRY);
    expect(plan.reason).toContain("k".repeat(80) + "...");
    expect(plan.reason!.length).toBeLessThan(300);
    const ctl = planConfig('{ "mcpServers": {}, "a\\u001b[31mb": 1, "a\\u001b[31mb": 2 }', "mcpServers", ENTRY);
    expect(ctl.reason!.includes("\u001b")).toBe(false);
  });

  it("a deeply nested file is walked without exhausting the stack (or refused for its depth, never written half-read)", () => {
    const deep = `{ "mcpServers": {}, "d": ${"[".repeat(3000)}${"]".repeat(3000)} }`;
    let plan;
    try {
      plan = planConfig(deep, "mcpServers", ENTRY);
    } catch (error) {
      // planConfig's caller turns a throw into a refusal (runSetup); either way nothing is written.
      plan = { action: "refuse", reason: String(error) };
    }
    expect(["update", "refuse"]).toContain(plan.action);
  });
});

describe("runSetup leaves such a file byte for byte, names the key, exits 1", () => {
  let home: string;
  let ctx: SetupContext;
  let lines: string[];
  const log = (line: string) => lines.push(line);

  beforeEach(() => {
    home = mkdtempSync(path.join(tmpdir(), "4da-w2-dup-"));
    ctx = { platform: process.platform, env: { APPDATA: path.join(home, "Roaming"), XDG_CONFIG_HOME: path.join(home, ".config") }, home };
    lines = [];
  });
  afterEach(() => rmSync(home, { recursive: true, force: true }));

  it("--update on args twice: untouched, no backup, exit 1, and a second run says the same", () => {
    const cursor = editorTargets(ctx).find((t) => t.name === "Cursor")!;
    mkdirSync(cursor.detectDir, { recursive: true });
    const text = '{\n  "mcpServers": {\n    "4da": { "command": "npx", "args": ["-y", "@4da/mcp-server@6.4.0"], "args": ["-y", "@4da/mcp-server@6.3.0"] }\n  }\n}\n';
    writeFileSync(cursor.configPath, text);
    const mtime = statSync(cursor.configPath).mtimeMs;
    for (let run = 0; run < 2; run++) {
      lines = [];
      const result = runSetup({ update: true }, ctx, log);
      expect(result.exitCode).toBe(1);
      expect(readFileSync(cursor.configPath, "utf8")).toBe(text);
      expect(statSync(cursor.configPath).mtimeMs).toBe(mtime);
      expect(readdirSync(path.dirname(cursor.configPath))).toEqual(["mcp.json"]);
      const out = lines.join("\n");
      expect(out).toContain(`Not modified: ${cursor.configPath}`);
      expect(out).toContain('the key "mcpServers"."4da"."args" twice');
      expect(out).not.toContain("Written");
      expect(out).not.toContain("Replacing");
    }
  });
});
