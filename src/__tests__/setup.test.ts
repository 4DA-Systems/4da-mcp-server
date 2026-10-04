// SPDX-License-Identifier: Apache-2.0
/**
 * `--setup` writes each editor's MCP config. Audited 2026-10-05: VS Code,
 * Windsurf and Claude Code were configured in files those editors never read,
 * and a config that failed JSON.parse (VS Code's mcp.json is JSONC) was
 * replaced by `{}` plus our entry, deleting the user's other servers.
 *
 * Paths are resolved from an injected platform/env/home, so every platform is
 * checked on every CI runner; the write tests use a temp home.
 */
import {
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  CLAUDE_CODE_COMMAND,
  claudeCodeConfigPath,
  editorTargets,
  planConfig,
  runSetup,
  writeConfigAtomic,
  type SetupContext,
} from "../setup.js";

const ENTRY = { command: "npx", args: ["@4da/mcp-server"] };
const VSCODE_ENTRY = { type: "stdio", command: "npx", args: ["@4da/mcp-server"] };

function byName(ctx: SetupContext): Record<string, { configPath: string; key: string; entry: Record<string, unknown> }> {
  return Object.fromEntries(editorTargets(ctx).map((t) => [t.name, t]));
}

describe("editor config paths", () => {
  it("Windows", () => {
    const t = byName({
      platform: "win32",
      env: { APPDATA: "C:\\Users\\u\\AppData\\Roaming" },
      home: "C:\\Users\\u",
    });
    expect(t["Cursor"].configPath).toBe("C:\\Users\\u\\.cursor\\mcp.json");
    expect(t["VS Code (Copilot)"].configPath).toBe("C:\\Users\\u\\AppData\\Roaming\\Code\\User\\mcp.json");
    expect(t["VS Code Insiders (Copilot)"].configPath).toBe(
      "C:\\Users\\u\\AppData\\Roaming\\Code - Insiders\\User\\mcp.json",
    );
    expect(t["Windsurf"].configPath).toBe("C:\\Users\\u\\.codeium\\windsurf\\mcp_config.json");
    expect(t["Devin Desktop / Devin CLI"].configPath).toBe("C:\\Users\\u\\AppData\\Roaming\\devin\\mcp_config.json");
    expect(t["Claude Desktop"].configPath).toBe("C:\\Users\\u\\AppData\\Roaming\\Claude\\claude_desktop_config.json");
  });

  it("Windows without APPDATA falls back to the profile's Roaming dir", () => {
    const t = byName({ platform: "win32", env: {}, home: "C:\\Users\\u" });
    expect(t["VS Code (Copilot)"].configPath).toBe("C:\\Users\\u\\AppData\\Roaming\\Code\\User\\mcp.json");
  });

  it("macOS", () => {
    const t = byName({ platform: "darwin", env: {}, home: "/Users/u" });
    expect(t["Cursor"].configPath).toBe("/Users/u/.cursor/mcp.json");
    expect(t["VS Code (Copilot)"].configPath).toBe("/Users/u/Library/Application Support/Code/User/mcp.json");
    expect(t["VS Code Insiders (Copilot)"].configPath).toBe(
      "/Users/u/Library/Application Support/Code - Insiders/User/mcp.json",
    );
    expect(t["Windsurf"].configPath).toBe("/Users/u/.codeium/windsurf/mcp_config.json");
    expect(t["Devin Desktop / Devin CLI"].configPath).toBe("/Users/u/.config/devin/mcp_config.json");
    expect(t["Claude Desktop"].configPath).toBe(
      "/Users/u/Library/Application Support/Claude/claude_desktop_config.json",
    );
  });

  it("Linux, default and with XDG_CONFIG_HOME", () => {
    const t = byName({ platform: "linux", env: {}, home: "/home/u" });
    expect(t["Cursor"].configPath).toBe("/home/u/.cursor/mcp.json");
    expect(t["VS Code (Copilot)"].configPath).toBe("/home/u/.config/Code/User/mcp.json");
    expect(t["Windsurf"].configPath).toBe("/home/u/.codeium/windsurf/mcp_config.json");
    expect(t["Devin Desktop / Devin CLI"].configPath).toBe("/home/u/.config/devin/mcp_config.json");
    expect(t["Claude Desktop"].configPath).toBe("/home/u/.config/Claude/claude_desktop_config.json");

    const x = byName({ platform: "linux", env: { XDG_CONFIG_HOME: "/xdg" }, home: "/home/u" });
    expect(x["VS Code (Copilot)"].configPath).toBe("/xdg/Code/User/mcp.json");
    expect(x["Devin Desktop / Devin CLI"].configPath).toBe("/xdg/devin/mcp_config.json");
    expect(x["Claude Desktop"].configPath).toBe("/xdg/Claude/claude_desktop_config.json");
  });

  it("VS Code uses `servers` with type stdio; every other editor `mcpServers`", () => {
    for (const target of editorTargets({ platform: "linux", env: {}, home: "/home/u" })) {
      if (target.name.startsWith("VS Code")) {
        expect(target.key).toBe("servers");
        expect(target.entry).toEqual(VSCODE_ENTRY);
      } else {
        expect(target.key).toBe("mcpServers");
        expect(target.entry).toEqual(ENTRY);
      }
    }
  });

  it("never targets the paths the audit found unread", () => {
    for (const platform of ["win32", "darwin", "linux"] as const) {
      const home = platform === "win32" ? "C:\\Users\\u" : "/home/u";
      for (const target of editorTargets({ platform, env: {}, home })) {
        expect(target.configPath).not.toMatch(/[\\/]\.vscode[\\/]mcp\.json$/);
        expect(target.configPath).not.toMatch(/[\\/]\.windsurf[\\/]mcp\.json$/);
        expect(target.configPath).not.toMatch(/[\\/]\.claude[\\/]settings\.json$/);
      }
    }
  });

  it("Claude Code: ~/.claude.json, or $CLAUDE_CONFIG_DIR/.claude.json", () => {
    expect(claudeCodeConfigPath({ platform: "linux", env: {}, home: "/home/u" })).toBe("/home/u/.claude.json");
    expect(claudeCodeConfigPath({ platform: "linux", env: { CLAUDE_CONFIG_DIR: "/cfg" }, home: "/home/u" })).toBe(
      "/cfg/.claude.json",
    );
    expect(claudeCodeConfigPath({ platform: "win32", env: {}, home: "C:\\Users\\u" })).toBe("C:\\Users\\u\\.claude.json");
  });
});

describe("planConfig", () => {
  it("creates a new file with only our entry", () => {
    const plan = planConfig(null, "mcpServers", ENTRY);
    expect(plan.action).toBe("create");
    expect(JSON.parse(plan.content!)).toEqual({ mcpServers: { "4da": ENTRY } });
  });

  it("treats an empty file as empty, not as unparseable", () => {
    const plan = planConfig("", "servers", VSCODE_ENTRY);
    expect(plan.action).toBe("update");
    expect(JSON.parse(plan.content!)).toEqual({ servers: { "4da": VSCODE_ENTRY } });
  });

  it("merges into a config holding other servers and other keys", () => {
    const existing = JSON.stringify(
      { mcpServers: { github: { command: "gh-mcp", env: { TOKEN: "x" } } }, preferences: { theme: "dark" } },
      null,
      2,
    );
    const plan = planConfig(existing, "mcpServers", ENTRY);
    expect(plan.action).toBe("update");
    expect(JSON.parse(plan.content!)).toEqual({
      mcpServers: { github: { command: "gh-mcp", env: { TOKEN: "x" } }, "4da": ENTRY },
      preferences: { theme: "dark" },
    });
  });

  it("updates an existing 4da entry in place, keeping its other fields", () => {
    const existing = JSON.stringify({
      mcpServers: { "4da": { command: "node", args: ["/old/dist/index.js"], env: { FOURDA_OFFLINE: "true" } } },
    });
    const plan = planConfig(existing, "mcpServers", ENTRY);
    expect(plan.action).toBe("update");
    const parsed = JSON.parse(plan.content!);
    expect(Object.keys(parsed.mcpServers)).toEqual(["4da"]);
    expect(parsed.mcpServers["4da"]).toEqual({ ...ENTRY, env: { FOURDA_OFFLINE: "true" } });
    expect(plan.content!.match(/"4da"/g)).toHaveLength(1);
  });

  it("reports an identical entry as unchanged", () => {
    const existing = JSON.stringify({ servers: { "4da": VSCODE_ENTRY } }, null, 2);
    expect(planConfig(existing, "servers", VSCODE_ENTRY)).toEqual({ action: "unchanged" });
  });

  it("refuses a file that does not parse", () => {
    const plan = planConfig('{ "mcpServers": { "x": { "command": "a" } ', "mcpServers", ENTRY);
    expect(plan.action).toBe("refuse");
    expect(plan.content).toBeUndefined();
    expect(plan.reason).toMatch(/does not parse/);
  });

  it("refuses a non-object top level or servers key", () => {
    expect(planConfig("[]", "mcpServers", ENTRY).action).toBe("refuse");
    expect(planConfig('{"mcpServers": []}', "mcpServers", ENTRY).action).toBe("refuse");
    expect(planConfig('{"mcpServers": {"4da": "npx"}}', "mcpServers", ENTRY).action).toBe("refuse");
  });

  it("keeps comments, trailing commas and other servers in a JSONC file", () => {
    const existing = [
      "{",
      "  // My servers. Keep this comment.",
      '  "servers": {',
      '    "memory": {',
      '      "command": "npx", // inline note',
      '      "args": ["-y", "@modelcontextprotocol/server-memory"],',
      "    },",
      "  },",
      '  "inputs": [],',
      "}",
      "",
    ].join("\n");
    const plan = planConfig(existing, "servers", VSCODE_ENTRY);
    expect(plan.action).toBe("update");
    expect(plan.content).toContain("// My servers. Keep this comment.");
    expect(plan.content).toContain("// inline note");
    expect(plan.content).toContain('"inputs": []');
    expect(plan.content).toContain("@modelcontextprotocol/server-memory");
    expect(plan.content).toMatch(/"4da":\s*\{\s*"type":\s*"stdio"/);
    // The edited file is still JSONC that parses to both servers.
    const recheck = planConfig(plan.content!, "servers", VSCODE_ENTRY);
    expect(recheck.action).toBe("unchanged");
  });

  it("keeps CRLF line endings", () => {
    const existing = '{\r\n  "mcpServers": {\r\n    "a": { "command": "a" }\r\n  }\r\n}\r\n';
    const plan = planConfig(existing, "mcpServers", ENTRY);
    expect(plan.content).not.toMatch(/[^\r]\n/);
  });
});

describe("runSetup against a temp home", () => {
  let home: string;
  let ctx: SetupContext;
  let lines: string[];
  const log = (line: string) => lines.push(line);
  const output = () => lines.join("\n");

  beforeEach(() => {
    home = mkdtempSync(path.join(tmpdir(), "4da-setup-"));
    ctx = {
      platform: process.platform,
      env: { APPDATA: path.join(home, "Roaming"), XDG_CONFIG_HOME: path.join(home, ".config") },
      home,
    };
    lines = [];
  });

  afterEach(() => {
    rmSync(home, { recursive: true, force: true });
  });

  const target = (name: string) => editorTargets(ctx).find((t) => t.name === name)!;

  /** Every file under the temp home with its bytes, to prove what was or was not touched. */
  function snapshot(): Record<string, string> {
    const out: Record<string, string> = {};
    const walk = (dir: string) => {
      for (const name of readdirSync(dir)) {
        const full = path.join(dir, name);
        if (statSync(full).isDirectory()) walk(full);
        else out[path.relative(home, full)] = readFileSync(full, "latin1");
      }
    };
    walk(home);
    return out;
  }

  function install(name: string, content?: string): string {
    const t = target(name);
    mkdirSync(t.detectDir, { recursive: true });
    if (content !== undefined) {
      mkdirSync(path.dirname(t.configPath), { recursive: true });
      writeFileSync(t.configPath, content);
    }
    return t.configPath;
  }

  it("detects nothing in an empty home and prints the manual config", () => {
    runSetup(false, ctx, log);
    expect(output()).toContain("No supported editors detected.");
    expect(output()).toContain(CLAUDE_CODE_COMMAND);
    expect(snapshot()).toEqual({});
  });

  it("--dry-run writes nothing and prints each path and entry", () => {
    install("Cursor", JSON.stringify({ mcpServers: { other: { command: "x" } } }));
    const vscode = install("VS Code (Copilot)");
    install("Windsurf");
    writeFileSync(path.join(home, ".claude.json"), "{}");
    const before = snapshot();

    runSetup(true, ctx, log);

    expect(snapshot()).toEqual(before);
    expect(output()).toContain("[DRY RUN]");
    expect(output()).toContain(`Would update: ${target("Cursor").configPath}`);
    expect(output()).toContain(`Would create: ${vscode}`);
    expect(output()).toContain(`Would create: ${target("Windsurf").configPath}`);
    expect(output()).toContain('"servers": {');
    expect(output()).toContain('"type": "stdio"');
    expect(output()).toContain(CLAUDE_CODE_COMMAND);
  });

  it("writes every detected editor, backs up what existed, and leaves no temp files", () => {
    const cursor = install("Cursor", JSON.stringify({ mcpServers: { other: { command: "x" } } }, null, 2));
    const vscode = install("VS Code (Copilot)", '{\n  // keep me\n  "servers": {},\n}\n');
    const claudeDesktop = install(
      "Claude Desktop",
      JSON.stringify({ mcpServers: {}, preferences: { sidebarMode: "chat" } }, null, 2),
    );
    const windsurf = install("Windsurf");

    runSetup(false, ctx, log);

    expect(JSON.parse(readFileSync(cursor, "utf-8")).mcpServers).toEqual({ other: { command: "x" }, "4da": ENTRY });
    expect(readFileSync(`${cursor}.bak`, "utf-8")).toContain('"other"');
    const vscodeText = readFileSync(vscode, "utf-8");
    expect(vscodeText).toContain("// keep me");
    expect(vscodeText).toContain('"type": "stdio"');
    expect(JSON.parse(readFileSync(claudeDesktop, "utf-8"))).toEqual({
      mcpServers: { "4da": ENTRY },
      preferences: { sidebarMode: "chat" },
    });
    expect(JSON.parse(readFileSync(windsurf, "utf-8"))).toEqual({ mcpServers: { "4da": ENTRY } });
    expect(existsSync(`${windsurf}.bak`)).toBe(false);
    expect(Object.keys(snapshot()).filter((f) => f.endsWith(".tmp"))).toEqual([]);
    expect(output()).toContain(`Written: ${cursor}`);
    expect(output()).toContain(`Backup:  ${cursor}.bak`);
  });

  it("a second run changes nothing", () => {
    install("Cursor");
    install("VS Code (Copilot)");
    runSetup(false, ctx, log);
    const after = snapshot();
    lines = [];
    runSetup(false, ctx, log);
    expect(snapshot()).toEqual(after);
    expect(output()).toContain(`Already configured: ${target("Cursor").configPath}`);
  });

  it("leaves an unparseable file byte-for-byte untouched, with no backup", () => {
    const broken = '{\n  "servers": {\n    "memory": { "command": "npx" }\n  \n'; // truncated
    const vscode = install("VS Code (Copilot)", broken);
    const cursor = install("Cursor");

    runSetup(false, ctx, log);

    expect(readFileSync(vscode, "latin1")).toBe(broken);
    expect(existsSync(`${vscode}.bak`)).toBe(false);
    expect(output()).toContain(`Not modified: ${vscode}`);
    expect(output()).toContain("does not parse");
    expect(output()).toContain('"type": "stdio"'); // the snippet to add by hand
    // The other editor is still configured.
    expect(JSON.parse(readFileSync(cursor, "utf-8")).mcpServers["4da"]).toEqual(ENTRY);
  });

  it("never edits ~/.claude.json: prints the command, or says it is already there", () => {
    const claudeJson = path.join(home, ".claude.json");
    const original = JSON.stringify({ numStartups: 3, projects: { "/p": { mcpServers: {} } } });
    writeFileSync(claudeJson, original);

    runSetup(false, ctx, log);
    expect(readFileSync(claudeJson, "utf-8")).toBe(original);
    expect(output()).toContain("Found: Claude Code");
    expect(output()).toContain(CLAUDE_CODE_COMMAND);

    lines = [];
    writeFileSync(claudeJson, JSON.stringify({ mcpServers: { "4da": ENTRY } }));
    runSetup(false, ctx, log);
    expect(output()).toContain("Already configured (user scope");
    expect(output()).not.toContain(CLAUDE_CODE_COMMAND);
  });
});

describe("writeConfigAtomic", () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(path.join(tmpdir(), "4da-atomic-"));
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it("creates parent directories and makes no backup for a new file", () => {
    const file = path.join(dir, "a", "b", "mcp.json");
    expect(writeConfigAtomic(file, "{}\n")).toBeNull();
    expect(readFileSync(file, "utf-8")).toBe("{}\n");
    expect(readdirSync(path.dirname(file))).toEqual(["mcp.json"]);
  });

  // Creating a symlink on Windows needs a privilege CI runners may lack.
  it.skipIf(process.platform === "win32")("writes through a symlinked config to its target", () => {
    const real = path.join(dir, "dotfiles-mcp.json");
    const link = path.join(dir, "mcp.json");
    writeFileSync(real, "v1");
    symlinkSync(real, link);
    writeConfigAtomic(link, "v2");
    expect(lstatSync(link).isSymbolicLink()).toBe(true);
    expect(readFileSync(real, "utf-8")).toBe("v2");
  });

  it("never overwrites an earlier backup", () => {
    const file = path.join(dir, "mcp.json");
    writeFileSync(file, "v1");
    expect(writeConfigAtomic(file, "v2")).toBe(`${file}.bak`);
    const second = writeConfigAtomic(file, "v3");
    expect(second).not.toBe(`${file}.bak`);
    expect(second).toMatch(/\.bak$/);
    expect(readFileSync(`${file}.bak`, "utf-8")).toBe("v1");
    expect(readFileSync(second!, "utf-8")).toBe("v2");
    expect(readFileSync(file, "utf-8")).toBe("v3");
  });
});
