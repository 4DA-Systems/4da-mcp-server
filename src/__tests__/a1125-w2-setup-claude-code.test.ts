// SPDX-License-Identifier: Apache-2.0
/**
 * Audit 2026-11-25, H-1: `--setup --update`, which the update notice tells every user to run, printed
 * "Already configured" for a Claude Code `4da` entry pinned to any release, so the old pin stayed with
 * a message that read as done; a plugin user was told to `claude mcp add` a second server. Setup still
 * never edits Claude Code's files: it shows what runs and prints the commands that change it.
 */
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { runSetup, type SetupContext } from "../setup.js";
import { claudeCodeReport, entryPin, readClaudeCodeState } from "../setup-claude-code.js";

const VERSION = JSON.parse(readFileSync(path.resolve("package.json"), "utf8")).version as string;
const PKG = "@4da/mcp-server";
const OLD = "6.4.0";
const exactEntry = { type: "stdio", command: "npx", args: ["-y", "--prefer-offline", `${PKG}@${VERSION}`], env: {} };

let home: string;
let cwd: string;
let ctx: SetupContext;
let lines: string[];
const log = (line: string) => lines.push(line);
const output = () => lines.join("\n");

/** Every file under the temp home with its bytes. */
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

function claudeJson(value: unknown): string {
  const file = path.join(home, ".claude.json");
  writeFileSync(file, typeof value === "string" ? value : JSON.stringify(value, null, 2));
  return file;
}

function plugin(pin: string | null, options: { scope?: string; id?: string; manifest?: string | null; enabled?: boolean } = {}): string {
  const id = options.id ?? "4da@4da";
  const installPath = path.join(home, ".claude", "plugins", "cache", "4da", "4da", pin ?? "x");
  mkdirSync(path.join(installPath, ".claude-plugin"), { recursive: true });
  if (options.manifest !== null) {
    const manifest = options.manifest ?? JSON.stringify({ name: "4da", mcpServers: { "4da": { command: "npx", args: ["-y", "--prefer-offline", `${PKG}@${pin}`] } } });
    writeFileSync(path.join(installPath, ".claude-plugin", "plugin.json"), manifest);
  }
  const record = { scope: options.scope ?? "user", installPath, version: pin ?? "x", installedAt: "2026-11-01T00:00:00.000Z" };
  mkdirSync(path.join(home, ".claude", "plugins"), { recursive: true });
  writeFileSync(path.join(home, ".claude", "plugins", "installed_plugins.json"), JSON.stringify({ version: 2, plugins: { [id]: [record] } }, null, 2));
  if (options.enabled !== undefined) writeFileSync(path.join(home, ".claude", "settings.json"), JSON.stringify({ enabledPlugins: { [id]: options.enabled } }));
  return installPath;
}

beforeEach(() => {
  home = mkdtempSync(path.join(tmpdir(), "4da-w2-cc-"));
  cwd = path.join(home, "work", "proj");
  mkdirSync(cwd, { recursive: true });
  ctx = { platform: process.platform, env: { APPDATA: path.join(home, "Roaming"), XDG_CONFIG_HOME: path.join(home, ".config") }, home, cwd };
  lines = [];
});

afterEach(() => {
  rmSync(home, { recursive: true, force: true });
});

describe("Claude Code: what runs, and the commands that move it", () => {
  it("an entry pinned to another release: never 'Already configured'; the version, then remove + add for its scope", () => {
    const file = claudeJson({ numStartups: 3, mcpServers: { "4da": { type: "stdio", command: "npx", args: ["-y", `${PKG}@${OLD}`], env: {} } } });
    const before = snapshot();
    const result = runSetup({ update: true }, ctx, log);
    expect(snapshot()).toEqual(before);
    expect(output()).not.toContain("Already configured");
    expect(output()).toContain(`it runs ${PKG}@${OLD}`);
    expect(output()).toContain(`(user scope, ${file})`);
    expect(output()).toContain("    claude mcp remove 4da -s user");
    expect(output()).toContain(`    claude mcp add --scope user 4da -- npx -y --prefer-offline ${PKG}@${VERSION}`);
    expect(output()).not.toContain("Nothing was written: every editor config found already has a 4da entry");
    expect(result.exitCode).toBe(0);
  });

  it("the same release, the same command: says so, with the version, and prints no command", () => {
    claudeJson({ mcpServers: { "4da": exactEntry } });
    runSetup({ update: true }, ctx, log);
    expect(output()).toContain(`Already configured (user scope, ${path.join(home, ".claude.json")}): it runs ${PKG}@${VERSION}, this release.`);
    expect(output()).not.toMatch(/^ +claude mcp add /m);
    expect(output()).not.toContain("claude mcp remove");
  });

  it("no version pinned: says so and prints the commands", () => {
    claudeJson({ mcpServers: { "4da": { command: "npx", args: ["-y", PKG] } } });
    runSetup({}, ctx, log);
    expect(output()).toContain("with no version pinned");
    expect(output()).toContain("claude mcp remove 4da -s user");
    expect(output()).not.toContain("Already configured");
  });

  it("a tag (latest) is not a pin", () => {
    expect(entryPin({ command: "npx", args: ["-y", `${PKG}@latest`] })).toEqual({ kind: "unpinned", spec: `${PKG}@latest` });
    expect(entryPin({ command: "npx", args: ["-y", `${PKG}@^6.5.0`] }).kind).toBe("unpinned");
    expect(entryPin({ command: "npx", args: ["-y", "--prefer-offline", `${PKG}@6.5.1`] })).toEqual({ kind: "pinned", version: "6.5.1" });
    expect(entryPin({ command: "node", args: ["/dev/4da-mcp-server/dist/index.js"] })).toEqual({ kind: "other", runs: "node /dev/4da-mcp-server/dist/index.js" });
  });

  it("a local build is named as one, never as configured", () => {
    claudeJson({ mcpServers: { "4da": { command: "node", args: ["/dev/4da-mcp-server/dist/index.js"] } } });
    runSetup({}, ctx, log);
    expect(output()).toContain("not a release of @4da/mcp-server from npm");
    expect(output()).toContain("claude mcp remove 4da -s user");
    expect(output()).not.toContain("Already configured");
  });

  it("this release with another command (no --prefer-offline): the version, and the commands to change it", () => {
    claudeJson({ mcpServers: { "4da": { command: "npx", args: ["-y", `${PKG}@${VERSION}`] } } });
    runSetup({}, ctx, log);
    expect(output()).toContain(`it runs ${PKG}@${VERSION}`);
    expect(output()).toContain("That is this release, started by another command");
    expect(output()).toContain("claude mcp remove 4da -s user");
  });

  it("a newer release than this one: nothing to do, no command that moves it back", () => {
    claudeJson({ mcpServers: { "4da": { command: "npx", args: ["-y", "--prefer-offline", `${PKG}@999.0.0`] } } });
    runSetup({}, ctx, log);
    expect(output()).toContain("newer release than this one");
    expect(output()).not.toContain("claude mcp remove");
  });

  it("its env names are said (never their values), since remove + add does not carry them", () => {
    claudeJson({ mcpServers: { "4da": { command: "npx", args: ["-y", `${PKG}@${OLD}`], env: { FOURDA_PRIVATE_PACKAGES: "npm:@acme/*", OPENAI_API_KEY: "sk-secret-value" } } } });
    runSetup({}, ctx, log);
    expect(output()).toContain("FOURDA_PRIVATE_PACKAGES, OPENAI_API_KEY");
    expect(output()).not.toContain("sk-secret-value");
    expect(output()).not.toContain("npm:@acme/*");
  });

  it("local scope (projects[<cwd>]) and project scope (.mcp.json in cwd) get their own scope in the commands", () => {
    const key = process.platform === "win32" ? cwd.replace(/\\/g, "/") : cwd;
    claudeJson({ projects: { [key]: { mcpServers: { "4da": { command: "npx", args: ["-y", `${PKG}@${OLD}`] } } } } });
    writeFileSync(path.join(cwd, ".mcp.json"), JSON.stringify({ mcpServers: { "4da": { command: "npx", args: ["-y", `${PKG}@6.3.0`] } } }));
    runSetup({}, ctx, log);
    expect(output()).toContain("claude mcp remove 4da -s local");
    expect(output()).toContain(`claude mcp add --scope local 4da -- npx -y --prefer-offline ${PKG}@${VERSION}`);
    expect(output()).toContain("claude mcp remove 4da -s project");
    expect(output()).toContain(`claude mcp add --scope project 4da -- npx -y --prefer-offline ${PKG}@${VERSION}`);
  });

  it("an unreadable ~/.claude.json: says what is not known, never 'Already configured', never a bare add as if nothing were there", () => {
    claudeJson('{ "mcpServers": { "4da": ');
    runSetup({}, ctx, log);
    expect(output()).toContain("Could not read");
    expect(output()).toContain("claude mcp list");
    expect(output()).not.toContain("Already configured");
  });

  it("control characters in a user's entry stay on one printable line", () => {
    claudeJson({ mcpServers: { "4da": { command: "node\u001b[31m", args: ["x\ny"] } } });
    runSetup({}, ctx, log);
    expect(output().includes("\u001b")).toBe(false);
    expect(output()).toContain("node [31m x y");
  });
});

describe("Claude Code plugin: the plugin provides the server, and updates it", () => {
  it("plugin on an older pin: says the plugin provides it, prints the plugin update, never `claude mcp add`", () => {
    plugin(OLD);
    const before = snapshot();
    runSetup({ update: true }, ctx, log);
    expect(snapshot()).toEqual(before);
    expect(output()).toContain(`The Claude Code plugin 4da@4da (user scope) provides the server: it runs ${PKG}@${OLD}.`);
    expect(output()).toContain("    claude plugin marketplace update 4da");
    expect(output()).toContain("    claude plugin update 4da@4da");
    expect(output()).not.toMatch(/^ +claude mcp add /m);
    expect(output()).not.toContain("Already configured");
  });

  it("plugin on this release: nothing to do", () => {
    plugin(VERSION);
    runSetup({}, ctx, log);
    expect(output()).toContain("That is this release: nothing to do.");
    expect(output()).not.toContain("claude plugin update");
    expect(output()).not.toMatch(/^ +claude mcp add /m);
  });

  it("a project-scope install gets --scope project on its update", () => {
    plugin(OLD, { scope: "project" });
    runSetup({}, ctx, log);
    expect(output()).toContain("claude plugin update 4da@4da --scope project");
  });

  it("a plugin whose manifest cannot be read: the pin is said unknown, the update still given, no add", () => {
    plugin(null, { manifest: "{ not json" });
    runSetup({}, ctx, log);
    expect(output()).toContain("its pinned release could not be read");
    expect(output()).toContain("claude plugin update 4da@4da");
    expect(output()).not.toMatch(/^ +claude mcp add /m);
  });

  it("a disabled plugin is said disabled", () => {
    plugin(OLD, { enabled: false });
    runSetup({}, ctx, log);
    expect(output()).toContain("disabled in your user settings");
  });

  it("another plugin whose name ends in 4da is not this one", () => {
    plugin(OLD, { id: "not4da@market" });
    runSetup({}, ctx, log);
    expect(output()).not.toContain("plugin not4da");
    expect(output()).toContain("claude mcp add --scope user 4da");
  });

  it("plugin and a ~/.claude.json entry both: both reported, keep one", () => {
    plugin(OLD);
    claudeJson({ mcpServers: { "4da": exactEntry } });
    runSetup({}, ctx, log);
    expect(output()).toContain("keep one of them");
  });

  it("an unreadable installed_plugins.json is said, and the add command is not printed as if nothing were there", () => {
    mkdirSync(path.join(home, ".claude", "plugins"), { recursive: true });
    writeFileSync(path.join(home, ".claude", "plugins", "installed_plugins.json"), "{ broken");
    runSetup({}, ctx, log);
    expect(output()).toContain("Could not read");
    expect(output()).toContain("claude plugin list");
  });

  it("$CLAUDE_CONFIG_DIR is where the plugin record is read", () => {
    const configDir = path.join(home, "cc-config");
    const installPath = path.join(configDir, "plugins", "cache", "4da", "4da", OLD);
    mkdirSync(path.join(installPath, ".claude-plugin"), { recursive: true });
    writeFileSync(path.join(installPath, ".claude-plugin", "plugin.json"), JSON.stringify({ mcpServers: { "4da": { command: "npx", args: ["-y", `${PKG}@${OLD}`] } } }));
    writeFileSync(path.join(configDir, "plugins", "installed_plugins.json"), JSON.stringify({ version: 2, plugins: { "4da@4da": [{ scope: "user", installPath }] } }));
    const state = readClaudeCodeState({ ...ctx, env: { CLAUDE_CONFIG_DIR: configDir } }, path.join(configDir, ".claude.json"), VERSION);
    expect(state.plugins.map((p) => p.pin)).toEqual([{ kind: "pinned", version: OLD }]);
    expect(claudeCodeReport(state, VERSION).join("\n")).toContain("claude plugin update 4da@4da");
  });
});
