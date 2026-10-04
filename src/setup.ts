#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
/**
 * 4DA MCP Setup — Zero-friction editor configuration
 *
 * Detects installed editors and writes MCP server configuration so
 * the user can start using 4DA tools immediately after install.
 *
 * Usage:
 *   npx @4da/mcp-server --setup [--dry-run]
 *   4da-mcp-setup [--dry-run]
 *   pnpm run setup
 *
 * Audited 2026-10-05: three of the four editors were configured in files the
 * editor never reads (`~/.vscode/mcp.json`, `~/.windsurf/mcp.json`, and
 * `mcpServers` in a project's `.claude/settings.json`), and any config file
 * that failed `JSON.parse` (VS Code's `mcp.json` is JSONC: comments and
 * trailing commas are legal) was replaced by `{}` plus our entry, deleting
 * every other server the user had. Each path below cites the doc it was
 * checked against, and a file that cannot be parsed is never written.
 */

import {
  copyFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";
import { homedir } from "node:os";
import jsonc from "jsonc-parser";
import type { JSONPath, ParseError } from "jsonc-parser";

/** The command every editor runs. */
const SERVER_COMMAND = { command: "npx", args: ["@4da/mcp-server"] };

/** MCP config snippet for editors that use the standard mcpServers format */
const MCP_CONFIG = {
  "4da": SERVER_COMMAND,
};

/** The Claude Code command printed instead of editing `~/.claude.json`. */
export const CLAUDE_CODE_COMMAND = "claude mcp add --scope user 4da -- npx @4da/mcp-server";

/** Where the paths are resolved: injected so tests can stand in any platform. */
export interface SetupContext {
  platform: NodeJS.Platform;
  env: NodeJS.ProcessEnv;
  home: string;
}

export function currentContext(): SetupContext {
  return { platform: process.platform, env: process.env, home: homedir() };
}

/** An editor whose MCP config file this setup writes. */
export interface EditorTarget {
  name: string;
  /** Config file the server entry goes into. */
  configPath: string;
  /** Directory whose existence means the editor is installed. */
  detectDir: string;
  /** Top-level key holding the servers: VS Code uses `servers`, the rest `mcpServers`. */
  key: "mcpServers" | "servers";
  /** The value written under `<key>["4da"]`. */
  entry: Record<string, unknown>;
  /** Where the path and key were verified. */
  docs: string;
}

function pathFor(ctx: SetupContext) {
  return ctx.platform === "win32" ? path.win32 : path.posix;
}

/** `%APPDATA%` on Windows, the Electron-style config base elsewhere. */
function roamingDir(ctx: SetupContext): string {
  const p = pathFor(ctx);
  return ctx.env.APPDATA?.trim() || p.join(ctx.home, "AppData", "Roaming");
}

function xdgConfigDir(ctx: SetupContext): string {
  return ctx.env.XDG_CONFIG_HOME?.trim() || pathFor(ctx).join(ctx.home, ".config");
}

/**
 * The per-platform user-data dir of a desktop app (Electron `appData`):
 * `%APPDATA%\<name>`, `~/Library/Application Support/<name>`,
 * `$XDG_CONFIG_HOME/<name>` (default `~/.config/<name>`).
 */
function appDataDir(ctx: SetupContext, name: string): string {
  const p = pathFor(ctx);
  if (ctx.platform === "win32") return p.join(roamingDir(ctx), name);
  if (ctx.platform === "darwin") return p.join(ctx.home, "Library", "Application Support", name);
  return p.join(xdgConfigDir(ctx), name);
}

/**
 * Every editor this setup can write, with its config path on `ctx.platform`.
 * Pure: nothing is read from disk here.
 */
export function editorTargets(ctx: SetupContext = currentContext()): EditorTarget[] {
  const p = pathFor(ctx);
  const vscodeEntry = { type: "stdio", ...SERVER_COMMAND };
  const vscode = (name: string, product: string): EditorTarget => {
    const userDir = p.join(appDataDir(ctx, product), "User");
    return {
      name,
      // The default profile's user-level file; it sits beside settings.json.
      // A non-default profile keeps its own under User/profiles/<id>/, which
      // VS Code does not name anywhere setup could find it.
      configPath: p.join(userDir, "mcp.json"),
      detectDir: userDir,
      key: "servers",
      entry: vscodeEntry,
      docs: "https://code.visualstudio.com/docs/copilot/reference/mcp-configuration",
    };
  };
  const devinDir =
    ctx.platform === "win32" ? p.join(roamingDir(ctx), "devin") : p.join(xdgConfigDir(ctx), "devin");
  const windsurfDir = p.join(ctx.home, ".codeium", "windsurf");

  return [
    {
      name: "Cursor",
      configPath: p.join(ctx.home, ".cursor", "mcp.json"),
      detectDir: p.join(ctx.home, ".cursor"),
      key: "mcpServers",
      entry: SERVER_COMMAND,
      docs: "https://cursor.com/docs/mcp",
    },
    vscode("VS Code (Copilot)", "Code"),
    vscode("VS Code Insiders (Copilot)", "Code - Insiders"),
    {
      name: "Windsurf",
      configPath: p.join(windsurfDir, "mcp_config.json"),
      detectDir: windsurfDir,
      key: "mcpServers",
      entry: SERVER_COMMAND,
      docs: "https://docs.devin.ai/cli/reference/configuration/read-config-from",
    },
    {
      // Windsurf's successor. Its Cascade agent and the Devin CLI read the
      // same user-level file.
      name: "Devin Desktop / Devin CLI",
      configPath: p.join(devinDir, "mcp_config.json"),
      detectDir: devinDir,
      key: "mcpServers",
      entry: SERVER_COMMAND,
      docs: "https://docs.devin.ai/desktop/cascade/mcp",
    },
    {
      name: "Claude Desktop",
      configPath: p.join(appDataDir(ctx, "Claude"), "claude_desktop_config.json"),
      detectDir: appDataDir(ctx, "Claude"),
      key: "mcpServers",
      entry: SERVER_COMMAND,
      docs: "https://modelcontextprotocol.io/docs/develop/connect-local-servers",
    },
  ];
}

/**
 * Claude Code keeps user- and local-scope servers in `~/.claude.json`
 * (`$CLAUDE_CONFIG_DIR/.claude.json` when set), a file it rewrites itself and
 * that also holds the sign-in session and per-project state. Setup never
 * edits it: it prints the `claude mcp add` command, which does.
 * https://code.claude.com/docs/en/mcp
 */
export function claudeCodeConfigPath(ctx: SetupContext = currentContext()): string {
  const p = pathFor(ctx);
  const configDir = ctx.env.CLAUDE_CONFIG_DIR?.trim();
  return configDir ? p.join(configDir, ".claude.json") : p.join(ctx.home, ".claude.json");
}

// =============================================================================
// Planning: what would change, decided before anything is written
// =============================================================================

export type PlanAction = "create" | "update" | "unchanged" | "refuse";

export interface ConfigPlan {
  action: PlanAction;
  /** The full new file content for create/update. */
  content?: string;
  /** Why a file is refused, for the user. */
  reason?: string;
}

function lineOf(text: string, offset: number): number {
  return text.slice(0, offset).split("\n").length;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function sameJson(a: unknown, b: unknown): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}

/**
 * Decide what writing `entry` under `<key>["4da"]` does to a config file whose
 * current text is `existing` (null when it does not exist).
 *
 * The file is parsed as JSONC (comments and trailing commas allowed) and
 * edited in place with `jsonc-parser`'s `modify`, so other servers, other keys,
 * comments and formatting all survive. A file that does not parse is refused,
 * never replaced. An existing `4da` entry keeps its other fields (`env`, say);
 * only the fields setup owns are set.
 */
export function planConfig(existing: string | null, key: string, entry: Record<string, unknown>): ConfigPlan {
  if (existing === null || existing.trim() === "") {
    return {
      action: existing === null ? "create" : "update",
      content: JSON.stringify({ [key]: { "4da": entry } }, null, 2) + "\n",
    };
  }

  const errors: ParseError[] = [];
  const root: unknown = jsonc.parse(existing, errors, { allowTrailingComma: true, disallowComments: false });
  if (errors.length > 0) {
    const first = errors[0];
    return {
      action: "refuse",
      reason: `it does not parse (${jsonc.printParseErrorCode(first.error)} at line ${lineOf(existing, first.offset)})`,
    };
  }
  if (!isPlainObject(root)) {
    return { action: "refuse", reason: "its top level is not a JSON object" };
  }
  const servers = root[key];
  if (servers !== undefined && !isPlainObject(servers)) {
    return { action: "refuse", reason: `its "${key}" is not an object` };
  }
  const current = servers?.["4da"];
  if (current !== undefined && !isPlainObject(current)) {
    return { action: "refuse", reason: `its "${key}"."4da" is not an object` };
  }
  if (current && Object.entries(entry).every(([field, value]) => sameJson(current[field], value))) {
    return { action: "unchanged" };
  }

  const eol = existing.includes("\r\n") ? "\r\n" : "\n";
  const indent = /^([ \t]+)\S/m.exec(existing)?.[1] ?? "  ";
  const formattingOptions = {
    insertSpaces: !indent.startsWith("\t"),
    tabSize: indent.startsWith("\t") ? 1 : indent.length,
    eol,
  };
  let content = existing;
  // Field by field when the entry exists, so its other fields and any
  // comments inside it stay; whole when it does not.
  const edits: Array<[JSONPath, unknown]> = current
    ? Object.entries(entry).map(([field, value]) => [[key, "4da", field], value])
    : [[[key, "4da"], entry]];
  for (const [jsonPath, value] of edits) {
    content = jsonc.applyEdits(content, jsonc.modify(content, jsonPath, value, { formattingOptions }));
  }
  return { action: "update", content };
}

/** Read a config file's text; null when it does not exist. */
function readConfig(filePath: string): string | null {
  return existsSync(filePath) ? readFileSync(filePath, "utf-8") : null;
}

/** `<file>.bak`, or a timestamped name when that is taken: an earlier backup is never overwritten. */
function backupPath(filePath: string): string {
  const plain = `${filePath}.bak`;
  if (!existsSync(plain)) return plain;
  const stamp = new Date().toISOString().replace(/[-:]/g, "").replace(/\..*$/, "");
  for (let n = 0; ; n++) {
    const candidate = `${filePath}.${stamp}${n === 0 ? "" : `-${n}`}.bak`;
    if (!existsSync(candidate)) return candidate;
  }
}

/**
 * Write `content` to `filePath`: back up an existing file first, then write a
 * temp file beside it and rename it over the original, so an interrupted run
 * leaves either the old file or the new one, never half of one. A symlinked
 * config (a dotfiles repo) is written through to its target.
 * @returns The backup path, when one was made.
 */
export function writeConfigAtomic(filePath: string, content: string): string | null {
  const target = existsSync(filePath) ? realpathSync(filePath) : filePath;
  mkdirSync(path.dirname(target), { recursive: true });
  let backup: string | null = null;
  if (existsSync(target)) {
    backup = backupPath(target);
    copyFileSync(target, backup);
  }
  const temp = `${target}.4da-${process.pid}.tmp`;
  try {
    writeFileSync(temp, content);
    renameSync(temp, target);
  } catch (error) {
    rmSync(temp, { force: true });
    throw error;
  }
  return backup;
}

// =============================================================================
// Run
// =============================================================================

type Log = (line: string) => void;

/** The snippet an editor gets, as printed in a dry run and for manual setup. */
function snippet(target: EditorTarget): string {
  return JSON.stringify({ [target.key]: { "4da": target.entry } }, null, 2)
    .split("\n")
    .map((line) => `    ${line}`)
    .join("\n");
}

/** Whether `~/.claude.json` already has a user-scope `4da` server. Read-only. */
function claudeCodeHas4da(configPath: string): boolean {
  try {
    const root: unknown = JSON.parse(readFileSync(configPath, "utf-8"));
    return isPlainObject(root) && isPlainObject(root.mcpServers) && "4da" in root.mcpServers;
  } catch {
    return false;
  }
}

/**
 * Run the setup wizard: detect editors and write MCP configurations.
 * @param dryRun If true, only report what would be written without modifying files.
 */
export function runSetup(dryRun = false, ctx: SetupContext = currentContext(), log: Log = console.log): void {
  log("\n  4DA MCP Server — Setup\n");
  if (dryRun) log("  [DRY RUN] No files will be modified.\n");
  log("  Detecting editors...\n");

  let found = 0;
  let refused = 0;

  // Claude Code: print the command, never edit ~/.claude.json.
  const claudeJson = claudeCodeConfigPath(ctx);
  const claudeDir = pathFor(ctx).join(ctx.home, ".claude");
  if (existsSync(claudeJson) || existsSync(claudeDir)) {
    found++;
    log("  Found: Claude Code");
    if (claudeCodeHas4da(claudeJson)) {
      log(`  Already configured (user scope, ${claudeJson}).`);
    } else {
      log("  Claude Code keeps its MCP servers in ~/.claude.json, which it rewrites");
      log("  itself; setup does not edit it. Add the server with:");
      log(`    ${CLAUDE_CODE_COMMAND}`);
    }
    log("");
  }

  for (const target of editorTargets(ctx)) {
    if (!existsSync(target.detectDir)) continue;
    found++;
    log(`  Found: ${target.name}`);
    let plan: ConfigPlan;
    try {
      plan = planConfig(readConfig(target.configPath), target.key, target.entry);
    } catch (error) {
      plan = { action: "refuse", reason: `it could not be read (${error instanceof Error ? error.message : String(error)})` };
    }

    if (plan.action === "unchanged") {
      log(`  Already configured: ${target.configPath}`);
    } else if (plan.action === "refuse") {
      refused++;
      log(`  Not modified: ${target.configPath}`);
      log(`  Setup left it untouched because ${plan.reason}. Add this by hand:`);
      log(snippet(target));
    } else if (dryRun) {
      log(`  Would ${plan.action === "create" ? "create" : "update"}: ${target.configPath}`);
      log(`  Adding under "${target.key}":`);
      log(snippet(target));
    } else {
      try {
        const backup = writeConfigAtomic(target.configPath, plan.content ?? "");
        log(`  Written: ${target.configPath}`);
        if (backup) log(`  Backup:  ${backup}`);
      } catch (error) {
        refused++;
        log(`  Could not write ${target.configPath}: ${error instanceof Error ? error.message : String(error)}`);
        log("  Add this by hand:");
        log(snippet(target));
      }
    }
    log("");
  }

  if (found === 0) {
    log("  No supported editors detected.\n");
    log("  Manual setup — add to your editor's MCP config:\n");
    log(`  ${JSON.stringify({ mcpServers: MCP_CONFIG }, null, 2)}\n`);
    log(`  Claude Code: ${CLAUDE_CODE_COMMAND}\n`);
  }

  if (refused > 0) log(`  ${refused} config file${refused === 1 ? " needs" : "s need"} the entry added by hand (above).`);
  log("  Done. Restart your editor to activate 4DA.");
  log("");
  log("  The server works on its own; with the 4DA desktop app installed it");
  log("  also reads the app's scored feed:");
  log("    https://github.com/4DA-Systems/4DA/releases/latest");
  log("");
  log("  Run: npx @4da/mcp-server --doctor  to verify everything works.\n");
}

// Run directly if invoked as a script (bin entry or pnpm run setup)
const isDirectRun =
  process.argv[1]?.endsWith("setup.js") || process.argv[1]?.endsWith("setup.ts");
if (isDirectRun) {
  const dryRun = process.argv.includes("--dry-run");
  runSetup(dryRun);
}
