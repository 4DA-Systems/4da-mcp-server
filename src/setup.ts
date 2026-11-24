#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
/**
 * 4DA MCP Setup — Zero-friction editor configuration
 *
 * Detects installed editors and writes MCP server configuration so
 * the user can start using 4DA tools immediately after install.
 *
 * Usage:
 *   npx @4da/mcp-server@<version> --setup [--dry-run] [--update]
 *   4da-mcp-setup [--dry-run] [--update]
 *   pnpm run setup
 *
 * What it holds to:
 *   - The command it writes pins the version of the package it runs from, so
 *     what an editor starts changes only when the user changes it.
 *   - A `4da` entry that is already there and differs is the user's: it is kept
 *     unless `--update` is given.
 *   - A config it cannot read exactly (unparseable, not UTF-8, the same key
 *     twice) is never written.
 *   - The exit code is non-zero when a detected editor's config was not written.
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
  accessSync,
  chmodSync,
  constants,
  copyFileSync,
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";
import { homedir } from "node:os";
import { fileURLToPath } from "node:url";
import jsonc from "jsonc-parser";
import type { JSONPath, Node, ParseError } from "jsonc-parser";

import { parseSetupArgs } from "./cli-args.js";
import { NPX_OPTIONS, PACKAGE, pinnedNpx, readPackageVersion } from "./usage.js";

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/**
 * The version of the package this module ships in (usage.ts, the one reader). Null when it cannot
 * be read: setup then writes nothing, because the only command it could write would be an unpinned one.
 */
export { readPackageVersion };

export const PACKAGE_VERSION = readPackageVersion();

/** The command every editor runs: npx with the package pinned to `version` (NPX_OPTIONS: usage.ts). */
function serverCommand(version: string): { command: string; args: string[] } {
  return { command: "npx", args: [...NPX_OPTIONS, `${PACKAGE}@${version}`] };
}

/** The Claude Code command printed instead of editing `~/.claude.json`. */
export function claudeCodeCommand(version: string): string {
  return `claude mcp add --scope user 4da -- npx ${NPX_OPTIONS.join(" ")} ${PACKAGE}@${version}`;
}

/** `claudeCodeCommand` for the running package. */
export const CLAUDE_CODE_COMMAND = claudeCodeCommand(PACKAGE_VERSION ?? "<version>");

function requireVersion(): string {
  if (PACKAGE_VERSION === null) throw new Error("this package's version could not be read from its package.json");
  return PACKAGE_VERSION;
}

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
 * Every editor this setup can write, with its config path on `ctx.platform`
 * and the entry pinned to `version` (the running package's by default).
 * Pure: nothing is read from disk here.
 */
export function editorTargets(ctx: SetupContext = currentContext(), version: string = requireVersion()): EditorTarget[] {
  const p = pathFor(ctx);
  const SERVER_COMMAND = serverCommand(version);
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

/**
 * `create` / `update`: the file gets a `4da` entry it did not have.
 * `unchanged`: its entry already is the one setup writes.
 * `keep`: its entry differs and is left as the user has it.
 * `replace`: its entry differs and `update` was asked.
 * `refuse`: the file is not written, for `reason`.
 */
export type PlanAction = "create" | "update" | "unchanged" | "keep" | "replace" | "refuse";

export interface ConfigPlan {
  action: PlanAction;
  /** The full new file content for create/update/replace. */
  content?: string;
  /** Why a file is refused, for the user. */
  reason?: string;
  /** keep/replace: the fields setup owns, as the existing entry has them. */
  previous?: Record<string, unknown>;
}

function lineOf(text: string, offset: number): number {
  return text.slice(0, offset).split("\n").length;
}

function sameJson(a: unknown, b: unknown): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}

/** The property nodes of an object node whose key passes `match`. JSON allows a key twice; a parsed value hides it. */
function propertiesOf(objectNode: Node | undefined, match: (key: string) => boolean): Node[] {
  if (objectNode?.type !== "object") return [];
  return (objectNode.children ?? []).filter((property) => typeof property.children?.[0]?.value === "string" && match(property.children[0].value));
}

/**
 * Decide what writing `entry` under `<key>["4da"]` does to a config file whose
 * current text is `existing` (null when it does not exist).
 *
 * The file is parsed as JSONC (comments and trailing commas allowed) and
 * edited in place with `jsonc-parser`'s `modify`, so other servers, other keys,
 * comments and formatting all survive, and a leading UTF-8 BOM is put back. A
 * file that does not parse is refused, never replaced; so is one that holds the
 * servers key or the `4da` entry twice, or `4da` in another casing, because the
 * entry written might not be the one the editor reads.
 *
 * An existing `4da` entry that differs from `entry` is the user's choice (another
 * pin, a local build, a wrapper): it is kept unless `options.update`, and then
 * only the fields setup owns are set, so `env`, `disabled` and comments stay.
 */
export function planConfig(
  existing: string | null,
  key: string,
  entry: Record<string, unknown>,
  options: { update?: boolean } = {},
): ConfigPlan {
  // A BOM is not JSON: it is set aside for parsing and put back on what is written.
  const bom = existing?.startsWith("\uFEFF") ? "\uFEFF" : "";
  const text = existing === null ? null : existing.slice(bom.length);
  if (text === null || text.trim() === "") {
    return {
      action: text === null ? "create" : "update",
      content: bom + JSON.stringify({ [key]: { "4da": entry } }, null, 2) + "\n",
    };
  }

  const errors: ParseError[] = [];
  const tree = jsonc.parseTree(text, errors, { allowTrailingComma: true, disallowComments: false });
  if (errors.length > 0) {
    const first = errors[0];
    return {
      action: "refuse",
      reason: `it does not parse (${jsonc.printParseErrorCode(first.error)} at line ${lineOf(text, first.offset)})`,
    };
  }
  const root: unknown = tree ? jsonc.getNodeValue(tree) : undefined;
  if (!isPlainObject(root)) {
    return { action: "refuse", reason: "its top level is not a JSON object" };
  }
  const serverKeys = propertiesOf(tree, (name) => name === key);
  if (serverKeys.length > 1) {
    return { action: "refuse", reason: `its "${key}" key appears ${serverKeys.length} times, and an editor reads only one of them` };
  }
  const servers = root[key];
  if (servers !== undefined && !isPlainObject(servers)) {
    return { action: "refuse", reason: `its "${key}" is not an object` };
  }
  const serversNode = serverKeys[0]?.children?.[1];
  const exact = propertiesOf(serversNode, (name) => name === "4da");
  if (exact.length > 1) {
    return { action: "refuse", reason: `its "${key}" holds ${exact.length} "4da" entries, and an editor reads only one of them` };
  }
  const otherCasing = propertiesOf(serversNode, (name) => name !== "4da" && name.toLowerCase() === "4da");
  if (exact.length === 0 && otherCasing.length > 0) {
    const name = String(otherCasing[0].children?.[0]?.value);
    return {
      action: "refuse",
      reason: `its "${key}" already has an entry named "${name}", and a "4da" entry beside it would be a second server; rename that entry to "4da" or remove it`,
    };
  }
  const current = servers?.["4da"];
  if (current !== undefined && !isPlainObject(current)) {
    return { action: "refuse", reason: `its "${key}"."4da" is not an object` };
  }
  let previous: Record<string, unknown> | undefined;
  if (current) {
    if (Object.entries(entry).every(([field, value]) => sameJson(current[field], value))) {
      return { action: "unchanged" };
    }
    previous = Object.fromEntries(Object.keys(entry).flatMap((field) => (field in current ? [[field, current[field]]] : [])));
    if (!options.update) return { action: "keep", previous };
  }

  const eol = text.includes("\r\n") ? "\r\n" : "\n";
  const indent = /^([ \t]+)\S/m.exec(text)?.[1] ?? "  ";
  const formattingOptions = {
    insertSpaces: !indent.startsWith("\t"),
    tabSize: indent.startsWith("\t") ? 1 : indent.length,
    eol,
  };
  let content = text;
  // Field by field when the entry exists, so its other fields and any
  // comments inside it stay; whole when it does not.
  const edits: Array<[JSONPath, unknown]> = current
    ? Object.entries(entry).map(([field, value]) => [[key, "4da", field], value])
    : [[[key, "4da"], entry]];
  for (const [jsonPath, value] of edits) {
    content = jsonc.applyEdits(content, jsonc.modify(content, jsonPath, value, { formattingOptions }));
  }
  return current ? { action: "replace", content: bom + content, previous } : { action: "update", content: bom + content };
}

type ConfigRead = { ok: true; text: string | null } | { ok: false; reason: string };

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/**
 * A config file's bytes as text, exactly: a byte sequence that is not UTF-8 is
 * refused, never decoded to U+FFFD, because the rewrite would then save the
 * damage. A leading BOM stays in the text (`planConfig` keeps it).
 */
export function decodeConfig(bytes: Uint8Array): ConfigRead {
  if (bytes.length >= 2 && ((bytes[0] === 0xff && bytes[1] === 0xfe) || (bytes[0] === 0xfe && bytes[1] === 0xff))) {
    return { ok: false, reason: "it is encoded as UTF-16, not UTF-8" };
  }
  try {
    return { ok: true, text: new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes) };
  } catch {
    return {
      ok: false,
      reason: "it is not valid UTF-8 (a legacy encoding such as Windows-1252, perhaps), and rewriting it would damage its non-ASCII characters",
    };
  }
}

/** Read a config file's text; null when it does not exist. */
function readConfig(filePath: string): ConfigRead {
  if (!existsSync(filePath)) return { ok: true, text: null };
  try {
    return decodeConfig(readFileSync(filePath));
  } catch (error) {
    return { ok: false, reason: `it could not be read (${errorMessage(error)})` };
  }
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
 *
 * The new file keeps the original's permission bits (a 0600 config holding
 * tokens stays 0600), a file the user cannot write is not replaced, and a write
 * that fails leaves nothing behind: not the temp file, not the backup it made.
 * @returns The backup path, when one was made.
 */
export function writeConfigAtomic(filePath: string, content: string): string | null {
  // Only a symlinked file is resolved: resolving the whole path would turn
  // macOS's /var/... into /private/var/... in every path reported back.
  const target = existsSync(filePath) && lstatSync(filePath).isSymbolicLink() ? realpathSync(filePath) : filePath;
  mkdirSync(path.dirname(target), { recursive: true });
  let backup: string | null = null;
  let mode: number | null = null;
  if (existsSync(target)) {
    // rename() needs only the directory's permission, so it would replace a read-only file.
    accessSync(target, constants.W_OK);
    mode = statSync(target).mode & 0o7777;
    backup = backupPath(target);
    copyFileSync(target, backup, constants.COPYFILE_EXCL);
  }
  const temp = `${target}.4da-${process.pid}.tmp`;
  try {
    writeFileSync(temp, content, mode === null ? {} : { mode });
    // The mode given at creation passes through the umask; chmod sets the original's bits exactly.
    if (mode !== null) chmodSync(temp, mode);
    renameSync(temp, target);
  } catch (error) {
    for (const leftover of [temp, backup]) {
      if (leftover === null) continue;
      try {
        rmSync(leftover, { force: true });
      } catch {
        // Not ours to remove (a directory by that name): the write error below is the one to report.
      }
    }
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
 * An entry's command on one line, for the kept / replacing report. The text is
 * the user's own config: control characters are dropped and the line is capped.
 */
function describeEntry(entry: Record<string, unknown> | undefined): string {
  const { command, args, type } = entry ?? {};
  let words: string;
  if (typeof command === "string" && Array.isArray(args) && args.every((arg) => typeof arg === "string")) words = [command, ...args].join(" ");
  else if (command === undefined && args === undefined) words = "(no command)";
  else words = JSON.stringify({ command, args });
  // eslint-disable-next-line no-control-regex -- replaces control characters on purpose: the line must stay one printable line
  const line = `${words}${type === undefined ? "" : ` (type ${JSON.stringify(type)})`}`.replace(/[\u0000-\u001f\u007f-\u009f]+/g, " ");
  return line.length > 240 ? `${line.slice(0, 240)}...` : line;
}

/** True when an entry runs this package through npx with no version: npx then picks the release. */
function isUnpinned(entry: Record<string, unknown> | undefined): boolean {
  return Array.isArray(entry?.args) && entry.args.includes(PACKAGE);
}

export interface SetupOptions {
  /** Report what would be written; write nothing. */
  dryRun?: boolean;
  /** Replace an existing `4da` entry that differs from the one setup writes (default: keep it). */
  update?: boolean;
  /** The version to pin. Default: the running package's; null means it could not be read. */
  version?: string | null;
}

export interface SetupResult {
  /** 0, or 1 when a detected editor's config was not written (refused, or the write failed). */
  exitCode: 0 | 1;
  /** Config files written (in a dry run: none). */
  written: string[];
  /** Config files whose differing `4da` entry was left as the user has it. */
  kept: string[];
  /** Config files that already held the entry setup writes. */
  unchanged: string[];
  /** Config files setup refused, or failed, to write. */
  notWritten: string[];
}

/**
 * Run the setup wizard: detect editors and write MCP configurations.
 * @param options `true` / `false` is `{ dryRun }`.
 */
export function runSetup(options: boolean | SetupOptions = {}, ctx: SetupContext = currentContext(), log: Log = console.log): SetupResult {
  const { dryRun = false, update = false, version = PACKAGE_VERSION } = typeof options === "boolean" ? { dryRun: options } : options;
  const result: SetupResult = { exitCode: 0, written: [], kept: [], unchanged: [], notWritten: [] };

  log("\n  4DA MCP Server — Setup\n");
  if (version === null) {
    log("  This package's version could not be read from its package.json, so setup");
    log("  cannot pin the command it writes, and it does not write an unpinned one.");
    log("  Nothing was written. Reinstall the package and run setup again.\n");
    result.exitCode = 1;
    return result;
  }
  if (dryRun) log("  [DRY RUN] No files will be modified.\n");
  log("  Detecting editors...\n");

  let found = 0;

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
      log(`    ${claudeCodeCommand(version)}`);
    }
    log("");
  }

  for (const target of editorTargets(ctx, version)) {
    if (!existsSync(target.detectDir)) continue;
    found++;
    log(`  Found: ${target.name}`);
    const read = readConfig(target.configPath);
    let plan: ConfigPlan;
    if (!read.ok) {
      plan = { action: "refuse", reason: read.reason };
    } else {
      try {
        plan = planConfig(read.text, target.key, target.entry, { update });
      } catch (error) {
        plan = { action: "refuse", reason: `it could not be edited (${errorMessage(error)})` };
      }
    }

    if (plan.action === "unchanged") {
      result.unchanged.push(target.configPath);
      log(`  Already configured: ${target.configPath}`);
    } else if (plan.action === "keep") {
      result.kept.push(target.configPath);
      log(`  Kept your existing entry: ${target.configPath}`);
      log(`    it runs:      ${describeEntry(plan.previous)}`);
      if (isUnpinned(plan.previous)) log("                  (no version is pinned: npx runs whatever it has cached, or the newest release)");
      log(`    setup writes: ${describeEntry(target.entry)}`);
      log("    To replace it, run setup again with --update (env and its other fields are kept).");
    } else if (plan.action === "refuse") {
      result.notWritten.push(target.configPath);
      log(`  Not modified: ${target.configPath}`);
      log(`  Setup left it untouched because ${plan.reason}. Add this by hand:`);
      log(snippet(target));
    } else {
      if (plan.action === "replace") {
        log(`  ${dryRun ? "Would replace" : "Replacing"} the 4da entry: ${target.configPath}`);
        log(`    was: ${describeEntry(plan.previous)}`);
        log(`    now: ${describeEntry(target.entry)}`);
      }
      if (dryRun) {
        if (plan.action !== "replace") {
          log(`  Would ${plan.action === "create" ? "create" : "update"}: ${target.configPath}`);
          log(`  Adding under "${target.key}":`);
          log(snippet(target));
        }
      } else {
        try {
          const backup = writeConfigAtomic(target.configPath, plan.content ?? "");
          result.written.push(target.configPath);
          log(`  Written: ${target.configPath}`);
          if (backup) log(`  Backup:  ${backup}`);
        } catch (error) {
          result.notWritten.push(target.configPath);
          log(`  Could not write ${target.configPath}: ${errorMessage(error)}`);
          log("  Add this by hand:");
          log(snippet(target));
        }
      }
    }
    log("");
  }

  if (found === 0) {
    log("  No supported editors detected.\n");
    log("  Manual setup — add to your editor's MCP config:\n");
    log(`  ${JSON.stringify({ mcpServers: { "4da": serverCommand(version) } }, null, 2)}\n`);
    log(`  Claude Code: ${claudeCodeCommand(version)}\n`);
  }

  // The closing line says what happened, not what was hoped for.
  const failed = result.notWritten.length;
  const wrote = result.written.length;
  if (failed > 0) {
    result.exitCode = 1;
    log(`  ${failed} config file${failed === 1 ? " was" : "s were"} not written: add the entry by hand (above).`);
  }
  if (dryRun) log("  Dry run: nothing was written.");
  else if (wrote > 0 && failed === 0) log("  Done. Restart your editor to activate 4DA.");
  else if (wrote > 0) log(`  ${wrote} config file${wrote === 1 ? " was" : "s were"} written. Restart your editor to activate 4DA.`);
  else if (failed === 0 && result.kept.length + result.unchanged.length > 0) log("  Nothing was written: every editor config found already has a 4da entry.");
  else log("  Nothing was written.");
  log("");
  log("  The server works on its own; with the 4DA desktop app installed it");
  log("  also reads the app's scored feed:");
  log("    https://github.com/4DA-Systems/4DA/releases/latest");
  log("");
  log(`  Run: ${pinnedNpx(version)} --doctor  to verify everything works.\n`);
  return result;
}

/** `4da-mcp-setup --help`, and the text an unknown argument exits with. */
export const SETUP_USAGE = `
  4da-mcp-setup — write the 4DA MCP server entry into your editors' configs

  Usage:
    4da-mcp-setup [--dry-run] [--update]

  Options:
    --dry-run       Print each file and entry, write nothing
    --update        Replace an existing 4da entry that differs from the one setup
                    writes (default: keep it and say so)
    --version, -v   Print the version
    --help, -h      Print this text

  The entry pins this package's version. Exit code 1 means a config that was
  found could not be written. An argument not listed here exits with this text
  and code 2, and writes nothing.
`;

/**
 * The `4da-mcp-setup` bin: only the arguments above do anything.
 * @returns The process exit code.
 */
export function runSetupCli(
  argv: readonly string[],
  ctx: SetupContext = currentContext(),
  log: Log = console.log,
  logError: Log = console.error,
): number {
  const parsed = parseSetupArgs(argv);
  if (!parsed.ok) {
    logError(`[4DA] ${parsed.error}`);
    logError(SETUP_USAGE);
    return 2;
  }
  if (parsed.command.kind === "help") {
    log(SETUP_USAGE);
    return 0;
  }
  if (parsed.command.kind === "version") {
    log(`${PACKAGE} ${PACKAGE_VERSION ?? "(version unreadable)"}`);
    return PACKAGE_VERSION === null ? 1 : 0;
  }
  return runSetup({ dryRun: parsed.command.dryRun, update: parsed.command.update }, ctx, log).exitCode;
}

/**
 * True when `argv1` (the script node was started with) is this module. On
 * macOS and Linux npm installs the `4da-mcp-setup` bin as a symlink named
 * just that, so matching the name against "setup.js" was false and the command
 * exited 0 having done nothing (audit 6.2.5 E-2). Resolving both sides covers the
 * symlink, `node dist/setup.js`, `pnpm run setup` and the Windows .cmd shim.
 */
export function isEntryPoint(argv1: string | undefined, moduleUrl: string): boolean {
  if (!argv1) return false;
  try {
    const a = realpathSync(argv1);
    const b = realpathSync(fileURLToPath(moduleUrl));
    return process.platform === "win32" ? a.toLowerCase() === b.toLowerCase() : a === b;
  } catch {
    return false;
  }
}

// Run directly if invoked as a script (bin entry or pnpm run setup)
if (isEntryPoint(process.argv[1], import.meta.url)) {
  process.exitCode = runSetupCli(process.argv.slice(2));
}
