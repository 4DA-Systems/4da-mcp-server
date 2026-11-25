// SPDX-License-Identifier: Apache-2.0
/**
 * What `--setup` says about Claude Code. Setup never edits Claude Code's files: it reads them and
 * prints the commands that do.
 *
 * Audit 2026-11-25 (H-1): the update notice tells every user to run `--setup --update`, and for
 * Claude Code that printed "Already configured" whenever a `4da` key existed, whatever release it
 * pinned, so the old pin stayed with a message that read as done. A plugin user, whose server comes
 * from the plugin and not from `~/.claude.json`, was told to `claude mcp add` a second server.
 *
 * Where Claude Code keeps a server (https://code.claude.com/docs/en/mcp):
 * - user scope: `mcpServers` at the top of `~/.claude.json` (`$CLAUDE_CONFIG_DIR/.claude.json`);
 * - local scope: `projects["<project path>"].mcpServers` in the same file, keyed by the absolute
 *   project path (forward slashes on Windows);
 * - project scope: `mcpServers` in `.mcp.json` at the project root.
 * An installed plugin is recorded in `<config dir>/plugins/installed_plugins.json` (`plugins`, keyed
 * `<name>@<marketplace>`, each a list of installs with `scope` and `installPath`); the server it
 * starts is the `mcpServers` of `<installPath>/.claude-plugin/plugin.json`.
 */

import { existsSync, readFileSync, statSync } from "node:fs";
import path from "node:path";

import { NPX_OPTIONS, PACKAGE } from "./usage.js";

export type ClaudeScope = "user" | "local" | "project";

/** Where Claude Code's files are, for the platform setup runs on (or a test stands in). */
export interface ClaudeCodeContext {
  platform: NodeJS.Platform;
  env: NodeJS.ProcessEnv;
  home: string;
  /** The directory setup runs in: its local- and project-scope servers are read. Left out, neither is. */
  cwd?: string;
}

/** What an entry runs, as far as setup can tell from its command and arguments. */
export type EntryPin =
  | { kind: "pinned"; version: string }
  | { kind: "unpinned"; spec: string }
  | { kind: "other"; runs: string };

/** A `4da` server Claude Code has, and where. */
export interface ClaudeCodeServer {
  scope: ClaudeScope;
  file: string;
  pin: EntryPin;
  /** The names of its `env` variables (never their values). */
  envNames: string[];
  /** True when its command and arguments are exactly the ones setup writes for `version`. */
  exact: boolean;
}

/** An installed copy of the `4da` Claude Code plugin. */
export interface ClaudePluginInstall {
  id: string;
  marketplace: string;
  scope: string;
  pin: EntryPin | null;
  /** Why the pin could not be read, when it could not. */
  unreadable: string | null;
  /** True when the user settings set `enabledPlugins[id]` to false. */
  disabled: boolean;
}

export interface ClaudeCodeState {
  servers: ClaudeCodeServer[];
  plugins: ClaudePluginInstall[];
  /** Files setup could not read, with the reason: what they hold is not known. */
  unreadable: { file: string; reason: string }[];
}

const MAX_CONFIG_BYTES = 64 * 1024 * 1024;
const RELEASE = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/;

function pathFor(platform: NodeJS.Platform) {
  return platform === "win32" ? path.win32 : path.posix;
}

/** Claude Code's configuration directory: `$CLAUDE_CONFIG_DIR`, else `~/.claude`. */
export function claudeConfigDir(ctx: ClaudeCodeContext): string {
  return ctx.env.CLAUDE_CONFIG_DIR?.trim() || pathFor(ctx.platform).join(ctx.home, ".claude");
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function errorText(error: unknown): string {
  return (error instanceof Error ? error.message : String(error)).split("\n")[0].slice(0, 200);
}

/** One printable line of text from a user's file: control characters dropped, capped. */
export function printable(text: string, max = 240): string {
  // eslint-disable-next-line no-control-regex -- replaces control characters on purpose: the line must stay one printable line
  const line = text.replace(/[\u0000-\u001f\u007f-\u009f]+/g, " ");
  return line.length > max ? `${line.slice(0, max)}...` : line;
}

type JsonRead = { ok: true; value: unknown } | { ok: false; reason: string } | { ok: true; value: undefined; missing: true };

function readJson(file: string): JsonRead {
  if (!existsSync(file)) return { ok: true, value: undefined, missing: true };
  try {
    if (statSync(file).size > MAX_CONFIG_BYTES) return { ok: false, reason: `it is over ${MAX_CONFIG_BYTES / (1024 * 1024)} MB` };
    return { ok: true, value: JSON.parse(readFileSync(file, "utf-8").replace(/^﻿/, "")) };
  } catch (error) {
    return { ok: false, reason: errorText(error) };
  }
}

/**
 * What an MCP server entry runs: `@4da/mcp-server@<release>` (pinned), the package with no release
 * or with a tag or range (unpinned), or something else (a local build, a wrapper).
 */
export function entryPin(entry: unknown): EntryPin {
  const command = isPlainObject(entry) && typeof entry.command === "string" ? entry.command : null;
  const args = isPlainObject(entry) && Array.isArray(entry.args) ? entry.args.filter((a): a is string => typeof a === "string") : [];
  for (const word of [command, ...args]) {
    if (word === null) continue;
    if (word === PACKAGE) return { kind: "unpinned", spec: PACKAGE };
    if (word.startsWith(`${PACKAGE}@`)) {
      const version = word.slice(PACKAGE.length + 1);
      return RELEASE.test(version) ? { kind: "pinned", version } : { kind: "unpinned", spec: word };
    }
  }
  const runs = command === null ? JSON.stringify(entry ?? null) : [command, ...args].join(" ");
  return { kind: "other", runs: printable(runs) };
}

/** True when the entry runs exactly `npx -y --prefer-offline @4da/mcp-server@<version>`. */
function isExactEntry(entry: unknown, version: string): boolean {
  if (!isPlainObject(entry) || entry.command !== "npx" || !Array.isArray(entry.args)) return false;
  const want = [...NPX_OPTIONS, `${PACKAGE}@${version}`];
  return entry.args.length === want.length && entry.args.every((a, i) => a === want[i]);
}

function serverFrom(scope: ClaudeScope, file: string, entry: unknown, version: string): ClaudeCodeServer {
  const env = isPlainObject(entry) && isPlainObject(entry.env) ? Object.keys(entry.env).map((k) => printable(k, 80)) : [];
  return { scope, file, pin: entryPin(entry), envNames: env, exact: isExactEntry(entry, version) };
}

/** The `projects` key Claude Code uses for `cwd`: its absolute path, with `/` on Windows. */
function projectEntry(projects: Record<string, unknown>, cwd: string, platform: NodeJS.Platform): unknown {
  const key = platform === "win32" ? cwd.replace(/\\/g, "/") : cwd;
  if (key in projects) return projects[key];
  if (platform !== "win32") return undefined;
  // Windows paths are not case-sensitive, and the drive letter's case varies between shells.
  const lower = key.toLowerCase();
  const match = Object.keys(projects).find((k) => k.toLowerCase() === lower);
  return match === undefined ? undefined : projects[match];
}

/**
 * Read (never write) every place Claude Code can hold a `4da` server, and the `4da` plugin.
 * `claudeJson` is `~/.claude.json` (or `$CLAUDE_CONFIG_DIR/.claude.json`).
 */
export function readClaudeCodeState(ctx: ClaudeCodeContext, claudeJson: string, version: string): ClaudeCodeState {
  const p = pathFor(ctx.platform);
  const state: ClaudeCodeState = { servers: [], plugins: [], unreadable: [] };

  const main = readJson(claudeJson);
  if (!main.ok) state.unreadable.push({ file: claudeJson, reason: main.reason });
  else if (isPlainObject(main.value)) {
    const user = isPlainObject(main.value.mcpServers) ? main.value.mcpServers["4da"] : undefined;
    if (user !== undefined) state.servers.push(serverFrom("user", claudeJson, user, version));
    if (ctx.cwd && isPlainObject(main.value.projects)) {
      const project = projectEntry(main.value.projects, ctx.cwd, ctx.platform);
      const local = isPlainObject(project) && isPlainObject(project.mcpServers) ? project.mcpServers["4da"] : undefined;
      if (local !== undefined) state.servers.push(serverFrom("local", claudeJson, local, version));
    }
  }

  if (ctx.cwd) {
    const mcpJson = p.join(ctx.cwd, ".mcp.json");
    const project = readJson(mcpJson);
    if (!project.ok) state.unreadable.push({ file: mcpJson, reason: project.reason });
    else if (isPlainObject(project.value) && isPlainObject(project.value.mcpServers) && project.value.mcpServers["4da"] !== undefined) {
      state.servers.push(serverFrom("project", mcpJson, project.value.mcpServers["4da"], version));
    }
  }

  const configDir = claudeConfigDir(ctx);
  const installedFile = p.join(configDir, "plugins", "installed_plugins.json");
  const installed = readJson(installedFile);
  if (!installed.ok) {
    state.unreadable.push({ file: installedFile, reason: installed.reason });
    return state;
  }
  const plugins = isPlainObject(installed.value) && isPlainObject(installed.value.plugins) ? installed.value.plugins : {};
  const settings = readJson(p.join(configDir, "settings.json"));
  const enabled = settings.ok && isPlainObject(settings.value) && isPlainObject(settings.value.enabledPlugins) ? settings.value.enabledPlugins : {};
  for (const [id, value] of Object.entries(plugins)) {
    const at = id.lastIndexOf("@");
    if ((at < 0 ? id : id.slice(0, at)) !== "4da") continue;
    const marketplace = at < 0 ? "" : id.slice(at + 1);
    // Version 2 keeps a list of installs per plugin; version 1 kept one record.
    for (const record of Array.isArray(value) ? value : [value]) {
      const install: ClaudePluginInstall = {
        id: printable(id, 120),
        marketplace: printable(marketplace, 80),
        scope: isPlainObject(record) && typeof record.scope === "string" ? printable(record.scope, 20) : "user",
        pin: null,
        unreadable: null,
        disabled: enabled[id] === false,
      };
      const installPath = isPlainObject(record) && typeof record.installPath === "string" ? record.installPath : null;
      if (installPath === null) install.unreadable = `${installedFile} names no installPath for it`;
      else {
        const manifestFile = p.join(installPath, ".claude-plugin", "plugin.json");
        const manifest = readJson(manifestFile);
        const servers = manifest.ok && isPlainObject(manifest.value) && isPlainObject(manifest.value.mcpServers) ? manifest.value.mcpServers : null;
        if (!manifest.ok) install.unreadable = `${manifestFile}: ${manifest.reason}`;
        else if (!servers || servers["4da"] === undefined) install.unreadable = `${manifestFile} has no 4da server`;
        else install.pin = entryPin(servers["4da"]);
      }
      state.plugins.push(install);
    }
  }
  return state;
}

/** -1, 0 or 1 for two releases by their major.minor.patch; null when either is not one, or they differ only after it. */
function compareReleases(a: string, b: string): number | null {
  const parse = (v: string) => /^(\d+)\.(\d+)\.(\d+)$/.exec(v)?.slice(1).map(Number) ?? null;
  const [x, y] = [parse(a), parse(b)];
  if (!x || !y) return null;
  for (let i = 0; i < 3; i++) if (x[i] !== y[i]) return x[i] < y[i] ? -1 : 1;
  return 0;
}

function describePin(pin: EntryPin): string {
  if (pin.kind === "pinned") return `${PACKAGE}@${pin.version}`;
  if (pin.kind === "unpinned") {
    return pin.spec === PACKAGE
      ? `${PACKAGE} with no version pinned: npx starts whatever it has cached, or the newest release`
      : `${printable(pin.spec, 120)}, which pins no release: npx starts whatever it has cached, or the newest release it names`;
  }
  return `${pin.runs}, not a release of ${PACKAGE} from npm (a local build or a wrapper)`;
}

/** `claude mcp add --scope <scope> 4da -- npx -y --prefer-offline @4da/mcp-server@<version>`. */
export function claudeMcpAdd(version: string, scope: ClaudeScope = "user"): string {
  return `claude mcp add --scope ${scope} 4da -- npx ${NPX_OPTIONS.join(" ")} ${PACKAGE}@${version}`;
}

/** The plugin's update, for an install in `scope`. */
function pluginUpdateCommands(install: ClaudePluginInstall): string[] {
  const scope = install.scope && install.scope !== "user" ? ` --scope ${install.scope}` : "";
  return [
    ...(install.marketplace ? [`claude plugin marketplace update ${install.marketplace}`] : []),
    `claude plugin update ${install.id}${scope}`,
  ];
}

/**
 * The lines setup prints for Claude Code. Never "Already configured" for an entry that runs another
 * release; never the `claude mcp add` command when a plugin already provides the server.
 */
export function claudeCodeReport(state: ClaudeCodeState, version: string): string[] {
  const out: string[] = [];
  const where = (s: ClaudeCodeServer) => `${s.scope} scope, ${s.file}`;

  for (const server of state.servers) {
    const pin = server.pin;
    const same = pin.kind === "pinned" && pin.version === version;
    if (same && server.exact) {
      out.push(`  Already configured (${where(server)}): it runs ${PACKAGE}@${version}, this release.`);
      continue;
    }
    const order = pin.kind === "pinned" ? compareReleases(pin.version, version) : null;
    out.push(`  Claude Code has a 4da server (${where(server)}): it runs ${describePin(pin)}.`);
    if (same) {
      out.push(`  That is this release, started by another command than the one setup writes (npx ${NPX_OPTIONS.join(" ")} ${PACKAGE}@${version}).`);
    } else if (order === 1) {
      out.push(`  That is a newer release than this one (${version}): nothing to do.`);
      continue;
    }
    out.push(`  Setup does not edit Claude Code's files. To run ${PACKAGE}@${version} there instead:`);
    out.push(`    claude mcp remove 4da -s ${server.scope}`);
    out.push(`    ${claudeMcpAdd(version, server.scope)}`);
    if (server.envNames.length > 0) {
      out.push(
        `  These commands do not carry its env (${server.envNames.join(", ")}): add -e NAME=value after "4da" in the add command for each, with the values from ${server.file}.`,
      );
    }
  }

  for (const install of state.plugins) {
    const scope = install.scope === "user" ? "user scope" : `${install.scope} scope`;
    const disabled = install.disabled ? " It is disabled in your user settings." : "";
    if (install.pin === null) {
      out.push(`  The Claude Code plugin ${install.id} (${scope}) provides a 4da server; its pinned release could not be read (${printable(install.unreadable ?? "unknown", 300)}).${disabled}`);
    } else {
      out.push(`  The Claude Code plugin ${install.id} (${scope}) provides the server: it runs ${describePin(install.pin)}.${disabled}`);
      const pin = install.pin;
      if (pin.kind === "pinned" && pin.version === version) {
        out.push("  That is this release: nothing to do.");
        continue;
      }
      if (pin.kind === "pinned" && compareReleases(pin.version, version) === 1) {
        out.push(`  That is a newer release than this one (${version}): nothing to do.`);
        continue;
      }
    }
    out.push("  The plugin moves its pin when the plugin is updated (setup does not edit it). Run, then restart Claude Code:");
    for (const command of pluginUpdateCommands(install)) out.push(`    ${command}`);
    out.push(`  Do not add a second 4da server with claude mcp add: the plugin's is the one to update.`);
  }

  if (state.servers.length > 0 && state.plugins.length > 0) {
    out.push("  Claude Code has a 4da server from the plugin and one in its own configuration; keep one of them.");
  }

  for (const { file, reason } of state.unreadable) {
    out.push(`  Could not read ${file} (${printable(reason, 200)}), so what it holds for 4da is not known.`);
  }

  if (state.servers.length === 0 && state.plugins.length === 0) {
    if (state.unreadable.length > 0) {
      out.push("  Check with `claude mcp list` and `claude plugin list`; if neither shows a 4da server, add it with:");
    } else {
      out.push("  Claude Code keeps its MCP servers in ~/.claude.json, which it rewrites");
      out.push("  itself; setup does not edit it. Add the server with:");
    }
    out.push(`    ${claudeMcpAdd(version)}`);
  }
  return out;
}
