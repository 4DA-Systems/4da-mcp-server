// SPDX-License-Identifier: Apache-2.0
/**
 * What a planned command can and cannot do on this project, read from the project's own files,
 * so that a row never offers a command that has no effect or cannot succeed:
 * - a uv workspace member's own uv.lock is not the lockfile uv uses: `uv lock` in that directory
 *   reads and writes the workspace root's uv.lock (mcp-python-sdk v1.1.0: the three examples'
 *   `uv lock --upgrade-package anyio==4.14.2` changed nothing, uv 0.9, 2026-11-23). A command is
 *   named once, at the root; a copy only such a file lists is a hand step (delete the file);
 * - a package the workspace itself defines (a uv, npm/pnpm/Yarn or Cargo workspace member's own
 *   name) is taken from the workspace, never upgraded from the registry (`uv lock
 *   --upgrade-package mcp==1.30.0` in that workspace: "your workspace requires mcp", exit 1);
 * - a uv `--upgrade-package name==version` whose release requires a Python the project's lowest
 *   supported one is below cannot lock (fastapi-backend: fastapi 0.162.6 requires Python ">=3.11",
 *   the project supports ">=3.10, <4.0": "requirements are unsatisfiable", exit 1). The row says
 *   to raise the project's requires-python first, as a hand step.
 * Also the operator of an npm declaration, to write a holder's upgrade the way the project does.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import type { FixPathSources } from "../live/fix-paths.js";
import { npmDeclared } from "../live/fix-paths.js";
import { wildcardMatch } from "../live/glob-match.js";
import { expandWorkspaces, memberNamesOf, pnpmYamlList } from "../live/js-manifests.js";
import { normalizePythonName } from "../live/lockfile-parsers-pygo.js";
import { tomlHeader, tomlKeyValue, tomlLines, tomlStrings } from "../live/private-hosts.js";
import { lowestPython, pythonSpecAdmits } from "../live/pygo-parents.js";

/** "^" or "~" when `dir`/package.json declares `name` with that operator on a plain version, "" for an exact pin; null otherwise. */
export function declaredNpmOperator(root: string, dir: string, name: string): string | null {
  const json = readText(path.join(path.resolve(root, dir), "package.json"));
  if (json === null) return null;
  const spec = npmDeclared(json, name);
  if (spec === null) return null;
  const m = /^([\^~]?)\d+(?:\.\d+){0,2}$/.exec(spec.trim());
  return m ? m[1] : null;
}

function readText(file: string): string | null {
  try {
    return fs.readFileSync(file, "utf-8");
  } catch {
    return null;
  }
}

/** The values of `key` in TOML table `table` of `content` (strings of an array, or one string). */
function tomlTableStrings(content: string, table: string, key: string): string[] {
  let current = "";
  const out: string[] = [];
  for (const line of tomlLines(content)) {
    const header = tomlHeader(line);
    if (header) {
      current = header.name;
      continue;
    }
    const kv = tomlKeyValue(line);
    if (kv && current === table && kv.key === key) out.push(...tomlStrings(kv.value));
  }
  return out;
}

/** Directories under `root` that `patterns` name, relative with "/", each holding `file` (segment globs: `*`, `?`, `**` bounded). */
function memberDirs(root: string, patterns: string[], exclude: string[], file: string): string[] {
  const found = new Set<string>();
  let listed = 0;
  const children = (rel: string): string[] => {
    if (++listed > 2_000) return [];
    try {
      return fs
        .readdirSync(path.join(root, rel), { withFileTypes: true })
        .filter((d) => d.isDirectory() && !d.name.startsWith(".") && d.name !== "node_modules" && d.name !== "target")
        .map((d) => d.name);
    } catch {
      return [];
    }
  };
  const walk = (rel: string, segments: string[], at: number, depth: number): void => {
    if (at === segments.length) {
      if (rel !== "" && fs.existsSync(path.join(root, rel, file))) found.add(rel);
      return;
    }
    const segment = segments[at];
    const join = (name: string) => (rel ? `${rel}/${name}` : name);
    if (segment === "**") {
      walk(rel, segments, at + 1, depth);
      if (depth < 4) for (const name of children(rel)) walk(join(name), segments, at, depth + 1);
    } else if (/[*?]/.test(segment)) {
      for (const name of children(rel)) if (wildcardMatch(segment, name)) walk(join(name), segments, at + 1, depth);
    } else if (segment !== ".." && fs.existsSync(path.join(root, join(segment)))) {
      walk(join(segment), segments, at + 1, depth);
    }
  };
  for (const p of patterns) {
    const segments = p.replace(/\\/g, "/").replace(/^\.\//, "").replace(/\/+$/, "").split("/").filter((s) => s !== "" && s !== ".");
    if (segments.length > 0) walk("", segments, 0, 0);
  }
  const excluded = (rel: string) => exclude.some((e) => {
    const ex = e.replace(/\\/g, "/").replace(/^\.\//, "").replace(/\/+$/, "").split("/");
    const have = rel.split("/");
    return ex.length <= have.length && ex.every((seg, i) => wildcardMatch(seg, have[i]));
  });
  return [...found].filter((d) => !excluded(d)).sort();
}

/** A uv workspace: its root, its members (relative to the project root), and the project names they define. */
export interface UvWorkspace {
  /** Relative to the project root, "." for the root. */
  root: string;
  members: string[];
  names: Set<string>;
}

const rel = (projectRoot: string, abs: string) => path.relative(projectRoot, abs).replace(/\\/g, "/") || ".";

/** The uv workspaces at the project root and in directories up to two levels below it. */
export function uvWorkspaces(projectRoot: string): UvWorkspace[] {
  const candidates = ["."];
  const list = (dir: string) => {
    try {
      return fs.readdirSync(path.join(projectRoot, dir), { withFileTypes: true }).filter((d) => d.isDirectory() && !d.name.startsWith(".") && d.name !== "node_modules").map((d) => (dir === "." ? d.name : `${dir}/${d.name}`));
    } catch {
      return [];
    }
  };
  for (const a of list(".")) {
    candidates.push(a);
    for (const b of list(a)) candidates.push(b);
  }
  const out: UvWorkspace[] = [];
  for (const dir of candidates) {
    const abs = path.join(projectRoot, dir);
    const manifest = readText(path.join(abs, "pyproject.toml"));
    if (manifest === null || !/^\[tool\.uv\.workspace\]\s*$/m.test(manifest)) continue;
    const members = memberDirs(abs, tomlTableStrings(manifest, "tool.uv.workspace", "members"), tomlTableStrings(manifest, "tool.uv.workspace", "exclude"), "pyproject.toml");
    const names = new Set<string>();
    for (const d of [".", ...members]) {
      const own = readText(path.join(abs, d, "pyproject.toml"));
      const name = own === null ? null : (tomlTableStrings(own, "project", "name")[0] ?? null);
      if (name) names.add(normalizePythonName(name));
    }
    out.push({ root: dir, members: members.map((m) => rel(projectRoot, path.join(abs, m))), names });
  }
  return out;
}

/** The package names the project's npm/pnpm/Yarn and Cargo workspaces define (members' own names), by ecosystem. */
export function workspaceOwnNames(projectRoot: string, uv: UvWorkspace[]): Map<string, Set<string>> {
  const out = new Map<string, Set<string>>();
  const add = (eco: string, name: string) => out.set(eco, (out.get(eco) ?? new Set()).add(name));
  for (const w of uv) for (const n of w.names) add("PyPI", n);
  const pkg = readText(path.join(projectRoot, "package.json"));
  let patterns: string[] = [];
  try {
    const w = pkg === null ? undefined : (JSON.parse(pkg) as { workspaces?: unknown }).workspaces;
    const list = Array.isArray(w) ? w : (w as { packages?: unknown } | undefined)?.packages;
    if (Array.isArray(list)) patterns = list.filter((p): p is string => typeof p === "string");
  } catch {
    patterns = [];
  }
  const pnpmYaml = readText(path.join(projectRoot, "pnpm-workspace.yaml"));
  if (pnpmYaml !== null) patterns = [...patterns, ...pnpmYamlList(pnpmYaml, "packages")];
  if (patterns.length > 0) for (const n of memberNamesOf(projectRoot, expandWorkspaces(projectRoot, patterns).dirs).names) add("npm", n);
  const cargo = readText(path.join(projectRoot, "Cargo.toml"));
  if (cargo !== null && /^\[workspace\]\s*$/m.test(cargo)) {
    const members = memberDirs(projectRoot, tomlTableStrings(cargo, "workspace", "members"), tomlTableStrings(cargo, "workspace", "exclude"), "Cargo.toml");
    for (const d of [".", ...members]) {
      const own = readText(path.join(projectRoot, d, "Cargo.toml"));
      const name = own === null ? null : (tomlTableStrings(own, "package", "name")[0] ?? null);
      if (name) add("crates.io", name);
    }
  }
  return out;
}

/** The row fields this module reads and rewrites: a structural subset of upgrade_planner's row. */
export interface RunnableRow {
  package: string;
  ecosystem: string;
  currentVersion: string | null;
  targetVersion: string | null;
  scope: string;
  reasons: string[];
  upgradeCommands?: Array<{ dir: string; command: string; refresh?: true }>;
  upgradeInstructions?: Array<{ dir: string; instruction: string }>;
  refreshCommands?: Array<{ dir: string; command: string }>;
  parentUpgrades?: Array<{
    levers: Array<{ name: string; to: string | null; commands?: Array<{ dir: string; command: string; refresh?: true }>; instructions?: Array<{ dir: string; instruction: string }> }>;
    refreshCommands?: Array<{ dir: string; command: string }>;
  }>;
}

/** The PyPI rows' commands named in a uv workspace member's directory: dropped (the root's command moves the one lockfile uv uses); each stale lockfile named. */
export function withUvWorkspaceLocks(rows: RunnableRow[], projectRoot: string, uv: UvWorkspace[]): string[] {
  const memberOf = new Map<string, UvWorkspace>();
  for (const w of uv) if (fs.existsSync(path.join(projectRoot, w.root, "uv.lock"))) for (const m of w.members) if (fs.existsSync(path.join(projectRoot, m, "uv.lock"))) memberOf.set(m, w);
  if (memberOf.size === 0) return [];
  const stale = new Set<string>();
  const lockOf = (dir: string) => `${dir}/uv.lock`;
  for (const r of rows) {
    if (r.ecosystem !== "PyPI") continue;
    const dirsOf = (list: Array<{ dir: string }> | undefined) => (list ?? []).map((c) => c.dir);
    const dirs = [...dirsOf(r.upgradeCommands), ...dirsOf(r.refreshCommands), ...(r.parentUpgrades ?? []).flatMap((u) => [...dirsOf(u.refreshCommands), ...u.levers.flatMap((l) => dirsOf(l.commands))])];
    const staleDirs = [...new Set(dirs.filter((d) => memberOf.has(d)))];
    if (staleDirs.length === 0) continue;
    const keep = <T extends { dir: string }>(list: T[] | undefined): T[] | undefined => {
      if (!list) return list;
      const kept = list.filter((c) => !memberOf.has(c.dir));
      return kept.length > 0 ? kept : undefined;
    };
    const removed = (list: Array<{ dir: string; command: string }> | undefined) => (list ?? []).filter((c) => memberOf.has(c.dir));
    const gone = [...removed(r.upgradeCommands), ...removed(r.refreshCommands), ...(r.parentUpgrades ?? []).flatMap((u) => [...removed(u.refreshCommands), ...u.levers.flatMap((l) => removed(l.commands))])];
    r.upgradeCommands = keep(r.upgradeCommands);
    if (!r.upgradeCommands) delete r.upgradeCommands;
    r.refreshCommands = keep(r.refreshCommands);
    if (!r.refreshCommands) delete r.refreshCommands;
    for (const u of r.parentUpgrades ?? []) {
      u.refreshCommands = keep(u.refreshCommands);
      if (!u.refreshCommands) delete u.refreshCommands;
      for (const l of u.levers) {
        l.commands = keep(l.commands);
        if (!l.commands) delete l.commands;
      }
    }
    // The words say each command once too: "`x` in a; `x` in b" loses the member's clause.
    r.reasons = r.reasons.map((t) => gone.reduce((acc, c) => acc.split(`; \`${c.command}\` in ${c.dir}`).join("").split(`\`${c.command}\` in ${c.dir}; `).join(""), t));
    const live = dirs.some((d) => !memberOf.has(d));
    for (const d of staleDirs) stale.add(lockOf(d));
    const w = memberOf.get(staleDirs[0])!;
    const files = staleDirs.map(lockOf);
    const words = `${files.join(" and ")} ${files.length === 1 ? "is" : "are"} not the lockfile uv uses: ${files.length === 1 ? "that directory is a member" : "those directories are members"} of the uv workspace at ${w.root === "." ? "the project root" : w.root}, so \`uv lock\` there reads and writes ${lockOf(w.root === "." ? "." : w.root).replace(/^\.\//, "")}`;
    if (live) {
      r.reasons.push(`${words}, which the command above updates; the copy of ${r.package} ${r.currentVersion} ${files.length === 1 ? "that file lists stays in it" : "those files list stays in them"} until ${files.length === 1 ? "it is" : "they are"} deleted by hand (uv never reads ${files.length === 1 ? "it" : "them"})`);
    } else {
      const instruction = `delete ${files.join(" and ")} (left from before ${files.length === 1 ? "that directory" : "those directories"} joined the workspace): ${words}, which does not hold ${r.package} ${r.currentVersion}, so no uv command moves the copy ${files.length === 1 ? "that file lists" : "those files list"}`;
      r.upgradeInstructions = [...(r.upgradeInstructions ?? []), ...staleDirs.map((dir) => ({ dir, instruction }))];
      r.reasons.push(instruction);
    }
  }
  return [...stale].sort();
}

/** A row about a package the workspace itself defines: no command (it is taken from the workspace, not the registry), and the row says so. */
export function withoutOwnPackageUpgrades(rows: RunnableRow[], own: Map<string, Set<string>>): void {
  for (const r of rows) {
    const names = own.get(r.ecosystem);
    if (!names || !names.has(r.ecosystem === "PyPI" ? normalizePythonName(r.package) : r.package)) continue;
    const had = Boolean(r.upgradeCommands?.length || r.refreshCommands?.length || r.parentUpgrades?.length);
    delete r.upgradeCommands;
    delete r.refreshCommands;
    delete r.parentUpgrades;
    const why = `${r.package} is a package this workspace defines itself (a workspace member's own name): the workspace's tool takes it from the member, not from the registry, so no upgrade of it is planned${had ? " (a registry upgrade of it cannot resolve in this workspace)" : ""}; the copy ${r.currentVersion} is one a lockfile lists from the registry`;
    if (!r.reasons.includes(why)) r.reasons.push(why);
  }
}

const UV_PIN = /^uv lock --upgrade-package (\S+)==(\S+)$/;

/** The project's declared Python support beside `dir`: uv.lock's `requires-python`, else pyproject.toml's `[project] requires-python`. */
function projectPython(dir: string): { spec: string; from: string } | null {
  const lock = readText(path.join(dir, "uv.lock"));
  const fromLock = lock === null ? null : (/^requires-python\s*=\s*"([^"]*)"/m.exec(lock.split(/^\[\[package\]\]/m)[0])?.[1] ?? null);
  if (fromLock) return { spec: fromLock, from: "uv.lock" };
  const manifest = readText(path.join(dir, "pyproject.toml"));
  const declared = manifest === null ? null : (tomlTableStrings(manifest, "project", "requires-python")[0] ?? null);
  return declared ? { spec: declared, from: "pyproject.toml" } : null;
}

/**
 * Every `uv lock --upgrade-package name==version` a PyPI row names (its own upgrade, a lever's)
 * whose release requires a Python above the project's lowest: moved to an instruction that raises
 * requires-python first. Read from the release facts the planner already looked up (cached); a
 * release whose Python requirement is not known keeps its command.
 */
export async function withPythonSupport(rows: RunnableRow[], projectRoot: string, sources: Pick<FixPathSources, "releaseFacts"> | null): Promise<void> {
  if (!sources) return;
  const pending: Array<{ list: Array<{ dir: string; command: string }>; owner: { instructions?: Array<{ dir: string; instruction: string }> }; r: RunnableRow; field: "upgrade" | "lever" }> = [];
  for (const r of rows) {
    if (r.ecosystem !== "PyPI") continue;
    if (r.upgradeCommands?.some((c) => UV_PIN.test(c.command))) pending.push({ list: r.upgradeCommands, owner: {}, r, field: "upgrade" });
    for (const u of r.parentUpgrades ?? []) for (const l of u.levers) if (l.commands?.some((c) => UV_PIN.test(c.command))) pending.push({ list: l.commands, owner: l, r, field: "lever" });
  }
  for (const p of pending) {
    const moved: Array<{ dir: string; command: string; instruction: string }> = [];
    for (const c of p.list) {
      const m = UV_PIN.exec(c.command);
      if (!m) continue;
      const python = projectPython(path.resolve(projectRoot, c.dir));
      const lowest = lowestPython(python?.spec ?? null);
      if (!python || !lowest) continue;
      const facts = await sources.releaseFacts("PyPI", m[1]).catch(() => null);
      const needs = facts?.requiresPython?.[m[2]];
      if (!needs || pythonSpecAdmits(needs, lowest) !== false) continue;
      moved.push({ dir: c.dir, command: c.command, instruction: `${m[1]} ${m[2]} requires Python "${needs}", and this project supports Python "${python.spec}" (${python.from}), down to ${lowest}: \`${c.command}\` alone cannot lock it. Raise requires-python in pyproject.toml to a range ${m[1]} ${m[2]} supports, then run \`${c.command}\`` });
    }
    if (moved.length === 0) continue;
    const left = p.list.filter((c) => !moved.some((x) => x.dir === c.dir && x.command === c.command));
    const instructions = moved.map((x) => ({ dir: x.dir, instruction: x.instruction }));
    if (p.field === "upgrade") {
      if (left.length > 0) p.r.upgradeCommands = left as RunnableRow["upgradeCommands"];
      else delete p.r.upgradeCommands;
      p.r.upgradeInstructions = [...(p.r.upgradeInstructions ?? []), ...instructions];
      // A row that said "fixable now with a lockfile refresh: `cmd`" no longer is, for that command.
      p.r.reasons = p.r.reasons.filter((t) => !(t.startsWith("Fixable now with a lockfile refresh") && moved.some((x) => t.includes(`\`${x.command}\``))));
    } else {
      const lever = p.owner as { commands?: unknown[]; instructions?: Array<{ dir: string; instruction: string }> };
      if (left.length > 0) lever.commands = left;
      else delete lever.commands;
      lever.instructions = [...(lever.instructions ?? []), ...instructions];
    }
    for (const x of moved) if (!p.r.reasons.includes(x.instruction)) p.r.reasons.push(x.instruction);
  }
}

/** run_order_note's sentence for uv workspace members' own lockfiles. */
export function staleLocksNote(files: string[]): string {
  const shown = files.slice(0, 6);
  const more = files.length > shown.length ? ` and ${files.length - shown.length} more` : "";
  return `${shown.join(", ")}${more} ${files.length === 1 ? "is" : "are"} not read by uv (a uv workspace member's own lockfile: uv reads and writes the workspace root's): no step moves the copies ${files.length === 1 ? "it lists" : "they list"}, and deleting ${files.length === 1 ? "it" : "them"} is a hand step.`;
}
