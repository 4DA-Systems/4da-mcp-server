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
import { pushAll } from "../array-utils.js";
import type { FixPathSources } from "../live/fix-paths.js";
import { npmDeclared } from "../live/fix-paths.js";
import { wildcardMatch } from "../live/glob-match.js";
import { expandWorkspaces, memberNamesOf, pnpmYamlList } from "../live/js-manifests.js";
import { normalizePythonName } from "../live/lockfile-parsers-pygo.js";
import { tomlHeader, tomlKeyValue, tomlLines, tomlStrings } from "../live/private-hosts.js";
import { yarnBlockVersion, yarnHeaderSpecs } from "../live/js-lockfile-readers.js";
import { lowestPython, parsePep508, pythonSpecAdmits } from "../live/pygo-parents.js";
import { isShellSafeDir, unsafeDirWords } from "../live/shell-safe.js";
import { compareVersions } from "../live/version-compare.js";
import { overrideCommandsOf, recordOverrideCommands } from "./upgrade-plan-overrides.js";

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
    if (kv && current === table && kv.key === key) pushAll(out, tomlStrings(kv.value));
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

/** The packages a uv.lock records as the project's own (editable or virtual sources), with their versions. */
function uvOwnPackages(dir: string): Map<string, string | null> {
  const out = new Map<string, string | null>();
  const lock = readText(path.join(dir, "uv.lock"));
  if (lock === null) return out;
  for (const block of lock.split(/^\[\[package\]\]\s*$/m).slice(1)) {
    const body = block.split(/^\[(?!\[package\]\])/m)[0];
    const name = /^name\s*=\s*"([^"]+)"/m.exec(body)?.[1];
    const source = /^source\s*=\s*\{([^}]*)\}/m.exec(body)?.[1] ?? "";
    if (!name || !/\b(?:editable|virtual)\s*=/.test(source)) continue;
    out.set(normalizePythonName(name), /^version\s*=\s*"([^"]+)"/m.exec(body)?.[1] ?? null);
  }
  return out;
}

/**
 * A `uv lock --upgrade-package name==version` whose release requires the project itself at a
 * version the project is not (crewAI 0.86.0: crewai-tools 1.15.1 requires crewai==1.15.1, and the
 * project is crewai 0.86.0): uv cannot lock it ("requirements are unsatisfiable"). Moved to words.
 * Read from the release's own requirements (cached); a release whose requirements are not known
 * keeps its command.
 */
export async function withoutSelfRequiringTargets(rows: RunnableRow[], projectRoot: string, sources: Pick<FixPathSources, "pypiRequiresDist"> | null): Promise<void> {
  if (!sources) return;
  for (const r of rows) {
    if (r.ecosystem !== "PyPI") continue;
    const lists: Array<{ list: Array<{ dir: string; command: string }>; set: (left: Array<{ dir: string; command: string }>, words: Array<{ dir: string; instruction: string }>) => void }> = [];
    if (r.upgradeCommands) {
      lists.push({
        list: r.upgradeCommands,
        set: (left, words) => {
          if (left.length > 0) r.upgradeCommands = left as RunnableRow["upgradeCommands"];
          else delete r.upgradeCommands;
          r.upgradeInstructions = [...(r.upgradeInstructions ?? []), ...words];
        },
      });
    }
    for (const u of r.parentUpgrades ?? []) {
      for (const l of u.levers) {
        if (!l.commands) continue;
        lists.push({
          list: l.commands,
          set: (left, words) => {
            if (left.length > 0) l.commands = left as typeof l.commands;
            else delete l.commands;
            l.instructions = [...(l.instructions ?? []), ...words];
          },
        });
      }
    }
    for (const { list, set } of lists) {
      const words: Array<{ dir: string; command: string; instruction: string }> = [];
      for (const c of list) {
        const m = UV_PIN.exec(c.command);
        if (!m) continue;
        const own = uvOwnPackages(path.resolve(projectRoot, c.dir));
        if (own.size === 0) continue;
        const requires = await sources.pypiRequiresDist(m[1], m[2]).catch(() => null);
        if (!requires) continue;
        for (const req of requires) {
          const parsed = parsePep508(req);
          if (!parsed || parsed.extra || !own.has(parsed.name)) continue;
          const version = own.get(parsed.name) ?? null;
          if (parsed.spec !== "" && version !== null && pythonSpecAdmits(parsed.spec, version) !== false) continue;
          const spec = /^[A-Za-z0-9.*!=<>~,+_-]{0,64}$/.test(parsed.spec) ? ` "${parsed.spec}"` : "";
          words.push({
            dir: c.dir,
            command: c.command,
            instruction: `no command: ${m[1]} ${m[2]} requires ${parsed.name}${spec}, and ${parsed.name} is this project itself${version ? ` (${version} in uv.lock)` : ""}: uv cannot lock a release that requires another version of the project, so \`${c.command}\` fails ("requirements are unsatisfiable"). It becomes possible once the project's own version is one ${m[1]} ${m[2]} admits; until then this advisory stays`,
          });
          break;
        }
      }
      if (words.length === 0) continue;
      set(
        list.filter((c) => !words.some((w) => w.dir === c.dir && w.command === c.command)),
        words.map((w) => ({ dir: w.dir, instruction: w.instruction })),
      );
      r.reasons = r.reasons.filter((t) => !(t.startsWith("Fixable now with a lockfile refresh") && words.some((w) => t.includes(`\`${w.command}\``))));
      for (const w of words) if (!r.reasons.includes(`${SELF_REQUIRING_START}${w.instruction}`)) r.reasons.push(`${SELF_REQUIRING_START}${w.instruction}`);
    }
  }
}

/** How the reason withoutSelfRequiringTargets writes starts. */
export const SELF_REQUIRING_START = "uv: ";

/** Whether withoutSelfRequiringTargets took a step off the row: not counted as fixed. */
export function hasSelfRequiringTarget(row: { reasons: string[] }): boolean {
  return row.reasons.some((r) => r.startsWith(`${SELF_REQUIRING_START}no command: `));
}

/** run_order_note's sentence for uv workspace members' own lockfiles. */
export function staleLocksNote(files: string[]): string {
  const shown = files.slice(0, 6);
  const more = files.length > shown.length ? ` and ${files.length - shown.length} more` : "";
  return `${shown.join(", ")}${more} ${files.length === 1 ? "is" : "are"} not read by uv (a uv workspace member's own lockfile: uv reads and writes the workspace root's): no step moves the copies ${files.length === 1 ? "it lists" : "they list"}, and deleting ${files.length === 1 ? "it" : "them"} is a hand step.`;
}

/** A version's release line: its major, or `0.minor` below 1.0. */
function lineOf(v: string): string | null {
  const m = /^v?(\d+)\.(\d+)/.exec(v);
  return m ? (m[1] === "0" ? `0.${m[2]}` : m[1]) : null;
}

/** Every version a Yarn classic yarn.lock holds of `name` (alias entries left out); null for a Berry lockfile or one that cannot be read. */
function yarnClassicVersions(lockfile: string, name: string): string[] | null {
  const content = readText(lockfile);
  if (content === null || /^__metadata:/m.test(content)) return null;
  const out = new Set<string>();
  for (const block of content.split(/\r?\n(?=\S)/)) {
    const first = block.split(/\r?\n/, 1)[0] ?? "";
    if (first.startsWith("#") || !first.trimEnd().endsWith(":")) continue;
    const specs = yarnHeaderSpecs(first);
    if (specs.some((s) => s.startsWith(`${name}@npm:`) || /@npm:/.test(s.slice(name.length + 1)))) return null;
    if (!specs.some((s) => s.startsWith(`${name}@`))) continue;
    const v = yarnBlockVersion(block);
    if (!v) return null;
    out.add(v);
  }
  return [...out];
}

const YARN_DELETE = /^delete every yarn\.lock entry that resolves to /;

/**
 * Yarn classic has no command that refreshes one package's entries: `yarn upgrade <transitive>`
 * changed nothing on zustand's yarn.lock ("Saved 0 new dependencies", yarn 1.22.22, 2026-11-23), and
 * for a declared one it re-resolves only the declared range. The in-range refresh the row gives is a
 * hand edit (delete the entries, then `yarn install`). Where the lockfile holds the package on one
 * release line only, every copy at or below the target, and every parent admits the target (the
 * row's own finding), an exact resolution moves every copy to the target and nothing else:
 * `npm pkg set "resolutions.<name>=<target>"`, then `yarn install`. It stays in package.json, which
 * the row says. Anything else (another line, a newer copy, an alias) keeps the hand step.
 */
export function withYarnClassicResolutions(rows: Array<RunnableRow & { action: string }>, projectRoot: string): void {
  for (const r of rows) {
    if (r.ecosystem !== "npm" || !r.currentVersion || !r.targetVersion) continue;
    if (r.action !== "lockfile_refresh" && r.action !== "upgrade_direct" && r.action !== "upgrade_parent") continue;
    const manual = [
      ...(r.refreshCommands ?? []).filter((c) => YARN_DELETE.test(c.command)).map((c) => c.dir),
      ...(r.upgradeInstructions ?? []).filter((i) => YARN_DELETE.test(i.instruction)).map((i) => i.dir),
      ...(r.parentUpgrades ?? []).flatMap((u) => (u.refreshCommands ?? []).filter((c) => YARN_DELETE.test(c.command)).map((c) => c.dir)),
    ];
    const dirs = [...new Set(manual)];
    if (dirs.length === 0) continue;
    const line = lineOf(r.targetVersion);
    const ok = dirs.every((d) => {
      const held = yarnClassicVersions(path.join(path.resolve(projectRoot, d), "yarn.lock"), r.package);
      return held !== null && held.length > 0 && line !== null && held.every((v) => lineOf(v) === line && compareVersions(v, r.targetVersion!, "npm") <= 0);
    });
    if (!ok) continue;
    recordOverrideCommands(r, dirs.map((dir) => ({ format: "yarn" as const, dir })), projectRoot, r.package, r.targetVersion, null);
    const cmds = overrideCommandsOf(r);
    if (cmds.length === 0) continue;
    const why = `Yarn classic has no command that refreshes one package's yarn.lock entries; every ${r.package} copy ${dirs.length === 1 && dirs[0] === "." ? "the lockfile" : `the lockfile in ${dirs.join(", ")}`} holds is on the ${line}.x line at or below ${r.targetVersion}, so an exact resolution moves them all there and nothing else: ${cmds.map((c) => `\`${c.command}\`${c.dir === "." ? "" : ` in ${c.dir}`}`).join(", then ")} (the resolution stays in package.json; remove it once every parent's own release holds ${r.targetVersion} or later)`;
    if (!r.reasons.includes(why)) r.reasons.push(why);
  }
}

// ---------------------------------------------------------------------------
// Directories whose names are not safe in a command (audit 2026-11-25 B-B1)
// ---------------------------------------------------------------------------

/** How the reason a row gets for a directory whose name is not safe in a command starts. */
export const UNSAFE_DIR_REASON_START = "NOT RUNNABLE HERE: ";
const UNSAFE_DIR_REASON = /^NOT RUNNABLE HERE: the directory /;

/** Whether the row has a step in a directory whose name is not safe in a command: never counted as fixed, never in run_order. */
/** How many steps (commands, instructions, reinstalls) withholdUnsafeDirs took off a row. */
const WITHHELD = new WeakMap<object, number>();
export function withheldStepsOf(row: object): number {
  return WITHHELD.get(row) ?? 0;
}

export function hasUnsafeDir(row: { reasons: string[] }): boolean {
  return row.reasons.some((r) => UNSAFE_DIR_REASON.test(r));
}

type DirField = { dir: string };

/**
 * Every command, instruction and reinstall directory of a row whose directory is not a plain path
 * (shell-safe.ts isShellSafeDir) is taken off the row: no command and no `dir` an agent could
 * paste is named there, only the reason, which names the directory escaped and says to handle it
 * by hand. Commands in the row's other directories stay. The directories found are returned, for
 * the answer's prose to be rewritten (escapeUnsafeDirs). `installDirs` is the reinstall row's
 * directories, rewritten in place.
 */
export function withholdUnsafeDirs<R extends RunnableRow & { installFix?: string }>(rows: R[], installDirs: Map<R, string[]>): Set<string> {
  const found = new Set<string>();
  for (const r of rows) {
    const bad = new Set<string>();
    let withheld = 0;
    const keep = <T extends DirField>(list: T[] | undefined): T[] | undefined => {
      if (!list) return list;
      for (const c of list) {
        if (isShellSafeDir(c.dir)) continue;
        bad.add(c.dir);
        withheld++;
      }
      return list.filter((c) => isShellSafeDir(c.dir));
    };
    const set = <K extends "upgradeCommands" | "upgradeInstructions" | "refreshCommands">(key: K) => {
      const kept = keep(r[key] as DirField[] | undefined);
      if (kept === undefined) return;
      if (kept.length > 0) (r as Record<K, unknown>)[key] = kept;
      else delete r[key];
    };
    set("upgradeCommands");
    set("upgradeInstructions");
    set("refreshCommands");
    for (const u of r.parentUpgrades ?? []) {
      const refresh = keep(u.refreshCommands);
      if (refresh !== undefined) {
        if (refresh.length > 0) u.refreshCommands = refresh;
        else delete u.refreshCommands;
      }
      for (const l of u.levers) {
        const cmds = keep(l.commands);
        if (cmds !== undefined) {
          if (cmds.length > 0) l.commands = cmds;
          else delete l.commands;
        }
        const words = keep(l.instructions);
        if (words !== undefined) {
          if (words.length > 0) l.instructions = words;
          else delete l.instructions;
        }
      }
    }
    for (const c of overrideCommandsOf(r)) {
      if (isShellSafeDir(c.dir)) continue;
      bad.add(c.dir);
      withheld++;
    }
    const reinstall = installDirs.get(r);
    if (reinstall) {
      for (const d of reinstall) {
        if (isShellSafeDir(d)) continue;
        bad.add(d);
        withheld++;
      }
      const safe = reinstall.filter((d) => isShellSafeDir(d));
      if (safe.length > 0) installDirs.set(r, safe);
      else if (reinstall.length > 0) {
        // Every directory to reinstall in is unsafe: no reinstall command at all (never the root's in their place).
        installDirs.delete(r);
        delete r.installFix;
      }
    }
    if (bad.size === 0) continue;
    WITHHELD.set(r, withheld);
    for (const d of [...bad].sort()) {
      found.add(d);
      const why = `${UNSAFE_DIR_REASON_START}${unsafeDirWords(d)}. That step is withheld; the row's steps in other directories stay in its commands and in run_order, and the row is not counted as fixed`;
      if (!r.reasons.includes(why)) r.reasons.push(why);
    }
  }
  return found;
}
