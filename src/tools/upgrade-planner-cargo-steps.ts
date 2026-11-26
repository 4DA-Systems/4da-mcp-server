// SPDX-License-Identifier: Apache-2.0
/**
 * Cargo steps whose preconditions are read before they are named (wave 2, design 2b), so that a
 * step either works on the lockfile it will meet or is not a command:
 *
 * - Every `cargo update -p name@installed --precise target` gets the pre-update it needs: the
 *   target release's own requirements (sparse index) against the locked versions
 *   (fix-paths.ts cargoPrecisePrerequisites). starship v1.0.0: chrono 0.4.30 needs iana-time-zone,
 *   which needs core-foundation-sys ^0.8.3 while 0.8.2 is locked; tempfile 3.4.0 needs fastrand
 *   ^1.6.0 while 1.5.0 is locked. Only the refresh path had it; a direct upgrade's and a parent
 *   lever's `--precise` did not, and both failed. When the requirements cannot be read in time, the
 *   step is words with the reason, not a command.
 * - A `cargo add` across an incompatible line while another locked crate still requires the old
 *   line, where both lines link the same native library (`links`): Cargo allows one package per
 *   native library in a build, so the command cannot resolve (git2 0.21 beside shadow-rs's git2
 *   0.13: both libgit2-sys lines link "git2"). No command: words naming the crate to move first.
 * - The order of `--precise` steps in run_order: a crate is moved before the crates that depend
 *   on it (cargoDependsOn), because `--precise` on a crate also moves the dependencies its new
 *   release needs, and a later step naming such a dependency at its old version finds nothing
 *   (crossbeam-epoch before crossbeam-utils, openssl before openssl-src).
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { cargoPrecisePrerequisites, type FixPathSources } from "../live/fix-paths.js";
import { parseCargoLockPackages } from "../live/lockfile-parsers.js";
import { cargoReqAdmits } from "../live/range-satisfies.js";
import { isShellSafeName, isShellSafeVersion } from "../live/shell-safe.js";
import { compareVersions } from "../live/version-compare.js";
import { isPrereleaseVersion } from "../live/osv-ranges.js";

/** How the reasons this pass writes start: a row with one is not counted as fixed by a command. */
export const CARGO_STEP_REASON_START = "Cargo: no command is named for ";
const CARGO_STEP_REASON = /^Cargo: no command is named for /;

export function hasCargoPrecondition(row: { reasons: string[] }): boolean {
  return row.reasons.some((r) => CARGO_STEP_REASON.test(r));
}

type Field = { dir: string; command: string };
type Instruction = { dir: string; instruction: string };

/** The row fields this pass reads and rewrites (a structural subset of upgrade_planner's row). */
export interface CargoStepRow {
  package: string;
  ecosystem: string;
  currentVersion: string | null;
  reasons: string[];
  upgradeCommands?: Array<Field & { refresh?: true; installs?: string }>;
  upgradeInstructions?: Instruction[];
  refreshCommands?: Field[];
  parentUpgrades?: Array<{
    levers: Array<{ name: string; version: string; to: string | null; commands?: Array<Field & { refresh?: true; installs?: string }>; instructions?: Instruction[] }>;
    refreshCommands?: Field[];
  }>;
}

const PRECISE = /^cargo update -p ([A-Za-z0-9_-]+)@(\S+) --precise (\S+)$/;
const ADD = /^cargo add "?([A-Za-z0-9_-]+)@[=^~]?([^"\s]+)"?(?: .*)?$/;

/** Cargo's compatibility line: one copy per line per lockfile ("1", "0.10", "0.0.3"). */
function cargoLine(version: string): string {
  const [major, minor, patch] = version.split(/[.+-]/);
  return major !== "0" ? major : minor !== "0" ? `0.${minor}` : `0.0.${patch}`;
}

/** The nearest Cargo.lock at or above `dir` (inside `root`); null when there is none. */
export function cargoLockFor(root: string, dir: string): string | null {
  const top = path.resolve(root);
  let at = path.resolve(top, dir);
  for (let i = 0; i < 32; i++) {
    const file = path.join(at, "Cargo.lock");
    if (fs.existsSync(file)) return file;
    const r = path.relative(top, at);
    if (r === "" || r.startsWith("..") || path.isAbsolute(r)) return null;
    at = path.dirname(at);
  }
  return null;
}

function readText(file: string): string | null {
  try {
    return fs.readFileSync(file, "utf8");
  } catch {
    return null;
  }
}

/** A lockfile's packages and its edges, `name@version` keyed. */
interface CargoGraph {
  packages: ReturnType<typeof parseCargoLockPackages>;
  /** name -> locked versions */
  locked: Map<string, string[]>;
  /** name@version -> name@version of its dependencies */
  deps: Map<string, string[]>;
}

function graphOf(content: string): CargoGraph {
  const packages = parseCargoLockPackages(content);
  const locked = new Map<string, string[]>();
  for (const p of packages) locked.set(p.name, [...(locked.get(p.name) ?? []), p.version]);
  const deps = new Map<string, string[]>();
  for (const p of packages) {
    const out: string[] = [];
    for (const d of p.dependencies) {
      const [n, v] = d.split(" ");
      const version = v ?? (locked.get(n)?.length === 1 ? locked.get(n)![0] : null);
      if (version) out.push(`${n}@${version}`);
    }
    deps.set(`${p.name}@${p.version}`, out);
  }
  return { packages, locked, deps };
}

/**
 * Whether `dependent` (name@version) depends, directly or not, on `dependency` in the lockfile at
 * or above `dir`; for run_order's order of `--precise` steps. Reads each lockfile once.
 */
export function cargoDependencyReader(root: string): (dir: string, dependent: string, dependency: string) => boolean {
  const graphs = new Map<string, CargoGraph | null>();
  const closures = new Map<string, Set<string>>();
  const graphFor = (dir: string): { file: string; graph: CargoGraph } | null => {
    const file = cargoLockFor(root, dir);
    if (!file) return null;
    if (!graphs.has(file)) {
      const text = readText(file);
      graphs.set(file, text === null ? null : graphOf(text));
    }
    const graph = graphs.get(file);
    return graph ? { file, graph } : null;
  };
  return (dir, dependent, dependency) => {
    const g = graphFor(dir);
    if (!g) return false;
    const key = `${g.file}\0${dependent}`;
    let seen = closures.get(key);
    if (!seen) {
      seen = new Set<string>();
      const stack = [...(g.graph.deps.get(dependent) ?? [])];
      while (stack.length > 0 && seen.size < 5000) {
        const k = stack.pop()!;
        if (seen.has(k)) continue;
        seen.add(k);
        for (const d of g.graph.deps.get(k) ?? []) stack.push(d);
      }
      closures.set(key, seen);
    }
    return seen.has(dependency);
  };
}

/** A conflict on a native library: the crate that keeps the old line, and the library both lines link. */
interface LinksConflict {
  holder: string;
  holderVersion: string;
  library: string;
  sys: string;
  oldSys: string;
  newSys: string;
}

const MAX_WALK = 60;
const LIBRARY = /^[A-Za-z0-9_.+-]{1,64}$/;

/**
 * For `cargo add crate@target` over `installed` on another compatibility line: a locked crate (not
 * the project's own) that keeps requiring `installed`, and a crate both trees need on different
 * lines that links the same native library. Null when there is none or it cannot be shown.
 */
async function linksConflict(sources: FixPathSources, graph: CargoGraph, crate: string, installed: string, target: string, deadline: number): Promise<LinksConflict | null> {
  const from = `${crate}@${installed}`;
  const holder = graph.packages.find((p) => p.source !== null && (graph.deps.get(`${p.name}@${p.version}`) ?? []).includes(from));
  if (!holder) return null;
  // The old copy's own tree stays with it.
  const oldTree = new Map<string, string>();
  const seen = new Set<string>();
  const stack = [from];
  while (stack.length > 0 && seen.size < 400) {
    const k = stack.pop()!;
    if (seen.has(k)) continue;
    seen.add(k);
    const at = k.lastIndexOf("@");
    if (!oldTree.has(k.slice(0, at))) oldTree.set(k.slice(0, at), k.slice(at + 1));
    for (const d of graph.deps.get(k) ?? []) stack.push(d);
  }
  const sparse = async (name: string) => {
    if (Date.now() > deadline) return null;
    const hit = await sources.cratesSparse(name).catch(() => null);
    if (hit && hit.links === undefined) return sources.cratesSparse(name, true).catch(() => null);
    return hit;
  };
  const visited = new Set<string>();
  const queue: Array<[string, string]> = [[crate, target]];
  while (queue.length > 0) {
    const [name, version] = queue.shift()!;
    if (visited.has(`${name}@${version}`)) continue;
    visited.add(`${name}@${version}`);
    if (visited.size > MAX_WALK) return null;
    const record = await sparse(name);
    const reqs = record?.reqs[version];
    if (!reqs) return null;
    for (const [dep, entries] of Object.entries(reqs)) {
      const lockedVersions = graph.locked.get(dep) ?? [];
      for (const { req, optional } of entries) {
        if (optional && lockedVersions.length === 0) continue;
        if (lockedVersions.some((v) => cargoReqAdmits(req, v) === true)) continue;
        const depRecord = await sparse(dep);
        if (!depRecord) return null;
        const best = depRecord.versions
          .filter((v) => !isPrereleaseVersion(v, "crates.io") && cargoReqAdmits(req, v) === true)
          .sort((a, b) => compareVersions(b, a, "crates.io"))[0];
        if (!best) return null;
        const old = oldTree.get(dep);
        const library = depRecord.links?.[best];
        if (old && cargoLine(old) !== cargoLine(best) && library && depRecord.links?.[old] === library) {
          return { holder: holder.name, holderVersion: holder.version, library, sys: dep, oldSys: old, newSys: best };
        }
        if (!visited.has(`${dep}@${best}`)) queue.push([dep, best]);
      }
    }
  }
  return null;
}

function linksWords(crate: string, installed: string, target: string, c: LinksConflict): string {
  const safe = [c.holder, c.sys].every((n) => isShellSafeName(n, "crates.io")) && [c.holderVersion, c.oldSys, c.newSys].every(isShellSafeVersion);
  const library = LIBRARY.test(c.library) ? `"${c.library}"` : "the same native library";
  if (!safe) {
    return `\`cargo add ${crate}@${target}\`: another locked crate still requires ${crate} ${installed}'s line, and both lines link ${library}, which Cargo allows once per build, so the command cannot resolve. Move the crate that requires ${crate} ${installed} first, then upgrade ${crate}`;
  }
  return (
    `\`cargo add ${crate}@${target}\`: ${c.holder} ${c.holderVersion} still requires ${crate} on its ${cargoLine(installed)} line, so ${crate} ${installed} stays in the build beside ${target}; ` +
    `${crate} ${installed} brings in ${c.sys} ${c.oldSys} and ${crate} ${target} needs ${c.sys} ${c.newSys}, and both link the native library ${library}, which Cargo allows once per build, so cargo refuses it ("failed to select a version for ${c.sys}"). ` +
    `Upgrade ${c.holder} first to a release that requires ${crate} ${cargoLine(target)} (or no ${crate}), or remove it; then upgrade ${crate}`
  );
}

function preciseWords(name: string, installed: string, target: string): string {
  return (
    `\`cargo update -p ${name}@${installed} --precise ${target}\`: what ${name} ${target} requires could not be compared with the locked versions in this call (the crates.io index did not answer for every crate it needs in time, or the walk is too large), so whether other locked crates must move first is not known. ` +
    `Run it, and if cargo reports that it failed to select a version for a crate, run \`cargo update -p <that crate>\` first and then run it again`
  );
}

/**
 * Rewrites the rows' Cargo commands (see the module comment). `deadline` bounds the index reads.
 */
export async function withCargoStepPreconditions(rows: CargoStepRow[], root: string, sources: FixPathSources | null, deadline: number): Promise<void> {
  const graphs = new Map<string, { content: string; graph: CargoGraph } | null>();
  const lockOf = (dir: string) => {
    const file = cargoLockFor(root, dir);
    if (!file) return null;
    if (!graphs.has(file)) {
      const content = readText(file);
      graphs.set(file, content === null ? null : { content, graph: graphOf(content) });
    }
    return graphs.get(file) ?? null;
  };
  const prereqsCache = new Map<string, Promise<string[] | null>>();
  for (const row of rows) {
    if (row.ecosystem !== "crates.io") continue;
    const said = new Set(row.reasons);
    const say = (text: string) => {
      if (!said.has(text)) row.reasons.push(text);
      said.add(text);
    };
    /** The fix of one command: kept (maybe with a pre-update), or taken off as words. */
    const judge = async (c: Field): Promise<{ command: string } | { words: string } | null> => {
      if (c.command.includes("&&")) return null;
      const precise = PRECISE.exec(c.command);
      if (precise) {
        const [, name, installed, target] = precise;
        const lock = lockOf(c.dir);
        if (!lock || !sources) return { words: preciseWords(name, installed, target) };
        const key = `${c.dir}\0${c.command}`;
        if (!prereqsCache.has(key)) {
          const left = deadline - Date.now();
          prereqsCache.set(
            key,
            left <= 0
              ? Promise.resolve(null)
              : Promise.race([
                  cargoPrecisePrerequisites(sources, lock.content, name, installed, target).catch(() => null),
                  new Promise<null>((resolve) => setTimeout(() => resolve(null), left).unref?.()),
                ]),
          );
        }
        const prereqs = await prereqsCache.get(key)!;
        if (prereqs === null || prereqs.some((p) => !/^[A-Za-z0-9_-]+(?:@[0-9A-Za-z.+_-]+)?$/.test(p))) return { words: preciseWords(name, installed, target) };
        return prereqs.length > 0 ? { command: `cargo update ${prereqs.map((p) => `-p ${p}`).join(" ")} && ${c.command}` } : null;
      }
      const add = ADD.exec(c.command);
      if (add && sources) {
        const [, crate, target] = add;
        const lock = lockOf(c.dir);
        if (!lock) return null;
        const versions = lock.graph.locked.get(crate) ?? [];
        // The copy the command replaces: on another line than the target (an in-line move keeps one copy).
        for (const installed of versions) {
          if (cargoLine(installed) === cargoLine(target)) continue;
          const conflict = await linksConflict(sources, lock.graph, crate, installed, target, deadline);
          if (conflict) return { words: linksWords(crate, installed, target, conflict) };
        }
      }
      return null;
    };
    /** Applies the judgement to one list of commands; the words go to `instructions`. */
    const rework = async <T extends Field>(list: T[] | undefined, instructions: Instruction[]): Promise<T[] | undefined> => {
      if (!list) return list;
      const kept: T[] = [];
      for (const c of list) {
        const j = await judge(c);
        if (j === null) kept.push(c);
        else if ("command" in j) kept.push({ ...c, command: j.command });
        else {
          instructions.push({ dir: c.dir, instruction: `no command: ${j.words}` });
          say(`${CARGO_STEP_REASON_START}${j.words}`);
        }
      }
      return kept;
    };
    const own: Instruction[] = [];
    const up = await rework(row.upgradeCommands, own);
    if (up !== undefined) {
      if (up.length > 0) row.upgradeCommands = up;
      else delete row.upgradeCommands;
    }
    const refresh = await rework(row.refreshCommands, own);
    if (refresh !== undefined) {
      if (refresh.length > 0) row.refreshCommands = refresh;
      else delete row.refreshCommands;
    }
    for (const u of row.parentUpgrades ?? []) {
      for (const lever of u.levers) {
        const words: Instruction[] = [];
        const cmds = await rework(lever.commands, words);
        if (cmds !== undefined) {
          if (cmds.length > 0) lever.commands = cmds;
          else delete lever.commands;
        }
        if (words.length > 0) lever.instructions = [...(lever.instructions ?? []), ...words];
      }
      const after = await rework(u.refreshCommands, own);
      if (after !== undefined) {
        if (after.length > 0) u.refreshCommands = after;
        else delete u.refreshCommands;
      }
    }
    if (own.length > 0) row.upgradeInstructions = [...(row.upgradeInstructions ?? []), ...own];
  }
}
