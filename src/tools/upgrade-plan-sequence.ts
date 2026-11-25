// SPDX-License-Identifier: Apache-2.0
/**
 * The plan as data: every command a row tells the developer to run, as `{ dir, run }`.
 *
 * `commands` is taken from the same row fields the row's sentences are built from (the direct
 * upgrade, the lockfile refresh, the parent's levers and the refresh after them, the reinstall, a
 * compiled requirements file's re-compile), after every pass that rewrites them, so the data and
 * the words never disagree. `dir` is project-relative, "." for the root. A compound command is one
 * entry per command, in order. A step the developer does by hand (deleting yarn.lock or bun.lock
 * entries, editing a manifest) is not a command: it stays in the row's reasons and
 * `upgradeInstructions`, and `commands` holds only what can be run. An override that does not
 * cross a major of what its parents declare is a command where one writes it exactly
 * (`npm pkg set "overrides.<name>=<version>"`, then the install: upgrade-plan-overrides.ts).
 */

import * as path from "node:path";
import { pushAll } from "../array-utils.js";
import { pypiCompileCommand } from "../live/pypi-advice.js";
import type { ReleaseMetadataSource } from "../live/release-metadata.js";
import { isShellSafeDir, isShellSafeName, isShellSafeVersion, unsafeDirLabel } from "../live/shell-safe.js";
import { compareVersions } from "../live/version-compare.js";
import { overrideCommandsOf } from "./upgrade-plan-overrides.js";
import { peerConflictReader, type PeerContext } from "./upgrade-plan-peers.js";

export interface PlanCommand {
  /** Project-relative directory the command runs in; "." for the root. */
  dir: string;
  run: string;
}

interface CommandField {
  dir: string;
  command: string;
}

/** The row fields read here: a structural subset of upgrade_planner's row. */
export interface CommandRow {
  package: string;
  ecosystem: string;
  currentVersion: string | null;
  targetVersion: string | null;
  refreshCommands?: CommandField[];
  upgradeCommands?: CommandField[];
  upgradeInstructions?: Array<{ dir: string; instruction: string }>;
  parentUpgrades?: Array<{ levers: Array<{ commands?: CommandField[] }>; refreshCommands?: CommandField[] }>;
  installFix?: string;
  commands?: PlanCommand[];
  action?: string;
  /** True when the row's target crosses a major (an override then forces it past what its parents were written for). */
  breaking?: boolean;
}

/**
 * The hand-edit steps live/fix-paths.ts `manualRefreshSteps` writes where a lockfile has no refresh
 * command (Yarn 1, Bun): instructions, never commands.
 */
const MANUAL_STEP = /^(?:delete every yarn\.lock entry |delete the .+ entries from bun\.lock|refresh this package's (?:yarn|bun)\.lock entries by hand)/;

export function isManualStep(text: string): boolean {
  return MANUAL_STEP.test(text);
}

/** One command per entry: `a && b` (the Cargo pre-update before `--precise`) is two, run in order. */
function splitCompound(command: string): string[] {
  return command
    .split(" && ")
    .map((c) => c.trim())
    .filter((c) => c.length > 0);
}

export interface CommandContext {
  /** The project root the row's directories are relative to. */
  root: string;
  /** Where node_modules drifted from the lockfile, for a reinstall row (relative directories). */
  installDirs?: string[];
}

/**
 * The commands of one row, in the order the row gives them: the direct upgrade; then every lever
 * of every blocking parent, then the refreshes that follow them (a refresh runs on the tree the
 * levers leave); then the row's own refresh; then the reinstall.
 */
export function rowCommands(row: CommandRow, ctx: CommandContext): PlanCommand[] {
  const out: PlanCommand[] = [];
  const add = (dir: string, command: string) => {
    // A directory whose name is not a plain path gets no command (audit 2026-11-25 B-B1): the row's reasons say it in words.
    if (isManualStep(command) || !isShellSafeDir(dir)) return;
    for (const run of splitCompound(command)) if (!out.some((c) => c.dir === dir && c.run === run)) out.push({ dir, run });
  };
  for (const c of row.upgradeCommands ?? []) add(c.dir, c.command);
  for (const u of row.parentUpgrades ?? []) for (const l of u.levers) for (const c of l.commands ?? []) add(c.dir, c.command);
  for (const u of row.parentUpgrades ?? []) for (const c of u.refreshCommands ?? []) add(c.dir, c.command);
  for (const c of row.refreshCommands ?? []) add(c.dir, c.command);
  for (const c of compiledCommands(row, ctx.root)) add(c.dir, c.command);
  if (row.action !== "override_or_replace" || row.breaking !== true) for (const c of overrideCommandsOf(row)) add(c.dir, c.command);
  if (row.installFix) for (const dir of ctx.installDirs && ctx.installDirs.length > 0 ? ctx.installDirs : ["."]) add(dir, row.installFix);
  return out;
}

/**
 * A PyPI row whose pin sits in a compiled requirements file: the re-compile its instruction names
 * (`uv pip compile ... --upgrade-package "x==v"`), from the same reader the instruction is worded by.
 */
function compiledCommands(row: CommandRow, root: string): CommandField[] {
  if (row.ecosystem !== "PyPI" || !row.upgradeInstructions || !row.currentVersion || !row.targetVersion) return [];
  const out: CommandField[] = [];
  for (const i of row.upgradeInstructions) {
    const command = pypiCompileCommand(path.resolve(root, i.dir), row.package, row.currentVersion, row.targetVersion);
    if (command && i.instruction.includes(command)) out.push({ dir: i.dir, command });
  }
  return out;
}

/** Set `commands` on every row (possibly empty: the row's reasons then say why nothing is run). */
export function attachCommands<R extends CommandRow>(rows: R[], ctx: (row: R) => CommandContext): void {
  for (const r of rows) r.commands = rowCommands(r, ctx(r));
}

// ---------------------------------------------------------------------------
// run_order: the rows shown as one script, safe to run from the first step to the last
// ---------------------------------------------------------------------------

export interface RunOrderStep {
  n: number;
  dir: string;
  run: string;
  /** Project-relative files the step changes (upgrade-plan-protocol.ts). */
  changes?: string[];
  /** How to put back what the step can leave edited when it fails (upgrade-plan-protocol.ts); absent when a failure writes nothing. */
  if_it_fails?: string;
  /** "ecosystem:package" of the rows this step serves. */
  fixes: string[];
}

/** The row fields the sequencer reads: a structural subset of upgrade_planner's row. */
export interface SequencedRow extends CommandRow {
  action: string;
  reasons: string[];
  parentUpgrades?: Array<{
    /** The transitive parent the levers move (vite, for esbuild's row). */
    parent?: string;
    levers: Array<{ name: string; version: string; to: string | null; commands?: CommandField[]; instructions?: unknown[]; sameCommandsAs?: string }>;
    refreshCommands?: CommandField[];
  }>;
  commands: PlanCommand[];
}

/**
 * Whether the row's commands are its whole fix: no part of it is a hand edit (a yarn.lock or
 * bun.lock edit, a manifest edit, a lever with no command). A row that is partly by hand is left
 * out of run_order, which never claims to serve a row it does not finish.
 */
function wholeByCommand(r: SequencedRow): boolean {
  if (r.commands.length === 0) return false;
  const refreshes = [...(r.refreshCommands ?? []), ...(r.parentUpgrades ?? []).flatMap((u) => u.refreshCommands ?? [])];
  // A hand refresh is covered where the row's resolution commands run in that directory (upgrade-plan-runnable.ts).
  const resolved = new Set(overrideCommandsOf(r).map((c) => c.dir));
  if (refreshes.some((c) => isManualStep(c.command) && !resolved.has(c.dir))) return false;
  if ((r.upgradeInstructions ?? []).some((i) => !resolved.has(i.dir) && !r.commands.some((c) => c.dir === i.dir && i.instruction.includes(c.run)))) return false;
  return (r.parentUpgrades ?? []).every((u) => u.levers.every((l) => l.to === null || Boolean(l.commands?.length) || l.sameCommandsAs !== undefined));
}

/** What a command does, read from the forms live/fix-paths.ts and its neighbours write. */
type Parsed =
  | { kind: "set"; tool: string; pkg: string; version: string; flags: string }
  | { kind: "refresh"; tool: string; pkg: string }
  | { kind: "goget"; mods: Array<{ module: string; version: string }> }
  | { kind: "tidy" }
  | { kind: "precise"; pkg: string; from: string; to: string }
  | { kind: "pre"; specs: string[] }
  | { kind: "compile"; head: string; upgrades: Array<{ pkg: string; version: string }> }
  | { kind: "reinstall" }
  | { kind: "other" };

const SPEC = String.raw`"?((?:@[^/\s"@]+\/)?[^@\s"]+)@[=^~]?([^"\s]+)"?`;
const SET_FORMS: Array<[RegExp, string]> = [
  [new RegExp(`^npm install ${SPEC}(?: --save-exact)?$`), "npm"],
  [new RegExp(`^pnpm up ${SPEC}$`), "pnpm"],
  // `--dev`: a Berry root `yarn add` for a dev dependency the manifest also lists as a peer (fix-paths.ts berryAddFlag).
  [new RegExp(`^yarn (?:upgrade|up|add) ${SPEC}(?: --dev)?$`), "yarn"],
];
const REFRESH_FORMS: Array<[RegExp, string]> = [
  [/^npm update (\S+)$/, "npm"],
  // `--depth Infinity --no-save`: every edge of a copy pnpm keeps at a workspace root (upgrade-planner-shared-copy.ts).
  [/^pnpm update (?:-r )?(\S+) (?:--no-save|--depth Infinity(?: --no-save)?)$/, "pnpm"],
  [/^yarn (?:upgrade|up -R) (\S+)$/, "yarn"],
  [/^uv lock --upgrade-package (\S+)$/, "uv"],
  [/^poetry update (\S+)$/, "poetry"],
];

export function parseCommand(run: string): Parsed {
  if (/^(?:npm ci|npm install|pnpm install|yarn install|yarn|bun install)$/.test(run)) return { kind: "reinstall" };
  for (const [form, tool] of SET_FORMS) {
    const m = form.exec(run);
    if (m) return { kind: "set", tool, pkg: m[1], version: m[2], flags: "" };
  }
  const member = new RegExp(`^yarn workspace (\\S+) add ${SPEC}( --dev| --optional)?$`).exec(run);
  if (member) return { kind: "set", tool: "yarn", pkg: member[2], version: member[3], flags: `workspace ${member[1]}` };
  const pnpmAdd = new RegExp(`^pnpm add (-D |-O )?${SPEC}$`).exec(run);
  if (pnpmAdd) return { kind: "set", tool: "pnpm", pkg: pnpmAdd[2], version: pnpmAdd[3], flags: "" };
  for (const [form, tool] of REFRESH_FORMS) {
    const m = form.exec(run);
    if (m) return { kind: "refresh", tool, pkg: m[1] };
  }
  const add = /^cargo add "?([A-Za-z0-9_-]+)@[=^~]?([^"\s]+)"?((?: .+)?)$/.exec(run);
  if (add) return { kind: "set", tool: "cargo", pkg: add[1], version: add[2], flags: add[3].trim() };
  const precise = /^cargo update -p ([A-Za-z0-9_-]+)@(\S+) --precise (\S+)$/.exec(run);
  if (precise) return { kind: "precise", pkg: precise[1], from: precise[2], to: precise[3] };
  const pre = /^cargo update((?: -p \S+)+)$/.exec(run);
  if (pre) return { kind: "pre", specs: pre[1].trim().split(/\s+/).filter((s) => s !== "-p") };
  const goget = /^go get (\S+@\S+(?: \S+@\S+)*)$/.exec(run);
  if (goget) return { kind: "goget", mods: goget[1].split(" ").map((a) => ({ module: a.slice(0, a.lastIndexOf("@")), version: a.slice(a.lastIndexOf("@") + 1) })) };
  if (run === "go mod tidy") return { kind: "tidy" };
  const compile = /^((?:uv pip compile \S+ -o \S+)|(?:pip-compile \S+ --output-file \S+))((?: --upgrade-package "[^"=]+==[^"]+")+)$/.exec(run);
  if (compile) {
    const upgrades = [...compile[2].matchAll(/--upgrade-package "([^"=]+)==([^"]+)"/g)].map((m) => ({ pkg: m[1], version: m[2] }));
    return { kind: "compile", head: compile[1], upgrades };
  }
  return { kind: "other" };
}

const ECOSYSTEM_OF_TOOL: Record<string, string> = { npm: "npm", pnpm: "npm", yarn: "npm", cargo: "crates.io", go: "Go", compile: "PyPI" };

/**
 * Priority among steps no ordering rule ties (lower first): Cargo's pre-updates and --precise
 * moves, then upgrades, then in-range refreshes, then what follows them. A refresh moves a copy up
 * within the ranges that hold it, so run after an upgrade it never lowers what the upgrade set; an
 * upgrade run after a refresh can (fastapi-frontend: @hey-api/openapi-ts 0.97.3 pins, through
 * @hey-api/json-schema-ref-parser 1.4.2, js-yaml 4.1.1, below the 4.3.2 `npm update js-yaml` had set).
 */
const PHASE = { pre: 0, precise: 1, set: 2, compile: 2, goget: 2, other: 2, refresh: 3, tidy: 4, reinstall: 5 } as const;

/** One step of the script, merged from every row command that does the same thing. */
interface Node {
  key: string;
  dir: string;
  phase: number;
  /** For the deterministic order: tool and package, then the command. */
  label: string;
  fixes: Set<string>;
  render: () => string | null;
}

/** A merged version-setting command: every row's candidate, the highest kept. */
interface SetState {
  ecosystem: string;
  candidates: Array<{ version: string; run: string; fix: string; row: SequencedRow }>;
  chosen(): { version: string; run: string };
}

export interface RunOrderOptions {
  /** The rows the plan returns, in its order. */
  rows: SequencedRow[];
  /** How many rows the plan has in all (more than `rows` when max_recommendations cut it). */
  totalRows: number;
  /** Whether a row's target is not a clean fix (it holds an affected dependency): never run as one. */
  heldUnclean: (row: SequencedRow) => boolean;
  /**
   * Go: what a module release's own go.mod requires (module -> minimum version); null when it could
   * not be read, undefined when it was not looked up.
   */
  goRequires?: (module: string, version: string) => Map<string, string> | null | undefined;
  /** How setting `pkg` to `version` in `dir` breaks a peer range installed direct dependencies declare (which, and why); null when it does not. */
  peerConflict?: (dir: string, pkg: string, version: string) => PeerConflict | null;
  /** The operator of `name`'s declaration in `dir`/package.json ("^", "~", "" for an exact pin); null when it is not declared there or not read. */
  declaredOperator?: (dir: string, name: string) => string | null;
  /**
   * Steps taken off a row because they would run in a directory whose name is not safe in a command
   * (upgrade-plan-runnable.ts withholdUnsafeDirs): its other steps still run; the note says how many were withheld.
   */
  withheldSteps?: (row: SequencedRow) => number;
}

export interface PeerConflict {
  /** The installed direct dependencies whose peer range on the package excludes the version. */
  holders: string[];
  /** "@vitest/coverage-v8 1.6.0 declares "1.6.0"", per holder. */
  who: string;
  /** The sentence for the row when the step cannot run with them. */
  text: string;
}

export interface RunOrder {
  run_order: RunOrderStep[];
  run_order_note: string;
  /** Rows left out because a command of theirs breaks a peer range, with why (the planner says it on the row). */
  peerBlocked: Map<SequencedRow, string>;
}

/** The actions whose commands are the whole fix on this host (the ones the summary counts as fixed). */
const FIX_ACTIONS = new Set(["upgrade_direct", "lockfile_refresh", "upgrade_parent", "reinstall"]);

/** A row whose commands are its whole fix on this host: a fix action, or an override whose snippet is written as commands (not one whose only commands are a parent lever that leaves other paths). */
const isRunnable = (opts: Pick<RunOrderOptions, "heldUnclean">) => (r: SequencedRow) =>
  (FIX_ACTIONS.has(r.action) || (r.action === "override_or_replace" && r.breaking !== true && overrideCommandsOf(r).length > 0)) && !opts.heldUnclean(r) && wholeByCommand(r) && (r.action !== "upgrade_direct" || r.targetVersion !== null);

/** A row left out because part of its fix is done by hand: a manifest or lockfile edit, an override, a lever with no command. */
function isHandEdit(r: SequencedRow): boolean {
  if (r.action === "override_or_replace") return r.reasons.some((x) => /^Transitive dependency.*\bForce \S+ to \S+: /.test(x));
  if ((r.upgradeInstructions ?? []).length > 0) return true;
  if ([...(r.refreshCommands ?? []), ...(r.parentUpgrades ?? []).flatMap((u) => u.refreshCommands ?? [])].some((c) => isManualStep(c.command))) return true;
  return (r.parentUpgrades ?? []).some((u) => u.levers.some((l) => l.to !== null && !l.commands?.length && l.sameCommandsAs === undefined && (l.instructions?.length ?? 0) > 0));
}

const keyOf = (r: SequencedRow) => `${r.ecosystem}:${r.package}`;
const copyOf = (r: SequencedRow) => `${r.package}${r.currentVersion ? ` ${r.currentVersion}` : ""}`;

/** The installed version of each package a row's version-setting command moves, per directory. */
function installedVersions(rows: SequencedRow[]): Map<string, string[]> {
  const out = new Map<string, string[]>();
  const note = (dir: string, pkg: string, version: string | null) => {
    if (!version) return;
    const k = `${dir}\0${pkg}`;
    out.set(k, [...(out.get(k) ?? []), version]);
  };
  for (const r of rows) {
    for (const c of r.upgradeCommands ?? []) note(c.dir, r.package, r.currentVersion);
    for (const u of r.parentUpgrades ?? []) for (const l of u.levers) for (const c of l.commands ?? []) note(c.dir, l.name, l.version);
  }
  return out;
}

/**
 * The rows shown as one script (DESIGN 3): one version-setting command per package per directory,
 * at the highest version any row needs; nothing set below what is installed; every `go get` of one
 * module directory in one command, without naming a module below what another target's go.mod
 * requires of it; Cargo pre-updates and `--precise` moves that name a crate version once; each row's
 * own order kept (a parent before the refreshes that follow it); a step whose target breaks a peer
 * range left out with its rows. Rows that are not a fix this host runs by command are left out and
 * named in the note. The order is total: two identical plans give the same script.
 */
export function buildRunOrder(opts: RunOrderOptions): RunOrder {
  const peerBlocked = new Map<SequencedRow, string>();
  const runnable = opts.rows.filter(isRunnable(opts));
  const groups: string[][] = [];
  const extra: ExtraSet[] = [];
  let graph = buildGraph(runnable, opts, groups, extra);
  // A target that breaks a peer range runs in one command with the holder's own upgrade when the
  // script upgrades the holder too, or a row moves the holder to a release that brings the target
  // in; otherwise its rows are left out entirely and the rest re-merged.
  for (let round = 0; round < 6 && opts.peerConflict; round++) {
    const live = runnable.filter((r) => !peerBlocked.has(r));
    const found = graph.conflicts(opts.peerConflict, holderMoves(live, opts));
    if (found.blocked.size === 0 && found.combine.length === 0) break;
    for (const [row, why] of found.blocked) peerBlocked.set(row, why);
    for (const e of found.extra) if (!extra.some((x) => x.key === e.key)) extra.push(e);
    for (const pair of found.combine) joinGroup(groups, pair);
    graph = buildGraph(
      runnable.filter((r) => !peerBlocked.has(r)),
      opts,
      groups,
      extra.filter((e) => e.rows.some((r) => !peerBlocked.has(r))),
    );
  }
  // Never a step in a directory whose name is not a plain path, whatever produced it.
  const steps = graph
    .order()
    .filter((n) => isShellSafeDir(n.dir))
    .map((n, i) => ({ n: i + 1, dir: n.dir, run: n.run, fixes: [...n.fixes].sort() }));
  const note = runOrderNote(opts, runnable, peerBlocked, steps.length, graph.notes);
  return { run_order: steps, run_order_note: note, peerBlocked };
}

/**
 * A holder's upgrade the script adds to keep a peer range: a row names the holder as a lever that
 * brings in the package whose target breaks the holder's installed peer range (esbuild's row:
 * @vitejs/plugin-react-swc 3.5.0 to 3.7.2, by an in-range `npm update`, beside vite 6.4.5), so the
 * holder's new release admits it, and the two install in one command.
 */
interface ExtraSet {
  key: string;
  dir: string;
  pkg: string;
  version: string;
  run: string;
  rows: SequencedRow[];
}

type HolderMoves = Map<string, { version: string; run: string }>;

/** `dir\0tool\0holder\0pkg` -> the release a row's lever moves the holder to so that it brings `pkg` in, as a command that sets it. */
function holderMoves(rows: SequencedRow[], opts: RunOrderOptions): HolderMoves {
  const out: HolderMoves = new Map();
  for (const r of rows) {
    for (const u of r.parentUpgrades ?? []) {
      if (!u.parent) continue;
      for (const l of u.levers) {
        if (!l.to || !isShellSafeName(l.name, "npm") || !isShellSafeVersion(l.to)) continue;
        for (const c of l.commands ?? []) {
          const p = parseCommand(c.command);
          if (p.kind !== "refresh" || p.pkg !== l.name || (p.tool !== "npm" && p.tool !== "pnpm")) continue;
          const op = opts.declaredOperator?.(c.dir, l.name);
          if (op !== "^" && op !== "~") continue;
          const k = `${c.dir}\0${p.tool}\0${l.name}\0${u.parent}`;
          const held = out.get(k);
          if (held && compareVersions(held.version, l.to, "npm") >= 0) continue;
          out.set(k, { version: l.to, run: `${p.tool === "npm" ? "npm install" : "pnpm up"} "${l.name}@${op}${l.to}"` });
        }
      }
    }
  }
  return out;
}

interface Graph {
  /** Rows whose step breaks a peer range it cannot run with the holder's upgrade, pairs of steps to run as one, and holder upgrades added for them. */
  conflicts(
    peerConflict: NonNullable<RunOrderOptions["peerConflict"]>,
    moves: HolderMoves,
  ): { blocked: Map<SequencedRow, string>; combine: Array<[string, string]>; extra: ExtraSet[] };
  order(): Array<{ dir: string; run: string; fixes: Set<string> }>;
  notes: string[];
}

/** Put two version-setting steps in one group (one command), merging the groups they are in. */
function joinGroup(groups: string[][], [a, b]: [string, string]): void {
  const ga = groups.find((g) => g.includes(a));
  const gb = groups.find((g) => g.includes(b));
  if (ga && ga === gb) return;
  if (ga && gb) {
    pushAll(ga, gb.filter((k) => !ga.includes(k)));
    groups.splice(groups.indexOf(gb), 1);
  } else if (ga) ga.push(b);
  else if (gb) gb.push(a);
  else groups.push([a, b]);
}

/**
 * One command for several version-setting commands of one tool in one directory: the same command
 * with every spec (`pnpm up "vitest@^4.1.12" "@vitest/coverage-v8@^4.1.11"`). Null when they differ
 * in anything but the spec (`npm install a@1 --save-exact` beside `npm install "b@^2"`).
 */
function combineRuns(runs: string[]): string | null {
  const parts = runs.map((r) => /^(.*?) ("?(?:@[^/\s"@]+\/)?[^@\s"]+@[^"\s]+"?)((?: --?\S+)*)$/.exec(r));
  if (parts.some((p) => !p)) return null;
  const [first] = parts as RegExpExecArray[];
  if (!(parts as RegExpExecArray[]).every((p) => p[1] === first[1] && p[3] === first[3])) return null;
  return `${first[1]} ${(parts as RegExpExecArray[]).map((p) => p[2]).join(" ")}${first[3]}`;
}

function buildGraph(rows: SequencedRow[], opts: RunOrderOptions, groups: string[][], extra: ExtraSet[] = []): Graph {
  const nodes = new Map<string, Node>();
  const sets = new Map<string, SetState>();
  const edges = new Map<string, Set<string>>();
  const notes: string[] = [];
  const installed = installedVersions(rows);
  const goNodes = new Map<string, Map<string, { version: string; fixes: Set<string> }>>();
  const compiles = new Map<string, Map<string, string>>();
  const pres = new Map<string, string[]>();
  const precises = new Map<string, { pkg: string; from: string; to: string }>();
  const preOwners = new Map<string, Set<string>>();

  const node = (key: string, dir: string, phase: number, label: string, render: () => string | null): Node => {
    let n = nodes.get(key);
    if (!n) {
      n = { key, dir, phase, label, fixes: new Set(), render };
      nodes.set(key, n);
    }
    return n;
  };
  const edge = (from: string, to: string) => {
    if (from === to) return;
    edges.set(from, (edges.get(from) ?? new Set()).add(to));
  };

  for (const row of rows) {
    const fix = keyOf(row);
    let previous: string | null = null;
    for (const c of row.commands) {
      const p = parseCommand(c.run);
      const n = place(p, c, row, fix);
      n.fixes.add(fix);
      if (previous) edge(previous, n.key);
      previous = n.key;
    }
  }
  for (const e of extra) {
    const p = parseCommand(e.run);
    if (p.kind !== "set") continue;
    for (const row of e.rows.filter((r) => rows.includes(r))) place(p, { dir: e.dir, run: e.run }, row, keyOf(row)).fixes.add(keyOf(row));
  }

  function place(p: Parsed, c: PlanCommand, row: SequencedRow, fix: string): Node {
    switch (p.kind) {
      case "set": {
        const key = `${c.dir}\0set\0${p.tool}\0${p.pkg}\0${p.flags}`;
        const state = sets.get(key) ?? newSet(ECOSYSTEM_OF_TOOL[p.tool] ?? "npm");
        sets.set(key, state);
        state.candidates.push({ version: p.version, run: c.run, fix, row });
        const group = groups.find((g) => g.includes(key));
        if (group) {
          // Run as one command with the steps it must not run without (rule e).
          return node(`group\0${[...group].sort().join("\u0001")}`, c.dir, PHASE.set, `${p.tool} ${[...group].map((k) => k.split("\0")[3]).sort().join(" ")}`, () => {
            const members = group.filter((k) => sets.has(k)).sort();
            if (members.some((k) => setRun(k) === null)) return null;
            return combineRuns(members.map((k) => setRun(k)!));
          });
        }
        return node(key, c.dir, PHASE.set, `${p.tool} ${p.pkg}`, () => setRun(key));
      }
      case "refresh":
        // Merged only when identical: `pnpm update x --no-save` and `pnpm update x --depth Infinity`
        // move different copies, and an in-range refresh never lowers what another step sets.
        return node(`${c.dir}\0refresh\0${c.run}`, c.dir, PHASE.refresh, `${p.tool} ${p.pkg}`, () => c.run);
      case "goget": {
        const key = `${c.dir}\0goget`;
        const mods = goNodes.get(c.dir) ?? new Map();
        goNodes.set(c.dir, mods);
        for (const m of p.mods) {
          const held = mods.get(m.module);
          if (!held || compareVersions(m.version, held.version, "Go") > 0) mods.set(m.module, { version: m.version, fixes: new Set([...(held?.fixes ?? []), fix]) });
          else held.fixes.add(fix);
        }
        return node(key, c.dir, PHASE.goget, "go get", () => goGet(c.dir, mods, opts, notes));
      }
      case "tidy": {
        const key = `${c.dir}\0tidy`;
        if (goNodes.has(c.dir)) edge(`${c.dir}\0goget`, key);
        return node(key, c.dir, PHASE.tidy, "go mod tidy", () => "go mod tidy");
      }
      case "precise": {
        const key = `${c.dir}\0precise\0${p.pkg}@${p.from}`;
        const held = precises.get(key);
        if (!held || compareVersions(p.to, held.to, "crates.io") > 0) precises.set(key, p);
        return node(key, c.dir, PHASE.precise, `cargo ${p.pkg}`, () => {
          const chosen = precises.get(key)!;
          return `cargo update -p ${chosen.pkg}@${chosen.from} --precise ${chosen.to}`;
        });
      }
      case "pre": {
        const key = `${c.dir}\0pre`;
        const specs = pres.get(c.dir) ?? [];
        for (const s of p.specs) if (!specs.includes(s)) specs.push(s);
        pres.set(c.dir, specs);
        for (const s of p.specs) preOwners.set(`${c.dir}\0${s}`, (preOwners.get(`${c.dir}\0${s}`) ?? new Set()).add(fix));
        return node(key, c.dir, PHASE.pre, "cargo update", () => {
          // A crate version another step moves with --precise is not pre-updated too: the second would find it gone.
          const left = specs.filter((s) => !precises.has(`${c.dir}\0precise\0${s}`));
          return left.length > 0 ? `cargo update ${left.map((s) => `-p ${s}`).join(" ")}` : null;
        });
      }
      case "compile": {
        const key = `${c.dir}\0compile\0${p.head}`;
        const ups = compiles.get(key) ?? new Map<string, string>();
        compiles.set(key, ups);
        for (const u of p.upgrades) {
          const held = ups.get(u.pkg);
          if (!held || compareVersions(u.version, held, "PyPI") > 0) ups.set(u.pkg, u.version);
        }
        return node(key, c.dir, PHASE.compile, p.head, () => `${p.head} ${[...ups].map(([pkg, v]) => `--upgrade-package "${pkg}==${v}"`).join(" ")}`);
      }
      case "reinstall":
        return node(`${c.dir}\0reinstall\0${c.run}`, c.dir, PHASE.reinstall, c.run, () => c.run);
      case "other":
        return node(`${c.dir}\0other\0${c.run}`, c.dir, PHASE.other, c.run, () => c.run);
    }
  }

  /** A version-setting step's command at its chosen version; null when that is below a version installed there (rule b). */
  function setRun(key: string): string | null {
    const state = sets.get(key)!;
    const [dir, , , pkg] = key.split("\0");
    const chosen = state.chosen();
    const below = (installed.get(`${dir}\0${pkg}`) ?? []).find((v) => compareVersions(chosen.version, v, state.ecosystem) < 0);
    return below ? null : chosen.run;
  }

  // A pre-update before every --precise of its directory; a crate it no longer names moves by its own --precise first.
  for (const [dir] of pres) {
    for (const [key, p] of precises) {
      if (!key.startsWith(`${dir}\0`)) continue;
      edge(`${dir}\0pre`, key);
      for (const [other] of precises) if (other !== key && preOwners.has(`${dir}\0${p.pkg}@${p.from}`) && other.startsWith(`${dir}\0`)) edge(key, other);
    }
  }
  for (const [key, state] of sets) {
    const chosen = state.chosen();
    const [dir, , , pkg] = key.split("\0");
    const versions = [...new Set(state.candidates.map((c) => c.version))].sort((a, b) => compareVersions(a, b, state.ecosystem));
    if (versions.length > 1) {
      const lower = [...new Set(state.candidates.filter((c) => c.version !== chosen.version).map((c) => copyOf(c.row)))];
      notes.push(
        `${pkg} is set once in ${dirWords(dir)}, at ${chosen.version}, for rows that named ${andList(versions)}: the highest any row needs, so no step lowers what another sets; that it also brings in the fix of ${andList(lower)}, whose ${lower.length === 1 ? "row" : "rows"} named a lower release, was not confirmed (re-scan after running)`,
      );
    }
    if (setRun(key) === null) notes.push(`${pkg} ${chosen.version} is not run in ${dirWords(dir)}: a newer ${pkg} is installed there`);
  }

  return {
    notes,
    conflicts(peerConflict, moves) {
      const blocked = new Map<SequencedRow, string>();
      const combine: Array<[string, string]> = [];
      const added: ExtraSet[] = [];
      for (const [key, state] of sets) {
        const [dir, , tool, pkg] = key.split("\0");
        if (tool !== "npm" && tool !== "pnpm" && tool !== "yarn") continue;
        const chosen = state.chosen().version;
        const conflict = peerConflict(dir, pkg, chosen);
        if (!conflict) continue;
        // Each holder the script upgrades too runs in the same command; one it does not leaves the step out.
        const group = groups.find((g) => g.includes(key)) ?? [key];
        const pending: Array<[string, string]> = [];
        let together = true;
        const adding: ExtraSet[] = [];
        for (const holder of conflict.holders) {
          let other = [...sets.keys()].find((k) => {
            const [d, , t, n] = k.split("\0");
            return d === dir && t === tool && n === holder;
          });
          if (other && group.includes(other)) continue;
          const move = other ? undefined : moves.get(`${dir}\0${tool}\0${holder}\0${pkg}`);
          if (move) {
            other = `${dir}\0set\0${tool}\0${holder}\0`;
            adding.push({ key: other, dir, pkg: holder, version: move.version, run: move.run, rows: state.candidates.map((c) => c.row) });
          }
          const runOf = (k: string) => (sets.has(k) ? setRun(k) : (adding.find((a) => a.key === k)?.run ?? null));
          const runs = other ? [...new Set([...group, other])].map(runOf) : [];
          if (!other || runs.some((r) => r === null) || combineRuns(runs as string[]) === null) {
            together = false;
            break;
          }
          pending.push([key, other]);
        }
        if (!together) for (const c of state.candidates) blocked.set(c.row, conflict.text);
        else {
          pushAll(combine, pending);
          pushAll(added, adding);
          notes.push(`${pkg} ${chosen} runs in one command with ${andList(conflict.holders)} in ${dirWords(dir)}, which the script upgrades too: installed, ${conflict.who}, a peer range that excludes ${chosen}`);
        }
      }
      return { blocked, combine, extra: added };
    },
    order: () => topological(nodes, edges),
  };
}

function newSet(ecosystem: string): SetState {
  const state: SetState = {
    ecosystem,
    candidates: [],
    chosen() {
      let best = state.candidates[0];
      for (const c of state.candidates) if (compareVersions(c.version, best.version, ecosystem) > 0) best = c;
      return { version: best.version, run: best.run };
    },
  };
  return state;
}

/**
 * One `go get` for a module directory. A module whose target another named release's go.mod already
 * requires at or above is not named: that release selects it, and naming the lower target would
 * downgrade the other one (glow: x/sys v0.44.0 after x/crypto v0.59.0, which requires v0.50.0).
 */
function goGet(dir: string, mods: Map<string, { version: string; fixes: Set<string> }>, opts: RunOrderOptions, notes: string[]): string {
  const names = [...mods.keys()].sort();
  const dropped = new Set<string>();
  const unread: string[] = [];
  for (const m of names) {
    for (const other of names) {
      if (other === m || dropped.has(other)) continue;
      const requires = opts.goRequires?.(other, mods.get(other)!.version);
      if (requires === null && !unread.includes(other)) unread.push(other);
      const min = requires?.get(m);
      if (min && compareVersions(min, mods.get(m)!.version, "Go") >= 0) {
        dropped.add(m);
        notes.push(`${m} is not named in ${dirWords(dir)}'s go get: ${other} ${mods.get(other)!.version}'s go.mod requires ${min}, at or above its target ${mods.get(m)!.version}, so the go get selects it`);
        break;
      }
    }
  }
  if (names.length > 1 && unread.length > 0) {
    notes.push(`the go.mod of ${andList(unread.map((u) => `${u} ${mods.get(u)!.version}`))} could not be read, so whether ${unread.length === 1 ? "it requires" : "they require"} another named module above its target was not checked: if go get reports a conflict, raise that module to the version it names`);
  }
  const kept = names.filter((m) => !dropped.has(m));
  return `go get ${kept.map((m) => `${m}@${mods.get(m)!.version}`).join(" ")}`;
}

/**
 * Kahn's order over the steps: every row's own order is an edge; among the steps free to run, the
 * lowest phase, then the root before other directories, then tool, package and command. A cycle
 * (two rows ordering the same pair both ways) runs the rest in that same order.
 */
function topological(nodes: Map<string, Node>, edges: Map<string, Set<string>>): Array<{ dir: string; run: string; fixes: Set<string> }> {
  // Each step is rendered once: a Go step's render also writes its notes.
  const text = new Map<string, string>();
  for (const n of nodes.values()) {
    const run = n.render();
    if (run !== null) text.set(n.key, run);
  }
  const live = [...nodes.values()].filter((n) => text.has(n.key));
  const indegree = new Map(live.map((n) => [n.key, 0]));
  for (const [from, tos] of edges) if (text.has(from)) for (const to of tos) if (text.has(to)) indegree.set(to, indegree.get(to)! + 1);
  const rank = (n: Node) => [n.phase, n.dir === "." ? "" : n.dir, n.label, text.get(n.key)!] as const;
  const before = (a: Node, b: Node) => {
    const x = rank(a);
    const y = rank(b);
    for (let i = 0; i < x.length; i++) if (x[i] !== y[i]) return x[i] < y[i] ? -1 : 1;
    return 0;
  };
  const sorted = [...live].sort(before);
  const out: Node[] = [];
  const done = new Set<string>();
  while (out.length < live.length) {
    const next = sorted.find((n) => !done.has(n.key) && indegree.get(n.key) === 0) ?? sorted.find((n) => !done.has(n.key))!;
    out.push(next);
    done.add(next.key);
    for (const to of edges.get(next.key) ?? []) if (indegree.has(to)) indegree.set(to, indegree.get(to)! - 1);
  }
  return out.map((n) => ({ dir: n.dir, run: text.get(n.key)!, fixes: n.fixes }));
}

function dirWords(dir: string): string {
  return dir === "." ? "the project root" : unsafeDirLabel(dir);
}

function andList(items: string[]): string {
  return items.length <= 1 ? items.join("") : `${items.slice(0, -1).join(", ")} and ${items[items.length - 1]}`;
}

export interface SequenceContext {
  totalRows: number;
  heldUnclean: (row: SequencedRow) => boolean;
  /** The Go release reader (each release's own go.mod), for one `go get` per module directory. */
  goSource?: Pick<ReleaseMetadataSource, "getRequirements"> | null;
  peers?: PeerContext;
  /** RunOrderOptions.declaredOperator. */
  declaredOperator?: RunOrderOptions["declaredOperator"];
  /** RunOrderOptions.withheldSteps. */
  withheldSteps?: RunOrderOptions["withheldSteps"];
  /** Time the go.mod reads may take. */
  budgetMs: number;
}

/** At most this many go.mod files are read per plan to combine its `go get` targets. */
const MAX_GO_MOD_READS = 24;

/**
 * What each `go get` target's own go.mod requires, for the module directories where the plan names
 * more than one module (one is never combined with anything). The reads go through the Go release
 * reader's cache and rate limit, and the private-name guard every release read runs under.
 */
async function goRequirements(rows: SequencedRow[], source: SequenceContext["goSource"], deadline: number): Promise<RunOrderOptions["goRequires"]> {
  if (!source?.getRequirements) return undefined;
  const perDir = new Map<string, Set<string>>();
  for (const r of rows) {
    if (!FIX_ACTIONS.has(r.action)) continue;
    for (const c of r.commands) {
      const p = parseCommand(c.run);
      if (p.kind !== "goget") continue;
      const set = perDir.get(c.dir) ?? new Set<string>();
      for (const m of p.mods) set.add(`${m.module}@${m.version}`);
      perDir.set(c.dir, set);
    }
  }
  const wanted = [...new Set([...perDir.values()].filter((s) => new Set([...s].map((x) => x.slice(0, x.lastIndexOf("@")))).size > 1).flatMap((s) => [...s]))].sort().slice(0, MAX_GO_MOD_READS);
  if (wanted.length === 0) return undefined;
  const read = new Map<string, Map<string, string> | null>();
  await Promise.all(
    wanted.map(async (key) => {
      const at = key.lastIndexOf("@");
      const left = deadline - Date.now();
      if (left <= 0) return void read.set(key, null);
      let timer: ReturnType<typeof setTimeout> | undefined;
      const late = new Promise<null>((resolve) => (timer = setTimeout(() => resolve(null), left)));
      const answer = await Promise.race([source.getRequirements!(key.slice(0, at), key.slice(at + 1)).catch(() => null), late]);
      if (timer !== undefined) clearTimeout(timer);
      read.set(key, answer && answer.status === "ok" ? new Map(answer.data.requirements.map((q) => [q.name, q.spec.startsWith("v") ? q.spec : `v${q.spec}`])) : null);
    }),
  );
  return (module, version) => read.get(`${module}@${version}`);
}

/**
 * run_order for the rows the plan returns, with the go.mod reads it needs; a row left out for a peer
 * range says so in its reasons, as rule (e) asks.
 */
export async function sequencePlan(rows: SequencedRow[], ctx: SequenceContext): Promise<{ run_order: RunOrderStep[]; run_order_note: string }> {
  const goRequires = await goRequirements(rows, ctx.goSource, Date.now() + ctx.budgetMs);
  const result = buildRunOrder({ rows, totalRows: ctx.totalRows, heldUnclean: ctx.heldUnclean, goRequires, peerConflict: ctx.peers ? peerConflictReader(ctx.peers) : undefined, declaredOperator: ctx.declaredOperator, withheldSteps: ctx.withheldSteps });
  for (const [row, why] of result.peerBlocked) if (!row.reasons.includes(why)) row.reasons.push(why);
  return { run_order: result.run_order, run_order_note: result.run_order_note };
}

/** At most this many copies are named per group in the note; the rest are counted. */
const NAMED_PER_GROUP = 6;
/** At most this many merge and Go notes are spelled out; the rest are counted. */
const MAX_NOTES = 12;

function named(rows: SequencedRow[]): string {
  const shown = rows.slice(0, NAMED_PER_GROUP).map(copyOf);
  return `${shown.join(", ")}${rows.length > NAMED_PER_GROUP ? ` and ${rows.length - NAMED_PER_GROUP} more` : ""}`;
}

/** What the script covers (the rows shown that a command fixes here) and what it leaves out, by why. */
function runOrderNote(opts: RunOrderOptions, runnable: SequencedRow[], peerBlocked: Map<SequencedRow, string>, steps: number, notes: string[]): string {
  const ran = runnable.filter((r) => !peerBlocked.has(r));
  const parts: string[] = [];
  const shown = opts.rows.length;
  parts.push(
    steps === 0
      ? `run_order is empty: none of the ${shown} row${shown === 1 ? "" : "s"} shown is fixed on this host by a command`
      : `run_order is ${steps} step${steps === 1 ? "" : "s"} for ${ran.length} of the ${shown} row${shown === 1 ? "" : "s"} shown, in an order that is safe to run from the first step to the last (no step lowers a version that is installed or that an earlier step sets), each in the directory it names: upgrades first, then in-range refreshes (which never lower what an upgrade set), and every parent upgrade before the refreshes that follow it`,
  );
  // The order is checked, and each upgraded release's first-level dependencies; nothing deeper.
  // held-second-level.ts: an npm target's dependencies' exact pins are judged; nothing deeper is.
  if (steps > 0) parts.push("An upgraded package's own dependencies are checked one level down, and on npm their exact pins two levels down; a range at that level, anything deeper and a copy bundled inside a package are not, so run vulnerability_scan again after running it");
  if (opts.totalRows > shown) parts.push(`it covers only the rows shown, not the other ${opts.totalRows - shown} (raise max_recommendations for them)`);
  const forced = ran.filter((r) => overrideCommandsOf(r).length > 0);
  if (forced.length > 0) parts.push(`${forced.length} of them force a version with an override or resolution written by \`npm pkg set\` (${named(forced)}): it applies to every copy its key names, so re-scan after running`);
  const inScript = new Set(runnable);
  const withheld = (r: SequencedRow) => opts.withheldSteps?.(r) ?? 0;
  // Steps that would run in a directory whose name is not safe in a command are withheld; the
  // row's steps elsewhere stay in the script (audit 2026-11-25 blind check: one odd directory
  // emptied run_order for the whole package).
  const partly = ran.filter((r) => withheld(r) > 0);
  const withheldTotal = opts.rows.reduce((n, r) => n + withheld(r), 0);
  if (withheldTotal > 0) {
    const one = withheldTotal === 1;
    const tail = partly.length > 0 ? `; ${partly.length} row${partly.length === 1 ? " is" : "s are"} here only for ${partly.length === 1 ? "its" : "their"} other directories and ${partly.length === 1 ? "is" : "are"} not counted as fixed (${named(partly)})` : "";
    parts.push(`${withheldTotal} step${one ? " was" : "s were"} withheld because ${one ? "it" : "they"} would run in a directory whose name is not safe to put in a command (it holds characters a shell reads as code; the rows' reasons name it, escaped): do ${one ? "it" : "them"} by hand${tail}`);
  }
  const unsafe = opts.rows.filter((r) => withheld(r) > 0 && !inScript.has(r));
  // Each row is named once, in the first group that holds it: one with every step withheld there.
  const rows = opts.rows.filter((r) => !unsafe.includes(r));
  const eligible = (r: SequencedRow) => !inScript.has(r) && !opts.heldUnclean(r) && (FIX_ACTIONS.has(r.action) || r.action === "override_or_replace") && (r.action !== "upgrade_direct" || r.targetVersion !== null);
  const hand = rows.filter((r) => eligible(r) && isHandEdit(r));
  // The script alone does not finish the job: what is left to edit by hand is counted and named.
  if (hand.length > 0) parts.push(`${hand.length} row${hand.length === 1 ? " is a hand edit" : "s are hand edits"} and ${hand.length === 1 ? "is" : "are"} not in this script: ${named(hand)} (a manifest or lockfile edit, or an override that crosses a major; ${hand.length === 1 ? "its reasons say" : "their reasons say"} what to edit)`);
  const groups: Array<[string, SequencedRow[]]> = [
    ["have their steps in a directory whose name is not safe to put in a command (handled by hand; their reasons name it, escaped)", unsafe],
    ["name no command for their fix (their reasons say why)", rows.filter((r) => eligible(r) && !isHandEdit(r) && r.action !== "override_or_replace")],
    ["name no confirmed target (NOT CHECKED; their reasons say why)", rows.filter((r) => r.action === "upgrade_direct" && r.targetVersion === null && !opts.heldUnclean(r))],
    ["have a target that is NOT a clean fix (it holds an affected dependency; see their reasons)", rows.filter((r) => FIX_ACTIONS.has(r.action) && opts.heldUnclean(r))],
    ["are not counted as fixed by their commands (override_or_replace, upgrade_parent_unverified: check their reasons first)", rows.filter((r) => (r.action === "override_or_replace" && !inScript.has(r) && !hand.includes(r)) || r.action === "upgrade_parent_unverified")],
    ["apply where the code is built, not on this host (not_built_on_this_host)", rows.filter((r) => r.action === "not_built_on_this_host")],
    [
      "have nothing to run (waiting on upstream, no fix, not determined, not checked, hold, or remove)",
      rows.filter((r) => !FIX_ACTIONS.has(r.action) && !["override_or_replace", "upgrade_parent_unverified", "not_built_on_this_host"].includes(r.action)),
    ],
    ["break a peer range an installed dependency declares (their reasons say which and what to upgrade with them)", [...peerBlocked.keys()]],
  ];
  const left = groups.filter(([, rows]) => rows.length > 0).map(([why, rows]) => `${rows.length} that ${why}: ${named(rows)}`);
  if (left.length > 0) parts.push(`Left out: ${left.join("; ")}`);
  const said = [...new Set(notes)];
  pushAll(parts, said.slice(0, MAX_NOTES));
  if (said.length > MAX_NOTES) parts.push(`and ${said.length - MAX_NOTES} more such notes`);
  return `${parts.join(". ")}.`;
}
