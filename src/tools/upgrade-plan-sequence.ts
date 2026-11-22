// SPDX-License-Identifier: Apache-2.0
/**
 * The plan as data: every command a row tells the developer to run, as `{ dir, run }`.
 *
 * `commands` is taken from the same row fields the row's sentences are built from (the direct
 * upgrade, the lockfile refresh, the parent's levers and the refresh after them, the reinstall, a
 * compiled requirements file's re-compile), after every pass that rewrites them, so the data and
 * the words never disagree. `dir` is project-relative, "." for the root. A compound command is one
 * entry per command, in order. A step the developer does by hand (deleting yarn.lock or bun.lock
 * entries, adding an override, editing a manifest) is not a command: it stays in the row's
 * reasons and `upgradeInstructions`, and `commands` holds only what can be run.
 */

import * as path from "node:path";
import { pypiCompileCommand } from "../live/pypi-advice.js";

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
    if (isManualStep(command)) return;
    for (const run of splitCompound(command)) if (!out.some((c) => c.dir === dir && c.run === run)) out.push({ dir, run });
  };
  for (const c of row.upgradeCommands ?? []) add(c.dir, c.command);
  for (const u of row.parentUpgrades ?? []) for (const l of u.levers) for (const c of l.commands ?? []) add(c.dir, c.command);
  for (const u of row.parentUpgrades ?? []) for (const c of u.refreshCommands ?? []) add(c.dir, c.command);
  for (const c of row.refreshCommands ?? []) add(c.dir, c.command);
  for (const c of compiledCommands(row, ctx.root)) add(c.dir, c.command);
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
