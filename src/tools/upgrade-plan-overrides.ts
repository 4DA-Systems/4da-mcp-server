// SPDX-License-Identifier: Apache-2.0
/**
 * An override (npm `overrides`, pnpm `pnpm.overrides`, Yarn and Bun `resolutions` / `overrides`)
 * as commands, where a plain command writes exactly the snippet the row's words give:
 * `npm pkg set "overrides.<name>=<version>"` (npm 7.24+ edits package.json and nothing else), then
 * the install that applies it, in the directory of the lockfile it is for. The snippet's own scope
 * is kept (npm `parent.name`, pnpm `parent>name`, Yarn classic `parent/name`).
 *
 * None is given, and the override stays a hand step, when the key could not be written as a path
 * (`npm pkg set` reads `.` as nesting, so a name with a dot is not one), when package.json already
 * has an entry the new one would collide with, or when the snippet forces every copy across lines
 * the lockfile holds (Yarn Berry and Bun cannot scope one).
 */

import * as fs from "node:fs";
import * as path from "node:path";
import type { LockfileFormat } from "../live/lockfile-parents.js";
import { isShellSafeName, isShellSafeVersion } from "../live/shell-safe.js";

export interface OverrideCommand {
  dir: string;
  command: string;
}

const COMMANDS = new WeakMap<object, OverrideCommand[]>();

/** The commands recorded for a row's override snippet; empty when none could be written. */
export function overrideCommandsOf(row: object): OverrideCommand[] {
  return COMMANDS.get(row) ?? [];
}

/** The entry at `keys` of `dir`/package.json: "absent", "object", or "value" (a string or anything else). */
function entryAt(dir: string, keys: string[]): "absent" | "object" | "value" | "unreadable" {
  let node: unknown;
  try {
    node = JSON.parse(fs.readFileSync(path.join(dir, "package.json"), "utf-8"));
  } catch {
    return "unreadable";
  }
  for (const k of keys) {
    if (node === null || typeof node !== "object" || Array.isArray(node)) return "value";
    if (!(k in (node as Record<string, unknown>))) return "absent";
    node = (node as Record<string, unknown>)[k];
  }
  return node !== null && typeof node === "object" && !Array.isArray(node) ? "object" : "value";
}

/** One override's commands for one lockfile directory; null when it is not written as commands. */
function commandsFor(format: LockfileFormat, root: string, dir: string, name: string, target: string, parents: string[] | null): OverrideCommand[] | null {
  const plain = (n: string) => isShellSafeName(n, "npm") && !n.includes(".");
  if (!plain(name) || !isShellSafeVersion(target) || (parents && !parents.every(plain))) return null;
  const abs = path.resolve(root, dir);
  const paths: string[][] =
    format === "package-lock"
      ? parents
        ? parents.map((p) => ["overrides", p, name])
        : [["overrides", name]]
      : format === "pnpm"
        ? (parents ?? [null]).map((p) => ["pnpm", "overrides", p ? `${p}>${name}` : name])
        : format === "yarn"
          ? (parents ?? [null]).map((p) => ["resolutions", p ? `${p}/${name}` : name])
          : format === "yarn-berry" && !parents
            ? [["resolutions", name]]
            : format === "bun" && !parents
              ? [["overrides", name]]
              : [];
  if (paths.length === 0) return null;
  // Every key above the new one is an object or absent, and the new one is not there yet.
  for (const keys of paths) {
    if (entryAt(abs, keys) !== "absent") return null;
    for (let i = 1; i < keys.length; i++) if (!["absent", "object"].includes(entryAt(abs, keys.slice(0, i)))) return null;
  }
  // pnpm 10 reads overrides from pnpm-workspace.yaml first: there the snippet is a hand edit.
  if (format === "pnpm" && fs.existsSync(path.join(abs, "pnpm-workspace.yaml")) && /^overrides:/m.test(fs.readFileSync(path.join(abs, "pnpm-workspace.yaml"), "utf-8"))) return null;
  const install = format === "package-lock" ? "npm install" : format === "pnpm" ? "pnpm install" : format === "bun" ? "bun install" : "yarn install";
  return [...paths.map((keys) => ({ dir, command: `npm pkg set "${keys.join(".")}=${target}"` })), { dir, command: install }];
}

/**
 * Record a row's override snippet as commands, one set per lockfile it names (each in that
 * lockfile's directory, relative to `root`); `parents` is the snippet's scope, null for a bare entry.
 * Nothing is recorded unless every lockfile's snippet could be written.
 */
export function recordOverrideCommands(row: object, lockfiles: Array<{ format: LockfileFormat; dir: string }>, root: string, name: string, target: string, parents: string[] | null): void {
  const out: OverrideCommand[] = [];
  for (const l of lockfiles) {
    const cmds = commandsFor(l.format, root, l.dir, name, target, parents);
    if (!cmds) {
      COMMANDS.delete(row);
      return;
    }
    for (const c of cmds) if (!out.some((x) => x.dir === c.dir && x.command === c.command)) out.push(c);
  }
  if (out.length > 0) COMMANDS.set(row, out);
  else COMMANDS.delete(row);
}

/** Carry a draft row's recorded commands to the row it is committed to (the planner verifies rows on drafts). */
export function carryOverrideCommands(from: object, to: object): void {
  const cmds = COMMANDS.get(from);
  if (cmds) COMMANDS.set(to, cmds);
  else COMMANDS.delete(to);
}
