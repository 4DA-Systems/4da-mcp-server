// SPDX-License-Identifier: Apache-2.0
/**
 * The step protocol of upgrade_planner's run_order (wave 2, design section 2a): what an agent needs
 * to carry a step out and to undo it, so that the agent closes the loop before a person is asked.
 *
 * - `changes`: the files the step changes, project-relative (the same base as the step's `dir`):
 *   `["Cargo.toml", "Cargo.lock"]` for a `cargo add` at the root, the workspace's `Cargo.lock` for a
 *   `cargo update` in a member. Every step carries it once its package manager is covered here.
 * - `if_it_fails`: only where a failed command can leave a file edited (a `cargo add` writes the
 *   manifest before it resolves, and a resolution error leaves the new requirement in place): how
 *   to put back exactly what the step changed, from the requirement the plan read. Never a blanket
 *   `git checkout`, which would also throw away the steps before it and the developer's own edits.
 *   A step whose command writes nothing when it fails (`cargo update`, `go get`, `uv lock`,
 *   `poetry update`, `uv pip compile`, `pip-compile`) has none.
 * - `after_run` (the plan's): what to do when the steps have run, and what the plan cannot promise.
 *
 * JavaScript steps (npm, pnpm, Yarn, Bun) are filled by lane plan-js through `jsStepProtocol`; until
 * then they carry no `changes`.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { isShellSafeDir, isShellSafeName } from "../live/shell-safe.js";

export interface StepProtocol {
  /** Project-relative files the step changes. */
  changes?: string[];
  /** How to put back what a failed step can leave edited; absent when a failure writes nothing. */
  if_it_fails?: string;
}

/** The plan's closing instruction (`after_run`). */
export const AFTER_RUN =
  "When the steps have run (or one failed and was put back as its if_it_fails says), call vulnerability_scan again: it lists what is left, and upgrade_planner plans from that. " +
  "What this plan cannot promise: the package manager's own resolver picks the versions of the copies no step names (transitive picks, which can bring in a copy with an advisory of its own), a release can need a newer toolchain than the project's (the rows say so where it was read), and a step can fail on what the plan could not read; a failed step means the steps after it run on a tree the plan did not expect, so stop there, put it back, and scan again.";

/** The directory chain from `dir` up to `root` (both absolute), nearest first. */
function upTo(root: string, dir: string): string[] {
  const out: string[] = [];
  let at = path.resolve(dir);
  const top = path.resolve(root);
  const inside = (p: string) => {
    const r = path.relative(top, p);
    return r === "" || (!r.startsWith("..") && !path.isAbsolute(r));
  };
  for (let i = 0; i < 32 && inside(at); i++) {
    out.push(at);
    if (at === top) break;
    const up = path.dirname(at);
    if (up === at) break;
    at = up;
  }
  return out;
}

const rel = (root: string, abs: string) => path.relative(root, abs).replace(/\\/g, "/") || ".";
const joinRel = (dir: string, file: string) => (dir === "." ? file : `${dir}/${file}`);

/** The nearest `file` at or above `dir` (inside `root`), project-relative; else `dir/file`. */
function nearest(root: string, dir: string, file: string): string {
  for (const d of upTo(root, path.resolve(root, dir))) if (fs.existsSync(path.join(d, file))) return rel(root, path.join(d, file));
  return joinRel(dir, file);
}

/** `-o out` / `--output-file out` of a compile command. */
function compileOutput(run: string): string | null {
  return /\s(?:-o|--output-file)\s+(\S+)/.exec(run)?.[1] ?? null;
}

/** `cargo add` arguments the plan writes: the crate, and the section its flags name. */
function cargoAddTarget(run: string): { crate: string; section: string; target: string | null; key: string } | null {
  const m = /^cargo add "?([A-Za-z0-9_-]+)@[^"\s]+"?((?: .+)?)$/.exec(run);
  if (!m) return null;
  const flags = m[2];
  const kind = /(?:^| )--dev(?: |$)/.test(flags) ? "dev-dependencies" : /(?:^| )--build(?: |$)/.test(flags) ? "build-dependencies" : "dependencies";
  const target = /--target "([^"]+)"/.exec(flags)?.[1] ?? null;
  const key = /--rename (\S+)/.exec(flags)?.[1] ?? m[1];
  return { crate: m[1], section: target ? `target.'${target}'.${kind}` : kind, target, key };
}

/** A Cargo version requirement in a plain shape (`0.13`, `^1.2.3`, `=1.6.0`, `>=1, <2`). */
const PLAIN_REQ = /^[0-9A-Za-z.*^~=<>, +-]{1,64}$/;

/**
 * The requirement `key` had in `section` of the manifest the plan read, as the words that put it
 * back; null when it cannot be told exactly (then the step says so instead).
 */
function cargoRestore(manifest: string | null, section: string, key: string): string | null {
  if (manifest === null) return null;
  const want = section.replace(/^target\.'([^']+)'\./, "target.$1.");
  let table: string | null = null;
  for (const raw of manifest.split("\n")) {
    const line = raw.replace(/\r$/, "");
    const head = /^\s*\[([^\]]+)\]\s*(?:#.*)?$/.exec(line);
    if (head) {
      table = head[1].trim().replace(/^target\.(['"])([^'"]+)\1\./, "target.$2.");
      continue;
    }
    if (table === `${want}.${key}`) {
      const v = /^\s*version\s*=\s*"([^"]*)"\s*(?:#.*)?$/.exec(line);
      if (v) return PLAIN_REQ.test(v[1]) ? `set version = "${v[1]}" back in [${section}.${key}]` : null;
      continue;
    }
    if (table !== want) continue;
    const m = /^\s*"?([A-Za-z0-9_-]+)"?\s*=\s*(.*?)\s*(?:#.*)?$/.exec(line);
    if (!m || m[1] !== key) continue;
    const value = m[2];
    const simple = /^"([^"]*)"$/.exec(value);
    if (simple) return PLAIN_REQ.test(simple[1]) ? `set the line back to \`${key} = "${simple[1]}"\` in [${section}]` : null;
    const inline = /\bversion\s*=\s*"([^"]*)"/.exec(value);
    if (value.startsWith("{") && inline) return PLAIN_REQ.test(inline[1]) ? `set version = "${inline[1]}" back in the ${key} entry of [${section}] (the rest of that entry as it was)` : null;
    return null;
  }
  return null;
}

/** Reads a file of the project; null when it cannot be read. */
function readText(file: string): string | null {
  try {
    return fs.readFileSync(file, "utf8");
  } catch {
    return null;
  }
}

/**
 * The protocol fields of one run_order step of a non-JavaScript package manager, or null for a
 * command this module does not cover (JavaScript: jsStepProtocol).
 */
export function stepProtocol(root: string, dir: string, run: string): StepProtocol | null {
  const tool = run.split(" ")[0];
  if (tool === "cargo") {
    const lock = nearest(root, dir, "Cargo.lock");
    if (!run.startsWith("cargo add ")) return { changes: [lock] };
    const add = cargoAddTarget(run);
    const manifest = joinRel(dir, "Cargo.toml");
    const restore = add && isShellSafeName(add.key, "crates.io") ? cargoRestore(readText(path.resolve(root, dir, "Cargo.toml")), add.section, add.key) : null;
    const where = isShellSafeDir(manifest) ? manifest : "the Cargo.toml of this step's directory";
    return {
      changes: [manifest, lock],
      if_it_fails: restore
        ? `cargo add writes ${where} before it resolves, so a failure leaves the new requirement there: ${restore} of ${where}; ${lock} is not written when it fails`
        : `cargo add writes ${where} before it resolves, so a failure leaves the new requirement there: put back the ${add?.key ?? "dependency"} entry as it was before this step (this plan could not quote it exactly); ${lock} is not written when it fails`,
    };
  }
  if (tool === "go") return { changes: [joinRel(dir, "go.mod"), joinRel(dir, "go.sum")] };
  if (tool === "uv" && run.startsWith("uv lock")) return { changes: [nearest(root, dir, "uv.lock")] };
  if (tool === "poetry") return { changes: [joinRel(dir, "poetry.lock")] };
  if (run.startsWith("uv pip compile ") || run.startsWith("pip-compile ")) {
    const out = compileOutput(run);
    return out ? { changes: [joinRel(dir, out)] } : null;
  }
  return null;
}

/** Lane plan-js fills this for npm, pnpm, Yarn and Bun steps; null until then. */
export function jsStepProtocol(_root: string, _dir: string, _run: string): StepProtocol | null {
  return null;
}

/** The protocol fields of any run_order step: non-JavaScript here, JavaScript from jsStepProtocol. */
export function protocolOf(root: string, dir: string, run: string): StepProtocol {
  return stepProtocol(root, dir, run) ?? jsStepProtocol(root, dir, run) ?? {};
}
