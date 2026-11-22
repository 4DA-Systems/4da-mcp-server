// SPDX-License-Identifier: Apache-2.0
/**
 * The fix for a PyPI dependency a uv project declares, read from its uv.lock.
 *
 * uv.lock records what the project itself requires: the root package's `[package.metadata]
 * requires-dist` and `[package.metadata.requires-dev]` (the `[tool.uv] dev-dependencies` and
 * `[dependency-groups]` entries), each with its specifier. When every requirement on the package
 * admits the target, `uv lock --upgrade-package <name>==<target>` moves the lock to exactly that
 * release and leaves pyproject.toml as it is (uv's documented form for upgrading one package to
 * a given version; plain `--upgrade-package <name>` resolves to the newest release the other
 * locked versions allow, which stopped short of the fix for virtualenv). When one excludes it,
 * the requirement has to be widened first, which is a manifest edit, said as one.
 *
 * Nothing is named when the lockfile is not beside the manifest (a workspace member), the root
 * package or its requirement on the package cannot be read, or a value is not a plain token.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { pushAll } from "../array-utils.js";
import { normalizePythonName } from "./lockfile-parsers-pygo.js";
import { pythonSpecAdmits } from "./pygo-parents.js";
import { isShellSafeName, isShellSafeVersion } from "./shell-safe.js";
import { readTextFile } from "./text-file.js";

export type PyprojectFix = { command: string; refresh: true } | { instruction: string };

/** One requirement the project puts on a package, as uv.lock records it. */
interface UvRequirement {
  specifier: string;
  /** "[project] dependencies", or the dependency group it is listed under. */
  where: string;
}

/** The `[[package]]` block of the project itself (`source = { editable = "." }` or `{ virtual = "." }`). */
function rootBlock(content: string): string | null {
  for (const block of content.split(/^\[\[package\]\]\s*$/m).slice(1)) {
    const head = block.split(/^\[/m)[0];
    if (/^source\s*=\s*\{\s*(?:editable|virtual)\s*=\s*"\."\s*\}/m.test(head)) return block;
  }
  return null;
}

/** The text of one sub-table of a package block (`[package.metadata]`), up to the next header. */
function subTable(block: string, header: string): string | null {
  const at = block.search(new RegExp(`^\\[${header.replace(/\./g, "\\.")}\\][ \\t]*$`, "m"));
  if (at < 0) return null;
  const rest = block.slice(at).replace(/^[^\n]*\n/, "");
  const end = rest.search(/^\[/m);
  return end < 0 ? rest : rest.slice(0, end);
}

/** `{ name = "x", specifier = "..." }` entries of `name` in a TOML text; null when one names it without a specifier. */
function entriesOf(text: string, name: string, where: string): UvRequirement[] | null {
  const want = normalizePythonName(name);
  const out: UvRequirement[] = [];
  for (const m of text.matchAll(/\{\s*name\s*=\s*"([^"]+)"([^}]*)\}/g)) {
    if (normalizePythonName(m[1]) !== want) continue;
    const specifier = /\bspecifier\s*=\s*"([^"]*)"/.exec(m[2])?.[1];
    if (specifier === undefined) return null;
    out.push({ specifier, where });
  }
  return out;
}

/** What the project at `projectDir` requires of `name`, from its uv.lock; null when that cannot be read. */
function uvRequirements(projectDir: string, name: string): UvRequirement[] | null {
  let content: string;
  try {
    content = readTextFile(path.join(projectDir, "uv.lock"));
  } catch {
    return null;
  }
  const root = rootBlock(content);
  if (!root) return null;
  const out: UvRequirement[] = [];
  const dist = subTable(root, "package.metadata");
  if (dist !== null) {
    // An older uv writes the development requirements inline, after `requires-dev =`.
    const [own, inlineDev = ""] = dist.split(/^requires-dev\s*=/m);
    const found = entriesOf(own, name, "[project] dependencies");
    const foundDev = entriesOf(inlineDev, name, "a development dependency group");
    if (found === null || foundDev === null) return null;
    pushAll(out, found);
    pushAll(out, foundDev);
  }
  const dev = subTable(root, "package.metadata.requires-dev");
  if (dev !== null) {
    for (const group of arrays(dev)) {
      const found = entriesOf(group.body, name, `the "${group.key}" dependency group`);
      if (found === null) return null;
      pushAll(out, found);
    }
  }
  return out;
}

/** Each `key = [ ... ]` of a TOML table text, on one line or over several (inner brackets matched). */
function arrays(text: string): Array<{ key: string; body: string }> {
  const out: Array<{ key: string; body: string }> = [];
  const open = /^([A-Za-z0-9_.-]+)\s*=\s*\[/gm;
  for (let m = open.exec(text); m !== null; m = open.exec(text)) {
    let depth = 1;
    let i = m.index + m[0].length;
    for (; i < text.length && depth > 0; i++) {
      if (text[i] === "[") depth++;
      else if (text[i] === "]") depth--;
      else if (text[i] === '"') i = Math.max(i, text.indexOf('"', i + 1));
    }
    out.push({ key: m[1], body: text.slice(m.index + m[0].length, i) });
    open.lastIndex = i;
  }
  return out;
}

/** How a direct PyPI row with neither a command nor a manifest edit starts its reason. */
export const PYPI_NO_COMMAND = "No command is named for this upgrade: ";

/** Why no fix could be named for a declared PyPI dependency, in the directories that declare it. */
export function pypiNoCommandReason(dirs: string[], name: string, target: string): string {
  const has = (file: string) => dirs.some((d) => fs.existsSync(path.join(d, file)));
  const why = !has("pyproject.toml")
    ? "no requirements file or pyproject.toml this server reads holds an editable pin for it"
    : has("uv.lock")
      ? "the project's own requirement on it could not be read from uv.lock beside pyproject.toml (or the lockfile sits above, in a workspace root)"
      : has("poetry.lock")
        ? "Poetry's `poetry update` resolves to the newest release the constraint admits, which is not the release checked here"
        : "pyproject.toml has no uv.lock beside it, so what the project's tool resolves is not read here";
  return `${PYPI_NO_COMMAND}${why}. Change the project's requirement on ${name} to admit ${target} where it is declared, then re-lock with the project's tool (uv lock, poetry lock or pip-compile) and confirm ${target} is what it resolves to`;
}

/** The fix for a dependency a uv project declares; null when none can be named with certainty. */
export function pyprojectDirectFix(projectDir: string, name: string, installed: string, target: string): PyprojectFix | null {
  if (!fs.existsSync(path.join(projectDir, "pyproject.toml")) || !fs.existsSync(path.join(projectDir, "uv.lock"))) return null;
  if (!isShellSafeName(name, "PyPI") || !isShellSafeVersion(target)) return null;
  const reqs = uvRequirements(projectDir, name);
  if (!reqs || reqs.length === 0) return null;
  // The locked copy satisfies what the project declares, or the lockfile is not the one read here.
  if (reqs.some((r) => pythonSpecAdmits(r.specifier, installed) !== true)) return null;
  const command = `uv lock --upgrade-package ${name}==${target}`;
  const excluding = reqs.filter((r) => pythonSpecAdmits(r.specifier, target) !== true);
  if (excluding.length === 0) return { command, refresh: true };
  const said = excluding.map((r) => `"${r.specifier || "any version"}" (${r.where})`).join(" and ");
  return {
    instruction: `pyproject.toml requires ${name} ${said}, which excludes ${target}: widen that requirement to admit ${target}, then run \`${command}\``,
  };
}
