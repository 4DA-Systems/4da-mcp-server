// SPDX-License-Identifier: Apache-2.0
/**
 * What a pyproject.toml's Poetry dependency tables declare (`[tool.poetry.dependencies]`,
 * `[tool.poetry.dev-dependencies]`, `[tool.poetry.group.<name>.dependencies]`), written as PEP 508
 * requirement strings, so a project with no poetry.lock is read by the rules `[project]
 * dependencies` are (lockfile-parsers-pygo.ts pyprojectPins):
 * - A bare version (`requests = "2.31.0"`), `==2.31.0` or `=2.31.0` is Poetry's exact constraint:
 *   `requests==2.31.0`, a pin. So is the `version` of an inline table (extras, markers kept out).
 * - Every other constraint (`^`, `~`, `>=,<`, `!=`, `*`, `2.31.*`, `||`, or several constraints in
 *   an array) names no installed version: the bare name, listed as unpinned and never sent.
 * - `{ git = ... }`, `{ url = ... }` and `{ path = ... }` are direct references (`name @ <location>`):
 *   not registry releases, and a local path is the project's own code.
 * - `python` is the project's Python, not a package.
 * The lines are read with the TOML helpers pyprojectManifestPrivate reads them with, so every name
 * pinned here is one the private-source rules (`source = "<private index>"`) also judged. A dotted
 * table (`[tool.poetry.dependencies.requests]`) is neither's, and is not read as a pin.
 */

import { inlineKey, tomlHeader, tomlKeyValue, tomlLines, tomlString } from "./private-hosts.js";

/** The tables pyprojectManifestPrivate reads Poetry dependencies from. */
const POETRY_TABLE = /^tool\.poetry\.(?:dependencies|dev-dependencies|group\.[^.]+\.dependencies)$/;
/** Poetry's exact constraint: a version with no operator, `==` or `=`; no wildcard. */
const EXACT = /^(?:==?)?\s*(\d[0-9A-Za-z.+!-]*)$/;
const NAME = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;

export interface PoetryRequirement {
  /** A PEP 508 requirement string: `requests==2.31.0`, `flask`, `gitpkg @ git+https://...`. */
  text: string;
  /** Declared in a dev table or a dependency group, not `[tool.poetry.dependencies]`. */
  dev: boolean;
}

export function poetryRequirements(content: string): PoetryRequirement[] {
  const out: PoetryRequirement[] = [];
  let table = "";
  for (const line of tomlLines(content)) {
    const header = tomlHeader(line);
    if (header) {
      table = header.array ? "" : header.name;
      continue;
    }
    if (!POETRY_TABLE.test(table)) continue;
    const kv = tomlKeyValue(line);
    if (!kv || !NAME.test(kv.key) || kv.key.toLowerCase() === "python") continue;
    out.push({ text: requirementText(kv.key, kv.value), dev: table !== "tool.poetry.dependencies" });
  }
  return out;
}

/** Inline-table keys that do not restrict where a Poetry dependency is installed: such a dependency is always locked. */
const UNRESTRICTED_KEYS = new Set(["version", "extras", "optional", "source", "allow-prereleases", "allows-prereleases"]);

/** The keys of a TOML inline table (`{ version = "1", markers = "..." }`); a string that looks like `, key =` only adds a key, so it errs toward "restricted". */
export function inlineTableKeys(table: string): string[] {
  return [...table.matchAll(/(?:^\{|,)\s*("(?:[^"\\]|\\.)*"|'[^']*'|[A-Za-z0-9_-]+)\s*=/g)].map((m) => m[1].replace(/^["']|["']$/g, ""));
}

/**
 * The names Poetry always writes a poetry.lock entry for (audit 2026-11-25, F1): every dependency
 * of `[tool.poetry.dependencies]`, the dev table and every group, `python` excepted, whose
 * constraint is a string or an inline table that does not restrict it (no `markers`, `python`,
 * `platform`) and that is a registry package (no `git`, `path`, `url`, `file`). Optional ones are
 * locked too (every extra is). An array of constraints, or a dotted table, is not compared. Names
 * as written; the caller normalises them.
 */
export function poetryLockedNames(content: string): string[] {
  const out: string[] = [];
  let table = "";
  for (const line of tomlLines(content)) {
    const header = tomlHeader(line);
    if (header) {
      table = header.array ? "" : header.name;
      continue;
    }
    if (!POETRY_TABLE.test(table)) continue;
    const kv = tomlKeyValue(line);
    if (!kv || !NAME.test(kv.key) || kv.key.toLowerCase() === "python") continue;
    if (kv.value.startsWith("{")) {
      if (inlineTableKeys(kv.value).every((key) => UNRESTRICTED_KEYS.has(key))) out.push(kv.key);
    } else if (tomlString(kv.value) !== null) out.push(kv.key);
  }
  return out;
}

function requirementText(name: string, value: string): string {
  if (value.startsWith("{")) {
    const git = inlineKey(value, "git");
    if (git !== null) return `${name} @ ${/^git\+/i.test(git) ? git : `git+${git}`}`;
    const url = inlineKey(value, "url");
    if (url !== null) return `${name} @ ${url}`;
    const local = inlineKey(value, "path") ?? inlineKey(value, "file");
    if (local !== null) return `${name} @ file:${local}`;
    const version = inlineKey(value, "version");
    return version === null ? name : constraint(name, version);
  }
  // An array holds several constraints (per Python, per platform): no one release is installed.
  if (value.startsWith("[")) return name;
  const version = tomlString(value);
  return version === null ? name : constraint(name, version);
}

function constraint(name: string, version: string): string {
  const exact = EXACT.exec(version.trim());
  return exact ? `${name}==${exact[1]}` : name;
}
