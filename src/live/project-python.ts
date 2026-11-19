// SPDX-License-Identifier: Apache-2.0
/**
 * The Python versions a project says it supports, and whether a PyPI release supports all of them.
 *
 * Read at the project root; the first file that declares one wins: pyproject.toml
 * `[project] requires-python`, poetry's `[tool.poetry.dependencies] python`, uv.lock's
 * `requires-python`, Pipfile `[requires]` (`python_full_version`, then `python_version`),
 * `.python-version` (its first version line), `runtime.txt` (`python-X.Y[.Z]`). A project that
 * declares none, or one that does not read as a version specifier, gets null and nothing is judged
 * against it: a Python version is never assumed.
 *
 * A release supports the project when its `requires_python` admits every Python the declaration
 * covers: the lowest version declared, and each later 3.x minor up to the declared upper bound (or
 * up to NEWEST_PYTHON_MINOR when there is none). A lock for the whole project (uv, poetry) holds a
 * release to that: `uv lock` for `requires-python >=3.9` refuses requests 2.33.0 (Python>=3.10).
 */

import * as path from "node:path";
import { lowestPython, poetryToPep440, pythonSpecAdmits } from "./pygo-parents.js";
import { readTextFile } from "./text-file.js";

/** The newest CPython 3.x minor with a final release: an open upper bound is checked up to it. */
export const NEWEST_PYTHON_MINOR = 14;

export interface ProjectPython {
  /** The declaration as the file writes it (version characters and operators only). */
  declared: string;
  /** The same in PEP 440. */
  spec: string;
  /** Where it was read, e.g. "pyproject.toml [project] requires-python". */
  source: string;
  /** The Python versions a release must support, lowest first. */
  covers: string[];
}

/** A release's Python requirement as the registry reader keeps it (ReleaseRecord). */
export interface ReleasePythonFacts {
  /** PEP 440; null when the release declares none (it supports any). Undefined: not read. */
  requiresPython?: string | null;
  /** The release declares one that does not read as a specifier. */
  requiresPythonUnreadable?: true;
}

export type PythonSupport =
  | { status: "supported" }
  | { status: "unsupported"; requires: string; missing: string[] }
  | { status: "unread"; why: string };

/** Characters a declaration may hold to be read (and printed) at all. */
const DECLARATION = /^[0-9A-Za-z.,*!<>=~^ _-]{1,120}$/;

/** The project's declared Python, or null when it declares none that can be read. */
export function readProjectPython(root: string): ProjectPython | null {
  for (const read of [fromPyproject, fromUvLock, fromPipfile, fromPythonVersion, fromRuntimeTxt]) {
    const found = read(root);
    if (found === undefined) continue;
    if (found === null) return null;
    const covers = coveredPythons(found.spec);
    return covers ? { ...found, covers } : null;
  }
  return null;
}

/** Whether `release` supports every Python the project declares. */
export function releasePythonSupport(project: ProjectPython, release: ReleasePythonFacts | undefined): PythonSupport {
  if (!release || release.requiresPython === undefined) return { status: "unread", why: "the Python versions it supports were not read from PyPI" };
  if (release.requiresPythonUnreadable) return { status: "unread", why: "the Python requirement PyPI lists for it does not read as a version specifier" };
  if (release.requiresPython === null) return { status: "supported" };
  const answers = project.covers.map((p) => [p, pythonSpecAdmits(release.requiresPython!, p)] as const);
  if (answers.some(([, a]) => a === null)) return { status: "unread", why: "the Python requirement PyPI lists for it does not read as a version specifier" };
  const missing = answers.filter(([, a]) => a === false).map(([p]) => p);
  return missing.length === 0 ? { status: "supported" } : { status: "unsupported", requires: release.requiresPython, missing };
}

/** Each clause of a PEP 440 specifier set reads (pep440SpecAdmits stops at the first false clause). */
export function readsAsPythonSpec(spec: string): boolean {
  const clauses = spec.split(",").filter((c) => c.trim() !== "");
  return clauses.length > 0 && clauses.every((c) => pythonSpecAdmits(c, "3.0") !== null);
}

type Found = { declared: string; spec: string; source: string } | null | undefined;

/** A declaration read from `source`: null when it is there but cannot be read (nothing is judged then). */
function declaration(raw: string, spec: string | null, source: string): Found {
  const declared = raw.trim();
  if (!DECLARATION.test(declared) || spec === null || !readsAsPythonSpec(spec)) return null;
  return { declared, spec, source };
}

function read(root: string, name: string): string | null {
  try {
    return readTextFile(path.join(root, name)).replace(/\r\n?/g, "\n");
  } catch {
    return null;
  }
}

/** TOML table headers (`[a.b]`, `[[a]]`), with where each starts. */
const HEADER = /^[ \t]*(\[\[?)[ \t]*([A-Za-z0-9_.\-" ]+?)[ \t]*\]\]?[ \t]*(?:#.*)?$/gm;

/** The body of TOML table `[name]` up to the next header; for "" the lines before the first header. */
function tomlTable(content: string, name: string): string | null {
  const headers = [...content.matchAll(HEADER)];
  if (name === "") return content.slice(0, headers[0]?.index ?? content.length);
  const at = headers.findIndex((h) => h[1] === "[" && h[2].replace(/["\s]/g, "") === name);
  if (at < 0) return null;
  return content.slice(headers[at].index! + headers[at][0].length, headers[at + 1]?.index ?? content.length);
}

/** A one-line basic or literal string value of `key` in a table body. */
function tomlString(table: string, key: string): string | null {
  for (const line of table.split("\n")) {
    const m = /^[ \t]*"?([A-Za-z0-9_-]+)"?[ \t]*=[ \t]*(?:"([^"\\\n]*)"|'([^'\n]*)')[ \t]*(?:#.*)?$/.exec(line);
    if (m && m[1] === key) return m[2] ?? m[3] ?? null;
  }
  return null;
}

function fromPyproject(root: string): Found {
  const content = read(root, "pyproject.toml");
  if (content === null) return undefined;
  const project = tomlTable(content, "project");
  const requires = project === null ? null : tomlString(project, "requires-python");
  if (requires !== null) return declaration(requires, requires.replace(/\s+/g, ""), "pyproject.toml [project] requires-python");
  const poetry = tomlTable(content, "tool.poetry.dependencies");
  const python = poetry === null ? null : tomlString(poetry, "python");
  if (python !== null) return declaration(python, poetryToPep440(python), "pyproject.toml [tool.poetry.dependencies] python");
  return undefined;
}

function fromUvLock(root: string): Found {
  const content = read(root, "uv.lock");
  const requires = content === null ? null : tomlString(tomlTable(content, "")!, "requires-python");
  return requires === null ? undefined : declaration(requires, requires.replace(/\s+/g, ""), "uv.lock requires-python");
}

/** A bare X.Y as the series (`==X.Y.*`), X.Y.Z as that release. */
function bareVersion(raw: string): string | null {
  const m = /^(\d+)\.(\d+)(?:\.(\d+))?$/.exec(raw.trim());
  return m ? (m[3] === undefined ? `==${m[1]}.${m[2]}.*` : `==${m[1]}.${m[2]}.${m[3]}`) : null;
}

function fromPipfile(root: string): Found {
  const content = read(root, "Pipfile");
  const table = content === null ? null : tomlTable(content, "requires");
  if (table === null) return undefined;
  const full = tomlString(table, "python_full_version");
  if (full !== null) return declaration(full, bareVersion(full), "Pipfile [requires] python_full_version");
  const minor = tomlString(table, "python_version");
  return minor === null ? undefined : declaration(minor, bareVersion(minor), "Pipfile [requires] python_version");
}

function fromPythonVersion(root: string): Found {
  const content = read(root, ".python-version");
  if (content === null) return undefined;
  const line = content.split("\n").map((l) => l.trim()).find((l) => l !== "" && !l.startsWith("#"));
  if (line === undefined) return undefined;
  // "3.12", "3.12.1", "cpython-3.12.1", "3.13t"; a PyPy or "system" line names no CPython version.
  const m = /^(?:cpython-?|python-?)?(\d+\.\d+(?:\.\d+)?)(?![\d.])/i.exec(line);
  return m ? declaration(m[1], bareVersion(m[1]), ".python-version") : null;
}

function fromRuntimeTxt(root: string): Found {
  const content = read(root, "runtime.txt");
  if (content === null) return undefined;
  const m = /^\s*python-(\d+\.\d+(?:\.\d+)?)\s*$/.exec(content.split("\n")[0] ?? "");
  return m ? declaration(m[1], bareVersion(m[1]), "runtime.txt") : null;
}

/**
 * The Python versions a declaration covers: its lowest, then each later 3.x minor up to its upper
 * bound (NEWEST_PYTHON_MINOR when it has none), as far as it admits them. Null without a lower bound.
 */
export function coveredPythons(spec: string): string[] | null {
  const low = lowestPython(spec);
  if (!low) return null;
  const [major, minor] = low.split(".").map(Number);
  if (!Number.isInteger(major)) return null;
  const top = upperMinor(spec);
  const points = [low];
  const first = major === 3 ? (Number.isInteger(minor) ? minor : 0) + 1 : major < 3 ? 0 : top + 1;
  for (let m = first; m <= top; m++) points.push(`3.${m}`);
  const admitted = points.filter((p) => pythonSpecAdmits(spec, p) === true);
  return admitted.length > 0 ? admitted : null;
}

/** The highest 3.x minor a specifier's upper bounds leave in. */
function upperMinor(spec: string): number {
  let top = NEWEST_PYTHON_MINOR;
  for (const clause of spec.split(",")) {
    const m = /^(<=|<|==|~=)(\d+)(?:\.(\d+))?(?:\.(\d+|\*))?$/.exec(clause.trim());
    if (!m) continue;
    const [, op, majorText, minorText, patch] = m;
    const major = Number(majorText);
    const minor = minorText === undefined ? null : Number(minorText);
    if (major > 3) continue;
    let bound: number | null;
    if (major < 3) bound = -1;
    else if (op === "<") bound = minor === null ? -1 : patch !== undefined && patch !== "*" && Number(patch) > 0 ? minor : minor - 1;
    else if (op === "~=") bound = patch !== undefined && minor !== null ? minor : null;
    else bound = minor;
    if (bound !== null && bound < top) top = bound;
  }
  return top;
}
