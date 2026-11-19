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
 * A declaration that is there but cannot be read is reported as such (readProjectPythonUnread), so
 * an answer says it was not read instead of silently judging nothing.
 *
 * In a repository of several projects, a project's declaration is read in its own folder, then in
 * each folder above it up to the repository root (readProjectPythonAt: uv takes `.python-version`
 * and a workspace's requires-python from above); `source` then names the file by its path from the
 * root, and `folder` the project. Several declarations judged together (mergeProjectPythons) cover
 * every Python any of them covers, and keep each one in `parts`.
 *
 * A release is unsupported only when its `requires_python` lower bound excludes a Python the
 * declaration covers (the lowest version declared, and each later 3.x minor up to the declared
 * upper bound, or NEWEST_PYTHON_MINOR when there is none): `uv lock` for `requires-python >=3.9`
 * refuses requests 2.33.0 (Python>=3.10). An upper cap or an excluded series on the release
 * (scipy 1.11.3, `<3.13,>=3.9`) does not make it unsupported: uv ignores upper bounds on a
 * dependency's requires-python and pip judges only the running interpreter, so it is a note
 * (`capped`), and the release stays a pick.
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
  /** The project folder this was read for, relative to the repository root ("." for the root). */
  folder?: string;
  /** When several projects' declarations are judged together: each one (mergeProjectPythons). */
  parts?: ProjectPython[];
  /** Declarations of the projects judged together that could not be read, by `source`. */
  unreadIn?: string[];
}

/** A release's Python requirement as the registry reader keeps it (ReleaseRecord). */
export interface ReleasePythonFacts {
  /** PEP 440; null when the release declares none (it supports any). Undefined: not read. */
  requiresPython?: string | null;
  /** The release declares one that does not read as a specifier. */
  requiresPythonUnreadable?: true;
}

export type PythonSupport =
  | { status: "supported"; capped?: { requires: string; pythons: string[] } }
  | { status: "unsupported"; requires: string; missing: string[] }
  | { status: "unread"; why: string };

/** Characters a declaration may hold to be read (and printed) at all. */
const DECLARATION = /^[0-9A-Za-z.,*!<>=~^ _-]{1,120}$/;

/** What the project's files declare: a readable Python, one that is there but cannot be read (where), or nothing. */
function readDeclaration(root: string): { python: ProjectPython } | { unread: string } | null {
  for (const read of [fromPyproject, fromUvLock, fromPipfile, fromPythonVersion, fromRuntimeTxt]) {
    const found = read(root);
    if (found === undefined) continue;
    if ("unread" in found) return found;
    const covers = coveredPythons(found.spec);
    return covers ? { python: { ...found, covers } } : { unread: found.source };
  }
  return null;
}

/** The project's declared Python, or null when it declares none that can be read. */
export function readProjectPython(root: string): ProjectPython | null {
  const found = readDeclaration(root);
  return found && "python" in found ? found.python : null;
}

/** Where the project declares a Python that could not be read (e.g. "pyproject.toml [project] requires-python"); null when it declares a readable one or none. */
export function readProjectPythonUnread(root: string): string | null {
  const found = readDeclaration(root);
  return found && "unread" in found ? found.unread : null;
}

/**
 * The declaration that applies to the project in `dir`: its own, else the nearest folder's above it
 * up to `root` (the walk never leaves the repository). `source` (or `unread`) is prefixed with the
 * file's folder relative to `root` when that is not the root itself.
 */
export function readProjectPythonAt(root: string, dir: string): { python: ProjectPython } | { unread: string } | null {
  const top = path.resolve(root);
  const folder = relativeFolder(top, path.resolve(dir));
  if (folder === null) return null;
  let here = path.resolve(dir);
  for (;;) {
    const found = readDeclaration(here);
    const at = relativeFolder(top, here) ?? ".";
    const prefix = at === "." ? "" : `${at}/`;
    if (found && "unread" in found) return { unread: `${prefix}${found.unread}` };
    if (found) return { python: { ...found.python, source: `${prefix}${found.python.source}`, folder } };
    if (here === top) return null;
    here = path.dirname(here);
  }
}

/** `dir` relative to `root` with "/" ("." for the root), or null when it is not inside it. */
function relativeFolder(root: string, dir: string): string | null {
  const rel = path.relative(root, dir);
  if (rel === "") return ".";
  if (rel.startsWith("..") || path.isAbsolute(rel)) return null;
  return rel.replace(/\\/g, "/");
}

/** Several projects' declarations judged as one: every Python any of them covers; each kept in `parts`. */
export function mergeProjectPythons(parts: ProjectPython[], unreadIn: string[] = []): ProjectPython {
  const covers = [...new Set(parts.flatMap((p) => p.covers))].sort(comparePython);
  return {
    declared: parts.map((p) => p.declared).join("; "),
    spec: parts.map((p) => p.spec).join("; "),
    source: parts.map((p) => p.source).join("; "),
    covers,
    parts,
    ...(unreadIn.length > 0 ? { unreadIn } : {}),
  };
}

function comparePython(a: string, b: string): number {
  const x = a.split(".").map(Number);
  const y = b.split(".").map(Number);
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    const d = (x[i] ?? 0) - (y[i] ?? 0);
    if (d !== 0) return d;
  }
  return a.length - b.length;
}

/** Whether `release` supports every Python the project declares. */
export function releasePythonSupport(project: ProjectPython, release: ReleasePythonFacts | undefined): PythonSupport {
  if (!release || release.requiresPython === undefined) return { status: "unread", why: "the Python versions it supports were not read from PyPI" };
  if (release.requiresPythonUnreadable) return { status: "unread", why: "the Python requirement PyPI lists for it does not read as a version specifier" };
  if (release.requiresPython === null) return { status: "supported" };
  const answers = project.covers.map((p) => [p, pythonSpecAdmits(release.requiresPython!, p)] as const);
  if (answers.some(([, a]) => a === null)) return { status: "unread", why: "the Python requirement PyPI lists for it does not read as a version specifier" };
  const missing = answers.filter(([, a]) => a === false).map(([p]) => p);
  if (missing.length === 0) return { status: "supported" };
  // Only the lower bound decides: a Python above it that an upper cap or exclusion leaves out is a note.
  const floor = lowerBoundSpec(release.requiresPython);
  const below = missing.filter((p) => floor !== "" && pythonSpecAdmits(floor, p) === false);
  if (below.length > 0) return { status: "unsupported", requires: release.requiresPython, missing: below };
  return { status: "supported", capped: { requires: release.requiresPython, pythons: missing } };
}

/** The lower-bound clauses of a specifier set (`>=`, `>`, and `~=` as its floor), joined; "" when it has none. */
function lowerBoundSpec(spec: string): string {
  return spec
    .split(",")
    .map((c) => c.trim())
    .map((c) => (c.startsWith("~=") ? `>=${c.slice(2)}` : c))
    .filter((c) => /^(>=|>)(?!=)/.test(c))
    .join(",");
}

/** Each clause of a PEP 440 specifier set reads (pep440SpecAdmits stops at the first false clause). */
export function readsAsPythonSpec(spec: string): boolean {
  const clauses = spec.split(",").filter((c) => c.trim() !== "");
  return clauses.length > 0 && clauses.every((c) => pythonSpecAdmits(c, "3.0") !== null);
}

type Found = { declared: string; spec: string; source: string } | { unread: string } | undefined;

/** A declaration read from `source`: `unread` when it is there but cannot be read (nothing is judged then, and the answer says so). */
function declaration(raw: string, spec: string | null, source: string): Found {
  const declared = raw.trim();
  if (!DECLARATION.test(declared) || spec === null || !readsAsPythonSpec(spec)) return { unread: source };
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
  return m ? declaration(m[1], bareVersion(m[1]), ".python-version") : { unread: ".python-version" };
}

function fromRuntimeTxt(root: string): Found {
  const content = read(root, "runtime.txt");
  if (content === null) return undefined;
  const m = /^\s*python-(\d+\.\d+(?:\.\d+)?)\s*$/.exec(content.split("\n")[0] ?? "");
  return m ? declaration(m[1], bareVersion(m[1]), "runtime.txt") : { unread: "runtime.txt" };
}

/**
 * The Python versions a declaration covers: its lowest, then each later 3.x minor up to its upper
 * bound (NEWEST_PYTHON_MINOR when it has none), as far as it admits them. Null without a lower bound.
 */
export function coveredPythons(spec: string): string[] | null {
  let low = lowestPython(spec);
  if (!low) return null;
  // `>3.9` admits 3.9.1 and later 3.9 patch releases: the series stays in, from its first admitted patch.
  if (pythonSpecAdmits(spec, low) === false && /^\d+\.\d+$/.test(low) && pythonSpecAdmits(spec, `${low}.1`) === true) low = `${low}.1`;
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
