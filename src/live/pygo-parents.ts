// SPDX-License-Identifier: Apache-2.0
/**
 * Python and Go transitive copies: who requires them, with which requirement, and whether a
 * lockfile refresh reaches the fix (audit 2026-11-11, a2 finding 10). Every PyPI and Go transitive
 * fix was "waiting on upstream" with no step: Django 3.2 requires `sqlparse>=0.2.2` and requests
 * 2.25.0 `certifi>=2017.4.17`, so a refresh reaches certifi's fix; Go's `// indirect` modules have
 * no upper bounds at all.
 *
 * PyPI: the parents and their requirements are read from the lockfile where it records them
 * (poetry.lock `[package.dependencies]`; the root's `requires-dist` in uv.lock), else from the
 * parent release's own `requires_dist` on PyPI (uv.lock and compiled requirements files name the
 * parents only). A refresh is claimed only when every parent's requirement admits the fix, the
 * newest release they all admit is clean, and the fix supports the project's lowest Python
 * (sqlparse 0.6.0 requires Python >= 3.10: a `^3.8` lock keeps 0.5.x, whatever the parents say).
 * Pipfile.lock and pdm.lock are not read for this (no parent graph; no verified command): the
 * conservative label stays.
 *
 * Go: minimal version selection takes the highest version any module requires and no `require`
 * sets an upper bound, so `go get module@vX && go mod tidy` raises an indirect requirement with
 * no parent moving, unless go.mod replaces or excludes that module (then nothing is claimed).
 */

import * as path from "node:path";
import { pep440SpecAdmits } from "../tools/dependency-check-versions.js";
import { compiledRequiredBy, compiledRequirements, normalizePythonName, parseGoMod, parseRequirements, requirementFiles } from "./lockfile-parsers-pygo.js";
import { isShellSafeName, isShellSafeVersion } from "./shell-safe.js";
import { readTextFile } from "./text-file.js";
import { compareVersions } from "./version-compare.js";

export type PythonLockFormat = "poetry" | "uv" | "compiled";

export interface PythonParent {
  parent: string;
  /** Null for the project itself. */
  parentVersion: string | null;
  /** The requirement(s) as the lockfile records them, PEP 440 ("" = any version); null when it records none (read from PyPI). */
  specs: string[] | null;
}

export interface PythonParents {
  format: PythonLockFormat;
  /** The file the edges came from. */
  file: string;
  edges: PythonParent[];
  /** The Python versions the project supports, PEP 440, when the lockfile says (uv `requires-python`, poetry `python-versions`). */
  projectPython: string | null;
}

function read(file: string): string | null {
  try {
    return readTextFile(file);
  } catch {
    return null;
  }
}

/** `[[package]]` tables, each with every sub-table that follows it. */
function packageBlocks(content: string): string[] {
  return content.split(/^\[\[package\]\]\s*$/m).slice(1);
}

function headField(block: string, key: string): string | null {
  const body = block.split(/^\[/m)[0];
  return new RegExp(`^${key}\\s*=\\s*"([^"]*)"`, "m").exec(body)?.[1] ?? null;
}

/**
 * Poetry's own constraint syntax, as poetry.lock and pyproject `python = ...` write it, in PEP 440:
 * `^3.8` -> `>=3.8,<4.0`, `~3.8` -> `>=3.8,<3.9`, `*` -> "" (any), a bare version -> `==`.
 * PEP 440 clauses pass through. Null when a clause cannot be read.
 */
export function poetryToPep440(spec: string): string | null {
  const out: string[] = [];
  for (const raw of spec.split(",")) {
    const c = raw.trim();
    if (c === "" || c === "*") continue;
    const caret = /^\^\s*(\d+)(?:\.(\d+))?(?:\.(\d+))?$/.exec(c);
    const tilde = /^~(?!=)\s*(\d+)(?:\.(\d+))?(?:\.(\d+))?$/.exec(c);
    if (caret) {
      const [maj, min, pat] = [Number(caret[1]), caret[2] === undefined ? null : Number(caret[2]), caret[3] === undefined ? null : Number(caret[3])];
      const floor = [maj, min ?? 0, pat ?? 0].join(".");
      const ceil = maj > 0 || min === null ? `${maj + 1}.0` : min > 0 || pat === null ? `0.${min + 1}` : `0.0.${(pat ?? 0) + 1}`;
      out.push(`>=${floor}`, `<${ceil}`);
    } else if (tilde) {
      const [maj, min] = [Number(tilde[1]), tilde[2] === undefined ? null : Number(tilde[2])];
      out.push(`>=${[maj, min ?? 0, tilde[3] ?? 0].join(".")}`, min === null ? `<${maj + 1}.0` : `<${maj}.${min + 1}`);
    } else if (/^\d[\w.!+]*$/.test(c)) {
      out.push(`==${c}`);
    } else if (/^(===|~=|==|!=|>=|<=|>|<)\s*\S+$/.test(c)) {
      out.push(c.replace(/\s+/g, ""));
    } else {
      return null;
    }
  }
  return out.join(",");
}

/** Whether a PEP 440 specifier admits a version ("" admits every one); null when unreadable. */
export function pythonSpecAdmits(spec: string, version: string): boolean | null {
  const s = spec.replace(/^\(|\)$/g, "").trim();
  if (s === "" || s === "*") return true;
  return pep440SpecAdmits(s, version);
}

/**
 * One PEP 508 requirement string (`idna (<3,>=2.5)`, `certifi>=2017.4.17`,
 * `PySocks (!=1.5.7,>=1.5.6) ; extra == 'socks'`): its normalised name, specifier, and whether a
 * marker gates it behind an extra. Null when it is not one.
 */
export function parsePep508(requirement: string): { name: string; spec: string; extra: boolean } | null {
  const [head, marker = ""] = requirement.split(";");
  const m = /^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(.*)$/.exec(head);
  if (!m) return null;
  if (m[2].trim().startsWith("@")) return null; // a direct URL reference: no specifier to read
  const spec = m[2].trim().replace(/^\(\s*/, "").replace(/\s*\)$/, "").replace(/\s+/g, "");
  return { name: normalizePythonName(m[1]), spec, extra: /\bextra\s*==/.test(marker) };
}

/** The specifiers a parent's `requires_dist` puts on `name`: the unconditional ones, else the extra-gated ones (the lock shows the edge, so the extra is on). */
export function requirementsOn(requiresDist: string[], name: string): string[] {
  const want = normalizePythonName(name);
  const all = requiresDist.map(parsePep508).filter((r): r is NonNullable<ReturnType<typeof parsePep508>> => r !== null && r.name === want);
  const plain = all.filter((r) => !r.extra);
  return (plain.length > 0 ? plain : all).map((r) => r.spec);
}

/** poetry.lock: each package whose `[package.dependencies]` names `name`, with the requirement it records. */
function poetryParents(content: string, name: string): PythonParent[] {
  const want = normalizePythonName(name);
  const out: PythonParent[] = [];
  for (const block of packageBlocks(content)) {
    const parent = headField(block, "name");
    const version = headField(block, "version");
    if (!parent || !version) continue;
    const table = /^\[package\.dependencies\]\s*$([\s\S]*?)(?=^\[|(?![\s\S]))/m.exec(block)?.[1];
    if (!table) continue;
    // One entry per key: `x = ">=1"`, `x = {version = ">=1", markers = "..."}`, or an array of those (possibly over lines).
    const entries = table.split(/^(?=[A-Za-z0-9"'][^=\n]*=)/m);
    for (const entry of entries) {
      const eq = entry.indexOf("=");
      if (eq < 0) continue;
      const key = entry.slice(0, eq).trim().replace(/^["']|["']$/g, "");
      if (normalizePythonName(key) !== want) continue;
      const value = entry.slice(eq + 1).trim();
      const quoted = /^"([^"]*)"/.exec(value)?.[1];
      const versions = quoted !== undefined ? [quoted] : [...value.matchAll(/\bversion\s*=\s*"([^"]*)"/g)].map((x) => x[1]);
      const specs = versions.map(poetryToPep440);
      out.push({ parent: normalizePythonName(parent), parentVersion: version, specs: specs.some((s) => s === null) || specs.length === 0 ? null : (specs as string[]) });
    }
  }
  return out;
}

/** uv.lock: each package that lists `name` (at `version`, when uv names one), and the root's own `requires-dist` specifier. */
function uvParents(content: string, name: string, version: string): PythonParent[] {
  const want = normalizePythonName(name);
  const out: PythonParent[] = [];
  for (const block of packageBlocks(content)) {
    const parent = headField(block, "name");
    if (!parent) continue;
    const local = /^source\s*=\s*\{\s*(editable|virtual|directory)\s*=/m.test(block.split(/^\[/m)[0]);
    const parentVersion = local ? null : headField(block, "version");
    if (!local && !parentVersion) continue;
    let listed = false;
    const specs: string[] = [];
    for (const t of block.matchAll(/\{\s*name\s*=\s*"([^"]+)"([^}]*)\}/g)) {
      if (normalizePythonName(t[1]) !== want) continue;
      const pinned = /\bversion\s*=\s*"([^"]*)"/.exec(t[2])?.[1];
      const specifier = /\bspecifier\s*=\s*"([^"]*)"/.exec(t[2])?.[1];
      if (specifier !== undefined) specs.push(specifier);
      else if (pinned === undefined || pinned === version) listed = true;
    }
    if (!listed && specs.length === 0) continue;
    out.push({ parent: normalizePythonName(parent), parentVersion, specs: specs.length > 0 ? specs : local ? [""] : null });
  }
  return out;
}

/** The parents of `name@version` in a poetry.lock or uv.lock; null for another file or an unreadable one. */
export function pythonLockParents(lockfile: string, name: string, version: string): PythonParents | null {
  const content = read(lockfile);
  if (content === null) return null;
  const base = path.basename(lockfile);
  if (base === "poetry.lock") {
    const python = /^\[metadata\][\s\S]*?^python-versions\s*=\s*"([^"]*)"/m.exec(content)?.[1];
    return { format: "poetry", file: lockfile, edges: poetryParents(content, name), projectPython: python ? poetryToPep440(python) : null };
  }
  if (base === "uv.lock") {
    const python = /^requires-python\s*=\s*"([^"]*)"/m.exec(content.split(/^\[\[package\]\]/m)[0])?.[1] ?? null;
    return { format: "uv", file: lockfile, edges: uvParents(content, name, version), projectPython: python };
  }
  return null;
}

/**
 * A compiled requirements file (`uv pip compile`, `pip-compile`) in `projectDir` that pins
 * `name==version` only because other packages require it (`# via requests`): those packages at the
 * versions the same file pins (their requirement is read from PyPI). Null when none does.
 */
export function compiledParents(projectDir: string, name: string, version: string): PythonParents | null {
  const want = normalizePythonName(name);
  for (const file of requirementFiles(projectDir)) {
    const body = read(file);
    if (body === null) continue;
    const pins = parseRequirements(body);
    if (!pins.some((p) => p.name === want && p.version === version)) continue;
    const compiled = compiledRequirements(body);
    if (!compiled) continue;
    const by = compiledRequiredBy(compiled, name);
    if (by.length === 0) return null;
    const edges = by.map((parent) => ({ parent, parentVersion: pins.find((p) => p.name === parent)?.version ?? null, specs: null }));
    return { format: "compiled", file, edges, projectPython: null };
  }
  return null;
}

/** The lowest Python a PEP 440 `requires-python` admits (`>=3.8,<4` -> "3.8"), when it states a lower bound. */
export function lowestPython(spec: string | null): string | null {
  if (!spec) return null;
  let low: string | null = null;
  for (const clause of spec.split(",")) {
    const m = /^\s*(>=|>|~=|==)\s*(\d+(?:\.\d+)*)(\.\*)?\s*$/.exec(clause);
    if (!m) continue;
    if (low === null || compareVersions(m[2], low, "PyPI") > 0) low = m[2];
  }
  return low;
}

/** The command that refreshes one transitive copy in a poetry.lock or uv.lock; null when its name is not a plain token. */
export function pythonRefreshCommand(format: "poetry" | "uv", name: string): string | null {
  if (!isShellSafeName(name, "PyPI")) return null;
  return format === "uv" ? `uv lock --upgrade-package ${name}` : `poetry update ${name}`;
}

/**
 * Go: the command that raises a transitive (`// indirect`, or go.sum-only before go 1.17) module
 * to `target`, or null when go.mod replaces or excludes it, it is a direct requirement, or a value
 * is not a plain token.
 */
export function goIndirectRaise(goModPath: string, module: string, installed: string, target: string): string | null {
  const content = read(goModPath);
  if (content === null) return null;
  if (!isShellSafeName(module, "Go") || !isShellSafeVersion(target)) return null;
  const mod = parseGoMod(content);
  if (mod.replacement(module, installed) !== undefined) return null;
  if (goExcluded(content).has(module)) return null;
  const direct = mod.rawRequires.find((r) => r.module === module && !r.indirect);
  if (direct) return null;
  const v = target.startsWith("v") ? target : `v${target}`;
  return `go get ${module}@${v} && go mod tidy`;
}

/** The modules a go.mod `exclude` directive names (single and block form). */
function goExcluded(content: string): Set<string> {
  const out = new Set<string>();
  let inBlock = false;
  for (const raw of content.split(/\r?\n/)) {
    const line = raw.replace(/\/\/.*$/, "").trim();
    if (inBlock) {
      if (line === ")") inBlock = false;
      else if (line) out.add(line.split(/\s+/)[0]);
      continue;
    }
    if (/^exclude\s*\($/.test(line)) inBlock = true;
    else if (line.startsWith("exclude ")) out.add(line.slice("exclude ".length).trim().split(/\s+/)[0]);
  }
  return out;
}
