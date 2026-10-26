// SPDX-License-Identifier: Apache-2.0
/**
 * How a PyPI pin is moved, worded for how its requirements file is produced and installed
 * (audit 6.2.5 A-4). Two kinds of advice installed nothing when run as written:
 *
 * - A compiled file (`uv pip compile`, `pip-compile`) pins the whole tree. Its `# via requests`
 *   pins are transitive, and every pin is regenerated from the input (requirements.in,
 *   pyproject.toml) on the next compile. "change `idna==2.7` to `idna==3.15` in requirements.txt"
 *   conflicted with requests 2.19.1 (`idna<2.8`), and a hand edit is reverted anyway. The fix is a
 *   re-compile with `--upgrade-package "idna==3.15"`, the checked target (a `>=` let the resolver
 *   take a newer release nothing checked). uv 0.6.8 and pip-compile 7.6.2 both refuse to resolve
 *   when a package that requires idna excludes 3.15 (run 2026-10-26 on Track A's hb-f6b fixture),
 *   where a bare `--upgrade-package idna` silently kept 2.7.
 * - A flat file that pins everything with `==`: each edit was presented as safe on its own, but 4
 *   of pygoat's 15 do not resolve against the other pins (Django 5.2.17 needs asgiref>=3.8.1,
 *   asgiref==3.6.0 is pinned), and neither does the full set. No resolver runs here, so the advice
 *   says the edits must be re-resolved together; it never claims they are.
 *
 * A command is spliced only from plain tokens (audit 6.2.5 C-1); otherwise the words name no command.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import {
  compiledIndirect,
  compiledRequiredBy,
  compiledRequirements,
  confinedInclude,
  normalizePythonName,
  parseRequirements,
  requirementFiles,
  requirementOptions,
  type CompiledRequirements,
} from "./lockfile-parsers-pygo.js";
import { isShellSafeName, isShellSafeVersion } from "./shell-safe.js";

/** A relative path of plain segments (`requirements.in`, `requirements/dev.txt`): no `..`, no root, no drive, nothing a shell expands. */
function isPlainPath(file: string): boolean {
  return /^[A-Za-z0-9_][A-Za-z0-9_.-]*(?:\/[A-Za-z0-9_][A-Za-z0-9_.-]*)*$/.test(file) && !file.split("/").includes("..") && file.length <= 256;
}

function readText(file: string): string | null {
  try {
    return fs.readFileSync(file, "utf-8");
  } catch {
    return null;
  }
}

/** Requirement files that pin `name` at `installed`, relative to `projectDir`: the ones the scan reads, then their confined `-r` includes. */
function filesPinning(projectDir: string, name: string, installed: string): Array<{ file: string; body: string }> {
  const want = normalizePythonName(name);
  const files = ["requirements.txt", "requirements-dev.txt", "requirements/base.txt"];
  for (const f of requirementFiles(projectDir)) {
    const rel = path.relative(projectDir, f).replace(/\\/g, "/");
    if (!files.includes(rel)) files.push(rel);
  }
  const out: Array<{ file: string; body: string }> = [];
  for (let i = 0; i < files.length && i < 32; i++) {
    const body = readText(path.join(projectDir, files[i]));
    if (body === null) continue;
    if (parseRequirements(body).some((p) => p.name === want && p.version === installed)) out.push({ file: files[i], body });
    for (const { option, target } of requirementOptions(body)) {
      const included = option === "r" ? confinedInclude(path.dirname(path.join(projectDir, files[i])), target, projectDir) : null;
      const rel = included ? path.relative(projectDir, included).replace(/\\/g, "/") : null;
      if (rel && !files.includes(rel)) files.push(rel);
    }
  }
  return out;
}

/** The input a compiled file names, when it is a plain path that exists inside the project (where the compile runs). */
function presentInput(projectDir: string, compiled: CompiledRequirements): string | null {
  const input = compiled.input;
  if (!input || !isPlainPath(input)) return null;
  const at = confinedInclude(projectDir, input, projectDir);
  return at && fs.existsSync(at) ? input : null;
}

/** `uv pip compile` / `pip-compile` with the upgrade, when every spliced value is a plain token. */
function compileCommand(tool: "uv" | "pip-compile", input: string, output: string, name: string, target: string): string | null {
  if (!isPlainPath(input) || !isPlainPath(output) || !isShellSafeName(name, "PyPI") || !isShellSafeVersion(target)) return null;
  // Double quotes: `>` is a redirect outside them on every shell; cmd.exe keeps single quotes.
  const upgrade = `--upgrade-package "${name}==${target}"`;
  return tool === "uv" ? `uv pip compile ${input} -o ${output} ${upgrade}` : `pip-compile ${input} --output-file ${output} ${upgrade}`;
}

/**
 * The advice for `name` at `installed` when a compiled requirements file in `projectDir` pins it;
 * null when no compiled file does (the caller keeps its own advice). Both a declared pin and an
 * indirect one are moved by re-compiling, never by editing the output.
 */
export function pypiCompiledInstruction(projectDir: string, name: string, installed: string, target: string): string | null {
  for (const { file, body } of filesPinning(projectDir, name, installed)) {
    const compiled = compiledRequirements(body);
    if (!compiled) continue;
    // Prose too carries only plain tokens: the target comes from advisory data, the rest from the repo.
    const label = isShellSafeName(name, "PyPI") ? name : "this package";
    const version = isShellSafeVersion(target) ? target : "the fixed release";
    const safeFile = isPlainPath(file) ? file : "the requirements file";
    const by = compiled.tool === "uv" ? " by `uv pip compile`" : compiled.tool === "pip-compile" ? " by `pip-compile`" : "";
    const input = presentInput(projectDir, compiled);
    const from = input ? ` from ${input}` : "";
    const indirect = compiledIndirect(compiled, name);
    const parents = compiledRequiredBy(compiled, name).filter((p) => isShellSafeName(p, "PyPI")).slice(0, 3);
    const command = input && compiled.tool && isPlainPath(file) ? compileCommand(compiled.tool, input, file, name, target) : null;
    const upgrade = isShellSafeName(name, "PyPI") && isShellSafeVersion(target) ? `\`--upgrade-package "${name}==${target}"\`` : "an `--upgrade-package` option for it";

    const what = indirect
      ? `${label} is not declared: ${safeFile} is compiled${by}${from} and pins it only because ${parents.length > 0 ? parents.join(", ") : "other packages"} require${parents.length === 1 ? "s" : ""} it`
      : `${safeFile} is compiled${by}${from}, so a hand edit of it is reverted by the next compile${input ? `; make sure the ${label} requirement in ${input} admits ${version}` : `; make sure the ${label} requirement in the file it is compiled from admits ${version}`}`;
    const instead = indirect ? " instead of editing it" : "";
    const how = command
      ? `${indirect ? "" : "then "}re-compile with the upgrade${instead}: \`${command}\`, keeping the other options its header records`
      : compiled.tool
        ? `${indirect ? "" : "then "}re-compile it${input ? "" : " from its input"} with ${upgrade}${instead}, keeping the options its header records`
        : `${indirect ? "" : "then "}re-compile it with the tool that wrote it (\`uv pip compile\` or \`pip-compile\`) and ${upgrade}${instead}`;
    const check = `the resolver refuses when ${indirect && parents.length > 0 ? parents.join(" or ") : "a package that requires it"} excludes ${version}; then raise ${indirect ? "that package" : "the one it names"} in the input as well, and put the other upgrades to ${safeFile} in the same compile (one --upgrade-package each)`;
    return `${what}; ${how}. ${capitalise(check)}`;
  }
  return null;
}

function capitalise(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

/**
 * The sentence for an `==` edit of `name` in a flat file that pins every requirement exactly (two
 * or more): its edits are not independently safe and must be resolved together. Null otherwise.
 * The file is the first that pins it, in the order directFix reads them.
 */
export function pypiPinnedTogether(projectDir: string, name: string, installed: string): string | null {
  const first = filesPinning(projectDir, name, installed)[0];
  if (!first || compiledRequirements(first.body)) return null;
  const { file, body } = first;
  const pins = parseRequirements(body).length;
  if (pins < 2 || pins !== requirementCount(body)) return null;
  const where = isPlainPath(file) ? file : "the requirements file";
  const check = isPlainPath(file) ? ` (\`uv pip compile ${file}\` prints the resolution and writes nothing; \`pip install --dry-run -r ${file}\` also checks)` : "";
  return `${where} pins every requirement exactly, so this edit is not safe on its own: make every pin change to it together, re-resolve the file${check}, and raise any other pin the resolver reports as conflicting before installing`;
}

/** Requirement lines in a file (pins and ranges alike), options and comments aside. */
function requirementCount(body: string): number {
  let n = 0;
  for (const raw of body.replace(/\\\r?\n/g, " ").split(/\r?\n/)) {
    const line = raw.replace(/(^|\s)#.*$/, "").trim();
    if (line && !line.startsWith("-") && /^[A-Za-z0-9]/.test(line)) n++;
  }
  return n;
}

/**
 * vulnerability_scan's short form, appended to "Upgrade X a → b": a compiled file is re-compiled
 * and a fully pinned one re-resolved, never one `==` edit taken as safe alone (audit 6.2.5 A-4).
 */
export function pypiScanNote(projectDir: string, name: string, installed: string): string | null {
  const first = filesPinning(projectDir, name, installed)[0];
  if (!first) return null;
  const where = isPlainPath(first.file) ? first.file : "the requirements file";
  const compiled = compiledRequirements(first.body);
  if (compiled) {
    const input = presentInput(projectDir, compiled);
    return `${where} is compiled${input ? ` from ${input}` : ""}: re-compile it with --upgrade-package instead of editing it${compiledIndirect(compiled, name) ? " (it is pinned only because other packages require it)" : ""}; upgrade_planner words the step`;
  }
  return pypiPinnedTogether(projectDir, name, installed) ? `${where} pins every requirement exactly: re-resolve it with the other pin changes before installing` : null;
}
