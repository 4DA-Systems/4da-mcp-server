// SPDX-License-Identifier: Apache-2.0
/**
 * Python and Go lockfile parsers (split out of lockfile-parsers.ts).
 *
 * Measured 2026-10-02 against osv-scanner and pip-audit, every miss below was
 * a parsing loss before OSV was ever asked:
 * - requirements.txt: `urllib3[secure]==1.25.0` and dotted names were skipped,
 *   and an inline comment rode along as part of the version — OSV was asked
 *   about `"8.0.0  # imaging"` and answered with 63 advisories for the real 45.
 * - poetry.lock: the reader required `name` and `version` on consecutive
 *   lines. Poetry before 1.0 wrote its keys alphabetically (`category`,
 *   `description`, `name`, ..., `version`), so a whole lockfile read as empty.
 * - go.sum: `(v[\d.]+)` cut `v0.0.0-20200622213623-75b288015ac9` to `v0.0.0`
 *   and dropped `+incompatible`; `v0.0.0` then sorted AFTER the real
 *   pseudo-version, so older advisories were missed and later ones invented.
 *   go.sum also lists versions the build never selected.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { emptySource, found, InstanceSet, type LockfileProblem, type VersionSource } from "./lockfile-types.js";

// =============================================================================
// Python: every lockfile and requirements file in the directory, merged
// =============================================================================

/** PEP 503 normalised name: lowercase, runs of `-`, `_`, `.` become one `-`. */
export function normalizePythonName(name: string): string {
  return name.trim().toLowerCase().replace(/[-_.]+/g, "-");
}

/** The TOML lockfiles: arrays of [[package]] tables. */
const PYTHON_TOML_LOCKS = ["poetry.lock", "uv.lock", "pdm.lock"];

/**
 * Requirement files in a project directory: `*requirements*.txt` beside it
 * (requirements-dev.txt, dev_requirements.txt, _test_minimum_requirements.txt)
 * and every `.txt` in a `requirements/` folder (pip-compile-multi: superset
 * keeps its 100 runtime pins in requirements/base.txt, which nothing read).
 */
export function requirementFiles(cwd: string): string[] {
  const out: string[] = [];
  try {
    for (const name of fs.readdirSync(cwd).sort()) {
      if (/requirements[\w.-]*\.txt$/i.test(name) || includesRequirements(path.join(cwd, name))) out.push(path.join(cwd, name));
    }
  } catch {
    return out;
  }
  try {
    for (const name of fs.readdirSync(path.join(cwd, "requirements")).sort()) {
      if (/\.txt$/i.test(name)) out.push(path.join(cwd, "requirements", name));
    }
  } catch {
    // no requirements/ folder
  }
  return out;
}

/** Above this a .txt is not read to decide whether it is a requirements file. */
const MAX_SNIFF_BYTES = 256 * 1024;

/**
 * A `.txt` whose name does not say "requirements" but that includes one with
 * `-r` and pins packages itself: CTFd's development.txt (`-r requirements.txt`,
 * then pytest==5.4.2 and 21 more pins, 6 advisories pip-audit reports).
 */
function includesRequirements(file: string): boolean {
  if (!/\.txt$/i.test(file) || /requirements[\w.-]*\.txt$/i.test(file)) return false;
  try {
    const stat = fs.statSync(file);
    if (!stat.isFile() || stat.size > MAX_SNIFF_BYTES) return false;
    const content = fs.readFileSync(file, "utf-8");
    return /^\s*(?:-r|--requirement)[\s=]+\S+\.txt\s*$/m.test(content) && parseRequirements(content).length > 0;
  } catch {
    return false;
  }
}

/**
 * Whether a requirements file is dev-only by name: requirements-dev.txt,
 * dev-requirements.txt, requirements/testing.txt, _test_minimum_requirements.txt,
 * docs-requirements.txt. The convention is near universal, but it is a name:
 * a package any other file also lists keeps an unknown scope, never "dev".
 */
export function devRequirementsFile(file: string): boolean {
  const name = path.basename(file).replace(/\.txt$/i, "");
  return /(?:^|[-_.])(?:dev|devel|develop|development|test|tests|testing|lint|linting|docs?|ci|typing|mypy|bench|benchmarks?)(?:[-_.]|$)/i.test(name);
}

/**
 * Every Python source in a directory, merged: poetry.lock, uv.lock, pdm.lock,
 * Pipfile.lock AND the requirement files. One source per ecosystem dropped
 * whatever sat beside the first: langchain's libs/community has a
 * poetry.lock and _test_minimum_requirements.txt, and only the lock was read.
 * The version a direct dependency resolves to comes from a lockfile first.
 */
export function resolvePython(cwd: string): VersionSource {
  const versions = new Map<string, string>();
  const instances = new InstanceSet();
  const sources: string[] = [];
  let lockfile = false;
  const take = (name: string, version: string, dev: boolean | undefined) => {
    instances.add(name, version, dev);
    if (!versions.has(name)) versions.set(name, version);
  };

  for (const file of PYTHON_TOML_LOCKS) {
    const lockPath = path.join(cwd, file);
    if (!fs.existsSync(lockPath)) continue;
    try {
      const read = readTomlPackageLock(fs.readFileSync(lockPath, "utf-8"));
      if (read.instances.size === 0) continue;
      for (const i of read.instances.toArray()) take(i.name, i.version, i.dev);
      sources.push(lockPath);
      lockfile = true;
    } catch { /* unreadable: the next source */ }
  }

  const pipfileLock = path.join(cwd, "Pipfile.lock");
  if (fs.existsSync(pipfileLock)) {
    try {
      const lock = JSON.parse(fs.readFileSync(pipfileLock, "utf-8"));
      let any = false;
      for (const [section, dev] of [["default", false], ["develop", true]] as const) {
        for (const [name, info] of Object.entries(lock[section] ?? {})) {
          const version = (info as { version?: string }).version?.replace(/^===?/, "");
          if (!version) continue;
          take(normalizePythonName(name), version, dev);
          any = true;
        }
      }
      if (any) {
        sources.push(pipfileLock);
        lockfile = true;
      }
    } catch { /* unreadable */ }
  }

  const collected: LockfileProblem[] = [];
  for (const file of requirementFiles(cwd)) {
    const dev = devRequirementsFile(file) ? true : undefined;
    const pins = readRequirementsFile(file, new Set(), cwd, collected);
    if (pins === null) continue;
    for (const { name, version } of pins) take(name, version, dev);
    sources.push(file);
  }
  // One problem per file, however many requirement files name it.
  const problems = [...new Map(collected.map((p) => [p.file.toLowerCase(), p])).values()];

  if (sources.length === 0) return problems.length > 0 ? { ...emptySource(), problems } : emptySource();
  const read = found(versions, instances, sources[0], lockfile ? "lockfile" : "manifest", { extraSources: sources.slice(1) });
  return problems.length > 0 ? { ...read, problems } : read;
}

/**
 * Exact pins from one requirements file, following `-r`/`--requirement`
 * includes (relative to the file) and applying `-c`/`--constraint` files:
 * a constraints file installs nothing by itself, so its pins only give a
 * version to a name the requirements list without one. Null when unreadable.
 *
 * Includes are confined to `root`, the project directory (default: the
 * file's own directory). A cloned repository's `-r ../outside/secrets.txt`,
 * an absolute path, or a UNC path (on Windows, opening `\\host\share\x.txt`
 * makes an SMB connection that sends the user's NTLM hash) used to be read,
 * and every `NAME==VALUE` line in it went to OSV.dev and back to the agent.
 * Such an include is skipped; absolute and UNC ones before any fs call.
 * Skipped is not silent: each one goes to `problems` (audit M4), which the
 * scan reports as a file whose pins were not checked.
 */
export function readRequirementsFile(
  file: string,
  visited: Set<string> = new Set(),
  root: string = path.dirname(path.resolve(file)),
  problems: LockfileProblem[] = [],
): Array<{ name: string; version: string }> | null {
  const key = path.resolve(file).toLowerCase();
  if (visited.has(key)) return [];
  visited.add(key);
  let content: string;
  try {
    content = fs.readFileSync(file, "utf-8");
  } catch {
    return null;
  }
  const dir = path.dirname(file);
  const out = parseRequirements(content);
  const overlong = overlongRequirementLines(content);
  if (overlong > 0) {
    problems.push({
      file: path.resolve(file),
      skipped: overlong,
      error: `${overlong === 1 ? "1 line" : `${overlong} lines`} longer than ${MAX_REQUIREMENT_LINE} characters (not requirement syntax) ${overlong === 1 ? "was" : "were"} skipped, so any pin on ${overlong === 1 ? "it was" : "them was"} not checked`,
    });
  }
  const constraints = new Map<string, string>();
  for (const { option, target } of requirementOptions(content)) {
    const included = confinedInclude(dir, target, root);
    if (included === null) {
      problems.push(refusedInclude(file, option, target));
      continue;
    }
    if (option === "r") out.push(...(readRequirementsFile(included, visited, root, problems) ?? []));
    else for (const pin of parseRequirements(safeRead(included))) constraints.set(pin.name, pin.version);
  }
  if (constraints.size > 0) {
    const pinned = new Set(out.map((p) => p.name));
    for (const name of unpinnedRequirementNames(content)) {
      const version = constraints.get(name);
      if (version && !pinned.has(name)) out.push({ name, version });
    }
  }
  return out;
}

/**
 * A refused include as a coverage problem. `file` is the include as it
 * resolves (an absolute, drive-letter or UNC target as written: it is never
 * resolved or touched), so the note names the file whose pins went unchecked.
 */
function refusedInclude(from: string, option: "r" | "c", target: string): LockfileProblem {
  const absolute = /^[\\/]/.test(target) || /^[A-Za-z]:/.test(target) || path.isAbsolute(target);
  return {
    file: absolute ? target : path.resolve(path.dirname(from), target),
    refused: true,
    error: `\`-${option} ${target}\` in ${path.basename(from)} points outside the project directory, and includes outside it are never read, so the ${option === "r" ? "pins" : "constraints"} in it were not checked`,
  };
}

/**
 * The include's absolute path when `target` is a relative path that stays
 * inside `root` (also after resolving symlinks, when it exists); otherwise
 * null. Absolute, drive-letter and UNC targets are refused before any
 * filesystem call.
 */
export function confinedInclude(dir: string, target: string, root: string): string | null {
  if (/^[\\/]/.test(target) || /^[A-Za-z]:/.test(target) || path.isAbsolute(target)) return null;
  const within = (base: string, p: string) => {
    const rel = path.relative(base, p);
    return rel === "" || (!rel.startsWith("..") && !path.isAbsolute(rel));
  };
  const rootDir = path.resolve(root);
  const included = path.resolve(dir, target);
  if (!within(rootDir, included)) return null;
  let real: string;
  try {
    real = fs.realpathSync(included);
  } catch {
    return included; // missing: nothing to escape through, and the read fails quietly
  }
  try {
    return within(fs.realpathSync(rootDir), real) ? included : null;
  } catch {
    return null;
  }
}

/** Longer lines are not requirements; capping them keeps the regexes below linear in the file size. */
const MAX_REQUIREMENT_LINE = 4096;

/**
 * Logical lines (backslash continuations joined, `--hash` options dropped),
 * with over-long lines left out. The cap used to apply with the hashes in:
 * a `pip-compile --generate-hashes` entry with many wheels (aiohttp 3.8.0:
 * 72 files, 5.7 KB) was dropped silently and never scanned. A hash is not
 * part of the pin, so it goes before the cap; the split is on whitespace,
 * which stays linear on a hostile line.
 */
function requirementLines(content: string): string[] {
  return logicalRequirementLines(content).filter((line) => line.length <= MAX_REQUIREMENT_LINE);
}

function logicalRequirementLines(content: string): string[] {
  return content
    .replace(/\\\r?\n/g, " ")
    .split(/\r?\n/)
    .map((line) => (line.includes("--hash") ? withoutHashes(line) : line));
}

function withoutHashes(line: string): string {
  const tokens = line.split(/[ \t]+/);
  const kept: string[] = [];
  for (let i = 0; i < tokens.length; i++) {
    if (tokens[i] === "--hash") i++; // `--hash sha256:...`: the value is the next token
    else if (!tokens[i].startsWith("--hash=") && !tokens[i].startsWith("--hash:")) kept.push(tokens[i]);
  }
  return kept.join(" ");
}

/** Lines left out for length that are not comments: what a read missed (audit L5's class). */
function overlongRequirementLines(content: string): number {
  return logicalRequirementLines(content).filter((line) => line.length > MAX_REQUIREMENT_LINE && !line.trimStart().startsWith("#")).length;
}

function safeRead(file: string): string {
  try {
    return fs.readFileSync(file, "utf-8");
  } catch {
    return "";
  }
}

/** `-r file` / `--requirement=file` / `-c file` / `--constraint file` lines (local paths only). */
function requirementOptions(content: string): Array<{ option: "r" | "c"; target: string }> {
  const out: Array<{ option: "r" | "c"; target: string }> = [];
  for (const raw of requirementLines(content)) {
    const m = /^\s*(?:-(r|c)|--(requirement|constraint))(?:\s*=\s*|\s+)(\S+)/.exec(raw);
    if (!m || /^[a-z][a-z+]*:\/\//i.test(m[3])) continue;
    out.push({ option: (m[1] ?? (m[2] === "requirement" ? "r" : "c")) as "r" | "c", target: m[3] });
  }
  return out;
}

/** Names a requirements file lists with no exact pin ("flask", "flask>=2"), PEP 503 normalised. */
function unpinnedRequirementNames(content: string): string[] {
  const out: string[] = [];
  for (const raw of requirementLines(content)) {
    const line = raw.replace(/(^|\s)#.*$/, "").trim();
    if (!line || line.startsWith("-")) continue;
    const spec = line.split(";")[0].trim();
    if (/===?/.test(spec)) continue;
    const m = /^([A-Za-z0-9][A-Za-z0-9._-]*)/.exec(spec);
    if (m) out.push(normalizePythonName(m[1]));
  }
  return out;
}

/**
 * Whether a lockfile [[package]] entry is a release from a package index.
 * Only those are what PyPI advisories describe. Not one: the project itself
 * and local code (uv `editable`/`virtual`/`directory`/`path`), a git checkout
 * or a direct-URL archive (uv `git`/`url`; poetry `[package.source] type =
 * "git" | "url" | "file" | "directory"`). A git checkout keeps the version
 * number of a release it is not: pydantic's uv.lock pins
 * pydantic-extra-types 2.10.0 from git `main` (4DA conformance corpus).
 * poetry's `legacy` source is a private index, so its packages are releases.
 */
function fromPackageIndex(block: string, body: string): boolean {
  const uv = /^source\s*=\s*\{\s*([a-z-]+)\s*=/m.exec(body)?.[1];
  if (uv && uv !== "registry") return false;
  const poetrySource = /^\[package\.source\]\s*$([\s\S]*?)(?=^\[|(?![\s\S]))/m.exec(block)?.[1] ?? "";
  const poetryType = /^type\s*=\s*"([^"]*)"/m.exec(poetrySource)?.[1];
  return !(poetryType && ["git", "url", "file", "directory"].includes(poetryType));
}

/**
 * [[package]] tables from poetry.lock (any version) or uv.lock. A pre-1.2
 * poetry.lock records `category = "dev"` for dev-only packages; newer files
 * and uv.lock do not record scope here, so it stays unknown.
 */
export function readTomlPackageLock(content: string): { versions: Map<string, string>; instances: InstanceSet } {
  const versions = new Map<string, string>();
  const instances = new InstanceSet();
  for (const block of content.split(/^\[\[package\]\]\s*$/m).slice(1)) {
    // Stop at the next table header (e.g. [package.dependencies], [metadata]).
    const body = block.split(/^\[/m)[0];
    const field = (key: string) => new RegExp(`^${key}\\s*=\\s*"([^"]*)"`, "m").exec(body)?.[1] ?? null;
    const name = field("name");
    const version = field("version");
    if (!name || !version) continue;
    if (!fromPackageIndex(block, body)) continue;
    const category = field("category");
    const normalized = normalizePythonName(name);
    instances.add(normalized, version, category === null ? undefined : category === "dev");
    if (!versions.has(normalized)) versions.set(normalized, version);
  }
  return { versions, instances };
}

/**
 * Exact pins from a requirements file: `name==1.2`, `name===1.2`,
 * `name[extra1,extra2]==1.2`, with environment markers and inline comments.
 * Ranges (`>=`, `~=`) do not name an installed version and are skipped, as are
 * options (`-r`, `-e`, `--hash`) and URL requirements.
 */
export function parseRequirements(content: string): Array<{ name: string; version: string }> {
  const out: Array<{ name: string; version: string }> = [];
  // Backslash continuations join physical lines into one requirement; a line
  // over 4 KB is no requirement and is dropped before any regex sees it (a
  // 64 KB line took ~5 s in the pin regex, audit 2026-10-12 B-10).
  const logical = requirementLines(content);
  for (const raw of logical) {
    // A `#` starts a comment at line start or after whitespace (PEP 508 URLs may contain `#`).
    const line = raw.replace(/(^|\s)#.*$/, "").trim();
    if (!line || line.startsWith("-")) continue;
    // Per-requirement options (pip-compile writes `--hash=sha256:...` on
    // continuation lines) follow the specifier; they are not part of it.
    const spec = line.split(";")[0].replace(/\s--?[A-Za-z][\w-]*(?:[=\s]\S+)?/g, "").trim();
    const match = /^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*===?\s*([^\s,;]+)\s*$/.exec(spec);
    if (!match) continue;
    out.push({ name: normalizePythonName(match[1]), version: match[2] });
  }
  return out;
}

// =============================================================================
// Go: go.mod (the selected module set) completed from go.sum for go < 1.17
// =============================================================================

/** A full Go module version: release, prerelease, pseudo-version, `+incompatible`. */
const GO_VERSION = /^v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;

export function resolveGo(cwd: string): VersionSource {
  const goModPath = path.join(cwd, "go.mod");
  if (!fs.existsSync(goModPath)) return emptySource();

  let mod: ReturnType<typeof parseGoMod>;
  try {
    mod = parseGoMod(fs.readFileSync(goModPath, "utf-8"));
  } catch {
    return emptySource();
  }
  // The build list: go.mod's requirements and, before go 1.17, the modules
  // go.sum says the build selected; `replace` applies to both.
  const selected = new Map(mod.rawRequires.map((r) => [r.module, r.version] as const));
  // From go 1.17 the go.mod `require` list names every module the build needs
  // (module-graph pruning), so it IS the selected set and go.sum (which keeps
  // hashes for versions the build never selects) would only over-report.
  // Before 1.17 go.mod lists direct requirements only; transitives come from
  // go.sum (selectedFromGoSum: the version MVS picked, when its source is built).
  if (!mod.goVersionAtLeast117) {
    const goSumPath = path.join(cwd, "go.sum");
    if (fs.existsSync(goSumPath)) {
      try {
        for (const [module, version] of selectedFromGoSum(fs.readFileSync(goSumPath, "utf-8"))) {
          if (!selected.has(module)) selected.set(module, version);
        }
      } catch { /* skip */ }
    }
  }
  const versions = new Map<string, string>();
  for (const [module, version] of selected) {
    const target = mod.replacement(module, version);
    if (target === null) continue; // replaced by a local directory: local code, not a registry module
    if (target) versions.set(target.module, target.version);
    else if (!versions.has(module)) versions.set(module, version);
  }
  const instances = new InstanceSet();
  for (const [module, version] of versions) instances.add(module, version);
  return found(versions, instances, goModPath, "lockfile");
}

/** A `replace` target: another module version, or null for a local directory. */
type GoReplacement = { module: string; version: string } | null;

/**
 * `require` lines (block and single form) with `replace` applied, the same
 * lines as written, `replace` for any other module version, and whether the
 * go directive is >= 1.17. A `replace` may name the version it replaces
 * (`old v1.2.3 => new v1.3.0`); that one wins over a versionless one.
 */
export function parseGoMod(content: string): {
  requires: Array<{ module: string; version: string; indirect: boolean }>;
  /** Requirements as written, before `replace`. */
  rawRequires: Array<{ module: string; version: string; indirect: boolean }>;
  /** What `replace` maps a module version to: undefined for nothing, null for local code. */
  replacement: (module: string, version: string) => GoReplacement | undefined;
  goVersionAtLeast117: boolean;
} {
  const requires = new Map<string, { module: string; version: string; indirect: boolean }>();
  const replaces = new Map<string, GoReplacement>();
  let block: "require" | "replace" | null = null;

  for (const rawLine of content.split(/\r?\n/)) {
    const indirect = /\/\/\s*indirect\b/.test(rawLine);
    const line = rawLine.replace(/\/\/.*$/, "").trim();
    if (!line) continue;
    if (block && line === ")") {
      block = null;
      continue;
    }
    const opener = /^(require|replace)\s*\($/.exec(line);
    if (opener) {
      block = opener[1] as "require" | "replace";
      continue;
    }
    const single = /^(require|replace)\s+(.+)$/.exec(line);
    const kind = single ? (single[1] as "require" | "replace") : block;
    const rest = single ? single[2] : line;
    if (kind === "require") {
      const [module, version] = rest.split(/\s+/);
      if (module && version && GO_VERSION.test(version)) requires.set(module, { module, version, indirect });
    } else if (kind === "replace") {
      // `old [v] => new v` replaces with another module version; `=> ./path` is local code.
      const [left, right] = rest.split("=>").map((s) => s.trim().split(/\s+/));
      if (!left?.[0] || !right?.[0]) continue;
      const key = left[1] ? `${left[0]} ${left[1]}` : left[0];
      replaces.set(key, right[1] && GO_VERSION.test(right[1]) ? { module: right[0], version: right[1] } : null);
    }
  }

  const replacement = (module: string, version: string): GoReplacement | undefined => {
    const exact = `${module} ${version}`;
    if (replaces.has(exact)) return replaces.get(exact);
    return replaces.has(module) ? replaces.get(module) : undefined;
  };
  const rawRequires = [...requires.values()];
  const result: Array<{ module: string; version: string; indirect: boolean }> = [];
  for (const req of rawRequires) {
    const target = replacement(req.module, req.version);
    if (target === undefined) result.push(req);
    else if (target) result.push({ module: target.module, version: target.version, indirect: req.indirect });
  }

  const go = /^go\s+(\d+)\.(\d+)/m.exec(content);
  const goVersionAtLeast117 = go ? Number(go[1]) > 1 || Number(go[2]) >= 17 : false;
  return { requires: result, rawRequires, replacement, goVersionAtLeast117 };
}

/**
 * Per module, the version the build selected according to go.sum (go < 1.17):
 * the HIGHEST version recorded there by either line, since minimal version
 * selection picks the highest version the module graph requires and go.sum
 * records every one, kept only when go.sum also hashes that version's SOURCE
 * (`module v1.2.3 h1:...`, not only `module v1.2.3/go.mod h1:...`).
 *
 * The go command records the go.mod hash of every module version it visits
 * while walking the graph, but downloads and hashes the source only of
 * modules whose packages the build imports. A module with only a `/go.mod`
 * line at its selected version is in `go list -m all` but is never compiled.
 * Counting those (the 6.2 rule) read 728 never-built modules as installed
 * on hugo, node_exporter and traefik: 4DA conformance corpus, 2026-10-12,
 * whose truth is the build list restricted to source-hashed modules, as the
 * desktop app reads it. An older version's leftover source hash does not make
 * that older version built either: node_exporter hashes gogo/protobuf
 * v1.1.1's source while the graph selects v1.2.1 (go.mod hash only), so
 * neither is installed.
 */
export function selectedFromGoSum(content: string): Map<string, string> {
  const highest = new Map<string, string>();
  const sourceHashed = new Set<string>();
  for (const line of content.split(/\r?\n/)) {
    const [module, rawVersion] = line.trim().split(/\s+/);
    if (!module || !rawVersion) continue;
    const version = rawVersion.replace(/\/go\.mod$/, "");
    if (!GO_VERSION.test(version)) continue;
    if (version === rawVersion) sourceHashed.add(`${module} ${version}`);
    const current = highest.get(module);
    if (!current || compareGoVersions(version, current) > 0) highest.set(module, version);
  }
  const selected = new Map<string, string>();
  for (const [module, version] of highest) if (sourceHashed.has(`${module} ${version}`)) selected.set(module, version);
  return selected;
}

/** Semver precedence over Go versions; build metadata (`+incompatible`) is ignored. */
export function compareGoVersions(a: string, b: string): number {
  const parse = (v: string) => {
    const m = /^v(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?/.exec(v);
    return m ? { nums: [Number(m[1]), Number(m[2]), Number(m[3])], pre: m[4] ? m[4].split(".") : [] } : null;
  };
  const pa = parse(a);
  const pb = parse(b);
  if (!pa || !pb) return 0;
  for (let i = 0; i < 3; i++) if (pa.nums[i] !== pb.nums[i]) return pa.nums[i] > pb.nums[i] ? 1 : -1;
  if (pa.pre.length === 0 || pb.pre.length === 0) return Math.sign(pb.pre.length - pa.pre.length);
  for (let i = 0; i < Math.min(pa.pre.length, pb.pre.length); i++) {
    const x = pa.pre[i];
    const y = pb.pre[i];
    if (x === y) continue;
    const xn = /^\d+$/.test(x);
    const yn = /^\d+$/.test(y);
    if (xn && yn) return BigInt(x) > BigInt(y) ? 1 : -1;
    if (xn !== yn) return xn ? -1 : 1;
    return x > y ? 1 : -1;
  }
  return Math.sign(pa.pre.length - pb.pre.length);
}
