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
import { emptySource, found, InstanceSet, partialRead, unreadableReason, type LockfileProblem, type UncheckableDependency, type VersionSource } from "./lockfile-types.js";
import { pyprojectRequirements, uvOverrideRequirements } from "./pyproject-requirements.js";
import { poetryRequirements } from "./poetry-requirements.js";
import { readTextFile } from "./text-file.js";
import { isPublicExtraPypiIndex, isPublicPypiIndex, sourceLabel, type PrivateIndexEntry } from "./private-packages.js";
import { pushAll } from "../array-utils.js";
import { findLinksLabel, isPublicFindLinks, pipLineOptions, privateDirectReference } from "./private-configs.js";

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
  // A symlinked requirements-dev.txt or a junctioned requirements/ folder can point anywhere; only
  // `-r` includes were confined, so pins from outside the project reached OSV and the output
  // (audit 6.2.5 C-3). Every file read must resolve inside the project.
  return out.filter((file) => confinedInclude(cwd, path.relative(cwd, file), cwd) !== null);
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
    const content = readTextFile(file);
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
 * The name of the file alone does not make its pins dev-only: see devOnlyRequirements.
 */
export function devRequirementsFile(file: string): boolean {
  const name = path.basename(file).replace(/\.txt$/i, "");
  return /(?:^|[-_.])(?:dev|devel|develop|development|test|tests|testing|lint|linting|docs?|ci|typing|mypy|bench|benchmarks?)(?:[-_.]|$)/i.test(name);
}

/**
 * Whether what a requirements file lists is installed for development only: the file is a dev
 * file by name, and so is every file that includes it with `-r`, however far up. `includes`
 * holds every include read (absolute paths).
 *
 * Both directions matter. `requirements-dev.txt` that says `-r prod.txt` installs prod.txt's
 * pins, but prod.txt is a production file: its pins are production, whoever includes it. And a
 * dev-named file a production file includes is installed in production with it.
 */
export function devOnlyRequirements(includes: ReadonlyArray<{ from: string; to: string }>): (file: string) => boolean {
  const key = (file: string) => path.resolve(file).toLowerCase();
  const includedBy = new Map<string, Set<string>>();
  for (const { from, to } of includes) includedBy.set(key(to), (includedBy.get(key(to)) ?? new Set<string>()).add(key(from)));
  const known = new Map<string, boolean>();
  return (file) => {
    const start = key(file);
    const cached = known.get(start);
    if (cached !== undefined) return cached;
    // The file and everything above it; `seen` ends an include loop.
    const seen = new Set<string>([start]);
    const queue = [start];
    let devOnly = true;
    while (devOnly && queue.length > 0) {
      const at = queue.pop() as string;
      if (!devRequirementsFile(at)) devOnly = false;
      for (const parent of includedBy.get(at) ?? []) {
        if (!seen.has(parent)) {
          seen.add(parent);
          queue.push(parent);
        }
      }
    }
    known.set(start, devOnly);
    return devOnly;
  };
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
  const uncheckable: UncheckableDependency[] = [];
  const privateIndex: PrivateIndexEntry[] = [];
  const damaged: LockfileProblem[] = [];
  let lockfile = false;
  /** Whether a file read here installs packages without recording the index each came from (pdm.lock, a requirements file). */
  let indexUnrecorded = false;
  const take = (name: string, version: string, dev: boolean | undefined) => {
    instances.add(name, version, dev);
    if (!versions.has(name)) versions.set(name, version);
  };

  // pyproject.toml is what a uv.lock is checked against (pythonLockDamage). Unreadable is not absent.
  const pyprojectPath = path.join(cwd, "pyproject.toml");
  let pyproject: string | null = null;
  let pyprojectUnread: LockfileProblem | null = null;
  if (fs.existsSync(pyprojectPath)) {
    try {
      pyproject = readTextFile(pyprojectPath);
    } catch (error) {
      pyprojectUnread = { file: pyprojectPath, error: unreadableReason(error) };
    }
  }

  for (const file of PYTHON_TOML_LOCKS) {
    const lockPath = path.join(cwd, file);
    if (!fs.existsSync(lockPath)) continue;
    try {
      const content = readTextFile(lockPath);
      const read = readTomlPackageLock(content);
      for (const other of read.uncheckable) uncheckable.push({ ...other, file: lockPath });
      for (const p of read.privateIndex) privateIndex.push({ ...p, file: lockPath });
      // pdm.lock records no index per package: what its configured sources serve is not visible in it.
      if (file === "pdm.lock") indexUnrecorded = true;
      const damage = pythonLockDamage(file, content, pyproject);
      if (read.instances.size === 0) {
        // Nothing was read and the file says why: named here, never taken for a project with no dependencies.
        if (damage) damaged.push({ file: lockPath, error: `${damage.reason}; no package version could be read from it` });
        continue;
      }
      for (const i of read.instances.toArray()) take(i.name, i.version, i.dev);
      sources.push(lockPath);
      lockfile = true;
      if (damage) damaged.push(partialRead(lockPath, damage.reason, damage.missing, damage.behindManifest === true));
    } catch { /* unreadable: the next source (resolveVersionSource names this one and why) */ }
  }

  const pipfileLock = path.join(cwd, "Pipfile.lock");
  if (fs.existsSync(pipfileLock)) {
    try {
      const read = readPipfileLock(JSON.parse(readTextFile(pipfileLock)), pipfileLock);
      pushAll(uncheckable, read.uncheckable);
      pushAll(privateIndex, read.privateIndex);
      for (const pin of read.pins) take(pin.name, pin.version, pin.dev);
      if (read.pins.length > 0) {
        sources.push(pipfileLock);
        lockfile = true;
      }
      // Entries skipped inside a file that was otherwise read (`skipped`), or a file that gave nothing.
      if (read.problem) damaged.push({ file: pipfileLock, error: read.problem, ...(read.pins.length > 0 && read.malformed > 0 ? { skipped: read.malformed } : {}) });
    } catch { /* unreadable or not JSON: resolveVersionSource names it and why */ }
  }

  const collected: LockfileProblem[] = [];
  const origins: NonNullable<RequirementExtras["origins"]> = [];
  const includes: NonNullable<RequirementExtras["includes"]> = [];
  const extras: RequirementExtras = { unpinned: [], uncheckable: [], directPrivate: [], origins, includes };
  const extraIndexes: Array<{ file: string; index: string }> = [];
  const registryWide: NonNullable<VersionSource["registryWide"]> = [];
  /** Every pin the requirement files install, in the order read; its scope is decided once every include is known. */
  const requirementPins: Array<{ name: string; version: string }> = [];
  for (const file of requirementFiles(cwd)) {
    const pins = readRequirementsFile(file, new Set(), cwd, collected, extras);
    // Unreadable: readRequirementsFile named it in `collected`.
    if (pins === null) continue;
    indexUnrecorded = true;
    pushAll(requirementPins, pins);
    sources.push(file);
    // `--index-url` / `-i` replaces pypi.org for every pin of the file: private when it is not a
    // public index (pre-publish audit 2026-11-13, S4). `--extra-index-url` adds one beside pypi.org,
    // and pip takes each package from whichever index has the newest release, so any pin may come
    // from it: private too (blind audit round 4; until then the names were sent and only a notice
    // said so). The answer still names the extra index (LiveIntelligence.getRegistryNotice).
    // The options of every file it includes (`-r base.txt`, `-c constraints.txt`, nested) apply to the
    // whole install: `--index-url` in an included base.txt sent every pin to OSV.dev (R7, 1).
    const options = requirementIndexOptions(file, cwd);
    const privateExtra = options.extra.find((index) => !isPublicExtraPypiIndex(index));
    const replaced = options.index && !isPublicPypiIndex(options.index) ? options.index : null;
    const privateSource = replaced ?? privateExtra;
    if (privateSource) {
      // A registry-kind reason: pip may fetch ANY name of this install from it, a name not pinned yet
      // included, so it is recorded for the group as well as for each pin (pre-publish round 10, W4).
      const setting = replaced ? "--index-url" : (options.settings.find((s) => s.value === privateExtra)?.option ?? "--extra-index-url");
      for (const { name, version } of pins) privateIndex.push({ name, version, registry: sourceLabel(privateSource), file, wide: setting });
      registryWide.push({ file, registry: sourceLabel(privateSource), setting });
    }
    for (const index of options.extra) if (!isPublicPypiIndex(index)) extraIndexes.push({ file, index: sourceLabel(index) });
  }
  // A pin is dev-only when every file that pins it is installed for development only
  // (devOnlyRequirements); any other pin keeps an unknown scope, which is never discounted.
  const devOnly = devOnlyRequirements(includes);
  const pinnedIn = new Map<string, Set<string>>();
  for (const { file, name, version } of origins) {
    const files = pinnedIn.get(`${name}\0${version}`);
    if (files) files.add(file);
    else pinnedIn.set(`${name}\0${version}`, new Set([file]));
  }
  for (const { name, version } of requirementPins) {
    const files = [...(pinnedIn.get(`${name}\0${version}`) ?? [])];
    take(name, version, files.length > 0 && files.every(devOnly) ? true : undefined);
  }
  // With no lockfile, an exact pin pyproject.toml declares is what gets installed, as a
  // requirements pin is: checked. (A lockfile, when there is one, holds those versions itself.)
  let manifestPins = 0;
  if (pyproject !== null && !lockfile) {
    const declared = pyprojectPins(pyproject);
    manifestPins = declared.pins.length;
    if (manifestPins > 0) {
      for (const pin of declared.pins) take(pin.name, pin.version, pin.dev ? true : undefined);
      sources.push(pyprojectPath);
      indexUnrecorded = true;
      // What it declares with no exact version has nothing to check, and is listed; a workspace
      // member's ranges are pinned by the lockfile above it and are left alone.
      if (!pythonLockAbove(cwd)) for (const name of declared.unpinned) extras.unpinned.push({ file: pyprojectPath, name });
      for (const other of declared.direct) extras.uncheckable.push({ ...other, version: null, file: pyprojectPath });
      for (const ref of declared.references) {
        if (privateDirectReference(ref.location)) extras.directPrivate.push({ name: ref.name, version: null, registry: directLabel(ref.location), file: pyprojectPath });
      }
    }
  }
  pushAll(uncheckable, extras.uncheckable);
  // A direct reference to a location that is not public (`name @ https://pkgs.acme.dev/...`, a private
  // git host, `file:`): installed from there, never from pypi.org, so the name is private (R7, 3).
  pushAll(privateIndex, extras.directPrivate);
  // With no lockfile read, what an unreadable pyproject.toml declares was checked nowhere.
  if (pyprojectUnread && !lockfile) damaged.push(pyprojectUnread);
  // One problem per file, however many requirement files name it.
  const problems = [...new Map([...damaged, ...collected].map((p) => [p.file.toLowerCase(), p])).values()];
  // A name some other file here pins exactly has a version to check: only what nothing pins is unpinned.
  const unpinnedByFile = new Map<string, Set<string>>();
  for (const { file, name } of extras.unpinned) {
    if (versions.has(name)) continue;
    unpinnedByFile.set(file, (unpinnedByFile.get(file) ?? new Set()).add(name));
  }
  const unpinned = [...unpinnedByFile].map(([file, names]) => ({ file, names: [...names] }));
  const extra = {
    ...(uncheckable.length > 0 ? { uncheckable: dedupeUncheckable(uncheckable) } : {}),
    ...(unpinned.length > 0 ? { unpinned } : {}),
    ...(problems.length > 0 ? { problems } : {}),
    ...(privateIndex.length > 0 ? { privateIndex } : {}),
    ...(extraIndexes.length > 0 ? { extraIndexes } : {}),
    ...(registryWide.length > 0 ? { registryWide } : {}),
  };

  if (sources.length === 0) return { ...emptySource(), ...extra };
  // Only the manifest's own pins: a manifest with no lockfile, as package.json and Cargo.toml are
  // read. Its pins were checked as declared and what they install with them was resolved nowhere,
  // which the answer says (no range is given a floor: a ranged name is listed as unpinned).
  if (manifestPins > 0 && sources.length === 1) return found(versions, instances, pyprojectPath, "declared_ranges", { ranges: new Map(), ...extra });
  return found(versions, instances, sources[0], lockfile ? "lockfile" : "manifest", { extraSources: sources.slice(1), ...extra, ...(lockfile && !indexUnrecorded ? { indexRecorded: true } : {}) });
}

/** Parent directories searched for a Python lockfile that pins a workspace member (as resolution.ts's pyprojectUnpinned does). */
const MAX_LOCK_PARENTS = 6;

/** Whether a directory above `dir`, up to the repository root, holds a uv, Poetry or PDM lockfile: a workspace member is pinned there. */
function pythonLockAbove(dir: string): boolean {
  let parent = path.dirname(path.resolve(dir));
  for (let level = 0; level < MAX_LOCK_PARENTS; level++) {
    if (PYTHON_TOML_LOCKS.some((lock) => fs.existsSync(path.join(parent, lock)))) return true;
    if (fs.existsSync(path.join(parent, ".git")) || path.dirname(parent) === parent) return false;
    parent = path.dirname(parent);
  }
  return false;
}

/**
 * What a pyproject.toml's `[project] dependencies`, `[project.optional-dependencies]`,
 * `[dependency-groups]` and Poetry dependency tables (poetry-requirements.ts) declare, read as
 * requirement lines are: exact pins (`requests==2.19.1`, Poetry `requests = "2.19.1"`), the names
 * with no exact version, and direct references (`name @ git+https://…`). A pin in a dependency
 * group (or a Poetry dev table or group) is a development one; an extra's or the project's own is not.
 */
function pyprojectPins(content: string): {
  pins: Array<{ name: string; version: string; dev: boolean }>;
  unpinned: string[];
  direct: Array<{ name: string; kind: "git" | "url" }>;
  references: Array<{ name: string; location: string }>;
} {
  const declared = pyprojectRequirements(content);
  // Poetry's tables, written as the same requirement strings (poetry-requirements.ts).
  const poetry = poetryRequirements(content);
  // One requirement per line, as a requirements file holds them; a string that spans lines is no requirement.
  const lines = (dev: boolean) =>
    [...declared.filter((r) => (r.section === "dependency-groups") === dev).map((r) => r.text), ...poetry.filter((r) => r.dev === dev).map((r) => r.text)]
      .filter((text) => !/[\r\n]/.test(text))
      .join("\n");
  const pins = [
    ...parseRequirements(lines(false)).map((pin) => ({ ...pin, dev: false })),
    ...parseRequirements(lines(true)).map((pin) => ({ ...pin, dev: true })),
  ];
  const rest = unpinnedRequirements(`${lines(false)}\n${lines(true)}`);
  const pinned = new Set(pins.map((p) => p.name));
  return { pins, unpinned: rest.names.filter((name) => !pinned.has(name)), direct: rest.direct, references: rest.references };
}

function dedupeUncheckable(list: UncheckableDependency[]): UncheckableDependency[] {
  return [...new Map(list.map((u) => [`${u.file.toLowerCase()}|${u.name}|${u.version ?? ""}|${u.kind}`, u])).values()];
}

/** What a Pipfile.lock holds: its index releases, what it installs from elsewhere, and what could not be read in it. */
interface PipfileLockRead {
  pins: Array<{ name: string; version: string; dev: boolean }>;
  uncheckable: UncheckableDependency[];
  privateIndex: PrivateIndexEntry[];
  /** Why the file is not a whole Pipfile.lock, or null. */
  problem: string | null;
  /** Entries that could not be read (counted in `problem`). */
  malformed: number;
}

/**
 * A parsed Pipfile.lock: `default` (runtime) and `develop` (dev) entries. Every value is checked
 * before it is used, so one entry that is not what pipenv writes (a `version` that is no string)
 * costs that entry and is said, never the entries around it and never the whole file.
 */
function readPipfileLock(lock: unknown, file: string): PipfileLockRead {
  const out: PipfileLockRead = { pins: [], uncheckable: [], privateIndex: [], problem: null, malformed: 0 };
  const isTable = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);
  if (!isTable(lock) || !["_meta", "default", "develop"].some((key) => key in lock)) {
    out.problem = "it is valid JSON but not a Pipfile.lock: it has no `default` or `develop` section";
    return out;
  }
  // `"index": "<source name>"` names the Pipfile source a package comes from.
  const meta = isTable(lock._meta) ? lock._meta : {};
  const indexes = new Map<string, string>(
    (Array.isArray(meta.sources) ? meta.sources : [])
      .filter((s: { name?: unknown; url?: unknown }) => typeof s?.name === "string" && typeof s?.url === "string")
      .map((s: { name: string; url: string }) => [s.name, s.url]),
  );
  const defaultSource = [...indexes.values()][0];
  const unread: string[] = [];
  for (const [section, dev] of [["default", false], ["develop", true]] as const) {
    const entries = lock[section];
    if (entries === undefined) continue;
    if (!isTable(entries)) {
      unread.push(`the \`${section}\` section`);
      continue;
    }
    for (const [name, info] of Object.entries(entries)) {
      if (!isTable(info) || (info.version !== undefined && typeof info.version !== "string")) {
        unread.push(name.replace(/[^\w.@/-]+/g, "?").slice(0, 80));
        continue;
      }
      const entry = info as { version?: string; git?: unknown; file?: unknown; path?: unknown; index?: unknown };
      const version = entry.version?.replace(/^===?/, "");
      if (!version) {
        // `{"git": "https://…", "ref": "…"}` or `{"file": "https://…/x.whl"}`: installed, but not an index release.
        if (typeof entry.git === "string") out.uncheckable.push({ name: normalizePythonName(name), version: null, kind: "git", file });
        else if (typeof entry.file === "string" && /^https?:/i.test(entry.file)) out.uncheckable.push({ name: normalizePythonName(name), version: null, kind: "url", file });
        // From a host that is not public, or local code: the name is private (R8, B4).
        const location = typeof entry.git === "string" ? entry.git : typeof entry.file === "string" ? entry.file : typeof entry.path === "string" ? `file:${entry.path}` : null;
        if (location && privateDirectReference(location)) out.privateIndex.push({ name: normalizePythonName(name), version: null, registry: directLabel(location), file, ...(/^file:/i.test(location) ? { local: true as const } : {}) });
        continue;
      }
      // An entry that names no index came from the default source, the first one (pipenv): a
      // Pipfile whose only source is private wrote no `index` at all, and every name was sent (R8, B4).
      const index = typeof entry.index === "string" ? indexes.get(entry.index) : defaultSource;
      if (index && !isPublicPypiIndex(index)) out.privateIndex.push({ name: normalizePythonName(name), version, registry: sourceLabel(index), file });
      out.pins.push({ name: normalizePythonName(name), version, dev });
    }
  }
  if (unread.length > 0) {
    out.malformed = unread.length;
    out.problem = `${unread.length === 1 ? "1 entry is" : `${unread.length} entries are`} not what pipenv writes (${unread.slice(0, 3).join(", ")}${unread.length > 3 ? ", ..." : ""}) and ${unread.length === 1 ? "was" : "were"} skipped, so ${unread.length === 1 ? "its version was" : "their versions were"} not checked`;
  }
  return out;
}

/**
 * Why a poetry.lock, uv.lock or pdm.lock is not the whole file its tool wrote for this project,
 * or null when nothing says so. Beyond the signs every TOML lockfile shares (tomlLockDamage), a
 * file cut cleanly between two `[[package]]` tables still parses, so each format is held to what
 * its tool always writes:
 * - poetry.lock ends with a `[metadata]` table;
 * - uv.lock holds a table for the project itself and for every package another table depends
 *   on, and for every requirement `pyproject.toml` declares for all environments that no
 *   `[tool.uv]` override or constraint covers.
 * pdm.lock carries nothing of the kind (its `[metadata]` comes first).
 */
function pythonLockDamage(name: string, content: string, pyproject: string | null): { reason: string; missing: number; behindManifest?: true } | null {
  const shared = tomlLockDamage(content);
  const parts: string[] = [];
  let missing = 0;
  let outOfDate = false;
  if (name === "poetry.lock" && !/^\[metadata\]\s*$/m.test(content)) parts.push("it has no [metadata] table, which Poetry writes last");
  if (name === "uv.lock") {
    const { tables, dangling } = uvLockTables(content);
    const some = (list: string[]) => `${list.slice(0, 3).join(", ")}${list.length > 3 ? ", ..." : ""}`;
    if (tables.size === 0) parts.push("it holds no [[package]] table, and uv always writes at least the project's own");
    if (dangling.length > 0) {
      parts.push(`${dangling.length} package${dangling.length === 1 ? "" : "s"} named as ${dangling.length === 1 ? "a dependency has" : "dependencies have"} no [[package]] table (${some(dangling)})`);
    }
    // A requirement behind an environment marker need not be locked; one for every environment is.
    // One an override or constraint names may legitimately not be locked (its marker can rule it out everywhere).
    const declared = pyproject === null ? [] : pyprojectRequirements(pyproject).filter((r) => r.section === "dependencies" && !r.text.includes(";"));
    const covered = new Set(pyproject === null ? [] : uvOverrideRequirements(pyproject).map(requirementName));
    const undeclared = [...new Set(declared.map((r) => requirementName(r.text)).filter((n): n is string => n !== null && !tables.has(n) && !covered.has(n)))].sort();
    if (undeclared.length > 0 && tables.size > 0) {
      outOfDate = dangling.length === 0;
      parts.push(`pyproject.toml declares ${undeclared.length === 1 ? "a dependency" : `${undeclared.length} dependencies`} it holds no [[package]] table for (${some(undeclared)})`);
    }
    missing = new Set([...dangling, ...undeclared]).size;
  }
  if (parts.length === 0) return shared;
  if (shared) return { reason: `${shared.reason}; ${parts.join("; ")}`, missing: shared.missing + missing };
  // Only the manifest disagrees: cut between two tables, or written before the manifest changed.
  if (outOfDate && parts.length === 1) return { reason: `it is truncated or out of date: ${parts[0]}`, missing, behindManifest: true };
  return { reason: `it is truncated or damaged: ${parts.join("; ")}`, missing };
}

/** The name a PEP 508 requirement string starts with, PEP 503 normalised; null when it starts with none. */
function requirementName(requirement: string): string | null {
  const name = /^\s*([A-Za-z0-9][A-Za-z0-9._-]*)/.exec(requirement)?.[1];
  return name ? normalizePythonName(name) : null;
}

/**
 * The packages a uv.lock holds a `[[package]]` table for, and those its tables depend on that
 * have none (`dependencies`, `[package.optional-dependencies]`, `[package.dev-dependencies]`).
 * `[package.metadata]` repeats the manifest's requirements, markers and all, and a requirement
 * no supported environment needs has no table: it is not read for this.
 */
function uvLockTables(content: string): { tables: Set<string>; dangling: string[] } {
  const blocks = content.split(/^\[\[package\]\]\s*$/m).slice(1);
  const tables = new Set<string>();
  for (const block of blocks) {
    const name = /^name\s*=\s*"([^"]*)"/m.exec(block.split(/^\[/m)[0])?.[1];
    if (name) tables.add(normalizePythonName(name));
  }
  const dangling = new Set<string>();
  for (const block of blocks) {
    const edges = block.split(/^\[package\.metadata/m)[0];
    for (const edge of edges.matchAll(/\{\s*name\s*=\s*"([A-Za-z0-9][A-Za-z0-9._-]*)"/g)) {
      const name = normalizePythonName(edge[1]);
      if (!tables.has(name)) dangling.add(name);
    }
  }
  return { tables, dangling: [...dangling].sort() };
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
 * scan reports as a file whose pins were not checked. So does a file that
 * cannot be read, the file itself or one it includes with `-r` (`includedBy`
 * says which line named it): its pins are unknown, which is not "no pins".
 */
export function readRequirementsFile(
  file: string,
  visited: Set<string> = new Set(),
  root: string = path.dirname(path.resolve(file)),
  problems: LockfileProblem[] = [],
  extras?: RequirementExtras,
  includedBy?: string,
): Array<{ name: string; version: string }> | null {
  const key = path.resolve(file).toLowerCase();
  if (visited.has(key)) return [];
  visited.add(key);
  let content: string;
  try {
    content = readTextFile(file);
  } catch (error) {
    const absent = (error as NodeJS.ErrnoException | null)?.code === "ENOENT";
    const why = absent ? "was not found" : unreadableReason(error);
    problems.push({ file: path.resolve(file), error: includedBy ? `${includedBy} ${why}, so the pins in it were not checked` : why });
    return null;
  }
  const dir = path.dirname(file);
  const out = parseRequirements(content);
  if (extras?.origins) for (const pin of out) extras.origins.push({ file: path.resolve(file), ...pin });
  if (extras) {
    // What this file lists but does not pin: a name with a range or no version, a git or URL requirement.
    const listed = unpinnedRequirements(content);
    for (const name of listed.names) extras.unpinned.push({ file: path.resolve(file), name });
    for (const other of listed.direct) extras.uncheckable.push({ ...other, version: null, file: path.resolve(file) });
    for (const ref of listed.references) {
      if (privateDirectReference(ref.location)) extras.directPrivate.push({ name: ref.name, version: null, registry: /^file:/i.test(ref.location) ? "a local file" : sourceLabel(ref.location.replace(/^git\+/i, "")), file: path.resolve(file) });
    }
  }
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
    if (option === "r") {
      // Recorded for a file read before, too: who includes a file decides what its pins are for.
      extras?.includes?.push({ from: path.resolve(file), to: path.resolve(included) });
      pushAll(out, readRequirementsFile(included, visited, root, problems, extras, `\`-r ${target.slice(0, 200)}\` in ${path.basename(file)}`) ?? []);
    } else for (const pin of parseRequirements(safeRead(included))) constraints.set(pin.name, pin.version);
  }
  if (constraints.size > 0) {
    const pinned = new Set(out.map((p) => p.name));
    for (const name of unpinnedRequirements(content).names) {
      const version = constraints.get(name);
      if (!version || pinned.has(name)) continue;
      out.push({ name, version });
      // The constraint gives the version; the file that lists the name is what installs it.
      extras?.origins?.push({ file: path.resolve(file), name, version });
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
    return included; // missing: nothing to escape through; what a failed read means is the caller's to say
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
    return readTextFile(file);
  } catch {
    return "";
  }
}

/**
 * A requirements file's `--index-url` / `-i` (the last one, as pip takes it), every
 * `--extra-index-url`, and every `--find-links` / `-f` location that is not public (read as an extra
 * index: pip may take any package from it). Options are read as pip's optparse reads them
 * (pipLineOptions): `-i<url>` attached, and any unambiguous prefix of a long option (`--index`,
 * `--extra-index`, `--find`). Each of those spellings sent every pin to OSV.dev (R8, B4).
 */
export function indexOptions(content: string): IndexOptions {
  let index: string | null = null;
  const extra: string[] = [];
  const settings: IndexOptions["settings"] = [];
  for (const raw of requirementLines(content)) {
    if (!raw.includes("-")) continue;
    for (const { option, value } of pipLineOptions(raw)) {
      if (!value) continue;
      if (option === "index-url") index = value;
      else if (option === "extra-index-url") extra.push(value);
      else if (option === "find-links" && !isPublicFindLinks(value)) extra.push(findLinksLabel(value));
      else continue;
      settings.push({ option: `--${option}`, value: option === "find-links" ? findLinksLabel(value) : value });
    }
  }
  return { index, extra, settings };
}

/**
 * A requirements file's index options; `settings` names the option each value came from, so the
 * answer says which setting makes the names private (pre-publish round 10, W4).
 */
export interface IndexOptions {
  index: string | null;
  extra: string[];
  settings: Array<{ option: string; value: string }>;
}

/** At most this many files deep a requirements file's includes are followed for its index options. */
const MAX_INCLUDE_DEPTH = 16;

/**
 * The index options of a requirements file and of every file it includes, `-r` and `-c`, nested,
 * each relative to the file that names it and confined to `root` as the pins are (a loop or a
 * depth past MAX_INCLUDE_DEPTH stops there). pip applies an option from any of them to the whole
 * install. The last `--index-url` read is pip's, but a non-public one anywhere is what matters.
 */
export function requirementIndexOptions(file: string, root: string, visited: Set<string> = new Set(), depth = 0): IndexOptions {
  const key = path.resolve(file).toLowerCase();
  if (visited.has(key) || depth > MAX_INCLUDE_DEPTH) return { index: null, extra: [], settings: [] };
  visited.add(key);
  const content = safeRead(file);
  const own = indexOptions(content);
  let index = own.index;
  const extra = [...own.extra];
  const settings = [...own.settings];
  for (const { target } of requirementOptions(content)) {
    const included = confinedInclude(path.dirname(file), target, root);
    if (included === null) continue;
    const nested = requirementIndexOptions(included, root, visited, depth + 1);
    // A replacing index that is not public wins over a public one, wherever it is.
    if (nested.index && (!index || isPublicPypiIndex(index))) index = nested.index;
    pushAll(extra, nested.extra);
    pushAll(settings, nested.settings);
  }
  return { index, extra, settings };
}

/** `-r file` / `--requirement=file` / `-c file` / `--constraint file` (and `-rfile`, `--requir`...): local paths only. */
export function requirementOptions(content: string): Array<{ option: "r" | "c"; target: string }> {
  const out: Array<{ option: "r" | "c"; target: string }> = [];
  for (const raw of requirementLines(content)) {
    if (!/^\s*-/.test(raw)) continue;
    for (const { option, value } of pipLineOptions(raw)) {
      if (!value || (option !== "requirement" && option !== "constraint") || /^[a-z][a-z+]*:\/\//i.test(value)) continue;
      out.push({ option: option === "requirement" ? "r" : "c", target: value });
    }
  }
  return out;
}

/**
 * A requirements file a resolver wrote: `uv pip compile` or `pip-compile` output. Its source of
 * truth is the input it was compiled from (requirements.in, pyproject.toml), and a hand edit of a
 * pin is reverted by the next compile. Each pin's `# via` annotation says why it is there: an
 * input (`-r requirements.in`, `name (pyproject.toml)`) or only the packages that require it.
 * The server read `# via requests` pins as declared and said "change `idna==2.7` to `idna==3.15`
 * in requirements.txt", which requests 2.19.1 (`idna<2.8`) then refused (audit 6.2.5 A-4).
 */
export interface CompiledRequirements {
  /** The tool its header names; null when only `# via` annotations show it (a `--no-header` compile). */
  tool: "uv" | "pip-compile" | null;
  /** The single input file the header's command (else the `# via` annotations) names, as written there; null when none or several. */
  input: string | null;
  /** PEP 503 name -> its `# via` entries as written (an entry per required-by package or input). */
  via: Map<string, string[]>;
}

/** Header lines searched for the tool and its command (uv writes 2, pip-compile 5 to 7). */
const COMPILED_HEADER_LINES = 12;

export function compiledRequirements(content: string): CompiledRequirements | null {
  const lines = content.split(/\r?\n/);
  const head = lines.slice(0, COMPILED_HEADER_LINES);
  const tool = head.some((l) => /^#.*autogenerated by uv\b/i.test(l))
    ? "uv"
    : head.some((l) => /^#.*autogenerated by pip-compile\b/i.test(l))
      ? "pip-compile"
      : null;
  const via = viaAnnotations(lines);
  if (tool === null && via.size === 0) return null;
  return { tool, input: headerInput(head) ?? viaInput(via), via };
}

/** Whether a `# via` entry is a package that requires the pin (not an input file or `-c` constraint). */
function viaIsPackage(entry: string): boolean {
  return /^[A-Za-z0-9][A-Za-z0-9._-]*(?:\[[^\]]*\])?$/.test(entry);
}

/** The input a `# via` entry names: `-r requirements.in`, or `project (pyproject.toml)`. */
function viaSource(entry: string): string | null {
  return /^-r\s+(\S+)$/.exec(entry)?.[1] ?? /^\S+\s+\(([^()\s]+)\)$/.exec(entry)?.[1] ?? null;
}

/**
 * Indirect: compiled in only because other packages require it (every `# via` entry is a package).
 * False for a pin an input names, and for one with no annotation (its reason is unknown).
 */
export function compiledIndirect(compiled: CompiledRequirements, name: string): boolean {
  const entries = (compiled.via.get(normalizePythonName(name)) ?? []).filter((e) => !/^-c\s/.test(e));
  return entries.length > 0 && entries.every(viaIsPackage);
}

/** The packages a compiled pin is `# via` (those that require it), PEP 503 normalised. */
export function compiledRequiredBy(compiled: CompiledRequirements, name: string): string[] {
  return (compiled.via.get(normalizePythonName(name)) ?? []).filter(viaIsPackage).map((e) => normalizePythonName(e.replace(/\[.*$/, "")));
}

/**
 * `# via` annotations per pin, in both styles the tools write: split (pip-tools 6+, uv)
 *   idna==2.7
 *       # via requests          or      # via
 *                                       #   requests
 *                                       #   -r requirements.in
 * and pip-tools 5's inline `idna==2.7  # via requests, urllib3`.
 */
function viaAnnotations(lines: string[]): Map<string, string[]> {
  const out = new Map<string, string[]>();
  let current: string | null = null;
  let listing = false;
  const add = (entry: string) => {
    const e = entry.trim();
    if (current && e) out.set(current, [...(out.get(current) ?? []), e]);
  };
  for (const raw of lines) {
    if (raw.length > MAX_REQUIREMENT_LINE) continue;
    const line = raw.trim();
    if (!line.startsWith("#")) {
      listing = false;
      if (line.startsWith("--hash") || line === "" || line.startsWith("-")) continue; // a hash continuation or an option keeps the pin
      const pin = /^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*===?/.exec(line);
      current = pin ? normalizePythonName(pin[1]) : null;
      const inline = /\s#\s*via\s+(.+)$/.exec(line);
      if (current && inline) for (const e of inline[1].split(",")) add(e);
      continue;
    }
    const via = /^#\s*via\b\s*(.*)$/.exec(line);
    if (via) {
      listing = via[1].trim() === "";
      if (!listing) add(via[1]);
    } else if (listing && /^#\s{2,}\S/.test(line)) {
      add(line.replace(/^#\s+/, ""));
    } else {
      listing = false;
    }
  }
  return out;
}

/** Input-file names a compile command takes: requirements.in / *.txt, pyproject.toml, setup.cfg, setup.py. */
const COMPILE_INPUT = /(?:\.in|\.txt|(?:^|\/)pyproject\.toml|(?:^|\/)setup\.cfg|(?:^|\/)setup\.py)$/i;
/** Options whose value is a file but not the input (output, constraints, overrides). */
const COMPILE_FILE_OPTIONS = new Set(["-o", "--output-file", "-c", "--constraint", "--constraints", "--override", "--overrides", "-b", "--build-constraint", "--build-constraints"]);

/** The one input file the header's command line names (uv: after "via the following command:"; pip-compile: "by the following command:" / "To update, run:"). */
function headerInput(head: string[]): string | null {
  const at = head.findIndex((l) => /following command:|to update, run:/i.test(l));
  if (at < 0) return null;
  const command = head.slice(at + 1).map((l) => l.replace(/^#\s*/, "").trim()).find((l) => l.length > 0);
  if (!command) return null;
  const tokens = command.split(/\s+/);
  const inputs = tokens.filter((t, i) => !t.startsWith("-") && COMPILE_INPUT.test(t) && !COMPILE_FILE_OPTIONS.has(tokens[i - 1] ?? ""));
  return inputs.length === 1 ? inputs[0] : null;
}

/** The one input the `# via` annotations name (`-r requirements.in`, `(pyproject.toml)`), when they name exactly one. */
function viaInput(via: Map<string, string[]>): string | null {
  const sources = new Set<string>();
  for (const entries of via.values()) for (const e of entries) {
    const s = viaSource(e);
    if (s) sources.add(s);
  }
  return sources.size === 1 ? [...sources][0] : null;
}

/** What requirement files list without pinning, gathered while they are read (resolvePython). */
export interface RequirementExtras {
  /** A name with a range or no version at all: nothing installed can be read from the line. */
  unpinned: Array<{ file: string; name: string }>;
  /** A requirement installed from git or a URL: not a release of the index package. */
  uncheckable: UncheckableDependency[];
  /** A direct reference whose location is not public: the name is private. */
  directPrivate: PrivateIndexEntry[];
  /** When set: every pin read, with the file it is written in (absolute). */
  origins?: Array<{ file: string; name: string; version: string }>;
  /** When set: every `-r` include followed, as the including and the included file (absolute). */
  includes?: Array<{ from: string; to: string }>;
}

/**
 * What a requirements file lists with no exact pin, PEP 503 normalised:
 * `names` ("flask", "flask>=2", "urllib3~=1.26.0") and `direct` references,
 * which install from git or a URL (`pkg @ git+https://…`, `-e git+…#egg=pkg`,
 * a bare archive URL) and are no release of the index package.
 *
 * `pydantic>=2.0.0` used to vanish here: no pin, so nothing was sent to OSV,
 * and the answer read "pydantic unknown (direct): no known advisories" (audit
 * 2026-11-11, T4). The line names a dependency with no installed version to
 * check; that is "not checked", never "no advisories".
 */
export function unpinnedRequirements(content: string): {
  names: string[];
  direct: Array<{ name: string; kind: "git" | "url" }>;
  /** Every direct reference with where it points (`file:` ones too), for the private-name rules. */
  references: Array<{ name: string; location: string }>;
} {
  const names: string[] = [];
  const direct: Array<{ name: string; kind: "git" | "url" }> = [];
  const references: Array<{ name: string; location: string }> = [];
  const kindOf = (location: string): "git" | "url" => (/^git\+|\.git(?:[@#]|$)/i.test(location) ? "git" : "url");
  for (const raw of requirementLines(content)) {
    const line = raw.replace(/(^|\s)#.*$/, "").trim();
    if (!line) continue;
    // `-e git+https://host/repo.git#egg=name` / `--editable <url>`: the egg fragment names it. A local path is the project's own code.
    const editable = /^(?:-e|--editable)[\s=]+(\S+)/.exec(raw.trim());
    if (editable) {
      const egg = /[#&]egg=([A-Za-z0-9][A-Za-z0-9._-]*)/.exec(editable[1]);
      if (/^[a-z][a-z0-9+.-]*:\/\//i.test(editable[1]) && !/^file:/i.test(editable[1])) {
        direct.push({ name: normalizePythonName(egg?.[1] ?? archiveName(editable[1])), kind: kindOf(editable[1]) });
      }
      if (/^[a-z][a-z0-9+.-]*:/i.test(editable[1])) references.push({ name: normalizePythonName(egg?.[1] ?? archiveName(editable[1])), location: editable[1] });
      continue;
    }
    if (line.startsWith("-")) continue;
    const spec = line.split(";")[0].trim();
    // A bare URL requirement: the archive's name is all there is.
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(spec)) {
      if (!/^file:/i.test(spec)) direct.push({ name: normalizePythonName(archiveName(spec)), kind: kindOf(spec) });
      references.push({ name: normalizePythonName(archiveName(spec)), location: spec });
      continue;
    }
    const m = /^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(.*)$/.exec(spec);
    if (!m) continue;
    // PEP 508 direct reference: `name @ https://…` or `name @ git+https://…`.
    const reference = /^@\s*(\S+)/.exec(m[2]);
    if (reference) {
      if (!/^file:/i.test(reference[1])) direct.push({ name: normalizePythonName(m[1]), kind: kindOf(reference[1]) });
      references.push({ name: normalizePythonName(m[1]), location: reference[1] });
      continue;
    }
    // An exact pin is parseRequirements' to return; `vendor/pkg.whl` is a local path, not a name.
    if (exactClause(m[2].replace(REQUIREMENT_OPTION, "")) !== null || /^[\\/]/.test(m[2])) continue;
    names.push(normalizePythonName(m[1]));
  }
  return { names: [...new Set(names)], direct, references };
}

/** The package name an archive or repository URL ends in: `…/requests-2.25.0-py3-none-any.whl` -> requests, `…/repo.git@v1` -> repo. */
function archiveName(url: string): string {
  const last = url.split(/[?#]/)[0].replace(/\/+$/, "").split("/").pop() ?? url;
  const stem = last.replace(/\.git(?:@.*)?$/i, "").replace(/@.*$/, "").replace(/\.(?:whl|zip|tar\.gz|tgz|tar\.bz2|tar)$/i, "");
  return /^([A-Za-z0-9][A-Za-z0-9._]*?)(?:-\d.*)?$/.exec(stem)?.[1] ?? stem;
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
function packageOrigin(block: string, body: string): "index" | "git" | "url" | "file" | "local" {
  const uv = /^source\s*=\s*\{\s*([a-z-]+)\s*=/m.exec(body)?.[1];
  if (uv && uv !== "registry") return uv === "git" ? "git" : uv === "url" ? "url" : uv === "path" ? "file" : "local";
  const poetrySource = /^\[package\.source\]\s*$([\s\S]*?)(?=^\[|(?![\s\S]))/m.exec(block)?.[1] ?? "";
  const poetryType = /^type\s*=\s*"([^"]*)"/m.exec(poetrySource)?.[1];
  if (poetryType === "git" || poetryType === "url" || poetryType === "file") return poetryType;
  return poetryType === "directory" ? "local" : "index";
}

/**
 * [[package]] tables from poetry.lock (any version) or uv.lock. A pre-1.2
 * poetry.lock records `category = "dev"` for dev-only packages; newer files
 * and uv.lock do not record scope here, so it stays unknown. A package from
 * git, a URL or a local archive is no index release: it is returned in
 * `uncheckable`, never as an instance.
 */
export function readTomlPackageLock(content: string): {
  versions: Map<string, string>;
  instances: InstanceSet;
  uncheckable: Array<{ name: string; version: string | null; kind: "git" | "url" | "file" }>;
  /**
   * Index releases from an index other than pypi.org (uv `registry`, a poetry `legacy` source), git
   * or URL packages from a host that is not public, and local code (a path, a directory, the project
   * itself): private, never sent (R8, B4: a uv.lock git source on a private host reached OSV.dev).
   */
  privateIndex: Array<{ name: string; version: string; registry: string; local?: true }>;
} {
  const versions = new Map<string, string>();
  const instances = new InstanceSet();
  const uncheckable: Array<{ name: string; version: string | null; kind: "git" | "url" | "file" }> = [];
  const privateIndex: Array<{ name: string; version: string; registry: string; local?: true }> = [];
  for (const block of content.split(/^\[\[package\]\]\s*$/m).slice(1)) {
    // Stop at the next table header (e.g. [package.dependencies], [metadata]).
    const body = block.split(/^\[/m)[0];
    const field = (key: string) => new RegExp(`^${key}\\s*=\\s*"([^"]*)"`, "m").exec(body)?.[1] ?? null;
    const name = field("name");
    const version = field("version");
    if (!name || !version) continue;
    const normalized = normalizePythonName(name);
    const origin = packageOrigin(block, body);
    if (origin !== "index") {
      if (origin !== "local") uncheckable.push({ name: normalized, version, kind: origin });
      const location = originLocation(block, body);
      if (origin === "local" || origin === "file") privateIndex.push({ name: normalized, version, registry: `local code${location ? ` (${location})` : ""}`, local: true });
      else if (location && privateDirectReference(location)) privateIndex.push({ name: normalized, version, registry: directLabel(location) });
      continue;
    }
    const index = indexUrl(block, body);
    if (index && !isPublicPypiIndex(index)) privateIndex.push({ name: normalized, version, registry: sourceLabel(index) });
    const category = field("category");
    instances.add(normalized, version, category === null ? undefined : category === "dev");
    if (!versions.has(normalized)) versions.set(normalized, version);
  }
  return { versions, instances, uncheckable, privateIndex };
}

/** Where a git, URL or local package comes from: uv `source = { git = "..." }` (or url, path, ...), a poetry `[package.source]` url. */
function originLocation(block: string, body: string): string | null {
  const uv = /^source\s*=\s*\{\s*[a-z-]+\s*=\s*"([^"]+)"/m.exec(body)?.[1];
  if (uv) return uv;
  const poetrySource = /^\[package\.source\]\s*$([\s\S]*?)(?=^\[|(?![\s\S]))/m.exec(block)?.[1] ?? "";
  return /^url\s*=\s*"([^"]+)"/m.exec(poetrySource)?.[1] ?? null;
}

/** A direct location as it may be shown: no credentials, query or fragment. */
function directLabel(location: string): string {
  return /^file:/i.test(location) ? "a local file" : sourceLabel(location.replace(/^git\+/i, ""));
}

/** The index an index release came from: uv `source = { registry = "..." }`, a poetry `[package.source]` url. */
function indexUrl(block: string, body: string): string | null {
  const uv = /^source\s*=\s*\{\s*registry\s*=\s*"([^"]+)"/m.exec(body)?.[1];
  if (uv) return uv;
  const poetrySource = /^\[package\.source\]\s*$([\s\S]*?)(?=^\[|(?![\s\S]))/m.exec(block)?.[1] ?? "";
  return /^url\s*=\s*"([^"]+)"/m.exec(poetrySource)?.[1] ?? null;
}

/**
 * Why a poetry.lock, uv.lock or pdm.lock is not the whole file its tool
 * wrote, or null when nothing says so: a `[[package]]` table with no name or
 * version, or a string, array or inline table still open where the file ends.
 * A lockfile cut short reads as fewer packages, with nothing else to show for
 * it (audit 2026-11-11, M12).
 */
export function tomlLockDamage(content: string): { reason: string; missing: number } | null {
  const blocks = content.split(/^\[\[package\]\]\s*$/m).slice(1);
  let nameless = 0;
  for (const block of blocks) {
    const body = block.split(/^\[/m)[0];
    const named = /^name\s*=\s*"[^"]*"/m.test(body);
    // uv writes no version for a project whose version is dynamic; that table is local code, never an index release.
    const versioned = /^version\s*=\s*"[^"]*"/m.test(body) || packageOrigin(block, body) !== "index";
    if (!named || !versioned) nameless++;
  }
  // Brackets and quotes over the file's last table: an open one means the file stops mid-value.
  const tail = content.slice(Math.max(0, content.lastIndexOf("\n[")));
  let depth = 0;
  let quote: string | null = null;
  let openString = false;
  for (const line of tail.split(/\r?\n/)) {
    if (line.trim() === "" || line.length > MAX_REQUIREMENT_LINE * 4) continue;
    quote = null;
    for (let i = 0; i < line.length; i++) {
      const ch = line[i];
      if (quote) {
        if (ch === "\\" && quote === '"') i++;
        else if (ch === quote) quote = null;
      } else if (ch === '"' || ch === "'") quote = ch;
      else if (ch === "#") break;
      else if (ch === "[" || ch === "{") depth++;
      else if (ch === "]" || ch === "}") depth--;
    }
    // TOML basic strings do not span lines in a lockfile: a quote still open at the line's end is a cut.
    openString = quote !== null;
  }
  // The table header's own brackets balance, so anything left open is a value.
  const parts: string[] = [];
  if (nameless > 0) parts.push(`${nameless} [[package]] table${nameless === 1 ? " has" : "s have"} no name or version`);
  if (openString) parts.push("its last line ends inside a string");
  else if (depth > 0) parts.push("its last array or table is not closed");
  return parts.length > 0 ? { reason: `it is truncated or damaged: ${parts.join("; ")}`, missing: nameless } : null;
}

/** A per-requirement option after the specifier (`--hash=sha256:...`, `--config-settings x`): not part of it. */
const REQUIREMENT_OPTION = /\s--?[A-Za-z][\w-]*(?:[=\s]\S+)?/g;

/**
 * The version an `==` (or `===`) clause of a version specifier names, whatever clauses stand
 * beside it: `==6.0.4,!=6.0.5` and `>=2.5,==2.8` install that one version or nothing, so each is
 * an exact pin. Null when no clause is exact (`>=2,<3`, `~=1.4`, `!=8.0.0`). A specifier in
 * parentheses (`name (==1.2)`, PEP 508) reads the same. A prefix match (`==2.32.*`) names a
 * series of releases, not one version, so it is no exact clause.
 */
export function exactClause(specifier: string): string | null {
  const clauses = specifier.trim().replace(/^\(/, "").replace(/\)$/, "");
  for (const clause of clauses.split(",")) {
    const exact = /^\s*===?\s*([^\s,;()]+)\s*$/.exec(clause);
    if (exact && !exact[1].includes("*")) return exact[1];
  }
  return null;
}

/**
 * Exact pins from a requirements file: `name==1.2`, `name===1.2`,
 * `name[extra1,extra2]==1.2`, with environment markers and inline comments,
 * and an `==` clause among others (`name==1.2,!=1.3`: exactClause).
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
    const spec = line.split(";")[0].replace(REQUIREMENT_OPTION, "").trim();
    const match = /^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(.*)$/.exec(spec);
    const version = match ? exactClause(match[2]) : null;
    if (!match || version === null) continue;
    out.push({ name: normalizePythonName(match[1]), version });
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
    mod = parseGoMod(readTextFile(goModPath));
  } catch {
    return emptySource(); // present and unreadable: resolveVersionSource names it and why
  }
  const problems: LockfileProblem[] = [];
  // Every go.mod names its module; one that does not, and requires nothing, is not a go.mod.
  if (mod.module === null && mod.rawRequires.length === 0) {
    return { ...emptySource(), problems: [{ file: goModPath, error: "it has no `module` directive and no requirement could be read from it: it is damaged or not a go.mod" }] };
  }
  // A directive block still open where the file ends: the lines after the cut are gone.
  if (mod.unclosed) problems.push(partialRead(goModPath, `it is truncated: its last \`${mod.unclosed} (\` block is not closed`));
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
        for (const [module, version] of selectedFromGoSum(readTextFile(goSumPath))) {
          if (!selected.has(module)) selected.set(module, version);
        }
      } catch (error) {
        // Before go 1.17 the modules go.mod does not list are recorded in go.sum only.
        problems.push({ file: goSumPath, error: `${unreadableReason(error)}, and before go 1.17 the modules go.mod does not list are recorded there only, so they were not checked` });
      }
    }
  }
  const versions = new Map<string, string>();
  // Local code: the module itself, and every module `replace` points at a directory. Never a proxy
  // release, so never sent: `replace github.com/acme/core => ../core` sent the module path from
  // dependency_check, upgrade_impact and the briefing (R8).
  const privateIndex: PrivateIndexEntry[] = [];
  const local = (module: string, why: string, file = goModPath) => privateIndex.push({ name: module, version: null, registry: why, file, local: true });
  if (mod.module) local(mod.module, "local code (this go.mod's own module)");
  for (const module of mod.localReplaced) local(module, "local code (replaced by a directory in go.mod)");
  // A workspace that uses this module builds it with go.work's `replace` directives, which win over go.mod's.
  const work = goWorkFor(cwd, (file, error) => {
    problems.push({ file, error: `${unreadableReason(error)}, so any \`replace\` it holds for this module was not applied` });
  });
  for (const module of work?.localReplaced ?? []) local(module, "local code (replaced by a directory in go.work)", work?.file);
  for (const [module, version] of selected) {
    const inWorkspace = work?.replacement(module, version);
    const target = inWorkspace !== undefined ? inWorkspace : mod.replacement(module, version);
    if (target === null) continue; // replaced by a local directory: local code, not a registry module
    if (target) versions.set(target.module, target.version);
    else if (!versions.has(module)) versions.set(module, version);
  }
  const instances = new InstanceSet();
  for (const [module, version] of versions) instances.add(module, version);
  return found(versions, instances, goModPath, "lockfile", {
    ...(work ? { extraSources: [work.file] } : {}),
    ...(privateIndex.length > 0 ? { privateIndex } : {}),
    ...(problems.length > 0 ? { problems } : {}),
  });
}

/** Directories above a module searched for the go.work that uses it. */
const MAX_WORK_PARENTS = 6;
/** `use` entries read from one go.work; a workspace with more is not a hand-written one. */
const MAX_WORKSPACE_MODULES = 2000;

/**
 * The go.work files that can apply to the module in `moduleDir`: the directory's own and its
 * parents', nearest first, up to the repository root. The go command takes the nearest one.
 */
export function goWorkCandidates(moduleDir: string): string[] {
  const out: string[] = [];
  let dir = path.resolve(moduleDir);
  for (let level = 0; level <= MAX_WORK_PARENTS; level++) {
    out.push(path.join(dir, "go.work"));
    if (fs.existsSync(path.join(dir, ".git")) || path.dirname(dir) === dir) break;
    dir = path.dirname(dir);
  }
  return out;
}

/** The workspace file that applies to a module, with what its `replace` directives say. */
export interface GoWork {
  /** Absolute path of the go.work. */
  file: string;
  /** What `replace` maps a module version to: undefined for nothing, null for a local directory. */
  replacement: (module: string, version: string) => GoReplacement | undefined;
  /** Modules a `replace` points at a local directory. */
  localReplaced: string[];
  /** Whether any `replace` names the module, as what is replaced or as what replaces it. */
  touches: (module: string) => boolean;
}

/**
 * The go.work that the module in `moduleDir` is built with: the nearest one (goWorkCandidates),
 * and only when one of its `use` directives names the module's directory. In a workspace the
 * go.work `replace` directives decide what is built, over go.mod's own; a workspace file that
 * does not use the module says nothing about it. Null when there is none, or it cannot be read
 * (`unreadable` is then told which file and why: its directives are unknown, not absent).
 */
export function goWorkFor(moduleDir: string, unreadable?: (file: string, error: unknown) => void): GoWork | null {
  const file = goWorkCandidates(moduleDir).find((candidate) => fs.existsSync(candidate));
  if (!file) return null;
  let content: string;
  try {
    content = readTextFile(file);
  } catch (error) {
    unreadable?.(file, error);
    return null;
  }
  const used: string[] = [];
  let inUse = false;
  for (const raw of content.split(/\r?\n/)) {
    if (raw.length > MAX_REQUIREMENT_LINE || used.length >= MAX_WORKSPACE_MODULES) continue;
    const line = raw.replace(/\/\/.*$/, "").trim();
    if (!line) continue;
    if (inUse && line === ")") inUse = false;
    else if (/^use\s*\($/.test(line)) inUse = true;
    else if (inUse) used.push(line);
    else if (line.startsWith("use ") || line.startsWith("use\t")) used.push(line.slice(4).trim());
  }
  const here = path.resolve(moduleDir);
  const uses = used.some((entry) => path.relative(path.resolve(path.dirname(file), entry.replace(/^["`]|["`]$/g, "")), here) === "");
  if (!uses) return null;
  const parsed = parseGoMod(content);
  const touched = new Set<string>();
  for (const [key, target] of parsed.replaces) {
    touched.add(key.split(" ")[0]);
    if (target) touched.add(target.module);
  }
  return { file, replacement: parsed.replacement, localReplaced: parsed.localReplaced, touches: (module) => touched.has(module) };
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
  /** The `module` directive's path, or null. */
  module: string | null;
  /** Modules a `replace` points at a local directory. */
  localReplaced: string[];
  /** The directive whose `(` block is still open where the file ends (a truncated file), or null. */
  unclosed: string | null;
  /** Every `replace`, keyed by the module (or `module version`) it replaces. */
  replaces: ReadonlyMap<string, GoReplacement>;
} {
  const requires = new Map<string, { module: string; version: string; indirect: boolean }>();
  const replaces = new Map<string, GoReplacement>();
  let block: "require" | "replace" | null = null;
  /** Any directive's open block (`exclude (`, `retract (`, ...), read or not. */
  let open: string | null = null;

  for (const rawLine of content.split(/\r?\n/)) {
    const indirect = /\/\/\s*indirect\b/.test(rawLine);
    const line = rawLine.replace(/\/\/.*$/, "").trim();
    if (!line) continue;
    if (line === ")") {
      block = null;
      open = null;
      continue;
    }
    const anyOpener = /^([a-z]+)\s*\($/.exec(line);
    if (anyOpener) open = anyOpener[1];
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
  const module = /^module\s+"?([^\s"/]+(?:\/[^\s"]+)*)"?\s*(?:\/\/.*)?$/m.exec(content)?.[1] ?? null;
  const localReplaced = [...new Set([...replaces].filter(([, target]) => target === null).map(([key]) => key.split(" ")[0]))];
  return { requires: result, rawRequires, replacement, goVersionAtLeast117, module, localReplaced, unclosed: open, replaces };
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
