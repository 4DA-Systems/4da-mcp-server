// SPDX-License-Identifier: Apache-2.0
/**
 * Lockfile parsers, one per ecosystem, each reporting WHICH file it resolved
 * from as well as the versions it read.
 *
 * Priority per ecosystem: lock file (exact) > manifest (range/specifier).
 * Uses only Node.js built-ins — no external parsers. The source path is what
 * lets the live layer notice when that file changes and re-resolve (measured
 * 2026-09-10: a server started before a lockfile bump kept reporting hono
 * 4.13.3 after the lockfile said 4.13.5). The pnpm and yarn readers live in
 * js-lockfile-readers.ts; Python and Go in lockfile-parsers-pygo.ts.
 *
 * Every parser reports two things (2026-10-02):
 * - `instances`: EVERY installed copy, name@version, with the lockfile's own
 *   dev flag when it records one. A lockfile routinely holds several versions
 *   of one package (nested npm copies, two semver-incompatible crates). The
 *   reader used to keep one version per name, last one wins: measured against
 *   osv-scanner on 12 projects, nodegoat lost 287 of 1,091 installed copies
 *   and 4DA's src-tauri lost 143 of 934 — including its own `rsa 0.9.10`
 *   (RUSTSEC-2023-0071), overwritten by `rsa 0.10.0-rc.18` — and the direct
 *   `minimist@1.2.0` was reported as its nested `0.0.8`.
 * - `versions`: the ONE version per name a direct dependency resolves to (the
 *   top-level npm copy, the crate version a workspace member depends on),
 *   which dependency health and upgrade planning read.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { pushAll } from "../array-utils.js";
import { readBunLock, stripTrailingCommas } from "./bun-lockfile.js";
import {
  emptyReadReport,
  MAX_LOCKFILE_LINE,
  nonRegistrySource,
  pnpmLockDamageSteps,
  readPnpmLockSteps,
  readYarnLock,
  type LockDamage,
  type NonRegistryEntry,
} from "./js-lockfile-readers.js";
import { inspectYarnLock, type YarnInspection } from "./js-dev-scope.js";
import { lazyNpmCatalogs } from "./npm-catalog.js";
import { classifyNpmSpec } from "./npm-spec.js";
import { DEPENDENCY_SECTIONS, expandWorkspaces, isLocalSpec, isRuntimeSection, MAX_MEMBER_MANIFESTS, memberListGapText, memberNamesOf, nameMatchesAny, pnpmYamlList, readManifestDeclarations, type DeclaredSpec, type MemberListGap } from "./js-manifests.js";
import { goWorkCandidates, requirementFiles, resolveGo, resolvePython } from "./lockfile-parsers-pygo.js";
import { runSteps, type Steps } from "./yield-point.js";
import { emptySource, found, InstanceSet, partialRead, unreadableReason, type DeclaredDependency, type LockfileProblem, type PackageInstance, type VersionSource } from "./lockfile-types.js";
import { resolvePhp, resolveRuby } from "./lockfile-parsers-rbphp.js";
import { isMergeConflictError, readManifestText, readTextFile } from "./text-file.js";
import { isPublicCratesSource, sourceLabel, type PrivateIndexEntry } from "./private-packages.js";
import type { OsvEcosystem } from "./types.js";

export type { PackageInstance, VersionSource } from "./lockfile-types.js";

const LOCKFILES: Partial<Record<OsvEcosystem, string[]>> = {
  // npm installs from npm-shrinkwrap.json and ignores package-lock.json when both are present.
  npm: ["npm-shrinkwrap.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock"],
  "crates.io": ["Cargo.lock"],
  PyPI: ["poetry.lock", "uv.lock", "pdm.lock", "Pipfile.lock"],
  Go: ["go.mod", "go.sum"],
  // gems.locked is the same file under Bundler's other name (beside gems.rb).
  RubyGems: ["Gemfile.lock", "gems.locked"],
  Packagist: ["composer.lock"],
};

const MANIFESTS: Partial<Record<OsvEcosystem, string>> = {
  npm: "package.json",
  "crates.io": "Cargo.toml",
  // Its exact `==` pins are read when no lockfile is (resolvePython).
  PyPI: "pyproject.toml",
};

/**
 * Every lock file the resolver may read for this ecosystem, present or not,
 * in priority order; for Python also every requirements file present now.
 */
export function lockfileCandidates(cwd: string, ecosystem: OsvEcosystem): string[] {
  const fixed = (LOCKFILES[ecosystem] ?? []).map((name) => path.join(cwd, name));
  // bun.lockb cannot be read, but its arrival or removal changes what the answer must say.
  if (ecosystem === "npm") return [...fixed, path.join(cwd, BUN_BINARY_LOCK)];
  // A go.work in the directory or above it decides what a module it uses is built with (goWorkFor).
  if (ecosystem === "Go") return [...fixed, ...goWorkCandidates(cwd)];
  return ecosystem === "PyPI" ? [...fixed, ...requirementFiles(cwd)] : fixed;
}

/** Bun's binary lockfile (before Bun 1.2, and still written beside bun.lock by some setups). Not readable here. */
const BUN_BINARY_LOCK = "bun.lockb";

/** The manifest the resolver falls back to for this ecosystem, or null when it has none. */
export function manifestCandidate(cwd: string, ecosystem: OsvEcosystem): string | null {
  const name = MANIFESTS[ecosystem];
  return name ? path.join(cwd, name) : null;
}

/**
 * The versions one directory pins for one ecosystem, plus every lockfile that
 * is present but could not be read (`problems`). A damaged or conflicted
 * lockfile used to fall through silently to the next candidate or to "no
 * lockfile" (audit B-9): now the answer names the file and the error.
 */
export function resolveVersionSource(cwd: string, ecosystem: OsvEcosystem): VersionSource {
  return runSteps(resolveVersionSourceSteps(cwd, ecosystem));
}

/** resolveVersionSource, pausing inside the readers that can take seconds (pnpm; pre-publish round 10, W11). */
export function* resolveVersionSourceSteps(cwd: string, ecosystem: OsvEcosystem): Steps<VersionSource> {
  let read: VersionSource;
  let thrown: LockfileProblem | null = null;
  try {
    read = yield* readVersionSourceSteps(cwd, ecosystem);
  } catch (error) {
    read = emptySource();
    const file = (LOCKFILES[ecosystem] ?? []).map((n) => path.join(cwd, n)).find((f) => fs.existsSync(f));
    if (file) thrown = { file, error: describeParseError(file, error) ?? "could not be parsed" };
  }
  // The reader's own problems (a refused requirements include, M4) and the lockfiles it could not read.
  // A file that holds a merge conflict is one problem of its own kind, whatever else was said of it.
  const conflicted = conflictedInputs(cwd, ecosystem, read);
  const problems = [
    ...[...(read.problems ?? []), ...(thrown ? [thrown] : unreadLockfiles(cwd, ecosystem, read))].filter((p) => !conflicted.has(path.resolve(p.file))),
    ...[...conflicted].map(mergeConflictProblem),
  ];
  return problems.length > 0 ? { ...read, problems: problems.map((p) => ({ ...p, ecosystem })) } : read;
}

/** Why a file with a merge conflict was not read, in the problem's words. */
export const MERGE_CONFLICT_TEXT =
  "it holds git merge-conflict markers (<<<<<<< / ======= / >>>>>>>), so neither side was read and nothing it pins or declares was checked: resolve the conflict (reinstall to regenerate a lockfile), then scan again";

function mergeConflictProblem(file: string): LockfileProblem {
  return { file, mergeConflict: true, error: MERGE_CONFLICT_TEXT };
}

/** Files besides the lockfiles that one ecosystem's resolution reads in a directory, checked for a merge conflict too. */
const CONFLICT_CHECKED_FILES: Partial<Record<OsvEcosystem, string[]>> = {
  npm: ["package.json", "pnpm-workspace.yaml"],
  "crates.io": ["Cargo.toml"],
  PyPI: ["pyproject.toml", "Pipfile"],
  RubyGems: ["Gemfile", "gems.rb"],
  Packagist: ["composer.json"],
};

/**
 * Every file this ecosystem's resolution in `cwd` reads or may read (its lockfiles, go.sum and
 * go.work included, and its manifests) that holds a merge conflict, absolute. A file the versions
 * were read from was read whole, so it holds none and is not opened again.
 */
function conflictedInputs(cwd: string, ecosystem: OsvEcosystem, read: VersionSource): Set<string> {
  const readFiles = new Set([read.source, ...(read.extraSources ?? [])].filter((f): f is string => Boolean(f)).map((f) => path.resolve(f)));
  const candidates = [...lockfileCandidates(cwd, ecosystem), ...(CONFLICT_CHECKED_FILES[ecosystem] ?? []).map((name) => path.join(cwd, name))];
  const conflicted = new Set<string>();
  for (const file of new Set(candidates.map((f) => path.resolve(f)))) {
    if (readFiles.has(file) || !fs.existsSync(file)) continue;
    try {
      // A manifest is read once per signature (readManifestText); a lockfile is read as it is.
      if ((CONFLICT_CHECKED_FILES[ecosystem] ?? []).includes(path.basename(file))) readManifestText(file);
      else readTextFile(file);
    } catch (error) {
      if (isMergeConflictError(error)) conflicted.add(file);
    }
  }
  return conflicted;
}

function* readVersionSourceSteps(cwd: string, ecosystem: OsvEcosystem): Steps<VersionSource> {
  switch (ecosystem) {
    case "npm":
      return yield* resolveNpmSteps(cwd);
    case "crates.io":
      return resolveRust(cwd);
    case "PyPI":
      return resolvePython(cwd);
    case "Go":
      return resolveGo(cwd);
    case "RubyGems":
      return resolveRuby(cwd);
    case "Packagist":
      return resolvePhp(cwd);
    default:
      return emptySource();
  }
}

/**
 * yarn.lock entries skipped because a line of theirs is past the reader's
 * length cap (B-10 keeps the patterns linear). Said, so the read is never
 * taken for complete (audit L5).
 */
function yarnSkippedProblem(file: string, skipped: number): LockfileProblem {
  const entries = skipped === 1 ? "1 entry" : `${skipped} entries`;
  return {
    file,
    skipped,
    error: `${entries} on a line longer than ${MAX_LOCKFILE_LINE} characters (not lockfile syntax) ${skipped === 1 ? "was" : "were"} skipped, so ${skipped === 1 ? "its version was" : "their versions were"} not checked`,
  };
}

function yarnSkips(file: string): number {
  try {
    return readYarnLock(readTextFile(file), new Map());
  } catch {
    return 0;
  }
}

/**
 * A lockfile that was read, but not all of it: truncated or damaged. The
 * packages before the damage were checked; the rest were not, and how many
 * that is can only be bounded from below (`missing`).
 */
function damagedProblem(file: string, damage: LockDamage): LockfileProblem {
  return partialRead(file, damage.reason, damage.missing);
}

type EntryCheckOptions = { skipLocal?: boolean; members?: { names: ReadonlySet<string>; complete: boolean }; ignoredOptional?: string[] };

/**
 * The dependencies the project's package.json declares that the lockfile
 * beside it has no entry for (`has`), each name once, in the order declared.
 * A text lockfile has no closing bracket to lose, so one cut between two
 * entries parses whole; but every lockfile a package manager writes holds an
 * entry for each declared dependency, so a declared name with none says the
 * file stops early or was written before the dependency was added.
 *
 * peerDependencies are not owed an entry (not every package manager installs
 * the project's own). `skipLocal` leaves out `link:`/`portal:`/`workspace:`
 * declarations and `members` the project's own packages, for lockfiles that
 * write no entry for local code. When the member list is not known whole
 * (`members.complete` false), any declared name may be a member, so none is
 * reported (notCrossCheckedProblem says so). `ignoredOptional` names optional
 * dependencies the package manager was told to leave out.
 */
function declaredWithoutEntry(cwd: string, has: (name: string) => boolean, options: EntryCheckOptions = {}): DeclaredSpec[] {
  const manifest = readManifestDeclarations(path.join(cwd, "package.json"));
  if (!manifest || options.members?.complete === false) return [];
  const seen = new Set<string>();
  return manifest.declared.filter((spec) => {
    if (spec.section === "peerDependencies" || seen.has(spec.name)) return false;
    seen.add(spec.name);
    if (options.skipLocal && isLocalSpec(spec.spec)) return false;
    if (spec.section === "optionalDependencies" && options.ignoredOptional && nameMatchesAny(options.ignoredOptional, spec.name)) return false;
    return !options.members?.names.has(spec.name) && !has(spec.name);
  });
}

/**
 * The cross-check declaredWithoutEntry does not make when the member list is not whole: the
 * declared names with no entry that are not known members may be members (which need none) or
 * missing from the lockfile. Said, never silent, and never as damage: the file itself was read
 * whole. Null when the member list is whole or every declared name has an entry.
 */
function notCrossCheckedProblem(file: string, cwd: string, has: (name: string) => boolean, options: EntryCheckOptions, gap: MemberListGap): LockfileProblem | null {
  if (!options.members || options.members.complete) return null;
  const unsure = declaredWithoutEntry(cwd, has, { ...options, members: { names: options.members.names, complete: true } });
  if (unsure.length === 0) return null;
  const one = unsure.length === 1;
  return {
    file,
    notCrossChecked: true,
    error: `${declaredText(unsure)} ${one ? "has" : "have"} no entry in it and may be ${one ? "a workspace member, which needs" : "workspace members, which need"} no entry, but the member list could not be read whole (${memberListGapText(gap)}), so whether ${one ? "it is" : "they are"} missing from this lockfile was not checked`,
  };
}

/**
 * A pnpm lockfile that records no importer for the project (none of `importers:`, v5's top-level
 * `dependencies:`): what it holds for package.json cannot be told, so the two were not compared.
 */
function noImporterProblem(file: string, cwd: string, options: EntryCheckOptions): LockfileProblem | null {
  const declared = declaredWithoutEntry(cwd, () => false, { ...options, members: options.members ? { names: options.members.names, complete: true } : undefined });
  if (declared.length === 0) return null;
  return { file, notCrossChecked: true, error: `it records no importer for the project itself, so what it holds for ${declaredText(declared)}, declared in package.json, was not checked against it` };
}

/**
 * What pnpm leaves out of a root importer on purpose: the workspace members (a link to one is
 * omitted under `excludeLinksFromLockfile`), from pnpm-workspace.yaml `packages`, and the
 * optional dependencies `ignoredOptionalDependencies` names (in package.json's `pnpm` field,
 * pnpm-workspace.yaml, or as the lockfile records it).
 */
function pnpmOmissions(cwd: string, lockContent: string): { members: { names: ReadonlySet<string>; complete: boolean }; ignoredOptional: string[]; gap: MemberListGap } {
  let workspaceYaml = "";
  try {
    workspaceYaml = readTextFile(path.join(cwd, "pnpm-workspace.yaml"));
  } catch {
    // no pnpm-workspace.yaml: no members, no settings there
  }
  const ignoredOptional = [...pnpmYamlList(workspaceYaml, "ignoredOptionalDependencies"), ...pnpmYamlList(lockContent, "ignoredOptionalDependencies")];
  try {
    const field = (JSON.parse(readTextFile(path.join(cwd, "package.json"))) as { pnpm?: { ignoredOptionalDependencies?: unknown } }).pnpm?.ignoredOptionalDependencies;
    if (Array.isArray(field)) for (const name of field) if (typeof name === "string") ignoredOptional.push(name);
  } catch {
    // unreadable package.json: declaredWithoutEntry reads nothing from it either
  }
  const expanded = expandWorkspaces(cwd, pnpmYamlList(workspaceYaml, "packages"));
  const members = memberNamesOf(cwd, expanded.dirs);
  const gap = { unreadable: members.unreadable, unlisted: !expanded.complete, tooMany: expanded.dirs.length > MAX_MEMBER_MANIFESTS };
  return { members: { names: members.names, complete: members.complete && expanded.complete }, ignoredOptional, gap };
}

/** "a (dependencies) and 2 more", for a note. */
function declaredText(specs: DeclaredSpec[]): string {
  return `${specs[0].name} (${specs[0].section})${specs.length > 1 ? ` and ${specs.length - 1} more` : ""}`;
}

/**
 * One problem for a lockfile that was read but is not whole: its own damage
 * (`damage`), the declared dependencies it has no entry for (`undeclared`),
 * or both. Null when neither.
 */
function incompleteProblem(file: string, damage: LockDamage | null, undeclared: DeclaredSpec[]): LockfileProblem | null {
  if (undeclared.length === 0) return damage ? damagedProblem(file, damage) : null;
  const them = undeclared.length === 1 ? "it" : "them";
  const missing = undeclared.length + (damage?.missing ?? 0);
  return {
    file,
    partial: true,
    skipped: missing,
    // Nothing damaged inside: it only lacks what package.json declares (lockfile-types.ts behindManifest).
    ...(damage ? {} : { behindManifest: true as const }),
    error: `package.json declares ${declaredText(undeclared)}, but this lockfile has no entry for ${them}: it is truncated, or older than package.json${damage ? `; also, ${damage.reason}` : ""}. What it would install for ${them}, and anything past a cut, was not checked: reinstall to regenerate the lockfile`,
  };
}

/**
 * A lockfile that holds no package at all beside a package.json that
 * declares dependencies: not a project with nothing installed. Null when
 * package.json declares nothing that is owed an entry.
 */
function emptyLockProblem(file: string, undeclared: DeclaredSpec[]): LockfileProblem | null {
  if (undeclared.length === 0) return null;
  return {
    file,
    error: `it holds no package, but package.json declares ${declaredText(undeclared)}: it is truncated, or older than package.json, so nothing it would install was checked: reinstall to regenerate the lockfile`,
  };
}

/** "it is truncated or damaged: ..." for a yarn.lock, from what its reader and its graph found, or null. */
function yarnLockDamage(incomplete: number, dangling: string[]): LockDamage | null {
  const parts: string[] = [];
  if (incomplete > 0) parts.push(incomplete === 1 ? "1 entry names a package but no version" : `${incomplete} entries name a package but no version`);
  if (dangling.length > 0) {
    const list = `${dangling.slice(0, 3).join(", ")}${dangling.length > 3 ? ", ..." : ""}`;
    parts.push(`${dangling.length} package${dangling.length === 1 ? " named as a dependency has" : "s named as dependencies have"} no entry (${list})`);
  }
  return parts.length > 0 ? { reason: `it is truncated or damaged: ${parts.join("; ")}`, missing: incomplete + dangling.length } : null;
}

/** Lines git writes into a file it could not merge. */
const CONFLICT_MARKER = /^(?:<{7}|>{7})(?: |$)|^={7}$/m;

/**
 * Lockfiles that exist here, rank above the file the versions came from (or
 * there is none), and were not read: each with the reason, re-derived from
 * the file so the note can say what is wrong with it.
 */
function unreadLockfiles(cwd: string, ecosystem: OsvEcosystem, read: VersionSource): LockfileProblem[] {
  const readFiles = new Set([read.source, ...(read.extraSources ?? [])].filter((f): f is string => Boolean(f)).map((f) => path.resolve(f)));
  // A file its reader already named, with the reason, is said once.
  const named = new Set((read.problems ?? []).map((p) => path.resolve(p.file)));
  const problems: LockfileProblem[] = [];
  for (const name of LOCKFILES[ecosystem] ?? []) {
    if (name === "go.sum") continue; // read with go.mod, never on its own
    const file = path.join(cwd, name);
    if (readFiles.has(path.resolve(file))) {
      // Python merges every lockfile it finds, so one that was read says nothing about the next.
      if (ecosystem === "PyPI") continue;
      break; // everything after it ranks lower (resolveNpm compares those itself)
    }
    if (!fs.existsSync(file) || named.has(path.resolve(file))) continue;
    // A yarn.lock whose entries were all skipped for length: named with the count, even when the file is short (L5).
    const skipped = name === "yarn.lock" ? yarnSkips(file) : 0;
    if (skipped > 0) {
      problems.push(yarnSkippedProblem(file, skipped));
      continue;
    }
    const error = describeParseError(file, null);
    if (error) problems.push({ file, error });
  }
  return problems;
}

/** Lockfiles written as JSON under a name that does not end in `.json`. */
const JSON_LOCKFILE_NAMES = new Set(["pipfile.lock", "composer.lock"]);

/** Whether a lockfile's format is JSON: it is then valid JSON or damaged, whatever its name or length. */
function isJsonLockfile(file: string): boolean {
  return /\.json$/i.test(file) || JSON_LOCKFILE_NAMES.has(path.basename(file).toLowerCase());
}

/**
 * Why a present lockfile yielded nothing, or null when nothing is wrong with
 * it (a valid lockfile of a project with no dependencies).
 */
function describeParseError(file: string, error: unknown): string | null {
  let content: string;
  try {
    content = readTextFile(file);
  } catch (readError) {
    if (isMergeConflictError(readError)) return MERGE_CONFLICT_TEXT;
    return `could not be read (${readError instanceof Error ? readError.message : String(readError)})`;
  }
  if (CONFLICT_MARKER.test(content)) return "it contains git merge-conflict markers (<<<<<<< / >>>>>>>): resolve the conflict and reinstall to regenerate it";
  // Every JSON-format lockfile is validated as JSON whatever its name. bun.lock is JSON with
  // trailing commas: a cut one is unparseable JSON, not a text lockfile that read short.
  const json = isJsonLockfile(file) || path.basename(file) === "bun.lock";
  if (json) {
    try {
      JSON.parse(path.basename(file) === "bun.lock" ? stripTrailingCommas(content) : content);
    } catch (parseError) {
      return `invalid JSON (${parseError instanceof Error ? parseError.message.slice(0, 120) : String(parseError)})`;
    }
  }
  if (error) return `could not be parsed (${error instanceof Error ? error.message.slice(0, 120) : String(error)})`;
  if (json) return null;
  // A YAML lockfile (pnpm-lock.yaml) whose flow sequence or mapping is never closed stops mid-value:
  // read as empty, it hid beside a package-lock.json that was read (review 2026-11-24).
  if (/\.ya?ml$/i.test(file) && unclosedFlow(content)) return "it is truncated or damaged: a [ or { is not closed";
  // A text lockfile of some size that gave no package at all is damaged or in a format this reader does not know.
  const lines = content.split(/\r?\n/).filter((l) => l.trim() !== "").length;
  return lines > 20 ? "no package versions could be read from it (unsupported format or damaged)" : null;
}

/** Instances for a manifest-only read: one per name, scope unknown. */
function manifestInstances(versions: Map<string, string>): PackageInstance[] {
  return [...versions].map(([name, version]) => ({ name, version }));
}

/**
 * A manifest read with no lockfile beside it. Only an exact pin names the
 * version that gets installed; any other requirement ("^1.2.0", "0.8") is
 * kept in `ranges`, and its floor in `versions` is a label, not an install.
 * nushell's samples/wasm/Cargo.toml (no Cargo.lock) was scanned as if its
 * floors were installed and produced 2 false findings (2026-10-10).
 */
function declaredRanges(declared: Map<string, string>, exact: (spec: string) => boolean, file: string): VersionSource {
  const versions = new Map<string, string>();
  const ranges = new Map<string, string>();
  for (const [name, spec] of declared) {
    // "0.3" and "1" are ranges too: their floor is 0.3.0 / 1.0.0.
    const partial = /(\d+)(?:\.(\d+))?/.exec(spec);
    const version = extractVersionFromSpec(spec) ?? (partial ? `${partial[1]}.${partial[2] ?? "0"}.0` : null);
    if (!version) continue;
    versions.set(name, version);
    if (!exact(spec)) ranges.set(name, spec);
  }
  // Only exact pins are installs; ranged names are not instances at all.
  const pinned = new Map([...versions].filter(([name]) => !ranges.has(name)));
  return found(versions, manifestInstances(pinned), file, "declared_ranges", { ranges });
}

// =============================================================================
// npm: npm-shrinkwrap.json > package-lock.json > pnpm-lock.yaml > yarn.lock > bun.lock > package.json ranges
// =============================================================================

/** What one npm-family lockfile holds, as its reader reports it. */
interface NpmLockRead {
  versions: Map<string, string>;
  instances: InstanceSet;
  uncheckable: NonRegistryEntry[];
  aliases?: Map<string, string>;
  problems: LockfileProblem[];
  /** Copies the project's own manifests declare, workspace members included (VersionSource.declared). */
  declared?: DeclaredDependency[];
  /** True when the reader graded the scope of every copy itself (VersionSource.scopeGraded). */
  scopeGraded?: boolean;
  /** The file holds no package although package.json declares dependencies: `problems` says so, and it is not read. */
  empty?: true;
  /** Names the lockfile installs from somewhere other than a registry (VersionSource.elsewhere). */
  elsewhere?: string[];
}

/** The read of a lockfile with no package in it: null, or `empty` when package.json says it should hold some. */
function emptyRead(problem: LockfileProblem | null): NpmLockRead | null {
  return problem ? { versions: new Map(), instances: new InstanceSet(), uncheckable: [], problems: [problem], empty: true } : null;
}

/**
 * The npm-family lockfiles in the order they are preferred, each with its
 * reader. A reader returns null for a file that holds no package at all (or
 * an `empty` read when package.json declares dependencies it should hold) and
 * throws for one it cannot parse.
 */
const NPM_LOCK_READERS: Array<{ name: string; read: (file: string, cwd: string) => NpmLockRead | null | Steps<NpmLockRead | null> }> = [
  // npm's own order: with both present it installs from the shrinkwrap and never opens package-lock.json.
  { name: "npm-shrinkwrap.json", read: readNpmLockFile },
  { name: "package-lock.json", read: readNpmLockFile },
  {
    // v5.x, v6 and v9, read by column; see js-lockfile-readers.ts
    name: "pnpm-lock.yaml",
    // A generator: the read that can take seconds pauses where it may (resolveNpmSteps, W11).
    *read(file, cwd) {
      const content = readTextFile(file);
      const versions = new Map<string, string>();
      const instances = new InstanceSet();
      const report = emptyReadReport();
      const installs = yield* readPnpmLockSteps(content, versions, instances, report);
      // pnpm writes every dependency of the project into its root importer; a link can be left out (excludeLinksFromLockfile).
      const listed = report.rootEntries;
      const { gap, ...omitted } = pnpmOmissions(cwd, content);
      if (versions.size === 0) return emptyRead(emptyLockProblem(file, declaredWithoutEntry(cwd, (name) => listed?.has(name) === true, { skipLocal: true, ...omitted })));
      const damage = yield* pnpmLockDamageSteps(content, report.missingDirect, installs);
      const undeclared = listed ? declaredWithoutEntry(cwd, (name) => listed.has(name), { skipLocal: true, ...omitted }) : [];
      const problem = incompleteProblem(file, damage, undeclared);
      const uncrossed = listed ? notCrossCheckedProblem(file, cwd, (name) => listed.has(name), { skipLocal: true, ...omitted }, gap) : noImporterProblem(file, cwd, { skipLocal: true, ...omitted });
      return {
        versions,
        instances,
        uncheckable: report.uncheckable,
        elsewhere: report.elsewhere,
        problems: [problem, uncrossed].filter((p): p is LockfileProblem => p !== null),
        declared: report.declared,
        scopeGraded: report.scopeGraded,
      };
    },
  },
  {
    // v1 and berry
    name: "yarn.lock",
    read(file, cwd) {
      const content = readTextFile(file);
      const versions = new Map<string, string>();
      const copies = new InstanceSet();
      const specs = new Map<string, string>();
      const report = emptyReadReport();
      const skipped = readYarnLock(content, versions, copies, specs, report);
      // The copy a direct dependency resolves to is the one its package.json range names.
      for (const [name, range] of manifestRanges(cwd)) {
        const version = specs.get(`${name}@${range}`);
        if (version) versions.set(name, version);
      }
      // yarn.lock states no scope: it is derived from the lockfile's graph and the package.json files.
      const read = copies.toArray();
      const keys = new Set(read.map((copy) => `${copy.name}\0${copy.version}`));
      let inspection: YarnInspection | null;
      try {
        inspection = inspectYarnLock(content, cwd, (key) => keys.has(key));
      } catch {
        inspection = null;
      }
      // Each declared dependency has an entry in a whole yarn.lock (a git or local one too), except a
      // workspace member (classic writes none) and a link.
      const entryCheck: EntryCheckOptions = { skipLocal: true, members: inspection ? { names: inspection.memberNames, complete: inspection.membersComplete } : undefined };
      const undeclared = declaredWithoutEntry(cwd, (name) => inspection?.hasEntry(name) === true, entryCheck);
      if (versions.size === 0) return emptyRead(emptyLockProblem(file, undeclared));
      const problems: LockfileProblem[] = skipped > 0 ? [yarnSkippedProblem(file, skipped)] : [];
      const incomplete = incompleteProblem(file, yarnLockDamage(report.incomplete, inspection?.dangling ?? []), undeclared);
      if (incomplete) problems.push(incomplete);
      const uncrossed = inspection ? notCrossCheckedProblem(file, cwd, (name) => inspection.hasEntry(name), entryCheck, inspection.membersGap) : null;
      if (uncrossed) problems.push(uncrossed);
      const grade = inspection?.grade ?? { scopes: new Map<string, boolean>(), declared: [], graded: false };
      const instances = new InstanceSet();
      for (const copy of read) instances.add(copy.name, copy.version, grade.scopes.get(`${copy.name}\0${copy.version}`));
      return { versions, instances, uncheckable: report.uncheckable, elsewhere: report.elsewhere, problems, declared: grade.declared, scopeGraded: grade.graded };
    },
  },
  {
    // Bun 1.2+ text lockfile; the binary bun.lockb is not readable (binaryBunLock)
    name: "bun.lock",
    read(file, cwd) {
      const versions = new Map<string, string>();
      const instances = new InstanceSet();
      const report = emptyReadReport();
      readBunLock(readTextFile(file), versions, instances, report);
      // Bun keys the copy each dependency of the project resolves to by its name.
      const listed = report.rootEntries;
      const undeclared = declaredWithoutEntry(cwd, (name) => listed?.has(name) === true, { skipLocal: true });
      if (versions.size === 0) return emptyRead(emptyLockProblem(file, undeclared));
      const problem = incompleteProblem(file, null, undeclared);
      return { versions, instances, uncheckable: report.uncheckable, elsewhere: report.elsewhere, problems: problem ? [problem] : [], declared: report.declared, scopeGraded: report.scopeGraded };
    },
  },
];

function readNpmLockFile(file: string, cwd: string): NpmLockRead | null {
  const lock: unknown = JSON.parse(readTextFile(file));
  const read = readPackageLock(lock as Parameters<typeof readPackageLock>[0]);
  if (read.instances.size === 0 && read.uncheckable.length === 0 && read.elsewhere.length === 0) return null;
  // npm writes an entry for every dependency package.json declares (a link entry for local code):
  // a declared name with none means the file was written before it was added, and what npm would
  // install for it was never checked. pnpm, yarn and bun lockfiles were cross-checked this way; npm's
  // was not, and a package-lock.json that lacked a declared dependency read as complete (6.5.0).
  const undeclared = declaredWithoutEntry(cwd, (name) => npmLockHasEntry(lock, name), { skipLocal: true });
  const problem = incompleteProblem(file, null, undeclared);
  // npm writes `dev` on every entry only devDependencies reach: the lockfile's own grading.
  return { versions: read.versions, instances: read.instances, uncheckable: read.uncheckable, elsewhere: read.elsewhere, aliases: read.aliases, problems: problem ? [problem] : [], declared: read.declared, scopeGraded: true };
}

/**
 * Whether an npm lockfile holds an entry for a dependency the project's own package.json declares:
 * `packages["node_modules/<name>"]` (lockfileVersion 2 and 3, a link entry included), else the
 * top-level `dependencies[<name>]` (lockfileVersion 1).
 */
function npmLockHasEntry(lock: unknown, name: string): boolean {
  if (!lock || typeof lock !== "object") return false;
  const { packages, dependencies } = lock as { packages?: unknown; dependencies?: unknown };
  if (packages && typeof packages === "object") return Object.hasOwn(packages, `node_modules/${name}`);
  return Boolean(dependencies && typeof dependencies === "object" && Object.hasOwn(dependencies, name));
}

function* resolveNpmSteps(cwd: string): Steps<VersionSource> {
  let chosen: { name: string; file: string; read: NpmLockRead } | null = null;
  const others: string[] = [];
  // Lockfiles ranked above the one read that hold no package although package.json declares some.
  const emptied: LockfileProblem[] = [];
  // A lockfile here holds a merge conflict: the project has a lockfile, so package.json's ranges are not read in its place.
  let conflicted = false;
  for (const reader of NPM_LOCK_READERS) {
    const file = path.join(cwd, reader.name);
    if (!fs.existsSync(file)) continue;
    if (chosen) {
      others.push(reader.name);
      continue;
    }
    try {
      const out = reader.read(file, cwd);
      const read = out && isSteps(out) ? yield* out : out;
      if (read?.empty) pushAll(emptied, read.problems);
      else if (read) chosen = { name: reader.name, file, read };
    } catch (error) {
      // Unreadable: the next lockfile; unreadLockfiles names this one and why.
      if (isMergeConflictError(error)) conflicted = true;
    }
  }

  if (chosen) {
    const { file, read } = chosen;
    const problems = [...emptied, ...read.problems, ...lockfileConflicts(cwd, chosen, others)];
    return found(read.versions, read.instances, file, "lockfile", {
      ...(read.uncheckable.length > 0 ? { uncheckable: read.uncheckable.map((u) => ({ ...u, file })) } : {}),
      ...(read.aliases && read.aliases.size > 0 ? { aliases: read.aliases } : {}),
      ...(read.elsewhere && read.elsewhere.length > 0 ? { elsewhere: read.elsewhere } : {}),
      ...(problems.length > 0 ? { problems } : {}),
      ...(read.declared && read.declared.length > 0 ? { declared: read.declared } : {}),
      ...(read.scopeGraded ? { scopeGraded: true as const } : {}),
    });
  }

  // No readable lockfile. A binary bun.lockb pins everything, but not in a form this server reads.
  const bunBinary = path.join(cwd, BUN_BINARY_LOCK);
  const problems: LockfileProblem[] = [...emptied];
  if (fs.existsSync(bunBinary)) {
    problems.push({
      file: bunBinary,
      error: "bun.lockb is Bun's binary lockfile, which this server cannot read: run `bun install --save-text-lockfile` (Bun 1.2 or later) to write bun.lock, then scan again",
    });
  }

  // No lockfile: package.json declares ranges, not installed versions.
  const pkgPath = path.join(cwd, "package.json");
  if (!conflicted && fs.existsSync(pkgPath)) {
    const declared = new Map<string, string>();
    const uncheckable: NonRegistryEntry[] = [];
    const aliases = new Map<string, string>();
    const catalogs = lazyNpmCatalogs(cwd);
    let pkg: Record<string, unknown>;
    try {
      const parsed: unknown = JSON.parse(readTextFile(pkgPath));
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("it is not a JSON object");
      pkg = parsed as Record<string, unknown>;
    } catch (error) {
      // What it declares is unknown, which is not "nothing declared": said, never a clean result.
      problems.push({ file: pkgPath, error: manifestParseError(error) });
      return { ...emptySource(), problems };
    }
    try {
      const sections = (field: string) => (pkg[field] && typeof pkg[field] === "object" && !Array.isArray(pkg[field]) ? (pkg[field] as Record<string, unknown>) : {});
      for (const [name, spec] of Object.entries({ ...sections("dependencies"), ...sections("devDependencies") })) {
        if (typeof spec !== "string") continue;
        // Read as npm reads it (npm-spec.ts): `"x": "github:user/repo"`, `"org/repo"`, `"../libs/x"`,
        // `"vendor/x-1.0.0.tgz"` or a tarball on another host is not a version of the registry's x.
        const read = classifyNpmSpec(name, spec, catalogs);
        // Local code, and a catalog: entry that could not be read, are said by the resolution (nonRegistryDirect).
        if (read.kind === "local" || read.kind === "catalog" || read.kind === "ambiguous") continue;
        if (read.kind !== "registry") uncheckable.push({ name, version: null, kind: read.kind });
        else if (read.name !== name) {
          // `"my-lodash": "npm:lodash@4.17.20"` declares lodash, under another folder name.
          declared.set(read.name, read.range);
          aliases.set(name, read.name);
        } else declared.set(name, read.range === spec.trim() ? spec : read.range);
      }
    } catch { /* skip */ }
    // npm installs exactly "1.2.3" (or "=1.2.3"); anything else is a range.
    const read = declaredRanges(declared, (spec) => /^=?v?\d+\.\d+\.\d+(?:-[\w.]+)?$/.test(spec.trim()), pkgPath);
    return {
      ...read,
      ...(uncheckable.length > 0 ? { uncheckable: uncheckable.map((u) => ({ ...u, file: pkgPath })) } : {}),
      ...(aliases.size > 0 ? { aliases } : {}),
      ...(problems.length > 0 ? { problems } : {}),
    };
  }

  return problems.length > 0 ? { ...emptySource(), problems } : emptySource();
}

/** Why a package.json with no lockfile beside it could not be read, and what that leaves unchecked. */
function manifestParseError(error: unknown): string {
  const why = error instanceof SyntaxError ? `it is not valid JSON (${error.message.slice(0, 120)})` : `it could not be read (${error instanceof Error ? error.message.slice(0, 120) : String(error)})`;
  return `${why}, so no dependency it declares was read or checked: fix the file, then scan again`;
}

/** A reader that returned its work as steps (a generator) rather than its result. */
function isSteps<T>(value: T | Steps<T>): value is Steps<T> {
  return typeof (value as Partial<Steps<T>>).next === "function" && typeof (value as Partial<Steps<T>>)[Symbol.iterator] === "function";
}

/** How many differing names a conflict note spells out. */
const CONFLICT_EXAMPLES = 3;

/**
 * The other lockfiles in a directory whose lockfile was read, when they do
 * not agree with it. One directory, two package managers' lockfiles: only one
 * of them is what gets installed, and the reader took the first by rank
 * without a word. Now the answer says which was read and that the other
 * exists and pins something else (audit 2026-11-11).
 *
 * An empty lockfile beside a full one hides nothing and is not reported; one
 * that cannot be parsed is, because it could not be compared.
 */
function lockfileConflicts(cwd: string, chosen: { name: string; read: NpmLockRead }, others: string[]): LockfileProblem[] {
  const problems: LockfileProblem[] = [];
  const pins = (read: NpmLockRead) => {
    const byName = new Map<string, Set<string>>();
    for (const i of read.instances.toArray()) byName.set(i.name, (byName.get(i.name) ?? new Set()).add(i.version));
    return byName;
  };
  const mine = pins(chosen.read);
  for (const name of others) {
    const file = path.join(cwd, name);
    let other: NpmLockRead | null = null;
    let failure: string | null = null;
    try {
      const out = NPM_LOCK_READERS.find((r) => r.name === name)?.read(file, cwd) ?? null;
      other = out && isSteps(out) ? runSteps(out) : out;
      if (!other) failure = describeParseError(file, null);
    } catch (error) {
      failure = describeParseError(file, error) ?? "could not be parsed";
    }
    // A lockfile with no package in it hides nothing, whatever package.json says it should hold.
    if (other?.empty) {
      other = null;
      failure = describeParseError(file, null);
    }
    if (!other) {
      if (failure) problems.push({ file, conflict: true, error: `${chosen.name} was read instead, and this lockfile could not be compared with it: ${failure}` });
      continue;
    }
    const theirs = pins(other);
    const differing: string[] = [];
    for (const pkg of new Set([...mine.keys(), ...theirs.keys()])) {
      const a = [...(mine.get(pkg) ?? [])].sort();
      const b = [...(theirs.get(pkg) ?? [])].sort();
      if (a.join(",") !== b.join(",")) differing.push(`${pkg} ${b.join("/") || "absent"} here, ${a.join("/") || "absent"} in ${chosen.name}`);
    }
    if (differing.length === 0) continue;
    differing.sort();
    const differ = `${differing.length} package${differing.length === 1 ? "" : "s"} differ (${differing.slice(0, CONFLICT_EXAMPLES).join("; ")}${differing.length > CONFLICT_EXAMPLES ? "; ..." : ""})`;
    // Between npm's two lockfiles the stale one is known: npm never reads package-lock.json beside a shrinkwrap.
    const npmPair = chosen.name === "npm-shrinkwrap.json" && name === "package-lock.json";
    problems.push({
      file,
      conflict: true,
      error: npmPair
        ? `${chosen.name} was read instead: npm installs from ${chosen.name} and ignores ${name} when both are present. This ignored lockfile pins a different set: ${differ}. It is the stale one: delete it, or delete ${chosen.name} if ${name} is the one you mean to install from`
        : `${chosen.name} was read instead (it ranks first), and this lockfile pins a different set: ${differ}. One of the two is stale and the scan cannot tell which: delete the one your package manager does not write`,
    });
  }
  const bunBinary = path.join(cwd, BUN_BINARY_LOCK);
  if (chosen.name !== "bun.lock" && fs.existsSync(bunBinary)) {
    problems.push({
      file: bunBinary,
      conflict: true,
      error: `${chosen.name} was read instead; bun.lockb is Bun's binary lockfile, which this server cannot read, so it could not be compared. If Bun installs this project, ${chosen.name} may be stale`,
    });
  }
  return problems;
}

/**
 * Node's lookup of `name` from the package-lock key `from` (an install path,
 * a workspace directory, or "" for the project): its own node_modules, then
 * each enclosing package's, then the root's. Null when no entry answers.
 */
export function resolveInstallPath(packages: Record<string, unknown>, from: string, name: string): string | null {
  let dir = from;
  for (;;) {
    const candidate = `${dir ? `${dir}/` : ""}node_modules/${name}`;
    if (Object.hasOwn(packages, candidate)) return candidate;
    if (dir === "") return null;
    const cut = dir.lastIndexOf("/node_modules/");
    dir = cut >= 0 ? dir.slice(0, cut) : "";
  }
}

/** The package name a package-lock `packages` key installs: the segment after its LAST `node_modules/`. */
export function packageNameFromNodeModulesPath(lockPath: string): string {
  const marker = "node_modules/";
  const index = lockPath.lastIndexOf(marker);
  return index === -1 ? "" : lockPath.slice(index + marker.length);
}

interface LockEntry {
  /** v2/v3: the package's real name, written when it differs from the folder (an alias, a git dependency). */
  name?: string;
  version?: string;
  resolved?: string;
  dev?: boolean;
  link?: boolean;
  dependencies?: Record<string, LockEntry | string>;
  devDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
}

/** A registry package name, scoped or not. */
const NPM_NAME = /^(?:@[a-z0-9~][a-z0-9._~-]*\/)?[a-z0-9~][a-z0-9._~-]*$/i;

/** v1: `"version": "npm:lodash@4.17.20"` under the alias's key. */
const V1_ALIAS = /^npm:((?:@[^/@\s]+\/)?[^/@\s]+)@(\d\S*)$/;

/** The version a registry tarball URL's file names for `name` (`.../-/olm-3.2.3.tgz` is olm 3.2.3), or null. */
function tarballRelease(name: string, url: string): string | null {
  let file: string;
  try {
    file = decodeURIComponent(url.split(/[?#]/)[0].split("/").pop() ?? "");
  } catch {
    return null;
  }
  const base = name.split("/").pop() ?? name;
  if (!file.startsWith(`${base}-`) || !/\.tgz$/i.test(file)) return null;
  const release = file.slice(base.length + 1, -".tgz".length);
  return /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]+)?$/.test(release) ? release : null;
}

/**
 * package-lock.json / npm-shrinkwrap.json, lockfile v1, v2 and v3.
 *
 * v2/v3 `packages` keys are install paths: `node_modules/a` is the hoisted
 * copy a direct dependency of the root resolves to, `node_modules/a/node_modules/b`
 * a nested one. npm writes `dev: true` on every entry only reachable from
 * devDependencies (`devOptional` = also reachable as an optional runtime dep,
 * so runtime), which makes the dev scope of a TRANSITIVE known. v1 nests the
 * same information under `dependencies`.
 *
 * The folder is not always the package. An alias (`"my-lodash":
 * "npm:lodash@4.17.20"`) installs lodash into node_modules/my-lodash: v2/v3
 * write the real `name` on the entry, v1 writes the spec as the version. Both
 * were read under the alias, so OSV was asked about `my-lodash` and answered
 * "no advisories" for a vulnerable lodash (audit 2026-11-11, M9). And an entry
 * resolved from git or an arbitrary URL is not a registry release at all:
 * `uncheckable`, never an instance.
 */
export function readPackageLock(lock: {
  packages?: Record<string, LockEntry>;
  dependencies?: Record<string, LockEntry>;
}): { versions: Map<string, string>; instances: InstanceSet; uncheckable: NonRegistryEntry[]; aliases: Map<string, string>; declared: DeclaredDependency[]; elsewhere: string[] } {
  const versions = new Map<string, string>();
  const instances = new InstanceSet();
  const uncheckable: NonRegistryEntry[] = [];
  // Top-level names the lockfile installs as a link (a workspace member, a `file:` directory) or from
  // git, a URL or a local archive: whatever package.json's spec says, not a registry release (VersionSource.elsewhere).
  const elsewhere = new Set<string>();
  const aliases = new Map<string, string>();
  const declared = new Map<string, DeclaredDependency>();

  if (lock.packages) {
    // What asked for each name, to tell a URL dependency from a registry with tarball paths of its own.
    // Appended in place: copying the list on every request made a name requested by 50,000 packages
    // cost 50,000²/2 copies (100,000 entries: 6.2 s of a 7.1 s read; pre-publish round 7).
    const requested = new Map<string, string[]>();
    for (const entry of Object.values(lock.packages)) {
      for (const field of ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"] as const) {
        const specs = entry?.[field];
        if (!specs || typeof specs !== "object") continue;
        for (const name in specs) {
          if (!Object.hasOwn(specs, name)) continue;
          const spec = specs[name];
          if (typeof spec !== "string") continue;
          const list = requested.get(name);
          if (list) list.push(spec);
          else requested.set(name, [spec]);
        }
      }
    }
    const urlRequested = (folder: string): string | undefined => {
      const specs = requested.get(folder) ?? [];
      return specs.length > 0 && specs.every((s) => nonRegistrySource(s, s) !== null) ? specs[0] : undefined;
    };

    const hoistedAliases: Array<[string, string]> = [];
    for (const [key, value] of Object.entries(lock.packages)) {
      const folder = packageNameFromNodeModulesPath(key);
      if (!folder || !value) continue;
      if (value.link) {
        if (key === `node_modules/${folder}`) elsewhere.add(folder);
        continue;
      }
      const name = typeof value.name === "string" && NPM_NAME.test(value.name) ? value.name : folder;
      const other = typeof value.resolved === "string" ? nonRegistrySource(value.resolved, urlRequested(folder)) : null;
      if (other) {
        if (key === `node_modules/${folder}`) elsewhere.add(folder);
        if (other !== "local") uncheckable.push({ name, version: value.version ?? null, kind: other });
        continue;
      }
      if (!value.version) continue;
      instances.add(name, value.version, value.dev === true);
      // The hoisted root copy is what `require(name)` from the project resolves to.
      if (key !== `node_modules/${folder}`) continue;
      if (name === folder) versions.set(name, value.version);
      else {
        aliases.set(folder, name);
        hoistedAliases.push([name, value.version]);
      }
    }
    // An aliased copy speaks for its package only when the package is not also installed under its own name.
    for (const [name, version] of hoistedAliases) {
      if (!versions.has(name)) versions.set(name, version);
    }
    // A workspace package's own nested copy (packages/x/node_modules/a) when nothing is hoisted.
    const copies = new Set<string>();
    for (const instance of instances.toArray()) {
      copies.add(`${instance.name}\0${instance.version}`);
      if (!versions.has(instance.name)) versions.set(instance.name, instance.version);
    }
    // What the project and each workspace member declare: the entries keyed by a directory, not an
    // install path, each dependency resolved from that directory as Node resolves it.
    for (const [key, value] of Object.entries(lock.packages)) {
      if (!value || value.link || packageNameFromNodeModulesPath(key) !== "") continue;
      for (const section of DEPENDENCY_SECTIONS) {
        const specs = value[section];
        if (!specs || typeof specs !== "object") continue;
        for (const dep of Object.keys(specs)) {
          const at = resolveInstallPath(lock.packages, key, dep);
          const target = at ? lock.packages[at] : undefined;
          if (!target || target.link || typeof target.version !== "string") continue;
          const name = typeof target.name === "string" && NPM_NAME.test(target.name) ? target.name : dep;
          const id = `${name}\0${target.version}`;
          if (!copies.has(id)) continue;
          const prior = declared.get(id);
          if (prior) prior.runtime ||= isRuntimeSection(section);
          else declared.set(id, { name, version: target.version, runtime: isRuntimeSection(section) });
        }
      }
    }
  }

  if (instances.size === 0 && uncheckable.length === 0 && lock.dependencies) {
    const topAliases: Array<[string, string]> = [];
    const walk = (deps: Record<string, LockEntry | string>, topLevel: boolean) => {
      for (const [folder, value] of Object.entries(deps)) {
        if (!value || typeof value !== "object") continue;
        const version = typeof value.version === "string" ? value.version : "";
        const alias = V1_ALIAS.exec(version);
        if (alias && NPM_NAME.test(alias[1])) {
          instances.add(alias[1], alias[2], value.dev === true);
          if (topLevel) {
            aliases.set(folder, alias[1]);
            topAliases.push([alias[1], alias[2]]);
          }
        } else if (/^\d/.test(version)) {
          instances.add(folder, version, value.dev === true);
          if (topLevel) versions.set(folder, version);
        } else if (version) {
          // v1 writes a git or URL dependency's location as its version.
          const other = nonRegistrySource(version, version);
          if (other && topLevel) elsewhere.add(folder);
          if (other && other !== "local") uncheckable.push({ name: folder, version: null, kind: other });
          else if (other === null) {
            // A registry-shaped tarball URL (`/<name>/-/<name>-<v>.tgz`) on any host: the release its file
            // names, as v2/v3 record it beside `resolved` (whose host the private rules judge). One whose
            // file names no release of this package is not checkable, and is listed.
            const release = tarballRelease(folder, version);
            if (release) {
              instances.add(folder, release, value.dev === true);
              if (topLevel) versions.set(folder, release);
            } else uncheckable.push({ name: folder, version: null, kind: "url" });
          }
        }
        if (value.dependencies) walk(value.dependencies, false);
      }
    };
    walk(lock.dependencies, true);
    for (const [name, version] of topAliases) {
      if (!versions.has(name)) versions.set(name, version);
    }
  }

  return { versions, instances, uncheckable, aliases, declared: [...declared.values()], elsewhere: [...elsewhere] };
}

// =============================================================================
// Rust: Cargo.lock
// =============================================================================

interface CargoPackage {
  name: string;
  version: string;
  source: string | null;
  dependencies: string[];
}

/**
 * Every `[[package]]` table in a Cargo.lock, read field by field. The old
 * reader required `name` and `version` on consecutive lines; that holds for
 * cargo's own writer, but the table is TOML and nothing else guarantees it.
 */
export function parseCargoLockPackages(content: string): CargoPackage[] {
  const packages: CargoPackage[] = [];
  for (const block of content.split(/^\[\[package\]\]\s*$/m).slice(1)) {
    const body = block.split(/^\[(?!\[package\]\])/m)[0];
    const field = (key: string) => new RegExp(`^${key}\\s*=\\s*"([^"]*)"`, "m").exec(body)?.[1] ?? null;
    const name = field("name");
    const version = field("version");
    if (!name || !version) continue;
    const depsMatch = /^dependencies\s*=\s*\[([\s\S]*?)\]/m.exec(body);
    const dependencies = depsMatch ? [...depsMatch[1].matchAll(/"([^"]+)"/g)].map((m) => m[1]) : [];
    packages.push({ name, version, source: field("source"), dependencies });
  }
  return packages;
}

/** The line shapes cargo writes into a Cargo.lock (lockfile 1 to 4), trimmed. Anything else is not lockfile syntax. */
const CARGO_LOCK_LINES = [
  /^#/,
  /^version\s*=\s*\d+$/,
  /^\[\[[A-Za-z0-9_.-]+\]\]$/,
  /^\[[A-Za-z0-9_.-]+\]$/,
  /^(?:[A-Za-z0-9_-]+|"(?:[^"\\]|\\.)*")\s*=\s*"(?:[^"\\]|\\.)*"$/,
  /^[A-Za-z0-9_-]+\s*=\s*\[(?:.*\])?$/,
  /^"(?:[^"\\]|\\.)*",?$/,
  /^\]$/,
];

/**
 * Why a Cargo.lock is not the whole file cargo wrote, or null when nothing
 * says so. A lockfile cut short still parses table by table, so a truncated
 * one read as 14 of its 85 packages with no notice (audit 2026-11-11, M12).
 *
 * Three signs, each absent from every file cargo writes: a line that is not
 * lockfile syntax (an unterminated string, a half-written table header), a
 * `[[package]]` table with no name or version, and a package named in some
 * `dependencies` list that has no table of its own. The last one catches a
 * file cut cleanly between two tables, unless the cut also took every table
 * that names the missing ones: `undeclared`, the dependencies the manifest
 * beside it declares that have no table (cargoLockMissingDeclared), catches that.
 */
export function cargoLockDamage(
  content: string,
  packages: CargoPackage[] = parseCargoLockPackages(content),
  undeclared: string[] = [],
): (LockDamage & { behindManifest?: true }) | null {
  const malformed: number[] = [];
  let arrayOpen = false;
  content.split(/\r?\n/).forEach((raw, index) => {
    const text = raw.trim();
    if (text === "" || text.length > MAX_LOCKFILE_LINE) return;
    if (!CARGO_LOCK_LINES.some((shape) => shape.test(text))) malformed.push(index + 1);
    else if (/=\s*\[$/.test(text)) arrayOpen = true;
    else if (text === "]") arrayOpen = false;
  });
  const tables = content.split(/^\[\[package\]\]\s*$/m).length - 1;
  const nameless = tables - packages.length;
  const names = new Set(packages.map((pkg) => pkg.name));
  const dangling = new Set<string>();
  for (const pkg of packages) {
    for (const dep of pkg.dependencies) {
      const name = dep.split(" ")[0];
      if (name && !names.has(name)) dangling.add(name);
    }
  }

  const parts: string[] = [];
  if (malformed.length > 0) {
    parts.push(`line${malformed.length === 1 ? "" : "s"} ${malformed.slice(0, 5).join(", ")}${malformed.length > 5 ? ", ..." : ""} ${malformed.length === 1 ? "is" : "are"} not lockfile syntax`);
  }
  if (arrayOpen) parts.push("its last `dependencies` list is not closed");
  if (nameless > 0) parts.push(`${nameless} [[package]] table${nameless === 1 ? " has" : "s have"} no name or version`);
  if (dangling.size > 0) {
    const list = [...dangling].sort();
    parts.push(`${dangling.size} package${dangling.size === 1 ? "" : "s"} named as ${dangling.size === 1 ? "a dependency has" : "dependencies have"} no [[package]] table (${list.slice(0, 3).join(", ")}${list.length > 3 ? ", ..." : ""})`);
  }
  // A crate both a `dependencies` list and the manifest name is one missing table, counted once.
  const danglingFolded = new Set([...dangling].map(foldCrateName));
  const unlisted = undeclared.filter((name) => !danglingFolded.has(foldCrateName(name)));
  if (undeclared.length > 0) {
    parts.push(`Cargo.toml declares ${undeclared.length === 1 ? "a dependency" : `${undeclared.length} dependencies`} it holds no [[package]] table for (${undeclared.slice(0, 3).join(", ")}${undeclared.length > 3 ? ", ..." : ""})`);
  }
  if (parts.length === 0) return null;
  const missing = dangling.size + Math.max(0, nameless) + unlisted.length;
  // Only the manifest disagrees: cut between two tables, or written before the manifest changed.
  if (parts.length === 1 && undeclared.length > 0) return { reason: `it is truncated or out of date: ${parts[0]}`, missing, behindManifest: true };
  return { reason: `it is truncated or damaged: ${parts.join("; ")}`, missing };
}

/** One dependency entry of a Cargo.toml, as cargoDeclaredPackages reads it. */
interface CargoDeclared {
  key: string;
  /** `package = "real-name"`: the crate the lockfile records under this key. */
  renamed: string | null;
  /** `workspace = true`: the entry, and any rename, come from `[workspace.dependencies]`. */
  inherited: boolean;
}

/**
 * The crates a Cargo.toml's own dependency tables declare, under the name the lockfile records
 * them by: `[dependencies]`, `[dev-dependencies]`, `[build-dependencies]`, their
 * `[target.<spec>.…]` forms and `[dependencies.<name>]` sub-tables, with `package = "…"` renames
 * applied. `[workspace.dependencies]` only offers entries to members, so it declares nothing by
 * itself; an entry inherited with `workspace = true` takes its rename from it.
 */
export function cargoDeclaredPackages(content: string): string[] {
  /** One entry per dependency per table: the same key in another table is another dependency. */
  const declared = new Map<string, CargoDeclared>();
  let tableNumber = 0;
  const offered = new Map<string, string>();
  /** The table the current line is in: a dependency table, one entry's sub-table, or neither. */
  let table: { workspace: boolean; entry: CargoDeclared | null } | null = null;
  const unquote = (key: string) => key.trim().replace(/^["']|["']$/g, "");
  for (const raw of content.split(/\r?\n/)) {
    if (raw.length > MAX_LOCKFILE_LINE) continue;
    const line = raw.trim();
    if (line === "" || line.startsWith("#")) continue;
    if (line.startsWith("[")) {
      table = null;
      tableNumber++;
      const header = /^\[([^[\]]+)\]/.exec(line)?.[1].trim();
      const at = header ? /(?:^|\.)(?:dev-|build-)?dependencies(?:\.(.+))?$/.exec(header) : null;
      if (!header || !at) continue;
      const prefix = header.slice(0, at.index);
      const workspace = prefix === "workspace";
      // `[package.metadata.x.dependencies]` and the like are a tool's own data, not cargo's.
      if (!workspace && prefix !== "" && !prefix.startsWith("target.")) continue;
      const entry = at[1] ? { key: unquote(at[1]), renamed: null, inherited: false } : null;
      if (entry && !workspace) declared.set(`${tableNumber}`, entry);
      table = { workspace, entry };
      continue;
    }
    if (!table) continue;
    const eq = line.indexOf("=");
    if (eq <= 0) continue;
    const key = line.slice(0, eq).trim();
    const value = line.slice(eq + 1);
    const renamedTo = (text: string) => /(?:^|[\s{,])package\s*=\s*"([^"]+)"/.exec(text)?.[1] ?? null;
    if (table.entry) {
      // Inside `[dependencies.name]`: one key per line.
      if (key === "package") table.entry.renamed = /^\s*"([^"]+)"/.exec(value)?.[1] ?? null;
      else if (key === "workspace" && /^\s*true\b/.test(value)) table.entry.inherited = true;
      if (table.workspace && key === "package" && table.entry.renamed) offered.set(table.entry.key, table.entry.renamed);
      continue;
    }
    // `name = "1"`, `name = { version = "1", package = "real" }`, `name.workspace = true`. Anything
    // else before the `=` is the inside of a value that spans lines, not an entry.
    const entry = /^("[^"]+"|'[^']+'|[A-Za-z0-9_-]+)(?:\s*\.\s*([A-Za-z0-9_-]+))?$/.exec(key);
    if (!entry) continue;
    const name = unquote(entry[1]);
    const field = entry[2] ?? null;
    if (!/^[A-Za-z0-9_-]+$/.test(name)) continue;
    const renamed = field === null ? renamedTo(value) : field === "package" ? (/^\s*"([^"]+)"/.exec(value)?.[1] ?? null) : null;
    const inherited = field === null ? /(?:^|[\s{,])workspace\s*=\s*true\b/.test(value) : field === "workspace" && /^\s*true\b/.test(value);
    if (table.workspace) {
      if (renamed) offered.set(name, renamed);
      continue;
    }
    // Dotted keys spread one entry over lines (`name.version = "1"`, `name.package = "real"`).
    const known = declared.get(`${tableNumber} ${name}`);
    if (known) {
      known.renamed ??= renamed;
      known.inherited ||= inherited;
    } else declared.set(`${tableNumber} ${name}`, { key: name, renamed, inherited });
  }
  // A crate name is letters, digits, `-` and `_`: a rename that is anything else names no crate.
  const crate = (name: string | null | undefined) => (name && /^[A-Za-z0-9_-]{1,64}$/.test(name) ? name : null);
  const lockedAs = (d: CargoDeclared) => crate(d.renamed !== null ? d.renamed : d.inherited && offered.has(d.key) ? offered.get(d.key) : d.key);
  return [...new Set([...declared.values()].map(lockedAs).filter((name): name is string => name !== null))];
}

/** crates.io reads `-` and `_` as one name; a manifest may spell either. */
const foldCrateName = (name: string) => name.toLowerCase().replace(/_/g, "-");

/**
 * The dependencies the Cargo.toml beside a Cargo.lock declares that the lockfile holds no
 * `[[package]]` table for. Cargo locks every declared dependency (optional, dev, build and
 * other-platform ones included), so a missing one means the lockfile was cut short between two
 * tables or was written for an older manifest. Empty when the manifest cannot be read.
 */
function cargoLockMissingDeclared(cwd: string, packages: CargoPackage[]): string[] {
  let manifest: string;
  try {
    manifest = readTextFile(path.join(cwd, "Cargo.toml"));
  } catch {
    return [];
  }
  const locked = new Set(packages.map((pkg) => foldCrateName(pkg.name)));
  return cargoDeclaredPackages(manifest).filter((name) => !locked.has(foldCrateName(name))).sort();
}

function resolveRust(cwd: string): VersionSource {
  const lockPath = path.join(cwd, "Cargo.lock");
  if (!fs.existsSync(lockPath)) {
    return resolveRustFromManifest(cwd);
  }

  const versions = new Map<string, string>();
  const instances = new InstanceSet();
  const problems: LockfileProblem[] = [];
  const privateIndex: PrivateIndexEntry[] = [];
  try {
    const content = readTextFile(lockPath);
    const packages = parseCargoLockPackages(content);
    if (packages.length === 0) {
      // Cargo writes at least the project's own package: a lockfile with none was not read at all.
      const error = describeParseError(lockPath, null) ?? "it holds no [[package]] table, and cargo always writes at least the project's own: it is truncated or not a Cargo.lock";
      return { ...emptySource(), problems: [{ file: lockPath, error }] };
    }
    const damage = cargoLockDamage(content, packages, cargoLockMissingDeclared(cwd, packages));
    if (damage) problems.push(partialRead(lockPath, damage.reason, damage.missing, damage.behindManifest === true));
    const versionsByName = new Map<string, string[]>();
    // Cargo writes `source` on every registry or git package. In a file it
    // wrote, a package with none is a workspace member or path dependency:
    // local code, not a release, so no advisory can be about it. A lockfile
    // with no `source` anywhere was not written by cargo; keep everything.
    const cargoWritten = packages.some((pkg) => pkg.source !== null);
    const isLocal = (pkg: CargoPackage) => cargoWritten && pkg.source === null;
    for (const pkg of packages) {
      // Local code is no crates.io release: its name is never sent either (R8: a path workspace member
      // went to crates.io and OSV.dev from dependency_check, upgrade_impact and the briefing).
      if (isLocal(pkg)) {
        privateIndex.push({ name: pkg.name, version: pkg.version, registry: "local code (a workspace member or path dependency)", file: lockPath, local: true });
        continue;
      }
      // From a registry other than crates.io, or from git: private (private-packages.ts). Kept as
      // an instance so the set is whole; the live layer leaves it out of every lookup.
      if (pkg.source && !isPublicCratesSource(pkg.source)) privateIndex.push({ name: pkg.name, version: pkg.version, registry: sourceLabel(pkg.source), file: lockPath });
      instances.add(pkg.name, pkg.version);
      versionsByName.set(pkg.name, [...(versionsByName.get(pkg.name) ?? []), pkg.version]);
    }
    // The version a direct dependency resolves to: the one a workspace member
    // names. Cargo writes "name version" when two versions coexist, else "name".
    for (const member of packages.filter(isLocal)) {
      for (const dep of member.dependencies) {
        const [name, version] = dep.split(" ");
        const candidates = versionsByName.get(name);
        if (!candidates || versions.has(name)) continue;
        if (version && candidates.includes(version)) versions.set(name, version);
        else if (!version && candidates.length === 1) versions.set(name, candidates[0]);
      }
    }
    for (const [name, list] of versionsByName) {
      if (!versions.has(name)) versions.set(name, list[0]);
    }
  } catch (error) {
    // Present and not read: it is the source of nothing, and the answer says why.
    return { ...emptySource(), problems: [{ file: lockPath, error: describeParseError(lockPath, error) ?? "could not be parsed" }] };
  }

  return found(versions, instances, lockPath, "lockfile", {
    ...(problems.length > 0 ? { problems } : {}),
    ...(privateIndex.length > 0 ? { privateIndex } : {}),
  });
}

function resolveRustFromManifest(cwd: string): VersionSource {
  const declared = new Map<string, string>();
  const cargoPath = path.join(cwd, "Cargo.toml");
  if (!fs.existsSync(cargoPath)) return emptySource();

  let manifest: string;
  try {
    manifest = readTextFile(cargoPath);
  } catch (error) {
    // Present and not readable: what it declares is not known, which is not "declares nothing".
    return { ...emptySource(), problems: [{ file: cargoPath, error: unreadableReason(error) }] };
  }
  // name = "1.0" or name = { version = "1.0", ... }, inside dependency tables
  // only: [package]'s own `version = "0.1.0"` and `edition = "2021"` were read
  // as crates named "version" and "edition".
  let inDeps = false;
  for (const line of manifest.split(/\r?\n/)) {
    const header = /^\s*\[([^\]]+)\]\s*$/.exec(line);
    if (header) {
      inDeps = /(?:^|\.)(?:dev-|build-)?dependencies$/.test(header[1].trim());
      continue;
    }
    if (!inDeps) continue;
    const match = /^\s*([a-zA-Z_][\w-]*)\s*=\s*(?:"([^"]+)"|.*?\bversion\s*=\s*"([^"]+)")/.exec(line);
    const spec = match?.[2] ?? match?.[3];
    if (match && spec && /^[=^~]?\s*\d/.test(spec)) declared.set(match[1], spec);
  }

  // Cargo reads "1.0" as "^1.0": only "=1.2.3" names one version.
  return declaredRanges(declared, (spec) => /^=\s*\d+\.\d+\.\d+/.test(spec.trim()), cargoPath);
}

// =============================================================================
// Helpers
// =============================================================================

/** package.json dependency ranges (all dependency fields), or none when unreadable. */
function manifestRanges(cwd: string): Array<[string, string]> {
  try {
    const pkg = JSON.parse(readTextFile(path.join(cwd, "package.json")));
    const out: Array<[string, string]> = [];
    for (const field of ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"]) {
      for (const [name, range] of Object.entries(pkg[field] ?? {})) {
        if (typeof range === "string") out.push([name, range]);
      }
    }
    return out;
  } catch {
    return [];
  }
}

/**
 * Extract a usable version from an npm version specifier.
 * "^4.18.2" -> "4.18.2", "~1.0.0" -> "1.0.0", ">=2.0.0" -> "2.0.0"
 */
function extractVersionFromSpec(spec: string): string | null {
  if (!spec) return null;
  const match = spec.match(/(\d+\.\d+\.\d+(?:-[\w.]+)?)/);
  return match ? match[1] : null;
}

/** A TOML key on the left of `=`: bare, quoted, or dotted parts of either. */
const TOML_KEY = /^\s*(?:[A-Za-z0-9_-]+|"(?:[^"\\]|\\.)*"|'[^']*')(?:\s*\.\s*(?:[A-Za-z0-9_-]+|"(?:[^"\\]|\\.)*"|'[^']*'))*\s*=/;
/** A table header on one line: `[a.b]`, `[[a]]`, `[a."b c"]`, with an optional comment. */
const TOML_HEADER = /^\s*\[\[?\s*(?:[A-Za-z0-9_-]+|"(?:[^"\\]|\\.)*"|'[^']*')(?:\s*\.\s*(?:[A-Za-z0-9_-]+|"(?:[^"\\]|\\.)*"|'[^']*'))*\s*\]\]?\s*(?:#.*)?$/;

/**
 * Why a TOML manifest (Cargo.toml, pyproject.toml) is not valid TOML, or null when nothing says so.
 * Not a full parser: it checks what a hand edit breaks (a table header left open, an array or inline
 * table never closed, a string left open at the end of its line, a line that is neither a header nor
 * `key = value`), which is what made a project read as having no dependencies (review 2026-11-24).
 */
/**
 * Where a multi-line string that is open at `from` closes on `line` (the index just past its
 * delimiter), or -1. TOML 1.0: in a basic string (`"""`) a backslash escapes the next character
 * (`\"""` is not a close), and one or two quotes right before the closing three belong to the
 * string (`"""He said "hi""""`, `""""" `): the close is the last three of a run of up to five
 * (re-check 2026-11-24: both were called "not closed", a valid Cargo.toml then UNREADABLE).
 */
function multilineClose(line: string, from: number, triple: string): number {
  const quote = triple[0];
  for (let i = from; i < line.length; i++) {
    if (quote === '"' && line[i] === "\\") {
      i++;
      continue;
    }
    if (line.startsWith(triple, i)) {
      let end = i + 3;
      while (end < line.length && line[end] === quote && end - i < 5) end++;
      return end;
    }
  }
  return -1;
}

export function tomlSyntaxProblem(content: string): string | null {
  let depth = 0;
  let multiline: string | null = null;
  const lines = content.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    let line = lines[i];
    if (multiline) {
      const end = multilineClose(line, 0, multiline);
      if (end < 0) continue;
      line = line.slice(end);
      multiline = null;
    } else if (depth === 0) {
      const t = line.trim();
      if (t === "" || t.startsWith("#")) continue;
      if (t.startsWith("[")) {
        if (!TOML_HEADER.test(t)) return `line ${i + 1} is a table header that is not closed or not valid (${t.slice(0, 60)})`;
        continue;
      }
      const key = TOML_KEY.exec(line);
      if (!key) return `line ${i + 1} is neither a table header nor \`key = value\` (${t.slice(0, 60)})`;
      line = line.slice(key[0].length);
      if (line.trim() === "") return `line ${i + 1} has no value after \`=\``;
    }
    for (let j = 0; j < line.length; j++) {
      const ch = line[j];
      if (ch === "#") break;
      if (ch === '"' || ch === "'") {
        const triple = line.slice(j, j + 3);
        if (triple === '"""' || triple === "'''") {
          const end = multilineClose(line, j + 3, triple);
          if (end < 0) {
            multiline = triple;
            break;
          }
          j = end - 1;
          continue;
        }
        let k = j + 1;
        while (k < line.length && line[k] !== ch) k += ch === '"' && line[k] === "\\" ? 2 : 1;
        if (k >= line.length) return `line ${i + 1} ends inside a string`;
        j = k;
        continue;
      }
      if (ch === "[" || ch === "{") depth++;
      else if (ch === "]" || ch === "}") {
        depth--;
        if (depth < 0) return `line ${i + 1} closes a bracket that was never opened`;
      }
    }
  }
  if (multiline) return "a multi-line string is not closed at the end of the file";
  if (depth > 0) return "an array or inline table is not closed at the end of the file";
  return null;
}

/**
 * Why the manifest the resolver reads beside a lockfile (package.json, Cargo.toml, pyproject.toml)
 * cannot be parsed, or null. A manifest that cannot be read is not "nothing declared": the direct
 * dependencies and the lockfile's cross-check against it are unknown (review 2026-11-24).
 */
export function manifestSyntaxProblem(file: string): string | null {
  let content: string;
  try {
    content = readManifestText(file);
  } catch (error) {
    if ((error as NodeJS.ErrnoException | null)?.code === "ENOENT") return null;
    return `it could not be read (${error instanceof Error ? error.message.slice(0, 120) : String(error)})`;
  }
  if (/\.json$/i.test(file)) {
    try {
      const parsed: unknown = JSON.parse(content);
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return "it is not a JSON object";
      return null;
    } catch (error) {
      return `it is not valid JSON (${error instanceof Error ? error.message.slice(0, 120) : String(error)})`;
    }
  }
  const toml = tomlSyntaxProblem(content);
  return toml ? `it is not valid TOML: ${toml}` : null;
}

/** The words for a manifest that could not be parsed: what was not checked because of it. */
export function manifestProblemText(why: string): string {
  return `${why}, so the dependencies it declares were not read: which are direct, and whether the lockfile holds every one, were not checked. Fix the file, then scan again`;
}

/** Whether YAML text leaves a flow sequence or mapping open at its end (brackets outside quotes and comments). */
function unclosedFlow(content: string): boolean {
  let depth = 0;
  for (const line of content.split(/\r?\n/)) {
    let quote: string | null = null;
    for (let i = 0; i < line.length; i++) {
      const ch = line[i];
      if (quote) {
        if (ch === quote) quote = null;
      } else if (ch === "'" || ch === '"') quote = ch;
      else if (ch === "#" && (i === 0 || /\s/.test(line[i - 1]))) break;
      else if (ch === "[" || ch === "{") depth++;
      else if (ch === "]" || ch === "}") depth = Math.max(0, depth - 1);
    }
  }
  return depth > 0;
}
