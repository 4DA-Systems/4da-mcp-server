// SPDX-License-Identifier: Apache-2.0
/**
 * pnpm and yarn lockfile readers: exact versions, no YAML parser.
 *
 * Measured 2026-09-11: the previous pnpm reader matched package keys with
 * `/^\s{2}'?(.+?)@(\d…)/gm` over the whole file. `\s` also matches a newline,
 * and pnpm writes a blank line between entries, so each match began on the
 * blank line and kept the next key's opening quote. Every scoped package
 * outside the importer blocks reached OSV as `'@scope/name` and matched
 * nothing: 525 names across five lockfiles in this repository, including
 * `@humanfs/node@0.16.7` (GHSA-p498-v437-472g), which GitHub and the app both
 * flagged. The test fixture had no blank lines, so it passed. The yarn reader's
 * header pattern could not start with `@`, so it dropped every scoped package,
 * and it never read yarn berry's `version: x` lines.
 *
 * So indentation is read by column on whole lines, never with `\s` across a
 * line break, and a key that does not pin a registry version (git, tarball,
 * file, link) is dropped instead of being queried as a package name.
 */

import type { DeclaredDependency, InstanceSet } from "./lockfile-types.js";
import { ScopeGraph } from "./scope-graph.js";
import { runSteps, STEP_MASK, type Steps } from "./yield-point.js";

const DEPENDENCY_BLOCKS = new Set(["dependencies:", "devDependencies:", "optionalDependencies:"]);

/** A dependency a JS lockfile installs from somewhere other than a registry, as its reader reports it. */
export interface NonRegistryEntry {
  name: string;
  /** The version its own package.json states, when the lockfile records one. */
  version: string | null;
  kind: "git" | "url" | "file";
}

/** What a reader could not turn into packages, beyond the packages themselves. */
export interface LockReadReport {
  /** Git, URL and local-archive dependencies: not registry releases, never matched as one. */
  uncheckable: NonRegistryEntry[];
  /** Entries that name a package but no version: the file stops mid-entry or is damaged. */
  incomplete: number;
  /** pnpm: direct dependencies an importer pins that have no `packages:` entry. */
  missingDirect: string[];
  /** pnpm: every copy an importer (the project or a workspace member) declares. */
  declared?: DeclaredDependency[];
  /** pnpm: true when the scope of each copy is the lockfile's own, or was derived from its importers. */
  scopeGraded?: boolean;
  /**
   * The dependency names the lockfile holds for the project's own package.json: what pnpm's root
   * importer lists, bun's package keys. Not set when the lockfile does not say (no importers).
   */
  rootEntries?: ReadonlySet<string>;
  /**
   * Names the lockfile installs from somewhere other than a registry (a link or workspace member,
   * a local directory or archive, git, a URL): pnpm's root importer, yarn's entries, bun's packages.
   * A direct dependency of such a name is not looked up by it (VersionSource.elsewhere).
   */
  elsewhere?: string[];
}

export function emptyReadReport(): LockReadReport {
  return { uncheckable: [], incomplete: 0, missingDirect: [], elsewhere: [] };
}

const GIT_LOCATION = /^(?:git\+|git:\/\/|git@|ssh:\/\/|github:|gitlab:|bitbucket:|gist:)/i;
const CODE_HOST = /^https?:\/\/(?:[^/@\s]*@)?(?:codeload\.github\.com|github\.com|api\.github\.com|raw\.githubusercontent\.com|gist\.github\.com|gitlab\.com|bitbucket\.org)\//i;
const ARCHIVE_FILE = /\.(?:tgz|tar\.gz|tar|zip)$/i;

/**
 * What a lockfile's `resolved` location (or a dependency spec) is when it is
 * NOT a registry release: a git checkout, an archive fetched from a URL, a
 * local archive (`file:`), or local source (`local`: a directory, never a
 * release). Null for a registry release.
 *
 * A `git+ssh://…` checkout keeps the version number its package.json states,
 * so `bignumber.js@2.0.7` from a fork was sent to OSV as npm's
 * `bignumber.js 2.0.7` (audit 2026-11-11). The registry package's advisories
 * do not describe a fork or an arbitrary commit, in either direction.
 *
 * A URL that is not registry-shaped is only called a URL dependency when it
 * is on a code host or `requested` (the spec that asked for it) is itself a
 * URL: private registries serve tarballs from paths of their own.
 */
export function nonRegistrySource(location: string, requested?: string): "git" | "url" | "file" | "local" | null {
  const where = location.trim();
  if (GIT_LOCATION.test(where)) return "git";
  if (/^file:/i.test(where)) return ARCHIVE_FILE.test(where.split(/[?#]/)[0]) ? "file" : "local";
  if (/^(?:link|workspace|portal|exec):/i.test(where)) return "local";
  if (!/^https?:\/\//i.test(where)) return null;
  if (isRegistryTarball(where)) return null;
  if (/\.git$/i.test(where.split(/[?#]/)[0]) || CODE_HOST.test(where)) return "git";
  const asked = requested?.trim() ?? "";
  return GIT_LOCATION.test(asked) || /^https?:\/\//i.test(asked) ? "url" : null;
}

/** A bare npm package name, scoped or not: no whitespace, no `/` beyond the scope, no version. */
const PACKAGE_NAME = /^(?:@[^\s/@]+\/)?[^\s/@]+$/;

function unquote(s: string): string {
  return s.length >= 2 && (s[0] === "'" || s[0] === '"') && s[s.length - 1] === s[0] ? s.slice(1, -1) : s;
}

/** An exact version with pnpm's peer suffixes removed: v6/v9 `1.2.3(react@18)`, v5 `1.2.3_react@18`. */
export function exactVersion(raw: string): string | null {
  const version = unquote(raw.trim()).split("(")[0].split("_")[0].trim();
  return /^\d/.test(version) ? version : null;
}

/**
 * Splits one `packages:` or `snapshots:` key into [name, version]:
 * v9 `'@scope/pkg@1.2.3(peer@4.5.6)'`, v6 `/pkg@1.2.3`, v5 `/@scope/pkg/1.2.3_peer@4.5.6`.
 * Returns null for a key that does not pin a registry version.
 */
export function parsePnpmKey(rawKey: string): [string, string] | null {
  let key = unquote(rawKey.trim());
  if (key.startsWith("/")) key = key.slice(1);
  const peers = key.indexOf("(");
  if (peers >= 0) key = key.slice(0, peers);

  // v6 and v9: the separator is the first `@` after a scoped name's own leading `@`.
  const at = key.indexOf("@", key.startsWith("@") ? 1 : 0);
  if (at > 0) {
    const name = key.slice(0, at);
    const version = exactVersion(key.slice(at + 1));
    if (PACKAGE_NAME.test(name) && version) return [name, version];
  }

  // v5: `name/version`, with any peers after an underscore.
  const v5 = /^((?:@[^/@\s]+\/)?[^/@\s]+)\/(\d[^/]*)$/.exec(key);
  if (v5) {
    const version = exactVersion(v5[2]);
    if (version) return [v5[1], version];
  }
  return null;
}

/** One `packages:`/`snapshots:` entry: its key and the fields that say what it installs. */
interface PnpmEntry {
  key: string;
  /** The entry's own `name:` and `version:` fields (written when the key is not `name@version`). */
  name?: string;
  version?: string;
  tarball?: string;
  /** A git or directory resolution (`commit:`, `repo:`, `directory:`): not a registry release. */
  local: boolean;
  /** A git resolution (`commit:`, `repo:`): somebody else's code, unlike a `directory:`. */
  git?: boolean;
  dev?: boolean;
  inResolution: boolean;
}

function yamlScalar(text: string, key: string): string | null {
  if (!text.startsWith(`${key}:`)) return null;
  const value = unquote(text.slice(key.length + 1).trim()).trim();
  return value === "" ? null : value;
}

function pnpmEntryField(entry: PnpmEntry, text: string): void {
  entry.inResolution = false;
  const dev = /^dev:\s*(true|false)\s*$/.exec(text);
  const name = yamlScalar(text, "name");
  const version = yamlScalar(text, "version");
  if (dev) entry.dev = dev[1] === "true";
  else if (name) entry.name = name;
  else if (version) entry.version = exactVersion(version) ?? undefined;
  else if (text.startsWith("resolution:")) {
    entry.inResolution = true;
    pnpmResolutionText(entry, text.slice("resolution:".length));
  }
}

/** `resolution:` is a flow mapping, on one line or (pnpm 5) spread over several. */
function pnpmResolutionText(entry: PnpmEntry, text: string): void {
  for (const part of text.split(/[,{}]/)) {
    const field = part.trim();
    if (field.startsWith("tarball:")) entry.tarball = unquote(field.slice("tarball:".length).trim());
    else if (/^(?:commit|repo|directory):/.test(field)) {
      entry.local = true;
      if (!field.startsWith("directory:")) entry.git = true;
    }
  }
}

/** A registry tarball (`https://<registry>/<name>/-/<name>-<version>.tgz`, query allowed), not a codeload/git/arbitrary archive. */
export function isRegistryTarball(url: string): boolean {
  const pathPart = url.split(/[?#]/)[0];
  return pathPart.includes("/-/") && /\.tgz$/i.test(pathPart);
}

/**
 * The (name, version) a pnpm entry installs from a registry, or null.
 *
 * The key is not always `name@version`: pnpm 5 keys a package fetched by
 * tarball URL by that URL and writes `name:`/`version:` fields under it.
 * trpc's lockfile installs @prisma/client 4.7.1 four times that way, from
 * registry.npmjs.com, and none of them was read (4DA conformance corpus,
 * 2026-10-12). The fields win when present; a tarball that is not a registry
 * artifact, a git checkout or a directory is not a registry release.
 */
function pnpmEntryIdentity(entry: PnpmEntry): [string, string] | null {
  if (entry.local) return null;
  const parsed = parsePnpmKey(entry.key);
  if (entry.name && PACKAGE_NAME.test(entry.name)) {
    if (entry.tarball && !isRegistryTarball(entry.tarball)) return null;
    const version = entry.version ?? parsed?.[1];
    return version ? [entry.name, version] : null;
  }
  return parsed;
}

/**
 * An entry that installs something, but not a registry release: a git
 * checkout or an archive from a URL. Null for a directory (local source) and
 * for a key that names nothing at all.
 */
function pnpmNonRegistry(entry: PnpmEntry): NonRegistryEntry | null {
  const gitHosted = entry.tarball !== undefined && !isRegistryTarball(entry.tarball);
  if (!entry.git && !gitHosted) return null;
  let key = unquote(entry.key.trim()).replace(/^\//, "");
  const peers = key.indexOf("(");
  if (peers >= 0) key = key.slice(0, peers);
  const at = key.indexOf("@", key.startsWith("@") ? 1 : 0);
  const keyName = at > 0 ? key.slice(0, at) : null;
  const name = entry.name && PACKAGE_NAME.test(entry.name) ? entry.name : keyName && PACKAGE_NAME.test(keyName) ? keyName : null;
  if (!name) return null;
  const kind = entry.git || nonRegistrySource(entry.tarball ?? "") === "git" ? "git" : "url";
  return { name, version: entry.version ?? null, kind };
}

/**
 * Each line of `content`, without its line ending, one at a time: the same lines, in the same
 * order, as `content.split(/\r?\n/)`, without an array of all of them. A 150,000-entry
 * pnpm-lock.yaml is about two million lines, and one read split it three times over: the pnpm read
 * peaked at 613 MB against 6.2.7's 327 MB (blind audit of e3aba98).
 */
export function* textLines(content: string): Generator<string> {
  let start = 0;
  for (;;) {
    const end = content.indexOf("\n", start);
    const stop = end < 0 ? content.length : end;
    yield stop > start && content.charCodeAt(stop - 1) === 13 ? content.slice(start, stop - 1) : content.slice(start, stop);
    if (end < 0) return;
    start = end + 1;
  }
}

/** A `packages:`/`snapshots:` key, or a dependency value that points at one, in one spelling: unquoted, no leading `/`. */
export function pnpmKeyRef(raw: string): string {
  const ref = unquote(raw.trim());
  return ref.startsWith("/") ? ref.slice(1) : ref;
}

export interface PnpmEntryReader {
  /** One line inside a `packages:` or `snapshots:` section (indent > 0). */
  line(indent: number, text: string): void;
  /** Ends the entry being read: call at every section change and at the end of the file. */
  finish(): void;
}

/**
 * Reads `packages:`/`snapshots:` entries line by line and reports the
 * registry (name, version) each installs (see pnpmEntryIdentity); entries
 * that install no registry release are not reported.
 */
export function pnpmEntryReader(
  onEntry: (key: string, id: [string, string], dev: boolean | undefined) => void,
  onNonRegistry?: (entry: NonRegistryEntry) => void,
): PnpmEntryReader {
  let entry: PnpmEntry | null = null;
  const finish = () => {
    const id = entry ? pnpmEntryIdentity(entry) : null;
    if (entry && id) onEntry(entry.key, id, entry.dev);
    else if (entry && onNonRegistry) {
      const other = pnpmNonRegistry(entry);
      if (other) onNonRegistry(other);
    }
    entry = null;
  };
  return {
    line(indent, text) {
      if (indent === 2 && text.endsWith(":")) {
        finish();
        entry = { key: text.slice(0, -1), inResolution: false, local: false };
      } else if (entry && indent === 4) {
        pnpmEntryField(entry, text);
      } else if (entry?.inResolution && indent > 4) {
        pnpmResolutionText(entry, text);
      }
    },
    finish,
  };
}

/** Every `packages:`/`snapshots:` entry's registry (name, version), by pnpmKeyRef of its key. */
export function pnpmEntryIdentities(content: string): Map<string, [string, string]> {
  const ids = new Map<string, [string, string]>();
  const reader = pnpmEntryReader((key, id) => ids.set(pnpmKeyRef(key), id));
  let inEntries = false;
  for (const line of textLines(content)) {
    const text = line.trim();
    if (text === "" || text.startsWith("#")) continue;
    const indent = line.length - line.trimStart().length;
    if (indent === 0) {
      reader.finish();
      inEntries = text === "packages:" || text === "snapshots:";
    } else if (inEntries) {
      reader.line(indent, text);
    }
  }
  reader.finish();
  return ids;
}

/**
 * Reads a pnpm lockfile (v5.x, v6 or v9) into `versions`; the first version seen wins.
 *
 * Direct pins are read first, from the dependency blocks: `importers:` → `  <dir>:` →
 * `    dependencies:` in a workspace, or a top-level `dependencies:` block in a v5/v6
 * single-project file. A direct pin therefore wins over a transitive copy of the same
 * name. Every other package comes from a key exactly two columns deep under
 * `packages:` or `snapshots:`.
 *
 * `instances`, when given, receives EVERY copy (a package keyed at two versions is
 * two copies), with the `dev: true|false` that v5/v6 lockfiles write under each
 * package key. pnpm 9 dropped that field, so its copies have unknown scope.
 */
export function readPnpmLock(content: string, versions: Map<string, string>, instances?: InstanceSet, report?: LockReadReport): ReadonlySet<string> {
  return runSteps(readPnpmLockSteps(content, versions, instances, report));
}

/** A `packages:`/`snapshots:` key without its peer suffix: every peer variant of one package is one node of the graph. */
function pnpmNodeKey(ref: string): string {
  const peers = ref.indexOf("(");
  return peers < 0 ? ref : ref.slice(0, peers);
}

/** A dependency value with a protocol (`link:../a`, `file:../b`, `https://...`): never an alias of a registry package. */
const PROTOCOL_VALUE = /^[A-Za-z][A-Za-z0-9+.-]*:/;

/** Graph roots that stand for the importers' own sections, in the "either of two keys" list. */
const RUNTIME_ROOT = -1;
const DEV_ROOT = -2;

/**
 * readPnpmLock, pausing every STEP_MASK + 1 lines and entries (runStepsYielding; pre-publish round 10, W11).
 *
 * Scope (dev-only or runtime) per copy:
 * - lockfile 5 and 6 write it on every entry: `dev: true` (only devDependencies reach it), `dev: false`
 *   (only runtime), or no field (both). One package keyed under several peer sets is runtime when
 *   ANY of its entries is; it is dev-only when all of them are.
 * - lockfile 9 dropped the field, so it is derived: the copies the importers' `dependencies` and
 *   `optionalDependencies` reach through the `snapshots:` graph are runtime, and what only their
 *   `devDependencies` reach is dev-only. Dev-only is claimed only when every dependency named in
 *   the graph has an entry; otherwise the unreached copies stay of unknown scope.
 */
export function* readPnpmLockSteps(content: string, versions: Map<string, string>, instances?: InstanceSet, report?: LockReadReport): Steps<ReadonlySet<string>> {
  let step = 0;
  // Each registry (name, version) the entries install, once, under its `name\0version` key, in the
  // order first seen. Lockfile 9 lists every package twice (`packages:` and `snapshots:`): a list of
  // every sighting, plus a key string per sighting for the set, the dev map and the instance set
  // each, held 300,000 pairs and 600,000 strings for a 150,000-entry file (pre-publish round 10, W9).
  const transitive = new Map<string, [string, string]>();
  const devByKey = new Map<string, boolean>();
  // Copies with an entry that states no scope, in a lockfile whose version does not say what that means.
  const unstated = new Set<string>();
  // Every (name, version) an importer pins, for the check that each has a `packages:` entry; and
  // those of them a runtime section (not devDependencies) pins.
  const directPins = new Map<string, string>();
  const runtimePins = new Set<string>();
  // Importer dependencies that point at an entry under another name (an alias): [name, version, runtime].
  const aliasPins: Array<[string, string, boolean]> = [];
  let lockMajor = 0;
  let sawImporter = false;
  // The dependency names the project's own importer lists (`.`, or the top-level blocks of a single-project lockfile).
  let rootImporter = false;
  const rootNames = new Set<string>();
  // Lockfile 9: the dependency graph over entry keys (pnpmNodeKey).
  const graph = new ScopeGraph();
  const isEntry: boolean[] = [];
  const identityOf: string[] = [];
  const runtimeRoots: number[] = [];
  const devRoots: number[] = [];
  // Edges and roots whose value is a key in one of two spellings: [from, `name@value`, `value`].
  const either: Array<[number, number, number]> = [];
  let graphWhole = true;
  let entryNode = -1; // the entry whose dependency lines are being read
  let openNode = -1; // the entry the entry reader has open (it reports an entry when the next one opens)
  let inEdges = false;
  const targetOfLine = new Map<string, number | [number, number] | null>();

  const setFirst = (rawName: string, rawVersion: string, runtime: boolean): void => {
    const [name, version] = detachPair(rawName, rawVersion);
    const pinned = `${name}@${version}`;
    directPins.set(pinned, name);
    if (runtime) runtimePins.add(pinned);
    if (!versions.has(name)) versions.set(name, version);
  };
  /** The node a dependency line `name: value` points at; a pair when the value is itself a key; null for a link. */
  const pointsAt = (name: string, rawValue: string): number | [number, number] | null => {
    const value = pnpmNodeKey(unquote(rawValue.trim()));
    if (/^\d/.test(value)) return graph.node(`${name}@${value}`);
    if (/^(?:link|workspace):/.test(value)) return null;
    const ref = value.replace(/^\//, "");
    return [graph.node(`${name}@${ref}`), graph.node(ref)];
  };
  let section = "";
  let blockIndent = -1; // column of the dependency block being read, or -1
  let blockRuntime = true; // false inside a devDependencies block
  let pending: string | null = null; // v6/v9: a name whose `version:` line follows
  /** One dependency an importer block resolves: `name` to `value` (a version, or a key). */
  const pin = (name: string, value: string): void => {
    const version = exactVersion(value);
    if (version) setFirst(name, version, blockRuntime);
    else {
      const real = PROTOCOL_VALUE.test(unquote(value.trim())) ? null : parsePnpmKey(pnpmNodeKey(pnpmKeyRef(value)));
      if (real) aliasPins.push([real[0], real[1], blockRuntime]);
      // `link:packages/a`, `file:../b`, a git or tarball key: the project's dependency is no registry release.
      else if (report && (blockIndent === 0 || rootImporter)) (report.elsewhere ??= []).push(name);
    }
    if (lockMajor < 9) return;
    const target = pointsAt(name, value);
    if (typeof target === "number") (blockRuntime ? runtimeRoots : devRoots).push(target);
    else if (target) either.push([blockRuntime ? RUNTIME_ROOT : DEV_ROOT, target[0], target[1]]);
  };
  const entries = pnpmEntryReader(
    (_rawKey, id, dev) => {
      const key = `${id[0]}\0${id[1]}`;
      if (!transitive.has(key)) transitive.set(key, detachedFromKey(key, id[0].length));
      if (dev !== undefined) devByKey.set(key, (devByKey.get(key) ?? true) && dev);
      else if (lockMajor >= 5 && lockMajor < 9) devByKey.set(key, false);
      else if (lockMajor === 0) unstated.add(key);
      // The entry the reader just closed is the one `openNode` was set for.
      if (openNode >= 0) identityOf[openNode] ??= key;
    },
    report ? (other) => report.uncheckable.push(other) : undefined,
  );

  for (const line of textLines(content)) {
    if ((++step & STEP_MASK) === 0) yield;
    const text = line.trim();
    if (text === "" || text.startsWith("#")) continue;
    const indent = line.length - line.trimStart().length;

    if (indent === 0) {
      entries.finish();
      section = text.endsWith(":") ? text.slice(0, -1) : "";
      if (text.startsWith("lockfileVersion:")) lockMajor = Number(/^lockfileVersion:[ \t]*['"]?(\d+)/.exec(text)?.[1] ?? "0");
      blockIndent = DEPENDENCY_BLOCKS.has(text) ? 0 : -1;
      blockRuntime = text !== "devDependencies:";
      if (blockIndent === 0) sawImporter = true;
      rootImporter = false;
      pending = null;
      entryNode = -1;
      openNode = -1;
      inEdges = false;
      continue;
    }
    if (section === "packages" || section === "snapshots") {
      // Closes the entry before this line when the line opens another: `openNode` is still that entry's.
      entries.line(indent, text);
      if (lockMajor < 9) continue;
      if (indent === 2) {
        const opens = text.endsWith(":");
        const key = opens ? text.slice(0, -1) : text.endsWith(": {}") ? text.slice(0, -4) : null;
        entryNode = key === null ? -1 : graph.node(pnpmNodeKey(pnpmKeyRef(key)));
        if (entryNode >= 0) isEntry[entryNode] = true;
        // An empty `key: {}` snapshot is no entry to the reader: the one before it stays open.
        if (opens) openNode = entryNode;
        inEdges = false;
      } else if (indent === 4) {
        inEdges = entryNode >= 0 && (text === "dependencies:" || text === "optionalDependencies:");
      } else if (indent === 6 && inEdges) {
        // Every parent of one copy writes the same line for it: each distinct line is parsed once.
        let target = targetOfLine.get(text);
        if (target === undefined) {
          const dep = line.length > MAX_LOCKFILE_LINE ? null : /^(?:'([^']+)'|"([^"]+)"|([^\s:'"]+)):[ ]+(.+)$/.exec(text);
          // A dependency line that cannot be read is an edge that cannot be followed.
          if (!dep) graphWhole = false;
          target = dep ? pointsAt(dep[1] ?? dep[2] ?? dep[3], dep[4]) : null;
          targetOfLine.set(text, target);
        }
        if (typeof target === "number") graph.edge(entryNode, target);
        else if (target) either.push([entryNode, target[0], target[1]]);
      }
      continue;
    }
    if (section === "importers" && indent <= 4) {
      sawImporter = true;
      // `.:` (or `.: {}`) is the project itself; every other importer is a workspace member.
      if (indent === 2) rootImporter = /^(?:\.|'\.'|"\."):/.test(text);
      blockIndent = indent === 4 && DEPENDENCY_BLOCKS.has(text) ? 4 : -1;
      blockRuntime = text !== "devDependencies:";
      pending = null;
      continue;
    }
    if (blockIndent < 0) continue;

    if (indent === blockIndent + 2) {
      pending = null;
      const entry = /^(?:'([^']+)'|"([^"]+)"|([^\s:'"]+)):(?:\s+(.*))?$/.exec(text);
      if (!entry) continue;
      const name = entry[1] ?? entry[2] ?? entry[3];
      if (blockIndent === 0 || rootImporter) rootNames.add(name);
      const value = entry[4];
      if (value === undefined || value === "") {
        pending = name;
      } else {
        pin(name, value); // v5: `name: 1.2.3_peer@4.5.6`
      }
    } else if (indent === blockIndent + 4 && pending && text.startsWith("version:")) {
      pin(pending, text.slice("version:".length));
      pending = null;
    }
  }

  entries.finish();
  // A Set, not `transitive.some` per entry: that was O(n²), and a 200k-entry pnpm-lock.yaml
  // held the single-threaded stdio server for 409 s (audit 6.2.5 C-8).
  const seen = new Set(transitive.keys());
  if (report) {
    // In a whole lockfile every version an importer pins has a `packages:` entry: one without lies past where the file stops.
    for (const [pinned, name] of directPins) {
      if (!seen.has(`${name}\0${pinned.slice(name.length + 1)}`)) report.missingDirect.push(pinned);
    }
  }
  for (const [name, version] of transitive.values()) {
    if (!versions.has(name)) versions.set(name, version);
  }

  if (lockMajor >= 9) {
    for (const [from, a, b] of either) {
      const to = isEntry[a] ? a : isEntry[b] ? b : -1;
      if (to < 0) graphWhole = false;
      else if (from === RUNTIME_ROOT) runtimeRoots.push(to);
      else if (from === DEV_ROOT) devRoots.push(to);
      else graph.edge(from, to);
    }
    const known = (node: number) => isEntry[node] === true;
    if (!graph.everyTarget(known) || !runtimeRoots.every(known) || !devRoots.every(known)) graphWhole = false;
    const runtime = graph.reach(runtimeRoots);
    const dev = graph.reach(devRoots);
    for (let node = 0; node < identityOf.length; node++) {
      if ((++step & STEP_MASK) === 0) yield;
      const key = identityOf[node];
      if (key === undefined) continue;
      if (runtime[node] === 1) devByKey.set(key, false);
      else if (dev[node] === 1 && graphWhole && devByKey.get(key) !== false) devByKey.set(key, true);
    }
  }
  if (report) {
    const declared = new Map<string, DeclaredDependency>();
    const declare = (name: string, version: string, runtime: boolean) => {
      const key = `${name}\0${version}`;
      if (!seen.has(key)) return;
      const prior = declared.get(key);
      if (prior) prior.runtime ||= runtime;
      else declared.set(key, { name, version, runtime });
    };
    for (const [pinned, name] of directPins) declare(name, pinned.slice(name.length + 1), runtimePins.has(pinned));
    for (const [name, version, runtime] of aliasPins) declare(name, version, runtime);
    report.declared = [...declared.values()];
    // Lockfile 5/6 grades every entry itself; lockfile 9 is graded from its importers when it has them.
    report.scopeGraded = lockMajor >= 9 ? sawImporter : lockMajor >= 5;
    if (sawImporter) report.rootEntries = rootNames;
  }

  if (!instances) return seen;
  for (const [name, version] of versions) {
    if ((++step & STEP_MASK) === 0) yield;
    if (!seen.has(`${name}\0${version}`)) instances.add(name, version);
  }
  for (const [key, [name, version]] of transitive) {
    if ((++step & STEP_MASK) === 0) yield;
    const dev = devByKey.get(key);
    instances.add(name, version, dev === false || !unstated.has(key) ? dev : undefined, key);
  }
  // Every registry (name, version) an entry installs, as `name\0version`: pnpmLockDamage reuses it.
  return seen;
}

/**
 * The name and version of a `name\0version` key, cut from the key itself. A name cut from a line
 * of the lockfile keeps the whole file's text alive for as long as the name lives (V8 keeps a
 * longer substring as a view of its parent): 40 MB held through the rest of the read by the names
 * of a 150,000-entry pnpm-lock.yaml. The key is a fresh string, flattened when it was hashed, and
 * kept anyway (pre-publish round 10, W9).
 */
function detachedFromKey(key: string, nameLength: number): [string, string] {
  return [key.slice(0, nameLength), key.slice(nameLength + 1)];
}

/** A name and version as fresh strings, sharing nothing with the lockfile text (detachedFromKey). */
function detachPair(name: string, version: string): [string, string] {
  // A JSON round trip copies exactly, a lone surrogate included (a UTF-8 round trip would not).
  const key = JSON.parse(JSON.stringify(`${name}\0${version}`)) as string;
  return detachedFromKey(key, name.length);
}

/** What is wrong with a lockfile that was read: how to say it, and how many packages are known to be missing (a lower bound). */
export interface LockDamage {
  reason: string;
  missing: number;
}

function listed(items: string[], limit = 3): string {
  return `${items.slice(0, limit).join(", ")}${items.length > limit ? ", ..." : ""}`;
}

/**
 * Why a pnpm-lock.yaml is not the whole file pnpm wrote, or null when nothing
 * says so. A lockfile cut short (a failed checkout, a disk that filled, a bad
 * merge) still reads: the reader takes every entry up to the cut and stops, and
 * a 93-package project scanned as 17 with no notice (audit 2026-11-11, M12).
 *
 * Checked, each a property every lockfile pnpm writes has:
 * - indentation is spaces, and a flow value (`{…}`, `[…]`) closes on its line;
 * - every version an importer pins has a `packages:` entry (`missingDirect`,
 *   from readPnpmLock);
 * - every `packages:` entry has a `resolution:`;
 * - every dependency an entry names with a plain version has an entry;
 * - lockfile 9: `packages:` comes with `snapshots:`, one or more per package.
 */
export function pnpmLockDamage(content: string, missingDirect: string[] = [], identities?: ReadonlySet<string>): LockDamage | null {
  return runSteps(pnpmLockDamageSteps(content, missingDirect, identities));
}

/** pnpmLockDamage, pausing every STEP_MASK + 1 lines (runStepsYielding; pre-publish round 10, W11). */
export function* pnpmLockDamageSteps(content: string, missingDirect: string[] = [], identities?: ReadonlySet<string>): Steps<LockDamage | null> {
  let step = 0;
  const lockMajor = Number(/^lockfileVersion:[ \t]*['"]?(\d+)/m.exec(content)?.[1] ?? "0");
  const sections = new Set<string>();
  // Every entry key as written (both sections), the `packages:` keys, and the `snapshots:` keys
  // without their peer suffix. One set each: no copy of the keys in a fourth (blind audit of e3aba98,
  // a 150,000-entry lockfile).
  const keys = new Set<string>();
  const packageKeys = new Set<string>();
  const snapshotBases = new Set<string>();
  // The registry (name, version) each entry installs, as readPnpmLock read them (`name\0version`).
  const installs = identities ?? new Set([...pnpmEntryIdentities(content).values()].map(([n, v]) => `${n}\0${v}`));
  const malformed: number[] = [];
  let section = "";
  let unresolvedEntries = 0;
  let entryOpen = false;
  let entryResolved = false;
  const closeEntry = () => {
    if (entryOpen && section === "packages" && !entryResolved) unresolvedEntries++;
    entryOpen = false;
  };

  // Pass 1: the syntax, the sections and every entry key. Line by line (textLines), no array of lines.
  let lineNumber = 0;
  for (const line of textLines(content)) {
    if ((++step & STEP_MASK) === 0) yield;
    lineNumber++;
    if (line.length > MAX_LOCKFILE_LINE) continue;
    const text = line.trim();
    if (text === "" || text.startsWith("#")) continue;
    if (/^[ ]*\t/.test(line)) {
      malformed.push(lineNumber);
      continue;
    }
    const flow = /^(?:- |(?:'[^']*'|"[^"]*"|[^\s:'"][^:]*):[ ]+)([{[].*)$/.exec(text)?.[1];
    if (flow && !flow.endsWith(flow[0] === "{" ? "}" : "]")) malformed.push(lineNumber);
    const indent = line.length - line.trimStart().length;
    if (indent === 0) {
      closeEntry();
      section = text.endsWith(":") ? text.slice(0, -1) : "";
      if (section) sections.add(section);
      continue;
    }
    if (section !== "packages" && section !== "snapshots") continue;
    if (indent === 2) {
      closeEntry();
      const key = /^(.*?):(?:[ ]*\{\})?$/.exec(text)?.[1];
      if (!key) continue;
      const ref = pnpmKeyRef(key);
      keys.add(ref);
      if (section === "packages") packageKeys.add(ref);
      else {
        // The key up to its peer suffix, as `split("(")[0]` gave it, without an array per entry (pre-publish round 10, W9).
        const peers = ref.indexOf("(");
        snapshotBases.add(peers < 0 ? ref : ref.slice(0, peers));
      }
      entryOpen = true;
      entryResolved = false;
    } else if (indent === 4 && text.startsWith("resolution:")) {
      entryResolved = true;
    }
  }
  closeEntry();

  // Pass 2: every dependency an entry names, checked against the keys as it is read: no list of
  // the (hundreds of thousands of) references is kept. Only a plain version is checked: an alias,
  // a link or a git reference points at an entry in a spelling of its own.
  const known = (name: string, value: string, version: string): boolean =>
    keys.has(`${name}@${value}`) || keys.has(`${name}/${value}`) || keys.has(`${name}@${version}`) || installs.has(`${name}\0${value}`) || installs.has(`${name}\0${version}`);
  const dangling = new Set<string>();
  section = "";
  let inDependencies = false;
  for (const line of textLines(content)) {
    if ((++step & STEP_MASK) === 0) yield;
    if (line.length > MAX_LOCKFILE_LINE) continue;
    const text = line.trim();
    if (text === "" || text.startsWith("#") || /^[ ]*\t/.test(line)) continue;
    const indent = line.length - line.trimStart().length;
    if (indent === 0) {
      section = text.endsWith(":") ? text.slice(0, -1) : "";
      inDependencies = false;
      continue;
    }
    if (section !== "packages" && section !== "snapshots") continue;
    if (indent === 2) {
      inDependencies = false;
    } else if (indent === 4) {
      inDependencies = text === "dependencies:";
    } else if (indent === 6 && inDependencies) {
      const dep = /^(?:'([^']+)'|"([^"]+)"|([^\s:'"]+)):[ ]+(.+)$/.exec(text);
      if (!dep) continue;
      const name = dep[1] ?? dep[2] ?? dep[3];
      const value = unquote(dep[4].trim());
      if (!/^\d/.test(value)) continue;
      const version = exactVersion(value) ?? value;
      if (!known(name, value, version)) dangling.add(`${name}@${version}`);
    }
  }
  const noSnapshots = lockMajor >= 9 && packageKeys.size > 0 && !sections.has("snapshots");
  const unsnapshotted: string[] = [];
  if (lockMajor >= 9 && !noSnapshots) {
    for (const k of packageKeys) {
      if ((++step & STEP_MASK) === 0) yield;
      if (!snapshotBases.has(k)) unsnapshotted.push(k);
    }
  }

  const parts: string[] = [];
  if (malformed.length > 0) {
    parts.push(`line${malformed.length === 1 ? "" : "s"} ${listed(malformed.map(String), 5)} ${malformed.length === 1 ? "is" : "are"} not lockfile syntax`);
  }
  if (missingDirect.length > 0) {
    parts.push(`${missingDirect.length} version${missingDirect.length === 1 ? "" : "s"} its importers pin ${missingDirect.length === 1 ? "has" : "have"} no \`packages:\` entry (${listed(missingDirect)})`);
  }
  if (unresolvedEntries > 0) parts.push(`${unresolvedEntries} \`packages:\` entr${unresolvedEntries === 1 ? "y has" : "ies have"} no \`resolution:\``);
  if (dangling.size > 0) {
    parts.push(`${dangling.size} package${dangling.size === 1 ? "" : "s"} named as ${dangling.size === 1 ? "a dependency has" : "dependencies have"} no entry (${listed([...dangling])})`);
  }
  if (noSnapshots) parts.push("it has `packages:` but no `snapshots:` section, which lockfile 9 always writes");
  if (unsnapshotted.length > 0) {
    parts.push(`${unsnapshotted.length} \`packages:\` entr${unsnapshotted.length === 1 ? "y has" : "ies have"} no \`snapshots:\` entry (${listed(unsnapshotted)})`);
  }
  if (parts.length === 0) return null;
  const missing = new Set([...missingDirect, ...dangling, ...unsnapshotted]).size;
  return { reason: `it is truncated or damaged: ${parts.join("; ")}`, missing };
}

/**
 * The registry package a yarn block installs. An npm alias
 * (`"string-width-cjs": "npm:string-width@^4.2.0"`) keys the block by the
 * alias, which is not a package: OSV knows `string-width`, so the alias was
 * queried for nothing and the real package went unscanned (hono's
 * benchmarks/routers yarn.lock, 4DA conformance corpus, 2026-10-12). berry
 * names the real package in `resolution:`; v1 only in the alias spec.
 */
export function yarnPackageName(block: string, firstLine: string, headerName: string): string {
  const resolution = yarnBlockField(block, /^[ \t]+resolution:[ \t]+"?((?:@[^\s/@"]+\/)?[^\s/@"]+)@npm:/);
  if (resolution) return resolution;
  const alias = /^"?(?:@[^\s/@"]+\/)?[^\s/@"]+@npm:((?:@[^\s/@"]+\/)?[^\s/@"]+)@/.exec(firstLine);
  return alias ? alias[1] : headerName;
}

/** Lines longer than this in a yarn.lock are not read: no real entry comes near it. */
export const MAX_LOCKFILE_LINE = 4096;

/**
 * The first capture of `lineRe` on any line of a yarn.lock block, or null.
 * Line by line with single-line regexes: the multiline `/^\s+version.../m`
 * forms they replace let `\s+` run across lines and took ~5 s on a hostile
 * 64 KB block (audit 2026-10-12, B-10).
 */
function yarnBlockField(block: string, lineRe: RegExp): string | null {
  for (const line of block.split(/\r?\n/)) {
    if (line.length > MAX_LOCKFILE_LINE) continue;
    const m = lineRe.exec(line);
    if (m) return m[1];
  }
  return null;
}

/**
 * Every descriptor a yarn.lock entry answers, unquoted. v1 quotes each one
 * (`"@scope/a@^1.0.0", "@scope/a@^1.1.0":`); berry quotes the whole list
 * (`"a@npm:^1.2.0, a@npm:^1.2.5":`), so a quote is never part of a descriptor
 * and the list is split only after the quotes are gone.
 */
export function yarnHeaderSpecs(firstLine: string): string[] {
  return firstLine
    .replace(/:\s*$/, "")
    .replaceAll('"', "")
    .split(",")
    .map((spec) => spec.trim())
    .filter((spec) => spec !== "");
}

/** The `version` of a yarn.lock block: v1 `  version "1.2.3"`, berry `  version: 1.2.3`. */
export function yarnBlockVersion(block: string): string | null {
  return yarnBlockField(block, /^[ \t]+version:?[ \t]+"?([^"\s]+)"?[ \t]*$/);
}

/**
 * Where a yarn block installs from when that is not a registry: berry states
 * it in `resolution:` (`name@npm:1.2.3` is the registry; a git or https
 * locator is not), v1 in `resolved`. Null for a registry release.
 */
function yarnNonRegistry(block: string, firstLine: string): "git" | "url" | "file" | "local" | null {
  const resolution = yarnBlockField(block, /^[ \t]+resolution:[ \t]+"?([^"\s]+)"?[ \t]*$/);
  if (resolution) {
    const at = resolution.indexOf("@", resolution.startsWith("@") ? 1 : 0);
    const locator = at > 0 ? resolution.slice(at + 1) : "";
    return locator.startsWith("npm:") ? null : nonRegistrySource(locator, locator);
  }
  const resolved = yarnBlockField(block, /^[ \t]+resolved[ \t]+"([^"]+)"/);
  if (!resolved) return null;
  const spec = yarnHeaderSpecs(firstLine)[0] ?? "";
  const at = spec.indexOf("@", spec.startsWith("@") ? 1 : 0);
  return nonRegistrySource(resolved, at > 0 ? spec.slice(at + 1) : undefined);
}

/**
 * Reads a yarn lockfile (v1 or berry) into `versions`.
 * v1: `"@scope/pkg@^1.0.0", "@scope/pkg@^1.1.0":` then `  version "1.2.3"`.
 * berry: `"@scope/pkg@npm:^1.0.0":` then `  version: 1.2.3`.
 * Workspace, link, portal, file, exec and patch entries do not name a registry version.
 * Returns how many entries were skipped because a line of theirs is longer
 * than MAX_LOCKFILE_LINE, so the caller can say the read was partial (audit
 * L5: the skip was silent).
 */
export function readYarnLock(
  content: string,
  versions: Map<string, string>,
  instances?: InstanceSet,
  specs?: Map<string, string>,
  report?: LockReadReport,
): number {
  let skipped = 0;
  for (const block of content.split(/\r?\n(?=\S)/)) {
    const firstLine = block.split(/\r?\n/)[0];
    if (firstLine.length > MAX_LOCKFILE_LINE) {
      skipped++;
      continue;
    }
    const header = /^"?(@?[^@\s"]+)@/.exec(firstLine);
    if (!header || header[1].startsWith("__")) continue;
    if (/@(?:workspace|link|portal|file|exec|patch):/.test(firstLine)) {
      // A workspace member, a link or a local directory: local code. A patch wraps a release, which has its own entry.
      if (report && !/@patch:/.test(firstLine)) (report.elsewhere ??= []).push(header[1]);
      continue;
    }
    const raw = yarnBlockVersion(block);
    const version = raw ? exactVersion(raw) : null;
    if (!version) {
      if (block.split(/\r?\n/).some((line) => line.length > MAX_LOCKFILE_LINE)) skipped++;
      // A package entry always states its version: one without is where the file stops, or damage.
      else if (report) report.incomplete++;
      continue;
    }
    // A git checkout or a URL archive keeps a version number, but it is not that release of the registry package.
    const other = yarnNonRegistry(block, firstLine);
    if (other) {
      if (other !== "local") report?.uncheckable.push({ name: header[1], version, kind: other });
      if (report) (report.elsewhere ??= []).push(header[1]);
      continue;
    }
    const name = yarnPackageName(block, firstLine, header[1]);
    // One block per resolved version. Blocks are sorted by spec, so the first
    // block of a name can be an old nested copy; `specs` lets the caller pick
    // the copy a package.json range resolves to instead.
    if (!versions.has(name)) versions.set(name, version);
    instances?.add(name, version);
    if (specs) {
      for (const spec of yarnHeaderSpecs(firstLine)) specs.set(spec.replace(/@npm:/, "@"), version);
    }
  }
  return skipped;
}
