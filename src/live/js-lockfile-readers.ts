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

import type { InstanceSet } from "./lockfile-types.js";

const DEPENDENCY_BLOCKS = new Set(["dependencies:", "devDependencies:", "optionalDependencies:"]);

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
    else if (/^(?:commit|repo|directory):/.test(field)) entry.local = true;
  }
}

/** A registry tarball (`https://<registry>/<name>/-/<name>-<version>.tgz`, query allowed), not a codeload/git/arbitrary archive. */
function isRegistryTarball(url: string): boolean {
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

/** A `packages:`/`snapshots:` key, or a dependency value that points at one, in one spelling: unquoted, no leading `/`. */
export function pnpmKeyRef(raw: string): string {
  return unquote(raw.trim()).replace(/^\//, "");
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
export function pnpmEntryReader(onEntry: (key: string, id: [string, string], dev: boolean | undefined) => void): PnpmEntryReader {
  let entry: PnpmEntry | null = null;
  const finish = () => {
    const id = entry ? pnpmEntryIdentity(entry) : null;
    if (entry && id) onEntry(entry.key, id, entry.dev);
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
  for (const line of content.split(/\r?\n/)) {
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
export function readPnpmLock(content: string, versions: Map<string, string>, instances?: InstanceSet): void {
  const transitive: Array<[string, string]> = [];
  const devByKey = new Map<string, boolean>();
  const setFirst = (name: string, version: string): void => {
    if (!versions.has(name)) versions.set(name, version);
  };
  let section = "";
  let blockIndent = -1; // column of the dependency block being read, or -1
  let pending: string | null = null; // v6/v9: a name whose `version:` line follows
  const entries = pnpmEntryReader((_key, id, dev) => {
    transitive.push(id);
    if (dev !== undefined) devByKey.set(`${id[0]}\0${id[1]}`, dev);
  });

  for (const line of content.split(/\r?\n/)) {
    const text = line.trim();
    if (text === "" || text.startsWith("#")) continue;
    const indent = line.length - line.trimStart().length;

    if (indent === 0) {
      entries.finish();
      section = text.endsWith(":") ? text.slice(0, -1) : "";
      blockIndent = DEPENDENCY_BLOCKS.has(text) ? 0 : -1;
      pending = null;
      continue;
    }
    if (section === "packages" || section === "snapshots") {
      entries.line(indent, text);
      continue;
    }
    if (section === "importers" && indent <= 4) {
      blockIndent = indent === 4 && DEPENDENCY_BLOCKS.has(text) ? 4 : -1;
      pending = null;
      continue;
    }
    if (blockIndent < 0) continue;

    if (indent === blockIndent + 2) {
      pending = null;
      const entry = /^(?:'([^']+)'|"([^"]+)"|([^\s:'"]+)):(?:\s+(.*))?$/.exec(text);
      if (!entry) continue;
      const name = entry[1] ?? entry[2] ?? entry[3];
      const value = entry[4];
      if (value === undefined || value === "") {
        pending = name;
      } else {
        const version = exactVersion(value); // v5: `name: 1.2.3_peer@4.5.6`
        if (version) setFirst(name, version);
      }
    } else if (indent === blockIndent + 4 && pending && text.startsWith("version:")) {
      const version = exactVersion(text.slice("version:".length));
      if (version) setFirst(pending, version);
      pending = null;
    }
  }

  entries.finish();
  for (const [name, version] of transitive) setFirst(name, version);
  if (!instances) return;
  // A Set, not `transitive.some` per entry: that was O(n²), and a 200k-entry pnpm-lock.yaml
  // held the single-threaded stdio server for 409 s (audit 6.2.5 C-8).
  const seen = new Set(transitive.map(([n, v]) => `${n} ${v}`));
  for (const [name, version] of versions) {
    if (!seen.has(`${name} ${version}`)) instances.add(name, version);
  }
  for (const [name, version] of transitive) instances.add(name, version, devByKey.get(`${name}\0${version}`));
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

/** The `version` of a yarn.lock block: v1 `  version "1.2.3"`, berry `  version: 1.2.3`. */
export function yarnBlockVersion(block: string): string | null {
  return yarnBlockField(block, /^[ \t]+version:?[ \t]+"?([^"\s]+)"?[ \t]*$/);
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
    if (/@(?:workspace|link|portal|file|exec|patch):/.test(firstLine)) continue;
    const raw = yarnBlockVersion(block);
    const version = raw ? exactVersion(raw) : null;
    if (!version) {
      if (block.split(/\r?\n/).some((line) => line.length > MAX_LOCKFILE_LINE)) skipped++;
      continue;
    }
    const name = yarnPackageName(block, firstLine, header[1]);
    // One block per resolved version. Blocks are sorted by spec, so the first
    // block of a name can be an old nested copy; `specs` lets the caller pick
    // the copy a package.json range resolves to instead.
    if (!versions.has(name)) versions.set(name, version);
    instances?.add(name, version);
    if (specs) {
      for (const spec of firstLine.replace(/:\s*$/, "").split(",")) {
        specs.set(unquote(spec.trim()).replace(/@npm:/, "@"), version);
      }
    }
  }
  return skipped;
}
