// SPDX-License-Identifier: Apache-2.0
/**
 * What a package.json dependency spec installs, read as npm reads it (npm-package-arg's
 * `resolve`): a registry release (a version, a range or a dist-tag of the registry package, or an
 * `npm:` alias to one), or something else, whose name is never looked up anywhere.
 *
 * Review of the 6.5.1 candidate (2026-11-24): the classifier it used (nonRegistrySource) knew only
 * `file:`, `link:`, git and URL prefixes, so the spellings npm reads as a path or as GitHub
 * without any prefix were taken for ranges and their names went to registry.npmjs.org, to
 * api.npmjs.org's download counts and, through ecosystem_pulse, to hn.algolia.com:
 * `"x": "../libs/x"`, `"./libs/x"`, `"~/x"`, `"/abs/x"`, `"vendor/x-1.0.0.tgz"`, `"org/repo"`,
 * `"org/repo#ref"`, and a tarball URL on a host of the company's own. npm-package-arg's order is:
 * `file:` and `npm:` prefixes; a hosted-git spelling (`org/repo`, `github:`...); anything with a
 * scheme (`/^(?:git[+])?[a-z]+:/i`, a Windows drive letter included); anything with a slash (a
 * backslash on Windows) or a tarball file name; and only then the registry. That is followed here,
 * with a backslash read as a path on every platform (no range or tag holds one).
 *
 * Deliberate additions. A tarball URL on the public npm registry (or a public mirror of it) that
 * names this very package is that registry release, so it is checked; a tarball anywhere else is
 * withheld. Yarn berry's `npm:<range>` and `patch:` wrap a registry release when what they wrap is
 * one. pnpm's and Bun's `catalog:` is what the catalog entry says (npm-catalog.ts), classified by
 * these same rules; an entry that cannot be found or read is `catalog` (withheld): what was not
 * classified is never sent (review 2026-11-24: a `link:` catalog entry went to the registry).
 *
 * Whitespace: npm-package-arg does not trim a spec. A range with spaces around it is still a range
 * to semver, and a path or git spelling stays one when trimmed, so the spec is trimmed; but a
 * protocol spelling (`npm:`, `catalog:`, `patch:`, a URL) with leading or trailing whitespace is
 * not what npm reads as that protocol, and is withheld.
 */

import { isPublicNpmHost } from "./private-hosts.js";

/** A registry release: `name` is the package a lookup may name (an alias's target, never the local key). */
export interface NpmRegistrySpec {
  kind: "registry";
  name: string;
  range: string;
  /** The catalog entry a `catalog:` spec resolved to. */
  catalogSpec?: string;
}

/**
 * Not a registry release: git, a remote archive, a local archive, local source code, or a
 * `catalog:` entry that could not be found or read (`catalog`).
 */
export interface NpmOtherSpec {
  kind: "git" | "url" | "file" | "local" | "catalog" | "ambiguous";
  /** The catalog entry a `catalog:` spec resolved to, when it was found. */
  catalogSpec?: string;
}

/** Where `catalog:` specs are resolved (npm-catalog.ts's NpmCatalogs). */
export interface NpmCatalogLookup {
  lookup(catalog: string, name: string): string | undefined;
}

export type NpmSpecClass = NpmRegistrySpec | NpmOtherSpec;

/** An npm package name, scoped or not (old names with capitals included). */
const PACKAGE_NAME = /^(?:@[a-z0-9~][a-z0-9._~-]*\/)?[a-z0-9~][a-z0-9._~-]*$/i;
/** npm-package-arg's isURL (any scheme, a drive letter included), with `+` and digits allowed after the first letter. */
const SCHEME = /^(?:git\+)?[a-z][a-z0-9+.-]*:/i;
/** npm-package-arg's isFileType: a tarball file name. */
const TARBALL_FILE = /\.(?:tgz|tar\.gz|tar)$/i;
/** hosted-git-info's GitHub shorthand: `org/repo`, `org/repo#ref` (nothing that starts like a path). */
const GITHUB_SHORTHAND = /^[^:@%/\\\s.~-][^:@%/\\\s]*\/[^:@\s/\\%]+(?:#.*)?$/;
const GIT_SCHEME = /^(?:git\+[a-z]+|git|ssh|github|gitlab|bitbucket|gist):/i;
const LOCAL_SCHEME = /^(?:link|workspace|portal|exec):/i;
const CODE_HOST = /^(?:codeload\.github\.com|github\.com|api\.github\.com|raw\.githubusercontent\.com|gist\.github\.com|gitlab\.com|bitbucket\.org)$/i;

const registry = (name: string, range: string): NpmRegistrySpec => ({ kind: "registry", name, range });

/**
 * What `spec`, declared under the key `name` in a package.json, installs. `catalogs` resolves a
 * `catalog:` spec; without it (or without the entry) the spec is withheld as `catalog`.
 */
export function classifyNpmSpec(name: string, rawSpec: string, catalogs?: NpmCatalogLookup): NpmSpecClass {
  const spec = rawSpec.trim();
  // npm reads "" as `*` (the latest release): a registry spec.
  if (spec === "") return registry(name, "*");
  // A protocol with whitespace around it is not that protocol to npm (npm-package-arg does not trim).
  if (spec !== rawSpec && SCHEME.test(spec) && !/^[a-z]:[\\/]/i.test(spec)) return { kind: "url" };
  if (/^npm:/i.test(spec)) return aliasSpec(name, spec.slice(4));
  if (/^catalog:/i.test(spec)) return catalogSpec(name, spec, catalogs);
  if (/^patch:/i.test(spec)) return patchSpec(name, spec);
  if (/^file:/i.test(spec)) return { kind: TARBALL_FILE.test(spec.split(/[?#]/)[0]) ? "file" : "local" };
  // `vendor/x-1.0.0.tgz` is a tarball file to npm (npm-package-arg's isFileType), not GitHub shorthand.
  if (!SCHEME.test(spec) && TARBALL_FILE.test(spec.split(/[?#]/)[0])) return { kind: "file" };
  if (GITHUB_SHORTHAND.test(spec)) return { kind: "git" };
  // A drive letter (`C:\src\x`, `C:/src/x`) is a path, not a scheme.
  if (/^[a-z]:[\\/]/i.test(spec)) return { kind: TARBALL_FILE.test(spec) ? "file" : "local" };
  if (SCHEME.test(spec)) {
    if (GIT_SCHEME.test(spec)) return { kind: "git" };
    if (LOCAL_SCHEME.test(spec)) return { kind: "local" };
    if (/^https?:\/\//i.test(spec)) return urlSpec(name, spec);
    // Any other protocol (jsr:, a registry of another tool): not the npm registry's package of that name.
    return { kind: "url" };
  }
  // npm-package-arg's isFileSpec: a leading `.`, `~/` (not `~`, which starts a tilde range) or a slash.
  if (/[\\/]/.test(spec) || spec.startsWith(".") || /^~[\\/]/.test(spec)) return { kind: TARBALL_FILE.test(spec.split(/[?#]/)[0]) ? "file" : "local" };
  if (TARBALL_FILE.test(spec)) return { kind: "file" };
  // A version, a range or a dist-tag (`latest`, `next`, `beta`) of the registry package.
  return registry(name, spec);
}

/** One numeric or wildcard part of a semver partial: `0`, `12`, `x`, `X`, `*`. */
const XR = /(?:0|[1-9]\d*|[xX*])/.source;
/** A prerelease or build identifier list. */
const IDS = /[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*/.source;
/** node-semver's partial: `1`, `1.x`, `1.2.3-rc.1+b`, with an optional leading `v`. */
const PARTIAL = `v?${XR}(?:\\.${XR}(?:\\.${XR}(?:-${IDS})?(?:\\+${IDS})?)?)?`;
/** One comparator: a partial with an operator, `~`, `~>` or `^`. */
const COMPARATOR = `(?:<=|>=|<|>|=|~>?|\\^)?\\s*${PARTIAL}`;
/** One range: a hyphen range, or comparators separated by spaces. */
const ONE_RANGE = `(?:${PARTIAL}\\s+-\\s+${PARTIAL}|${COMPARATOR}(?:\\s+${COMPARATOR})*)`;
/** The whole string is a node-semver range set (`||`-separated; an empty side is `*`). */
const SEMVER_RANGE = new RegExp(`^\\s*(?:${ONE_RANGE})?\\s*(?:\\|\\|\\s*(?:${ONE_RANGE})?\\s*)*$`);
/** A full version: `1.2.3`, `1.2.3-rc.1+b`. */
const FULL_VERSION = new RegExp(`^v?(?:0|[1-9]\\d*)\\.(?:0|[1-9]\\d*)\\.(?:0|[1-9]\\d*)(?:-${IDS})?(?:\\+${IDS})?$`);
/** Dist-tags in common use: in npm `npm:latest` aliases a package called `latest`, in Yarn it is the key's own tag. */
const COMMON_TAGS = new Set(["latest", "next", "beta", "alpha", "canary", "rc", "dev", "nightly", "experimental", "stable", "insiders", "preview", "legacy"]);

/** Whether the whole of `text` is a semver version or range, by node-semver's grammar. */
export function isSemverRange(text: string): boolean {
  return text.length <= 256 && SEMVER_RANGE.test(text);
}

/** A plain version, range or dist-tag: a registry spec with no protocol of its own. */
function plainRange(name: string, range: string): NpmRegistrySpec | null {
  const r = range.trim();
  if (SCHEME.test(r)) return null;
  const read = classifyNpmSpec(name, r);
  return read.kind === "registry" ? read : null;
}

/**
 * `npm:<target>@<range>`, `npm:<target>`, or Yarn berry's `npm:<range>` for the key's own name.
 * npm-package-arg refuses an alias whose subspec is not a plain registry spec (a URL, git, a path,
 * another protocol, an alias of an alias), an empty one, and a target that is a tarball file name:
 * what npm refuses to install is withheld.
 *
 * With no `@<range>`, `npm:<x>` means a package named x to npm and the key's own release x to Yarn.
 * The rule (review 2026-11-24; a prefix test read `npm:v8-compile-cache` and `npm:7zip-bin` as
 * ranges and sent the KEY):
 * - the whole of x is a semver range that no package could be named (`^1.2.0`, `>=1 <2`,
 *   `^1 || ^2`, `*`), or a full version (`2.1.3`, `1.2.3-rc.1`): the key's own release, as Yarn reads it;
 * - x is a package name and no range (`v8-compile-cache`, `7zip-bin`, `x.js`): an alias to x, as
 *   npm reads it;
 * - x is both (`1`, `1.x`, `2048`, `x`) or a common dist-tag (`latest`, `next`): which one is meant
 *   depends on the package manager, so it is withheld (nothing is sent);
 * - inside Yarn's `patch:` (`yarn` true) Yarn's reading is certain: a range or tag is the key's own.
 */
function aliasSpec(name: string, rest: string, yarn = false): NpmSpecClass {
  if (rest.trim() === "" || rest !== rest.trim() || /^npm:/i.test(rest)) return { kind: "url" };
  const at = rest.indexOf("@", rest.startsWith("@") ? 1 : 0);
  if (at < 0) {
    // `"next": "npm:next"`: npm and Yarn agree, it is that package from the registry.
    if (rest.toLowerCase() === name.toLowerCase() && PACKAGE_NAME.test(rest)) return registry(name, "*");
    const range = isSemverRange(rest);
    // A name a package could be published under now (no `~`, which only legacy names hold).
    const named = PACKAGE_NAME.test(rest) && !rest.includes("~") && !TARBALL_FILE.test(rest);
    if (yarn && (range || /^[a-z][a-z0-9._-]*$/i.test(rest))) return registry(name, rest);
    if (range && (!named || FULL_VERSION.test(rest))) return registry(name, rest);
    if (named && !range && !COMMON_TAGS.has(rest.toLowerCase())) return registry(rest, "*");
    // npm reads x as a package, Yarn as a tag or range of the key: which is meant is not known.
    return named ? { kind: "ambiguous" } : { kind: "url" };
  }
  const target = rest.slice(0, at);
  if (!PACKAGE_NAME.test(target) || TARBALL_FILE.test(target)) return { kind: "url" };
  const range = rest.slice(at + 1);
  const inner = plainRange(target, range);
  if (inner) return registry(target, inner.range);
  const what = classifyNpmSpec(target, range);
  return what.kind === "registry" ? { kind: "url" } : what;
}

/**
 * Yarn berry's `patch:<name>@<encoded inner spec>#<patch file>`: the inner spec says where the code
 * is from. Inside it Yarn's own rule applies: `npm:<version-or-range>` is that release of the SAME
 * package (`patch:lodash@npm%3A4.17.21#...` patches lodash 4.17.21), `npm:other@1` is other's. A
 * patch of a non-registry source is withheld, as that source is.
 */
function patchSpec(name: string, spec: string): NpmSpecClass {
  let inner: string;
  try {
    inner = decodeURIComponent(spec.slice("patch:".length).split("#")[0]);
  } catch {
    return { kind: "url" };
  }
  const at = inner.indexOf("@", inner.startsWith("@") ? 1 : 0);
  if (at <= 0) return { kind: "url" };
  const target = inner.slice(0, at);
  const range = inner.slice(at + 1);
  if (!PACKAGE_NAME.test(target)) return { kind: "url" };
  const read = /^npm:/i.test(range) ? aliasSpec(target, range.slice(4), true) : classifyNpmSpec(target, range);
  return read.kind === "registry" ? registry(read.name, read.range) : read;
}

/** pnpm's and Bun's `catalog:` / `catalog:<name>`: the catalog entry, classified by the same rules. */
function catalogSpec(name: string, spec: string, catalogs: NpmCatalogLookup | undefined): NpmSpecClass {
  const catalog = spec.slice("catalog:".length).trim() || "default";
  const entry = catalogs?.lookup(catalog, name);
  if (entry === undefined) return { kind: "catalog" };
  // A catalog entry that is itself `catalog:` is not resolved by pnpm either.
  if (/^\s*catalog:/i.test(entry)) return { kind: "catalog", catalogSpec: entry };
  const read = classifyNpmSpec(name, entry);
  return { ...read, catalogSpec: entry };
}

/**
 * An http(s) spec: the public registry's tarball of this very package is its release; a code host
 * or a `.git` URL is git; any other URL is an archive from that host, and the host may be private.
 */
function urlSpec(name: string, spec: string): NpmSpecClass {
  let url: URL;
  try {
    url = new URL(spec);
  } catch {
    return { kind: "url" };
  }
  const host = url.hostname.toLowerCase();
  if (CODE_HOST.test(host) || /\.git$/i.test(url.pathname)) return { kind: "git" };
  if (!isPublicNpmHost(host)) return { kind: "url" };
  let pathname: string;
  try {
    pathname = decodeURIComponent(url.pathname);
  } catch {
    return { kind: "url" };
  }
  // `/<name>/-/<basename>-<version>.tgz`, the basename being the name without its scope.
  const m = /^\/((?:@[^/]+\/)?[^/]+)\/-\/([^/]+)\.tgz$/i.exec(pathname);
  if (!m || m[1] !== name) return { kind: "url" };
  const base = name.startsWith("@") ? name.slice(name.indexOf("/") + 1) : name;
  if (!m[2].startsWith(`${base}-`)) return { kind: "url" };
  const version = m[2].slice(base.length + 1);
  return /^\d+\.\d+\.\d+/.test(version) ? registry(name, version) : { kind: "url" };
}

/** True when `spec` under `name` is a registry release of some package (the name a lookup may send is `.name`). */
export function isNpmRegistrySpec(name: string, spec: string): boolean {
  return classifyNpmSpec(name, spec).kind === "registry";
}
