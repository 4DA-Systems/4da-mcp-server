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
 * Two deliberate additions. A tarball URL on the public npm registry (or a public mirror of it)
 * that names this very package is that registry release, so it is checked; a tarball anywhere else
 * is withheld. pnpm's `catalog:` names a registry range kept in pnpm-workspace.yaml, and Yarn
 * berry's `npm:<range>` and `patch:` wrap a registry release: those stay registry releases.
 */

import { isPublicNpmHost } from "./private-hosts.js";

/** A registry release: `name` is the package a lookup may name (an alias's target, never the local key). */
export interface NpmRegistrySpec {
  kind: "registry";
  name: string;
  range: string;
}

/** Not a registry release: git, a remote archive, a local archive, or local source code. */
export interface NpmOtherSpec {
  kind: "git" | "url" | "file" | "local";
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

/** What `spec`, declared under the key `name` in a package.json, installs. */
export function classifyNpmSpec(name: string, rawSpec: string): NpmSpecClass {
  const spec = rawSpec.trim();
  // npm reads "" as `*` (the latest release): a registry spec.
  if (spec === "") return registry(name, "*");
  if (/^npm:/i.test(spec)) return aliasSpec(name, spec.slice(4).trim());
  if (/^catalog:/i.test(spec)) return registry(name, spec);
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

/** `npm:<target>@<range>`, `npm:<target>`, or Yarn berry's `npm:<range>` for the key's own name. */
function aliasSpec(name: string, rest: string): NpmSpecClass {
  const at = rest.indexOf("@", rest.startsWith("@") ? 1 : 0);
  const target = at > 0 ? rest.slice(0, at) : rest;
  if (PACKAGE_NAME.test(target)) {
    const range = at > 0 ? rest.slice(at + 1) : "*";
    // npm-package-arg refuses an alias whose subspec is not a registry spec (and an alias of an alias).
    if (/^npm:/i.test(range.trim())) return { kind: "url" };
    const inner = classifyNpmSpec(target, range);
    return inner.kind === "registry" ? registry(target, inner.range) : inner;
  }
  const own = classifyNpmSpec(name, rest);
  return own.kind === "registry" && !/^(?:catalog|patch):/i.test(rest) ? own : { kind: "url" };
}

/** Yarn berry's `patch:<name>@<encoded inner spec>#<patch file>`: the inner spec says where the code is from. */
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
  const read = /^npm:/i.test(range) ? aliasSpec(target, range.slice(4)) : classifyNpmSpec(target, range);
  return read.kind === "registry" ? registry(read.name === target ? target : read.name, read.range) : read;
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
