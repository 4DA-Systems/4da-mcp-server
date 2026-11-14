// SPDX-License-Identifier: Apache-2.0
/**
 * The last line of defence for private package names (private-packages.ts): every OSV.dev,
 * registry and search request goes through fetchWithTimeout (http-utils.ts), which asks this
 * module first and refuses a request whose URL or JSON body names a private package. A refused
 * request fails like an unreachable one, so whatever asked reports "not checked", never clean.
 *
 * Defence in depth (review of #64): the live layer leaves private names out of its dependency
 * set, but upgrade_planner's fix-path lookups read parent and lever names straight from the
 * lockfile (`@acme/api` reached registry.npmjs.org). The sources now refuse them too
 * (LiveIntelligence.getFixPathSources), and this guard catches anything that still slips through.
 * `private-guard.test.ts` fails on any network call in src/ that bypasses it.
 *
 * Which rules apply. A request made FOR a project (a live layer's scan, advisory query, registry
 * read or fix-path lookup runs inside that layer's context, `withPrivateContext`) is judged by that
 * project's rules alone: another project's private name is no reason to refuse it. A request with
 * no project context is judged by the union of every registered project, which can only refuse
 * more. (Union-only, a name private in one test's fixture refused another test's public lookup in
 * the same worker: CI run 43253624606.)
 *
 * Registration. A live layer resolved for a project is held strongly under its project root,
 * replacing the previous one for that root, so the registry never depends on the collector (on
 * Node 24 a weakly held source vanished before the request it should have refused, CI run
 * 43241199693). An entry goes when its layer is disposed or its root no longer exists. A layer
 * with no project yet (user-level rules only) is held weakly.
 */

import * as fs from "node:fs";
import { AsyncLocalStorage } from "node:async_hooks";

/** What one live layer says is private: why a name is, or null. */
export interface PrivateNameSource {
  privateReason(ecosystem: string, name: string): string | null;
  /** The project the rules are for; an entry whose project directory is gone is dropped. */
  getProjectRoot?(): string | null;
}

/** True when the source's project directory no longer exists. */
function rootGone(source: PrivateNameSource, root: string | null): boolean {
  const dir = root ?? source.getProjectRoot?.() ?? null;
  return dir !== null && !fs.existsSync(dir);
}

const sources = new Set<WeakRef<PrivateNameSource>>();
const byKey = new Map<string, { source: PrivateNameSource; root: string | null }>();
const context = new AsyncLocalStorage<PrivateNameSource>();

/**
 * Register a source: strongly under `key` (it replaces that key's previous source; `root`, when
 * given, is a directory whose disappearance drops the entry), else weakly.
 */
export function registerPrivateNames(source: PrivateNameSource, key?: string, root?: string): void {
  if (key === undefined) {
    sources.add(new WeakRef(source));
    return;
  }
  byKey.set(key, { source, root: root ?? null });
}

/** Forget a source everywhere it is registered (a disposed live layer). */
export function unregisterPrivateNames(source: PrivateNameSource): void {
  for (const [key, entry] of byKey) if (entry.source === source) byKey.delete(key);
  for (const ref of sources) if (ref.deref() === source) sources.delete(ref);
}

/** Run `fn`, and every request it makes (awaits included), as made for `source`'s project. */
export function withPrivateContext<T>(source: PrivateNameSource, fn: () => T): T {
  return context.run(source, fn);
}

/** How many sources are registered (tests assert nothing leaks between them). */
export function privateGuardSize(): number {
  return byKey.size + sources.size;
}

/** Forget every source (the test suite, between tests). */
export function resetPrivateGuard(): void {
  byKey.clear();
  sources.clear();
}

function* liveSources(): Generator<PrivateNameSource> {
  for (const [key, entry] of byKey) {
    if (rootGone(entry.source, entry.root)) {
      byKey.delete(key);
      continue;
    }
    yield entry.source;
  }
  for (const ref of sources) {
    const source = ref.deref();
    if (source && !rootGone(source, null)) yield source;
    else sources.delete(ref);
  }
}

/** Zero-width and other invisible characters a name can carry without looking different. */
const INVISIBLE = /[­͏؜ᅟᅠ឴឵᠋-᠏​-‏‪-‮⁠-⁯ㅤ︀-️﻿ﾠ]|\uDB40[\uDC00-\uDDEF]/g;

/**
 * Every form of `name` a registry or OSV.dev could read as a package: the name as written, then
 * the same name without what an agent may wrap it in. A private name written `npm:acme-x`,
 * `acme-x@1.0.0`, `%40acme%2Fui`, `omega[extra]`, `omega==3.2.0`, with a trailing zero-width
 * space, as a registry URL, or as a Go path with a capitalised host reached the network: only
 * the exact spelling was recognised (blind audit 2026-11-14, F2). Only more refusals can follow.
 */
/**
 * Free text (a briefing task) as a reader sees it: percent-escapes decoded and invisible characters
 * removed, before any package name is read from it. "install %40acme%2Fvault-core version 2.0.0"
 * was split at the `%` and `2fvault-core` sent to OSV.dev and npm, naming the private
 * `@acme/vault-core` (black-box round 3, 2026-11-14). A malformed escape is left as written.
 */
export function readableText(text: string): string {
  const decoded = text.replace(/(?:%[0-9a-f]{2})+/gi, (run) => {
    try {
      return decodeURIComponent(run);
    } catch {
      // Not UTF-8 as a whole: each escape that is a single ASCII byte on its own.
      return run.replace(/%([0-7][0-9a-f])/gi, (_, hex: string) => String.fromCharCode(parseInt(hex, 16)));
    }
  });
  return decoded.replace(INVISIBLE, "");
}

export function nameForms(name: string): string[] {
  const out = new Set<string>();
  const add = (s: string) => {
    const t = s.trim();
    if (t) out.add(t);
  };
  const queue = [name];
  for (let i = 0; i < queue.length && i < 64; i++) {
    const n = queue[i];
    if (out.has(n.trim()) && i > 0) continue;
    add(n);
    const next = (s: string) => {
      const t = s.trim();
      if (t && t !== n.trim() && !queue.includes(t)) queue.push(t);
    };
    next(n.replace(INVISIBLE, ""));
    try {
      next(decodeURIComponent(n));
    } catch {
      // not percent-encoded
    }
    next(n.replace(/^(?:npm|pypi|cargo|crate|go|gem|composer):/i, ""));
    // name@version, @scope/name@version (the scope's own @ is not a version).
    next(n.replace(/(?<=.)@[^@/]*$/, ""));
    // PyPI extras and version specifiers: name[extra], name==1.0, name>=1,<2, name ~= 1.0, name; marker
    next(n.replace(/\s*(?:\[[^\]]*\]|(?:===?|~=|>=|<=|!=|>|<|;).*)$/, ""));
    // A URL to a registry: the package is the path after the host (and a scoped npm name is two segments).
    const url = /^[a-z][a-z0-9+.-]*:\/\/[^/]+\/(.+?)\/?$/i.exec(n);
    if (url) {
      const segs = url[1].split("/").filter(Boolean);
      next(url[1]);
      if (segs.length >= 2 && segs[segs.length - 2].startsWith("@")) next(segs.slice(-2).join("/"));
      if (segs.length >= 1) next(segs[segs.length - 1]);
    }
    // A Go module's host is case-insensitive; GOPRIVATE patterns are written in lower case.
    const slash = n.indexOf("/");
    if (slash > 0 && /\./.test(n.slice(0, slash))) next(n.slice(0, slash).toLowerCase() + n.slice(slash));
    next(n.toLowerCase());
  }
  return [...out];
}

/** Why `name` (in `ecosystem`, or any ecosystem when null) is private, or null: the request's project, else any. */
function privateWhy(ecosystem: string | null, name: string): string | null {
  // Sources read every form of the name themselves (LiveIntelligence.privateReason, nameForms).
  const own = context.getStore();
  for (const source of own ? [own] : liveSources()) {
    for (const eco of ecosystem ? [ecosystem] : ALL_ECOSYSTEMS) {
      const why = source.privateReason(eco, name);
      if (why) return why;
    }
  }
  return null;
}

/** The refusal thrown for a request that names a private package. */
export class PrivateRequestRefused extends Error {
  readonly code = "FOURDA_PRIVATE_REFUSED";
}

/** Go module proxy paths escape capitals as `!x` (golang.org/x/mod/module EscapePath). */
const goUnescape = (s: string) => s.replace(/!([a-z])/g, (_, c: string) => c.toUpperCase());

const ALL_ECOSYSTEMS = ["npm", "crates.io", "PyPI", "Go", "RubyGems", "Packagist"];
const OSV_ECOSYSTEMS: Record<string, string> = { npm: "npm", "crates.io": "crates.io", pypi: "PyPI", go: "Go", rubygems: "RubyGems", packagist: "Packagist" };
/** purl types (`pkg:<type>/...`) as OSV ecosystems. */
const PURL_TYPES: Record<string, string> = { npm: "npm", cargo: "crates.io", pypi: "PyPI", golang: "Go", gem: "RubyGems", composer: "Packagist" };

/** The (ecosystem, name) a package URL names: `pkg:npm/%40acme/api@1.0.0`, `pkg:golang/github.com/acme/x@v1`. */
export function purlName(purl: string): [string | null, string] | null {
  const m = /^pkg:([a-z0-9.+-]+)\/([^?#]+)/i.exec(purl.trim());
  if (!m) return null;
  // The version follows the last segment's `@` (`pkg:npm/@acme/api@1.0.0`: the scope's `@` is not one).
  const parts = m[2].split("/");
  parts[parts.length - 1] = parts[parts.length - 1].replace(/(?<=.)@.*$/, "");
  let name: string;
  try {
    name = parts.map((s) => decodeURIComponent(s)).join("/");
  } catch {
    name = parts.join("/");
  }
  return [PURL_TYPES[m[1].toLowerCase()] ?? null, name];
}

/** A request body as text, whatever form fetch was handed it in. */
function bodyText(body: unknown): string | null {
  if (typeof body === "string") return body;
  if (body instanceof Uint8Array) return new TextDecoder().decode(body);
  if (body instanceof ArrayBuffer) return new TextDecoder().decode(new Uint8Array(body));
  if (ArrayBuffer.isView(body)) return new TextDecoder().decode(new Uint8Array(body.buffer, body.byteOffset, body.byteLength));
  if (body instanceof URLSearchParams) return body.toString();
  return null;
}

/** The (ecosystem, name) pairs a request names, read per host. Ecosystem null: any. */
export function namesInRequest(url: string, body: unknown): Array<[string | null, string]> {
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    return [];
  }
  const segments = u.pathname.split("/").filter(Boolean).map((s) => {
    try {
      return decodeURIComponent(s);
    } catch {
      return s;
    }
  });
  const out: Array<[string | null, string]> = [];
  // `registry.npmjs.org.` is the same host.
  const host = u.hostname.toLowerCase().replace(/\.+$/, "");
  if (host === "registry.npmjs.org" || host === "registry.npmjs.com" || host === "registry.yarnpkg.com") {
    // `/@scope%2fname`, `/@scope/name/1.0.0`, `/name/-/name-1.0.0.tgz`
    const first = segments[0] ?? "";
    if (first.startsWith("@")) out.push(["npm", first.includes("/") ? first : `${first}/${segments[1] ?? ""}`]);
    else if (first) out.push(["npm", first]);
  } else if (host === "api.npmjs.org") {
    // /downloads/point/<period>/<a,b,@s/c> (a scoped name spans two segments)
    const rest = segments.slice(3).join("/");
    for (const n of rest.split(",")) if (n) out.push(["npm", n]);
  } else if (host === "crates.io" || host === "static.crates.io") {
    const at = segments.indexOf("crates");
    if (at >= 0 && segments[at + 1]) out.push(["crates.io", segments[at + 1]]);
  } else if (host === "index.crates.io") {
    const last = segments[segments.length - 1];
    if (last && last !== "config.json") out.push(["crates.io", last]);
  } else if (host === "pypi.org" || host === "pypi.python.org") {
    const at = segments.indexOf("pypi");
    if (at >= 0 && segments[at + 1]) out.push(["PyPI", segments[at + 1]]);
    const simple = segments.indexOf("simple");
    if (simple >= 0 && segments[simple + 1]) out.push(["PyPI", segments[simple + 1]]);
  } else if (host === "files.pythonhosted.org") {
    // .../<name>-<version>.tar.gz: the distribution name before the version.
    const file = segments[segments.length - 1] ?? "";
    const m = /^(.+?)-\d/.exec(file);
    if (m) out.push(["PyPI", m[1]]);
  } else if (host === "proxy.golang.org" || host === "sum.golang.org") {
    const path = goUnescape(segments.join("/"));
    const module = path.replace(/\/@(v|latest)(\/.*)?$/, "").replace(/^lookup\//, "");
    if (module) out.push(["Go", module.replace(/@.*$/, "")]);
  } else if (host === "rubygems.org" || host === "index.rubygems.org") {
    // /api/v1/gems/<name>.json, /api/v1/versions/<name>.json, /gems/<name>-<v>.gem, /info/<name>
    const at = segments.findIndex((s) => s === "gems" || s === "versions" || s === "info");
    const raw = at >= 0 ? segments[at + 1] : undefined;
    if (raw) out.push(["RubyGems", raw.replace(/\.json$/, "").replace(/-\d[^/]*\.gem$/, "")]);
  } else if (host === "repo.packagist.org" || host === "packagist.org") {
    // /p2/<vendor>/<name>.json, /packages/<vendor>/<name>.json
    const at = segments.findIndex((s) => s === "p2" || s === "p" || s === "packages");
    if (at >= 0 && segments[at + 2]) out.push(["Packagist", `${segments[at + 1]}/${segments[at + 2].replace(/(~dev)?\.json$/, "")}`]);
  } else if (host === "hn.algolia.com") {
    for (const term of (u.searchParams.get("query") ?? "").split(/[\s"]+/)) if (term) out.push([null, term]);
  }
  // OSV.dev (and any JSON body): package names in `package.name` / `queries[].package.name`, or a
  // `purl`; a body in bytes or with leading whitespace is read the same (review of #64).
  const text = bodyText(body)?.trim() ?? null;
  if (text && (text.startsWith("{") || text.startsWith("["))) {
    try {
      type Pkg = { name?: unknown; ecosystem?: unknown; purl?: unknown };
      const parsed = JSON.parse(text) as { package?: Pkg; queries?: Array<{ package?: Pkg }> } | Array<{ package?: Pkg }>;
      const list = Array.isArray(parsed) ? parsed.map((q) => q?.package) : [parsed.package, ...(parsed.queries ?? []).map((q) => q?.package)];
      for (const p of list) {
        if (!p) continue;
        if (typeof p.name === "string") {
          const eco = typeof p.ecosystem === "string" ? (OSV_ECOSYSTEMS[p.ecosystem.toLowerCase()] ?? null) : null;
          out.push([eco, p.name]);
        }
        if (typeof p.purl === "string") {
          const named = purlName(p.purl);
          if (named) out.push(named);
        }
      }
    } catch {
      // not JSON: nothing named
    }
  }
  return out;
}

/** Throws PrivateRequestRefused when the request names a private package; returns otherwise. */
export function refusePrivateRequest(url: string, init?: { body?: unknown }): void {
  if (sources.size === 0 && byKey.size === 0 && !context.getStore()) return;
  for (const [eco, name] of namesInRequest(url, init?.body)) {
    const why = privateWhy(eco, name);
    if (why) {
      throw new PrivateRequestRefused(`not sent: ${name} is a private package (${why})`);
    }
  }
}
