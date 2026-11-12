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
 * Every LiveIntelligence registers what it knows is private (its rules and its lockfiles'
 * private names); the union of the instances still alive is applied. Held weakly, so a
 * per-call instance (a `project_path` scan) is forgotten once collected.
 */

/** What one live layer says is private: why a name is, or null. */
export interface PrivateNameSource {
  privateReason(ecosystem: string, name: string): string | null;
}

const sources = new Set<WeakRef<PrivateNameSource>>();

export function registerPrivateNames(source: PrivateNameSource): void {
  sources.add(new WeakRef(source));
}

/** Why `name` (in `ecosystem`, or any ecosystem when null) is private to some live layer, or null. */
function privateWhy(ecosystem: string | null, name: string): string | null {
  for (const ref of sources) {
    const source = ref.deref();
    if (!source) {
      sources.delete(ref);
      continue;
    }
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
  if (sources.size === 0) return;
  for (const [eco, name] of namesInRequest(url, init?.body)) {
    const why = privateWhy(eco, name);
    if (why) {
      throw new PrivateRequestRefused(`not sent: ${name} is a private package (${why})`);
    }
  }
}
