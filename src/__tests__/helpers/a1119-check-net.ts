// SPDX-License-Identifier: Apache-2.0
/**
 * A stubbed network for the a1119-check tests: the four registries dependency_check reads and
 * OSV.dev, answered from small in-memory fixtures at the HTTP boundary. OSV's batch answer is worked
 * out from the same advisory records its list returns, so the two never disagree by accident.
 */

import { vi } from "vitest";
import type { OsvVulnerability } from "../../live/types.js";

export interface GoModule {
  /** `@v/list` body; default: the versions of `mods` and `info`, one per line. */
  list?: string;
  /** version -> publish time (ISO). */
  info?: Record<string, string>;
  /** version -> go.mod body; `*` answers any version without its own entry. */
  mods?: Record<string, string>;
}

export interface CrateFixture {
  /** Versions as the crates.io API lists them. */
  versions: Array<{ num: string; created_at: string; yanked?: boolean }>;
  /** Sparse index lines (objects), or the raw file body. */
  sparse: Array<Record<string, unknown>> | string;
}

export interface PypiFixture {
  /** version -> its files (upload time, yank flag, requires_python). */
  releases: Record<string, Array<{ upload_time_iso_8601: string; yanked?: boolean; requires_python?: string | null }>>;
  /** version -> requires_dist of that release (the per-release document). */
  requires?: Record<string, string[] | null>;
  /** The `info.version` the project document names as latest; default: the last key of `releases`. */
  latest?: string;
}

export interface Net {
  npm: Record<string, unknown>;
  go: Record<string, GoModule>;
  crates: Record<string, CrateFixture>;
  pypi: Record<string, PypiFixture>;
  /** Advisory records; each names its package, ecosystem and ranges. */
  osv: OsvVulnerability[];
  /** Hosts whose requests throw. */
  down: string[];
  /** URL substrings whose requests answer HTTP 503. */
  failing: string[];
  /** When set, `/v1/querybatch` answers this status. */
  batchStatus: number | null;
  /** Every request made, as `METHOD url` (and for OSV posts, the body after a space). */
  requests: string[];
}

export function emptyNet(): Net {
  return { npm: {}, go: {}, crates: {}, pypi: {}, osv: [], down: [], failing: [], batchStatus: null, requests: [] };
}

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
const notFound = () => new Response("not found", { status: 404 });

/** Dotted numeric order, `v` and a `+incompatible` suffix ignored: enough for fixture versions. */
export function cmpVersions(a: string, b: string): number {
  const parts = (v: string) => v.replace(/^v/, "").replace(/\+.*$/, "").split(/[.-]/).map((p) => (/^\d+$/.test(p) ? Number(p) : p));
  const pa = parts(a);
  const pb = parts(b);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const x = pa[i] ?? 0;
    const y = pb[i] ?? 0;
    if (x === y) continue;
    if (typeof x === "number" && typeof y === "number") return x - y;
    return String(x) < String(y) ? -1 : 1;
  }
  return 0;
}

const pep503 = (name: string) => name.toLowerCase().replace(/[-_.]+/g, "-");
const sameName = (eco: string, a: string, b: string) => (eco === "PyPI" ? pep503(a) === pep503(b) : eco === "crates.io" ? a.toLowerCase().replace(/_/g, "-") === b.toLowerCase().replace(/_/g, "-") : a === b);

/** Whether a fixture advisory affects `version` of the package (SEMVER / ECOSYSTEM ranges, introduced..fixed or ..last_affected). */
export function affects(v: OsvVulnerability, ecosystem: string, name: string, version: string): boolean {
  for (const a of v.affected ?? []) {
    if (!a.package || a.package.ecosystem !== ecosystem || !sameName(ecosystem, a.package.name, name)) continue;
    if ((a.versions ?? []).includes(version)) return true;
    for (const range of a.ranges ?? []) {
      let introduced: string | null = null;
      for (const e of range.events ?? []) {
        if (e.introduced !== undefined) introduced = e.introduced;
        else if (e.fixed !== undefined && introduced !== null) {
          if ((introduced === "0" || cmpVersions(version, introduced) >= 0) && cmpVersions(version, e.fixed) < 0) return true;
          introduced = null;
        } else if (e.last_affected !== undefined && introduced !== null) {
          if ((introduced === "0" || cmpVersions(version, introduced) >= 0) && cmpVersions(version, e.last_affected) <= 0) return true;
          introduced = null;
        }
      }
      if (introduced !== null && (introduced === "0" || cmpVersions(version, introduced) >= 0)) return true;
    }
  }
  return false;
}

/** One advisory record: affected from `introduced` (default "0") up to `fixed` (never fixed when null). */
export function advisory(
  id: string,
  ecosystem: string,
  name: string,
  fixed: string | null,
  opts: { severity?: string; introduced?: string; summary?: string; aliases?: string[]; extra?: Partial<OsvVulnerability> } = {},
): OsvVulnerability {
  return {
    id,
    aliases: opts.aliases ?? [],
    summary: opts.summary ?? `${name} advisory ${id}`,
    database_specific: { severity: opts.severity ?? "MODERATE" },
    affected: [
      {
        package: { name, ecosystem },
        ranges: [{ type: ecosystem === "PyPI" ? "ECOSYSTEM" : "SEMVER", events: [{ introduced: opts.introduced ?? "0" }, ...(fixed ? [{ fixed }] : [])] }],
      },
    ],
    ...opts.extra,
  } as OsvVulnerability;
}

/** An npm packument: version -> publish time (ISO) and, optionally, its dependencies. `latest` is the last version given. */
export function npmDoc(name: string, versions: Record<string, { at: string; dependencies?: Record<string, string> }>): unknown {
  const list = Object.keys(versions);
  return {
    name,
    "dist-tags": { latest: list[list.length - 1] },
    time: { created: versions[list[0]].at, ...Object.fromEntries(list.map((v) => [v, versions[v].at])) },
    versions: Object.fromEntries(list.map((v) => [v, { name, version: v, ...(versions[v].dependencies ? { dependencies: versions[v].dependencies } : {}) }])),
  };
}

function goEscape(path: string): string {
  return path.replace(/[A-Z]/g, (c) => `!${c.toLowerCase()}`);
}

function route(net: Net, url: string, init?: RequestInit): Response {
  const u = new URL(url);
  if (net.down.includes(u.hostname)) throw new TypeError("fetch failed (simulated outage)");
  if (net.failing.some((part) => url.includes(part))) return new Response("unavailable", { status: 503 });

  if (u.hostname === "registry.npmjs.org") {
    const doc = net.npm[decodeURIComponent(u.pathname.slice(1))];
    return doc ? json(doc) : json({ error: "Not found" }, 404);
  }

  if (u.hostname === "proxy.golang.org") {
    const m = /^\/(.+)\/@(v\/list|latest|v\/(.+)\.(info|mod))$/.exec(u.pathname);
    const mod = m ? Object.entries(net.go).find(([path]) => goEscape(path) === m[1])?.[1] : undefined;
    if (!m || !mod) return notFound();
    const versions = [...new Set([...Object.keys(mod.info ?? {}), ...Object.keys(mod.mods ?? {}).filter((v) => v !== "*")])];
    if (m[2] === "v/list") return new Response(mod.list ?? `${versions.join("\n")}\n`);
    if (m[2] === "latest") return notFound();
    const version = m[3];
    if (m[4] === "info") return mod.info?.[version] ? json({ Version: version, Time: mod.info[version] }) : notFound();
    const body = mod.mods?.[version] ?? mod.mods?.["*"];
    return body !== undefined ? new Response(body) : notFound();
  }

  if (u.hostname === "crates.io") {
    const m = /^\/api\/v1\/crates\/([^/]+)(\/versions)?$/.exec(u.pathname);
    const crate = m ? Object.entries(net.crates).find(([name]) => sameName("crates.io", name, decodeURIComponent(m[1])))?.[1] : undefined;
    if (!m || !crate) return json({ errors: [{ detail: "Not Found" }] }, 404);
    if (m[2]) return json({ versions: crate.versions, meta: { next_page: null } });
    const name = Object.keys(net.crates).find((n) => sameName("crates.io", n, decodeURIComponent(m[1])))!;
    return json({ crate: { name, created_at: "2015-01-01T00:00:00Z", num_versions: crate.versions.length }, versions: crate.versions });
  }
  if (u.hostname === "index.crates.io") {
    const crate = net.crates[u.pathname.split("/").pop()!];
    if (!crate) return notFound();
    return new Response(typeof crate.sparse === "string" ? crate.sparse : crate.sparse.map((l) => JSON.stringify(l)).join("\n"));
  }

  if (u.hostname === "pypi.org") {
    const whole = /^\/pypi\/([^/]+)\/json$/.exec(u.pathname);
    const one = /^\/pypi\/([^/]+)\/([^/]+)\/json$/.exec(u.pathname);
    const find = (name: string) => Object.entries(net.pypi).find(([n]) => pep503(n) === pep503(decodeURIComponent(name)));
    if (whole) {
      const hit = find(whole[1]);
      if (!hit) return json({ message: "Not Found" }, 404);
      const [name, doc] = hit;
      const latest = doc.latest ?? Object.keys(doc.releases).pop()!;
      return json({ info: { name, version: latest, requires_dist: doc.requires?.[latest] ?? null }, releases: doc.releases });
    }
    if (one) {
      const hit = find(one[1]);
      const version = decodeURIComponent(one[2]);
      if (!hit || !hit[1].releases[version]) return json({ message: "Not Found" }, 404);
      const files = hit[1].releases[version];
      return json({ info: { name: hit[0], version, requires_dist: hit[1].requires?.[version] ?? null, requires_python: files[0]?.requires_python ?? null }, urls: files });
    }
    return notFound();
  }

  if (u.hostname === "api.osv.dev" && u.pathname === "/v1/query") {
    const q = JSON.parse(String(init?.body)) as { package: { name: string; ecosystem: string }; version?: string };
    const all = net.osv.filter((v) => (v.affected ?? []).some((a) => a.package?.ecosystem === q.package.ecosystem && sameName(q.package.ecosystem, a.package.name, q.package.name)));
    return json({ vulns: q.version ? all.filter((v) => affects(v, q.package.ecosystem, q.package.name, q.version!)) : all });
  }
  if (u.hostname === "api.osv.dev" && u.pathname === "/v1/querybatch") {
    if (net.batchStatus !== null) return new Response("unavailable", { status: net.batchStatus });
    const { queries } = JSON.parse(String(init?.body)) as { queries: Array<{ package: { name: string; ecosystem: string }; version: string }> };
    return json({
      results: queries.map((q) => ({
        vulns: net.osv.filter((v) => affects(v, q.package.ecosystem, q.package.name, q.version)).map((v) => ({ id: v.id, modified: "2026-01-01T00:00:00Z" })),
      })),
    });
  }
  if (u.hostname === "api.osv.dev" && u.pathname.startsWith("/v1/vulns/")) {
    const id = decodeURIComponent(u.pathname.slice("/v1/vulns/".length));
    const hit = net.osv.find((v) => v.id === id);
    return hit ? json(hit) : json({}, 404);
  }
  throw new Error(`unrouted request in test: ${url}`);
}

/** Stub `fetch` with `net`; undo with `vi.unstubAllGlobals()`. */
export function stubNet(net: Net): void {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: string | URL, init?: RequestInit) => {
      const url = String(input);
      net.requests.push(`${init?.method ?? "GET"} ${url}${url.includes("api.osv.dev") && init?.body ? ` ${String(init.body)}` : ""}`);
      return route(net, url, init);
    }),
  );
}

/** Every `name@version` an OSV batch query asked about, as `ecosystem:name@version`. */
export function batchAsked(net: Net): string[] {
  return net.requests
    .filter((r) => r.includes("/v1/querybatch "))
    .flatMap((r) => (JSON.parse(r.slice(r.indexOf("{"))) as { queries: Array<{ package: { name: string; ecosystem: string }; version: string }> }).queries)
    .map((q) => `${q.package.ecosystem}:${q.package.name}@${q.version}`);
}

/** FOURDA_OFFLINE cleared for a test file's run; returns the restore function. */
export function onlineForTests(): () => void {
  const prior = process.env.FOURDA_OFFLINE;
  delete process.env.FOURDA_OFFLINE;
  return () => {
    if (prior === undefined) delete process.env.FOURDA_OFFLINE;
    else process.env.FOURDA_OFFLINE = prior;
  };
}
