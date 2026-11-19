// SPDX-License-Identifier: Apache-2.0
/**
 * crates.io release reader for dependency_check.
 *
 * Three name-only reads:
 * - `crates.io/api/v1/crates/<name>`, for a whole version list (a constraint, "latest"): every
 *   version in one request, with its publish time, publisher, `trustpub_data` and yanked flag,
 *   and the crate's creation date; else `crates.io/api/v1/crates/<name>/versions` (paged, newest
 *   semver first, same fields), which stops at the versions asked about.
 * - the sparse index (`index.crates.io`, the CDN file cargo itself reads):
 *   each version's dependency list, which the versions endpoint lacks, and
 *   with it what each version requires (getRequirements).
 * - `crates.io/api/v1/crates/<name>`: when a newly introduced dependency
 *   was first published.
 *
 * crates.io asks API clients for a descriptive User-Agent and at most one
 * request per second; every API request here waits for its slot. Paging
 * stops as soon as the versions the caller asked about (and the release just
 * below them) have been seen, so an exact check costs one or two pages, and a
 * whole list one request, not one per hundred versions.
 *
 * Privacy: requests carry the crate NAME only, never the installed version.
 */

import type { LiveCache } from "./cache.js";
import type { RateLimiter } from "./rate-limiter.js";
import { fetchWithTimeout } from "./http-utils.js";
import { compareVersionPrecedence, parseSemverPrecedence } from "./semver-precedence.js";
import { cargoReqAdmits } from "./range-satisfies.js";
import { UNREADABLE_NAME } from "../untrusted-text.js";
import type {
  PackageReleaseIndex,
  RegistryLookup,
  ReleaseMetadataSource,
  ReleaseRecord,
  ReleaseRequirement,
  ReleaseRequirements,
} from "./release-metadata.js";

const CRATES_API = "https://crates.io/api/v1/crates";
export const CRATES_USER_AGENT = "4DA-MCP-Server/1.0 (https://4da.ai)";
const TIMEOUT_MS = 15_000;
const MAX_PAGES = 25;
const VERSIONS_TTL = 3600;
const CREATED_TTL = 30 * 86_400; // a crate's creation date never changes

interface CratesVersion {
  num: string;
  created_at?: string;
  yanked?: boolean;
  published_by?: { login?: string } | null;
  trustpub_data?: { provider?: string; repository?: string } | null;
}

interface CratesVersionsPage {
  versions?: CratesVersion[];
  meta?: { next_page?: string | null };
}

interface SparseDep {
  /** The name the crate uses for the dependency (its key in Cargo.toml). */
  name: string;
  req?: string;
  kind?: string | null;
  /** The dependency's real crate name, when it is renamed. */
  package?: string;
  optional?: boolean;
  /** Another registry's index URL; absent or null for crates.io. */
  registry?: string | null;
}

interface SparseLine {
  /** The crate's published spelling (the index files it under that name only). */
  name?: string;
  vers: string;
  deps?: SparseDep[];
  features?: Record<string, string[]>;
  /** Features written in the newer syntax (`dep:x`, `x?/y`), merged with `features`. */
  features2?: Record<string, string[]>;
}

/** A crate name as crates.io accepts one: up to 64 ASCII letters, digits, `-` and `_`. */
const CRATE_NAME = /^[A-Za-z0-9_-]{1,64}$/;

export function isCrateName(name: unknown): name is string {
  return typeof name === "string" && CRATE_NAME.test(name);
}

/** A dependency name as a release declares it, or the placeholder when it is not a crate name. */
export function readableCrateName(name: unknown): string {
  return isCrateName(name) ? name : UNREADABLE_NAME;
}

/** A Cargo requirement fit to print: a short run of version numbers, operators, commas and spaces that Cargo's own grammar reads. */
function isReadableCargoReq(req: unknown): req is string {
  return typeof req === "string" && req.length > 0 && req.length <= 200 && /^[0-9A-Za-z.,*^~<>=+ -]+$/.test(req) && cargoReqAdmits(req, "1.0.0") !== null;
}

const CRATES_IO_INDEXES = new Set(["https://github.com/rust-lang/crates.io-index", "sparse+https://index.crates.io/", "https://index.crates.io/"]);

/**
 * The optional dependencies a crate's `default` feature turns on, by the name the crate uses for
 * them: `dep:x`, `x/feature` (not `x?/feature`), or the feature an optional dependency defines by
 * its own name, followed through the features `default` enables.
 */
function defaultEnabledDependencies(line: SparseLine): Set<string> {
  const features = new Map<string, string[]>();
  for (const table of [line.features, line.features2]) {
    if (!table || typeof table !== "object") continue;
    for (const [name, values] of Object.entries(table)) {
      if (Array.isArray(values)) features.set(name, [...(features.get(name) ?? []), ...values.filter((v): v is string => typeof v === "string")]);
    }
  }
  const enabled = new Set<string>();
  const seen = new Set<string>();
  const stack = ["default"];
  while (stack.length > 0 && seen.size < 1_000) {
    const feature = stack.pop()!;
    if (seen.has(feature)) continue;
    seen.add(feature);
    // An optional dependency defines a feature of its own name unless the crate uses `dep:` for it.
    if (!features.has(feature)) enabled.add(feature);
    for (const value of features.get(feature) ?? []) {
      if (value.startsWith("dep:")) enabled.add(value.slice(4));
      else if (value.includes("/")) {
        const dep = value.slice(0, value.indexOf("/"));
        if (!dep.endsWith("?")) enabled.add(dep);
      } else stack.push(value);
    }
  }
  return enabled;
}

/**
 * What one index line says the release requires at build time: normal and build dependencies from
 * crates.io, an optional one only when the `default` feature turns it on. Dev-dependencies are not
 * part of what a dependent builds. One entry per crate and requirement.
 */
function requirementsOf(line: SparseLine): ReleaseRequirements {
  const byDefault = defaultEnabledDependencies(line);
  const out = new Map<string, ReleaseRequirement>();
  let unreadable = 0;
  for (const d of Array.isArray(line.deps) ? line.deps : []) {
    if (!d || typeof d !== "object" || d.kind === "dev") continue;
    if (d.optional === true && !byDefault.has(String(d.name))) continue;
    const crate = d.package ?? d.name;
    const foreign = typeof d.registry === "string" && d.registry !== "" && !CRATES_IO_INDEXES.has(d.registry);
    if (foreign || !isCrateName(crate) || !isReadableCargoReq(d.req)) {
      unreadable++;
      continue;
    }
    const spec = d.req.trim();
    out.set(`${crate}\0${spec}`, { name: crate, spec });
  }
  return { requirements: [...out.values()], unreadable };
}

interface SparseRead {
  deps: Record<string, string[]>;
  name: string | null;
  /** Per version: what it requires (requirementsOf). */
  reqs: Record<string, ReleaseRequirements>;
}

class HttpStatusError extends Error {
  constructor(readonly status: number) {
    super(`HTTP ${status}`);
  }
}

export class CratesVersionsReader implements ReleaseMetadataSource {
  /** Earliest time the next crates.io API request may start. Reserved synchronously so concurrent callers queue. */
  private nextSlotMs = 0;

  constructor(
    private cache: LiveCache,
    private rateLimiter: RateLimiter,
    /** crates.io's crawler policy: one request per second. Tests pass 0. */
    private minIntervalMs = 1000,
  ) {}

  async getReleases(name: string, wanted: string[]): Promise<RegistryLookup<PackageReleaseIndex>> {
    // v2: the index carries the crate's published spelling in `name` (pre-publish round 10, W2).
    const key = `crates-versions:v2:${name}`;
    const cached = this.cache.get<{ index: PackageReleaseIndex; complete: boolean }>(key);
    if (cached && (cached.complete || pagesSatisfy(Object.keys(cached.index.releases), wanted))) {
      return { status: "ok", data: cached.index };
    }

    const releases: Record<string, ReleaseRecord> = {};
    let query: string | null = "?per_page=100&sort=semver";
    let pages = 0;
    /** The crate's published spelling, once a read has named it. */
    let canonical: string | null = null;
    let wholeRead = false;
    // The whole list (a constraint, "latest"): `/crates/<name>` carries every version in ONE
    // request. Paging it 100 at a time at crates.io's one request a second took clap 5 s
    // (5 pages) and a 25-item check 16 s of crates.io alone (audit 2026-11-11 W1 M2-5).
    if (wanted.length === 0) {
      const whole = await this.wholeList(name);
      if (whole) {
        for (const v of whole.versions) releases[v.num] = toRecord(v);
        canonical = whole.name;
        wholeRead = true;
        query = null;
      }
    }
    try {
      while (query && pages < MAX_PAGES) {
        const page: CratesVersionsPage = await this.apiGet<CratesVersionsPage>(
          `${CRATES_API}/${encodeURIComponent(name)}/versions${query}`,
        );
        pages++;
        for (const v of page.versions ?? []) releases[v.num] = toRecord(v);
        query = page.meta?.next_page ?? null;
        if (query && pagesSatisfy(Object.keys(releases), wanted)) break;
      }
    } catch (err) {
      if (err instanceof HttpStatusError && err.status === 404) {
        return { status: "not_found", detail: `"${name}" is not on crates.io` };
      }
      return { status: "unreachable", detail: `crates.io: ${errorText(err)}` };
    }

    // Dependency lists come from the sparse index; without them the
    // new-dependency signal reports "unknown" rather than "none".
    // crates.io and Cargo read `-` and `_` (and case) in a crate name as one crate, and the API
    // answers `serde-json` with serde_json's versions, but the sparse index files a crate under its
    // published spelling only: `serde-json` read no dependency lists and came back unknown while
    // `serde_json` was proceed (pre-publish round 10, W2). The published spelling comes from the
    // registry's own answer: `/crates/<name>`, or the sparse index's `name` field.
    let sparse = await this.sparseDependencies(canonical ?? name);
    // `/crates/<name>` already answered (the whole list) when wholeRead: asking it again names nothing new.
    if (sparse === "not_found" && canonical === null && !wholeRead) {
      const published = await this.publishedName(name);
      // The spelling could not be confirmed: never judged as if it had been (fail closed).
      if (published.status !== "ok") {
        return { status: "unreachable", detail: `crates.io: the sparse index has no entry under "${name}" and its published spelling could not be read (${published.detail})` };
      }
      canonical = published.data;
      if (canonical !== name) sparse = await this.sparseDependencies(canonical);
    }
    if (sparse && sparse !== "not_found") {
      canonical ??= sparse.name;
      for (const [version, names] of Object.entries(sparse.deps)) {
        if (releases[version]) releases[version].dependencies = names;
      }
    }

    const index: PackageReleaseIndex = { ecosystem: "crates.io", name: canonical ?? name, createdAt: null, releases };
    this.cache.set(key, { index, complete: query === null }, "crates", VERSIONS_TTL);
    return { status: "ok", data: index };
  }

  async getCreatedAt(name: string): Promise<RegistryLookup<string | null>> {
    const key = `crates-created:${name}`;
    const cached = this.cache.get<{ createdAt: string | null }>(key);
    if (cached) return { status: "ok", data: cached.createdAt };
    try {
      const body = await this.apiGet<{ crate?: { created_at?: string } }>(
        `${CRATES_API}/${encodeURIComponent(name)}`,
      );
      const createdAt = body.crate?.created_at ?? null;
      this.cache.set(key, { createdAt }, "crates", CREATED_TTL);
      return { status: "ok", data: createdAt };
    } catch (err) {
      if (err instanceof HttpStatusError && err.status === 404) {
        return { status: "not_found", detail: `"${name}" is not on crates.io` };
      }
      return { status: "unreachable", detail: `crates.io: ${errorText(err)}` };
    }
  }

  /**
   * What one release requires, from the sparse index (the file cargo itself resolves from): its
   * normal and build dependencies, optional ones only where the default feature enables them.
   * `name` is the crate's published spelling (the index files a crate under that one only).
   */
  async getRequirements(name: string, version: string): Promise<RegistryLookup<ReleaseRequirements>> {
    const sparse = await this.sparseDependencies(name);
    if (sparse === "not_found") return { status: "not_found", detail: "the crates.io index has no entry under this spelling" };
    if (sparse === null) return { status: "unreachable", detail: "the crates.io index could not be read" };
    const requirements = sparse.reqs[version];
    return requirements ? { status: "ok", data: requirements } : { status: "not_found", detail: "the crates.io index does not list this version" };
  }

  /**
   * Every version of a crate from `/crates/<name>`, or null when that read fails or the list it
   * returns is shorter than the crate's version count (the caller then pages). Its creation date
   * is kept for getCreatedAt.
   */
  private async wholeList(name: string): Promise<{ versions: CratesVersion[]; name: string | null } | null> {
    try {
      const body = await this.apiGet<{ crate?: { name?: string; created_at?: string; num_versions?: number; versions?: unknown[] }; versions?: CratesVersion[] }>(
        `${CRATES_API}/${encodeURIComponent(name)}`,
      );
      const versions = body.versions ?? [];
      const expected = body.crate?.num_versions ?? body.crate?.versions?.length ?? null;
      if (versions.length === 0 || expected === null || versions.length < expected) return null;
      if (body.crate?.created_at) this.cache.set(`crates-created:${name}`, { createdAt: body.crate.created_at }, "crates", CREATED_TTL);
      return { versions, name: isCrateName(body.crate?.name) ? body.crate.name : null };
    } catch {
      return null;
    }
  }

  /** The crate's published spelling, from `/crates/<name>` (crates.io answers any `-`/`_` or case spelling of it). */
  private async publishedName(name: string): Promise<RegistryLookup<string>> {
    try {
      const body = await this.apiGet<{ crate?: { name?: string } }>(`${CRATES_API}/${encodeURIComponent(name)}`);
      // An answer that names no crate renames nothing: the dependency lists stay unread, which the
      // new-dependency signal reports as unknown, never as none.
      const published = body.crate?.name;
      return { status: "ok", data: isCrateName(published) ? published : name };
    } catch (err) {
      return { status: "unreachable", detail: errorText(err) };
    }
  }

  private async apiGet<T>(url: string): Promise<T> {
    if (!this.rateLimiter.consume("crates")) throw new Error("crates.io rate limit reached for this minute");
    await this.waitForSlot();
    const response = await fetchWithTimeout(
      url,
      { headers: { Accept: "application/json", "User-Agent": CRATES_USER_AGENT } },
      TIMEOUT_MS,
    );
    if (!response.ok) throw new HttpStatusError(response.status);
    return (await response.json()) as T;
  }

  private async waitForSlot(): Promise<void> {
    const now = Date.now();
    const start = Math.max(now, this.nextSlotMs);
    this.nextSlotMs = start + this.minIntervalMs;
    if (start > now) await new Promise((resolve) => setTimeout(resolve, start - now).unref());
  }

  /**
   * version -> runtime dependency names (normal + build; renamed deps by their real crate name), and
   * the crate's published spelling from the index lines (null when they carry none). "not_found":
   * the index has no file under this spelling; null: it could not be read.
   */
  private async sparseDependencies(name: string): Promise<SparseRead | "not_found" | null> {
    // v3: each version's requirements are kept beside its dependency names; v4: those names are crate-shaped.
    const key = `crates-sparse-deps:v4:${name}`;
    const cached = this.cache.get<SparseRead>(key);
    if (cached) return cached;
    try {
      const response = await fetchWithTimeout(
        sparseIndexUrl(name),
        { headers: { "User-Agent": CRATES_USER_AGENT } },
        TIMEOUT_MS,
      );
      if (response.status === 404) return "not_found";
      if (!response.ok) return null;
      const deps: Record<string, string[]> = {};
      const reqs: Record<string, ReleaseRequirements> = {};
      let published: string | null = null;
      for (const line of (await response.text()).split("\n")) {
        if (!line.trim()) continue;
        try {
          const entry = JSON.parse(line) as SparseLine;
          if (published === null && isCrateName(entry.name)) published = entry.name;
          // A dependency name is a registry identifier only in crates.io's shape; anything else is
          // the placeholder, which names no crate (it still counts as a dependency).
          const names = (Array.isArray(entry.deps) ? entry.deps : [])
            .filter((d) => d && typeof d === "object" && d.kind !== "dev")
            .map((d) => readableCrateName(d.package ?? d.name));
          deps[entry.vers] = [...new Set(names)];
          reqs[entry.vers] = requirementsOf(entry);
        } catch {
          // skip a malformed line
        }
      }
      const out: SparseRead = { deps, name: published, reqs };
      this.cache.set(key, out, "crates", VERSIONS_TTL);
      return out;
    } catch {
      return null;
    }
  }
}

function toRecord(v: CratesVersion): ReleaseRecord {
  const tp = v.trustpub_data;
  const who = v.published_by?.login ? ` (published by crates.io user "${v.published_by.login}")` : "";
  return {
    version: v.num,
    publishedAt: v.created_at ?? null,
    trust: tp ? 2 : 0,
    trustEvidence: tp
      ? `trusted publisher (${[tp.provider, tp.repository].filter(Boolean).join(" ") || "OIDC"})`
      : `no trusted publisher${who}`,
    installScripts: null,
    deprecated: null,
    withdrawn: v.yanked ? "yanked" : null,
    dependencies: null,
  };
}

/**
 * True once every wanted version is present AND a release (not a prerelease)
 * below all of them has been seen. Pages arrive in descending semver order,
 * so at that point the release just below the target on its line — the
 * new-dependency trust baseline — has been seen too, if it exists.
 */
export function pagesSatisfy(seen: string[], wanted: string[]): boolean {
  if (wanted.length === 0) return false;
  const have = new Set(seen);
  if (!wanted.every((w) => have.has(w))) return false;
  return seen.some((v) => {
    const p = parseSemverPrecedence(v);
    if (!p || p.prerelease.length > 0) return false;
    return wanted.every((w) => (compareVersionPrecedence(v, w) ?? 0) < 0);
  });
}

function sparseIndexUrl(name: string): string {
  const n = name.toLowerCase();
  switch (n.length) {
    case 1: return `https://index.crates.io/1/${n}`;
    case 2: return `https://index.crates.io/2/${n}`;
    case 3: return `https://index.crates.io/3/${n[0]}/${n}`;
    default: return `https://index.crates.io/${n.slice(0, 2)}/${n.slice(2, 4)}/${n}`;
  }
}

function errorText(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
