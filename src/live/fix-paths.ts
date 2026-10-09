// SPDX-License-Identifier: Apache-2.0
/**
 * Fix paths for vulnerable dependencies: WHICH version to move to, and HOW.
 *
 * Two defects found by the fix-path oracle (2026-10-10, 19 public repos;
 * each recommendation applied in a copy, re-resolved, re-scanned):
 *
 * 1. The target could itself be vulnerable. It was the highest fix among the
 *    advisories that affect the installed version, so an advisory the
 *    installed version predates was never consulted: openssl 0.10.38 was sent
 *    to 0.10.79, which GHSA-phqj-4mhp-q6mq affects (0.10.50 up to 0.10.80).
 *    Now: the smallest published version at or above every per-advisory fix
 *    that NO advisory of the package affects (osv-ranges.ts).
 * 2. Every transitive finding was "waiting on upstream", 3 wrong out of 3:
 *    minimist 1.2.5 (npm), braces 3.0.2 (pnpm) and mio 0.8.0 (Cargo) all had
 *    parents whose declared requirement already admitted the fix, and a
 *    lockfile refresh fixed each one. Now: the parents' requirements are
 *    read (from the lockfile, or from the parent's registry metadata for
 *    pnpm and Cargo) and a refresh is recommended when they all admit a
 *    clean version.
 *
 * Network: api.osv.dev (one /v1/query per vulnerable package) and the
 * package's own registry; package names and versions only. Every lookup is
 * cached, and any failure degrades to the old answer, never to a guess.
 */

import type { LiveCache } from "./cache.js";
import type { RateLimiter } from "./rate-limiter.js";
import { fetchWithTimeout } from "./http-utils.js";
import { escapeModulePath } from "./go-registry.js";
import { advisoryRanges, advisoryAffects, isPrereleaseVersion, smallestCleanVersion, type AdvisoryRanges, type CleanTarget } from "./osv-ranges.js";
import * as fs from "node:fs";
import { readLockfileParents, type LockfileFormat, type ParentEdge } from "./lockfile-parents.js";
import { parseCargoLockPackages } from "./lockfile-parsers.js";
import { cargoReqAdmits, npmRangeAdmits } from "./range-satisfies.js";
import { compareVersions } from "./version-compare.js";
import { CRATES_USER_AGENT } from "./crates-versions.js";
import type { OsvEcosystem, OsvVulnerability } from "./types.js";

const TIMEOUT_MS = 15_000;
const ADVISORY_TTL = 6 * 3600;
const VERSIONS_TTL = 6 * 3600;
/** A published version's manifest never changes. */
const VERSION_DEPS_TTL = 30 * 86_400;
const MAX_OSV_PAGES = 10;

/** Bump when the shape of anything this module caches changes. */
const CACHE_VERSION = 2;

export interface CrateDepReq {
  req: string;
  optional: boolean;
}

export interface CratesSparse {
  /** Versions not yanked. */
  versions: string[];
  /** version -> dependency crate name -> requirements (one per target/kind entry; dev-dependencies left out). */
  reqs: Record<string, Record<string, CrateDepReq[]>>;
}

export class FixPathSources {
  constructor(
    private cache: LiveCache,
    private rateLimiter: RateLimiter,
  ) {}

  /** Every non-withdrawn OSV advisory for a package, as ranges; null when OSV could not be read. */
  async packageAdvisories(ecosystem: OsvEcosystem, name: string): Promise<AdvisoryRanges[] | null> {
    const key = `fixpath:v${CACHE_VERSION}:osv-package:${ecosystem}:${name}`;
    const hit = this.cache.get<AdvisoryRanges[]>(key);
    if (hit) return hit;
    if (!this.rateLimiter.consume("osv-package")) return null;
    const out: AdvisoryRanges[] = [];
    let token: string | undefined;
    try {
      for (let page = 0; page < MAX_OSV_PAGES; page++) {
        const res = await fetchWithTimeout(
          "https://api.osv.dev/v1/query",
          {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ package: { name, ecosystem }, ...(token ? { page_token: token } : {}) }),
          },
          TIMEOUT_MS,
        );
        if (!res.ok) return null;
        const body = (await res.json()) as { vulns?: OsvVulnerability[]; next_page_token?: string };
        for (const v of body.vulns ?? []) {
          const ranges = advisoryRanges(v, name, ecosystem);
          if (ranges) out.push(ranges);
        }
        token = body.next_page_token;
        if (!token) break;
      }
      if (token) return null; // more pages than the cap: an incomplete list cannot prove a version clean
    } catch {
      return null;
    }
    this.cache.set(key, out, "osv", ADVISORY_TTL);
    return out;
  }

  /** Published, installable versions (not yanked); null when the registry could not be read or is not supported. */
  async publishedVersions(ecosystem: OsvEcosystem, name: string): Promise<string[] | null> {
    switch (ecosystem) {
      case "npm":
        return this.npmVersions(name);
      case "crates.io":
        return (await this.cratesSparse(name))?.versions ?? null;
      case "PyPI":
        return this.pypiVersions(name);
      case "Go":
        return this.goVersions(name);
      default:
        return null;
    }
  }

  /**
   * The requirements `parent@parentVersion` declares on `dep`, from the
   * registry: npm (pnpm lockfiles record none) and crates.io (Cargo.lock
   * records none). Null when unknown; [] when the parent declares none.
   */
  async parentRequirements(ecosystem: OsvEcosystem, parent: string, parentVersion: string, dep: string): Promise<string[] | null> {
    if (ecosystem === "crates.io") {
      const sparse = await this.cratesSparse(parent);
      const deps = sparse?.reqs[parentVersion];
      return deps ? (deps[dep] ?? []).map((d) => d.req) : null;
    }
    if (ecosystem !== "npm") return null;
    const key = `fixpath:v${CACHE_VERSION}:npm-version-deps:${parent}@${parentVersion}`;
    let deps = this.cache.get<Record<string, string>>(key);
    if (!deps) {
      if (!this.rateLimiter.consume("fixpath-registry")) return null;
      try {
        const res = await fetchWithTimeout(
          `https://registry.npmjs.org/${encodeURIComponent(parent)}/${encodeURIComponent(parentVersion)}`,
          { headers: { Accept: "application/json" } },
          TIMEOUT_MS,
        );
        if (!res.ok) return null;
        const doc = (await res.json()) as Record<string, Record<string, string> | undefined>;
        deps = { ...doc.peerDependencies, ...doc.optionalDependencies, ...doc.dependencies };
        this.cache.set(key, deps, "npm", VERSION_DEPS_TTL);
      } catch {
        return null;
      }
    }
    return typeof deps[dep] === "string" ? [deps[dep]] : [];
  }

  private async npmVersions(name: string): Promise<string[] | null> {
    const key = `fixpath:v${CACHE_VERSION}:npm-versions:${name}`;
    const hit = this.cache.get<string[]>(key);
    if (hit) return hit;
    if (!this.rateLimiter.consume("fixpath-registry")) return null;
    try {
      // The abbreviated document: versions without READMEs.
      const res = await fetchWithTimeout(
        `https://registry.npmjs.org/${encodeURIComponent(name)}`,
        { headers: { Accept: "application/vnd.npm.install-v1+json" } },
        TIMEOUT_MS,
      );
      if (!res.ok) return null;
      const doc = (await res.json()) as { versions?: Record<string, unknown> };
      const versions = Object.keys(doc.versions ?? {});
      this.cache.set(key, versions, "npm", VERSIONS_TTL);
      return versions;
    } catch {
      return null;
    }
  }

  /** A crate's sparse-index record: versions and per-version dependency requirements. */
  async cratesSparse(name: string): Promise<CratesSparse | null> {
    const key = `fixpath:v${CACHE_VERSION}:crates-sparse:${name}`;
    const hit = this.cache.get<CratesSparse>(key);
    if (hit) return hit;
    if (!this.rateLimiter.consume("fixpath-registry")) return null;
    try {
      const res = await fetchWithTimeout(sparseIndexUrl(name), { headers: { "User-Agent": CRATES_USER_AGENT } }, TIMEOUT_MS);
      if (!res.ok) return null;
      const out: CratesSparse = { versions: [], reqs: {} };
      for (const line of (await res.text()).split("\n")) {
        if (!line.trim()) continue;
        try {
          const entry = JSON.parse(line) as {
            vers: string;
            yanked?: boolean;
            deps?: Array<{ name: string; req: string; kind?: string | null; package?: string; optional?: boolean }>;
          };
          if (!entry.yanked) out.versions.push(entry.vers);
          const reqs: Record<string, CrateDepReq[]> = {};
          for (const d of entry.deps ?? []) {
            if (d.kind === "dev") continue;
            const crate = d.package ?? d.name;
            (reqs[crate] ??= []).push({ req: d.req, optional: d.optional === true });
          }
          out.reqs[entry.vers] = reqs;
        } catch {
          // a malformed line
        }
      }
      this.cache.set(key, out, "crates", VERSIONS_TTL);
      return out;
    } catch {
      return null;
    }
  }

  private async pypiVersions(name: string): Promise<string[] | null> {
    const key = `fixpath:v${CACHE_VERSION}:pypi-versions:${name}`;
    const hit = this.cache.get<string[]>(key);
    if (hit) return hit;
    if (!this.rateLimiter.consume("fixpath-registry")) return null;
    try {
      const res = await fetchWithTimeout(`https://pypi.org/pypi/${encodeURIComponent(name)}/json`, {}, TIMEOUT_MS);
      if (!res.ok) return null;
      const doc = (await res.json()) as { releases?: Record<string, Array<{ yanked?: boolean }>> };
      // A release with files, not all of them yanked.
      const versions = Object.entries(doc.releases ?? {})
        .filter(([, files]) => files.length > 0 && files.some((f) => !f.yanked))
        .map(([v]) => v);
      this.cache.set(key, versions, "pypi", VERSIONS_TTL);
      return versions;
    } catch {
      return null;
    }
  }

  private async goVersions(name: string): Promise<string[] | null> {
    const key = `fixpath:v${CACHE_VERSION}:go-versions:${name}`;
    const hit = this.cache.get<string[]>(key);
    if (hit) return hit;
    if (!this.rateLimiter.consume("fixpath-registry")) return null;
    try {
      const res = await fetchWithTimeout(`https://proxy.golang.org/${escapeModulePath(name)}/@v/list`, {}, TIMEOUT_MS);
      if (!res.ok) return null;
      // OSV's Go ranges carry no `v`.
      const versions = (await res.text()).split("\n").map((v) => v.trim().replace(/^v/, "")).filter(Boolean);
      this.cache.set(key, versions, "go", VERSIONS_TTL);
      return versions;
    } catch {
      return null;
    }
  }
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

// ---------------------------------------------------------------------------
// Analysis
// ---------------------------------------------------------------------------

export type FixTargetResult = CleanTarget;

/** The minimal clean target for one installed copy, or null when the advisories could not be read. */
export async function cleanFixTarget(
  sources: FixPathSources,
  ecosystem: OsvEcosystem,
  name: string,
  perAdvisoryFixes: string[],
): Promise<FixTargetResult | null> {
  if (perAdvisoryFixes.length === 0) return null;
  const [advisories, published] = await Promise.all([
    sources.packageAdvisories(ecosystem, name),
    sources.publishedVersions(ecosystem, name),
  ]);
  if (!advisories) return null;
  return smallestCleanVersion({ ecosystem, fixes: perAdvisoryFixes, advisories, published });
}

export interface RefreshVerdict {
  /** True when every parent's requirement already admits a clean version. */
  refreshFixes: boolean;
  format: LockfileFormat;
  /** The command, run in the lockfile's directory. */
  command: string;
  /** Parent requirements that do NOT admit a clean version (why it is waiting on upstream). */
  blocking: Array<{ parent: string; parentVersion: string | null; requirement: string }>;
  /** The version a refresh resolves to, when the registry's version list was read. */
  resolvesTo: string | null;
}

/** The refresh command for one lockfile format. */
export function refreshCommand(format: LockfileFormat, name: string, installed: string, target: string): string {
  switch (format) {
    case "package-lock":
      return `npm update ${name}`;
    case "pnpm":
      return `pnpm update ${name}`;
    case "yarn-berry":
      return `yarn up -R ${name}`;
    case "yarn":
      return `delete the ${name}@ entries from yarn.lock, then run yarn install`;
    case "bun":
      return `delete the ${name} entries from bun.lock, then run bun install`;
    case "cargo":
      return `cargo update -p ${name}@${installed} --precise ${target}`;
  }
}

/**
 * Whether refreshing `lockfile` moves `name@installed` to a clean version
 * without any parent changing its declared requirement. Null when the
 * lockfile or a requirement cannot be read (the caller keeps "waiting on
 * upstream", the conservative answer).
 */
export async function refreshVerdict(
  sources: FixPathSources,
  ecosystem: OsvEcosystem,
  lockfile: string,
  name: string,
  installed: string,
  target: string,
  advisories: AdvisoryRanges[] | null,
  published: string[] | null,
): Promise<RefreshVerdict | null> {
  const parents = readLockfileParents(lockfile, name, installed);
  if (!parents || parents.edges.length === 0) return null;
  const isCargo = parents.format === "cargo";
  const admits = (range: string, version: string) => (isCargo ? cargoReqAdmits(range, version) : npmRangeAdmits(range, version));
  const clean = (v: string) => !advisories || !advisories.some((a) => advisoryAffects(a, v, ecosystem));
  const releases = (published ?? []).filter((v) => !isPrereleaseVersion(v, ecosystem));

  const blocking: RefreshVerdict["blocking"] = [];
  let resolvesTo: string | null = null;
  const edgeReqs = await Promise.all(parents.edges.map((edge) => requirementsOf(sources, ecosystem, edge, name)));
  for (const [i, edge] of parents.edges.entries()) {
    const all = edgeReqs[i];
    if (all === null || all.length === 0) return null;
    // A parent can declare the same crate twice under different names (feature-gated
    // `mio-0_6` / `mio-0_7` aliases): only the requirements this copy satisfies apply.
    const matching = all.filter((req) => admits(req, installed) === true);
    const reqs = matching.length > 0 ? [...new Set(matching)] : [...new Set(all)];
    for (const req of reqs) {
      if (isCargo) {
        // `cargo update --precise` moves to exactly the clean target, if every requirement admits it.
        const ok = admits(req, target);
        if (ok === null) return null;
        if (!ok) blocking.push({ parent: edge.parent, parentVersion: edge.parentVersion, requirement: req });
        else resolvesTo = target;
        continue;
      }
      // npm, pnpm, yarn and bun resolve each requirement to its newest match.
      if (releases.length > 0) {
        const newest = releases
          .filter((v) => admits(req, v) === true)
          .sort((a, b) => compareVersions(b, a, ecosystem))[0];
        if (!newest || compareVersions(newest, target, ecosystem) < 0 || !clean(newest)) {
          blocking.push({ parent: edge.parent, parentVersion: edge.parentVersion, requirement: req });
        } else if (!resolvesTo || compareVersions(newest, resolvesTo, ecosystem) < 0) {
          resolvesTo = newest;
        }
      } else {
        const ok = admits(req, target);
        if (ok === null) return null;
        if (!ok) blocking.push({ parent: edge.parent, parentVersion: edge.parentVersion, requirement: req });
      }
    }
  }
  let command = refreshCommand(parents.format, name, installed, target);
  if (isCargo && blocking.length === 0) {
    let content: string;
    try {
      content = fs.readFileSync(lockfile, "utf-8");
    } catch {
      return null;
    }
    const prereqs = await cargoPrecisePrerequisites(sources, content, name, installed, target);
    if (prereqs === null) return null;
    if (prereqs.length > 0) command = `cargo update ${prereqs.map((p) => `-p ${p}`).join(" ")} && ${command}`;
  }
  return {
    refreshFixes: blocking.length === 0,
    format: parents.format,
    command,
    blocking,
    resolvesTo: blocking.length === 0 ? resolvesTo : null,
  };
}

async function requirementsOf(sources: FixPathSources, ecosystem: OsvEcosystem, edge: ParentEdge, name: string): Promise<string[] | null> {
  if (edge.range !== null) return [edge.range];
  if (edge.parentVersion === null) return null;
  return sources.parentRequirements(ecosystem, edge.parent, edge.parentVersion, name);
}

// ---------------------------------------------------------------------------
// Cargo: what `--precise` needs moved first
// ---------------------------------------------------------------------------

/** Cargo's compatibility line: one copy per line per lockfile ("1", "0.10", "0.0.3"). */
function cargoLine(version: string): string {
  const [major, minor, patch] = version.split(/[.+-]/);
  return major !== "0" ? major : minor !== "0" ? `0.${minor}` : `0.0.${patch}`;
}

const MAX_CLOSURE_CRATES = 60;

/**
 * The locked crates `cargo update -p name@installed --precise target` cannot
 * move by itself, as `crate@lockedVersion` specs to update first; null when it
 * cannot be worked out (a registry read failed, or the walk is too large).
 *
 * Measured on nushell (2026-10-10): `cargo update -p openssl@0.10.38
 * --precise 0.10.80` fails. 0.10.80 needs openssl-macros 0.1.1 -> syn 2 ->
 * quote ^1.0.25, and quote 1.0.15 is locked by rstest, outside openssl's own
 * dependency tree, so cargo keeps it and reports a conflict. `cargo update -p
 * quote` first, then the precise update, works. Crates in the installed
 * version's own tree may move with it (openssl-sys did) and are not listed.
 *
 * The walk follows the target's normal and build dependencies (optional ones
 * only when the crate is already in the lockfile): a requirement a locked copy
 * satisfies is reused; one whose compatibility line holds a locked copy that
 * does not satisfy it names that copy; anything else is a new crate, walked
 * at its newest matching version.
 */
export async function cargoPrecisePrerequisites(
  sources: FixPathSources,
  lockContent: string,
  name: string,
  installed: string,
  target: string,
): Promise<string[] | null> {
  const packages = parseCargoLockPackages(lockContent);
  const locked = new Map<string, string[]>();
  for (const p of packages) locked.set(p.name, [...(locked.get(p.name) ?? []), p.version]);

  // The installed version's own dependency tree, which cargo may move with it.
  const byKey = new Map(packages.map((p) => [`${p.name}@${p.version}`, p]));
  const own = new Set<string>();
  const stack = [`${name}@${installed}`];
  while (stack.length > 0) {
    const key = stack.pop()!;
    if (own.has(key)) continue;
    own.add(key);
    for (const dep of byKey.get(key)?.dependencies ?? []) {
      const [depName, depVersion] = dep.split(" ");
      const version = depVersion ?? (locked.get(depName)?.length === 1 ? locked.get(depName)![0] : null);
      if (version) stack.push(`${depName}@${version}`);
    }
  }

  const prereqs = new Set<string>();
  const visited = new Set<string>();
  const queue: Array<[string, string]> = [[name, target]];
  while (queue.length > 0) {
    const [crate, version] = queue.shift()!;
    if (visited.has(`${crate}@${version}`)) continue;
    visited.add(`${crate}@${version}`);
    if (visited.size > MAX_CLOSURE_CRATES) return null;
    const deps = (await sources.cratesSparse(crate))?.reqs[version];
    if (!deps) return null;
    for (const [dep, entries] of Object.entries(deps)) {
      const lockedVersions = locked.get(dep) ?? [];
      for (const { req, optional } of entries) {
        if (optional && lockedVersions.length === 0) continue; // a feature this build does not enable
        if (lockedVersions.some((v) => cargoReqAdmits(req, v) === true)) continue;
        const available = (await sources.cratesSparse(dep))?.versions;
        if (!available) return null;
        const best = available
          .filter((v) => !isPrereleaseVersion(v, "crates.io") && cargoReqAdmits(req, v) === true)
          .sort((a, b) => compareVersions(b, a, "crates.io"))[0];
        if (!best) return null;
        const sameLine = lockedVersions.find((v) => cargoLine(v) === cargoLine(best));
        if (sameLine) {
          if (!own.has(`${dep}@${sameLine}`)) prereqs.add(`${dep}@${sameLine}`);
        } else if (!visited.has(`${dep}@${best}`)) {
          queue.push([dep, best]);
        }
      }
    }
  }
  return [...prereqs].sort();
}
