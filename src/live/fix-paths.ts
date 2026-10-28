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

import { isShellSafeCargoTarget, isShellSafeName, isShellSafeVersion } from "./shell-safe.js";
import type { LiveCache } from "./cache.js";
import type { RateLimiter } from "./rate-limiter.js";
import { fetchWithTimeout } from "./http-utils.js";
import { escapeModulePath } from "./go-registry.js";
import { advisoryRanges, advisoryAffects, installableFix, isListedVersion, remainsText, isPrereleaseVersion, smallestCleanVersion, type AdvisoryRanges, type CleanTarget } from "./osv-ranges.js";
import * as fs from "node:fs";
import * as path from "node:path";
import { lockfileFormat, readLockfileParents, type LockfileFormat, type ParentEdge } from "./lockfile-parents.js";
import { parseCargoLockPackages } from "./lockfile-parsers.js";
import { compiledRequirements, confinedInclude, requirementOptions } from "./lockfile-parsers-pygo.js";
import { cargoReqAdmits, npmRangeAdmits } from "./range-satisfies.js";
import { refreshRule, requirementAdmits, type ParentRequirement, type RequirementDialect } from "./refresh-rule.js";
import { compareVersions, maxVersion } from "./version-compare.js";
import { CRATES_USER_AGENT } from "./crates-versions.js";
import { isNpmDeprecated, npmExcludedVersions, sayWithdrawn, withdrawalText, withheldNote } from "./withdrawn-releases.js";
import { andList, heldSpecsOf, heldText, type AdvisoryQuery, type HeldDependency } from "./held-dependencies.js";
import { withHeldTargets } from "./held-targets.js";
import type { OsvEcosystem, OsvVulnerability } from "./types.js";

const TIMEOUT_MS = 15_000;
const ADVISORY_TTL = 6 * 3600;
const VERSIONS_TTL = 6 * 3600;
/** A published version's manifest never changes. */
const VERSION_DEPS_TTL = 30 * 86_400;
const MAX_OSV_PAGES = 10;

/** Bump when the shape of anything this module caches changes (10: npm facts carry `heldSpecs`, audit 6.2.5 D-4). */
const CACHE_VERSION = 10;

/** What a registry says about one package's releases, for fix targets and parent advice. */
export interface PackageReleaseFacts {
  /** Published, installable versions: every release except the `withdrawn` ones. */
  versions: string[];
  /**
   * Releases the registry withdrew, never a fix target (withdrawn-releases.ts, the 4DA app's
   * rule): yanked (crates.io; PyPI: every file), and npm `deprecated` only where a later,
   * non-deprecated stable release exists on the same caret line and `latest` is not deprecated.
   */
  withdrawn: string[];
  /** Per withdrawn release, the registry's words ("4.18.0 is deprecated on npm ("Bad release...")"). */
  withdrawnWhy: Record<string, string>;
  /** The registry's latest release (npm `latest` tag; crates.io the highest non-yanked), or null. */
  latest: string | null;
  /** The package-level deprecation of the newest release (npm), or null. */
  deprecatedLatest: string | null;
  /**
   * npm: releases that carry a `deprecated` message the withdrawal rule does NOT withdraw (a
   * notice on a whole line, such as glob's "Old versions of glob are not supported"), with the
   * message. Still candidates; a tool that offers one says it is deprecated (final release audit
   * of 6.2.5: the plan targeted glob 10.5.0 while dependency_check said review on it).
   */
  lineNotices?: Record<string, string>;
  /**
   * npm: per release, the dependencies it holds (exact pins and narrow ranges, held-dependencies.ts):
   * name -> spec. A release that holds none is absent. Its advisories come with the release
   * (audit 6.2.5 D-4: express 4.20.0 exact-pins qs 6.11.0).
   */
  heldSpecs?: Record<string, Record<string, string>>;
}

export interface CrateDepReq {
  req: string;
  optional: boolean;
}

export interface CratesSparse {
  /** Versions not yanked. */
  versions: string[];
  /** Yanked versions. */
  yanked?: string[];
  /** version -> dependency crate name -> requirements (one per target/kind entry; dev-dependencies left out). */
  reqs: Record<string, Record<string, CrateDepReq[]>>;
}

/** npm's abbreviated document: per version, the fields fix paths read. */
interface NpmAbbreviatedDoc {
  versions?: Record<
    string,
    { deprecated?: unknown; dependencies?: Record<string, string>; optionalDependencies?: Record<string, string>; peerDependencies?: Record<string, string> }
  >;
  "dist-tags"?: { latest?: string };
}

/** How long, and how many, npm documents are kept in memory between the lookups of one plan. */
const NPM_DOC_MEMORY_MS = 120_000;
const NPM_DOCS_KEPT = 16;

/** Per published release of a parent: its requirements on one package, and whether it declares it only as a peer. */
export type RequirementHistory = Record<string, { reqs: string[]; peer: boolean }>;

export class FixPathSources {
  private npmDocs = new Map<string, { at: number; doc: Promise<NpmAbbreviatedDoc | null> }>();

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
        return (await this.npmFacts(name))?.versions ?? null;
      case "crates.io":
        return (await this.cratesSparse(name))?.versions ?? null;
      case "PyPI":
        return (await this.pypiFacts(name))?.versions ?? null;
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
        // Not peerDependencies, as in the 4DA app: a peer is resolved from whoever provides it
        // higher in the tree, so the parent's peer range does not decide which copy a refresh picks.
        deps = { ...doc.optionalDependencies, ...doc.dependencies };
        this.cache.set(key, deps, "npm", VERSION_DEPS_TTL);
      } catch {
        return null;
      }
    }
    return typeof deps[dep] === "string" ? [deps[dep]] : [];
  }

  /**
   * What every published release of `parent` requires of `dep`, from the
   * registry: version -> requirements (`reqs: []` when that release does not
   * depend on it). npm reads dependencies and optionalDependencies of the
   * abbreviated document (as `parentRequirements`), and, when neither holds
   * it, peerDependencies, flagged `peer`: npm 7+ installs a missing peer, so
   * moving a package into peerDependencies is not dropping it (readiness
   * review 2026-10-17, finding 10). crates.io: the sparse index. Null when
   * unknown or unsupported. Used to find the smallest parent release that
   * admits a clean version (audit H1).
   */
  async requirementHistory(ecosystem: OsvEcosystem, parent: string, dep: string): Promise<RequirementHistory | null> {
    if (ecosystem === "crates.io") {
      const sparse = await this.cratesSparse(parent);
      if (!sparse) return null;
      return Object.fromEntries(Object.entries(sparse.reqs).map(([v, deps]) => [v, { reqs: (deps[dep] ?? []).map((d) => d.req), peer: false }]));
    }
    if (ecosystem !== "npm") return null;
    const key = `fixpath:v${CACHE_VERSION}:npm-requirement-history:${parent}:${dep}`;
    const hit = this.cache.get<RequirementHistory>(key);
    if (hit) return hit;
    const doc = await this.npmDocument(parent);
    if (!doc) return null;
    const out: RequirementHistory = {};
    for (const [version, m] of Object.entries(doc.versions ?? {})) {
      const req = m?.dependencies?.[dep] ?? m?.optionalDependencies?.[dep];
      const peer = m?.peerDependencies?.[dep];
      out[version] =
        typeof req === "string" ? { reqs: [req], peer: false } : typeof peer === "string" ? { reqs: [peer], peer: true } : { reqs: [], peer: false };
    }
    this.cache.set(key, out, "npm", VERSIONS_TTL);
    return out;
  }

  /**
   * One npm abbreviated document per package, shared by the release facts and the requirement
   * history of a plan (a parent's document was downloaded twice: NodeGoat's mongodb, ~600
   * releases). Kept in memory for a short while, at most a few at a time; a failure is not kept.
   */
  private npmDocument(name: string): Promise<NpmAbbreviatedDoc | null> {
    const now = Date.now();
    for (const [n, e] of this.npmDocs) if (now - e.at > NPM_DOC_MEMORY_MS) this.npmDocs.delete(n);
    const hit = this.npmDocs.get(name);
    if (hit) return hit.doc;
    if (!this.rateLimiter.consume("fixpath-registry")) return Promise.resolve(null);
    const doc = (async (): Promise<NpmAbbreviatedDoc | null> => {
      try {
        const res = await fetchWithTimeout(
          `https://registry.npmjs.org/${encodeURIComponent(name)}`,
          { headers: { Accept: "application/vnd.npm.install-v1+json" } },
          TIMEOUT_MS,
        );
        if (!res.ok) return null;
        return (await res.json()) as NpmAbbreviatedDoc;
      } catch {
        return null;
      }
    })();
    this.npmDocs.set(name, { at: now, doc });
    void doc.then((d) => {
      if (d === null) this.npmDocs.delete(name);
    });
    while (this.npmDocs.size > NPM_DOCS_KEPT) this.npmDocs.delete(this.npmDocs.keys().next().value!);
    return doc;
  }

  /**
   * Release facts for a parent or a fix target: what is installable, what is
   * deprecated or yanked, and the latest release. Null when the registry
   * could not be read or is not supported.
   */
  async releaseFacts(ecosystem: OsvEcosystem, name: string): Promise<PackageReleaseFacts | null> {
    if (ecosystem === "npm") return this.npmFacts(name);
    const highest = (versions: string[]) =>
      versions.filter((v) => !isPrereleaseVersion(v, ecosystem)).sort((a, b) => compareVersions(a, b, ecosystem)).pop() ?? null;
    if (ecosystem === "crates.io") {
      const sparse = await this.cratesSparse(name);
      if (!sparse) return null;
      const yanked = sparse.yanked ?? [];
      const withdrawnWhy = Object.fromEntries(yanked.map((v) => [v, withdrawalText("crates.io", v)]));
      return { versions: sparse.versions, withdrawn: yanked, withdrawnWhy, latest: highest(sparse.versions), deprecatedLatest: null };
    }
    if (ecosystem === "PyPI") {
      const facts = await this.pypiFacts(name);
      return facts ? { ...facts, latest: highest(facts.versions), deprecatedLatest: null } : null;
    }
    // Go: `retract` lives in the newest version's go.mod, which is not read (as in the 4DA app).
    const versions = await this.publishedVersions(ecosystem, name);
    if (!versions) return null;
    return { versions, withdrawn: [], withdrawnWhy: {}, latest: highest(versions), deprecatedLatest: null };
  }

  /**
   * npm's abbreviated document: versions without READMEs, with each
   * version's `deprecated` message. A withdrawn release is never offered as a
   * fix target: lodash 4.18.0 ("Bad release. Please use lodash@4.17.21
   * instead.") was recommended by vulnerability_scan (audit B-8, 2026-10-12).
   * Withdrawn means the app's rule (withdrawn-releases.ts): a deprecated
   * release with a later clean one on its caret line. A whole-major notice
   * (glob, tar 6.x) withdraws nothing, or glob 10.4.5 is sent to 12.0.0.
   */
  private async npmFacts(name: string): Promise<PackageReleaseFacts | null> {
    const key = `fixpath:v${CACHE_VERSION}:npm-facts:${name}`;
    const hit = this.cache.get<PackageReleaseFacts>(key);
    if (hit) return hit;
    const doc = await this.npmDocument(name);
    if (!doc) return null;
    const versions = doc.versions ?? {};
    const latest = doc["dist-tags"]?.latest ?? null;
    const withdrawn = npmExcludedVersions(Object.fromEntries(Object.entries(versions).map(([v, m]) => [v, m?.deprecated])), latest);
    const out = new Set(withdrawn);
    const message = (v: string) => (typeof versions[v]?.deprecated === "string" ? (versions[v].deprecated as string) : null);
    const noticed = Object.keys(versions).filter((v) => !out.has(v) && isNpmDeprecated(versions[v]?.deprecated));
    const heldSpecs: Record<string, Record<string, string>> = {};
    for (const [v, m] of Object.entries(versions)) {
      const held = heldSpecsOf(m?.dependencies, m?.optionalDependencies);
      if (Object.keys(held).length > 0) heldSpecs[v] = held;
    }
    const facts: PackageReleaseFacts = {
      versions: Object.keys(versions).filter((v) => !out.has(v)),
      withdrawn,
      withdrawnWhy: Object.fromEntries(withdrawn.map((v) => [v, withdrawalText("npm", v, message(v))])),
      latest,
      deprecatedLatest: latest && isNpmDeprecated(versions[latest]?.deprecated) ? (message(latest) ?? "deprecated") : null,
      ...(noticed.length > 0 ? { lineNotices: Object.fromEntries(noticed.map((v) => [v, message(v) ?? "deprecated"])) } : {}),
      heldSpecs,
    };
    this.cache.set(key, facts, "npm", VERSIONS_TTL);
    return facts;
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
      const out: CratesSparse = { versions: [], yanked: [], reqs: {} };
      for (const line of (await res.text()).split("\n")) {
        if (!line.trim()) continue;
        try {
          const entry = JSON.parse(line) as {
            vers: string;
            yanked?: boolean;
            deps?: Array<{ name: string; req: string; kind?: string | null; package?: string; optional?: boolean }>;
          };
          if (!entry.yanked) out.versions.push(entry.vers);
          else out.yanked!.push(entry.vers);
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

  /**
   * PyPI's JSON API: every release with files; one whose every file is yanked is withdrawn
   * (PEP 592, the app's `parse_pypi`). A release with no files cannot be installed and is not listed.
   */
  private async pypiFacts(name: string): Promise<{ versions: string[]; withdrawn: string[]; withdrawnWhy: Record<string, string> } | null> {
    const key = `fixpath:v${CACHE_VERSION}:pypi-facts:${name}`;
    const hit = this.cache.get<{ versions: string[]; withdrawn: string[]; withdrawnWhy: Record<string, string> }>(key);
    if (hit) return hit;
    if (!this.rateLimiter.consume("fixpath-registry")) return null;
    try {
      const res = await fetchWithTimeout(`https://pypi.org/pypi/${encodeURIComponent(name)}/json`, {}, TIMEOUT_MS);
      if (!res.ok) return null;
      const doc = (await res.json()) as { releases?: Record<string, Array<{ yanked?: boolean; yanked_reason?: string | null }>> };
      const out = { versions: [] as string[], withdrawn: [] as string[], withdrawnWhy: {} as Record<string, string> };
      for (const [version, files] of Object.entries(doc.releases ?? {})) {
        if (!Array.isArray(files) || files.length === 0) continue;
        if (files.every((f) => f.yanked === true)) {
          out.withdrawn.push(version);
          out.withdrawnWhy[version] = withdrawalText("PyPI", version, files.find((f) => f.yanked_reason)?.yanked_reason ?? null);
        } else {
          out.versions.push(version);
        }
      }
      this.cache.set(key, out, "pypi", VERSIONS_TTL);
      return out;
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

export type FixTargetResult = CleanTarget & {
  /** No target and a malicious landing: "<pkg> is flagged malicious (<id>): remove or replace <pkg>" (#994 review). */
  landingNote?: string;
  /**
   * True when the package's advisories could not be read (OSV /v1/query
   * failed) but the registry could: `target` is then only the smallest
   * installable release at or above the highest per-advisory fix, which is
   * deprecated, yanked or unpublished (`floorWithdrawn` says which). It is
   * NOT checked against the package's other advisories; callers report the
   * fix as checked against the installed version's advisories only.
   */
  advisoriesUnread?: boolean;
  /**
   * True when the package's registry could not be read: withdrawn (yanked, deprecated) releases
   * were not checked, and the target comes from the advisory data alone, as before FX-H5.
   */
  registryUnread?: boolean;
  /** The registry's words for each `withheld` release and each withdrawn line fix. */
  withheldWhy?: Record<string, string>;
  /**
   * Per-advisory fixes the registry withdrew, keyed by that fix: the release to take instead
   * (`fix: null` when none past it is known) and the withdrawn ones passed (installableFix).
   */
  lineFixes?: Record<string, { fix: string | null; withheld: string[] }>;
  /**
   * npm: the target carries a deprecation notice the withdrawal rule keeps (one on its whole line,
   * no later release on the line free of it: glob 10.5.0, "Old versions of glob are not
   * supported"). It stays the target, the smallest fix without a major upgrade, and every tool
   * says it is deprecated, as dependency_check does with `review` (final release audit 7f).
   */
  targetNotice?: string;
  /** The package's malware advisories (#981 rule a): a release one affects is never the target. */
  malware?: string[];
  /**
   * npm (audit 6.2.5 D-4): the release the package's own advisories pointed at, passed because a
   * dependency it holds (an exact pin, or a narrow range whose newest release is affected) brings
   * an advisory in; `heldPast` names each release passed and why. `target` is then the smallest
   * later release on that line whose own advisories AND held dependencies are clean.
   */
  heldFrom?: string;
  heldPast?: Array<{ version: string; affected: HeldDependency[] }>;
  /**
   * The target holds an affected dependency and no later release searched (`searched`) clears it: not a
   * clean fix. `unchecked`: the releases in `searched` whose held dependencies could not be judged,
   * neither clean nor affected (4DA `HeldOutcome::Blocked.unchecked`, #1039).
   */
  heldBlocked?: { affected: HeldDependency[]; searched: string[]; unchecked?: string[] };
  /** Whether the target's held dependencies are affected could not be checked, and why: not a clean fix either. */
  heldUnchecked?: string;
};

/**
 * Whether a checked target may be reported as checked against every advisory (fix_checked
 * `all_advisories`): its own advisories were read, and, for npm, what it installs at a fixed
 * version was judged clean (audit 6.2.5 D-4).
 */
export function targetCheckedAll(clean: FixTargetResult): boolean {
  return !clean.advisoriesUnread && !clean.heldBlocked && clean.heldUnchecked === undefined;
}

/** The words for a target's held dependencies (FixTargetResult.heldFrom / heldBlocked / heldUnchecked), or null when there is nothing to say. */
export function heldNote(clean: FixTargetResult): string | null {
  if (clean.heldFrom && clean.heldPast && clean.heldPast.length > 0 && clean.target) {
    const [first, ...rest] = clean.heldPast;
    const names = [...new Set(rest.flatMap((p) => p.affected.map((d) => d.name)))];
    const later = rest.length === 0
      ? ""
      : `; ${rest.length === 1 ? rest[0].version : `${rest.length} later releases (${rest[0].version} to ${rest[rest.length - 1].version})`} still bring${rest.length === 1 ? "s" : ""} in an affected ${names.join(", ")}`;
    return `${heldText(first.version, first.affected)}${later}; so ${clean.target}, the smallest later release on its line whose own advisories and held dependencies are clean`;
  }
  if (clean.heldBlocked && clean.target) {
    const last = clean.heldBlocked.searched[clean.heldBlocked.searched.length - 1];
    const upTo = last && last !== clean.target ? `up to ${last} ` : "";
    const unchecked = clean.heldBlocked.unchecked ?? [];
    const partial = unchecked.length > 0 ? `, of the releases that could be checked (${andList(unchecked)} NOT CHECKED)` : "";
    return `${heldText(clean.target, clean.heldBlocked.affected)}; no release on its line ${upTo}that its own advisories leave clean clears ${clean.heldBlocked.affected.length === 1 ? "it" : "them"}${partial}, so ${clean.target} is NOT a clean fix: confirm a release with dependency_check before pinning it`;
  }
  if (clean.heldUnchecked !== undefined && clean.target) {
    return `whether the dependencies ${clean.target} exact-pins or narrowly ranges are affected was NOT CHECKED (${clean.heldUnchecked}): confirm it with dependency_check before pinning it`;
  }
  return null;
}

/**
 * The minimal clean target for one installed copy, or null when neither the
 * advisories nor anything that changes the answer could be read.
 *
 * Advisories unreadable, registry readable (audit H5: OSV /v1/query down):
 * a deprecated or yanked release is still never the target. lodash 4.17.20
 * went to 4.18.0 ("Bad release") because the whole check was skipped; the
 * registry facts alone move it to 4.18.1, flagged `advisoriesUnread`.
 *
 * With no per-advisory fix at all (advisories that give only `last_affected`,
 * audit A6), and the installed version known, the registry is asked for the
 * first published release above the installed one that no known advisory
 * affects: a fix candidate the advisories never named, flagged
 * `noAdvisoryFix`, instead of "no fix".
 */
export async function cleanFixTarget(
  sources: FixPathSources,
  ecosystem: OsvEcosystem,
  name: string,
  perAdvisoryFixes: string[],
  installed?: string | null,
): Promise<FixTargetResult | null> {
  if (perAdvisoryFixes.length === 0 && !installed) return null;
  const [advisories, facts] = await Promise.all([
    sources.packageAdvisories(ecosystem, name),
    sources.releaseFacts(ecosystem, name),
  ]);
  if (!advisories && !facts && perAdvisoryFixes.length > 0 && WITHDRAWALS_READ.has(ecosystem)) {
    // Neither OSV's list nor the registry answered: the highest per-advisory fix stands, checked
    // against the installed version's advisories only, and the answer says the withdrawal check
    // did not run (lodash 4.18.0, "Bad release", went out with no word of it: final audit 7a).
    const floor = maxVersion(perAdvisoryFixes, ecosystem) ?? perAdvisoryFixes[0];
    return { target: floor, basis: "advisory_fixes", floor, floorAffectedBy: [], stillAffectedBy: [], unfixable: [], withheld: [], advisoriesUnread: true, registryUnread: true };
  }
  if (!advisories) return perAdvisoryFixes.length > 0 && facts ? registryOnlyTarget(ecosystem, perAdvisoryFixes, facts) : null;
  // Every release the registry lists, the withdrawn ones included so the result can name them;
  // `excluded` keeps them from ever being the target (FX-H5).
  const published = facts ? [...facts.versions, ...facts.withdrawn] : null;
  const excluded = facts?.withdrawn ?? [];
  const malware = advisories.filter((a) => a.malware).map((a) => a.id);
  if (perAdvisoryFixes.length > 0) {
    const clean = smallestCleanVersion({ ecosystem, fixes: perAdvisoryFixes, advisories, published, excluded, installed });
    if (!clean) return null;
    if (malware.length > 0) Object.assign(clean, { malware });
    if (clean.target === null && clean.maliciousLanding) Object.assign(clean, { landingNote: malwareText(name, clean.maliciousLanding) });
    return withRegistryFacts({ ...clean, ...(facts?.withdrawn.includes(clean.floor) ? { floorWithdrawn: true } : {}) }, ecosystem, perAdvisoryFixes, advisories, facts);
  }
  // Only a registry list can show a release past a last_affected bound.
  if (!published || published.length === 0) return null;
  const clean = smallestCleanVersion({ ecosystem, fixes: [installed!], advisories, published, excluded, installed });
  if (!clean || clean.target === null || clean.target === installed || clean.stillAffectedBy.length > 0) return null;
  return withRegistryFacts({ ...clean, noAdvisoryFix: true }, ecosystem, [], advisories, facts);
}

/**
 * The registry side of a target: that the registry was not read (so withdrawn releases were
 * not checked), or the words for each withdrawn release and the installable fix for each
 * per-advisory fix the registry withdrew (the app's `installable_fix`: the lowest allowed
 * release above it that the advisories fixed at it do not affect).
 */
function withRegistryFacts(
  clean: FixTargetResult,
  ecosystem: OsvEcosystem,
  fixes: string[],
  advisories: AdvisoryRanges[],
  facts: PackageReleaseFacts | null,
): FixTargetResult {
  // Only the registries whose withdrawals are read (as in the app: Go `retract` and the RubyGems /
  // Packagist readers are not); for the rest there was nothing to check, so nothing to say.
  if (!facts) return WITHDRAWALS_READ.has(ecosystem) ? { ...clean, registryUnread: true } : clean;
  const lineFixes: NonNullable<FixTargetResult["lineFixes"]> = {};
  const published = [...facts.versions, ...facts.withdrawn];
  for (const fix of new Set(fixes)) {
    if (!facts.withdrawn.includes(fix)) continue;
    const fixedHere = advisories.filter((a) => a.spans.some((s) => s.fixed !== null && compareVersions(s.fixed, fix, ecosystem) === 0));
    lineFixes[fix] = installableFix({ ecosystem, fix, advisories: fixedHere, published, excluded: facts.withdrawn });
  }
  const named = new Set([...clean.withheld, ...Object.values(lineFixes).flatMap((l) => l.withheld)]);
  // A withheld version the registry does not list at all (audit A-1) is not called deprecated or yanked.
  const why = (v: string) =>
    facts.withdrawnWhy[v] ?? (isListedVersion(published, v, ecosystem) ? withdrawalText(ecosystem, v) : `${v} is not a release the registry lists`);
  const withheldWhy = Object.fromEntries([...named].map((v) => [v, why(v)]));
  const notice = clean.target ? facts.lineNotices?.[clean.target] : undefined;
  return {
    ...clean,
    ...(named.size > 0 ? { withheldWhy } : {}),
    ...(Object.keys(lineFixes).length > 0 ? { lineFixes } : {}),
    ...(notice ? { targetNotice: lineNoticeText(clean.target!, notice) } : {}),
  };
}

/**
 * With no advisory list: the smallest installable release at or above the
 * highest per-advisory fix, only when that fix itself is withdrawn or not
 * published (otherwise the unchecked answer stands as it is). Null when
 * nothing changes or no installable release qualifies.
 */
function registryOnlyTarget(ecosystem: OsvEcosystem, fixes: string[], facts: PackageReleaseFacts): FixTargetResult | null {
  if (facts.versions.length === 0) return null;
  const published = [...facts.versions, ...facts.withdrawn];
  const clean = smallestCleanVersion({ ecosystem, fixes, advisories: [], published, excluded: facts.withdrawn });
  if (!clean || (clean.target !== null && clean.target === clean.floor)) return null;
  if (clean.target === null && clean.withheld.length === 0) return null;
  return withRegistryFacts({ ...clean, floorWithdrawn: facts.withdrawn.includes(clean.floor), advisoriesUnread: true }, ecosystem, fixes, [], facts);
}

/** #981 (b): an advisory whose ranges cannot be read leaves the release unknown, never skipped silently. */
export function unreadableText(ids: string[]): string {
  return `the affected ranges of ${ids.join(", ")} cannot be read, so whether any release clears ${ids.length === 1 ? "it" : "them"} is unknown: no release is named`;
}

/** The 4DA lead's rule (2026-10-18): no release is offered that brings in an advisory the installed version does not have. */
export function introducesText(ids: string[]): string {
  return `every fixing release brings in ${ids.join(", ")}, which the installed version does not have, so no release is named`;
}

/** #981 round 3: an installed copy a malicious advisory affects names no release; the advice is to remove or replace it. */
export function malwareText(name: string, ids: string[]): string {
  return `${name} is flagged malicious (${ids.join(", ")}): remove or replace ${name}`;
}

/** The words for a target that carries a line-wide deprecation notice (FixTargetResult.targetNotice). */
export function lineNoticeText(version: string, message: string): string {
  const quoted = message.length > 120 ? `${message.slice(0, 117)}...` : message;
  return `${version} is deprecated on npm ("${quoted}"), a notice on its whole line rather than a withdrawn release (no later release on the line is free of it), so it stays the smallest fix without a major upgrade; dependency_check says review for it: tell the user it is deprecated`;
}

/** The ecosystems whose registry withdrawals (yanked, deprecated) are read. */
const WITHDRAWALS_READ: ReadonlySet<string> = new Set(["npm", "crates.io", "PyPI"]);

/** `withheldNote` for a checked target: the withdrawn releases passed, in plain words; null when none. */
export function withheldText(clean: FixTargetResult, ecosystem: string): string | null {
  return withheldNote(clean.withheld, clean.target, clean.withheldWhy ?? {}, ecosystem, clean.stillAffectedBy.length === 0);
}

/**
 * Verified targets for many installed copies at once, within a time budget:
 * the copies that could not be checked in time (or offline) are simply
 * absent from the result, and the caller says so. Keyed by `key`.
 */
export async function verifyFixTargets(
  sources: FixPathSources | null,
  items: Array<{ key: string; ecosystem: OsvEcosystem; name: string; fixes: string[]; installed?: string }>,
  budgetMs: number,
  concurrency = 12,
  options: { heldQuery?: AdvisoryQuery } = {},
): Promise<Map<string, FixTargetResult>> {
  const out = new Map<string, FixTargetResult>();
  const todo = items.filter((i) => i.fixes.length > 0 || i.installed);
  if (!sources || todo.length === 0) return out;
  const deadline = Date.now() + budgetMs;
  let next = 0;
  const worker = async () => {
    while (next < todo.length && Date.now() < deadline) {
      const item = todo[next++];
      let timer: ReturnType<typeof setTimeout> | undefined;
      const late = new Promise<null>((resolve) => {
        timer = setTimeout(() => resolve(null), Math.max(0, deadline - Date.now()));
      });
      try {
        const clean = await Promise.race([cleanFixTarget(sources, item.ecosystem, item.name, item.fixes, item.installed).catch(() => null), late]);
        if (clean) out.set(item.key, clean);
      } finally {
        if (timer !== undefined) clearTimeout(timer);
      }
    }
  };
  await Promise.all(Array.from({ length: Math.min(concurrency, todo.length) }, worker));
  if (options.heldQuery) {
    // npm: what each target installs at a fixed version, in one advisory lookup for all of them
    // (audit 6.2.5 D-4). It gets at least HELD_FLOOR_MS even when the targets used the budget up:
    // without it a cold scan would downgrade every npm target that holds a dependency.
    const npm = todo.filter((i) => i.ecosystem === "npm" && out.has(i.key)).map((i) => ({ key: i.key, name: i.name, installed: i.installed, clean: out.get(i.key)! }));
    const held = await withHeldTargets(sources, options.heldQuery, npm, Math.max(deadline, Date.now() + HELD_FLOOR_MS));
    for (const [key, clean] of held) out.set(key, clean);
  }
  return out;
}

/** The least time the held-dependency check of a scan's npm targets gets (verifyFixTargets). */
const HELD_FLOOR_MS = 3_000;

/** Said whenever the registry could not be read: withdrawn releases are then not ruled out, never silently. */
export const REGISTRY_UNREAD_NOTE = "the registry could not be read, so whether it yanked or deprecated this release was not checked";

/**
 * One clause for a target that is not the highest per-advisory fix, or null when it is.
 * Withdrawn releases passed on the way are named in the registry's own words (FX-H5).
 */
export function targetNote(clean: FixTargetResult, ecosystem = ""): string | null {
  if (clean.heldFrom) {
    // The advisory-side reasoning is about the release the advisories pointed at; the held step follows it.
    const { heldFrom, heldPast: _past, targetNotice, ...rest } = clean;
    const base = targetNote({ ...rest, target: heldFrom }, ecosystem);
    return [base, heldNote(clean), targetNotice ?? null].filter((p): p is string => Boolean(p)).join("; ") || null;
  }
  const held = heldNote(clean);
  if (held) {
    const { heldBlocked: _b, heldUnchecked: _u, ...rest } = clean;
    return [targetNote(rest, ecosystem), held].filter((p): p is string => Boolean(p)).join("; ");
  }
  const withheld = withheldText(clean, ecosystem);
  if (clean.advisoriesUnread) {
    const unchecked = "not checked against the package's other advisories (OSV.dev did not answer)";
    if (clean.registryUnread) return `${clean.target} is the highest per-advisory fix, ${unchecked}; ${REGISTRY_UNREAD_NOTE}`;
    // Not "clean": nothing but the installed version's advisories was checked.
    if (withheld && clean.target) return `${withheld.replace(/ is the smallest clean release$/, " is the smallest installable release past it")}; ${unchecked}`;
    if (withheld) return `${withheld}; ${unchecked}`;
    return `${clean.target} is the smallest installable release at or above ${clean.floor}, the highest per-advisory fix, which ${clean.floorWithdrawn ? "is deprecated or yanked on the registry" : "is not a published release"}; ${unchecked}`;
  }
  const parts: string[] = [];
  if (clean.noAdvisoryFix) {
    parts.push(`no advisory names a fixed version (they give only a last affected one); ${clean.target} is the first published release above the installed version that no known advisory affects`);
    if (withheld) parts.push(withheld);
  } else if (clean.target === null) {
    if (withheld) parts.push(withheld);
  } else if (clean.target !== clean.floor) {
    if (clean.floorAffectedBy.length > 0) {
      parts.push(`${clean.target} is the smallest version clear of every advisory a release fixes; ${clean.floor}, the highest per-advisory fix, is itself affected by ${clean.floorAffectedBy.join(", ")}`);
      if (withheld) parts.push(withheld);
    } else if (withheld) {
      parts.push(withheld);
    } else {
      parts.push(`${clean.target} is the smallest version clear of every advisory a release fixes; ${clean.floor}, the highest per-advisory fix, ${clean.floorWithdrawn ? "is deprecated or yanked on the registry" : "is not a published release"}`);
    }
  }
  if (clean.target && clean.stillAffectedBy.length > 0) {
    parts.push(`${clean.target} ${remainsText(clean.stillAffectedBy)}: ${clean.stillAffectedBy.length === 1 ? "it affects" : "they affect"} every newer release too`);
  }
  if (clean.target === null && clean.unreadable && clean.unreadable.length > 0) parts.push(unreadableText(clean.unreadable));
  if (clean.target === null && clean.landingNote) parts.push(clean.landingNote);
  if (clean.target === null && clean.introduces && clean.introduces.length > 0) parts.push(introducesText(clean.introduces));
  if (clean.registryUnread) parts.push(REGISTRY_UNREAD_NOTE);
  if (clean.targetNotice) parts.push(clean.targetNotice);
  return parts.length > 0 ? parts.join("; ") : null;
}

/**
 * A finding's own fix as the registry still offers it (the app's `installable_fix`): the
 * advisory's fixed version, or, when the registry withdrew it, the release to take instead
 * (null: none past it is known), with the withdrawn ones and the plain-words note.
 */
export function rowFix(
  fixed: string | null,
  clean: FixTargetResult | undefined,
  ecosystem: string,
): { fixed: string | null; withheld: string[]; note: string | null } {
  const line = fixed && clean?.lineFixes?.[fixed];
  if (!fixed || !line) return { fixed, withheld: [], note: null };
  const said = sayWithdrawn(line.withheld, clean.withheldWhy ?? {}, ecosystem);
  const note = line.fix
    ? `${said}; ${line.fix} is the smallest release past it that fixes this advisory`
    : `No installable fix for this advisory: ${said}, and no later release is known to fix it`;
  return { fixed: line.fix, withheld: line.withheld, note };
}

export interface RefreshVerdict {
  /** True when a lockfile refresh reaches a clean version (read, or inferred: see `inferred`). */
  refreshFixes: boolean;
  /**
   * True when no parent's requirement could be read (or not every one) and none
   * excludes the target, so the verdict comes from semver compatibility
   * (4DA AD-055 ¶1): a refresh when the target is caret-compatible with the
   * installed version, the parent otherwise.
   */
  inferred: boolean;
  format: LockfileFormat;
  /** The command, run in the lockfile's directory; for yarn 1 and bun, the manual steps (no command moves one copy in place). */
  command: string;
  /**
   * Parent requirements that do NOT admit a clean version (why it is waiting on upstream).
   * `bundled`: the copy ships inside that parent's tarball, so neither a refresh nor an override reaches it (audit E8).
   */
  blocking: Array<{ parent: string; parentVersion: string | null; requirement: string; bundled?: boolean }>;
  /** The version a refresh resolves to, when the registry's version list was read. */
  resolvesTo: string | null;
}

/**
 * The command that refreshes one transitive copy in place, for the tools it
 * can be named for (4DA AD-055 ¶4); null for yarn 1 and bun, which have none
 * (see `manualRefreshSteps`).
 *
 * pnpm: at a workspace root (`pnpm-workspace.yaml`), `pnpm update <pkg>`
 * touches only the root project's tree, so a member's transitive copy stayed
 * where it was; `-r` reaches every member (measured with pnpm 10.34.6: a
 * member's mkdirp -> minimist 1.2.5 moved to 1.2.8 only with `-r`). `--depth
 * Infinity` is the form the fix-path oracle applied (2026-10-10, U04/U10);
 * pnpm 8.15 to 10.34 also moved a root project's transitive copy without it.
 */
export function refreshCommand(format: LockfileFormat, name: string, installed: string, target: string, workspaceRoot = false): string | null {
  const ecosystem = format === "cargo" ? "crates.io" : "npm";
  if (!isShellSafeName(name, ecosystem) || !isShellSafeVersion(installed) || !isShellSafeVersion(target)) return null;
  switch (format) {
    case "package-lock":
      return `npm update ${name}`;
    case "pnpm":
      return `pnpm update ${workspaceRoot ? "-r " : ""}${name} --depth Infinity`;
    case "yarn-berry":
      return `yarn up -R ${name}`;
    case "yarn":
    case "bun":
      return null;
    case "cargo":
      return `cargo update -p ${name}@${installed} --precise ${target}`;
  }
}

/**
 * Whether an override (npm `overrides`, pnpm `pnpm.overrides`, yarn `resolutions`) can reach the copy
 * these blocking parents hold: never when one of them ships it bundled (rule vectors rv-066..rv-068).
 */
export function overrideReaches(blocking: Array<{ bundled?: boolean }>): boolean {
  return !blocking.some((b) => b.bundled === true);
}

// ---------------------------------------------------------------------------
// Direct upgrades: the command that moves a DECLARED dependency, keeping how it is declared
// ---------------------------------------------------------------------------

/**
 * How a DIRECT dependency moves to its fix target, worded for the tool and the manifest that
 * declares it: a port of the 4DA app's `osv/direct_upgrade.rs` (rule vectors fc-028..fc-053),
 * read from the declaring project's own manifest. A command is named only where it was run
 * against the tool (2026-10-15/16: npm 10.9.2, pnpm 10.34.6, yarn 1.22.22, yarn 4.9.1, cargo
 * 1.95, go 1.24) and moved the dependency while keeping it as declared. Plain `npm install x@v`
 * wrote `^v` over an exact pin and over `~` (readiness review 2026-10-17, finding 4).
 *
 * Null, and the plan keeps its plain "bump it where it is declared", for anything this cannot
 * read with certainty: a dependency declared in two sections; a declared spec that does not
 * admit the installed copy; `>=`, `||`, x-range, tag, git, `workspace:` or alias specs; a git,
 * path or alternate-registry crate; a yarn workspace member (`yarn up` is project-wide); a Go
 * `replace`; hashed or compiled (pip-compile, uv) requirements; bun or an unknown tool.
 */
export type DirectFix =
  | { command: string; refresh?: false }
  /**
   * The declaration ALREADY admits the target (navcal: sharp, next and vite under `^`): the minimal
   * advice is the tool's in-range lockfile refresh, which leaves the manifest untouched, not a bump
   * of the declaration (the 4DA app's DirectFix::Refresh). Each was run on a project declaring
   * `ms ^2.1.1` locked at 2.1.1 (2026-10-18): it moved the lock to 2.1.3 and left package.json
   * unchanged; plain `pnpm update ms` rewrote `^2.1.1` to `^2.1.3`, hence `--no-save`. Cargo:
   * `itoa = "1.0.5"` locked 1.0.11 with Cargo.toml unchanged. Any readable range qualifies,
   * `>=` and `||` included: no operator needs carrying.
   */
  | { command: string; refresh: true }
  | { instruction: string };

type NpmManager = "npm" | "pnpm" | "yarn1" | "yarn-berry";

/** The verified in-range refresh of a DECLARED npm-family dependency (DirectFix refresh). */
function npmDirectRefresh(manager: NpmManager, name: string): string {
  switch (manager) {
    case "npm":
      return `npm update ${name}`;
    case "pnpm":
      return `pnpm update ${name} --no-save`;
    case "yarn1":
      return `yarn upgrade ${name}`;
    case "yarn-berry":
      return `yarn up -R ${name}`;
  }
}

/** How far up from a project directory a workspace lockfile is looked for (the app's MAX_LOCKFILE_ASCENT). */
const MAX_LOCKFILE_ASCENT = 6;

/** The npm-family tool whose lockfile holds the project at `dir`, nearest directory first (yarn, pnpm, npm, as the app). */
function npmManager(dir: string): NpmManager | null {
  let here = path.resolve(dir);
  for (let i = 0; i <= MAX_LOCKFILE_ASCENT; i++) {
    if (fs.existsSync(path.join(here, "yarn.lock"))) {
      let berry = false;
      try {
        berry = fs.readFileSync(path.join(here, "yarn.lock"), "utf-8").split("\n").slice(0, 12).some((l) => l.startsWith("__metadata:"));
      } catch {
        berry = false;
      }
      return berry ? "yarn-berry" : "yarn1";
    }
    if (fs.existsSync(path.join(here, "pnpm-lock.yaml"))) return "pnpm";
    if (fs.existsSync(path.join(here, "package-lock.json"))) return "npm";
    const up = path.dirname(here);
    if (up === here) break;
    here = up;
  }
  return null;
}

function readText(file: string): string | null {
  try {
    return fs.readFileSync(file, "utf-8");
  } catch {
    return null;
  }
}

/** The spec `name` is declared with, when exactly one of dependencies / devDependencies / optionalDependencies holds it. */
export function npmDeclared(packageJson: string, name: string): string | null {
  let pkg: Record<string, Record<string, unknown> | undefined>;
  try {
    pkg = JSON.parse(packageJson);
  } catch {
    return null;
  }
  const found = ["dependencies", "devDependencies", "optionalDependencies"]
    .map((s) => pkg?.[s]?.[name])
    .filter((v): v is string => typeof v === "string");
  return found.length === 1 ? found[0] : null;
}

const PRERELEASE_BASE = /^\d+\.\d+\.\d+-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*$/;
const FULL_SEMVER = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;

/** The operator a declared npm spec carries: "" for an exact pin, "^" or "~"; null for anything else. */
function npmOperator(declared: string): "" | "^" | "~" | null {
  const d = declared.trim();
  const digits = (s: string) => {
    const parts = s.split(".");
    return parts.length >= 1 && parts.length <= 3 && parts.every((p) => /^\d+$/.test(p));
  };
  // The 4DA lead (2026-10-19): a `^` or `~` on a PRERELEASE base (`^2.0.0-rc.4`, `~1.2.3-beta.1`)
  // is bounded too: a full X.Y.Z with prerelease identifiers, no build metadata.
  const base = (s: string) => digits(s) || PRERELEASE_BASE.test(s);
  if (d.startsWith("^")) return base(d.slice(1)) ? "^" : null;
  if (d.startsWith("~")) return base(d.slice(1)) ? "~" : null;
  const exact = (d.startsWith("=") ? d.slice(1) : d).replace(/^v+/, "");
  return FULL_SEMVER.test(exact) ? "" : null;
}

/** The command that moves a declared npm-family dependency, keeping its operator (quoted: `^` is cmd.exe's escape). */
export function npmDirectCommand(manager: NpmManager, declared: string, name: string, target: string): string | null {
  if (!isShellSafeName(name, "npm") || !isShellSafeVersion(target)) return null;
  const op = npmOperator(declared);
  if (op === null) return null;
  const spec = op === "" ? `${name}@${target}` : `"${name}@${op}${target}"`;
  switch (manager) {
    case "npm":
      return op === "" ? `npm install ${spec} --save-exact` : `npm install ${spec}`;
    case "pnpm":
      return `pnpm up ${spec}`;
    case "yarn1":
      return `yarn upgrade ${spec}`;
    case "yarn-berry":
      return `yarn up ${spec}`;
  }
}

interface CargoDecl {
  kind: "normal" | "dev" | "build";
  target: string | null;
  key: string;
  req: string | null;
  workspace: boolean;
  otherSource: boolean;
}

const unquote = (s: string) => s.trim().replace(/^["']+|["']+$/g, "");
const crateKey = (name: string) => name.trim().toLowerCase().replace(/_/g, "-");

/** `[dependencies]`, `[dev-dependencies.foo]`, `[target.'cfg(unix)'.build-dependencies]`, ... */
function cargoTable(header: string): { kind: CargoDecl["kind"]; target: string | null; key: string | null } | null {
  const inner = header.replace(/^\[+/, "").replace(/\]+$/, "").trim();
  let target: string | null = null;
  let rest = inner;
  if (inner.startsWith("target.")) {
    const after = inner.slice("target.".length);
    if (after.startsWith("'") || after.startsWith('"')) {
      const q = after.slice(1);
      const close = q.search(/['"]/);
      if (close < 0) return null;
      target = q.slice(0, close);
      rest = q.slice(close + 1).replace(/^\.+/, "");
    } else {
      const dot = after.indexOf(".");
      if (dot < 0) return null;
      target = after.slice(0, dot);
      rest = after.slice(dot + 1);
    }
  }
  const dot = rest.indexOf(".");
  const section = dot < 0 ? rest : rest.slice(0, dot);
  const key = dot < 0 ? null : unquote(rest.slice(dot + 1));
  const kind = section === "dependencies" ? "normal" : section === "dev-dependencies" ? "dev" : section === "build-dependencies" ? "build" : null;
  return kind ? { kind, target, key } : null;
}

/** Every declaration of `crate` in a Cargo.toml (by crate name, so a renamed dependency is found through `package = ...`). */
export function cargoDeclarations(manifest: string, crate: string): CargoDecl[] {
  const want = crateKey(crate);
  type Fields = { req: string | null; pkg: string | null; workspace: boolean; otherSource: boolean };
  const found: Array<{ kind: CargoDecl["kind"]; target: string | null; key: string; f: Fields }> = [];
  let table: ReturnType<typeof cargoTable> = null;
  const set = (f: Fields, field: string, value: string) => {
    if (field === "version") f.req = unquote(value);
    else if (field === "package") f.pkg = unquote(value);
    else if (field === "workspace") f.workspace ||= value.trim() === "true";
    else if (field === "git" || field === "path" || field === "registry") f.otherSource = true;
  };
  for (const raw of manifest.split("\n")) {
    const line = (raw.split("#")[0] ?? "").trim();
    if (line.startsWith("[")) {
      table = cargoTable(line);
      continue;
    }
    const eq = line.indexOf("=");
    if (!table || eq < 0) continue;
    const k = unquote(line.slice(0, eq));
    const v = line.slice(eq + 1);
    let key: string;
    let field: string | null;
    if (table.key !== null) {
      key = table.key;
      field = k;
    } else {
      const dot = k.indexOf(".");
      if (dot >= 0) {
        key = unquote(k.slice(0, dot));
        field = k.slice(dot + 1).trim();
      } else {
        key = k;
        field = null;
      }
    }
    let slot = found.find((d) => d.kind === table!.kind && d.target === table!.target && d.key === key);
    if (!slot) {
      slot = { kind: table.kind, target: table.target, key, f: { req: null, pkg: null, workspace: false, otherSource: false } };
      found.push(slot);
    }
    if (field !== null) set(slot.f, field, v);
    else if (v.trimStart().startsWith("{")) {
      const body = v.trim().replace(/^\{/, "").replace(/\}$/, "");
      for (const kv of body.split(",")) {
        const at = kv.indexOf("=");
        if (at >= 0) set(slot.f, kv.slice(0, at).trim(), kv.slice(at + 1).trim());
      }
    } else slot.f.req = unquote(v);
  }
  return found
    .filter((d) => crateKey(d.f.pkg ?? d.key) === want)
    .map((d) => ({ kind: d.kind, target: d.target, key: d.key, req: d.f.req, workspace: d.f.workspace, otherSource: d.f.otherSource }));
}

/** The fix for one Cargo declaration. */
function cargoDirect(decl: CargoDecl, crate: string, target: string): DirectFix | null {
  if (decl.otherSource) return null;
  if (decl.workspace) {
    return {
      instruction: `bump ${crate} to ${target} in the workspace root's [workspace.dependencies] (it is inherited here; \`cargo add\` in this crate would replace the inheritance with a local pin)`,
    };
  }
  // Every value spliced below comes from the project's own Cargo.toml or lockfile (C-1).
  const keyRenamed = crateKey(decl.key) !== crateKey(crate);
  if (
    !isShellSafeName(crate, "crates.io") ||
    !isShellSafeVersion(target) ||
    (decl.target !== null && !isShellSafeCargoTarget(decl.target)) ||
    (keyRenamed && !isShellSafeName(decl.key, "crates.io"))
  ) {
    return { instruction: `bump the ${isShellSafeName(crate, "crates.io") ? crate : "dependency"} requirement in Cargo.toml so it admits the fixed release (no command is named: the declaration holds characters that are unsafe in a command)` };
  }
  const r = decl.req?.trim() ?? "";
  const op = r.startsWith("=") ? "=" : r.startsWith("~") ? "~" : r.startsWith("^") ? "^" : /^\d/.test(r) ? "" : null;
  if (op === null) return null;
  let cmd = `cargo add ${op === "" ? `${crate}@${target}` : `"${crate}@${op}${target}"`}`;
  if (decl.kind === "dev") cmd += " --dev";
  if (decl.kind === "build") cmd += " --build";
  // Double quotes: cmd.exe keeps single quotes as part of the argument.
  if (decl.target) cmd += ` --target "${decl.target}"`;
  if (crateKey(decl.key) !== crateKey(crate)) cmd += ` --rename ${decl.key}`;
  return { command: cmd };
}

/** `go get <module>@v<target>` when go.mod requires the module directly at `installed` and no `replace` points it elsewhere. */
export function goDirectCommand(goMod: string, module: string, installed: string, target: string): string | null {
  if (!isShellSafeName(module, "Go") || !isShellSafeVersion(installed) || !isShellSafeVersion(target)) return null;
  const v = (s: string) => (s.startsWith("v") ? s : `v${s}`);
  let inRequire = false;
  let inReplace = false;
  let requiredAt: string | null = null;
  for (const raw of goMod.split("\n")) {
    const line = raw.trim();
    if (line === "require (") inRequire = true;
    else if (line === "replace (") inReplace = true;
    else if (line === ")") inRequire = inReplace = false;
    const replaced = inReplace ? line : line.startsWith("replace ") ? line.slice("replace ".length) : null;
    if (replaced !== null && replaced.split(/\s+/)[0] === module) return null;
    const entry = inRequire ? line : line.startsWith("require ") ? line.slice("require ".length) : null;
    if (entry !== null && !entry.includes("// indirect")) {
      const parts = entry.split(/\s+/);
      if (parts[0] === module) requiredAt = parts[1] ?? null;
    }
  }
  return requiredAt !== null && requiredAt === v(installed) ? `go get ${module}@${v(target)}` : null;
}

/** The edit of the requirements line that pins the package with `==` at `installed` (markers, extras kept). */
export function pypiDirectInstruction(requirements: string, file: string, name: string, installed: string, target: string): string | null {
  const lines = requirements.split("\n");
  // Compiled output (pip-compile, and `uv pip compile`, whose header the old check missed, or any
  // file with `# via` annotations) is regenerated from its input: a hand edit is reverted, and an
  // indirect pin conflicts with its parent (audit 6.2.5 A-4). pypi-advice.ts words the re-compile.
  if (compiledRequirements(requirements)) return null;
  const norm = (s: string) => s.toLowerCase().replace(/[_.]/g, "-");
  const want = norm(name);
  for (const [i, raw] of lines.entries()) {
    const line = raw.trim();
    const at = line.indexOf("==");
    if (at < 0) continue;
    const head = line.slice(0, at);
    const rest = line.slice(at + 2);
    if (norm((head.split("[")[0] ?? head).trim()) !== want) continue;
    const endAt = rest.search(/[;\\#\s]/);
    const end = endAt < 0 ? rest.length : endAt;
    const version = rest.slice(0, end);
    const tail = rest.slice(end);
    const continued = line.endsWith("\\") || line.includes("--hash") || (lines[i + 1]?.trimStart().startsWith("--hash") ?? false);
    if (continued || version !== installed) continue;
    return `change \`${line}\` to \`${head}==${target}${tail}\` in ${file}`;
  }
  return null;
}

/**
 * The fix for `name` at `installed`, declared in the project at `projectDir`, read from its own
 * manifest; null when it cannot be named with certainty (see DirectFix).
 */
export function directFix(projectDir: string, ecosystem: string, name: string, installed: string, target: string): DirectFix | null {
  const read = (file: string) => readText(path.join(projectDir, file));
  switch (ecosystem) {
    case "npm": {
      const manager = npmManager(projectDir);
      if (!manager) return null;
      // yarn's up / upgrade act on the whole workspace: from a member they rewrite siblings too.
      if ((manager === "yarn1" || manager === "yarn-berry") && !fs.existsSync(path.join(projectDir, "yarn.lock"))) return null;
      const json = read("package.json");
      const declared = json === null ? null : npmDeclared(json, name);
      if (declared === null || npmRangeAdmits(declared, installed) !== true) return null;
      // In an npm workspace member too, run in the member's directory: on lockfiles npm wrote,
      // `npm update ms` there moved a member's own ^2.1.1 copy (hoisted and nested layouts, npm
      // 10.9.2, 2026-10-18). An earlier "it does not move" came from a hand-edited fixture lockfile
      // that carried 1.2.8's integrity under version 1.2.5.
      // Only a range bounded below the next major (`^`, `~`) is refreshed: a refresh installs the
      // NEWEST release in range, so a `>=` / `||` / `*` / x-range could jump a major or land on a
      // withdrawn or held release, and names nothing (fc-059, the app's npm_direct_fix).
      const op = npmOperator(declared);
      const bounded = op === "^" || op === "~";
      if (bounded && npmRangeAdmits(declared, target) === true) return isShellSafeName(name, "npm") ? { command: npmDirectRefresh(manager, name), refresh: true } : null;
      const command = npmDirectCommand(manager, declared, name, target);
      return command ? { command } : null;
    }
    case "crates.io": {
      const manifest = read("Cargo.toml");
      if (manifest === null) return null;
      const decls = cargoDeclarations(manifest, name);
      if (decls.length !== 1) return null;
      const [only] = decls;
      const admits = only.req !== null ? cargoReqAdmits(only.req, installed) === true : only.workspace;
      // A workspace-inherited, git, path or alternate-registry entry is never refreshed this way.
      if (admits && only.req !== null && !only.workspace && !only.otherSource && cargoReqAdmits(only.req, target) === true) {
        const command = refreshCommand("cargo", name, installed, target);
        return command ? { command, refresh: true } : null;
      }
      return admits ? cargoDirect(only, name, target) : null;
    }
    case "Go": {
      const goMod = read("go.mod");
      const command = goMod === null ? null : goDirectCommand(goMod, name, installed, target);
      return command ? { command } : null;
    }
    case "PyPI": {
      // A pin in a file included with `-r` is declared too, and edited there (audit 7g).
      const files = ["requirements.txt", "requirements-dev.txt", "requirements/base.txt"];
      for (let i = 0; i < files.length && i < 16; i++) {
        const body = read(files[i]);
        if (body === null) continue;
        const instruction = pypiDirectInstruction(body, files[i], name, installed, target);
        if (instruction) return { instruction };
        for (const { option, target: inc } of requirementOptions(body)) {
          const included = option === "r" ? confinedInclude(path.dirname(path.join(projectDir, files[i])), inc, projectDir) : null;
          const rel = included ? path.relative(projectDir, included).replace(/\\/g, "/") : null;
          if (rel && !files.includes(rel)) files.push(rel);
        }
      }
      return null;
    }
    default:
      return null;
  }
}

/** For a lockfile with no in-place refresh command (yarn 1, bun): the steps that move the copy. */
export function manualRefreshSteps(format: "yarn" | "bun", name: string): string {
  // The steps are read and followed; a name a shell would read specially is not echoed into them (C-1).
  if (!isShellSafeName(name, "npm")) return `refresh this package's ${format === "yarn" ? "yarn.lock" : "bun.lock"} entries by hand: its name contains characters that are unsafe in a command`;
  // Yarn 1 keys a block by every spec that resolved to it, and an alias block's
  // first key names the alias ("string-width-cjs@npm:string-width@^4.2.0"), so
  // name both forms. Deleting the entries and reinstalling is what moved the
  // copy in the fix-path oracle (case U11).
  return format === "yarn"
    ? `delete every yarn.lock entry that resolves to ${name} (keys "${name}@…" and alias keys "…@npm:${name}@…"), then run yarn install`
    : `delete the ${name} entries from bun.lock, then run bun install`;
}

/** Whether a pnpm lockfile sits at a workspace root (`pnpm-workspace.yaml` beside it). */
function isPnpmWorkspaceRoot(lockfile: string): boolean {
  return fs.existsSync(path.join(path.dirname(lockfile), "pnpm-workspace.yaml"));
}

/** The refresh command for the project whose lockfile is `lockfile`; null when no command is named for it. */
export function refreshCommandFor(lockfile: string, name: string, installed: string, target: string): string | null {
  let content: string;
  try {
    content = fs.readFileSync(lockfile, "utf-8");
  } catch {
    return null;
  }
  const format = lockfileFormat(lockfile, content);
  return format ? refreshCommand(format, name, installed, target, format === "pnpm" && isPnpmWorkspaceRoot(lockfile)) : null;
}

/**
 * Whether refreshing `lockfile` moves `name@installed` to a clean version
 * without any parent changing its declared requirement: `refreshRule` over
 * every requirement the parents declare (read from the lockfile, else the
 * parent's registry metadata). Null when the lockfile cannot be read or no
 * verdict is possible (the caller keeps "waiting on upstream", the
 * conservative answer).
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
  const dialect: RequirementDialect = isCargo ? "cargo" : "npm";
  // A maintenance notice never makes a copy unclean (#994 review).
  const clean = (v: string) => !advisories || !advisories.some((a) => !a.maintenance && advisoryAffects(a, v, ecosystem));
  const releases = (published ?? []).filter((v) => !isPrereleaseVersion(v, ecosystem));

  const edgeReqs = await Promise.all(parents.edges.map((edge) => requirementsOf(sources, ecosystem, edge, name)));
  const reqs: Array<ParentRequirement & { edge: ParentEdge }> = [];
  for (const [i, edge] of parents.edges.entries()) {
    const all = edgeReqs[i];
    if (all === null || all.length === 0) {
      reqs.push({ parent: edge.parent, text: null, dialect, edge }); // not read: the rule cannot count it as admitting
      continue;
    }
    // A parent can declare the same crate twice under different names (feature-gated
    // `mio-0_6` / `mio-0_7` aliases): only the requirements this copy satisfies apply.
    const asReq = (text: string): ParentRequirement => ({ parent: edge.parent, text, dialect });
    const matching = all.filter((text) => requirementAdmits(asReq(text), installed) === true);
    for (const text of new Set(matching.length > 0 ? matching : all)) reqs.push({ ...asReq(text), edge });
  }
  const rule = refreshRule(installed, target, reqs);
  if (rule.verdict === "unknown") return null;

  const blocking: RefreshVerdict["blocking"] = [];
  const block = (r: (typeof reqs)[number]) =>
    blocking.push({ parent: r.edge.parent, parentVersion: r.edge.parentVersion, requirement: r.text ?? "", ...(r.edge.bundled ? { bundled: true } : {}) });
  for (const r of reqs) if (requirementAdmits(r, target) === false) block(r);

  let resolvesTo: string | null = null;
  if (rule.verdict === "refresh" && !rule.inferred) {
    if (isCargo) {
      // `cargo update --precise` moves to exactly the clean target, which every requirement admits.
      resolvesTo = target;
    } else if (releases.length > 0) {
      // npm, pnpm, yarn and bun resolve each requirement to its newest match, which must be clean too.
      for (const r of reqs) {
        const newest = releases
          .filter((v) => requirementAdmits(r, v) === true)
          .sort((a, b) => compareVersions(b, a, ecosystem))[0];
        if (!newest || compareVersions(newest, target, ecosystem) < 0 || !clean(newest)) block(r);
        else if (!resolvesTo || compareVersions(newest, resolvesTo, ecosystem) < 0) resolvesTo = newest;
      }
    }
  }
  const refreshFixes = rule.verdict === "refresh" && blocking.length === 0;
  const named = refreshCommand(parents.format, name, installed, target, parents.format === "pnpm" && isPnpmWorkspaceRoot(lockfile));
  let command = named ?? manualRefreshSteps(parents.format === "bun" ? "bun" : "yarn", name);
  if (isCargo && refreshFixes) {
    let content: string;
    try {
      content = fs.readFileSync(lockfile, "utf-8");
    } catch {
      return null;
    }
    const prereqs = await cargoPrecisePrerequisites(sources, content, name, installed, target);
    if (prereqs === null) return null;
    if (prereqs.some((p) => !/^[A-Za-z0-9_-]+(?:@[0-9A-Za-z.+_-]+)?$/.test(p))) return null;
    if (prereqs.length > 0) command = `cargo update ${prereqs.map((p) => `-p ${p}`).join(" ")} && ${command}`;
  }
  return {
    refreshFixes,
    inferred: rule.inferred,
    format: parents.format,
    command,
    blocking,
    resolvesTo: refreshFixes ? resolvesTo : null,
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
