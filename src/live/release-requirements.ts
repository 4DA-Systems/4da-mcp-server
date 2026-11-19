// SPDX-License-Identifier: Apache-2.0
/**
 * What a crates.io, PyPI or Go release requires, and which of those requirements carry advisories.
 *
 * A release's own advisories are not the whole answer to "is this a clean thing to install": npm's
 * answer already counts what a release holds (held-dependencies.ts). The same question on the other
 * registries, each by its own rule:
 * - Go: the `require` lines of a release's go.mod are minimums. Minimal version selection gives a
 *   project that takes the release at least those versions, and the project's own newer selection
 *   wins, so each required module is judged at the version the project would end up with. An
 *   affected one is a minimum the project can raise in its own go.mod (`minimum`), never a hold.
 * - crates.io and PyPI: a requirement is a range, and an install takes the newest release it
 *   admits. One whose newest admitted release is affected is held, as on npm; an exact pin is
 *   judged as written.
 *
 * One OSV lookup covers every requirement of every release asked about (AdvisoryQuery: batched,
 * cached, rate-limited). Fail closed: a requirement list, a required package's release list or
 * OSV's answer that cannot be had leaves the release `unchecked` with the reason, and so does a
 * list longer than the cap; a concrete finding still stands.
 */

import { advisoryHits, answerFailure, byDeadline, type AdvisoryHit, type AdvisoryQuery, type HeldCheck, type HeldDependency, type HeldFacts } from "./held-dependencies.js";
import { advisoriesAffecting, isPrereleaseVersion, type AdvisoryRanges } from "./osv-ranges.js";
import { cargoReqAdmits } from "./range-satisfies.js";
import type { RegistryLookup, ReleaseMetadataSource, ReleaseRequirement, ReleaseRequirements } from "./release-metadata.js";
import { compareVersions, isComparable, parsePep440 } from "./version-compare.js";
import type { OsvEcosystem, ResolvedDependency } from "./types.js";
import { pep440SpecAdmits, rangeNamesPrerelease } from "../tools/dependency-check-versions.js";
import { quoteThirdParty } from "../untrusted-text.js";
import { markerApplies } from "./pep508-marker.js";

/** PyPI: whether a marker-gated requirement is installed for the project, as HeldDependency.condition; "drop" when on none of its Pythons. */
function requirementCondition(requirement: ReleaseRequirement, pythons: readonly string[] | null | undefined): HeldDependency["condition"] | "drop" | undefined {
  if (!requirement.conditional) return undefined;
  if (requirement.marker === undefined) return { marker: null, uncertain: true };
  const applies = markerApplies(requirement.marker, pythons);
  if (applies.kind === "none") return "drop";
  if (applies.kind === "all") return undefined;
  if (applies.kind === "some") return { marker: requirement.marker, on: applies.on };
  return { marker: requirement.marker, uncertain: true, ...(applies.on ? { on: applies.on } : {}) };
}

/** The registries whose releases' requirements are read here (npm: held-dependencies.ts). */
export type RequirementEcosystem = "crates.io" | "PyPI" | "Go";

export function isRequirementEcosystem(ecosystem: string): ecosystem is RequirementEcosystem {
  return ecosystem === "crates.io" || ecosystem === "PyPI" || ecosystem === "Go";
}

/** Requirements judged per release at most; a longer list leaves the release unchecked. */
export const MAX_REQUIREMENTS_EXAMINED: Record<RequirementEcosystem, number> = { Go: 300, "crates.io": 60, PyPI: 40 };
/** Release lists of required packages read at once (crates.io, PyPI). */
const FACTS_CONCURRENCY = 8;
/** Affected Go modules whose clearing release is looked up, per call. */
const MAX_FIX_LOOKUPS = 8;

/** The lookups a requirement check makes. FixPathSources supplies the last three. */
export interface RequirementSources {
  /** Whether this ecosystem's reader reads requirement lists at all. */
  reads(ecosystem: RequirementEcosystem): boolean;
  /** The release's own requirement list (asked only where `reads`). */
  requirements(ecosystem: RequirementEcosystem, name: string, version: string): Promise<RegistryLookup<ReleaseRequirements>>;
  releaseFacts(ecosystem: OsvEcosystem, name: string): Promise<HeldFacts | null>;
  packageAdvisories(ecosystem: OsvEcosystem, name: string): Promise<AdvisoryRanges[] | null>;
  publishedVersions(ecosystem: OsvEcosystem, name: string): Promise<string[] | null>;
}

/** RequirementSources over a live layer's release readers (getReleaseSources) and fix-path sources (getFixPathSources). */
export function requirementSources(
  readers: Partial<Record<string, ReleaseMetadataSource>>,
  fix: Pick<RequirementSources, "releaseFacts" | "packageAdvisories" | "publishedVersions">,
): RequirementSources {
  return {
    reads: (ecosystem) => typeof readers[ecosystem]?.getRequirements === "function",
    requirements: (ecosystem, name, version) =>
      readers[ecosystem]?.getRequirements?.(name, version) ?? Promise.resolve({ status: "unreachable" as const, detail: "requirement lists are not read for this registry" }),
    releaseFacts: (ecosystem, name) => fix.releaseFacts(ecosystem, name),
    packageAdvisories: (ecosystem, name) => fix.packageAdvisories(ecosystem, name),
    publishedVersions: (ecosystem, name) => fix.publishedVersions(ecosystem, name),
  };
}

export interface RequirementOptions {
  /** When the check stops waiting (epoch ms). */
  deadline: number;
  /** Go: the version of a module the project's own go.mod / go.sum already selects, or null. */
  selected?: (ecosystem: RequirementEcosystem, name: string) => string | null;
  /**
   * PyPI: the Python versions the project declares (project-python.ts `covers`), or null when it
   * declares none. A requirement whose environment marker no declared Python satisfies is dropped;
   * one that applies on some is judged and says on which; one whose marker cannot be settled
   * (no declared Python, a platform variable) is judged as a caveat (`condition.uncertain`).
   */
  pythons?: readonly string[] | null;
}

export interface RequirementRelease {
  /** The caller's key for this release in the answer. */
  key: string;
  ecosystem: RequirementEcosystem;
  name: string;
  version: string;
}

const CARGO_EXACT = /^=\s*(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)(?:\+[0-9A-Za-z.-]+)?$/;
const PEP440_EXACT = /^={2,3}\s*([^,*\s]+)$/;

/**
 * The release an install of a crates.io or PyPI requirement gets: the pin, or the newest release
 * the requirement admits (stable ones first, as cargo and pip choose). Null when it cannot be said.
 */
export function resolveRequirement(ecosystem: "crates.io" | "PyPI", spec: string, facts: HeldFacts | null | undefined): { version: string; exact: boolean } | null {
  const text = spec.trim();
  if (ecosystem === "crates.io") {
    const pin = CARGO_EXACT.exec(text);
    if (pin) return { version: pin[1], exact: true };
  } else {
    const pin = PEP440_EXACT.exec(text);
    if (pin && parsePep440(pin[1])) return { version: pin[1], exact: true };
  }
  if (!facts) return null;
  const admits = (v: string) => (ecosystem === "crates.io" ? cargoReqAdmits(text, v) === true : text === "" ? true : pep440SpecAdmits(text, v) === true);
  const admitted = facts.versions.filter((v) => isComparable(v, ecosystem) && admits(v));
  const stable = admitted.filter((v) => !isPrereleaseVersion(v, ecosystem));
  // A prerelease only where the requirement names one, or admits nothing else (pip's own fallback).
  const namesPrerelease = ecosystem === "PyPI" ? rangeNamesPrerelease("PyPI", text) : text.includes("-");
  const pool = stable.length > 0 && !namesPrerelease ? stable : admitted;
  const newest = pool.reduce<string | null>((max, v) => (max === null || compareVersions(v, max, ecosystem) > 0 ? v : max), null);
  return newest === null ? null : { version: newest, exact: false };
}

function lookupDep(ecosystem: RequirementEcosystem, name: string, version: string): ResolvedDependency {
  return { name, version, ecosystem, isDev: false, isDirect: false, devScopeKnown: false, target: null, platformActive: true, sourceDirs: [] };
}

const REGISTRY_NAME: Record<RequirementEcosystem, string> = { "crates.io": "crates.io", PyPI: "PyPI", Go: "the Go module proxy" };

/** Run `work` over `items`, at most `limit` at a time, stopping at `deadline`. */
async function pooled<T>(items: T[], limit: number, deadline: number, work: (item: T) => Promise<void>): Promise<void> {
  let next = 0;
  await Promise.all(
    Array.from({ length: Math.min(limit, items.length) }, async () => {
      while (next < items.length && Date.now() < deadline) await work(items[next++]);
    }),
  );
}

interface Judged {
  requirement: ReleaseRequirement;
  condition?: HeldDependency["condition"];
  /** The version an install gets; null when it could not be resolved. */
  version: string | null;
  exact: boolean;
  selected: boolean;
}

/**
 * For each release, which of its requirements an advisory affects. A release whose ecosystem's
 * reader reads no requirement list is absent from the answer (nothing was judged, and nothing is
 * claimed about it).
 */
export async function requirementAdvisories(
  sources: RequirementSources,
  query: AdvisoryQuery,
  releases: RequirementRelease[],
  options: RequirementOptions,
): Promise<Map<string, HeldCheck>> {
  const { deadline } = options;
  const out = new Map<string, HeldCheck>();
  const lists = new Map<string, ReleaseRequirements>();
  /** Releases whose list was cut at the cap: key -> how many it declares. */
  const cut = new Map<string, number>();
  const readable: RequirementRelease[] = [];
  const asked = releases.filter((release) => sources.reads(release.ecosystem));
  await pooled(asked, FACTS_CONCURRENCY, deadline, async (release) => {
    const lookup = await byDeadline<RegistryLookup<ReleaseRequirements> | null>(sources.requirements(release.ecosystem, release.name, release.version), deadline, null);
    if (lookup === null) return;
    if (lookup.status !== "ok") out.set(release.key, { status: "unchecked", reason: `its requirement list could not be read from ${REGISTRY_NAME[release.ecosystem]} (${quoteThirdParty(lookup.detail, 120)})` });
    else {
      const cap = MAX_REQUIREMENTS_EXAMINED[release.ecosystem];
      // A requirement no declared Python installs is not one of this project's (PyPI markers).
      const applying = lookup.data.requirements.filter((r) => requirementCondition(r, options.pythons) !== "drop");
      if (applying.length > cap) cut.set(release.key, applying.length);
      lists.set(release.key, { ...lookup.data, requirements: applying.slice(0, cap) });
      readable.push(release);
    }
  });
  // A release not read before the deadline is unchecked, not absent (absent means "no reader").
  for (const release of asked) {
    if (!out.has(release.key) && !lists.has(release.key)) out.set(release.key, { status: "unchecked", reason: "its requirement list could not be read in time" });
  }

  // crates.io and PyPI: the release list of each required package whose requirement is a range.
  const ranged = new Map<string, { ecosystem: "crates.io" | "PyPI"; name: string }>();
  for (const release of readable) {
    if (release.ecosystem === "Go") continue;
    for (const r of lists.get(release.key)!.requirements) {
      if (resolveRequirement(release.ecosystem, r.spec, null) === null) ranged.set(`${release.ecosystem}\0${r.name}`, { ecosystem: release.ecosystem, name: r.name });
    }
  }
  const facts = new Map<string, HeldFacts | null>();
  await pooled([...ranged.entries()], FACTS_CONCURRENCY, deadline, async ([key, { ecosystem, name }]) => {
    facts.set(key, await byDeadline(sources.releaseFacts(ecosystem, name), deadline, null));
  });

  const judged = new Map<string, Judged[]>();
  const wanted = new Map<string, ResolvedDependency>();
  for (const release of readable) {
    const eco = release.ecosystem;
    const rows = lists.get(release.key)!.requirements.map((requirement): Judged => {
      if (eco === "Go") {
        const own = options.selected?.("Go", requirement.name) ?? null;
        const raised = own !== null && isComparable(own, "Go") && compareVersions(own, requirement.spec, "Go") > 0;
        return { requirement, version: raised ? own : requirement.spec, exact: false, selected: raised };
      }
      const resolved = resolveRequirement(eco, requirement.spec, facts.get(`${eco}\0${requirement.name}`));
      const condition = requirementCondition(requirement, options.pythons);
      return { requirement, version: resolved?.version ?? null, exact: resolved?.exact ?? false, selected: false, ...(condition && condition !== "drop" ? { condition } : {}) };
    });
    judged.set(release.key, rows);
    for (const row of rows) if (row.version) wanted.set(`${eco}\0${row.requirement.name}@${row.version}`, lookupDep(eco, row.requirement.name, row.version));
  }

  let failure: string | null = null;
  const hits = new Map<string, AdvisoryHit>();
  if (wanted.size > 0) {
    const answer = await byDeadline(query([...wanted.values()]), deadline, null);
    failure = answerFailure(answer);
    if (!failure && answer) {
      for (const eco of new Set(readable.map((r) => r.ecosystem))) {
        for (const [copy, hit] of advisoryHits(answer.vulnerabilities.filter((v) => v.ecosystem === eco))) hits.set(`${eco}\0${copy}`, hit);
      }
    }
  }

  const affectedOf = new Map<string, HeldDependency[]>();
  for (const release of readable) {
    const affected = judged.get(release.key)!.flatMap((row): HeldDependency[] => {
      const hit = row.version ? hits.get(`${release.ecosystem}\0${row.requirement.name}@${row.version}`) : undefined;
      if (!hit || !row.version) return [];
      return [
        {
          name: row.requirement.name,
          spec: row.requirement.spec,
          exact: row.exact,
          version: row.version,
          ids: hit.ids,
          severity: hit.severity,
          ...(hit.unread ? { unread: true as const } : {}),
          ...(release.ecosystem === "Go" ? { minimum: true as const, fixedIn: null } : {}),
          ...(row.selected ? { selected: true as const } : {}),
          ...(row.requirement.indirect ? { indirect: true as const } : {}),
          ...(row.condition ? { condition: row.condition } : {}),
        },
      ];
    });
    affectedOf.set(release.key, affected);
  }
  // Go: the smallest release that clears each affected minimum, so the answer can say what to raise it to.
  const goAffected = [...affectedOf.values()].flat().filter((d) => d.minimum);
  if (goAffected.length > 0) {
    const fixes = await clearingReleases(sources, query, goAffected, deadline);
    for (const d of goAffected) d.fixedIn = fixes.get(`${d.name}@${d.version}`) ?? null;
  }

  for (const release of readable) {
    const affected = affectedOf.get(release.key)!;
    const rows = judged.get(release.key)!;
    const list = lists.get(release.key)!;
    const unresolved = rows.filter((row) => !row.version).map((row) => `${row.requirement.name} "${row.requirement.spec}"`);
    const total = cut.get(release.key);
    if (affected.length > 0) out.set(release.key, { status: "checked", affected, examined: rows.length, ...(list.unreadable > 0 ? { unreadable: list.unreadable } : {}) });
    else if (unresolved.length > 0) {
      out.set(release.key, {
        status: "unchecked",
        reason: `the releases ${unresolved.slice(0, 3).join(", ")}${unresolved.length > 3 ? ` and ${unresolved.length - 3} more` : ""} admit could not be read from ${REGISTRY_NAME[release.ecosystem]}`,
      });
    } else if (failure && rows.length > 0) out.set(release.key, { status: "unchecked", reason: failure });
    else if (total !== undefined) out.set(release.key, { status: "unchecked", reason: `only the first ${rows.length} of the ${total} requirements it declares were examined` });
    else out.set(release.key, { status: "checked", affected: [], examined: rows.length, ...(list.unreadable > 0 ? { unreadable: list.unreadable } : {}) });
  }
  return out;
}

/**
 * Go: per affected `module@version`, the smallest stable release above it that the module's
 * advisory list leaves clean and OSV.dev's batch query confirms clean. Absent (read as none known)
 * when the list or the proxy could not be read, when nothing clears them, or when the batch query
 * does not confirm it: a release is never named clean on the list alone.
 */
async function clearingReleases(sources: RequirementSources, query: AdvisoryQuery, affected: HeldDependency[], deadline: number): Promise<Map<string, string>> {
  const unique = [...new Map(affected.map((d) => [`${d.name}@${d.version}`, d])).values()].slice(0, MAX_FIX_LOOKUPS);
  const candidates = new Map<string, { name: string; version: string }>();
  await pooled(unique, FACTS_CONCURRENCY, deadline, async (d) => {
    const [advisories, versions] = await Promise.all([
      byDeadline(sources.packageAdvisories("Go", d.name), deadline, null),
      byDeadline(sources.publishedVersions("Go", d.name), deadline, null),
    ]);
    if (!advisories || !versions) return;
    const clean = versions
      .map((v) => (v.startsWith("v") ? v : `v${v}`))
      .filter((v) => isComparable(v, "Go") && !isPrereleaseVersion(v, "Go") && compareVersions(v, d.version, "Go") > 0 && advisoriesAffecting(advisories, v, "Go").length === 0)
      .sort((a, b) => compareVersions(a, b, "Go"))[0];
    if (clean) candidates.set(`${d.name}@${d.version}`, { name: d.name, version: clean });
  });
  const out = new Map<string, string>();
  if (candidates.size === 0) return out;
  const answer = await byDeadline(query([...candidates.values()].map((c) => lookupDep("Go", c.name, c.version))), deadline, null);
  if (answerFailure(answer) || !answer) return out;
  const hits = advisoryHits(answer.vulnerabilities.filter((v) => v.ecosystem === "Go"));
  for (const [key, c] of candidates) if (!hits.has(`${c.name}@${c.version}`)) out.set(key, c.version);
  return out;
}

/**
 * What release `version` of `name` requires, and which of those requirements carry advisories.
 * `checked` with `affected` empty: every requirement was judged and none is affected. `unchecked`:
 * it could not be said, and why. Null: this ecosystem's requirement lists are not read (npm's held
 * dependencies are judged by held-dependencies.ts heldAdvisories).
 *
 * An affected requirement of a Go release is a minimum (`minimum`), judged at the version the
 * project ends up with (`options.selected`), with the release that clears it (`fixedIn`); of a
 * crates.io or PyPI release it is held: `version` is the newest release `spec` admits, or the pin.
 */
export async function releaseRequirements(
  sources: RequirementSources,
  query: AdvisoryQuery,
  release: { ecosystem: string; name: string; version: string },
  options: RequirementOptions,
): Promise<HeldCheck | null> {
  if (!isRequirementEcosystem(release.ecosystem)) return null;
  const answer = await requirementAdvisories(sources, query, [{ key: "release", ecosystem: release.ecosystem, name: release.name, version: release.version }], options);
  return answer.get("release") ?? null;
}
