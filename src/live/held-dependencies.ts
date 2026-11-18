// SPDX-License-Identifier: Apache-2.0
/**
 * Held dependencies: what an npm release installs whatever the project's lockfile holds.
 *
 * A release's own advisories are not the whole answer to "is this a clean fix". express 4.20.0
 * exact-pins qs 6.11.0 (3 advisories), cookie 0.6.0, body-parser 1.20.3 and path-to-regexp
 * 0.1.10; installing it installs them. vulnerability_scan and dependency_check named it the clean
 * fix for NodeGoat's express 4.16.4, judged on express's own advisories alone, and agents wrote it
 * in 2 of 2 headless runs (audit 6.2.5 D-4). The same holds one step wider: express 4.22.0 to
 * 4.22.2 require qs "~6.14.0" / "~6.15.1", and every qs those ranges admit is affected by
 * GHSA-4mjr-xmp4-gh2g (fixed in 6.16.0), so only 4.22.3 ("~6.16.0") installs clean.
 *
 * So a release HOLDS a dependency when its spec is
 * - an exact pin: a bare version or `=version`, installed as written; or
 * - a narrow range: one capped below the dependency's next major (`~1.2.3`, `^0.1.2`, `1.2.x`,
 *   anything with a `<` bound, a hyphen range), whose newest admitted release is the best any
 *   install can do (npm takes `latest` when the range admits it, else the highest it admits).
 * - a wide range (`^6.0.2`, `>=1`, `*`), judged the same way: by the newest release it admits,
 *   which is what a fresh install or a lockfile refresh resolves it to.
 * Wide ranges were once left out on the premise that a refresh reaches a clean release. That holds
 * only when one exists: mocha 10.6.0 to 10.8.2 require serialize-javascript "^6.0.2", and every
 * 6.x is affected (GHSA-5c6j-r48x-rmvq, fixed 7.0.3), yet upgrade_impact named 10.6.0 the first
 * clean release and dependency_check said proceed (pre-publish round 10, W13). A wide range whose
 * newest admitted release is clean brings nothing, so upgrade_planner's lever logic is untouched.
 * An npm alias (`"x": "npm:event-stream@3.3.6"`) installs the aliased package and is judged as it.

 * A held dependency whose installed version an advisory affects brings that advisory with the
 * release. The question is asked of OSV through the scanner the tools already use
 * (LiveIntelligence.queryAdvisories: batched, cached per dependency, rate-limited), in one call per
 * check. Fail closed: when a range's releases or OSV's answer cannot be had, the release is
 * `unchecked` with the reason, and no tool calls it clean on that.
 */

import { cleanReleases, isPrereleaseVersion, type AdvisoryRanges } from "./osv-ranges.js";
import { groupAdvisories } from "./advisory-groups.js";
import { isMaintenanceNotice } from "./maintenance.js";
import { npmRangeAdmits } from "./range-satisfies.js";
import { SEVERITY_RANK } from "./severity-scope.js";
import { compareVersions } from "./version-compare.js";
import type { ResolvedDependency, VulnerabilityEntry, VulnerabilityScanResult } from "./types.js";
import { isNpmPackageName, isReadableNpmSpec } from "../untrusted-text.js";

/** The registry facts this module reads (fix-paths.ts PackageReleaseFacts; a type only, no import cycle). */
export interface HeldFacts {
  versions: string[];
  withdrawn: string[];
  latest: string | null;
  /** Per release: its held specs (dependency name -> spec). A release with none is absent. */
  heldSpecs?: Record<string, Record<string, string>>;
}

export interface HeldSources {
  releaseFacts(ecosystem: "npm", name: string): Promise<HeldFacts | null>;
}

/** The advisory lookup the tools share (LiveIntelligence.queryAdvisories). */
export type AdvisoryQuery = (deps: ResolvedDependency[]) => Promise<VulnerabilityScanResult>;

export interface HeldDependency {
  name: string;
  /** The release's own spec for it, as published. */
  spec: string;
  /** True for an exact pin; false for a range (narrow or wide). */
  exact: boolean;
  /** What an install of the release gets: the pin, or the newest release the range admits. */
  version: string;
  /** The advisories that affect `version` (one id per alias group, maintenance notices left out). */
  ids: string[];
  severity: VulnerabilityEntry["severity"];
  /** An advisory here was matched but its record could not be read: its severity is not known, and counts as high. */
  unread?: true;
  /**
   * Go (release-requirements.ts): `spec` is a minimum, not a hold. Minimal version selection gives
   * the project at least `version`, and the project can raise it in its own go.mod.
   */
  minimum?: true;
  /** Go: `version` is what the project's own go.mod already selects, above the release's minimum. */
  selected?: true;
  /** Go: the line is `// indirect` in the release's go.mod. */
  indirect?: true;
  /** Go: the smallest release that clears `ids`, confirmed with OSV.dev; null when none is known. */
  fixedIn?: string | null;
}

export type HeldCheck =
  | {
      status: "checked";
      affected: HeldDependency[];
      /** How many requirements were judged (release-requirements.ts); absent for npm's held specs. */
      examined?: number;
      /** Declared requirements that are not a registry package with a readable requirement: never judged. */
      unreadable?: number;
    }
  | { status: "unchecked"; reason: string };

/** How many releases a fix-target search judges at most (the advisories' target and the next on its line). */
export const HELD_CANDIDATES = 10;
/** Registry reads in flight at once for the narrow ranges' release lists. */
const FACTS_CONCURRENCY = 8;

const EXACT = /^=?\s*v?(\d+\.\d+\.\d+(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?)(?:\+[0-9A-Za-z.-]+)?$/;

/** The version an exact npm pin installs ("6.11.0", "=6.11.0", "v6.11.0"); null for anything else. */
export function exactPinVersion(spec: unknown): string | null {
  if (typeof spec !== "string") return null;
  const m = EXACT.exec(spec.trim());
  return m ? m[1] : null;
}

/**
 * The package and spec an npm alias installs: `npm:event-stream@3.3.6` -> event-stream "3.3.6",
 * `npm:@scope/x` -> @scope/x "*" (no spec is the latest). Null for anything that is not an alias.
 */
export function npmAliasTarget(spec: string): { name: string; spec: string } | null {
  const m = /^npm:((?:@[^/@\s]+\/)?[^/@\s]+)(?:@(.*))?$/.exec(spec.trim());
  if (!m) return null;
  return { name: m[1], spec: m[2] === undefined || m[2].trim() === "" ? "*" : m[2].trim() };
}

/**
 * A release's held specs, dependencies and optionalDependencies (npm installs both): every
 * registry spec, exact, narrow or wide, keyed by the package it installs (an alias by its target).
 */
export function heldSpecsOf(dependencies?: Record<string, unknown>, optionalDependencies?: Record<string, unknown>): Record<string, string> {
  const out: Record<string, string> = {};
  // An optional dependency's spec wins over the same name in dependencies, as npm reads it.
  for (const [key, raw] of Object.entries({ ...dependencies, ...optionalDependencies })) {
    if (typeof raw !== "string") continue;
    // An alias installs another package: judge that one (pre-publish round 10, W13).
    const alias = npmAliasTarget(raw);
    const name = alias ? alias.name : key;
    const spec = alias ? alias.spec : raw;
    // Names and specs are whatever the publisher wrote, and both are printed ("requires qs
    // "~6.14.0""). Only a real package name with a plain version range is a held dependency: a
    // key or a "range" that is free text installs nothing from the registry and is never shown.
    if (!isNpmPackageName(key) || !isNpmPackageName(name) || !isReadableNpmSpec(spec)) continue;
    // An alias and a plain entry on one package both install; one spec per package is kept, and an
    // exact pin wins over a range, since a pin is what a refresh can never move off an affected copy.
    if (out[name] === undefined || (exactPinVersion(spec) !== null && exactPinVersion(out[name]) === null)) out[name] = spec.trim();
  }
  return out;
}

/** The release an install of `spec` gets, from the dependency's registry facts; null when it cannot be said. */
function resolveSpec(spec: string, facts: HeldFacts | null | undefined): string | null {
  const pinned = exactPinVersion(spec);
  if (pinned !== null) return pinned;
  if (!facts) return null;
  const admits = (v: string) => npmRangeAdmits(spec, v) === true;
  if (facts.latest && admits(facts.latest)) return facts.latest;
  const pool = [...facts.versions, ...facts.withdrawn].filter((v) => (spec.includes("-") || !isPrereleaseVersion(v, "npm")) && admits(v));
  return pool.sort((a, b) => compareVersions(a, b, "npm")).pop() ?? null;
}

function lookupDep(name: string, version: string): ResolvedDependency {
  return { name, version, ecosystem: "npm", isDev: false, isDirect: false, devScopeKnown: false, target: null, platformActive: true, sourceDirs: [] };
}

/** Resolves to `late` once `deadline` passes. */
export async function byDeadline<T>(work: Promise<T>, deadline: number, late: T): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<T>((resolve) => {
    timer = setTimeout(() => resolve(late), Math.max(0, deadline - Date.now()));
    timer.unref?.();
  });
  try {
    return await Promise.race([work.catch(() => late), timeout]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

/** Why an advisory answer is not a current one for every release asked about; null when it is. */
export function answerFailure(answer: VulnerabilityScanResult | null): string | null {
  if (!answer) return "the OSV.dev lookup did not finish in time";
  if (answer.offline) return answer.uncheckedReason ?? "OSV.dev could not be queried";
  if ((answer.staleAnswers ?? 0) > 0) return `OSV.dev gave only expired cached answers (${answer.staleReason ?? "the fresh query failed"})`;
  return null;
}

export interface AdvisoryHit {
  /** One id per alias group, sorted. */
  ids: string[];
  severity: VulnerabilityEntry["severity"];
  /** An advisory matched whose record could not be read: its severity is not known. */
  unread: boolean;
}

/** Per `name@version` asked about: the advisories that affect it (maintenance notices left out) and their worst grade. */
export function advisoryHits(vulnerabilities: readonly VulnerabilityEntry[]): Map<string, AdvisoryHit> {
  const byCopy = new Map<string, VulnerabilityEntry[]>();
  for (const v of vulnerabilities) {
    if (isMaintenanceNotice(v)) continue;
    const k = `${v.package}@${v.currentVersion}`;
    byCopy.set(k, [...(byCopy.get(k) ?? []), v]);
  }
  const hits = new Map<string, AdvisoryHit>();
  for (const [k, entries] of byCopy) {
    const groups = groupAdvisories(entries);
    const worst = groups.map((g) => g.best.severity).reduce((a, b) => ((SEVERITY_RANK[b as keyof typeof SEVERITY_RANK] ?? 0) > (SEVERITY_RANK[a as keyof typeof SEVERITY_RANK] ?? 0) ? b : a), "unknown" as VulnerabilityEntry["severity"]);
    const unread = groups.some((g) => g.best.severity === "unknown" && g.members.some((m) => m.detailUnavailable));
    hits.set(k, { ids: groups.map((g) => g.best.vulnId).sort(), severity: worst, unread });
  }
  return hits;
}

/**
 * For each release (`key` -> its held specs), which held dependencies an advisory affects: one OSV
 * call for all of them, the narrow ranges resolved from each dependency's registry facts first.
 * A release whose held dependencies could not all be resolved and judged is `unchecked`, unless
 * one that could be is already affected (a concrete finding stands).
 */
export async function heldAdvisories(
  sources: HeldSources,
  query: AdvisoryQuery,
  releases: Array<{ key: string; specs: Record<string, string> }>,
  deadline: number,
): Promise<Map<string, HeldCheck>> {
  const out = new Map<string, HeldCheck>();
  const ranged = [...new Set(releases.flatMap((r) => Object.entries(r.specs).filter(([, s]) => exactPinVersion(s) === null).map(([n]) => n)))];
  const facts = new Map<string, HeldFacts | null>();
  let next = 0;
  await Promise.all(
    Array.from({ length: Math.min(FACTS_CONCURRENCY, ranged.length) }, async () => {
      while (next < ranged.length && Date.now() < deadline) {
        const name = ranged[next++];
        facts.set(name, await byDeadline(sources.releaseFacts("npm", name), deadline, null));
      }
    }),
  );
  const resolved = releases.map((r) => ({
    key: r.key,
    deps: Object.entries(r.specs).map(([name, spec]) => ({ name, spec, exact: exactPinVersion(spec) !== null, version: resolveSpec(spec, facts.get(name)) })),
  }));
  const wanted = new Map<string, ResolvedDependency>();
  for (const r of resolved) for (const d of r.deps) if (d.version) wanted.set(`${d.name}@${d.version}`, lookupDep(d.name, d.version));

  let answer: VulnerabilityScanResult | null = null;
  let failure: string | null = null;
  if (wanted.size > 0) {
    answer = await byDeadline(query([...wanted.values()]), deadline, null);
    failure = answerFailure(answer);
  }
  const hits = advisoryHits(failure ? [] : (answer?.vulnerabilities ?? []));
  for (const r of resolved) {
    const affected: HeldDependency[] = r.deps.flatMap((d) => {
      const hit = d.version ? hits.get(`${d.name}@${d.version}`) : undefined;
      return hit ? [{ name: d.name, spec: d.spec, exact: d.exact, version: d.version!, ids: hit.ids, severity: hit.severity, ...(hit.unread ? { unread: true as const } : {}) }] : [];
    });
    const unread = r.deps.filter((d) => !d.version).map((d) => `${d.name} "${d.spec}"`);
    if (affected.length > 0) out.set(r.key, { status: "checked", affected });
    else if (unread.length > 0) out.set(r.key, { status: "unchecked", reason: `the releases ${unread.slice(0, 3).join(", ")}${unread.length > 3 ? ` and ${unread.length - 3} more` : ""} admit could not be read from the npm registry` });
    else if (failure && r.deps.length > 0) out.set(r.key, { status: "unchecked", reason: failure });
    else out.set(r.key, { status: "checked", affected: [] });
  }
  return out;
}

/** "a", "a and b", "a, b and c". */
export function andList(parts: string[]): string {
  return parts.length > 1 ? `${parts.slice(0, -1).join(", ")} and ${parts[parts.length - 1]}` : (parts[0] ?? "");
}

/**
 * What releases holding `affected` do, in words chosen per case: an exact pin, a range whose newest
 * admitted release is affected (narrow or wide), or both. Since W13 a wide range counts too, so the
 * old "exact-pins or narrowly ranges" misdescribed mocha 12.x's glob "^13.0.0" (pre-publish round 10, W16).
 */
export function heldVerb(affected: HeldDependency[]): string {
  const exact = affected.some((d) => d.exact);
  const ranged = affected.some((d) => !d.exact);
  if (exact && !ranged) return "exact-pins a dependency with a known advisory";
  if (ranged && !exact) return "holds a dependency range whose newest admitted release is affected";
  return "exact-pins a dependency with a known advisory or holds a range whose newest admitted release is affected";
}

/**
 * "4.20.0 exact-pins qs 6.11.0 (GHSA-a, GHSA-b) and cookie 0.6.0 (GHSA-c)", and for a narrow range
 * "4.22.0 requires qs "~6.14.0", whose newest admitted release 6.14.2 is affected (GHSA-d)".
 * At most three dependencies are named; the rest are counted.
 */
export function heldText(release: string, affected: HeldDependency[]): string {
  const shown = affected.slice(0, 3);
  const and = andList;
  const exact = shown.filter((d) => d.exact).map((d) => `${d.name} ${d.version} (${d.ids.join(", ")})`);
  const ranged = shown
    .filter((d) => !d.exact)
    .map((d) => `${d.name} "${d.spec}", whose newest admitted release ${d.version} is affected (${d.ids.join(", ")})`);
  const clauses = [...(exact.length > 0 ? [`exact-pins ${and(exact)}`] : []), ...(ranged.length > 0 ? [`requires ${and(ranged)}`] : [])];
  const rest = affected.length - shown.length;
  const more = rest > 0 ? `, and ${rest} more affected dependenc${rest === 1 ? "y" : "ies"}` : "";
  return `${release} ${clauses.join("; it also ")}${more}`;
}

/** The worst severity among held dependencies' advisories. */
export function heldSeverity(affected: HeldDependency[]): VulnerabilityEntry["severity"] {
  return affected.reduce<VulnerabilityEntry["severity"]>(
    (worst, d) => ((SEVERITY_RANK[d.severity as keyof typeof SEVERITY_RANK] ?? 0) > (SEVERITY_RANK[worst as keyof typeof SEVERITY_RANK] ?? 0) ? d.severity : worst),
    "unknown",
  );
}

/** Same compatibility line in npm's caret sense: same major, or same 0.minor below 1.0. */
export function sameNpmLine(a: string, b: string): boolean {
  const pa = /^v?(\d+)\.(\d+)\./.exec(a);
  const pb = /^v?(\d+)\.(\d+)\./.exec(b);
  if (!pa || !pb) return false;
  return pa[1] === pb[1] && (pa[1] !== "0" || pa[2] === pb[2]);
}

/**
 * The releases a fix-target search judges, smallest first: `target`, then the later stable,
 * installable releases on its line that the package's own advisories leave clean (the one
 * predicate every tool uses, osv-ranges cleanReleases), HELD_CANDIDATES in all at most.
 */
export function heldCandidates(target: string, facts: HeldFacts, advisories: readonly AdvisoryRanges[], installed?: string | null): string[] {
  const view = cleanReleases(advisories, "npm", facts.versions, installed);
  const later = facts.versions
    .filter((v) => !isPrereleaseVersion(v, "npm") && sameNpmLine(v, target) && compareVersions(v, target, "npm") > 0 && view.clean(v))
    .sort((a, b) => compareVersions(a, b, "npm"));
  return [target, ...later].slice(0, HELD_CANDIDATES);
}
