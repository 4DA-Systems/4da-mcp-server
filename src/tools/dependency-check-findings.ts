// SPDX-License-Identifier: Apache-2.0
/**
 * dependency_check, what a pass finds beside the advisories (dependency-check.ts checkPass): a clean
 * release inside the release-age hold that holding back would leave nothing safe for (a waiver), a
 * name that is malware itself, and a new dependency one slip from a popular package.
 */

import { npmWeeklyDownloads } from "../live/npm-downloads.js";
import type { AdvisoryRanges } from "../live/osv-ranges.js";
import type { CheckEcosystem, PackageReleaseIndex, RegistryLookup, ReleaseMetadataSource } from "../live/release-metadata.js";
import { isSecurityHoldingRelease } from "../live/osv-scanner.js";
import type { AdvisoryFacts, CheckItem, HoldWaiver, Signal } from "./dependency-check-signals.js";
import { checkRange, isPrereleaseIn, lineOf, rangeAdmits } from "./dependency-check-versions.js";
import { maliciousName, type MaliciousName } from "./dependency-check-malicious.js";
import { nameCheckSignal, nearMissOf } from "./dependency-check-nearmiss.js";
import { pypiNameCheckSignal, pypiNearMissOf } from "./dependency-check-nearmiss-pypi.js";
import { normalizePypiName } from "./briefing-names.js";
import { lookupKey, type Resolved } from "./dependency-check-items.js";
import type { AdvisoryListReader, Lookups, PassContext } from "./dependency-check-lookups.js";
import { isYoung } from "./dependency-check-resolve.js";
import { hasRealAdvisory } from "./dependency-check-batch.js";
import { findCaseVariants } from "./dependency-check-gocase.js";

/** What a pass finds about its items beside their advisories. */
export interface Findings {
  /** Clean targets inside the release-age hold that holding back would leave nothing safe for. */
  holdWaivers: Map<Resolved, HoldWaiver>;
  /** Names that are malware themselves. */
  malicious: Map<Resolved, MaliciousName>;
  /** New npm and PyPI dependencies one slip from a popular package. */
  nameChecks: Map<Resolved, Signal>;
  /** Go paths with upper-case letters answered clean, whose lower-case path has advisories (dependency-check-gocase.ts, C-5). */
  caseVariants: Map<Resolved, Signal>;
}

/** The hold waivers, then the malware names, then the near-miss names. */
export async function gatherFindings(ctx: PassContext, lookups: Lookups, items: Resolved[], advisoriesFor: (item: CheckItem) => AdvisoryFacts): Promise<Findings> {
  const { now, liveIntel, sources, packageAdvisoryLists } = ctx;
  const { indexes, advisoryLists } = lookups;
  const holdWaivers = await findHoldWaivers(items, indexes, advisoryLists, packageAdvisoryLists, sources.Go, advisoriesFor, now);
  // A name that is malware itself (a typo-squat npm took down): avoid, whatever the release says.
  const malicious = await findMaliciousNames(items, indexes, advisoryLists, packageAdvisoryLists);
  // A new npm dependency one slip away from a popular package: review or avoid unless it is established.
  // A name the project's lockfiles already hold is not a new dependency; a `from` alone does not
  // say that (pre-publish audit 2026-11-12, S2: {reactt, latest, from 1.0.0} said proceed).
  // PyPI: the same for a project one slip from a popular one (PEP 503 names: dependency-check-nearmiss-pypi.ts).
  const installedKey = (ecosystem: string, name: string) => `${ecosystem}\0${ecosystem === "PyPI" ? normalizePypiName(name) : name.toLowerCase()}`;
  const installedNames = new Set(
    liveIntel.isInitialized?.()
      ? [...liveIntel.getResolvedDeps(), ...liveIntel.getAuditDeps()].filter((d) => d.ecosystem === "npm" || d.ecosystem === "PyPI").map((d) => installedKey(d.ecosystem, d.name))
      : [],
  );
  const nameChecks = await findNearMisses(items, indexes, malicious, now, (ecosystem, name) => installedNames.has(installedKey(ecosystem, name)));
  const caseVariants = await findCaseVariants(ctx, items, advisoriesFor);
  return { holdWaivers, malicious, nameChecks, caseVariants };
}

/** Go publish dates read per item to decide a hold waiver (the list has none). */
const GO_WAIVER_READS = 8;

/**
 * Clean `to` versions inside the release-age hold for which holding back
 * leaves nothing safe to write: every safe release on the line is inside the
 * hold as well, and the line has older releases, all with a known advisory.
 * A package whose only releases are new keeps the hold, which is what it is for.
 * An undated release (Go lists carry no dates) counts as old, never as safe.
 */
async function findHoldWaivers(
  items: Resolved[],
  indexes: Map<string, RegistryLookup<PackageReleaseIndex>>,
  advisoryLists: Map<string, AdvisoryRanges[] | null>,
  packageAdvisoryLists: AdvisoryListReader,
  go: ReleaseMetadataSource,
  advisoriesFor: (item: CheckItem) => AdvisoryFacts,
  now: Date,
): Promise<Map<Resolved, HoldWaiver>> {
  const out = new Map<Resolved, HoldWaiver>();
  const held = items.filter((i) => {
    const lookup = indexes.get(lookupKey(i));
    if (i.unresolved || lookup?.status !== "ok") return false;
    const facts = advisoriesFor(i);
    return facts.available && !hasRealAdvisory(facts) && isYoung(lookup.data.releases[i.to]?.publishedAt, now);
  });
  if (held.length === 0) return out;
  const missing = held.filter((i) => !advisoryLists.has(lookupKey(i)));
  for (const [k, v] of await packageAdvisoryLists(missing)) advisoryLists.set(k, v);

  for (const item of held) {
    const lookup = indexes.get(lookupKey(item));
    const advisories = advisoryLists.get(lookupKey(item));
    const line = lineOf(item.ecosystem, item.to);
    if (lookup?.status !== "ok" || !advisories || !line) continue;
    const index = lookup.data;
    const rc = checkRange({ ecosystem: item.ecosystem, index, range: line, basis: "same_line", advisories, from: item.from, allowPrerelease: isPrereleaseIn(item.ecosystem, item.to) });
    // safe_versions holds the newest few; it must reach the smallest to cover them all.
    if (rc.smallest_safe_in_range === null || !rc.safe_versions.includes(rc.smallest_safe_in_range)) continue;
    if (item.ecosystem === "Go") {
      const undated = rc.safe_versions.filter((v) => !index.releases[v]?.publishedAt).slice(0, GO_WAIVER_READS);
      if (undated.length > 0) {
        const read = await go.getReleases(item.package, undated);
        if (read.status === "ok") {
          for (const v of undated) if (read.data.releases[v]) index.releases[v] = read.data.releases[v];
        }
      }
    }
    if (!rc.safe_versions.every((v) => isYoung(index.releases[v]?.publishedAt, now))) continue;
    const safe = new Set(rc.safe_versions);
    const older = Object.values(index.releases).filter(
      (r) =>
        !r.withdrawn &&
        !safe.has(r.version) &&
        !isPrereleaseIn(item.ecosystem, r.version) &&
        rangeAdmits(item.ecosystem, line, r.version) === true &&
        !isYoung(r.publishedAt, now),
    );
    if (older.length > 0) out.set(item, { line, olderVulnerable: older.length });
  }
  return out;
}

/**
 * The items whose package name is malware itself (dependency-check-malicious.ts): asked of a new
 * dependency (no `from`), of a name the registry does not have, and of an npm name held by a
 * security placeholder, with the package's advisory list (read once, shared with the range checks).
 */
async function findMaliciousNames(
  items: Resolved[],
  indexes: Map<string, RegistryLookup<PackageReleaseIndex>>,
  advisoryLists: Map<string, AdvisoryRanges[] | null>,
  packageAdvisoryLists: AdvisoryListReader,
): Promise<Map<Resolved, MaliciousName>> {
  const out = new Map<Resolved, MaliciousName>();
  // npm holds the name: a placeholder, and nothing else it still serves.
  const holdingOnly = (lookup: RegistryLookup<PackageReleaseIndex> | undefined) => {
    if (lookup?.status !== "ok") return false;
    const all = Object.values(lookup.data.releases);
    return all.some((r) => isSecurityHoldingRelease("npm", r.version)) && all.every((r) => isSecurityHoldingRelease("npm", r.version) || r.withdrawn);
  };
  const asked = items.filter((i) => {
    const lookup = indexes.get(lookupKey(i));
    return !i.from || lookup?.status === "not_found" || (i.ecosystem === "npm" && (isSecurityHoldingRelease("npm", i.to) || holdingOnly(lookup)));
  });
  const missing = asked.filter((i) => !advisoryLists.has(lookupKey(i)));
  for (const [k, v] of await packageAdvisoryLists(missing)) advisoryLists.set(k, v);
  for (const item of asked) {
    const lookup = indexes.get(lookupKey(item));
    const found = maliciousName({
      ecosystem: item.ecosystem,
      package: item.package,
      to: item.to,
      index: lookup?.status === "ok" ? lookup.data : null,
      notFound: lookup?.status === "not_found",
      advisories: advisoryLists.get(lookupKey(item)),
    });
    if (found) out.set(item, found);
  }
  return out;
}

/**
 * The name check for each new PyPI dependency (dependency-check-nearmiss-pypi.ts: no request) and
 * each new npm dependency (dependency-check-nearmiss.ts) whose name is a
 * near-miss of a popular package and is on the registry (new: not in this project's lockfiles, whether or not `from` is given): one request to api.npmjs.org for the
 * weekly downloads of those names and of the packages they resemble. Nothing is asked for any
 * other item. A name already found to be malware is not checked again.
 */
async function findNearMisses(
  items: Resolved[],
  indexes: Map<string, RegistryLookup<PackageReleaseIndex>>,
  malicious: Map<Resolved, MaliciousName>,
  now: Date,
  installed: (ecosystem: CheckEcosystem, name: string) => boolean,
): Promise<Map<Resolved, Signal>> {
  const out = new Map<Resolved, Signal>();
  // PyPI: judged from the project document already read; no request.
  for (const item of items) {
    const lookup = indexes.get(lookupKey(item));
    if (item.ecosystem !== "PyPI" || installed("PyPI", item.package) || lookup?.status !== "ok" || malicious.has(item)) continue;
    const nearMiss = pypiNearMissOf(item.package);
    if (nearMiss) out.set(item, pypiNameCheckSignal({ package: item.package, nearMiss, index: lookup.data, now }));
  }
  const near = items.flatMap((item) => {
    const lookup = indexes.get(lookupKey(item));
    if (item.ecosystem !== "npm" || installed("npm", item.package) || lookup?.status !== "ok" || malicious.has(item)) return [];
    const nearMiss = nearMissOf(item.package);
    return nearMiss ? [{ item, index: lookup.data, nearMiss }] : [];
  });
  if (near.length === 0) return out;
  const failed = (error: unknown) => ({ status: "unreachable" as const, detail: `api.npmjs.org: ${String(error).slice(0, 80)}` });
  const names = near.flatMap((n) => [n.item.package, n.nearMiss.of]);
  const downloads = await npmWeeklyDownloads(names).catch((error) => new Map(names.map((name) => [name, failed(error)])));
  for (const { item, index, nearMiss } of near) {
    out.set(
      item,
      nameCheckSignal({
        package: item.package,
        nearMiss,
        downloads: downloads.get(item.package) ?? failed("no answer"),
        popularDownloads: downloads.get(nearMiss.of),
        createdAt: index.createdAt,
        installScripts: index.releases[item.to]?.installScripts ?? null,
        now,
      }),
    );
  }
  return out;
}
