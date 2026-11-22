// SPDX-License-Identifier: Apache-2.0
/**
 * dependency_check, the answers of a pass (dependency-check.ts checkPass): what blocks each item or
 * what its release newly brings in, the first-publish dates of what it brings in, and each item's
 * verdict, reason and the signals behind them.
 */

import type { AdvisoryRanges } from "../live/osv-ranges.js";
import type { CheckEcosystem, PackageReleaseIndex, RegistryLookup } from "../live/release-metadata.js";
import { andList } from "../live/held-dependencies.js";
import { goPathMajor, goVersionMajor } from "../live/upgrade-go.js";
import { quoteThirdParty } from "../untrusted-text.js";
import { closestPopularPypi } from "./briefing-names.js";
import { closestPopularNpm, maliciousSignal, type MaliciousName } from "./dependency-check-malicious.js";
import { pythonSupportSignal } from "./dependency-check-python.js";
import {
  advisoriesSignal,
  decide,
  installScriptSignal,
  introducedDependencies,
  newDependenciesSignal,
  publishTrustSignal,
  releaseAgeSignal,
  selectBaseline,
  trustBaseline,
  upgradeTypeSignal,
  withdrawnSignal,
  type AdvisoryFacts,
  type CheckItem,
  type CreatedAtFact,
  type Signal,
  type Verdict,
} from "./dependency-check-signals.js";
import { compareIn, isPrereleaseIn, type RangeCheck } from "./dependency-check-versions.js";
import { head, lookupKey, type ItemResult, type Resolved } from "./dependency-check-items.js";
import { mapLimit, REGISTRY_CONCURRENCY, type Lookups, type PassContext } from "./dependency-check-lookups.js";
import type { Findings } from "./dependency-check-findings.js";
import { batchUnreadText, listGapText, withAlternatives } from "./dependency-check-reason.js";

/** First-publish lookups for newly introduced dependencies, per call (each is a registry read). */
const MAX_NEW_DEP_LOOKUPS = 40;

/** Per item: what blocks it (no release metadata, or no single version), or its release index and what `to` newly brings in. */
export type Plan = ReturnType<typeof planItem>;

/** Each item's plan, and the first-publish dates of the dependencies the plans newly bring in. */
export async function readFirstPublished(ctx: PassContext, lookups: Lookups, items: Resolved[]): Promise<{ plans: Plan[]; created: Map<string, CreatedAtFact> }> {
  const { sources } = ctx;
  const { indexes } = lookups;
  // Phase 2: first-publish dates of newly introduced dependencies.
  const plans = items.map((item) => planItem(item, indexes.get(lookupKey(item))!));
  const wantedCreated = new Map<string, { ecosystem: CheckEcosystem; name: string }>();
  for (const p of plans) {
    for (const name of p.introduced ?? []) {
      if (wantedCreated.size >= MAX_NEW_DEP_LOOKUPS) break;
      wantedCreated.set(`${p.item.ecosystem}\0${name}`, { ecosystem: p.item.ecosystem, name });
    }
  }
  const created = new Map<string, CreatedAtFact>();
  await mapLimit([...wantedCreated.entries()], REGISTRY_CONCURRENCY, async ([key, { ecosystem, name }]) => {
    const lookup = await sources[ecosystem].getCreatedAt(name);
    created.set(key, lookup.status === "ok" ? { status: "ok", createdAt: lookup.data } : lookup);
  });
  return { plans, created };
}

/** What every item's answer is read from, beside its plan. */
export interface AnswerInputs {
  ctx: PassContext;
  lookups: Lookups;
  advisoriesFor: (item: CheckItem) => AdvisoryFacts;
  findings: Findings;
  /** First-publish dates of the dependencies the plans newly bring in (readFirstPublished). */
  created: Map<string, CreatedAtFact>;
}

/** What an item's answer reads first, whichever kind of plan it has. */
interface PlanFacts {
  extra: { range_check?: RangeCheck };
  bad: MaliciousName | undefined;
  nameCheck: Signal | undefined;
}

/** Each item's answer: its verdict, the reason, and the signals behind it. */
export function itemResults(plans: Plan[], a: AnswerInputs): ItemResult[] {
  const { malicious, nameChecks } = a.findings;
  return plans.map((p) => {
    const extra = p.item.rangeCheck ? { range_check: p.item.rangeCheck } : {};
    const bad = malicious.get(p.item);
    const nameCheck = nameChecks.get(p.item);
    if (p.blocked) return blockedResult(p, { extra, bad, nameCheck }, a);
    return judgedResult(p, { extra, bad, nameCheck }, a);
  });
}

/** No release metadata, or no single version: only the advisory lookup and the name check can still speak. */
function blockedResult(p: Plan & { blocked: string }, { extra, bad, nameCheck }: PlanFacts, a: AnswerInputs): ItemResult {
  const { heldAt } = a.ctx;
  const { indexes, advisoryLists } = a.lookups;
  const { advisoriesFor } = a;
  // A near-miss name that is not established is a finding whatever else could not be read.
  const nameFinding = nameCheck && (nameCheck.effect === "avoid" || nameCheck.effect === "review") ? nameCheck : null;
  // No release metadata: only the advisory lookup can still speak, and
  // only a negative finding is worth more than "unknown".
  if (bad) {
    const sig = maliciousSignal(p.item, bad, null);
    return { ...head(p.item), verdict: "avoid" as const, reason: `${sig.id}: ${sig.evidence}`, signals: [sig], ...extra };
  }
  // Not on the registry, yet OSV.dev lists advisories against every release of the name: they are
  // what is known about it, named, never dropped for a bare "not found" (round 8, B3).
  const gone = indexes.get(lookupKey(p.item))?.status === "not_found" ? everyRelease(advisoryLists.get(lookupKey(p.item))) : [];
  if (gone.length > 0) {
    const evidence = `OSV.dev lists ${andList(gone)} against every release of ${p.item.package}, which ${p.item.ecosystem} no longer serves. Do not add it.`;
    return {
      ...head(p.item),
      verdict: "avoid" as const,
      reason: `advisories: ${evidence} | ${p.blocked}`,
      signals: [{ id: "advisories", value: { affecting_every_release: gone }, effect: "avoid", evidence }],
      ...extra,
    };
  }
  if (p.item.unresolved) {
    const outside = p.item.rangeCheck?.newest_safe_outside_range ? ` Newest safe release outside it: ${p.item.rangeCheck.newest_safe_outside_range}.` : "";
    const unnamed = p.item.listGap
      ? ` | ${listGapText(p.item.package, p.item.listGap)}`
      : p.item.batchUnread
        ? ` | ${batchUnreadText(p.item.package, p.item.batchUnread)}`
        : "";
    return {
      ...head(p.item),
      verdict: nameFinding ? (nameFinding.effect as Verdict) : ("unknown" as const),
      reason: `${nameFinding ? `name_check: ${nameFinding.evidence} | ` : ""}${p.blocked}${outside}${unnamed}`,
      signals: nameCheck ? [nameCheck] : [],
      ...extra,
    };
  }
  const advisories = advisoriesSignal(p.item, advisoriesFor(p.item), heldAt(p.item));
  const found = [advisories, ...(nameFinding ? [nameFinding] : [])].filter((s) => s.effect === "avoid" || s.effect === "review");
  const negative = found.length > 0;
  return {
    ...head(p.item),
    verdict: found.some((s) => s.effect === "avoid") ? "avoid" : negative ? "review" : "unknown",
    reason: withAlternatives(
      negative ? `${found.map((s) => `${s.id}: ${s.evidence}`).join(" | ")} | ${p.blocked}` : p.blocked,
      p.item,
      found.some((s) => s.effect === "avoid") ? "avoid" : negative ? "review" : "unknown",
    ),
    signals: [advisories, ...(nameCheck ? [nameCheck] : [])],
    // Only an unknown is worth asking again for: a negative finding already stands.
    ...(p.retryAfterSeconds && !negative ? { retry_after_seconds: p.retryAfterSeconds } : {}),
    ...extra,
    ...noticesOf(advisories),
  };
}

/** A published release: every signal, and the verdict they decide. */
function judgedResult(p: Plan, { extra, bad, nameCheck }: PlanFacts, a: AnswerInputs): ItemResult {
  const { now, pythons, heldAt } = a.ctx;
  const { advisoriesFor, created } = a;
  const { holdWaivers } = a.findings;
  const { item, index } = p;
  const to = index!.releases[item.to];
  const base = selectBaseline(index!, item);
  const own = advisoriesSignal(item, advisoriesFor(item), heldAt(item));
  const advisories = bad ? maliciousSignal(item, bad, own) : own;
  const createdForItem = new Map<string, CreatedAtFact>();
  for (const name of p.introduced ?? []) {
    const fact = created.get(`${item.ecosystem}\0${name}`);
    if (fact) createdForItem.set(name, fact);
  }
  const signals: Signal[] = [
    advisories,
    ...(nameCheck ? [nameCheck] : []),
    releaseAgeSignal(item, to, advisories, now, holdWaivers.get(item)),
    publishTrustSignal(item, to, trustBaseline(index!, item)),
    installScriptSignal(item, to, item.from ? index!.releases[item.from] ?? null : null),
    newDependenciesSignal(item, to, base, p.introduced, createdForItem),
    withdrawnSignal(item, to, index!),
    ...[pythonSupportSignal(item, to, pythons.of(item), pythons.unreadOf(item))].filter((s): s is Signal => s !== null),
    upgradeTypeSignal(item, releasesBack(item, index!)),
  ];
  const decided = decide(signals, item.ecosystem);
  return { ...head(item), verdict: decided.verdict, reason: withAlternatives(decided.reason, item, decided.verdict), signals, ...extra, ...noticesOf(advisories) };
}

/** The unmaintained-package notices an advisories signal carries, as the answer's field. */
const noticesOf = (s: Signal) => {
  const ids = (s.value as { maintenance_notices?: string[] } | null)?.maintenance_notices;
  return ids && ids.length > 0 ? { maintenance_notices: ids } : {};
};

/** Each answer for a crate asked under another spelling names the published one first. */
export function nameCrateSpellings(results: ItemResult[], items: Resolved[]): void {
  // A crate asked under another spelling is named as published (round 10, W2).
  results.forEach((res, i) => {
    const asked = items[i].asked;
    if (asked) {
      res.reason = `${asked} is published as ${res.package}: ${crateSpellingReason(asked, res.package)}, so it was checked as ${res.package}; write the published spelling, ${res.package}, in Cargo.toml. | ${res.reason}`;
    }
  });
}

/**
 * Why crates.io took `asked` as `published`: letter case, "-" against "_", or both. "Smallvec" was
 * told crates.io read "-" and "_" as the same when the difference was case (pre-publish round 10, W10).
 */
export function crateSpellingReason(asked: string, published: string): string {
  const fold = (s: string) => s.replace(/_/g, "-");
  const caseDiffers = fold(asked) !== fold(published);
  const dashDiffers = asked.toLowerCase() !== published.toLowerCase();
  if (caseDiffers && dashDiffers) return `crates.io treats crate names that differ only in letter case or in "-" against "_" as the same crate`;
  if (caseDiffers) return "crates.io treats crate names that differ only in letter case as the same crate";
  return `crates.io and Cargo read "-" and "_" in a crate name as the same crate`;
}

/** For a downgrade: the published, stable releases above `to` up to and including `from` (upgradeTypeSignal). */
function releasesBack(item: Resolved, index: PackageReleaseIndex): number | null {
  if (!item.from || compareIn(item.ecosystem, item.to, item.from) >= 0) return null;
  return Object.values(index.releases).filter(
    (r) => !r.withdrawn && !isPrereleaseIn(item.ecosystem, r.version) && compareIn(item.ecosystem, r.version, item.to) > 0 && compareIn(item.ecosystem, r.version, item.from!) <= 0,
  ).length;
}

/** The ids of the advisories (maintenance notices left out) that are open from the first release with no fix. */
function everyRelease(list: readonly AdvisoryRanges[] | null | undefined): string[] {
  const open = (a: AdvisoryRanges) => a.spans.some((s) => s.fixed === null && s.lastAffected === null && /^0(?:\.0)*(?:-0)?$/.test(s.introduced));
  return [...new Set((list ?? []).filter((a) => !a.maintenance && open(a)).map((a) => a.id))].sort();
}

function planItem(item: Resolved, lookup: RegistryLookup<PackageReleaseIndex>) {
  if (lookup.status === "unreachable") {
    return { item, blocked: unreachableText(item, lookup), index: null, introduced: null, retryAfterSeconds: lookup.ownLimit?.retryAfterSeconds };
  }
  if (lookup.status === "not_found") {
    const guess = item.ecosystem === "npm" ? closestPopularNpm(item.package) : item.ecosystem === "PyPI" ? closestPopularPypi(item.package) : null;
    return {
      item,
      blocked: `${quoteThirdParty(lookup.detail, 160)}. If it is a private package this tool cannot judge it; otherwise check the name for a typo or a hallucinated package before adding it${guess ? ` (did you mean ${guess}?)` : ""}.`,
      index: null,
      introduced: null,
    };
  }
  if (item.unresolved) return { item, blocked: item.unresolved, index: lookup.data, introduced: null };
  const index = lookup.data;
  const to = index.releases[item.to];
  if (!to) {
    return { item, blocked: `${item.package}@${item.to} is not a published version on ${item.ecosystem}.${goMajorHint(item)}`, index, introduced: null };
  }
  return { item, blocked: null, index, introduced: introducedDependencies(to, selectBaseline(index, item).record) };
}

/**
 * Why an item whose registry read failed was not judged. This server's own request limit is named
 * as the cause when it was (the registry was never asked, so it is never blamed), and a release
 * list read without the file that lists its withdrawals says that whether `to` was withdrawn was
 * not checked.
 */
function unreachableText(item: Resolved, lookup: Extract<RegistryLookup<PackageReleaseIndex>, { status: "unreachable" }>): string {
  const limit = lookup.ownLimit;
  const retry = limit ? ` Call dependency_check again for this item in ${limit.retryAfterSeconds} s (retry_after_seconds).` : "";
  if (lookup.withdrawalsUnread) {
    const why = limit
      ? `this server's own request limit for ${limit.registry} was reached before it could be read (${limit.registry} was not asked and is not at fault)`
      : `it could not be read (${quoteThirdParty(lookup.detail, 160)})`;
    return `NOT CHECKED: ${item.package}'s retractions were not read, so whether ${item.to} is retracted was not checked: they are listed in ${lookup.withdrawalsUnread}, and ${why}. Nothing about ${item.to} was verified; this is not a clean result.${retry}`;
  }
  if (limit) {
    const unread = item.ecosystem === "Go" ? `${item.package}'s version list, retractions and release dates were` : `${item.package}'s release data was`;
    return `NOT CHECKED: this server's own request limit for ${limit.registry} was reached, so ${unread} not read and nothing about ${item.to} was verified (${limit.registry} was not asked and is not at fault).${retry}`;
  }
  return `Registry could not be reached (${quoteThirdParty(lookup.detail, 160)}); nothing about ${item.to} was verified.`;
}

/** Go majors 2+ live at their own module path. */
function goMajorHint(item: CheckItem): string {
  if (item.ecosystem !== "Go") return "";
  const major = goVersionMajor(item.to);
  const pathMajor = goPathMajor(item.package) ?? 1;
  if (major === null || major < 2 || major === pathMajor) return "";
  return ` Go major ${major} is a different module: ${item.package.replace(/\/v\d+$/, "")}/v${major}.`;
}
