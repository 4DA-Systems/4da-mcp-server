// SPDX-License-Identifier: Apache-2.0
/**
 * dependency_check signal evaluation — pure functions, no I/O.
 *
 * Each signal states a fact with its evidence and the verdict that fact
 * implies on its own (`effect`). The item verdict is the strongest effect by
 * a fixed precedence. `unknown` sits above `wait`/`proceed` and below
 * `review`/`avoid`: a concrete negative finding stays actionable even when
 * another source was unreachable, but a missing source never lets the
 * verdict fall through to `proceed`.
 */

import type { CheckEcosystem, PackageReleaseIndex, ReleaseRecord } from "../live/release-metadata.js";
import { compareIn, isPrereleaseIn, versionParts } from "./dependency-check-versions.js";

export type Verdict = "proceed" | "wait" | "review" | "avoid" | "unknown";
export type SignalEffect = Verdict | "info";

export interface CheckItem {
  ecosystem: CheckEcosystem;
  package: string;
  to: string;
  from?: string;
}

export interface Signal {
  id:
    | "advisories"
    | "release_age"
    | "publish_trust"
    | "install_script_added"
    | "new_dependencies"
    | "yanked_or_deprecated"
    | "upgrade_type";
  value: unknown;
  evidence: string;
  effect: SignalEffect;
}

export interface AdvisoryRef {
  id: string;
  severity: "critical" | "high" | "medium" | "low" | "unknown";
  summary: string;
  /** Unmaintained-crate notice rather than an exploitable vulnerability. */
  maintenance: boolean;
  /** The GHSA alias `severity` was read from, when this record carries none of its own (Go). */
  severityFrom?: string;
}

export type AdvisoryFacts =
  | { available: true; to: AdvisoryRef[]; from: AdvisoryRef[] }
  | { available: false; detail: string };

/** A newly introduced dependency's first-publish lookup. */
export type CreatedAtFact =
  | { status: "ok"; createdAt: string | null }
  | { status: "not_found"; detail: string }
  | { status: "unreachable"; detail: string };

/** Verdict precedence, strongest first. */
const PRECEDENCE: Verdict[] = ["avoid", "review", "unknown", "wait", "proceed"];

export const WAIT_DAYS = 3;
export const NEW_DEP_MIN_AGE_DAYS = 30;
const DAY_MS = 86_400_000;

/** The release `to` is judged against: the installed `from`, else the previous release on `to`'s line. */
export function selectBaseline(
  index: PackageReleaseIndex,
  item: CheckItem,
): { record: ReleaseRecord | null; kind: "from" | "previous_on_line"; note: string } {
  if (item.from) {
    const rec = index.releases[item.from] ?? null;
    return {
      record: rec,
      kind: "from",
      note: rec ? `installed ${item.from}` : `installed version ${item.from} is not listed on the registry`,
    };
  }
  const eco = item.ecosystem;
  const target = versionParts(eco, item.to);
  if (!target) return { record: null, kind: "previous_on_line", note: "target version is not readable" };
  const targetPre = isPrereleaseIn(eco, item.to);
  let best: ReleaseRecord | null = null;
  for (const rec of Object.values(index.releases)) {
    if (rec.withdrawn) continue;
    const p = versionParts(eco, rec.version);
    if (!p || !sameLine(p, target) || compareIn(eco, rec.version, item.to) >= 0) continue;
    if (isPrereleaseIn(eco, rec.version) && !targetPre) continue;
    if (!best || compareIn(eco, rec.version, best.version) > 0) best = rec;
  }
  return best
    ? { record: best, kind: "previous_on_line", note: `previous release on the same line, ${best.version}` }
    : { record: null, kind: "previous_on_line", note: "first release on its line; nothing earlier to compare" };
}

/** Same compatibility line: same major, or same 0.minor below 1.0. */
function sameLine(a: { major: number; minor: number }, b: { major: number; minor: number }): boolean {
  return a.major === b.major && (a.major !== 0 || a.minor === b.minor);
}

/** Runtime dependency names in `to` that the baseline did not have; null when either list is unknown. */
export function introducedDependencies(to: ReleaseRecord, base: ReleaseRecord | null): string[] | null {
  if (!to.dependencies || !base?.dependencies) return null;
  const before = new Set(base.dependencies);
  return to.dependencies.filter((d) => !before.has(d)).sort();
}

export function advisoriesSignal(item: CheckItem, facts: AdvisoryFacts): Signal {
  if (!facts.available) {
    return { id: "advisories", value: null, evidence: `OSV.dev could not be reached: ${facts.detail}`, effect: "unknown" };
  }
  const fromIds = new Set(facts.from.map((a) => a.id));
  const toIds = new Set(facts.to.map((a) => a.id));
  const fixed = facts.from.filter((a) => !toIds.has(a.id) && !a.maintenance);
  const value = { affecting_to: facts.to.map((a) => a.id), fixed_by_this_change: fixed.map((a) => a.id) };
  const fixedNote = fixed.length > 0 ? ` This change fixes ${list(fixed)} affecting ${item.from}.` : "";

  const serious = facts.to.filter((a) => !a.maintenance && (a.severity === "critical" || a.severity === "high"));
  if (serious.length > 0) {
    return { id: "advisories", value, effect: "avoid", evidence: `${item.to} is affected by ${list(serious)}.${fixedNote}` };
  }
  const other = facts.to.filter((a) => !a.maintenance);
  const newNotices = facts.to.filter((a) => a.maintenance && !fromIds.has(a.id));
  if (other.length > 0 || newNotices.length > 0) {
    return {
      id: "advisories",
      value,
      effect: "review",
      evidence: `${item.to} is affected by ${list([...other, ...newNotices])}.${fixedNote}`,
    };
  }
  // Only maintenance notices that `from` already carries can remain here.
  const carried = facts.to.length > 0 ? ` (maintenance notice${facts.to.length > 1 ? "s" : ""} ${facts.to.map((a) => a.id).join(", ")} already apply to ${item.from})` : "";
  return {
    id: "advisories",
    value,
    effect: "proceed",
    evidence: `No known advisory affects ${item.to}${carried}.${fixedNote}`,
  };
}

function fmt(a: AdvisoryRef): string {
  return `${a.id} (${a.maintenance ? "unmaintained notice" : a.severityFrom ? `${a.severity}, per ${a.severityFrom}` : a.severity})`;
}

/** At most three named in prose; the full id list is in the signal's `value`. */
function list(advisories: AdvisoryRef[]): string {
  const shown = advisories.slice(0, 3).map(fmt).join(", ");
  return advisories.length > 3 ? `${shown} and ${advisories.length - 3} more` : shown;
}

/**
 * Why the hold does not apply to a clean `to`: every safe release on its line
 * is inside the hold too, and every older release on it has an advisory, so
 * holding back would leave only vulnerable releases to write.
 */
export interface HoldWaiver {
  /** The release line judged ("7.x", "v0", "==3.1.*"). */
  line: string;
  /** Releases on the line past the hold, all with a known advisory. */
  olderVulnerable: number;
}

export function releaseAgeSignal(item: CheckItem, to: ReleaseRecord, advisories: Signal, now: Date, waiver?: HoldWaiver): Signal {
  if (!to.publishedAt) {
    return { id: "release_age", value: null, evidence: `The registry gives no publish time for ${item.to}.`, effect: "unknown" };
  }
  const days = (now.getTime() - Date.parse(to.publishedAt)) / DAY_MS;
  const value = { days: Math.round(days * 10) / 10, published_at: to.publishedAt };
  const ageText = `${item.to} was published ${value.days} day${value.days === 1 ? "" : "s"} ago (${to.publishedAt})`;
  if (days >= WAIT_DAYS) {
    return { id: "release_age", value, evidence: `${ageText}.`, effect: "proceed" };
  }
  const fixed = (advisories.value as { fixed_by_this_change?: string[] } | null)?.fixed_by_this_change ?? [];
  if (fixed.length > 0) {
    return {
      id: "release_age",
      value,
      effect: "proceed",
      evidence: `${ageText}, under the ${WAIT_DAYS}-day hold, but it fixes ${fixed.join(", ")} affecting ${item.from}; a security fix is not held back.`,
    };
  }
  if (waiver) {
    return {
      id: "release_age",
      value: { ...value, hold_waived: "no_settled_safe_release" },
      effect: "proceed",
      evidence:
        `${ageText}, under the ${WAIT_DAYS}-day hold, but every release of ${waiver.line} older than that has a known advisory ` +
        `(${waiver.olderVulnerable} of them) and no safe one is past the hold; a vulnerable release is the worse risk, so the hold is not applied. ` +
        `Tell the user this version is ${value.days} day${value.days === 1 ? "" : "s"} old.`,
    };
  }
  return {
    id: "release_age",
    value,
    effect: "wait",
    evidence: `${ageText}; releases younger than ${WAIT_DAYS} days are held so a compromised publish can be caught and pulled first.`,
  };
}

export function publishTrustSignal(item: CheckItem, to: ReleaseRecord, base: ReturnType<typeof selectBaseline>): Signal {
  if (item.ecosystem === "PyPI" || item.ecosystem === "Go") {
    return { id: "publish_trust", value: "not_applicable", evidence: to.trustEvidence, effect: "info" };
  }
  if (to.withdrawn === "unpublished") {
    // Its publisher record is gone with it; comparing would report a "drop" we cannot see.
    return { id: "publish_trust", value: null, evidence: `${item.to} was unpublished; its publish metadata is gone.`, effect: "info" };
  }
  if (!base.record) {
    return {
      id: "publish_trust",
      value: { to: to.trust, baseline: null },
      evidence: `${item.to}: ${to.trustEvidence}. No baseline: ${base.note}.`,
      effect: "info",
    };
  }
  const b = base.record;
  const value = { to: to.trust, baseline: b.trust, baseline_version: b.version, baseline_kind: base.kind };
  const evidence = `${item.to}: level ${to.trust}, ${to.trustEvidence}. ${b.version} (${base.note}): level ${b.trust}, ${b.trustEvidence}.`;
  if (to.trust < b.trust) {
    return { id: "publish_trust", value, effect: "review", evidence: `Publish trust dropped. ${evidence}` };
  }
  return { id: "publish_trust", value, effect: "proceed", evidence };
}

export function installScriptSignal(item: CheckItem, to: ReleaseRecord, from: ReleaseRecord | null): Signal {
  if (item.ecosystem !== "npm") {
    return { id: "install_script_added", value: "not_applicable", evidence: NO_INSTALL_SCRIPTS[item.ecosystem], effect: "info" };
  }
  const scripts = to.installScripts ?? [];
  if (!item.from) {
    return {
      id: "install_script_added",
      value: scripts,
      effect: "info",
      evidence: scripts.length > 0 ? `${item.to} runs install-time scripts: ${scripts.join(", ")}.` : `${item.to} declares no install-time scripts.`,
    };
  }
  if (!from || from.installScripts === null) {
    return { id: "install_script_added", value: null, effect: "unknown", evidence: `Install scripts of ${item.from} are unknown (${from ? "release metadata gone" : "not on the registry"}).` };
  }
  const added = scripts.filter((s) => !from.installScripts!.includes(s));
  if (added.length > 0) {
    return {
      id: "install_script_added",
      value: added,
      effect: "review",
      evidence: `${item.to} adds install-time script${added.length > 1 ? "s" : ""} ${added.join(", ")} that ${item.from} did not have; it runs on every install.`,
    };
  }
  return {
    id: "install_script_added",
    value: [],
    effect: "proceed",
    evidence: scripts.length > 0 ? `Install scripts unchanged (${scripts.join(", ")}).` : "Neither version declares install-time scripts.",
  };
}

const NO_INSTALL_SCRIPTS: Record<Exclude<CheckEcosystem, "npm">, string> = {
  "crates.io": "not applicable: npm only (crates run build.rs at build time, which the registry does not expose).",
  PyPI: "not applicable: PyPI's index exposes no install hooks (an sdist-only release runs its build backend at install).",
  Go: "not applicable: Go runs no package code when a module is downloaded.",
};

export function newDependenciesSignal(
  item: CheckItem,
  to: ReleaseRecord,
  base: ReturnType<typeof selectBaseline>,
  introduced: string[] | null,
  created: Map<string, CreatedAtFact>,
): Signal {
  if (item.ecosystem === "PyPI" || item.ecosystem === "Go") {
    return {
      id: "new_dependencies",
      value: "not_applicable",
      evidence: `not applicable: per-release dependency lists are not read for ${item.ecosystem}.`,
      effect: "info",
    };
  }
  if (!base.record) {
    return { id: "new_dependencies", value: null, evidence: `No baseline to diff against: ${base.note}.`, effect: "info" };
  }
  if (introduced === null) {
    return { id: "new_dependencies", value: null, evidence: `Dependency lists for ${to.version} or ${base.record.version} are unavailable.`, effect: "unknown" };
  }
  if (introduced.length === 0) {
    return { id: "new_dependencies", value: [], evidence: `No runtime dependency added since ${base.record.version}.`, effect: "proceed" };
  }
  const ref = to.publishedAt ? Date.parse(to.publishedAt) : Date.now();
  const rows = introduced.map((name) => {
    const fact = created.get(name);
    if (!fact) return { name, first_published: null, age_days: null, note: "not checked (per-call lookup cap)" };
    if (fact.status !== "ok") return { name, first_published: null, age_days: null, note: fact.detail, status: fact.status };
    const age = fact.createdAt ? Math.round(((ref - Date.parse(fact.createdAt)) / DAY_MS) * 10) / 10 : null;
    return { name, first_published: fact.createdAt, age_days: age };
  });
  const young = rows.filter((r) => r.age_days !== null && r.age_days < NEW_DEP_MIN_AGE_DAYS);
  const missing = rows.filter((r) => "status" in r && r.status === "not_found");
  const gaps = rows.filter((r) => r.age_days === null && !("status" in r && r.status === "not_found"));
  const list = rows.map((r) => (r.age_days !== null ? `${r.name} (first published ${r.age_days} days before ${to.version})` : `${r.name} (${r.note})`)).join(", ");
  if (young.length > 0 || missing.length > 0) {
    return {
      id: "new_dependencies",
      value: rows,
      effect: "review",
      evidence: `${to.version} adds ${list} since ${base.record.version}. A brand-new or vanished package as a new dependency is how injected-dependency compromises arrive.`,
    };
  }
  return {
    id: "new_dependencies",
    value: rows,
    effect: gaps.length > 0 ? "unknown" : "proceed",
    evidence: `${to.version} adds ${list} since ${base.record.version}.`,
  };
}

export function withdrawnSignal(item: CheckItem, to: ReleaseRecord): Signal {
  if (to.withdrawn) {
    return { id: "yanked_or_deprecated", value: { [to.withdrawn]: true }, effect: "avoid", evidence: `${item.to} was ${to.withdrawn} from the registry.` };
  }
  if (to.deprecated) {
    return { id: "yanked_or_deprecated", value: { deprecated: to.deprecated }, effect: "avoid", evidence: `${item.to} is deprecated: "${to.deprecated}".` };
  }
  return { id: "yanked_or_deprecated", value: null, effect: "proceed", evidence: `${item.to} is neither yanked nor deprecated.` };
}

/**
 * The bump's semver class. A breaking range (a major, or below 1.0 a minor or
 * 0.0.x patch) is `review`: the supply-chain signals say nothing about whether
 * the project's code survives it. Until 6.0.2 this was information only, so
 * vitest 3 -> 5, reqwest 0.12 -> 0.13 and stripe 22 -> 23 all came back
 * "proceed" and the summary told the agent to apply them (2026-10-07 eval).
 */
export function upgradeTypeSignal(item: CheckItem): Signal {
  const kind = upgradeType(item.from, item.to, item.ecosystem);
  const text = item.from ? `${item.from} -> ${item.to}: ${kind}` : `new dependency at ${item.to}`;
  if (kind === "major") {
    const zeroX = /^v?0\./.test(item.from ?? "") ? " (below 1.0 a minor bump is a major one)" : "";
    return {
      id: "upgrade_type",
      value: kind,
      evidence: `${text}${zeroX}: breaking version range, run upgrade_impact to see what changes for this project.`,
      effect: "review",
    };
  }
  return { id: "upgrade_type", value: kind, evidence: `${text}.`, effect: "info" };
}

export function upgradeType(
  from: string | undefined,
  to: string,
  ecosystem: CheckEcosystem = "npm",
): "patch" | "minor" | "major" | "downgrade" | "none" | "new_dependency" | "unknown" {
  if (!from) return "new_dependency";
  const a = versionParts(ecosystem, from);
  const b = versionParts(ecosystem, to);
  if (!a || !b) return "unknown";
  const cmp = compareIn(ecosystem, to, from);
  if (cmp === 0) return "none";
  if (cmp < 0) return "downgrade";
  if (a.major !== b.major) return "major";
  if (a.minor !== b.minor) return a.major === 0 ? "major" : "minor";
  if (a.major === 0 && a.minor === 0 && a.patch !== b.patch) return "major";
  return "patch";
}

/** The item verdict and its one-line reason, from the strongest signal effect. */
export function decide(signals: Signal[]): { verdict: Verdict; reason: string } {
  for (const verdict of PRECEDENCE) {
    const hits = signals.filter((s) => s.effect === verdict);
    if (hits.length === 0) continue;
    if (verdict === "proceed") {
      const fixes = signals.find((s) => s.id === "release_age" && /security fix/.test(s.evidence));
      return { verdict, reason: fixes ? fixes.evidence : "No advisory, age, trust, script or new-dependency concern found." };
    }
    return { verdict, reason: hits.map((s) => `${s.id}: ${s.evidence}`).join(" | ") };
  }
  return { verdict: "unknown", reason: "No signal could be evaluated." };
}
