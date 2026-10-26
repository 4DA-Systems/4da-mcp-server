// SPDX-License-Identifier: Apache-2.0
/**
 * One severity rule for every surface (AD-046).
 *
 * The desktop app grades an advisory by where the vulnerable package sits in
 * the dependency graph, and every 4DA surface presents that one grade. This
 * module is the MCP server's copy of the rule. Its Rust twin is
 * `osv::identity::scope_adjusted_urgency` (src-tauri/src/osv/identity.rs):
 * change one, change both, or the MCP server and the app disagree about the
 * same advisory again.
 *
 * Measured 2026-09-10: `vulnerability_scan` graded `sandbox@3.1.2` (a
 * transitive of paddle-webhook, dev/runtime scope unknown) CRITICAL
 * (`by_severity.critical: 1`, and the briefing read "CRITICAL: Sandbox
 * Breakout") while the app graded the same advisory High.
 *
 * The rule, applied in this order:
 *   (a) transitive-only clamps critical to high;
 *   (b) dev-only drops ONE level: critical to high, high to medium, medium to
 *       low; low stays low.
 * `unknown` stays `unknown` through both steps. Unknown dev scope is not dev:
 * no discount without evidence. The advisory's own tier is never discarded;
 * surfaces carry it beside the presented grade as `advisory_severity`.
 */

import type { VulnerabilityEntry } from "./types.js";
import { isMalware } from "./malware.js";

export type SeverityTier = VulnerabilityEntry["severity"];

export interface DependencyScope {
  isDirect: boolean;
  isDev: boolean;
  devScopeKnown: boolean;
}

/**
 * Dev-only: EVERY installed path to this copy goes through dev dependencies (vulnerability_scan's
 * `is_dev` with a known scope: a direct devDependency, or a transitive the lockfile marks dev).
 * The one population `include_dev: false` leaves out, in vulnerability_scan, dependency_health and
 * upgrade_planner alike. The three meant three things: health left out only direct
 * devDependencies yet said "devDependencies left out" (NodeGoat: 82 vulnerable packages where 34
 * are runtime), the scan kept 225 dev-only rows, and the planner dropped all 90 dev-only copies
 * (final release audit of 6.2.5, finding 6).
 */
export function isDevOnlyCopy(d: { isDev: boolean; devScopeKnown?: boolean }): boolean {
  return d.isDev === true && d.devScopeKnown === true;
}

const ONE_LEVEL_DOWN: Record<SeverityTier, SeverityTier> = {
  critical: "high",
  high: "medium",
  medium: "low",
  low: "low",
  unknown: "unknown",
};

/** Ordering for sorts and "at or above" filters; unknown ranks lowest. */
export const SEVERITY_RANK: Record<SeverityTier, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  unknown: 0,
};

/**
 * THE rule. Twin of the Rust `osv::identity::scope_adjusted_urgency`.
 *
 * direct runtime critical -> critical; transitive runtime critical -> high;
 * direct dev critical -> high; transitive dev critical -> medium;
 * direct dev high -> medium; transitive dev high -> medium;
 * transitive runtime high -> high.
 */
export function scopeAdjustedSeverity(advisory: SeverityTier, scope: DependencyScope): SeverityTier {
  let tier = advisory;
  if (!scope.isDirect && tier === "critical") tier = "high";
  if (scope.devScopeKnown && scope.isDev) tier = ONE_LEVEL_DOWN[tier];
  return tier;
}

type ScopedEntry = Pick<VulnerabilityEntry, "severity" | "isDirect" | "isDev" | "devScopeKnown" | "malware">;

/**
 * The grade a surface presents for one scan entry. A missing `isDirect`
 * (never produced today; defensive for foreign cache rows) is treated as
 * direct, and a missing `devScopeKnown` as unknown: both mean no discount.
 */
export function presentedSeverity(v: ScopedEntry): SeverityTier {
  // An installed malicious copy is critical wherever it sits: a transitive or
  // dev-only copy runs its install scripts all the same. The scan capped it at
  // high for a transitive copy while the planner said critical (audit 6.2.5 D-3).
  if (v.malware === true) return "critical";
  return scopeAdjustedSeverity(v.severity, {
    isDirect: v.isDirect !== false,
    isDev: v.isDev === true,
    devScopeKnown: v.devScopeKnown === true,
  });
}

/**
 * Why the presented grade differs from the advisory's own tier, in words, or
 * null when it does not differ.
 */
export function scopeAdjustmentReason(v: ScopedEntry): string | null {
  if (presentedSeverity(v) === v.severity) return null;
  const transitive = v.isDirect === false;
  const dev = v.devScopeKnown === true && v.isDev === true;
  if (transitive && dev) return "transitive, dev-only dependency";
  if (dev) return "dev-only dependency";
  return "transitive-only dependency";
}

export type SeverityCounts = Record<SeverityTier, number>;

/** Count entries per tier, using whichever tier function the caller names. */
export function countBySeverity<T>(entries: T[], tierOf: (entry: T) => SeverityTier): SeverityCounts {
  const counts: SeverityCounts = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
  for (const entry of entries) counts[tierOf(entry)]++;
  return counts;
}

/**
 * The tier a finding RANKS by (the 4DA app's base urgency, severity vectors sv-004/sv-010/sv-019),
 * then the scope rule, as presentedSeverity applies it: an ungraded advisory ranks medium, a
 * malicious-package record (MAL-) at least high. A dev-only medium ranks low, as the scan presents
 * it; the planner kept it at medium (final release audit, finding 2 and the 4DA severity parity).
 */
export function rankedSeverity(v: ScopedEntry & { vulnId?: string; aliases?: string[]; malware?: boolean; summary?: string }): Exclude<SeverityTier, "unknown"> {
  // An installed malicious copy is critical (the 4DA lead, 2026-10-18), whatever its own grade.
  if (v.malware === true || isMalware(v.vulnId ?? "", v.aliases ?? [], [], v.summary ?? "")) return "critical";
  const base = v.severity === "unknown" ? "medium" : v.severity;
  const tier = presentedSeverity({ ...v, severity: base });
  return tier === "unknown" ? "medium" : tier;
}
