// SPDX-License-Identifier: Apache-2.0
/**
 * The scan's instruction for each vulnerable copy, for the tools that report the same findings.
 *
 * One advisory gets one instruction in every tool. get_actionable_signals and what_should_i_know
 * give, for a package version, the line vulnerability_scan's `recommendations` holds for it, built
 * by the same functions from the same inputs: the target checked against every advisory of the
 * package, then the planner's fix-path verdict (lockfile refresh, parent upgrade, override or
 * replace, blocked upstream). They never word a fix of their own from an advisory's "fixed" field:
 * zip 8.6.0 under docx-rs read "Upgrade zip: the advisory names 9.0.0 as its fix" in the signals
 * while the scan said blocked upstream at 9.0.5 and dependency_check called 9.0.0 avoid.
 */

import type { FixTargetResult } from "../live/fix-paths.js";
import { LiveIntelligence } from "../live/index.js";
import type { VulnerabilityEntry, VulnerabilityScanResult } from "../live/types.js";
import { driftAction, groupDriftRows, installDriftAdvisories } from "./install-drift-notes.js";
import { fixTargetKey, formatScanResult } from "./vulnerability-scan-format.js";
import { scanVerdicts, verifyScanTargets } from "./vulnerability-scan.js";

export interface ScanAdvice {
  /** The scan's recommendation line per vulnerable copy, keyed fixTargetKey(ecosystem, package, version). */
  lines: ReadonlyMap<string, string>;
  /** The reinstall instruction per drifted copy (node_modules holds what the lockfile does not pin), keyed driftKey(). */
  reinstalls: ReadonlyMap<string, string>;
  /** The scan's upgrade target per vulnerable copy, checked against every advisory of the package, keyed fixTargetKey(). */
  targets: ReadonlyMap<string, FixTargetResult>;
}

/** One drifted copy: the package, the version node_modules holds, and the one its lockfile pins. */
function driftKey(v: Pick<VulnerabilityEntry, "ecosystem" | "package" | "currentVersion" | "installDriftOf">): string {
  return `${v.ecosystem}\0${v.package}\0${v.currentVersion}\0${v.installDriftOf ?? ""}`;
}

/**
 * The scan's instruction for every vulnerable copy in `scan`. Only the live layer itself can run
 * the target and fix-path checks; for anything else they do not run, and each line then says its
 * target was NOT CHECKED, as the scan's own lines do in that state.
 */
export async function scanAdvice(intel: unknown, scan: VulnerabilityScanResult): Promise<ScanAdvice> {
  const scanner = intel instanceof LiveIntelligence ? intel : null;
  const [verifiedTargets, verdicts] = scanner ? await Promise.all([verifyScanTargets(scanner, scan), scanVerdicts(scanner, scan)]) : [undefined, undefined];
  const lines = new Map<string, string>();
  formatScanResult(scan, undefined, { resolution: null, reResolvedThisCall: false, drift: [], includeDev: true, verifiedTargets, verdicts, recommendationsByCopy: lines });
  // installDriftAdvisories gives one advisory per group of groupDriftRows, in that order: the
  // briefing's words for a reinstall, which name the same command the scan's reinstall line does.
  const groups = groupDriftRows(scan.vulnerabilities);
  const drift = installDriftAdvisories(scan);
  const reinstalls = new Map(groups.map((group, i) => [driftKey(group[0]), drift[i].action]));
  return { lines, reinstalls, targets: verifiedTargets ?? new Map() };
}

/**
 * A maintenance notice ("X is unmaintained") as the scan treats it: not a vulnerability, listed
 * apart under maintenance_notices and counted in no total, with nothing to upgrade to. Never
 * worded as an advisory whose fix is missing ("No fix is published for chrono").
 */
export function maintenanceAction(pkg: string, version: string): string {
  return `Maintenance notice, not a vulnerability: ${pkg} ${version}. Nothing in it is exploitable and it calls for no upgrade: plan around it (a replacement, when the package is unmaintained). vulnerability_scan lists it under maintenance_notices and counts it in no total.`;
}

/** The same for an advisory record in the 4DA feed that reads as a maintenance notice. */
export const FEED_MAINTENANCE_ACTION =
  "Maintenance notice (advisory record), not a vulnerability: nothing in it is exploitable and it calls for no upgrade; plan around it.";

/** No advice: every copy's line says its step was not determined. */
export const NO_SCAN_ADVICE: ScanAdvice = { lines: new Map(), reinstalls: new Map(), targets: new Map() };

/** The scan's instruction for this copy; without one, a NOT CHECKED sentence that names no version. */
export function adviceFor(advice: ScanAdvice, v: VulnerabilityEntry): string {
  if (v.installDriftOf) return advice.reinstalls.get(driftKey(v)) ?? driftAction(v);
  return (
    advice.lines.get(fixTargetKey(v.ecosystem, v.package, v.currentVersion)) ??
    `NOT CHECKED: how to fix ${v.package} ${v.currentVersion} was not determined in this call; vulnerability_scan with package "${v.package}" gives the step. Never bump it to an advisory's own fixed version without that check.`
  );
}
