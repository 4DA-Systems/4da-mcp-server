// SPDX-License-Identifier: Apache-2.0
/**
 * Maintenance-notice predicate, shared by every consumer of a vulnerability
 * scan (vulnerability_scan, get_actionable_signals, what_should_i_know,
 * dependency_health) so they all draw the same line.
 */

import { cweIdsOf, isMalware } from "./malware.js";
import type { OsvVulnerability, VulnerabilityEntry } from "./types.js";
import { samePackageName } from "./version-compare.js";

/** The `informational` kinds that make a notice. `unsound` is a vulnerability: it has real fixes. */
const NOTICE_KINDS: ReadonlySet<string> = new Set(["unmaintained", "notice"]);

const NOTICE_WORDING = /\b(unmaintained|no longer maintained)\b/i;

/** GitHub's severity labels, as OSV carries them in `database_specific.severity`. */
const GRADE_LABELS: ReadonlySet<string> = new Set(["LOW", "MODERATE", "MEDIUM", "HIGH", "CRITICAL"]);

type NoticeRecord = Pick<OsvVulnerability, "summary" | "database_specific" | "affected"> & Partial<Pick<OsvVulnerability, "id" | "aliases" | "severity">>;

/**
 * Is this advisory a maintenance notice rather than a vulnerability?
 *
 * RustSec publishes "X is unmaintained" as an advisory so tooling can see it,
 * and OSV carries it through with no severity and no fixed version. It is real
 * information — an unmaintained dependency is a risk to plan around — but it is
 * not something an attacker can exploit and not something you can upgrade away
 * today, so it does not belong in the same list, the same count, or the same
 * "Review X" recommendation as a live CVE.
 *
 * Live scan: 23 of 41 findings were these (the whole gtk-rs GTK3 family, all
 * five `unic-*` crates, `paste`, `proc-macro-error`, `ttf-parser`), producing
 * 27 "Review" lines around six genuinely actionable upgrades.
 *
 * An entry the scan marked from the record (`maintenance`, isMaintenanceRecord:
 * every entry the scanner builds) is one whatever its wording. Only an entry
 * without that answer (a foreign or stub entry, and the shared held-dependency
 * vector ft-092) falls back to the wording, deliberately NOT on "deprecated",
 * which appears in plenty of real vulnerability summaries. A malicious-package
 * entry is never a notice.
 */
export function isMaintenanceNotice(v: Pick<VulnerabilityEntry, "summary"> & { maintenance?: boolean; malware?: boolean }): boolean {
  if (typeof v.maintenance === "boolean") return v.maintenance;
  if (v.malware) return false;
  return NOTICE_WORDING.test(v.summary || "");
}

/**
 * Why a record is a maintenance notice for one package, or null when it is a vulnerability.
 * - `declared`: the record itself states an informational class for this package
 *   (`database_specific.informational` of `unmaintained` / `notice`, on the package's
 *   `affected[]` entry first, else on the record). RustSec writes it per affected entry, never on
 *   the record: RUSTSEC-2018-0017 (`tempdir` crate has been deprecated; use `tempfile`) carries
 *   it only there.
 * - `wording`: the record states nothing at all (no class, no grade, no category, no fix) and its
 *   summary says "unmaintained" / "no longer maintained".
 *
 * Structured facts beat wording, in this order (audit 2026-11-11, M11: `olm-sys` read proceed
 * while GHSA-p2q9-36vw-c468 grades it HIGH, because both records say "unmaintained"):
 * 1. A malicious-package record (malware.ts) is never a notice.
 * 2. A record that carries a grade is a vulnerability: a severity label, a CVSS vector, or
 *    RustSec's per-package `cvss`. GHSA-p2q9-36vw-c468 "olm-sys: wrapped library unmaintained,
 *    potentially vulnerable" is HIGH.
 * 3. A record that names an exploit category for the package is a vulnerability: RustSec's
 *    `categories` (RUSTSEC-2024-0368 `crypto-failure`, RUSTSEC-2025-0031 `memory-corruption`,
 *    "Unsound public API in unmaintained crate").
 * 4. A stated class decides alone: `unmaintained` / `notice` is a notice, `unsound` or any other
 *    class is not (serde_yml's unsound advisory reads "unmaintained", audit 6.2.5 F-7). RustSec
 *    states `informational: null` for a vulnerability, and that is a statement too.
 * 5. With nothing stated, the wording decides, unless the record has a `fixed` event for the
 *    package: GO-2026-5932 ("golang.org/x/crypto/openpgp is unmaintained, unsafe by design, and
 *    has known security issues") closes its range with a fix, so there is something to move to.
 *
 * Rules 4 and 5 keep the reading both engines pin in the shared vectors (sv-011, sv-018, sv-023,
 * sv-024..027, ft-071..074, ft-092): a declared class with a fix is still a notice there (ring's
 * RUSTSEC-2025-0010), and a bare summary still decides for a record that states nothing.
 * dependency_check, which answers "may I write this version", is stricter: isDeclaredNotice.
 */
export function maintenanceBasis(vuln: NoticeRecord, packageName: string, ecosystem: string): "declared" | "wording" | null {
  if (isMalware(vuln.id ?? "", vuln.aliases ?? [], cweIdsOf(vuln), vuln.summary ?? "")) return null;
  const entries = affectedEntries(vuln, packageName, ecosystem);
  if (carriesGrade(vuln, entries)) return null;
  if (entries.some((a) => Array.isArray(a.database_specific?.categories) && a.database_specific.categories.length > 0)) return null;
  const own = entries.find((a) => a.database_specific?.informational)?.database_specific?.informational;
  const stated = own ?? vuln.database_specific?.informational;
  if (stated) return NOTICE_KINDS.has(stated) ? "declared" : null;
  // RustSec exports the key on every record; `null` there means "not informational": a vulnerability.
  if (entries.some((a) => hasKey(a.database_specific, "informational")) || hasKey(vuln.database_specific, "informational")) return null;
  if (hasFixedEvent(entries)) return null;
  return NOTICE_WORDING.test(vuln.summary ?? "") ? "wording" : null;
}

/** The predicate over an OSV record, for one package (the rule both engines share): see maintenanceBasis. */
export function isMaintenanceRecord(vuln: NoticeRecord, packageName: string, ecosystem: string): boolean {
  return maintenanceBasis(vuln, packageName, ecosystem) !== null;
}

/**
 * dependency_check's reading, for the verdict on a version about to be written: the notice
 * downgrade applies only when the record itself DECLARES the informational class and carries no
 * `fixed` event for the package. A summary that merely says "unmaintained" downgrades nothing
 * there, and a declared notice with a fixed release ("versions before 0.17 are unmaintained") is
 * advice to act on, so it counts.
 */
export function isDeclaredNotice(vuln: NoticeRecord, packageName: string, ecosystem: string): boolean {
  if (maintenanceBasis(vuln, packageName, ecosystem) !== "declared") return false;
  return !hasFixedEvent(affectedEntries(vuln, packageName, ecosystem));
}

type AffectedEntry = NonNullable<OsvVulnerability["affected"]>[number];

function affectedEntries(vuln: NoticeRecord, packageName: string, ecosystem: string): AffectedEntry[] {
  return (vuln.affected ?? []).filter((a) => a.package?.ecosystem === ecosystem && samePackageName(a.package.name, packageName, ecosystem));
}

function carriesGrade(vuln: NoticeRecord, entries: AffectedEntry[]): boolean {
  const label = vuln.database_specific?.severity;
  if (typeof label === "string" && GRADE_LABELS.has(label.trim().toUpperCase())) return true;
  if ((vuln.severity ?? []).some((s) => typeof s?.score === "string" && s.score.trim() !== "")) return true;
  return entries.some((a) => typeof a.database_specific?.cvss === "string" && a.database_specific.cvss.trim() !== "");
}

function hasFixedEvent(entries: AffectedEntry[]): boolean {
  return entries.some((a) => (a.ranges ?? []).some((r) => r.type !== "GIT" && (r.events ?? []).some((e) => e.fixed !== undefined)));
}

function hasKey(value: unknown, key: string): boolean {
  return typeof value === "object" && value !== null && key in value;
}

/**
 * The advisories a scan can actually ask the user to act on today: built on
 * this host AND exploitable (not a maintenance notice). This is the set
 * `vulnerability_scan` reports as `vulnerabilities` / `total_vulnerable_packages`;
 * every other tool that counts "vulnerable" must count the same set or the
 * numbers disagree across tools over one scan.
 */
export function isActionableVulnerability(
  v: Pick<VulnerabilityEntry, "summary" | "platformActive"> & { maintenance?: boolean },
): boolean {
  return v.platformActive !== false && !isMaintenanceNotice(v);
}
