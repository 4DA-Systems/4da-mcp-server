// SPDX-License-Identifier: Apache-2.0
/**
 * Maintenance-notice predicate, shared by every consumer of a vulnerability
 * scan (vulnerability_scan, get_actionable_signals, what_should_i_know,
 * dependency_health) so they all draw the same line.
 */

import type { OsvVulnerability, VulnerabilityEntry } from "./types.js";
import { samePackageName } from "./version-compare.js";

/** The `informational` kinds that make a notice. `unsound` is a vulnerability: it has real fixes. */
const NOTICE_KINDS: ReadonlySet<string> = new Set(["unmaintained", "notice"]);

const NOTICE_WORDING = /\b(unmaintained|no longer maintained)\b/i;

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
 * Matched on the advisory's own wording, which RustSec keeps consistent, and
 * deliberately NOT on "deprecated" — that word appears in plenty of real
 * vulnerability summaries. An entry the scan marked from the record's
 * `informational` field (`maintenance`, isMaintenanceRecord) is one whatever
 * its wording.
 */
export function isMaintenanceNotice(v: Pick<VulnerabilityEntry, "summary"> & { maintenance?: boolean }): boolean {
  return v.maintenance === true || NOTICE_WORDING.test(v.summary || "");
}

/**
 * The same predicate over an OSV record, for one package (the rule both engines
 * share, vectors ft-074 / sv-024): the summary wording, OR `informational` of
 * `unmaintained` / `notice` on the record, OR on an `affected[]` entry for this
 * package. RustSec writes it per affected entry, never on the record:
 * RUSTSEC-2018-0017 (`tempdir` crate has been deprecated; use `tempfile`)
 * carries it only there, and was graded a vulnerability while only the record
 * level was read.
 */
export function isMaintenanceRecord(
  vuln: Pick<OsvVulnerability, "summary" | "database_specific" | "affected">,
  packageName: string,
  ecosystem: string,
): boolean {
  if (NOTICE_WORDING.test(vuln.summary ?? "")) return true;
  if (NOTICE_KINDS.has(vuln.database_specific?.informational ?? "")) return true;
  return (vuln.affected ?? []).some(
    (a) =>
      a.package?.ecosystem === ecosystem &&
      samePackageName(a.package.name, packageName, ecosystem) &&
      NOTICE_KINDS.has(a.database_specific?.informational ?? ""),
  );
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
