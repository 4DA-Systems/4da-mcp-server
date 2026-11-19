// SPDX-License-Identifier: Apache-2.0
/**
 * dependency_check, the reason text of an answer (dependency-check.ts checkPass): what was found,
 * then the safe releases to write instead, or why none is named.
 */

import { andList } from "../live/held-dependencies.js";
import type { Verdict } from "./dependency-check-signals.js";
import type { RangeCheck } from "./dependency-check-versions.js";
import type { ListGap, Resolved } from "./dependency-check-items.js";

/**
 * The reason, plus the safe releases to write instead when the verdict is against `to`. `verdict`
 * decides how an incomplete advisory list is worded: under a proceed or wait the version checked
 * WAS confirmed, so the reason says what was confirmed and never "NOT CHECKED" (pre-publish audit
 * 2026-11-14: a proceed reason read "NOT CHECKED: OSV.dev's advisory list ... left out ...").
 */
export function withAlternatives(reason: string, item: Resolved, verdict: Verdict): string {
  const unsafe = verdict === "avoid" || verdict === "review";
  const confirmed = verdict === "proceed" || verdict === "wait";
  if (item.listGap) return `${reason} | ${confirmed ? listGapConfirmedText(item, item.listGap) : listGapText(item.package, item.listGap)}`;
  if (item.batchUnread) return `${reason} | ${confirmed ? batchUnreadConfirmedText(item.package) : batchUnreadText(item.package, item.batchUnread)}`;
  const rc = item.rangeCheck;
  if (!rc) return reason;
  const where = rc.basis === "requested" ? `in ${rc.range}` : `on ${item.to}'s line (${rc.range})`;
  // The registry's own words about a withheld release are data in their own field, never here.
  const quoted = rc.quoted_from_registry ? " The registry's message is in range_check.quoted_from_registry." : "";
  if (rc.smallest_safe_in_range === null) {
    if (rc.releases_in_range === 0 && rc.prereleases_not_offered) {
      // Only prereleases there, and none was asked for: none is named as the safe release.
      const n = rc.prereleases_not_offered;
      const outsideIt = rc.newest_safe_outside_range ? ` Newest safe release outside it: ${rc.newest_safe_outside_range}.` : "";
      return `${reason} | No stable release ${where}: the ${n} release${n === 1 ? "" : "s"} there ${n === 1 ? "is a prerelease" : "are prereleases"}, and a prerelease is never offered as the safe release unless you ask for one.${outsideIt}`;
    }
    const ids = rc.affecting_all ?? [];
    // The count comes from the uncapped total: `affecting_all` names at most 10.
    const total = Math.max(rc.affecting_all_total ?? ids.length, ids.length);
    const all = ids.length ? `: ${ids.slice(0, 3).join(", ")}${total > 3 ? ` and ${total - 3} more` : ""} ${total === 1 ? "affects" : "affect"} every one` : "";
    const outside = rc.newest_safe_outside_range ? ` Newest safe release outside it: ${rc.newest_safe_outside_range}.` : "";
    const withheld = rc.withheld_note ? ` ${rc.withheld_note}.${quoted}` : "";
    // OSV.dev's own answer for `to` lists no advisory, but the published ranges of these advisories
    // read (fail-closed) as covering every release: apache-airflow ">=1.10" said proceed 3.4.0 and
    // "No release ... is free of known advisories" in one breath (`last_affected: "2.9.0-NA"`;
    // blind audit 2026-11-14). Say which is which instead of contradicting the verdict.
    // r7 blocker: releases left out only because what they hold could not be judged are NOT
    // CHECKED, not affected; a healthy run may name them safe. Say that, never "free of advisories".
    if (rc.held_not_checked && (rc.affecting_all_total ?? 0) === 0) {
      return `${reason} | ${item.ecosystem === "npm" ? heldNotCheckedText(item.package, where, rc) : requirementsNotCheckedText(item.package, where, rc)}${withheld}`;
    }
    // PyPI: the releases that clear the advisories do not support the Python the project declares.
    if (rc.python_excluded && (rc.affecting_all_total ?? 0) === 0) {
      const n = rc.python_excluded;
      const h = rc.held_excluded ?? 0;
      const heldToo = h > 0 ? `; ${h} more require a dependency whose newest admitted release (or exact pin) has a known advisory` : "";
      // Outside the range too, nothing was found that is clear and supports it (not "is affected":
      // a release whose requirements were not judged is not counted clear).
      const none = rc.newest_safe_outside_range ? "" : ` No release of ${item.package} outside it was found both clear of known advisories and supporting that Python.`;
      // Nothing there is affected: the Python is the only reason, and no advisory is implied.
      if (rc.vulnerable_in_range === 0) {
        return `${reason} | No release ${where} supports the Python this project declares (${rc.python_note}).${withheld}${outside}${none}`;
      }
      return `${reason} | No release ${where} clears ${item.package}'s advisories on the Python this project declares: the ${n} release${n === 1 ? "" : "s"} that clear${n === 1 ? "s" : ""} them ${n === 1 ? "does" : "do"} not support it (${rc.python_note})${heldToo}.${withheld}${outside}${none}`;
    }
    // crates.io, PyPI: every release clear of the package's own advisories requires a dependency
    // held at an affected release. That is why none is named, and it is not the package's own advisory.
    if (item.ecosystem !== "npm" && rc.held_excluded && (rc.affecting_all_total ?? 0) === 0) {
      const n = rc.held_excluded;
      return `${reason} | No release ${where} is named safe: the ${n} release${n === 1 ? "" : "s"} clear of ${item.package}'s own advisories ${n === 1 ? "requires" : "require"} a dependency whose newest admitted release (or exact pin) has a known advisory.${withheld}${outside}`;
    }
    if (!unsafe && ids.length > 0) {
      return `${reason} | OSV.dev lists no advisory against ${item.to}, but the published ranges of ${ids.slice(0, 3).join(", ")}${total > 3 ? ` and ${total - 3} more` : ""} cannot rule out any release ${where}, so no other release there is vouched for.${withheld}${outside}`;
    }
    return `${reason} | No release ${where} is free of known advisories${all}.${withheld}${heldAdviceText(item, rc)}${outside}`;
  }
  const upgrade = rc.smallest_safe_upgrade && rc.smallest_safe_upgrade !== rc.smallest_safe_in_range ? `, smallest above ${item.from} ${rc.smallest_safe_upgrade}` : "";
  // FX-H5: a withdrawn release the pick steps over is named (the registry's words are quoted beside it).
  const withheld = rc.withheld_note ? ` ${rc.withheld_note}.${quoted}` : "";
  // audit 6.2.5 D-4: releases passed over for what they hold are counted, never dropped silently.
  const heldOut = rc.held_excluded ? ` ${rc.held_excluded} release${rc.held_excluded === 1 ? "" : "s"} clear of ${item.package}'s own advisories left out: ${rc.held_note}.` : "";
  const pythonOut = rc.python_excluded ? ` ${rc.python_excluded} release${rc.python_excluded === 1 ? "" : "s"} clear of advisories left out for the project's Python: ${rc.python_note}.` : "";
  // Blind audit round 4: a safe release inside the release-age hold is never named silently.
  const tooNew = rc.too_new_note ? ` ${rc.too_new_note}.` : "";
  // Go: a named pick that requires an affected minimum is never named without that said.
  const caveats = rc.requirement_caveats ? ` ${Object.values(rc.requirement_caveats).join(". ")}.` : "";
  const safe = `Safe ${where}: smallest ${rc.smallest_safe_in_range}${upgrade}, newest ${rc.newest_safe_in_range}.${withheld}${heldOut}${pythonOut}${tooNew}${caveats}`;
  if (rc.basis === "same_line" && !unsafe) return reason;
  // Round 8 (B2): the verdict is on what the constraint installs; a safe release in it is written as an exact pin.
  const pin = item.from ? (rc.smallest_safe_upgrade ?? null) : rc.newest_safe_in_range;
  const pinIt = item.resolvesRange && verdict !== "proceed" && pin && pin !== item.to
    ? ` Pin exactly ${pin}; the range as written resolves to ${item.to} (${verdict}).`
    : "";
  return `${reason} | ${safe}${pinIt}`;
}

/** The batch query names advisories for releases that the list's own ranges do not show as affected. */
function misreadText(pkg: string, gap: ListGap): string {
  const ids = gap.misread ?? [];
  return `OSV.dev's batch query names ${ids.slice(0, 3).join(", ")}${ids.length > 3 ? ` and ${ids.length - 3} more` : ""} for ${pkg} ${andList(gap.versions)}, which the ranges in ${pkg}'s advisory list (/v1/query) do not show as affecting ${gap.versions.length === 1 ? "it" : "them"}`;
}

/** NOT CHECKED: the package's advisory list is incomplete (Resolved.listGap), so no release is named. */
export function listGapText(pkg: string, gap: ListGap): string {
  if (gap.ids.length === 0) return `NOT CHECKED: ${misreadText(pkg, gap)}, so those ranges cannot be relied on and no release of ${pkg} is named safe from them (the verdict on the version checked comes from the batch query and stands). Check a specific version with dependency_check.`;
  const ids = `${gap.ids.slice(0, 3).join(", ")}${gap.ids.length > 3 ? ` and ${gap.ids.length - 3} more` : ""}`;
  return `NOT CHECKED: OSV.dev's advisory list for ${pkg} (/v1/query) left out ${ids}, which its batch query names for ${andList(gap.versions)}, so the list is incomplete and no release of ${pkg} is named safe from it (the verdict on the version checked comes from the batch query and stands). Check again later, or check a specific version with dependency_check.`;
}

/** The same gap under a proceed or wait: what was confirmed comes first, and nothing reads as NOT CHECKED. */
function listGapConfirmedText(item: Resolved, gap: ListGap): string {
  if (gap.ids.length === 0) return `OSV.dev's batch check lists no advisory for ${item.package} ${item.to}. ${misreadText(item.package, gap)}, so other releases were not compared and none is named as an alternative.`;
  const ids = `${gap.ids.slice(0, 3).join(", ")}${gap.ids.length > 3 ? ` and ${gap.ids.length - 3} more` : ""}`;
  return `OSV.dev's batch check lists no advisory for ${item.package} ${item.to}. Its full advisory list for ${item.package} (/v1/query) was incomplete (it left out ${ids}, which the batch check names for ${andList(gap.versions)}), so other releases were not compared and none is named as an alternative.`;
}

/** The batch gap under a proceed or wait (not reached today: an unread batch makes the advisories signal unknown). */
function batchUnreadConfirmedText(pkg: string): string {
  return `${pkg}'s full advisory list (/v1/query) could not be held against a current batch answer, so other releases were not compared and none is named as an alternative.`;
}

/** NOT CHECKED: no release in range is named safe because what they hold could not be judged (r7 blocker). */
function heldNotCheckedText(pkg: string, where: string, rc: RangeCheck): string {
  const n = rc.held_not_checked ?? 0;
  return `NOT CHECKED: no release of ${pkg} ${where} is named safe: ${n} release${n === 1 ? "" : "s"} clear of ${pkg}'s own advisories ${n === 1 ? "holds" : "hold"} dependencies (exact pins or ranges) whose advisories could not be checked (${rc.held_not_checked_reason}). This is not a clean result and names no version to write: check again later.`;
}

/** The same for crates.io and PyPI, where a release is left out until what it requires has been examined. */
function requirementsNotCheckedText(pkg: string, where: string, rc: RangeCheck): string {
  const n = rc.held_not_checked ?? 0;
  const affected = (rc.held_excluded ?? 0) - n;
  const examined = affected > 0 ? `, and the ${affected} examined ${affected === 1 ? "requires" : "require"} a dependency whose newest admitted release (or exact pin) has a known advisory` : "";
  return `NOT CHECKED: no release of ${pkg} ${where} is named safe: what ${n} release${n === 1 ? "" : "s"} clear of ${pkg}'s own advisories ${n === 1 ? "requires" : "require"} was not examined (${rc.held_not_checked_reason})${examined}. This is not a clean result and names no version to write: check a specific release with dependency_check.`;
}

/** NOT CHECKED: the batch query gave no current answer (Resolved.batchUnread), so no release is named. */
export function batchUnreadText(pkg: string, why: string): string {
  return `NOT CHECKED: OSV.dev's batch query gave no current answer (${why}), so ${pkg}'s advisory list (/v1/query) could not be confirmed complete and no release of ${pkg} is named safe. This is not a clean result: check again later.`;
}

/**
 * " Only a low or moderate advisory on a dependency they install keeps them out: 24.0.5 holds
 * minimatch 10.2.5 (GHSA-x, medium). 13.2.4, the newest release clear of every advisory, is not
 * offered: 11 majors below 24.0.5 [...]. To install 24.0.5 without it, override minimatch to ..."
 */
function heldAdviceText(item: Resolved, rc: RangeCheck): string {
  const advice = rc.held_advice;
  if (!advice) return "";
  const deps = advice.dependencies;
  const one = deps.length === 1;
  const named = andList(deps.map((d) => `${d.package} ${d.installs} (${d.advisories.join(", ")}, ${d.severity})`));
  const subject = advice.alternative ?? item.to;
  const notOffered = advice.not_offered
    ? ` ${advice.not_offered.version}, the newest release clear of every advisory, is not offered: ${advice.not_offered.reason}.`
    : "";
  // A high or critical one keeps the verdict at avoid; the override is still what clears it.
  const serious = deps.some((d) => d.severity === "high" || d.severity === "critical");
  const held = advice.alternative
    ? `${notOffered} The newest release clear of ${item.package}'s own advisories is ${subject}, which holds ${named}: check it with dependency_check.`
    : serious
      ? ` What keeps them out is a dependency they install: ${subject} holds ${named}. A high or critical advisory, so ${subject} as published stays avoid.${notOffered}`
      : ` Only a low or moderate advisory on a dependency they install keeps them out: ${subject} holds ${named}.${notOffered}`;
  const overrides = deps
    .filter((d) => d.fixed_in)
    .map((d) => {
      const major = (v: string) => v.split(".")[0];
      const newMajor = major(d.fixed_in!) !== major(d.installs) ? `, a new major of ${d.package}: check that ${item.package} works with it` : "";
      return `${d.package} to ${d.fixed_in}${newMajor}`;
    });
  const unfixed = deps.filter((d) => !d.fixed_in).map((d) => d.package);
  const how =
    overrides.length > 0
      ? ` To install ${subject} without ${one ? "it" : "them"}, override ${andList(overrides)} (npm "overrides", pnpm "overrides", Yarn "resolutions")${unfixed.length > 0 ? ` (no fixed release of ${andList(unfixed)} is known)` : ""}, or wait for a later ${item.package} release that moves past ${one ? "it" : "them"}.`
      : ` No fixed release of ${andList(unfixed)} is known: wait for one, and for a ${item.package} release that takes it, or accept the advisory knowingly.`;
  return `${held}${how}`;
}
