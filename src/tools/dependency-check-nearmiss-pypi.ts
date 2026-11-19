// SPDX-License-Identifier: Apache-2.0
/**
 * dependency_check and PyPI names one slip away from a popular project: npm's near-miss check
 * (dependency-check-nearmiss.ts) on PyPI. `numpi` said proceed: it is on PyPI, no advisory names
 * it, nothing about its releases is wrong, and an agent about to add it meant numpy.
 *
 * The rule, for a PyPI dependency this project's lockfiles do not hold whose name (PEP 503
 * normalised) is a near-miss of a popular project (briefing-names.ts closestPopularPypi: one edit
 * for names of 5 characters or more, two for 8 or more; never a name on the popular list itself):
 * - `review`, with "did you mean X", unless the name is established;
 * - `avoid` when it was first published under 30 days ago with at most 3 releases: a near-miss
 *   name nobody can have come to rely on yet is how a typo-squat looks before it is taken down;
 * - nothing (an `info` line) when it is established.
 *
 * PyPI publishes no download counts (npm's measure), so "established" is read from the project's
 * own history in the document dependency_check already fetched: first published at least 2 years
 * ago, with at least 10 releases. A history that cannot be read never counts as established. No
 * request is made for this check.
 */

import type { PackageReleaseIndex } from "../live/release-metadata.js";
import { closestPopularPypi, normalizePypiName } from "./briefing-names.js";
import { editDistance } from "./dependency-check-malicious.js";
import { NEW_PACKAGE_DAYS } from "./dependency-check-nearmiss.js";
import type { Signal } from "./dependency-check-signals.js";

/** First published at least this long ago... */
export const ESTABLISHED_PYPI_DAYS = 730;
/** ...with at least this many releases: established in its own right. */
export const ESTABLISHED_PYPI_RELEASES = 10;
/** A near-miss this new with this few releases: strong evidence. */
const FEW_RELEASES = 3;
const DAY_MS = 86_400_000;

/** The popular PyPI project `name` is a near-miss of, and how close; null otherwise. */
export function pypiNearMissOf(name: string): { of: string; closeness: "one_edit" | "two_edits" } | null {
  const of = closestPopularPypi(name);
  if (!of) return null;
  return { of, closeness: editDistance(normalizePypiName(name), of, 2) === 1 ? "one_edit" : "two_edits" };
}

/** The name-check signal for a PyPI dependency whose name is a near-miss (see the module comment). */
export function pypiNameCheckSignal(input: { package: string; nearMiss: { of: string; closeness: "one_edit" | "two_edits" }; index: PackageReleaseIndex; now: Date }): Signal {
  const { nearMiss, index } = input;
  const pkg = input.package;
  const releases = Object.keys(index.releases).length;
  const at = index.createdAt && Number.isFinite(Date.parse(index.createdAt)) ? index.createdAt : null;
  const ageDays = at ? Math.floor((input.now.getTime() - Date.parse(at)) / DAY_MS) : null;
  const value = {
    near_miss_of: nearMiss.of,
    closeness: nearMiss.closeness,
    first_published: at,
    age_days: ageDays,
    releases,
    weekly_downloads: null,
    downloads_lookup: "not_applicable",
  };
  const close = `${pkg} is ${nearMiss.closeness === "one_edit" ? "one character" : "two characters"} away from ${nearMiss.of}, one of the most-used PyPI projects`;
  const history = `${at ? `first published ${at.slice(0, 10)} (${ageDays} day${ageDays === 1 ? "" : "s"} ago)` : "no first publish date on record"}, ${releases} release${releases === 1 ? "" : "s"}`;
  if (ageDays !== null && ageDays >= ESTABLISHED_PYPI_DAYS && releases >= ESTABLISHED_PYPI_RELEASES) {
    return { id: "name_check", value, effect: "info", evidence: `${close}, and is established in its own right (${history}): judged as its own package. Make sure it is the one you mean.` };
  }
  const shape = `${close}, and nothing shows it is established: PyPI publishes no download counts, and its history is short (${history}; a project is taken as established at ${ESTABLISHED_PYPI_DAYS / 365} years and ${ESTABLISHED_PYPI_RELEASES} releases).`;
  if (ageDays !== null && ageDays < NEW_PACKAGE_DAYS && releases <= FEW_RELEASES) {
    return { id: "name_check", value, effect: "avoid", evidence: `${shape} A near-miss name this new, that nobody can have come to rely on yet, is how a typo-squat looks before it is taken down. Do not install it. Did you mean ${nearMiss.of}?` };
  }
  return { id: "name_check", value, effect: "review", evidence: `${shape} A misspelled name is how a typo-squat gets installed. Did you mean ${nearMiss.of}? Write ${pkg} only if the user confirms it is the package they want.` };
}
