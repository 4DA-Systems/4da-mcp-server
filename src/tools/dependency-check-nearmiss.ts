// SPDX-License-Identifier: Apache-2.0
/**
 * dependency_check and names that are one slip away from a popular package (audit 2026-11-11, M2).
 *
 * `expres`, `reactt` and `expresss` each said proceed: all three are on the registry, no advisory
 * names them, and nothing about their releases is wrong. But an agent about to ADD `expres` meant
 * `express`, and a name that close to a popular package is exactly what a typo-squat registers.
 * The near-miss was computed (closestPopularNpm) and only printed beside names npm had already
 * taken down. For most squats there is no advisory yet; the name is the evidence.
 *
 * The rule, for a NEW npm dependency (no `from`) whose name is a near-miss of a popular package
 * (dependency-check-malicious.ts closestPopularNpm: one edit, a dropped `.js` / `-js` / `js` /
 * `node-` affix, or two edits for names of 6 characters or more; never a name that is itself on
 * the popular list):
 * - `review`, with "did you mean X", when the name is not established:
 *   - it has fewer than 10,000 downloads a week, or npm has no download record for it; or
 *   - it has fewer than 100,000 and under one thousandth of the popular package's own (a typo of
 *     a package installed 200 million times a week collects thousands of mistaken installs: on
 *     2026-11-11 `expres` had 5,216 against express's 195 million, `loadsh` 13,444 against
 *     lodash's 202 million); or
 *   - it was first published under 90 days ago; or
 *   - its downloads could not be read. A failed lookup never reads as "established".
 * - `avoid` when the evidence is strong: not established by a count that WAS read, and either
 *   first published under 30 days ago or running install-time scripts, which is how a squat runs
 *   its payload.
 * - nothing (an `info` line) when it is established: `preact` is one edit from `react` and is
 *   its own package.
 *
 * Measured the same day over 2,301 typo-shaped names of 70 popular unscoped packages (the first 70
 * of five characters or more on the bundled list; one character dropped, doubled or swapped with
 * its neighbour, or a `s` / `js` / `-js` suffix): 184 have a download record; 178 have under
 * 10,000 downloads a week, 3 more fall under the one-thousandth rule (dbug, lrucache, loadsh),
 * and 3 are established (ansistyles, findup, ttypescript, 187,000 to 337,000 a week).
 *
 * Data: the packument dependency_check already read (first publish, install scripts) and one
 * request to api.npmjs.org for the two names' weekly downloads, made only for a near-miss.
 * Other ecosystems have no bundled popular list, so the rule is npm's alone.
 */

import type { WeeklyDownloads } from "../live/npm-downloads.js";
import { POPULAR_NPM } from "../live/popular-npm.js";
import { closestPopularNpm, editDistance } from "./dependency-check-malicious.js";
import type { Signal } from "./dependency-check-signals.js";

/** Under this many downloads a week a near-miss name is not established. */
export const LOW_WEEKLY_DOWNLOADS = 10_000;
/** At or above this many it is established whatever the popular package's own count. */
export const ESTABLISHED_WEEKLY_DOWNLOADS = 100_000;
/** Between the two: established only at this share of the popular package's downloads or more. */
export const TYPO_TRAFFIC_SHARE = 1 / 1000;
/** A package first published more recently than this is "very young". */
export const YOUNG_PACKAGE_DAYS = 90;
/** Younger than this, with a low count: strong evidence. */
export const NEW_PACKAGE_DAYS = 30;
const DAY_MS = 86_400_000;

const POPULAR = new Set(POPULAR_NPM);

export interface NearMiss {
  /** The popular package the name resembles. */
  of: string;
  closeness: "one_edit" | "two_edits" | "affix";
}

/** The popular npm package `name` is a near-miss of, and how close; null for a popular name and for anything else. */
export function nearMissOf(name: string): NearMiss | null {
  const n = name.trim().toLowerCase();
  if (POPULAR.has(n)) return null;
  const of = closestPopularNpm(n);
  if (!of) return null;
  const d = editDistance(n, of, 2);
  return { of, closeness: d === 1 ? "one_edit" : d === 2 ? "two_edits" : "affix" };
}

const CLOSENESS: Record<NearMiss["closeness"], string> = {
  one_edit: "one character away from",
  two_edits: "two characters away from",
  affix: "the same name, with an affix, as",
};

/** The name-check signal for a new npm dependency whose name is a near-miss (see the module comment). */
export function nameCheckSignal(input: {
  package: string;
  nearMiss: NearMiss;
  /** Weekly downloads of the name itself. */
  downloads: WeeklyDownloads;
  /** Weekly downloads of the popular package it resembles, when they could be read. */
  popularDownloads: WeeklyDownloads | undefined;
  /** When the package was first published, or null when the registry does not say. */
  createdAt: string | null;
  /** Install-time scripts of the release being judged; null when unknown. */
  installScripts: string[] | null;
  now: Date;
}): Signal {
  const { nearMiss, downloads } = input;
  const pkg = input.package;
  const weekly = downloads.status === "ok" ? downloads.downloads : downloads.status === "no_data" ? 0 : null;
  const popular = input.popularDownloads?.status === "ok" ? input.popularDownloads.downloads : null;
  const ageDays = input.createdAt && Number.isFinite(Date.parse(input.createdAt)) ? Math.floor((input.now.getTime() - Date.parse(input.createdAt)) / DAY_MS) : null;
  const scripts = input.installScripts ?? [];
  const n = (x: number) => x.toLocaleString("en-US");

  // Why the name is not established, each a fact that was read (or a lookup that failed).
  const weak: string[] = [];
  let countRead = false;
  if (weekly === null) {
    weak.push(`its weekly downloads could not be read (${downloads.status === "unreachable" ? downloads.detail : "no answer"}), so nothing shows that anyone installs it`);
  } else if (downloads.status === "no_data") {
    countRead = true;
    weak.push("npm has no download record for it");
  } else if (weekly < LOW_WEEKLY_DOWNLOADS) {
    countRead = true;
    weak.push(`it has ${n(weekly)} download${weekly === 1 ? "" : "s"} a week (under ${n(LOW_WEEKLY_DOWNLOADS)})${popular !== null ? `, against ${n(popular)} for ${nearMiss.of}` : ""}`);
  } else if (weekly < ESTABLISHED_WEEKLY_DOWNLOADS && popular !== null && weekly < popular * TYPO_TRAFFIC_SHARE) {
    countRead = true;
    weak.push(`it has ${n(weekly)} downloads a week, under one thousandth of ${nearMiss.of}'s ${n(popular)}: the level mistaken installs alone reach`);
  } else if (weekly < ESTABLISHED_WEEKLY_DOWNLOADS && popular === null) {
    weak.push(`it has ${n(weekly)} downloads a week and ${nearMiss.of}'s own count could not be read to compare`);
  }
  const young = ageDays !== null && ageDays < YOUNG_PACKAGE_DAYS;
  if (young) weak.push(`it was first published ${ageDays} day${ageDays === 1 ? "" : "s"} ago`);

  const value = {
    near_miss_of: nearMiss.of,
    closeness: nearMiss.closeness,
    weekly_downloads: downloads.status === "ok" ? downloads.downloads : null,
    downloads_lookup: downloads.status,
    popular_weekly_downloads: popular,
    first_published: input.createdAt,
    age_days: ageDays,
    install_scripts: scripts,
  };
  const close = `${pkg} is ${CLOSENESS[nearMiss.closeness]} ${nearMiss.of}, one of the most-used npm packages`;
  if (weak.length === 0) {
    return {
      id: "name_check",
      value,
      effect: "info",
      evidence: `${close}, and is established in its own right (${weekly !== null ? `${n(weekly)} downloads a week` : "downloads unknown"}${ageDays !== null ? `, first published ${input.createdAt!.slice(0, 10)}` : ""}): judged as its own package. Make sure it is the one you mean.`,
    };
  }
  // Strong: a count that was read says nobody installs it, and it is brand new or runs code at install.
  const strong: string[] = [];
  if (countRead && ageDays !== null && ageDays < NEW_PACKAGE_DAYS) strong.push(`it is ${ageDays} day${ageDays === 1 ? "" : "s"} old`);
  if (countRead && scripts.length > 0) strong.push(`it runs install-time scripts (${scripts.join(", ")})`);
  const shape = `${close}, and ${weak.join("; ")}.`;
  if (strong.length > 0) {
    return {
      id: "name_check",
      value,
      effect: "avoid",
      evidence: `${shape} A near-miss name that nobody installs, where ${strong.join(" and ")}, is how a typo-squat looks before it is taken down. Do not install it. Did you mean ${nearMiss.of}?`,
    };
  }
  return {
    id: "name_check",
    value,
    effect: "review",
    evidence: `${shape} A misspelled name is how a typo-squat gets installed. Did you mean ${nearMiss.of}? Write ${pkg} only if the user confirms it is the package they want.`,
  };
}
