// SPDX-License-Identifier: Apache-2.0
/**
 * dependency_check: the release a package manager installs for what the agent writes, when that is
 * more than one release (pre-publish round 10, W2). Each is judged in full and the WORSE verdict
 * stands, so a clean answer never covers a release the agent's write can still install.
 *
 * - Cargo: a bare "1.6.0" in Cargo.toml is the requirement ^1.6.0. A Cargo.lock that already holds
 *   1.6.0 keeps it (it satisfies ^1.6.0); a fresh resolve (no lock entry, `cargo update`) installs
 *   the newest release ^1.6.0 admits (smallvec: 1.16.5). It was judged as an exact pin only:
 *   smallvec "1.6.0" said avoid without saying that, and a bare version whose newest compatible
 *   release is bad said proceed. "=1.6.0" is exactly 1.6.0, and stays one release.
 * - npm: `npm install` takes the `latest` dist-tag when the range admits it and it is not
 *   deprecated, else the highest admitted release that is not deprecated, else the highest
 *   (npm-pick-manifest 10.0.0, lib/index.js: the defaultTag branch, then the sort "not deprecated
 *   and engine ok, engine ok, not deprecated, semver"). Yarn and pnpm can install the highest
 *   admitted release. Both are judged when they differ. `engines` is not read (the packument
 *   projection keeps no engines), so a release npm skips for an engines mismatch is not modelled;
 *   the highest is judged either way.
 */

import type { PackageReleaseIndex } from "../live/release-metadata.js";
import { pushAll } from "../array-utils.js";
import type { DetailedItem } from "./dependency-check-concise.js";
import type { Signal, Verdict } from "./dependency-check-signals.js";
import { compareIn, rangeAdmits } from "./dependency-check-versions.js";

const ORDER: readonly Verdict[] = ["avoid", "review", "unknown", "wait", "proceed"];

/** The worse of two verdicts (avoid > review > unknown > wait > proceed). */
export function worseVerdict(a: Verdict, b: Verdict): Verdict {
  return ORDER.indexOf(a) <= ORDER.indexOf(b) ? a : b;
}

/**
 * A bare crates.io version ("1.6.0", "v1.6.0"), which Cargo.toml reads as ^1.6.0: the version with
 * any build metadata dropped (Cargo ignores it in a requirement, and warns), or null for anything
 * else ("=1.6.0", a range, "latest").
 */
export function cargoBareVersion(raw: string): string | null {
  const m = /^v?(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)(?:\+[0-9A-Za-z.-]+)?$/.exec(raw.trim());
  return m ? m[1] : null;
}

/** Why npm installs the release it picks for a range. */
export type NpmWhy = "latest" | "not_deprecated" | "highest";

const NPM_WHY: Record<NpmWhy, string> = {
  latest: 'its "latest" dist-tag, which the range admits',
  not_deprecated: "the highest release it admits that is not deprecated",
  highest: "the highest release it admits (all of them are deprecated)",
};

/**
 * The release `npm install` picks among `admitted` (the published, non-withdrawn releases the range
 * admits, prereleases only as npm's own range check admits them): the `latest` dist-tag when it is
 * among them and not deprecated, else the highest non-deprecated one, else the highest.
 */
export function npmPick(index: PackageReleaseIndex, admitted: readonly string[]): { version: string; why: NpmWhy } | null {
  if (admitted.length === 0) return null;
  const latest = index.latest ?? null;
  if (latest && admitted.includes(latest) && !index.releases[latest]?.deprecated) return { version: latest, why: "latest" };
  const highest = (pool: readonly string[]) => pool.reduce((max, v) => (compareIn("npm", v, max) > 0 ? v : max));
  const live = admitted.filter((v) => !index.releases[v]?.deprecated);
  return live.length > 0 ? { version: highest(live), why: "not_deprecated" } : { version: highest(admitted), why: "highest" };
}

export function npmWhyText(why: NpmWhy): string {
  return NPM_WHY[why];
}

/** The result of one dependency_check item, as the merge reads and writes it. */
export interface MergeItem extends DetailedItem {
  package_requested?: string;
  resolution?: Resolution;
}

/** The releases what the agent writes can install, each judged (MergeItem.resolution). */
export interface Resolution {
  /** How the package manager reads what was asked ("^1.6.0", or the npm range as written). */
  reads_as: string;
  judged: Array<{ version: string; installed_when: string; verdict: Verdict; advisories: string[]; signals?: Signal[] }>;
}

const advisoriesOf = (item: DetailedItem): string[] => {
  const ids: string[] = [];
  for (const s of item.signals) {
    if (s.id !== "advisories") continue;
    const to = (s.value as { affecting_to?: string[] } | null)?.affecting_to;
    if (Array.isArray(to)) pushAll(ids, to);
  }
  return [...new Set(ids)];
};

/** A sub-result judged no release at all (blocked before signals). */
const judgedNothing = (item: DetailedItem) => item.signals.length === 0;

/** Both reasons, the second left out when it says nothing the first does not. */
function parts(a: { label: string; reason: string }, b: { label: string; reason: string } | null): string {
  if (!b || b.reason === a.reason) return `${a.label}: ${a.reason}`;
  return `${a.label}: ${a.reason} | ${b.label}: ${b.reason}`;
}

/**
 * One answer for a bare crates.io version from its two checks: `exact` (the release itself, what a
 * Cargo.lock holding it keeps) and `caret` (^X, which resolves to the newest release it admits).
 */
export function mergeCargoBare(exact: MergeItem, caret: MergeItem, raw: string, version: string): MergeItem {
  const req = `^${version}`;
  // Not looked up (private) or not judged at all: both checks say the same; one answer, read as Cargo reads it.
  if (exact.not_checked) return { ...exact, to_requested: raw, to_read_as: cargoReading(raw, req, version, null) };
  const fresh = judgedNothing(caret) ? null : caret.to;
  const verdict = worseVerdict(exact.verdict, caret.verdict);
  const same = fresh === exact.to;
  const head =
    fresh === null
      ? `Cargo reads a bare "${raw}" as ${req}: a Cargo.lock that already holds ${exact.to} keeps it, and a fresh resolve installs the newest release ${req} admits, which could not be determined.`
      : same
        ? `Cargo reads a bare "${raw}" as ${req}; ${exact.to} is the newest release it admits, so a fresh resolve installs ${exact.to} as well.`
        : `Cargo reads a bare "${raw}" as ${req}: a Cargo.lock that already holds ${exact.to} keeps it, and a fresh resolve (no Cargo.lock entry, or cargo update) installs ${fresh}, the newest release ${req} admits. Both were judged; the worse verdict stands.`;
  const held = exact.from && exact.from !== exact.to && rangeAdmits("crates.io", req, exact.from) === true ? ` A Cargo.lock holding ${exact.from} keeps ${exact.from} (it satisfies ${req}).` : "";
  const body = same || fresh === null
    ? parts({ label: exact.to, reason: exact.reason }, caret.verdict !== exact.verdict ? { label: `${req}`, reason: caret.reason } : null)
    : parts({ label: `${exact.to} (exact)`, reason: exact.reason }, { label: `${fresh} (fresh resolve)`, reason: caret.reason });
  const advice = verdict === "proceed" ? "" : cargoAdvice(exact, caret, raw, req, fresh);
  const judged: Resolution["judged"] = [
    { version: exact.to, installed_when: `a Cargo.lock already holds ${exact.to}`, verdict: exact.verdict, advisories: advisoriesOf(exact) },
  ];
  if (fresh !== null && !same) {
    judged.push({
      version: fresh,
      installed_when: "a fresh resolve (no Cargo.lock entry, or cargo update)",
      verdict: caret.verdict,
      advisories: advisoriesOf(caret),
      signals: caret.signals,
    });
  }
  const notices = [...new Set([...(exact.maintenance_notices ?? []), ...(caret.maintenance_notices ?? [])])];
  const rc = caret.range_check ?? exact.range_check;
  return {
    ...exact,
    to_requested: raw,
    to_read_as: cargoReading(raw, req, exact.to, fresh),
    verdict,
    reason: `${head}${held} | ${body}${advice ? ` | ${advice}` : ""}`,
    ...(rc ? { range_check: rc } : {}),
    ...(notices.length > 0 ? { maintenance_notices: notices } : {}),
    ...(caret.not_checked && !exact.not_checked ? { not_checked: caret.not_checked } : {}),
    resolution: { reads_as: req, judged },
  };
}

function cargoReading(raw: string, req: string, version: string, fresh: string | null): string {
  const installs = fresh && fresh !== version ? `; a fresh resolve installs ${fresh}` : "";
  return `Cargo requirement ${req}: Cargo.toml reads a bare "${raw}" as ${req}. A Cargo.lock that already holds ${version} keeps it${installs}. Both were judged and the worse verdict stands; "=${version}" requires exactly ${version}`;
}

/** What to write instead, in Cargo.toml syntax. */
function cargoAdvice(exact: MergeItem, caret: MergeItem, raw: string, req: string, fresh: string | null): string {
  if (exact.verdict === "proceed" && fresh && fresh !== exact.to) {
    return `Write "=${exact.to}" to require exactly ${exact.to} (proceed); as a bare "${raw}", a fresh resolve installs ${fresh} (${caret.verdict}).`;
  }
  if (caret.verdict === "proceed" && fresh && fresh !== exact.to) {
    return `Write "${fresh}" (Cargo reads it as ^${fresh}: a fresh resolve installs ${fresh}, proceed, and an older Cargo.lock entry moves to it), or "=${fresh}".`;
  }
  const rc = caret.range_check;
  const pin = rc ? (exact.from ? (rc.smallest_safe_upgrade ?? null) : rc.newest_safe_in_range) : null;
  if (pin && pin !== exact.to) return `Write "=${pin}" to require exactly ${pin}, the ${exact.from ? `smallest release above ${exact.from}` : "newest release"} in ${req} with no known advisory; check it with dependency_check.`;
  return "";
}

/**
 * One answer for an npm range whose npm pick (`picked`, `to` of the range check) differs from the
 * highest release it admits (`highest`, judged as an exact version).
 */
export function mergeNpmPicks(picked: MergeItem, highest: MergeItem, why: NpmWhy): MergeItem {
  if (highest.not_checked || judgedNothing(highest)) {
    // The highest could not be judged: never read as covered (fail closed).
    const verdict = worseVerdict(picked.verdict, "unknown");
    return {
      ...picked,
      verdict,
      reason: `npm installs ${picked.to} for "${picked.to_requested ?? picked.to}" (${NPM_WHY[why]}); Yarn and pnpm can install ${highest.to}, the highest release it admits, which could NOT be checked: ${highest.reason} | ${picked.to} (npm): ${picked.reason}`,
    };
  }
  const verdict = worseVerdict(picked.verdict, highest.verdict);
  const asked = picked.to_requested ?? picked.to;
  const head = `npm installs ${picked.to} for "${asked}" (${NPM_WHY[why]}); Yarn and pnpm can install ${highest.to}, the highest release it admits. Both were judged; the worse verdict stands.`;
  const advice = verdict !== "proceed" && picked.verdict === "proceed" ? ` | Pin exactly ${picked.to} (proceed): the range as written lets Yarn or pnpm install ${highest.to} (${highest.verdict}).` : "";
  return {
    ...picked,
    verdict,
    reason: `${head} | ${picked.to} (npm): ${picked.reason} | ${highest.to} (highest): ${highest.reason}${advice}`,
    resolution: {
      reads_as: asked,
      judged: [
        { version: picked.to, installed_when: `npm install (${NPM_WHY[why]})`, verdict: picked.verdict, advisories: advisoriesOf(picked) },
        {
          version: highest.to,
          installed_when: "Yarn or pnpm (the highest release the range admits)",
          verdict: highest.verdict,
          advisories: advisoriesOf(highest),
          signals: highest.signals,
        },
      ],
    },
  };
}

/**
 * A bare crates.io requirement short of X.Y.Z ("1.6", "1", "v1.6"): Cargo reads it as the caret
 * range ^1.6 / ^1, so a Cargo.lock that already holds a release in it (1.6.0) keeps that release.
 * Only X.Y.Z was read as a caret, and "1.6" said proceed (for the newest 1.x) without saying that a
 * locked 1.6.0 stays (pre-publish round 10, W10). The requirement, or null for anything else.
 */
export function cargoPartialBare(raw: string): string | null {
  const m = /^v?(\d+(?:\.\d+)?)$/.exec(raw.trim());
  return m ? `^${m[1]}` : null;
}

/**
 * One answer for a partial bare crates.io requirement from its range check and, for each release in
 * it the project's own Cargo.lock holds, that release judged exactly. A locked release the range
 * keeps is installed as surely as the newest one, so the worse verdict stands; with no locked
 * release the verdict is the range's, and a note says what a Cargo.lock entry would keep.
 */
export function mergeCargoPartial(range: MergeItem, locked: MergeItem[], raw: string, req: string): MergeItem {
  if (range.not_checked && locked.length === 0) return range;
  const head = `Cargo reads a bare "${raw}" as ${req}, a caret range: a Cargo.lock that already holds a release in it keeps that release, and a fresh resolve (no Cargo.lock entry, or cargo update) installs ${range.to}.`;
  if (locked.length === 0) {
    const rc = range.range_check;
    const note =
      rc && rc.vulnerable_in_range > 0
        ? ` ${rc.vulnerable_in_range} of the releases ${req} admits have a known advisory${rc.smallest_safe_in_range ? ` (the smallest without one is ${rc.smallest_safe_in_range})` : ""}; a Cargo.lock holding one keeps it, so check the locked release with dependency_check.`
        : "";
    return { ...range, reason: `${head}${note} | ${range.reason}` };
  }
  let verdict = range.verdict;
  const said: string[] = [];
  const judged: Resolution["judged"] = [];
  for (const l of locked) {
    const unjudged = l.not_checked || judgedNothing(l);
    const v: Verdict = unjudged ? "unknown" : l.verdict;
    verdict = worseVerdict(verdict, v);
    const ids = advisoriesOf(l);
    said.push(unjudged ? `${l.to} in your Cargo.lock could not be checked: ${l.reason}` : ids.length > 0 ? `${l.to} in your Cargo.lock is affected by ${ids.join(", ")} (${l.verdict})` : `${l.to} in your Cargo.lock: ${l.verdict}`);
    judged.push({ version: l.to, installed_when: `your Cargo.lock holds ${l.to}`, verdict: v, advisories: ids, signals: l.signals });
  }
  if (!range.not_checked && !judgedNothing(range)) {
    judged.push({ version: range.to, installed_when: "a fresh resolve (no Cargo.lock entry, or cargo update)", verdict: range.verdict, advisories: advisoriesOf(range), signals: range.signals });
  }
  const advice = verdict === "proceed" || range.verdict !== "proceed" ? "" : ` | Run cargo update -p ${range.package} (or write "${range.to}") so the lockfile moves to ${range.to} (proceed).`;
  return {
    ...range,
    verdict,
    reason: `${head} ${said.join("; ")}. Both were judged; the worse verdict stands. | ${range.to} (fresh resolve): ${range.reason}${advice}`,
    resolution: { reads_as: req, judged },
  };
}
