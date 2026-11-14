// SPDX-License-Identifier: Apache-2.0
/**
 * Which releases a registry has withdrawn, so that no fix target is ever one
 * of them (4DA FX-H5, the app's `osv/release_facts.rs`; the rule the shared
 * fix_target vectors pin, README "Optional fix_target registry fields").
 *
 * - crates.io: `yanked`.
 * - PyPI: a release whose every file is `yanked` (PEP 592).
 * - npm: `deprecated`, but ONLY when a later, non-deprecated, stable release
 *   exists on the same caret line (same major; same minor for 0.x). npm's
 *   `deprecated` is often a whole-major "please upgrade" notice rather than a
 *   withdrawn release: glob deprecates 160 of its 168 versions ("Old versions
 *   of glob are not supported"), 10.5.0 included, and excluding them all sent
 *   glob 10.4.5 to 12.0.0, a major jump. lodash 4.18.0 ("Bad release") is
 *   excluded because 4.18.1 is clean on 4.x. A package whose `latest` is
 *   itself deprecated (retired whole) excludes nothing.
 *
 * Pure functions; the registry readers (fix-paths.ts, npm-packument.ts) call
 * them on what they already fetched.
 */

import { quoteThirdParty } from "../untrusted-text.js";
import { comparePrecedence, parseSemverPrecedence } from "./semver-precedence.js";
import type { PackageReleaseIndex } from "./release-metadata.js";

/**
 * dependency_check's view: every release of `index` that is never a candidate, with the
 * registry's words. Withdrawn records (crates.io/PyPI yanked, npm unpublished, Go retracted:
 * none of them installable as asked) plus the npm deprecations the rule above withdraws.
 */
export function excludedReleases(index: PackageReleaseIndex): Map<string, string> {
  const out = new Map<string, string>();
  const releases = Object.values(index.releases);
  for (const r of releases) {
    if (r.withdrawn) out.set(r.version, r.withdrawn === "yanked" ? withdrawalText(index.ecosystem, r.version) : `${r.version} was ${r.withdrawn} from the registry`);
  }
  if (index.ecosystem === "npm") {
    const live = Object.fromEntries(releases.filter((r) => !r.withdrawn).map((r) => [r.version, r.deprecated]));
    // The same rule fix-paths.ts npmFacts applies (one rule for every tool): the shared withdrawal
    // rule, plus a release its maintainer deprecated with its own message on a line that carries
    // another notice. dependency_check named lodash.template 4.18.0 ("Bad release. Please use
    // lodash.template@4.5.0 instead") as the smallest safe release while the scan withheld it
    // (black-box re-run of 96c16d2, 2026-11-13).
    for (const v of [...npmExcludedVersions(live, index.latest), ...npmFlaggedReleases(live, index.latest)]) out.set(v, withdrawalText("npm", v, index.releases[v]?.deprecated));
  }
  return out;
}

/** npm's per-version `deprecated`: a non-empty message, or `true` (the app's `npm_deprecated`). */
export function isNpmDeprecated(value: unknown): boolean {
  return (typeof value === "string" && value !== "") || value === true;
}

/**
 * The npm releases to exclude as fix targets, from a packument's `versions`
 * (version -> its `deprecated`) and `dist-tags.latest` (see the module notes).
 */
export function npmExcludedVersions(deprecation: Record<string, unknown>, latest: string | null | undefined): string[] {
  if (latest && latest in deprecation && isNpmDeprecated(deprecation[latest])) return [];
  const clean = Object.entries(deprecation)
    .filter(([, d]) => !isNpmDeprecated(d))
    .map(([v]) => parseSemverPrecedence(v))
    .filter((p): p is NonNullable<typeof p> => p !== null && p.prerelease.length === 0);
  return Object.entries(deprecation)
    .filter(([, d]) => isNpmDeprecated(d))
    .filter(([v]) => {
      const p = parseSemverPrecedence(v);
      return p !== null && clean.some((c) => c.major === p.major && (p.major > 0 || c.minor === p.minor) && comparePrecedence(c, p) > 0);
    })
    .map(([v]) => v);
}

/**
 * npm releases whose maintainer deprecated THAT RELEASE, on a line that carries a different notice
 * (or none): never a fix target either.
 *
 * `npmExcludedVersions` withdraws a deprecated release only when a later release on its line is
 * not deprecated at all, and nothing when `latest` is deprecated. That reads every deprecation of
 * a retired package as one whole-line notice. lodash.template is retired ("This package is
 * deprecated. Use ...eta instead." on every release) and 4.18.0 alone says "Bad release. Please
 * use lodash.template@4.5.0 instead.": the plan sent 4.5.0 to 4.18.0, the one release its
 * maintainer flagged, past 4.18.1, which carries only the package notice (audit 2026-11-11, M6).
 *
 * A release is flagged when its `deprecated` message is not the notice of its caret line, where
 * the line's notice is, in order: the message `latest` carries, when a release on the line carries
 * it too (the package's own retirement notice); else what the line's newest stable release says,
 * when another release on the line says the same; else what most of the line's stable releases
 * say (a tie goes to the newest). A line whose releases all say one thing flags nothing (glob
 * 10.x, "Old versions of glob are not supported"), and neither does a release that is not
 * deprecated. Prereleases are left to the rule above.
 */
export function npmFlaggedReleases(deprecation: Record<string, unknown>, latest: string | null | undefined): string[] {
  const state = (v: string): string | null => {
    const d = deprecation[v];
    return isNpmDeprecated(d) ? (typeof d === "string" ? d.trim() : "deprecated") : null;
  };
  const packageNotice = latest && latest in deprecation ? state(latest) : null;
  const lines = new Map<string, Array<{ version: string; parsed: NonNullable<ReturnType<typeof parseSemverPrecedence>> }>>();
  for (const version of Object.keys(deprecation)) {
    const parsed = parseSemverPrecedence(version);
    if (!parsed || parsed.prerelease.length > 0) continue;
    const line = parsed.major > 0 ? `${parsed.major}` : `0.${parsed.minor}`;
    const at = lines.get(line);
    if (at) at.push({ version, parsed });
    else lines.set(line, [{ version, parsed }]);
  }
  const flagged: string[] = [];
  for (const releases of lines.values()) {
    if (releases.length < 2) continue;
    releases.sort((a, b) => comparePrecedence(a.parsed, b.parsed));
    const states = releases.map((r) => state(r.version));
    if (states.every((x) => x === states[0])) continue;
    const count = (x: string | null) => states.filter((y) => y === x).length;
    const newest = states[states.length - 1];
    let notice: string | null;
    if (packageNotice !== null && states.includes(packageNotice)) notice = packageNotice;
    else if (count(newest) >= 2) notice = newest;
    else {
      // Most of the line; on a tie the later release's.
      notice = newest;
      let best = count(newest);
      for (let i = states.length - 2; i >= 0; i--) {
        if (count(states[i]) > best) {
          notice = states[i];
          best = count(states[i]);
        }
      }
    }
    for (const [i, r] of releases.entries()) if (states[i] !== null && states[i] !== notice) flagged.push(r.version);
  }
  return flagged;
}

/** How a registry names a withdrawal, for the release `version`. */
export function withdrawalText(ecosystem: string, version: string, detail?: string | null): string {
  const said = detail ? quoteThirdParty(detail) : "";
  const quoted = said ? ` ("${said}")` : "";
  switch (ecosystem) {
    case "npm":
      return `${version} is deprecated on npm${quoted}`;
    case "crates.io":
      return `${version} is yanked on crates.io`;
    case "PyPI":
      return `${version} is yanked on PyPI${quoted}`;
    default:
      return `${version} is withdrawn on the registry${quoted}`;
  }
}

/**
 * The withdrawn releases in plain words, releases with the same reason said once:
 * "7.5.3, 7.5.4 and 7.5.5 are deprecated on npm ("Old versions of tar ...")".
 */
export function sayWithdrawn(versions: string[], why: Record<string, string>, ecosystem: string): string {
  const groups: Array<{ rest: string; versions: string[] }> = [];
  for (const v of versions) {
    const text = why[v] ?? withdrawalText(ecosystem, v);
    const rest = text.startsWith(`${v} is `) ? text.slice(v.length + " is ".length) : null;
    const last = groups[groups.length - 1];
    if (rest !== null && last && last.rest === rest) last.versions.push(v);
    else groups.push({ rest: rest ?? text, versions: rest === null ? [] : [v] });
  }
  return groups
    .map((g) => {
      if (g.versions.length === 0) return g.rest;
      const names = g.versions.length === 1 ? g.versions[0] : `${g.versions.slice(0, -1).join(", ")} and ${g.versions[g.versions.length - 1]}`;
      return `${names} ${g.versions.length === 1 ? "is" : "are"} ${g.rest}`;
    })
    .join("; ");
}

/**
 * The plain-words note for a target moved past withdrawn releases, or for no
 * target because every release that would fix it was withdrawn (the app's
 * Upgrade Plan wording: "No installable fix").
 *   "4.18.0 is deprecated on npm ("Bad release..."); 4.18.1 is the smallest clean release"
 *   "No installable fix: 0.3.17 is yanked on crates.io, and no later release is known to clear it"
 * `why` holds the registry's own text per withdrawn release (withdrawalText).
 * `clean: false`: the target clears only the advisories a release fixes.
 */
export function withheldNote(
  withheld: string[],
  target: string | null,
  why: Record<string, string>,
  ecosystem: string,
  clean = true,
): string | null {
  if (withheld.length === 0) return null;
  const said = sayWithdrawn(withheld, why, ecosystem);
  if (!target) return `No installable fix: ${said}, and no later release is known to clear it — pin, patch, or replace`;
  return `${said}; ${target} is the smallest ${clean ? "clean release" : "installable release that clears the advisories a release fixes"}`;
}
