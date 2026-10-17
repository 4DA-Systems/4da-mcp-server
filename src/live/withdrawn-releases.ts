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
    for (const v of npmExcludedVersions(live, index.latest)) out.set(v, withdrawalText("npm", v, index.releases[v]?.deprecated));
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

/** How a registry names a withdrawal, for the release `version`. */
export function withdrawalText(ecosystem: string, version: string, detail?: string | null): string {
  const quoted = detail?.trim() ? ` ("${clip(detail.trim(), 120)}")` : "";
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

/** At most `max` characters, cut at a word, "..." when cut. */
function clip(text: string, max: number): string {
  if (text.length <= max) return text;
  const cut = text.slice(0, max);
  return `${cut.slice(0, Math.max(cut.lastIndexOf(" "), max / 2)).replace(/[\s,;:.]+$/, "")}...`;
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
