// SPDX-License-Identifier: Apache-2.0
/**
 * dependency_check and names that are malware themselves (typo-squats).
 *
 * `{npm, lodahs, latest}` said proceed: `latest` is 0.0.1-security, the empty placeholder npm
 * publishes after it takes a malicious package down, and MAL-2025-25502 records lodahs as
 * malware. `electorn` and `loadyaml` read the same. The scanner rightly drops findings on a
 * security holding release (osv-scanner.ts isNpmSecurityHolding: an installed placeholder is no
 * code, so it is not installed malware), and that left nothing for a pre-install check to see.
 * But an agent about to ADD the name has misspelled what it meant, or was steered to the squat.
 *
 * So, before a version is written, a name is `avoid` when:
 * - npm took it down: `to` is a security holding release, or every release the registry lists
 *   is one (a constraint then admits nothing, and that is no reason to say "unknown"); or
 * - a malicious-package record (malware.ts isMalware) covers the name itself, not one release of
 *   it: open from the first version with no fix, or affecting every release the registry lists,
 *   or the registry no longer has the package at all.
 * A hijacked release of a real package (chalk 5.6.1, nx 21.5.0, ua-parser-js 0.7.29) is not the
 * name: those records list the bad releases, which stay `avoid` through the advisories of `to`
 * as before, and the package's other releases are judged as usual.
 *
 * With it, the popular package the name is closest to (edit distance 1 or 2, a transposition
 * counting 1, over the bundled popular-npm.ts list), when there is one: "did you mean lodash?".
 */

import { advisoryAffects, type AdvisoryRanges } from "../live/osv-ranges.js";
import { isSecurityHoldingRelease } from "../live/osv-scanner.js";
import { POPULAR_NPM } from "../live/popular-npm.js";
import type { CheckEcosystem, PackageReleaseIndex } from "../live/release-metadata.js";
import type { Signal } from "./dependency-check-signals.js";

export interface MaliciousName {
  /** The malicious-package records on the name, sorted. */
  ids: string[];
  /** npm took the package down and holds the name with an empty `0.0.N-security` release. */
  takenDown: boolean;
  /** That release, when known. */
  placeholder: string | null;
  /** The popular package the name is a near-miss of, or null. */
  didYouMean: string | null;
}

/** Whether the name itself is malware (see the module comment); null when nothing says so. */
export function maliciousName(input: {
  ecosystem: CheckEcosystem;
  package: string;
  to: string;
  index: PackageReleaseIndex | null;
  /** The registry answered that the package does not exist. */
  notFound: boolean;
  advisories: readonly AdvisoryRanges[] | null | undefined;
}): MaliciousName | null {
  const { ecosystem } = input;
  // npm's own placeholders: the `0.0.N-security` holding release, and the `0.0.0-stage` stub npm
  // publishes for a held name (yummy-bolts: MAL-2026-19107 lists every release it published, 1.0.0
  // to 1.4.0, and the registry serves only 0.0.0-stage and 0.0.1-security; `to: "0.0.0-stage"`
  // said proceed and `^1.0.0` unknown, blind audit round 5).
  const holding = (v: string) => isSecurityHoldingRelease(ecosystem, v) || (ecosystem === "npm" && v === "0.0.0-stage");
  const releases = input.index ? Object.keys(input.index.releases) : [];
  // Unpublished (withdrawn) releases are listed too: crossenv's packument names 6.1.1 it no longer serves.
  const real = releases.filter((v) => !holding(v) && !input.index!.releases[v].withdrawn);
  const takenDown = holding(input.to) || (releases.some(holding) && real.length === 0);
  const malware = (input.advisories ?? []).filter((a) => a.malware && !a.maintenance);
  const gone = takenDown || input.notFound;
  const covering = malware.filter(
    (a) =>
      a.spans.some((s) => s.introduced === "0" && s.fixed === null && s.lastAffected === null) ||
      (gone && real.length === 0) ||
      (real.length > 0 && real.every((v) => advisoryAffects(a, v, ecosystem))),
  );
  if (!takenDown && covering.length === 0) return null;
  // Every record that covers the name, not only the ones read as malware: the ecosystem's own record
  // of the same takedown (GO-2025-3451 beside MAL-2025-2545 for boltdb-go/bolt; RUSTSEC-2026-0483,
  // "removed from crates.io for malicious code", beside MAL-2026-19058) carries no MAL id, and 6.2.7
  // listed both (black-box re-run of 96c16d2, 2026-11-13).
  const openEnded = (a: AdvisoryRanges) => a.spans.some((s) => s.fixed === null && s.lastAffected === null && (s.introduced === "0" || /^0(?:\.0)*(?:-0)?$/.test(s.introduced)));
  const companions = (input.advisories ?? []).filter(
    (a) => !a.malware && !a.maintenance && openEnded(a),
  );
  const ids = [...new Set([...(takenDown ? malware : covering), ...companions].map((a) => a.id))].sort();
  const security = releases.find((v) => isSecurityHoldingRelease(ecosystem, v));
  const placeholder = isSecurityHoldingRelease(ecosystem, input.to) ? input.to : (security ?? releases.find(holding) ?? null);
  return { ids, takenDown, placeholder: takenDown ? placeholder : null, didYouMean: ecosystem === "npm" ? closestPopularNpm(input.package) : null };
}

/** The advisories signal, overruled: the name itself is malware. */
export function maliciousSignal(item: { package: string; to: string; from?: string }, found: MaliciousName, own: Signal | null): Signal {
  const records = (subject: string) => `${found.ids.join(", ")} record${found.ids.length === 1 ? "s" : ""} ${subject} as a malicious package`;
  const what = found.takenDown
    ? `npm took ${item.package} down as malware and holds the name with an empty security placeholder${found.placeholder ? ` (${found.placeholder})` : ""}${found.ids.length > 0 ? `; ${records("it")}` : ""}.`
    : `${records(item.package)}: the name itself, not one release of it.`;
  const remove = item.from ? ` Remove the installed ${item.package}@${item.from} as well.` : "";
  const guess = found.didYouMean ? ` Did you mean ${found.didYouMean}? Check the name before adding anything.` : " Check the package name for a typo before adding anything.";
  const value = own && own.value && typeof own.value === "object" ? (own.value as object) : {};
  return {
    id: "advisories",
    value: { ...value, malicious_package: { ids: found.ids, taken_down: found.takenDown, did_you_mean: found.didYouMean } },
    effect: "avoid",
    evidence: `${what} Do not install it.${remove}${guess}`,
  };
}

const POPULAR = new Set(POPULAR_NPM);

/**
 * The popular npm package a name is a near-miss of: the most popular one edit away (names of 4
 * characters or more), else the name with a `.js` / `-js` / `js` suffix or a `node-` prefix
 * dropped, else the most popular one two edits away (names of 6 or more). Null for a popular
 * name itself and for anything else. Deterministic and offline.
 */
export function closestPopularNpm(name: string): string | null {
  const n = name.trim().toLowerCase();
  if (n.length < 4 || POPULAR.has(n)) return null;
  const nearest = (max: number) => {
    let best: string | null = null;
    let bestDistance = max + 1;
    for (const p of POPULAR_NPM) {
      if (Math.abs(p.length - n.length) >= bestDistance) continue;
      const d = editDistance(n, p, bestDistance - 1);
      if (d > 0 && d < bestDistance) {
        best = p;
        bestDistance = d;
      }
    }
    return best;
  };
  // One edit first (nodesass -> node-sass, not sass), then a dropped affix (jquery.js -> jquery), then two edits.
  const one = nearest(1);
  if (one) return one;
  for (const bare of [n.replace(/(?:\.js|-js|js)$/, ""), n.replace(/^node-?/, "")]) {
    if (bare !== n && bare.length >= 2 && POPULAR.has(bare)) return bare;
  }
  return n.length >= 6 ? nearest(2) : null;
}

/**
 * Optimal string alignment distance (Levenshtein plus adjacent transposition, so lodahs ->
 * lodash is 1). Returns `limit + 1` as soon as the distance must exceed `limit`.
 */
export function editDistance(a: string, b: string, limit: number): number {
  if (Math.abs(a.length - b.length) > limit) return limit + 1;
  let prev2: number[] = [];
  let prev = Array.from({ length: b.length + 1 }, (_, j) => j);
  for (let i = 1; i <= a.length; i++) {
    const cur = [i];
    let rowMin = i;
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      let d = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) d = Math.min(d, prev2[j - 2] + 1);
      cur.push(d);
      if (d < rowMin) rowMin = d;
    }
    if (rowMin > limit) return limit + 1;
    prev2 = prev;
    prev = cur;
  }
  return prev[b.length] <= limit ? prev[b.length] : limit + 1;
}
