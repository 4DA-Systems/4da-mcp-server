// SPDX-License-Identifier: Apache-2.0
/**
 * A release a tool OFFERS as an upgrade (upgrade_planner's target for a row with no advisory,
 * dependency_health's latestStableVersion, what_should_i_know's "latest") is checked the way
 * dependency_check decides `proceed`: against every advisory of the package with the same
 * predicate (osv-ranges.ts advisoriesAffecting) and against the registry's withdrawals. A
 * known-affected or withdrawn release is never offered as a safe upgrade, and the answer says why.
 *
 * Final release audit of 6.2.5 (2026-10-18): upgrade_planner sent crossenv 0.0.2-security, npm's
 * placeholder for a removed malware package, to 1.0.1, which GHSA-c2m4-w5hm-vqjw (last_affected
 * 1.0.1) lists as the malware itself. The same held for cross-env.js, mongose, babelcli, d3.js,
 * jquery.js, ffmepg, nodesass and nodefabric: rows with no advisory on the installed version took
 * the registry's latest stable release with no check at all.
 */

import type { FixPathSources } from "./fix-paths.js";
import { advisoriesAffecting, cleanReleases, isPrereleaseVersion, remainsText } from "./osv-ranges.js";
import { unreadableText } from "./fix-paths.js";
import { isSecurityHoldingRelease } from "./osv-scanner.js";
import { compareVersions } from "./version-compare.js";
import type { OsvEcosystem } from "./types.js";

export interface OfferedRelease {
  /** The release the tool was about to offer. */
  offered: string;
  /** False when the package's advisories could not be read: the offer is unchecked, and said to be. */
  checked: boolean;
  /** Advisories that affect `offered`. */
  affectedBy: string[];
  /** The registry's words when it withdrew `offered` (yanked, or deprecated with a later clean release on its line). */
  withdrawn: string | null;
  /** The release to offer instead: the newest release above the installed one that is neither affected nor withdrawn; null when none. */
  safe: string | null;
  /**
   * The installed version is npm's security placeholder (`0.0.x-security`, published after the
   * malware was taken down) and no release above it is safe: the placeholder is the safe state,
   * and the step is removing the dependency.
   */
  holding: boolean;
  /** Plain words for an offer that changed or could not be checked; null when `offered` stands as it is. */
  note: string | null;
}

/** Releases named in a list, "1.0.0 and 1.0.1" / "1.0.0, 1.0.1 and 1.0.2". */
function list(versions: string[]): string {
  return versions.length <= 1 ? versions.join("") : `${versions.slice(0, -1).join(", ")} and ${versions[versions.length - 1]}`;
}

/**
 * Check one offered release. `installed` is the version the project holds; the replacement is
 * looked for above it (a stable one unless nothing stable is newer).
 */
export async function vetOfferedRelease(
  sources: FixPathSources,
  ecosystem: OsvEcosystem,
  name: string,
  installed: string | null,
  offered: string,
): Promise<OfferedRelease> {
  const [advisories, facts] = await Promise.all([
    sources.packageAdvisories(ecosystem, name).catch(() => null),
    sources.releaseFacts(ecosystem, name).catch(() => null),
  ]);
  const base: OfferedRelease = { offered, checked: advisories !== null, affectedBy: [], withdrawn: null, safe: offered, holding: false, note: null };
  if (!advisories) {
    return { ...base, note: `${name} ${offered} was not checked against ${name}'s advisories (OSV.dev did not answer): run dependency_check on it before writing it` };
  }
  // The one clean-release predicate (#981): malware never skipped, unreadable ranges unknown, a
  // genuinely unfixed advisory skipped and said.
  const view = cleanReleases(advisories, ecosystem, [...(facts?.versions ?? []), offered]);
  if (view.unreadable.length > 0) {
    return { ...base, safe: null, note: `${name} ${offered} is not offered: ${unreadableText(view.unreadable)}` };
  }
  // An unfixed advisory is skipped only where the installed version has it too: an upgrade must
  // never bring in one the project does not have (widget 1.0.0 -> 1.2.0).
  const unavoidable = view.unfixed.filter((id) => installed !== null && advisoriesAffecting(advisories, installed, ecosystem).includes(id));
  const affectedBy = advisoriesAffecting(advisories, offered, ecosystem).filter((id) => !unavoidable.includes(id));
  const withdrawnWhy = facts?.withdrawn.includes(offered) ? (facts.withdrawnWhy[offered] ?? `${offered} is withdrawn on the registry`) : null;
  if (affectedBy.length === 0 && !withdrawnWhy) {
    const remains = view.remains(offered).filter((id) => unavoidable.includes(id));
    return remains.length > 0 ? { ...base, note: `${name} ${offered} ${remainsText(remains)}` } : base;
  }

  const cmp = (a: string, b: string) => compareVersions(a, b, ecosystem);
  const above = (facts?.versions ?? []).filter((v) => !installed || cmp(v, installed) > 0);
  const stable = above.filter((v) => !isPrereleaseVersion(v, ecosystem));
  const pool = (stable.length > 0 ? stable : above).sort(cmp);
  const clean = (v: string) => advisoriesAffecting(advisories, v, ecosystem).every((id) => unavoidable.includes(id)) && view.unreadable.length === 0;
  const safe = facts ? ([...pool].reverse().find(clean) ?? null) : null;
  const holding = safe === null && installed !== null && isSecurityHoldingRelease(ecosystem, installed);

  const why = affectedBy.length > 0
    ? advisories.some((a) => a.malware && affectedBy.includes(a.id))
      ? `is malware (${affectedBy.join(", ")})`
      : `is affected by ${affectedBy.join(", ")}`
    : withdrawnWhy!.startsWith(`${offered} `) ? withdrawnWhy!.slice(offered.length + 1) : `is withdrawn (${withdrawnWhy})`;
  let note: string;
  if (holding) {
    const newer = pool.filter((v) => !clean(v));
    const malware = advisories.some((a) => a.malware && newer.some((v) => advisoriesAffecting([a], v, ecosystem).length > 0));
    const ids = [...new Set(newer.flatMap((v) => advisoriesAffecting(advisories, v, ecosystem)))];
    note =
      `${name} ${list(newer)} ${newer.length === 1 ? "is" : "are"} ${malware ? "malware" : "affected by a known advisory"} (${ids.join(", ")}); ` +
      `${installed} is npm's empty security placeholder published in ${newer.length === 1 ? "its" : "their"} place, the safe state: do not upgrade ${name}, remove it from the project`;
  } else if (safe) {
    note = `${name} ${offered} ${why}, so it is not offered: ${safe} is the newest release above ${installed ?? "the installed version"} that no advisory affects and the registry has not withdrawn`;
  } else if (!facts) {
    note = `${name} ${offered} ${why}, so it is not offered; the registry could not be read to name a release that is not`;
  } else {
    note = `${name} ${offered} ${why}, and no release above ${installed ?? "the installed version"} is free of known advisories and withdrawals: stay on ${installed ?? "the installed version"}`;
  }
  return { offered, checked: true, affectedBy, withdrawn: withdrawnWhy, safe, holding, note };
}

/**
 * vetOfferedRelease over many rows within a time budget; a row not checked in time is absent from
 * the result, and the caller says so. Keyed by `key`.
 */
export async function vetOfferedReleases(
  sources: FixPathSources | null,
  items: Array<{ key: string; ecosystem: OsvEcosystem; name: string; installed: string | null; offered: string }>,
  budgetMs: number,
  concurrency = 12,
): Promise<Map<string, OfferedRelease>> {
  const out = new Map<string, OfferedRelease>();
  if (!sources || items.length === 0) return out;
  const deadline = Date.now() + budgetMs;
  let next = 0;
  const worker = async () => {
    while (next < items.length && Date.now() < deadline) {
      const item = items[next++];
      let timer: ReturnType<typeof setTimeout> | undefined;
      const late = new Promise<null>((resolve) => {
        timer = setTimeout(() => resolve(null), Math.max(0, deadline - Date.now()));
      });
      try {
        const vet = await Promise.race([vetOfferedRelease(sources, item.ecosystem, item.name, item.installed, item.offered).catch(() => null), late]);
        if (vet) out.set(item.key, vet);
      } finally {
        if (timer !== undefined) clearTimeout(timer);
      }
    }
  };
  await Promise.all(Array.from({ length: Math.min(concurrency, items.length) }, worker));
  return out;
}

/** Said for an offer that could not be checked in time (the budget ran out, or offline). */
export function uncheckedOfferNote(name: string, offered: string): string {
  return `${name} ${offered} was not checked against ${name}'s advisories in time: run dependency_check on it before writing it`;
}
