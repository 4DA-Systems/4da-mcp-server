// SPDX-License-Identifier: Apache-2.0
/**
 * A direct upgrade target on Go, crates.io or PyPI, judged by what the target release itself
 * requires (release-requirements.ts), as dependency_check judges it.
 *
 * A target clean of its own package's advisories can still bring advisories in: gin v1.9.1's own
 * go.mod requires old golang.org/x/crypto, x/net and protobuf, so taking it raised a project from
 * 11 advisories to 52. A target whose requirements carry advisories is not a clean fix
 * (`requiresAffected`); one whose requirements could not be read was not examined
 * (`requiresUnchecked`). Neither is ever reported as checked against every advisory
 * (fix-paths.ts targetCheckedAll).
 *
 * Bounded: at most MAX_REQUIRED_TARGETS distinct releases per tool call (shared by every tool the
 * call runs, the scan's planner verdicts included), within the call's budget, through the cached
 * readers and the shared advisory lookup. A target past the cap is `requiresUnchecked` and says so.
 * npm targets are judged by what they hold instead (held-targets.ts).
 */

import { callMemo } from "../call-budget.js";
import { andList, heldText, type AdvisoryQuery, type HeldDependency } from "./held-dependencies.js";
import { isRequirementEcosystem, requirementAdvisories, type RequirementEcosystem, type RequirementRelease, type RequirementSources } from "./release-requirements.js";
import { compareVersions, inEcosystemForm, isComparable } from "./version-compare.js";
import type { FixTargetResult } from "./fix-paths.js";
import type { ResolvedDependency } from "./types.js";

/** Distinct target releases whose requirements one tool call examines. */
export const MAX_REQUIRED_TARGETS = 10;

/** The releases this call has examined (or is examining), by `ecosystem\0name@version`. */
function examinedThisCall(): { keys: Set<string> } {
  return callMemo("required-targets:examined", () => ({ keys: new Set<string>() }));
}

/** Words for a target past the cap. */
export function notExaminedCapText(): string {
  return `this call examines what at most ${MAX_REQUIRED_TARGETS} upgrade targets require, and this one was past that; dependency_check on it examines it`;
}

/** Go: the version of each module the project already selects (the highest it holds). */
export function selectedGoModules(deps: Array<Pick<ResolvedDependency, "ecosystem" | "name" | "version">>): (ecosystem: RequirementEcosystem, name: string) => string | null {
  const selected = new Map<string, string>();
  for (const d of deps) {
    if (d.ecosystem !== "Go" || !d.version) continue;
    const v = d.version.startsWith("v") ? d.version : `v${d.version}`;
    if (!isComparable(v, "Go")) continue;
    const held = selected.get(d.name);
    if (!held || compareVersions(v, held, "Go") > 0) selected.set(d.name, v);
  }
  return (ecosystem, name) => (ecosystem === "Go" ? (selected.get(name) ?? null) : null);
}

export interface RequiredTargetItem {
  key: string;
  ecosystem: string;
  name: string;
  clean: FixTargetResult;
}

/**
 * Each item's target, with what it requires judged: `requiresAffected` or `requiresUnchecked` set
 * where it applies. Items on npm, or without a target, come back unchanged (absent from the map).
 * One advisory lookup covers every target examined here.
 */
export async function withRequiredTargets(
  sources: RequirementSources,
  query: AdvisoryQuery,
  items: RequiredTargetItem[],
  deadline: number,
  selected?: (ecosystem: RequirementEcosystem, name: string) => string | null,
): Promise<Map<string, FixTargetResult>> {
  const out = new Map<string, FixTargetResult>();
  const examined = examinedThisCall();
  const releases: RequirementRelease[] = [];
  for (const item of items) {
    if (!item.clean.target || !isRequirementEcosystem(item.ecosystem) || !sources.reads(item.ecosystem)) continue;
    const release = `${item.ecosystem}\0${item.name}@${item.clean.target}`;
    if (!examined.keys.has(release) && examined.keys.size >= MAX_REQUIRED_TARGETS) {
      out.set(item.key, { ...item.clean, requiresUnchecked: notExaminedCapText() });
      continue;
    }
    examined.keys.add(release);
    releases.push({ key: item.key, ecosystem: item.ecosystem, name: item.name, version: item.clean.target });
  }
  if (releases.length === 0) return out;
  let answer: Awaited<ReturnType<typeof requirementAdvisories>>;
  try {
    answer = await requirementAdvisories(sources, query, releases, { deadline, ...(selected ? { selected } : {}) });
  } catch (err) {
    const why = `the check failed: ${err instanceof Error ? err.message.slice(0, 120) : "unknown error"}`;
    for (const r of releases) out.set(r.key, { ...items.find((i) => i.key === r.key)!.clean, requiresUnchecked: why });
    return out;
  }
  for (const item of items) {
    const check = answer.get(item.key);
    if (!check || !releases.some((r) => r.key === item.key)) continue;
    if (check.status === "unchecked") out.set(item.key, { ...item.clean, requiresUnchecked: check.reason });
    else if (check.affected.length > 0) out.set(item.key, { ...item.clean, requiresAffected: { affected: check.affected, examined: check.examined ?? check.affected.length } });
  }
  return out;
}

/** A step reason requiresNote wrote for a target whose own requirements carry advisories. */
export const REQUIRES_AFFECTED_REASON = /'s own (?:go\.mod requires|requirements bring in) .*is NOT a clean fix/;
/** A step reason requiresNote wrote for a target whose requirements were not examined; and the cap's own words. */
export const REQUIRES_UNEXAMINED_REASON = /itself requires was not examined \(/;
export const REQUIRES_CAP_REASON = /upgrade targets require, and this one was past that/;

const advisories = (n: number) => `${n} advisor${n === 1 ? "y" : "ies"}`;

/**
 * The words for a target's requirements (FixTargetResult.requiresAffected / requiresUnchecked):
 * which requirements carry advisories, how many, what to raise afterwards; or that they were not
 * examined. Null when there is nothing to say. Each ends in a phrase HELD_UNCLEAN_REASON matches.
 */
export function requiresNote(clean: FixTargetResult, ecosystem: string): string | null {
  if (!clean.target) return null;
  const target = inEcosystemForm(ecosystem, clean.target);
  if (clean.requiresAffected) {
    const affected = clean.requiresAffected.affected;
    const total = affected.reduce((n, d) => n + d.ids.length, 0);
    const what = `${target}'s own ${ecosystem === "Go" ? "go.mod requires" : "requirements bring in"} ${affected.length === 1 ? "a dependency" : `${affected.length} dependencies`} with ${advisories(total)} in all`;
    return `${what}: ${requiredList(affected, ecosystem, target)}; ${raiseText(affected, ecosystem)}, so ${target} is NOT a clean fix: confirm a release with dependency_check before pinning it`;
  }
  if (clean.requiresUnchecked !== undefined) {
    return `what ${target} itself requires was not examined (${clean.requiresUnchecked}): confirm it with dependency_check before pinning it`;
  }
  return null;
}

function requiredList(affected: HeldDependency[], ecosystem: string, target: string): string {
  if (ecosystem !== "Go") return heldText(target, affected).replace(`${target} `, "");
  const shown = affected.slice(0, 4).map((d) => {
    const which = d.selected ? `${d.name} ${d.version} (your go.mod's selection over the ${d.spec} it requires)` : `${d.name} ${d.version}`;
    const clears = d.fixedIn ? `${d.fixedIn} clears ${d.ids.length === 1 ? "it" : "them"}` : `no release that clears ${d.ids.length === 1 ? "it" : "them"} is known`;
    return `${which} (${advisories(d.ids.length)}; ${clears})`;
  });
  const rest = affected.length - shown.length;
  return `${andList(shown)}${rest > 0 ? `, and ${rest} more` : ""}`;
}

function raiseText(affected: HeldDependency[], ecosystem: string): string {
  if (ecosystem === "Go") {
    const fixable = affected.filter((d) => d.fixedIn);
    const get = fixable.length > 0 ? ` (go get ${fixable.slice(0, 6).map((d) => `${d.name}@${d.fixedIn}`).join(" ")}${fixable.length > 6 ? " ..." : ""})` : "";
    return `minimal version selection gives the project at least these versions of the ones its build uses: after upgrading, run go mod tidy and raise each one your go.mod lists${get}`;
  }
  // A held requirement's newest admitted release is the affected one: the project cannot raise it past
  // what the target requires, so the way out is another release of the package, not a later bump.
  return `installing it installs ${affected.length === 1 ? "that release" : "those releases"}, and no newer one ${affected.length === 1 ? "its requirement admits" : "their requirements admit"} is clean`;
}
