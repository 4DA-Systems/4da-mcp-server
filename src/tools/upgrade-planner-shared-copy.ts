// SPDX-License-Identifier: Apache-2.0
/**
 * A declared npm dependency's upgrade moves the project's own requirement, not the other packages'
 * that use the same copy. uptime-kuma declares tar "~6.1.11" and its one tar 6.1.15 is also what
 * @louislam/sqlite3, @mapbox/node-pre-gyp, cacache and node-gyp require ("^6..."); after `npm
 * install "tar@~7.5.21"` the root had tar 7.5.23 and each of the four a nested tar 6.2.1, which 12
 * advisories affect, while the row said `fixes: ["npm:tar"]`.
 *
 * From the lockfile's own edges, the packages whose requirement on that copy excludes the target
 * are found, with the copy each keeps. Measured 2026-11-23 with semver 5.7.1 shared by the project
 * ("5.7.1") and normalize-package-data 2.5.0 ("2 || 3 || 4 || 5"), the project moved to 7.5.4: npm
 * 10.9.2 and Yarn 1.22.22 gave normalize-package-data a new copy, 5.7.3, the newest release its
 * requirement admits (npm nests it); pnpm 9.3.0 and Yarn 4.9.1 kept 5.7.1, the copy the lockfile
 * entry holds. When a copy they keep is affected (or that could not be established), the row says
 * which packages, their requirements and the copy, whether a release inside those requirements
 * clears it, and the hand step that moves them (upgradeInstructions). A row whose fix is partly by
 * hand is left out of run_order, which never claims to serve a row it does not finish, and the
 * plan's summary does not count it as fixed.
 */

import * as path from "node:path";
import type { FixPathSources, PackageReleaseFacts } from "../live/fix-paths.js";
import { byDeadline } from "../live/held-dependencies.js";
import type { LiveIntelligence } from "../live/index.js";
import { prepareLockfileParents, type LockfileFormat, type ParentEdge } from "../live/lockfile-parents.js";
import { advisoryAffects, cleanReleases, type AdvisoryRanges } from "../live/osv-ranges.js";
import { npmRangeAdmits } from "../live/range-satisfies.js";
import { computeSemverDistance } from "../live/semver-utils.js";
import { compareVersions } from "../live/version-compare.js";
import { npmPick } from "./dependency-check-resolution.js";
import { overrideHint, type FixPathInput, type FixPathStep } from "./upgrade-planner-fixpaths.js";
import { relativeDir } from "./vulnerability-scan-format.js";

type Intel = Pick<LiveIntelligence, "getFixPathSources" | "lockfileFor" | "getProjectRoot">;

/** The first words of the reason written here: upgrade_planner counts such a row apart from its fixes. */
export const SHARED_COPY_REASON = /^Other packages that use this copy of \S+ keep one on its old line after this upgrade/;

/** Holders named per row; the rest are counted. */
const MAX_NAMED = 4;
/** Holders whose requirement is read per lockfile (pnpm lockfiles record none; the registry is asked). */
const MAX_HOLDERS = 24;
/** Advisory ids named per row; the rest are counted. */
const MAX_IDS = 6;

const NPM_FAMILY = new Set<LockfileFormat>(["package-lock", "pnpm", "yarn", "yarn-berry"]);

interface Holder {
  name: string;
  version: string;
  /** Its requirement on the package; null when it could not be read. */
  requirement: string | null;
  /** The copy it keeps after the upgrade; null when that could not be established. */
  keeps: string | null;
}

export async function withSharedCopies(steps: FixPathStep[], inputs: FixPathInput[], liveIntel: Intel, deadline: number): Promise<void> {
  const sources = liveIntel.getFixPathSources();
  if (!sources) return;
  for (const step of steps) {
    if (step.ecosystem !== "npm" || step.scope !== "direct" || step.action !== "upgrade_direct" || !step.targetVersion || !step.currentVersion) continue;
    if (!step.upgradeCommands?.length) continue;
    if (step.reasons.some((r) => SHARED_COPY_REASON.test(r))) continue;
    const dirs = [...new Set(inputs.find((i) => i.step === step)?.sourceDirs ?? [])];
    for (const dir of dirs) {
      if (Date.now() >= deadline) return;
      await sharedCopy(step, dir, sources, liveIntel, deadline).catch(() => undefined);
    }
  }
}

async function sharedCopy(step: FixPathStep, dir: string, sources: FixPathSources, liveIntel: Intel, deadline: number): Promise<void> {
  const name = step.package;
  const installed = step.currentVersion!;
  const target = step.targetVersion!;
  const lockfile = liveIntel.lockfileFor(dir, "npm");
  if (!lockfile) return;
  const index = await prepareLockfileParents(lockfile);
  if (!index || !NPM_FAMILY.has(index.format)) return;
  const edges = index.parents(name, installed).filter((e) => !e.local && e.parentVersion !== null);
  if (edges.length === 0) return;

  const [facts, listed] = await Promise.all([
    byDeadline(sources.releaseFacts("npm", name), deadline, null),
    byDeadline(sources.packageAdvisories("npm", name), deadline, null),
  ]);
  const holders: Holder[] = [];
  const seen = new Set<string>();
  for (const e of edges.slice(0, MAX_HOLDERS)) {
    const key = `${e.parent}@${e.parentVersion}`;
    if (seen.has(key)) continue;
    seen.add(key);
    // A peer holds no copy of its own: it is resolved from the tree (a peer range the target leaves is run_order's rule e).
    const history = await byDeadline(sources.requirementHistory("npm", e.parent, name), deadline, null);
    if (history?.[e.parentVersion!]?.peer === true) continue;
    const requirement = await requirementOf(e, name, sources, deadline);
    // A requirement that admits the target shares the upgraded copy.
    if (requirement !== null && npmRangeAdmits(requirement, target) === true) continue;
    holders.push({ name: e.parent, version: e.parentVersion!, requirement, keeps: e.bundled ? installed : keptCopy(index.format, requirement, installed, facts) });
  }
  if (holders.length === 0) return;
  const more = Math.max(0, edges.length - MAX_HOLDERS);

  const ids = (v: string) => (listed ? [...new Set(listed.filter((a) => !a.maintenance && advisoryAffects(a, v, "npm")).map((a) => a.id))].sort() : null);
  const kept = [...new Set(holders.map((h) => h.keeps))];
  const affected = kept.flatMap((v) => (v === null ? [] : (ids(v) ?? [])));
  const unknown = !listed || kept.includes(null) || holders.some((h) => h.requirement === null);
  if (!unknown && affected.length === 0) return;

  const root = liveIntel.getProjectRoot() ?? process.cwd();
  const where = relativeDir(path.dirname(lockfile), root);
  const named = holders.slice(0, MAX_NAMED).map((h) => `${h.name} ${h.version} (${h.requirement === null ? "its requirement could not be read" : `"${h.requirement}"`})`);
  const rest = holders.length - named.length + more;
  const who = `${holders.length + more} ${holders.length + more === 1 ? "package requires" : "packages require"} ${name} outside ${target}: ${named.join(", ")}${rest > 0 ? ` and ${rest} more` : ""}`;
  const copies = kept.filter((v): v is string => v !== null).sort((a, b) => compareVersions(a, b, "npm"));
  const keepsWords =
    copies.length === 0
      ? "which copy they keep could not be established"
      : RESOLVES_ANEW.has(index.format)
        ? `${index.format === "package-lock" ? "npm" : "Yarn"} installs ${name} ${copies.join(", ")} for them (the newest release their requirement admits)`
        : `they keep ${name} ${copies.join(", ")}, the copy their lockfile entry holds`;
  const uniqueIds = [...new Set(affected)];
  const affectedWords = unknown && uniqueIds.length === 0
    ? `whether ${copies.length === 1 ? "it is" : "they are"} affected was not established${listed ? "" : ` (OSV.dev gave no answer for ${name})`}`
    : `${uniqueIds.length} advisor${uniqueIds.length === 1 ? "y still affects" : "ies still affect"} ${copies.length === 1 ? "it" : "them"} (${uniqueIds.slice(0, MAX_IDS).join(", ")}${uniqueIds.length > MAX_IDS ? ` and ${uniqueIds.length - MAX_IDS} more` : ""})`;
  const inside = cleanInside(holders, facts, listed);
  // An override past what they declare; across a major when the target is on a later major than the copies they keep.
  const crosses = copies.some((v) => computeSemverDistance(v, target)?.label === "major");
  const override = `an override${crosses ? " that crosses a major" : " past the range they declare"}`;
  const insideWords =
    inside === null
      ? "whether a release inside their requirements clears it was not established"
      : inside.length > 0
        ? `${andList(inside.map((r) => `${name} ${r}`))} ${inside.length === 1 ? "is a release" : "are releases"} inside their requirements that no advisory affects: refreshing those copies, or upgrading those packages, moves them`
        : `no release inside their requirements is clear of every advisory: ${override} (${overrideHint(index.format, name, target, where)}; check they run on it) or upgrades of those packages to releases that require ${name} ${target} or later move them`;
  step.reasons.push(
    `Other packages that use this copy of ${name} keep one on its old line after this upgrade: ${who}; ${keepsWords}, and ${affectedWords}. Upgrading ${name} moves only this project's own copy; ${insideWords}. Until then those copies remain, so this row is not counted as fixed and is a hand edit, not in run_order`,
  );
  const one = holders.length + more === 1;
  const instruction = `after upgrading ${name}, the ${one ? "copy" : "copies"} of ${name} that ${one ? `${holders[0].name} keeps remains` : `${holders.length + more} other packages keep remain`} (${copies.length > 0 ? copies.join(", ") : "not established"}): ${inside !== null && inside.length > 0 ? `refresh ${one ? "it" : "them"}, or upgrade ${one ? "that package" : "those packages"}, to move to ${inside[inside.length - 1]} or later` : `move ${one ? "it" : "them"} by hand, with ${override} or by upgrading ${one ? "that package" : "those packages"}`}, then run vulnerability_scan`;
  step.upgradeInstructions = [...(step.upgradeInstructions ?? []).filter((i) => i.instruction !== instruction), { dir: where, instruction }];
}

/** A holder's requirement on `name`: the lockfile's, else the holder release's own from the registry. */
async function requirementOf(e: ParentEdge, name: string, sources: FixPathSources, deadline: number): Promise<string | null> {
  if (e.range !== null) return e.range;
  const reqs = await byDeadline(sources.parentRequirements("npm", e.parent, e.parentVersion!, name), deadline, null);
  return reqs && reqs.length === 1 ? reqs[0] : null;
}

/** Lockfiles whose tool resolves a new copy for the other packages, rather than keeping the locked one. */
const RESOLVES_ANEW = new Set<LockfileFormat>(["package-lock", "yarn"]);

/**
 * The copy a holder keeps: npm's pick for its requirement (package-lock), Yarn 1's (the highest
 * release it admits, established only where that is npm's pick too), or the locked copy (pnpm, Yarn 4).
 */
function keptCopy(format: LockfileFormat, requirement: string | null, installed: string, facts: PackageReleaseFacts | null): string | null {
  if (!RESOLVES_ANEW.has(format)) return installed;
  if (requirement === null || !facts) return null;
  const every = [...new Set([...facts.versions, ...facts.withdrawn])];
  const admitted = every.filter((v) => npmRangeAdmits(requirement, v) === true);
  if (admitted.length === 0) return null;
  const deprecated = new Set([...facts.withdrawn, ...Object.keys(facts.lineNotices ?? {})]);
  const pick = npmPick({ latest: facts.latest, releases: Object.fromEntries(every.map((v) => [v, { deprecated: deprecated.has(v) ? "deprecated" : null }])) }, admitted)?.version ?? null;
  if (format === "package-lock") return pick;
  const highest = admitted.reduce((m, v) => (compareVersions(v, m, "npm") > 0 ? v : m));
  return pick === highest ? pick : null;
}

/** The newest release inside every holder's requirement that no advisory affects (one per distinct requirement); null when not established. */
function cleanInside(holders: Holder[], facts: PackageReleaseFacts | null, listed: AdvisoryRanges[] | null): string[] | null {
  if (!facts || !listed || holders.some((h) => h.requirement === null)) return null;
  const view = cleanReleases(listed, "npm", facts.versions);
  if (view.unreadable.length > 0) return null;
  const out = new Set<string>();
  for (const req of new Set(holders.map((h) => h.requirement!))) {
    const clean = facts.versions.filter((v) => npmRangeAdmits(req, v) === true && !listed.some((a) => !a.maintenance && advisoryAffects(a, v, "npm")));
    if (clean.length === 0) return [];
    out.add(clean.sort((a, b) => compareVersions(a, b, "npm")).pop()!);
  }
  return [...out].sort((a, b) => compareVersions(a, b, "npm"));
}

function andList(parts: string[]): string {
  return parts.length > 1 ? `${parts.slice(0, -1).join(", ")} and ${parts[parts.length - 1]}` : (parts[0] ?? "");
}
