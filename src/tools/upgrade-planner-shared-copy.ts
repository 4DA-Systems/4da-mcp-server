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

import * as fs from "node:fs";
import * as path from "node:path";
import { HELD_UNCLEAN_REASON, type FixPathSources, type PackageReleaseFacts } from "../live/fix-paths.js";
import { byDeadline } from "../live/held-dependencies.js";
import type { LiveIntelligence } from "../live/index.js";
import { prepareLockfileParents, type LockfileFormat, type ParentEdge } from "../live/lockfile-parents.js";
import { advisoryAffects, cleanReleases, isPrereleaseVersion, type AdvisoryRanges } from "../live/osv-ranges.js";
import { npmRangeAdmits } from "../live/range-satisfies.js";
import { computeSemverDistance } from "../live/semver-utils.js";
import { isShellSafeName } from "../live/shell-safe.js";
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
  /** The release this plan's own steps move it to, whose requirement is the one read. */
  movedTo?: string;
}

/**
 * What the plan's own steps move an installed npm package to (`name@version` -> release): a direct
 * upgrade, a parent upgrade every lever of which has a command, and those levers. A package another
 * step moves is judged at the release it moves to (the kuma plan's cypress upgrade replaces
 * @cypress/request 2.88.12, which held qs "~6.10.3"). A row whose target is not a clean fix moves nothing here.
 */
function planMoves(steps: FixPathStep[]): Map<string, string> {
  const out = new Map<string, string>();
  for (const s of steps) {
    if (s.ecosystem !== "npm" || s.reasons.some((r) => HELD_UNCLEAN_REASON.test(r))) continue;
    if (s.action === "upgrade_direct" && s.targetVersion && s.currentVersion && s.upgradeCommands?.length) out.set(`${s.package}@${s.currentVersion}`, s.targetVersion);
    if (s.action !== "upgrade_parent") continue;
    for (const u of s.parentUpgrades ?? []) {
      const named = u.levers.filter((l) => l.to !== null);
      if (named.length === 0 || named.length !== u.levers.length || named.some((l) => !l.commands?.length && l.sameCommandsAs === undefined)) continue;
      for (const l of named) out.set(`${l.name}@${l.version}`, l.to!);
      const brings = [...new Set(named.map((l) => l.brings ?? u.to))];
      if (u.to && brings.length === 1 && brings[0]) out.set(`${u.parent}@${u.from}`, brings[0]);
    }
  }
  return out;
}

export async function withSharedCopies(steps: FixPathStep[], inputs: FixPathInput[], liveIntel: Intel, deadline: number): Promise<void> {
  const sources = liveIntel.getFixPathSources();
  if (!sources) return;
  const moves = planMoves(steps);
  for (const step of steps) {
    if (step.ecosystem !== "npm" || step.scope !== "direct" || step.action !== "upgrade_direct" || !step.targetVersion || !step.currentVersion) continue;
    if (!step.upgradeCommands?.length) continue;
    if (step.reasons.some((r) => SHARED_COPY_REASON.test(r))) continue;
    const dirs = [...new Set(inputs.find((i) => i.step === step)?.sourceDirs ?? [])];
    for (const dir of dirs) {
      if (Date.now() >= deadline) return;
      await sharedCopy(step, dir, sources, liveIntel, moves, deadline).catch(() => undefined);
    }
  }
}

async function sharedCopy(step: FixPathStep, dir: string, sources: FixPathSources, liveIntel: Intel, moves: Map<string, string>, deadline: number): Promise<void> {
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
  // pnpm at a workspace root and Yarn Berry keep the locked copy for an edge whose range admits the target too.
  const full = fullRefresh(index.format, name);
  const locked = keepsLocked(index.format, lockfile) && !(step.upgradeCommands ?? []).some((c) => full !== null && c.command === full) && !(index.format === "yarn-berry" && (step.upgradeCommands ?? []).some((c) => c.command === `yarn up -R ${name}`));
  const lockKept: Holder[] = [];
  const holders: Holder[] = [];
  const seen = new Set<string>();
  for (const e of edges.slice(0, MAX_HOLDERS)) {
    const key = `${e.parent}@${e.parentVersion}`;
    if (seen.has(key)) continue;
    seen.add(key);
    // A peer holds no copy of its own: it is resolved from the tree (a peer range the target leaves is run_order's rule e).
    const history = await byDeadline(sources.requirementHistory("npm", e.parent, name), deadline, null);
    if (history?.[e.parentVersion!]?.peer === true) continue;
    const movedTo = e.bundled ? undefined : moves.get(key);
    if (movedTo !== undefined) {
      // Another step moves it: what that release requires decides which copy it keeps.
      const reqs = await byDeadline(sources.parentRequirements("npm", e.parent, movedTo, name), deadline, null);
      if (reqs !== null && reqs.length === 0) continue;
      const requirement = reqs?.length === 1 ? reqs[0] : null;
      if (requirement !== null && npmRangeAdmits(requirement, target) === true) {
        if (locked) lockKept.push({ name: e.parent, version: e.parentVersion!, requirement, keeps: installed, movedTo });
        continue;
      }
      const keeps = requirement === null ? null : npmRangeAdmits(requirement, installed) === true ? keptCopy(index.format, requirement, installed, facts) : keptCopy("package-lock", requirement, installed, facts);
      holders.push({ name: e.parent, version: e.parentVersion!, requirement, keeps, movedTo });
      continue;
    }
    const requirement = await requirementOf(e, name, sources, deadline);
    // A requirement that admits the target shares the upgraded copy (npm, Yarn 1, pnpm outside a
    // workspace root); pnpm at a workspace root and Yarn Berry keep the locked one for it.
    if (requirement !== null && npmRangeAdmits(requirement, target) === true) {
      if (locked && !e.bundled) lockKept.push({ name: e.parent, version: e.parentVersion!, requirement, keeps: installed });
      continue;
    }
    // Under pnpm and Yarn Berry an unread requirement keeps the locked copy as well: said below, never assumed shared.
    holders.push({ name: e.parent, version: e.parentVersion!, requirement, keeps: e.bundled ? installed : keptCopy(index.format, requirement, installed, facts) });
  }
  if (holders.length === 0 && lockKept.length > 0) {
    const unexamined = Math.max(0, edges.length - MAX_HOLDERS);
    return lockedCopies(step, { name, installed, target, unexamined }, lockKept, index.format, lockDir(lockfile, liveIntel), facts, listed);
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
  const named = holders
    .slice(0, MAX_NAMED)
    .map((h) => `${h.name} ${h.version}${h.movedTo ? `, which this plan moves to ${h.movedTo},` : ""} (${h.requirement === null ? "its requirement could not be read" : `"${h.requirement}"`})`);
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

/**
 * Whether the package manager of `lockfile` keeps the locked copy for a requiring edge the step does
 * not name, even when that edge's range admits the target. Measured 2026-11-26 (scripts off): Yarn
 * Berry 3.2.4 / 4.9.1 always (one resolution per descriptor: redux-toolkit's "nanoid@npm:^3.1.23"
 * stayed on 3.3.4 after `yarn workspace docs add "nanoid@^3.3.18"`); pnpm 7.33.7 / 10.34.6 at a
 * workspace root (vue core: json5's edge stayed on minimist 1.2.5 after the root's
 * `pnpm update minimist --no-save`, with or without `--depth Infinity`), but not in a project that
 * is no workspace, where the root's own update or `pnpm up` moved the json5 edge too.
 */
function keepsLocked(format: LockfileFormat, lockfile: string): boolean {
  return format === "yarn-berry" || (format === "pnpm" && fs.existsSync(path.join(path.dirname(lockfile), "pnpm-workspace.yaml")));
}

/**
 * The manager's own refresh of every edge of `name`, which leaves every manifest as it is: Yarn
 * Berry's `yarn up -R` (each descriptor to the newest release it admits); pnpm's
 * `update -r ... --depth Infinity --no-save` (every importer, every depth; without --no-save it
 * rewrote the root's ^1.2.0 to ^1.2.8). Null for a name that cannot be carried in a command.
 */
function fullRefresh(format: LockfileFormat, name: string): string | null {
  if (!isShellSafeName(name, "npm")) return null;
  if (format === "yarn-berry") return `yarn up -R ${name}`;
  if (format === "pnpm") return `pnpm update -r ${name} --depth Infinity --no-save`;
  return null;
}

function lockDir(lockfile: string, liveIntel: Intel): string {
  return relativeDir(path.dirname(lockfile), liveIntel.getProjectRoot() ?? process.cwd());
}

/**
 * Other packages hold the same locked copy through a range that admits the target, and their
 * manager keeps that copy when only the declared entry moves. When each of their requirements
 * resolves to a release at or above the target that no advisory affects (the release a refresh
 * installs: the newest it admits), the row also runs the manager's refresh of every edge, after the
 * step; otherwise the row says which copy stays and is a hand edit, not counted as fixed.
 */
function lockedCopies(
  step: FixPathStep,
  copy: { name: string; installed: string; target: string; unexamined: number },
  kept: Holder[],
  format: LockfileFormat,
  dir: string,
  facts: PackageReleaseFacts | null,
  listed: AdvisoryRanges[] | null,
): void {
  const { name, installed, target, unexamined } = copy;
  const manager = format === "yarn-berry" ? "Yarn Berry" : "at a pnpm workspace root pnpm";
  const shown = kept.slice(0, MAX_NAMED).map((h) => `${h.name} ${h.version}${h.movedTo ? `, which this plan moves to ${h.movedTo},` : ""} ("${h.requirement}")`);
  const rest = kept.length - shown.length + unexamined;
  const named = `${shown.join(", ")}${rest > 0 ? ` and ${rest} more` : ""}`;
  const one = kept.length + unexamined === 1;
  const command = fullRefresh(format, name);

  // What a refresh installs for each of their requirements: the newest release it admits.
  let why: string | null = null;
  const resolves = new Set<string>();
  if (!facts || !listed || unexamined > 0 || command === null) {
    why = `whether a refresh of ${one ? "its" : "their"} requirement reaches a clean release was not established${unexamined > 0 ? ` (${unexamined} of them were not read)` : ""}`;
  } else {
    const releases = facts.versions.filter((v) => !isPrereleaseVersion(v, "npm") && !facts.withdrawn.includes(v));
    for (const req of new Set(kept.map((h) => h.requirement!))) {
      const newest = releases.filter((v) => npmRangeAdmits(req, v) === true).sort((a, b) => compareVersions(b, a, "npm"))[0];
      if (!newest) {
        why = `no release ${one ? "its" : "their"} requirement "${req}" admits was found`;
        break;
      }
      if (compareVersions(newest, target, "npm") < 0) {
        why = `a refresh of ${one ? "its" : "their"} requirement resolves to ${name} ${newest}, below the fix ${target}`;
        break;
      }
      const ids = [...new Set(listed.filter((a) => !a.maintenance && advisoryAffects(a, newest, "npm")).map((a) => a.id))].sort();
      if (ids.length > 0) {
        why = `a refresh of ${one ? "its" : "their"} requirement resolves to ${name} ${newest}, which ${ids.length === 1 ? "an advisory affects" : `${ids.length} advisories affect`} (${ids.slice(0, MAX_IDS).join(", ")}${ids.length > MAX_IDS ? ` and ${ids.length - MAX_IDS} more` : ""})`;
        break;
      }
      resolves.add(newest);
    }
  }
  if (why === null && command !== null) {
    const to = [...resolves].sort((a, b) => compareVersions(a, b, "npm"));
    step.refreshCommands = [...(step.refreshCommands ?? []).filter((c) => !(c.dir === dir && c.command === command)), { dir, command }];
    step.reasons.push(
      `${named} also ${one ? "holds" : "hold"} ${name} ${installed}: ${manager} keeps that locked copy when only the declared entry moves, so this row also runs \`${command}\`, which resolves their requirement to ${name} ${to.join(", ")} (no advisory affects ${to.length === 1 ? "it" : "them"})`,
    );
    return;
  }
  step.reasons.push(
    `Other packages that use this copy of ${name} keep one on its old line after this upgrade: ${named} ${one ? "keeps" : "keep"} ${name} ${installed}, the copy ${one ? "its lockfile entry holds" : "their lockfile entries hold"} (${manager} keeps a locked copy when only the declared entry moves), and ${why}. Upgrading ${name} moves only this project's own copy, so this row is not counted as fixed and is a hand edit, not in run_order`,
  );
  const instruction = `after upgrading ${name}, the copy of ${name} ${installed} that ${one ? `${kept[0].name} keeps remains` : `${kept.length + unexamined} other packages keep remains`}: move it by hand (an override, or an upgrade of ${one ? "that package" : "those packages"}), then run vulnerability_scan`;
  step.upgradeInstructions = [...(step.upgradeInstructions ?? []).filter((i) => i.instruction !== instruction), { dir, instruction }];
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
