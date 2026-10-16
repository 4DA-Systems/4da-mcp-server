// SPDX-License-Identifier: Apache-2.0
/**
 * Fix-path verification for upgrade_planner steps (see live/fix-paths.ts):
 * the target must clear EVERY known advisory of the package, and a
 * transitive step is "waiting on upstream" only when a parent's declared
 * requirement actually excludes every clean version AND nothing about the
 * parent's releases could be read.
 *
 * When a parent blocks the refresh and has a newer release, the step names
 * the move (readiness audit H1, 2026-10-16; the 4DA app's
 * `evidence/upgrade_parent.rs::parent_move`): the smallest parent release
 * whose own declared requirement admits a clean version, read from the
 * registry, through the direct dependency the parent arrives by when it is
 * transitive; otherwise the parent's newest release, to check. NodeGoat's
 * path-to-regexp 0.1.7 was "waiting on upstream" while express 4.22.0
 * already requires ~0.1.12.
 *
 * Runs on the steps the plan returns, within a time budget. A step whose
 * lookups fail or run out of time keeps its unverified answer and says so in
 * `fixPathChecked`.
 */

import * as fs from "node:fs";
import type { LiveIntelligence } from "../live/index.js";
import { cleanFixTarget, directCommandFor, overrideReaches, refreshVerdict, type FixPathSources, type FixTargetResult, type PackageReleaseFacts, type RefreshVerdict } from "../live/fix-paths.js";
import {
  cargoParents,
  lockfileFormat,
  packageLockParents,
  pnpmParents,
  readLockfileParents,
  yarnParents,
  type LockfileFormat,
  type ParentEdge,
} from "../live/lockfile-parents.js";
import { advisoryAffects, isPrereleaseVersion, type AdvisoryRanges } from "../live/osv-ranges.js";
import { requirementAdmits, type RequirementDialect } from "../live/refresh-rule.js";
import { compareVersions } from "../live/version-compare.js";
import { computeSemverDistance } from "../live/semver-utils.js";
import type { OsvEcosystem } from "../live/types.js";
import { relativeDir } from "./vulnerability-scan-format.js";

/**
 * One blocking parent that can move: the release of it that admits a clean
 * version of the package, and the dependency the project declares that moves it.
 */
export interface ParentUpgrade {
  /** The installed parent whose requirement excludes every clean version. */
  parent: string;
  from: string;
  /** The smallest release of `parent` whose own requirement admits a clean version; null when its requirements could not be read. */
  to: string | null;
  /** `to`'s requirement on the package; null when `to` no longer depends on it. Absent when `to` is null. */
  requirement?: string | null;
  /** The version `to`'s requirement resolves the package to (its newest match), when the registry's version list was read. */
  resolvesTo?: string | null;
  /** When `to` is null: the parent's newest release, which may or may not admit a clean version. */
  latest?: string;
  /**
   * What the project declares and bumps: the parent itself when it is a direct dependency, else
   * the direct dependency it arrives through. `to` is the lever's release that brings the fix in,
   * or null when it could not be worked out (then the reason says what to check).
   */
  lever: { name: string; version: string; to: string | null };
  /** The command that moves the lever to `lever.to`, in the lockfile's directory. */
  command?: string;
}

/** The planner fields this step reads and rewrites. */
export interface FixPathStep {
  package: string;
  ecosystem: string;
  currentVersion: string | null;
  targetVersion: string | null;
  latestVersion?: string | null;
  upgradeType: "patch" | "minor" | "major" | "unknown";
  reasons: string[];
  breaking: boolean;
  scope: "direct" | "transitive";
  action: string;
  /** How the target was checked: against every advisory of the package, or only the installed version's. */
  fixPathChecked?: "all_advisories" | "installed_advisories_only";
  /** lockfile_refresh: the command per lockfile directory. */
  refreshCommands?: Array<{ dir: string; command: string }>;
  /** lockfile_refresh: true when not every parent's requirement could be read and the verdict comes from semver compatibility. */
  refreshInferred?: boolean;
  /** upgrade_direct: the command that moves the declared dependency to targetVersion, per lockfile directory. */
  upgradeCommands?: Array<{ dir: string; command: string }>;
  /** upgrade_parent / override_or_replace: the releases of the blocking parents that admit a clean version. */
  parentUpgrades?: ParentUpgrade[];
  isDev?: boolean;
}

export interface FixPathInput {
  step: FixPathStep;
  /** Per-advisory fixes on the installed line (each advisory's own fixedVersion). */
  fixes: string[];
  /** Manifest directories that pin this copy (the scan's sourceDirs). */
  sourceDirs: string[];
  /** Advisories (one per alias group) that name no fixed version: `id` to print, `ids` every id of the group (M2). */
  unfixed?: Array<{ id: string; ids: string[] }>;
}

type Intel = Pick<LiveIntelligence, "getFixPathSources" | "lockfileFor" | "getProjectRoot">;

/** Total time the plan spends verifying fix paths before answering with what it has. */
const FIX_PATH_BUDGET_MS = 25_000;
const CONCURRENCY = 12;
/** Blocking parents whose releases are looked up, per step. */
const MAX_PARENTS = 5;
/** Lockfile entries visited when looking for the direct dependency a parent arrives through. */
const MAX_THROUGH_NODES = 40;

const TRANSITIVE_REASON = /^Transitive dependency — /;
const NO_FIX_REASON = /^\d+ of them (?:has|have) no published fix$/;

/** Verify and rewrite the steps in place. Returns how many could not be verified (offline, failure, budget). */
export async function verifyFixPaths(inputs: FixPathInput[], liveIntel: Intel, budgetMs = FIX_PATH_BUDGET_MS): Promise<number> {
  const sources = liveIntel.getFixPathSources();
  // A step with no per-advisory fix ("no_fix_available") is still looked up: its advisories
  // may give only a last_affected bound with a clean release above it (A6).
  // Runtime steps first (stable: plan order within each): with dev-only rows in the plan
  // (audit H4), NodeGoat's 104 dev rows ran express's own steps past the budget.
  const todo = inputs
    .filter((i) => (i.fixes.length > 0 || i.step.action === "no_fix_available") && i.step.currentVersion)
    .sort((a, b) => Number(a.step.isDev === true) - Number(b.step.isDev === true));
  if (!sources) {
    for (const i of todo) i.step.fixPathChecked = "installed_advisories_only";
    return todo.length;
  }
  const deadline = Date.now() + budgetMs;
  let unverified = 0;
  let next = 0;
  const worker = async () => {
    while (next < todo.length) {
      const input = todo[next++];
      const remaining = deadline - Date.now();
      const ok = remaining > 0 && (await withTimeout(verifyOne(input, sources, liveIntel), remaining));
      if (!ok) {
        input.step.fixPathChecked = "installed_advisories_only";
        unverified++;
      }
    }
  };
  await Promise.all(Array.from({ length: Math.min(CONCURRENCY, todo.length) }, worker));
  return unverified;
}

async function withTimeout(work: Promise<boolean>, ms: number): Promise<boolean> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const late = new Promise<boolean>((resolve) => {
    timer = setTimeout(() => resolve(false), ms);
  });
  try {
    return await Promise.race([work.catch(() => false), late]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

function setTarget(step: FixPathStep, target: string): void {
  step.targetVersion = target;
  const d = step.currentVersion ? computeSemverDistance(step.currentVersion, target) : null;
  step.upgradeType = !d || d.label === "up-to-date" ? "unknown" : d.label;
  if (step.scope === "direct") step.breaking = step.upgradeType === "major";
}

async function verifyOne(input: FixPathInput, sources: FixPathSources, liveIntel: Intel): Promise<boolean> {
  const { step } = input;
  const ecosystem = step.ecosystem as OsvEcosystem;
  const clean = await cleanFixTarget(sources, ecosystem, step.package, input.fixes, step.currentVersion);
  if (input.fixes.length === 0) {
    // No advisory names a fix: the answer stays "no fix" unless the registry has a clean release past the bound.
    if (!clean?.noAdvisoryFix || !clean.target) return true;
    step.fixPathChecked = "all_advisories";
    step.reasons.push(
      `No advisory names a fixed version (they give only a last affected one); ${clean.target} is the first published release above ${step.currentVersion} that no known advisory affects`,
    );
    setTarget(step, clean.target);
    step.breaking = step.scope === "direct" && step.upgradeType === "major";
    step.action = step.scope === "direct" ? "upgrade_direct" : "waiting_on_upstream";
    if (step.scope === "transitive" && step.currentVersion) await refreshOrUpstream(input, sources, liveIntel, clean.target, clean.unfixable);
    withUpgradeCommands(input, liveIntel);
    return true;
  }
  if (!clean) return false;
  if (clean.advisoriesUnread && clean.target) {
    // H5: OSV did not list the advisories, the registry answered. The highest per-advisory fix
    // is withdrawn (lodash 4.18.0, "Bad release"), so it is never the target; the step still
    // counts as checked against the installed version's advisories only.
    step.reasons.push(
      `${clean.target} is the smallest installable release at or above ${clean.floor}, the highest per-advisory fix, which ${clean.floorWithdrawn ? "is deprecated or yanked on the registry" : "is not a published release"}; the package's other advisories could not be read`,
    );
    setTarget(step, clean.target);
    if (step.latestVersion === step.targetVersion) delete step.latestVersion;
    withUpgradeCommands(input, liveIntel);
    return false;
  }
  step.fixPathChecked = "all_advisories";

  if (clean.target === null) {
    step.reasons.push(
      `No published version clears every known advisory: ${clean.floor}, the highest per-advisory fix, is still affected by ${clean.stillAffectedBy.join(", ")}`,
    );
    step.targetVersion = null;
    step.upgradeType = "unknown";
    step.breaking = false;
    step.action = "no_fix_available";
    return true;
  }
  if (clean.stillAffectedBy.length > 0) {
    step.reasons.push(
      `${clean.stillAffectedBy.join(", ")} also affect${clean.stillAffectedBy.length === 1 ? "s" : ""} ${clean.target} and every newer release: no published version fixes ${clean.stillAffectedBy.length === 1 ? "it" : "them"}`,
    );
  }
  rewriteNoFixReason(input, clean);
  if (clean.target !== clean.floor) {
    const why = clean.floorAffectedBy.length > 0
      ? `is itself affected by ${clean.floorAffectedBy.join(", ")}`
      : clean.floorWithdrawn
        ? "is deprecated or yanked on the registry"
        : "is not a published release";
    step.reasons.push(
      `${clean.target} is the smallest ${clean.basis === "registry" ? "published " : ""}version clear of every advisory a release fixes (${clean.floor}, the highest per-advisory fix, ${why})`,
    );
  }
  if (step.targetVersion !== clean.target) setTarget(step, clean.target);
  if (step.latestVersion === step.targetVersion) delete step.latestVersion;

  if (step.scope === "transitive" && step.action === "waiting_on_upstream" && step.currentVersion) {
    await refreshOrUpstream(input, sources, liveIntel, clean.target, clean.unfixable);
  }
  withUpgradeCommands(input, liveIntel);
  return true;
}

/**
 * "N of them have no published fix" is true only of the advisories that still affect the target.
 * One that gives only a last affected version below the target is resolved by it (M2: pyjwt
 * PYSEC-2025-183, last_affected 2.10.1, target 2.15.0).
 */
function rewriteNoFixReason(input: FixPathInput, clean: FixTargetResult): void {
  const { step } = input;
  const at = step.reasons.findIndex((r) => NO_FIX_REASON.test(r));
  if (at < 0 || !clean.target || !input.unfixed || input.unfixed.length === 0) return;
  const still = input.unfixed.filter((u) => u.ids.some((id) => clean.stillAffectedBy.includes(id)));
  const past = input.unfixed.filter((u) => !still.includes(u));
  const parts: string[] = [];
  if (still.length > 0) {
    parts.push(
      `${still.length} of them ${still.length === 1 ? "has" : "have"} no published fix (${still.map((u) => u.id).join(", ")} also affect${still.length === 1 ? "s" : ""} ${clean.target})`,
    );
  }
  if (past.length > 0) {
    parts.push(
      `${past.map((u) => u.id).join(", ")} name${past.length === 1 ? "s" : ""} no fixed version (only a last affected one); ${clean.target} is past ${past.length === 1 ? "it" : "them"}`,
    );
  }
  step.reasons[at] = parts.join("; ");
}

/** upgrade_direct: name the command that moves the declared dependency, per lockfile the project holds (audit E8). */
function withUpgradeCommands(input: FixPathInput, liveIntel: Pick<LiveIntelligence, "lockfileFor" | "getProjectRoot">): void {
  const { step } = input;
  if (step.action !== "upgrade_direct" || step.scope !== "direct" || !step.targetVersion) return;
  const root = liveIntel.getProjectRoot() ?? process.cwd();
  const commands = [...new Set(input.sourceDirs)].flatMap((dir) => {
    const lockfile = liveIntel.lockfileFor(dir, step.ecosystem as OsvEcosystem);
    const command = lockfile ? directCommandFor(lockfile, step.package, step.targetVersion!, step.isDev === true) : null;
    return command ? [{ dir: relativeDir(dir, root), command }] : [];
  });
  if (commands.length > 0) step.upgradeCommands = commands;
}

type Blocking = RefreshVerdict["blocking"][number] & { lockfile: string; format: LockfileFormat };

async function refreshOrUpstream(
  input: FixPathInput,
  sources: FixPathSources,
  liveIntel: Pick<LiveIntelligence, "lockfileFor" | "getProjectRoot">,
  target: string,
  unfixable: string[],
): Promise<void> {
  const { step } = input;
  const ecosystem = step.ecosystem as OsvEcosystem;
  const installed = step.currentVersion!;
  const lockfiles = [...new Set(input.sourceDirs)]
    .map((dir) => ({ dir, lockfile: liveIntel.lockfileFor(dir, ecosystem) }))
    .filter((l): l is { dir: string; lockfile: string } => l.lockfile !== null);
  if (lockfiles.length === 0) return;

  // An advisory no release fixes cannot make a refresh target unclean: every target has it.
  const [all, published] = await Promise.all([
    sources.packageAdvisories(ecosystem, step.package),
    sources.publishedVersions(ecosystem, step.package),
  ]);
  const advisories = all?.filter((a) => !unfixable.includes(a.id)) ?? null;
  const results = await Promise.all(
    lockfiles.map(async ({ dir, lockfile }) => ({
      dir,
      lockfile,
      verdict: await refreshVerdict(sources, ecosystem, lockfile, step.package, installed, target, advisories, published),
    })),
  );
  // Unknown for one lockfile: the conservative label stays.
  if (results.some((r) => r.verdict === null)) return;
  const verdicts = results as Array<{ dir: string; lockfile: string; verdict: RefreshVerdict }>;

  const root = liveIntel.getProjectRoot() ?? process.cwd();
  const where = (dir: string) => relativeDir(dir, root);
  const reasonAt = step.reasons.findIndex((r) => TRANSITIVE_REASON.test(r));
  const replaceReason = (text: string) => {
    if (reasonAt >= 0) step.reasons[reasonAt] = text;
    else step.reasons.push(text);
  };

  if (verdicts.every((v) => v.verdict.refreshFixes)) {
    step.action = "lockfile_refresh";
    step.refreshCommands = verdicts.map((v) => ({ dir: where(v.dir), command: v.verdict.command }));
    if (verdicts.some((v) => v.verdict.inferred)) {
      // 4DA AD-055 ¶1: nothing readable falls back to semver compatibility, and says so.
      step.refreshInferred = true;
      replaceReason(
        `Transitive dependency: not every parent's requirement on ${step.package} could be read, and none that was excludes ${target}; ${target} is semver-compatible with ${installed}, so a lockfile refresh should reach it (inferred, not read from the parents): ${verdicts.map((v) => `\`${v.verdict.command}\` in ${where(v.dir)}`).join("; ")}`,
      );
      return;
    }
    const resolves = verdicts.map((v) => v.verdict.resolvesTo).filter((v): v is string => v !== null);
    const to = resolves.length > 0 ? ` (a refresh resolves it to ${[...new Set(resolves)].join(", ")})` : "";
    replaceReason(
      `Transitive dependency: every parent's declared requirement already admits ${target}${to}, so a lockfile refresh is enough, no parent upgrade: ${verdicts.map((v) => `\`${v.verdict.command}\` in ${where(v.dir)}`).join("; ")}`,
    );
    return;
  }
  // Inferred from semver with nothing read that blocks: the conservative label and its reason stay.
  if (verdicts.every((v) => v.verdict.blocking.length === 0)) return;
  const seen = new Set<string>();
  const blocking: Blocking[] = verdicts
    .flatMap((v) => v.verdict.blocking.map((b) => ({ ...b, lockfile: v.lockfile, format: v.verdict.format })))
    .filter((b) => {
      const key = `${b.parent} ${b.parentVersion} ${b.requirement}`;
      return !seen.has(key) && Boolean(seen.add(key));
    });
  const named = blocking
    .slice(0, 3)
    .map((b) =>
      b.bundled
        ? `${b.parent}${b.parentVersion ? ` ${b.parentVersion}` : ""} ships it bundled at ${b.requirement}`
        : `${b.parent}${b.parentVersion ? ` ${b.parentVersion}` : ""} requires "${b.requirement}"`,
    )
    .join(", ");
  const more = blocking.length > 3 ? ` and ${blocking.length - 3} more` : "";
  // A bundled copy ships inside its owner's tarball: no lockfile refresh and no override reaches it
  // (npm 10.9.2, checked 2026-10-15), so the only moves are a new owner release or replacing the owner.
  if (!overrideReaches(blocking)) {
    const owners = [...new Set(blocking.filter((b) => b.bundled).map((b) => b.parent))];
    step.action = "waiting_on_upstream";
    replaceReason(
      `Transitive dependency, waiting on upstream: ${named}${more}. A bundled copy ships inside its owner's package, so neither a lockfile refresh nor an override can move it to ${target}: ${owners.join(", ")} must release a version that ships ${step.package} >= ${target}, or be replaced`,
    );
    return;
  }

  // What each blocking parent can do: move to a release that admits a clean version (H1), or
  // nothing (deprecated, already latest, no release admits one: A4), or unknown.
  const clean = (v: string) => !advisories || !advisories.some((a) => advisoryAffects(a, v, ecosystem));
  const releases = (published ?? []).filter((v) => !isPrereleaseVersion(v, ecosystem));
  const ctx: MoveContext = { sources, ecosystem, pkg: step.package, target, clean, releases, dev: step.isDev === true, readers: new Map() };
  const considered = blocking.filter((b) => b.parentVersion !== null).slice(0, MAX_PARENTS);
  const standings = await Promise.all(considered.map((b) => parentStanding(ctx, b)));
  const stuck = standings.filter((s): s is Extract<Standing, { kind: "stuck" }> => s.kind === "stuck");
  const moves = standings.filter((s): s is Extract<Standing, { kind: "move" }> => s.kind === "move");
  if (moves.length > 0) step.parentUpgrades = moves.map((m) => m.upgrade);

  if (stuck.length > 0) {
    // A parent that will not move makes "waiting on upstream" a dead end (A4, request 2.88.2):
    // the step is an override of the transitive, or replacing that parent.
    step.action = "override_or_replace";
    const formats = [...new Set(verdicts.map((v) => v.verdict.format))];
    const others = moves.length > 0 ? `. The other parents can move: ${moves.map((m) => m.text).join("; ")}` : "";
    replaceReason(
      `Transitive dependency: ${named}${more}, and ${stuck.map((s) => s.text).join("; ")}, so no parent release will widen it. Force ${step.package} to ${target}: ${formats.map((f) => overrideHint(f, step.package, target)).join("; ")}; or replace the parent${others}`,
    );
    return;
  }
  if (moves.length > 0 && moves.length === blocking.length) {
    step.action = "upgrade_parent";
    replaceReason(`Transitive dependency: ${moves.map((m) => m.text).join("; ")}`);
    return;
  }
  const known = moves.length > 0 ? `; meanwhile ${moves.map((m) => m.text).join("; ")}` : "";
  replaceReason(
    `Transitive dependency, waiting on upstream: ${named}${more}, so a refresh cannot reach a clean version, and the releases of ${standings.length < blocking.length ? "some parents were not checked" : "a parent could not be read"}${known}`,
  );
}

interface MoveContext {
  sources: FixPathSources;
  ecosystem: OsvEcosystem;
  pkg: string;
  target: string;
  /** Not affected by any advisory a release fixes. */
  clean: (version: string) => boolean;
  /** The package's installable, non-prerelease versions; [] when unknown. */
  releases: string[];
  dev: boolean;
  /** One parsed lockfile per path, for the walk up to a direct dependency. */
  readers: Map<string, ((name: string, version: string) => ParentEdge[]) | null>;
}

type Standing = { kind: "stuck"; text: string } | { kind: "move"; upgrade: ParentUpgrade; text: string } | { kind: "unknown" };

async function parentStanding(ctx: MoveContext, b: Blocking): Promise<Standing> {
  const { sources, ecosystem, pkg, target } = ctx;
  const parent = b.parent;
  const from = b.parentVersion!;
  const facts = await sources.releaseFacts(ecosystem, parent).catch(() => null);
  if (!facts) return { kind: "unknown" };
  if (facts.deprecatedLatest) return { kind: "stuck", text: `${parent} is deprecated ("${facts.deprecatedLatest.slice(0, 120)}")` };
  if (facts.latest && compareVersions(from, facts.latest, ecosystem) >= 0) return { kind: "stuck", text: `${parent} ${from} is already its latest release` };

  const dialect: RequirementDialect = b.format === "cargo" ? "cargo" : "npm";
  const excludes = requirementAdmits({ parent, text: b.requirement, dialect }, target) === false;
  const head = `${parent} ${from} requires "${b.requirement}", ${excludes ? `which excludes ${pkg} ${target}` : `under which a refresh does not reach a clean ${pkg}`}`;
  const through = findThrough(ctx, b.lockfile, parent, from);
  const history = await sources.requirementHistory(ecosystem, parent, pkg).catch(() => null);
  const newest = facts.latest ?? newestOf(facts.versions, ecosystem);

  if (!history) {
    // The app's ParentStanding::Newer: a newer release exists, whether it admits the fix is open.
    const lever = through ?? { name: parent, version: from };
    const leverLatest = through ? ((await sources.releaseFacts(ecosystem, through.name).catch(() => null))?.latest ?? null) : newest;
    const check = through ? `check that it brings in a ${parent} that admits ${pkg} >= ${target}` : `check that it admits ${pkg} >= ${target}`;
    const via = through ? `${parent} arrives through ${through.name} ${through.version}, a direct dependency; ` : "";
    return {
      kind: "move",
      upgrade: { parent, from, to: null, ...(newest ? { latest: newest } : {}), lever: { name: lever.name, version: lever.version, to: null } },
      text: `${head}; ${parent}'s release requirements could not be read: ${via}upgrade ${lever.name} (${leverLatest ? `${lever.name} ${leverLatest} is its newest release; ` : ""}${check})`,
    };
  }

  const found = smallestAdmitting(ctx, facts, from, history, dialect);
  if (!found) return { kind: "stuck", text: `no ${parent} release up to ${newest ?? "its latest"} admits a clean ${pkg} (>= ${target})` };
  const admits =
    found.requirement === null
      ? `${parent} ${found.version} is the smallest ${parent} release that no longer depends on ${pkg}`
      : `${parent} ${found.version} is the smallest ${parent} release whose requirement "${found.requirement}" admits ${pkg} ${target}${found.resolvesTo ? ` (a refresh then resolves ${found.resolvesTo})` : ""}`;
  const upgrade: ParentUpgrade = {
    parent,
    from,
    to: found.version,
    requirement: found.requirement,
    resolvesTo: found.resolvesTo,
    lever: { name: parent, version: from, to: found.version },
  };
  if (!through) {
    const command = directCommandFor(b.lockfile, parent, found.version, ctx.dev);
    if (command) upgrade.command = command;
    return { kind: "move", upgrade, text: `${head}; ${admits}: upgrade ${parent} to ${found.version}${majorNote(from, found.version)}${command ? ` (\`${command}\`)` : ""}` };
  }

  // The parent is transitive: the move is a release of the direct dependency it arrives through.
  const hop = through.adjacent ? await throughRelease(ctx, through, parent, from, facts, history, dialect) : null;
  if (hop) {
    upgrade.lever = { name: through.name, version: through.version, to: hop.version };
    const command = directCommandFor(b.lockfile, through.name, hop.version, ctx.dev);
    if (command) upgrade.command = command;
    return {
      kind: "move",
      upgrade,
      text: `${head}; ${admits}. ${parent} arrives through ${through.name} ${through.version}, a direct dependency: ${through.name} ${hop.version} is the smallest ${through.name} release that brings in ${parent} ${hop.brings}${hop.brings === found.version ? "" : ` (>= ${found.version})`}: upgrade ${through.name} to ${hop.version}${majorNote(through.version, hop.version)}${command ? ` (\`${command}\`)` : ""}`,
    };
  }
  upgrade.lever = { name: through.name, version: through.version, to: null };
  const throughLatest = (await sources.releaseFacts(ecosystem, through.name).catch(() => null))?.latest ?? null;
  return {
    kind: "move",
    upgrade,
    text: `${head}; ${admits}. ${parent} arrives through ${through.name} ${through.version}, a direct dependency: upgrade ${through.name} to a release that brings in ${parent} >= ${found.version} (${throughLatest ? `${through.name} ${throughLatest} is its newest release; ` : ""}check that it does)`,
  };
}

function majorNote(from: string, to: string): string {
  return computeSemverDistance(from, to)?.label === "major" ? " (a major upgrade)" : "";
}

function newestOf(versions: string[], ecosystem: string): string | null {
  return versions.filter((v) => !isPrereleaseVersion(v, ecosystem)).sort((a, b) => compareVersions(a, b, ecosystem)).pop() ?? null;
}

/**
 * Whether a parent release's requirements on the package admit a clean version: every
 * requirement's newest match (what a fresh resolution picks) is at or above the target and
 * clean. Without the package's version list, the requirement must admit the target itself.
 * `requirement: null` when the release no longer depends on the package.
 */
function admitsClean(ctx: MoveContext, reqs: string[], dialect: RequirementDialect): { requirement: string | null; resolvesTo: string | null } | null {
  if (reqs.length === 0) return { requirement: null, resolvesTo: null };
  let resolvesTo: string | null = null;
  for (const text of reqs) {
    const req = { parent: "", text, dialect };
    if (ctx.releases.length > 0) {
      const newest = ctx.releases.filter((v) => requirementAdmits(req, v) === true).sort((a, b) => compareVersions(b, a, ctx.ecosystem))[0];
      if (!newest || compareVersions(newest, ctx.target, ctx.ecosystem) < 0 || !ctx.clean(newest)) return null;
      if (resolvesTo === null || compareVersions(newest, resolvesTo, ctx.ecosystem) < 0) resolvesTo = newest;
    } else if (requirementAdmits(req, ctx.target) !== true) {
      return null;
    }
  }
  return { requirement: reqs[0], resolvesTo };
}

/** The smallest installable release of a parent above `from` whose requirement admits a clean version. */
function smallestAdmitting(
  ctx: MoveContext,
  facts: PackageReleaseFacts,
  from: string,
  history: Record<string, string[]>,
  dialect: RequirementDialect,
): { version: string; requirement: string | null; resolvesTo: string | null } | null {
  const candidates = facts.versions
    .filter((v) => !isPrereleaseVersion(v, ctx.ecosystem) && compareVersions(v, from, ctx.ecosystem) > 0)
    .sort((a, b) => compareVersions(a, b, ctx.ecosystem));
  for (const version of candidates) {
    const reqs = history[version];
    if (reqs === undefined) continue;
    const ok = admitsClean(ctx, reqs, dialect);
    if (ok) return { version, ...ok };
  }
  return null;
}

/**
 * The smallest release of the direct dependency `through` that brings in a `parent` release
 * admitting a clean package: its requirement on `parent` resolves (newest match) to a release
 * above the installed one whose own requirement admits a clean version. Only when `through`
 * depends on `parent` directly; null when not found or not readable.
 */
async function throughRelease(
  ctx: MoveContext,
  through: { name: string; version: string },
  parent: string,
  parentFrom: string,
  parentFacts: PackageReleaseFacts,
  parentHistory: Record<string, string[]>,
  dialect: RequirementDialect,
): Promise<{ version: string; brings: string } | null> {
  const [facts, history] = await Promise.all([
    ctx.sources.releaseFacts(ctx.ecosystem, through.name).catch(() => null),
    ctx.sources.requirementHistory(ctx.ecosystem, through.name, parent).catch(() => null),
  ]);
  if (!facts || !history) return null;
  const parentReleases = parentFacts.versions.filter((v) => !isPrereleaseVersion(v, ctx.ecosystem));
  const candidates = facts.versions
    .filter((v) => !isPrereleaseVersion(v, ctx.ecosystem) && compareVersions(v, through.version, ctx.ecosystem) > 0)
    .sort((a, b) => compareVersions(a, b, ctx.ecosystem));
  for (const version of candidates) {
    const reqs = history[version];
    if (!reqs || reqs.length !== 1) continue;
    const req = { parent: through.name, text: reqs[0], dialect };
    const brings = parentReleases.filter((v) => requirementAdmits(req, v) === true).sort((a, b) => compareVersions(b, a, ctx.ecosystem))[0];
    if (!brings || compareVersions(brings, parentFrom, ctx.ecosystem) <= 0) continue;
    const pkgReqs = parentHistory[brings];
    if (pkgReqs !== undefined && admitsClean(ctx, pkgReqs, dialect)) return { version, brings };
  }
  return null;
}

/** The lockfile's parents of one entry, from one parse of the file per plan step. */
function parentsReader(ctx: MoveContext, lockfile: string): ((name: string, version: string) => ParentEdge[]) | null {
  if (ctx.readers.has(lockfile)) return ctx.readers.get(lockfile)!;
  let reader: ((name: string, version: string) => ParentEdge[]) | null = null;
  try {
    const content = fs.readFileSync(lockfile, "utf-8");
    const format = lockfileFormat(lockfile, content);
    if (format === "package-lock") {
      const lock = JSON.parse(content);
      reader = (n, v) => packageLockParents(lock, n, v);
    } else if (format === "pnpm") reader = (n, v) => pnpmParents(content, n, v);
    else if (format === "yarn" || format === "yarn-berry") reader = (n, v) => yarnParents(content, n, v);
    else if (format === "cargo") reader = (n, v) => cargoParents(content, n, v);
    else if (format === "bun") reader = (n, v) => readLockfileParents(lockfile, n, v)?.edges ?? [];
  } catch {
    reader = null;
  }
  ctx.readers.set(lockfile, reader);
  return reader;
}

/**
 * The direct dependency a transitive parent arrives through (the app's `Through`): the nearest
 * lockfile entry above it that the project or a workspace member declares. Null when the
 * parent is itself direct, or none is found within the walk's bound. `adjacent` when that
 * dependency requires the parent directly.
 */
function findThrough(ctx: MoveContext, lockfile: string, parent: string, version: string): { name: string; version: string; adjacent: boolean } | null {
  const read = parentsReader(ctx, lockfile);
  if (!read) return null;
  const start = read(parent, version);
  if (start.length === 0 || start.some((e) => e.local)) return null;
  const queue = start.filter((e) => e.parentVersion !== null).map((e) => ({ name: e.parent, version: e.parentVersion!, adjacent: true }));
  const seen = new Set<string>([`${parent}@${version}`]);
  while (queue.length > 0 && seen.size < MAX_THROUGH_NODES) {
    const node = queue.shift()!;
    const key = `${node.name}@${node.version}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const edges = read(node.name, node.version);
    if (edges.some((e) => e.local)) return node;
    for (const e of edges) if (e.parentVersion !== null) queue.push({ name: e.parent, version: e.parentVersion, adjacent: false });
  }
  return null;
}

/**
 * A direct bump must not stop at a release that still pins a vulnerable transitive a slightly
 * newer release of it clears (audit H1: express 4.20.0, its own advisories' fix, still pins
 * path-to-regexp 0.1.10). When a plan step names this direct dependency as the lever of a
 * parent upgrade, its target is raised to that release, provided it does not cross a major the
 * target does not, and no advisory of the package affects it; otherwise the row says what
 * remains.
 */
export async function reconcileDirectTargets(steps: FixPathStep[], inputs: FixPathInput[], liveIntel: Intel): Promise<void> {
  const sources = liveIntel.getFixPathSources();
  const key = (eco: string, name: string, version: string) => `${eco}\0${name}\0${version}`;
  // Per direct dependency: the highest release a step names for it, and per package the release it needs.
  const needs = new Map<string, { to: string; byPackage: Map<string, string> }>();
  for (const s of steps) {
    for (const u of s.parentUpgrades ?? []) {
      if (!u.lever.to) continue;
      const k = key(s.ecosystem, u.lever.name, u.lever.version);
      const need = needs.get(k) ?? { to: u.lever.to, byPackage: new Map<string, string>() };
      if (compareVersions(u.lever.to, need.to, s.ecosystem) > 0) need.to = u.lever.to;
      const prior = need.byPackage.get(s.package);
      if (!prior || compareVersions(u.lever.to, prior, s.ecosystem) > 0) need.byPackage.set(s.package, u.lever.to);
      needs.set(k, need);
    }
  }
  if (needs.size === 0) return;
  for (const s of steps) {
    if (s.scope !== "direct" || s.action !== "upgrade_direct" || !s.currentVersion || !s.targetVersion) continue;
    const found = needs.get(key(s.ecosystem, s.package, s.currentVersion));
    if (!found || compareVersions(found.to, s.targetVersion, s.ecosystem) <= 0) continue;
    const old = s.targetVersion;
    // Only the packages the current target does not already clear.
    const packages = [...found.byPackage].filter(([, to]) => compareVersions(to, old, s.ecosystem) > 0).map(([p]) => p);
    const need = { to: found.to, packages };
    const which = packages.join(", ");
    const pinned = `${s.package} ${old} still requires a vulnerable ${which}`;
    if (computeSemverDistance(old, need.to)?.label === "major") {
      s.reasons.push(`${pinned}: ${need.to}, a major upgrade from ${old}, is the smallest ${s.package} release that admits a clean ${which} (see ${need.packages.length === 1 ? "its row" : "their rows"})`);
      continue;
    }
    const advisories: AdvisoryRanges[] | null = sources ? await sources.packageAdvisories(s.ecosystem as OsvEcosystem, s.package).catch(() => null) : null;
    const affected = advisories?.filter((a) => advisoryAffects(a, need.to, s.ecosystem)).map((a) => a.id) ?? null;
    if (affected === null || affected.length > 0) {
      s.reasons.push(
        `${pinned}; ${need.to} admits a clean ${which}, but ${affected === null ? "it could not be checked against " + s.package + "'s own advisories" : `${affected.join(", ")} affect${affected.length === 1 ? "s" : ""} it`}`,
      );
      continue;
    }
    const why =
      need.packages.length === 1
        ? `${need.to} is the smallest ${s.package} release whose requirement admits a clean ${which} (see its row)`
        : `${need.to} is the highest of the ${s.package} releases their rows name as admitting a clean version`;
    s.reasons.push(`${need.to}, not ${old}: ${pinned}; ${why}, and no advisory of ${s.package} affects it`);
    setTarget(s, need.to);
    if (s.latestVersion === s.targetVersion) delete s.latestVersion;
    const input = inputs.find((i) => i.step === s);
    if (input) withUpgradeCommands(input, liveIntel);
    else if (s.upgradeCommands) s.upgradeCommands = s.upgradeCommands.map((c) => ({ ...c, command: c.command.replace(`${s.package}@${old}`, `${s.package}@${need.to}`) }));
  }
}

/** How to force one transitive version, per lockfile format. */
export function overrideHint(format: LockfileFormat, name: string, target: string): string {
  switch (format) {
    case "package-lock":
      return `npm: add "overrides": { "${name}": "${target}" } to package.json (npm 8.3+), then npm install`;
    case "pnpm":
      return `pnpm: add "pnpm": { "overrides": { "${name}": "${target}" } } to package.json (or overrides: in pnpm-workspace.yaml), then pnpm install`;
    case "yarn":
    case "yarn-berry":
      return `yarn: add "resolutions": { "${name}": "${target}" } to package.json, then yarn install`;
    case "bun":
      return `bun: add "overrides": { "${name}": "${target}" } to package.json, then bun install`;
    case "cargo":
      return `Cargo cannot select a version outside the parent's requirement; point [patch.crates-io] ${name} at a fork or path that carries the fix`;
  }
}
