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
 * registry, and that is itself clear of the parent's own advisories; then
 * the dependency the project DECLARES that moves it, the parent itself or
 * every declared dependency it arrives through (readiness review
 * 2026-10-17). A parent the walk cannot tie to a declaration names no lever
 * and no command: `npm install <transitive>@v` would add it as a direct
 * dependency. When the new requirement still admits the installed copy, an
 * install keeps that copy (npm 10.9.2, checked 2026-10-17: express 4.21.2 ->
 * 4.22.0 kept path-to-regexp 0.1.12 under `~0.1.12`), so the step names the
 * refresh that follows.
 *
 * Runs on the steps the plan returns, within a time budget, each on a draft
 * of its step: a lookup that runs out of time never writes to the step
 * afterwards. A step whose lookups fail or run out of time keeps its
 * unverified answer and says so in `fixPathChecked`.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import type { LiveIntelligence } from "../live/index.js";
import {
  cleanFixTarget,
  directFix,
  manualRefreshSteps,
  overrideReaches,
  refreshCommandFor,
  refreshVerdict,
  REGISTRY_UNREAD_NOTE,
  withheldText,
  type FixPathSources,
  type FixTargetResult,
  type PackageReleaseFacts,
  type RefreshVerdict,
  type RequirementHistory,
} from "../live/fix-paths.js";
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

/** One dependency the project declares that moves a blocking parent. */
export interface ParentLever {
  name: string;
  version: string;
  /** The release of it that brings the fix in; null when it could not be worked out (the reason says what to check). */
  to: string | null;
  /** True when `to` crosses a major version (a 0.x minor counts). */
  breaking: boolean;
  /** The command that moves it to `to`, per declaring project directory (the declared operator kept). */
  commands?: Array<{ dir: string; command: string }>;
  /** A manifest edit, where no single verified command makes it (a workspace-inherited crate, a requirements pin). */
  instructions?: Array<{ dir: string; instruction: string }>;
}

/**
 * One blocking parent that can move: the release of it that admits a clean
 * version of the package, and the declared dependencies that move it.
 */
export interface ParentUpgrade {
  /** The installed parent whose requirement excludes every clean version. */
  parent: string;
  from: string;
  /** The smallest release of `parent` clear of its own advisories whose requirement admits a clean version; null when its requirements could not be read. */
  to: string | null;
  /** True when `to` crosses a major version of `parent` (mongodb 2.2.36 -> 3.1.3). */
  breaking: boolean;
  /** `to`'s requirement on the package; null when `to` no longer depends on it. Absent when `to` is null. */
  requirement?: string | null;
  /** True when `to` declares the package only as a peer dependency (npm 7+ installs it). */
  peer?: boolean;
  /** The version `to`'s requirement resolves the package to (its newest match), when the registry's version list was read. */
  resolvesTo?: string | null;
  /** When `to` is null: the parent's newest release, which may or may not admit a clean version. */
  latest?: string;
  /**
   * What the project declares and bumps: the parent itself when a manifest declares it, else
   * every declared dependency it arrives through (at most three; `moreLevers` counts the
   * rest). Empty when none could be tied to a declaration: then `leverUnknown` says why and
   * no command is named.
   */
  levers: ParentLever[];
  moreLevers?: number;
  leverUnknown?: string;
  /**
   * The refresh to run after the lever's install: the new requirement still admits the
   * installed copy, which an install keeps (npm 10.9.2), so the install alone does not fix it.
   */
  refreshCommands?: Array<{ dir: string; command: string }>;
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
  /** upgrade_direct: the command that moves the declared dependency to targetVersion, per declaring project directory. */
  upgradeCommands?: Array<{ dir: string; command: string }>;
  /** upgrade_direct: a manifest edit where no single verified command makes it. */
  upgradeInstructions?: Array<{ dir: string; instruction: string }>;
  /** upgrade_parent / override_or_replace: the releases of the blocking parents that admit a clean version. */
  parentUpgrades?: ParentUpgrade[];
  /**
   * Releases the registry withdrew (yanked, deprecated) that the target steps over; with no
   * target, the only releases that fixed it (FX-H5). The reasons say which and why.
   */
  withheld?: string[];
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

type Intel = Pick<LiveIntelligence, "getFixPathSources" | "lockfileFor" | "getProjectRoot" | "getResolvedDeps">;

/** Total time the plan spends verifying fix paths before answering with what it has. */
const FIX_PATH_BUDGET_MS = 25_000;
/** Time the direct targets may spend on their own advisories when one is raised for a transitive. */
const RECONCILE_BUDGET_MS = 5_000;
const CONCURRENCY = 12;
/** Blocking parents whose releases are looked up, per step. */
const MAX_PARENTS = 5;
/** Lockfile entries visited when looking for the declared dependencies a parent arrives through. */
const MAX_THROUGH_NODES = 40;
/** Declared dependencies named per parent ("and N more" past it). */
const MAX_LEVERS = 3;

const TRANSITIVE_REASON = /^Transitive dependency — /;
const NO_FIX_REASON = /^\d+ of them (?:has|have) no published fix$/;

/**
 * For a lever with a named release: whether another release of it also brings the fix in (with
 * the requirement it then has on the package, for a parent that is its own lever), so that one
 * bump can serve both its own row and this one (reconcileDirectTargets). Null when it does not.
 */
const LEVER_ADMITS = new WeakMap<ParentLever, (version: string) => { requirement?: string | null; resolvesTo?: string | null } | null>();

type Outcome = "verified" | "unverified" | "failed";

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
      // On a draft: when the budget runs out first, the lookups still in flight write to the
      // draft, never to the step (readiness review 2026-10-17, finding 9).
      const draft = structuredClone(input.step);
      const outcome: Outcome = remaining > 0 ? await withTimeout(verifyOne({ ...input, step: draft }, sources, liveIntel), remaining, "failed") : "failed";
      if (outcome !== "failed") commit(input.step, draft);
      if (outcome !== "verified") {
        input.step.fixPathChecked = "installed_advisories_only";
        unverified++;
      }
    }
  };
  await Promise.all(Array.from({ length: Math.min(CONCURRENCY, todo.length) }, worker));
  return unverified;
}

/** Make `step` equal to `draft`, keeping the object (the planner keys its inputs by it). */
function commit(step: FixPathStep, draft: FixPathStep): void {
  for (const key of Object.keys(step) as Array<keyof FixPathStep>) if (!(key in draft)) delete step[key];
  Object.assign(step, draft);
}

async function withTimeout<T>(work: Promise<T>, ms: number, late: T): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<T>((resolve) => {
    timer = setTimeout(() => resolve(late), ms);
  });
  try {
    return await Promise.race([work.catch(() => late), timeout]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

/** Every release that fixes the package was withdrawn by its registry: nothing to upgrade to (FX-H5). */
function noInstallableFix(step: FixPathStep): void {
  step.targetVersion = null;
  step.upgradeType = "unknown";
  step.breaking = false;
  step.action = "no_fix_available";
  delete step.upgradeCommands;
  delete step.upgradeInstructions;
}

function setTarget(step: FixPathStep, target: string): void {
  step.targetVersion = target;
  const d = step.currentVersion ? computeSemverDistance(step.currentVersion, target) : null;
  step.upgradeType = !d || d.label === "up-to-date" ? "unknown" : d.label;
  if (step.scope === "direct") step.breaking = step.upgradeType === "major";
}

async function verifyOne(input: FixPathInput, sources: FixPathSources, liveIntel: Intel): Promise<Outcome> {
  const { step } = input;
  const ecosystem = step.ecosystem as OsvEcosystem;
  const clean = await cleanFixTarget(sources, ecosystem, step.package, input.fixes, step.currentVersion);
  if (input.fixes.length === 0) {
    // No advisory names a fix: the answer stays "no fix" unless the registry has a clean release past the bound.
    if (!clean?.noAdvisoryFix || !clean.target) return "verified";
    step.fixPathChecked = "all_advisories";
    step.reasons.push(
      `No advisory names a fixed version (they give only a last affected one); ${clean.target} is the first published release above ${step.currentVersion} that no known advisory affects`,
    );
    const passed = withheldText(clean, ecosystem);
    if (passed) {
      step.withheld = clean.withheld;
      step.reasons.push(passed);
    }
    setTarget(step, clean.target);
    step.breaking = step.scope === "direct" && step.upgradeType === "major";
    step.action = step.scope === "direct" ? "upgrade_direct" : "waiting_on_upstream";
    if (step.scope === "transitive" && step.currentVersion) await refreshOrUpstream(input, sources, liveIntel, clean.target, clean.unfixable);
    withUpgradeCommands(input, liveIntel);
    return "verified";
  }
  if (!clean) return "failed";
  const withheld = withheldText(clean, ecosystem);
  if (clean.withheld.length > 0) step.withheld = clean.withheld;
  if (clean.advisoriesUnread && (clean.target || withheld)) {
    // H5: OSV did not list the advisories, the registry answered. The highest per-advisory fix
    // is withdrawn (lodash 4.18.0, "Bad release"), so it is never the target; the step still
    // counts as checked against the installed version's advisories only.
    step.reasons.push(
      withheld
        ? `${withheld}; the package's other advisories could not be read`
        : `${clean.target} is the smallest installable release at or above ${clean.floor}, the highest per-advisory fix, which ${clean.floorWithdrawn ? "is deprecated or yanked on the registry" : "is not a published release"}; the package's other advisories could not be read`,
    );
    if (clean.target) {
      setTarget(step, clean.target);
      if (step.latestVersion === step.targetVersion) delete step.latestVersion;
    } else {
      noInstallableFix(step);
    }
    withUpgradeCommands(input, liveIntel);
    return "unverified";
  }
  step.fixPathChecked = "all_advisories";
  // FX-H5: the registry could not be read, so the target is the advisory data's alone. Said, never silent.
  if (clean.registryUnread) step.reasons.push(`The ${step.package} registry could not be read: ${REGISTRY_UNREAD_NOTE.replace(/^the registry could not be read, so /, "")}`);

  if (clean.target === null && withheld) {
    // Every release that fixes it was withdrawn: "no installable fix", never "no fix published" (the app's Upgrade Plan).
    step.reasons.push(withheld);
    noInstallableFix(step);
    return "verified";
  }
  if (clean.target === null) {
    step.reasons.push(
      `No published version clears every known advisory: ${clean.floor}, the highest per-advisory fix, is still affected by ${clean.stillAffectedBy.join(", ")}`,
    );
    step.targetVersion = null;
    step.upgradeType = "unknown";
    step.breaking = false;
    step.action = "no_fix_available";
    return "verified";
  }
  if (clean.stillAffectedBy.length > 0) {
    step.reasons.push(
      `${clean.stillAffectedBy.join(", ")} also affect${clean.stillAffectedBy.length === 1 ? "s" : ""} ${clean.target} and every newer release: no published version fixes ${clean.stillAffectedBy.length === 1 ? "it" : "them"}`,
    );
  }
  rewriteNoFixReason(input, clean);
  if (clean.target !== clean.floor) {
    if (clean.floorAffectedBy.length > 0 || !withheld) {
      const why = clean.floorAffectedBy.length > 0
        ? `is itself affected by ${clean.floorAffectedBy.join(", ")}`
        : clean.floorWithdrawn
          ? "is deprecated or yanked on the registry"
          : "is not a published release";
      step.reasons.push(
        `${clean.target} is the smallest ${clean.basis === "registry" ? "published " : ""}version clear of every advisory a release fixes (${clean.floor}, the highest per-advisory fix, ${why})`,
      );
    }
    // The withdrawn releases passed, in the registry's words: "4.18.0 is deprecated on npm (...); 4.18.1 is the smallest clean release".
    if (withheld) step.reasons.push(withheld);
  }
  if (step.targetVersion !== clean.target) setTarget(step, clean.target);
  if (step.latestVersion === step.targetVersion) delete step.latestVersion;

  if (step.scope === "transitive" && step.action === "waiting_on_upstream" && step.currentVersion) {
    await refreshOrUpstream(input, sources, liveIntel, clean.target, clean.unfixable);
  }
  withUpgradeCommands(input, liveIntel);
  return "verified";
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

/**
 * The fix for a declared dependency in each project directory that declares it, read from that
 * project's own manifest (the declared operator kept; nothing named where it cannot be read
 * with certainty: live/fix-paths.ts directFix).
 */
function declaredFixes(
  liveIntel: Pick<LiveIntelligence, "getProjectRoot">,
  ecosystem: string,
  name: string,
  installed: string,
  target: string,
  dirs: string[],
): Pick<ParentLever, "commands" | "instructions"> {
  const root = liveIntel.getProjectRoot() ?? process.cwd();
  const commands: Array<{ dir: string; command: string }> = [];
  const instructions: Array<{ dir: string; instruction: string }> = [];
  for (const dir of [...new Set(dirs)]) {
    const fix = directFix(dir, ecosystem, name, installed, target);
    if (fix && "command" in fix) commands.push({ dir: relativeDir(dir, root), command: fix.command });
    else if (fix) instructions.push({ dir: relativeDir(dir, root), instruction: fix.instruction });
  }
  return { ...(commands.length > 0 ? { commands } : {}), ...(instructions.length > 0 ? { instructions } : {}) };
}

/** upgrade_direct: name the command that moves the declared dependency, per declaring project (audit E8). */
function withUpgradeCommands(input: FixPathInput, liveIntel: Pick<LiveIntelligence, "getProjectRoot">): void {
  const { step } = input;
  if (step.action !== "upgrade_direct" || step.scope !== "direct" || !step.targetVersion || !step.currentVersion) return;
  const fixes = declaredFixes(liveIntel, step.ecosystem, step.package, step.currentVersion, step.targetVersion, input.sourceDirs);
  delete step.upgradeCommands;
  delete step.upgradeInstructions;
  if (fixes.commands) step.upgradeCommands = fixes.commands;
  if (fixes.instructions) step.upgradeInstructions = fixes.instructions;
}

type Blocking = RefreshVerdict["blocking"][number] & { lockfile: string; format: LockfileFormat };

async function refreshOrUpstream(input: FixPathInput, sources: FixPathSources, liveIntel: Intel, target: string, unfixable: string[]): Promise<void> {
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
  const ctx: MoveContext = {
    sources,
    intel: liveIntel,
    ecosystem,
    pkg: step.package,
    installed,
    target,
    clean,
    releases,
    readers: new Map(),
    advisories: new Map(),
  };
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
  intel: Intel;
  ecosystem: OsvEcosystem;
  pkg: string;
  /** The vulnerable copy's version. */
  installed: string;
  target: string;
  /** Not affected by any advisory a release fixes. */
  clean: (version: string) => boolean;
  /** The package's installable, non-prerelease versions; [] when unknown. */
  releases: string[];
  /** One parsed lockfile per path, for the walk up to the declared dependencies. */
  readers: Map<string, ((name: string, version: string) => ParentEdge[]) | null>;
  /** A parent's or lever's own advisories, looked up once per step. */
  advisories: Map<string, Promise<AdvisoryRanges[] | null>>;
}

type Standing = { kind: "stuck"; text: string } | { kind: "move"; upgrade: ParentUpgrade; text: string } | { kind: "unknown" };

/** The declared dependencies a parent arrives through, or why none can be named. */
type Route =
  | { kind: "direct"; dirs: string[] }
  | { kind: "through"; levers: Array<{ name: string; version: string; adjacent: boolean; dirs: string[] }>; more: number }
  | { kind: "unknown"; why: string };

/** A release is clear of a package's own advisories (one that also affects the newest release has no fix and does not count). */
async function ownClean(ctx: MoveContext, name: string, facts: PackageReleaseFacts): Promise<{ clean: (v: string) => boolean; read: boolean; any: boolean }> {
  let pending = ctx.advisories.get(name);
  if (!pending) {
    pending = ctx.sources.packageAdvisories(ctx.ecosystem, name).catch(() => null);
    ctx.advisories.set(name, pending);
  }
  const advisories = await pending;
  if (!advisories) return { clean: () => true, read: false, any: false };
  const newest = newestOf(facts.versions, ctx.ecosystem);
  const fixable = advisories.filter((a) => !newest || !advisoryAffects(a, newest, ctx.ecosystem));
  return { clean: (v) => !fixable.some((a) => advisoryAffects(a, v, ctx.ecosystem)), read: true, any: fixable.length > 0 };
}

/** The project directories whose manifests declare `name` at `version` (the resolution's direct rows). */
function declaredDirs(intel: Intel, ecosystem: string, name: string, version: string): string[] {
  return [
    ...new Set(
      intel
        .getResolvedDeps()
        .filter((d) => d.isDirect && d.ecosystem === ecosystem && d.name === name && d.version === version)
        .flatMap((d) => d.sourceDirs ?? []),
    ),
  ];
}

function isMajor(from: string, to: string): boolean {
  return computeSemverDistance(from, to)?.label === "major";
}

function commandText(lever: ParentLever): string {
  const cmds = lever.commands ?? [];
  if (cmds.length === 0) return "";
  return ` (${cmds.map((c) => `\`${c.command}\`${cmds.length > 1 ? ` in ${c.dir}` : ""}`).join("; ")})`;
}

/** The refresh that moves `name` from `installed` inside the ranges, in the lockfile's directory. */
function refreshFor(ctx: MoveContext, b: Blocking, name: string, installed: string, target: string): { dir: string; command: string } {
  const root = ctx.intel.getProjectRoot() ?? process.cwd();
  const dir = relativeDir(path.dirname(b.lockfile), root);
  const command =
    refreshCommandFor(b.lockfile, name, installed, target) ?? manualRefreshSteps(b.format === "bun" ? "bun" : "yarn", name);
  return { dir, command };
}

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
  const route = findRoute(ctx, b.lockfile, parent, from);
  const [history, own] = await Promise.all([sources.requirementHistory(ecosystem, parent, pkg).catch(() => null), ownClean(ctx, parent, facts)]);
  const newest = facts.latest ?? newestOf(facts.versions, ecosystem);

  if (!history) {
    // The app's ParentStanding::Newer: a newer release exists, whether it admits the fix is open.
    const upgrade: ParentUpgrade = { parent, from, to: null, breaking: false, ...(newest ? { latest: newest } : {}), levers: [] };
    let advice: string;
    if (route.kind === "direct") {
      upgrade.levers = [{ name: parent, version: from, to: null, breaking: false }];
      advice = `upgrade ${parent} (${newest ? `${parent} ${newest} is its newest release; ` : ""}check that it admits ${pkg} >= ${target})`;
    } else if (route.kind === "through") {
      upgrade.levers = route.levers.map((l) => ({ name: l.name, version: l.version, to: null, breaking: false }));
      if (route.more > 0) upgrade.moreLevers = route.more;
      advice = `${parent} arrives through ${leverList(route)}: upgrade ${route.levers.length + route.more === 1 ? "it" : "each"} to a release that brings in a ${parent} that admits ${pkg} >= ${target}, and check that it does`;
    } else {
      upgrade.leverUnknown = route.why;
      advice = `which of this project's dependencies brings ${parent} ${from} in could not be worked out (${route.why}); bump the one that does to a release that brings in a ${parent} that admits ${pkg} >= ${target}`;
    }
    return { kind: "move", upgrade, text: `${head}; ${parent}'s release requirements could not be read: ${advice}` };
  }

  const found = smallestAdmitting(ctx, facts, from, history, dialect, own.clean);
  if (!found) {
    const clause = own.any ? ` both admits a clean ${pkg} (>= ${target}) and is clear of ${parent}'s own advisories` : ` admits a clean ${pkg} (>= ${target})`;
    return { kind: "stuck", text: `no ${parent} release up to ${newest ?? "its latest"}${clause}` };
  }
  const requirementClause =
    found.requirement === null
      ? `${parent} ${found.version} is the smallest ${parent} release that no longer depends on ${pkg}`
      : `${parent} ${found.version} is the smallest ${parent} release whose ${found.peer ? "peer " : ""}requirement "${found.requirement}" admits ${pkg} ${target}${found.peer ? " (npm 7+ installs a missing peer)" : ""}${found.resolvesTo ? ` (a fresh resolve picks ${found.resolvesTo})` : ""}`;
  const ownClause = !own.read ? `; not checked against ${parent}'s own advisories (OSV.dev did not answer)` : own.any ? `, and no advisory of ${parent} affects it` : "";
  const upgrade: ParentUpgrade = {
    parent,
    from,
    to: found.version,
    breaking: isMajor(from, found.version),
    requirement: found.requirement,
    ...(found.peer ? { peer: true } : {}),
    resolvesTo: found.resolvesTo,
    levers: [],
  };
  // An install keeps a copy the new requirement still admits (npm 10.9.2): the refresh follows.
  const refreshes: Array<{ dir: string; command: string }> = [];
  const others = (parentsReader(ctx, b.lockfile)?.(pkg, ctx.installed) ?? []).some((e) => !(e.parent === parent && e.parentVersion === from));
  if (found.keepsInstalled || (found.requirement === null && others)) refreshes.push(refreshFor(ctx, b, pkg, ctx.installed, target));
  const keepsText = (r: Array<{ command: string }>) =>
    r.length === 0
      ? ""
      : `; ${found.requirement === null ? `another parent still holds ${pkg} ${ctx.installed}` : `${pkg} ${ctx.installed} still satisfies "${found.requirement}"`}, and an install keeps a copy that satisfies it, so then run ${r.map((c) => `\`${c.command}\``).join(", then ")}`;
  const admitsAt = (v: string) => {
    const entry = history[v];
    const ok = entry !== undefined && own.clean(v) ? admitsClean(ctx, entry.reqs, dialect) : null;
    return ok ? { requirement: entry!.reqs[0] ?? null, resolvesTo: ok.resolvesTo } : null;
  };

  if (route.kind === "direct") {
    const lever: ParentLever = {
      name: parent,
      version: from,
      to: found.version,
      breaking: upgrade.breaking,
      ...declaredFixes(ctx.intel, ecosystem, parent, from, found.version, route.dirs),
    };
    LEVER_ADMITS.set(lever, admitsAt);
    upgrade.levers = [lever];
    if (refreshes.length > 0) upgrade.refreshCommands = refreshes;
    return {
      kind: "move",
      upgrade,
      text: `${head}; ${requirementClause}${ownClause}: upgrade ${parent} to ${found.version}${upgrade.breaking ? " (a major upgrade)" : ""}${commandText(lever)}${keepsText(refreshes)}`,
    };
  }
  if (route.kind === "unknown") {
    upgrade.leverUnknown = route.why;
    if (refreshes.length > 0) upgrade.refreshCommands = refreshes;
    return {
      kind: "move",
      upgrade,
      text: `${head}; ${requirementClause}${ownClause}. Which of this project's dependencies brings ${parent} ${from} in could not be worked out (${route.why}), so no command is named: bump the one that does to a release that brings in ${parent} >= ${found.version}${keepsText(refreshes)}`,
    };
  }

  // The parent is transitive: each declared dependency it arrives through must bring in a fixed release.
  const leverTexts: string[] = [];
  for (const l of route.levers) {
    const hop = l.adjacent ? await throughRelease(ctx, l, parent, from, facts, history, dialect, own.clean) : null;
    if (hop?.kind === "stuck") {
      return { kind: "stuck", text: `${parent} arrives through ${l.name} ${l.version}, and ${hop.text}` };
    }
    if (hop?.kind === "found") {
      const lever: ParentLever = {
        name: l.name,
        version: l.version,
        to: hop.version,
        breaking: isMajor(l.version, hop.version),
        ...declaredFixes(ctx.intel, ecosystem, l.name, l.version, hop.version, l.dirs),
      };
      LEVER_ADMITS.set(lever, hop.admitsAt);
      upgrade.levers.push(lever);
      if (hop.keepsParent) {
        const r = refreshFor(ctx, b, parent, from, hop.brings);
        if (!refreshes.some((x) => x.command === r.command)) refreshes.unshift(r);
      }
      leverTexts.push(
        `${l.name} ${hop.version} is the smallest ${l.name} release that brings in ${parent} ${hop.brings}${hop.brings === found.version ? "" : ` (>= ${found.version})`}${hop.keepsParent ? ` (its requirement still admits ${parent} ${from}, which an install keeps)` : ""}: upgrade ${l.name} to ${hop.version}${lever.breaking ? " (a major upgrade)" : ""}${commandText(lever)}`,
      );
    } else {
      const latest = (await sources.releaseFacts(ecosystem, l.name).catch(() => null))?.latest ?? null;
      upgrade.levers.push({ name: l.name, version: l.version, to: null, breaking: false });
      leverTexts.push(
        `upgrade ${l.name} to a release that brings in ${parent} >= ${found.version} (${latest ? `${l.name} ${latest} is its newest release; ` : ""}check that it does)`,
      );
    }
  }
  if (route.more > 0) upgrade.moreLevers = route.more;
  if (refreshes.length > 0) upgrade.refreshCommands = refreshes;
  const many = route.levers.length + route.more > 1;
  const tail = route.more > 0 ? `; and ${route.more} more declared ${route.more === 1 ? "dependency brings" : "dependencies bring"} it in, each of which must move the same way` : "";
  return {
    kind: "move",
    upgrade,
    text: `${head}; ${requirementClause}${ownClause}. ${parent} arrives through ${leverList(route)}${many ? ", each of which must move" : ""}: ${leverTexts.join("; ")}${tail}${keepsText(refreshes)}`,
  };
}

function leverList(route: Extract<Route, { kind: "through" }>): string {
  const names = route.levers.map((l) => `${l.name} ${l.version}`);
  const total = route.levers.length + route.more;
  const list = names.length <= 1 ? names.join("") : `${names.slice(0, -1).join(", ")} and ${names[names.length - 1]}`;
  return `${list}${route.more > 0 ? ` (and ${route.more} more)` : ""}, ${total === 1 ? "a direct dependency" : "direct dependencies"}`;
}

function newestOf(versions: string[], ecosystem: string): string | null {
  return versions.filter((v) => !isPrereleaseVersion(v, ecosystem)).sort((a, b) => compareVersions(a, b, ecosystem)).pop() ?? null;
}

/**
 * Whether a parent release's requirements on the package admit a clean version: every
 * requirement's newest match (what a fresh resolution picks) is at or above the target and
 * clean. Without the package's version list, the requirement must admit the target itself.
 * `keepsInstalled` when a requirement still admits the installed copy: an install then keeps
 * it (npm 10.9.2), and only a refresh reaches the clean one.
 */
function admitsClean(ctx: MoveContext, reqs: string[], dialect: RequirementDialect): { resolvesTo: string | null; keepsInstalled: boolean } | null {
  if (reqs.length === 0) return { resolvesTo: null, keepsInstalled: false };
  let resolvesTo: string | null = null;
  let keepsInstalled = false;
  for (const text of reqs) {
    const req = { parent: "", text, dialect };
    if (ctx.releases.length > 0) {
      const newest = ctx.releases.filter((v) => requirementAdmits(req, v) === true).sort((a, b) => compareVersions(b, a, ctx.ecosystem))[0];
      if (!newest || compareVersions(newest, ctx.target, ctx.ecosystem) < 0 || !ctx.clean(newest)) return null;
      if (resolvesTo === null || compareVersions(newest, resolvesTo, ctx.ecosystem) < 0) resolvesTo = newest;
    } else if (requirementAdmits(req, ctx.target) !== true) {
      return null;
    }
    if (requirementAdmits(req, ctx.installed) === true) keepsInstalled = true;
  }
  return { resolvesTo, keepsInstalled };
}

/** The smallest installable release of a parent above `from`, clear of its own advisories, whose requirement admits a clean version. */
function smallestAdmitting(
  ctx: MoveContext,
  facts: PackageReleaseFacts,
  from: string,
  history: RequirementHistory,
  dialect: RequirementDialect,
  ownClean: (version: string) => boolean,
): { version: string; requirement: string | null; peer: boolean; resolvesTo: string | null; keepsInstalled: boolean } | null {
  const candidates = facts.versions
    .filter((v) => !isPrereleaseVersion(v, ctx.ecosystem) && compareVersions(v, from, ctx.ecosystem) > 0)
    .sort((a, b) => compareVersions(a, b, ctx.ecosystem));
  for (const version of candidates) {
    const entry = history[version];
    if (entry === undefined || !ownClean(version)) continue;
    const ok = admitsClean(ctx, entry.reqs, dialect);
    if (ok) return { version, requirement: entry.reqs[0] ?? null, peer: entry.peer, ...ok };
  }
  return null;
}

type ThroughHop =
  | { kind: "found"; version: string; brings: string; keepsParent: boolean; admitsAt: (version: string) => object | null }
  | { kind: "stuck"; text: string };

/**
 * The smallest release of the declared dependency `lever`, clear of its own advisories, that
 * brings in a `parent` release clear of the parent's advisories whose requirement admits a
 * clean package: the lever's requirement on `parent` resolves (newest match) to it. `keepsParent`
 * when that requirement still admits the installed parent (an install keeps it; a refresh of
 * the parent follows). Stuck when every release was read and none does; null when not readable.
 */
async function throughRelease(
  ctx: MoveContext,
  lever: { name: string; version: string },
  parent: string,
  parentFrom: string,
  parentFacts: PackageReleaseFacts,
  parentHistory: RequirementHistory,
  dialect: RequirementDialect,
  parentClean: (version: string) => boolean,
): Promise<ThroughHop | null> {
  const [facts, history] = await Promise.all([
    ctx.sources.releaseFacts(ctx.ecosystem, lever.name).catch(() => null),
    ctx.sources.requirementHistory(ctx.ecosystem, lever.name, parent).catch(() => null),
  ]);
  if (!facts || !history) return null;
  if (facts.deprecatedLatest) return { kind: "stuck", text: `${lever.name} is deprecated ("${facts.deprecatedLatest.slice(0, 120)}")` };
  if (facts.latest && compareVersions(lever.version, facts.latest, ctx.ecosystem) >= 0) {
    return { kind: "stuck", text: `${lever.name} ${lever.version} is already its latest release` };
  }
  const own = await ownClean(ctx, lever.name, facts);
  const parentReleases = parentFacts.versions.filter((v) => !isPrereleaseVersion(v, ctx.ecosystem));
  const brought = (v: string): { brings: string; keepsParent: boolean } | null => {
    const entry = history[v];
    if (!entry || entry.reqs.length !== 1 || !own.clean(v)) return null;
    const req = { parent: lever.name, text: entry.reqs[0], dialect };
    const brings = parentReleases.filter((p) => requirementAdmits(req, p) === true).sort((a, b) => compareVersions(b, a, ctx.ecosystem))[0];
    if (!brings || compareVersions(brings, parentFrom, ctx.ecosystem) <= 0 || !parentClean(brings)) return null;
    const pkgReqs = parentHistory[brings];
    if (pkgReqs === undefined || admitsClean(ctx, pkgReqs.reqs, dialect) === null) return null;
    return { brings, keepsParent: requirementAdmits(req, parentFrom) === true };
  };
  const candidates = facts.versions
    .filter((v) => !isPrereleaseVersion(v, ctx.ecosystem) && compareVersions(v, lever.version, ctx.ecosystem) > 0)
    .sort((a, b) => compareVersions(a, b, ctx.ecosystem));
  for (const version of candidates) {
    const hit = brought(version);
    if (hit) return { kind: "found", version, ...hit, admitsAt: (v) => (brought(v) ? {} : null) };
  }
  const newest = facts.latest ?? newestOf(facts.versions, ctx.ecosystem);
  return { kind: "stuck", text: `no ${lever.name} release up to ${newest ?? "its latest"} brings in a ${parent} that admits a clean ${ctx.pkg}` };
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
 * The declared dependencies a parent moves through (the app's `Through`). `direct` only when the
 * lockfile has the project or a workspace member requiring it AND a manifest the plan read
 * declares it; `through` with EVERY declared dependency above it (walked to the first declared
 * one on each path), when the walk finishes within its bound; otherwise `unknown`, with why.
 * Treating "not found" as "direct" named `npm install <transitive>@v`, which adds a transitive
 * as a direct dependency (readiness review 2026-10-17, finding 1).
 */
function findRoute(ctx: MoveContext, lockfile: string, parent: string, version: string): Route {
  const read = parentsReader(ctx, lockfile);
  if (!read) return { kind: "unknown", why: "the lockfile could not be read" };
  const start = read(parent, version);
  if (start.some((e) => e.local)) {
    const dirs = declaredDirs(ctx.intel, ctx.ecosystem, parent, version);
    return dirs.length > 0 ? { kind: "direct", dirs } : { kind: "unknown", why: `no manifest this plan read declares ${parent} ${version}` };
  }
  if (start.length === 0) return { kind: "unknown", why: `the lockfile names no parent of ${parent} ${version}` };
  const found = new Map<string, { name: string; version: string; adjacent: boolean; dirs: string[] }>();
  const undeclared: string[] = [];
  const queue = start.filter((e) => e.parentVersion !== null).map((e) => ({ name: e.parent, version: e.parentVersion!, adjacent: true }));
  const seen = new Set<string>([`${parent}@${version}`]);
  while (queue.length > 0) {
    if (seen.size >= MAX_THROUGH_NODES) {
      return { kind: "unknown", why: `the walk up the lockfile stopped after ${MAX_THROUGH_NODES} entries before it reached every declared dependency above ${parent}` };
    }
    const node = queue.shift()!;
    const key = `${node.name}@${node.version}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const edges = read(node.name, node.version);
    if (edges.some((e) => e.local)) {
      const dirs = declaredDirs(ctx.intel, ctx.ecosystem, node.name, node.version);
      if (dirs.length > 0) {
        if (!found.has(key)) found.set(key, { ...node, dirs });
        continue;
      }
      undeclared.push(key);
    }
    if (edges.length === 0) undeclared.push(key);
    for (const e of edges) if (!e.local && e.parentVersion !== null) queue.push({ name: e.parent, version: e.parentVersion, adjacent: false });
  }
  if (undeclared.length > 0 || found.size === 0) {
    return { kind: "unknown", why: found.size === 0 ? `no declared dependency above ${parent} in the lockfile` : `${undeclared[0]} leads to no declared dependency` };
  }
  const levers = [...found.values()];
  return { kind: "through", levers: levers.slice(0, MAX_LEVERS), more: Math.max(0, levers.length - MAX_LEVERS) };
}

/**
 * One dependency, one command (readiness review 2026-10-17, finding 2): a direct row and the
 * parent upgrades that name it as their lever agree on its release.
 *
 * - A direct bump must not stop at a release that still pins a vulnerable transitive a slightly
 *   newer release of it clears (audit H1: express 4.20.0, its own advisories' fix, still pins
 *   path-to-regexp 0.1.10). Its target is raised to the highest release a lever names for it,
 *   provided that does not cross a major the target does not, and no advisory of the package
 *   affects it; otherwise the row says what remains.
 * - A lever below its own row's (vulnerability-driven) target is raised to that target when the
 *   target still brings the fix in, so the two rows name the same command.
 *
 * The advisory lookups are bounded (RECONCILE_BUDGET_MS); a row that could not be checked in
 * time is left as it is, and nothing is written after the budget runs out.
 */
export async function reconcileDirectTargets(steps: FixPathStep[], inputs: FixPathInput[], liveIntel: Intel, budgetMs = RECONCILE_BUDGET_MS): Promise<void> {
  const sources = liveIntel.getFixPathSources();
  const key = (eco: string, name: string, version: string) => `${eco}\0${name}\0${version}`;
  // Per declared dependency: the highest release a lever names for it, and per package the release it needs.
  const needs = new Map<string, { to: string; byPackage: Map<string, string> }>();
  const leversOf = new Map<string, Array<{ step: FixPathStep; lever: ParentLever; upgrade: ParentUpgrade }>>();
  for (const s of steps) {
    for (const u of s.parentUpgrades ?? []) {
      for (const lever of u.levers) {
        if (!lever.to) continue;
        const k = key(s.ecosystem, lever.name, lever.version);
        leversOf.set(k, [...(leversOf.get(k) ?? []), { step: s, lever, upgrade: u }]);
        const need = needs.get(k) ?? { to: lever.to, byPackage: new Map<string, string>() };
        if (compareVersions(lever.to, need.to, s.ecosystem) > 0) need.to = lever.to;
        const prior = need.byPackage.get(s.package);
        if (!prior || compareVersions(lever.to, prior, s.ecosystem) > 0) need.byPackage.set(s.package, lever.to);
        needs.set(k, need);
      }
    }
  }
  if (needs.size === 0) return;
  const rows = steps.filter(
    (s) => s.scope === "direct" && s.action === "upgrade_direct" && s.currentVersion && s.targetVersion && needs.has(key(s.ecosystem, s.package, s.currentVersion)),
  );
  // Look up, bounded, then write: nothing is written once the budget has run out.
  const toRaise = rows.filter((s) => compareVersions(needs.get(key(s.ecosystem, s.package, s.currentVersion!))!.to, s.targetVersion!, s.ecosystem) > 0);
  const looked = await withTimeout(
    Promise.all(
      toRaise.map(async (s) => [s, sources ? await sources.packageAdvisories(s.ecosystem as OsvEcosystem, s.package).catch(() => null) : null] as const),
    ),
    budgetMs,
    null,
  );
  const advisoriesOf = new Map<FixPathStep, AdvisoryRanges[] | null>(looked ?? []);

  for (const s of toRaise) {
    const found = needs.get(key(s.ecosystem, s.package, s.currentVersion!))!;
    const old = s.targetVersion!;
    // Only the packages the current target does not already clear.
    const packages = [...found.byPackage].filter(([, to]) => compareVersions(to, old, s.ecosystem) > 0).map(([p]) => p);
    const which = packages.join(", ");
    const pinned = `${s.package} ${old} still requires a vulnerable ${which}`;
    if (isMajor(old, found.to)) {
      s.reasons.push(`${pinned}: ${found.to}, a major upgrade from ${old}, is the smallest ${s.package} release that admits a clean ${which} (see ${packages.length === 1 ? "its row" : "their rows"})`);
      continue;
    }
    if (!advisoriesOf.has(s)) {
      s.reasons.push(`${pinned}; ${found.to} admits a clean ${which}, but it could not be checked against ${s.package}'s own advisories in time`);
      continue;
    }
    const advisories = advisoriesOf.get(s)!;
    const affected = advisories?.filter((a) => advisoryAffects(a, found.to, s.ecosystem)).map((a) => a.id) ?? null;
    if (affected === null || affected.length > 0) {
      s.reasons.push(
        `${pinned}; ${found.to} admits a clean ${which}, but ${affected === null ? `it could not be checked against ${s.package}'s own advisories` : `${affected.join(", ")} affect${affected.length === 1 ? "s" : ""} it`}`,
      );
      continue;
    }
    const why =
      packages.length === 1
        ? `${found.to} is the smallest ${s.package} release whose requirement admits a clean ${which} (see its row)`
        : `${found.to} is the highest of the ${s.package} releases their rows name as admitting a clean version`;
    s.reasons.push(`${found.to}, not ${old}: ${pinned}; ${why}, and no advisory of ${s.package} affects it`);
    setTarget(s, found.to);
    if (s.latestVersion === s.targetVersion) delete s.latestVersion;
    const input = inputs.find((i) => i.step === s);
    if (input) withUpgradeCommands(input, liveIntel);
  }

  // A lever below its own row's target moves to that target when it still brings the fix in.
  for (const s of rows) {
    if (!inputs.some((i) => i.step === s)) continue; // a freshness row's target is the newest release, not a fix
    const target = s.targetVersion!;
    for (const { step, lever, upgrade } of leversOf.get(key(s.ecosystem, s.package, s.currentVersion!)) ?? []) {
      if (compareVersions(lever.to!, target, s.ecosystem) >= 0) continue;
      const at = isMajor(lever.to!, target) ? null : (LEVER_ADMITS.get(lever)?.(target) ?? null);
      if (!at) continue;
      const before = lever.to!;
      const oldCommands = commandText(lever);
      lever.to = target;
      lever.breaking = isMajor(lever.version, target);
      delete lever.commands;
      delete lever.instructions;
      Object.assign(lever, declaredFixes(liveIntel, s.ecosystem, lever.name, lever.version, target, declaredDirs(liveIntel, s.ecosystem, lever.name, lever.version)));
      // The step's own sentence names the lifted release too, never the one it replaced.
      const moved = `upgrade ${lever.name} to ${target}${lever.breaking ? " (a major upgrade)" : ""}${commandText(lever)}`;
      step.reasons = step.reasons.map((r) => r.split(`upgrade ${lever.name} to ${before}${isMajor(lever.version, before) ? " (a major upgrade)" : ""}${oldCommands}`).join(moved));
      if (upgrade.parent === lever.name && upgrade.from === lever.version) {
        upgrade.to = target;
        upgrade.breaking = lever.breaking;
        if (at.requirement !== undefined) upgrade.requirement = at.requirement;
        if (at.resolvesTo !== undefined) upgrade.resolvesTo = at.resolvesTo;
      }
      step.reasons.push(
        `${lever.name} ${target}, not ${before}: ${lever.name}'s own row targets ${target}, and ${target} also brings the fix in, so one bump serves both rows${commandText(lever)}`,
      );
    }
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
