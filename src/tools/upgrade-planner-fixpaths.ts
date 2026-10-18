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
  introducesText,
  malwareText,
  unreadableText,
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
import { advisoriesAffecting, advisoryAffects, cleanReleases, isPrereleaseVersion, remainsText, type AdvisoryRanges } from "../live/osv-ranges.js";
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
  commands?: Array<{ dir: string; command: string; refresh?: true }>;
  /** A manifest edit, where no single verified command makes it (a workspace-inherited crate, a requirements pin). */
  instructions?: Array<{ dir: string; instruction: string }>;
  /** Set only when `to` was lifted above it (one release per dependency): the lever's OWN smallest release that brings the fix in. */
  smallest?: string;
  /** Through a transitive parent: the parent's smallest release that admits a clean copy, which the lever must bring in at least. */
  floor?: string;
  /** Through a transitive parent: the parent release `to` brings in. */
  brings?: string;
}

/**
 * One blocking parent that can move: the release of it that admits a clean
 * version of the package, and the declared dependencies that move it.
 */
export interface ParentUpgrade {
  /** The installed parent whose requirement excludes every clean version. */
  parent: string;
  from: string;
  /** The smallest release of `parent` clear of its own advisories whose requirement admits a clean version (raised to the one release its lever names); null when its requirements could not be read, or when it leaves the tree (`goesAway`). */
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
  /** Set only when `to` was lifted above it (one release per dependency): the parent's own smallest release that admits a clean copy. */
  smallest?: string;
  /**
   * The parent will not move (no release admits a clean version, or it is already its newest), but
   * every declared dependency it arrives through has a release that no longer brings it in: the
   * levers name those releases, and the vulnerable copy goes away from that path with them (`to`
   * is then null, as the parent leaves the tree).
   */
  goesAway?: boolean;
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
  upgradeCommands?: Array<{ dir: string; command: string; refresh?: true }>;
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
  const standings = STANDINGS.get(draft);
  if (standings) STANDINGS.set(step, standings);
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
  // #981 round 3: an installed copy flagged malicious names no release at all: remove or replace it.
  const own = step.currentVersion ? await sources.packageAdvisories(ecosystem, step.package).catch(() => null) : null;
  const malicious = own ? cleanReleases(own, ecosystem, []).maliciousAt(step.currentVersion!) : [];
  if (malicious.length > 0) {
    step.reasons.push(malwareText(step.package, malicious));
    noInstallableFix(step);
    step.action = "remove_dependency";
    step.fixPathChecked = "all_advisories";
    return "verified";
  }
  const clean = await cleanFixTarget(sources, ecosystem, step.package, input.fixes, step.currentVersion);
  if (input.fixes.length === 0) {
    // No advisory names a fix: the answer stays "no fix" unless the registry has a clean release past the bound.
    if (!clean?.noAdvisoryFix || !clean.target) {
      // #981 (a)/(b): malware is never "no fix yet" but remove-or-replace; unreadable ranges are said.
      const all = (await sources.packageAdvisories(ecosystem, step.package).catch(() => null)) ?? [];
      const view = cleanReleases(all, ecosystem, (await sources.publishedVersions(ecosystem, step.package).catch(() => null)) ?? []);
      if (view.unreadable.length > 0) {
        step.reasons.push(`No release is named: ${unreadableText(view.unreadable)}`);
      }
      return "verified";
    }
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
      clean.registryUnread
        ? `${clean.target} is the highest per-advisory fix; neither the package's other advisories nor its registry could be read: ${REGISTRY_UNREAD_NOTE}`
        : withheld
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
  if (clean.target === null && clean.introduces && clean.introduces.length > 0) {
    // Never introduce an advisory: no release, no command, and why.
    step.reasons.push(`No release is named: ${introducesText(clean.introduces)}`);
    noInstallableFix(step);
    return "verified";
  }
  if (clean.target === null && clean.unreadable && clean.unreadable.length > 0) {
    // #981 (b): unknown, never skipped silently: no release, no command.
    step.reasons.push(`No release is named: ${unreadableText(clean.unreadable)}`);
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
      `${clean.target} ${remainsText(clean.stillAffectedBy)}; ${clean.stillAffectedBy.join(", ")} also affect${clean.stillAffectedBy.length === 1 ? "s" : ""} ${clean.target} and every newer release: no published version fixes ${clean.stillAffectedBy.length === 1 ? "it" : "them"}`,
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
  // A deprecation notice on the target's whole line: still the target, and said (audit 7f).
  if (clean.targetNotice) step.reasons.push(clean.targetNotice);

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
  const commands: Array<{ dir: string; command: string; refresh?: true }> = [];
  const instructions: Array<{ dir: string; instruction: string }> = [];
  for (const dir of [...new Set(dirs)]) {
    const fix = directFix(dir, ecosystem, name, installed, target);
    if (fix && "command" in fix) commands.push({ dir: relativeDir(dir, root), command: fix.command, ...(fix.refresh ? { refresh: true as const } : {}) });
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
  // Every fix on the row an in-range refresh: said in the app's words, not as a bump.
  step.reasons = step.reasons.filter((r) => !r.startsWith(REFRESH_ROW) && !r.endsWith(REFRESH_LABEL));
  const cmds = fixes.commands ?? [];
  const list = (cs: typeof cmds) => cs.map((c) => `\`${c.command}\`${cmds.length > 1 ? ` in ${c.dir}` : ""}`).join("; ");
  if (cmds.length > 0 && cmds.every((c) => c.refresh) && !fixes.instructions) step.reasons.push(`${REFRESH_ROW}: ${list(cmds)}`);
  else if (cmds.some((c) => c.refresh)) step.reasons.push(`${list(cmds.filter((c) => c.refresh))}${REFRESH_LABEL}`);
}

/** A row whose every fix is an in-range refresh (the app's wording). */
const REFRESH_ROW = "Fixable now with a lockfile refresh (the declared range already admits the fix)";

type Blocking = RefreshVerdict["blocking"][number] & { lockfile: string; format: LockfileFormat };

async function refreshOrUpstream(input: FixPathInput, sources: FixPathSources, liveIntel: Intel, target: string, unfixable: string[]): Promise<void> {
  const { step } = input;
  const ecosystem = step.ecosystem as OsvEcosystem;
  const installed = step.currentVersion!;
  const lockfiles = [...new Set(input.sourceDirs)]
    .map((dir) => ({ dir, lockfile: liveIntel.lockfileFor(dir, ecosystem) }))
    .filter((l): l is { dir: string; lockfile: string } => l.lockfile !== null);
  if (lockfiles.length === 0) return;
  if (memberUpgrade(input, lockfiles, liveIntel, target)) return;

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
  STANDINGS.set(step, considered.map((b, i) => ({ parent: b.parent, from: b.parentVersion!, standing: standings[i] })));
  const malicious = standings.filter((s): s is Extract<Standing, { kind: "malicious" }> => s.kind === "malicious");
  if (malicious.length > 0) {
    // #981 round 3: a parent or lever flagged malicious: no release is named, no command given.
    step.action = "override_or_replace";
    step.targetVersion = null;
    step.upgradeType = "unknown";
    delete step.refreshCommands;
    replaceReason(`Transitive dependency: ${named}${more}; ${malicious.map((m) => m.text).join("; ")}`);
    return;
  }
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
    // Fixed by upgrading the parent only when every move names the release of what the project
    // declares; a lever with no release (to: null) is a check, not a fix (final audit 7c: victauri
    // rand through tauri, NodeGoat braces and nconf through forever).
    const verified = moves.every((m) => m.upgrade.levers.length > 0 && m.upgrade.levers.every((l) => l.to !== null));
    step.action = verified ? "upgrade_parent" : "upgrade_parent_unverified";
    replaceReason(
      verified
        ? `Transitive dependency: ${moves.map((m) => m.text).join("; ")}`
        : `Transitive dependency, not verified: ${moves.map((m) => m.text).join("; ")}. No release of what this project declares was verified to bring the fixed parent in, so this is not counted as fixed: check the releases named above before upgrading`,
    );
    return;
  }
  const unknownWhy = standings.flatMap((s) => (s.kind === "unknown" && s.text ? [s.text] : []));
  const known = `${unknownWhy.length > 0 ? `; ${unknownWhy.join("; ")}` : ""}${moves.length > 0 ? `; meanwhile ${moves.map((m) => m.text).join("; ")}` : ""}`;
  replaceReason(
    `Transitive dependency, waiting on upstream: ${named}${more}, so a refresh cannot reach a clean version, and the releases of ${standings.length < blocking.length ? "some parents were not checked" : "a parent could not be read"}${known}`,
  );
}

/**
 * A copy a workspace member's own manifest declares (packages/a devDependencies minimist ^1.2.5)
 * is a declared dependency of that member, not a transitive "not declared in your manifest", and
 * it moves where it is declared: npm 10.9.2 left minimist 1.2.5 in place for `npm update minimist`
 * run at the root and in the member, and moved it with `npm install "minimist@^1.2.6"` run in the
 * member's directory, keeping it in devDependencies (checked 2026-10-18; final release audit,
 * finding 3). Taken only when every other parent's requirement already admits the target, so the
 * member's bump is the whole step. True when the step was rewritten.
 */
function memberUpgrade(input: FixPathInput, lockfiles: Array<{ dir: string; lockfile: string }>, liveIntel: Intel, target: string): boolean {
  const { step } = input;
  const members: Array<{ dir: string; rel: string; section: string; range: string | null }> = [];
  for (const { lockfile } of lockfiles) {
    const parents = readLockfileParents(lockfile, step.package, step.currentVersion!);
    if (!parents) return false;
    const dialect: RequirementDialect = parents.format === "cargo" ? "cargo" : "npm";
    for (const e of parents.edges) {
      if (e.local && e.dir && e.dir !== ".") {
        members.push({ dir: path.join(path.dirname(lockfile), e.dir), rel: e.dir, section: e.section ?? "dependencies", range: e.range });
      } else if (e.range === null || requirementAdmits({ parent: e.parent, text: e.range, dialect }, target) !== true) {
        return false;
      }
    }
  }
  if (members.length === 0) return false;
  const root = liveIntel.getProjectRoot() ?? process.cwd();
  input.sourceDirs = [...new Set(members.map((m) => m.dir))];
  step.scope = "direct";
  step.action = "upgrade_direct";
  step.breaking = step.upgradeType === "major";
  const where = members.map((m) => `${relativeDir(m.dir, root)}/package.json (${m.section}${m.range ? ` "${m.range}"` : ""})`).join(", ");
  const text = `Declared by workspace member${members.length === 1 ? "" : "s"} ${where}, not by the project root: move it to ${target} where it is declared, in that member's directory`;
  const at = step.reasons.findIndex((r) => TRANSITIVE_REASON.test(r));
  if (at >= 0) step.reasons[at] = text;
  else step.reasons.push(text);
  return true;
}

/** Per step: what each blocking parent could do (the parent_release vector runner reads it). */
const STANDINGS = new WeakMap<FixPathStep, Array<{ parent: string; from: string; standing: Standing }>>();

/**
 * Each blocking parent of a planned step, in the app's ParentStanding terms: a release (the parent
 * upgrade), or deprecated / latest / none_admits / unread / undecided / malicious.
 */
export function parentOutcomes(step: FixPathStep): Array<{ parent: string; from: string; outcome: string; upgrade?: ParentUpgrade }> {
  return (STANDINGS.get(step) ?? []).map(({ parent, from, standing }) => ({
    parent,
    from,
    outcome:
      standing.kind === "move"
        ? "release"
        : standing.kind === "stuck"
          ? (standing.outcome ?? "none_admits")
          : standing.kind === "malicious"
            ? "malicious"
            : standing.undecided
              ? "undecided"
              : "unread",
    ...(standing.kind === "move" ? { upgrade: standing.upgrade } : {}),
  }));
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

/** The 4DA app's ParentStanding names, for what a parent cannot do (parent_release vectors). */
export type StuckOutcome = "deprecated" | "latest" | "none_admits" | "introduces";

type Standing =
  | { kind: "stuck"; text: string; outcome?: StuckOutcome }
  | { kind: "move"; upgrade: ParentUpgrade; text: string }
  | { kind: "unknown"; text?: string; undecided?: boolean }
  /** The installed parent or lever is flagged malicious: the row names no release (#981 round 3). */
  | { kind: "malicious"; text: string };

/** The declared dependencies a parent arrives through, or why none can be named. */
type Route =
  | { kind: "direct"; dirs: string[] }
  | { kind: "through"; levers: Array<{ name: string; version: string; adjacent: boolean; dirs: string[] }>; more: number }
  | { kind: "unknown"; why: string };

/**
 * A parent's or lever's own advisories, and its NEWEST release by the 4DA H1 review's rule (#981,
 * 8b): the highest stable release the registry has not withdrawn (facts.versions keeps the
 * withdrawal rule, 8a) that no advisory of the package affects, by the predicate dependency_check
 * decides by (advisoriesAffecting). Without the advisories, the highest stable non-withdrawn one.
 * A release is clean when no advisory affects it; an advisory that affects every release leaves
 * no newest, and then none is clean.
 */
async function ownClean(
  ctx: MoveContext,
  name: string,
  facts: PackageReleaseFacts,
  installed?: string,
): Promise<{ clean: (v: string) => boolean; read: boolean; any: boolean; newest: string | null; unreadable: string[]; remains: (v: string) => string[]; maliciousAt: (v: string) => string[]; introducedAt: (v: string) => string[]; cleanButIntroduced: (v: string) => boolean }> {
  let pending = ctx.advisories.get(name);
  if (!pending) {
    pending = ctx.sources.packageAdvisories(ctx.ecosystem, name).catch(() => null);
    ctx.advisories.set(name, pending);
  }
  const advisories = await pending;
  if (!advisories) return { clean: () => true, read: false, any: false, newest: newestOf(facts.versions, ctx.ecosystem), unreadable: [], remains: () => [], maliciousAt: () => [], introducedAt: () => [], cleanButIntroduced: () => false };
  // The one clean-release predicate (#981): malware never skipped, unreadable ranges unknown, a
  // genuinely unfixed advisory skipped and said (osv-ranges.ts cleanReleases).
  const view = cleanReleases(advisories, ctx.ecosystem, facts.versions, installed);
  return { clean: view.clean, read: true, any: advisories.some((a) => !a.maintenance), newest: view.newest, unreadable: view.unreadable, remains: view.remains, maliciousAt: view.maliciousAt, introducedAt: view.introducedAt, cleanButIntroduced: view.cleanButIntroduced };
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

/**
 * The project directories that declare `name@version`: the resolution's direct rows, plus each
 * workspace member whose own manifest the lockfile shows declaring it (its devDependencies too).
 */
function localDeclarers(ctx: MoveContext, lockfile: string, edges: ParentEdge[], name: string, version: string): string[] {
  const members = edges.filter((e) => e.local && e.dir && e.dir !== ".").map((e) => path.join(path.dirname(lockfile), e.dir!));
  return [...new Set([...declaredDirs(ctx.intel, ctx.ecosystem, name, version), ...members])];
}

function isMajor(from: string, to: string): boolean {
  return computeSemverDistance(from, to)?.label === "major";
}

function commandText(lever: ParentLever): string {
  const cmds = lever.commands ?? [];
  if (cmds.length === 0) return "";
  return ` (${cmds.map((c) => `\`${c.command}\`${cmds.length > 1 ? ` in ${c.dir}` : ""}${c.refresh ? REFRESH_LABEL : ""}`).join("; ")})`;
}

/** A refresh among a row's fixes (the declaration already admits the target), in the app's words. */
const REFRESH_LABEL = " (a lockfile refresh: the declared range already admits it)";

/** The refresh that moves `name` from `installed` inside the ranges, in the lockfile's directory. */
function refreshFor(ctx: MoveContext, b: Blocking, name: string, installed: string, target: string): { dir: string; command: string } {
  const root = ctx.intel.getProjectRoot() ?? process.cwd();
  const dir = relativeDir(path.dirname(b.lockfile), root);
  const command =
    refreshCommandFor(b.lockfile, name, installed, target) ?? manualRefreshSteps(b.format === "bun" ? "bun" : "yarn", name);
  return { dir, command };
}

/**
 * How a move is rendered, kept per parent upgrade so that one release per dependency
 * (reconcileDirectTargets) can lift a lever and rewrite EVERYTHING derived from its release: the
 * text, the parent's `to` / `requirement` / `resolvesTo`, the lever's commands, and whether a
 * refresh must follow (final release audit, findings 4 and 7b). `render` takes the lever releases
 * to use and returns the new text, or null when one of them does not bring the fix in.
 */
const MOVES = new WeakMap<ParentUpgrade, { text: string; render: (lifts: ReadonlyMap<string, string>) => string | null }>();

/** "admits path-to-regexp 0.1.13 (a fresh resolve picks 0.1.13)", or, when the requirement does not admit the target itself, what it resolves to (audit 7d). */
function admitsWords(ctx: MoveContext, requirement: string, dialect: RequirementDialect, resolvesTo: string | null, peer = false): string {
  const peerNote = peer ? " (npm 7+ installs a missing peer)" : "";
  if (requirementAdmits({ parent: "", text: requirement, dialect }, ctx.target) === true) {
    return `admits ${ctx.pkg} ${ctx.target}${peerNote}${resolvesTo ? ` (a fresh resolve picks ${resolvesTo})` : ""}`;
  }
  // "~2.75" does not admit request 2.68.0; it resolves to 2.75.x, which is clean (audit 7d).
  return `resolves ${ctx.pkg} to ${resolvesTo ?? "a release"}, a release at or above ${ctx.target} that no advisory with a fix affects${peerNote}`;
}

/** Every other parent edge of the vulnerable copy admits the target: only then does a refresh after this parent's move reach it (7b). */
async function othersAdmitTarget(ctx: MoveContext, b: Blocking, parent: string, from: string): Promise<{ any: boolean; all: boolean }> {
  const others = (parentsReader(ctx, b.lockfile)?.(ctx.pkg, ctx.installed) ?? []).filter((e) => !(e.parent === parent && e.parentVersion === from));
  if (others.length === 0) return { any: false, all: true };
  const dialect: RequirementDialect = b.format === "cargo" ? "cargo" : "npm";
  for (const e of others) {
    const reqs = e.range !== null ? [e.range] : e.parentVersion !== null ? await ctx.sources.parentRequirements(ctx.ecosystem, e.parent, e.parentVersion, ctx.pkg).catch(() => null) : null;
    if (!reqs || reqs.length === 0 || reqs.some((text) => requirementAdmits({ parent: e.parent, text, dialect }, ctx.target) !== true)) return { any: true, all: false };
  }
  return { any: true, all: true };
}

/**
 * A lever release that takes the blocking parent out of the path altogether: the smallest
 * release of `lever` (clear of its own advisories) whose requirements name neither `parent` nor
 * the package, or name the package at a requirement that admits a clean version. xsv's memoffset
 * 0.2.1 and lock_api 0.1.3 arrive through crossbeam-channel 0.2.4 -> crossbeam-epoch /
 * parking_lot; crossbeam-channel 0.4.4 depends only on crossbeam-utils and maybe-uninit, so they go
 * away with it, where the plan said to point [patch.crates-io] at a fork (final audit, finding 5).
 */
async function dropRelease(ctx: MoveContext, lever: { name: string; version: string }, parent: string, dialect: RequirementDialect): Promise<{ version: string; drops: (v: string) => boolean } | null> {
  const [facts, viaParent, direct] = await Promise.all([
    ctx.sources.releaseFacts(ctx.ecosystem, lever.name).catch(() => null),
    ctx.sources.requirementHistory(ctx.ecosystem, lever.name, parent).catch(() => null),
    ctx.sources.requirementHistory(ctx.ecosystem, lever.name, ctx.pkg).catch(() => null),
  ]);
  if (!facts || !viaParent || !direct) return null;
  const own = await ownClean(ctx, lever.name, facts, lever.version);
  if (own.unreadable.length > 0) return null;
  const drops = (v: string) => {
    const p = viaParent[v];
    const d = direct[v];
    return p !== undefined && d !== undefined && p.reqs.length === 0 && own.clean(v) && (d.reqs.length === 0 || admitsClean(ctx, d.reqs, dialect) !== null);
  };
  const version = facts.versions
    .filter((v) => !isPrereleaseVersion(v, ctx.ecosystem) && compareVersions(v, lever.version, ctx.ecosystem) > 0)
    .sort((a, b) => compareVersions(a, b, ctx.ecosystem))
    .find(drops);
  return version ? { version, drops } : null;
}

/**
 * A parent that will not move (no release admits a clean version, or it is already its newest)
 * still need not be overridden when every declared dependency it arrives through has a release
 * that drops it from the path (dropRelease): the step names that release instead.
 */
async function goesAway(ctx: MoveContext, b: Blocking, parent: string, from: string, route: Route, stuckText: string, outcome: StuckOutcome): Promise<Standing> {
  if (route.kind !== "through" || route.more > 0 || !route.levers.every((l) => l.adjacent)) return { kind: "stuck", text: stuckText, outcome };
  const dialect: RequirementDialect = b.format === "cargo" ? "cargo" : "npm";
  const found = await Promise.all(route.levers.map((l) => dropRelease(ctx, l, parent, dialect)));
  if (found.some((f) => f === null)) return { kind: "stuck", text: stuckText, outcome };
  const upgrade: ParentUpgrade = { parent, from, to: null, breaking: false, requirement: null, goesAway: true, levers: [] };
  const hops = route.levers.map((l, i) => ({ l, drop: found[i]! }));
  const render = (lifts: ReadonlyMap<string, string>): string | null => {
    const texts: string[] = [];
    const levers: ParentLever[] = [];
    for (const { l, drop } of hops) {
      const version = lifts.get(l.name) ?? drop.version;
      if (version !== drop.version && !drop.drops(version)) return null;
      const lever: ParentLever = {
        name: l.name,
        version: l.version,
        to: version,
        breaking: isMajor(l.version, version),
        ...declaredFixes(ctx.intel, ctx.ecosystem, l.name, l.version, version, l.dirs),
      };
      LEVER_ADMITS.set(lever, (v) => (drop.drops(v) ? {} : null));
      levers.push(lever);
      const smallest = version === drop.version ? `${l.name} ${version} is the smallest ${l.name} release` : `${l.name} ${version}, like ${drop.version}, the smallest ${l.name} release that does, is a release`;
      texts.push(
        `${smallest} whose requirements no longer bring in ${parent}, so ${ctx.pkg} ${ctx.installed} goes away from that path with ${l.name} ${version}: upgrade ${l.name} to ${version}${lever.breaking ? " (a major upgrade)" : ""}${commandText(lever)}`,
      );
    }
    upgrade.levers = levers;
    return `${stuckText}, but ${parent} arrives through ${leverList(route)}: ${texts.join("; ")}`;
  };
  const text = render(new Map())!;
  MOVES.set(upgrade, { text, render });
  return { kind: "move", upgrade, text };
}

async function parentStanding(ctx: MoveContext, b: Blocking): Promise<Standing> {
  const { sources, ecosystem, pkg, target } = ctx;
  const parent = b.parent;
  const from = b.parentVersion!;
  const facts = await sources.releaseFacts(ecosystem, parent).catch(() => null);
  if (!facts) return { kind: "unknown" };
  // 8a/8b (the 4DA H1 review): candidates follow the fix-target withdrawal rule (facts.versions:
  // an npm deprecated release only when a later clean one is on its line, nothing when `latest` is
  // deprecated), and "newest" is the highest stable non-withdrawn release, not the `latest` tag.
  // A deprecated package is not stuck by that alone: its releases are judged like any other's.
  const deprecated = facts.deprecatedLatest ? `${parent} is deprecated ("${facts.deprecatedLatest.slice(0, 120)}"), and ` : "";
  const route = findRoute(ctx, b.lockfile, parent, from);
  const own = await ownClean(ctx, parent, facts, from);
  if (own.unreadable.length > 0) return { kind: "unknown", undecided: true, text: `${parent}'s own advisories cannot be judged: ${unreadableText(own.unreadable)}` };
  if (own.maliciousAt(from).length > 0) return { kind: "malicious", text: malwareText(parent, own.maliciousAt(from)) };
  const newest = own.newest;
  // The app's `standing` order (parent_release vectors): a package whose latest release is
  // deprecated is retired whole (Standing::Deprecated, pr-006); the installed parent at or above
  // its latest release (the `latest` tag, else its highest) can move nowhere (Standing::Latest).
  // The withdrawal rule (8a) withdraws none of a retired package's releases; that decides the
  // copy's own targets, not this move.
  if (facts.deprecatedLatest) {
    return goesAway(ctx, b, parent, from, route, `${parent} is deprecated ("${facts.deprecatedLatest.slice(0, 120)}")`, "deprecated");
  }
  const latestOf = facts.latest ?? newestOf(facts.versions, ecosystem);
  if (latestOf && compareVersions(from, latestOf, ecosystem) >= 0) {
    return goesAway(ctx, b, parent, from, route, `${parent} ${from} is already its latest release`, "latest");
  }
  if (!newest || compareVersions(from, newest, ecosystem) >= 0) {
    return goesAway(ctx, b, parent, from, route, `no ${parent} release above ${from} is clear of ${parent}'s own advisories`, "none_admits");
  }

  const dialect: RequirementDialect = b.format === "cargo" ? "cargo" : "npm";
  const excludes = requirementAdmits({ parent, text: b.requirement, dialect }, target) === false;
  const head = `${parent} ${from} requires "${b.requirement}", ${excludes ? `which excludes ${pkg} ${target}` : `under which a refresh does not reach a clean ${pkg}`}`;
  const history = await sources.requirementHistory(ecosystem, parent, pkg).catch(() => null);

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
    // Parity decision 2 (pr-010): a release would admit the fix but brings in an advisory the
    // installed parent does not have. No release is named, and the reason says which.
    const blocked = admittingReleases(ctx, facts, from, history, dialect, (v) => !own.clean(v) && own.cleanButIntroduced(v), true);
    if (blocked.length > 0) {
      // #994 review: the union over every blocked admitting release, sorted.
      const ids = [...new Set(blocked.flatMap((x) => own.introducedAt(x.version)))].sort();
      return goesAway(ctx, b, parent, from, route, `${deprecated}${introducesText(ids).replace(/, so no release is named$/, "")}`, "introduces");
    }
    const clause = own.any ? ` both admits a clean ${pkg} (>= ${target}) and is clear of ${parent}'s own advisories` : ` admits a clean ${pkg} (>= ${target})`;
    return goesAway(ctx, b, parent, from, route, `${deprecated}no ${parent} release up to ${newest ?? "its latest"}${clause}`, "none_admits");
  }
  const requirementClause =
    found.requirement === null
      ? `${parent} ${found.version} is the smallest ${parent} release that no longer depends on ${pkg}`
      : `${parent} ${found.version} is the smallest ${parent} release whose ${found.peer ? "peer " : ""}requirement "${found.requirement}" ${admitsWords(ctx, found.requirement, dialect, found.resolvesTo, found.peer)}`;
  const ownClause =
    (!own.read
      ? `; not checked against ${parent}'s own advisories (OSV.dev did not answer)`
      : own.remains(found.version).length > 0
        ? `, though ${parent} ${found.version} ${remainsText(own.remains(found.version))}`
        : own.any
          ? `, and no advisory of ${parent} affects it`
          : "") +
    // A package retired as a whole keeps its releases installable (8a); the move says it is deprecated.
    (facts.deprecatedLatest ? ` (${parent} is deprecated: "${facts.deprecatedLatest.slice(0, 120)}")` : "");
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
  const others = await othersAdmitTarget(ctx, b, parent, from);
  /** What the package's requirement is at a parent release, for the refresh and the fields (7b). */
  const pkgAt = (v: string) => {
    const entry = history[v];
    const ok = entry !== undefined && own.clean(v) ? admitsClean(ctx, entry.reqs, dialect) : null;
    return ok ? { requirement: entry!.reqs[0] ?? null, peer: entry!.peer, resolvesTo: ok.resolvesTo, keepsInstalled: ok.keepsInstalled } : null;
  };
  /**
   * The refresh to run after an install that brings in parent release `v`: when its requirement
   * still admits the installed copy (an install keeps it, npm 10.9.2), or when it drops the package
   * while another parent still holds the copy; never when another parent's requirement keeps the
   * copy below the target, where `npm update` cannot reach it (micromatch: the other parents require
   * ^3 and the target is 4.0.8; final audit 7b).
   */
  const refreshAt = (v: string): Array<{ dir: string; command: string }> => {
    const at = pkgAt(v);
    if (!at || !others.all) return [];
    return at.keepsInstalled || (at.requirement === null && others.any) ? [refreshFor(ctx, b, pkg, ctx.installed, target)] : [];
  };
  const keepsText = (r: Array<{ command: string }>, requirement: string | null) =>
    r.length === 0
      ? ""
      : `; ${requirement === null ? `another parent still holds ${pkg} ${ctx.installed}` : `${pkg} ${ctx.installed} still satisfies "${requirement}"`}, and an install keeps a copy that satisfies it, so then run ${r.map((c) => `\`${c.command}\``).join(", then ")}`;
  /** The parent's fields at the release it is moved to. */
  const setParentAt = (v: string) => {
    const at = pkgAt(v);
    upgrade.to = v;
    upgrade.breaking = isMajor(from, v);
    if (at) {
      upgrade.requirement = at.requirement;
      upgrade.resolvesTo = at.resolvesTo;
      if (at.peer) upgrade.peer = true;
      else delete upgrade.peer;
    }
  };
  const atText = (v: string) => {
    if (v === found.version) return "";
    const at = pkgAt(v);
    if (!at) return "";
    return at.requirement === null
      ? ` (${parent} ${v} no longer depends on ${pkg} either)`
      : ` (${parent} ${v} requires "${at.requirement}", which ${admitsWords(ctx, at.requirement, dialect, at.resolvesTo)})`;
  };

  if (route.kind === "direct") {
    const render = (lifts: ReadonlyMap<string, string>): string | null => {
      const v = lifts.get(parent) ?? found.version;
      if (!pkgAt(v)) return null;
      const lever: ParentLever = { name: parent, version: from, to: v, breaking: isMajor(from, v), ...declaredFixes(ctx.intel, ecosystem, parent, from, v, route.dirs) };
      LEVER_ADMITS.set(lever, (x) => pkgAt(x));
      upgrade.levers = [lever];
      setParentAt(v);
      if (v !== found.version) upgrade.smallest = found.version;
      else delete upgrade.smallest;
      const refreshes = refreshAt(v);
      if (refreshes.length > 0) upgrade.refreshCommands = refreshes;
      else delete upgrade.refreshCommands;
      return `${head}; ${requirementClause}${ownClause}: upgrade ${parent} to ${v}${lever.breaking ? " (a major upgrade)" : ""}${atText(v)}${commandText(lever)}${keepsText(refreshes, pkgAt(v)?.requirement ?? null)}`;
    };
    const text = render(new Map())!;
    MOVES.set(upgrade, { text, render });
    return { kind: "move", upgrade, text };
  }
  if (route.kind === "unknown") {
    upgrade.leverUnknown = route.why;
    const refreshes = refreshAt(found.version);
    if (refreshes.length > 0) upgrade.refreshCommands = refreshes;
    return {
      kind: "move",
      upgrade,
      text: `${head}; ${requirementClause}${ownClause}. Which of this project's dependencies brings ${parent} ${from} in could not be worked out (${route.why}), so no command is named: bump the one that does to a release that brings in ${parent} >= ${found.version}${keepsText(refreshes, found.requirement)}`,
    };
  }

  // The parent is transitive: each declared dependency it arrives through must bring in a fixed release.
  const hops: Array<{ l: (typeof route.levers)[number]; hop: Extract<ThroughHop, { kind: "found" }> | null }> = [];
  for (const l of route.levers) {
    const hop = l.adjacent ? await throughRelease(ctx, l, parent, from, facts, history, dialect, own.clean) : null;
    if (hop?.kind === "malicious") return { kind: "malicious", text: hop.text };
    if (hop?.kind === "stuck") {
      // The lever cannot bring in a fixed parent; it may still drop the parent from the path.
      const drop = await dropRelease(ctx, l, parent, dialect);
      if (!drop) return { kind: "stuck", text: `${parent} arrives through ${l.name} ${l.version}, and ${hop.text}`, outcome: hop.outcome };
      hops.push({ l, hop: { kind: "found", version: drop.version, brings: null, keepsParent: false, admitsAt: (v) => (drop.drops(v) ? { brings: null, keepsParent: false } : null) } });
      continue;
    }
    hops.push({ l, hop });
  }
  const newestOfLever = new Map<string, string | null>();
  for (const { l, hop } of hops) {
    if (!hop) {
      const f = await sources.releaseFacts(ecosystem, l.name).catch(() => null);
      newestOfLever.set(l.name, f ? (await ownClean(ctx, l.name, f, l.version)).newest : null);
    }
  }
  const many = route.levers.length + route.more > 1;
  const tail = route.more > 0 ? `; and ${route.more} more declared ${route.more === 1 ? "dependency brings" : "dependencies bring"} it in, each of which must move the same way` : "";
  const render = (lifts: ReadonlyMap<string, string>): string | null => {
    const leverTexts: string[] = [];
    const levers: ParentLever[] = [];
    const refreshes: Array<{ dir: string; command: string }> = [];
    let brought: string | null = null;
    for (const { l, hop } of hops) {
      if (!hop) {
        levers.push({ name: l.name, version: l.version, to: null, breaking: false });
        const latest = newestOfLever.get(l.name) ?? null;
        leverTexts.push(`upgrade ${l.name} to a release that brings in ${parent} >= ${found.version} (${latest ? `${l.name} ${latest} is its newest release; ` : ""}check that it does)`);
        continue;
      }
      const v = lifts.get(l.name) ?? hop.version;
      const at = v === hop.version ? { brings: hop.brings, keepsParent: hop.keepsParent } : (hop.admitsAt(v) as { brings: string | null; keepsParent: boolean } | null);
      if (!at) return null;
      const lever: ParentLever = {
        name: l.name,
        version: l.version,
        to: v,
        breaking: isMajor(l.version, v),
        ...(v !== hop.version ? { smallest: hop.version } : {}),
        ...(at.brings !== null ? { floor: found.version, brings: at.brings } : {}),
        ...declaredFixes(ctx.intel, ecosystem, l.name, l.version, v, l.dirs),
      };
      LEVER_ADMITS.set(lever, hop.admitsAt as (version: string) => { requirement?: string | null; resolvesTo?: string | null } | null);
      levers.push(lever);
      if (at.keepsParent && at.brings) {
        const r = refreshFor(ctx, b, parent, from, at.brings);
        if (!refreshes.some((x) => x.command === r.command)) refreshes.unshift(r);
      }
      if (at.brings && (!brought || compareVersions(at.brings, brought, ecosystem) > 0)) brought = at.brings;
      const lifted = v !== hop.version;
      const smallest = lifted ? `${l.name} ${v} (the smallest that does is ${hop.version})` : `${l.name} ${v} is the smallest ${l.name} release that`;
      leverTexts.push(
        at.brings === null
          ? `${smallest} no longer brings in ${parent}, so ${pkg} ${ctx.installed} goes away from that path: upgrade ${l.name} to ${v}${lever.breaking ? " (a major upgrade)" : ""}${commandText(lever)}`
          : lifted
            ? // #981 round 3: the lever's own smallest release, then the release its own upgrade moves to.
              `${l.name} ${hop.version} is the smallest ${l.name} release that brings in a ${parent} that admits it, and ${l.name} ${v}, the release ${l.name}'s own upgrade moves to, also brings in ${parent} ${at.brings} (>= ${parent} ${found.version})${at.keepsParent ? ` (its requirement still admits ${parent} ${from}, which an install keeps)` : ""}: upgrade ${l.name} to ${v}${lever.breaking ? " (a major upgrade)" : ""}${commandText(lever)}`
            : `${smallest} brings in ${parent} ${at.brings}${at.brings === found.version ? "" : ` (>= ${found.version})`}${at.keepsParent ? ` (its requirement still admits ${parent} ${from}, which an install keeps)` : ""}: upgrade ${l.name} to ${v}${lever.breaking ? " (a major upgrade)" : ""}${commandText(lever)}`,
      );
    }
    upgrade.levers = levers;
    if (route.more > 0) upgrade.moreLevers = route.more;
    // The package's requirement at the parent release the levers bring in, not at the smallest one.
    const atParent = brought ?? found.version;
    for (const r of refreshAt(atParent)) if (!refreshes.some((x) => x.command === r.command)) refreshes.push(r);
    if (refreshes.length > 0) upgrade.refreshCommands = refreshes;
    else delete upgrade.refreshCommands;
    return `${head}; ${requirementClause}${ownClause}. ${parent} arrives through ${leverList(route)}${many ? ", each of which must move" : ""}: ${leverTexts.join("; ")}${tail}${keepsText(refreshes, pkgAt(atParent)?.requirement ?? found.requirement)}`;
  };
  const text = render(new Map())!;
  MOVES.set(upgrade, { text, render });
  return { kind: "move", upgrade, text };
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
  return admittingReleases(ctx, facts, from, history, dialect, ownClean, false)[0] ?? null;
}

/** The installable releases of a parent above `from` that pass `ownClean` and admit a clean version, smallest first; only the first unless `all`. */
function admittingReleases(
  ctx: MoveContext,
  facts: PackageReleaseFacts,
  from: string,
  history: RequirementHistory,
  dialect: RequirementDialect,
  ownClean: (version: string) => boolean,
  all: boolean,
): Array<{ version: string; requirement: string | null; peer: boolean; resolvesTo: string | null; keepsInstalled: boolean }> {
  const found: Array<{ version: string; requirement: string | null; peer: boolean; resolvesTo: string | null; keepsInstalled: boolean }> = [];
  const candidates = facts.versions
    .filter((v) => !isPrereleaseVersion(v, ctx.ecosystem) && compareVersions(v, from, ctx.ecosystem) > 0)
    .sort((a, b) => compareVersions(a, b, ctx.ecosystem));
  for (const version of candidates) {
    const entry = history[version];
    if (entry === undefined || !ownClean(version)) continue;
    const ok = admitsClean(ctx, entry.reqs, dialect);
    if (!ok) continue;
    found.push({ version, requirement: entry.reqs[0] ?? null, peer: entry.peer, ...ok });
    if (!all) break;
  }
  return found;
}

type ThroughHop =
  | { kind: "found"; version: string; brings: string | null; keepsParent: boolean; admitsAt: (version: string) => object | null }
  | { kind: "stuck"; text: string; outcome: StuckOutcome }
  | { kind: "malicious"; text: string };

/**
 * The smallest release of the declared dependency `lever`, clear of its own advisories, that
 * brings in a `parent` release clear of the parent's advisories whose requirement admits a
 * clean package: the lever's requirement on `parent` resolves (newest match) to it. `keepsParent`
 * when that requirement still admits the installed parent (an install keeps it; a refresh of
 * the parent follows). Stuck when every release was read and none does; null when not readable.
 * Candidates follow the fix-target withdrawal rule and "newest" is the highest stable release (8a/8b).
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
  const own = await ownClean(ctx, lever.name, facts, lever.version);
  if (own.unreadable.length > 0) return null; // #981 (b): unknown, never a release named
  if (own.maliciousAt(lever.version).length > 0) return { kind: "malicious", text: malwareText(lever.name, own.maliciousAt(lever.version)) };
  const newest = own.newest;
  if (!newest || compareVersions(lever.version, newest, ctx.ecosystem) >= 0) {
    const atLatest = !facts.latest || compareVersions(lever.version, facts.latest, ctx.ecosystem) >= 0;
    return { kind: "stuck", outcome: atLatest ? "latest" : "none_admits", text: atLatest ? `${lever.name} ${lever.version} is already its latest release` : `no ${lever.name} release above ${lever.version} is clear of ${lever.name}'s own advisories` };
  }
  const parentReleases = parentFacts.versions.filter((v) => !isPrereleaseVersion(v, ctx.ecosystem));
  const brought = (v: string, leverOk: (v: string) => boolean = own.clean): { brings: string; keepsParent: boolean } | null => {
    const entry = history[v];
    if (!entry || entry.reqs.length !== 1 || !leverOk(v)) return null;
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
    if (hit) return { kind: "found", version, ...hit, admitsAt: (v) => brought(v) };
  }
  // Parity decision 2 (pr-010), for a lever: a release that would bring the fix in, blocked only
  // by an advisory the installed lever does not have, is not offered, and the reason says which.
  const blocked = candidates.filter((v) => !own.clean(v) && own.cleanButIntroduced(v) && brought(v, own.cleanButIntroduced));
  if (blocked.length > 0) {
    const ids = [...new Set(blocked.flatMap((v) => own.introducedAt(v)))].sort();
    return { kind: "stuck", outcome: "introduces", text: `${lever.name}: ${introducesText(ids).replace(/, so no release is named$/, "")}` };
  }
  const deprecated = facts.deprecatedLatest ? `${lever.name} is deprecated ("${facts.deprecatedLatest.slice(0, 120)}"), and ` : "";
  return { kind: "stuck", outcome: "none_admits", text: `${deprecated}no ${lever.name} release up to ${newest ?? "its latest"} brings in a ${parent} that admits a clean ${ctx.pkg}` };
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
    const dirs = localDeclarers(ctx, lockfile, start, parent, version);
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
      const dirs = localDeclarers(ctx, lockfile, edges, node.name, node.version);
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
 * One release per dependency across ALL rows (final release audit of 6.2.5, finding 4; readiness
 * review 2026-10-17, finding 2). NodeGoat named express-session 1.18.1 on the cookie row, 1.18.2 on
 * the on-headers row and 1.19.0 on its own row (and 1.18.1 still requires on-headers ~1.0.2,
 * which is vulnerable); xsv named crossbeam-channel 0.4.4 on its own row and 0.5.0 as a lever.
 *
 * Per declared dependency, the release is the highest of what its rows need (each lever's
 * release, its own row's target) that
 * - crosses no major the installed version is not already crossed by a row's only fix (a row
 *   whose only fix is across a major makes the release breaking, and it is flagged);
 * - no advisory of the dependency affects (the predicate dependency_check decides by);
 * - still brings in every lever's fix (each lever's own check at that release).
 * Every row that names the dependency then gives that release and that command, and everything
 * derived from the release is recomputed at it (the parent's requirement and resolvesTo, the
 * refresh that follows or not: 7b). A dependency for which no release passes is left as it is,
 * and its rows say why.
 *
 * The advisory lookups are bounded (RECONCILE_BUDGET_MS); a release that could not be checked in
 * time is not chosen, and nothing is written after the budget runs out.
 */
export async function reconcileDirectTargets(steps: FixPathStep[], inputs: FixPathInput[], liveIntel: Intel, budgetMs = RECONCILE_BUDGET_MS): Promise<void> {
  const sources = liveIntel.getFixPathSources();
  const key = (eco: string, name: string, version: string) => `${eco}\0${name}\0${version}`;
  type Use = { step: FixPathStep; lever: ParentLever; upgrade: ParentUpgrade };
  const leversOf = new Map<string, { eco: string; name: string; version: string; uses: Use[] }>();
  for (const s of steps) {
    for (const u of s.parentUpgrades ?? []) {
      for (const lever of u.levers) {
        if (!lever.to) continue;
        const k = key(s.ecosystem, lever.name, lever.version);
        const entry = leversOf.get(k) ?? { eco: s.ecosystem, name: lever.name, version: lever.version, uses: [] };
        entry.uses.push({ step: s, lever, upgrade: u });
        leversOf.set(k, entry);
      }
    }
  }
  if (leversOf.size === 0) return;
  const ownRows = new Map<string, FixPathStep>();
  for (const s of steps) {
    if (s.scope === "direct" && s.action === "upgrade_direct" && s.currentVersion && s.targetVersion && leversOf.has(key(s.ecosystem, s.package, s.currentVersion))) {
      ownRows.set(key(s.ecosystem, s.package, s.currentVersion), s);
    }
  }
  const fixRow = (s: FixPathStep) => inputs.some((i) => i.step === s);

  // Look up, bounded, then write: nothing is written once the budget has run out.
  const looked = await withTimeout(
    Promise.all(
      [...leversOf.values()].map(async (d) => {
        const [advisories, facts] = sources
          ? await Promise.all([sources.packageAdvisories(d.eco as OsvEcosystem, d.name).catch(() => null), sources.releaseFacts(d.eco as OsvEcosystem, d.name).catch(() => null)])
          : [null, null];
        // The one clean-release predicate (#981), over the dependency's own release list.
        return [key(d.eco, d.name, d.version), advisories ? cleanReleases(advisories, d.eco, facts?.versions ?? [], d.version) : null] as const;
      }),
    ),
    budgetMs,
    null,
  );
  const advisoriesOf = new Map<string, ReturnType<typeof cleanReleases> | null>(looked ?? []);

  const lifted = new Map<ParentUpgrade, Map<string, string>>();
  const notes = new Map<FixPathStep, string[]>();
  const note = (s: FixPathStep, text: string) => notes.set(s, [...(notes.get(s) ?? []), text]);
  for (const [k, d] of leversOf) {
    const own = ownRows.get(k);
    const eco = d.eco;
    const cmp = (a: string, b: string) => compareVersions(a, b, eco);
    const needs = [...d.uses.map((u) => u.lever.to!), ...(own && fixRow(own) ? [own.targetVersion!] : [])];
    // The releases its rows NEED: each lever's, and its own row's when that row is a fix (the app's
    // row_target). A freshness row's newest release is not a need: it follows the release chosen.
    const candidates = [...new Set(needs)].sort((a, b) => cmp(b, a));
    const majorNeed = needs.filter((n) => isMajor(d.version, n));
    const minimum = needs.reduce((m, n) => (cmp(n, m) > 0 ? n : m), needs[0]);
    const advisories = advisoriesOf.get(k);
    // Without the dependency's advisories, only a release this plan already checked (its own
    // vulnerable row's verified target) can be chosen.
    const verified = new Set(own && fixRow(own) ? [own.targetVersion!] : []);
    const allowed = (c: string) => {
      if (cmp(c, minimum) < 0) return false;
      if (isMajor(d.version, c) && !majorNeed.some((n) => !isMajor(n, c))) return false;
      if (advisories) {
        if (!advisories.clean(c)) return false;
      } else if (!verified.has(c)) {
        return false;
      }
      return d.uses.every((u) => cmp(c, u.lever.to!) === 0 || (cmp(c, u.lever.to!) > 0 && (LEVER_ADMITS.get(u.lever)?.(c) ?? null) !== null));
    };
    const release = candidates.find(allowed) ?? null;
    if (!release && own && !advisories && cmp(minimum, own.targetVersion!) > 0) {
      own.reasons.push(
        `${own.package} ${own.targetVersion} still requires a vulnerable ${[...new Set(d.uses.map((u) => u.step.package))].join(", ")}; ${minimum} admits a clean version, but it could not be checked against ${own.package}'s own advisories in time`,
      );
      continue;
    }
    if (!release) {
      const named = [...new Set(d.uses.map((u) => `${u.lever.to} (${u.step.package} row)`))];
      for (const u of d.uses) {
        note(u.step, `${d.name} has no one release for every row that names it: ${named.join(", ")}${own ? `, and ${own.targetVersion} on its own row` : ""}; no single release ${advisories === null || advisories === undefined ? "could be checked against its advisories in time" : "is clear of its advisories and brings each fix in without crossing a further major"}`);
      }
      continue;
    }
    // Its own row.
    if (own && own.targetVersion !== release) {
      const old = own.targetVersion!;
      const why = fixRow(own)
        ? `${own.package} ${old} still requires a vulnerable ${[...new Set(d.uses.filter((u) => cmp(u.lever.to!, old) > 0).map((u) => u.step.package))].join(", ")}`
        : `${old} is its newest release, but the rows that name ${own.package} need ${release}`;
      own.reasons.push(
        `${release}, not ${old}: one release of ${own.package} for every row that names it (${why}); no advisory of ${own.package} affects ${release}${isMajor(old, release) ? `, a major upgrade from ${old}` : ""}`,
      );
      // A row's only fix across a major raises the row, flagged, never silently (the 4DA lead, 2026-10-18).
      if (isMajor(old, release)) {
        const children = [...new Set(d.uses.filter((u) => u.lever.to === release && isMajor(d.version, release)).map((u) => u.step.package))];
        if (children.length > 0) own.reasons.push(`the only release of ${own.package} that fixes ${children.join(", ")} is ${release}, a major upgrade`);
      }
      if (!fixRow(own) && cmp(old, release) > 0) own.latestVersion = old;
      setTarget(own, release);
      if (own.latestVersion === own.targetVersion) delete own.latestVersion;
      const input = inputs.find((i) => i.step === own) ?? { step: own, fixes: [], sourceDirs: declaredDirs(liveIntel, eco, own.package, own.currentVersion!) };
      withUpgradeCommands(input, liveIntel);
    }
    // Every lever that names it.
    for (const u of d.uses) {
      if (u.lever.to === release) continue;
      const lifts = lifted.get(u.upgrade) ?? new Map<string, string>();
      lifts.set(d.name, release);
      lifted.set(u.upgrade, lifts);
      note(u.step, `${d.name} ${release}, not ${u.lever.to}: one release of ${d.name} for every row that names it${own ? ", its own row included" : ""}, and ${release} also brings this fix in`);
    }
  }

  // Re-render each lifted move at its new releases, replacing its text where the step says it.
  for (const s of steps) {
    for (const u of s.parentUpgrades ?? []) {
      const lifts = lifted.get(u);
      const move = MOVES.get(u);
      if (!lifts || !move) continue;
      const before = move.text;
      const after = move.render(lifts);
      if (after === null) continue;
      s.reasons = s.reasons.map((r) => r.split(before).join(after));
      MOVES.set(u, { text: after, render: move.render });
    }
  }
  for (const [s, texts] of notes) {
    for (const t of texts) if (!s.reasons.includes(t)) s.reasons.push(t);
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
