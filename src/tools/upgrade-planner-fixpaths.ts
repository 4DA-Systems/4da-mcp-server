// SPDX-License-Identifier: Apache-2.0
/**
 * Fix-path verification for upgrade_planner steps (see live/fix-paths.ts):
 * the target must clear EVERY known advisory of the package, and a
 * transitive step is "waiting on upstream" only when a parent's declared
 * requirement actually excludes every clean version.
 *
 * Runs on the steps the plan returns, within a time budget. A step whose
 * lookups fail or run out of time keeps its unverified answer and says so in
 * `fixPathChecked`.
 */

import type { LiveIntelligence } from "../live/index.js";
import { cleanFixTarget, refreshVerdict, type FixPathSources, type RefreshVerdict } from "../live/fix-paths.js";
import type { LockfileFormat } from "../live/lockfile-parents.js";
import { compareVersions } from "../live/version-compare.js";
import { computeSemverDistance } from "../live/semver-utils.js";
import type { OsvEcosystem } from "../live/types.js";
import { relativeDir } from "./vulnerability-scan-format.js";

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
}

export interface FixPathInput {
  step: FixPathStep;
  /** Per-advisory fixes on the installed line (each advisory's own fixedVersion). */
  fixes: string[];
  /** Manifest directories that pin this copy (the scan's sourceDirs). */
  sourceDirs: string[];
}

/** Total time the plan spends verifying fix paths before answering with what it has. */
const FIX_PATH_BUDGET_MS = 25_000;
const CONCURRENCY = 12;

const TRANSITIVE_REASON = /^Transitive dependency — /;

/** Verify and rewrite the steps in place. Returns how many could not be verified (offline, failure, budget). */
export async function verifyFixPaths(
  inputs: FixPathInput[],
  liveIntel: Pick<LiveIntelligence, "getFixPathSources" | "lockfileFor" | "getProjectRoot">,
  budgetMs = FIX_PATH_BUDGET_MS,
): Promise<number> {
  const sources = liveIntel.getFixPathSources();
  // A step with no per-advisory fix ("no_fix_available") is still looked up: its advisories
  // may give only a last_affected bound with a clean release above it (A6).
  const todo = inputs.filter((i) => (i.fixes.length > 0 || i.step.action === "no_fix_available") && i.step.currentVersion);
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

async function verifyOne(
  input: FixPathInput,
  sources: FixPathSources,
  liveIntel: Pick<LiveIntelligence, "lockfileFor" | "getProjectRoot">,
): Promise<boolean> {
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
    step.targetVersion = clean.target;
    const d = step.currentVersion ? computeSemverDistance(step.currentVersion, clean.target) : null;
    step.upgradeType = !d || d.label === "up-to-date" ? "unknown" : d.label;
    step.breaking = step.scope === "direct" && step.upgradeType === "major";
    step.action = step.scope === "direct" ? "upgrade_direct" : "waiting_on_upstream";
    if (step.scope === "transitive" && step.currentVersion) await refreshOrUpstream(input, sources, liveIntel, clean.target, clean.unfixable);
    return true;
  }
  if (!clean) return false;
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
  if (step.targetVersion !== clean.target) {
    step.targetVersion = clean.target;
    const d = step.currentVersion ? computeSemverDistance(step.currentVersion, clean.target) : null;
    step.upgradeType = !d || d.label === "up-to-date" ? "unknown" : d.label;
    if (step.scope === "direct") step.breaking = step.upgradeType === "major";
  }
  if (step.latestVersion === step.targetVersion) delete step.latestVersion;

  if (step.scope === "transitive" && step.action === "waiting_on_upstream" && step.currentVersion) {
    await refreshOrUpstream(input, sources, liveIntel, clean.target, clean.unfixable);
  }
  return true;
}

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
      verdict: await refreshVerdict(sources, ecosystem, lockfile, step.package, installed, target, advisories, published),
    })),
  );
  // Unknown for one lockfile: the conservative label stays.
  if (results.some((r) => r.verdict === null)) return;
  const verdicts = results as Array<{ dir: string; verdict: RefreshVerdict }>;

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
  const blocking = verdicts.flatMap((v) => v.verdict.blocking).filter((b) => {
    const key = `${b.parent} ${b.parentVersion} ${b.requirement}`;
    return !seen.has(key) && Boolean(seen.add(key));
  });
  const named = blocking
    .slice(0, 3)
    .map((b) => `${b.parent}${b.parentVersion ? ` ${b.parentVersion}` : ""} requires "${b.requirement}"`)
    .join(", ");
  // A parent that will not move (deprecated, or already at its latest
  // release) makes "waiting on upstream" a dead end (A4, request 2.88.2):
  // the step is then an override of the transitive, or replacing the parent.
  const stuck = await stuckParents(sources, ecosystem, blocking);
  if (stuck.length > 0) {
    step.action = "override_or_replace";
    const formats = [...new Set(verdicts.map((v) => v.verdict.format))];
    replaceReason(
      `Transitive dependency: ${named}${blocking.length > 3 ? ` and ${blocking.length - 3} more` : ""}, and ${stuck.join("; ")}, so no parent release will widen it. Force ${step.package} to ${target}: ${formats.map((f) => overrideHint(f, step.package, target)).join("; ")}; or replace the parent`,
    );
    return;
  }
  replaceReason(
    `Transitive dependency, waiting on upstream: ${named}${blocking.length > 3 ? ` and ${blocking.length - 3} more` : ""}, so a refresh cannot reach a clean version; the fix arrives with a parent release that widens it`,
  );
}

/** Blocking parents that will not release a fix: deprecated, or already at their latest release. */
async function stuckParents(
  sources: FixPathSources,
  ecosystem: OsvEcosystem,
  blocking: Array<{ parent: string; parentVersion: string | null }>,
): Promise<string[]> {
  const out: string[] = [];
  for (const b of blocking.slice(0, 5)) {
    if (!b.parentVersion) continue;
    const facts = await sources.releaseFacts(ecosystem, b.parent).catch(() => null);
    if (!facts) continue;
    if (facts.deprecatedLatest) out.push(`${b.parent} is deprecated ("${facts.deprecatedLatest.slice(0, 120)}")`);
    else if (facts.latest && compareVersions(b.parentVersion, facts.latest, ecosystem) >= 0) out.push(`${b.parent} ${b.parentVersion} is already its latest release`);
  }
  return out;
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
