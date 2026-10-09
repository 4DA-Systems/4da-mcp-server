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
  const todo = inputs.filter((i) => i.fixes.length > 0 && i.step.currentVersion);
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
  const clean = await cleanFixTarget(sources, ecosystem, step.package, input.fixes);
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
    const resolves = verdicts.map((v) => v.verdict.resolvesTo).filter((v): v is string => v !== null);
    const to = resolves.length > 0 ? ` (a refresh resolves it to ${[...new Set(resolves)].join(", ")})` : "";
    replaceReason(
      `Transitive dependency: every parent's declared requirement already admits ${target}${to}, so a lockfile refresh is enough, no parent upgrade: ${verdicts.map((v) => `\`${v.verdict.command}\` in ${where(v.dir)}`).join("; ")}`,
    );
    return;
  }
  const seen = new Set<string>();
  const blocking = verdicts.flatMap((v) => v.verdict.blocking).filter((b) => {
    const key = `${b.parent} ${b.parentVersion} ${b.requirement}`;
    return !seen.has(key) && Boolean(seen.add(key));
  });
  const named = blocking
    .slice(0, 3)
    .map((b) => `${b.parent}${b.parentVersion ? ` ${b.parentVersion}` : ""} requires "${b.requirement}"`)
    .join(", ");
  replaceReason(
    `Transitive dependency, waiting on upstream: ${named}${blocking.length > 3 ? ` and ${blocking.length - 3} more` : ""}, so a refresh cannot reach a clean version; the fix arrives with a parent release that widens it`,
  );
}
