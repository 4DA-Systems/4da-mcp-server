// SPDX-License-Identifier: Apache-2.0
/**
 * npm: the release a parent upgrade names for what the project declares (the lever) is judged by
 * what it holds, one and two levels down, as the planner's direct targets and dependency_check are
 * (held-dependencies.ts, held-second-level.ts):
 * nyc 18.0.0 brings istanbul-lib-processinfo's uuid fix in, and also requires glob "^13.0.6",
 * every 13.x of which an advisory affects. A lever release that holds an affected dependency the
 * installed release does not is not named as the fix silently:
 * - the smallest later release that still brings every row's fix in, is clear of the lever's own
 *   advisories and holds nothing new that is affected, is named instead (on every row that names
 *   the lever, so one release per dependency holds), with why;
 * - otherwise the release is kept and the row says what it brings, in words that keep the step out
 *   of the fixed counts; when the check cannot finish, the row says it was NOT CHECKED.
 * Within the call's budget; the lookups are the ones the planner's held checks already make.
 */

import { listConfirmed } from "../live/batch-confirm.js";
import { heldAdvisories, heldText, HELD_CANDIDATES, type HeldCheck, type HeldDependency } from "../live/held-dependencies.js";
import type { LiveIntelligence } from "../live/index.js";
import { cleanReleases, isPrereleaseVersion } from "../live/osv-ranges.js";
import { compareVersions } from "../live/version-compare.js";
import { leverBringsAt, liftMove, type FixPathStep, type ParentLever, type ParentUpgrade } from "./upgrade-planner-fixpaths.js";

type Intel = Pick<LiveIntelligence, "getFixPathSources"> & Partial<Pick<LiveIntelligence, "queryAdvisories">>;

interface Use {
  step: FixPathStep;
  upgrade: ParentUpgrade;
  lever: ParentLever;
}

const sameCopy = (held: HeldDependency[], d: HeldDependency) => held.some((x) => x.name === d.name && x.version === d.version);

export async function withLeverHolds(steps: FixPathStep[], liveIntel: Intel, deadline: number): Promise<void> {
  const sources = liveIntel.getFixPathSources();
  const query = liveIntel.queryAdvisories?.bind(liveIntel);
  if (!sources || !query) return;
  const groups = new Map<string, Use[]>();
  for (const step of steps) {
    if (step.ecosystem !== "npm") continue;
    for (const upgrade of step.parentUpgrades ?? []) {
      for (const lever of upgrade.levers) {
        if (!lever.to || lever.outcome || (!lever.commands?.length && !lever.instructions?.length && !lever.sameCommandsAs)) continue;
        const key = `${lever.name}\0${lever.version}\0${lever.to}`;
        groups.set(key, [...(groups.get(key) ?? []), { step, upgrade, lever }]);
      }
    }
  }
  // Releases judged NOT a clean fix here: one judgement for the whole plan (below).
  // The cause, when what the release installs two levels down was only NOT CHECKED; null when it is affected.
  const rejected = new Map<string, string | null>();
  for (const uses of groups.values()) {
    const { name, version } = uses[0].lever;
    const to = uses[0].lever.to!;
    const say = (text: string) => {
      for (const s of new Set(uses.map((u) => u.step))) if (!s.reasons.includes(text)) s.reasons.push(text);
    };
    // A release the plan calls NOT a clean fix, or whose holds were NOT CHECKED, gets no command and
    // no all_advisories claim, on the lever or on the row (claims review 2026-11-24, twolevel85: the
    // handlebars row kept `npm install @hey-api/openapi-ts@0.97.3` and fixPathChecked all_advisories).
    const withhold = (text: string, unchecked: string | null = null) => {
      say(text);
      rejected.set(`${name}\0${to}`, unchecked);
      for (const u of uses) {
        delete u.lever.commands;
        delete u.lever.instructions;
        delete u.lever.sameCommandsAs;
        if (u.step.fixPathChecked === "all_advisories") u.step.fixPathChecked = "installed_advisories_only";
        // No field names the rejected release as the one to move to, and no reason carries its install
        // command (re-check 2026-11-24, twolevel85: the reason still read "upgrade @hey-api/openapi-ts
        // to 0.97.3 (`npm install @hey-api/openapi-ts@0.97.3 --save-exact`)" and parentUpgrades `to: "0.97.3"`).
        u.lever.to = null;
        if (u.upgrade.levers.every((l) => l.to === null)) u.upgrade.to = null;
        u.step.reasons = u.step.reasons.map((r) => (r === text || !r.includes(`${name}@${to}`) && !r.includes(`upgrade ${name} to ${to}`) ? r : withoutCommand(r, name, to)));
      }
    };
    const facts = await sources.releaseFacts("npm", name).catch(() => null);
    const judge = async (v: string): Promise<HeldCheck | undefined> => {
      const specs = facts?.heldSpecs?.[v];
      if (facts && !specs) return { status: "checked", affected: [] };
      if (!specs || Date.now() >= deadline) return undefined;
      // Two levels down too (held-second-level.ts), as a direct target is judged: a lever release is
      // installed by the step as a target is. The installed release is judged the same way, so what it
      // already holds there is carried over, not brought in.
      return (await heldAdvisories(sources, query, [{ key: v, specs }], deadline, { secondLevel: true }).catch(() => null))?.get(v);
    };
    const at = facts ? await judge(to) : undefined;
    if (!at || at.status === "unchecked") {
      const why = at?.status === "unchecked" ? at.reason : facts ? "the planner's time budget ran out before it finished" : `the registry gave no answer for the releases of ${name}`;
      withhold(`whether the dependencies ${name} ${to} holds are affected was NOT CHECKED (${why}): confirm it with dependency_check before pinning it`, why);
      continue;
    }
    if (at.affected.length === 0) continue;
    const installed = await judge(version);
    // What the installed release already holds is carried over by the upgrade, not brought in by it.
    const brought = at.affected.filter((d) => !(installed?.status === "checked" && sameCopy(installed.affected, d)));
    if (brought.length === 0) continue;

    const lifted = await liftedRelease(uses, steps, facts!, judge, installed, sources, query, deadline);
    if (lifted) {
      const lifts = new Map([[name, lifted]]);
      if (uses.every((u) => liftMove(u.step, u.upgrade, lifts))) {
        say(`${name} ${lifted}, not ${to}: ${heldText(to, brought)}, an advisory the installed ${name} ${version} does not bring; ${lifted} is the smallest ${name} release past it that still brings this fix in and holds nothing affected`);
        continue;
      }
    }
    withhold(`${name} ${heldText(to, brought)}: upgrading ${name} to ${to} installs ${brought.length === 1 ? "it" : "them"}, so ${to} is NOT a clean fix: confirm a release with dependency_check before pinning it`);
  }
  // The package's own row, pulled to the same release by the one-release-per-package rule, gets the
  // same judgement: no target, no command, no all_advisories, so no run_order step (check of round 2:
  // vercel 32.2.1 was NOT a clean fix on the lever rows and `npm install vercel@32.2.1` on its own).
  for (const step of steps) {
    if (step.ecosystem !== "npm" || step.scope !== "direct" || !step.targetVersion || !rejected.has(`${step.package}\0${step.targetVersion}`)) continue;
    const release = step.targetVersion;
    const unchecked = rejected.get(`${step.package}\0${release}`);
    step.targetVersion = null;
    delete step.upgradeCommands;
    delete step.upgradeInstructions;
    if (step.fixPathChecked === "all_advisories") step.fixPathChecked = "installed_advisories_only";
    step.reasons.push(
      unchecked
        ? `${step.package} ${release}: whether what it installs two levels down is affected was NOT CHECKED (${unchecked}), so no target or command is given`
        : `${step.package} ${release} is NOT a clean fix (what it installs two levels down is affected: see the rows that name it), so no target or command is given`,
    );
  }
}

/**
 * The smallest release above the named one that every row naming the lever still gets its fix
 * from, clear of the lever's own advisories (confirmed by OSV.dev's batch query), whose held
 * dependencies bring nothing affected the installed release lacks. Null when none is found among
 * the next HELD_CANDIDATES, when a check does not finish, or when the lever has its own row (its
 * release is that row's target, already judged there).
 */
async function liftedRelease(
  uses: Use[],
  steps: FixPathStep[],
  facts: { versions: string[] },
  judge: (v: string) => Promise<HeldCheck | undefined>,
  installed: HeldCheck | undefined,
  sources: NonNullable<ReturnType<Intel["getFixPathSources"]>>,
  query: NonNullable<Intel["queryAdvisories"]>,
  deadline: number,
): Promise<string | null> {
  const { name, version } = uses[0].lever;
  const to = uses[0].lever.to!;
  if (steps.some((s) => s.ecosystem === "npm" && s.scope === "direct" && s.package === name && s.currentVersion === version)) return null;
  const listed = await sources.packageAdvisories("npm", name).catch(() => null);
  const later = facts.versions.filter((v) => !isPrereleaseVersion(v, "npm") && compareVersions(v, to, "npm") > 0).sort((a, b) => compareVersions(a, b, "npm"));
  if (!listed || later.length === 0) return null;
  if (!(await listConfirmed(query, listed, "npm", name, [version, later[later.length - 1]], deadline))) return null;
  const own = cleanReleases(listed, "npm", facts.versions, version);
  const candidates = later.filter((v) => own.clean(v) && uses.every((u) => leverBringsAt(u.lever, v) === true)).slice(0, HELD_CANDIDATES);
  for (const v of candidates) {
    const check = await judge(v);
    if (!check || check.status === "unchecked") return null;
    if (check.affected.every((d) => installed?.status === "checked" && sameCopy(installed.affected, d))) return v;
  }
  return null;
}

/** A reason with the rejected lever release's install command taken out and its advice turned into a warning. */
function withoutCommand(reason: string, name: string, to: string): string {
  const quoted = reason.replace(/\s*\(`[^`]*`\)/g, (m) => (m.includes(`${name}@${to}`) ? "" : m));
  return quoted.replace(/ \(a major upgrade\)/, "").replace(`upgrade ${name} to ${to}`, `upgrading ${name} to ${to} would drop it, but ${to} is NOT a clean fix (see below), so no command is given`);
}
