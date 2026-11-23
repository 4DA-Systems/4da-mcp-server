// SPDX-License-Identifier: Apache-2.0
/**
 * A command written with a range installs the release the package manager picks for that range,
 * not the release the row checked: `npm install "mssql@~10.0.3"` installs mssql 10.0.6, whose
 * tedious "^16.4.0" does not bring in the tedious 18 the row needed, and `npm install
 * "@actions/github@~6.0.0"` installs 6.0.1, which requires undici "^5.28.5" itself. So for every
 * range command a row names (a direct upgrade, a parent upgrade's lever, pnpm's declaration of a
 * package a parent takes as a peer), the release it installs
 * is worked out as the package manager picks it, and:
 * - it is the target: nothing changes;
 * - it is another release and passes every check the row made on the target (the package's
 *   advisories, with OSV.dev's batch query confirming the list; for a lever, that it still brings
 *   the fix in and needs no refresh the row does not already name; npm: what it holds; crates.io,
 *   a direct upgrade: what it requires): the range command stays, carries `installs`, and the row
 *   says which release installs;
 * - otherwise, or when that release cannot be established: the command names the target exactly
 *   (the form written for an exactly pinned dependency), and the row says why.
 * npm's pick is dependency_check's (npmPick). Yarn and pnpm can install the highest release a range
 * admits, so where that is not npm's pick the release is not established for them.
 */

import { listConfirmed } from "../live/batch-confirm.js";
import { targetCheckedAll, type FixPathSources, type FixTargetResult, type PackageReleaseFacts } from "../live/fix-paths.js";
import { byDeadline, heldAdvisories, heldText, type HeldCheck, type HeldDependency } from "../live/held-dependencies.js";
import type { LiveIntelligence } from "../live/index.js";
import { advisoryAffects, cleanReleases, type AdvisoryRanges } from "../live/osv-ranges.js";
import { isPrereleaseVersion } from "../live/osv-ranges.js";
import { cargoReqAdmits, npmRangeAdmits } from "../live/range-satisfies.js";
import { requirementSources } from "../live/release-requirements.js";
import { withRequiredTargets } from "../live/required-targets.js";
import type { OsvEcosystem } from "../live/types.js";
import { compareVersions } from "../live/version-compare.js";
import { npmPick, type NpmWhy } from "./dependency-check-resolution.js";
import { leverAt, type FixPathStep, type LeverBrings, type ParentLever, type ParentUpgrade } from "./upgrade-planner-fixpaths.js";

type Intel = Pick<LiveIntelligence, "getFixPathSources"> & Partial<Pick<LiveIntelligence, "queryAdvisories" | "getReleaseSources">>;

type Tool = "npm" | "pnpm" | "yarn" | "cargo";
const TOOL_NAME: Record<Tool, string> = { npm: "npm", pnpm: "pnpm", yarn: "Yarn", cargo: "Cargo" };

/** A version-setting command that names a range: what it moves, the range as written, and the same command naming the target exactly. */
export interface RangeCommand {
  tool: Tool;
  name: string;
  /** The range as the package manager reads it ("~10.0.3"; Cargo reads a bare "1.2.3" as "^1.2.3"). */
  spec: string;
  target: string;
  exact: string;
}

const NPM_RANGE = /^(npm install|pnpm up|pnpm add(?: -D| -O)?|yarn upgrade|yarn up|yarn add|yarn workspace \S+ add) "((?:@[^/\s"@]+\/)?[^@\s"]+)@([\^~])(\d[^"\s]*)"((?: --dev| --optional)?)$/;
const CARGO_RANGE = /^cargo add (?:"([A-Za-z0-9_-]+)@([\^~])(\d[^"\s]*)"|([A-Za-z0-9_-]+)@(\d[^"\s]*))((?: .+)?)$/;

/** The range command `command` is, in the forms live/fix-paths.ts writes; null for any other command. */
export function readRangeCommand(command: string): RangeCommand | null {
  const n = NPM_RANGE.exec(command);
  if (n) {
    const [, head, name, op, target, tail] = n;
    const tool: Tool = head === "npm install" ? "npm" : head.startsWith("pnpm ") ? "pnpm" : "yarn";
    return { tool, name, spec: `${op}${target}`, target, exact: `${head} ${name}@${target}${tail}${tool === "npm" ? " --save-exact" : ""}` };
  }
  const c = CARGO_RANGE.exec(command);
  if (c) {
    const name = c[1] ?? c[4];
    const target = c[3] ?? c[5];
    return { tool: "cargo", name, spec: `${c[2] ?? "^"}${target}`, target, exact: `cargo add "${name}@=${target}"${c[6]}` };
  }
  return null;
}

type Entry = { dir: string; command: string; refresh?: true; installs?: string };

interface Use {
  step: FixPathStep;
  entry: Entry;
  /** The installed release the command moves from. */
  installed: string | null;
  via?: { lever: ParentLever; upgrade: ParentUpgrade };
}

interface Group {
  ecosystem: OsvEcosystem;
  command: string;
  parsed: RangeCommand;
  uses: Use[];
}

type Decision = { kind: "same" } | { kind: "keep"; installs: string; head: string; checks: string } | { kind: "pin"; why: string };

/** Groups decided at once; each decision's lookups go through the shared caches and rate limits. */
const CONCURRENCY = 6;

export async function withInstalledReleases(steps: FixPathStep[], liveIntel: Intel, deadline: number): Promise<void> {
  const groups = new Map<string, Group>();
  const add = (ecosystem: string, use: Use, name: string, target: string) => {
    if (use.entry.refresh) return;
    const parsed = readRangeCommand(use.entry.command);
    if (!parsed || parsed.name !== name || parsed.target !== target) return;
    const key = `${ecosystem}\0${use.entry.dir}\0${use.entry.command}`;
    const group = groups.get(key) ?? { ecosystem: ecosystem as OsvEcosystem, command: use.entry.command, parsed, uses: [] };
    group.uses.push(use);
    groups.set(key, group);
  };
  for (const step of steps) {
    if (step.ecosystem !== "npm" && step.ecosystem !== "crates.io") continue;
    if (step.targetVersion) for (const entry of step.upgradeCommands ?? []) add(step.ecosystem, { step, entry, installed: step.currentVersion }, step.package, step.targetVersion);
    for (const upgrade of step.parentUpgrades ?? []) {
      for (const lever of upgrade.levers) {
        if (!lever.to) continue;
        for (const entry of lever.commands ?? []) add(step.ecosystem, { step, entry, installed: lever.version, via: { lever, upgrade } }, lever.name, lever.to);
      }
      // pnpm: the declaration of the row's own package after a parent that takes it as a peer (`pnpm add -D "vite@^6.4.5"`).
      for (const entry of upgrade.refreshCommands ?? []) {
        const parsed = readRangeCommand(entry.command);
        if (parsed?.tool === "pnpm" && parsed.name === step.package) add(step.ecosystem, { step, entry, installed: step.currentVersion }, step.package, parsed.target);
      }
    }
  }
  if (groups.size === 0) return;
  const sources = liveIntel.getFixPathSources();
  const all = [...groups.values()];
  let next = 0;
  const worker = async () => {
    while (next < all.length) {
      const group = all[next++];
      const decision: Decision = sources
        ? await decide(group, sources, liveIntel, deadline).catch(() => ({ kind: "pin" as const, why: `which release "${group.parsed.spec}" installs could not be established` }))
        : { kind: "pin", why: `which release "${group.parsed.spec}" installs could not be established (live lookups are off)` };
      apply(group, decision);
    }
  };
  await Promise.all(Array.from({ length: Math.min(CONCURRENCY, all.length) }, worker));
}

/** Write a group's decision onto every row and command it serves. */
function apply(group: Group, decision: Decision): void {
  if (decision.kind === "same") return;
  const { parsed, command } = group;
  const say = (step: FixPathStep, text: string) => {
    if (!step.reasons.includes(text)) step.reasons.push(text);
  };
  for (const use of group.uses) {
    if (decision.kind === "keep") use.entry.installs = decision.installs;
    else {
      use.entry.command = parsed.exact;
      delete use.entry.installs;
    }
  }
  for (const step of new Set(group.uses.map((u) => u.step))) {
    if (decision.kind === "keep") {
      const brings = group.uses.filter((u) => u.step === step && u.via).map((u) => bringsWords(u, decision.installs)).filter((w): w is string => w !== null);
      const still = brings.length > 0 ? `, and it still brings this fix in (${[...new Set(brings)].join("; ")})` : "";
      say(step, `\`${command}\` installs ${parsed.name} ${decision.installs}, not ${parsed.target}: ${decision.head}; ${decision.installs} was checked as ${parsed.target} was: ${decision.checks}${still}`);
      continue;
    }
    // The words name the command the row now gives.
    step.reasons = step.reasons.map((r) => r.split(`\`${command}\``).join(`\`${parsed.exact}\``));
    say(step, `\`${parsed.exact}\`, not \`${command}\`: ${decision.why}; the exact form installs ${parsed.target}, the release this plan checked`);
  }
}

/** What the release a lever command installs brings in, for the row's words; null when it is not known. */
function bringsWords(use: Use, version: string): string | null {
  const at = leverAt(use.via!.lever, version);
  if (!at) return null;
  const { upgrade } = use.via!;
  if ("brings" in at) return at.brings === null ? `${use.via!.lever.name} ${version} no longer brings in ${upgrade.parent}` : `${use.via!.lever.name} ${version} brings in ${upgrade.parent} ${at.brings}`;
  if ("requirement" in at) {
    return at.requirement === null
      ? `${upgrade.parent} ${version} no longer depends on ${use.step.package}`
      : `${upgrade.parent} ${version} requires ${use.step.package} "${at.requirement}"${at.resolvesTo ? `, which resolves to ${at.resolvesTo}` : ""}`;
  }
  return `${use.via!.lever.name} ${version} no longer brings in ${upgrade.parent}`;
}

const WHY: Record<NpmWhy, (spec: string) => string> = {
  latest: (spec) => `it is the "latest" dist-tag, which "${spec}" admits`,
  not_deprecated: (spec) => `it is the highest release "${spec}" admits that is not deprecated`,
  highest: (spec) => `it is the highest release "${spec}" admits (every one of them is deprecated)`,
};

/** The release the command's tool installs for its range, from the registry's release list. */
function installedRelease(
  cmd: RangeCommand,
  facts: PackageReleaseFacts,
  ecosystem: OsvEcosystem,
): { version: string; why: string; admitted: string[] } | { unknown: string } {
  const cmp = (a: string, b: string) => compareVersions(a, b, ecosystem);
  const highestOf = (vs: string[]) => vs.reduce((m, v) => (cmp(v, m) > 0 ? v : m));
  if (cmd.tool === "cargo") {
    // A fresh resolve takes the newest release the requirement admits, as dependency_check reads it; a yanked one never.
    const pre = isPrereleaseVersion(cmd.target, ecosystem);
    const admitted = facts.versions.filter((v) => cargoReqAdmits(cmd.spec, v) === true && (pre || !isPrereleaseVersion(v, ecosystem)));
    if (admitted.length === 0) return { unknown: `no release of ${cmd.name} the registry lists matches "${cmd.spec}"` };
    return { version: highestOf(admitted), why: `it is the newest release "${cmd.spec}" admits, which a resolve takes`, admitted };
  }
  // npm's own candidates: every published release, the deprecated ones included (npmPick passes over them).
  const every = [...new Set([...facts.versions, ...facts.withdrawn])];
  const admitted = every.filter((v) => npmRangeAdmits(cmd.spec, v) === true);
  if (admitted.length === 0) return { unknown: `no release of ${cmd.name} the registry lists matches "${cmd.spec}"` };
  const deprecated = new Set([...facts.withdrawn, ...Object.keys(facts.lineNotices ?? {})]);
  const pick = npmPick({ latest: facts.latest, releases: Object.fromEntries(every.map((v) => [v, { deprecated: deprecated.has(v) ? "deprecated" : null }])) }, admitted)!;
  if (cmd.tool === "npm") return { version: pick.version, why: WHY[pick.why](cmd.spec), admitted };
  const highest = highestOf(admitted);
  if (pick.version === highest) return { version: highest, why: `it is the highest release "${cmd.spec}" admits`, admitted };
  return { unknown: `npm would install ${pick.version} for it and ${TOOL_NAME[cmd.tool]} can install ${highest}, the highest release it admits` };
}

const sameCopy = (held: HeldDependency[], d: HeldDependency) => held.some((x) => x.name === d.name && x.version === d.version);
const affectedOf = (check: HeldCheck | undefined) => (check?.status === "checked" ? check.affected : []);

/** "mssql 10.0.6", or "mssql 10.0.4 to 10.0.6" for several releases. */
function releasesWords(name: string, versions: string[]): string {
  return versions.length === 1 ? `${name} ${versions[0]}` : `${name} ${versions[0]} to ${versions[versions.length - 1]}`;
}

async function decide(group: Group, sources: FixPathSources, liveIntel: Intel, deadline: number): Promise<Decision> {
  const { parsed: cmd, ecosystem, uses } = group;
  const { name, target, spec } = cmd;
  const facts = await byDeadline(sources.releaseFacts(ecosystem, name), deadline, null);
  if (!facts) return { kind: "pin", why: `which release "${spec}" installs was not established (the registry gave no answer for ${name})` };
  const pick = installedRelease(cmd, facts, ecosystem);
  if ("unknown" in pick) return { kind: "pin", why: `which release "${spec}" installs was not established (${pick.unknown})` };
  const installs = pick.version;
  if (compareVersions(installs, target, ecosystem) === 0) return { kind: "same" };
  const head = `${TOOL_NAME[cmd.tool]} installs ${name} ${installs} for "${spec}" (${pick.why})`;
  const pin = (why: string): Decision => ({ kind: "pin", why: `${head}, and ${why}` });

  // The package's own advisories: the same list the target was judged by, confirmed for this release too.
  const listed: AdvisoryRanges[] | null = await byDeadline(sources.packageAdvisories(ecosystem, name), deadline, null);
  if (!listed) return pin(`OSV.dev gave no answer for ${name}'s advisories, so ${installs} was not checked`);
  const query = liveIntel.queryAdvisories?.bind(liveIntel);
  if (!(await listConfirmed(query, listed, ecosystem, name, [installs], deadline))) return pin(`OSV.dev's batch query did not confirm ${name}'s advisory list for ${installs}, so it was not checked`);
  if (cleanReleases(listed, ecosystem, []).unreadable.length > 0) return pin(`an advisory of ${name} could not be read, so ${installs} was not checked`);
  const ids = (v: string) => [...new Set(listed.filter((a) => !a.maintenance && advisoryAffects(a, v, ecosystem)).map((a) => a.id))];
  const atTarget = ids(target);
  const extra = ids(installs).filter((id) => !atTarget.includes(id));
  if (extra.length > 0) return pin(`${extra.join(", ")} affect${extra.length === 1 ? "s" : ""} ${installs}, not ${target}`);

  // A lever: the release that installs must bring the fix in as the target does.
  for (const use of uses) {
    if (!use.via) continue;
    const { lever, upgrade } = use.via;
    const at = leverAt(lever, installs);
    if (at === undefined) return pin(`whether ${name} ${installs} brings this fix in was not established`);
    if (at === null) {
      const above = pick.admitted.filter((v) => compareVersions(v, target, ecosystem) > 0).sort((a, b) => compareVersions(a, b, ecosystem));
      const failing = above.filter((v) => leverAt(lever, v) === null);
      const dep = upgrade.parent === lever.name ? use.step.package : upgrade.parent;
      const history = await byDeadline(sources.requirementHistory(ecosystem, lever.name, dep), deadline, null);
      const reqs = history?.[installs]?.reqs;
      const requires = reqs === undefined ? "" : reqs.length === 0 ? ` (${name} ${installs} no longer requires ${dep})` : ` (${name} ${installs} requires ${dep} "${reqs.join('", "')}")`;
      return pin(`${releasesWords(name, failing.length > 0 ? failing : [installs])}, which "${spec}" also admits, ${failing.length > 1 ? "do" : "does"} not bring this fix in${requires}`);
    }
    if (keeps(at) && !keeps(leverAt(lever, target))) {
      return pin(`${name} ${installs}'s requirement still admits ${upgrade.parent === lever.name ? `${use.step.package} ${use.step.currentVersion}` : `${upgrade.parent} ${upgrade.from}`}, which an install keeps, and this row names no refresh for that`);
    }
  }

  const ownWords = atTarget.length === 0 ? `no advisory of ${name} affects it` : `no advisory affects it that does not affect ${target}`;
  if (cmd.tool !== "cargo") {
    // npm: what the release holds comes with it (held-dependencies.ts), judged as the target's was.
    if (!query) return pin(`what ${name} ${installs} holds was not checked`);
    if (!facts.heldSpecs) return pin(`what ${name} ${installs} holds was not read from the registry`);
    const releases = [...new Set([installs, target, ...uses.filter((u) => u.via && u.installed).map((u) => u.installed!)])];
    const held = await heldAdvisories(sources, query, releases.map((v) => ({ key: v, specs: facts.heldSpecs![v] ?? {} })), deadline);
    const atInstalls = held.get(installs);
    if (!atInstalls || atInstalls.status === "unchecked") return pin(`whether what ${name} ${installs} holds is affected could not be checked${atInstalls?.status === "unchecked" ? ` (${atInstalls.reason})` : " in time"}`);
    for (const use of uses) {
      // A lever's own installed release carries what it holds already; a direct target clears what it does not hold.
      const base = [...affectedOf(held.get(target)), ...(use.via && use.installed ? affectedOf(held.get(use.installed)) : [])];
      const brought = atInstalls.affected.filter((d) => !sameCopy(base, d));
      if (brought.length > 0) return pin(`${name} ${heldText(installs, brought)}, which ${target} does not bring`);
    }
    return { kind: "keep", installs, head: pick.why, checks: `${ownWords}, and it holds no affected dependency ${target} does not` };
  }
  if (uses.some((u) => !u.via)) {
    // crates.io, a direct upgrade: the target's requirements are judged (judgeDirectRequirements); so are this release's.
    const releaseSources = liveIntel.getReleaseSources?.();
    if (!query || !releaseSources) return pin(`what ${name} ${installs} requires was not checked`);
    const judged = await withRequiredTargets(requirementSources(releaseSources, sources), query, [{ key: "installs", ecosystem, name, clean: { target: installs } as FixTargetResult }], deadline);
    const at = judged.get("installs");
    if (at && !targetCheckedAll(at)) return pin(at.requiresAffected ? `what ${name} ${installs} requires carries advisories` : `what ${name} ${installs} requires could not be examined in this call`);
    return { kind: "keep", installs, head: pick.why, checks: `${ownWords}, and what it requires carries no advisory` };
  }
  return { kind: "keep", installs, head: pick.why, checks: ownWords };
}

function keeps(at: LeverBrings | null | undefined): boolean {
  return at?.keepsParent === true || at?.keepsInstalled === true;
}
