// SPDX-License-Identifier: Apache-2.0
/**
 * A PyPI transitive copy whose blocking parent has a release that admits the fix.
 *
 * requests 2.25.1 requires idna "<3", so no refresh reaches idna 3.15. When the project declares
 * requests itself, that is not something to wait for: a release of requests that admits the fix is
 * the step, and the refresh of idna follows it (the new requirement still admits the locked copy,
 * and a lockfile keeps a copy that satisfies it). This module finds that release.
 *
 * A blocking parent the project does not declare moves by its own lockfile refresh when everything
 * that requires it admits the release a refresh resolves it to, and that release admits the fix:
 * httpcore 1.0.5 holds h11 "<0.15", httpx 0.27.2 requires "httpcore==1.*", and httpcore 1.0.9
 * requires h11 ">=0.16", so `uv lock --upgrade-package httpcore` moves both (uv, checked
 * 2026-11-23). When what requires it holds it below every release that admits the fix, the release
 * is named and the row says what holds it; no command is given.
 *
 * A parent release is named only when everything it rests on was read: the parent's release list,
 * its own advisories (confirmed by OSV.dev's batch query, as every list-based claim is), the
 * release's own `requires_dist`, and the package's advisories for what the refresh resolves to.
 * Anything unread is reported as undetermined, never as a release and never as blocked.
 *
 * PyPI serves one release's requirements per request, so the search is bounded: the smallest
 * releases clear of the parent's own advisories first, then its newest.
 */

import type { LiveIntelligence } from "../live/index.js";
import type { FixPathSources } from "../live/fix-paths.js";
import { listConfirmed } from "../live/batch-confirm.js";
import { normalizePythonName } from "../live/lockfile-parsers-pygo.js";
import { advisoryAffects, cleanReleases, isPrereleaseVersion, type AdvisoryRanges } from "../live/osv-ranges.js";
import { compiledParents, lowestPython, pythonLockParents, pythonRefreshCommand, pythonSpecAdmits, requirementsOnGated } from "../live/pygo-parents.js";
import { pypiCompileCommand } from "../live/pypi-advice.js";
import { computeSemverDistance } from "../live/semver-utils.js";
import { compareVersions } from "../live/version-compare.js";
import type { ParentLever, ParentUpgrade } from "./upgrade-planner-fixpaths.js";
import type { PyBlocked, PyEdge } from "./upgrade-planner-pygo.js";
import { relativeDir } from "./vulnerability-scan-format.js";

type Intel = Pick<LiveIntelligence, "getProjectRoot" | "getResolvedDeps"> & Partial<Pick<LiveIntelligence, "queryAdvisories">>;

/** Releases of one parent whose requirements are read, per pass (each is one request, cached). */
const MAX_PROBES = 6;
/** Time the parent's advisory list may spend being confirmed by the batch query. */
const CONFIRM_MS = 5_000;

export type PyParentOutcome =
  /**
   * Every blocking parent moves to a release that admits the fix: the project's own by its upgrade,
   * any other by its own lockfile refresh. `refresh` when every one moves by a refresh.
   */
  | { kind: "move"; upgrades: ParentUpgrade[]; text: string; refresh?: true }
  /** A release of every blocking parent admits the fix, but what requires one of them holds it below that release. */
  | { kind: "unverified"; upgrades: ParentUpgrade[]; text: string }
  /** A parent blocks, and whether a release of it admits the fix could not be read. */
  | { kind: "undetermined"; text: string }
  /** No release read of a blocking parent admits the fix: the caller's wording stands. */
  | null;

/** How a blocking parent the project does not declare reaches a release that admits the fix. */
interface ParentRoute {
  /** The commands that refresh it, per lockfile directory; absent when what requires it holds it back. */
  refresh?: Array<{ dir: string; command: string }>;
  /** What requires it, in words ("httpx 0.27.2 requires httpcore "==1.*""). */
  holders: string;
  /** True when one package requires it. */
  one: boolean;
  /** When it cannot move by a refresh: why. */
  held?: string;
}

interface Picked {
  version: string;
  /** The release's requirements on the package; none when it no longer requires it. */
  specs: string[];
  gated: boolean;
  /** False when it is the parent's newest release and smaller ones were left unread. */
  smallest: boolean;
  /** The Python it requires, when the project's lowest supported Python is below it. */
  needsPython: string | null;
}

/** Whether every requirement of an edge admits `v` (a gated edge), or any one does (alternatives of one requirement). */
function edgeAdmits(e: Pick<PyEdge, "specs" | "gated">, v: string): boolean {
  const each = e.specs.map((s) => pythonSpecAdmits(s, v));
  return e.gated ? each.every((ok) => ok === true) : each.some((ok) => ok === true);
}

const label = (e: PyEdge, pkg: string) => `${e.parent} ${e.parentVersion} requires ${pkg} "${e.specs.join('" or "') || "any version"}"`;

export async function pythonParentMove(args: {
  pkg: string;
  installed: string;
  target: string;
  found: PyBlocked;
  sources: FixPathSources;
  intel: Intel;
  /** The package's advisories that a release fixes; null when they could not be read. */
  advisories: AdvisoryRanges[] | null;
  declaredFixes: (name: string, installed: string, target: string, dirs: string[]) => Pick<ParentLever, "commands" | "instructions">;
}): Promise<PyParentOutcome> {
  const { pkg, installed, target, found, sources, intel, advisories } = args;
  const direct = intel.getResolvedDeps().filter((d) => d.isDirect && d.ecosystem === "PyPI");
  const owned = found.blocking.map((b) => ({
    b,
    decl: direct.find((d) => b.parentVersion !== null && normalizePythonName(d.name) === normalizePythonName(b.parent) && d.version === b.parentVersion),
  }));
  // The project's own requirement is the one that excludes it: not a parent to move.
  if (owned.some((o) => o.b.parentVersion === null)) return null;

  const blockedWords = `${found.blocking.slice(0, 3).map((b) => label(b, pkg)).join(", ")}${found.blocking.length > 3 ? ` and ${found.blocking.length - 3} more` : ""}, which excludes ${pkg} ${target}`;
  const ofWhat = owned.every((o) => o.decl) ? "what this project declares" : "the blocking parent";
  const undetermined = (why: string): PyParentOutcome => ({ kind: "undetermined", text: `${blockedWords}, so a lockfile refresh cannot reach it; whether a newer release of ${ofWhat} admits it was not established (${why})` });

  const facts = await sources.releaseFacts("PyPI", pkg).catch(() => null);
  if (!facts) return undetermined(`the registry gave no answer for the releases of ${pkg}`);
  if (!advisories) return undetermined(`OSV.dev gave no answer for the advisories of ${pkg}`);
  const projectPython = found.read.map((r) => r.parents.projectPython).find((p) => p !== null) ?? null;
  const lowest = lowestPython(projectPython);
  const onProjectPython = (requires: string | undefined) => !requires || !lowest || pythonSpecAdmits(requires, lowest) !== false;
  // The fix itself must run on the project's lowest Python: otherwise that, not the parent, holds it.
  if (!onProjectPython(facts.requiresPython?.[target])) return null;

  const picks = new Map<PyEdge, Picked>();
  const routes = new Map<PyEdge, ParentRoute>();
  for (const { b, decl } of owned) {
    if (decl) {
      const picked = await admittingRelease(sources, intel, decl.name, b.parentVersion!, pkg, target, onProjectPython);
      if (picked === null) return null;
      if (typeof picked === "string") return undetermined(picked);
      picks.set(b, picked);
      continue;
    }
    const routed = await transitiveParentRoute(sources, intel, found, b, pkg, target, onProjectPython);
    if (routed === null) return null;
    if (typeof routed === "string") return undetermined(routed);
    picks.set(b, routed.picked);
    routes.set(b, routed.route);
  }

  // What a refresh resolves the package to once each blocking parent holds its new requirement.
  const after: Array<Pick<PyEdge, "specs" | "gated">> = found.edges.flatMap((e) => {
    const picked = picks.get(e);
    if (!picked) return [e];
    return picked.specs.length > 0 ? [{ specs: picked.specs, gated: picked.gated }] : [];
  });
  const clean = (v: string) => !advisories.some((a) => !a.maintenance && advisoryAffects(a, v, "PyPI"));
  const resolvesTo =
    after.length === 0
      ? null
      : (facts.versions
          .filter((v) => !isPrereleaseVersion(v, "PyPI") && after.every((e) => edgeAdmits(e, v)) && onProjectPython(facts.requiresPython?.[v]))
          .sort((a, b) => compareVersions(b, a, "PyPI"))[0] ?? null);
  if (after.length > 0 && (!resolvesTo || compareVersions(resolvesTo, target, "PyPI") < 0 || !clean(resolvesTo))) return null;

  // A lockfile keeps a copy its requirements still admit: then the package's own refresh follows.
  const keepsInstalled = after.length > 0 && after.every((e) => edgeAdmits(e, installed));
  const root = intel.getProjectRoot() ?? process.cwd();
  const refreshes: Array<{ dir: string; command: string }> = [];
  if (keepsInstalled) {
    for (const { dir, parents } of found.read) {
      const command = parents.format === "compiled" ? pypiCompileCommand(dir, pkg, installed, target) : pythonRefreshCommand(parents.format, pkg);
      if (command) refreshes.push({ dir: relativeDir(dir, root), command });
    }
  }

  const upgrades: ParentUpgrade[] = [];
  const texts: string[] = [];
  for (const { b, decl } of owned) {
    const picked = picks.get(b)!;
    const from = b.parentVersion!;
    const breaking = computeSemverDistance(from, picked.version)?.label === "major";
    const route = routes.get(b);
    if (!decl && route) {
      const requirement = picked.specs.length > 0 ? picked.specs.join(" or ") : null;
      const admits = picked.specs.length > 0 ? `whose requirement "${picked.specs.join('" or "')}" admits ${pkg} ${target}` : `that no longer requires ${pkg}`;
      if (route.refresh) {
        const commands = [...route.refresh, ...refreshes.filter((r) => !route.refresh!.some((x) => x.dir === r.dir && x.command === r.command))];
        upgrades.push({ parent: b.parent, from, to: picked.version, breaking, requirement, resolvesTo, levers: [], refreshCommands: commands, refreshOnly: true });
        texts.push(
          `${label(b, pkg)}, which excludes ${pkg} ${target}; ${b.parent} is not declared by this project, and ${route.holders}, which ${route.one ? "admits" : "all admit"} ${b.parent} ${picked.version}, the newest ${b.parent} release ${route.one ? "it admits" : "they admit"} (clear of ${b.parent}'s own advisories), ${admits}: a lockfile refresh of ${b.parent} moves it there, and nothing this project declares has to be upgraded (${route.refresh.map((c) => `\`${c.command}\` in ${c.dir}`).join("; ")})`,
        );
      } else {
        upgrades.push({ parent: b.parent, from, to: picked.version, breaking, requirement, resolvesTo, levers: [], leverUnknown: route.held ?? route.holders });
        const which = picked.smallest ? `the smallest ${b.parent} release` : `the newest ${b.parent} release (the ones between were not all read)`;
        texts.push(`${label(b, pkg)}, which excludes ${pkg} ${target}; ${b.parent} ${picked.version} is ${which} clear of ${b.parent}'s own advisories ${admits}, but ${route.held}`);
      }
      continue;
    }
    const name = decl!.name;
    const lever: ParentLever = { name, version: from, to: picked.version, breaking, ...args.declaredFixes(name, from, picked.version, decl!.sourceDirs ?? []) };
    upgrades.push({
      parent: name,
      from,
      to: picked.version,
      breaking,
      requirement: picked.specs.length > 0 ? picked.specs.join(" or ") : null,
      resolvesTo,
      levers: [lever],
      ...(refreshes.length > 0 ? { refreshCommands: refreshes } : {}),
    });
    const which = picked.smallest ? `the smallest ${name} release` : `the newest ${name} release (the ones between were not all read)`;
    const admits = picked.specs.length > 0 ? `whose requirement "${picked.specs.join('" or "')}" admits ${pkg} ${target}` : `that no longer requires ${pkg}`;
    const how = lever.commands?.length
      ? ` (${lever.commands.map((c) => `\`${c.command}\`${lever.commands!.length > 1 ? ` in ${c.dir}` : ""}`).join("; ")})`
      : lever.instructions?.length
        ? ` (${lever.instructions.map((i) => i.instruction).join("; ")})`
        : " where this project declares it";
    const python = picked.needsPython
      ? `; ${name} ${picked.version} requires Python "${picked.needsPython}" and this project supports Python "${projectPython}", so raise the project's lowest supported Python first`
      : "";
    texts.push(
      `${label(b, pkg)}, which excludes ${pkg} ${target}; ${name} is this project's own dependency, and ${name} ${picked.version} is ${which} clear of ${name}'s own advisories ${admits}: upgrade ${name} to ${picked.version}${breaking ? " (a major upgrade)" : ""}${how}${python}`,
    );
  }
  const held = [...routes.values()].some((r) => !r.refresh);
  const moveWord = held
    ? `moving ${[...new Set(owned.map((o) => o.b.parent))].join(" and ")}`
    : owned.some((o) => o.decl)
      ? "the upgrade itself"
      : "the refresh itself";
  const tail =
    after.length === 0
      ? `; nothing else requires ${pkg}, so it leaves the lockfile with that upgrade`
      : keepsInstalled
        ? `; ${pkg} ${installed} still satisfies the new requirement, and a lockfile keeps a copy that satisfies it, so then ${
            refreshes.length > 0 ? `run ${refreshes.map((c) => `\`${c.command}\` in ${c.dir}`).join("; ")}` : `refresh the lockfile entry for ${pkg}`
          } (a refresh resolves it to ${resolvesTo})`
        : `; the new requirement excludes ${pkg} ${installed}, so ${moveWord} moves it (a fresh resolve picks ${resolvesTo})`;
  const text = `${texts.join("; ")}${tail}`;
  if (held) return { kind: "unverified", upgrades, text: `${text}. No command is named and this is not counted as fixed: check what is named above` };
  return { kind: "move", upgrades, text, ...(routes.size === owned.length ? { refresh: true as const } : {}) };
}

/**
 * A blocking parent the project does not declare: the release a lockfile refresh of it resolves to
 * (the newest one, clear of its own advisories, that everything requiring it admits) when that
 * release admits the fix; else the smallest release that admits the fix, held back by what requires
 * the parent. Null when no release read admits the fix; a string says what could not be read.
 */
async function transitiveParentRoute(
  sources: FixPathSources,
  intel: Intel,
  found: PyBlocked,
  b: PyEdge,
  pkg: string,
  target: string,
  onProjectPython: (requires: string | undefined) => boolean,
): Promise<{ picked: Picked; route: ParentRoute } | string | null> {
  const parent = b.parent;
  const from = b.parentVersion!;
  const smallest = await admittingRelease(sources, intel, parent, from, pkg, target, onProjectPython);
  if (smallest === null || typeof smallest === "string") return smallest;

  // What requires the parent, with the requirement each puts on it, in every lockfile.
  const holders: PyEdge[] = [];
  for (const { dir, parents } of found.read) {
    const read = parents.format === "compiled" ? compiledParents(dir, parent, from) : pythonLockParents(parents.file, parent, from);
    if (!read || read.edges.length === 0) return `the lockfile does not show what requires ${parent} ${from}`;
    for (const e of read.edges) {
      let specs = e.specs;
      let gated = e.gated === true;
      if (specs === null && e.parentVersion !== null) {
        const dist = await sources.pypiRequiresDist(e.parent, e.parentVersion).catch(() => null);
        if (!dist) return `the registry gave no answer for what ${e.parent} ${e.parentVersion} requires`;
        const on = requirementsOnGated(dist, parent);
        specs = on.specs.length > 0 ? on.specs : null;
        gated ||= on.gated;
      }
      if (specs === null) return `what ${e.parent}${e.parentVersion ? ` ${e.parentVersion}` : ""} requires of ${parent} could not be read`;
      if (!holders.some((x) => x.parent === e.parent && x.parentVersion === e.parentVersion)) holders.push({ parent: e.parent, parentVersion: e.parentVersion, specs, gated });
    }
  }
  const holderWords = holders
    .slice(0, 3)
    .map((h) => `${h.parentVersion === null ? "the project" : `${h.parent} ${h.parentVersion}`} requires ${parent} "${h.specs.join('" or "') || "any version"}"`)
    .join(", ");
  const holdersText = `${holderWords}${holders.length > 3 ? ` and ${holders.length - 3} more` : ""}`;

  // A refresh resolves the parent to the newest release they all admit (on the project's lowest Python).
  const [facts, listed] = await Promise.all([sources.releaseFacts("PyPI", parent).catch(() => null), sources.packageAdvisories("PyPI", parent).catch(() => null)]);
  if (!facts || !listed) return `the registry or OSV.dev gave no answer for ${parent}`;
  const resolves = facts.versions
    .filter((v) => !isPrereleaseVersion(v, "PyPI") && compareVersions(v, from, "PyPI") > 0 && holders.every((h) => edgeAdmits(h, v)) && onProjectPython(facts.requiresPython?.[v]))
    .sort((x, y) => compareVersions(y, x, "PyPI"))[0];
  const ownClean = cleanReleases(listed, "PyPI", facts.versions, from).clean;
  if (resolves && ownClean(resolves)) {
    const dist = resolves === smallest.version ? null : await sources.pypiRequiresDist(parent, resolves).catch(() => null);
    if (resolves !== smallest.version && !dist) return `the registry gave no answer for what ${parent} ${resolves} requires`;
    const on = dist ? requirementsOnGated(dist, pkg) : { specs: smallest.specs, gated: smallest.gated };
    if (on.specs.length === 0 || edgeAdmits(on, target)) {
      const root = intel.getProjectRoot() ?? process.cwd();
      const refresh: Array<{ dir: string; command: string }> = [];
      for (const { dir, parents } of found.read) {
        const command = parents.format === "compiled" ? pypiCompileCommand(dir, parent, from, resolves) : pythonRefreshCommand(parents.format, parent);
        if (!command) return `no command is named for ${parent} in ${relativeDir(dir, root)}`;
        refresh.push({ dir: relativeDir(dir, root), command });
      }
      return { picked: { version: resolves, specs: on.specs, gated: on.gated, smallest: false, needsPython: null }, route: { refresh, holders: holdersText, one: holders.length === 1 } };
    }
  }
  const excluding = holders.filter((h) => !edgeAdmits(h, smallest.version));
  const held =
    excluding.length > 0
      ? `${excluding.slice(0, 3).map((h) => `${h.parentVersion === null ? "the project" : `${h.parent} ${h.parentVersion}`} requires ${parent} "${h.specs.join('" or "') || "any version"}"`).join(", ")}, which excludes ${parent} ${smallest.version}, so a refresh cannot move ${parent} there: ${[...new Set(excluding.map((h) => h.parent))].join(", ")} has to move first`
      : `a refresh of ${parent} resolves it to ${resolves ?? "no newer release"}${resolves ? `, which ${ownClean(resolves) ? `does not admit ${pkg} ${target}` : `an advisory of ${parent} affects`}` : ""}, so a refresh alone does not reach the fix (${holdersText})`;
  return { picked: smallest, route: { holders: holdersText, one: holders.length === 1, held } };
}

/**
 * The release of the project's own dependency `parent` to move to: clear of the parent's own
 * advisories, above `from`, with a requirement that admits `target` (or none on the package).
 * Releases that run on the project's lowest Python are tried first. A string says what could not
 * be read; null says no release read admits the fix.
 */
async function admittingRelease(
  sources: FixPathSources,
  intel: Intel,
  parent: string,
  from: string,
  pkg: string,
  target: string,
  onProjectPython: (requires: string | undefined) => boolean,
): Promise<Picked | string | null> {
  const [facts, listed] = await Promise.all([sources.releaseFacts("PyPI", parent).catch(() => null), sources.packageAdvisories("PyPI", parent).catch(() => null)]);
  if (!facts) return `the registry gave no answer for the releases of ${parent}`;
  if (!listed) return `OSV.dev gave no answer for the advisories of ${parent}`;
  const stable = facts.versions.filter((v) => !isPrereleaseVersion(v, "PyPI")).sort((a, b) => compareVersions(a, b, "PyPI"));
  const newest = stable[stable.length - 1];
  if (!newest || compareVersions(newest, from, "PyPI") <= 0) return null;
  // The list calls a release clean only once the batch query, asked about the releases at both ends, names nothing it lacks.
  if (!(await listConfirmed(intel.queryAdvisories?.bind(intel), listed, "PyPI", parent, [from, newest], Date.now() + CONFIRM_MS))) {
    return `the advisories of ${parent} were not confirmed by OSV.dev's batch query`;
  }
  const own = cleanReleases(listed, "PyPI", facts.versions, from);
  const candidates = stable.filter((v) => compareVersions(v, from, "PyPI") > 0 && own.clean(v));
  const probed = new Set<string>();
  const probe = async (version: string): Promise<Picked | "unread" | null> => {
    probed.add(version);
    const dist = await sources.pypiRequiresDist(parent, version).catch(() => null);
    if (!dist) return "unread";
    const on = requirementsOnGated(dist, pkg);
    if (on.specs.length > 0 && !edgeAdmits(on, target)) return null;
    const requires = facts.requiresPython?.[version];
    return { version, specs: on.specs, gated: on.gated, smallest: true, needsPython: onProjectPython(requires) ? null : (requires ?? null) };
  };
  const unread = (version: string) => `the registry gave no answer for what ${parent} ${version} requires`;
  for (const pass of [candidates.filter((v) => onProjectPython(facts.requiresPython?.[v])), candidates.filter((v) => !onProjectPython(facts.requiresPython?.[v]))]) {
    for (const version of pass.slice(0, MAX_PROBES)) {
      const hit = await probe(version);
      if (hit === "unread") return unread(version);
      if (hit) return hit;
    }
  }
  const last = candidates[candidates.length - 1];
  if (last && !probed.has(last)) {
    const hit = await probe(last);
    if (hit === "unread") return unread(last);
    if (hit) return { ...hit, smallest: false };
  }
  return null;
}
