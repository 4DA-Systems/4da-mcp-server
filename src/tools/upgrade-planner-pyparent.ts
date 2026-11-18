// SPDX-License-Identifier: Apache-2.0
/**
 * A PyPI transitive copy whose blocking parent is the project's own dependency.
 *
 * requests 2.25.1 requires idna "<3", so no refresh reaches idna 3.15. When the project declares
 * requests itself, that is not something to wait for: a release of requests that admits the fix is
 * the step, and the refresh of idna follows it (the new requirement still admits the locked copy,
 * and a lockfile keeps a copy that satisfies it). This module finds that release.
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
import { lowestPython, pythonRefreshCommand, pythonSpecAdmits, requirementsOnGated } from "../live/pygo-parents.js";
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
  /** Every blocking parent is the project's own and has a release that admits the fix. */
  | { kind: "move"; upgrades: ParentUpgrade[]; text: string }
  /** The project's own parent blocks, and whether a release of it admits the fix could not be read. */
  | { kind: "undetermined"; text: string }
  /** Not the project's to move, or no release read admits the fix: the caller's wording stands. */
  | null;

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
  // A parent the project does not declare is moved by whatever brings it in, which is not read here.
  if (owned.some((o) => !o.decl)) return null;

  const blockedWords = `${found.blocking.slice(0, 3).map((b) => label(b, pkg)).join(", ")}${found.blocking.length > 3 ? ` and ${found.blocking.length - 3} more` : ""}, which excludes ${pkg} ${target}`;
  const undetermined = (why: string): PyParentOutcome => ({ kind: "undetermined", text: `${blockedWords}, so a lockfile refresh cannot reach it; whether a newer release of what this project declares admits it was not established (${why})` });

  const facts = await sources.releaseFacts("PyPI", pkg).catch(() => null);
  if (!facts) return undetermined(`the registry gave no answer for the releases of ${pkg}`);
  if (!advisories) return undetermined(`OSV.dev gave no answer for the advisories of ${pkg}`);
  const projectPython = found.read.map((r) => r.parents.projectPython).find((p) => p !== null) ?? null;
  const lowest = lowestPython(projectPython);
  const onProjectPython = (requires: string | undefined) => !requires || !lowest || pythonSpecAdmits(requires, lowest) !== false;
  // The fix itself must run on the project's lowest Python: otherwise that, not the parent, holds it.
  if (!onProjectPython(facts.requiresPython?.[target])) return null;

  const picks = new Map<PyEdge, Picked>();
  for (const { b, decl } of owned) {
    const picked = await admittingRelease(sources, intel, decl!.name, b.parentVersion!, pkg, target, onProjectPython);
    if (picked === null) return null;
    if (typeof picked === "string") return undetermined(picked);
    picks.set(b, picked);
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
    const name = decl!.name;
    const from = b.parentVersion!;
    const breaking = computeSemverDistance(from, picked.version)?.label === "major";
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
  const tail =
    after.length === 0
      ? `; nothing else requires ${pkg}, so it leaves the lockfile with that upgrade`
      : keepsInstalled
        ? `; ${pkg} ${installed} still satisfies the new requirement, and a lockfile keeps a copy that satisfies it, so then ${
            refreshes.length > 0 ? `run ${refreshes.map((c) => `\`${c.command}\` in ${c.dir}`).join("; ")}` : `refresh the lockfile entry for ${pkg}`
          } (a refresh resolves it to ${resolvesTo})`
        : `; the new requirement excludes ${pkg} ${installed}, so the upgrade itself moves it (a fresh resolve picks ${resolvesTo})`;
  return { kind: "move", upgrades, text: `${texts.join("; ")}${tail}` };
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
