// SPDX-License-Identifier: Apache-2.0
/**
 * A PyPI or Go transitive step: a lockfile refresh with its command when every parent admits the
 * fix, "blocked upstream" naming the parent when one does not, and said when the project's own
 * Python support is what keeps the old copy (live/pygo-parents.ts has the reading rules).
 *
 * Before (audit 2026-11-11, a2 finding 10): every such step was "waiting on upstream ... the fix
 * arrives via a parent package update or a lockfile refresh", with no command and no parent named,
 * although poetry.lock records `certifi = ">=2017.4.17"` under requests and PyPI says the same.
 */

import * as path from "node:path";
import type { LiveIntelligence } from "../live/index.js";
import type { FixPathSources } from "../live/fix-paths.js";
import { advisoryAffects, isPrereleaseVersion, type AdvisoryRanges } from "../live/osv-ranges.js";
import { pypiCompileCommand } from "../live/pypi-advice.js";
import {
  compiledParents,
  goIndirectRaise,
  lowestPython,
  pythonLockParents,
  pythonRefreshCommand,
  pythonSpecAdmits,
  requirementsOn,
  type PythonParents,
} from "../live/pygo-parents.js";
import { readTextFile } from "../live/text-file.js";
import { compareVersions } from "../live/version-compare.js";
import { relativeDir } from "./vulnerability-scan-format.js";

/** The planner fields this module reads and rewrites (a subset of FixPathStep). */
export interface PyGoStep {
  package: string;
  ecosystem: string;
  currentVersion: string | null;
  action: string;
  reasons: string[];
  refreshCommands?: Array<{ dir: string; command: string }>;
}

type Intel = Pick<LiveIntelligence, "lockfileFor" | "getProjectRoot">;

const TRANSITIVE_REASON = /^Transitive dependency — /;

function replaceReason(step: PyGoStep, text: string): void {
  const at = step.reasons.findIndex((r) => TRANSITIVE_REASON.test(r));
  if (at >= 0) step.reasons[at] = text;
  else step.reasons.push(text);
}

/**
 * Decide a PyPI or Go transitive step. True when the step was rewritten; false leaves the
 * conservative "waiting on upstream" (a lockfile or a requirement could not be read).
 */
export async function pygoRefreshOrUpstream(
  step: PyGoStep,
  sourceDirs: string[],
  sources: FixPathSources,
  liveIntel: Intel,
  target: string,
  advisories: AdvisoryRanges[] | null,
): Promise<boolean> {
  const installed = step.currentVersion;
  if (!installed) return false;
  const root = liveIntel.getProjectRoot() ?? process.cwd();
  const dirs = [...new Set(sourceDirs)];
  if (dirs.length === 0) return false;
  if (step.ecosystem === "Go") return goRaise(step, dirs, root, installed, target, sources);
  if (step.ecosystem !== "PyPI") return false;

  const read: Array<{ dir: string; parents: PythonParents }> = [];
  for (const dir of dirs) {
    const lock = liveIntel.lockfileFor(dir, "PyPI");
    const parents = (lock ? pythonLockParents(lock, step.package, installed) : null) ?? compiledParents(dir, step.package, installed);
    if (!parents || parents.edges.length === 0) return false;
    read.push({ dir, parents });
  }

  const facts = await sources.releaseFacts("PyPI", step.package).catch(() => null);
  const edges: Array<{ parent: string; parentVersion: string | null; specs: string[] }> = [];
  for (const { parents } of read) {
    for (const e of parents.edges) {
      let specs = e.specs;
      if (specs === null && e.parentVersion !== null) {
        const dist = await sources.pypiRequiresDist(e.parent, e.parentVersion).catch(() => null);
        const on = dist ? requirementsOn(dist, step.package) : null;
        specs = on && on.length > 0 ? on : null;
      }
      // A requirement that cannot be read leaves the step as it was: never a refresh on a guess.
      if (specs === null) return false;
      if (!edges.some((x) => x.parent === e.parent && x.parentVersion === e.parentVersion)) edges.push({ parent: e.parent, parentVersion: e.parentVersion, specs });
    }
  }
  const admits = (specs: string[], v: string) => specs.map((s) => pythonSpecAdmits(s, v));
  if (edges.some((e) => admits(e.specs, target).every((ok) => ok === null))) return false;
  const label = (e: (typeof edges)[number]) => `${e.parentVersion === null ? "the project" : `${e.parent} ${e.parentVersion}`} requires ${step.package} "${e.specs.join('" or "') || "any version"}"`;

  // A parent whose every requirement excludes the fix: blocked upstream, named.
  const blocking = edges.filter((e) => admits(e.specs, target).every((ok) => ok === false));
  if (blocking.length > 0) {
    const newer = await Promise.all(blocking.map((b) => newestAdmits(sources, b.parent, b.parentVersion, step.package, target)));
    const moves = blocking.map((b, i) => newer[i]).filter((t): t is string => t !== null);
    step.action = "waiting_on_upstream";
    replaceReason(
      step,
      `Transitive dependency, blocked upstream: ${blocking.slice(0, 3).map(label).join(", ")}${blocking.length > 3 ? ` and ${blocking.length - 3} more` : ""}, which excludes ${step.package} ${target}, so a lockfile refresh cannot reach it: ${[...new Set(blocking.map((b) => b.parent))].join(", ")} has to move first${moves.length > 0 ? ` (${moves.join("; ")})` : ""}`,
    );
    return true;
  }

  // Without the package's release list nothing below can be checked: the conservative label stays.
  if (!facts) return false;
  // The project's own Python support: a fix that drops the lowest Python it supports is not reached.
  const projectPython = read.map((r) => r.parents.projectPython).find((p) => p !== null) ?? null;
  const lowest = lowestPython(projectPython);
  const needs = (v: string) => facts.requiresPython?.[v] ?? null;
  const supports = (v: string) => {
    const req = needs(v);
    return !req || !lowest || pythonSpecAdmits(req, lowest) !== false;
  };
  if (!supports(target)) {
    step.action = "waiting_on_upstream";
    replaceReason(
      step,
      `Transitive dependency, held back by the project's Python support: every parent admits ${step.package} ${target} (${edges.slice(0, 3).map(label).join(", ")}), but ${target} requires Python "${needs(target)}" and this project supports Python "${projectPython}", so a resolver keeps ${step.package} ${installed} for Python ${lowest}: raise the project's lowest supported Python to one ${target} supports, then refresh the lockfile`,
    );
    return true;
  }

  // What a refresh resolves to: the newest stable release every parent admits (on the project's
  // lowest Python), which must be the fix or above it, and clean.
  const clean = (v: string) => !advisories || !advisories.some((a) => !a.maintenance && advisoryAffects(a, v, "PyPI"));
  const candidates = facts.versions
    .filter((v) => !isPrereleaseVersion(v, "PyPI") && edges.every((e) => admits(e.specs, v).some((ok) => ok === true)) && supports(v))
    .sort((a, b) => compareVersions(b, a, "PyPI"));
  const resolvesTo = candidates[0] ?? null;
  // A compiled file is re-compiled with `--upgrade-package "x==target"`: the fix itself, not the newest.
  const pinned = read.every((r) => r.parents.format === "compiled");
  if (!pinned && (!resolvesTo || compareVersions(resolvesTo, target, "PyPI") < 0 || !clean(resolvesTo))) {
    step.action = "waiting_on_upstream";
    replaceReason(
      step,
      `Transitive dependency, waiting on upstream: every parent admits ${step.package} ${target} (${edges.slice(0, 3).map(label).join(", ")}), but a refresh resolves it to ${resolvesTo ?? "no release"}${resolvesTo ? ", which an advisory affects or which is below the fix" : ""}, so no refresh command is named`,
    );
    return true;
  }

  const commands: Array<{ dir: string; command: string }> = [];
  for (const { dir, parents } of read) {
    const command = parents.format === "compiled" ? pypiCompileCommand(dir, step.package, installed, target) : pythonRefreshCommand(parents.format, step.package);
    if (!command) return false;
    commands.push({ dir: relativeDir(dir, root), command });
  }
  step.action = "lockfile_refresh";
  step.refreshCommands = commands;
  const to = pinned ? "" : ` (a refresh resolves it to ${resolvesTo})`;
  replaceReason(
    step,
    `Transitive dependency: every parent's declared requirement already admits ${target} (${edges.slice(0, 3).map(label).join(", ")}${edges.length > 3 ? ` and ${edges.length - 3} more` : ""})${to}, so a lockfile refresh is enough, no parent upgrade: ${commands.map((c) => `\`${c.command}\` in ${c.dir}`).join("; ")}`,
  );
  return true;
}

/** "requests 2.34.2, its newest release, requires idna "<4,>=2.5", which admits 3.15", or null when it does not or could not be read. */
async function newestAdmits(sources: FixPathSources, parent: string, from: string | null, pkg: string, target: string): Promise<string | null> {
  const facts = await sources.releaseFacts("PyPI", parent).catch(() => null);
  const latest = facts?.latest ?? null;
  if (!latest || (from !== null && compareVersions(latest, from, "PyPI") <= 0)) return null;
  const dist = await sources.pypiRequiresDist(parent, latest).catch(() => null);
  if (!dist) return null;
  const specs = requirementsOn(dist, pkg);
  if (specs.length === 0) return `${parent} ${latest}, its newest release, no longer requires ${pkg}`;
  return specs.some((s) => pythonSpecAdmits(s, target) === true) ? `${parent} ${latest}, its newest release, requires ${pkg} "${specs.join('" or "')}", which admits ${target}` : null;
}

/**
 * Go: raise the indirect requirement in each go.mod; false when any go.mod replaces, excludes or
 * directly requires it. When the fix needs a newer Go than a go.mod says, the step says which
 * (checked 2026-11-12 with go 1.24.4: `go get golang.org/x/text@v0.41.0` refuses under
 * GOTOOLCHAIN=local, "requires go >= 1.25.0"; v0.3.8 moved x/text alone, x/net untouched).
 */
async function goRaise(step: PyGoStep, dirs: string[], root: string, installed: string, target: string, sources: FixPathSources): Promise<boolean> {
  const commands: Array<{ dir: string; command: string }> = [];
  const directives: string[] = [];
  for (const dir of dirs) {
    const goMod = path.join(dir, "go.mod");
    const command = goIndirectRaise(goMod, step.package, installed, target);
    if (!command) return false;
    commands.push({ dir: relativeDir(dir, root), command });
    const own = goDirectiveOf(goMod);
    if (own) directives.push(own);
  }
  const needs = await sources.goDirective(step.package, target).catch(() => null);
  const oldest = directives.sort((a, b) => compareVersions(a, b, "PyPI"))[0] ?? null;
  const newerGo =
    needs && oldest && compareVersions(needs, oldest, "PyPI") > 0
      ? `; ${step.package} v${target.replace(/^v/, "")} requires go >= ${needs} and go.mod says go ${oldest}, so go get also raises the go directive to ${needs} (a Go older than ${needs} with GOTOOLCHAIN=local refuses it: install Go ${needs} or later first)`
      : "";
  step.action = "lockfile_refresh";
  step.refreshCommands = commands;
  replaceReason(
    step,
    `Transitive dependency: Go selects the highest version any module requires and no requirement sets an upper bound, so raising it in go.mod reaches ${target} with no parent moving: ${commands.map((c) => `\`${c.command}\` in ${c.dir}`).join("; ")} (go get also raises what that release itself requires)${newerGo}`,
  );
  return true;
}

/** The `go` directive of a go.mod on disk, or null. */
function goDirectiveOf(goMod: string): string | null {
  try {
    return /^go\s+(\d+\.\d+(?:\.\d+)?)\s*$/m.exec(readTextFile(goMod))?.[1] ?? null;
  } catch {
    return null;
  }
}
