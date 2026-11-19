// SPDX-License-Identifier: Apache-2.0
/**
 * Where a direct npm-family copy is declared, when the project root does not declare it.
 *
 * A workspace member's own dependency is direct (version-resolver.ts), but a scan entry's
 * `sourceDirs` name the directory whose lockfile holds the copy: the workspace root. Its fix runs
 * where it is declared, in the member's directory, as memberUpgrade (upgrade-planner-fixpaths.ts)
 * does for a copy first read as transitive. The lockfile's own local edges say which manifests
 * declare the copy, and in which section.
 */

import * as path from "node:path";
import type { LiveIntelligence } from "../live/index.js";
import { prepareLockfileParents, readLockfileParents } from "../live/lockfile-parents.js";
import { yarnDeclarers } from "../live/yarn-workspace.js";
import type { FixPathInput } from "./upgrade-planner-fixpaths.js";
import { relativeDir } from "./vulnerability-scan-format.js";

/**
 * Points a direct npm step's `sourceDirs` at every manifest that declares the copy: the root's
 * directory when the root declares it (or no local edge names a manifest), and each declaring
 * workspace member's directory. Says which members, with the section and range they declare.
 * Changes nothing when no member declares it.
 */
export async function aimAtDeclaringMembers(input: FixPathInput, liveIntel: Pick<LiveIntelligence, "lockfileFor" | "getProjectRoot">): Promise<void> {
  const { step } = input;
  if (step.ecosystem !== "npm" || step.scope !== "direct" || !step.currentVersion) return;
  const dirs: string[] = [];
  const members: Array<{ dir: string; text: string }> = [];
  let rootDeclares = false;
  /** Yarn workspaces whose package.json files were not all read: why, for the step. */
  const unread: string[] = [];
  let unestablished = false;
  for (const dir of new Set(input.sourceDirs)) {
    const lockfile = liveIntel.lockfileFor(dir, "npm");
    if (!lockfile) {
      dirs.push(dir);
      continue;
    }
    await prepareLockfileParents(lockfile);
    const read = readLockfileParents(lockfile, step.package, step.currentVersion);
    let local = (read?.edges ?? []).filter((e) => e.local);
    if (read?.format === "yarn" || read?.format === "yarn-berry") {
      // yarn.lock names no manifest as a parent: the workspace's package.json files say who declares it.
      const yarn = yarnDeclarers(lockfile, step.package, step.currentVersion);
      local = yarn?.edges ?? [];
      if (yarn && !yarn.complete) unread.push(yarn.unread);
      // Not the root, and no member that was read: which member declares it is not known, and no directory is guessed.
      unestablished ||= local.length === 0 && yarn !== null && !yarn.complete;
    }
    const atRoot = local.length === 0 || local.some((e) => (e.dir ?? ".") === ".");
    if (atRoot) dirs.push(dir);
    rootDeclares ||= atRoot;
    for (const e of local) {
      if (!e.dir || e.dir === ".") continue;
      const memberDir = path.join(path.dirname(lockfile), e.dir);
      dirs.push(memberDir);
      const declared = [e.section, e.range === null ? null : `"${e.range}"`].filter(Boolean).join(" ");
      members.push({ dir: memberDir, text: `${relativeDir(memberDir, liveIntel.getProjectRoot() ?? process.cwd())}/package.json${declared ? ` (${declared})` : ""}` });
    }
  }
  const caveat = unread.length > 0 ? `; ${[...new Set(unread)].join("; ")}, so a member declaring it there is not named` : "";
  if (members.length === 0) {
    const text = `Declared by a Yarn workspace member, but the workspace member that declares it could not be established (${[...new Set(unread)].join("; ")}): no directory or command is named for it; run the upgrade in the member whose package.json declares it`;
    if (unestablished && !step.reasons.includes(text)) step.reasons.push(text);
    return;
  }
  input.sourceDirs = [...new Set(dirs)];
  const where = [...new Set(members.map((m) => m.text))].join(", ");
  const plural = new Set(members.map((m) => m.dir)).size === 1 ? "" : "s";
  const text = rootDeclares
    ? `Also declared by workspace member${plural} ${where}: it moves there too, in that member's directory${caveat}`
    : `Declared by workspace member${plural} ${where}, not by the project root: it moves where it is declared, in that member's directory${caveat}`;
  if (!step.reasons.includes(text)) step.reasons.push(text);
}
