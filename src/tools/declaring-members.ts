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
  for (const dir of new Set(input.sourceDirs)) {
    const lockfile = liveIntel.lockfileFor(dir, "npm");
    if (!lockfile) {
      dirs.push(dir);
      continue;
    }
    await prepareLockfileParents(lockfile);
    const local = (readLockfileParents(lockfile, step.package, step.currentVersion)?.edges ?? []).filter((e) => e.local);
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
  if (members.length === 0) return;
  input.sourceDirs = [...new Set(dirs)];
  const where = [...new Set(members.map((m) => m.text))].join(", ");
  const plural = new Set(members.map((m) => m.dir)).size === 1 ? "" : "s";
  const text = rootDeclares
    ? `Also declared by workspace member${plural} ${where}: it moves there too, in that member's directory`
    : `Declared by workspace member${plural} ${where}, not by the project root: it moves where it is declared, in that member's directory`;
  if (!step.reasons.includes(text)) step.reasons.push(text);
}
