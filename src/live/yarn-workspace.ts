// SPDX-License-Identifier: Apache-2.0
/**
 * The package.json files of a Yarn workspace, for what yarn.lock does not record: which of the
 * project's own manifests declares a copy. npm, pnpm and bun lockfiles name the declaring manifest
 * (a local parent edge, lockfile-parents.ts); yarn.lock does not (classic writes no entry for the
 * project or a member, berry's workspace entries mix devDependencies in with the rest).
 *
 * The members are the directories the root's `workspaces` patterns name (expandWorkspaces: a
 * bounded walk), read up to MAX_MEMBER_MANIFESTS; a declaration counts when it resolves to the copy
 * in yarn.lock (ParentIndex.resolve), the rule js-dev-scope.ts calls a copy direct by. Read once
 * per tool call.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { callMemo } from "../call-budget.js";
import { expandWorkspaces, MAX_MEMBER_MANIFESTS, readManifestDeclarations, type ManifestDeclarations } from "./js-manifests.js";
import { lockfileParentIndex, type ParentEdge } from "./lockfile-parents.js";

export interface YarnWorkspace {
  /** The project itself (".") and each member, relative to the workspace root with "/"; null where package.json could not be read. */
  manifests: Array<{ dir: string; manifest: ManifestDeclarations | null }>;
  /** False when a pattern could not be expanded, a member's package.json could not be read, or there are more members than are read. */
  complete: boolean;
}

/** The workspace whose root (the directory holding yarn.lock) is `root`; null when its package.json cannot be read. */
export function yarnWorkspace(root: string): YarnWorkspace | null {
  return callMemo(`yarn-workspace:${path.resolve(root)}`, () => {
    const manifest = readManifestDeclarations(path.join(root, "package.json"));
    if (!manifest) return null;
    const expanded = expandWorkspaces(root, manifest.workspaces);
    const members = expanded.dirs.slice(0, MAX_MEMBER_MANIFESTS).map((dir) => ({ dir, manifest: readManifestDeclarations(path.join(root, dir, "package.json")) }));
    return {
      manifests: [{ dir: ".", manifest }, ...members],
      complete: expanded.complete && expanded.dirs.length <= MAX_MEMBER_MANIFESTS && members.every((m) => m.manifest !== null),
    };
  });
}

/** The order a manifest's sections name a local edge in (lockfile-parents.ts LOCAL_DEP_FIELDS). */
const SECTION_ORDER = ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"] as const;

export interface YarnDeclarers {
  /** One local edge per manifest whose declaration resolves to the copy (dir "." for the project itself). */
  edges: ParentEdge[];
  /** False when some manifest was not read (YarnWorkspace.complete): another member may declare it too. */
  complete: boolean;
  /** Why not complete, for the step: the manifests that could not be read, or that the member list is not whole. */
  unread: string;
}

/** Which manifests of the Yarn workspace rooted at `lockfile`'s directory declare `name` at `version`; null when that cannot be read at all. */
export function yarnDeclarers(lockfile: string, name: string, version: string): YarnDeclarers | null {
  const index = lockfileParentIndex(lockfile);
  const workspace = index?.resolve ? yarnWorkspace(path.dirname(lockfile)) : null;
  if (!index?.resolve || !workspace) return null;
  const edges: ParentEdge[] = [];
  for (const { dir, manifest } of workspace.manifests) {
    if (!manifest) continue;
    const spec = SECTION_ORDER.map((section) => manifest.declared.find((d) => d.name === name && d.section === section)).find((d) => d !== undefined);
    if (spec && index.resolve(name, spec.spec) === version) edges.push({ parent: manifest.name ?? dir, parentVersion: null, range: spec.spec, local: true, dir, section: spec.section });
  }
  const unreadable = workspace.manifests.filter((m) => m.manifest === null).map((m) => `${m.dir}/package.json`);
  const unread =
    unreadable.length > 0
      ? `${unreadable.slice(0, 3).join(", ")}${unreadable.length > 3 ? ` and ${unreadable.length - 3} more` : ""} could not be read`
      : "the workspace member list could not be read whole";
  return { edges, complete: workspace.complete, unread };
}

/** How far up from a member a workspace's yarn.lock is looked for (fix-paths.ts MAX_LOCKFILE_ASCENT). */
const MAX_ASCENT = 6;

/** The Yarn workspace member at `dir`, with its readable package.json; null when `dir` is no member of the workspace above it. */
export function yarnWorkspaceMember(dir: string): ManifestDeclarations | null {
  let here = path.dirname(path.resolve(dir));
  for (let i = 0; i < MAX_ASCENT; i++) {
    if (fs.existsSync(path.join(here, "yarn.lock"))) {
      const rel = path.relative(here, path.resolve(dir)).replace(/\\/g, "/");
      return yarnWorkspace(here)?.manifests.find((m) => m.dir !== "." && m.dir === rel)?.manifest ?? null;
    }
    const up = path.dirname(here);
    if (up === here) break;
    here = up;
  }
  return null;
}
