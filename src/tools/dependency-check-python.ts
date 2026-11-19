// SPDX-License-Identifier: Apache-2.0
/**
 * dependency_check on PyPI: whether a release supports the Python versions the project declares
 * (live/project-python.ts). One whose lower bound excludes a declared Python is never `proceed` and
 * never a safe pick: a lock for the project refuses it, and an install on that Python does not get
 * it. An upper cap is a note on a release that stays a pick. A project that declares no Python is
 * judged as before, with no signal and no filter; one whose declaration could not be read gets an
 * info signal that says so.
 *
 * Which declaration: that of the project (or projects) whose manifests declare the package, among
 * the Python projects the project-tree walk found (projectPythons); a package declared nowhere yet
 * is judged against every one of them, and the answer names the folder where a release is
 * unsupported. With no Python project found, the repository root's, as before.
 */

import { andList } from "../live/held-dependencies.js";
import { normalizePythonName } from "../live/lockfile-parsers-pygo.js";
import { mergeProjectPythons, readProjectPythonAt, releasePythonSupport, type ProjectPython } from "../live/project-python.js";
import type { PackageReleaseIndex, ReleaseRecord } from "../live/release-metadata.js";
import type { CheckItem, Signal } from "./dependency-check-signals.js";

/** checkRange's filter: releases that do not support the project's Python are not safe picks. */
export interface PythonRangeFilter {
  unsupported: (version: string) => boolean;
  /** Which of `left` (ascending) need which Python, and what the project declares. */
  note: (left: string[]) => string;
}

/** The Python each item is judged against, and where a declaration could not be read. */
export interface ItemPythons {
  of(item: { ecosystem: string; package: string }): ProjectPython | null;
  /** When nothing readable applies: the declarations that could not be read, by source; else null. */
  unreadOf(item: { ecosystem: string; package: string }): string | null;
  /** The Python versions a PyPI package is judged on (RequirementOptions.pythons). */
  coversOf(name: string): readonly string[] | null;
}

/**
 * Per PyPI package: the declarations of the Python projects whose manifests declare it (each read in
 * its folder, then above it: readProjectPythonAt), or of every Python project when none declares it;
 * the root's when the walk found no Python project. Reads each folder once per call.
 */
export function projectPythons(projects: ReadonlyArray<{ dir: string; names: ReadonlySet<string> }>, root: string | null): ItemPythons {
  const read = new Map<string, ReturnType<typeof readProjectPythonAt>>();
  const at = (dir: string) => {
    if (!read.has(dir)) read.set(dir, readProjectPythonAt(root!, dir));
    return read.get(dir)!;
  };
  const judged = new Map<string, { python: ProjectPython | null; unread: string[] }>();
  const forName = (name: string) => {
    const key = normalizePythonName(name);
    const hit = judged.get(key);
    if (hit) return hit;
    const declaring = projects.filter((p) => p.names.has(key)).map((p) => p.dir);
    const dirs = root === null ? [] : declaring.length > 0 ? declaring : projects.length > 0 ? projects.map((p) => p.dir) : [root];
    const parts: ProjectPython[] = [];
    const unread: string[] = [];
    for (const dir of [...new Set(dirs)].sort()) {
      const found = at(dir);
      if (found === null) continue;
      if ("unread" in found) {
        if (!unread.includes(found.unread)) unread.push(found.unread);
      } else if (!parts.some((p) => p.source === found.python.source)) parts.push(found.python);
    }
    const python = parts.length === 0 ? null : parts.length === 1 ? { ...parts[0], ...(unread.length > 0 ? { unreadIn: unread } : {}) } : mergeProjectPythons(parts, unread);
    const out = { python, unread };
    judged.set(key, out);
    return out;
  };
  return {
    of: (item) => (item.ecosystem === "PyPI" ? forName(item.package).python : null),
    unreadOf: (item) => {
      if (item.ecosystem !== "PyPI") return null;
      const { python, unread } = forName(item.package);
      return python === null && unread.length > 0 ? unread.join(", ") : null;
    },
    coversOf: (name) => forName(name).python?.covers ?? null,
  };
}

/** "Python >=3.9 (pyproject.toml [project] requires-python)"; for projects judged together, each one. */
export function projectPythonText(project: ProjectPython): string {
  if (project.parts && project.parts.length > 1) return andList(project.parts.map(projectPythonText));
  return `Python ${project.declared} (${project.source})`;
}

/** "this project declares" / "the projects here declare". */
function declares(project: ProjectPython): string {
  return project.parts && project.parts.length > 1 ? "the projects here declare" : "this project declares";
}

/** The declarations that could not be read, said after a judgment of the readable ones. */
function unreadNote(item: CheckItem, project: ProjectPython): string {
  const unread = project.unreadIn ?? [];
  if (unread.length === 0) return "";
  return ` ${andList(unread)} ${unread.length === 1 ? "does" : "do"} not read as a version specifier, so ${item.to} was not judged against ${unread.length === 1 ? "it" : "them"}.`;
}

/** The python_support signal of `to`; null outside PyPI or when the project declares no Python. */
export function pythonSupportSignal(item: CheckItem, to: ReleaseRecord | undefined, project: ProjectPython | null, unreadAt: string | null = null): Signal | null {
  if (item.ecosystem !== "PyPI") return null;
  if (!project && unreadAt) {
    return {
      id: "python_support",
      value: { declared_in: unreadAt, project_python: null },
      effect: "info",
      evidence: `This project declares a Python version in ${unreadAt}, but it does not read as a version specifier, so whether ${item.to} supports the project's Python was not checked.`,
    };
  }
  if (!project) return null;
  if (project.parts && project.parts.length > 1) return projectsSignal(item, to, project);
  const support = releasePythonSupport(project, to);
  const declared = projectPythonText(project);
  const value = {
    project_python: project.declared,
    declared_in: project.source,
    requires_python: to?.requiresPython ?? null,
    ...(project.folder !== undefined ? { folder: project.folder } : {}),
    ...(project.unreadIn ? { unread_in: project.unreadIn } : {}),
  };
  const note = unreadNote(item, project);
  if (support.status === "unread") {
    return { id: "python_support", value, effect: "unknown", evidence: `Whether ${item.to} supports this project's ${declared} was not checked: ${support.why}.${note}` };
  }
  if (support.status === "supported" && support.capped) {
    const capped = support.capped.pythons;
    const last = project.covers[project.covers.length - 1];
    const which = capped.length > 1 && capped[capped.length - 1] === last ? `${capped[0]}+` : andList(capped);
    return {
      id: "python_support",
      value: { ...value, capped_pythons: capped },
      effect: "proceed",
      evidence: `${item.to} supports the lowest Python this project declares (${declared}) and declares no support for Python ${which} (requires_python ${support.capped.requires}). uv ignores an upper bound on a dependency's requires-python when locking, and pip judges only the running interpreter, so this is a note, not a hold: test on Python ${capped[0]} before relying on it there.${note}`,
    };
  }
  if (support.status === "supported") {
    return { id: "python_support", value, effect: "proceed", evidence: `${item.to} supports every Python version this project declares, ${declared}.${note}` };
  }
  const missing = support.missing;
  return {
    id: "python_support",
    value: { ...value, unsupported_pythons: missing },
    effect: "review",
    evidence: `${item.to} requires Python ${support.requires}, but this project declares ${declared}, which includes Python ${namedPythons(missing)}: a lock for the project cannot use ${item.to}, and an install on Python ${missing[0]} does not get it. Keep a release that supports every Python the project declares, or raise the project's lowest supported Python first.${note}`,
  };
}

function namedPythons(missing: string[]): string {
  return missing.length > 3 ? `${missing.slice(0, 2).join(", ")} and ${missing.length - 2} more` : andList(missing);
}

/** Several projects' declarations: each judged, and the folders where `to` is unsupported named. */
function projectsSignal(item: CheckItem, to: ReleaseRecord | undefined, project: ProjectPython): Signal {
  const parts = project.parts!;
  const each = parts.map((p) => ({ p, support: releasePythonSupport(p, to) }));
  const folder = (p: ProjectPython) => p.folder ?? ".";
  const projects = each.map(({ p, support }) => ({
    folder: folder(p),
    project_python: p.declared,
    declared_in: p.source,
    status: support.status,
    ...(support.status === "unsupported" ? { unsupported_pythons: support.missing } : {}),
    ...(support.status === "supported" && support.capped ? { capped_pythons: support.capped.pythons } : {}),
  }));
  const value = { project_python: project.declared, declared_in: project.source, requires_python: to?.requiresPython ?? null, projects, ...(project.unreadIn ? { unread_in: project.unreadIn } : {}) };
  const note = unreadNote(item, project);
  const unread = each.find((e) => e.support.status === "unread");
  if (unread && unread.support.status === "unread") {
    return { id: "python_support", value, effect: "unknown", evidence: `Whether ${item.to} supports the Python the projects here declare (${projectPythonText(project)}) was not checked: ${unread.support.why}.${note}` };
  }
  const bad = each.flatMap(({ p, support }) => (support.status === "unsupported" ? [{ p, support }] : []));
  if (bad.length > 0) {
    const missing = [...new Set(bad.flatMap((b) => b.support.missing))];
    const where = bad.map((b) => `${folder(b.p)} declares ${projectPythonText(b.p)}, which includes Python ${namedPythons(b.support.missing)}`);
    return {
      id: "python_support",
      value: { ...value, unsupported_pythons: missing },
      effect: "review",
      evidence: `${item.to} requires Python ${bad[0].support.requires}, but ${andList(where)}: a lock for ${bad.length === 1 ? "that project" : "those projects"} cannot use ${item.to}, and an install there on Python ${bad[0].support.missing[0]} does not get it. Keep a release that supports every Python declared here, or raise the lowest supported Python there first.${note}`,
    };
  }
  const capped = each.flatMap(({ p, support }) => (support.status === "supported" && support.capped ? [`${folder(p)} (Python ${andList(support.capped.pythons)}, requires_python ${support.capped.requires})`] : []));
  const cappedNote = capped.length > 0 ? ` It declares no support for some Python they cover: ${andList(capped)}; uv ignores such an upper bound when locking, so this is a note, not a hold.` : "";
  return { id: "python_support", value, effect: "proceed", evidence: `${item.to} supports every Python version the ${parts.length} projects here declare, ${projectPythonText(project)}.${cappedNote}${note}` };
}

/** The range filter for one package's releases; undefined when nothing is judged. */
export function pythonRangeFilter(project: ProjectPython | null, ecosystem: string, index: PackageReleaseIndex): PythonRangeFilter | undefined {
  if (ecosystem !== "PyPI" || !project) return undefined;
  const support = (v: string) => releasePythonSupport(project, index.releases[v]);
  return {
    unsupported: (v) => support(v).status !== "supported",
    note: (left) => {
      const groups = new Map<string, string[]>();
      for (const v of left) {
        const s = support(v);
        const need = s.status === "unsupported" ? `require Python ${s.requires}` : "list a Python requirement that could not be read";
        groups.set(need, [...(groups.get(need) ?? []), v]);
      }
      const parts = [...groups].map(([need, vs]) => `${vs.length === 1 ? vs[0] : `${vs.length} releases (${vs[0]} to ${vs[vs.length - 1]})`} ${vs.length === 1 ? need.replace(/^require /, "requires ").replace(/^list /, "lists ") : need}`);
      return `${andList(parts)}, and ${declares(project)} ${projectPythonText(project)}`;
    },
  };
}

/** Whether `to` (an exact version) is a release that does not support the project's Python. */
export function lacksProjectPython(project: ProjectPython | null, ecosystem: string, to: ReleaseRecord | undefined): boolean {
  return ecosystem === "PyPI" && project !== null && releasePythonSupport(project, to).status === "unsupported";
}
