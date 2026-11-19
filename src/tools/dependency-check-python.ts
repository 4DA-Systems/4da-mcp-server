// SPDX-License-Identifier: Apache-2.0
/**
 * dependency_check on PyPI: whether a release supports the Python versions the project declares
 * (live/project-python.ts). One that does not is never `proceed` and never a safe pick: a lock for
 * the project refuses it, and an install on the project's lowest Python does not get it. A
 * project that declares no Python is judged as before, with no signal and no filter.
 */

import { andList } from "../live/held-dependencies.js";
import { releasePythonSupport, type ProjectPython } from "../live/project-python.js";
import type { PackageReleaseIndex, ReleaseRecord } from "../live/release-metadata.js";
import type { CheckItem, Signal } from "./dependency-check-signals.js";

/** checkRange's filter: releases that do not support the project's Python are not safe picks. */
export interface PythonRangeFilter {
  unsupported: (version: string) => boolean;
  /** Which of `left` (ascending) need which Python, and what the project declares. */
  note: (left: string[]) => string;
}

/** "Python >=3.9 (pyproject.toml [project] requires-python)". */
export function projectPythonText(project: ProjectPython): string {
  return `Python ${project.declared} (${project.source})`;
}

/** The python_support signal of `to`; null outside PyPI or when the project declares no Python. */
export function pythonSupportSignal(item: CheckItem, to: ReleaseRecord | undefined, project: ProjectPython | null): Signal | null {
  if (item.ecosystem !== "PyPI" || !project) return null;
  const support = releasePythonSupport(project, to);
  const declared = projectPythonText(project);
  const value = { project_python: project.declared, declared_in: project.source, requires_python: to?.requiresPython ?? null };
  if (support.status === "unread") {
    return { id: "python_support", value, effect: "unknown", evidence: `Whether ${item.to} supports this project's ${declared} was not checked: ${support.why}.` };
  }
  if (support.status === "supported") {
    return { id: "python_support", value, effect: "proceed", evidence: `${item.to} supports every Python version this project declares, ${declared}.` };
  }
  const missing = support.missing;
  const named = missing.length > 3 ? `${missing.slice(0, 2).join(", ")} and ${missing.length - 2} more` : andList(missing);
  return {
    id: "python_support",
    value: { ...value, unsupported_pythons: missing },
    effect: "review",
    evidence: `${item.to} requires Python ${support.requires}, but this project declares ${declared}, which includes Python ${named}: a lock for the project cannot use ${item.to}, and an install on Python ${missing[0]} does not get it. Keep a release that supports every Python the project declares, or raise the project's lowest supported Python first.`,
  };
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
      return `${andList(parts)}, and this project declares ${projectPythonText(project)}`;
    },
  };
}

/** Whether `to` (an exact version) is a release that does not support the project's Python. */
export function lacksProjectPython(project: ProjectPython | null, ecosystem: string, to: ReleaseRecord | undefined): boolean {
  return ecosystem === "PyPI" && project !== null && releasePythonSupport(project, to).status === "unsupported";
}
