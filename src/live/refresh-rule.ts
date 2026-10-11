// SPDX-License-Identifier: Apache-2.0
/**
 * THE refresh-or-parent rule for a transitive copy (4DA AD-055 ¶1): given
 * every requirement read for the parents that pull `installed` in, does a
 * lockfile refresh reach `target`?
 *
 * - Any requirement that excludes the target sends the fix to that parent,
 *   even when another parent's requirement cannot be read.
 * - Every requirement admitting it makes a refresh enough.
 * - Nothing (or not everything) readable falls back to semver compatibility,
 *   the caret rule: same major at >= 1.0, same minor below it, any bump at
 *   0.0.z leaves it. That answer is `inferred`, and every rendering says so.
 *
 * The 4DA desktop app's `osv::fix_path::refresh_verdict` is the same rule;
 * the shared rule vectors (`refresh_verdict.jsonl`) hold both engines to it.
 * Pure: no I/O.
 */

import { cargoReqAdmits, npmRangeAdmits } from "./range-satisfies.js";
import { parseSemverPrecedence } from "./semver-precedence.js";

/** How a requirement is written: npm (a bare version is an exact pin) or Cargo (a bare version is a caret). */
export type RequirementDialect = "npm" | "cargo";

export interface ParentRequirement {
  parent: string;
  /** The requirement as declared; null when it could not be read at all. */
  text: string | null;
  dialect: RequirementDialect;
}

export interface RefreshRule {
  verdict: "refresh" | "parent_must_move" | "unknown";
  /** True when no requirement decided and the verdict comes from semver compatibility. */
  inferred: boolean;
  /** Parents whose requirement excludes the target, in input order. */
  via: string[];
}

/** Whether a requirement admits a version; null when either cannot be read. */
export function requirementAdmits(req: ParentRequirement, version: string): boolean | null {
  if (req.text === null) return null;
  return req.dialect === "cargo" ? cargoReqAdmits(req.text, version) : npmRangeAdmits(req.text, version);
}

/** True when moving from `installed` to `target` leaves the caret range of `installed`; null when either is unreadable. */
export function leavesCaret(installed: string, target: string): boolean | null {
  const a = parseSemverPrecedence(installed.replace(/^v(?=\d)/, ""));
  const b = parseSemverPrecedence(target.replace(/^v(?=\d)/, ""));
  if (!a || !b) return null;
  if (a.major !== b.major) return true;
  if (a.major === 0 && a.minor !== b.minor) return true;
  return a.major === 0 && a.minor === 0 && a.patch !== b.patch;
}

export function refreshRule(installed: string, target: string, requirements: ParentRequirement[]): RefreshRule {
  const read = requirements.map((r) => requirementAdmits(r, target));
  const via = requirements.filter((_, i) => read[i] === false).map((r) => r.parent);
  if (via.length > 0) return { verdict: "parent_must_move", inferred: false, via: [...new Set(via)] };
  if (read.length > 0 && read.every((ok) => ok === true)) return { verdict: "refresh", inferred: false, via: [] };
  const leaves = leavesCaret(installed, target);
  if (leaves === null) return { verdict: "unknown", inferred: true, via: [] };
  return { verdict: leaves ? "parent_must_move" : "refresh", inferred: true, via: [] };
}
