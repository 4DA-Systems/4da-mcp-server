// SPDX-License-Identifier: Apache-2.0
/**
 * A release number OSV can be asked about: starts with a digit (after Go's `v`). "latest", "next",
 * a dist-tag, a range or an empty string is not one. For a package the registry does not have,
 * "latest" reached OSV.dev as a version (second blind audit, round 6), and again from
 * dependency_check and what_should_i_know (r7), past the guard batch-confirm.ts kept for its own
 * queries only. The scanner (osv-scanner.ts) now holds every query to it: such a version is never
 * sent, and its dependency is NOT CHECKED, never clean.
 */
export function isConcreteVersion(version: string | null | undefined): version is string {
  return typeof version === "string" && /^v?\d[0-9A-Za-z.+!_-]*$/.test(version);
}
