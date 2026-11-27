// SPDX-License-Identifier: Apache-2.0
/**
 * NOTES: how it reads; not part of the contract (what-should-i-know.ts THE CONTRACT).
 *
 * The name-level check of a loose word a task adds (pre-publish round 10, W3).
 *
 * A word after a verb that names a way of working as often as a package ("use blueprints", "try
 * generators") is `loose` (briefing-new-packages.ts): only a finding about the NAME stands for it, a
 * malicious-package record or npm's takedown placeholder. The whole dependency_check run it used to
 * get also judged the newest release, so "use blueprints" sent blueprints to OSV.dev twice, its
 * advisory list (/v1/query) and its newest release (/v1/querybatch), and hydrated an advisory the
 * briefing then dropped as prose. The name is still checked (dropping loose words would miss
 * "use crossenv"-style malware), from one advisory-list read and one registry read: the same
 * inputs, and the same predicate (dependency-check-malicious.ts maliciousName), dependency_check
 * decides a malware name from.
 */

import type { LiveIntelligence } from "../live/index.js";
import type { CheckEcosystem } from "../live/release-metadata.js";
import { maliciousName, maliciousSignal, type MaliciousName } from "./dependency-check-malicious.js";

export type NameOnlyLive = Partial<Pick<LiveIntelligence, "getReleaseSources" | "getFixPathSources" | "lookupPrivateReason" | "privateReason">>;

export type NameOnlyAnswer =
  | { kind: "unchecked"; why: string }
  | { kind: "malware"; found: MaliciousName; reason: string }
  | { kind: "not_found"; reason: string }
  | { kind: "clean"; reason: string };

/** What the name alone says: malware, not on the registry, nothing against it, or not checked. */
export async function checkNameOnly(liveIntel: NameOnlyLive, ecosystem: CheckEcosystem, name: string): Promise<NameOnlyAnswer> {
  // Never sent when the project marks it private (the briefing filters these first; this holds anyway).
  const why = (liveIntel.lookupPrivateReason ?? liveIntel.privateReason)?.call(liveIntel, ecosystem, name) ?? null;
  if (why) return { kind: "unchecked", why: `it is private (${why}) and was not sent` };
  const sources = liveIntel.getReleaseSources?.();
  const fixSources = liveIntel.getFixPathSources?.();
  if (!sources || !fixSources) return { kind: "unchecked", why: "the registry lookups are not available in this session" };
  const [lookup, advisories] = await Promise.all([
    sources[ecosystem].getReleases(name, []).catch(() => null),
    fixSources.packageAdvisories(ecosystem, name).catch(() => null),
  ]);
  if (!lookup || lookup.status === "unreachable") return { kind: "unchecked", why: `${ecosystem} could not be read` };
  // An unread advisory list cannot say the name is not malware.
  if (advisories === null) return { kind: "unchecked", why: "OSV.dev's advisory list for it could not be read" };
  const index = lookup.status === "ok" ? lookup.data : null;
  const to = index?.latest ?? "latest";
  const found = maliciousName({ ecosystem, package: name, to, index, notFound: lookup.status === "not_found", advisories });
  if (found) {
    const sig = maliciousSignal({ package: name, to }, found, null);
    return { kind: "malware", found, reason: `${sig.id}: ${sig.evidence}` };
  }
  if (lookup.status === "not_found") {
    return { kind: "not_found", reason: `${name} is not on ${ecosystem}. If it is a private package this tool cannot judge it; otherwise check the name for a typo or a hallucinated package before adding it.` };
  }
  return { kind: "clean", reason: `name check: no malicious-package record covers ${name} on ${ecosystem}. Its releases were not judged here: call dependency_check on the version you write.` };
}
