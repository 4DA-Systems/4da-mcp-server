// SPDX-License-Identifier: Apache-2.0
/**
 * dependency_check, Go: a module path with upper-case letters whose release OSV.dev answers clean,
 * while the same code under the lower-case path has advisories (pre-publish audit 2026-11-25, C-5).
 *
 * `github.com/Sirupsen/logrus` is the path logrus had before it moved to `github.com/sirupsen/logrus`;
 * its old releases declare no go.mod, so the go command accepts the upper-case spelling as a module
 * of its own, and OSV.dev keys GO-2025-4188 (logrus v1.8.1 and earlier) under the lower-case path
 * only. v1.0.6 answered proceed under the upper-case path and avoid under the lower-case one.
 *
 * So, only for a Go item whose path holds an upper-case letter and whose `to` the batch answered
 * clean: ONE more OSV.dev batch query, for the lower-cased path at the same release (every such item
 * of the pass in that one request). The lower-cased path is the same public name in other letters,
 * and a name a private rule covers in either spelling is never asked. Advisories there make the item
 * review, naming the module and the advisories; a failed query is unknown, never clean.
 */

import type { ResolvedDependency } from "../live/types.js";
import type { AdvisoryFacts, CheckItem, Signal } from "./dependency-check-signals.js";
import { hasRealAdvisory, refs } from "./dependency-check-batch.js";
import type { Resolved } from "./dependency-check-items.js";
import type { PassContext } from "./dependency-check-lookups.js";

/** Per Go item: what its lower-case path's advisories say, when that was asked. */
export async function findCaseVariants(ctx: PassContext, items: Resolved[], advisoriesFor: (item: CheckItem) => AdvisoryFacts): Promise<Map<Resolved, Signal>> {
  const out = new Map<Resolved, Signal>();
  const { liveIntel } = ctx;
  const privateWhy = (name: string) => (liveIntel.lookupPrivateReason ?? liveIntel.privateReason)?.call(liveIntel, "Go", name) ?? null;
  const asked = items.filter((item) => {
    if (item.ecosystem !== "Go" || item.unresolved || item.package === item.package.toLowerCase()) return false;
    const facts = advisoriesFor(item);
    return facts.available && !hasRealAdvisory(facts) && !privateWhy(item.package) && !privateWhy(item.package.toLowerCase());
  });
  if (asked.length === 0) return out;
  const deps = asked.map((item) => goDep(item.package.toLowerCase(), item.to));
  const scan = await liveIntel.queryAdvisories(deps).catch(() => null);
  for (const item of asked) {
    const lower = item.package.toLowerCase();
    if (!scan || scan.offline || (scan.staleAnswers ?? 0) > 0) {
      out.set(item, {
        id: "module_path_case",
        value: { module: lower, advisories: null },
        effect: "unknown",
        evidence: `${item.package} has upper-case letters, and OSV.dev keys advisories by the exact module path: the same module under ${lower} could not be checked for ${item.to}, so whether its advisories apply is not known.`,
      });
      continue;
    }
    const found = refs(scan.vulnerabilities.filter((v) => v.package === lower && v.currentVersion === item.to)).filter((a) => !a.maintenance);
    if (found.length === 0) continue;
    const ids = found.map((a) => a.id);
    out.set(item, {
      id: "module_path_case",
      value: { module: lower, advisories: ids },
      effect: "review",
      evidence:
        `OSV.dev lists no advisory under ${item.package}, but the same module under its lower-case path ${lower} has ${ids.length === 1 ? "one" : ids.length} for ${item.to}: ` +
        `${ids.slice(0, 5).join(", ")}${ids.length > 5 ? ` and ${ids.length - 5} more` : ""}. Go module paths are case-sensitive, so OSV.dev matches ${item.package} to none of them, ` +
        `but where the host ignores letter case (github.com does) both paths serve the same code: treat them as applying, and move to ${lower} at a release that clears them.`,
    });
  }
  return out;
}

function goDep(name: string, version: string): ResolvedDependency {
  return { name, version, ecosystem: "Go", isDev: false, isDirect: true, devScopeKnown: true, target: null, platformActive: true, sourceDirs: [] };
}
