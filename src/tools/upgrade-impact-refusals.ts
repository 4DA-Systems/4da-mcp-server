// SPDX-License-Identifier: Apache-2.0
/**
 * upgrade_impact's refusals say what is known about the release asked for (r7).
 *
 * `{chalk, to_version: "5.6.1"}` (the September 2025 hijack, unpublished by npm) said only "not
 * published on npm"; a downgrade to a vulnerable release was refused as "not older" with no word
 * that it is vulnerable; and an unmatched version ended "Nearest published versions: ." with an
 * empty list. A refusal now names malware (OSV.dev's malicious-package record), an unpublished
 * release, and the advisories that affect the target, and never prints an empty list.
 */

import { getOsvRecordFacts, type RegistryIndex, type UpgradeEcosystem, type UpgradeNet } from "../live/upgrade-sources.js";
import { nearestVersions } from "./upgrade-impact-report.js";

const list = (ids: string[]) => `${ids.slice(0, 5).join(", ")}${ids.length > 5 ? ` and ${ids.length - 5} more` : ""}`;

/** What OSV.dev's records say about `pkg@version`, as one or two sentences ("" when nothing affects it). */
export function targetFactsText(pkg: string, version: string, facts: { ids: string[]; malware: string[] }): string {
  if (facts.malware.length > 0) {
    return `MALWARE: ${pkg} ${version} is a malicious release (${list(facts.malware)}); never install it.`;
  }
  if (facts.ids.length > 0) return `${version} is affected by ${list(facts.ids)}: do not move to it.`;
  return "";
}

/** The error for a `to_version` the registry does not serve. */
export async function notPublishedText(
  ctx: { net: UpgradeNet },
  eco: UpgradeEcosystem,
  index: RegistryIndex,
  name: string,
  wanted: string,
  published: string[],
): Promise<string> {
  const unpublished = index.unpublished?.includes(wanted) ?? false;
  // Only a concrete version is asked of OSV.dev (never a tag or a range).
  const concrete = /^v?\d+(?:\.\d+){1,2}(?:[-+.][0-9A-Za-z.+-]+)?$/.test(wanted);
  const facts = concrete ? await getOsvRecordFacts(ctx.net, eco, index.name, wanted) : null;
  const known = facts ? targetFactsText(index.name, wanted, facts) : "";
  const near = nearestVersions(published, wanted);
  const nearText = near.length > 0 ? ` Nearest published versions: ${near.join(", ")}.` : " No published version is near it: pass a release number, or omit to_version for the newest stable release.";
  const head = unpublished
    ? `${name}@${wanted} was unpublished from ${eco}: the registry lists it but no longer serves it.`
    : `${name}@${wanted} is not published on ${eco}.`;
  return `${known ? `${known} ` : ""}${head}${nearText}`;
}
