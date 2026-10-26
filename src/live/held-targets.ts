// SPDX-License-Identifier: Apache-2.0
/**
 * Fix targets judged by what they hold, not only by their own advisories (audit 6.2.5 D-4).
 *
 * cleanFixTarget (fix-paths.ts) picks the smallest release that no advisory of the package
 * affects. For npm that is not yet a clean fix: express 4.20.0 is clear of express's advisories
 * and exact-pins qs 6.11.0, cookie 0.6.0, body-parser 1.20.3 and path-to-regexp 0.1.10, all
 * affected; 4.22.0 to 4.22.2 require qs ranges no clean qs is in. NodeGoat's scan said
 * "Upgrade express 4.16.4 -> 4.20.0", and agents installed it.
 *
 * Here a checked npm target is judged with its held dependencies (held-dependencies.ts). When
 * one is affected, the next releases on its line that the package's own advisories leave clean are
 * judged too, HELD_CANDIDATES in all and in ONE advisory lookup for every target at once, and the
 * smallest that holds nothing affected becomes the target, with the reason. None clean among
 * them: the target stays, flagged `heldBlocked`; the check could not run (registry, OSV, time):
 * flagged `heldUnchecked`. Either way the target is no longer reported as checked against every
 * advisory (targetCheckedAll). A release that holds nothing needs no lookup at all.
 */

import { heldAdvisories, heldCandidates, type AdvisoryQuery, type HeldCheck } from "./held-dependencies.js";
import { cleanReleases } from "./osv-ranges.js";
import { lineNoticeText, type FixPathSources, type FixTargetResult } from "./fix-paths.js";

export interface HeldTargetItem {
  key: string;
  name: string;
  installed?: string | null;
  clean: FixTargetResult;
}

/**
 * The npm targets of `items`, re-judged by what they hold, within `deadline`. Returns the
 * replacement result per key; keys with nothing held (or not npm, or not checked) are absent.
 */
export async function withHeldTargets(
  sources: FixPathSources,
  query: AdvisoryQuery,
  items: HeldTargetItem[],
  deadline: number,
): Promise<Map<string, FixTargetResult>> {
  const out = new Map<string, FixTargetResult>();
  // Only a target that was checked against the package's own advisories can be moved on from;
  // one that was not is already reported as checked against the installed version's advisories only.
  const todo = items.filter((i) => i.clean.target && !i.clean.advisoriesUnread);
  const plans: Array<{ item: HeldTargetItem; candidates: string[]; facts: NonNullable<Awaited<ReturnType<FixPathSources["releaseFacts"]>>> }> = [];
  await Promise.all(
    todo.map(async (item) => {
      const target = item.clean.target!;
      const facts = await settle(sources.releaseFacts("npm", item.name), deadline);
      if (!facts) {
        out.set(item.key, { ...item.clean, heldUnchecked: "the npm registry could not be read in time" });
        return;
      }
      if (!facts.heldSpecs) {
        out.set(item.key, { ...item.clean, heldUnchecked: "the npm registry facts carry no dependency specs" });
        return;
      }
      if (!facts.heldSpecs[target]) return; // holds nothing: what it installs is ranges a refresh moves
      const advisories = await settle(sources.packageAdvisories("npm", item.name), deadline);
      // Without the package's own advisory list no later release can be judged; the target alone still can.
      const candidates = advisories ? heldCandidates(target, facts, advisories, item.installed) : [target];
      plans.push({ item, candidates, facts });
    }),
  );
  if (plans.length === 0) return out;

  const releases = plans.flatMap((p) => p.candidates.map((v) => ({ key: `${p.item.name}@${v}`, specs: p.facts.heldSpecs![v] ?? {} })));
  const checks = await heldAdvisories(sources, query, releases, deadline);

  for (const { item, candidates, facts } of plans) {
    const target = item.clean.target!;
    const at = (v: string): HeldCheck => checks.get(`${item.name}@${v}`) ?? { status: "unchecked", reason: "the check did not finish in time" };
    const own = at(target);
    if (own.status === "unchecked") {
      out.set(item.key, { ...item.clean, heldUnchecked: own.reason });
      continue;
    }
    if (own.affected.length === 0) continue;
    const past: NonNullable<FixTargetResult["heldPast"]> = [];
    let chosen: string | null = null;
    for (const v of candidates) {
      const c = at(v);
      if (c.status === "checked" && c.affected.length === 0) {
        chosen = v;
        break;
      }
      // An unchecked candidate is passed silently: the one chosen after it was itself judged clean.
      if (c.status === "checked") past.push({ version: v, affected: c.affected });
    }
    if (!chosen) {
      out.set(item.key, { ...item.clean, heldBlocked: { affected: own.affected, searched: candidates } });
      continue;
    }
    const view = cleanReleases((await settle(sources.packageAdvisories("npm", item.name), deadline)) ?? [], "npm", facts.versions, item.installed);
    const notice = facts.lineNotices?.[chosen];
    const { targetNotice: _old, ...rest } = item.clean;
    out.set(item.key, {
      ...rest,
      target: chosen,
      stillAffectedBy: view.remains(chosen),
      heldFrom: target,
      heldPast: past,
      ...(notice ? { targetNotice: lineNoticeText(chosen, notice) } : {}),
    });
  }
  return out;
}

/** The value, or null when it fails or `deadline` passes first. */
async function settle<T>(work: Promise<T | null>, deadline: number): Promise<T | null> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const late = new Promise<null>((resolve) => {
    timer = setTimeout(() => resolve(null), Math.max(0, deadline - Date.now()));
  });
  try {
    return await Promise.race([work.catch(() => null), late]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}
