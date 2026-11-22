// SPDX-License-Identifier: Apache-2.0
/**
 * One feed item per advisory, with the strongest provenance.
 *
 * The desktop app stores an advisory once per source that reports it. Its CVE source's item for
 * CVE-2026-119346 links GHSA-f3mh-rxg3-f5g2 and is grounded in the installed `next`; its OSV
 * source's item for GHSA-f3mh-rxg3-f5g2 links CVE-2026-119346 and is not. Both are one advisory.
 *
 * Only items from advisory sources are merged, and only on evidence that they are the same
 * advisory: the same source id; or each links the other (its URL or its title's leading "[ID]"
 * is the other's source id); or one links the other and their headlines are the same. An id
 * named anywhere else in a title is not enough: "[CVE-2026-128071] Nuxt: Incomplete fix for
 * GHSA-6gq8-jgmh-3ffp" is another advisory. The item kept has the strongest provenance (the
 * first at a tie) and takes the place of the first of its twins.
 */

/** Feed sources whose items are advisory records. */
const FEED_ADVISORY_SOURCES = new Set(["osv", "cve"]);

/** An advisory id as the app's advisory sources write them, whole. */
const ADVISORY_ID = /^(?:CVE-\d{4}-\d{4,}|GHSA(?:-[0-9a-z]{4}){3}|RUSTSEC-\d{4}-\d{4}|PYSEC-\d{4}-\d+|GO-\d{4}-\d+|MAL-\d{4}-\d+|OSV-\d{4}-\d+)$/i;

export interface FeedItemIdentity {
  source_type: string;
  source_id: string;
  url: string | null;
  title: string | null;
}

/** The provenance the app's grounding gives a feed item (RelevantItem.evidence_class). */
export type GroundedEvidenceClass = "osv_verified" | "dependency_grounded" | "semantic_only";

/** A security advisory matched to an installed dependency is osv_verified; any other match dependency_grounded. */
export function groundedEvidenceClass(item: { dep_match_count?: number | null; content_type?: string | null }): GroundedEvidenceClass {
  if ((item.dep_match_count ?? 0) <= 0) return "semantic_only";
  return item.content_type === "security_advisory" ? "osv_verified" : "dependency_grounded";
}

/** Stronger provenance ranks higher. */
export const EVIDENCE_STRENGTH: Record<GroundedEvidenceClass | "keyword_heuristic", number> = {
  osv_verified: 3,
  dependency_grounded: 2,
  semantic_only: 1,
  keyword_heuristic: 0,
};

function advisoryId(text: string | null | undefined): string | null {
  const t = (text ?? "").trim();
  return ADVISORY_ID.test(t) ? t.toUpperCase() : null;
}

/** The id an advisory page's URL ends with (…/advisories/GHSA-…, …/vuln/detail/CVE-…, …/RUSTSEC-….html, ?id=CVE-…). */
function urlId(url: string | null): string | null {
  if (!url) return null;
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return null;
  }
  const last = parsed.pathname.replace(/\/+$/, "").split("/").pop() ?? "";
  return advisoryId(last.replace(/\.(?:html|json)$/i, "")) ?? advisoryId(parsed.searchParams.get("id"));
}

/** The "[ID]" a title starts with. */
function titleId(title: string | null): string | null {
  const m = /^\s*\[([^\]]{1,64})\]/.exec(title ?? "");
  return m ? advisoryId(m[1]) : null;
}

/** The title after its "[ID]", in lower case with single spaces. */
function headline(title: string | null): string {
  return (title ?? "").replace(/^\s*\[[^\]]{1,64}\]\s*/, "").toLowerCase().replace(/\s+/g, " ").trim();
}

/** Whether `a` points at `b`: its URL or title id is `b`'s source id. */
function links(a: FeedItemIdentity, b: FeedItemIdentity): boolean {
  const target = advisoryId(b.source_id);
  return target !== null && (urlId(a.url) === target || titleId(a.title) === target);
}

/** One headline is the other with a prefix ("next: Next.js: …" and "Next.js: …"); short ones never match. */
function sameHeadline(a: FeedItemIdentity, b: FeedItemIdentity): boolean {
  const [x, y] = [headline(a.title), headline(b.title)];
  return x.length >= 20 && y.length >= 20 && (x.endsWith(y) || y.endsWith(x));
}

function sameAdvisory(a: FeedItemIdentity, b: FeedItemIdentity): boolean {
  const idA = advisoryId(a.source_id);
  if (idA !== null && idA === advisoryId(b.source_id)) return true;
  const ab = links(a, b);
  const ba = links(b, a);
  return (ab && ba) || ((ab || ba) && sameHeadline(a, b));
}

/**
 * `items` with each advisory once: twins from the advisory sources collapse to the one with the
 * highest `strength`, in the place of the first twin. Every other item passes through in order.
 */
export function oneItemPerAdvisory<T extends FeedItemIdentity>(items: readonly T[], strength: (item: T) => number): T[] {
  const slots: Array<{ kept: T; members: T[] }> = [];
  for (const item of items) {
    const advisory = FEED_ADVISORY_SOURCES.has(item.source_type) && advisoryId(item.source_id) !== null;
    const slot = advisory ? slots.find((s) => FEED_ADVISORY_SOURCES.has(s.kept.source_type) && s.members.some((m) => sameAdvisory(m, item))) : undefined;
    if (!slot) {
      slots.push({ kept: item, members: [item] });
      continue;
    }
    slot.members.push(item);
    if (strength(item) > strength(slot.kept)) slot.kept = item;
  }
  return slots.map((s) => s.kept);
}
