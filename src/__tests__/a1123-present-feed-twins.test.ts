// SPDX-License-Identifier: Apache-2.0
/**
 * One feed item per advisory, with the stronger provenance. The desktop app stores an advisory
 * once per source that reports it: its CVE source held CVE-2026-119346 (linking
 * GHSA-f3mh-rxg3-f5g2, grounded in the installed `next`: `osv_verified`) and its OSV source held
 * GHSA-f3mh-rxg3-f5g2 (linking CVE-2026-119346, not grounded: `semantic_only`). Both reached
 * get_relevant_content and get_actionable_signals: one advisory, two rows, two provenances
 * (the same for CVE-2026-119349 / GHSA-rhh4-g77r-r9qj). An id merely named in another advisory's
 * title is a different advisory and stays.
 */
import { describe, expect, it } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import Database from "better-sqlite3";
import { FourDADatabase } from "../db.js";
import { dispatchTool } from "../tool-dispatch.js";
import { executeGetActionableSignals } from "../tools/get-actionable-signals.js";
import { oneItemPerAdvisory } from "../feed-advisory-twins.js";
// @ts-expect-error -- plain ESM helper shared with scripts/app-schema-contract.mjs
import { loadAppSchema } from "../../scripts/app-schema-loader.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const SCHEMA = fs.readFileSync(path.resolve(here, "..", "..", "contract", "app-schema.sql"), "utf-8");

/** The four rows of the audit's evidence (C1 31-untracked-05), plus an advisory whose title names another. */
const ROWS = [
  { type: "cve", id: "CVE-2026-119346", url: "https://github.com/advisories/GHSA-f3mh-rxg3-f5g2", title: "[CVE-2026-119346] Next.js: HttpOnly cookie exposure through internal response header on Next.js Edge runtime routes", score: 0.8, grounded: true },
  { type: "osv", id: "GHSA-f3mh-rxg3-f5g2", url: "https://nvd.nist.gov/vuln/detail/CVE-2026-119346", title: "[GHSA-f3mh-rxg3-f5g2] next: Next.js: HttpOnly cookie exposure through internal response header on Next.js Edge runtime routes", score: 0.65, grounded: false },
  { type: "osv", id: "GHSA-rhh4-g77r-r9qj", url: "https://nvd.nist.gov/vuln/detail/CVE-2026-119349", title: "[GHSA-rhh4-g77r-r9qj] next: Next.js: Cross-user cache disclosure and poisoning in Next.js", score: 0.85, grounded: false },
  { type: "cve", id: "CVE-2026-119349", url: "https://github.com/advisories/GHSA-rhh4-g77r-r9qj", title: "[CVE-2026-119349] Next.js: Cross-user cache disclosure and poisoning in Next.js", score: 0.8, grounded: true },
  { type: "cve", id: "CVE-2026-128071", url: "https://github.com/advisories/GHSA-f3x9-2chm-73c8", title: "[CVE-2026-128071] Nuxt: Incomplete fix for GHSA-6gq8-jgmh-3ffp: an encoded slash bypasses the check", score: 0.7, grounded: false },
  { type: "osv", id: "GHSA-6gq8-jgmh-3ffp", url: "https://nvd.nist.gov/vuln/detail/CVE-2025-99999", title: "[GHSA-6gq8-jgmh-3ffp] nuxt: Nuxt: path check bypass", score: 0.6, grounded: false },
  { type: "hackernews", id: "hn-1", url: "https://news.ycombinator.com/item?id=1", title: "CVE-2026-119346 explained: Next.js leaks HttpOnly cookies", score: 0.75, grounded: false },
];

function appDb(rows = ROWS): FourDADatabase {
  const raw = new Database(":memory:");
  loadAppSchema(raw, SCHEMA);
  const item = raw.prepare(
    `INSERT INTO source_items (source_type, source_id, url, title, content, content_hash, embedding,
                               relevance_score, feed_relevant, signal_type, signal_priority, content_type)
     VALUES (?, ?, ?, ?, ?, ?, X'00', ?, 1, 'security_alert', 'high', 'security_advisory')`,
  );
  const dep = raw.prepare(`INSERT INTO source_item_dependencies (source_item_id, package_name, ecosystem, match_type, confidence) VALUES (?, 'next', 'npm', 'osv_affected', 1.0)`);
  const judge = raw.prepare(`INSERT INTO llm_judgments (source_item_id, relevance_score, explanation, confidence, model) VALUES (?, 0.9, 'ok', 0.9, 'test')`);
  for (const r of rows) {
    const id = Number(item.run(r.type, r.id, r.url, r.title, r.title, `h-${r.id}`, r.score).lastInsertRowid);
    if (r.grounded) dep.run(id);
    judge.run(id);
  }
  const db = Object.create(FourDADatabase.prototype) as FourDADatabase;
  (db as unknown as { db: Database.Database }).db = raw;
  return db;
}

const idsOf = (items: Array<{ source_id: string }>) => items.map((i) => i.source_id);

describe("oneItemPerAdvisory", () => {
  const item = (r: (typeof ROWS)[number]) => ({ source_type: r.type, source_id: r.id, url: r.url, title: r.title, strength: r.grounded ? 3 : 1 });

  it("keeps one of two items that link each other: the stronger, in the place of the first", () => {
    const out = oneItemPerAdvisory(ROWS.map(item), (i) => i.strength);
    expect(idsOf(out)).toEqual(["CVE-2026-119346", "CVE-2026-119349", "CVE-2026-128071", "GHSA-6gq8-jgmh-3ffp", "hn-1"]);
    // The weaker twin ranked first (GHSA-rhh4 at 0.85): the stronger takes its place.
    const reversed = oneItemPerAdvisory([...ROWS].reverse().map(item), (i) => i.strength);
    expect(idsOf(reversed)).toEqual(["hn-1", "GHSA-6gq8-jgmh-3ffp", "CVE-2026-128071", "CVE-2026-119349", "CVE-2026-119346"]);
  });

  it("merges a one-way link only when the headlines are the same", () => {
    const cve = { source_type: "cve", source_id: "CVE-2026-1", url: "https://github.com/advisories/GHSA-aaaa-bbbb-cccc", title: "[CVE-2026-1] pkg: a long enough headline about the bug", strength: 1 };
    const sameText = { source_type: "osv", source_id: "GHSA-aaaa-bbbb-cccc", url: "https://example.com/blog", title: "[GHSA-aaaa-bbbb-cccc] pkg: pkg: a long enough headline about the bug", strength: 3 };
    const otherText = { ...sameText, title: "[GHSA-aaaa-bbbb-cccc] pkg: something else entirely, a different issue" };
    expect(idsOf(oneItemPerAdvisory([cve, sameText], (i) => i.strength))).toEqual(["GHSA-aaaa-bbbb-cccc"]);
    expect(idsOf(oneItemPerAdvisory([cve, otherText], (i) => i.strength))).toEqual(["CVE-2026-1", "GHSA-aaaa-bbbb-cccc"]);
  });

  it("merges the same advisory id from two advisory sources, and never an item from another source", () => {
    const a = { source_type: "osv", source_id: "GHSA-aaaa-bbbb-cccc", url: null, title: "[GHSA-aaaa-bbbb-cccc] x", strength: 1 };
    const b = { source_type: "cve", source_id: "ghsa-aaaa-bbbb-cccc", url: null, title: "x", strength: 2 };
    const news = { source_type: "reddit", source_id: "GHSA-aaaa-bbbb-cccc", url: null, title: "[GHSA-aaaa-bbbb-cccc] x", strength: 3 };
    expect(idsOf(oneItemPerAdvisory([a, b, news], (i) => i.strength))).toEqual(["ghsa-aaaa-bbbb-cccc", "GHSA-aaaa-bbbb-cccc"]);
  });
});

describe("the feed tools on the app database", () => {
  it("get_relevant_content: one row per advisory, osv_verified kept over semantic_only", async () => {
    const db = appDb();
    const items = db.getRelevantContent(0.35, undefined, 20, 24);
    expect(idsOf(items).sort()).toEqual(["CVE-2026-119346", "CVE-2026-119349", "CVE-2026-128071", "GHSA-6gq8-jgmh-3ffp", "hn-1"]);
    for (const id of ["CVE-2026-119346", "CVE-2026-119349"]) expect(items.find((i) => i.source_id === id)?.evidence_class).toBe("osv_verified");

    const res = await dispatchTool("get_relevant_content", db, {});
    const payload = res.structuredContent as { items: Array<{ source_id: string; evidence_class: string }> };
    expect(idsOf(payload.items)).not.toContain("GHSA-f3mh-rxg3-f5g2");
    expect(idsOf(payload.items)).not.toContain("GHSA-rhh4-g77r-r9qj");
  });

  it("the limit counts advisories, not their twins", () => {
    // The top three by score are GHSA-rhh4 (0.85) and two CVEs (0.8), one of them its twin.
    const items = appDb().getRelevantContent(0.35, undefined, 3, 24);
    expect(items).toHaveLength(3);
    expect(idsOf(items)).not.toContain("GHSA-rhh4-g77r-r9qj");
    expect(idsOf(items)).toEqual(expect.arrayContaining(["CVE-2026-119349", "CVE-2026-119346", "hn-1"]));
  });

  it("get_actionable_signals: one signal per advisory", () => {
    const out = executeGetActionableSignals(appDb(), { signal_type: "security_alert" }, null);
    const urls = out.signals.map((s) => s.url);
    expect(urls.filter((u) => u?.includes("GHSA-f3mh-rxg3-f5g2") || u?.includes("CVE-2026-119346"))).toHaveLength(1);
    expect(urls.filter((u) => u?.includes("GHSA-rhh4-g77r-r9qj") || u?.includes("CVE-2026-119349"))).toHaveLength(1);
  });
});
