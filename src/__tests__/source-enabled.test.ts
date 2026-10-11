// SPDX-License-Identifier: Apache-2.0
/**
 * Items from sources the user turned off in the desktop app stay out of every
 * feed-reading tool (app schema 126, AD-054: social/editorial "interests" are
 * opt-in). The app's rule is `source_class::enabled_source_sql`:
 *
 *   <col> NOT IN (SELECT source_type FROM sources WHERE enabled = 0)
 *
 * so a type with no `sources` row counts as on, and a database without the
 * `sources.enabled` column is read unfiltered, as before. Offline: an
 * in-memory database built from the vendored app schema.
 */
import { describe, it, expect, vi } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import Database from "better-sqlite3";
import { FourDADatabase } from "../db.js";
import { dispatchTool, sourcesNote } from "../tool-dispatch.js";
import { loadCandidates } from "../tools/knowledge-gap-citations.js";
import { judgedReadingFor, type TaskPackage } from "../tools/briefing-task-scope.js";
import { executeGetActionableSignals } from "../tools/get-actionable-signals.js";
// @ts-expect-error -- plain ESM helper shared with scripts/app-schema-contract.mjs
import { loadAppSchema } from "../../scripts/app-schema-loader.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const SCHEMA = fs.readFileSync(path.resolve(here, "..", "..", "contract", "app-schema.sql"), "utf-8");

type Variant = "current" | "no-enabled-column" | "no-sources-table";

/**
 * hackernews: turned off. reddit: on. osv: on (a stack source).
 * lobsters: items but no `sources` row at all.
 */
function appDb(variant: Variant = "current"): { db: FourDADatabase; raw: Database.Database } {
  const raw = new Database(":memory:");
  loadAppSchema(raw, SCHEMA);
  if (variant !== "current") raw.exec("DROP TABLE sources");
  if (variant === "no-enabled-column") {
    // The shape of a registry with no on/off column.
    raw.exec(`CREATE TABLE sources (id INTEGER PRIMARY KEY AUTOINCREMENT, source_type TEXT NOT NULL UNIQUE, name TEXT NOT NULL)`);
  }
  if (variant === "current") {
    const src = raw.prepare("INSERT INTO sources (source_type, name, enabled) VALUES (?, ?, ?)");
    src.run("hackernews", "Hacker News", 0);
    src.run("reddit", "Reddit", 1);
    src.run("osv", "OSV", 1);
  } else if (variant === "no-enabled-column") {
    const src = raw.prepare("INSERT INTO sources (source_type, name) VALUES (?, ?)");
    for (const t of ["hackernews", "reddit", "osv"]) src.run(t, t);
  }
  const item = raw.prepare(
    `INSERT INTO source_items (source_type, source_id, url, title, content, content_hash, embedding,
                               relevance_score, feed_relevant, signal_type, signal_priority, content_type)
     VALUES (?, ?, ?, ?, ?, ?, X'00', 0.9, 1, 'tool_discovery', 'medium', NULL)`,
  );
  const judge = raw.prepare(
    `INSERT INTO llm_judgments (source_item_id, relevance_score, explanation, confidence, model) VALUES (?, 0.9, 'ok', 0.9, 'test')`,
  );
  for (const [type, title] of [
    ["hackernews", "tokio 2.0 released with a new scheduler"],
    ["reddit", "tokio deep dive: the runtime internals"],
    ["osv", "[GHSA-xxxx] tokio: race in the scheduler"],
    ["lobsters", "tokio and the async book"],
  ] as const) {
    const id = Number(item.run(type, `${type}-1`, `https://example.com/${type}`, title, title, `h-${type}`).lastInsertRowid);
    judge.run(id);
  }
  const db = Object.create(FourDADatabase.prototype) as FourDADatabase;
  (db as unknown as { db: Database.Database }).db = raw;
  return { db, raw };
}

const sourcesOf = (items: Array<{ source_type: string }>) => [...new Set(items.map((i) => i.source_type))].sort();

const tokio: TaskPackage = {
  name: "tokio",
  ecosystem: "crates.io",
  installed: ["1.40.0"],
  direct: true,
  dev: false,
  requested_from: null,
  requested_to: null,
} as TaskPackage;

describe("turned-off sources (sources.enabled = 0)", () => {
  it("get_relevant_content leaves them out, keeps sources with no row, and says so", async () => {
    const { db } = appDb();
    expect(sourcesOf(db.getRelevantContent(0.35, undefined, 20, 24))).toEqual(["lobsters", "osv", "reddit"]);

    const res = await dispatchTool("get_relevant_content", db, {});
    const payload = res.structuredContent as { sources_note?: string; items: Array<{ source_type: string }> };
    expect(sourcesOf(payload.items)).toEqual(["lobsters", "osv", "reddit"]);
    expect(payload.sources_note).toBe(
      "1 interest source is turned off in the 4DA app; their items are not included. Turn them on in Settings → Sources.",
    );
  });

  it("asking for a turned-off source by name returns nothing from it", async () => {
    const { db } = appDb();
    const res = await dispatchTool("get_relevant_content", db, { source_type: "hackernews" });
    const payload = res.structuredContent as { sources_note?: string; items: unknown[] };
    expect(payload.items).toEqual([]);
    expect(payload.sources_note).toMatch(/turned off/);
  });

  it("get_actionable_signals leaves them out", () => {
    const { db } = appDb();
    const out = executeGetActionableSignals(db, {}, null);
    expect(out.signals.length).toBeGreaterThan(0);
    expect(out.signals.some((s) => s.source_type === "hackernews")).toBe(false);
  });

  it("knowledge_gaps candidates and what_should_i_know reading leave them out", () => {
    const { db } = appDb();
    expect(sourcesOf(loadCandidates(db))).toEqual(["lobsters", "osv", "reddit"]);
    const reading = judgedReadingFor(db, [tokio], 10);
    expect(reading.length).toBeGreaterThan(0);
    expect(reading.some((r) => r.source === "hackernews")).toBe(false);
  });

  it("probes the sources.enabled column once per connection", () => {
    const { db } = appDb();
    const probe = vi.spyOn(db, "hasColumn");
    db.getRelevantContent(0.35, undefined, 20, 24);
    db.getRelevantContent(0.35, undefined, 20, 24);
    db.disabledSources();
    expect(probe.mock.calls.filter(([t, c]) => t === "sources" && c === "enabled")).toHaveLength(1);
  });
});

describe.each(["no-enabled-column", "no-sources-table"] as const)("an older database (%s)", (variant) => {
  it("is read unfiltered, without error and without a note", async () => {
    const { db } = appDb(variant);
    expect(db.enabledSourceClause("source_type")).toBe("");
    expect(db.disabledSources()).toEqual([]);
    expect(sourcesOf(db.getRelevantContent(0.35, undefined, 20, 24))).toEqual(["hackernews", "lobsters", "osv", "reddit"]);
    expect(sourcesOf(loadCandidates(db))).toEqual(["hackernews", "lobsters", "osv", "reddit"]);

    const res = await dispatchTool("get_relevant_content", db, {});
    expect(res.isError).toBeUndefined();
    const payload = res.structuredContent as { sources_note?: string; items: Array<{ source_type: string }> };
    expect(payload.sources_note).toBeUndefined();
    expect(sourcesOf(payload.items)).toEqual(["hackernews", "lobsters", "osv", "reddit"]);
  });
});

describe("a database where every source is on", () => {
  it("filters nothing and adds no note", async () => {
    const { db, raw } = appDb();
    raw.exec("UPDATE sources SET enabled = 1");
    const res = await dispatchTool("get_relevant_content", db, {});
    const payload = res.structuredContent as { sources_note?: string; items: Array<{ source_type: string }> };
    expect(payload.sources_note).toBeUndefined();
    expect(sourcesOf(payload.items)).toEqual(["hackernews", "lobsters", "osv", "reddit"]);
  });
});

describe("sourcesNote", () => {
  it("counts what the database says, and calls them interests only when none is a stack source", () => {
    expect(sourcesNote([])).toBeNull();
    expect(sourcesNote(["hackernews", "reddit"])).toMatch(/^2 interest sources are turned off/);
    expect(sourcesNote(["hackernews", "osv"])).toMatch(/^2 sources are turned off/);
  });
});
