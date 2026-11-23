// SPDX-License-Identifier: Apache-2.0
/**
 * The feed tools never widen a window the caller asked for, and say so when they widen their own.
 * get_relevant_content and get_actionable_signals went 24 h (48 h) -> 168 h -> 720 h when nothing
 * matched, with no word of it: `since_hours: 1` returned items 3 to 5 days old.
 */

import { describe, expect, it } from "vitest";
import { dispatchTool } from "../tool-dispatch.js";
import { executeGetActionableSignals } from "../tools/get-actionable-signals.js";
import { getRelevantContentAnswer } from "../tools/get-relevant-content.js";
import { appDb, feedRow } from "./helpers/a1123-advice.js";

/** An app database whose only feed rows are three to five days old. */
function oldFeed() {
  const { db, raw } = appDb();
  feedRow(raw, { source_type: "crates_io", source_id: "tokio-1.99.0", title: "crates.io: tokio v1.99.0", hoursAgo: 72, signal_type: "tech_trend", signal_priority: "medium", content_type: null, relevance: 0.8 });
  feedRow(raw, { source_type: "osv", source_id: "GHSA-old0-0000-0001", title: "[GHSA-old0-0000-0001] hono: old advisory", content: "hono (npm)\nold advisory", hoursAgo: 120, relevance: 0.8 });
  return db;
}

describe("get_relevant_content windows", () => {
  it("a window the caller passed is never widened: nothing matched in it, and the answer says so", () => {
    const out = getRelevantContentAnswer(oldFeed(), { since_hours: 1 });
    expect(Array.isArray(out)).toBe(false);
    expect(out).toMatchObject({ window: { requested_hours: 1, used_hours: 1, widened: false }, item_count: 0, items: [] });
    expect((out as { summary: string }).summary).toMatch(/^Nothing matched in the last 1 hour/);
  });

  it("the default window, widened, carries `window` and a summary that says so", () => {
    const out = getRelevantContentAnswer(oldFeed(), {});
    expect(out).toMatchObject({ window: { requested_hours: 24, used_hours: 168, widened: true } });
    const widened = out as { summary: string; items: Array<{ discovered_ago: string }>; item_count: number };
    expect(widened.summary).toMatch(/widened to the last 168 hours/);
    expect(widened.items.length).toBe(widened.item_count);
    expect(widened.items.length).toBeGreaterThan(0);
  });

  it("through the protocol the items keep their place beside the window", async () => {
    const res = await dispatchTool("get_relevant_content", oldFeed(), { since_hours: 2 });
    const payload = res.structuredContent as { window?: unknown; items: unknown[]; item_count: number; summary?: string };
    expect(payload.window).toEqual({ requested_hours: 2, used_hours: 2, widened: false });
    expect(payload.items).toEqual([]);
    expect(payload.item_count).toBe(0);
  });

  it("a window inside the requested one answers as before: the items, no note", () => {
    const { db, raw } = appDb();
    feedRow(raw, { source_type: "crates_io", source_id: "serde-1.0.300", title: "crates.io: serde v1.0.300", hoursAgo: 2, signal_type: null, signal_priority: null, content_type: null, relevance: 0.8 });
    const out = getRelevantContentAnswer(db, { since_hours: 24 });
    expect(Array.isArray(out)).toBe(true);
  });
});

describe("get_actionable_signals windows", () => {
  it("a window the caller passed is never widened", async () => {
    const out = await executeGetActionableSignals(oldFeed(), { since_hours: 1 }, null);
    expect(out.signals.filter((s) => s.source_type !== "osv_live")).toEqual([]);
    expect(out.window).toEqual({ requested_hours: 1, used_hours: 1, widened: false });
    expect(out.note).toMatch(/Nothing in the 4DA feed matched in the last 1 hour/);
    expect(out.note).not.toMatch(/No source items in the database/);
  });

  it("the default window, widened, carries `window` and the note says so", async () => {
    const out = await executeGetActionableSignals(oldFeed(), {}, null);
    expect(out.window).toEqual({ requested_hours: 48, used_hours: 168, widened: true });
    expect(out.note).toMatch(/widened to the last 168 hours/);
    expect(out.signals.some((s) => s.source_type === "osv")).toBe(true);
  });
});
