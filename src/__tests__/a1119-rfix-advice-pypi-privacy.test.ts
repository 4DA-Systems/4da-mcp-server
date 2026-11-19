// SPDX-License-Identifier: Apache-2.0
/**
 * dependency_check never asks PyPI for the per-release document of the installed (`from`)
 * version unless that version is the one being judged (`to`); the privacy note says exactly what
 * is sent: per-release documents of the releases being judged, and lookups of what they require.
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach, vi } from "vitest";
import Database from "better-sqlite3";
import { LiveIntelligence } from "../live/index.js";
import { executeDependencyCheck } from "../tools/dependency-check.js";
import type { FourDADatabase } from "../db.js";
import { emptyNet, onlineForTests, stubNet, type Net } from "./helpers/a1119-check-net.js";

const noDb = null as unknown as FourDADatabase;
const NOW = new Date("2026-11-19T00:00:00Z");
const daysAgo = (n: number) => new Date(NOW.getTime() - n * 86_400_000).toISOString();
const PKG = "certstore-lite";
const VERSIONS = ["2025.1.31", "2025.4.26", "2025.6.15", "2025.8.3"];

let net: Net;
let restore: () => void;
beforeAll(() => {
  restore = onlineForTests();
});
afterAll(() => restore());
beforeEach(() => {
  net = emptyNet();
  net.pypi[PKG] = {
    releases: Object.fromEntries(VERSIONS.map((v, i) => [v, [{ upload_time_iso_8601: daysAgo(400 - i * 60) }]])),
    requires: Object.fromEntries(VERSIONS.map((v) => [v, null])),
  };
  stubNet(net);
});
afterEach(() => vi.unstubAllGlobals());

const live = () => new LiveIntelligence(new Database(":memory:"));
const releaseDocs = () => net.requests.filter((q) => new RegExp(`/pypi/${PKG}/[^/]+/json$`).test(q));

describe("PyPI per-release documents", () => {
  it("a constraint check never requests the installed version's own document", async () => {
    const out = await executeDependencyCheck(noDb, { items: [{ ecosystem: "PyPI", package: PKG, from: "2025.6.15", to: ">=2025.1" }] }, live(), { now: NOW });
    expect(out.results[0].verdict).not.toBe("avoid");
    expect(releaseDocs().some((q) => q.includes("/2025.6.15/json"))).toBe(false);
  });

  it("from == to: the judged release's document may be read, and the note says what was sent", async () => {
    const out = await executeDependencyCheck(noDb, { items: [{ ecosystem: "PyPI", package: PKG, from: "2025.6.15", to: "2025.6.15" }] }, live(), { now: NOW });
    expect(releaseDocs()).toEqual([`GET https://pypi.org/pypi/${PKG}/2025.6.15/json`]);
    const privacy = JSON.stringify(out).match(/"privacy":"([^"]*)"/)?.[1] ?? "";
    expect(privacy).toContain("per-release documents of the releases being judged");
    expect(privacy).not.toMatch(/the installed version was sent to no registry but the Go proxy/);
  });
});
