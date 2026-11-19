// SPDX-License-Identifier: Apache-2.0
/**
 * A go.mod saved with CRLF line endings retracts what it says it retracts: read line by line with
 * only "\n" as the separator, no `retract` directive matched and a retracted release came back
 * proceed.
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach, vi } from "vitest";
import Database from "better-sqlite3";
import { LiveIntelligence } from "../live/index.js";
import { parseRetractions } from "../live/go-releases.js";
import { executeDependencyCheck } from "../tools/dependency-check.js";
import type { FourDADatabase } from "../db.js";
import { emptyNet, onlineForTests, stubNet, type Net } from "./helpers/a1119-check-net.js";

const noDb = null as unknown as FourDADatabase;
const NOW = new Date("2026-11-19T00:00:00Z");
const daysAgo = (n: number) => new Date(NOW.getTime() - n * 86_400_000).toISOString();

const LF_MOD = "module example.com/crlf\n\ngo 1.22\n\nretract v1.1.0 // data loss on upgrade\n\nretract (\n\tv1.3.0 // bad tag\n\t[v1.4.0, v1.4.2] // broken build\n)\n";
const CRLF_MOD = LF_MOD.replace(/\n/g, "\r\n");

let net: Net;
let restore: () => void;
beforeAll(() => {
  restore = onlineForTests();
});
afterAll(() => restore());
beforeEach(() => {
  net = emptyNet();
  const versions = ["v1.0.0", "v1.1.0", "v1.2.0", "v1.3.0", "v1.4.1", "v1.5.0"];
  net.go["example.com/crlf"] = {
    info: Object.fromEntries(versions.map((v, i) => [v, daysAgo(400 - i * 30)])),
    mods: { "*": CRLF_MOD },
  };
  stubNet(net);
});
afterEach(() => vi.unstubAllGlobals());

const check = async (items: unknown[]) => executeDependencyCheck(noDb, { items }, new LiveIntelligence(new Database(":memory:")), { now: NOW });

describe("go.mod retractions with CRLF line endings", () => {
  it("parses the same retractions from a CRLF file as from an LF one, with no carriage return left in a rationale", () => {
    const lf = parseRetractions(LF_MOD);
    expect(lf).toEqual([
      { low: "v1.1.0", high: "v1.1.0", rationale: "data loss on upgrade" },
      { low: "v1.3.0", high: "v1.3.0", rationale: "bad tag" },
      { low: "v1.4.0", high: "v1.4.2", rationale: "broken build" },
    ]);
    expect(parseRetractions(CRLF_MOD)).toEqual(lf);
    // A file with bare carriage returns (classic Mac) reads the same.
    expect(parseRetractions(LF_MOD.replace(/\n/g, "\r"))).toEqual(lf);
  });

  it("a release the CRLF go.mod retracts is avoid, never proceed", async () => {
    const out = await check([
      { ecosystem: "Go", package: "example.com/crlf", to: "v1.1.0" },
      { ecosystem: "Go", package: "example.com/crlf", to: "v1.4.1" },
      { ecosystem: "Go", package: "example.com/crlf", to: "v1.2.0" },
    ]);
    const [single, interval, kept] = out.results;
    expect(single.verdict).toBe("avoid");
    expect(single.signals.find((s) => s.id === "yanked_or_deprecated")).toMatchObject({ value: { retracted: true }, effect: "avoid", quoted_from_registry: "retracted: data loss on upgrade" });
    expect(interval.verdict).toBe("avoid");
    expect(interval.signals.find((s) => s.id === "yanked_or_deprecated")).toMatchObject({ value: { retracted: true } });
    // One it does not retract is not withdrawn.
    expect(kept.signals.find((s) => s.id === "yanked_or_deprecated")).toMatchObject({ value: null, effect: "proceed" });
  });

  it('"latest" and a constraint never resolve to a retracted release', async () => {
    net.go["example.com/crlf"].mods = { "*": "module example.com/crlf\r\n\r\nretract v1.5.0 // published by mistake\r\n" };
    const out = await check([
      { ecosystem: "Go", package: "example.com/crlf", to: "latest" },
      { ecosystem: "Go", package: "example.com/crlf", to: "v1" },
    ]);
    expect(out.results[0].to).toBe("v1.4.1");
    expect(out.results[1].to).toBe("v1.4.1");
  });
});
