// SPDX-License-Identifier: Apache-2.0
/**
 * A signal's priority follows the presented grade. The 4DA feed's advisory rows carry the app
 * pipeline's own stamp: GHSA-m665-v7pm-7grj (zip, CVSS 9.4, rated critical by the advisory) came
 * out medium and RUSTSEC-2026-0461 (rmcp, CVSS 7.5, high) came out critical. A feed row about an
 * advisory the scan found is the same finding as the scan's signal, which carries the scan's grade
 * and says where the advisory's own grade is higher; any other advisory row is graded by the
 * advisory's own grade where the app's advisory copy knows it.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as fs from "node:fs";
import { executeGetActionableSignals } from "../tools/get-actionable-signals.js";
import { appDb, emptyNetwork, feedRow, liveFor, projectDir, stubNetwork, zipUnderDocx, type Network } from "./helpers/a1123-advice.js";

let dir: string;
let net: Network;

beforeEach(() => {
  dir = projectDir();
  net = emptyNetwork();
  zipUnderDocx(dir, net);
  stubNetwork(net);
});

afterEach(() => {
  vi.unstubAllGlobals();
  fs.rmSync(dir, { recursive: true, force: true });
});

function feed() {
  const { db, raw } = appDb();
  feedRow(raw, {
    source_type: "osv",
    source_id: "GHSA-m665-v7pm-7grj",
    title: "[GHSA-m665-v7pm-7grj] zip: zip: Critical Parser Differential & Security Control Bypass",
    content: "zip (crates.io)\nCritical Parser Differential",
    signal_priority: "advisory",
  });
  feedRow(raw, {
    source_type: "osv",
    source_id: "RUSTSEC-2026-0461",
    title: "[RUSTSEC-2026-0461] rmcp: Unbounded tool schema cache in Streamable HTTP server transport",
    content: "rmcp (crates.io)\nUnbounded tool schema cache",
    signal_priority: "critical",
  });
  // The app's copy of the advisory: its own grade.
  raw
    .prepare("INSERT INTO osv_advisories (advisory_id, summary, package_name, ecosystem, cvss_score, severity_label, aliases) VALUES (?, ?, ?, ?, ?, ?, ?)")
    .run("RUSTSEC-2026-0461", "Unbounded tool schema cache", "rmcp", "crates.io", 7.5, "high", JSON.stringify(["GHSA-rmcp-0461-xxxx"]));
  return db;
}

describe("signal priorities follow the presented grade", () => {
  it("a feed row about an advisory the scan found is that finding: one signal, at the scan's grade, saying the advisory rates it critical", async () => {
    const out = await executeGetActionableSignals(feed(), { signal_type: "security_alert", limit: 50 }, await liveFor(dir));

    const m665 = out.signals.filter((s) => s.title.includes("GHSA-m665-v7pm-7grj") || s.triggers.includes("GHSA-m665-v7pm-7grj"));
    expect(m665).toHaveLength(1);
    expect(m665[0]).toMatchObject({ source_type: "osv_live", signal_priority: "high" });
    expect(m665[0].action).toMatch(/\(the advisory rates it critical; graded high as a transitive-only dependency\)$/);
    // No zip signal is below high: every one of them is the scan's grade.
    for (const s of out.signals.filter((x) => /\bzip\b/.test(x.title))) expect(s.signal_priority).toBe("high");
  });

  it("an advisory row the scan did not find is graded by the advisory's own grade, and says it was not matched here", async () => {
    const out = await executeGetActionableSignals(feed(), { signal_type: "security_alert", limit: 50 }, await liveFor(dir));

    const rmcp = out.signals.find((s) => s.title.includes("RUSTSEC-2026-0461"))!;
    expect(rmcp.signal_priority).toBe("high");
    expect(rmcp.action).toMatch(/not matched to any installed version this project's vulnerability scan read/);
  });

  it("without a completed scan an advisory row is NOT CHECKED against the installed versions", async () => {
    net.osvDown = 503;
    const out = await executeGetActionableSignals(feed(), { signal_type: "security_alert", limit: 50 }, await liveFor(dir));

    const rmcp = out.signals.find((s) => s.title.includes("RUSTSEC-2026-0461"))!;
    expect(rmcp.signal_priority).toBe("high");
    expect(rmcp.action).toMatch(/NOT CHECKED against this project's installed versions/);
  });
});
