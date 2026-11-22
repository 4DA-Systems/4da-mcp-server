// SPDX-License-Identifier: Apache-2.0
/**
 * A maintenance notice ("chrono is unmaintained") is not an advisory with a missing fix: the scan
 * lists it apart, counts it nowhere, and has nothing to upgrade to. The signals and the briefing
 * word it that way, and it never raises a briefing's verdict as a vulnerability would.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as fs from "node:fs";
import { executeGetActionableSignals } from "../tools/get-actionable-signals.js";
import { executeWhatShouldIKnow } from "../tools/what-should-i-know.js";
import { adv, appDb, cargoLock, emptyNetwork, feedRow, liveFor, projectDir, stubNetwork, write, type Network } from "./helpers/a1123-advice.js";

let dir: string;
let net: Network;

const NO_FIX_WORDS = /no fix (version )?(is )?published|No fix is published|no fixed release/i;

beforeEach(() => {
  dir = projectDir();
  net = emptyNetwork();
  write(dir, "Cargo.toml", '[package]\nname = "app"\nversion = "0.1.0"\n\n[dependencies]\nchrono = "0.4"\n');
  write(dir, "Cargo.lock", cargoLock([{ name: "app", version: "0.1.0", deps: ["chrono"], root: true }, { name: "chrono", version: "0.4.45" }]));
  net.advisories.chrono = [
    adv("RUSTSEC-2026-0400", "chrono", [{ introduced: "0" }], "crates.io", "LOW", { summary: "chrono is unmaintained", database_specific: { informational: "unmaintained" } }),
  ];
});

afterEach(() => {
  vi.unstubAllGlobals();
  fs.rmSync(dir, { recursive: true, force: true });
});

describe("maintenance notices are worded as the scan treats them", () => {
  it("the signal for an unmaintained crate says it is a notice, not a vulnerability with no fix", async () => {
    stubNetwork(net);
    const out = await executeGetActionableSignals(appDb().db, { signal_type: "security_alert" }, await liveFor(dir));
    const row = out.signals.find((s) => s.title.includes("(chrono@0.4.45)"))!;
    expect(row).toMatchObject({ signal_priority: "low" });
    expect(row.title.startsWith("MAINTENANCE:")).toBe(true);
    expect(row.action).toMatch(/^Maintenance notice, not a vulnerability: chrono 0\.4\.45/);
    expect(row.action).toMatch(/maintenance_notices/);
    expect(row.action).not.toMatch(NO_FIX_WORDS);
  });

  it("a feed row that is a maintenance notice is low and worded as one", async () => {
    stubNetwork(net);
    const { db, raw } = appDb();
    feedRow(raw, { source_type: "osv", source_id: "RUSTSEC-2024-0436", title: "[RUSTSEC-2024-0436] paste: paste - no longer maintained", content: "paste (crates.io)\nno longer maintained", signal_priority: "alert" });
    const out = await executeGetActionableSignals(db, { signal_type: "security_alert" }, await liveFor(dir));
    const row = out.signals.find((s) => s.title.includes("RUSTSEC-2024-0436"))!;
    expect(row.signal_priority).toBe("low");
    expect(row.action).toMatch(/^Maintenance notice \(advisory record\), not a vulnerability/);
    expect(row.action).not.toMatch(NO_FIX_WORDS);
  });

  it("the briefing names the task package's notice as a notice and does not call it unfixed", async () => {
    stubNetwork(net);
    const briefing = await executeWhatShouldIKnow(appDb().db, { task: "bump the chrono crate" }, await liveFor(dir));
    const chrono = briefing.task_dependencies.find((d) => d.package === "chrono")!;
    expect(chrono.vulnerabilities).toEqual([]);
    expect(chrono.maintenance_notices).toEqual([{ id: "RUSTSEC-2026-0400", installed: "0.4.45", summary: "chrono is unmaintained" }]);
    expect(briefing.summary).toMatch(/1 maintenance notice on them \(not a vulnerability\)/);
    expect(JSON.stringify(briefing.advisories)).not.toMatch(NO_FIX_WORDS);
    expect(briefing.delegation_assessment.level).not.toBe("human_only");
  });

  it("a feed maintenance notice stamped critical does not make an unscanned task human_only", async () => {
    net.osvDown = 503;
    stubNetwork(net);
    const { db, raw } = appDb();
    feedRow(raw, { source_type: "osv", source_id: "RUSTSEC-2026-0400", title: "[RUSTSEC-2026-0400] chrono: chrono is unmaintained", content: "chrono (crates.io)\nunmaintained", signal_priority: "critical" });
    const briefing = await executeWhatShouldIKnow(db, { task: "bump the chrono crate" }, await liveFor(dir));
    expect(briefing.scan_status).toBe("unavailable");
    const row = briefing.advisories.find((a) => a.title.includes("RUSTSEC-2026-0400"))!;
    expect(row.priority).toBe("low");
    expect(row.action).toMatch(/maintenance notice/i);
    expect(briefing.delegation_assessment.level).toBe("unknown");
  });
});
