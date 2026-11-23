// SPDX-License-Identifier: Apache-2.0
/**
 * get_actionable_signals as the first call of a session: it starts the project's vulnerability
 * scan and waits for it, as what_should_i_know, upgrade_planner and dependency_health do. When the
 * scan cannot complete, the answer says NOT CHECKED: an empty list is never the answer for a
 * project nothing was checked for.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as fs from "node:fs";
import { executeGetActionableSignals } from "../tools/get-actionable-signals.js";
import { adv, appDb, emptyNetwork, fixedIn, liveFor, npmProject, projectDir, stubNetwork, type Network } from "./helpers/a1123-advice.js";

let dir: string;
let net: Network;

beforeEach(() => {
  dir = projectDir();
  net = emptyNetwork();
  npmProject(dir, { minimist: "^1.2.0" }, { minimist: { version: "1.2.5" } });
  net.advisories.minimist = [adv("GHSA-xvch-5gv4-984h", "minimist", fixedIn("1.2.6"), "npm", "CRITICAL")];
  net.npm.minimist = { latest: "1.2.8", versions: { "1.2.5": {}, "1.2.6": {}, "1.2.8": {} } };
});

afterEach(() => {
  vi.unstubAllGlobals();
  fs.rmSync(dir, { recursive: true, force: true });
});

describe("get_actionable_signals as the first call of a session", () => {
  it("starts the scan, waits for it, and reports the vulnerable copy", async () => {
    stubNetwork(net);
    const li = await liveFor(dir);
    expect(li.getVulnerabilities()).toBeNull();

    const out = await executeGetActionableSignals(appDb().db, { signal_type: "security_alert" }, li);

    const live = out.signals.filter((s) => s.source_type === "osv_live");
    expect(live.map((s) => s.title)).toEqual([expect.stringContaining("(minimist@1.2.5)")]);
    expect(live[0].signal_priority).toBe("critical");
    expect(out.total).toBe(1);
    expect(out.scan).toMatchObject({ status: "ready", scanned_at: expect.any(String) });
    expect(out.note ?? "").not.toMatch(/NOT CHECKED/);
  });

  it("says NOT CHECKED, first, when OSV.dev cannot be reached", async () => {
    net.osvDown = 503;
    stubNetwork(net);
    const li = await liveFor(dir);

    const out = await executeGetActionableSignals(appDb().db, { signal_type: "security_alert" }, li);

    expect(out.signals.filter((s) => s.source_type === "osv_live")).toEqual([]);
    expect(out.scan.status).toBe("unavailable");
    expect(out.note).toMatch(/^NOT CHECKED: /);
    expect(out.note).toMatch(/not a clean result/);
  });

  it("a call for another signal type looks nothing up", async () => {
    stubNetwork(net);
    const li = await liveFor(dir);
    const out = await executeGetActionableSignals(appDb().db, { signal_type: "breaking_change" }, li);
    expect(net.asked).toEqual([]);
    expect(out.scan.status).toBe("unavailable");
    expect(li.getVulnerabilities()).toBeNull();
  });

  it("says NOT CHECKED when there is no live layer at all", async () => {
    const out = await executeGetActionableSignals(appDb().db, {}, null);
    expect(out.scan.status).toBe("disabled");
    expect(out.note).toMatch(/^NOT CHECKED: /);
  });
});
