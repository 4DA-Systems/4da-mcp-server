// SPDX-License-Identifier: Apache-2.0
/**
 * One advisory, one instruction. zip 8.6.0 under docx-rs (4DA's own src-tauri): vulnerability_scan
 * says blocked upstream at 9.0.5 (docx-rs 0.4.22, its newest release, requires ^8.6.0), while
 * get_actionable_signals said "Upgrade zip: the advisory names 9.0.0 as its fix" on most rows and
 * dependency_check calls 9.0.0 avoid. Every tool now gives the scan's fix verdict for the package
 * version, built by the same functions.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as fs from "node:fs";
import { executeGetActionableSignals } from "../tools/get-actionable-signals.js";
import { executeVulnerabilityScan } from "../tools/vulnerability-scan.js";
import { executeWhatShouldIKnow } from "../tools/what-should-i-know.js";
import { adv, appDb, emptyNetwork, fixedIn, liveFor, npmProject, projectDir, stubNetwork, zipUnderDocx, type Network } from "./helpers/a1123-advice.js";

let dir: string;
let net: Network;

beforeEach(() => {
  dir = projectDir();
  net = emptyNetwork();
});

afterEach(() => {
  vi.unstubAllGlobals();
  fs.rmSync(dir, { recursive: true, force: true });
});

describe("zip 8.6.0 under docx-rs: the signals and the briefing give the scan's instruction", () => {
  it("every zip signal carries the scan's blocked-upstream line, never the advisory's own 9.0.0", async () => {
    zipUnderDocx(dir, net);
    stubNetwork(net);
    const li = await liveFor(dir);

    // The signals first, as a session's first call.
    const signals = await executeGetActionableSignals(appDb().db, { signal_type: "security_alert", limit: 50 }, li);
    const zipRows = signals.signals.filter((s) => s.source_type === "osv_live" && s.title.endsWith("(zip@8.6.0)"));
    expect(zipRows).toHaveLength(8);

    const scan = (await executeVulnerabilityScan(null, {}, li)) as { recommendations: string[] };
    const line = scan.recommendations.find((r) => r.includes("zip 8.6.0"))!;
    expect(line).toMatch(/^Blocked upstream: zip 8\.6\.0 in \. \[.*\] — 9\.0\.5 would resolve 8 CVEs, but no parent release admits it, so it takes an override or replacing the parent/);

    for (const row of zipRows) {
      // The scan's line, plus the scope note where the advisory's own grade is higher.
      expect(row.action.startsWith(line)).toBe(true);
      expect(row.action).not.toMatch(/advisory names/);
      expect(row.action).not.toMatch(/\b9\.0\.0\b/);
    }

    // The briefing for a task naming zip says the same.
    const briefing = await executeWhatShouldIKnow(appDb().db, { packages: [], task: "bump the zip crate" }, li);
    const zipAdvisory = briefing.advisories.find((a) => a.scope === "task" && a.title.startsWith("zip 8.6.0"));
    expect(zipAdvisory?.action).toBe(line);
  });

  it("a direct copy: the briefing's instruction is the scan's line for it too", async () => {
    npmProject(dir, { minimist: "^1.2.0" }, { minimist: { version: "1.2.5" } });
    net.advisories.minimist = [adv("GHSA-xvch-5gv4-984h", "minimist", fixedIn("1.2.6"), "npm", "CRITICAL"), adv("GHSA-vh95-rmgr-6w4m", "minimist", fixedIn("1.2.3"), "npm", "MODERATE")];
    net.npm.minimist = { latest: "1.2.8", versions: { "1.2.5": {}, "1.2.6": {}, "1.2.8": {} } };
    stubNetwork(net);
    const li = await liveFor(dir);

    const briefing = await executeWhatShouldIKnow(appDb().db, { packages: [], task: "update the minimist package" }, li);
    const scan = (await executeVulnerabilityScan(null, {}, li)) as { recommendations: string[] };
    const line = scan.recommendations.find((r) => r.includes("minimist 1.2.5"))!;
    expect(line).toMatch(/^Upgrade minimist 1\.2\.5 → 1\.2\.6/);
    expect(briefing.advisories.find((a) => a.scope === "task")?.action).toBe(line);
    const signals = await executeGetActionableSignals(appDb().db, { signal_type: "security_alert" }, li);
    expect(signals.signals.filter((s) => s.source_type === "osv_live").map((s) => s.action)).toEqual([line]);
  });

  it("a high advisory whose fix is only NOT CHECKED is not called one with no fixed release, and the row agrees with the scan's", async () => {
    npmProject(dir, { minimist: "^1.2.0" }, { minimist: { version: "1.2.5" } });
    net.advisories.minimist = [adv("GHSA-xvch-5gv4-984h", "minimist", fixedIn("1.2.6"), "npm", "HIGH")];
    // The registry does not answer: what 1.2.6 holds cannot be judged, so the target is not confirmed.
    stubNetwork(net);
    const li = await liveFor(dir);

    const briefing = await executeWhatShouldIKnow(appDb().db, { packages: [], task: "update the minimist package" }, li);
    const dep = briefing.task_dependencies.find((d) => d.package === "minimist")!;
    expect(dep.vulnerabilities[0]).toMatchObject({ fixed_version: null, fixed_version_note: expect.stringMatching(/^NOT CHECKED: 1\.2\.6/) });
    expect(briefing.delegation_assessment.level).toBe("review_needed");
    expect(briefing.delegation_assessment.reason).not.toMatch(/no fixed release/);

    const detailed = (await executeVulnerabilityScan(null, { response_format: "detailed" }, li)) as { recommendations: string[]; vulnerabilities: Array<{ fixed_version: string | null }> };
    expect(detailed.vulnerabilities[0].fixed_version).toBeNull();
    expect(briefing.advisories.find((a) => a.scope === "task")?.action).toBe(detailed.recommendations.find((r) => r.includes("minimist 1.2.5")));
  });
});
