// SPDX-License-Identifier: Apache-2.0
/**
 * Fourth blind check of the 2026-11-25 fixes, item 5: `pip install "requests[security]==2.25.0"` listed
 * PyPI:security, and with two extras requests was judged at latest. An extra is never a name, and the
 * requirement keeps its version. Stubbed fetch.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { executeWhatShouldIKnow } from "../tools/what-should-i-know.js";
import { adv, createHarness, fixedIn, type Harness } from "./helpers/a1119-planner-harness.js";

let h: Harness;
beforeEach(() => {
  h = createHarness();
  h.write("requirements.txt", "flask==3.0.0\n");
  h.PYPI = { flask: { "3.0.0": {} }, requests: { "2.25.0": {}, "2.32.3": {} }, celery: { "5.3.0": {}, "5.4.0": {} } };
  h.ADVISORIES = { requests: [adv("GHSA-j8r2-6x86-q33q", "requests", fixedIn("2.31.0"), "PyPI")] };
});
afterEach(() => h.dispose());

async function brief(task: string): Promise<Record<string, any>> {
  return (await executeWhatShouldIKnow(null, { task, project_path: h.dir }, await h.live())) as Record<string, any>;
}

describe("a PEP 508 extra is never a name, and the version stays bound", () => {
  it.each(['pip install "requests[security]==2.25.0"', 'pip install "requests[security,socks]==2.25.0"', "pip install requests[security, socks]==2.25.0"])("%s", async (task) => {
    const r = await brief(task);
    expect(JSON.stringify(r.unverified_words ?? [])).not.toMatch(/security|socks/);
    expect(JSON.stringify(r.new_packages ?? [])).not.toMatch(/security|socks/);
    expect(h.requests.some((u) => /security|socks/.test(u))).toBe(false);
    expect(r.requested_versions).toMatchObject([{ name: "requests", to: "2.25.0", verdict: "avoid" }]);
  });

  it('poetry add "celery[redis]>=5.3": celery at >=5.3', async () => {
    const r = await brief('poetry add "celery[redis]>=5.3"');
    expect(r.requested_versions).toMatchObject([{ name: "celery", to: ">=5.3" }]);
    expect(JSON.stringify(r.unverified_words ?? [])).not.toContain("redis");
  });
});
