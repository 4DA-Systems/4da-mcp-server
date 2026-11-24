// SPDX-License-Identifier: Apache-2.0
/**
 * A target that installs an affected copy two levels down is not a clean fix.
 *
 * @hey-api/openapi-ts 0.97.3 (the release that clears GHSA-hhx9-57xq-r5rw) exact-pins
 * @hey-api/json-schema-ref-parser 1.4.2, which exact-pins js-yaml 4.1.1, affected by four
 * advisories; the installed 0.96.0 holds no js-yaml at all (ref-parser 1.4.0 uses yaml). 6.5.0
 * judged what a target holds one level down only, so its plan said "0.97.3 is the smallest safe
 * release", fixPathChecked "all_advisories", and dependency_check said proceed: installing it adds
 * js-yaml 4.1.1 that no lockfile refresh can move (audit 2026-11-23 track B, finding 5; the public
 * chain re-read from registry.npmjs.org on 2026-11-23). The shapes below are that chain's, trimmed.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { executeDependencyCheck } from "../tools/dependency-check.js";
import { adv, createHarness, fixedIn, type Harness } from "./helpers/a1119-planner-harness.js";

const OPENAPI = "@hey-api/openapi-ts";
const REF = "@hey-api/json-schema-ref-parser";

let h: Harness;
beforeEach(() => {
  h = createHarness();
  h.ADVISORIES = {
    [OPENAPI]: [adv("GHSA-hhx9-57xq-r5rw", OPENAPI, fixedIn("0.97.3"))],
    "js-yaml": [adv("GHSA-2883-xcg3-v3hh", "js-yaml", [{ introduced: "4.0.0" }, { fixed: "4.3.2" }])],
  };
  h.NPM = {
    [OPENAPI]: {
      latest: "0.97.3",
      versions: { "0.96.0": { dependencies: { [REF]: "1.4.0" } }, "0.97.3": { dependencies: { [REF]: "1.4.2" } } },
    },
    [REF]: { latest: "1.4.2", versions: { "1.4.0": { dependencies: { yaml: "2.8.3" } }, "1.4.2": { dependencies: { "js-yaml": "4.1.1" } } } },
    yaml: { latest: "2.8.3", versions: { "2.8.3": {} } },
    "js-yaml": { latest: "4.3.2", versions: { "4.1.1": {}, "4.3.2": {} } },
  };
  h.npmProject(
    { [OPENAPI]: "0.96.0" },
    {},
    {
      [OPENAPI]: { version: "0.96.0", dependencies: { [REF]: "1.4.0" } },
      [REF]: { version: "1.4.0", dependencies: { yaml: "2.8.3" } },
      yaml: { version: "2.8.3" },
    },
  );
});
afterEach(() => h.dispose());

describe("a target that pins an affected copy two levels down", () => {
  it("the plan does not call it a clean fix, and names the copy and the dependency that pins it", async () => {
    const { result, step } = await h.plan();
    const row = step(OPENAPI);
    expect(row, JSON.stringify(result.recommendations)).toBeTruthy();
    expect(row.fixPathChecked).not.toBe("all_advisories");
    const text = row.reasons.join(" ");
    expect(text).toMatch(/0\.97\.3 installs, two levels down, @hey-api\/json-schema-ref-parser 1\.4\.2 \(its exact pin\), which exact-pins js-yaml 4\.1\.1 \(GHSA-2883-xcg3-v3hh\)/);
    expect(text).toMatch(/0\.97\.3 is NOT a clean fix/);
    // As for a release that holds an affected copy itself: no target to pin, no command that pins it,
    // and the summary does not count it as upgradable.
    expect(row.targetVersion).toBeNull();
    expect(row.commands ?? []).toEqual([]);
    expect(result.run_order.map((s: { run: string }) => s.run).join("\n")).not.toContain("0.97.3");
    expect(result.summary).toMatch(/1 fix target NOT a clean fix/);
    expect(result.summary).not.toMatch(/upgradable directly/);
  });

  it("vulnerability_scan does not name it as the fixed version", async () => {
    const scan = await h.scan({ response_format: "detailed" });
    const row = (scan.vulnerabilities as Array<{ package: string; fixed_version: string | null }>).find((v) => v.package === OPENAPI);
    expect(row, JSON.stringify(scan.vulnerabilities)).toBeTruthy();
    expect(row!.fixed_version).not.toBe("0.97.3");
  });

  it("dependency_check does not answer proceed for it", async () => {
    const answer = (await executeDependencyCheck(null as never, { items: [{ ecosystem: "npm", package: OPENAPI, from: "0.96.0", to: "0.97.3" }], response_format: "detailed" }, await h.live())) as {
      results: Array<{ verdict: string; reason: string }>;
    };
    const r = answer.results[0];
    expect(r.verdict, r.reason).not.toBe("proceed");
    expect(r.reason).toMatch(/js-yaml 4\.1\.1/);
  });

  it("what a held dependency pins could not be read: the target is not called clean, and says why", async () => {
    // The target's own document is read; the document of the dependency it pins is not.
    delete h.NPM[REF];
    const { step } = await h.plan();
    const row = step(OPENAPI);
    expect(row.fixPathChecked).not.toBe("all_advisories");
    expect(row.targetVersion).toBeNull();
    expect(row.reasons.join(" ")).toMatch(/what @hey-api\/json-schema-ref-parser 1\.4\.2 exact-pins could not be read from the npm registry, so the copies two levels down were not checked/);
  });

  it("a release whose second-level pins are clean stays a clean fix (control)", async () => {
    h.NPM[REF].versions["1.4.2"] = { dependencies: { "js-yaml": "4.3.2" } };
    const { step } = await h.plan();
    expect(step(OPENAPI).fixPathChecked).toBe("all_advisories");
    expect(step(OPENAPI).targetVersion).toBe("0.97.3");
  });
});
