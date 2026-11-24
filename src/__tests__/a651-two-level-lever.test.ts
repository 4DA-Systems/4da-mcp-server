// SPDX-License-Identifier: Apache-2.0
/**
 * A parent upgrade's lever is judged two levels down too, as a direct target is.
 *
 * Seen in bench/plan-exec on the 6.5.1 candidate (full-stack-fastapi-template 0.7.1 frontend):
 * @hey-api/openapi-ts 0.34.1 exact-pins handlebars 4.7.8 (11 advisories). The handlebars row's
 * parent upgrade named openapi-ts 0.97.3 (it no longer depends on handlebars) with
 * `fixPathChecked: "all_advisories"`, and run_order's first step installed it. 0.97.3 exact-pins
 * @hey-api/json-schema-ref-parser 1.4.2, which exact-pins js-yaml 4.1.1: the plan's own js-yaml
 * refresh (a later step, `fixes: ["npm:js-yaml"]`) could then never move that copy, and the rescan
 * held js-yaml 4.1.1 with four advisories. In the same plan the openapi-ts row already said "0.97.3
 * is NOT a clean fix" for that copy: the lever path judged what 0.97.3 holds one level down only.
 * Now the lever is judged as the target is: the plan never names, as a parent upgrade, a release
 * that brings in an affected copy two levels down (the existing rule one level down), so the row
 * says so and is not run as a clean fix.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { adv, createHarness, fixedIn, type Harness } from "./helpers/a1119-planner-harness.js";

const OPENAPI = "@hey-api/openapi-ts";
const REF = "@hey-api/json-schema-ref-parser";

let h: Harness;
beforeEach(() => {
  h = createHarness();
  h.ADVISORIES = {
    handlebars: [adv("GHSA-2qvq-rjwj-gvw9", "handlebars", fixedIn("4.7.9"), "npm", "CRITICAL")],
    "js-yaml": [adv("GHSA-2883-xcg3-v3hh", "js-yaml", [{ introduced: "4.0.0" }, { fixed: "4.3.2" }])],
  };
  h.NPM = {
    [OPENAPI]: {
      latest: "0.97.3",
      versions: {
        "0.34.1": { dependencies: { handlebars: "4.7.8", [REF]: "1.4.0" } },
        "0.97.3": { dependencies: { [REF]: "1.4.2" } },
      },
    },
    [REF]: { latest: "1.4.2", versions: { "1.4.0": { dependencies: { yaml: "2.8.3" } }, "1.4.2": { dependencies: { "js-yaml": "4.1.1" } } } },
    handlebars: { latest: "4.7.9", versions: { "4.7.8": {}, "4.7.9": {} } },
    yaml: { latest: "2.8.3", versions: { "2.8.3": {} } },
    "js-yaml": { latest: "4.3.2", versions: { "4.1.1": {}, "4.3.2": {} } },
  };
  h.npmProject(
    { [OPENAPI]: "0.34.1" },
    {},
    {
      [OPENAPI]: { version: "0.34.1", dependencies: { handlebars: "4.7.8", [REF]: "1.4.0" } },
      handlebars: { version: "4.7.8" },
      [REF]: { version: "1.4.0", dependencies: { yaml: "2.8.3" } },
      yaml: { version: "2.8.3" },
    },
  );
});
afterEach(() => h.dispose());

const runText = (result: Record<string, any>) => result.run_order.map((s: { run: string }) => s.run).join("\n");

describe("a parent upgrade whose lever pins an affected copy two levels down", () => {
  it("the handlebars row does not name openapi-ts 0.97.3 as a clean fix, and run_order does not install it", async () => {
    const { result, step } = await h.plan();
    const row = step("handlebars");
    expect(row, JSON.stringify(result.recommendations.map((r: { package: string }) => r.package))).toBeTruthy();
    const text = row.reasons.join(" ");
    expect(text).toMatch(/js-yaml 4\.1\.1/);
    expect(text).toMatch(/0\.97\.3 is NOT a clean fix/);
    expect(runText(result)).not.toContain(`${OPENAPI}@`);
    // No command for a release the row itself calls NOT a clean fix, on the row or on its lever, and
    // no all_advisories claim (claims review 2026-11-24, twolevel85).
    expect(JSON.stringify(row.commands ?? [])).not.toContain(`${OPENAPI}@`);
    expect(JSON.stringify(row.parentUpgrades ?? [])).not.toContain(`${OPENAPI}@0.97.3`);
    expect(row.fixPathChecked).not.toBe("all_advisories");
  });

  it("control: a lever whose second level is clean is named and run as before", async () => {
    h.NPM[REF].versions["1.4.2"] = { dependencies: { "js-yaml": "4.3.2" } };
    const { result, step } = await h.plan();
    const row = step("handlebars");
    expect(row.reasons.join(" ")).not.toMatch(/NOT a clean fix/);
    expect(runText(result)).toContain(`${OPENAPI}@`);
  });
});
