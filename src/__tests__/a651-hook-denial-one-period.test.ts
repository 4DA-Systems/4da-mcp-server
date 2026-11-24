// SPDX-License-Identifier: Apache-2.0
/**
 * The guard hook's denial quotes the reason dependency_check stored with its verdict and closes it
 * with a period. The stored reason already ends a sentence ("... Safe on 4.17.20's line (4.x):
 * smallest 4.18.1, newest 4.18.1."), so the denial read "newest 4.18.1.. Write a version it answers
 * proceed for." The period is added only where the reason does not end a sentence itself.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { sandbox, type Sandbox } from "./helpers/a1123-hookfix-run.js";

let s: Sandbox;
beforeEach(() => {
  s = sandbox();
});
afterEach(() => s.dispose());

const PKG = JSON.stringify({ name: "x", version: "1.0.0", dependencies: { ms: "2.1.3" } }, null, 2);
const add = (file: string) => s.edit(file, '"ms": "2.1.3"', '"ms": "2.1.3",\n    "lodash": "4.17.20"');

describe("the denial quotes a stored reason with one period", () => {
  it("a reason that ends a sentence is not given a second period", () => {
    s.ledger([
      {
        ecosystem: "npm",
        package: "lodash",
        version: "4.17.20",
        verdict: "avoid",
        reason: "4.17.20 is affected by 3 advisories. Safe on 4.17.20's line (4.x): smallest 4.18.1, newest 4.18.1.",
      },
    ]);
    const run = add(s.file("package.json", PKG));
    expect(run.decision, run.text).toBe("deny");
    // Quoted as the ledger holds it (re-check of 0d30b40, S8); the sentence after the quote closes once.
    expect(run.text).toContain(`recorded reason "4.17.20 is affected by 3 advisories. Safe on 4.17.20's line (4.x): smallest 4.18.1, newest 4.18.1.". Write a version it answers proceed for.`);
    expect(run.text).not.toMatch(/\.\.\s+Write/);
  });

  it("controls: a reason with no closing period gets one, and none recorded reads as before", () => {
    s.ledger([{ ecosystem: "npm", package: "lodash", version: "4.17.20", verdict: "avoid", reason: "advisories" }]);
    const file = s.file("package.json", PKG);
    expect(add(file).text).toContain(`recorded reason "advisories". Write a version it answers proceed for.`);

    s.ledger([{ ecosystem: "npm", package: "lodash", version: "4.17.20", verdict: "avoid", reason: "" }]);
    expect(add(file).text).toContain("recorded reason (none). Write a version it answers proceed for.");
  });
});
