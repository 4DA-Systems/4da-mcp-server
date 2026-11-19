// SPDX-License-Identifier: Apache-2.0
/**
 * A Go direct upgrade whose target's go.mod sets minimum versions with advisories keeps its target.
 * For go.mod `require github.com/gin-gonic/gin v1.9.0`, upgrade_planner gave `targetVersion: null`
 * with "NOT CHECKED: v1.9.1 was not confirmed free of gin's known advisories" (it is free of them),
 * and vulnerability_scan gave `fixed_version: null` beside "Upgrade ... v1.9.0 -> v1.9.1". Minimums
 * are raised in the project's own go.mod afterwards, so the target stays, with the raises named.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { adv, createHarness, fixedIn, type Harness } from "./helpers/a1119-planner-harness.js";

let h: Harness;
beforeEach(() => {
  h = createHarness();
});
afterEach(() => h.dispose());

const GIN = "github.com/gin-gonic/gin";

function ginProject(requires: string[] | null) {
  h.write("go.mod", `module example.com/demo\n\ngo 1.21\n\nrequire (\n\t${GIN} v1.9.0\n)\n`);
  h.write("go.sum", `${GIN} v1.9.0 h1:a=\n${GIN} v1.9.0/go.mod h1:b=\n`);
  h.ADVISORIES[GIN] = [adv("GO-2023-1737", GIN, fixedIn("1.9.1"), "Go")];
  h.GO[GIN] = ["v1.9.0", "v1.9.1"];
  if (requires) {
    h.GOMOD[`${GIN}@v1.9.1`] = "1.18";
    h.GOREQ[`${GIN}@v1.9.1`] = requires;
  }
  h.ADVISORIES["golang.org/x/crypto"] = [adv("GO-2024-3321", "golang.org/x/crypto", fixedIn("0.31.0"), "Go"), adv("GO-2023-2402", "golang.org/x/crypto", fixedIn("0.17.0"), "Go")];
  h.GO["golang.org/x/crypto"] = ["v0.5.0", "v0.17.0", "v0.31.0"];
  h.ADVISORIES["golang.org/x/net"] = [adv("GO-2024-3333", "golang.org/x/net", fixedIn("0.33.0"), "Go")];
  h.GO["golang.org/x/net"] = ["v0.7.0", "v0.33.0"];
}

const reasonsOf = (row: Record<string, any>) => (row.reasons as string[]).join(" | ");

describe("upgrade_planner: Go minimums are a caveat on a kept target", () => {
  it("keeps v1.9.1, names the go get raises and the advisory count, and never says NOT CHECKED", async () => {
    ginProject(["golang.org/x/crypto v0.5.0", "golang.org/x/net v0.7.0", "golang.org/x/sys v0.5.0"]);
    const { step } = await h.plan();
    const row = step(GIN);
    expect(row).toMatchObject({ scope: "direct", action: "upgrade_direct", targetVersion: "v1.9.1", fixPathChecked: "all_advisories" });
    const reasons = reasonsOf(row);
    expect(reasons).not.toMatch(/NOT CHECKED|NOT a clean fix|not confirmed free/);
    expect(reasons).toMatch(/v1\.9\.1 clears this package's own advisories, but its go\.mod sets 2 minimum versions with 3 advisories in all/);
    expect(reasons).toMatch(/go get golang\.org\/x\/crypto@v0\.31\.0 golang\.org\/x\/net@v0\.33\.0/);
  });

  it("a go.mod that could not be read: the target is kept and the step says it was not examined", async () => {
    ginProject(null);
    const { step } = await h.plan();
    const row = step(GIN);
    expect(row).toMatchObject({ targetVersion: "v1.9.1" });
    expect(reasonsOf(row)).toMatch(/what its go\.mod requires was not examined \(/);
    expect(reasonsOf(row)).not.toMatch(/NOT CHECKED: v1\.9\.1|not confirmed free/);
  });
});

describe("vulnerability_scan: the same target, the same answer", () => {
  it("fixed_version is set, and the recommendation carries the caveat beside the upgrade", async () => {
    ginProject(["golang.org/x/crypto v0.5.0", "golang.org/x/net v0.7.0"]);
    const out = await h.scan({ response_format: "detailed" });
    const text = JSON.stringify(out);
    expect(text).toMatch(/"fixed_version":"v1\.9\.1"/);
    expect(text).not.toMatch(/"fixed_version":null/);
    const recs = JSON.stringify((out as Record<string, unknown>).recommendations ?? out);
    expect(recs).toMatch(/Upgrade github\.com\/gin-gonic\/gin v1\.9\.0 → v1\.9\.1[^"]*its go\.mod sets 2 minimum versions with 3 advisories in all[^"]*go get golang\.org\/x\/crypto@v0\.31\.0/);
    expect(text).not.toMatch(/NOT a clean fix|NOT CHECKED: v1\.9\.1/);
    expect(out.requirements_note).toMatch(/1 Go upgrade target whose go\.mod sets minimum versions with advisories \(the target is kept/);
  });
});
