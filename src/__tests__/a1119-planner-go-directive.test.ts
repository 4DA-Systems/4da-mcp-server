// SPDX-License-Identifier: Apache-2.0
/**
 * A direct Go upgrade says when the fixed release needs a newer Go than go.mod states.
 *
 * golang.org/x/text v0.41.0 declares `go 1.25.0`. With go.mod at `go 1.21`,
 * `go get golang.org/x/text@v0.41.0` raises the go directive, and a Go 1.24 toolchain under
 * GOTOOLCHAIN=local refuses it ("requires go >= 1.25.0"). The indirect (refresh) step already said
 * so; the direct step now carries the same sentence, from the same proxy read.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { adv, createHarness, fixedIn, type Harness } from "./helpers/a1119-planner-harness.js";

let h: Harness;
beforeEach(() => {
  h = createHarness();
});
afterEach(() => h.dispose());

const NEEDS_NEWER_GO =
  "golang.org/x/text v0.41.0 requires go >= 1.25.0 and go.mod says go 1.21, so go get also raises the go directive to 1.25.0 (a Go older than 1.25.0 with GOTOOLCHAIN=local refuses it: install Go 1.25.0 or later first)";

function goProject() {
  h.write("go.mod", "module example.com/demo\n\ngo 1.21\n\nrequire (\n\tgolang.org/x/text v0.3.2\n)\n");
  h.write("go.sum", "golang.org/x/text v0.3.2 h1:a=\ngolang.org/x/text v0.3.2/go.mod h1:b=\n");
  h.ADVISORIES["golang.org/x/text"] = [adv("GO-2020-0015", "golang.org/x/text", fixedIn("0.3.3"), "Go"), adv("GO-2026-5970", "golang.org/x/text", fixedIn("0.41.0"), "Go")];
  h.GO["golang.org/x/text"] = ["v0.3.2", "v0.3.3", "v0.41.0", "v0.44.0"];
}

describe("a direct Go upgrade whose fixed release declares a newer go directive", () => {
  it("says the release needs a newer Go, beside the go get command", async () => {
    goProject();
    h.GOMOD["golang.org/x/text@v0.41.0"] = "1.25.0";
    const { step } = await h.plan();
    const row = step("golang.org/x/text");
    expect(row).toMatchObject({ scope: "direct", action: "upgrade_direct", targetVersion: "v0.41.0", upgradeCommands: [{ dir: ".", command: "go get golang.org/x/text@v0.41.0" }] });
    expect(row.reasons).toContain(NEEDS_NEWER_GO);
  });

  it("says nothing about the go directive when go.mod already states that Go or newer", async () => {
    goProject();
    h.GOMOD["golang.org/x/text@v0.41.0"] = "1.18";
    const { step } = await h.plan();
    const row = step("golang.org/x/text");
    expect(row).toMatchObject({ action: "upgrade_direct", targetVersion: "v0.41.0" });
    expect(row.reasons.join(" ")).not.toMatch(/go directive|NOT CHECKED/);
  });

  it("says nothing either when the release's go.mod was read and declares no go directive", async () => {
    goProject();
    h.GOMOD["golang.org/x/text@v0.41.0"] = "";
    const { step } = await h.plan();
    expect(step("golang.org/x/text").reasons.join(" ")).not.toMatch(/go directive|NOT CHECKED/);
  });

  it("says the check did not run when the proxy gives no go.mod for the release", async () => {
    goProject();
    // No .mod served for v0.41.0: what Go it needs is unread, and said, not assumed fine.
    const { step } = await h.plan();
    const row = step("golang.org/x/text");
    expect(row).toMatchObject({ action: "upgrade_direct", targetVersion: "v0.41.0" });
    expect(row.reasons.join(" ")).toMatch(/whether golang\.org\/x\/text v0\.41\.0 needs a newer Go than go\.mod's go 1\.21 was NOT CHECKED/);
  });
});
