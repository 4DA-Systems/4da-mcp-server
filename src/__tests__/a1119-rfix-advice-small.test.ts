// SPDX-License-Identifier: Apache-2.0
/**
 * Smaller defects: (a) a Go row's go-directive note is for its FINAL target (reconcileDirectTargets
 * can raise it after the note was written); (b) a range check's "not examined" reason does not
 * repeat itself; (c) the Claude Desktop bundle text claims only what is true and carries no tool
 * count; (d) a release blocked by a cancelled CI run says to re-run CI on the commit.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { RequirementJudge } from "../tools/dependency-check-held.js";
import { reconcileDirectTargets } from "../tools/upgrade-planner-fixpaths.js";
import { adv, createHarness, fixedIn, type Harness } from "./helpers/a1119-planner-harness.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const text = (file: string) => readFileSync(join(root, file), "utf8");

describe("(a) the go directive is re-checked for a raised target", () => {
  let h: Harness;
  beforeEach(() => {
    h = createHarness();
  });
  afterEach(() => h.dispose());

  it("a row raised from v0.3.3 to v0.41.0 says what v0.41.0 needs, not what v0.3.3 needed", async () => {
    h.write("go.mod", "module example.com/demo\n\ngo 1.21\n\nrequire (\n\tgolang.org/x/text v0.3.2\n)\n");
    h.write("go.sum", "golang.org/x/text v0.3.2 h1:a=\ngolang.org/x/text v0.3.2/go.mod h1:b=\n");
    h.ADVISORIES["golang.org/x/text"] = [adv("GO-2020-0015", "golang.org/x/text", fixedIn("0.3.3"), "Go")];
    h.GO["golang.org/x/text"] = ["v0.3.2", "v0.3.3", "v0.41.0"];
    h.GOMOD["golang.org/x/text@v0.3.3"] = "1.11";
    h.GOMOD["golang.org/x/text@v0.41.0"] = "1.25.0";
    const li = await h.live();
    const own = { package: "golang.org/x/text", ecosystem: "Go", currentVersion: "v0.3.2", targetVersion: "v0.3.3", upgradeType: "patch", reasons: [] as string[], breaking: false, scope: "direct", action: "upgrade_direct" } as Record<string, any>;
    const child = {
      package: "example.com/child", ecosystem: "Go", currentVersion: "v1.0.0", targetVersion: "v1.0.1", upgradeType: "patch", reasons: [] as string[], breaking: false, scope: "transitive",
      action: "upgrade_parent", parentUpgrades: [{ parent: "golang.org/x/text", from: "v0.3.2", to: "v0.41.0", breaking: true, levers: [{ name: "golang.org/x/text", version: "v0.3.2", to: "v0.41.0", breaking: true }] }],
    };
    await reconcileDirectTargets([own as never, child as never], [{ step: own as never, fixes: ["0.3.3"], sourceDirs: [h.dir] }], li as never, 10_000);
    expect(own.targetVersion).toBe("v0.41.0");
    expect(own.reasons).toContain(
      "golang.org/x/text v0.41.0 requires go >= 1.25.0 and go.mod says go 1.21, so go get also raises the go directive to 1.25.0 (a Go older than 1.25.0 with GOTOOLCHAIN=local refuses it: install Go 1.25.0 or later first)",
    );
  });
});

describe("(b) the not-examined reason of a range check is said once", () => {
  it("the default reason is not the sentence it is placed in", () => {
    const judge = new RequirementJudge({ reads: () => true } as never, async () => ({}) as never).of("PyPI")!;
    const reason = judge.rangeFilter("x")!.reason;
    expect(reason).not.toMatch(/was not examined/);
    expect(reason).toMatch(/smallest and newest/);
  });
});

describe("(c) the Claude Desktop bundle text", () => {
  const source = text("scripts/build-mcpb.mjs");
  it("does not say only package names and versions leave the machine, and carries no tool count", () => {
    expect(source).not.toMatch(/Only public package names and versions (?:leave your machine|are ever sent)/);
    expect(source).not.toMatch(/\b(?:eleven|twelve|ten|sixteen|\d+) tools\b/);
    expect(source).toMatch(/ecosystem pulse sends your dependency names to Hacker News search/);
  });
});

describe("(d) the release gate on a cancelled CI run", () => {
  it("says to re-run CI on the commit, not to fix main", () => {
    const yml = text(".github/workflows/release.yml");
    expect(yml).toMatch(/cancelled\)[\s\S]{0,400}re-run CI on \$GITHUB_SHA/i);
    expect(yml).toMatch(/\*\)[\s\S]{0,200}Fix main/);
  });
});
