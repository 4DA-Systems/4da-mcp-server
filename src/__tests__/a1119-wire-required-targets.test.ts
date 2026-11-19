// SPDX-License-Identifier: Apache-2.0
/**
 * A direct upgrade on Go, crates.io or PyPI is judged by what the target release itself requires.
 *
 * The scan and the planner said "Upgrade github.com/gin-gonic/gin v1.6.3 -> v1.9.1, resolves 3
 * CVEs"; doing it took the project from 11 advisories to 52, because v1.9.1's own go.mod requires
 * old x/crypto, x/net and protobuf. Now such a step says which requirements carry advisories, how
 * many, and what to raise afterwards, and is never called a clean fix; one whose requirements could
 * not be read says they were not examined; the work is capped per call and the cap is said.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { runWithCallBudget } from "../call-budget.js";
import { MAX_REQUIRED_TARGETS, notExaminedCapText, withRequiredTargets } from "../live/required-targets.js";
import type { RequirementSources } from "../live/release-requirements.js";
import type { FixTargetResult } from "../live/fix-paths.js";
import { adv, createHarness, fixedIn, type Harness } from "./helpers/a1119-planner-harness.js";

let h: Harness;
beforeEach(() => {
  h = createHarness();
});
afterEach(() => h.dispose());

const GIN = "github.com/gin-gonic/gin";

function ginProject(requires: string[] | null) {
  h.write("go.mod", `module example.com/demo\n\ngo 1.21\n\nrequire (\n\t${GIN} v1.6.3\n)\n`);
  h.write("go.sum", `${GIN} v1.6.3 h1:a=\n${GIN} v1.6.3/go.mod h1:b=\n`);
  h.ADVISORIES[GIN] = ["GO-2020-0001", "GO-2021-0052", "GO-2023-1737"].map((id) => adv(id, GIN, fixedIn("1.9.1"), "Go"));
  h.GO[GIN] = ["v1.6.3", "v1.9.1"];
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

describe("upgrade_planner: a Go direct upgrade whose target's go.mod requires affected modules", () => {
  it("says which, how many advisories, what to raise, and does not call the target clean", async () => {
    ginProject(["golang.org/x/crypto v0.5.0", "golang.org/x/net v0.7.0", "golang.org/x/sys v0.5.0"]);
    const { result, step } = await h.plan();
    const row = step(GIN);
    // Not a clean fix: like any target not checked against everything it brings in, it is named only
    // in the reasons, never in the field an agent pins from (unconfirmed-targets.ts).
    expect(row).toMatchObject({ scope: "direct", action: "upgrade_direct", targetVersion: null });
    const reasons = reasonsOf(row);
    expect(reasons).toMatch(/v1\.9\.1's own go\.mod requires 2 dependencies with 3 advisories in all: golang\.org\/x\/crypto v0\.5\.0 \(2 advisories; v0\.31\.0 clears them\) and golang\.org\/x\/net v0\.7\.0 \(1 advisory; v0\.33\.0 clears it\)/);
    expect(reasons).toMatch(/go get golang\.org\/x\/crypto@v0\.31\.0 golang\.org\/x\/net@v0\.33\.0/);
    expect(reasons).toMatch(/so v1\.9\.1 is NOT a clean fix/);
    expect(row.fixPathChecked).not.toBe("all_advisories");
    expect(result.summary).toMatch(/1 of them because the target's own requirements/);
    expect(result.summary).not.toMatch(/1 upgradable directly/);
  });

  it("a target whose requirements carry no advisory stays a clean, checked fix", async () => {
    ginProject(["golang.org/x/crypto v0.31.0", "golang.org/x/net v0.33.0"]);
    const { step } = await h.plan();
    const row = step(GIN);
    expect(row).toMatchObject({ action: "upgrade_direct", targetVersion: "v1.9.1", fixPathChecked: "all_advisories" });
    expect(reasonsOf(row)).not.toMatch(/NOT a clean fix|not examined/);
  });

  it("a target whose go.mod could not be read: its requirements were not examined, and the step says so", async () => {
    ginProject(null);
    const { result, step } = await h.plan();
    const row = step(GIN);
    expect(reasonsOf(row)).toMatch(/what v1\.9\.1 itself requires was not examined \(its requirement list could not be read from the Go module proxy/);
    expect(row.fixPathChecked).not.toBe("all_advisories");
    expect(result.summary).toMatch(/1 target whose own requirements were not examined/);
  });
});

describe("vulnerability_scan: the same direct upgrade", () => {
  it("the recommendation names the requirements and never claims a clean fix", async () => {
    ginProject(["golang.org/x/crypto v0.5.0", "golang.org/x/net v0.7.0"]);
    const out = await h.scan({ response_format: "detailed" });
    const text = JSON.stringify(out);
    expect(text).toMatch(/v1\.9\.1's own go\.mod requires 2 dependencies with 3 advisories in all/);
    expect(text).toMatch(/so v1\.9\.1 is NOT a clean fix/);
    expect(out.requirements_note).toMatch(/1 upgrade target whose own requirements carry advisories/);
    // The fix target is not given as checked against every advisory.
    expect(text).not.toMatch(/"target":"v1\.9\.1","checked":"all_advisories"/);
  });

  it("requirements that could not be read: not examined, said in the answer", async () => {
    ginProject(null);
    const out = await h.scan({ response_format: "detailed" });
    expect(JSON.stringify(out)).toMatch(/what v1\.9\.1 itself requires was not examined/);
    expect(out.requirements_note).toMatch(/1 upgrade target whose own requirements were not examined/);
  });

  it("clean requirements: no note, the target checked against every advisory", async () => {
    ginProject(["golang.org/x/crypto v0.31.0"]);
    const out = await h.scan({ response_format: "detailed" });
    expect(out.requirements_note).toBeUndefined();
    expect(JSON.stringify(out)).not.toMatch(/NOT a clean fix|not examined/);
  });
});

describe("crates.io: a target that exact-pins an affected crate", () => {
  it("both tools say so and neither calls the target clean", async () => {
    h.write("Cargo.toml", `[package]\nname = "demo"\nversion = "0.1.0"\n\n[dependencies]\nwidget = "1.0.0"\n`);
    h.write(
      "Cargo.lock",
      `version = 3\n\n[[package]]\nname = "demo"\nversion = "0.1.0"\ndependencies = ["widget"]\n\n[[package]]\nname = "widget"\nversion = "1.0.0"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n`,
    );
    h.ADVISORIES.widget = [adv("RUSTSEC-2024-0001", "widget", fixedIn("1.1.0"), "crates.io")];
    h.ADVISORIES.gadget = [adv("RUSTSEC-2024-0002", "gadget", fixedIn("0.2.0"), "crates.io")];
    h.CRATES.widget = [{ vers: "1.0.0" }, { vers: "1.1.0", deps: [{ name: "gadget", req: "=0.1.0" }] }];
    h.CRATES.gadget = [{ vers: "0.1.0" }, { vers: "0.2.0" }];
    const { step } = await h.plan();
    const reasons = reasonsOf(step("widget"));
    expect(reasons).toMatch(/1\.1\.0's own requirements bring in a dependency with 1 advisory in all: exact-pins gadget 0\.1\.0 \(RUSTSEC-2024-0002\)/);
    expect(reasons).toMatch(/so 1\.1\.0 is NOT a clean fix/);
    expect(JSON.stringify(await h.scan({ response_format: "detailed" }))).toMatch(/so 1\.1\.0 is NOT a clean fix/);
  });
});

describe("the work is bounded per call", () => {
  const clean = (target: string): FixTargetResult => ({ target, basis: "advisory_fixes", floor: target, floorAffectedBy: [], stillAffectedBy: [], unfixable: [], withheld: [] }) as unknown as FixTargetResult;
  const sources = (asked: string[]): RequirementSources => ({
    reads: () => true,
    requirements: async (_eco, name, version) => {
      asked.push(`${name}@${version}`);
      return { status: "ok", data: { requirements: [], unreadable: 0 } };
    },
    releaseFacts: async () => null,
    packageAdvisories: async () => [],
    publishedVersions: async () => [],
  });
  const query = async () => ({ vulnerabilities: [], totalScanned: 0, offline: false }) as never;

  it(`at most ${MAX_REQUIRED_TARGETS} releases per call, across calls of the helper; the rest say they were not examined`, async () => {
    const asked: string[] = [];
    const items = Array.from({ length: MAX_REQUIRED_TARGETS + 2 }, (_, i) => ({ key: `k${i}`, ecosystem: "Go", name: `example.com/m${i}`, clean: clean("v1.0.1") }));
    const [first, second] = await runWithCallBudget(Date.now(), async () => [
      await withRequiredTargets(sources(asked), query, items.slice(0, 6), Date.now() + 5_000),
      await withRequiredTargets(sources(asked), query, items.slice(6), Date.now() + 5_000),
    ]);
    expect(asked).toHaveLength(MAX_REQUIRED_TARGETS);
    expect(first.size).toBe(0);
    const capped = [...second.values()].filter((c) => c.requiresUnchecked === notExaminedCapText());
    expect(capped).toHaveLength(2);
  });

  it("npm targets and items without a target are left alone", async () => {
    const asked: string[] = [];
    const out = await withRequiredTargets(sources(asked), query, [{ key: "a", ecosystem: "npm", name: "x", clean: clean("1.0.0") }, { key: "b", ecosystem: "Go", name: "y", clean: { ...clean("v1"), target: null } as FixTargetResult }], Date.now() + 5_000);
    expect(asked).toEqual([]);
    expect(out.size).toBe(0);
  });
});
