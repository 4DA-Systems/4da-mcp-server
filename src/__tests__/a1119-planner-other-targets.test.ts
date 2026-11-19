// SPDX-License-Identifier: Apache-2.0
/**
 * A vulnerable crate this host does not build still has to be fixed where it is built.
 *
 * nix 0.20.0 sits under `[target.'cfg(unix)'.dependencies]`; planned on Windows, its row named
 * the fixed release and nothing to run, so applying every recommendation left it in place for
 * the Linux build. The row stays apart from the findings this host builds (its own action, low
 * rank), and now carries the fix with its label: "applies when you build for cfg(unix)".
 *
 * As in the other platform tests, the scan is a stand-in that marks the copy not built on this
 * host (no `cargo tree` runs here); the registry and OSV are stubbed at the HTTP boundary.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import Database from "better-sqlite3";
import { LiveIntelligence } from "../live/index.js";
import { restampDepContext } from "../live/osv-scanner.js";
import type { ResolvedDependency, VulnerabilityEntry, VulnerabilityScanResult } from "../live/types.js";
import { executeUpgradePlanner } from "../tools/upgrade-planner.js";
import type { FourDADatabase } from "../db.js";
import { adv, createHarness, fixedIn, type Harness } from "./helpers/a1119-planner-harness.js";

const noDb = null as unknown as FourDADatabase;

let h: Harness;
beforeEach(() => {
  h = createHarness();
});
afterEach(() => h.dispose());

function cargoLock(packages: Array<{ name: string; version: string; deps?: string[]; root?: boolean }>) {
  return [
    "version = 4",
    "",
    ...packages.flatMap((p) => [
      "[[package]]",
      `name = "${p.name}"`,
      `version = "${p.version}"`,
      ...(p.root ? [] : ['source = "registry+https://github.com/rust-lang/crates.io-index"']),
      ...(p.deps && p.deps.length > 0 ? ["dependencies = [", ...p.deps.map((d) => ` "${d}",`), "]"] : []),
      "",
    ]),
  ].join("\n");
}

/** A LiveIntelligence whose scan reports nix 0.20.0 as vulnerable (fixed in `fixed`) and not built on this host, gated by `target`. */
async function intelWithInactiveNix(target: string | null, fixed = "0.20.2") {
  const li = new LiveIntelligence(new Database(":memory:"));
  const scanOf = async (deps: ResolvedDependency[], projectPath: string): Promise<VulnerabilityScanResult> => {
    const vulnerabilities = deps
      // Per version, as OSV.dev answers: the installed 0.20.0 is affected, a release asked about as the target is not.
      .filter((d) => d.name === "nix" && d.version === "0.20.0")
      .map((d) =>
        restampDepContext(
          {
            package: "", currentVersion: "", ecosystem: "crates.io", isDev: false, isDirect: false, devScopeKnown: true,
            vulnId: "RUSTSEC-2021-0119", aliases: [], severity: "high", cvssScore: null, summary: "out-of-bounds write in getgrouplist", fixedVersion: fixed,
            published: "2021-09-27T00:00:00Z", references: [], target: null, platformActive: false, sourceDirs: [],
          } as unknown as VulnerabilityEntry,
          d,
        ),
      )
      .map((v) => ({ ...v, platformActive: false, target }));
    return {
      scannedAt: new Date().toISOString(), projectPath, ecosystemsScanned: ["crates.io"], totalScanned: deps.length, totalVulnerable: 0,
      platformInactiveVulnerable: 1, bySeverity: { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 }, vulnerabilities,
      cleanCount: deps.length - 1, scanDurationMs: 1, cached: false, offline: false,
    };
  };
  (li as unknown as { osvScanner: { scan: typeof scanOf } }).osvScanner = { scan: scanOf } as never;
  const { scanProjectTree, treeResolutionGroups } = await import("../project-tree.js");
  const { entries, discovery } = scanProjectTree(h.dir);
  li.initFromProjectTree(h.dir, treeResolutionGroups(entries), discovery);
  return li;
}

const planWith = async (li: LiveIntelligence) => (await executeUpgradePlanner(noDb, { project_path: h.dir, max_recommendations: 50 }, li)) as Record<string, any>;
const rowOf = (plan: Record<string, any>, name: string) => plan.recommendations.find((r: { package: string }) => r.package === name) as Record<string, any>;

function nixRegistry(fixed = "0.20.2") {
  h.ADVISORIES.nix = [adv("RUSTSEC-2021-0119", "nix", fixedIn(fixed), "crates.io")];
  h.CRATES.nix = [{ vers: "0.20.0" }, { vers: "0.20.1" }, { vers: "0.20.2" }, { vers: "0.23.0" }];
}

describe("a vulnerable crate that is not built on this host", () => {
  it("declared for another target: the row carries the command that fixes it there, labelled with the target", async () => {
    nixRegistry();
    h.write("Cargo.toml", '[package]\nname = "app"\nversion = "0.1.0"\nedition = "2021"\n\n[target.\'cfg(unix)\'.dependencies]\nnix = "=0.20.0"\n');
    h.write("Cargo.lock", cargoLock([{ name: "app", version: "0.1.0", deps: ["nix"], root: true }, { name: "nix", version: "0.20.0" }]));
    const plan = await planWith(await intelWithInactiveNix("cfg(unix)"));
    const row = rowOf(plan, "nix");
    // Still apart from what this host builds: its own action, never counted among this host's upgrades.
    expect(row).toMatchObject({ scope: "direct", action: "not_built_on_this_host", platformActive: false, targetVersion: "0.20.2", fixPathChecked: "all_advisories" });
    // And the fix is on the row, not omitted.
    expect(row).toMatchObject({
      appliesWhenBuiltFor: ["cfg(unix)"],
      whenBuilt: "upgrade_direct",
      upgradeCommands: [{ dir: ".", command: 'cargo add "nix@=0.20.2" --target "cfg(unix)"' }],
    });
    expect(row.reasons.join(" | ")).toMatch(/Applies when you build for cfg\(unix\): .*upgrade nix 0\.20\.0 to 0\.20\.2.*cargo add "nix@=0\.20\.2" --target "cfg\(unix\)"/);
    expect(plan.summary).toMatch(/1 vulnerable only in code not built on this host \(the fix on each row applies when you build for its target: cfg\(unix\)\)/);
    // Not counted with the upgrades this host needs.
    expect(plan.quickWins).toBe(0);
  });

  it("a transitive copy: the refresh that moves it is on the row too", async () => {
    nixRegistry();
    h.CRATES.ctrlc = [{ vers: "3.1.9", deps: [{ name: "nix", req: "^0.20" }] }];
    h.write("Cargo.toml", '[package]\nname = "app"\nversion = "0.1.0"\nedition = "2021"\n\n[dependencies]\nctrlc = "=3.1.9"\n');
    h.write("Cargo.lock", cargoLock([
      { name: "app", version: "0.1.0", deps: ["ctrlc"], root: true },
      { name: "ctrlc", version: "3.1.9", deps: ["nix"] },
      { name: "nix", version: "0.20.0" },
    ]));
    const plan = await planWith(await intelWithInactiveNix("not built for x86_64-pc-windows-msvc"));
    const row = rowOf(plan, "nix");
    expect(row).toMatchObject({
      scope: "transitive",
      action: "not_built_on_this_host",
      targetVersion: "0.20.2",
      whenBuilt: "lockfile_refresh",
      refreshCommands: [{ dir: ".", command: "cargo update -p nix@0.20.0 --precise 0.20.2" }],
    });
    expect(row.reasons.join(" | ")).toMatch(/Applies when you build for a target other than x86_64-pc-windows-msvc: .*cargo update -p nix@0\.20\.0 --precise 0\.20\.2/);
    // Never counted as a refresh this host needs.
    expect(plan.lockfileRefreshes).toBe(0);
    expect(plan.summary).toMatch(/1 vulnerable only in code not built on this host/);
  });

  it("says so when how it is fixed there could not be read", async () => {
    // The fix is on another 0.x line, so nothing is inferred from semver either.
    nixRegistry("0.23.0");
    h.write("Cargo.toml", '[package]\nname = "app"\nversion = "0.1.0"\nedition = "2021"\n\n[dependencies]\nctrlc = "=3.1.9"\n');
    h.write("Cargo.lock", cargoLock([
      { name: "app", version: "0.1.0", deps: ["ctrlc"], root: true },
      { name: "ctrlc", version: "3.1.9", deps: ["nix"] },
      { name: "nix", version: "0.20.0" },
    ]));
    // ctrlc is not served: what it requires of nix is unread.
    const plan = await planWith(await intelWithInactiveNix("cfg(unix)", "0.23.0"));
    const row = rowOf(plan, "nix");
    expect(row).toMatchObject({ action: "not_built_on_this_host", targetVersion: "0.23.0", whenBuilt: "not_determined" });
    expect(row.refreshCommands).toBeUndefined();
    expect(row.reasons.join(" | ")).toMatch(/Applies when you build for cfg\(unix\): .*NOT DETERMINED/);
  });
});
