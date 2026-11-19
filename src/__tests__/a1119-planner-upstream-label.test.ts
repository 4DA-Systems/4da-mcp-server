// SPDX-License-Identifier: Apache-2.0
/**
 * "Waiting on upstream" means one thing: the fix exists, every path to it is blocked by a parent
 * the project cannot move, and that was read, not assumed.
 *
 * - A blocking parent the project declares itself, with a release that admits the fix, is an
 *   upgrade of that parent (uv: requests 2.25.1 holds idna "<3" and urllib3 "<1.27"; requests
 *   2.33.0 admits both fixes, and a refresh of each follows).
 * - Parent releases that could not be read (the registry did not answer) leave the fix path NOT
 *   DETERMINED, never "waiting on upstream".
 * - A parent release that fixes the copy and holds only the affected dependencies the installed
 *   parent already holds brings in nothing new, and is named (mocha 7.1.0 -> 7.1.1 for
 *   yargs-parser 13.1.1; both pin the same diff, debug and js-yaml).
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { adv, createHarness, fixedIn, type Harness } from "./helpers/a1119-planner-harness.js";

let h: Harness;
beforeEach(() => {
  h = createHarness();
});
afterEach(() => h.dispose());

const reasonsOf = (step: Record<string, any>) => (step.reasons as string[]).join(" | ");

// ---------------------------------------------------------------------------
// A parent the project declares itself
// ---------------------------------------------------------------------------

describe("a blocking parent that is the project's own direct dependency (uv.lock)", () => {
  function uvProject(requiresPython: string) {
    h.ADVISORIES = {
      requests: [adv("PYSEC-2023-74", "requests", fixedIn("2.31.0"), "PyPI"), adv("PYSEC-2026-1872", "requests", fixedIn("2.33.0"), "PyPI")],
      idna: [adv("PYSEC-2024-60", "idna", fixedIn("3.7"), "PyPI"), adv("PYSEC-2026-215", "idna", fixedIn("3.15"), "PyPI")],
      urllib3: [adv("PYSEC-2023-192", "urllib3", fixedIn("1.26.17"), "PyPI"), adv("PYSEC-2026-4177", "urllib3", fixedIn("2.8.0"), "PyPI")],
    };
    h.PYPI = {
      requests: {
        "2.25.1": { requiresDist: ["chardet (<5,>=3.0.2)", "idna (<3,>=2.5)", "urllib3 (<1.27,>=1.21.1)", "certifi (>=2017.4.17)"] },
        "2.31.0": { requiresPython: ">=3.7", requiresDist: ["idna (<4,>=2.5)", "urllib3 (<3,>=1.21.1)", "certifi (>=2017.4.17)"] },
        "2.33.0": { requiresPython: ">=3.10", requiresDist: ["idna<4,>=2.5", "urllib3<3,>=1.26", "certifi>=2023.5.7"] },
        "2.34.2": { requiresPython: ">=3.10", requiresDist: ["idna<4,>=2.5", "urllib3<3,>=1.26", "certifi>=2023.5.7"] },
      },
      idna: { "2.10": {}, "3.7": { requiresPython: ">=3.5" }, "3.15": { requiresPython: ">=3.8" } },
      urllib3: { "1.26.5": {}, "1.26.20": {}, "2.8.0": { requiresPython: ">=3.9" } },
      // What requests 2.33.0 requires is judged too: each requirement needs a readable release list.
      certifi: { "2024.2.2": {} },
    };
    h.write("pyproject.toml", `[project]\nname = "example"\nversion = "0.1.0"\nrequires-python = "${requiresPython}"\ndependencies = ["requests==2.25.1"]\n`);
    h.write("uv.lock", [
      `version = 1\nrequires-python = "${requiresPython}"\n`,
      '[[package]]\nname = "example"\nversion = "0.1.0"\nsource = { virtual = "." }\ndependencies = [\n    { name = "requests" },\n]\n\n[package.metadata]\nrequires-dist = [{ name = "requests", specifier = "==2.25.1" }]\n',
      '[[package]]\nname = "idna"\nversion = "2.10"\nsource = { registry = "https://pypi.org/simple" }\n',
      '[[package]]\nname = "requests"\nversion = "2.25.1"\nsource = { registry = "https://pypi.org/simple" }\ndependencies = [\n    { name = "idna" },\n    { name = "urllib3" },\n]\n',
      '[[package]]\nname = "urllib3"\nversion = "1.26.5"\nsource = { registry = "https://pypi.org/simple" }\n',
    ].join("\n"));
  }

  it("is an upgrade of that parent, with the refresh that follows, not waiting on upstream", async () => {
    uvProject(">=3.10");
    const { result, step } = await h.plan();

    for (const [name, target] of [["idna", "3.15"], ["urllib3", "2.8.0"]] as const) {
      const row = step(name);
      expect(row, name).toMatchObject({ scope: "transitive", action: "upgrade_parent", targetVersion: target });
      expect(row.parentUpgrades).toMatchObject([
        {
          parent: "requests",
          from: "2.25.1",
          to: "2.33.0",
          levers: [{ name: "requests", version: "2.25.1", to: "2.33.0" }],
          refreshCommands: [{ dir: ".", command: `uv lock --upgrade-package ${name}` }],
        },
      ]);
      expect(reasonsOf(row)).toMatch(new RegExp(`requests 2\\.25\\.1 requires ${name} "[^"]+", which excludes ${name} ${target.replace(/\./g, "\\.")}`));
      expect(reasonsOf(row)).toMatch(/upgrade requests to 2\.33\.0/);
      expect(reasonsOf(row)).not.toMatch(/waiting on upstream|blocked upstream|has to move first/i);
    }
    // The parent's own row names the same release.
    expect(step("requests")).toMatchObject({ scope: "direct", action: "upgrade_direct", targetVersion: "2.33.0" });
    expect(result.waitingOnUpstream).toBe(0);
    expect(result.parentUpgradeSteps).toBe(2);
    expect(result.summary).not.toMatch(/waiting on upstream/);
  });

  it("says so when the parent release needs a newer Python than the project supports", async () => {
    uvProject(">=3.9");
    const { step } = await h.plan();
    const row = step("idna");
    expect(row).toMatchObject({ action: "upgrade_parent" });
    expect(row.parentUpgrades[0]).toMatchObject({ parent: "requests", to: "2.33.0" });
    expect(reasonsOf(row)).toMatch(/requests 2\.33\.0 requires Python ">=3\.10" and this project supports Python ">=3\.9"/);
  });

  it("stays blocked when no release of the parent admits the fix", async () => {
    uvProject(">=3.10");
    for (const v of ["2.31.0", "2.33.0", "2.34.2"]) h.PYPI.requests[v].requiresDist = ["idna (<3,>=2.5)", "urllib3 (<3,>=1.21.1)"];
    const { step } = await h.plan();
    expect(step("idna")).toMatchObject({ action: "waiting_on_upstream" });
    expect(step("idna").parentUpgrades).toBeUndefined();
    expect(reasonsOf(step("idna"))).toMatch(/blocked upstream: requests 2\.25\.1 requires idna "<3,>=2\.5"/);
    // urllib3's fix is admitted by the same releases: that row still moves.
    expect(step("urllib3")).toMatchObject({ action: "upgrade_parent" });
  });
});

// ---------------------------------------------------------------------------
// The registry does not answer
// ---------------------------------------------------------------------------

describe("parent releases that could not be read", () => {
  function expressProject() {
    h.ADVISORIES = { "body-parser": [adv("GHSA-qwcr-r2fm-qrc7", "body-parser", fixedIn("1.20.3"))] };
    h.NPM = {
      express: { latest: "4.22.3", versions: { "4.17.1": { dependencies: { "body-parser": "1.19.0" } }, "4.22.3": { dependencies: { "body-parser": "~1.20.3" } } } },
      "body-parser": { latest: "1.20.3", versions: { "1.19.0": {}, "1.20.3": {} } },
    };
    h.npmProject({ express: "4.17.1" }, {}, {
      express: { version: "4.17.1", dependencies: { "body-parser": "1.19.0" } },
      "body-parser": { version: "1.19.0" },
    });
  }

  it("with the registry up, the parent upgrade is named", async () => {
    expressProject();
    const { result, step } = await h.plan();
    expect(step("body-parser")).toMatchObject({ action: "upgrade_parent" });
    expect(step("body-parser").parentUpgrades[0]).toMatchObject({ parent: "express", to: "4.22.3" });
    expect(result.summary).not.toMatch(/not determined/i);
  });

  it("with the registry unreachable, the fix path is NOT DETERMINED, never waiting on upstream", async () => {
    expressProject();
    h.down.add("registry.npmjs.org");
    const { result, step } = await h.plan();
    const row = step("body-parser");
    expect(row).toMatchObject({ scope: "transitive", action: "not_determined" });
    expect(row.parentUpgrades).toBeUndefined();
    expect(reasonsOf(row)).toMatch(/NOT DETERMINED/);
    expect(reasonsOf(row)).toMatch(/express 4\.17\.1 requires "1\.19\.0"/);
    expect(reasonsOf(row)).toMatch(/registry (?:could not be read|did not answer)/);
    expect(reasonsOf(row)).not.toMatch(/waiting on upstream/i);
    expect(result.waitingOnUpstream).toBe(0);
    expect(result.fixPathNotDetermined).toBe(1);
    expect(result.summary).toMatch(/1 transitive, fix path not determined/);
    expect(result.summary).not.toMatch(/waiting on upstream/);
  });

  it("vulnerability_scan does not call it waiting on upstream either", async () => {
    expressProject();
    h.down.add("registry.npmjs.org");
    const concise = await h.scan();
    const text = JSON.stringify(concise);
    expect(text).not.toMatch(/Waiting on upstream/);
    expect(text).not.toMatch(/"fix_action":"waiting_on_upstream"/);
    const line = (concise.recommendations as string[]).find((r) => r.includes("body-parser 1.19.0"));
    expect(line).toMatch(/NOT CHECKED/);
  });

  it("a transitive row no lookup ran for (offline) is not determined either", async () => {
    expressProject();
    h.down.add("registry.npmjs.org");
    h.down.add("api.osv.dev");
    // Nothing answers: the plan has no vulnerability data at all, and claims no wait.
    const { result } = await h.plan();
    expect(result.waitingOnUpstream).toBe(0);
    expect(result.summary).not.toMatch(/waiting on upstream/);
  });
});

// ---------------------------------------------------------------------------
// A parent release that brings in nothing new
// ---------------------------------------------------------------------------

describe("a parent release that holds only what the installed parent already holds", () => {
  const pins = { debug: "3.2.6", diff: "3.5.0", "js-yaml": "3.13.1" };
  function mochaProject() {
    h.ADVISORIES = {
      "yargs-parser": [adv("GHSA-p9pc-299p-vxgp", "yargs-parser", fixedIn("13.1.2"))],
      diff: [adv("GHSA-73rr-hh4g-fpgx", "diff", fixedIn("3.5.1"))],
      debug: [adv("GHSA-gxpj-cx7g-858c", "debug", fixedIn("3.2.7"))],
      "js-yaml": [adv("GHSA-mh29-5h37-fv8m", "js-yaml", fixedIn("3.14.2"))],
      "serialize-javascript": [adv("GHSA-5c6j-r48x-rmvq", "serialize-javascript", fixedIn("7.0.3"))],
    };
    h.NPM = {
      mocha: {
        latest: "7.1.2",
        versions: {
          "7.1.0": { dependencies: { ...pins, "yargs-parser": "13.1.1" } },
          "7.1.1": { dependencies: { ...pins, "yargs-parser": "13.1.2" } },
          "7.1.2": { dependencies: { ...pins, "yargs-parser": "13.1.2" } },
        },
      },
      "yargs-parser": { latest: "13.1.2", versions: { "13.1.1": {}, "13.1.2": {} } },
      diff: { latest: "3.5.1", versions: { "3.5.0": {}, "3.5.1": {} } },
      debug: { latest: "3.2.7", versions: { "3.2.6": {}, "3.2.7": {} } },
      "js-yaml": { latest: "3.14.2", versions: { "3.13.1": {}, "3.14.2": {} } },
      "serialize-javascript": { latest: "7.0.3", versions: { "3.0.0": {}, "7.0.3": {} } },
    };
    h.npmProject({}, { mocha: "7.1.0" }, {
      mocha: { version: "7.1.0", dev: true, dependencies: { ...pins, "yargs-parser": "13.1.1" } },
      "yargs-parser": { version: "13.1.1", dev: true },
      diff: { version: "3.5.0", dev: true },
      debug: { version: "3.2.6", dev: true },
      "js-yaml": { version: "3.13.1", dev: true },
    });
  }

  it("is named: it fixes this copy and brings in no advisory the installed parent lacks", async () => {
    mochaProject();
    const { step } = await h.plan();
    const row = step("yargs-parser");
    expect(row).toMatchObject({ scope: "transitive", action: "upgrade_parent", targetVersion: "13.1.2" });
    expect(row.parentUpgrades).toMatchObject([{ parent: "mocha", from: "7.1.0", to: "7.1.1", levers: [{ name: "mocha", to: "7.1.1" }] }]);
    const why = reasonsOf(row);
    expect(why).toMatch(/upgrade mocha to 7\.1\.1/);
    // Said, not hidden: the release still holds them, as the installed one does.
    expect(why).toMatch(/mocha 7\.1\.1 exact-pins/);
    expect(why).toMatch(/diff 3\.5\.0/);
    expect(why).toMatch(/as mocha 7\.1\.0 does/);
    expect(why).not.toMatch(/waiting on upstream/i);
  });

  it("is not named when it also brings in an affected dependency the installed parent does not hold", async () => {
    mochaProject();
    for (const v of ["7.1.1", "7.1.2"]) h.NPM.mocha.versions[v].dependencies!["serialize-javascript"] = "3.0.0";
    const { step } = await h.plan();
    const row = step("yargs-parser");
    expect(row.action).not.toBe("upgrade_parent");
    expect(row.parentUpgrades).toBeUndefined();
    expect(reasonsOf(row)).toMatch(/serialize-javascript 3\.0\.0/);
  });
});
