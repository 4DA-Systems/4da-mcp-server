// SPDX-License-Identifier: Apache-2.0
/**
 * An `npm:` alias's key (the folder name it installs under) is never sent: only its target is a
 * registry package. Privacy review of the 6.5.1 candidate (2026-11-24, case auto-pnpm9):
 * package.json `"zqrev-alias-key": "npm:ms@2.1.3"` with a pnpm (v6, v9), Yarn v1, Yarn berry or Bun
 * lockfile sent `registry.npmjs.org/zqrev-alias-key` from dependency_health and upgrade_planner,
 * the api.npmjs.org downloads URL and an hn.algolia.com query, and made a dependency_health row for
 * the key with no version: the key was mapped to its target (resolution.ts `real()`) only through
 * the aliases the package-lock and no-lockfile readers record, and the pnpm, Yarn and Bun readers
 * record none. Asked directly, dependency_check and upgrade_impact sent the key (in any letter case)
 * to OSV and the registry and judged the registry's package of that name.
 *
 * Now the manifests' own aliases map every key to its target, whatever the lockfile, and the key is
 * withheld when asked about directly, with the target named. Stubbed fetch: nothing leaves the machine.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { executeDependencyHealth } from "../tools/dependency-health.js";
import { executeDependencyCheck } from "../tools/dependency-check.js";
import { executeEcosystemPulse } from "../tools/ecosystem-pulse.js";
import { executeUpgradeImpact } from "../tools/upgrade-impact.js";
import { executeWhatShouldIKnow } from "../tools/what-should-i-know.js";
import { createHarness, type Harness } from "./helpers/a1119-planner-harness.js";

let h: Harness;
let bodies: string[];
const KEY = /acme-alias-key/i;
const sent = () => [...h.requests, ...bodies].map((s) => decodeURIComponent(s));
const leaked = () => sent().filter((s) => KEY.test(s));

beforeEach(() => {
  h = createHarness();
  bodies = [];
  const inner = globalThis.fetch;
  vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
    if (init?.body) bodies.push(String(init.body));
    return inner(input, init);
  });
  h.NPM = { ms: { latest: "2.1.3", versions: { "2.1.3": {} } }, lodash: { latest: "4.17.21", versions: { "4.17.21": {} } } };
});
afterEach(() => h.dispose());

const MANIFEST = { name: "app", version: "1.0.0", dependencies: { ms: "2.1.3", lodash: "4.17.21", "acme-alias-key": "npm:ms@2.1.3" } };

const LOCKFILES: Record<string, Record<string, string>> = {
  "pnpm-lock.yaml v9": {
    "pnpm-lock.yaml": [
      "lockfileVersion: '9.0'",
      "",
      "importers:",
      "",
      "  .:",
      "    dependencies:",
      "      acme-alias-key:",
      "        specifier: npm:ms@2.1.3",
      "        version: ms@2.1.3",
      "      lodash:",
      "        specifier: 4.17.21",
      "        version: 4.17.21",
      "      ms:",
      "        specifier: 2.1.3",
      "        version: 2.1.3",
      "",
      "packages:",
      "",
      "  lodash@4.17.21:",
      "    resolution: {integrity: sha512-x}",
      "",
      "  ms@2.1.3:",
      "    resolution: {integrity: sha512-x}",
      "",
      "snapshots:",
      "",
      "  lodash@4.17.21: {}",
      "",
      "  ms@2.1.3: {}",
      "",
    ].join("\n"),
  },
  "pnpm-lock.yaml v6": {
    "pnpm-lock.yaml": [
      "lockfileVersion: '6.0'",
      "",
      "dependencies:",
      "  acme-alias-key:",
      "    specifier: npm:ms@2.1.3",
      "    version: /ms@2.1.3",
      "  lodash:",
      "    specifier: 4.17.21",
      "    version: 4.17.21",
      "  ms:",
      "    specifier: 2.1.3",
      "    version: 2.1.3",
      "",
      "packages:",
      "",
      "  /lodash@4.17.21:",
      "    resolution: {integrity: sha512-x}",
      "    dev: false",
      "",
      "  /ms@2.1.3:",
      "    resolution: {integrity: sha512-x}",
      "    dev: false",
      "",
    ].join("\n"),
  },
  "yarn.lock v1": {
    "yarn.lock": [
      "# yarn lockfile v1",
      "",
      "",
      "lodash@4.17.21:",
      '  version "4.17.21"',
      '  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz#x"',
      "",
      'ms@2.1.3, "acme-alias-key@npm:ms@2.1.3":',
      '  version "2.1.3"',
      '  resolved "https://registry.yarnpkg.com/ms/-/ms-2.1.3.tgz#x"',
      "",
    ].join("\n"),
  },
  "yarn.lock berry": {
    "yarn.lock": [
      "__metadata:",
      "  version: 8",
      "  cacheKey: 10c0",
      "",
      '"app@workspace:.":',
      "  version: 0.0.0-use.local",
      '  resolution: "app@workspace:."',
      "  dependencies:",
      '    acme-alias-key: "npm:ms@2.1.3"',
      "    lodash: 4.17.21",
      "    ms: 2.1.3",
      "  languageName: unknown",
      "  linkType: soft",
      "",
      '"lodash@npm:4.17.21":',
      "  version: 4.17.21",
      '  resolution: "lodash@npm:4.17.21"',
      "  checksum: 10c0/0000",
      "  languageName: node",
      "  linkType: hard",
      "",
      '"ms@npm:2.1.3, acme-alias-key@npm:ms@2.1.3":',
      "  version: 2.1.3",
      '  resolution: "ms@npm:2.1.3"',
      "  checksum: 10c0/0000",
      "  languageName: node",
      "  linkType: hard",
      "",
    ].join("\n"),
  },
  "bun.lock": {
    "bun.lock": JSON.stringify({
      lockfileVersion: 1,
      workspaces: { "": { name: "app", dependencies: MANIFEST.dependencies } },
      packages: {
        "acme-alias-key": ["ms@2.1.3", "", {}, "sha512-x"],
        lodash: ["lodash@4.17.21", "", {}, "sha512-x"],
        ms: ["ms@2.1.3", "", {}, "sha512-x"],
      },
    }),
  },
  "no lockfile": {},
};

describe.each(Object.entries(LOCKFILES))("an npm: alias key with %s", (_label, files) => {
  beforeEach(() => {
    h.write("package.json", JSON.stringify(MANIFEST));
    for (const [file, body] of Object.entries(files)) h.write(file, body);
  });

  it("no automatic tool sends the key, and no row is named after it", async () => {
    const r = (await executeDependencyHealth(null, {}, await h.live())) as unknown as Record<string, any>;
    await h.plan();
    await h.scan();
    await executeEcosystemPulse(null, {}, await h.live());
    expect(leaked()).toEqual([]);
    expect(r.dependencies.map((d: { name: string }) => d.name).filter((n: string) => KEY.test(n))).toEqual([]);
    expect(h.requests).toContain("https://registry.npmjs.org/ms");
  });

  it("asked directly, in any letter case, the key is withheld and its target named", async () => {
    const live = await h.live();
    const check = (await executeDependencyCheck(null, { items: [{ ecosystem: "npm", package: "acme-alias-key", to: "2.1.3" }, { ecosystem: "npm", package: "ACME-ALIAS-KEY", to: "2.1.3" }] }, live)) as { results: Array<{ verdict: string; not_checked?: string; reason?: string }> };
    const impact = await executeUpgradeImpact(null, { package: "acme-alias-key", to_version: "3.0.0", ecosystem: "npm" }, live);
    await executeWhatShouldIKnow(null, { task: "upgrade acme-alias-key to 3.0.0", project_path: h.dir }, live);
    expect(leaked()).toEqual([]);
    expect(check.results.map((x) => [x.verdict, x.not_checked])).toEqual([
      ["unknown", "private"],
      ["unknown", "private"],
    ]);
    expect(check.results[0].reason).toMatch(/alias of ms/);
    expect(JSON.stringify(impact)).toMatch(/alias of ms/);
  });
});
