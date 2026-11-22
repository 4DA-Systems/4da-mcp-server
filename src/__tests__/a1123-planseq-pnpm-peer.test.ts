// SPDX-License-Identifier: Apache-2.0
/**
 * pnpm after a major bump of a parent (h3): vitest 4.1.12 lists vite under dependencies AND
 * peerDependencies, and pnpm takes a peer from the copy the project already has, so after
 * `pnpm up "vitest@^4.1.12"` the lockfile still held vite 5.3.1 and its 20 advisories. Checked with
 * pnpm 9.3.0 on a copy of h3's lockfile (2026-11-23): `pnpm update vite --depth Infinity` and
 * `pnpm up "vite@^6.4.5"` left it; `pnpm add -D "vite@^6.4.5"` moved it. The plan now names that
 * step after the parent's, on the row and in run_order.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { adv, createHarness, fixedIn, type Harness } from "./helpers/a1119-planner-harness.js";

let h: Harness;
beforeEach(() => {
  h = createHarness();
});
afterEach(() => h.dispose());

const LOCK = `lockfileVersion: '9.0'

settings:
  autoInstallPeers: true
  excludeLinksFromLockfile: false

importers:

  .:
    devDependencies:
      vitest:
        specifier: ^1.6.0
        version: 1.6.0

packages:

  vite@5.3.1:
    resolution: {integrity: sha512-vite}

  vitest@1.6.0:
    resolution: {integrity: sha512-vitest}

snapshots:

  vite@5.3.1: {}

  vitest@1.6.0:
    dependencies:
      vite: 5.3.1
`;

function project(vitest4: { dependencies?: Record<string, string>; peerDependencies?: Record<string, string> }) {
  h.write("package.json", JSON.stringify({ name: "x", version: "1.0.0", devDependencies: { vitest: "^1.6.0" } }));
  h.write("pnpm-lock.yaml", LOCK);
  h.ADVISORIES = { vite: [adv("GHSA-vite-0001", "vite", fixedIn("6.4.5"))] };
  h.NPM = {
    vitest: { latest: "4.1.12", versions: { "1.6.0": { dependencies: { vite: "^5.0.0" } }, "4.1.12": vitest4 } },
    vite: { latest: "6.4.5", versions: { "5.3.1": {}, "6.4.5": {} } },
  };
}

const RANGE = "^6.0.0 || ^7.0.0 || ^8.0.0";

describe("pnpm: a parent release that takes the vulnerable package as a peer", () => {
  it("names the declaring step after the parent's upgrade, on the row and in run_order", async () => {
    project({ dependencies: { vite: RANGE }, peerDependencies: { vite: RANGE } });
    const { result, step } = await h.plan();
    const vite = step("vite");
    expect(vite).toMatchObject({ scope: "transitive", action: "upgrade_parent" });
    expect(vite.commands).toEqual([
      { dir: ".", run: 'pnpm up "vitest@^4.1.12"' },
      { dir: ".", run: 'pnpm add -D "vite@^6.4.5"' },
    ]);
    expect(vite.reasons.join(" ")).toMatch(/vitest 4\.1\.12 lists vite as a peer dependency, and pnpm takes a peer from the copy the project already has, so it keeps vite 5\.3\.1 after that upgrade: then declare it, `pnpm add -D "vite@\^6\.4\.5"`/);
    expect(result.run_order.map((s: { run: string }) => s.run)).toEqual(['pnpm up "vitest@^4.1.12"', 'pnpm add -D "vite@^6.4.5"']);
    expect(result.run_order[1].fixes).toEqual(["npm:vite"]);
  });

  it("names no such step when the new parent release lists it only as a dependency", async () => {
    project({ dependencies: { vite: RANGE } });
    const { result, step } = await h.plan();
    expect(step("vite").commands).toEqual([{ dir: ".", run: 'pnpm up "vitest@^4.1.12"' }]);
    expect(step("vite").reasons.join(" ")).not.toMatch(/peer dependency/);
    expect(result.run_order.map((s: { run: string }) => s.run)).toEqual(['pnpm up "vitest@^4.1.12"']);
  });
});
