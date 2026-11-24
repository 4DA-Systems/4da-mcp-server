// SPDX-License-Identifier: Apache-2.0
/**
 * An override that redirects a dependency to local code, git or a URL makes that dependency what the
 * override says: npm `overrides` (nested form included), Yarn `resolutions`, pnpm `pnpm.overrides`
 * and the `overrides:` of pnpm-workspace.yaml.
 *
 * Privacy review of the 6.5.1 candidate (2026-11-24, projects/npm-overrides): with no lockfile,
 * `"zqrev-ovr-npm": "^1.0.0"` overridden to `file:./vendor/...`, a `portal:` resolution and a
 * `link:` pnpm override: all three names went to registry.npmjs.org, api.npmjs.org and
 * hn.algolia.com. Stubbed fetch: nothing leaves the machine.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { executeDependencyHealth } from "../tools/dependency-health.js";
import { executeDependencyCheck } from "../tools/dependency-check.js";
import { executeEcosystemPulse } from "../tools/ecosystem-pulse.js";
import { allOverrideSpecs, overrideKeyName } from "../live/overrides.js";
import { createHarness, type Harness } from "./helpers/a1119-planner-harness.js";

let h: Harness;
let bodies: string[];
const INVENTED = /acme/i;
const sent = () => [...h.requests, ...bodies].map((s) => decodeURIComponent(s));
const leaked = () => sent().filter((s) => INVENTED.test(s));

beforeEach(() => {
  h = createHarness();
  bodies = [];
  const inner = globalThis.fetch;
  vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
    if (init?.body) bodies.push(String(init.body));
    return inner(input, init);
  });
  h.NPM = { ms: { latest: "2.1.3", versions: { "2.1.3": {} } } };
});
afterEach(() => h.dispose());

describe("override keys and tables", () => {
  it("names the package each key forces", () => {
    expect(["foo", "foo@1", "bar>foo", "bar@1>foo@2", "**/foo", "bar/foo", "@s/x", "**/@s/x@1", "bar>@s/x"].map(overrideKeyName)).toEqual(["foo", "foo", "foo", "foo", "foo", "foo", "@s/x", "@s/x", "@s/x"]);
    const specs = allOverrideSpecs({ overrides: { a: { ".": "1.0.0", b: "file:./b" } }, resolutions: { "**/c": "portal:./c" }, pnpm: { overrides: { "x>d": "link:./d" } } }, "overrides:\n  e: link:./e\n");
    expect(specs.map((s) => [s.name, s.spec])).toEqual([
      ["a", "1.0.0"],
      ["b", "file:./b"],
      ["c", "portal:./c"],
      ["d", "link:./d"],
      ["e", "link:./e"],
    ]);
  });
});

describe("no lockfile: an override to local code keeps the name off the network", () => {
  it("npm overrides, Yarn resolutions, pnpm.overrides and pnpm-workspace.yaml overrides", async () => {
    h.write(
      "package.json",
      JSON.stringify({
        name: "ovr",
        version: "1.0.0",
        dependencies: { "acme-ovr-npm": "^1.0.0", "acme-ovr-yarn": "^1.0.0", "acme-ovr-pnpm": "^1.0.0", "acme-ovr-yaml": "^1.0.0", "acme-ovr-nested": "^1.0.0", ms: "2.1.3" },
        overrides: { "acme-ovr-npm": "file:./vendor/acme-ovr-npm", ms: { "acme-ovr-nested": "github:acmeorg/acme-ovr-nested" } },
        resolutions: { "acme-ovr-yarn": "portal:./vendor/acme-ovr-yarn" },
        pnpm: { overrides: { "acme-ovr-pnpm": "link:./vendor/acme-ovr-pnpm" } },
      }),
    );
    h.write("pnpm-workspace.yaml", "overrides:\n  acme-ovr-yaml: link:./vendor/acme-ovr-yaml\n");
    await executeDependencyHealth(null, {}, await h.live());
    await h.plan();
    await h.scan();
    const live = await h.live();
    await executeEcosystemPulse(null, {}, live);
    await executeDependencyCheck(null, { items: ["acme-ovr-npm", "acme-ovr-yarn", "acme-ovr-pnpm", "acme-ovr-yaml", "acme-ovr-nested"].map((p) => ({ ecosystem: "npm", package: p, to: "1.0.1" })) }, live);
    expect(leaked()).toEqual([]);
    expect(h.requests).toContain("https://registry.npmjs.org/ms");
  });
});
