// SPDX-License-Identifier: Apache-2.0
/**
 * A dependency package.json takes from a path (`file:` directory or archive), git or a URL is not
 * the registry package of its name, and its name may be private: it is never sent anywhere (the
 * README's privacy section says so). On 6.5.0 dependency_health and upgrade_planner made a
 * registry row for each declared npm dependency by name, so `"acme-local-lib": "file:libs/..."`
 * went to registry.npmjs.org/acme-local-lib and api.npmjs.org/downloads (seen on the published
 * 6.5.0 behind a dead proxy: a row for it with `fetchError: "fetch failed"`). Now no registry row
 * is made for such a dependency, so its name is not sent; the registry dependencies beside it are
 * looked up as before. Every request is recorded by the harness's stubbed fetch.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { executeDependencyHealth } from "../tools/dependency-health.js";
import { createHarness, type Harness } from "./helpers/a1119-planner-harness.js";

let h: Harness;
const LOCAL = /acme-local-lib|acme-git-lib|acme-tgz|acme-url-lib/;

beforeEach(() => {
  h = createHarness();
  h.NPM = { minimist: { latest: "1.2.8", versions: { "1.2.8": {} } } };
  const root = {
    name: "x",
    version: "1.0.0",
    dependencies: {
      minimist: "1.2.8",
      "acme-local-lib": "file:libs/acme-local-lib",
      "acme-tgz": "file:vendor/acme-tgz-1.0.0.tgz",
      "acme-git-lib": "github:acme/acme-git-lib",
      "acme-url-lib": "https://example.com/acme-url-lib-1.0.0.tgz",
    },
  };
  h.write("package.json", JSON.stringify(root));
  h.write("libs/acme-local-lib/package.json", JSON.stringify({ name: "acme-local-lib", version: "1.0.0" }));
  // As npm 10 writes them (npm install --package-lock-only).
  h.write(
    "package-lock.json",
    JSON.stringify({
      name: "x",
      version: "1.0.0",
      lockfileVersion: 3,
      requires: true,
      packages: {
        "": root,
        "libs/acme-local-lib": { version: "1.0.0" },
        "node_modules/acme-local-lib": { resolved: "libs/acme-local-lib", link: true },
        "node_modules/acme-tgz": { version: "1.0.0", resolved: "file:vendor/acme-tgz-1.0.0.tgz" },
        "node_modules/acme-git-lib": { version: "1.0.0", resolved: "git+ssh://git@github.com/acme/acme-git-lib.git#0123456789abcdef0123456789abcdef01234567" },
        "node_modules/acme-url-lib": { version: "1.0.0", resolved: "https://example.com/acme-url-lib-1.0.0.tgz" },
        "node_modules/minimist": { version: "1.2.8", resolved: "https://registry.npmjs.org/minimist/-/minimist-1.2.8.tgz" },
      },
    }),
  );
});
afterEach(() => h.dispose());

describe("npm dependencies from a path, git or a URL are never sent", () => {
  it("dependency_health asks the registry about minimist only", async () => {
    const r = (await executeDependencyHealth(null, {}, await h.live())) as unknown as Record<string, any>;
    expect(h.requests.filter((u) => LOCAL.test(decodeURIComponent(u)))).toEqual([]);
    expect(h.requests.some((u) => u === "https://registry.npmjs.org/minimist")).toBe(true);
    expect(r.dependencies.map((d: { name: string }) => d.name)).toEqual(["minimist"]);
  });

  it("upgrade_planner and vulnerability_scan send none of their names either", async () => {
    await h.plan();
    await h.scan();
    expect(h.requests.filter((u) => LOCAL.test(decodeURIComponent(u)))).toEqual([]);
  });
});
