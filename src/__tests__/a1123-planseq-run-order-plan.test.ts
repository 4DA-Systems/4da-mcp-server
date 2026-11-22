// SPDX-License-Identifier: Apache-2.0
/**
 * run_order end to end: upgrade_planner on a fixture lockfile, registry and OSV stubbed at the HTTP
 * boundary, one case per rule of DESIGN 3 that the planner itself can reach.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { adv, createHarness, fixedIn, type Harness } from "./helpers/a1119-planner-harness.js";

let h: Harness;
beforeEach(() => {
  h = createHarness();
});
afterEach(() => h.dispose());

const steps = (result: Record<string, any>) => (result.run_order as Array<{ n: number; dir: string; run: string; fixes: string[] }>).map((s) => s.run);

describe("(a) one command per package per directory", () => {
  it("two rows that need different releases of one lever get one install, at the higher, and the note says the lower row was not confirmed", async () => {
    h.ADVISORIES = { a: [adv("GHSA-aaaa-0001", "a", fixedIn("1.0.1"))], b: [adv("GHSA-bbbb-0001", "b", fixedIn("1.0.1"))] };
    h.NPM = {
      lev: { latest: "3.0.0", versions: { "1.0.0": { dependencies: { a: "1.0.0", b: "1.0.0" } }, "2.0.0": { dependencies: { a: "^1.0.1", b: "1.0.0" } }, "3.0.0": { dependencies: { a: "1.0.0", b: "^1.0.1" } } } },
      a: { latest: "1.0.1", versions: { "1.0.0": {}, "1.0.1": {} } },
      b: { latest: "1.0.1", versions: { "1.0.0": {}, "1.0.1": {} } },
    };
    h.npmProject({ lev: "1.0.0" }, {}, { lev: { version: "1.0.0", dependencies: { a: "1.0.0", b: "1.0.0" } }, a: { version: "1.0.0" }, b: { version: "1.0.0" } });
    const { result, step } = await h.plan();
    expect(step("a").commands).toEqual([{ dir: ".", run: "npm install lev@2.0.0 --save-exact" }]);
    expect(step("b").commands).toEqual([{ dir: ".", run: "npm install lev@3.0.0 --save-exact" }]);
    const lev = result.run_order.filter((s: { run: string }) => /^npm install lev@/.test(s.run));
    expect(lev).toEqual([{ n: lev[0].n, dir: ".", run: "npm install lev@3.0.0 --save-exact", fixes: ["npm:a", "npm:b"] }]);
    expect(result.run_order_note).toMatch(/lev is set once in the project root, at 3\.0\.0, for rows that named 2\.0\.0 and 3\.0\.0/);
    expect(result.run_order_note).toMatch(/that it also brings in the fix of a 1\.0\.0, whose row named a lower release, was not confirmed/);
  });
});

describe("(c) one go get per module directory", () => {
  it("a direct target another target's go.mod already raises past is not named, so nothing is downgraded", async () => {
    h.write("go.mod", "module example.com/demo\n\ngo 1.21\n\nrequire (\n\tgolang.org/x/sys v0.1.0\n\tgolang.org/x/crypto v0.1.0 // indirect\n)\n");
    h.write("go.sum", ["golang.org/x/sys v0.1.0 h1:a=", "golang.org/x/sys v0.1.0/go.mod h1:b=", "golang.org/x/crypto v0.1.0 h1:c=", "golang.org/x/crypto v0.1.0/go.mod h1:d="].join("\n") + "\n");
    h.ADVISORIES = {
      "golang.org/x/sys": [adv("GO-2026-0001", "golang.org/x/sys", fixedIn("0.44.0"), "Go")],
      "golang.org/x/crypto": [adv("GO-2026-0002", "golang.org/x/crypto", fixedIn("0.59.0"), "Go")],
    };
    h.GO = { "golang.org/x/sys": ["v0.1.0", "v0.44.0", "v0.50.0"], "golang.org/x/crypto": ["v0.1.0", "v0.59.0"] };
    h.GOMOD = { "golang.org/x/sys@v0.44.0": "1.21", "golang.org/x/crypto@v0.59.0": "1.21" };
    h.GOREQ = { "golang.org/x/crypto@v0.59.0": ["golang.org/x/sys v0.50.0"] };
    const { result, step } = await h.plan();
    expect(step("golang.org/x/sys")).toMatchObject({ action: "upgrade_direct", commands: [{ dir: ".", run: "go get golang.org/x/sys@v0.44.0" }] });
    expect(step("golang.org/x/crypto")).toMatchObject({ action: "lockfile_refresh", commands: [{ dir: ".", run: "go get golang.org/x/crypto@v0.59.0" }, { dir: ".", run: "go mod tidy" }] });
    expect(steps(result)).toEqual(["go get golang.org/x/crypto@v0.59.0", "go mod tidy"]);
    expect(result.run_order[0].fixes).toEqual(["Go:golang.org/x/crypto", "Go:golang.org/x/sys"]);
    expect(result.run_order_note).toMatch(/golang\.org\/x\/sys is not named in the project root's go get: golang\.org\/x\/crypto v0\.59\.0's go\.mod requires v0\.50\.0/);
  });
});

describe("(d) a parent upgrade before the refreshes it carries", () => {
  it("the refresh that follows a lever's install runs after it; an unrelated refresh runs with the other refreshes, after the upgrades", async () => {
    h.ADVISORIES = { child: [adv("GHSA-cccc-0001", "child", fixedIn("1.0.2"))], other: [adv("GHSA-oooo-0001", "other", fixedIn("2.0.1"))] };
    h.NPM = {
      par: { latest: "1.0.1", versions: { "1.0.0": { dependencies: { child: "1.0.0" } }, "1.0.1": { dependencies: { child: "^1.0.0" } } } },
      child: { latest: "1.0.2", versions: { "1.0.0": {}, "1.0.2": {} } },
      host: { latest: "1.0.0", versions: { "1.0.0": { dependencies: { other: "^2.0.0" } } } },
      other: { latest: "2.0.1", versions: { "2.0.0": {}, "2.0.1": {} } },
    };
    h.npmProject({ par: "1.0.0", host: "1.0.0" }, {}, {
      par: { version: "1.0.0", dependencies: { child: "1.0.0" } },
      child: { version: "1.0.0" },
      host: { version: "1.0.0", dependencies: { other: "^2.0.0" } },
      other: { version: "2.0.0" },
    });
    const { result, step } = await h.plan();
    expect(step("child").commands).toEqual([
      { dir: ".", run: "npm install par@1.0.1 --save-exact" },
      { dir: ".", run: "npm update child" },
    ]);
    expect(steps(result)).toEqual(["npm install par@1.0.1 --save-exact", "npm update child", "npm update other"]);
  });
});

describe("(e) a target that leaves an installed direct dependency's peer range", () => {
  it("is left out of run_order, and its row names the holder and the range", async () => {
    h.ADVISORIES = { vite: [adv("GHSA-vvvv-0001", "vite", fixedIn("6.4.5"))], nanoid: [adv("GHSA-nnnn-0001", "nanoid", fixedIn("3.3.8"))] };
    h.NPM = {
      vite: { latest: "6.4.5", versions: { "5.0.0": { dependencies: { nanoid: "^3.3.7" } }, "6.4.5": {} } },
      "@vitejs/plugin-react-swc": { latest: "3.5.0", versions: { "3.5.0": { peerDependencies: { vite: "^4 || ^5" } } } },
      nanoid: { latest: "3.3.8", versions: { "3.3.7": {}, "3.3.8": {} } },
    };
    const root = { name: "x", version: "1.0.0", devDependencies: { vite: "^5.0.0", "@vitejs/plugin-react-swc": "3.5.0" } };
    h.write("package.json", JSON.stringify(root));
    h.write(
      "package-lock.json",
      JSON.stringify({
        name: "x",
        lockfileVersion: 3,
        packages: {
          "": root,
          "node_modules/vite": { version: "5.0.0", dev: true, dependencies: { nanoid: "^3.3.7" } },
          "node_modules/@vitejs/plugin-react-swc": { version: "3.5.0", dev: true, peerDependencies: { vite: "^4 || ^5" } },
          "node_modules/nanoid": { version: "3.3.7", dev: true },
        },
      }),
    );
    const { result, step } = await h.plan();
    const vite = step("vite");
    expect(vite.commands).toEqual([{ dir: ".", run: 'npm install "vite@^6.4.5"' }]);
    expect(vite.reasons.join(" ")).toMatch(/vite 6\.4\.5 leaves a peer range an installed direct dependency holds on it \(@vitejs\/plugin-react-swc 3\.5\.0 declares "\^4 \|\| \^5"\)/);
    expect(steps(result)).toEqual(["npm update nanoid"]);
    expect(result.run_order_note).toMatch(/break a peer range an installed dependency declares .*: vite 5\.0\.0/);
  });
});

describe("(f) every step and snippet names its directory", () => {
  it("an override in a nested project names that project's package.json and where to install", async () => {
    h.ADVISORIES = { child: [adv("GHSA-cccc-0002", "child", fixedIn("1.0.2"))] };
    h.NPM = {
      par: { latest: "1.0.0", versions: { "1.0.0": { dependencies: { child: "1.0.0" } } } },
      child: { latest: "1.0.2", versions: { "1.0.0": {}, "1.0.2": {} } },
    };
    const web = { name: "web", version: "1.0.0", dependencies: { par: "1.0.0" } };
    h.write("web/package.json", JSON.stringify(web));
    h.write(
      "web/package-lock.json",
      JSON.stringify({ name: "web", lockfileVersion: 3, packages: { "": web, "node_modules/par": { version: "1.0.0", dependencies: { child: "1.0.0" } }, "node_modules/child": { version: "1.0.0" } } }),
    );
    const { result, step } = await h.plan();
    const row = step("child");
    expect(row.action).toBe("override_or_replace");
    expect(row.reasons.join(" ")).toContain('npm: add "overrides": { "child": "1.0.2" } to web/package.json (npm 8.3+), then npm install in web');
    // The snippet is also written as the commands that make it, in that project's directory.
    expect(row.commands).toEqual([
      { dir: "web", run: 'npm pkg set "overrides.child=1.0.2"' },
      { dir: "web", run: "npm install" },
    ]);
    expect(result.run_order.map((s: { dir: string; run: string }) => [s.dir, s.run])).toEqual([
      ["web", 'npm pkg set "overrides.child=1.0.2"'],
      ["web", "npm install"],
    ]);
    expect(result.run_order_note).toMatch(/1 of them force a version with an override or resolution written by `npm pkg set` \(child 1\.0\.0\)/);
    for (const s of result.run_order) expect(typeof s.dir).toBe("string");
  });
});
