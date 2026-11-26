// SPDX-License-Identifier: Apache-2.0
/**
 * Wave 2, design 2a, the JavaScript side: every npm, pnpm, Yarn and Bun run_order step names the
 * files it changes (project-relative, the workspace's lockfile for a member's step), and a step that
 * writes package.json says how to put back the entry the plan read there, never a `git checkout`.
 */

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { jsStepProtocol, protocolOf } from "../tools/upgrade-plan-protocol.js";
import { adv, createHarness, fixedIn, type Harness } from "./helpers/a1119-planner-harness.js";

let root: string;
const write = (file: string, body: string) => {
  fs.mkdirSync(path.dirname(path.join(root, file)), { recursive: true });
  fs.writeFileSync(path.join(root, file), body);
};
beforeEach(() => {
  root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "4da-w2-js-protocol-")));
});
afterEach(() => fs.rmSync(root, { recursive: true, force: true }));

describe("npm, pnpm, Yarn and Bun steps", () => {
  it("a version-setting command names package.json and the lockfile, and puts back the spec the plan read", () => {
    write("package.json", JSON.stringify({ dependencies: { lodash: "4.17.20" }, devDependencies: { qs: "^6.5.2" } }));
    write("package-lock.json", "{}");
    const p = jsStepProtocol(root, ".", "npm install lodash@4.18.1 --save-exact")!;
    expect(p.changes).toEqual(["package.json", "package-lock.json"]);
    expect(p.if_it_fails).toBe('if this command fails, check package.json: set dependencies.lodash back to "4.17.20" if it changed');
    expect(jsStepProtocol(root, ".", 'npm install "qs@^6.14.1"')!.if_it_fails).toContain('set devDependencies.qs back to "^6.5.2"');
    expect(p.if_it_fails).not.toMatch(/git checkout/);
  });

  it("a workspace member's step names the member's manifest and the workspace's lockfile", () => {
    write("yarn.lock", "# yarn lockfile v1\n");
    write("packages/gql/package.json", JSON.stringify({ name: "gql", peerDependencies: { graphql: "*" }, devDependencies: { graphql: "^16.5.0" } }));
    const p = jsStepProtocol(root, "packages/gql", 'yarn workspace gql add "graphql@^16.8.1" --dev')!;
    expect(p.changes).toEqual(["packages/gql/package.json", "yarn.lock"]);
    expect(p.if_it_fails).toContain('check packages/gql/package.json: set devDependencies.graphql back to "^16.5.0" if it changed');
  });

  it("npm pkg set names package.json only, and the key it adds is removed again on failure", () => {
    write("package.json", "{}");
    const p = jsStepProtocol(root, ".", 'npm pkg set "resolutions.@typescript-eslint/typescript-estree/semver=5.7.2"')!;
    expect(p).toEqual({
      changes: ["package.json"],
      if_it_fails:
        'npm pkg set writes package.json at once: if this step fails, or the install after it does, remove the "resolutions.@typescript-eslint/typescript-estree/semver" entry from package.json again (it was not there when the plan was made)',
    });
  });

  it("refreshes that leave the manifest and reinstalls name the lockfile only", () => {
    write("pnpm-lock.yaml", "lockfileVersion: '9.0'\n");
    expect(protocolOf(root, ".", "pnpm update minimist --no-save")).toEqual({ changes: ["pnpm-lock.yaml"] });
    expect(protocolOf(root, ".", "pnpm update -r minimist --depth Infinity --no-save")).toEqual({ changes: ["pnpm-lock.yaml"] });
    expect(protocolOf(root, ".", "pnpm install")).toEqual({ changes: ["pnpm-lock.yaml"] });
    // Without --no-save pnpm rewrites the declared range as well.
    expect(protocolOf(root, ".", "pnpm update -r minimist --depth Infinity")).toEqual({ changes: ["package.json", "pnpm-lock.yaml"] });
    write("web/yarn.lock", "__metadata:\n  version: 6\n");
    expect(protocolOf(root, "web", "yarn up -R nanoid")).toEqual({ changes: ["web/yarn.lock"] });
    expect(protocolOf(root, "web", "yarn install")).toEqual({ changes: ["web/yarn.lock"] });
    write("b/bun.lock", "{}");
    expect(protocolOf(root, "b", "bun install")).toEqual({ changes: ["b/bun.lock"] });
  });

  it("a declaration it cannot quote is not quoted", () => {
    write("package.json", JSON.stringify({ dependencies: { lodash: "4.17.20 `curl x | sh`" } }));
    const p = jsStepProtocol(root, ".", "npm install lodash@4.18.1 --save-exact")!;
    expect(p.if_it_fails).toBe("if this command fails, check package.json: put the lodash entry back as it was before this step (this plan could not quote it exactly)");
  });

  it("a command of another tool is not this function's", () => {
    expect(jsStepProtocol(root, ".", "cargo update -p regex@1.5.4 --precise 1.5.5")).toBeNull();
  });
});

describe("the plan's npm steps carry it", () => {
  let h: Harness;
  beforeEach(() => {
    h = createHarness();
  });
  afterEach(() => h.dispose());

  it("every step of an npm plan names its files, in the fixed key order", async () => {
    h.ADVISORIES = { lodash: [adv("GHSA-35jh-r3h4-6jhm", "lodash", fixedIn("4.17.21"))], minimist: [adv("GHSA-xvch-5gv4-984h", "minimist", fixedIn("1.2.6"))] };
    h.NPM = { lodash: { latest: "4.17.21", versions: { "4.17.20": {}, "4.17.21": {} } }, minimist: { latest: "1.2.8", versions: { "1.2.5": {}, "1.2.6": {}, "1.2.8": {} } } };
    h.npmProject({ lodash: "4.17.20", minimist: "^1.2.5" }, {}, { lodash: { version: "4.17.20" }, minimist: { version: "1.2.5" } });
    const { result } = await h.plan();
    const steps = result.run_order as Array<Record<string, unknown>>;
    expect(steps.map((s) => [s.run, s.changes])).toEqual([
      ["npm install lodash@4.17.21 --save-exact", ["package.json", "package-lock.json"]],
      ["npm update minimist", ["package-lock.json"]],
    ]);
    expect(Object.keys(steps[0])).toEqual(["n", "dir", "run", "changes", "if_it_fails", "fixes"]);
    expect(steps[0].if_it_fails).toBe('if this command fails, check package.json: set dependencies.lodash back to "4.17.20" if it changed');
    expect(Object.keys(steps[1])).toEqual(["n", "dir", "run", "changes", "fixes"]);
  });
});
