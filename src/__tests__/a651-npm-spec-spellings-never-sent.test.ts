// SPDX-License-Identifier: Apache-2.0
/**
 * Every npm spelling of a dependency that is not a registry release keeps its name off the network,
 * as npm-package-arg reads the spec: a bare relative or absolute path (`../libs/x`, `./libs/x`,
 * `~/x`, `/abs/x`, `C:\x`), a bare tarball path (`vendor/x-1.0.0.tgz`, `x-1.0.0.tgz`), GitHub
 * shorthand (`org/repo`, `org/repo#ref`), and a tarball URL on a host that is not the public
 * registry. The 6.5.1 candidate withheld only `file:`, `github:` and URL specs: review of the
 * candidate (2026-11-24, out-priv1/out-priv2) saw `registry.npmjs.org/zqrev-relpath`,
 * `zqrev-ghshort`, `zqrev-bare-tgz`, `zqrev-privreg-tarball` and the api.npmjs.org downloads batch
 * carrying all of them, with and without a package-lock.json that marks them `link: true` or
 * `git+ssh`. The lockfile's own evidence counts too: a dependency declared with a range that the
 * lockfile installs as a link (a workspace member) is local code.
 *
 * Controls: ordinary ranges and dist-tags on real packages (`^1.2.3`, `7.x`, `>=4 <5`, `*`, ``,
 * `latest`, `next`, an exact version, an `npm:` alias's TARGET, `catalog:`) are still looked up.
 * Every request (URL and body) is recorded by the harness's stubbed fetch; nothing leaves the machine.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { executeDependencyHealth } from "../tools/dependency-health.js";
import { executeDependencyCheck } from "../tools/dependency-check.js";
import { executeEcosystemPulse } from "../tools/ecosystem-pulse.js";
import { executeUpgradeImpact } from "../tools/upgrade-impact.js";
import { executeWhatShouldIKnow } from "../tools/what-should-i-know.js";
import { classifyNpmSpec } from "../live/npm-spec.js";
import { createHarness, type Harness } from "./helpers/a1119-planner-harness.js";

let h: Harness;
let bodies: string[];
const INVENTED = /acme/i;

/** Every request the tools made, URL and body, decoded. */
const sent = () => [...h.requests, ...bodies].map((s) => decodeURIComponent(s));
const leaked = () => sent().filter((s) => INVENTED.test(s));

const NON_REGISTRY: Record<string, string> = {
  "acme-relpath": "../libs/acme-relpath",
  "acme-dotpath": "./libs/acme-relpath",
  "acme-homepath": "~/src/acme-homepath",
  "acme-abspath": "/opt/src/acme-abspath",
  "acme-winpath": "C:\\src\\acme-winpath",
  "acme-bare-tgz": "vendor/acme-bare-tgz-1.0.0.tgz",
  "acme-flat-tgz": "acme-flat-tgz-1.0.0.tgz",
  "acme-ghshort": "acmeorg/acme-ghshort",
  "acme-ghshort-ref": "acmeorg/acme-ghshort-ref#main",
  "acme-privreg-tarball": "https://npm.internal.example/acme-privreg-tarball/-/acme-privreg-tarball-1.0.0.tgz",
  "acme-gitlab-https": "https://gitlab.internal.example/acme/acme-gitlab-https.git",
  "acme-file": "file:./libs/acme-relpath",
  "acme-link": "link:./libs/acme-relpath",
};

/** Real public packages with every ordinary registry spelling: these must still be checked. */
const CONTROLS: Record<string, string> = {
  minimist: "1.2.8",
  ms: "^2.1.3",
  semver: "7.x",
  debug: ">=4 <5",
  chalk: "*",
  lodash: "",
  react: "latest",
  typescript: "next",
  "string-width-cjs": "npm:string-width@^4.2.0",
  "is-number": "https://registry.npmjs.org/is-number/-/is-number-7.0.0.tgz",
};

beforeEach(() => {
  h = createHarness();
  bodies = [];
  const inner = globalThis.fetch;
  vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
    if (init?.body) bodies.push(String(init.body));
    return inner(input, init);
  });
  h.NPM = { minimist: { latest: "1.2.8", versions: { "1.2.8": {} } } };
});
afterEach(() => h.dispose());

describe("classifyNpmSpec follows npm-package-arg", () => {
  it("calls every path, tarball, git and foreign-URL spelling non-registry", () => {
    for (const [name, spec] of Object.entries(NON_REGISTRY)) expect([name, classifyNpmSpec(name, spec).kind]).not.toEqual([name, "registry"]);
  });
  it("keeps ranges, dist-tags, an alias target and a public registry tarball as registry releases", () => {
    for (const [name, spec] of Object.entries(CONTROLS)) expect([name, classifyNpmSpec(name, spec).kind]).toEqual([name, "registry"]);
    expect(classifyNpmSpec("string-width-cjs", "npm:string-width@^4.2.0")).toEqual({ kind: "registry", name: "string-width", range: "^4.2.0" });
    expect(classifyNpmSpec("x", "catalog:")).toMatchObject({ kind: "registry", name: "x" });
    // An alias whose target is not a registry spec is not a registry release (npa refuses it).
    expect(classifyNpmSpec("acme-a", "npm:acme-b@github:acmeorg/acme-b").kind).not.toBe("registry");
    // A registry-shaped tarball on another host, or one naming another package, is not this name's release.
    expect(classifyNpmSpec("is-number", "https://registry.npmjs.org/other/-/other-7.0.0.tgz").kind).not.toBe("registry");
  });
});

describe("no lockfile: no non-registry spelling is sent, ordinary ranges still are", () => {
  beforeEach(() => {
    h.write("package.json", JSON.stringify({ name: "acme-root", version: "1.0.0", dependencies: { ...CONTROLS, ...NON_REGISTRY } }));
    h.write("libs/acme-relpath/package.json", JSON.stringify({ name: "acme-relpath", version: "1.0.0" }));
  });

  it("dependency_health asks about the controls only", async () => {
    const r = (await executeDependencyHealth(null, {}, await h.live())) as unknown as Record<string, any>;
    expect(leaked()).toEqual([]);
    for (const name of ["minimist", "ms", "semver", "debug", "chalk", "lodash", "react", "typescript", "string-width", "is-number"]) {
      expect([name, h.requests.includes(`https://registry.npmjs.org/${name}`)]).toEqual([name, true]);
    }
    expect(h.requests).not.toContain("https://registry.npmjs.org/string-width-cjs");
    expect(r.dependencies.map((d: { name: string }) => d.name).filter((n: string) => INVENTED.test(n))).toEqual([]);
  });

  it("upgrade_planner, vulnerability_scan, ecosystem_pulse, what_should_i_know send none of them", async () => {
    await h.plan();
    await h.scan();
    const live = await h.live();
    await executeEcosystemPulse(null, {}, live);
    await executeWhatShouldIKnow(null, { task: "wire acme-relpath and acme-ghshort into the minimist parser", project_path: h.dir }, live);
    expect(leaked()).toEqual([]);
  });

  it("dependency_check and upgrade_impact do not look up a name the project takes from a path or git", async () => {
    const live = await h.live();
    const check = await executeDependencyCheck(null, { items: [{ ecosystem: "npm", package: "acme-relpath", to: "1.0.1" }, { ecosystem: "npm", package: "acme-ghshort", to: "1.0.1" }] }, live);
    const impact = await executeUpgradeImpact(null, { package: "acme-bare-tgz", to_version: "2.0.0", ecosystem: "npm" }, live);
    expect(leaked()).toEqual([]);
    const results = (check as { results: Array<{ verdict: string; not_checked?: string; reason?: string }> }).results;
    expect(results.map((x) => [x.verdict, x.not_checked])).toEqual([
      ["unknown", "private"],
      ["unknown", "private"],
    ]);
    expect(results[0].reason).toContain("../libs/acme-relpath");
    expect(JSON.stringify(impact)).toMatch(/private/i);
  });
});

describe("package-lock.json: what the lockfile installs from a link or git is not sent either", () => {
  beforeEach(() => {
    const manifest = { name: "acme-root", version: "1.0.0", workspaces: ["packages/*"], dependencies: { minimist: "1.2.8", "acme-member": "^1.0.0", ...NON_REGISTRY } };
    h.write("package.json", JSON.stringify(manifest));
    h.write("packages/acme-member/package.json", JSON.stringify({ name: "acme-member", version: "1.0.0" }));
    h.write("libs/acme-relpath/package.json", JSON.stringify({ name: "acme-relpath", version: "1.0.0" }));
    const sha = "0123456789abcdef0123456789abcdef01234567";
    h.write(
      "package-lock.json",
      JSON.stringify({
        name: "acme-root",
        version: "1.0.0",
        lockfileVersion: 3,
        requires: true,
        packages: {
          "": manifest,
          "libs/acme-relpath": { version: "1.0.0" },
          "packages/acme-member": { name: "acme-member", version: "1.0.0" },
          "node_modules/minimist": { version: "1.2.8", resolved: "https://registry.npmjs.org/minimist/-/minimist-1.2.8.tgz" },
          "node_modules/acme-member": { resolved: "packages/acme-member", link: true },
          "node_modules/acme-relpath": { resolved: "libs/acme-relpath", link: true },
          "node_modules/acme-dotpath": { resolved: "libs/acme-relpath", link: true },
          "node_modules/acme-file": { resolved: "libs/acme-relpath", link: true },
          "node_modules/acme-link": { resolved: "libs/acme-relpath", link: true },
          "node_modules/acme-ghshort": { version: "1.0.0", resolved: `git+ssh://git@github.com/acmeorg/acme-ghshort.git#${sha}` },
          "node_modules/acme-ghshort-ref": { version: "1.0.0", resolved: `git+ssh://git@github.com/acmeorg/acme-ghshort-ref.git#${sha}` },
          "node_modules/acme-bare-tgz": { version: "1.0.0", resolved: "file:vendor/acme-bare-tgz-1.0.0.tgz" },
          "node_modules/acme-flat-tgz": { version: "1.0.0", resolved: "file:acme-flat-tgz-1.0.0.tgz" },
          "node_modules/acme-privreg-tarball": { version: "1.0.0", resolved: "https://npm.internal.example/acme-privreg-tarball/-/acme-privreg-tarball-1.0.0.tgz" },
          "node_modules/acme-gitlab-https": { version: "1.0.0", resolved: `git+https://gitlab.internal.example/acme/acme-gitlab-https.git#${sha}` },
        },
      }),
    );
  });

  it("no tool sends a name the lockfile links or takes from git, minimist is still checked", async () => {
    const r = (await executeDependencyHealth(null, {}, await h.live())) as unknown as Record<string, any>;
    await h.plan();
    await h.scan();
    const live = await h.live();
    await executeEcosystemPulse(null, {}, live);
    await executeDependencyCheck(null, { items: [{ ecosystem: "npm", package: "acme-member", to: "1.0.1" }] }, live);
    expect(leaked()).toEqual([]);
    expect(h.requests).toContain("https://registry.npmjs.org/minimist");
    expect(r.dependencies.map((d: { name: string }) => d.name)).toEqual(["minimist"]);
  });
});

describe("pnpm, Yarn and Bun lockfiles: a workspace member or link declared with a range is not sent", () => {
  const manifest = { name: "acme-root", version: "1.0.0", workspaces: ["packages/*"], dependencies: { minimist: "1.2.8", "acme-member": "^1.0.0", "acme-ghshort": "acmeorg/acme-ghshort" } };
  beforeEach(() => {
    h.write("package.json", JSON.stringify(manifest));
    h.write("packages/acme-member/package.json", JSON.stringify({ name: "acme-member", version: "1.0.0" }));
  });

  it("pnpm-lock.yaml v9: `version: link:` in the root importer", async () => {
    h.write("pnpm-workspace.yaml", "packages:\n  - packages/*\n");
    h.write(
      "pnpm-lock.yaml",
      [
        "lockfileVersion: '9.0'",
        "",
        "importers:",
        "",
        "  .:",
        "    dependencies:",
        "      acme-ghshort:",
        "        specifier: acmeorg/acme-ghshort",
        "        version: https://codeload.github.com/acmeorg/acme-ghshort/tar.gz/0123456789abcdef0123456789abcdef01234567",
        "      acme-member:",
        "        specifier: ^1.0.0",
        "        version: link:packages/acme-member",
        "      minimist:",
        "        specifier: 1.2.8",
        "        version: 1.2.8",
        "",
        "  packages/acme-member: {}",
        "",
        "packages:",
        "",
        "  acme-ghshort@https://codeload.github.com/acmeorg/acme-ghshort/tar.gz/0123456789abcdef0123456789abcdef01234567:",
        "    resolution: {tarball: https://codeload.github.com/acmeorg/acme-ghshort/tar.gz/0123456789abcdef0123456789abcdef01234567}",
        "    version: 1.0.0",
        "",
        "  minimist@1.2.8:",
        "    resolution: {integrity: sha512-x}",
        "",
        "snapshots:",
        "",
        "  acme-ghshort@https://codeload.github.com/acmeorg/acme-ghshort/tar.gz/0123456789abcdef0123456789abcdef01234567: {}",
        "",
        "  minimist@1.2.8: {}",
        "",
      ].join("\n"),
    );
    const r = (await executeDependencyHealth(null, {}, await h.live())) as unknown as Record<string, any>;
    await h.plan();
    expect(leaked()).toEqual([]);
    expect(r.dependencies.map((d: { name: string }) => d.name)).toEqual(["minimist"]);
  });

  it("yarn.lock v1: a workspace member has no entry at all", async () => {
    h.write(
      "yarn.lock",
      [
        "# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.",
        "# yarn lockfile v1",
        "",
        "",
        '"acme-ghshort@acmeorg/acme-ghshort":',
        '  version "1.0.0"',
        '  resolved "https://codeload.github.com/acmeorg/acme-ghshort/tar.gz/0123456789abcdef0123456789abcdef01234567"',
        "",
        "minimist@1.2.8:",
        '  version "1.2.8"',
        '  resolved "https://registry.yarnpkg.com/minimist/-/minimist-1.2.8.tgz#x"',
        "",
      ].join("\n"),
    );
    const r = (await executeDependencyHealth(null, {}, await h.live())) as unknown as Record<string, any>;
    await h.plan();
    expect(leaked()).toEqual([]);
    expect(r.dependencies.map((d: { name: string }) => d.name)).toEqual(["minimist"]);
  });

  it("bun.lock: `acme-member@workspace:` entry", async () => {
    h.write(
      "bun.lock",
      JSON.stringify({
        lockfileVersion: 1,
        workspaces: { "": { name: "acme-root", dependencies: manifest.dependencies }, "packages/acme-member": { name: "acme-member", version: "1.0.0" } },
        packages: {
          "acme-member": ["acme-member@workspace:packages/acme-member"],
          "acme-ghshort": ["acme-ghshort@github:acmeorg/acme-ghshort#0123456", {}, "acmeorg-acme-ghshort-0123456"],
          minimist: ["minimist@1.2.8", "", {}, "sha512-x"],
        },
      }),
    );
    const r = (await executeDependencyHealth(null, {}, await h.live())) as unknown as Record<string, any>;
    await h.plan();
    expect(leaked()).toEqual([]);
    expect(r.dependencies.map((d: { name: string }) => d.name)).toEqual(["minimist"]);
  });
});
