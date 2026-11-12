// SPDX-License-Identifier: Apache-2.0
/** The rules that say a package name is private (live/private-packages.ts), and the lockfile readers that feed them. */
import { describe, expect, it } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import {
  goPrivateMatch,
  isPublicCratesSource,
  isPublicNpmRegistry,
  npmrcPrivateScopes,
  PrivatePackageRules,
  sourceLabel,
  yarnrcPrivateScopes,
} from "../live/private-packages.js";
import { readTomlPackageLock, resolvePython } from "../live/lockfile-parsers-pygo.js";

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), "4da-private-rules-"));
const noUser = { NPM_CONFIG_USERCONFIG: path.join(os.tmpdir(), "4da-no-such-npmrc"), GOENV: "off" };

describe("npm", () => {
  it(".npmrc: a scope mapped to a non-public registry is private; the public registry and its mirrors are not", () => {
    const scopes = npmrcPrivateScopes(
      [
        "# comment",
        "@acme:registry=https://npm.acme.internal/",
        "@Corp:registry = https://pkgs.dev.azure.com/corp/_packaging/feed/npm/registry/",
        "@public:registry=https://registry.npmjs.org/",
        "@yarn:registry=https://registry.yarnpkg.com",
        "registry=https://artifactory.acme.internal/api/npm/npm/",
        "//npm.acme.internal/:_authToken=${NPM_TOKEN}",
      ].join("\n"),
    );
    expect(scopes).toEqual(["@acme", "@corp"]);
    expect(isPublicNpmRegistry("https://registry.npmjs.org/")).toBe(true);
    expect(isPublicNpmRegistry("https://npm.acme.internal/")).toBe(false);
  });

  it(".yarnrc.yml npmScopes with their own registry server", () => {
    const scopes = yarnrcPrivateScopes(
      ["nodeLinker: node-modules", "npmScopes:", "  acme:", '    npmRegistryServer: "https://npm.acme.internal"', "  public:", "    npmRegistryServer: https://registry.npmjs.org", "yarnPath: x"].join("\n"),
    );
    expect(scopes).toEqual(["@acme"]);
  });

  it("the project's and the user's .npmrc both count; the reason names the file", () => {
    const project = tmp();
    const home = tmp();
    fs.writeFileSync(path.join(project, ".npmrc"), "@acme:registry=https://npm.acme.internal/\n");
    fs.writeFileSync(path.join(home, ".npmrc"), "@globex:registry=https://npm.globex.internal/\n");
    const rules = new PrivatePackageRules([project], { HOME: home, USERPROFILE: home, GOENV: "off" });
    expect(rules.reasonFor("npm", "@acme/billing")).toContain(path.join(project, ".npmrc"));
    expect(rules.reasonFor("npm", "@globex/x")).toContain(path.join(home, ".npmrc"));
    expect(rules.reasonFor("npm", "@other/x")).toBeNull();
    expect(rules.reasonFor("npm", "lodash")).toBeNull();
    // Scope rules are npm's: the same text is no private name elsewhere.
    expect(rules.reasonFor("PyPI", "@acme/billing")).toBeNull();
  });
});

describe("Go", () => {
  it("GOPRIVATE globs match leading path elements, as go does", () => {
    expect(goPrivateMatch("github.com/acme/*", "github.com/acme/ledger/v2")).toBe("github.com/acme/*");
    expect(goPrivateMatch("*.corp.example.com,rsc.io/private", "git.corp.example.com/team/x")).toBe("*.corp.example.com");
    expect(goPrivateMatch("*.corp.example.com,rsc.io/private", "rsc.io/private/quote")).toBe("rsc.io/private");
    expect(goPrivateMatch("github.com/acme/*", "github.com/acmeco/x")).toBeNull();
    expect(goPrivateMatch("github.com/acme", "github.com/acme-other/x")).toBeNull();
  });

  it("GOPRIVATE / GONOPROXY / GONOSUMDB from the environment, else from the `go env -w` file", () => {
    const dir = tmp();
    const goenv = path.join(dir, "env");
    fs.writeFileSync(goenv, "GOPRIVATE=git.acme.internal\nGOFLAGS=-mod=mod\n");
    const fromFile = new PrivatePackageRules([], { ...noUser, GOENV: goenv });
    expect(fromFile.reasonFor("Go", "git.acme.internal/team/svc")).toContain("GOPRIVATE (go env)");
    const fromEnv = new PrivatePackageRules([], { ...noUser, GOENV: goenv, GONOSUMDB: "github.com/acme" });
    expect(fromEnv.reasonFor("Go", "github.com/acme/x")).toContain("GONOSUMDB (the environment)");
    expect(fromEnv.reasonFor("Go", "golang.org/x/net")).toBeNull();
  });
});

describe("FOURDA_PRIVATE_PACKAGES", () => {
  it("globs, optionally by ecosystem; `*` crosses `/`", () => {
    const rules = new PrivatePackageRules([], { ...noUser, FOURDA_PRIVATE_PACKAGES: "npm:@acme/*, cargo:acme-*  Go:github.com/acme/*,internal-tools" });
    expect(rules.reasonFor("npm", "@acme/a")).toContain("npm:@acme/*");
    expect(rules.reasonFor("crates.io", "acme-ledger")).toContain("crates.io:acme-*");
    expect(rules.reasonFor("npm", "acme-ledger")).toBeNull();
    expect(rules.reasonFor("Go", "github.com/acme/a/b")).not.toBeNull();
    expect(rules.reasonFor("PyPI", "Internal-Tools")).not.toBeNull();
    expect(new PrivatePackageRules([], noUser).empty).toBe(true);
  });
});

describe("lockfile sources", () => {
  it("crates.io is public in both index forms; anything else is not", () => {
    expect(isPublicCratesSource("registry+https://github.com/rust-lang/crates.io-index")).toBe(true);
    expect(isPublicCratesSource("sparse+https://index.crates.io/")).toBe(true);
    expect(isPublicCratesSource("sparse+https://cargo.acme.internal/index/")).toBe(false);
    expect(isPublicCratesSource("git+https://github.com/acme/x#abc")).toBe(false);
  });

  it("a registry URL is shown without credentials, query or fragment", () => {
    expect(sourceLabel("git+https://user:s3cret@github.com/acme/x?branch=main#abc")).toBe("git+https://github.com/acme/x");
    expect(sourceLabel("https://token@pypi.acme.internal/simple/")).toBe("https://pypi.acme.internal/simple");
    expect(sourceLabel("https://pypi.acme.internal/simple")).not.toContain("token");
  });

  it("uv.lock and poetry.lock: an index other than pypi.org", () => {
    const uv = readTomlPackageLock(
      ['[[package]]', 'name = "acme-auth"', 'version = "2.1.0"', 'source = { registry = "https://pypi.acme.internal/simple" }', "", '[[package]]', 'name = "requests"', 'version = "2.32.3"', 'source = { registry = "https://pypi.org/simple" }'].join("\n"),
    );
    expect(uv.privateIndex).toEqual([{ name: "acme-auth", version: "2.1.0", registry: "https://pypi.acme.internal/simple" }]);
    const poetry = readTomlPackageLock(
      ['[[package]]', 'name = "acme_auth"', 'version = "1.0.0"', "", "[package.source]", 'type = "legacy"', 'url = "https://nexus.acme.internal/repository/pypi/simple"', 'reference = "acme"', "", '[[package]]', 'name = "flask"', 'version = "3.0.0"'].join("\n"),
    );
    expect(poetry.privateIndex.map((p) => p.name)).toEqual(["acme-auth"]);
  });

  it("Pipfile.lock: a package whose `index` names a non-PyPI source", () => {
    const dir = tmp();
    fs.writeFileSync(
      path.join(dir, "Pipfile.lock"),
      JSON.stringify({
        _meta: { sources: [{ name: "pypi", url: "https://pypi.org/simple", verify_ssl: true }, { name: "acme", url: "https://pypi.acme.internal/simple", verify_ssl: true }] },
        default: { requests: { version: "==2.32.3" }, "acme-auth": { version: "==2.1.0", index: "acme" } },
        develop: {},
      }),
    );
    const read = resolvePython(dir);
    expect(read.privateIndex?.map((p) => [p.name, p.version])).toEqual([["acme-auth", "2.1.0"]]);
  });
});
