// SPDX-License-Identifier: Apache-2.0
/**
 * Round 22, from the seam hunt on round 20 (F1, F2, F3): what "private" means is split in two. The
 * server keeps its privacy decision as broad as it was (a name is never sent), and the ledger now
 * says why: "listed" (FOURDA_PRIVATE_PACKAGES), "named" (a rule naming the package or its scope, with
 * the folder of the file that holds it, or "environment"), or "registry-wide" (the default registry
 * is a host the server does not know as public). The hook releases a listed name everywhere, a named
 * one only in its config folder (or everywhere for an environment rule), and a registry-wide one
 * never. And a Go package path is answered as the module that contains it (F3).
 */

import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { ledgerEntries } from "../check-ledger.js";
import { goModuleContaining } from "../live/go-path.js";
import { PrivatePackageRules } from "../live/private-packages.js";
import { screenItems } from "../tools/dependency-check-screen.js";
import { sandbox, type Sandbox } from "./helpers/a1123-hookfix-run.js";

let s: Sandbox;
beforeEach(() => {
  s = sandbox();
});
afterEach(() => s.dispose());

const run = (command: string, cwd = s.project, tool = "Bash") => s.run({ session_id: "s", cwd, hook_event_name: "PreToolUse", tool_name: tool, tool_input: { command } });
const at = (m: number) => new Date(Date.now() - m * 60_000).toISOString();
function lines(entries: Array<Record<string, string>>): void {
  writeFileSync(join(s.home, "check-ledger.jsonl"), entries.map((e) => JSON.stringify({ sv: "6.6.0", t: at(1), ...e })).join("\n") + "\n");
}
const PRIV = (eco: string, pkg: string, extra: Record<string, string>) => ({ ecosystem: eco, package: pkg, version: "latest", verdict: "unknown", reason: "NOT CHECKED (private)", not_checked: "private", ...extra });

describe("S1 (server): the ledger says why a name is private", () => {
  let root: string;
  let env: NodeJS.ProcessEnv;
  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), "a1125-s1-"));
    env = { HOME: join(root, "home"), USERPROFILE: join(root, "home"), CARGO_HOME: join(root, "home", ".cargo"), GOENV: "off", PIP_CONFIG_FILE: join(root, "none.conf") };
    mkdirSync(join(root, "home"), { recursive: true });
  });
  afterEach(() => rmSync(root, { recursive: true, force: true }));

  it("a member's default registry: every name registry-wide, with the member's folder and the host", () => {
    const billing = join(root, "apps", "billing");
    mkdirSync(billing, { recursive: true });
    writeFileSync(join(root, "package.json"), '{"name":"mono","workspaces":["apps/*"]}');
    writeFileSync(join(billing, "package.json"), '{"name":"billing"}');
    writeFileSync(join(billing, ".npmrc"), "registry=https://npm.vendor.internal/\n");
    const rules = new PrivatePackageRules([root], env, [billing]);
    expect(rules.privateRuleKind("npm", "minimist", [root, billing])).toEqual({ rule: "registry-wide", dir: billing, host: "npm.vendor.internal" });
  });
  it("a root scope mapping: named, with the root folder", () => {
    writeFileSync(join(root, "package.json"), '{"name":"r"}');
    writeFileSync(join(root, ".npmrc"), "@seamco:registry=https://npm.seamco.internal/\n");
    const rules = new PrivatePackageRules([root], env);
    expect(rules.privateRuleKind("npm", "@seamco/utils", [root])).toEqual({ rule: "named", dir: root, host: null, config: "npm" });
  });
  it("a scope mapped in the environment, and GOPRIVATE: named, environment", () => {
    const rules = new PrivatePackageRules([root], { ...env, "npm_config_@envco:registry": "https://npm.envco.internal/", GOPRIVATE: "example.internal/*" });
    expect(rules.privateRuleKind("npm", "@envco/x", [root])).toEqual({ rule: "named", dir: "environment", host: null, config: "npm" });
    expect(rules.privateRuleKind("Go", "example.internal/mod", [root])).toEqual({ rule: "named", dir: "environment", host: null, config: "go" });
  });
  it("FOURDA_PRIVATE_PACKAGES: listed", () => {
    const rules = new PrivatePackageRules([root], { ...env, FOURDA_PRIVATE_PACKAGES: "acme-utils" });
    expect(rules.privateRuleKind("PyPI", "acme-utils", [root]).rule).toBe("listed");
  });
  it("the ledger line carries the rule, the folder and the host (never credentials); nothing known is registry-wide", () => {
    const item = { ecosystem: "npm", package: "minimist", to: "1.2.5", verdict: "unknown", not_checked: "private" };
    const wide = ledgerEntries([item], new Date(), () => true, () => ({ rule: "registry-wide", dir: join(root, "apps", "billing"), host: "npm.vendor.internal" }))[0];
    expect(wide).toMatchObject({ private_rule: "registry-wide", config_dir: join(root, "apps", "billing"), registry_host: "npm.vendor.internal" });
    const unknown = ledgerEntries([item], new Date(), () => true, null)[0];
    expect(unknown.private_rule).toBe("registry-wide");
    expect(unknown.config_dir).toBeUndefined();
    // A requirements file's --index-url the rules do not hold: the host is read from the answer's reason, credentials dropped.
    const fromReason = ledgerEntries([{ ...item, ecosystem: "PyPI", package: "requests", reason: "NOT CHECKED (private): services/ml/requirements.txt sets --index-url https://user:pw@pypi.ml-vendor.internal/simple: ..." }], new Date(), () => true, () => ({ rule: "registry-wide", dir: null, host: null }))[0];
    expect(fromReason.registry_host).toBe("pypi.ml-vendor.internal");
    expect(fromReason.registry_host).not.toContain("@");
  });
});

describe("S3: a public name withheld for a registry-wide reason is not called a private package", () => {
  it("the answer names the host and how to have it checked", async () => {
    const live = {
      lookupPrivateReason: () => "Your npm registry is npm.vendor.internal (apps/billing/.npmrc), not the public registry",
      privateRecordScope: () => ({ rule: "registry-wide", dir: "/x", host: "npm.vendor.internal" }),
      isEnabled: () => false,
      withheldUnreadableFile: () => null,
    };
    const screened = await screenItems([{ ecosystem: "npm", package: "minimist", raw: "1.2.5", target: { kind: "exact", version: "1.2.5" } }] as never, live as never);
    const [result] = screened.inOrder([]);
    expect(result.reason).toContain("this project's default registry is npm.vendor.internal, which 4DA does not know as public");
    expect(result.reason).toContain("FOURDA_PUBLIC_MIRRORS");
    expect(result.reason).not.toContain("is a private package");
  });
});

describe("S2 (hook): a registry-wide record never releases", () => {
  it.each(["npm i minimist@1.2.5 nanoid@3.3.7", "cd apps/web && npm i minimist@1.2.5", "pnpm add minimist@1.2.5"])("%s: held, with how to have it checked", (command) => {
    s.file("package.json", '{"name":"mono","workspaces":["apps/*"]}');
    s.file("apps/web/package.json", '{"name":"web"}');
    lines([PRIV("npm", "minimist", { private_rule: "registry-wide", config_dir: join(s.project, "apps", "billing"), registry_host: "npm.vendor.internal" }), PRIV("npm", "nanoid", { private_rule: "registry-wide", config_dir: join(s.project, "apps", "billing"), registry_host: "npm.vendor.internal" })]);
    const r = run(command);
    expect(r.decision).toBe("deny");
    expect(r.text).toContain("this project's registry (npm.vendor.internal) is not one 4DA knows as public");
    expect(r.text).toContain("FOURDA_PUBLIC_MIRRORS");
  });
  it("a member's requirements index (pip): held elsewhere and in the member", () => {
    lines([PRIV("PyPI", "requests", { private_rule: "registry-wide" })]);
    expect(run("pip install requests==2.19.0").decision).toBe("deny");
  });
});

describe("S2 (hook): a named record releases only in its config folder, with nothing moved", () => {
  beforeEach(() => {
    s.file("package.json", '{"name":"r"}');
    s.file("examples/demo/package.json", '{"name":"demo"}');
    s.file("src/.keep", "");
    lines([PRIV("npm", "@seamco/utils", { private_rule: "named", config_dir: s.project, config_of: "npm" })]);
  });
  it("in the config folder, and in a folder below it that holds no package.json: released", () => {
    expect(run("npm i @seamco/utils@9.9.9").decision).toBe("allow");
    expect(run("npm i @seamco/utils@9.9.9", join(s.project, "src")).decision).toBe("allow");
  });
  it.each([
    ["npm i @seamco/utils@9.9.9", "examples/demo"],
    ["cd examples/demo && npm i @seamco/utils@9.9.9", "."],
    ["cd ../x && npm i @seamco/utils@9.9.9", "."],
    ["npm i @seamco/utils@9.9.9 --prefix examples/demo", "."],
    ["pnpm -C examples/demo add @seamco/utils@9.9.9", "."],
    ["yarn --cwd examples/demo add @seamco/utils@9.9.9", "."],
    ["npm i -g @seamco/utils@9.9.9", "."],
  ])("%s (from %s): held, with where the rule applies", (command, from) => {
    const r = run(command, join(s.project, from));
    expect(r.decision, r.text).toBe("deny");
    expect(r.text).toContain("the registry rule that makes this name private belongs to another folder");
  });
  it("an environment rule releases everywhere; a listed name everywhere", () => {
    const other = mkdtempSync(join(tmpdir(), "a1125-s2-other-"));
    try {
      lines([PRIV("npm", "@envco/x", { private_rule: "named", config_dir: "environment" }), PRIV("npm", "@listed/y", { private_rule: "listed" })]);
      expect(run("npm i -g @envco/x@1.0.0", other).decision).toBe("allow");
      expect(run("npm i @listed/y@1.0.0", other).decision).toBe("allow");
    } finally {
      rmSync(other, { recursive: true, force: true });
    }
  });
  it("an avoid for the version still denies a named record's release", () => {
    lines([PRIV("npm", "@seamco/utils", { private_rule: "named", config_dir: s.project, config_of: "npm" }), { ecosystem: "npm", package: "@seamco/utils", version: "9.9.9", verdict: "avoid", reason: "test avoid" }]);
    expect(run("npm i @seamco/utils@9.9.9").decision).toBe("deny");
  });
});

describe("F3: a Go package path is judged as the module that contains it", () => {
  it("goModuleContaining finds the longest prefix the proxy serves at the version (stubbed proxy)", async () => {
    const served = new Set(["golang.org/x/tools", "github.com/golangci/golangci-lint"]);
    const fetchFn = (async (url: string) => {
      const m = /^https:\/\/proxy\.golang\.org\/(.+?)\/@(?:v\/[^/]+\.info|latest)$/.exec(url);
      const path = m ? decodeURIComponent(m[1]).replace(/!([a-z])/g, (_x, c: string) => c.toUpperCase()) : "";
      return { ok: served.has(path), status: served.has(path) ? 200 : 404, json: async () => ({}), text: async () => "" };
    }) as never;
    expect(await goModuleContaining("golang.org/x/tools/cmd/stringer", "v0.30.0", () => false, fetchFn)).toBe("golang.org/x/tools");
    expect(await goModuleContaining("github.com/golangci/golangci-lint/cmd/golangci-lint", "v1.55.2", () => false, fetchFn)).toBe("github.com/golangci/golangci-lint");
    // A private prefix is never sent; a short path is taken as a module.
    expect(await goModuleContaining("golang.org/x/tools/cmd/stringer", "v0.30.0", (p) => p === "golang.org/x/tools/cmd/stringer", fetchFn)).toBeNull();
    expect(await goModuleContaining("golang.org/x/tools", "v0.30.0", () => false, fetchFn)).toBeNull();
  });
  it("the hook: the answer recorded for the path releases go install of it", () => {
    lines([{ ecosystem: "Go", package: "golang.org/x/tools/cmd/stringer", version: "v0.30.0", verdict: "proceed", go_module: "golang.org/x/tools" }]);
    expect(run("go install golang.org/x/tools/cmd/stringer@v0.30.0").decision).toBe("allow");
  });
});
