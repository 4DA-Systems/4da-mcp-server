// SPDX-License-Identifier: Apache-2.0
/**
 * Pre-publish round 10, W4: one policy for names this project does not install yet.
 *
 * A name is private for a new lookup only when the package manager would fetch ANY name of that
 * ecosystem from a source that is not public (a REGISTRY-kind reason: a default registry, index or
 * proxy, a requirements `--index-url` / extra index / find-links, a Cargo source replacement,
 * GOPROXY, a lockfile that installs every package from one private host). A scope, a GOPRIVATE
 * pattern or a per-package index makes only the names it covers private (a NAME-kind reason), so a
 * project whose only npm packages are `@acme/*` from a private registry still checks lodash.
 *
 * Every request is recorded by a stubbed fetch: nothing leaves the process. Private-looking names
 * carry `zq`; the stub fails the test if one is ever seen. HOME and the user's configuration
 * directories point into the test's own temporary directory.
 */
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { FourDADatabase } from "../db.js";
import { LiveIntelligence } from "../live/index.js";
import { clearLiveIntelligence, setLiveIntelligence } from "../live-singleton.js";
import { dispatchTool } from "../tool-dispatch.js";
import { TOOL_REGISTRY } from "../schema-registry.js";
import { scanProjectTree, treeResolutionGroups } from "../project-tree.js";

vi.mock("../live/cargo-platform.js", async (importOriginal) => ({ ...(await importOriginal<typeof import("../live/cargo-platform.js")>()), activeCratesForHost: () => null }));

let scratch: string;
let home: string;
let project: string;
let sent: string[];
const savedEnv = new Map<string, string | undefined>();
const setEnv = (key: string, value: string | undefined) => {
  if (!savedEnv.has(key)) savedEnv.set(key, process.env[key]);
  if (value === undefined) delete process.env[key];
  else process.env[key] = value;
};
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
const writeFiles = (root: string, files: Record<string, string>) => {
  for (const [file, content] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(root, file)), { recursive: true });
    fs.writeFileSync(path.join(root, file), content);
  }
};
const leaks = (re: RegExp) => sent.filter((s) => re.test(s));

beforeAll(() => setEnv("FOURDA_OFFLINE", undefined));
afterAll(() => {
  for (const [key, value] of savedEnv) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
});
beforeEach(() => {
  scratch = fs.mkdtempSync(path.join(os.tmpdir(), "4da-private-r10-"));
  home = path.join(scratch, "home");
  project = path.join(scratch, "project");
  fs.mkdirSync(home, { recursive: true });
  fs.mkdirSync(project, { recursive: true });
  sent = [];
  setEnv("HOME", home);
  setEnv("USERPROFILE", home);
  setEnv("APPDATA", path.join(home, "AppData", "Roaming"));
  setEnv("LOCALAPPDATA", path.join(home, "AppData", "Local"));
  setEnv("XDG_CONFIG_HOME", undefined);
  setEnv("XDG_CONFIG_DIRS", path.join(home, "xdg-none"));
  setEnv("ProgramData", path.join(home, "ProgramData"));
  setEnv("VIRTUAL_ENV", undefined);
  setEnv("PIP_CONFIG_FILE", undefined);
  setEnv("PIP_INDEX_URL", undefined);
  setEnv("PIP_EXTRA_INDEX_URL", undefined);
  setEnv("GOPROXY", undefined);
  setEnv("GOPRIVATE", undefined);
  setEnv("GONOSUMDB", undefined);
  setEnv("GONOPROXY", undefined);
  setEnv("GOENV", "off");
  setEnv("CARGO_HOME", path.join(home, ".cargo"));
  setEnv("FOURDA_PUBLIC_MIRRORS", undefined);
  setEnv("FOURDA_PRIVATE_PACKAGES", undefined);
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: string, init?: RequestInit) => {
      const url = String(input);
      const body = typeof init?.body === "string" ? init.body : "";
      let readable = url;
      for (let i = 0; i < 4; i++) {
        try {
          const next = decodeURIComponent(readable);
          if (next === readable) break;
          readable = next;
        } catch {
          break;
        }
      }
      sent.push(`${readable} ${body}`);
      const u = new URL(url);
      if (u.hostname === "api.osv.dev" && u.pathname === "/v1/querybatch") {
        const { queries } = JSON.parse(body) as { queries: unknown[] };
        return json({ results: queries.map(() => ({ vulns: [] })) });
      }
      if (u.hostname === "api.osv.dev") return json({ vulns: [] });
      if (u.hostname === "hn.algolia.com") return json({ hits: [] });
      return json({ error: "Not found" }, 404);
    }),
  );
});
afterEach(() => {
  vi.unstubAllGlobals();
  clearLiveIntelligence();
  for (const [key, value] of savedEnv) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
  savedEnv.clear();
  setEnv("FOURDA_OFFLINE", undefined);
  try {
    fs.rmSync(scratch, { recursive: true, force: true });
  } catch {
    // Windows: left for the OS temp cleaner.
  }
});

/** The project's live layer, made the server's. */
function liveFor(files: Record<string, string>, homeFiles: Record<string, string> = {}): LiveIntelligence {
  writeFiles(project, files);
  writeFiles(home, homeFiles);
  const live = new LiveIntelligence(null);
  const { entries, discovery } = scanProjectTree(project);
  live.initFromProjectTree(project, treeResolutionGroups(entries), discovery);
  setLiveIntelligence(live);
  return live;
}

async function call(tool: string, args: Record<string, unknown>): Promise<string> {
  const db = new FourDADatabase(path.join(scratch, `standalone-${Math.random().toString(36).slice(2)}.db`));
  try {
    const result = await dispatchTool(tool, db, args).catch((error: unknown) => ({ content: [{ type: "text", text: String(error) }] }));
    return JSON.stringify(result);
  } finally {
    db.close();
  }
}

const npmLock = (deps: Record<string, string>, resolved: (name: string, version: string) => string | undefined) =>
  JSON.stringify({
    name: "app",
    lockfileVersion: 3,
    packages: {
      "": { name: "app", dependencies: deps },
      ...Object.fromEntries(Object.entries(deps).map(([name, version]) => [`node_modules/${name}`, { version, ...(resolved(name, version) ? { resolved: resolved(name, version) } : {}) }])),
    },
  });
const npmProject = (deps: Record<string, string>, resolved: (name: string, version: string) => string | undefined) => ({
  "package.json": JSON.stringify({ name: "app", version: "1.0.0", dependencies: deps }),
  "package-lock.json": npmLock(deps, resolved),
});
const publicNpm = (name: string, version: string) => `https://registry.npmjs.org/${name}/-/${name.split("/").pop()}-${version}.tgz`;
const NPM_CONTROL = npmProject({ lodash: "4.17.20" }, publicNpm);

describe("item 1: only a registry-wide reason makes an ecosystem private for new names", () => {
  const scopeOnly = () =>
    liveFor({
      ".npmrc": "@zqacme:registry=https://npm.acme.internal/\n",
      ...npmProject({ "@zqacme/ui": "1.0.0", "@zqacme/core": "2.0.0" }, (name, version) => `https://npm.acme.internal/${name}/-/${name.split("/")[1]}-${version}.tgz`),
    });

  it("a project whose only npm packages are a private scope: \"add lodash\" is checked under npm", async () => {
    scopeOnly();
    const brief = await call("what_should_i_know", { task: "add lodash" });
    expect(leaks(/zqacme/i)).toEqual([]);
    expect(leaks(/lodash/).length).toBeGreaterThan(0);
    expect(brief).not.toMatch(/lodash is private|every npm package this project installs is private/);
    const check = await call("dependency_check", { items: [{ ecosystem: "npm", package: "lodash", to: "4.17.21" }] });
    expect(check).not.toContain('not_checked\\":\\"private');
  });

  it("the scope's own new names stay private", async () => {
    scopeOnly();
    await call("what_should_i_know", { task: "add @zqacme/newthing" });
    await call("dependency_check", { items: [{ ecosystem: "npm", package: "@zqacme/newthing", to: "1.0.0" }] });
    expect(leaks(/zqacme/i)).toEqual([]);
  });

  it("the private reason carries its kind: name for a scope, registry for a default registry", () => {
    const live = scopeOnly();
    expect(live.getPrivateDependencies().map((d) => d.kind)).toEqual(["name", "name"]);
    expect(live.registryPrivate("npm")).toBeNull();
  });

  it("an .npmrc default registry that is not public: a new name is private, and so said", async () => {
    const live = liveFor({ ".npmrc": "registry=https://npm.zq.internal/\n", ...npmProject({ "zq-left": "1.0.0" }, () => undefined) });
    expect(live.getPrivateDependencies().map((d) => d.kind)).toEqual(["registry"]);
    expect(live.registryPrivate("npm")).toMatch(/npm\.zq\.internal/);
    const brief = await call("what_should_i_know", { task: "add zqnew-pkg" });
    expect(leaks(/zqnew/i)).toEqual([]);
    expect(brief).toMatch(/NOT CHECKED \(private\)/);
  });

  it("GOPRIVATE only (a name rule): \"add example.com/newthing\" is checked; a module under the pattern is not", async () => {
    setEnv("GOPRIVATE", "git.zq.internal");
    liveFor({ "go.mod": "module example.com/app\n\ngo 1.22\n\nrequire git.zq.internal/team/core v1.0.0\n", "go.sum": "git.zq.internal/team/core v1.0.0 h1:aaaa=\ngit.zq.internal/team/core v1.0.0/go.mod h1:bbbb=\n" });
    await call("what_should_i_know", { task: "add git.zq.internal/team/newmod" });
    await call("dependency_check", { items: [{ ecosystem: "Go", package: "git.zq.internal/team/newmod", to: "v1.0.0" }] });
    expect(leaks(/zq/i)).toEqual([]);
    await call("dependency_check", { items: [{ ecosystem: "Go", package: "example.com/newthing", to: "v1.0.0" }] });
    expect(leaks(/example\.com\/newthing/).length).toBeGreaterThan(0);
    // The briefing too: every installed Go module is private by GOPRIVATE, which covers only its pattern.
    sent.length = 0;
    // Final design of the 2026-11-25 fixes: the briefing lists a module on no bundled list in unverified_words for
    // dependency_check (sent above, by that call), never as private.
    const brief = await call("what_should_i_know", { task: "go get example.com/newthing" });
    expect(brief).toMatch(/"word": ?"example\.com\/newthing"/);
    expect(brief).not.toMatch(/example\.com\/newthing is private/);
  });

  it("pnpm-workspace.yaml: block-list scopes and a flow mapping are read", async () => {
    const { pnpmWorkspaceRegistries } = await import("../live/private-packages.js");
    expect(pnpmWorkspaceRegistries('registries:\n  "https://npm.acme.internal/":\n    scopes:\n      - "@zqa"\n      - \'@zqb\'\n  https://registry.npmjs.org/:\n    scopes: ["@pub"]\n')).toEqual({ scopes: ["@zqa", "@zqb"], registry: null });
    expect(pnpmWorkspaceRegistries('registries: { default: "https://npm.zq.internal/", "@zqc": "https://npm.zq.internal/" }\n')).toEqual({ scopes: ["@zqc"], registry: "https://npm.zq.internal/" });
    expect(pnpmWorkspaceRegistries("packages:\n  - apps/*\n# registry: https://npm.zq.internal/\n")).toEqual({ scopes: [], registry: null });
  });
});

describe("item 2: dependency_check and upgrade_impact given an ecosystem use the same registry policy", () => {
  const reqs = (options: string) => liveFor({ ...NPM_CONTROL, "requirements.txt": `${options}\nzqxpy-core==1.0.0\n` });
  for (const [label, options] of [
    ["--index-url", "--index-url https://pypi.zq.internal/simple"],
    ["-i", "-i https://pypi.zq.internal/simple"],
    ["--extra-index-url", "--extra-index-url https://pypi.zq.internal/simple"],
    ["--find-links", "--find-links https://wheels.zq.internal/"],
  ] as const) {
    it(`requirements ${label}: {PyPI, zqxpy-new} is never sent`, async () => {
      const live = reqs(options);
      expect(live.registryPrivate("PyPI")).not.toBeNull();
      expect(live.lookupPrivateReason("PyPI", "zqxpy-new")).not.toBeNull();
      const check = await call("dependency_check", { items: [{ ecosystem: "PyPI", package: "zqxpy-new", to: "1.0" }, { ecosystem: "npm", package: "lodash", to: "4.17.21" }] });
      await call("upgrade_impact", { package: "zqxpy-new", to_version: "2.0.0", ecosystem: "PyPI" });
      // The briefing, told the ecosystem (beside public npm a bare "add zqxpy-new" is guessed npm, as round 9 settled).
      await call("what_should_i_know", { task: "add zqxpy-new to requirements.txt" });
      expect(leaks(/zqxpy/i)).toEqual([]);
      expect(check).toContain('not_checked\\":\\"private');
      // npm beside it is not touched by the Python index.
      expect(leaks(/lodash/).length).toBeGreaterThan(0);
    });
  }

  it("a package-lock.json that installs every package from one private host, no .npmrc: a new npm name is private", async () => {
    const live = liveFor(npmProject({ "zq-alpha": "1.0.0", "zq-beta": "2.0.0" }, (name, version) => `https://npm.zq.internal/${name}/-/${name}-${version}.tgz`));
    expect(live.registryPrivate("npm")).toMatch(/npm\.zq\.internal/);
    await call("dependency_check", { items: [{ ecosystem: "npm", package: "zqnew-thing", to: "1.0.0" }] });
    await call("upgrade_impact", { package: "zqnew-thing", to_version: "2.0.0", ecosystem: "npm" });
    await call("what_should_i_know", { task: "add zqnew-thing" });
    expect(leaks(/zq/i)).toEqual([]);
  });

  it("a Cargo.lock whose every crate comes from one private registry, no config: a new crate is private", async () => {
    const live = liveFor({
      "Cargo.toml": '[package]\nname = "app"\nversion = "0.1.0"\n\n[dependencies]\nzq-serde = "1"\n',
      "Cargo.lock": 'version = 3\n\n[[package]]\nname = "app"\nversion = "0.1.0"\ndependencies = ["zq-serde"]\n\n[[package]]\nname = "zq-serde"\nversion = "1.0.0"\nsource = "sparse+https://cargo.zq.internal/index/"\n',
    });
    expect(live.registryPrivate("crates.io")).toMatch(/cargo\.zq\.internal/);
    await call("dependency_check", { items: [{ ecosystem: "crates.io", package: "zqnew-crate", to: "1.0.0" }] });
    expect(leaks(/zq/i)).toEqual([]);
  });

  it("a uv.lock whose every package comes from one private index, no index config: a new name is private", async () => {
    const live = liveFor({
      "pyproject.toml": '[project]\nname = "app"\nversion = "0.1.0"\ndependencies = ["zqxpy-core==1.0.0"]\n',
      "uv.lock": 'version = 1\n\n[[package]]\nname = "zqxpy-core"\nversion = "1.0.0"\nsource = { registry = "https://pypi.zq.internal/simple" }\n',
    });
    expect(live.registryPrivate("PyPI")).toMatch(/pypi\.zq\.internal/);
    await call("dependency_check", { items: [{ ecosystem: "PyPI", package: "zqxpy-new", to: "1.0.0" }] });
    expect(leaks(/zq/i)).toEqual([]);
  });

  it("a lockfile with public and private hosts is not registry-wide (a scope or a pinned index explains it)", () => {
    const live = liveFor(npmProject({ "zq-alpha": "1.0.0", lodash: "4.17.20" }, (name, version) => (name === "lodash" ? publicNpm(name, version) : `https://npm.zq.internal/${name}/-/${name}-${version}.tgz`)));
    expect(live.registryPrivate("npm")).toBeNull();
    expect(live.lookupPrivateReason("npm", "left-pad")).toBeNull();
    expect(live.privateReason("npm", "zq-alpha")).not.toBeNull();
  });
});

describe("item 3: pnpm-workspace.yaml registries", () => {
  for (const [label, yaml] of [
    ["registries.default (scope-to-URL shape)", "packages:\n  - 'packages/*'\nregistries:\n  default: https://npm.zq.internal/\n"],
    ["registries with a bare \"@\" scope (URL-keyed shape)", 'registries:\n  https://npm.zq.internal/:\n    scopes: ["@"]\n'],
    ["registry", "registry: https://npm.zq.internal/\n"],
  ] as const) {
    it(`${label}: every npm name is private`, async () => {
      const live = liveFor({ "pnpm-workspace.yaml": yaml, ...npmProject({ "zq-left": "1.0.0" }, () => undefined) });
      expect(live.registryPrivate("npm")).toMatch(/npm\.zq\.internal/);
      await call("dependency_check", { items: [{ ecosystem: "npm", package: "zq-left", to: "1.0.1" }, { ecosystem: "npm", package: "zqnew-pkg", to: "1.0.0" }] });
      await call("vulnerability_scan", { include_dev: true });
      expect(leaks(/zq/i)).toEqual([]);
    });
  }

  for (const [label, yaml] of [
    ["registries scope-to-URL", 'registries:\n  default: https://registry.npmjs.org/\n  "@zqacme": https://npm.acme.internal/\n  "@zqtools": https://npm.acme.internal/\n'],
    ["registries URL-keyed with scopes", 'registries:\n  https://npm.acme.internal/:\n    serverType: artifactory\n    scopes: ["@zqacme", "@zqtools"]\n'],
  ] as const) {
    it(`${label}: the scope is private, lodash is still checked`, async () => {
      const live = liveFor({ "pnpm-workspace.yaml": yaml, ...npmProject({ "@zqacme/ui": "1.0.0", lodash: "4.17.20" }, (name, version) => (name === "lodash" ? publicNpm(name, version) : undefined)) });
      expect(live.privateReason("npm", "@zqacme/ui")).toMatch(/pnpm-workspace\.yaml/);
      expect(live.registryPrivate("npm")).toBeNull();
      await call("vulnerability_scan", { include_dev: true });
      await call("dependency_check", { items: [{ ecosystem: "npm", package: "@zqtools/x", to: "1.0.0" }, { ecosystem: "npm", package: "left-pad", to: "1.3.0" }] });
      expect(leaks(/zq/i)).toEqual([]);
      expect(leaks(/left-pad/).length).toBeGreaterThan(0);
    });
  }

  it("a member's pnpm-workspace.yaml applies only under it", () => {
    const live = liveFor({
      ...NPM_CONTROL,
      "other/pnpm-workspace.yaml": "registries:\n  default: https://npm.zq.internal/\n",
      "other/package.json": JSON.stringify({ name: "other", version: "1.0.0", dependencies: { "zq-mem": "1.0.0" } }),
      "other/package-lock.json": npmLock({ "zq-mem": "1.0.0" }, () => undefined),
    });
    expect(live.privateReason("npm", "zq-mem")).toMatch(/pnpm-workspace\.yaml/);
    expect(live.privateReason("npm", "lodash")).toBeNull();
  });
});

describe("item 4: a pyproject.toml in a subfolder with no lockfile", () => {
  const sub = (index: string, deps = '["zqxpy-core>=1.0", "zqxpy-pinned==1.2.0"]') =>
    liveFor({ ...NPM_CONTROL, "svc/pyproject.toml": `[project]\nname = "svc"\nversion = "0.1.0"\ndependencies = ${deps}\n\n${index}` });
  for (const [label, index] of [
    ["[tool.uv] index-url", '[tool.uv]\nindex-url = "https://pypi.zq.internal/simple"\n'],
    ["[[tool.uv.index]] (default)", '[[tool.uv.index]]\nname = "corp"\nurl = "https://pypi.zq.internal/simple"\ndefault = true\n'],
    ["[[tool.poetry.source]]", '[[tool.poetry.source]]\nname = "corp"\nurl = "https://pypi.zq.internal/simple"\npriority = "primary"\n'],
    ["[[tool.pdm.source]]", '[[tool.pdm.source]]\nname = "corp"\nurl = "https://pypi.zq.internal/simple"\n'],
  ] as const) {
    it(`${label}: its names are never sent and are listed as not checked`, async () => {
      const live = sub(index);
      expect(live.registryPrivate("PyPI")).not.toBeNull();
      const scan = await call("vulnerability_scan", { include_dev: true });
      await call("dependency_check", { items: [{ ecosystem: "PyPI", package: "zqxpy-core", to: "1.1" }, { ecosystem: "PyPI", package: "zqxpy-new", to: "1.0" }] });
      await call("what_should_i_know", { task: "upgrade zqxpy-core and zqxpy-pinned" });
      await call("upgrade_planner", {});
      await call("dependency_health", {});
      expect(leaks(/zqxpy/i)).toEqual([]);
      expect(scan).toMatch(/zqxpy-core/);
      expect(scan).toMatch(/zqxpy-pinned/);
      // The npm control was still checked.
      expect(leaks(/lodash/).length).toBeGreaterThan(0);
    });
  }
});

describe("item 5: Go under a private GOPROXY, GOPRIVATE, GONOSUMDB", () => {
  const goPrivateOnly = { "go.mod": "module example.com/app\n\ngo 1.22\n\nrequire git.zq.internal/team/core v1.0.0\n", "go.sum": "git.zq.internal/team/core v1.0.0 h1:aaaa=\ngit.zq.internal/team/core v1.0.0/go.mod h1:bbbb=\n" };
  it("GOPROXY private: every Go name is private, installed or not", async () => {
    setEnv("GOPROXY", "https://goproxy.zq.internal");
    const live = liveFor(goPrivateOnly);
    expect(live.registryPrivate("Go")).toMatch(/goproxy\.zq\.internal/);
    await call("what_should_i_know", { task: "add git.zq.internal/team/newmod" });
    await call("what_should_i_know", { task: "add example.com/zqnewthing" });
    await call("dependency_check", { items: [{ ecosystem: "Go", package: "example.com/zqnewthing", to: "v1.0.0" }, { ecosystem: "Go", package: "git.zq.internal/team/core", to: "v1.1.0" }] });
    await call("upgrade_impact", { package: "example.com/zqnewthing", to_version: "v2.0.0", ecosystem: "Go" });
    await call("vulnerability_scan", { include_dev: true });
    expect(leaks(/zq/i)).toEqual([]);
  });
  for (const key of ["GOPRIVATE", "GONOSUMDB"]) {
    it(`${key}: modules under the pattern are never sent`, async () => {
      setEnv(key, "git.zq.internal");
      liveFor(goPrivateOnly);
      await call("what_should_i_know", { task: "add git.zq.internal/team/newmod" });
      await call("dependency_check", { items: [{ ecosystem: "Go", package: "git.zq.internal/team/newmod", to: "v1.0.0" }] });
      await call("vulnerability_scan", { include_dev: true });
      expect(leaks(/zq/i)).toEqual([]);
    });
  }
});

describe("item 6: under a private pip index, public requests is not looked up, and every answer says why", () => {
  const PIPFILE = '[[source]]\nurl = "https://pypi.zq.internal/simple"\nverify_ssl = true\nname = "corp"\n\n[packages]\nrequests = "==2.25.1"\n';
  const LAYOUTS: Array<{ name: string; files: Record<string, string>; homeFiles?: Record<string, string>; env?: Record<string, string>; setting: RegExp; perName?: true }> = [
    { name: "pip.conf index-url", files: { "requirements.txt": "requests==2.25.1\n" }, homeFiles: { ".config/pip/pip.conf": "[global]\nindex-url = https://pypi.zq.internal/simple\n" }, setting: /pip\.conf/ },
    { name: "pip.ini continuation", files: { "requirements.txt": "requests==2.25.1\n" }, homeFiles: { "pip/pip.ini": "[global]\nindex-url =\n    https://pypi.zq.internal/simple\n" }, setting: /pip\.ini/ },
    { name: "PIP_EXTRA_INDEX_URL", files: { "requirements.txt": "requests==2.25.1\n" }, env: { PIP_EXTRA_INDEX_URL: "https://pypi.zq.internal/simple" }, setting: /PIP_EXTRA_INDEX_URL/ },
    { name: "requirements --index-url", files: { "requirements.txt": "--index-url https://pypi.zq.internal/simple\nrequests==2.25.1\n" }, setting: /--index-url/ },
    { name: "requirements --extra-index-url", files: { "requirements.txt": "--extra-index-url https://pypi.zq.internal/simple\nrequests==2.25.1\n" }, setting: /--extra-index-url/ },
    { name: "requirements --find-links", files: { "requirements.txt": "--find-links https://wheels.zq.internal/\nrequests==2.25.1\n" }, setting: /--find-links/ },
    { name: "requirements -i<url> (attached)", files: { "requirements.txt": "-ihttps://pypi.zq.internal/simple\nrequests==2.25.1\n" }, setting: /--index-url/ },
    { name: "requirements --extra-index (an abbreviation)", files: { "requirements.txt": "--extra-index https://pypi.zq.internal/simple\nrequests==2.25.1\n" }, setting: /--extra-index-url/ },
    { name: "requirements -f <url>", files: { "requirements.txt": "-f https://wheels.zq.internal/\nrequests==2.25.1\n" }, setting: /--find-links/ },
    { name: "PIP_FIND_LINKS", files: { "requirements.txt": "requests==2.25.1\n" }, env: { PIP_FIND_LINKS: "https://wheels.zq.internal/" }, setting: /PIP_FIND_LINKS/ },
    // No Pipfile.lock: the scan does not read a bare Pipfile (NOT COVERED), so only the per-name tools are judged.
    { name: "Pipfile source", files: { Pipfile: PIPFILE }, setting: /Pipfile \[\[source\]\]/, perName: true },
    {
      name: "Pipfile source with a Pipfile.lock",
      files: {
        Pipfile: PIPFILE,
        "Pipfile.lock": JSON.stringify({
          _meta: { hash: { sha256: "00" }, "pipfile-spec": 6, requires: {}, sources: [{ name: "corp", url: "https://pypi.zq.internal/simple", verify_ssl: true }] },
          default: { requests: { version: "==2.25.1", hashes: ["sha256:aaaa"] } },
          develop: {},
        }),
      },
      setting: /Pipfile/,
    },
    {
      name: "PDM source",
      files: { "pyproject.toml": '[project]\nname = "app"\nversion = "0.1.0"\ndependencies = ["requests==2.25.1"]\n\n[[tool.pdm.source]]\nname = "corp"\nurl = "https://pypi.zq.internal/simple"\n' },
      setting: /pyproject\.toml/,
    },
  ];
  for (const layout of LAYOUTS) {
    it(layout.name, async () => {
      for (const [k, v] of Object.entries(layout.env ?? {})) setEnv(k, v);
      liveFor(layout.files, layout.homeFiles);
      const answers: Record<string, string> = {};
      const args: Record<string, Record<string, unknown>> = {
        dependency_check: { items: [{ ecosystem: "PyPI", package: "requests", to: "2.32.3" }] },
        upgrade_impact: { package: "requests", to_version: "2.32.3", ecosystem: "PyPI" },
        what_should_i_know: { task: "upgrade requests to 2.32.3" },
        vulnerability_scan: { include_dev: true },
        upgrade_planner: {},
        dependency_health: {},
      };
      for (const tool of Object.keys(args)) {
        expect(Object.hasOwn(TOOL_REGISTRY, tool)).toBe(true);
        if (layout.perName && !["dependency_check", "upgrade_impact", "what_should_i_know"].includes(tool)) continue;
        answers[tool] = await call(tool, args[tool]);
      }
      expect(leaks(/requests|zq/i)).toEqual([]);
      for (const [tool, answer] of Object.entries(answers)) {
        expect(answer, tool).toMatch(/NOT CHECKED \(private\)|not_checked\\":\\"private/);
        expect(answer, tool).toMatch(layout.setting);
        expect(answer, tool).toMatch(/FOURDA_PUBLIC_MIRRORS/);
      }
    });
  }
});

describe("W10: pnpm-workspace.yaml registry values in any shape, unread ones failing closed", () => {
  it("reads multi-line flow maps and flow sequences", async () => {
    const { pnpmWorkspaceRegistries } = await import("../live/private-packages.js");
    expect(pnpmWorkspaceRegistries('registries: {\n  default: "https://npm.zqx.internal/"\n}\n')).toEqual({ scopes: [], registry: "https://npm.zqx.internal/" });
    expect(pnpmWorkspaceRegistries('registries:\n  https://npm.acme.internal/:\n    scopes: [\n      "@zqa",\n      "@zqb"\n    ]\n')).toEqual({ scopes: ["@zqa", "@zqb"], registry: null });
    expect(pnpmWorkspaceRegistries('registries:\n  https://npm.acme.internal/: {\n    scopes: ["@zqc"]\n  }\n')).toEqual({ scopes: ["@zqc"], registry: null });
    // A same-indent block sequence, and the four shapes that already worked.
    expect(pnpmWorkspaceRegistries('registries:\n  https://npm.acme.internal/:\n    scopes:\n    - "@zqd"\n')).toEqual({ scopes: ["@zqd"], registry: null });
    expect(pnpmWorkspaceRegistries("registries:\n  default: https://npm.zq.internal/\n")).toEqual({ scopes: [], registry: "https://npm.zq.internal/" });
    expect(pnpmWorkspaceRegistries("registry: https://npm.zq.internal/\n\npackages:\n  - apps/*\n")).toEqual({ scopes: [], registry: "https://npm.zq.internal/" });
    expect(pnpmWorkspaceRegistries('registries:\n  "@zqe": https://npm.acme.internal/\n')).toEqual({ scopes: ["@zqe"], registry: null });
    expect(pnpmWorkspaceRegistries("namedRegistries:\n  work: https://npm.acme.internal/\n")).toEqual({ scopes: [], registry: null });
  });

  it("an anchor, alias, block scalar, unknown key or non-URL value is unread (fail closed)", async () => {
    const { pnpmWorkspaceRegistries } = await import("../live/private-packages.js");
    for (const yaml of [
      "registries: *corp\n",
      "registry: |\n  https://npm.zq.internal/\n",
      "registries:\n  default: &r https://npm.zq.internal/\n",
      "registries:\n  <<: *base\n",
      "registries:\n  mirror: https://npm.zq.internal/\n",
      "registry: ${NPM_REGISTRY}\n",
      "registries: { default: https://npm.zq.internal/\n",
      "namedRegistries: [https://npm.zq.internal/]\n",
    ]) expect(pnpmWorkspaceRegistries(yaml).unread, yaml).toBeDefined();
    expect(pnpmWorkspaceRegistries("registries:\n  default: &r https://npm.zq.internal/\n").unread).toEqual({ url: "https://npm.zq.internal/" });
    expect(pnpmWorkspaceRegistries("registries: *corp\n").unread).toEqual({ url: null });
  });

  it("the reviewer's multi-line flow map: zqx-newlib and @zqxs/core are never sent", async () => {
    const live = liveFor({ "pnpm-workspace.yaml": 'registries: {\n  default: "https://npm.zqx.internal/"\n}\n', ...npmProject({ "zq-left": "1.0.0" }, () => undefined) });
    expect(live.registryPrivate("npm")).toMatch(/npm\.zqx\.internal/);
    await call("dependency_check", { items: [{ ecosystem: "npm", package: "zqx-newlib", to: "1.2.3" }, { ecosystem: "npm", package: "@zqxs/core", to: "^2.0.0" }] });
    await call("vulnerability_scan", { include_dev: true });
    expect(leaks(/zq/i)).toEqual([]);
  });

  it("an unread registry value makes npm private for the folder, naming the file and FOURDA_PUBLIC_MIRRORS", async () => {
    const live = liveFor({ "pnpm-workspace.yaml": "registries: *corp\n", ...npmProject({ "zq-left": "1.0.0" }, () => undefined) });
    expect(live.registryPrivate("npm")).toMatch(/pnpm-workspace\.yaml/);
    expect(live.registryPrivate("npm")).toMatch(/FOURDA_PUBLIC_MIRRORS/);
    const check = await call("dependency_check", { items: [{ ecosystem: "npm", package: "zqx-newlib", to: "1.2.3" }] });
    await call("vulnerability_scan", { include_dev: true });
    expect(leaks(/zq/i)).toEqual([]);
    expect(check).toMatch(/pnpm-workspace\.yaml/);
  });

  it("an unread value naming a declared public mirror is checked again", () => {
    setEnv("FOURDA_PUBLIC_MIRRORS", "npm.mirror.example");
    const live = liveFor({ "pnpm-workspace.yaml": "registries:\n  default: &m https://npm.mirror.example/\n", ...NPM_CONTROL });
    expect(live.registryPrivate("npm")).toBeNull();
  });
});
