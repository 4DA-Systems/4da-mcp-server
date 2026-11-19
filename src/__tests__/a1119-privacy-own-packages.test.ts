// SPDX-License-Identifier: Apache-2.0
/**
 * A project's own packages are not dependencies. A Cargo crate that depends by `path =` on another
 * crate of the same project (victauri's `examples/tauri3`, verax's `apps/bridge/src-tauri`) counted
 * that crate as an unchecked private dependency, so the scan read NOT CHECKED and
 * `total_vulnerable_packages` was null; a uv workspace member did the same, and a go.work module
 * was sent to OSV.dev as if it were a proxy release.
 *
 * - Own packages (Cargo workspace crates and `path =` crates inside the project, go.work modules,
 *   uv / Poetry local packages inside the project) are in no count and are never sent; the answer
 *   says how many were recognised (`own_packages`).
 * - Local code outside the project, and a registry release that shares an own package's name, keep
 *   today's behaviour: the first is NOT CHECKED (private), the second is checked.
 * - A go.work that cannot be read fails closed for Go.
 *
 * Every request is recorded by a stubbed fetch: nothing leaves the process. Made-up names carry `zq`.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { FourDADatabase } from "../db.js";
import { LiveIntelligence } from "../live/index.js";
import { clearLiveIntelligence, setLiveIntelligence } from "../live-singleton.js";
import { dispatchTool } from "../tool-dispatch.js";
import { scanProjectTree, treeResolutionGroups } from "../project-tree.js";
import { goWorkModules, pythonLocalPackages } from "../live/private-packages.js";

vi.mock("../live/cargo-platform.js", async (importOriginal) => ({ ...(await importOriginal<typeof import("../live/cargo-platform.js")>()), activeCratesForHost: () => null }));

let scratch: string;
let sent: string[];
const savedEnv = new Map<string, string | undefined>();
const setEnv = (key: string, value: string | undefined) => {
  if (!savedEnv.has(key)) savedEnv.set(key, process.env[key]);
  if (value === undefined) delete process.env[key];
  else process.env[key] = value;
};

beforeEach(() => {
  scratch = fs.mkdtempSync(path.join(os.tmpdir(), "4da-a1119-own-"));
  sent = [];
  setEnv("FOURDA_OFFLINE", undefined);
  setEnv("GOWORK", undefined);
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: string, init?: RequestInit) => {
      const url = String(input);
      const body = typeof init?.body === "string" ? init.body : "";
      sent.push(`${decodeURIComponent(url)} ${body}`);
      if (url.endsWith("/v1/querybatch")) return new Response(JSON.stringify({ results: (JSON.parse(body) as { queries: unknown[] }).queries.map(() => ({ vulns: [] })) }), { status: 200 });
      return new Response(JSON.stringify({ error: "Not found" }), { status: 404 });
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
  try {
    fs.rmSync(scratch, { recursive: true, force: true });
  } catch {
    // Windows: left for the OS temp cleaner.
  }
});

const sentAbout = (re: RegExp) => sent.filter((s) => re.test(s));

/** The project's live layer for `files` under `<scratch>/<rel>`, made the server's. */
function project(files: Record<string, string>, rel = "project"): { root: string; live: LiveIntelligence } {
  const root = path.join(scratch, rel);
  for (const [file, text] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(scratch, file)), { recursive: true });
    fs.writeFileSync(path.join(scratch, file), text);
  }
  fs.mkdirSync(root, { recursive: true });
  const live = new LiveIntelligence(null);
  const { entries, discovery } = scanProjectTree(root);
  live.initFromProjectTree(root, treeResolutionGroups(entries), discovery);
  setLiveIntelligence(live);
  return { root, live };
}

async function call(tool: string, args: Record<string, unknown>): Promise<Record<string, unknown>> {
  const db = new FourDADatabase(path.join(scratch, `standalone-${Math.random().toString(36).slice(2)}.db`));
  try {
    const result = (await dispatchTool(tool, db, args)) as { content: Array<{ text: string }> };
    return JSON.parse(result.content[0].text) as Record<string, unknown>;
  } finally {
    db.close();
  }
}

const SERDE = 'name = "serde"\nversion = "1.0.200"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\nchecksum = "aa"';
const cargoLock = (...packages: string[]) => `version = 4\n\n${packages.map((p) => `[[package]]\n${p}\n`).join("\n")}`;

describe("Cargo: the project's own crates are not dependencies", () => {
  // victauri's shape: a crate outside the root workspace depends by path on the workspace's crates.
  const tree = {
    "project/Cargo.toml": '[workspace]\nresolver = "2"\nmembers = ["crates/zqown-core", "crates/zqown-plugin"]\nexclude = ["examples/zqdemo"]\n',
    "project/Cargo.lock": cargoLock(SERDE, 'name = "zqown-core"\nversion = "0.1.0"\ndependencies = [\n "serde",\n]', 'name = "zqown-plugin"\nversion = "0.1.0"\ndependencies = [\n "zqown-core",\n]'),
    "project/crates/zqown-core/Cargo.toml": '[package]\nname = "zqown-core"\nversion = "0.1.0"\n\n[dependencies]\nserde = "1.0.200"\n',
    "project/crates/zqown-core/src/lib.rs": "",
    "project/crates/zqown-plugin/Cargo.toml": '[package]\nname = "zqown-plugin"\nversion = "0.1.0"\n\n[dependencies]\nzqown-core = { path = "../zqown-core" }\n',
    "project/crates/zqown-plugin/src/lib.rs": "",
    "project/examples/zqdemo/Cargo.toml": '[workspace]\n\n[package]\nname = "zqdemo"\nversion = "0.1.0"\n\n[dependencies]\nserde = "1.0.200"\nzqown-plugin = { path = "../../crates/zqown-plugin" }\nzqown-core = { path = "../../crates/zqown-core" }\n',
    "project/examples/zqdemo/src/main.rs": "",
    "project/examples/zqdemo/Cargo.lock": cargoLock(SERDE, 'name = "zqdemo"\nversion = "0.1.0"\ndependencies = [\n "serde",\n "zqown-core",\n "zqown-plugin",\n]', 'name = "zqown-core"\nversion = "0.1.0"\ndependencies = [\n "serde",\n]', 'name = "zqown-plugin"\nversion = "0.1.0"\ndependencies = [\n "zqown-core",\n]'),
  };

  it("a path crate of the same project: checked, counted as own, no NOT CHECKED, and its name is never sent", async () => {
    const { live } = project(tree);
    expect(live.getPrivateDependencies()).toEqual([]);
    const scan = await call("vulnerability_scan", { force_refresh: true });
    expect(scan.summary).toBeUndefined();
    expect(scan.total_vulnerable_packages).toBe(0);
    expect(scan.own_packages).toBe(3);
    expect(sentAbout(/serde/).length).toBeGreaterThan(0);
    await call("dependency_check", { items: [{ ecosystem: "crates.io", package: "zqown-core", to: "0.2.0" }] });
    await call("upgrade_impact", { package: "zqown-plugin", ecosystem: "crates.io", from_version: "0.1.0", to_version: "0.2.0" });
    expect(sentAbout(/zqown|zqdemo/)).toEqual([]);
    // dependency_health agrees: nothing private, nothing withheld for own code.
    const health = await call("dependency_health", {});
    expect(String(health.summary)).not.toMatch(/NOT CHECKED \(private\)|zqown/);
  });

  it("local code outside the project stays a private dependency: NOT CHECKED, never sent", async () => {
    project({
      "project/Cargo.toml": '[package]\nname = "zqown-app"\nversion = "0.1.0"\n\n[dependencies]\nserde = "1.0.200"\nzqext-lib = { path = "../zqext-lib" }\n',
      "project/src/main.rs": "",
      "project/Cargo.lock": cargoLock(SERDE, 'name = "zqext-lib"\nversion = "0.1.0"', 'name = "zqown-app"\nversion = "0.1.0"\ndependencies = [\n "serde",\n "zqext-lib",\n]'),
      "zqext-lib/Cargo.toml": '[package]\nname = "zqext-lib"\nversion = "0.1.0"\n',
    });
    const scan = await call("vulnerability_scan", { force_refresh: true });
    expect(String(scan.summary)).toMatch(/^NOT CHECKED \(private\): 1 dependency is private \(zqext-lib\)/);
    expect(scan.total_vulnerable_packages).toBeNull();
    expect(scan.own_packages).toBe(1);
    expect(sentAbout(/zqext/)).toEqual([]);
  });

  it("a crates.io release that shares an own crate's name is a dependency, and is checked", async () => {
    const registry = 'name = "zqown-core"\nversion = "0.9.0"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\nchecksum = "bb"';
    project({
      ...tree,
      "project/examples/zqdemo/Cargo.lock": cargoLock(
        SERDE,
        registry,
        'name = "zqdemo"\nversion = "0.1.0"\ndependencies = [\n "serde",\n "zqown-core 0.1.0",\n "zqown-plugin",\n]',
        'name = "zqown-core"\nversion = "0.1.0"\ndependencies = [\n "serde",\n "zqown-core 0.9.0",\n]',
        'name = "zqown-plugin"\nversion = "0.1.0"\ndependencies = [\n "zqown-core 0.1.0",\n]',
      ),
    });
    await call("vulnerability_scan", { force_refresh: true });
    expect(sentAbout(/"name":"zqown-core","ecosystem":"crates.io"\},"version":"0\.9\.0"/).length).toBe(1);
    expect(sentAbout(/"version":"0\.1\.0"/)).toEqual([]);
  });
});

describe("Go: a go.work module is the project's own, never a proxy release", () => {
  const goSum = "golang.org/x/net v0.0.1 h1:cccc=\ngolang.org/x/net v0.0.1/go.mod h1:dddd=\n";
  const tree = {
    "project/go.work": "go 1.22\n\nuse (\n\t./a\n\t\"./b\" // quoted\n)\n",
    "project/a/go.mod": "module example.com/zqown/a\n\ngo 1.22\n\nrequire (\n\texample.com/zqown/b v0.0.0\n\tgolang.org/x/net v0.0.1\n)\n",
    "project/a/go.sum": goSum,
    "project/b/go.mod": "module example.com/zqown/b\n\ngo 1.22\n\nrequire golang.org/x/net v0.0.1\n",
    "project/b/go.sum": goSum,
  };

  it("the module another member requires is not sent and not counted; the answer counts the own modules", async () => {
    project(tree);
    const scan = await call("vulnerability_scan", { force_refresh: true });
    expect(scan.summary).toBeUndefined();
    expect(scan.total_dependencies_scanned).toBe(1);
    expect(scan.own_packages).toBe(2);
    expect(sentAbout(/golang\.org\/x\/net/).length).toBeGreaterThan(0);
    await call("dependency_check", { items: [{ ecosystem: "Go", package: "example.com/zqown/b", to: "v0.1.0" }] });
    expect(sentAbout(/zqown/)).toEqual([]);
  });

  it("the go.work is read from the member's directory up to the project root, never above it", () => {
    write({ "go.work": "go 1.22\n\nuse ./project/a\n", ...tree });
    const root = path.join(scratch, "project");
    // The project's own go.work governs, and only directories inside the project are read.
    expect(goWorkModules(path.join(root, "a"), root).map((p) => p.name).sort()).toEqual(["example.com/zqown/a", "example.com/zqown/b"]);
    fs.rmSync(path.join(root, "go.work"));
    // The one above the project root is not this project's.
    expect(goWorkModules(path.join(root, "a"), root)).toEqual([]);
    fs.writeFileSync(path.join(root, "go.work"), "go 1.22\n\nuse ../outside\nreplace example.com/zqown/c => ./c\nreplace example.com/zqown/d => example.com/zqfork/d v1.0.0\n");
    expect(goWorkModules(path.join(root, "a"), root).map((p) => p.name)).toEqual(["example.com/zqown/c"]);
    setEnv("GOWORK", "off");
    expect(goWorkModules(path.join(root, "a"), root)).toEqual([]);
  });

  it("a go.work that cannot be read fails closed for Go only", async () => {
    setEnv("FOURDA_MAX_LOCKFILE_BYTES", "4096");
    project({ ...tree, "project/go.work": `go 1.22\n\nuse (\n\t./a\n\t./b\n)\n${"// padding\n".repeat(600)}`, "project/web/package.json": JSON.stringify({ name: "web", dependencies: { lodash: "4.17.20" } }), "project/web/package-lock.json": JSON.stringify({ name: "web", lockfileVersion: 3, packages: { "": { name: "web", dependencies: { lodash: "4.17.20" } }, "node_modules/lodash": { version: "4.17.20", resolved: "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz" } } }) });
    const scan = await call("vulnerability_scan", { force_refresh: true });
    // Either way of saying it is not a clean answer: the Go reader names go.work as unread
    // (coverage incomplete), or the private rules mark Go NOT CHECKED. Since the Go reader also
    // reads go.work (its `replace` directives), the first is what an oversized one produces.
    const coverage = scan.coverage as { complete?: boolean; unreadable_lockfiles?: Array<{ path: string }> } | undefined;
    const namedUnread = coverage?.complete === false && (coverage.unreadable_lockfiles ?? []).some((l) => l.path === "go.work");
    expect(namedUnread || /NOT CHECKED \(private\)/.test(String(scan.summary))).toBe(true);
    expect(String(JSON.stringify(scan))).toMatch(/go\.work/);
    expect(sentAbout(/zqown|golang\.org/)).toEqual([]);
    expect(sentAbout(/lodash/).length).toBeGreaterThan(0);
  });
});

describe("Python: a uv workspace member is the project's own", () => {
  it("not NOT CHECKED, counted as own, its name never sent; requests is checked", async () => {
    project({
      "project/pyproject.toml": '[project]\nname = "zqown-root"\nversion = "0.1.0"\ndependencies = ["zqown-lib", "requests==2.31.0"]\n\n[tool.uv.workspace]\nmembers = ["packages/*"]\n\n[tool.uv.sources]\nzqown-lib = { workspace = true }\n',
      "project/packages/lib/pyproject.toml": '[project]\nname = "zqown-lib"\nversion = "0.1.0"\ndependencies = []\n',
      "project/uv.lock":
        'version = 1\nrequires-python = ">=3.12"\n\n[manifest]\nmembers = ["zqown-lib", "zqown-root"]\n\n[[package]]\nname = "requests"\nversion = "2.31.0"\nsource = { registry = "https://pypi.org/simple" }\n\n[[package]]\nname = "zqown-lib"\nversion = "0.1.0"\nsource = { editable = "packages/lib" }\n\n[[package]]\nname = "zqown-root"\nversion = "0.1.0"\nsource = { virtual = "." }\ndependencies = [\n    { name = "requests" },\n    { name = "zqown-lib" },\n]\n',
    });
    const scan = await call("vulnerability_scan", { force_refresh: true });
    expect(scan.summary).toBeUndefined();
    expect(scan.total_vulnerable_packages).toBe(0);
    expect(scan.own_packages).toBe(2);
    expect(sentAbout(/requests/).length).toBeGreaterThan(0);
    await call("dependency_check", { items: [{ ecosystem: "PyPI", package: "zqown-lib", to: "0.2.0" }] });
    expect(sentAbout(/zqown/)).toEqual([]);
  });

  it("a Poetry directory package names its directory, in either key order", () => {
    write({ "project/poetry.lock": '[[package]]\nname = "zqown-util"\nversion = "0.1.0"\n\n[package.source]\nurl = "libs/util"\ntype = "directory"\n\n[[package]]\nname = "requests"\nversion = "2.31.0"\n' });
    const root = path.join(scratch, "project");
    expect(pythonLocalPackages(root)).toEqual([expect.objectContaining({ name: "zqown-util", local: true, at: path.join(root, "libs", "util") })]);
  });
});

function write(files: Record<string, string>): void {
  for (const [file, text] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(scratch, file)), { recursive: true });
    fs.writeFileSync(path.join(scratch, file), text);
  }
}
