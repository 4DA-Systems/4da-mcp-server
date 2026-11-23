// SPDX-License-Identifier: Apache-2.0
/**
 * A lockfile that is there and could not be read (not valid JSON, truncated, garbage, a merge
 * conflict) is said as that by every tool, and the briefing never clears a task over it.
 *
 * - vulnerability_scan, dependency_health and upgrade_planner say the npm dependencies under an
 *   unreadable package-lock.json are NOT CHECKED (unreadable lockfile), naming the file: they are
 *   withheld (where they come from is not known), never called private, and never sent.
 * - what_should_i_know is never safe_to_delegate while a lockfile of the project was not read, or
 *   not read whole, in any ecosystem; it names each file and why (lockfiles_not_read).
 *
 * Every request is recorded by a stubbed fetch: nothing leaves the process.
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

vi.mock("../live/cargo-platform.js", async (importOriginal) => ({ ...(await importOriginal<typeof import("../live/cargo-platform.js")>()), activeCratesForHost: () => null }));

let scratch: string;
let project: string;
let sent: string[];
const savedEnv = new Map<string, string | undefined>();
const setEnv = (key: string, value: string | undefined) => {
  if (!savedEnv.has(key)) savedEnv.set(key, process.env[key]);
  if (value === undefined) delete process.env[key];
  else process.env[key] = value;
};
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
const leaks = (re: RegExp) => sent.filter((s) => re.test(s));

beforeEach(() => {
  scratch = fs.mkdtempSync(path.join(os.tmpdir(), "4da-a1123-briefing-"));
  project = path.join(scratch, "project");
  const home = path.join(scratch, "home");
  fs.mkdirSync(project, { recursive: true });
  fs.mkdirSync(home, { recursive: true });
  sent = [];
  setEnv("FOURDA_OFFLINE", undefined);
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
  setEnv("UV_CONFIG_FILE", undefined);
  setEnv("GOPROXY", undefined);
  setEnv("GOPRIVATE", undefined);
  setEnv("GONOPROXY", undefined);
  setEnv("GONOSUMDB", undefined);
  setEnv("GOFLAGS", undefined);
  setEnv("GOENV", "off");
  setEnv("CARGO_HOME", path.join(home, ".cargo"));
  setEnv("NPM_CONFIG_USERCONFIG", path.join(home, ".npmrc"));
  setEnv("NPM_CONFIG_GLOBALCONFIG", path.join(home, "global-npmrc"));
  setEnv("FOURDA_PUBLIC_MIRRORS", undefined);
  setEnv("FOURDA_PRIVATE_PACKAGES", undefined);
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: string, init?: RequestInit) => {
      const url = String(input);
      const body = typeof init?.body === "string" ? init.body : "";
      sent.push(`${decodeURIComponent(url)} ${body}`);
      const u = new URL(url);
      if (u.hostname === "api.osv.dev" && u.pathname === "/v1/querybatch") {
        const { queries } = JSON.parse(body) as { queries: unknown[] };
        return json({ results: queries.map(() => ({ vulns: [] })) });
      }
      if (u.hostname === "api.osv.dev") return json({ vulns: [] });
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
  try {
    fs.rmSync(scratch, { recursive: true, force: true });
  } catch {
    // Windows: left for the OS temp cleaner.
  }
});

function liveFor(files: Record<string, string>): LiveIntelligence {
  for (const [file, content] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(project, file)), { recursive: true });
    fs.writeFileSync(path.join(project, file), content);
  }
  const live = new LiveIntelligence(null);
  const { entries, discovery } = scanProjectTree(project);
  live.initFromProjectTree(project, treeResolutionGroups(entries), discovery);
  setLiveIntelligence(live);
  return live;
}

/** The tool's answer, parsed. */
async function call(tool: string, args: Record<string, unknown>): Promise<Record<string, any>> {
  const db = new FourDADatabase(path.join(scratch, `standalone-${Math.random().toString(36).slice(2)}.db`));
  try {
    const result = (await dispatchTool(tool, db, args)) as { content: Array<{ text: string }> };
    return JSON.parse(result.content[0].text) as Record<string, any>;
  } finally {
    db.close();
  }
}

const TASK = { task: "add a date picker to the settings page" };

const PKG_JSON = JSON.stringify({ name: "app", version: "1.0.0", dependencies: { lodash: "4.17.20", minimist: "1.2.5" } }, null, 2);
const REQUIREMENTS = "requests==2.25.0\nurllib3==1.26.4\n";
const NPM_LOCK = JSON.stringify(
  {
    name: "app",
    version: "1.0.0",
    lockfileVersion: 3,
    requires: true,
    packages: {
      "": { name: "app", version: "1.0.0", dependencies: { lodash: "4.17.20", minimist: "1.2.5" } },
      "node_modules/lodash": { version: "4.17.20", resolved: "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz" },
      "node_modules/minimist": { version: "1.2.5", resolved: "https://registry.npmjs.org/minimist/-/minimist-1.2.5.tgz" },
    },
  },
  null,
  2,
);
const PNPM_LOCK = `lockfileVersion: '9.0'

settings:
  autoInstallPeers: true
  excludeLinksFromLockfile: false

importers:

  .:
    dependencies:
      lodash:
        specifier: 4.17.20
        version: 4.17.20
      minimist:
        specifier: 1.2.5
        version: 1.2.5

packages:

  lodash@4.17.20:
    resolution: {integrity: sha512-PlhdFcillOINfeV7Ni6oF1TAEayyZBoZ8bcshTHqOYJYlrqzRK5hagpagky5o4HfCzzd1TRkXPMFq6cKk9rGmA==}

  minimist@1.2.5:
    resolution: {integrity: sha512-FM9nNUYrRBAELZQT3xeZQ7fmMOBg6nWNmJKTcgsJeaLstP/UODVpGsr5OhXhhXg6f+qtJ8uiZ+PUxkDWcgIXLw==}

snapshots:

  lodash@4.17.20: {}

  minimist@1.2.5: {}
`;
const YARN_LOCK = `# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.
# yarn lockfile v1


lodash@4.17.20:
  version "4.17.20"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.20.tgz#b44a9b6297bcb698f1c51a3545a2b3b368d59c52"
  integrity sha512-PlhdFcillOINfeV7Ni6oF1TAEayyZBoZ8bcshTHqOYJYlrqzRK5hagpagky5o4HfCzzd1TRkXPMFq6cKk9rGmA==

minimist@1.2.5:
  version "1.2.5"
  resolved "https://registry.yarnpkg.com/minimist/-/minimist-1.2.5.tgz#67d66014b66a6a8aaa0c083c5fd58df4e4e97602"
  integrity sha512-FM9nNUYrRBAELZQT3xeZQ7fmMOBg6nWNmJKTcgsJeaLstP/UODVpGsr5OhXhhXg6f+qtJ8uiZ+PUxkDWcgIXLw==
`;
const CARGO_TOML = `[package]
name = "app"
version = "0.1.0"
edition = "2021"

[dependencies]
smallvec = "=1.6.0"
`;
const CARGO_LOCK = `# This file is automatically @generated by Cargo.
# It is not intended for manual editing.
version = 3

[[package]]
name = "app"
version = "0.1.0"
dependencies = [
 "smallvec",
]

[[package]]
name = "smallvec"
version = "1.6.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "fe0f37c9e8f3c5a4a66ad655a93c74daac4ad00c441533bf5c6e7990bb42604e"
`;
const PYPROJECT = `[project]
name = "app"
version = "0.1.0"
requires-python = ">=3.9"
dependencies = ["requests==2.25.0"]
`;
const UV_LOCK = `version = 1
requires-python = ">=3.9"

[[package]]
name = "app"
version = "0.1.0"
source = { virtual = "." }
dependencies = [
    { name = "requests" },
]

[package.metadata]
requires-dist = [{ name = "requests", specifier = "==2.25.0" }]

[[package]]
name = "requests"
version = "2.25.0"
source = { registry = "https://pypi.org/simple" }
sdist = { url = "https://files.pythonhosted.org/packages/requests-2.25.0.tar.gz", hash = "sha256:7f1a0b932f4a60a1a65caa4263921bb7d9ee911957e0ae4a23a6dd08185ad5f8", size = 102161 }
`;
const GO_MOD_116 = "module example.com/app\n\ngo 1.16\n\nrequire golang.org/x/text v0.3.0\n";
const GO_SUM = "golang.org/x/text v0.3.0 h1:g61tztE5qeGQ89tm6NTjjM9VPIm088od1l6aSorWRWg=\ngolang.org/x/text v0.3.0/go.mod h1:NqM8EUOU14njkJ3fqMW+pc6Ldnwhi/IjpwHt7yyuwOQ=\n";

const GARBAGE = "this is not a lockfile at all }{ [[[ :::\n";
const half = (text: string) => text.slice(0, Math.floor(text.length / 2));

/** Each lockfile kind, the files beside it (always a second ecosystem that reads, so the scan is ready), and its valid text. */
const KINDS: Array<{ lock: string; beside: Record<string, string>; valid: string }> = [
  { lock: "package-lock.json", beside: { "package.json": PKG_JSON, "requirements.txt": REQUIREMENTS }, valid: NPM_LOCK },
  { lock: "pnpm-lock.yaml", beside: { "package.json": PKG_JSON, "requirements.txt": REQUIREMENTS }, valid: PNPM_LOCK },
  { lock: "yarn.lock", beside: { "package.json": PKG_JSON, "requirements.txt": REQUIREMENTS }, valid: YARN_LOCK },
  { lock: "Cargo.lock", beside: { "Cargo.toml": CARGO_TOML, "requirements.txt": REQUIREMENTS }, valid: CARGO_LOCK },
  { lock: "uv.lock", beside: { "pyproject.toml": PYPROJECT, "package.json": PKG_JSON, "package-lock.json": NPM_LOCK }, valid: UV_LOCK },
  { lock: "go.sum", beside: { "go.mod": GO_MOD_116, "requirements.txt": REQUIREMENTS }, valid: GO_SUM },
];

describe("an npm lockfile that is not valid JSON is said as unreadable, never as private", () => {
  for (const [variant, text] of [
    ["truncated", half(NPM_LOCK)],
    ["garbage", GARBAGE],
  ] as const) {
    it(`${variant}: the scan headline names the unreadable file; lodash and minimist are withheld, not called private`, async () => {
      liveFor({ "package.json": PKG_JSON, "package-lock.json": text, "requirements.txt": REQUIREMENTS });
      const scan = await call("vulnerability_scan", { force_refresh: true });
      expect(scan.summary).toMatch(/^NOT CHECKED \(unreadable lockfile\): package-lock\.json could not be read/);
      expect(scan.summary).not.toMatch(/are private|is private/);
      expect(scan.coverage.complete).toBe(false);
      expect(scan.coverage.note).not.toMatch(/dependencies are private/);
      expect(scan.coverage.unreadable_lockfiles.map((u: { path: string }) => u.path)).toEqual(["package-lock.json"]);
      expect(scan.coverage.private_dependency_list.map((d: { name: string; unreadable_file?: string }) => [d.name, d.unreadable_file])).toEqual([
        ["lodash", "package-lock.json"],
        ["minimist", "package-lock.json"],
      ]);
      expect(scan.coverage.osv_status).toBe("dependencies under a lockfile or manifest that could not be read were not sent");
      // Withheld for privacy all the same: where they come from is not known.
      expect(leaks(/lodash|minimist/)).toEqual([]);
      expect(leaks(/requests/).length).toBeGreaterThan(0);

      const health = await call("dependency_health", {});
      expect(health.healthScore).toBeNull();
      expect(health.summary).toContain("NOT CHECKED (unreadable lockfile)");
      expect(health.summary).not.toMatch(/are private|is private/);
      const plan = await call("upgrade_planner", {});
      expect(plan.summary).toContain("NOT CHECKED (unreadable lockfile)");
      expect(plan.summary).not.toMatch(/are private|is private/);
      expect(leaks(/lodash|minimist/)).toEqual([]);
    });
  }

  it("an npm-only project with a garbage lockfile: nothing was checked, and the reason is the unreadable file", async () => {
    liveFor({ "package.json": PKG_JSON, "package-lock.json": GARBAGE });
    const health = await call("dependency_health", {});
    expect(health.healthScore).toBeNull();
    expect(health.summary).toContain("NOT CHECKED (unreadable lockfile)");
    expect(health.summary).not.toMatch(/are private|is private/);
    const brief = await call("what_should_i_know", TASK);
    expect(brief.delegation_assessment.level).toBe("unknown");
    expect(brief.delegation_assessment.reason).toMatch(/^UNREADABLE: 1 lockfile could not be read.*package-lock\.json/);
  });

  it("a task naming a withheld package says its lockfile could not be read, not that it is private", async () => {
    liveFor({ "package.json": PKG_JSON, "package-lock.json": GARBAGE, "requirements.txt": REQUIREMENTS });
    const brief = await call("what_should_i_know", { task: "upgrade lodash to 4.17.21" });
    expect(brief.delegation_assessment.level).not.toBe("safe_to_delegate");
    expect(brief.private_dependencies.map((p: { package: string; unreadable_file?: string }) => [p.package, path.basename(p.unreadable_file ?? "")])).toEqual([["lodash", "package-lock.json"]]);
    expect(brief.summary).toContain("NOT CHECKED (unreadable lockfile): the task touches lodash 4.17.20");
    expect(brief.summary).not.toMatch(/a private package/);
    expect(brief.delegation_assessment.reason).toContain("lodash was not checked:");
    expect(leaks(/lodash|minimist/)).toEqual([]);
  });
});

describe("what_should_i_know is never safe_to_delegate over a lockfile it did not read", () => {
  for (const { lock, beside, valid } of KINDS) {
    it(`${lock} that reads: the control is safe_to_delegate, with nothing in lockfiles_not_read`, async () => {
      liveFor({ ...beside, [lock]: valid });
      const brief = await call("what_should_i_know", TASK);
      expect(brief.lockfiles_not_read).toBeUndefined();
      expect(brief.delegation_assessment.level).toBe("safe_to_delegate");
    });
    for (const [variant, text] of [
      ["truncated", half(valid)],
      ["garbage", GARBAGE],
    ] as const) {
      it(`${lock}, ${variant}: unknown, naming the file`, async () => {
        liveFor({ ...beside, [lock]: text });
        const brief = await call("what_should_i_know", TASK);
        expect(brief.delegation_assessment.level).toBe("unknown");
        expect(brief.lockfiles_not_read.map((f: { path: string }) => f.path)).toEqual([lock]);
        expect(["unreadable", "partial"]).toContain(brief.lockfiles_not_read[0].reason);
        expect(brief.summary).toContain(lock);
        expect(brief.summary).toMatch(/^(UNREADABLE|PARTIAL): /);
        expect(brief.delegation_assessment.reason).toContain(lock);
        const scan = await call("vulnerability_scan", {});
        expect(scan.coverage.complete).toBe(false);
      });
    }
  }
});

describe("a lockfile with merge-conflict markers: the briefing says NOT CHECKED (merge conflict) and which file, as every tool does", () => {
  const conflicted = (ours: string, theirs: string) => `<<<<<<< HEAD\n${ours}\n=======\n${theirs}\n>>>>>>> feature\n`;
  const CASES: Array<{ name: string; files: Record<string, string>; lock: string }> = [
    { name: "npm only", files: { "package.json": PKG_JSON, "package-lock.json": conflicted(NPM_LOCK, NPM_LOCK) }, lock: "package-lock.json" },
    { name: "npm beside requirements.txt", files: { "package.json": PKG_JSON, "package-lock.json": conflicted(NPM_LOCK, NPM_LOCK), "requirements.txt": REQUIREMENTS }, lock: "package-lock.json" },
    { name: "yarn.lock beside requirements.txt", files: { "package.json": PKG_JSON, "yarn.lock": conflicted(YARN_LOCK, YARN_LOCK), "requirements.txt": REQUIREMENTS }, lock: "yarn.lock" },
    { name: "Cargo.lock beside requirements.txt", files: { "Cargo.toml": CARGO_TOML, "Cargo.lock": conflicted(CARGO_LOCK, CARGO_LOCK), "requirements.txt": REQUIREMENTS }, lock: "Cargo.lock" },
  ];
  for (const { name, files, lock } of CASES) {
    it(`${name}: unknown, the summary and the reason lead with the merge-conflict note naming ${lock}`, async () => {
      liveFor(files);
      const brief = await call("what_should_i_know", TASK);
      expect(brief.delegation_assessment.level).toBe("unknown");
      const note = `NOT CHECKED (merge conflict): 1 file holds git merge-conflict markers (${lock})`;
      expect(brief.summary.startsWith(note)).toBe(true);
      expect(brief.delegation_assessment.reason.startsWith(note)).toBe(true);
      expect(brief.lockfiles_not_read).toEqual([{ path: lock, reason: "merge_conflict", error: expect.any(String) }]);
      // dependency_health says the same of the same file.
      const health = await call("dependency_health", {});
      expect(health.summary).toContain("NOT CHECKED (merge conflict): 1 file holds git merge-conflict markers");
      expect(health.summary).toContain(lock);
    });
  }
});
