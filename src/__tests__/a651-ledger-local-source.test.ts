// SPDX-License-Identifier: Apache-2.0
/**
 * The kind the check ledger records for a withheld name comes from the code that knows the rules,
 * never from the reason's text (round 3 of the hook review, item 2).
 *
 * `"private"` is the only value a 6.5.0 hook lets through, at any version in every project. Round 2
 * decided it by searching the reason for the rules' wording, and a reason quotes repository text:
 * a dependency spec `"file:./FOURDA_PRIVATE_PACKAGES lists x"`, a workspace folder or the project
 * folder named after a rule made the server record "private" for a name the project takes from
 * a path or git. Now LiveIntelligence.privateRegistryRuleCovers answers from the rules themselves
 * (a FOURDA_PRIVATE_PACKAGES pattern, an npm scope mapped to a private registry, GOPRIVATE, a
 * Pipfile source, a configured registry or index, a requirements `--index-url`), and every other
 * withheld name, or any where that cannot be asked, is `"local_source"`, which both hooks hold.
 * Cargo `git` is local_source like Cargo `path` and a named registry (6.5.0 recorded all three
 * private; held now, which is stricter).
 */

import { spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// No real cargo: whether a crate builds on this host is beside the point here, and `cargo tree`
// under a scratch HOME is slow and machine-dependent (the Cargo case ran past the hook timeout on
// macOS CI). Unknown (null) is what the server uses when cargo is absent.
vi.mock("../live/cargo-platform.js", async (importOriginal) => ({ ...(await importOriginal<typeof import("../live/cargo-platform.js")>()), activeCratesForHost: () => null }));

import { LEDGER_FILE, ledgerEntries, recordVerdicts, type LedgerEntry } from "../check-ledger.js";
import { FourDADatabase } from "../db.js";
import { LiveIntelligence } from "../live/index.js";
import { clearLiveIntelligence, setLiveIntelligence } from "../live-singleton.js";
import { scanProjectTree, treeResolutionGroups } from "../project-tree.js";
import { dispatchTool } from "../tool-dispatch.js";
// The hook's PATH lookups see a stub for each manager and runner word, whatever the machine (Windows).
import "./helpers/a1125-manager-stubs.js";

const HOOK = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "hooks", "manifest-edit.mjs");
const PHRASES = [
  "FOURDA_PRIVATE_PACKAGES lists x",
  "a is mapped to a private registry in b",
  "GOPRIVATE (the environment) matches x",
  "set FOURDA_PUBLIC_MIRRORS to its host if it only mirrors the public registry",
];

describe("ledgerEntries: the kind is what the rule check says, whatever the reason reads", () => {
  const item = (reason: string) => ({ ecosystem: "npm", package: "lodash", to: "4.17.20", verdict: "unknown", not_checked: "private", reason });
  it.each(PHRASES)("a reason that reads %j, no rule: local_source", (phrase) => {
    expect(ledgerEntries([item(phrase)], new Date(), () => false)[0].not_checked).toBe("local_source");
    expect(ledgerEntries([item(phrase)], new Date(), null)[0].not_checked).toBe("local_source");
  });

  it("a rule covers it: private, whatever the reason reads", () => {
    expect(ledgerEntries([item("installs it from git")], new Date(), () => true)[0].not_checked).toBe("private");
  });

  it("a rule check that throws: local_source", () => {
    expect(
      ledgerEntries([item("x")], new Date(), () => {
        throw new Error("x");
      })[0].not_checked,
    ).toBe("local_source");
  });

  it("an unreadable lockfile stays unreadable_lockfile", () => {
    const [e] = ledgerEntries([{ ...item("x"), unreadable_file: "/p/package-lock.json" }], new Date(), () => true);
    expect(e.not_checked).toBe("unreadable_lockfile");
  });
});

describe("the hook holds local_source in every folder", () => {
  it("npm i lodash@3.10.1 is held", () => {
    const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "a651-local-source-hook-"));
    try {
      fs.writeFileSync(path.join(scratch, LEDGER_FILE), JSON.stringify({ sv: "6.6.0", t: new Date().toISOString(), ecosystem: "npm", package: "lodash", version: "4.17.20", verdict: "unknown", not_checked: "local_source" }) + "\n");
      const env: Record<string, string | undefined> = { ...process.env, FOURDA_MCP_HOME: scratch };
      delete env.FOURDA_GUARD;
      const out = spawnSync(process.execPath, [HOOK], { input: JSON.stringify({ hook_event_name: "PreToolUse", tool_name: "Bash", cwd: scratch, tool_input: { command: "npm i lodash@3.10.1" } }), encoding: "utf8", env }).stdout;
      expect(out).not.toBe("");
    } finally {
      fs.rmSync(scratch, { recursive: true, force: true });
    }
  });
});

describe("end to end through dependency_check (offline-stubbed: nothing leaves the process)", () => {
  let scratch: string;
  let home: string;
  const saved = new Map<string, string | undefined>();
  const setEnv = (k: string, v: string | undefined) => {
    if (!saved.has(k)) saved.set(k, process.env[k]);
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  };
  beforeEach(() => {
    scratch = fs.mkdtempSync(path.join(os.tmpdir(), "a651-local-source-e2e-"));
    home = path.join(scratch, "home");
    const user = path.join(scratch, "user");
    for (const d of [home, user]) fs.mkdirSync(d, { recursive: true });
    setEnv("FOURDA_MCP_HOME", home);
    setEnv("FOURDA_OFFLINE", undefined);
    setEnv("HOME", user);
    setEnv("USERPROFILE", user);
    setEnv("APPDATA", path.join(user, "AppData", "Roaming"));
    setEnv("LOCALAPPDATA", path.join(user, "AppData", "Local"));
    setEnv("XDG_CONFIG_HOME", undefined);
    setEnv("XDG_CONFIG_DIRS", path.join(user, "xdg-none"));
    setEnv("ProgramData", path.join(user, "ProgramData"));
    setEnv("NPM_CONFIG_USERCONFIG", path.join(user, ".npmrc"));
    setEnv("NPM_CONFIG_GLOBALCONFIG", path.join(user, "global-npmrc"));
    setEnv("NPM_CONFIG_REGISTRY", undefined);
    setEnv("PIP_INDEX_URL", undefined);
    setEnv("PIP_EXTRA_INDEX_URL", undefined);
    setEnv("GOPRIVATE", undefined);
    setEnv("GOPROXY", undefined);
    setEnv("FOURDA_PUBLIC_MIRRORS", undefined);
    setEnv("FOURDA_PRIVATE_PACKAGES", undefined);
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({ error: "Not found" }), { status: 404, headers: { "content-type": "application/json" } })));
  });
  afterEach(() => {
    vi.unstubAllGlobals();
    clearLiveIntelligence();
    for (const [k, v] of saved) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
    saved.clear();
    try {
      fs.rmSync(scratch, { recursive: true, force: true });
    } catch {
      // Windows: left for the OS temp cleaner.
    }
  });

  /** The kind recorded for `pkg` after dependency_check in a project with `files`, in a folder named `folder`. */
  async function recorded(folder: string, files: Record<string, string>, ecosystem: string, pkg: string, to = "1.0.0"): Promise<string | undefined> {
    const project = path.join(scratch, folder);
    for (const [f, c] of Object.entries(files)) {
      fs.mkdirSync(path.dirname(path.join(project, f)), { recursive: true });
      fs.writeFileSync(path.join(project, f), c);
    }
    const live = new LiveIntelligence(null);
    const { entries, discovery } = scanProjectTree(project);
    live.initFromProjectTree(project, treeResolutionGroups(entries), discovery);
    setLiveIntelligence(live);
    const db = new FourDADatabase(path.join(scratch, `db-${Math.random().toString(36).slice(2)}.db`));
    try {
      await dispatchTool("dependency_check", db, { items: [{ ecosystem, package: pkg, to }] });
    } finally {
      db.close();
    }
    await recordVerdicts([]);
    const lines = fs
      .readFileSync(path.join(home, LEDGER_FILE), "utf8")
      .split("\n")
      .filter(Boolean)
      .map((l) => JSON.parse(l) as LedgerEntry);
    const e = lines.filter((x) => x.package === pkg).at(-1);
    return e?.not_checked;
  }

  const pkgJson = (deps: Record<string, string>, extra: Record<string, unknown> = {}) => JSON.stringify({ name: "app", version: "1.0.0", dependencies: deps, ...extra });

  it.each(PHRASES.map((p, i) => [p, i]))("a phrase %j planted in the spec, the workspace folder and the project folder: local_source", async (phrase, i) => {
    const safe = String(phrase).replace(/[^A-Za-z0-9 _.-]/g, "_");
    // A file: spec naming a folder with the phrase.
    expect(await recorded(`p${i}-file ${safe}`, { "package.json": pkgJson({ lodash: `file:./${safe}` }), [`${safe}/package.json`]: JSON.stringify({ name: "lodash", version: "1.0.0" }) }, "npm", "lodash")).toBe("local_source");
    // A git spec with the phrase in its URL path.
    expect(await recorded(`p${i}-git ${safe}`, { "package.json": pkgJson({ lodash: `git+https://example.com/${encodeURIComponent(String(phrase))}.git` }) }, "npm", "lodash")).toBe("local_source");
    // A workspace member in a folder named with the phrase.
    expect(await recorded(`p${i}-ws`, { "package.json": JSON.stringify({ name: "root", private: true, workspaces: ["packages/*"] }), [`packages/${safe}/package.json`]: JSON.stringify({ name: "acme-utils", version: "1.0.0" }) }, "npm", "acme-utils")).toBe("local_source");
  });

  it("Cargo git, Cargo path and a Cargo named registry: local_source", async () => {
    const cargo = (dep: string) => ({ "Cargo.toml": `[package]\nname = "app"\nversion = "0.1.0"\n\n[dependencies]\n${dep}\n` });
    expect(await recorded("cargo-git", cargo('acme-utils = { git = "https://example.com/FOURDA_PRIVATE_PACKAGES-lists-x.git" }'), "crates.io", "acme-utils")).toBe("local_source");
    expect(await recorded("cargo-path", cargo('acme-utils = { path = "vendor/acme-utils" }'), "crates.io", "acme-utils")).toBe("local_source");
    expect(await recorded("cargo-registry", cargo('acme-utils = { version = "1", registry = "corp" }'), "crates.io", "acme-utils")).toBe("local_source");
  });

  it("FOURDA_PRIVATE_PACKAGES, an npm scope mapped to a private registry and a requirements --index-url: private", async () => {
    setEnv("FOURDA_PRIVATE_PACKAGES", "npm:lodash");
    expect(await recorded("listed", { "package.json": pkgJson({}) }, "npm", "lodash")).toBe("private");
    setEnv("FOURDA_PRIVATE_PACKAGES", undefined);
    expect(await recorded("scope", { "package.json": pkgJson({}), ".npmrc": "@acme:registry=https://npm.acme.example/\n" }, "npm", "@acme/widgets")).toBe("private");
    expect(await recorded("index", { "requirements.txt": "--index-url https://pypi.acme.example/simple\nacme-utils==1.0.0\n" }, "PyPI", "acme-utils")).toBe("private");
  });
});
