// SPDX-License-Identifier: Apache-2.0
/**
 * The ledger keeps `not_checked: "private"` for what 6.5.0 called private, and records the names
 * 6.5.1 newly withholds (a git, path, file:, tarball, link:, workspace source, a patched crate) as
 * `"local_source"`.
 *
 * Independent re-check of 0d30b40 (S4): a 6.5.1 server beside a 6.5.0 hook was LESS safe than
 * 6.5.0 with 6.5.0. The 6.5.0 hook lets any `not_checked: "private"` name through, at any version,
 * in every project; 6.5.1 records many more names as private (`"lodash": "github:me/lodash"`:
 * 6.5.0 server, deny/deny; 6.5.1 server + 6.5.0 hook, allow/allow). A 6.5.0 hook holds every value
 * other than "private", so the new value is held there; the 6.5.1 hook treats it as private within
 * its project.
 *
 * "private" is kept only on positive evidence of a 6.5.0-class rule in the server's reason
 * (FOURDA_PRIVATE_PACKAGES, an npm scope mapped to a private registry, GOPRIVATE / GONOPROXY /
 * GONOSUMDB, or a registry, index or proxy that is not public, whose reasons carry the
 * FOURDA_PUBLIC_MIRRORS hint); anything else is "local_source", which no 6.5.0 hook lets through.
 */

import { spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { LEDGER_FILE, ledgerEntries, recordVerdicts, type LedgerEntry } from "../check-ledger.js";
import { FourDADatabase } from "../db.js";
import { LiveIntelligence } from "../live/index.js";
import { clearLiveIntelligence, setLiveIntelligence } from "../live-singleton.js";
import { scanProjectTree, treeResolutionGroups } from "../project-tree.js";
import { dispatchTool } from "../tool-dispatch.js";

const HOOK = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "hooks", "manifest-edit.mjs");
const reason = (why: string) => `NOT CHECKED (private): lodash is a private package (${why}), so nothing about it was sent to OSV.dev or a public registry.`;
const kind = (why: string) => ledgerEntries([{ ecosystem: "npm", package: "lodash", to: "4.17.20", verdict: "unknown", not_checked: "private", reason: reason(why) }], new Date())[0].not_checked;

describe("ledgerEntries: which withheld names stay private", () => {
  it.each([
    ["FOURDA_PRIVATE_PACKAGES lists npm:lodash"],
    ["@acme is mapped to a private registry in /p/.npmrc"],
    ["GOPRIVATE (the environment) matches example.com/*"],
    ["npm installs it from https://npm.acme.example/ (/p/.npmrc), not the public registry; set FOURDA_PUBLIC_MIRRORS to its host if it only mirrors the public registry"],
    ["package-lock.json installs it from https://npm.acme.example/, not the public registry; set FOURDA_PUBLIC_MIRRORS to its host if it only mirrors the public registry"],
  ])("%s: private", (why) => {
    expect(kind(why)).toBe("private");
  });

  it.each([
    ["/p/package.json installs it from github:me/lodash, not the public registry"],
    ["/p/package.json installs it from file:./vendor/lodash, not the public registry"],
    ["/p/Cargo.toml patches it from https://github.com/me/time, not crates.io"],
    ["a workspace member of /p"],
    ["something this hook has not seen"],
  ])("%s: local_source", (why) => {
    expect(kind(why)).toBe("local_source");
  });

  it("an unreadable lockfile stays unreadable_lockfile", () => {
    const [e] = ledgerEntries([{ ecosystem: "npm", package: "lodash", to: "1", verdict: "unknown", not_checked: "private", unreadable_file: "/p/package-lock.json", reason: reason("FOURDA_PRIVATE_PACKAGES lists x") }], new Date());
    expect(e.not_checked).toBe("unreadable_lockfile");
  });
});

describe("the 6.5.1 hook: local_source is held", () => {
  let scratch: string;
  beforeEach(() => {
    scratch = fs.mkdtempSync(path.join(os.tmpdir(), "a651-local-source-"));
  });
  afterEach(() => fs.rmSync(scratch, { recursive: true, force: true }));

  it("held in A and in B: a registry install of a name A takes from elsewhere is unchecked (round 3, item 1)", () => {
    const home = path.join(scratch, "home");
    const a = path.join(scratch, "a");
    const b = path.join(scratch, "b");
    for (const d of [home, a, b]) fs.mkdirSync(d);
    fs.writeFileSync(path.join(home, LEDGER_FILE), JSON.stringify({ t: new Date().toISOString(), ecosystem: "npm", package: "lodash", version: "4.17.20", verdict: "unknown", not_checked: "local_source" }) + "\n");
    const run = (cwd: string) => {
      const env: Record<string, string | undefined> = { ...process.env, FOURDA_MCP_HOME: home };
      delete env.FOURDA_GUARD;
      const out = spawnSync(process.execPath, [HOOK], { input: JSON.stringify({ hook_event_name: "PreToolUse", tool_name: "Bash", cwd, tool_input: { command: "npm i lodash@3.10.1" } }), encoding: "utf8", env }).stdout;
      return out === "" ? "allow" : "deny";
    };
    expect(run(a)).toBe("deny");
    expect(run(b)).toBe("deny");
  });
});

describe("end to end through dependency_check (offline-stubbed: nothing leaves the process)", () => {
  let scratch: string;
  let home: string;
  let project: string;
  const saved = new Map<string, string | undefined>();
  const setEnv = (k: string, v: string | undefined) => {
    if (!saved.has(k)) saved.set(k, process.env[k]);
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  };
  beforeEach(() => {
    scratch = fs.mkdtempSync(path.join(os.tmpdir(), "a651-local-source-e2e-"));
    home = path.join(scratch, "home");
    project = path.join(scratch, "app");
    const user = path.join(scratch, "user");
    for (const d of [home, project, user]) fs.mkdirSync(d, { recursive: true });
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

  async function answer(files: Record<string, string>): Promise<LedgerEntry> {
    for (const [f, c] of Object.entries(files)) fs.writeFileSync(path.join(project, f), c);
    const live = new LiveIntelligence(null);
    const { entries, discovery } = scanProjectTree(project);
    live.initFromProjectTree(project, treeResolutionGroups(entries), discovery);
    setLiveIntelligence(live);
    const db = new FourDADatabase(path.join(scratch, `db-${Math.random().toString(36).slice(2)}.db`));
    try {
      await dispatchTool("dependency_check", db, { items: [{ ecosystem: "npm", package: "lodash", to: "4.17.20" }] });
    } finally {
      db.close();
    }
    await recordVerdicts([]);
    const lines = fs.readFileSync(path.join(home, LEDGER_FILE), "utf8").split("\n").filter(Boolean);
    return JSON.parse(lines.at(-1)!) as LedgerEntry;
  }

  it('a GitHub shorthand dependency ("github:me/lodash") is local_source', async () => {
    expect((await answer({ "package.json": JSON.stringify({ name: "a", version: "1.0.0", dependencies: { lodash: "github:me/lodash" } }) })).not_checked).toBe("local_source");
  });

  it("FOURDA_PRIVATE_PACKAGES stays private", async () => {
    setEnv("FOURDA_PRIVATE_PACKAGES", "npm:lodash");
    expect((await answer({ "package.json": JSON.stringify({ name: "a", version: "1.0.0" }) })).not_checked).toBe("private");
  });

  it("an npm scope mapped to a private registry stays private", async () => {
    const files = { "package.json": JSON.stringify({ name: "a", version: "1.0.0" }), ".npmrc": "@acme:registry=https://npm.acme.example/\n" };
    for (const [f, c] of Object.entries(files)) fs.writeFileSync(path.join(project, f), c);
    const live = new LiveIntelligence(null);
    const { entries, discovery } = scanProjectTree(project);
    live.initFromProjectTree(project, treeResolutionGroups(entries), discovery);
    setLiveIntelligence(live);
    const db = new FourDADatabase(path.join(scratch, "db-scope.db"));
    try {
      await dispatchTool("dependency_check", db, { items: [{ ecosystem: "npm", package: "@acme/widgets", to: "1.0.0" }] });
    } finally {
      db.close();
    }
    await recordVerdicts([]);
    const last = JSON.parse(fs.readFileSync(path.join(home, LEDGER_FILE), "utf8").split("\n").filter(Boolean).at(-1)!) as LedgerEntry;
    expect(last.not_checked).toBe("private");
  });
});
