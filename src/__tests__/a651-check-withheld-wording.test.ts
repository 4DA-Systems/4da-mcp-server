// SPDX-License-Identifier: Apache-2.0
/**
 * dependency_check on a name it withholds (never sent anywhere) must not read as checked or clean.
 *
 * On 6.5.0, beside an npm lockfile that is not valid JSON, `dependency_check {lodash 4.17.21}`
 * answered "NOT CHECKED (private): lodash is a private package (...)" and "check it with your
 * private registry's own tooling": lodash is not private, the lockfile is unreadable, and the remedy
 * is to repair it. And whenever every item was withheld, `_meta.sources_note` said "Nothing was sent
 * in this call: every answer was read from the local cache", which reads as answered (from the
 * cache) when nothing about any item is known. Seen on the published 6.5.0 behind a dead proxy.
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

beforeEach(() => {
  scratch = fs.mkdtempSync(path.join(os.tmpdir(), "4da-a651-withheld-"));
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
  setEnv("NPM_CONFIG_USERCONFIG", path.join(home, ".npmrc"));
  setEnv("NPM_CONFIG_GLOBALCONFIG", path.join(home, "global-npmrc"));
  setEnv("NPM_CONFIG_REGISTRY", undefined);
  setEnv("FOURDA_PUBLIC_MIRRORS", undefined);
  setEnv("FOURDA_PRIVATE_PACKAGES", undefined);
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: string, init?: RequestInit) => {
      sent.push(`${decodeURIComponent(String(input))} ${typeof init?.body === "string" ? init.body : ""}`);
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

function liveFor(files: Record<string, string>): void {
  for (const [file, content] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(project, file)), { recursive: true });
    fs.writeFileSync(path.join(project, file), content);
  }
  const live = new LiveIntelligence(null);
  const { entries, discovery } = scanProjectTree(project);
  live.initFromProjectTree(project, treeResolutionGroups(entries), discovery);
  setLiveIntelligence(live);
}

async function call(args: Record<string, unknown>): Promise<Record<string, any>> {
  const db = new FourDADatabase(path.join(scratch, `standalone-${Math.random().toString(36).slice(2)}.db`));
  try {
    const result = (await dispatchTool("dependency_check", db, args)) as { content: Array<{ text: string }> };
    return JSON.parse(result.content[0].text) as Record<string, any>;
  } finally {
    db.close();
  }
}

const PKG_JSON = JSON.stringify({ name: "app", version: "1.0.0", dependencies: { lodash: "4.17.21" } });
const GARBAGE_LOCK = '{"name":"app","lockfileVersion":3,"packages":{"":{';

describe("dependency_check on a withheld name", () => {
  it("beside an unreadable package-lock.json: said as the unreadable lockfile, not as private, and nothing is sent", async () => {
    liveFor({ "package.json": PKG_JSON, "package-lock.json": GARBAGE_LOCK });
    const r = await call({ items: [{ ecosystem: "npm", package: "lodash", to: "4.17.21" }], response_format: "detailed" });
    const item = r.results[0];
    expect(item.verdict).toBe("unknown");
    expect(item.not_checked).toBe("private");
    expect(item.reason).toMatch(/^NOT CHECKED \(unreadable lockfile\): .*package-lock\.json could not be read/);
    expect(item.reason).not.toMatch(/is a private package|private registry/);
    expect(item.unreadable_file).toMatch(/package-lock\.json$/);
    expect(r.summary).toMatch(/^NOT CHECKED: 1 not checked \(unreadable lockfile\)/);
    expect(r.summary).not.toMatch(/private registry/);
    expect(r.summary).toMatch(/repair or regenerate .*package-lock\.json/);
    expect(r._meta.private_packages).toBeUndefined();
    expect(r._meta.unreadable_lockfile).toMatch(/^1 item was withheld because a lockfile/);
    // Withheld for privacy all the same.
    expect(sent.filter((s) => /lodash/.test(s))).toEqual([]);
  });

  it("every item withheld: sources_note does not say the answers came from the cache", async () => {
    liveFor({ "package.json": PKG_JSON, "package-lock.json": GARBAGE_LOCK, ".npmrc": "@acme:registry=https://npm.acme.example/\n" });
    const r = await call({
      items: [
        { ecosystem: "npm", package: "lodash", to: "4.17.21" },
        { ecosystem: "npm", package: "@acme/widgets", to: "1.0.0" },
      ],
      response_format: "detailed",
    });
    expect(r.results.map((x: { not_checked?: string }) => x.not_checked)).toEqual(["private", "private"]);
    expect(r._meta.sources).toEqual([]);
    expect(r._meta.sources_note).not.toMatch(/read from the local cache/);
    expect(r._meta.sources_note).toMatch(/none of the 2 items was looked up/);
    expect(sent).toEqual([]);
  });

  it("a scoped name an .npmrc maps to a private registry is still said as private", async () => {
    liveFor({ "package.json": JSON.stringify({ name: "app", version: "1.0.0" }), ".npmrc": "@acme:registry=https://npm.acme.example/\n" });
    const r = await call({ items: [{ ecosystem: "npm", package: "@acme/widgets", to: "1.0.0" }], response_format: "detailed" });
    expect(r.results[0].reason).toMatch(/^NOT CHECKED \(private\): @acme\/widgets is a private package/);
    expect(r.results[0].unreadable_file).toBeUndefined();
    expect(r.summary).toMatch(/^NOT CHECKED: 1 not checked \(private\)/);
    expect(r._meta.private_packages).toMatch(/^1 item names a private package/);
    expect(r._meta.sources_note).toMatch(/the item was not looked up/);
    expect(sent).toEqual([]);
  });
});
