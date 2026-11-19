// SPDX-License-Identifier: Apache-2.0
/**
 * what_should_i_know's `newer_releases` lists the registry releases newer than the installed one
 * that the desktop app's feed recorded (it watches npm and crates.io). Without that feed (the
 * standalone database has an empty source_items table), for an ecosystem the feed does not watch
 * (PyPI, Go), or for a package it does not follow, the briefing has no answer: the field is left
 * out, never `[]`, which reads as "no newer release" (express 4.17.1, Jinja2 2.10 and PyYAML 5.1
 * all have many). `[]` is kept for what it says: the feed follows the package and recorded
 * nothing above the installed version.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { clearNpmDownloadsMemo } from "../live/npm-downloads.js";
import type { ResolvedDependency } from "../live/types.js";
import { executeWhatShouldIKnow } from "../tools/what-should-i-know.js";
import type { FourDADatabase } from "../db.js";
import { dep, installFetchStub, memoryDb, stubIntel, type Stub } from "./helpers/briefing-stub.js";

let stub: Stub;
let db: FourDADatabase;
let priorOffline: string | undefined;
beforeEach(() => {
  priorOffline = process.env.FOURDA_OFFLINE;
  delete process.env.FOURDA_OFFLINE;
  clearNpmDownloadsMemo();
  db = memoryDb();
  // The table every database has, the standalone one included; empty until the app's feed writes to it.
  db.getRawDb().exec("CREATE TABLE source_items (id INTEGER PRIMARY KEY, source_type TEXT, source_id TEXT, title TEXT, url TEXT, content TEXT, created_at TEXT)");
  stub = { asked: [], npm: { express: { latest: "4.21.2", versions: ["4.17.1", "4.21.2"] } }, osv: [] };
  installFetchStub(stub);
});
afterEach(() => {
  if (priorOffline === undefined) delete process.env.FOURDA_OFFLINE;
  else process.env.FOURDA_OFFLINE = priorOffline;
});

/** A release row as the app's registry sources title it. */
function feedRelease(source: "npm_registry" | "crates_io", title: string, createdAt = "2026-11-01 00:00:00") {
  db.getRawDb().prepare("INSERT INTO source_items (source_type, source_id, title, url, content, created_at) VALUES (?, ?, ?, ?, '', ?)")
    .run(source, title, title, `https://example.invalid/${encodeURIComponent(title)}`, createdAt);
}

async function brief(task: string, deps: ResolvedDependency[]) {
  const result = await executeWhatShouldIKnow(db, { task }, stubIntel(deps));
  return (name: string) => result.task_dependencies.find((d) => d.package === name) as unknown as Record<string, unknown>;
}

describe("newer_releases says only what the desktop app's feed recorded", () => {
  it("no feed (an empty source_items, as in the standalone database): the field is absent, not []", async () => {
    const of = await brief("upgrade express", [dep("express", "4.17.1")]);
    expect(of("express")).toBeDefined();
    expect(of("express")).not.toHaveProperty("newer_releases");
  });

  it("PyPI: the feed does not watch it, so the field is absent even beside a feed that has rows", async () => {
    feedRelease("npm_registry", "npm: express v4.21.2");
    const of = await brief("upgrade Jinja2 and PyYAML", [dep("Jinja2", "2.10", "PyPI"), dep("PyYAML", "5.1", "PyPI")]);
    expect(of("Jinja2")).toBeDefined();
    expect(of("PyYAML")).toBeDefined();
    expect(of("Jinja2")).not.toHaveProperty("newer_releases");
    expect(of("PyYAML")).not.toHaveProperty("newer_releases");
  });

  it("an npm package the feed does not follow: absent, though the feed records other packages' releases", async () => {
    feedRelease("npm_registry", "npm: lodash v4.17.21");
    const of = await brief("upgrade express", [dep("express", "4.17.1")]);
    expect(of("express")).not.toHaveProperty("newer_releases");
  });

  it("a package the feed follows: the releases above the installed one, newest first", async () => {
    feedRelease("npm_registry", "npm: express v4.17.1", "2026-01-01 00:00:00");
    feedRelease("npm_registry", "npm: express v4.21.2", "2026-06-01 00:00:00");
    feedRelease("npm_registry", "npm: express v5.1.0", "2026-10-01 00:00:00");
    const of = await brief("upgrade express", [dep("express", "4.17.1")]);
    const releases = of("express").newer_releases as Array<{ version: string }>;
    expect(releases.map((r) => r.version)).toEqual(["5.1.0", "4.21.2"]);
  });

  it("a package the feed follows with nothing newer recorded: [] is kept, and means exactly that", async () => {
    feedRelease("npm_registry", "npm: express v4.16.0");
    feedRelease("npm_registry", "npm: express v4.17.1");
    const of = await brief("upgrade express", [dep("express", "4.17.1")]);
    expect(of("express").newer_releases).toEqual([]);
  });
});
