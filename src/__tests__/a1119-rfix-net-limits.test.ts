// SPDX-License-Identifier: Apache-2.0
/**
 * Limits that must fit real answers and apply on every path: GitHub's body cap holds a real
 * first page of releases, the cache's row limit holds for every write, and readers that stop
 * at a limit say so.
 */

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { gzipSync } from "node:zlib";

import Database from "better-sqlite3";
import { Agent, EnvHttpProxyAgent } from "undici";
import { afterEach, describe, expect, it, vi } from "vitest";

import { LiveCache } from "../live/cache.js";
import { isChangelogName } from "../live/changelog.js";
import { getGithubChangelog, releasesToSectionsWithin } from "../live/github-releases.js";
import { responseCap } from "../live/http-utils.js";
import { MAX_LOCKFILE_LINE } from "../live/js-lockfile-readers.js";
import { fetchLoopbackJson } from "../live/loopback-http.js";
import { MAX_ARCHIVE_TEXT_FILES, readRootTextFiles, stoppedAtLimit, type FetchFn } from "../live/package-archive.js";
import { npmLockPrivateSources } from "../live/private-packages.js";
import { createUpgradeNet, getChangelog, type RegistryIndex } from "../live/upgrade-sources.js";
import { compareVersions } from "../live/version-compare.js";

const MB = 1024 * 1024;

describe("response caps fit what the hosts really send", () => {
  it("GitHub's API and raw files hold a 13.3 MB first page of releases with room to spare", () => {
    expect(responseCap("https://api.github.com/repos/electron/electron/releases?per_page=100")).toBe(64 * MB);
    expect(responseCap("https://raw.githubusercontent.com/electron/electron/main/CHANGELOG.md")).toBe(64 * MB);
  });
});

describe("the cache's row limit holds for every write", () => {
  it("setMany on a database skips the oversized row and keeps the rest", () => {
    const cache = new LiveCache(new Database(":memory:"));
    const huge = "x".repeat(25 * 1024 * 1024);
    cache.setMany([["k:small", { v: 1 }], ["k:huge", { v: huge }], ["k:after", { v: 2 }]], "test", 3600);
    expect(cache.get("k:small")).toEqual({ v: 1 });
    expect(cache.get("k:after")).toEqual({ v: 2 });
    expect(cache.getStale("k:huge")).toBeNull();
  });
});

describe("the GitHub changelog path is under the parse time allowance", () => {
  const order = (a: string, b: string) => compareVersions(a, b, "PyPI");
  const changelog = Array.from({ length: 300 }, (_, n) => `## 1.${300 - n}.0\n\n- Change ${n}.\n`).join("\n");
  /** A clock that jumps a second each time it is read: any time allowance runs out within a few checks. */
  const racingClock = () => {
    let t = 1_000_000;
    return vi.spyOn(Date, "now").mockImplementation(() => (t += 1000));
  };
  afterEach(() => vi.restoreAllMocks());

  it("a linked changelog file read past the allowance carries the incomplete note", async () => {
    const fetchFn: FetchFn = async () => new Response(changelog, { status: 200 });
    const net = createUpgradeNet(null, fetchFn);
    racingClock();
    const result = await getGithubChangelog(net, {
      pkg: "zqpkg", ecosystem: "PyPI", repository: null, from: "1.0.0", to: "1.300.0", order,
      changelogLinks: ["https://github.com/zq/zqpkg/blob/main/CHANGELOG.md"],
    });
    vi.restoreAllMocks();
    expect(result.incomplete ?? result.reason ?? "").toMatch(/time allowed/);
  });

  it("release notes read past the allowance stop there and say so", async () => {
    const body = Array.from({ length: 400 }, (_, n) => `- note ${n}`).join("\n");
    const releases = Array.from({ length: 5 }, (_, n) => ({ tag_name: `v1.${5 - n}.0`, body, draft: false, published_at: "2026-01-01T00:00:00Z" }));
    racingClock();
    const parsed = releasesToSectionsWithin(releases, "zqpkg", null);
    vi.restoreAllMocks();
    expect(parsed.complete).toBe(false);
    expect(parsed.sections.length).toBeLessThan(5);
  });
});

describe("an archive read that stops at a limit says so", () => {
  function tgz(entries: Array<{ name: string; body: string }>): Buffer {
    const parts: Buffer[] = [];
    for (const e of entries) {
      const body = Buffer.from(e.body, "utf8");
      const h = Buffer.alloc(512);
      h.write(e.name, 0, "utf8");
      h.write("0000644\0", 100, "ascii");
      h.write("0000000\0", 108, "ascii");
      h.write("0000000\0", 116, "ascii");
      h.write(`${body.length.toString(8).padStart(11, "0")}\0`, 124, "ascii");
      h.write("00000000000\0", 136, "ascii");
      h.write("0", 156, "ascii");
      h.write("ustar\0", 257, "ascii");
      h.write("00", 263, "ascii");
      h.fill(0x20, 148, 156);
      let sum = 0;
      for (const b of h) sum += b;
      h.write(`${sum.toString(8).padStart(6, "0")}\0 `, 148, "ascii");
      parts.push(h, body.length % 512 === 0 ? body : Buffer.concat([body, Buffer.alloc(512 - (body.length % 512))]));
    }
    parts.push(Buffer.alloc(1024));
    return gzipSync(Buffer.concat(parts));
  }
  // 40 changelog-named files with no version headings come first; the real changelog is after the 32-file limit.
  const entries = [
    ...Array.from({ length: 40 }, (_, n) => ({ name: `d${n}/NEWS.txt`, body: "nothing versioned here\n" })),
    { name: "package/CHANGELOG.md", body: "# Changelog\n\n## 2.0.0\n\n- Removed `oldThing()`.\n" },
  ];

  it("the tar reader flags a read that stopped at the file limit", () => {
    const files = readRootTextFiles(tgz(entries), isChangelogName);
    expect(files.size).toBe(MAX_ARCHIVE_TEXT_FILES);
    expect(stoppedAtLimit(files)).toBe(true);
    expect(stoppedAtLimit(readRootTextFiles(tgz(entries.slice(-1)), isChangelogName))).toBe(false);
  });

  it("getChangelog says the archive holds more changelog-named files than are read", async () => {
    const archive = tgz(entries);
    const net = createUpgradeNet(null, async () => new Response(new Uint8Array(archive), { status: 200 }));
    const index: RegistryIndex = { name: "zqpkg", ecosystem: "npm", versions: [], repository: null };
    const result = await getChangelog(net, index, { version: "2.0.0", published: null, tarball: "https://registry.npmjs.org/zqpkg/-/zqpkg-2.0.0.tgz" });
    expect(result.found).toBe(false);
    expect(result.reason).toMatch(/holds more changelog-named files than are read/);
    expect(result.reason).not.toMatch(/ships no changelog file/);
  });
});

describe("local embedding requests never take the environment proxy", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("passes a direct dispatcher that is not the environment proxy agent", async () => {
    const seen: Array<RequestInit & { dispatcher?: unknown }> = [];
    vi.stubGlobal("fetch", async (_url: string, init: RequestInit) => {
      seen.push(init);
      return new Response("{}", { status: 200, headers: { "content-type": "application/json" } });
    });
    await fetchLoopbackJson("http://127.0.0.1:11434/api/tags");
    expect(seen).toHaveLength(1);
    expect(seen[0].dispatcher).toBeInstanceOf(Agent);
    expect(seen[0].dispatcher).not.toBeInstanceOf(EnvHttpProxyAgent);
  });
});

describe("a yarn.lock block whose header is over the line cap", () => {
  it("makes the private-source pass report the file as not fully read", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "a1119-rfix-net-yarn-"));
    try {
      const header = `"@acme/ui@${"x".repeat(MAX_LOCKFILE_LINE + 10)}":`;
      fs.writeFileSync(path.join(dir, "yarn.lock"), `# yarn lockfile v1\n\n${header}\n  version "1.0.0"\n  resolved "https://npm.acme.internal/@acme/ui/-/ui-1.0.0.tgz"\n`);
      const out = npmLockPrivateSources(dir, new Set());
      expect(out.some((e) => e.unread && e.file.endsWith("yarn.lock"))).toBe(true);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
