// SPDX-License-Identifier: Apache-2.0
/**
 * The HTTP choke point for private package names (live/private-guard.ts): every OSV.dev,
 * registry and search request goes through fetchWithTimeout, which refuses one that names a
 * private package. And nothing in src/ reaches the network around it.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { fetchWithTimeout } from "../live/http-utils.js";
import { namesInRequest, PrivateRequestRefused, registerPrivateNames, type PrivateNameSource } from "../live/private-guard.js";

const src = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

/** Held strongly for the whole file: the guard holds sources weakly. */
const keep: PrivateNameSource[] = [];
function privateNames(map: Record<string, string[]>): void {
  const source: PrivateNameSource = { privateReason: (eco, name) => (map[eco]?.includes(name) ? "test rule" : null) };
  keep.push(source);
  registerPrivateNames(source, "test:private-guard");
}

afterEach(() => vi.unstubAllGlobals());

describe("the choke point", () => {
  privateNames({ npm: ["@guard/secret"], "crates.io": ["guard-core"], PyPI: ["guard-auth"], Go: ["github.com/GuardCorp/ledger"] });

  it.each([
    ["https://registry.npmjs.org/%40guard%2Fsecret", undefined],
    ["https://registry.npmjs.org/@guard/secret/1.0.0", undefined],
    ["https://api.npmjs.org/downloads/point/last-week/lodash,@guard/secret", undefined],
    ["https://crates.io/api/v1/crates/guard-core/versions?per_page=100", undefined],
    ["https://index.crates.io/gu/ar/guard-core", undefined],
    ["https://pypi.org/pypi/guard-auth/json", undefined],
    ["https://proxy.golang.org/github.com/!guard!corp/ledger/@v/list", undefined],
    ["https://api.osv.dev/v1/querybatch", JSON.stringify({ queries: [{ package: { name: "lodash", ecosystem: "npm" }, version: "1" }, { package: { name: "@guard/secret", ecosystem: "npm" }, version: "1" }] })],
    ["https://api.osv.dev/v1/query", JSON.stringify({ package: { name: "guard-core", ecosystem: "crates.io" } })],
  ])("refuses %s, and never calls fetch", async (url, body) => {
    const fetchSpy = vi.fn(async () => new Response("{}"));
    vi.stubGlobal("fetch", fetchSpy);
    await expect(fetchWithTimeout(url, body ? { method: "POST", body } : {})).rejects.toBeInstanceOf(PrivateRequestRefused);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("lets a public request through", async () => {
    const fetchSpy = vi.fn(async () => new Response("{}"));
    vi.stubGlobal("fetch", fetchSpy);
    await fetchWithTimeout("https://registry.npmjs.org/lodash");
    await fetchWithTimeout("https://api.osv.dev/v1/querybatch", { method: "POST", body: JSON.stringify({ queries: [{ package: { name: "lodash", ecosystem: "npm" } }] }) });
    expect(fetchSpy).toHaveBeenCalledTimes(2);
  });

  it("reads names the way each host spells them", () => {
    expect(namesInRequest("https://registry.npmjs.org/%40a%2Fb", undefined)).toEqual([["npm", "@a/b"]]);
    expect(namesInRequest("https://proxy.golang.org/github.com/!azure/x/@v/v1.0.0.info", undefined)).toEqual([["Go", "github.com/Azure/x"]]);
    expect(namesInRequest("https://static.crates.io/crates/serde/serde-1.0.0.crate", undefined)).toEqual([["crates.io", "serde"]]);
  });
});

describe("nothing in src/ reaches the network around the choke point", () => {
  /** The only places a bare fetch() may appear, and why. */
  const ALLOWED: Record<string, string> = {
    "live/http-utils.ts": "the choke point itself: refusePrivateRequest runs first",
    "live/hn-fetcher.ts": "calls refusePrivateRequest on the same URL just before",
    "embeddings.ts": "the user's own embedding provider (opt-in), never a registry or OSV.dev",
  };

  it("every bare fetch() is in an allowed file, and the guarded ones call the guard", () => {
    const files: string[] = [];
    const walk = (dir: string) => {
      for (const name of fs.readdirSync(dir)) {
        const p = path.join(dir, name);
        if (fs.statSync(p).isDirectory()) {
          if (name !== "__tests__") walk(p);
        } else if (p.endsWith(".ts") && !p.endsWith(".d.ts") && name !== "test-setup.ts") files.push(p);
      }
    };
    walk(src);
    const offenders: string[] = [];
    for (const file of files) {
      const rel = path.relative(src, file).replaceAll("\\", "/");
      const code = fs.readFileSync(file, "utf8").replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/.*$/gm, "");
      // A call of the global: `fetch(` not preceded by `.`, a word character (fetchWithTimeout, net.fetch) or `async `-method names.
      if (/(?<![.\w])fetch\s*\(/.test(code) || /globalThis\.fetch\s*\(/.test(code)) {
        if (!ALLOWED[rel]) offenders.push(rel);
      }
    }
    expect(offenders).toEqual([]);
    for (const rel of ["live/http-utils.ts", "live/hn-fetcher.ts"]) {
      expect(fs.readFileSync(path.join(src, rel), "utf8")).toContain("refusePrivateRequest(");
    }
    // The upgrade_impact network seam defaults to the choke point.
    expect(fs.readFileSync(path.join(src, "live/package-archive.ts"), "utf8")).toMatch(/defaultFetch: FetchFn = \(url, init, timeoutMs\) => fetchWithTimeout\(/);
  });
});

describe("every fix-path lookup is guarded at the source", () => {
  it("PrivateAwareFixPathSources overrides every async lookup FixPathSources has", async () => {
    const { FixPathSources } = await import("../live/fix-paths.js");
    const { PrivateAwareFixPathSources } = await import("../live/private-fix-sources.js");
    const lookups = Object.getOwnPropertyNames(FixPathSources.prototype).filter((n) => n !== "constructor" && typeof (FixPathSources.prototype as unknown as Record<string, unknown>)[n] === "function");
    const guarded = new Set(Object.getOwnPropertyNames(PrivateAwareFixPathSources.prototype));
    // Private helpers of FixPathSources (no package name of their own) are listed here, with why.
    const internal = new Set(["npmDocument", "npmFacts", "pypiFacts", "goVersions"]);
    expect(lookups.filter((n) => !guarded.has(n) && !internal.has(n))).toEqual([]);
  });
});

describe("a live layer's registration survives garbage collection", () => {
  it("a project's live layer still refuses its private names after a gc, though nothing else holds it", async () => {
    const os = await import("node:os");
    const { LiveIntelligence } = await import("../live/index.js");
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "4da-guard-gc-"));
    fs.writeFileSync(path.join(dir, ".npmrc"), "@gcscope:registry=https://npm.gcscope.internal/\n");
    (() => {
      // Created and dropped: only the guard's registry can still reach it.
      new LiveIntelligence(null).initFromProject(dir, [], [], "javascript");
    })();
    (globalThis as { gc?: () => void }).gc?.();
    await new Promise((resolve) => setTimeout(resolve, 0));
    (globalThis as { gc?: () => void }).gc?.();
    await expect(fetchWithTimeout("https://registry.npmjs.org/@gcscope/x")).rejects.toBeInstanceOf(PrivateRequestRefused);
  });
});
