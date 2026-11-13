// SPDX-License-Identifier: Apache-2.0
/**
 * The HTTP choke point for private package names (live/private-guard.ts): every OSV.dev,
 * registry and search request goes through fetchWithTimeout, which refuses one that names a
 * private package. And nothing in src/ reaches the network around it.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
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
  // Registered before each test: the suite forgets every source after each one (test-setup.ts).
  beforeEach(() => privateNames({ npm: ["@guard/secret"], "crates.io": ["guard-core"], PyPI: ["guard-auth"], Go: ["github.com/GuardCorp/ledger"] }));

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

describe("which project's rules judge a request (CI run 43253624606)", () => {
  const project = async (npmrc: string | null) => {
    const os = await import("node:os");
    const { LiveIntelligence } = await import("../live/index.js");
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "4da-guard-ctx-"));
    if (npmrc) fs.writeFileSync(path.join(dir, ".npmrc"), npmrc);
    const live = new LiveIntelligence(null);
    live.initFromProject(dir, [], [], "javascript");
    return { live, dir };
  };
  const stubFetch = () => {
    const spy = vi.fn(async () => new Response("{}"));
    vi.stubGlobal("fetch", spy);
    return spy;
  };

  it("a request made for a project is judged by that project's rules, not another project's", async () => {
    const a = await project("@scopea:registry=https://npm.a.internal/\n");
    const b = await project(null);
    const { registerPrivateNames: register } = await import("../live/private-guard.js");
    register(a.live, "test:a");
    stubFetch();
    // For project B, @scopea is a public scope: sent.
    await expect(b.live.runInContext(() => fetchWithTimeout("https://registry.npmjs.org/@scopea/x"))).resolves.toBeInstanceOf(Response);
    // For project A, refused.
    await expect(a.live.runInContext(() => fetchWithTimeout("https://registry.npmjs.org/@scopea/x"))).rejects.toBeInstanceOf(PrivateRequestRefused);
    // With no project context, the union of registered projects: refused.
    await expect(fetchWithTimeout("https://registry.npmjs.org/@scopea/x")).rejects.toBeInstanceOf(PrivateRequestRefused);
  });

  it("a request made for a layer is refused even when the registry has forgotten the layer and the collector ran", async () => {
    const a = await project("@gcscope:registry=https://npm.gcscope.internal/\n");
    const { resetPrivateGuard } = await import("../live/private-guard.js");
    resetPrivateGuard();
    (globalThis as { gc?: () => void }).gc?.();
    stubFetch();
    await expect(a.live.runInContext(() => fetchWithTimeout("https://registry.npmjs.org/@gcscope/x"))).rejects.toBeInstanceOf(PrivateRequestRefused);
  });

  it("an entry goes when its layer is disposed, or when its project root no longer exists", async () => {
    const { registerPrivateNames: register, privateGuardSize, resetPrivateGuard } = await import("../live/private-guard.js");
    resetPrivateGuard();
    const a = await project("@disp:registry=https://npm.disp.internal/\n");
    register(a.live, "test:disp");
    a.live.dispose();
    expect(privateGuardSize()).toBe(0);
    stubFetch();
    await expect(fetchWithTimeout("https://registry.npmjs.org/@disp/x")).resolves.toBeInstanceOf(Response);

    resetPrivateGuard();
    const gone = await project("@gone:registry=https://npm.gone.internal/\n");
    register(gone.live, "test:gone", gone.dir);
    await expect(fetchWithTimeout("https://registry.npmjs.org/@gone/x")).rejects.toBeInstanceOf(PrivateRequestRefused);
    fs.rmSync(gone.dir, { recursive: true, force: true });
    await expect(fetchWithTimeout("https://registry.npmjs.org/@gone/x")).resolves.toBeInstanceOf(Response);
    expect(privateGuardSize()).toBe(0);
  });

  it("the server's live layer is held strongly while it is current, and replaced cleanly", async () => {
    const { privateGuardSize, resetPrivateGuard } = await import("../live/private-guard.js");
    const { clearLiveIntelligence, setLiveIntelligence } = await import("../live-singleton.js");
    resetPrivateGuard();
    const a = await project("@srv:registry=https://npm.srv.internal/\n");
    const b = await project(null);
    resetPrivateGuard();
    setLiveIntelligence(a.live);
    stubFetch();
    await expect(fetchWithTimeout("https://registry.npmjs.org/@srv/x")).rejects.toBeInstanceOf(PrivateRequestRefused);
    setLiveIntelligence(b.live);
    expect(privateGuardSize()).toBe(1);
    await expect(fetchWithTimeout("https://registry.npmjs.org/@srv/x")).resolves.toBeInstanceOf(Response);
    clearLiveIntelligence();
    expect(privateGuardSize()).toBe(0);
  });
});

describe("rewriting a rules file with the same rules changes nothing (CI run 43253624606)", () => {
  it("the stored scan and dependency set stand when the user .npmrc is rewritten unchanged", async () => {
    const os = await import("node:os");
    const { LiveIntelligence } = await import("../live/index.js");
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "4da-rules-touch-"));
    const npmrc = path.join(dir, "user-npmrc");
    fs.writeFileSync(npmrc, "");
    const prior = process.env.NPM_CONFIG_USERCONFIG;
    process.env.NPM_CONFIG_USERCONFIG = npmrc;
    try {
      const live = new LiveIntelligence(null);
      live.initFromProject(dir, [], [], "javascript");
      const scan = { scannedAt: new Date().toISOString(), offline: false } as unknown;
      (live as unknown as { lastVulnScan: unknown }).lastVulnScan = scan;
      // Another process rewrites the file with the same (empty) content, a moment later.
      const later = new Date(Date.now() + 5_000);
      fs.writeFileSync(npmrc, "");
      fs.utimesSync(npmrc, later, later);
      expect(live.refreshPrivateRules()).toBe(false);
      expect((live as unknown as { lastVulnScan: unknown }).lastVulnScan).toBe(scan);
      // A real change still counts.
      fs.writeFileSync(npmrc, "@touched:registry=https://npm.touched.internal/\n");
      expect(live.refreshPrivateRules()).toBe(true);
      expect(live.privateReason("npm", "@touched/x")).not.toBeNull();
    } finally {
      if (prior === undefined) delete process.env.NPM_CONFIG_USERCONFIG;
      else process.env.NPM_CONFIG_USERCONFIG = prior;
    }
  });
});
