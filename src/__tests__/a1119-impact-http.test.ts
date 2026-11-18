// SPDX-License-Identifier: Apache-2.0
/**
 * The one place requests are made: where a redirect may lead, how much of an answer is read,
 * and which hosts a call is recorded as having contacted.
 *
 * Before: redirects were left to the runtime, which followed them anywhere (another host, plain
 * http, a loopback or link-local address, and for OSV's POST the whole dependency list replayed
 * to the new address), while `_meta.sources` named only the first host; and a response body was
 * buffered whole, whatever its size.
 */

import { afterEach, describe, expect, it, vi } from "vitest";

import { callHosts, runWithCallBudget } from "../call-budget.js";
import { capResponseBody, fetchWithTimeout, redirectTarget, RedirectRefused, responseCap, ResponseTooLarge } from "../live/http-utils.js";

afterEach(() => {
  vi.unstubAllGlobals();
});

type Step = { status: number; location?: string; body?: string };

/** A fetch that answers each URL from `steps` and records what it was asked. */
function scripted(steps: Record<string, Step>) {
  const calls: Array<{ url: string; init: RequestInit }> = [];
  vi.stubGlobal("fetch", async (url: string, init: RequestInit = {}) => {
    calls.push({ url, init });
    const step = steps[url];
    if (!step) throw new Error(`unexpected request to ${url}`);
    return new Response(step.status >= 300 && step.status < 400 ? null : (step.body ?? "{}"), { status: step.status, headers: step.location ? { location: step.location } : {} });
  });
  return calls;
}

describe("where a redirect may lead", () => {
  const from = "https://registry.npmjs.org/left-pad";

  it("the same host, over https", () => {
    expect(redirectTarget(from, "https://registry.npmjs.org/left-pad/", "GET")).toBe("https://registry.npmjs.org/left-pad/");
    expect(redirectTarget("https://pypi.org/pypi/Django/json", "/pypi/django/json", "GET")).toBe("https://pypi.org/pypi/django/json");
  });

  it("a host's own download host", () => {
    expect(redirectTarget("https://proxy.golang.org/m/@v/v1.zip", "https://storage.googleapis.com/proxy-golang-org-prod/x.zip", "GET")).toContain("storage.googleapis.com");
    expect(redirectTarget("https://crates.io/api/v1/crates/serde/1.0.0/download", "https://static.crates.io/crates/serde/serde-1.0.0.crate", "GET")).toContain("static.crates.io");
  });

  it("no other host, no plain http, no address inside the machine or network", () => {
    for (const to of ["https://mirror.example/left-pad", "http://registry.npmjs.org/left-pad", "http://127.0.0.1:8080/", "http://169.254.169.254/latest/meta-data/", "https://localhost/x", "https://static.crates.io/x", "file:///etc/hosts"]) {
      expect(() => redirectTarget(from, to, "GET"), to).toThrow(RedirectRefused);
    }
  });

  it("never for a request that carries a body", () => {
    expect(() => redirectTarget("https://api.osv.dev/v1/querybatch", "https://api.osv.dev/v2/querybatch", "POST")).toThrow(/POST request with a redirect, which is not followed/);
  });

  it("a redirect that names no address is refused", () => {
    expect(() => redirectTarget(from, null, "GET")).toThrow(RedirectRefused);
    expect(() => redirectTarget(from, "", "GET")).toThrow(RedirectRefused);
  });

  it("the refusal names hosts only, and an unreadable host not at all", () => {
    const refusal = (to: string) => {
      try {
        redirectTarget(from, to, "GET");
        return "";
      } catch (err) {
        return (err as Error).message;
      }
    };
    expect(refusal("https://mirror.example/a/secret/path?token=1")).toBe("registry.npmjs.org redirected to another host (mirror.example), which is not followed");
  });
});

describe("fetchWithTimeout follows redirects itself", () => {
  it("asks the runtime not to follow, and follows an allowed hop", async () => {
    const calls = scripted({
      "https://pypi.org/pypi/Django/json": { status: 301, location: "https://pypi.org/pypi/django/json" },
      "https://pypi.org/pypi/django/json": { status: 200, body: '{"ok":true}' },
    });
    const res = await fetchWithTimeout("https://pypi.org/pypi/Django/json");
    expect(await res.json()).toEqual({ ok: true });
    expect(calls.map((c) => c.url)).toEqual(["https://pypi.org/pypi/Django/json", "https://pypi.org/pypi/django/json"]);
    expect(calls.every((c) => c.init.redirect === "manual")).toBe(true);
  });

  it("does not request a refused target", async () => {
    const calls = scripted({ "https://registry.npmjs.org/left-pad": { status: 302, location: "http://169.254.169.254/latest/meta-data/" } });
    await expect(fetchWithTimeout("https://registry.npmjs.org/left-pad")).rejects.toThrow(RedirectRefused);
    expect(calls.map((c) => c.url)).toEqual(["https://registry.npmjs.org/left-pad"]);
  });

  it("does not replay a POST body to the address a redirect names", async () => {
    const calls = scripted({ "https://api.osv.dev/v1/querybatch": { status: 307, location: "https://api.osv.dev/elsewhere" } });
    await expect(fetchWithTimeout("https://api.osv.dev/v1/querybatch", { method: "POST", body: '{"queries":[]}' })).rejects.toThrow(RedirectRefused);
    expect(calls).toHaveLength(1);
  });

  it("gives up on a redirect loop", async () => {
    const calls = scripted({ "https://crates.io/a": { status: 302, location: "https://crates.io/b" }, "https://crates.io/b": { status: 302, location: "https://crates.io/a" } });
    await expect(fetchWithTimeout("https://crates.io/a")).rejects.toThrow(/redirected more than 5 times/);
    expect(calls.length).toBe(6);
  });

  it("keeps credentials with the host they were given for", async () => {
    const calls = scripted({
      "https://api.github.com/repos/o/r/contents/CHANGELOG.md": { status: 302, location: "https://raw.githubusercontent.com/o/r/main/CHANGELOG.md" },
      "https://raw.githubusercontent.com/o/r/main/CHANGELOG.md": { status: 200, body: "# x" },
    });
    await fetchWithTimeout("https://api.github.com/repos/o/r/contents/CHANGELOG.md", { headers: { Authorization: "Bearer t0ken", Accept: "application/json" } });
    const first = new Headers(calls[0].init.headers as Record<string, string>);
    const second = new Headers(calls[1].init.headers as Record<string, string>);
    expect(first.get("authorization")).toBe("Bearer t0ken");
    expect(second.get("authorization")).toBeNull();
    expect(second.get("accept")).toBe("application/json");
  });

  it("records every host a call contacted, redirects included", async () => {
    scripted({
      "https://proxy.golang.org/m/@v/v1.0.0.zip": { status: 302, location: "https://storage.googleapis.com/proxy-golang-org-prod/m.zip" },
      "https://storage.googleapis.com/proxy-golang-org-prod/m.zip": { status: 200, body: "zip" },
      "https://api.osv.dev/v1/query": { status: 200 },
    });
    const hosts = await runWithCallBudget(Date.now(), async () => {
      expect(callHosts()).toEqual([]);
      await fetchWithTimeout("https://proxy.golang.org/m/@v/v1.0.0.zip");
      await fetchWithTimeout("https://api.osv.dev/v1/query", { method: "POST", body: "{}" });
      return callHosts();
    });
    expect(hosts).toEqual(["api.osv.dev", "proxy.golang.org", "storage.googleapis.com"]);
    expect(callHosts()).toEqual([]);
  });
});

describe("how much of an answer is read", () => {
  it("every host has a limit, and an unknown one the default", () => {
    expect(responseCap("https://api.osv.dev/v1/vulns/X")).toBeLessThan(responseCap("https://registry.npmjs.org/vite"));
    expect(responseCap("https://unknown.example/x")).toBe(32 * 1024 * 1024);
    expect(responseCap("not a url")).toBe(32 * 1024 * 1024);
  });

  it("an answer that declares more than the limit is refused unread", () => {
    const res = new Response("small", { headers: { "content-length": "999999" } });
    expect(() => capResponseBody(res, 1000, "api.osv.dev")).toThrow(ResponseTooLarge);
    expect(() => capResponseBody(new Response("small", { headers: { "content-length": "999999" } }), 1000, "api.osv.dev")).toThrow("the answer from api.osv.dev is larger than 0 MB and was not read");
  });

  it("an answer that runs past the limit fails the read instead of being buffered", async () => {
    const big = new Response("x".repeat(5000));
    await expect(capResponseBody(big, 1000, "pypi.org").text()).rejects.toThrow(ResponseTooLarge);
    const chunks = new ReadableStream<Uint8Array>({
      start(controller) {
        for (let i = 0; i < 10; i++) controller.enqueue(new Uint8Array(400));
        controller.close();
      },
    });
    await expect(capResponseBody(new Response(chunks), 1000, "pypi.org").arrayBuffer()).rejects.toThrow(ResponseTooLarge);
  });

  it("an answer within the limit is read unchanged, with its status and headers", async () => {
    const res = capResponseBody(new Response('{"a":1}', { status: 203, headers: { "x-test": "kept" } }), 1000, "pypi.org");
    expect(res.status).toBe(203);
    expect(res.headers.get("x-test")).toBe("kept");
    expect(await res.json()).toEqual({ a: 1 });
  });

  it("a stand-in without a body stream is passed through", () => {
    const standIn = { ok: true, status: 200, json: async () => ({}) } as unknown as Response;
    expect(capResponseBody(standIn, 10, "pypi.org")).toBe(standIn);
  });

  it("applies to what fetchWithTimeout returns", async () => {
    vi.stubGlobal("fetch", async () => new Response("y".repeat(64), { headers: { "content-length": String(200 * 1024 * 1024) } }));
    await expect(fetchWithTimeout("https://api.osv.dev/v1/vulns/GHSA-xxxx")).rejects.toThrow(ResponseTooLarge);
  });
});
