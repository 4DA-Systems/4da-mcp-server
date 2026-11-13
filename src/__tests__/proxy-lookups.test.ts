// SPDX-License-Identifier: Apache-2.0
/**
 * HTTPS_PROXY / HTTP_PROXY / NO_PROXY (black-box re-run of 96c16d2, 2026-11-14): the server
 * ignored them, even with NODE_USE_ENV_PROXY=1. Every lookup now goes through the shared layer's
 * EnvHttpProxyAgent (live/http-utils.ts). A local recording proxy shows the requests arrive through
 * it, NO_PROXY reaches the host directly, and a proxy on a closed port makes the lookup fail
 * (NOT CHECKED), never a direct connection.
 */
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import * as http from "node:http";
import * as net from "node:net";
import type { AddressInfo } from "node:net";
import { fetchWithTimeout } from "../live/http-utils.js";
import { configureProxy } from "../proxy.js";
import { executeDependencyCheck } from "../tools/dependency-check.js";
import { LiveIntelligence } from "../live/index.js";

let upstream: http.Server;
let upstreamPort: number;
let upstreamHits: string[];
let proxy: http.Server;
let proxyPort: number;
let proxied: string[];
const saved: Record<string, string | undefined> = {};
const KEYS = ["HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy", "FOURDA_OFFLINE"];

const listen = (server: http.Server) => new Promise<number>((resolve) => server.listen(0, "127.0.0.1", () => resolve((server.address() as AddressInfo).port)));

/** A port nothing listens on: bound, then closed. */
async function closedPort(): Promise<number> {
  const s = net.createServer();
  await new Promise<void>((resolve) => s.listen(0, "127.0.0.1", resolve));
  const port = (s.address() as AddressInfo).port;
  await new Promise<void>((resolve) => s.close(() => resolve()));
  return port;
}

beforeAll(async () => {
  upstream = http.createServer((req, res) => {
    upstreamHits.push(req.url ?? "");
    res.setHeader("content-type", "application/json");
    res.end(JSON.stringify({ ok: true }));
  });
  upstreamPort = await listen(upstream);
  // A forward proxy: tunnels CONNECT, forwards absolute-URL requests; records every target.
  proxy = http.createServer((req, res) => {
    proxied.push(req.url ?? "");
    const target = new URL(req.url ?? "");
    const out = http.request({ host: target.hostname, port: target.port, path: target.pathname + target.search, method: req.method, headers: req.headers }, (r) => {
      res.writeHead(r.statusCode ?? 502, r.headers);
      r.pipe(res);
    });
    req.pipe(out);
  });
  proxy.on("connect", (req, socket, head) => {
    proxied.push(`CONNECT ${req.url}`);
    const [host, port] = (req.url ?? "").split(":");
    const upstreamSocket = net.connect(Number(port), host, () => {
      socket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      upstreamSocket.write(head);
      upstreamSocket.pipe(socket);
      socket.pipe(upstreamSocket);
    });
    upstreamSocket.on("error", () => socket.destroy());
  });
  proxyPort = await listen(proxy);
});

afterAll(async () => {
  await new Promise((r) => upstream.close(r));
  await new Promise((r) => proxy.close(r));
});

// Each test sets its own proxy variables (env below); they are restored after it.
afterEach(() => {
  for (const k of KEYS) {
    if (saved[k] === undefined) delete process.env[k];
    else process.env[k] = saved[k];
  }
});

function env(vars: Record<string, string>) {
  upstreamHits = [];
  proxied = [];
  for (const k of KEYS) saved[k] = process.env[k];
  for (const k of KEYS) delete process.env[k];
  Object.assign(process.env, vars);
}

describe("lookups through HTTP_PROXY / HTTPS_PROXY", () => {
  it("a lookup goes through the proxy the environment names", async () => {
    env({ HTTP_PROXY: `http://127.0.0.1:${proxyPort}` });
    const res = await fetchWithTimeout(`http://127.0.0.1:${upstreamPort}/v1/ping`, {}, 5_000);
    expect(await res.json()).toEqual({ ok: true });
    expect(proxied.length).toBe(1);
    expect(proxied[0]).toContain(`127.0.0.1:${upstreamPort}`);
  });

  it("NO_PROXY: that host is reached directly", async () => {
    env({ HTTP_PROXY: `http://127.0.0.1:${proxyPort}`, NO_PROXY: "127.0.0.1" });
    const res = await fetchWithTimeout(`http://127.0.0.1:${upstreamPort}/direct`, {}, 5_000);
    expect(res.ok).toBe(true);
    expect(proxied).toEqual([]);
    expect(upstreamHits).toEqual(["/direct"]);
  });

  it("a proxy that cannot be reached fails the lookup, and nothing goes direct", async () => {
    env({ HTTP_PROXY: `http://127.0.0.1:${await closedPort()}` });
    await expect(fetchWithTimeout(`http://127.0.0.1:${upstreamPort}/must-not-arrive`, {}, 5_000)).rejects.toBeTruthy();
    expect(upstreamHits).toEqual([]);
  });

  it("dependency_check behind an unreachable proxy says unknown, never proceed", async () => {
    env({ HTTPS_PROXY: `http://127.0.0.1:${await closedPort()}`, HTTP_PROXY: `http://127.0.0.1:${await closedPort()}` });
    const live = new LiveIntelligence(null);
    const result = await executeDependencyCheck(null, { items: [{ ecosystem: "npm", package: "left-pad-proxy-test-name", to: "1.3.0" }] }, live);
    expect(result.results[0].verdict).toBe("unknown");
  }, 60_000);

  it("the startup line says what happens", () => {
    expect(configureProxy({})).toEqual({ state: "none", note: null });
    expect(configureProxy({ HTTPS_PROXY: "http://proxy.corp:8080", NO_PROXY: "localhost" })).toEqual({
      state: "lookups",
      note: "Proxy: every lookup goes through the proxy from HTTPS_PROXY (NO_PROXY honoured); one that cannot be reached makes the answer NOT CHECKED, never a direct connection.",
    });
    expect(configureProxy({ https_proxy: "not a url" }).state).toBe("invalid");
  });
});
