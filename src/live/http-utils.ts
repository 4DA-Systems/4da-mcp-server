// SPDX-License-Identifier: Apache-2.0

import { EnvHttpProxyAgent, fetch as undiciFetch } from "undici";

import { noteCallHost } from "../call-budget.js";
import { refusePrivateRequest } from "./private-guard.js";
import { shutdownSignal } from "../shutdown.js";

/**
 * HTTPS_PROXY / HTTP_PROXY / NO_PROXY (black-box re-run of 96c16d2: the server ignored them, even
 * with NODE_USE_ENV_PROXY=1, so a corporate user got nothing or went around the proxy). When one
 * of the proxy variables is set, every lookup goes through undici's EnvHttpProxyAgent, which reads
 * them (lower and upper case) and honours NO_PROXY. A proxy that cannot be reached fails the
 * request like any unreachable host: the answer says NOT CHECKED, and nothing is retried direct.
 */
const PROXY_VARIABLES = ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "NO_PROXY", "no_proxy"];
let proxyAgent: { key: string; agent: EnvHttpProxyAgent } | null = null;

/** The dispatcher for the proxy the environment names now, or null when it names none. */
export function proxyDispatcher(env: NodeJS.ProcessEnv = process.env): EnvHttpProxyAgent | null {
  const set = ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"].some((k) => (env[k] ?? "").trim() !== "");
  if (!set) return null;
  const key = PROXY_VARIABLES.map((k) => `${k}=${env[k] ?? ""}`).join("\n");
  if (proxyAgent?.key !== key) {
    void proxyAgent?.agent.close().catch(() => undefined);
    proxyAgent = { key, agent: new EnvHttpProxyAgent() };
  }
  return proxyAgent.agent;
}

const DEFAULT_TIMEOUT_MS = 10_000;

// ---------------------------------------------------------------------------------------------
// Redirects
// ---------------------------------------------------------------------------------------------

/** Redirects followed for one request before it is given up. */
const MAX_REDIRECTS = 5;

/**
 * Where a host's redirect may lead besides itself: the storage or download host its own operator
 * serves from. Anything else is refused. The servers asked here are a fixed, public set, and
 * none of them has reason to send a lookup anywhere else, so a redirect to another host is
 * either a fault or an attempt to have this machine fetch something for someone else.
 */
const REDIRECT_FAMILY: Readonly<Record<string, readonly string[]>> = {
  "crates.io": ["static.crates.io", "index.crates.io"],
  "pypi.org": ["files.pythonhosted.org"],
  "proxy.golang.org": ["storage.googleapis.com"],
  "api.github.com": ["raw.githubusercontent.com", "codeload.github.com", "objects.githubusercontent.com"],
  "github.com": ["raw.githubusercontent.com", "codeload.github.com", "objects.githubusercontent.com"],
};

/** Raised when a redirect is not followed; the message is fit for tool output and names only hosts. */
export class RedirectRefused extends Error {}

/**
 * The URL a redirect from `from` may be followed to, or a RedirectRefused. Followed only when
 * the request is a body-less GET or HEAD (a POST's body is never replayed to another address),
 * the target is https, and its host is the same host or one of that host's own download hosts.
 */
export function redirectTarget(from: string, location: string | null, method: string): string {
  const origin = new URL(from);
  if (method !== "GET" && method !== "HEAD") {
    throw new RedirectRefused(`${origin.host} answered a ${method} request with a redirect, which is not followed`);
  }
  let target: URL;
  try {
    target = new URL(location ?? "", origin);
  } catch {
    throw new RedirectRefused(`${origin.host} answered with a redirect that names no address`);
  }
  if (!location) throw new RedirectRefused(`${origin.host} answered with a redirect that names no address`);
  if (target.protocol !== "https:") {
    throw new RedirectRefused(`${origin.host} redirected to an address that is not https, which is not followed`);
  }
  if (target.host !== origin.host && !(REDIRECT_FAMILY[origin.host] ?? []).includes(target.host)) {
    throw new RedirectRefused(`${origin.host} redirected to another host (${hostText(target.host)}), which is not followed`);
  }
  return target.toString();
}

/** A host name as it may be shown: plain host characters only, capped. */
function hostText(host: string): string {
  return /^[A-Za-z0-9.:[\]-]{1,100}$/.test(host) ? host : "an unreadable host name";
}

/** Headers for the next hop: credentials stay with the host they were given for. */
function headersForHop(headers: RequestInit["headers"], sameHost: boolean): RequestInit["headers"] {
  if (sameHost || !headers) return headers;
  const kept = new Headers(headers as ConstructorParameters<typeof Headers>[0]);
  kept.delete("authorization");
  kept.delete("cookie");
  kept.delete("proxy-authorization");
  return kept;
}

// ---------------------------------------------------------------------------------------------
// Response size
// ---------------------------------------------------------------------------------------------

const MB = 1024 * 1024;
/**
 * The most a response body may hold, by host. A body is read into memory whole (JSON, text or an
 * archive that has its own, smaller cap), so without a limit one oversized answer cost gigabytes
 * of memory, tens of seconds of a blocked event loop and a cache row of the same size. Each
 * limit sits above the largest real answer measured for that host: npm documents of packages
 * with thousands of releases run up to 75 MB (cap 128 MB), and a first page of 100 GitHub
 * releases up to 13.3 MB (electron/electron; cap 64 MB).
 */
const RESPONSE_CAPS: Readonly<Record<string, number>> = {
  "registry.npmjs.org": 128 * MB,
  "api.npmjs.org": 4 * MB,
  "api.osv.dev": 32 * MB,
  "pypi.org": 64 * MB,
  "files.pythonhosted.org": 24 * MB,
  "crates.io": 32 * MB,
  "index.crates.io": 32 * MB,
  "static.crates.io": 24 * MB,
  "proxy.golang.org": 32 * MB,
  "storage.googleapis.com": 32 * MB,
  "hn.algolia.com": 4 * MB,
  "api.github.com": 64 * MB,
  "raw.githubusercontent.com": 64 * MB,
};
const DEFAULT_RESPONSE_CAP = 32 * MB;

/** The body limit for a URL's host. */
export function responseCap(url: string): number {
  try {
    return RESPONSE_CAPS[new URL(url).host] ?? DEFAULT_RESPONSE_CAP;
  } catch {
    return DEFAULT_RESPONSE_CAP;
  }
}

/** Raised when a response body runs past its limit; the message is fit for tool output. */
export class ResponseTooLarge extends Error {}

/**
 * The same response with its body held to `cap` bytes: a declared length over the cap is refused
 * before anything is read, and a body that runs past it fails the read (json(), text(),
 * arrayBuffer() or a reader) instead of being buffered to the end.
 */
export function capResponseBody(response: Response, cap: number, host: string): Response {
  const tooLarge = () => new ResponseTooLarge(`the answer from ${hostText(host)} is larger than ${Math.round(cap / MB)} MB and was not read`);
  // Anything that is not a streamed response (an injected stand-in with only json() or text())
  // has no body to hold to a limit and is returned as it is.
  if (typeof response.headers?.get !== "function") return response;
  const declared = Number(response.headers.get("content-length"));
  if (Number.isFinite(declared) && declared > cap) {
    void response.body?.cancel().catch(() => undefined);
    throw tooLarge();
  }
  if (!response.body || typeof response.body.pipeThrough !== "function") return response;
  let seen = 0;
  const limiter = new TransformStream<Uint8Array, Uint8Array>({
    transform(chunk, controller) {
      seen += chunk.byteLength;
      if (seen > cap) controller.error(tooLarge());
      else controller.enqueue(chunk);
    },
  });
  const capped = new Response(response.body.pipeThrough(limiter), { status: response.status, statusText: response.statusText, headers: response.headers });
  // `url` and `redirected` are read-only on a constructed Response; callers here use neither.
  return capped;
}

// ---------------------------------------------------------------------------------------------
// The request
// ---------------------------------------------------------------------------------------------

const REDIRECT_STATUS = new Set([301, 302, 303, 307, 308]);

export async function fetchWithTimeout(
  url: string,
  options: RequestInit = {},
  timeoutMs: number = DEFAULT_TIMEOUT_MS,
): Promise<Response> {
  // A server that is shutting down makes no new request, and one in flight is aborted
  // (shutdown.ts): the host closed stdin, so no answer can reach anyone.
  if (shutdownSignal.aborted) throw new Error("not requested: the server is shutting down");
  const controller = new AbortController();
  const stop = () => controller.abort(shutdownSignal.reason);
  shutdownSignal.addEventListener("abort", stop, { once: true });
  let timeout = setTimeout(() => controller.abort(), timeoutMs);
  timeout.unref?.();
  try {
    const method = (options.method ?? "GET").toUpperCase();
    let current = url;
    let headers = options.headers;
    let response: Response;
    for (let hop = 0; ; hop++) {
      // The choke point: a request that names a private package is never made (private-guard.ts).
      // Every hop passes it, so a redirect cannot lead around it.
      refusePrivateRequest(current, options);
      noteCallHost(new URL(current).host);
      const init = { ...options, headers, redirect: "manual" as const, signal: controller.signal };
      const dispatcher = proxyDispatcher();
      response = dispatcher
        ? ((await undiciFetch(current, { ...(init as Record<string, unknown>), dispatcher } as Parameters<typeof undiciFetch>[1])) as unknown as Response)
        : await fetch(current, init);
      if (!REDIRECT_STATUS.has(response.status)) break;
      // Redirects are followed here, one hop at a time, so each can be held to the rule above;
      // left to the runtime they went anywhere, plain http and loopback addresses included.
      void response.body?.cancel().catch(() => undefined);
      if (hop >= MAX_REDIRECTS) throw new RedirectRefused(`${hostText(new URL(url).host)} redirected more than ${MAX_REDIRECTS} times`);
      const next = redirectTarget(current, response.headers.get("location"), method);
      headers = headersForHop(headers, new URL(next).host === new URL(current).host);
      current = next;
    }
    // The headers are in; the body is not read yet. Clearing the abort here left json(), text()
    // and arrayBuffer() with no deadline: a server that stalled mid-body hung vulnerability_scan
    // and dependency_check, and every later scan that joined the stuck one (audit 6.2.5 B-6).
    // The abort stays armed for the body, with its own allowance; unref'd, it never holds the
    // process open, and aborting a body already read does nothing.
    clearTimeout(timeout);
    timeout = setTimeout(() => {
      controller.abort();
      shutdownSignal.removeEventListener("abort", stop);
    }, timeoutMs);
    timeout.unref?.();
    return capResponseBody(response, responseCap(current), new URL(current).host);
  } catch (error) {
    clearTimeout(timeout);
    shutdownSignal.removeEventListener("abort", stop);
    throw error;
  }
}

export async function fetchJson<T>(
  url: string,
  options: RequestInit = {},
  timeoutMs: number = DEFAULT_TIMEOUT_MS,
): Promise<T> {
  const response = await fetchWithTimeout(url, options, timeoutMs);
  if (!response.ok) {
    throw new Error(`HTTP ${response.status}: ${url}`);
  }
  return (await response.json()) as T;
}
