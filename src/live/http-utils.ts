// SPDX-License-Identifier: Apache-2.0

import { EnvHttpProxyAgent, fetch as undiciFetch } from "undici";

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

export async function fetchWithTimeout(
  url: string,
  options: RequestInit = {},
  timeoutMs: number = DEFAULT_TIMEOUT_MS,
): Promise<Response> {
  // The choke point: a request that names a private package is never made (private-guard.ts).
  refusePrivateRequest(url, options);
  // A server that is shutting down makes no new request, and one in flight is aborted
  // (shutdown.ts): the host closed stdin, so no answer can reach anyone.
  if (shutdownSignal.aborted) throw new Error("not requested: the server is shutting down");
  const controller = new AbortController();
  const stop = () => controller.abort(shutdownSignal.reason);
  shutdownSignal.addEventListener("abort", stop, { once: true });
  let timeout = setTimeout(() => controller.abort(), timeoutMs);
  timeout.unref?.();
  try {
    const dispatcher = proxyDispatcher();
    const response = dispatcher
      ? ((await undiciFetch(url, { ...(options as Record<string, unknown>), signal: controller.signal, dispatcher } as Parameters<typeof undiciFetch>[1])) as unknown as Response)
      : await fetch(url, { ...options, signal: controller.signal });
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
    return response;
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
