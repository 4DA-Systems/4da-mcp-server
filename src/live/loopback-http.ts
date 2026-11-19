// SPDX-License-Identifier: Apache-2.0
/**
 * Requests to a service on this machine (a local Ollama): the one place besides http-utils.ts
 * where fetch is called.
 *
 * A loopback address is this machine, so what is sent there does not leave it. It is never sent
 * through a proxy: a proxy asked for `http://localhost:11434` looks for it on the proxy's own host,
 * and the request body has left the machine to get there. A redirect is an error for the same
 * reason: the body would follow it to another host. Every other address goes through
 * fetchWithTimeout (http-utils.ts), which applies the private-name check and the proxy.
 */

import { shutdownSignal } from "../shutdown.js";

/** Whether `url` names this machine: `localhost`, 127.0.0.0/8 or `::1`, over http or https. */
export function isLoopbackUrl(url: string): boolean {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return false;
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return false;
  const host = parsed.hostname.toLowerCase();
  return host === "localhost" || host === "[::1]" || /^127(?:\.\d{1,3}){3}$/.test(host);
}

const DEFAULT_TIMEOUT_MS = 10_000;

/**
 * The JSON a loopback service answers with, or null when its status is not 2xx. Throws for an
 * address that is not loopback (before any request), when the server is shutting down, on a
 * redirect, and when `timeoutMs` passes or `init.signal` aborts before the body is read.
 */
export async function fetchLoopbackJson(url: string, init: RequestInit = {}, timeoutMs: number = DEFAULT_TIMEOUT_MS): Promise<unknown> {
  if (!isLoopbackUrl(url)) throw new Error("not requested: only a loopback address is asked directly");
  if (shutdownSignal.aborted) throw new Error("not requested: the server is shutting down");
  const caller = init.signal ?? null;
  if (caller?.aborted) throw new Error("not requested: the call was cancelled");
  const controller = new AbortController();
  const stop = () => controller.abort();
  shutdownSignal.addEventListener("abort", stop, { once: true });
  caller?.addEventListener("abort", stop, { once: true });
  const timeout = setTimeout(stop, timeoutMs);
  timeout.unref?.();
  try {
    const response = await fetch(url, { ...init, signal: controller.signal, redirect: "error" });
    return response.ok ? await response.json() : null;
  } finally {
    clearTimeout(timeout);
    shutdownSignal.removeEventListener("abort", stop);
    caller?.removeEventListener("abort", stop);
  }
}
