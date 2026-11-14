// SPDX-License-Identifier: Apache-2.0
/**
 * `--doctor`'s network check: can this process reach OSV.dev and each registry, through the proxy
 * the environment names?
 *
 * Blind audit of e3aba98: with HTTPS_PROXY=http://127.0.0.1:9 (nothing listening) the doctor said
 * "All clear", because it only checked that the proxy variable parsed as a URL; every lookup the
 * server then made failed. Each endpoint is now asked once, through the same request layer the
 * tools use (live/http-utils.ts: proxy, NO_PROXY), and one that does not answer is a failure.
 * Any HTTP answer counts as reachable: the question is the path, not the endpoint's status.
 */

import { fetchWithTimeout } from "./live/http-utils.js";
import { isOfflineMode } from "./env-flags.js";

export interface Endpoint {
  name: string;
  url: string;
}

/** The hosts the tools send lookups to (live/), one cheap URL each. */
export const LOOKUP_ENDPOINTS: Endpoint[] = [
  { name: "OSV.dev", url: "https://api.osv.dev/v1/vulns/GHSA-0000-0000-0000" },
  { name: "npm registry", url: "https://registry.npmjs.org/-/ping" },
  { name: "PyPI", url: "https://pypi.org/simple/" },
  { name: "crates.io", url: "https://index.crates.io/config.json" },
  { name: "Go module proxy", url: "https://proxy.golang.org/" },
];

export interface ReachabilityCheck {
  name: string;
  status: "pass" | "warn" | "fail";
  detail: string;
}

type Fetcher = (url: string, init: RequestInit, timeoutMs: number) => Promise<Response>;

/** One check per endpoint, asked in parallel; offline mode asks nothing and says so. */
export async function checkLookupReachability(
  options: { endpoints?: Endpoint[]; timeoutMs?: number; fetcher?: Fetcher; env?: NodeJS.ProcessEnv } = {},
): Promise<ReachabilityCheck[]> {
  const env = options.env ?? process.env;
  const endpoints = options.endpoints ?? LOOKUP_ENDPOINTS;
  if (isOfflineMode(env)) {
    return [{ name: "Lookups (OSV.dev, registries)", status: "warn", detail: "FOURDA_OFFLINE is set: no lookup is made, so vulnerability answers come from the local cache only" }];
  }
  const fetcher = options.fetcher ?? fetchWithTimeout;
  const timeoutMs = options.timeoutMs ?? 8000;
  const proxied = ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"].some((k) => (env[k] ?? "").trim() !== "");
  const via = proxied ? " through the configured proxy" : "";
  return Promise.all(
    endpoints.map(async (endpoint): Promise<ReachabilityCheck> => {
      const started = Date.now();
      try {
        const response = await fetcher(endpoint.url, { method: "GET", headers: { Accept: "*/*" } }, timeoutMs);
        await response.body?.cancel().catch(() => undefined);
        return { name: `Reach ${endpoint.name}`, status: "pass", detail: `answered HTTP ${response.status}${via} in ${Date.now() - started} ms` };
      } catch (error) {
        const reason = describe(error);
        return {
          name: `Reach ${endpoint.name}`,
          status: "fail",
          detail: `not reachable${via} (${reason}): its lookups will answer NOT CHECKED${proxied ? "; check HTTPS_PROXY / HTTP_PROXY and NO_PROXY" : ""}`,
        };
      }
    }),
  );
}

function describe(error: unknown): string {
  if (!(error instanceof Error)) return String(error).slice(0, 120);
  const cause = (error as { cause?: unknown }).cause;
  const code = cause && typeof cause === "object" && "code" in cause ? String((cause as { code: unknown }).code) : "";
  const message = error.name === "AbortError" ? "timed out" : error.message;
  return `${message}${code ? `, ${code}` : ""}`.slice(0, 160);
}
