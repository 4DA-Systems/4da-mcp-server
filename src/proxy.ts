// SPDX-License-Identifier: Apache-2.0
/**
 * HTTPS_PROXY / HTTP_PROXY / NO_PROXY: what the startup log and --doctor say about them.
 *
 * Every OSV.dev, registry and search lookup goes through the shared layer (live/http-utils.ts),
 * which sends it through undici's EnvHttpProxyAgent whenever a proxy variable is set, on every
 * supported Node, with NO_PROXY honoured. (Until 6.3.0 the server relied on Node's own proxy
 * support, which needs Node 24.14, or 22.21 with NODE_USE_ENV_PROXY=1, and in practice the lookups
 * went direct: black-box re-run of 96c16d2.) A proxy that cannot be reached fails the lookup, which
 * the answer reports as NOT CHECKED: nothing is retried direct.
 *
 * The one exception is an embedding provider you configure (embeddings.ts), which uses Node's own
 * fetch and so Node's own proxy support.
 */

const PROXY_VARIABLES = ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"];

export interface ProxySetup {
  /** `none`: no proxy variable is set. `lookups`: every lookup goes through it. `invalid`: set, but not a URL. */
  state: "none" | "lookups" | "invalid";
  /** One line for the startup log; null when there is nothing to say. */
  note: string | null;
}

/** What this process does with the proxy the environment names. */
export function configureProxy(env: NodeJS.ProcessEnv = process.env): ProxySetup {
  const named = PROXY_VARIABLES.filter((name) => (env[name] ?? "").trim() !== "");
  if (named.length === 0) return { state: "none", note: null };
  const which = [...new Set(named.map((n) => n.toUpperCase()))].join(" / ");
  const bad = named.find((n) => {
    try {
      new URL(env[n]!.trim());
      return false;
    } catch {
      return true;
    }
  });
  if (bad) {
    return { state: "invalid", note: `Proxy: ${bad.toUpperCase()} is not a URL, so every lookup fails (NOT CHECKED); nothing goes direct. Set it to http://host:port.` };
  }
  return {
    state: "lookups",
    note: `Proxy: every lookup goes through the proxy from ${which} (NO_PROXY honoured); one that cannot be reached makes the answer NOT CHECKED, never a direct connection.`,
  };
}
