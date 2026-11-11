// SPDX-License-Identifier: Apache-2.0
/**
 * HTTPS_PROXY / HTTP_PROXY / NO_PROXY.
 *
 * Every lookup goes through Node's own `fetch`, and Node does not send
 * `fetch` through a proxy by itself: behind a proxy that is required, every
 * lookup failed and nothing said why (audit 2026-11-11, M15). No dependency
 * is added for it; this uses what the running Node has:
 *
 * - `http.setGlobalProxyFromEnv()` (Node 24.14 and later): called here, so
 *   the proxy variables are honoured with nothing else to set.
 * - `NODE_USE_ENV_PROXY=1` or `--use-env-proxy` (Node 22.21 and later): Node
 *   reads the proxy variables itself, at startup only, so the variable has to
 *   be in the server's environment before it starts. This module can only
 *   notice that it is.
 * - Anything older: not supported. The lookups go direct.
 *
 * Whatever the case, the startup log says which one it is, so "the lookups
 * fail behind our proxy" has an answer in the first lines of stderr.
 */

import * as http from "node:http";

const PROXY_VARIABLES = ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"];

export interface ProxySetup {
  /**
   * `none`: no proxy variable is set. `runtime`: turned on here. `startup`: Node turned it on at
   * startup (NODE_USE_ENV_PROXY). `unsupported`: a proxy is configured and this process does not use it.
   */
  state: "none" | "runtime" | "startup" | "unsupported";
  /** One line for the startup log; null when there is nothing to say. */
  note: string | null;
}

function atLeast(version: string, major: number, minor: number): boolean {
  const [maj, min] = version.replace(/^v/, "").split(".").map(Number);
  return maj > major || (maj === major && min >= minor);
}

/** Node reads the proxy variables at startup from 22.21 on the 22 line and from 24.0 (there is no 23 release with it). */
function startupProxySupported(version: string): boolean {
  const major = Number(version.replace(/^v/, "").split(".")[0]);
  return major === 22 ? atLeast(version, 22, 21) : major >= 24;
}

/**
 * Route this process's lookups through the proxy the environment names, when the running Node can.
 * `runtime` stands in for `http.setGlobalProxyFromEnv` (tests); the rest is read from `env`.
 */
export function configureProxy(
  env: NodeJS.ProcessEnv = process.env,
  options: { nodeVersion?: string; execArgv?: string[]; runtime?: (() => unknown) | null } = {},
): ProxySetup {
  const named = PROXY_VARIABLES.filter((name) => (env[name] ?? "").trim() !== "");
  if (named.length === 0) return { state: "none", note: null };
  const which = [...new Set(named.map((n) => n.toUpperCase()))].join(" / ");
  const nodeVersion = options.nodeVersion ?? process.version;
  const runtime =
    options.runtime !== undefined ? options.runtime : ((http as unknown as { setGlobalProxyFromEnv?: (proxyEnv?: NodeJS.ProcessEnv) => unknown }).setGlobalProxyFromEnv ?? null);
  if (typeof runtime === "function") {
    try {
      runtime();
      return { state: "runtime", note: `Proxy: lookups go through the proxy from ${which} (NO_PROXY honoured).` };
    } catch (error) {
      return {
        state: "unsupported",
        note: `Proxy: ${which} is set, but turning proxy support on failed (${error instanceof Error ? error.message.slice(0, 120) : String(error)}); lookups go DIRECT.`,
      };
    }
  }
  const flagged =
    env.NODE_USE_ENV_PROXY === "1" || (options.execArgv ?? process.execArgv).includes("--use-env-proxy") || /(?:^|\s)--use-env-proxy(?:\s|$)/.test(env.NODE_OPTIONS ?? "");
  if (flagged && startupProxySupported(nodeVersion)) {
    return { state: "startup", note: `Proxy: lookups go through the proxy from ${which} (Node read it at startup: NODE_USE_ENV_PROXY; NO_PROXY honoured).` };
  }
  const how = startupProxySupported(nodeVersion)
    ? `Add NODE_USE_ENV_PROXY=1 to this server's environment (in the MCP server entry's "env") and restart it.`
    : `Node ${nodeVersion} cannot send fetch through a proxy: run the server on Node 22.21 or later with NODE_USE_ENV_PROXY=1 in its environment.`;
  return {
    state: "unsupported",
    note: `Proxy: ${which} is set, but this process does NOT use it, so lookups go direct and will fail (NOT CHECKED) where the proxy is required. ${how}`,
  };
}
