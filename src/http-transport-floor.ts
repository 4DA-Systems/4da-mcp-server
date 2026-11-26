// SPDX-License-Identifier: Apache-2.0
/**
 * HTTP mode serves through @hono/node-server, which @modelcontextprotocol/node loads and admits as
 * "^1.19.9 || ^2.1.3". Every 1.x release and every 2.x release below 2.1.6 carries a known advisory
 * (GHSA-wc8c-qw6v-h7f6, high, on 1.19.9; GHSA-jpvv-r467-5p4w and GHSA-qv5m-9pm6-hqp3 below 2.1.6;
 * read from OSV.dev through dependency_check on 2026-11-26). A fresh install resolves a clean
 * release, but npm keeps an older copy that the folder already holds, and nothing this package
 * declares changes which copy @modelcontextprotocol/node loads there: a direct dependency of ours
 * lands nested where nothing loads it, and `overrides` of a dependency are ignored (audit
 * 2026-11-25, H-8, measured with packed tarballs). So HTTP mode reads the version of the copy that
 * WILL be loaded and refuses to serve on an affected one. The stdio server never loads it.
 */
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { pinnedNpx, RUNNING_VERSION } from "./usage.js";

/** The smallest @hono/node-server release free of known advisories. */
export const NODE_SERVER_FLOOR = "2.1.6";

/** True when `version` is a release below the floor; null when it is not a plain x.y.z version. */
export function belowNodeServerFloor(version: string): boolean | null {
  const read = (v: string): number[] | null => {
    const m = /^(\d{1,6})\.(\d{1,6})\.(\d{1,6})(?:[-+].*)?$/.exec(v.trim());
    return m ? [Number(m[1]), Number(m[2]), Number(m[3])] : null;
  };
  const have = read(version);
  const floor = read(NODE_SERVER_FLOOR)!;
  if (!have) return null;
  for (let i = 0; i < 3; i++) {
    if (have[i] !== floor[i]) return have[i] < floor[i];
  }
  return false;
}

/**
 * The package.json Node would load for `name` when a module in `fromFile` imports it: the nearest
 * node_modules/<name> walking up from that file. Reads no export map, so it works for a package
 * that does not export its package.json.
 */
export function nearestPackageJson(fromFile: string, name: string): string | null {
  for (let dir = dirname(fromFile), hops = 0; hops < 64; dir = dirname(dir), hops++) {
    const candidate = join(dir, "node_modules", ...name.split("/"), "package.json");
    if (existsSync(candidate)) return candidate;
    if (dirname(dir) === dir) break;
  }
  return null;
}

/** The version of the @hono/node-server copy that @modelcontextprotocol/node loads; null when it cannot be read. */
export function loadedNodeServerVersion(): string | null {
  try {
    const mcpNode = fileURLToPath(import.meta.resolve("@modelcontextprotocol/node"));
    const manifest = nearestPackageJson(mcpNode, "@hono/node-server");
    if (!manifest) return null;
    const version: unknown = (JSON.parse(readFileSync(manifest, "utf8")) as { version?: unknown }).version;
    return typeof version === "string" ? version : null;
  } catch {
    return null;
  }
}

/** Why HTTP mode must not start on this installation, or null. A version that cannot be read is not a refusal. */
export function nodeServerProblem(version: string | null = loadedNodeServerVersion()): string | null {
  if (version === null || belowNodeServerFloor(version) !== true) return null;
  return (
    `Refusing to start the MCP HTTP transport: this installation would serve through @hono/node-server ${version},\n` +
    `  which has known vulnerabilities (fixed in ${NODE_SERVER_FLOOR}). The folder this server was installed into already\n` +
    `  held that older copy, and npm kept it.\n` +
    `  Run the server with npx (${pinnedNpx(RUNNING_VERSION)} --http), or install @hono/node-server@^${NODE_SERVER_FLOOR} in that\n` +
    `  folder and start it again. The stdio server does not load it and is not affected.`
  );
}
