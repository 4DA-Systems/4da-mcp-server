// SPDX-License-Identifier: Apache-2.0
/**
 * The commands this server prints for a person to run, pinned to the version that prints them.
 *
 * npx's own options come before the package (after it they would reach the server, which refuses
 * them): `-y` installs without asking, `--prefer-offline` starts a cached copy of the pinned
 * version without asking the registry first. Unpinned, `npx @4da/mcp-server` starts whatever npx
 * cached first, or the newest release, which need not be the server that printed the line.
 */

import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

/** The package these commands run. */
export const PACKAGE = "@4da/mcp-server";

/**
 * The version of the package this module ships in, from the package.json beside `dist/` (or
 * `src/`). Null when it cannot be read: setup then writes nothing, because the only command it
 * could write would be an unpinned one.
 */
export function readPackageVersion(moduleUrl: string = import.meta.url): string | null {
  try {
    const manifest = path.join(path.dirname(fileURLToPath(moduleUrl)), "..", "package.json");
    const pkg: unknown = JSON.parse(readFileSync(manifest, "utf-8"));
    if (pkg === null || typeof pkg !== "object" || Array.isArray(pkg)) return null;
    const { name, version } = pkg as { name?: unknown; version?: unknown };
    if (name !== PACKAGE || typeof version !== "string") return null;
    return /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(version) ? version : null;
  } catch {
    return null;
  }
}

/** This package's version, or null when its package.json cannot be read. */
export const RUNNING_VERSION = readPackageVersion();

/** npx's options, in the order every surface writes them. */
export const NPX_OPTIONS: readonly string[] = ["-y", "--prefer-offline"];

/**
 * `npx -y --prefer-offline @4da/mcp-server@<version>`; `<version>` when the version is not known.
 * `extra`: further npx options, written after these and before the package (`--allow-scripts=...`).
 */
export function pinnedNpx(version: string | null, extra: readonly string[] = []): string {
  return `npx ${[...NPX_OPTIONS, ...extra].join(" ")} ${PACKAGE}@${version ?? "<version>"}`;
}

/** --help, and the text an unknown argument exits with (cli-args.ts), for the running version. */
export function serverUsage(version: string | null): string {
  const npx = pinnedNpx(version);
  // The longest row is `<npx> --version` (10 characters after npx); two spaces after it.
  const pad = (s: string) => s.padEnd(npx.length + 12);
  return `
  ${PACKAGE} — Dependency intelligence for AI coding agents

  Usage:
    ${pad(npx)}Start MCP server (stdio transport)
    ${pad(`${npx} --http`)}Start Streamable HTTP transport
    ${pad(`${npx} --setup`)}Auto-configure your editor
    ${pad(`${npx} --doctor`)}Check installation health
    ${pad(`${npx} --version`)}Print version

  Options:
    --http              Use Streamable HTTP instead of stdio
    --port <number>     HTTP port, 1 to 65535 (default: 4840)
    --host <address>    HTTP bind address (default: 127.0.0.1). A non-loopback
                        address exposes every tool to the network and is
                        refused unless MCP_AUTH_SECRET is set; authentication
                        is then mandatory for every request.
    --setup             Detect editors and write MCP config
    --dry-run           With --setup: print each file and entry, write nothing
    --update            With --setup: replace an existing 4da entry that differs
                        (default: keep it and say so)
    --doctor            Check Node.js, the SQLite driver, the data folder and
                        databases, the embedding provider, and that OSV.dev
                        and the registries answer

  An argument not listed here exits with this text and code 2.

  Environment (a yes/no variable is on for 1, true, yes or on, any case):
    FOURDA_DB_PATH      Path to 4DA's SQLite database (auto-detected if omitted)
    FOURDA_OFFLINE      Set to 1 / true to disable all network calls (OSV.dev, the
                        package registries, Hacker News)
    FOURDA_CALL_BUDGET_MS  Time one tool call may take (default 20000). Past it the
                        call is answered NOT CHECKED; its lookups run on and are cached.
    HTTPS_PROXY, HTTP_PROXY, NO_PROXY  Every lookup goes through the proxy (NO_PROXY
                        honoured); an unreachable proxy means NOT CHECKED, never direct.
    MCP_AUTH_SECRET     Shared secret for verifying relay-issued Bearer tokens
                        (HMAC-SHA256). Falls back to JWT_SECRET. Without it, no
                        token is accepted.
    MCP_AUTH_REQUIRED   Set to 1 / true to require auth on a loopback --http bind
                        (always required on a non-loopback bind)
    MCP_ALLOWED_HOSTS   Extra comma-separated hostnames accepted in the Host /
                        Origin headers (needed when binding to 0.0.0.0)

  Works standalone (scans your project on startup) or with the full
  4DA desktop app for content scoring, source monitoring, and more.
  Desktop app: https://github.com/4DA-Systems/4DA/releases/latest
  Docs:        https://4da.ai
`;
}
