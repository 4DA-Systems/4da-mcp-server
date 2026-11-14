// SPDX-License-Identifier: Apache-2.0
/**
 * Command-line parsing for the server binary.
 *
 * `--port 80abc` bound port 80 (parseInt reads a prefix), and `--bogus` started the server as if
 * nothing had been passed (pre-publish round 7): a typo in an editor's MCP config then served
 * something other than what was written. A port is now a whole number from 1 to 65535 written in
 * digits only, and a flag this binary does not know ends it with the usage and exit code 2.
 */

export type CliCommand =
  | { kind: "version" }
  | { kind: "help" }
  | { kind: "setup"; dryRun: boolean }
  | { kind: "doctor" }
  | { kind: "http"; port: number; host: string }
  | { kind: "stdio" };

export type CliParse = { ok: true; command: CliCommand } | { ok: false; error: string };

export const DEFAULT_HTTP_PORT = 4840;
export const DEFAULT_HTTP_HOST = "127.0.0.1";

/** Flags that stand alone. `setup` and `doctor` are also accepted as bare words, as before. */
const SWITCHES = new Set(["--version", "-v", "--help", "-h", "--setup", "setup", "--doctor", "doctor", "--dry-run", "--http"]);
/** Flags that take the next argument as their value. */
const VALUED = new Set(["--port", "--host"]);

/** A TCP port: digits only, 1 to 65535. */
export function parsePort(raw: string): number | null {
  if (!/^\d{1,5}$/.test(raw)) return null;
  const port = Number(raw);
  return port >= 1 && port <= 65535 ? port : null;
}

export function parseCliArgs(argv: readonly string[]): CliParse {
  const seen = new Set<string>();
  const values = new Map<string, string>();
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    // `--port=8080` is the same as `--port 8080`.
    const eq = arg.startsWith("--") ? arg.indexOf("=") : -1;
    const flag = eq > 0 ? arg.slice(0, eq) : arg;
    if (VALUED.has(flag)) {
      const value = eq > 0 ? arg.slice(eq + 1) : argv[i + 1];
      // A flag with no value (or followed by another flag) is a typo, not a request to bind
      // everywhere: refused rather than guessed.
      if (value === undefined || value === "" || (eq < 0 && value.startsWith("-"))) return { ok: false, error: `${flag} requires a value` };
      if (values.has(flag)) return { ok: false, error: `${flag} is given twice` };
      values.set(flag, value);
      if (eq < 0) i++;
      continue;
    }
    if (eq > 0 || !SWITCHES.has(arg)) return { ok: false, error: `unknown argument ${JSON.stringify(arg.slice(0, 80))}` };
    seen.add(arg);
  }

  if (seen.has("--version") || seen.has("-v")) return { ok: true, command: { kind: "version" } };
  if (seen.has("--help") || seen.has("-h")) return { ok: true, command: { kind: "help" } };
  const httpOnly = [...values.keys()];
  if (seen.has("--setup") || seen.has("setup")) return { ok: true, command: { kind: "setup", dryRun: seen.has("--dry-run") } };
  if (seen.has("--dry-run")) return { ok: false, error: "--dry-run is used only with --setup" };
  if (seen.has("--doctor") || seen.has("doctor")) return { ok: true, command: { kind: "doctor" } };
  if (seen.has("--http")) {
    const rawPort = values.get("--port");
    const port = rawPort === undefined ? DEFAULT_HTTP_PORT : parsePort(rawPort);
    if (port === null) return { ok: false, error: `Invalid --port value: ${JSON.stringify(String(rawPort).slice(0, 40))} (a whole number from 1 to 65535)` };
    return { ok: true, command: { kind: "http", port, host: values.get("--host") ?? DEFAULT_HTTP_HOST } };
  }
  if (httpOnly.length > 0) return { ok: false, error: `${httpOnly.join(" and ")} ${httpOnly.length === 1 ? "is" : "are"} used only with --http` };
  return { ok: true, command: { kind: "stdio" } };
}
