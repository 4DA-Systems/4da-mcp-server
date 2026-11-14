// SPDX-License-Identifier: Apache-2.0
/**
 * Boolean environment variables, read one way everywhere.
 *
 * Each was compared with the exact string "true": `FOURDA_OFFLINE=1` left the server online and a
 * scan sent 463 requests (pre-publish round 7), and `MCP_AUTH_REQUIRED=1` left a loopback HTTP
 * bind unauthenticated. A flag is on for 1, true, yes or on, and off for 0, false, no, off or
 * empty, in any case and with surrounding spaces ignored.
 *
 * Any other value is a typo whose intent cannot be known, so it is read as the SAFE side of that
 * flag (offline: no lookups; auth: required; GitHub release notes: not read), and the server says
 * so once on stderr.
 */

const TRUE_WORDS = new Set(["1", "true", "yes", "on"]);
const FALSE_WORDS = new Set(["", "0", "false", "no", "off"]);

/** Every boolean variable the server reads, and what an unreadable value is taken to mean. */
export const BOOLEAN_ENV_FLAGS = {
  /** No network lookups at all (OSV.dev, registries, HN, embeddings). */
  FOURDA_OFFLINE: { unrecognised: true, meaning: "offline: no lookups are made" },
  /** Authentication on a loopback --http bind (always on for any other bind). */
  MCP_AUTH_REQUIRED: { unrecognised: true, meaning: "authentication is required" },
  /** upgrade_impact may read GitHub release notes (opt-in). */
  FOURDA_GITHUB_CHANGELOG: { unrecognised: false, meaning: "GitHub is not asked for release notes" },
} as const;

export type BooleanEnvFlag = keyof typeof BOOLEAN_ENV_FLAGS;

const warned = new Set<string>();

/** "on", "off", or null for a value that is neither. */
export function parseFlagValue(raw: string | undefined): boolean | null {
  const value = (raw ?? "").trim().toLowerCase();
  if (TRUE_WORDS.has(value)) return true;
  if (FALSE_WORDS.has(value)) return false;
  return null;
}

/** The stderr line for an unreadable value of `name`, or null when the value is readable. */
export function flagWarning(name: BooleanEnvFlag, raw: string | undefined): string | null {
  if (parseFlagValue(raw) !== null) return null;
  const spec = BOOLEAN_ENV_FLAGS[name];
  return `[4DA] ${name}=${JSON.stringify(String(raw).slice(0, 40))} is not one of 1/true/yes/on or 0/false/no/off; read as ${spec.unrecognised ? "on" : "off"} (${spec.meaning}).`;
}

/** Whether boolean flag `name` is on. An unreadable value is its safe side, said once on stderr. */
export function envFlag(name: BooleanEnvFlag, env: NodeJS.ProcessEnv = process.env): boolean {
  const raw = env[name];
  const parsed = parseFlagValue(raw);
  if (parsed !== null) return parsed;
  const key = `${name}=${raw}`;
  if (!warned.has(key)) {
    warned.add(key);
    const line = flagWarning(name, raw);
    if (line) console.error(line);
  }
  return BOOLEAN_ENV_FLAGS[name].unrecognised;
}

/** FOURDA_OFFLINE: no network lookups. */
export function isOfflineMode(env: NodeJS.ProcessEnv = process.env): boolean {
  return envFlag("FOURDA_OFFLINE", env);
}

/** Says, at startup, which boolean variables hold a value that is not read as written. */
export function warnUnreadableEnvFlags(env: NodeJS.ProcessEnv = process.env): void {
  for (const name of Object.keys(BOOLEAN_ENV_FLAGS) as BooleanEnvFlag[]) {
    if (env[name] !== undefined) envFlag(name, env);
  }
}
