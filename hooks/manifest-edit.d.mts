// SPDX-License-Identifier: Apache-2.0
// Types for manifest-edit.mjs, so the tests that import it are type-checked.

export interface Install {
  ecosystem: "npm" | "crates.io" | "PyPI" | "Go";
  name: string;
  spec: string;
}

/** `readBudgetMs`: how long reading a call may take before it is held as not read in time (tests make it 0). */
export function respond(input: unknown, env?: Record<string, string | undefined>, now?: number, readBudgetMs?: number): string;
/** `depth`: the wrappers (a shell's `-c`, a runner) the command was found inside; 0 for a command line as typed. */
export function installsIn(command: string, dialect: "bash" | "powershell", depth?: number): Install[];
/** `redirects`, when given, collects the redirection targets (`write`: `>` or `>>`). */
export function simpleCommands(
  line: string,
  dialect: "bash" | "powershell",
  redirects?: Array<{ target: string; write: boolean }> | null,
  dropped?: Array<{ text: string; readings: string[][] }> | null,
  cap?: number,
): string[][] | null;
/** Whether a text holds, on one line, a package-manager word followed later by one of its verbs (round 8, R8-1). */
export function detectsInstall(text: string): boolean;
export function dataDir(env?: Record<string, string | undefined>, platform?: string, home?: string): string;
export function poetryToPep440(spec: string): string;
/** Round 14 (R1): the options each manager may carry beside a named package, each with its reason. */
export const NAMED_OPTIONS: Record<string, Array<[string, string]>>;
/** Round 14 (R7): the first pnpm-workspace.yaml line that is not plain YAML, or null. */
export function pnpmUnplainLine(text: string): string | null;
/** THE CONTRACT's constants (a1125-w2-hook-contract.test.ts). */
export const MANAGERS: readonly string[];
export const VERBS: Readonly<Record<string, readonly string[]>>;
export const MANIFESTS: ReadonlySet<string>;
export const MANIFEST_NAME_RULES: ReadonlyArray<{ kind: string; name: RegExp; folder: RegExp | null }>;
export const UNREAD_MANIFESTS: readonly string[];
export const DATA_SPECS: Record<string, unknown>;
export const SINK_SPECS: Record<string, unknown>;
export const ADVICE_VERBS: ReadonlyMap<string, ReadonlySet<string>>;
export const LEDGER_WINDOW_MS: number;
export const LATEST_WINDOW_MS: number;
export const READ_BUDGET_MS: number;
export const WALL_LIMIT_MS: number;
export const WORKER_ABOVE_CHARS: number;
export const SELF_LIMIT_MS: number;
export const MAX_INPUT_CHARS: number;
export const MAX_PARSE_CHARS: number;
export const MAX_ACCOUNT_CHARS: number;
export const MAX_MANIFEST_BYTES: number;
export const MAX_LEDGER_BYTES: number;
export const PROJECT_DEPTH: number;
/** The manifest kind of a path, or null (THE CONTRACT, P1). */
export function manifestKind(filePath: string): string | null;
export const INERT_SETTING: RegExp;
/** Round 23 (V3): the first server version whose proceed and review answers the hook counts. */
export const MIN_VERDICT_SERVER: string;
/** Round 23 (W5): the longest piece of a call a denial repeats. */
export const CALL_PIECE_MAX: number;
/** Round 23 (V1): the characters cmd.exe treats specially in a .cmd or .bat program's arguments. */
export const CMD_SPECIAL: RegExp;
/** Round 23 (W3): the managers that read each kind of configuration a named rule sits in. */
export const CONFIG_READERS: Readonly<Record<string, readonly string[]>>;
/** What builds a command from other words (P1). */
export const BUILDS_COMMAND: RegExp;
/** Round 23 (W5): a piece of the call as a denial repeats it. */
export function callData(text: unknown): string;
/** Round 23 (V2): a path as Claude Code opens it, or null. */
export function windowsPath(path: string, base?: string | null): string | null;
/** Round 23 (W4): whether a command's text names the data folder or ledger as a path segment. */
export function namesDataSegment(text: string, env: NodeJS.ProcessEnv): boolean;
/** Round 24 (Y1): the dependency value forms that name no registry release, with the managers that define each. */
export const OWN_SOURCE_FORMS: ReadonlyArray<readonly [string, string]>;
/** Round 24b: the prefixes after which the next word is started from PATH too (L2). */
export const PATH_LAUNCHERS: ReadonlySet<string>;
/** Round 25 (S6): the verbs that write a manager's own configuration. */
export const CONFIG_WRITE_VERBS: Readonly<Record<string, readonly string[]>>;
/** Round 25 (S6): the configuration keys whose write changes no release a manager resolves. */
export const INERT_CONFIG_KEYS: readonly string[];
/** Round 25 (S7): the verbs that fetch a named release to disk. */
export const FETCH_VERBS: Readonly<Record<string, readonly string[]>>;
/** Round 25 (S3): per manifest kind, the resolver settings that change no release resolved. */
export const INERT_MANIFEST_KEYS: Readonly<Record<string, readonly string[]>>;
/** Round 25 (S1): the requirements option lines that change no release resolved. */
export const REQUIREMENTS_INERT_OPTIONS: readonly string[];
/** Round 25 (S4): the keys a Cargo dependency entry may carry. */
export const CARGO_ENTRY_KEYS: ReadonlySet<string>;
/** Round 25 (S1): the bounds on following include and constraint lines. */
export const REQUIREMENTS_DEPTH: number;
export const REQUIREMENTS_FILES: number;
/** Round 25b: the package managers' configuration files the hook examines. */
export const CONFIG_FILES: ReadonlyArray<{ readonly name: string; readonly folder?: string; readonly format: string; readonly managers: string }>;
/** Round 25b: per configuration file, the keys whose change changes no release resolved. */
export const CONFIG_INERT_KEYS: Readonly<Record<string, readonly string[]>>;
/** Round 26 (R2): the forms in which a runner fetches a package it names, with the ecosystem. */
export const RUNNER_FETCH_FORMS: ReadonlyArray<readonly [string, string]>;
/** Round 27 (E1): each runner's options before the package it fetches, with their arity. */
export const RUNNER_OPTIONS: Readonly<Record<string, { readonly flags: readonly string[]; readonly values: readonly string[]; readonly fetch: readonly string[]; readonly source: readonly string[]; readonly held: readonly string[] }>>;
/** Round 27 (E4): each manager's global options before its sub-command, with their arity (npm reads NPM_OPTIONS). */
export const MANAGER_GLOBAL_OPTIONS: Readonly<Record<string, { readonly flags: readonly string[]; readonly values: readonly string[] }>>;
/** Round 27 (E5): the options that name a configuration source on a manager's command. */
export const CONFIG_SOURCE_OPTIONS: Readonly<Record<string, readonly string[]>>;
/** Round 27 (F7): the keys each tool reads in one of its index tables. */
export const INDEX_TABLE_KEYS: Readonly<Record<string, readonly string[]>>;
/** Round 27 (E4): npm option names (abbreviations read against them). */
export const NPM_OPTIONS: readonly string[];
/** Round 28 (F11): the JavaScript package managers an npm-family runner may run (their own command is read). */
export const JS_MANAGERS: ReadonlySet<string>;
/** Round 29 (H3): the pnpm-workspace.yaml settings that put no registry release in the lockfile. */
export const PNPM_INERT_KEYS: ReadonlySet<string>;
