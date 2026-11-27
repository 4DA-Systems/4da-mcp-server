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
