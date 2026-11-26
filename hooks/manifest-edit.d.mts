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
