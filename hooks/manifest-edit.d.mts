// SPDX-License-Identifier: Apache-2.0
// Types for manifest-edit.mjs, so the tests that import it are type-checked.

export interface Install {
  ecosystem: "npm" | "crates.io" | "PyPI" | "Go";
  name: string;
  spec: string;
}

export function respond(input: unknown, env?: Record<string, string | undefined>, now?: number): string;
export function installsIn(command: string, dialect: "bash" | "powershell"): Install[];
export function simpleCommands(line: string, dialect: "bash" | "powershell"): string[][] | null;
export function dataDir(env?: Record<string, string | undefined>, platform?: string, home?: string): string;
export function poetryToPep440(spec: string): string;
