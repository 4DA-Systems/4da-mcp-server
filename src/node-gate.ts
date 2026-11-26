// SPDX-License-Identifier: Apache-2.0
/**
 * The server needs Node.js 22 or newer (package.json `engines`; CI runs 22, 22.12 and 24). Below it,
 * it started and served with no word of its own: npm prints an `EBADENGINE` warning when it installs,
 * which an MCP client hides, and on Node 20.20.2 a cold `npx` start took 30 s and then ran an untested
 * server (audit 2026-11-25, H-7).
 *
 * This module is the entry's first import: ES modules run in import order, so it runs before any
 * other module of the server (and its dependencies) is evaluated, and stops the process with one
 * line on stderr and exit code 1. `--version` and `--help` still answer, so a user can see what is
 * installed. Nothing here needs more than what every Node.js since 12 has.
 */

import { writeSync } from "node:fs";

import { readPackageVersion, serverUsage } from "./usage.js";

/** The lowest Node.js major this server runs on. */
export const MIN_NODE_MAJOR = 22;

/** The line to stop with, or null when `version` (default: the running Node.js) is new enough. */
export function nodeTooOldLine(version: string = process.versions.node): string | null {
  const major = Number.parseInt(version.split(".")[0], 10);
  if (Number.isFinite(major) && major >= MIN_NODE_MAJOR) return null;
  return (
    `[4DA] Node.js ${MIN_NODE_MAJOR} or newer is needed; this is Node.js ${version}. ` +
    `Install Node.js 22.13 or later (its built-in SQLite driver needs nothing built), then start the server again.`
  );
}

/** True when the arguments only ask for the version or the usage, which every Node.js can answer. */
export function asksOnlyForVersionOrHelp(argv: readonly string[]): boolean {
  return argv.length > 0 && argv.every((a) => a === "--version" || a === "-v" || a === "--help" || a === "-h");
}

/** Write and exit: synchronous, because process.exit() does not wait for an asynchronous write to a pipe. */
function writeAndExit(fd: 1 | 2, text: string, code: number): never {
  try {
    writeSync(fd, text);
  } catch {
    (fd === 1 ? console.log : console.error)(text.replace(/\n$/, ""));
  }
  process.exit(code);
}

const tooOld = nodeTooOldLine();
if (tooOld !== null) {
  const argv = process.argv.slice(2);
  if (!asksOnlyForVersionOrHelp(argv)) writeAndExit(2, `${tooOld}\n`, 1);
  // Answered here: the rest of the server (undici among it) does not even load on Node.js 18.
  const version = readPackageVersion();
  if (argv.includes("--version") || argv.includes("-v")) writeAndExit(1, `@4da/mcp-server ${version ?? "0.0.0"}\n`, 0);
  try {
    writeSync(2, `${tooOld}\n`);
  } catch {
    // The usage below is what was asked for.
  }
  writeAndExit(1, `${serverUsage(version)}\n`, 0);
}
