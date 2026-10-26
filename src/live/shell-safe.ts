// SPDX-License-Identifier: Apache-2.0
/**
 * Which values may be spliced into a command an agent is told to run.
 *
 * Package names, installed versions, Cargo dependency keys and `[target.'cfg(...)']`
 * headers come from the scanned project's own files: a cloned repository controls
 * them. upgrade_planner put a Cargo.toml target header inside `--target "..."`,
 * where bash and PowerShell still expand `$(...)` and backticks, and a dependency
 * key unquoted after `--rename` (audit 6.2.5 C-1). A command is named only when
 * every spliced value is a plain token no shell (sh, bash, zsh, cmd.exe,
 * PowerShell) reads specially; otherwise the caller falls back to words.
 */

/** npm (scoped or not), crates.io and PyPI names: letters, digits, `.`, `_`, `-`; npm's `@scope/`. */
const PACKAGE_NAME = /^(?:@[A-Za-z0-9][A-Za-z0-9._-]*\/)?[A-Za-z0-9][A-Za-z0-9._-]*$/;
/** Go module paths: host/path segments of letters, digits, `.`, `_`, `~`, `-`. */
const GO_MODULE = /^[A-Za-z0-9][A-Za-z0-9._~-]*(?:\/[A-Za-z0-9._~-]+)*$/;
/** Versions as every supported ecosystem writes them: `1.2.3`, `v1.2.3`, `1.0.0-rc.1+build`, `2.0.0b1`. */
const VERSION = /^v?[0-9A-Za-z][0-9A-Za-z.+_-]*$/;
/** A Cargo target given as a plain triple (`x86_64-pc-windows-msvc`). */
const TARGET_TRIPLE = /^[A-Za-z0-9_.-]+$/;
/** A Cargo `cfg(...)` target with no string literals: `cfg(windows)`, `cfg(not(unix))`, `cfg(all(unix, target_pointer_width = 64))`. */
const CFG_PLAIN = /^cfg\([A-Za-z0-9_(), =]*\)$/;

export function isShellSafeName(name: string, ecosystem: string): boolean {
  return (ecosystem === "Go" ? GO_MODULE : PACKAGE_NAME).test(name) && name.length <= 214;
}

export function isShellSafeVersion(version: string): boolean {
  return VERSION.test(version) && version.length <= 128;
}

/**
 * A Cargo target header that can go inside double quotes on every shell. A `cfg` with a string
 * literal (`cfg(target_os = "linux")`) cannot: its quotes end the argument early. It is left to
 * the words, which was always the only correct answer for it.
 */
export function isShellSafeCargoTarget(target: string): boolean {
  return (TARGET_TRIPLE.test(target) || CFG_PLAIN.test(target)) && target.length <= 256;
}
