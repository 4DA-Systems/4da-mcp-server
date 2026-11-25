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

// ---------------------------------------------------------------------------
// Directories (audit 2026-11-25 B-B1)
// ---------------------------------------------------------------------------

/**
 * A character a directory name may hold and still be a plain path on bash, cmd.exe and
 * PowerShell: a letter, a combining mark or a digit in any script, `.`, `_`, `-`, `+`, `@` and the
 * ASCII space (a name with a space breaks an unquoted `cd` and nothing else). Not parentheses:
 * PowerShell runs an unquoted `(x86)` as a subexpression (`cd Program Files (x86)` runs `x86`), so
 * a "Program Files (x86)"-style directory inside a project gets words, not a command. Not `~`,
 * `,`, `=`, `#`, `[`, `]`, `{`, `}`, quotes, `$`, backticks, `%`, `!`, `^`, `&`, `|`, `;`, `<`,
 * `>`, `*`, `?`, `:` or `\`, and no other punctuation: PowerShell reads the Unicode dashes and
 * curly quotes as its own `-` and `'`.
 */
const DIR_CHAR = /^[\p{L}\p{M}\p{N}._+@ -]$/u;
/** Letters and marks that render as nothing: Hangul fillers, variation selectors. */
const INVISIBLE = /[\u115f\u1160\u3164\uffa0\ufe00-\ufe0f\u{e0100}-\u{e01ef}]/u;
/** A leading drive (`C:/`) or root (`/`): the one place `:` and an empty first segment are allowed. */
const DIR_ROOT = /^(?:[A-Za-z]:\/|\/)/;
const MAX_DIR_LENGTH = 1024;

/**
 * Whether `dir` (a project-relative directory as the plans write it, `/`-separated, or "." for the
 * root) may be named as the directory a command runs in: no character a shell reads specially, no
 * control or invisible character, no segment that starts with `-` (read as an option), no leading
 * `@` (PowerShell splatting), no empty segment and no space at either end of a segment. A directory
 * that fails it comes from the repository and is named only escaped, in words (unsafeDirLabel).
 */
export function isShellSafeDir(dir: string): boolean {
  if (dir === ".") return true;
  if (dir.length === 0 || dir.length > MAX_DIR_LENGTH) return false;
  const rest = dir.replace(DIR_ROOT, "");
  if (rest.startsWith("@") || INVISIBLE.test(rest)) return false;
  for (const segment of rest.split("/")) {
    if (segment === "" || segment.startsWith("-") || segment !== segment.trim()) return false;
    for (const ch of segment) if (!DIR_CHAR.test(ch)) return false;
  }
  return true;
}

const hex = (cp: number) => (cp > 0xffff ? `\\U${cp.toString(16).toUpperCase().padStart(8, "0")}` : `\\u${cp.toString(16).toUpperCase().padStart(4, "0")}`);

/**
 * How a directory is named in words: as it is when it is a plain path, otherwise escaped, every
 * character that is not plain written as `\uXXXX`, inside a marker
 * (`[unsafe directory name, escaped: a\u0024\u0028PWN1\u0029]`). Pasted into any shell the label
 * expands nothing, runs nothing and is not a valid package name or option.
 */
export function unsafeDirLabel(dir: string): string {
  if (isShellSafeDir(dir)) return dir;
  const shown = dir.length > MAX_DIR_LENGTH ? dir.slice(0, MAX_DIR_LENGTH) : dir;
  let out = "";
  let segmentStart = true;
  for (const ch of shown) {
    const cp = ch.codePointAt(0)!;
    // `@` is escaped wherever it stands in an unsafe name: after a space it would start a token.
    const plain = DIR_CHAR.test(ch) && !INVISIBLE.test(ch) && ch !== "@" && !(segmentStart && (ch === "-" || ch === " "));
    out += ch === "/" ? "/" : plain ? ch : hex(cp);
    segmentStart = ch === "/";
  }
  return `[unsafe directory name, escaped: ${out}${dir.length > MAX_DIR_LENGTH ? "..." : ""}]`;
}

/** The sentence a step in such a directory carries in place of its command. */
export function unsafeDirWords(dir: string): string {
  return `the directory ${unsafeDirLabel(dir)} has a name that is not safe to put in a command (it holds characters a shell reads as code, or starts with "-" or "@"), so no command or directory is named for it: handle that directory by hand, with its name quoted`;
}

/**
 * Keys whose strings are kept verbatim: commands (only ever named for a safe directory) and the
 * project's own root, which the caller chose and an agent passes back as project_path.
 */
const VERBATIM_KEYS = new Set(["command", "run", "installFix", "projectPath", "projectScope", "project_path", "project_root"]);
const NAME_START = /[\p{L}\p{N}._-]/u;
const escapeRegExp = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/**
 * `value` (a tool result) with every unsafe directory in `dirs` named by its label wherever it
 * appears in prose: outside command fields and outside `backtick` spans (a span is a command;
 * a directory name holding a backtick is rewritten everywhere but command fields, since no
 * command the server writes holds one). A match must start a word (not follow a letter, digit,
 * `.`, `_` or `-`). Both `/` and `\` spellings are matched; longest first, in one pass.
 */
export function escapeUnsafeDirs<T>(value: T, dirs: Iterable<string>): T {
  const unsafe = [...new Set([...dirs].filter((d) => !isShellSafeDir(d) && d.length > 0))];
  if (unsafe.length === 0) return value;
  const label = new Map<string, string>();
  for (const d of unsafe) {
    label.set(d, unsafeDirLabel(d));
    if (d.includes("/")) label.set(d.replace(/\//g, "\\"), unsafeDirLabel(d));
  }
  const spellings = [...label.keys()].sort((a, b) => b.length - a.length);
  const ticked = spellings.filter((s) => s.includes("`"));
  const plain = spellings.filter((s) => !s.includes("`"));
  const pattern = (list: string[]) => (list.length > 0 ? new RegExp(`(?<!${NAME_START.source})(?:${list.map(escapeRegExp).join("|")})`, "gu") : null);
  const all = pattern(ticked);
  const outside = pattern(plain);
  const rewrite = (text: string): string => {
    let s = all ? text.replace(all, (m) => label.get(m) ?? m) : text;
    if (outside && s.length > 0) s = s.split(/(`[^`\n]*`)/).map((part, i) => (i % 2 === 1 ? part : part.replace(outside, (m) => label.get(m) ?? m))).join("");
    return s;
  };
  const walk = (v: unknown, key: string | null): unknown => {
    if (typeof v === "string") return key !== null && VERBATIM_KEYS.has(key) ? v : rewrite(v);
    if (Array.isArray(v)) return v.map((x) => walk(x, key));
    if (v && typeof v === "object") {
      const out: Record<string, unknown> = {};
      for (const [k, x] of Object.entries(v)) out[k] = walk(x, k);
      return out;
    }
    return v;
  };
  return walk(value, null) as T;
}
