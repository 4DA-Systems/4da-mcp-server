// SPDX-License-Identifier: Apache-2.0
/**
 * A Go module path as the user wrote it is checked before anything is looked up under it.
 *
 * The blind pre-publish audit of main 96c16d2 (2026-11-12, B1): dependency_check said `proceed`
 * for gin v1.6.0 written as `github.com/gin-gonic/gin/`, `github.com//gin-gonic/gin`,
 * `github.com/GIN-gonic/gin` or `github.com/x/y/../../gin-gonic/gin`, and for
 * `github.com/Labstack/Echo/v4` v4.1.0, while the canonical paths are `avoid` (GO-2021-0052 and
 * 16 advisories). proxy.golang.org answers several of those spellings (the case-encoded one fetches
 * the same GitHub repository), OSV.dev matches the module path exactly and matches nothing, and no
 * advisory read as clean. The go command refuses every one of them: a path with an empty, `.` or
 * `..` element or a trailing slash is not a module path, and a path whose case differs from the
 * module's own go.mod `module` line is "a different module" (`go get` reports the mismatch).
 *
 * So: a path that is not well-formed, or whose case is not the one the module declares, is
 * answered `unknown` with the canonical path named, never matched against advisories.
 */

import { fetchWithTimeout } from "./http-utils.js";
import { escapeModulePath } from "./go-registry.js";

const PROXY = "https://proxy.golang.org";
const TIMEOUT_MS = 8_000;

/** Why `raw` is not a module path the go command accepts, with the path it most likely means; null when it is well-formed. */
export function goPathShapeProblem(raw: string): { canonical: string | null; reason: string } | null {
  const path = raw.trim();
  const problems: string[] = [];
  if (/\s/.test(path)) problems.push("it contains whitespace");
  if (path.includes("\\")) problems.push("it contains a backslash");
  if (path.includes("@")) problems.push("it contains `@` (a version goes in `to`, not in the module path)");
  if (path.startsWith("/")) problems.push("it starts with `/`");
  if (path.endsWith("/")) problems.push("it ends with `/`");
  if (path.includes("//")) problems.push("it has an empty path element (`//`)");
  const elements = path.split("/");
  if (elements.some((e) => e === "." || e === "..")) problems.push("it has a `.` or `..` element");
  if (problems.length === 0) return null;
  return { canonical: canonicalGuess(path), reason: problems.join("; ") };
}

/** The path a malformed spelling most likely means: version dropped, slashes collapsed, `.`/`..` resolved. */
function canonicalGuess(path: string): string | null {
  const noVersion = path.replace(/\\/g, "/").split("@")[0].trim();
  const out: string[] = [];
  for (const e of noVersion.split("/")) {
    if (e === "" || e === ".") continue;
    if (e === "..") {
      out.pop();
      continue;
    }
    out.push(e);
  }
  const guess = out.join("/");
  return guess.includes(".") && out.length >= 2 ? guess : null;
}

/** The `module` line of a go.mod body, or null. */
export function goModModuleLine(body: string): string | null {
  const m = /^\s*module\s+("?)([^\s"]+)\1\s*(?:\/\/.*)?$/m.exec(body);
  return m ? m[2] : null;
}

export type GoPathVerdict =
  | { ok: true }
  | { ok: false; canonical: string | null; reason: string };

/**
 * Whether a user-supplied Go module path is one the go command would accept as written: well-formed,
 * and spelled as the module's own go.mod `module` line spells it (read from the proxy at `version`
 * when given, else at @latest). Lowercase is no proof: `github.com/azure/azure-sdk-for-go` fetches
 * the repository that declares `github.com/Azure/azure-sdk-for-go`, and OSV keys the latter. When
 * the declaration cannot be read, a lowercase path is let through (the lookups that follow say what
 * they could not read); a path with uppercase letters is not, since most modules declare lowercase.
 * Answers are kept in memory for the process (bounded).
 */
export async function checkGoModulePath(raw: string, version?: string | null, fetchFn: typeof fetchWithTimeout = fetchWithTimeout): Promise<GoPathVerdict> {
  const shape = goPathShapeProblem(raw);
  if (shape) return { ok: false, ...shape };
  const path = raw.trim();
  const key = `${path}@${version ?? ""}`;
  const hit = MEMO.get(key);
  if (hit) return hit;
  const verdict = await declaredCase(path, version, fetchFn);
  if (verdict.ok || verdict.canonical) {
    MEMO.set(key, verdict);
    if (MEMO.size > MEMO_MAX) MEMO.delete(MEMO.keys().next().value!);
  }
  return verdict;
}

const MEMO = new Map<string, GoPathVerdict>();
const MEMO_MAX = 500;

async function declaredCase(path: string, version: string | null | undefined, fetchFn: typeof fetchWithTimeout): Promise<GoPathVerdict> {
  const escaped = escapeModulePath(path);
  try {
    let v = version && /^v\d/.test(version) ? version : null;
    if (!v) {
      const latest = await fetchFn(`${PROXY}/${escaped}/@latest`, {}, TIMEOUT_MS);
      if (latest.ok) v = ((await latest.json()) as { Version?: string }).Version ?? null;
    }
    if (v) {
      const mod = await fetchFn(`${PROXY}/${escaped}/@v/${escapeModulePath(v)}.mod`, {}, TIMEOUT_MS);
      if (mod.ok) {
        const declared = goModModuleLine(await mod.text());
        if (declared === path) return { ok: true };
        if (declared) {
          return { ok: false, canonical: declared, reason: `the module declares itself as \`${declared}\` in its go.mod; Go module paths are case-sensitive, so \`${path}\` is not that module (go get reports the mismatch)` };
        }
      }
    }
  } catch {
    // fall through: not confirmed
  }
  const lower = path.toLowerCase();
  if (path === lower) return { ok: true };
  return {
    ok: false,
    canonical: null,
    reason: `it has uppercase letters and the module's go.mod could not be read from proxy.golang.org to confirm that it declares this exact spelling (Go module paths are case-sensitive; most are lowercase, such as \`${lower}\`)`,
  };
}

/** The sentence an answer gives for a rejected path. */
export function goPathNotCheckedText(raw: string, verdict: Extract<GoPathVerdict, { ok: false }>): string {
  const use = verdict.canonical ? ` Check \`${verdict.canonical}\` instead.` : "";
  return `NOT CHECKED: \`${raw}\` is not a Go module path the go command accepts as written (${verdict.reason}), and OSV.dev matches advisories by the exact module path, so nothing about it was checked.${use} This is not a clean result.`;
}
