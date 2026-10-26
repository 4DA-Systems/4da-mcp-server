// SPDX-License-Identifier: Apache-2.0
/**
 * Cargo features a project enables on a crate, for `upgrade_impact`.
 *
 * Symbol matching cannot see a renamed or removed Cargo feature: the project
 * names it only in Cargo.toml (`reqwest = { features = ["rustls-tls"] }`), and
 * reqwest 0.13 renamed `rustls-tls` to `rustls` and removed
 * `macos-system-configuration`. Measured 2026-10-12 on 4DA: none of those
 * breaking entries was flagged as touching the project, whose src-tauri
 * enables both (audit B-7). So: read the features each manifest that declares
 * the crate enables, and flag a breaking or deprecation entry that names one
 * of them as a feature.
 */

import * as fs from "node:fs";
import * as path from "node:path";

/** Manifests read per call: the root, the pinning directories and workspace members. */
const MAX_MANIFESTS = 64;
const MAX_MANIFEST_BYTES = 512 * 1024;

function escapeRegex(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** Quoted strings of a TOML array body: `"a", 'b'`. */
function stringsOf(arrayBody: string): string[] {
  return [...arrayBody.matchAll(/"([^"\n]*)"|'([^'\n]*)'/g)].map((m) => m[1] ?? m[2]).filter(Boolean);
}

/** `features = [...]` of one dependency's table body (inline or `[dependencies.x]`). */
function featuresIn(body: string): string[] {
  const m = /(?<![\w-])features\s*=\s*\[([^\]]*)\]/.exec(body);
  return m ? stringsOf(m[1]) : [];
}

/**
 * Features one Cargo.toml enables on `crate`, across `[dependencies]`,
 * `[dev-dependencies]`, `[build-dependencies]`, `[target.*.dependencies]`
 * and `[workspace.dependencies]`, in inline-table (`x = { features = [..] }`)
 * and table (`[dependencies.x]`) form, with renames (`package = "x"`).
 */
export function cargoFeaturesInManifest(content: string, crate: string): string[] {
  const out = new Set<string>();
  const name = escapeRegex(crate);
  const dashOrUnderscore = name.replace(/[-_]/g, "[-_]");
  // Inline tables: `reqwest = { ... }` (TOML 1.1 allows them across lines).
  for (const m of content.matchAll(/^[ \t]*("?)([A-Za-z0-9_-]+)\1[ \t]*=[ \t]*\{([^}]*)\}/gm)) {
    const key = m[2];
    const body = m[3];
    const renamed = /(?<![\w-])package\s*=\s*["']([^"']+)["']/.exec(body)?.[1];
    if ((renamed ?? key).replace(/_/g, "-") !== crate.replace(/_/g, "-")) continue;
    for (const f of featuresIn(body)) out.add(f);
  }
  // Table form: `[dependencies.reqwest]` / `[target.'cfg(x)'.dependencies.reqwest]`.
  const header = new RegExp(String.raw`^[ \t]*\[[^\]\n]*dependencies\.["']?${dashOrUnderscore}["']?[ \t]*\][ \t]*$`, "gm");
  for (const m of content.matchAll(header)) {
    const start = (m.index ?? 0) + m[0].length;
    const next = content.slice(start).search(/^[ \t]*\[/m);
    const body = next === -1 ? content.slice(start) : content.slice(start, start + next);
    for (const f of featuresIn(body)) out.add(f);
  }
  return [...out];
}

function readManifest(dir: string): string | null {
  const manifest = path.join(dir, "Cargo.toml");
  try {
    if (fs.statSync(manifest).size > MAX_MANIFEST_BYTES) return null;
    return fs.readFileSync(manifest, "utf8");
  } catch {
    return null; // No manifest there, or unreadable: nothing to add.
  }
}

/** The body of the `[workspace]` table (up to the next table header), or null. */
function workspaceTable(content: string): string | null {
  const m = /^[ \t]*\[workspace\][ \t]*(?:#.*)?$/m.exec(content);
  if (!m) return null;
  const start = m.index + m[0].length;
  const next = content.slice(start).search(/^[ \t]*\[/m);
  return next === -1 ? content.slice(start) : content.slice(start, start + next);
}

/** `key = [ ... ]` of a table body, as strings (TOML arrays may span lines). */
function arrayIn(body: string, key: string): string[] {
  const m = new RegExp(String.raw`(?<![\w-])${key}\s*=\s*\[([^\]]*)\]`).exec(body);
  return m ? stringsOf(m[1].replace(/#[^\n]*/g, "")) : [];
}

/** One path segment glob (`*`, `?`) as a regex. */
function segmentRegex(glob: string): RegExp {
  return new RegExp(`^${glob.split("").map((c) => (c === "*" ? "[^/\\\\]*" : c === "?" ? "[^/\\\\]" : escapeRegex(c))).join("")}$`);
}

/** Directories a member pattern names under `wsRoot`: plain paths and `*` / `?` globs per segment (Cargo's glob members). */
function expandMember(wsRoot: string, pattern: string): string[] {
  let dirs = [wsRoot];
  for (const segment of pattern.split(/[\\/]+/).filter((s) => s && s !== ".")) {
    if (!/[*?]/.test(segment)) {
      dirs = dirs.map((d) => path.join(d, segment));
      continue;
    }
    const re = segmentRegex(segment);
    dirs = dirs.flatMap((d) => {
      try {
        return fs.readdirSync(d, { withFileTypes: true }).filter((e) => e.isDirectory() && re.test(e.name)).map((e) => path.join(d, e.name));
      } catch {
        return [];
      }
    });
  }
  return dirs;
}

/**
 * The member directories a workspace manifest at `wsRoot` declares: `[workspace] members`
 * (globs expanded), less `exclude` (readiness audit M3: victauri's members enable
 * `rustls-tls`, none was read).
 */
function workspaceMembers(wsRoot: string, content: string): string[] {
  const table = workspaceTable(content);
  if (!table) return [];
  const excluded = new Set(arrayIn(table, "exclude").flatMap((p) => expandMember(wsRoot, p)).map((d) => path.resolve(d)));
  return arrayIn(table, "members")
    .flatMap((p) => expandMember(wsRoot, p))
    .map((d) => path.resolve(d))
    .filter((d) => !excluded.has(d));
}

/**
 * Features this project enables on `crate`: the Cargo.toml at the project
 * root (workspace dependencies), in each manifest directory that pins the
 * crate directly, and in every member of a workspace either declares.
 * Bounded; unreadable manifests are skipped.
 */
export function projectCargoFeatures(
  root: string | null,
  crate: string,
  installed: Array<{ name: string; ecosystem: string; isDirect: boolean; sourceDirs?: string[] }>,
): string[] {
  const dirs = new Set<string>();
  if (root) dirs.add(path.resolve(root));
  for (const d of installed) {
    if (d.ecosystem !== "crates.io" || !d.isDirect || d.name.replace(/_/g, "-") !== crate.replace(/_/g, "-")) continue;
    for (const dir of d.sourceDirs ?? []) dirs.add(path.resolve(dir));
  }
  const out = new Set<string>();
  const read = new Set<string>();
  const queue = [...dirs];
  while (queue.length > 0 && read.size < MAX_MANIFESTS) {
    const dir = queue.shift()!;
    if (read.has(dir)) continue;
    read.add(dir);
    const content = readManifest(dir);
    if (content === null) continue;
    for (const f of cargoFeaturesInManifest(content, crate)) out.add(f);
    for (const member of workspaceMembers(dir, content)) if (!read.has(member)) queue.push(member);
  }
  return [...out].sort();
}

/**
 * The enabled features an entry names as a feature: in backticks, or as a
 * whole word in an entry that talks about features. `default` never counts
 * (every crate has it; "default" is ordinary prose).
 */
export function matchFeatures(text: string, features: string[]): string[] {
  const aboutFeatures = /\bfeatures?\b/i.test(text);
  return features.filter((f) => {
    if (f === "default" || f.length < 2) return false;
    const e = escapeRegex(f);
    if (new RegExp(String.raw`\x60${e}\x60`).test(text)) return true;
    return aboutFeatures && new RegExp(String.raw`(?<![\w-])${e}(?![\w-])`).test(text);
  });
}
