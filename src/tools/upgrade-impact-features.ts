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

const MAX_MANIFESTS = 20;
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

/**
 * Features this project enables on `crate`: the Cargo.toml at the project
 * root (workspace dependencies) and in each manifest directory that pins the
 * crate directly. Bounded; unreadable manifests are skipped.
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
  for (const dir of [...dirs].slice(0, MAX_MANIFESTS)) {
    const manifest = path.join(dir, "Cargo.toml");
    try {
      if (fs.statSync(manifest).size > MAX_MANIFEST_BYTES) continue;
      for (const f of cargoFeaturesInManifest(fs.readFileSync(manifest, "utf8"), crate)) out.add(f);
    } catch {
      // No manifest there, or unreadable: nothing to add.
    }
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
