// SPDX-License-Identifier: Apache-2.0
/**
 * The version a project forces for a package: npm `overrides`, pnpm
 * `pnpm.overrides` (and `overrides:` in pnpm-workspace.yaml), yarn
 * `resolutions`. An override replaces every parent's own requirement on the
 * package it names, so it is the requirement a lockfile refresh resolves by.
 *
 * The lockfile does not show it: a package-lock edge records the PARENT's
 * requirement. With `"overrides": { "qs": "^6.16.0" }` in package.json and qs
 * 6.16.0 installed, the plan read request 2.88.2's own `~6.5.2`, called the
 * parent stuck, and told the user to "add overrides" to a project that had
 * one, while `npm update qs` moves it to the fixed 6.16.1 (audit 2026-11-11;
 * the 4DA app's `osv/parent_override.rs`, found live on 2026-11-10).
 *
 * Only a plain entry for the package counts: `"qs": "^6.16.0"`, or the name under yarn's
 * any-depth glob (two stars and a slash before it). A parent-scoped entry (`"request": { "qs": ... }`, `request>qs`,
 * `request/qs`), a versioned selector (`qs@<6.5`) and a `$name` reference
 * apply to some copies only, or need the manifest to resolve: they are left to
 * the lockfile, as in the app. Each tool reads its own tables, so an
 * `overrides` field in a Yarn project (which Yarn ignores) is not taken for an
 * override.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { callMemo } from "../call-budget.js";
import { readTextFile } from "./text-file.js";
import type { LockfileFormat } from "./lockfile-parents.js";

export interface ProjectOverride {
  /** The forced spec, as written ("^6.16.0", "6.16.1"). */
  spec: string;
  /** Where it is declared, in words for an answer: `"overrides" in package.json`. */
  where: string;
}

type Table = "overrides" | "pnpm.overrides" | "resolutions";

/** The tables each tool honours (npm: overrides; pnpm: its own and resolutions; Yarn: resolutions; Bun: both). */
const TABLES: Record<LockfileFormat, Table[]> = {
  "package-lock": ["overrides"],
  pnpm: ["pnpm.overrides", "resolutions"],
  yarn: ["resolutions"],
  "yarn-berry": ["resolutions"],
  bun: ["overrides", "resolutions"],
  cargo: [],
};

function plainSpec(table: unknown, name: string): string | null {
  if (!table || typeof table !== "object") return null;
  for (const key of [name, `**/${name}`]) {
    const value = Object.hasOwn(table, key) ? (table as Record<string, unknown>)[key] : undefined;
    if (typeof value !== "string") continue;
    const spec = value.trim();
    if (spec && !spec.startsWith("$")) return spec;
  }
  return null;
}

/** The plain override a parsed package.json holds for `name`, among the tables `format`'s tool reads. */
export function manifestOverride(manifest: unknown, name: string, format: LockfileFormat): ProjectOverride | null {
  if (!manifest || typeof manifest !== "object") return null;
  const m = manifest as Record<string, unknown>;
  for (const table of TABLES[format]) {
    const at = table === "pnpm.overrides" ? (m.pnpm as Record<string, unknown> | undefined)?.overrides : m[table];
    const spec = plainSpec(at, name);
    if (spec) return { spec, where: `"${table === "pnpm.overrides" ? "pnpm.overrides" : table}" in package.json` };
  }
  return null;
}

/** `overrides:` of a pnpm-workspace.yaml (pnpm 9.5+ / 10 keep their settings there): the plain entry for `name`. */
export function workspaceYamlOverride(content: string, name: string): string | null {
  let inside = false;
  for (const raw of content.split("\n")) {
    const line = raw.replace(/\r$/, "");
    if (!line.trim() || line.trimStart().startsWith("#")) continue;
    if (!/^\s/.test(line)) {
      inside = /^overrides:\s*(?:#.*)?$/.test(line);
      continue;
    }
    if (!inside) continue;
    const colon = line.lastIndexOf(": ");
    if (colon < 0) continue;
    const unquote = (text: string) => text.trim().replace(/^(['"])(.*)\1$/, "$2");
    const key = unquote(line.slice(0, colon));
    if (key !== name && key !== `**/${name}`) continue;
    const spec = unquote(line.slice(colon + 2).replace(/\s+#.*$/, ""));
    if (spec && !spec.startsWith("$")) return spec;
  }
  return null;
}

/**
 * The override the project whose lockfile sits in `dir` declares for `name`, or null. Overrides
 * are honoured at the root of the install (the lockfile's directory), which is where this reads.
 */
export function projectOverride(dir: string, name: string, format: LockfileFormat): ProjectOverride | null {
  if (format === "cargo") return null;
  // Read once per tool call: a scan asks for every parent of every finding (blind audit round 6).
  return callMemo(`project-override:${format}:${dir}|${name}`, () => readProjectOverride(dir, name, format));
}

function readProjectOverride(dir: string, name: string, format: LockfileFormat): ProjectOverride | null {
  try {
    const found = manifestOverride(JSON.parse(readTextFile(path.join(dir, "package.json"))), name, format);
    if (found) return found;
  } catch {
    // no package.json, or not JSON: no override is known
  }
  if (format === "pnpm") {
    try {
      const file = path.join(dir, "pnpm-workspace.yaml");
      if (fs.existsSync(file)) {
        const spec = workspaceYamlOverride(readTextFile(file), name);
        if (spec) return { spec, where: `"overrides" in pnpm-workspace.yaml` };
      }
    } catch {
      // unreadable: no override is known
    }
  }
  return null;
}

/** The package an override key names: `foo`, `foo@1`, `bar>foo@2` (pnpm), Yarn's any-depth glob or `bar/foo`, `@s/x`. */
export function overrideKeyName(key: string, format: "npm" | "yarn" | "pnpm" = "pnpm"): string | null {
  let k = key.trim();
  // Only pnpm has a parent selector (`parent>child`); a `>` after `@`, `<`, `=`, `>` or a space, or
  // before `=`, belongs to a version range (`x@>=1 <2`), in every format (re-check 2026-11-24).
  if (format === "pnpm") {
    for (let i = k.length - 1; i > 0; i--) {
      if (k[i] !== ">" || /[@<>=\s]/.test(k[i - 1]) || k[i + 1] === "=") continue;
      k = k.slice(i + 1).trim();
      break;
    }
  }
  const segments = k.split("/").filter((s) => s !== "" && s !== "**");
  if (segments.length === 0) return null;
  const last = segments[segments.length - 1];
  const scope = segments.length >= 2 && segments[segments.length - 2].startsWith("@") ? segments[segments.length - 2] : null;
  let name = scope ? `${scope}/${last}` : last;
  const at = name.indexOf("@", name.startsWith("@") ? 1 : 0);
  if (at > 0) name = name.slice(0, at);
  return name || null;
}

/**
 * Every override, resolution and pnpm override in a parsed package.json (and the `overrides:` of a
 * pnpm-workspace.yaml's text), whatever tool would honour it, as the name it forces and the spec:
 * npm's nested form (`"a": { ".": "1", "b": "file:..." }`) is walked. A `$name` reference is skipped.
 */
export function allOverrideSpecs(manifest: unknown, workspaceYaml: string | null = null): Array<{ name: string; spec: string; where: string }> {
  const out: Array<{ name: string; spec: string; where: string }> = [];
  const walk = (table: unknown, where: string, depth: number, format: "npm" | "yarn" | "pnpm") => {
    if (!table || typeof table !== "object" || Array.isArray(table) || depth > 8) return;
    for (const [key, value] of Object.entries(table as Record<string, unknown>)) {
      if (key === ".") continue;
      const name = overrideKeyName(key, format);
      if (typeof value === "string") {
        if (name && value.trim() && !value.trim().startsWith("$")) out.push({ name, spec: value, where });
      } else if (value && typeof value === "object") {
        const self = (value as Record<string, unknown>)["."];
        if (name && typeof self === "string" && self.trim() && !self.trim().startsWith("$")) out.push({ name, spec: self, where });
        walk(value, where, depth + 1, format);
      }
    }
  };
  if (manifest && typeof manifest === "object" && !Array.isArray(manifest)) {
    const m = manifest as Record<string, unknown>;
    walk(m.overrides, `"overrides" in package.json`, 0, "npm");
    walk(m.resolutions, `"resolutions" in package.json`, 0, "yarn");
    walk((m.pnpm as Record<string, unknown> | undefined)?.overrides, `"pnpm.overrides" in package.json`, 0, "pnpm");
  }
  if (workspaceYaml) {
    let inside = false;
    for (const raw of workspaceYaml.split("\n")) {
      const line = raw.replace(/\r$/, "");
      if (!line.trim() || line.trimStart().startsWith("#")) continue;
      if (!/^\s/.test(line)) {
        inside = /^overrides:\s*(?:#.*)?$/.test(line);
        continue;
      }
      if (!inside) continue;
      const colon = line.lastIndexOf(": ");
      if (colon < 0) continue;
      const unquote = (text: string) => text.trim().replace(/^(['"])(.*)\1$/, "$2");
      const name = overrideKeyName(unquote(line.slice(0, colon)), "pnpm");
      const spec = unquote(line.slice(colon + 2).replace(/\s+#.*$/, ""));
      if (name && spec && !spec.startsWith("$")) out.push({ name, spec, where: `"overrides" in pnpm-workspace.yaml` });
    }
  }
  return out;
}
