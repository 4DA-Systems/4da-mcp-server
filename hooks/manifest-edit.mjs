#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
/**
 * Claude Code plugin hook (PostToolUse on Edit / MultiEdit / Write): when an
 * edit changes a dependency's version in a manifest, tell the agent which
 * packages moved and to check upgrade_impact before it builds.
 *
 * Why a hook and not only a tool: an agent calls a tool when it thinks to.
 * Measured 2026-10-01, the agent asked to "bump fastembed 5 -> 7" got no
 * fastembed-specific help from the briefing it chose to call; a hook fires on
 * the edit itself. Developers asked for exactly this ("If this was a claude
 * plugin with a hook on my dep files, I'd be in", HN, 2026).
 *
 * Fast and quiet by design: no network, no dependencies, plain Node. Any
 * input it does not understand exits 0 with no output, so it can never block
 * or slow an edit. It reads the edit payload Claude Code passes on stdin and,
 * when the edited lines do not show which section they are in, the edited
 * manifest itself (only dependency sections declare dependencies).
 */

import { readFileSync } from "node:fs";
import { basename } from "node:path";

const MANIFESTS = new Set(["package.json", "Cargo.toml", "pyproject.toml", "requirements.txt", "go.mod"]);

/**
 * Only dependency sections declare dependencies. `"version": "1.2.0"` and engines'
 * `"node": ">=20"` were reported as dependencies called `version` and `node`, and
 * Cargo's `edition = "2021"` / `rust-version` and pyproject's `version` the same
 * (pre-publish audit of 5d709ff).
 */
const NPM_DEPENDENCY_SECTIONS = new Set(["dependencies", "devDependencies", "optionalDependencies", "peerDependencies", "overrides", "resolutions"]);
/** A TOML table of dependencies: [dependencies], [dev-dependencies], [target.'cfg(..)'.build-dependencies], [workspace.dependencies], [tool.poetry.group.dev.dependencies]. */
const TOML_DEPENDENCY_TABLE = /(?:^|\.)(?:dependencies|dev-dependencies|build-dependencies)$/;
/** `[dependencies.serde]`: the table of one dependency, whose `version` key is that dependency's. */
const TOML_ONE_DEPENDENCY = /(?:^|\.)(?:dependencies|dev-dependencies|build-dependencies)\.["']?([\w.-]+)["']?$/;
/** TOML keys that are never a dependency, wherever they stand (Poetry lists the interpreter as `python`). */
const TOML_NOT_DEPENDENCIES = new Set(["version", "edition", "rust-version", "requires-python", "resolver", "python", "name"]);
/** package.json keys outside the dependency sections that hold a version. */
const NPM_NOT_DEPENDENCIES = new Set(["version", "node", "npm", "pnpm", "yarn", "bun", "deno", "vscode", "packageManager"]);

/** The object a JSON snippet's key at `index` sits in, when the snippet shows it: its key, "" for the top level, or null when unseen. */
function enclosingJsonKey(text, index) {
  let depth = 0;
  let inString = false;
  for (let i = index - 1; i >= 0; i--) {
    const ch = text[i];
    if (ch === '"' && text[i - 1] !== "\\") inString = !inString;
    if (inString) continue;
    if (ch === "}" || ch === "]") depth++;
    else if (ch === "{" || ch === "[") {
      if (depth === 0) {
        const key = /"([^"]+)"\s*:\s*$/.exec(text.slice(0, i));
        return key ? key[1] : ch === "{" && text.slice(0, i).trim() === "" ? "" : null;
      }
      depth--;
    }
  }
  return null;
}

/** The TOML table header a snippet's line at `index` sits under, when the snippet shows it. */
function enclosingTomlTable(text, index) {
  const headers = [...text.slice(0, index).matchAll(/^\s*\[{1,2}\s*([^\]]+?)\s*\]{1,2}\s*$/gm)];
  return headers.length > 0 ? headers[headers.length - 1][1].replace(/\s+/g, "") : null;
}

/** The edited manifest as it is now on disk (PostToolUse: the edit is already written), parsed lazily; null when unreadable. */
function onDisk(path) {
  let cached;
  return () => {
    if (cached !== undefined) return cached;
    try {
      cached = readFileSync(path, "utf8");
    } catch {
      cached = null;
    }
    return cached;
  };
}

/**
 * Whether `name` in a package.json is a dependency: the snippet's own section when it shows it,
 * else the file on disk; a key the file has only outside the dependency sections is not one.
 */
function npmDependency(text, index, name, disk) {
  const section = enclosingJsonKey(text, index);
  if (section !== null) return NPM_DEPENDENCY_SECTIONS.has(section);
  const raw = disk();
  if (raw) {
    try {
      const doc = JSON.parse(raw);
      const inDeps = [...NPM_DEPENDENCY_SECTIONS].some((s) => doc?.[s] && typeof doc[s] === "object" && Object.hasOwn(doc[s], name));
      if (inDeps) return true;
      const elsewhere = Object.hasOwn(doc ?? {}, name) || (doc?.engines && Object.hasOwn(doc.engines, name)) || (doc?.volta && Object.hasOwn(doc.volta, name));
      if (elsewhere) return false;
    } catch {
      // Not JSON (yet): the snippet alone decides.
    }
  }
  return !NPM_NOT_DEPENDENCIES.has(name);
}

/**
 * The dependency a TOML `key = ...` line declares, or null: the snippet's table when it shows
 * one, else the table the key sits under in the file on disk.
 */
function tomlDependency(text, index, key, disk) {
  let table = enclosingTomlTable(text, index);
  if (table === null) {
    const raw = disk();
    if (raw) {
      const at = new RegExp(`^\\s*["']?${key.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}["']?\\s*=`, "m").exec(raw);
      if (at) table = enclosingTomlTable(raw, at.index) ?? "";
    }
  }
  if (table !== null) {
    const one = TOML_ONE_DEPENDENCY.exec(table);
    if (one) return key === "version" ? one[1] : null;
    if (!TOML_DEPENDENCY_TABLE.test(table)) return null;
  }
  return TOML_NOT_DEPENDENCIES.has(key.toLowerCase()) ? null : key;
}

/** name -> version specifier pairs a manifest snippet declares, in its dependency sections only. */
function declaredVersions(file, text, disk = () => null) {
  const out = new Map();
  if (!text) return out;
  if (file === "package.json") {
    for (const m of text.matchAll(/"(@?[a-z0-9][\w.\-/]*)"\s*:\s*"([~^<>=]*\s*v?\d[^"]*)"/gi)) {
      if (npmDependency(text, m.index, m[1], disk)) out.set(m[1], m[2]);
    }
  } else if (file === "Cargo.toml") {
    for (const m of text.matchAll(/^\s*([A-Za-z_][\w-]*)\s*=\s*"([~^<>=]*\s*\d[^"]*)"/gm)) {
      const name = tomlDependency(text, m.index, m[1], disk);
      if (name) out.set(name, m[2]);
    }
    for (const m of text.matchAll(/^\s*([A-Za-z_][\w-]*)\s*=\s*\{[^}]*\bversion\s*=\s*"([^"]+)"/gm)) {
      const name = tomlDependency(text, m.index, m[1], disk);
      if (name) out.set(name, m[2]);
    }
  } else if (file === "pyproject.toml" || file === "requirements.txt") {
    // A requirement string ("requests>=2.31") is a dependency wherever it is written.
    for (const m of text.matchAll(/["']?([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*(===?|~=|>=)\s*([0-9][^"',;\s]*)/g)) out.set(m[1].toLowerCase(), `${m[2]}${m[3]}`);
    if (file === "pyproject.toml") {
      for (const m of text.matchAll(/^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*=\s*"([~^<>=]*\s*\d[^"]*)"/gm)) {
        const name = tomlDependency(text, m.index, m[1], disk);
        if (name) out.set(name.toLowerCase(), m[2]);
      }
    }
  } else if (file === "go.mod") {
    for (const m of text.matchAll(/^\s*(?:require\s+)?([a-z0-9.-]+\.[a-z]{2,}\/\S+)\s+(v\d\S*)/gm)) out.set(m[1], m[2]);
  }
  return out;
}

/** Changed or added dependency versions between two snippets of one manifest. */
function versionChanges(file, before, after, disk) {
  const old = declaredVersions(file, before, disk);
  const changes = [];
  for (const [name, spec] of declaredVersions(file, after, disk)) {
    const prev = old.get(name);
    if (prev !== spec) changes.push({ name, from: prev ?? null, to: spec });
  }
  return changes;
}

const exact = (spec) => /^v?\d+\.\d+\.\d+([-+][\w.]+)?$/.test(spec.replace(/^[=\s]+/, "")) ? spec.replace(/^[=v\s]+/, "") : null;

const ECOSYSTEM = {
  "package.json": "npm",
  "Cargo.toml": "crates.io",
  "pyproject.toml": "PyPI",
  "requirements.txt": "PyPI",
  "go.mod": "Go",
};

/** An exact pin: `==2.0` (PEP 440 two-part releases too) or a full x.y.z. */
const exactFor = (ecosystem, spec) => {
  if (ecosystem === "PyPI") {
    const m = /^={2,3}\s*(\d[\w.!+-]*)$/.exec(spec.trim());
    return m ? m[1] : null;
  }
  return exact(spec);
};

function adviceFor(file, changes) {
  const ecosystem = ECOSYSTEM[file] ?? null;
  // dependency_check and upgrade_impact both read all four ecosystems.
  const checkable = ecosystem !== null;
  const lines = changes.slice(0, 8).map((c) => {
    const target = exactFor(ecosystem, c.to);
    const call = ecosystem
      ? `; check with upgrade_impact ${JSON.stringify({ package: c.name, ...(target ? { to_version: target } : {}), ecosystem })}`
      : "";
    return `- ${c.name}: ${c.from ?? "(added)"} -> ${c.to}${call}`;
  });
  const more = changes.length > 8 ? `\n- ...and ${changes.length - 8} more` : "";
  // An exact pin is checked as that version; a range ("^1.2", ">=2,<3") as a constraint, which
  // returns the smallest and newest safe release it admits. Go versions keep their `v`.
  const items = checkable
    ? changes.slice(0, 25).map((c) => {
        const to = ecosystem === "Go" ? c.to : exactFor(ecosystem, c.to) ?? c.to.trim();
        const from = c.from ? (ecosystem === "Go" ? c.from : exactFor(ecosystem, c.from)) : null;
        return { ecosystem, package: c.name, to, ...(from ? { from } : {}) };
      })
    : [];
  const check = items.length > 0
    ? `Before installing, call the 4da MCP tool dependency_check ${JSON.stringify({ items })} for a proceed/review/avoid verdict on each version (advisories, yanks, release age; for a range, its safe releases).\n`
    : "";
  const tail = ecosystem
    ? "Before building, call the 4da MCP tool upgrade_impact for each upgraded package: it lists the breaking changes between the versions and the files in this project that use the package."
    : "Before building, call the 4da MCP tool what_should_i_know with the upgrade as the task, and vulnerability_scan after installing.";
  return `4DA: this edit changes dependency versions in ${file}:\n${lines.join("\n")}${more}\n${check}${tail}`;
}

async function main() {
  let raw = "";
  for await (const chunk of process.stdin) raw += chunk;
  let input;
  try {
    input = JSON.parse(raw);
  } catch {
    return;
  }
  const toolInput = input?.tool_input ?? {};
  const file = basename(String(toolInput.file_path ?? ""));
  if (!MANIFESTS.has(file)) return;

  let changes = [];
  const disk = onDisk(String(toolInput.file_path));
  if (input.tool_name === "Edit") {
    changes = versionChanges(file, toolInput.old_string ?? "", toolInput.new_string ?? "", disk);
  } else if (input.tool_name === "MultiEdit" && Array.isArray(toolInput.edits)) {
    changes = toolInput.edits.flatMap((e) => versionChanges(file, e?.old_string ?? "", e?.new_string ?? "", disk));
  }
  // Write replaces the whole file and its payload carries no "before": stay quiet
  // rather than report every dependency as changed.
  if (changes.length === 0) return;

  process.stdout.write(
    JSON.stringify({ hookSpecificOutput: { hookEventName: "PostToolUse", additionalContext: adviceFor(file, changes) } }),
  );
}

main().catch(() => {
  // A hook must never fail the edit it observes.
});
