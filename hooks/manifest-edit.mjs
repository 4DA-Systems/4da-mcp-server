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

/**
 * For a JSON snippet, the object each position sits in, read in one forward pass (r8: a backward
 * scan per key made a very large edit quadratic). Returns `at(index)`: the key of the innermost
 * object or array open at `index`, "" for the top level when the snippet starts with it, or null
 * when the snippet does not show it (it closed more than it opened, or the object has no key).
 */
function jsonSections(text) {
  const events = [];
  const stack = [];
  let unseen = false;
  let inString = false;
  let lastString = null;
  let stringStart = -1;
  let keyBeforeColon = null;
  let seenNonSpace = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (inString) {
      if (ch === "\\") i++;
      else if (ch === '"') {
        inString = false;
        lastString = text.slice(stringStart + 1, i);
      }
      continue;
    }
    if (ch === '"') {
      inString = true;
      stringStart = i;
      seenNonSpace = true;
      continue;
    }
    if (ch === ":") keyBeforeColon = lastString;
    else if (ch === "{" || ch === "[") {
      stack.push(keyBeforeColon !== null ? keyBeforeColon : ch === "{" && !seenNonSpace ? "" : null);
      events.push({ index: i, key: stack[stack.length - 1], depth: stack.length, unseen });
      keyBeforeColon = null;
    } else if (ch === "}" || ch === "]") {
      // Closing an object the snippet never opened: what follows sits somewhere it does not show.
      if (stack.length > 0) stack.pop();
      else unseen = true;
      events.push({ index: i, key: stack.length > 0 ? stack[stack.length - 1] : null, depth: stack.length, unseen });
      keyBeforeColon = null;
    } else if (ch === ",") keyBeforeColon = null;
    if (!/\s/.test(ch)) seenNonSpace = true;
  }
  return (index) => {
    const e = lastBefore(events, index);
    return !e || e.depth === 0 ? null : e.key;
  };
}

/** The last of `events` (sorted by index) that starts before `index`, by binary search; null when none. */
function lastBefore(events, index) {
  let lo = 0;
  let hi = events.length - 1;
  let found = -1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    if (events[mid].index < index) {
      found = mid;
      lo = mid + 1;
    } else hi = mid - 1;
  }
  return found < 0 ? null : events[found];
}

/** For a TOML text, the table each position sits under, from its headers read once: `at(index)`, or null before any header. */
function tomlTables(text) {
  const headers = [...text.matchAll(/^[ \t]*\[{1,2}[ \t]*([^\]\n]+?)[ \t]*\]{1,2}[ \t]*$/gm)].map((m) => ({ index: m.index, name: m[1].replace(/\s+/g, "") }));
  return (index) => lastBefore(headers, index)?.name ?? null;
}

/**
 * The edited manifest as it is now on disk (PostToolUse: the edit is already written), read once,
 * its JSON sections and TOML tables computed once; null when unreadable.
 */
function onDisk(path) {
  let cached;
  return () => {
    if (cached !== undefined) return cached;
    try {
      const text = readFileSync(path, "utf8");
      let json;
      let toml;
      let parsed;
      cached = {
        text,
        json: () => (json ??= jsonSections(text)),
        toml: () => (toml ??= tomlTables(text)),
        parsed: () => {
          if (parsed === undefined) {
            try {
              parsed = JSON.parse(text);
            } catch {
              parsed = null;
            }
          }
          return parsed;
        },
      };
    } catch {
      cached = null;
    }
    return cached;
  };
}

/** Where on disk a snippet of the edit starts (the new text is there after the edit): -1 unless found exactly once. */
function placeOnDisk(disk, snippet) {
  const file = disk();
  if (!file || !snippet) return -1;
  const at = file.text.indexOf(snippet);
  return at >= 0 && file.text.indexOf(snippet, at + 1) < 0 ? at : -1;
}

/**
 * Whether `name` in a package.json is a dependency: the snippet's own section when it shows it, else
 * where the edit sits in the file on disk, else the file's dependency sections; a key the file has
 * only outside them is not one.
 */
function npmDependency(section, place, name, disk) {
  if (section !== null) return NPM_DEPENDENCY_SECTIONS.has(section);
  const file = disk();
  if (file && place >= 0) {
    const there = file.json()(place);
    if (there !== null) return NPM_DEPENDENCY_SECTIONS.has(there);
  }
  const doc = file?.parsed();
  if (doc && typeof doc === "object") {
    const inDeps = [...NPM_DEPENDENCY_SECTIONS].some((s) => doc[s] && typeof doc[s] === "object" && Object.hasOwn(doc[s], name));
    if (inDeps) return true;
    const elsewhere = Object.hasOwn(doc, name) || (doc.engines && Object.hasOwn(doc.engines, name)) || (doc.volta && Object.hasOwn(doc.volta, name));
    if (elsewhere) return false;
  }
  return !NPM_NOT_DEPENDENCIES.has(name);
}

const escapeRegex = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/** The dependency a TOML key under `table` declares, or null. */
function dependencyIn(table, key) {
  const one = TOML_ONE_DEPENDENCY.exec(table);
  if (one) return key === "version" ? one[1] : null;
  if (!TOML_DEPENDENCY_TABLE.test(table)) return null;
  return TOML_NOT_DEPENDENCIES.has(key.toLowerCase()) ? null : key;
}

/**
 * The dependency a TOML `key = ...` line declares, or null: the snippet's table when it shows one,
 * else the table the edit sits under on disk, else the tables that very line stands under on disk.
 * `[dependencies.serde]` + `version = "1.0.200"` is serde's even when `[package]` has a `version`
 * line too (r8: the file's first `version =`, the package's own, decided it, and the edit was
 * ignored although the CHANGELOG said it was fixed).
 */
function tomlDependency(table, place, line, key, disk) {
  if (table === null) {
    const file = disk();
    if (file && place >= 0) table = file.toml()(place);
    if (table === null && file) {
      // Every place this exact line stands in the file: a dependency in any of them is one.
      const at = new RegExp(`^[ \\t]*${escapeRegex(line.trim())}`, "gm");
      const tables = [...file.text.matchAll(at)].map((m) => file.toml()(m.index) ?? "");
      if (tables.length > 0) {
        for (const t of tables) {
          const name = dependencyIn(t, key);
          if (name) return name;
        }
        return null;
      }
    }
  }
  if (table !== null) return dependencyIn(table, key);
  return TOML_NOT_DEPENDENCIES.has(key.toLowerCase()) ? null : key;
}

/**
 * name -> version specifier pairs a manifest snippet declares, in its dependency sections only.
 * `place` is where the snippet starts in the file on disk (-1 when unknown).
 */
function declaredVersions(file, text, disk = () => null, place = -1) {
  const out = new Map();
  if (typeof text !== "string" || !text) return out;
  const at = (index) => (place >= 0 ? place + index : -1);
  if (file === "package.json") {
    const sections = jsonSections(text);
    for (const m of text.matchAll(/"(@?[a-z0-9][\w.\-/]*)"\s*:\s*"([~^<>=]*\s*v?\d[^"]*)"/gi)) {
      if (npmDependency(sections(m.index), at(m.index), m[1], disk)) out.set(m[1], m[2]);
    }
  } else if (file === "Cargo.toml") {
    const tables = tomlTables(text);
    for (const m of text.matchAll(/^[ \t]*([A-Za-z_][\w-]*)[ \t]*=[ \t]*"([~^<>=]*\s*\d[^"]*)"/gm)) {
      const name = tomlDependency(tables(m.index), at(m.index), m[0], m[1], disk);
      if (name) out.set(name, m[2]);
    }
    for (const m of text.matchAll(/^[ \t]*([A-Za-z_][\w-]*)[ \t]*=[ \t]*\{[^}\n]*\bversion\s*=\s*"([^"]+)"/gm)) {
      const name = tomlDependency(tables(m.index), at(m.index), m[0], m[1], disk);
      if (name) out.set(name, m[2]);
    }
  } else if (file === "pyproject.toml" || file === "requirements.txt") {
    // A requirement string ("requests>=2.31") is a dependency wherever it is written.
    for (const m of text.matchAll(/["']?([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*(===?|~=|>=)\s*([0-9][^"',;\s]*)/g)) out.set(m[1].toLowerCase(), `${m[2]}${m[3]}`);
    if (file === "pyproject.toml") {
      const tables = tomlTables(text);
      for (const m of text.matchAll(/^[ \t]*([A-Za-z0-9][A-Za-z0-9._-]*)[ \t]*=[ \t]*"([~^<>=]*\s*\d[^"]*)"/gm)) {
        const name = tomlDependency(tables(m.index), at(m.index), m[0], m[1], disk);
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
  if (typeof after !== "string") return [];
  // Where the edit sits in the file: the new text is on disk now, and the old text stood at the same place.
  const place = placeOnDisk(disk, after);
  const old = declaredVersions(file, typeof before === "string" ? before : "", disk, place);
  const changes = [];
  for (const [name, spec] of declaredVersions(file, after, disk, place)) {
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
    // One malformed edit never hides the valid ones beside it (r8: a non-string old_string threw, and
    // the whole MultiEdit said nothing).
    for (const e of toolInput.edits) {
      try {
        for (const c of versionChanges(file, e?.old_string ?? "", e?.new_string ?? "", disk)) changes.push(c);
      } catch {
        // This edit is not one the hook can read; the others still count.
      }
    }
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
