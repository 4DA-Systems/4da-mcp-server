#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
/**
 * The 4DA guard: a Claude Code plugin hook that stops a dependency version from being written or
 * installed before `dependency_check` has judged it.
 *
 * PreToolUse on Edit / MultiEdit / Write (a manifest) and Bash / PowerShell (an install command),
 * the default: each dependency version the call would introduce is looked up in the check ledger
 * the server writes in its data folder (src/check-ledger.ts), entries of the last 24 hours only.
 * - An exact version with a `proceed` or `review` verdict goes ahead, silently.
 * - One with an `avoid` or `wait` verdict is denied with that verdict's reason.
 * - One with no verdict, or only an `unknown` one, is denied with the `dependency_check` call to
 *   make; the call goes through once it answers proceed.
 * - A range or constraint is denied only when the ledger has no verdict for the package at all
 *   (the server resolves a constraint to exact releases; this hook does not), or when its own last
 *   verdict for that same constraint was `avoid` or `wait`.
 * - A package the server recorded as private (never looked up) goes ahead.
 * A command this hook does not take apart exactly (a variable, a substitution, a heredoc, a
 * custom registry or index, a git or path source), a bare `npm install` or `npm ci`, and a
 * package named without a version all go ahead without comment.
 *
 * FOURDA_GUARD=advise: never denies; after a manifest edit (PostToolUse) the agent is told which
 * versions moved and which calls check them. FOURDA_GUARD=off: the hook does nothing.
 *
 * It denies only where a ledger exists. A server from 6.5.0 on starts one when it starts; a
 * server before 6.5.0 records no verdict, so beside one a denied call could never pass. With no
 * ledger file in the data folder the hook works as it did before 6.5.0: nothing is denied, and
 * the advice follows a manifest edit.
 *
 * It fails open: an error of its own, a payload it does not understand, a data folder that does
 * not exist, or its own time limit ends it with exit 0 and no output. No network, no
 * dependencies, plain Node.
 *
 * Names and versions it repeats come from the edit or command, which may quote a third party's
 * manifest, so each is held to its shape first (NAME_TEXT, specText).
 */

import { existsSync, readFileSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, join } from "node:path";

const MANIFESTS = new Set(["package.json", "Cargo.toml", "pyproject.toml", "requirements.txt", "go.mod", "pnpm-workspace.yaml"]);
/** The largest hook payload read (characters). */
const MAX_INPUT_CHARS = 8 * 1024 * 1024;
/** The largest manifest read from disk (bytes): a manifest is kilobytes. */
const MAX_MANIFEST_BYTES = 8 * 1024 * 1024;
/** The longest command line taken apart (characters). */
const MAX_COMMAND_CHARS = 64 * 1024;
/** The hook ends itself, silently, before Claude Code's own timeout (hooks.json: 10 s). */
const SELF_LIMIT_MS = 8000;
/** How long a dependency_check verdict counts. */
const LEDGER_WINDOW_MS = 24 * 60 * 60 * 1000;
/** The ledger files the server writes (src/check-ledger.ts): the previous one is read first. */
const LEDGER_FILES = ["check-ledger.1.jsonl", "check-ledger.jsonl"];
/** A ledger file larger than this is not read (the server keeps each under 512 KB). */
const MAX_LEDGER_BYTES = 4 * 1024 * 1024;
/** dependency_check takes at most this many items per call. */
const MAX_CALL_ITEMS = 25;

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
/** pnpm-workspace.yaml sections that set dependency versions. */
const PNPM_VERSION_SECTIONS = new Set(["catalog", "catalogs", "overrides"]);

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
  // Read line by line, by hand: one pattern for the whole header line is cubic on a line of `[`
  // followed by blanks, and this runs on a file the edit did not write.
  const headers = [];
  let index = 0;
  for (const line of text.split("\n")) {
    const t = line.trim();
    if (t.startsWith("[") && t.endsWith("]")) {
      const inner = t.replace(/^\[{1,2}/, "").replace(/\]{1,2}$/, "");
      if (inner.trim() && !inner.includes("]") && !inner.includes("[")) headers.push({ index, name: inner.replace(/\s+/g, "") });
    }
    index += line.length + 1;
  }
  return (at) => lastBefore(headers, at)?.name ?? null;
}

/** A manifest's text as context: its JSON sections and TOML tables computed once, on demand. */
function fileContext(text) {
  let json;
  let toml;
  let parsed;
  return {
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
}

/** A manifest's text from disk, or null when it is missing, unreadable or far larger than a manifest. */
function readManifest(path) {
  try {
    if (statSync(path).size > MAX_MANIFEST_BYTES) return null;
    return readFileSync(path, "utf8");
  } catch {
    return null;
  }
}

/** The edited manifest as it is now on disk (PostToolUse: the edit is already written), read once; null when unreadable. */
function onDisk(path) {
  let cached;
  return () => {
    if (cached !== undefined) return cached;
    const text = readManifest(path);
    cached = text === null ? null : fileContext(text);
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

/** Whole-file lookups one hook run may make, and the longest line looked up. */
const MAX_LINE_LOOKUPS = 200;
const MAX_LOOKUP_LINE = 2000;
let lookups = 0;

/**
 * The dependency a TOML `key = ...` line declares, or null: the snippet's table when it shows one,
 * else the table the edit sits under on disk, else the tables that very line stands under on disk.
 * `[dependencies.serde]` + `version = "1.0.200"` is serde's even when `[package]` has a `version`
 * line too (r8: the file's first `version =`, the package's own, decided it).
 */
function tomlDependency(table, place, line, key, disk) {
  if (table === null) {
    const file = disk();
    if (file && place >= 0) table = file.toml()(place);
    if (table === null && file && line.length <= MAX_LOOKUP_LINE && lookups++ < MAX_LINE_LOOKUPS) {
      // Every place this exact line stands in the file: a dependency in any of them is one.
      // Each lookup reads the whole file, so an edit gets a bounded number of them.
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

/** One PEP 440 clause, and a set of them joined by commas. */
const PEP440_CLAUSE = String.raw`(?:===|==|~=|!=|<=|>=|<|>)\s*[0-9A-Za-z*.+!_-]{1,80}`;
const PEP440_SPECIFIERS = new RegExp(String.raw`^(${PEP440_CLAUSE}(?:\s*,\s*${PEP440_CLAUSE}){0,7})`);

/**
 * A requirements-file line (pip's format) as name and specifier set, or null: comments, options
 * (`-r`, `-e`, `--hash`), direct references (`name @ url`) and paths name no version.
 */
function requirementLine(line) {
  const text = line.replace(/(^|\s)#.*$/, "").trim();
  if (!text || text.startsWith("-")) return null;
  const m = /^([A-Za-z0-9][A-Za-z0-9._-]{0,99})(?![A-Za-z0-9._-])\s*(?:\[[^\]\n]{0,200}\])?\s*\(?\s*/.exec(text);
  if (!m) return null;
  const rest = text.slice(m[0].length);
  const spec = PEP440_SPECIFIERS.exec(rest);
  return spec ? { name: m[1].toLowerCase(), spec: spec[1].replace(/\s+/g, "") } : null;
}

/** A YAML plain or quoted scalar on one line, its comment dropped; null when empty or not a scalar. */
function yamlScalar(raw) {
  if (raw === undefined) return null;
  let v = raw.trim();
  if (v.startsWith("'") || v.startsWith('"')) {
    const q = v[0];
    const end = v.indexOf(q, 1);
    return end > 1 ? v.slice(1, end) : null;
  }
  v = v.replace(/\s+#.*$/, "").trim();
  if (!v || /^[[{&*!|>%@`]/.test(v)) return null;
  return v;
}

/**
 * pnpm-workspace.yaml: the versions its `catalog`, named `catalogs` and `overrides` set, keyed by
 * name and section (the same package in two catalogs is two entries). Only plain `key: value`
 * lines are read; flow mappings and anchors are not.
 */
function pnpmWorkspaceVersions(text, out) {
  let top = null;
  let catalog = null;
  let catalogIndent = -1;
  for (const raw of text.split("\n")) {
    const line = raw.replace(/\r$/, "");
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const indent = line.length - line.trimStart().length;
    const m = /^\s*(?:'([^'\n]{1,214})'|"([^"\n]{1,214})"|([^\s:#'"][^:#\n]{0,213}?))\s*:(?:\s+(.*))?$/.exec(line);
    if (indent === 0) {
      top = m && yamlScalar(m[4]) === null && PNPM_VERSION_SECTIONS.has(m[3] ?? "") ? m[3] : null;
      catalog = null;
      continue;
    }
    if (!m || top === null) continue;
    const key = m[1] ?? m[2] ?? m[3];
    const value = yamlScalar(m[4]);
    if (top === "catalogs" && value === null) {
      catalog = key;
      catalogIndent = indent;
      continue;
    }
    if (value === null || !/^[~^<>=*\dvxX]/.test(value)) continue;
    // An override keyed by a selector ("foo@<2", "bar>qs") is not one package's version.
    if (top === "overrides" && /.@|>/.test(key)) continue;
    if (top === "catalogs" && (catalog === null || indent <= catalogIndent)) continue;
    out.set(`${key}\0${top === "catalogs" ? `catalogs.${catalog}` : top}`, value);
  }
}

/**
 * name -> version specifier pairs a manifest snippet declares, in its dependency sections only.
 * `place` is where the snippet starts in the file on disk (-1 when unknown). A key may carry the
 * section after a NUL (pnpm catalogs) so one name in two places is two entries.
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
  } else if (file === "Cargo.toml" || file === "pyproject.toml") {
    const python = file === "pyproject.toml";
    const fold = (name) => (python ? name.toLowerCase() : name);
    if (python) {
      // A requirement string ("requests>=2.31") is a dependency wherever it is written.
      // A name starts where no name character precedes it and is at most 100 characters (PyPI's own
      // limit is far lower): without both, one unbroken token of 100,000 characters costs its square.
      for (const m of text.matchAll(/(?<![A-Za-z0-9._-])([A-Za-z0-9][A-Za-z0-9._-]{0,99})(?:\[[^\]\n]{0,200}\])?[ \t]*((?:===?|~=|>=|<=|!=|<|>)[ \t]*[0-9][^"',;\s]{0,80}(?:[ \t]*,[ \t]*(?:===?|~=|>=|<=|!=|<|>)[ \t]*[0-9][^"',;\s]{0,80}){0,7})/g)) {
        out.set(m[1].toLowerCase(), m[2].replace(/[ \t]+/g, ""));
      }
    }
    const tables = tomlTables(text);
    const key = python ? "[A-Za-z0-9][A-Za-z0-9._-]*" : "[A-Za-z_][\\w-]*";
    for (const m of text.matchAll(new RegExp(`^[ \\t]*(${key})[ \\t]*=[ \\t]*"([~^<>=]*\\s*\\d[^"]*)"`, "gm"))) {
      const name = tomlDependency(tables(m.index), at(m.index), m[0], m[1], disk);
      if (name) out.set(fold(name), m[2]);
    }
    for (const m of text.matchAll(new RegExp(`^[ \\t]*(${key})[ \\t]*=[ \\t]*\\{[^}\\n]*\\bversion\\s*=\\s*"([^"]+)"`, "gm"))) {
      const name = tomlDependency(tables(m.index), at(m.index), m[0], m[1], disk);
      if (name) out.set(fold(name), m[2]);
    }
  } else if (file === "requirements.txt") {
    for (const line of text.split("\n")) {
      const r = requirementLine(line);
      if (r) out.set(r.name, r.spec);
    }
  } else if (file === "go.mod") {
    for (const m of text.matchAll(/^\s*(?:require\s+)?([a-z0-9.-]+\.[a-z]{2,}\/\S+)\s+(v\d\S*)/gm)) out.set(m[1], m[2]);
  } else if (file === "pnpm-workspace.yaml") {
    pnpmWorkspaceVersions(text, out);
  }
  return out;
}

/** The package name of a declaredVersions key (which may carry its section after a NUL). */
const keyName = (key) => key.split("\0")[0];

/** Changed or added dependency versions between two snippets of one manifest. */
function versionChanges(file, before, after, disk) {
  if (typeof after !== "string") return [];
  // Where the edit sits in the file: the new text is on disk now, and the old text stood at the same place.
  const place = placeOnDisk(disk, after);
  const old = declaredVersions(file, typeof before === "string" ? before : "", disk, place);
  return diffVersions(old, declaredVersions(file, after, disk, place));
}

/** Changed or added entries between two declaredVersions maps. */
function diffVersions(old, now) {
  const changes = [];
  for (const [key, spec] of now) {
    const prev = old.get(key);
    if (prev !== spec) changes.push({ name: keyName(key), from: prev ?? null, to: spec });
  }
  return changes;
}

/** Changed or added dependency versions between two whole texts of one manifest (both show every section). */
function wholeFileChanges(file, before, after) {
  const versionsOf = (text) => {
    const context = fileContext(text);
    return declaredVersions(file, text, () => context, 0);
  };
  return diffVersions(versionsOf(before), versionsOf(after));
}

const ECOSYSTEM = {
  "package.json": "npm",
  "pnpm-workspace.yaml": "npm",
  "Cargo.toml": "crates.io",
  "pyproject.toml": "PyPI",
  "requirements.txt": "PyPI",
  "go.mod": "Go",
};

/** A full semver version, optionally spelled `=1.2.3` or `v1.2.3` (npm and Cargo read both as that release). */
const FULL_SEMVER = /^(?:={1,2}\s*)?v?(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)$/;
/** A bare PEP 440 release (Poetry and dependency_check read it as that one release). */
const PEP440_RELEASE = /^v?(\d+(?:\.\d+)*(?:(?:a|b|rc|\.post|\.dev|post|dev)\d+)*)$/i;
/** A full Go version: release, prerelease or pseudo-version, `+incompatible` allowed. */
const GO_EXACT = /^(v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+incompatible)?)$/;

/**
 * The exact version a specifier names, or null when it is a range: npm and Cargo `1.2.3`,
 * `=1.2.3` (Cargo's bare `1.2.3` is judged as that release, as dependency_check judges it), PyPI
 * `==2.0` / `===2.0` and Poetry's bare `2.0`, Go `v1.2.3`.
 */
function exactFor(ecosystem, spec) {
  const s = String(spec).trim();
  if (ecosystem === "PyPI") {
    const m = /^={2,3}\s*([^,*\s]+)$/.exec(s) ?? PEP440_RELEASE.exec(s);
    return m && PEP440_RELEASE.test(m[1]) ? m[1].replace(/^v/i, "") : null;
  }
  if (ecosystem === "Go") return GO_EXACT.exec(s)?.[1] ?? null;
  return FULL_SEMVER.exec(s)?.[1] ?? null;
}

/**
 * Poetry's caret and tilde constraints as the PEP 440 specifiers dependency_check reads (it
 * refuses `^2.19`): `^2.19` -> `>=2.19,<3`, `^0.2.3` -> `>=0.2.3,<0.3`, `~2.19` -> `>=2.19,<2.20`,
 * `~2` -> `>=2,<3`. Anything else is returned as it is.
 */
export function poetryToPep440(spec) {
  const m = /^([~^])\s*(\d+(?:\.\d+){0,2})$/.exec(String(spec).trim());
  if (!m) return String(spec).trim();
  const parts = m[2].split(".").map(Number);
  let bump;
  if (m[1] === "^") {
    bump = parts.findIndex((p) => p !== 0);
    if (bump < 0) bump = parts.length - 1;
  } else {
    bump = parts.length === 1 ? 0 : 1;
  }
  const upper = parts.slice(0, bump + 1);
  upper[bump] += 1;
  return `>=${m[2]},<${upper.join(".")}`;
}

/** The `to` of the dependency_check call for a specifier: its exact version, else the constraint as dependency_check reads it. */
function callTarget(ecosystem, spec) {
  const exactVersion = exactFor(ecosystem, spec);
  if (exactVersion) return exactVersion;
  const s = String(spec).trim();
  if (ecosystem === "PyPI") return s === "*" ? "latest" : poetryToPep440(s);
  return s;
}

/**
 * What the hook says is read by the agent, and the names and versions in it come from the edit's
 * own text (which may quote a third party's manifest). So each is held to its shape before it is
 * repeated: a name is a package name, and of a version only its leading run of version-spec
 * characters is kept. Text after that run (a comment, a sentence) is not a version and is dropped.
 */
const NAME_TEXT = /^[@A-Za-z0-9][\w.\-/~@]{0,213}$/;
/**
 * A version specifier is a sequence of comparator clauses: an optional operator (`^ ~ > < = !`
 * and their combinations), an optional `v`, then a version that starts with a digit and is made
 * of `[0-9A-Za-z.+_-]` and `*`/`x` wildcards; or a bare `*`. Clauses are joined by `||`, `,`,
 * ` - ` or a space. Reading stops at the first token that is not a clause, so a word or sentence
 * after a version ("4.17.21 IMPORTANT ...") is never repeated, and an operator or joiner left
 * dangling before it ("4.17.21 <", "1.2 ||") goes with it. At most SPEC_MAX characters are kept,
 * in whole clauses.
 */
const SPEC_CLAUSE = /(?:[~^<>=!]{1,3}\s*)?(?:v?\d[0-9A-Za-z.+_*-]*|\*)/y;
const SPEC_JOINER = /\s*\|\|\s*|\s*,\s*|\s+-\s+|\s+/y;
const SPEC_MAX = 80;
const specText = (spec) => {
  if (typeof spec !== "string") return "";
  const s = spec.trim().slice(0, SPEC_MAX * 2);
  let kept = "";
  let at = 0;
  for (let first = true; ; first = false) {
    let joiner = "";
    if (!first) {
      SPEC_JOINER.lastIndex = at;
      const j = SPEC_JOINER.exec(s);
      if (!j) break;
      joiner = j[0];
      at = SPEC_JOINER.lastIndex;
    }
    SPEC_CLAUSE.lastIndex = at;
    const c = SPEC_CLAUSE.exec(s);
    if (!c || kept.length + joiner.length + c[0].length > SPEC_MAX) break;
    kept += joiner + c[0];
    at = SPEC_CLAUSE.lastIndex;
  }
  return kept;
};

/** The changes fit to repeat: shaped names, cleaned versions, nothing else. */
function repeatable(changes) {
  const out = [];
  for (const c of changes) {
    if (typeof c?.name !== "string" || !NAME_TEXT.test(c.name)) continue;
    const to = specText(c.to);
    if (!to) continue;
    const from = c.from == null ? null : specText(c.from) || null;
    out.push({ name: c.name, from, to });
  }
  return out;
}

/** The advice given after a manifest edit (FOURDA_GUARD=advise). */
function adviceFor(file, changes) {
  const ecosystem = ECOSYSTEM[file] ?? null;
  const lines = changes.slice(0, 8).map((c) => {
    const target = ecosystem ? exactFor(ecosystem, c.to) : null;
    const call = ecosystem
      ? `; check with upgrade_impact ${JSON.stringify({ package: c.name, ...(target ? { to_version: target.replace(/^v(?=\d)/, "") } : {}), ecosystem })}`
      : "";
    return `- ${c.name}: ${c.from ?? "(added)"} -> ${c.to}${call}`;
  });
  const more = changes.length > 8 ? `\n- ...and ${changes.length - 8} more` : "";
  // An exact pin is checked as that version; a range ("^1.2", ">=2,<3") as a constraint, which
  // returns the smallest and newest safe release it admits. Go versions keep their `v`.
  const items = ecosystem ? changes.slice(0, MAX_CALL_ITEMS).map((c) => callItem(ecosystem, c.name, c.to, c.from)) : [];
  const check = items.length > 0
    ? `Before installing, call the 4da MCP tool dependency_check ${JSON.stringify({ items })} for a proceed/review/avoid verdict on each version (advisories, yanks, release age; for a range, its safe releases).\n`
    : "";
  const tail = ecosystem
    ? "Before building, call the 4da MCP tool upgrade_impact for each upgraded package: it lists the breaking changes between the versions and the files in this project that use the package."
    : "Before building, call the 4da MCP tool what_should_i_know with the upgrade as the task, and vulnerability_scan after installing.";
  return `4DA: this edit changes dependency versions in ${file}:\n${lines.join("\n")}${more}\n${check}${tail}`;
}

/** One dependency_check item: the exact version or the constraint, and the installed version when it is exact. */
function callItem(ecosystem, name, to, from) {
  const fromExact = from ? exactFor(ecosystem, from) : null;
  return { ecosystem, package: name, to: callTarget(ecosystem, to), ...(fromExact ? { from: fromExact } : {}) };
}

// =============================================================================
// Which file is a manifest
// =============================================================================

/** The manifest kind of a path (its ECOSYSTEM key), or null: `requirements-dev.txt` and `requirements/base.txt` read as requirements.txt. */
function manifestKind(filePath) {
  const name = basename(filePath);
  if (MANIFESTS.has(name)) return name;
  if (/^requirements[-_.][\w.-]*\.txt$/i.test(name)) return "requirements.txt";
  if (/\.txt$/i.test(name) && basename(dirname(filePath)).toLowerCase() === "requirements") return "requirements.txt";
  return null;
}

// =============================================================================
// Before the edit: the file as it will be
// =============================================================================

/**
 * `text` after one Edit, as Claude Code applies it, or null when it would refuse the edit: the old
 * text missing, or (without `replace_all`) found more than once. An empty old text creates a file.
 */
function applyEdit(text, oldString, newString, replaceAll) {
  if (typeof oldString !== "string" || typeof newString !== "string") return null;
  if (oldString === "") return text === "" ? newString : null;
  const first = text.indexOf(oldString);
  if (first < 0) return null;
  if (replaceAll === true) return text.split(oldString).join(newString);
  if (text.indexOf(oldString, first + 1) >= 0) return null;
  return text.slice(0, first) + newString + text.slice(first + oldString.length);
}

/** The edits of an Edit or MultiEdit payload, or null when it holds none in a shape this reads. */
function editsOf(toolName, toolInput) {
  if (toolName === "Edit") return [{ old_string: toolInput.old_string, new_string: toolInput.new_string, replace_all: toolInput.replace_all }];
  if (toolName === "MultiEdit" && Array.isArray(toolInput.edits)) return toolInput.edits.filter((e) => e && typeof e === "object");
  return null;
}

/**
 * The dependency versions an Edit, MultiEdit or Write of a manifest introduces. The file on disk
 * still holds its old text (PreToolUse), so the new text is built from it the way the tool will
 * write it, and the two whole files are compared. When it cannot be built (the old text is not
 * there, so the tool will refuse the edit), the edit's own snippets are compared instead.
 */
function introducedByEdit(kind, toolName, toolInput, path) {
  const disk = readManifest(path);
  if (toolName === "Write") {
    if (typeof toolInput.content !== "string") return [];
    return wholeFileChanges(kind, disk ?? "", toolInput.content);
  }
  const edits = editsOf(toolName, toolInput);
  if (!edits) return [];
  // Claude Code matches an edit against the file with its line endings read as "\n".
  for (const base of disk === null ? [""] : [disk, disk.replace(/\r\n/g, "\n")]) {
    let text = base;
    for (const e of edits) {
      text = text === null ? null : applyEdit(text, e.old_string, e.new_string, e.replace_all);
    }
    if (text !== null) return wholeFileChanges(kind, base, text);
  }
  const changes = [];
  for (const e of edits) {
    try {
      for (const c of versionChanges(kind, e.old_string ?? "", e.new_string ?? "", () => null)) changes.push(c);
    } catch {
      // This edit is not one the hook can read; the others still count.
    }
  }
  return changes;
}

// =============================================================================
// Install commands
// =============================================================================

/**
 * The simple commands of a command line, each as its words, or null when the line holds anything
 * this reader does not take apart exactly: a variable or command substitution, a subshell or
 * group, a heredoc, an escape it does not know, an unclosed quote. Redirections (`2>&1`,
 * `> out.txt`) are read and dropped. `dialect` is "bash" or "powershell".
 */
export function simpleCommands(line, dialect) {
  if (typeof line !== "string" || line.length > MAX_COMMAND_CHARS) return null;
  const commands = [];
  let words = [];
  let word = null;
  const endWord = () => {
    if (word !== null) words.push(word);
    word = null;
  };
  const endCommand = () => {
    endWord();
    if (words.length > 0) commands.push(words);
    words = [];
  };
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === "'") {
      const end = line.indexOf("'", i + 1);
      if (end < 0) return null;
      word = (word ?? "") + line.slice(i + 1, end);
      i = end;
    } else if (ch === '"') {
      const end = line.indexOf('"', i + 1);
      if (end < 0) return null;
      const inner = line.slice(i + 1, end);
      if (/[$`\\]/.test(inner)) return null;
      word = (word ?? "") + inner;
      i = end;
    } else if (ch === " " || ch === "\t") {
      endWord();
    } else if (ch === "\n" || ch === "\r" || ch === ";") {
      endCommand();
    } else if (ch === "&" || ch === "|") {
      endCommand();
      if (line[i + 1] === ch) i++;
    } else if (ch === "#" && word === null) {
      const nl = line.indexOf("\n", i);
      if (nl < 0) break;
      i = nl - 1;
    } else if (ch === ">" || ch === "<") {
      // A redirection: an fd number before it ("2>") belongs to it, and so does its target.
      if (ch === "<" && line[i + 1] === "<") return null;
      if (word !== null && /^(?:\d+|\*)$/.test(word)) word = null;
      endWord();
      let j = i + 1;
      if (line[j] === ">") j++;
      if (line[j] === "&") {
        j++;
        while (j < line.length && /[\d-]/.test(line[j])) j++;
        i = j - 1;
        continue;
      }
      while (line[j] === " " || line[j] === "\t") j++;
      const target = /^[^\s;&|<>()$`'"]+/.exec(line.slice(j));
      if (!target) return null;
      i = j + target[0].length - 1;
    } else if (dialect === "bash" && ch === "\\") {
      if (line[i + 1] === "\n") i++;
      else if (line[i + 1] === "\r" && line[i + 2] === "\n") i += 2;
      else return null;
    } else if ("$`(){}".includes(ch)) {
      return null;
    } else if (dialect === "powershell" && ((ch === "@" && word === null) || ch === "," || (ch === "-" && word === null && line.startsWith("--%", i)))) {
      // PowerShell reads an unquoted `@name` as splatting and `a,b` as an array.
      return null;
    } else {
      word = (word ?? "") + ch;
    }
  }
  endCommand();
  return commands;
}

/** A program's name as typed: its last path part, lower case, without .exe / .cmd / .bat / .ps1. */
function programName(word) {
  return word.split(/[\\/]/).pop().toLowerCase().replace(/\.(?:exe|cmd|bat|ps1)$/, "");
}

/** Words that run the command after them unchanged. */
const WRAPPERS = new Set(["sudo", "env", "time", "command", "nohup", "corepack"]);

/**
 * The operands of a command's arguments, or null when one of `refuse` is given (a custom
 * registry or index, a git or path source: the package is not the public one this hook can name).
 * `values`: options that take the next word as their value.
 */
function operands(args, { values = new Set(), refuse = new Set() }) {
  const out = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--") {
      out.push(...args.slice(i + 1));
      break;
    }
    if (a.startsWith("-") && a.length > 1) {
      const flag = a.includes("=") ? a.slice(0, a.indexOf("=")) : a;
      if (refuse.has(flag) || flag.startsWith("--@")) return null;
      if (!a.includes("=") && values.has(flag)) i++;
      continue;
    }
    out.push(a);
  }
  return out;
}

/** A version or range after `@` in a JS package manager's spec, or null for a tag, alias, git or URL source. */
function jsVersion(text) {
  if (!text || /[/:]/.test(text) || text.startsWith("npm:")) return null;
  if (exactFor("npm", text)) return text;
  return specText(text) === text.trim() && /^[~^<>=*\dvxX]/.test(text) ? text : null;
}

const NPM_SPEC = /^((?:@[a-z0-9][a-z0-9._~-]*\/)?[a-z0-9._~][a-z0-9._~-]*)@(.+)$/i;
const CARGO_SPEC = /^([A-Za-z0-9_][A-Za-z0-9_-]*)@(.+)$/;
const GO_SPEC = /^([A-Za-z0-9][A-Za-z0-9._~-]*\.[A-Za-z]{2,}(?:\/[A-Za-z0-9._~+-]+)*)@(.+)$/;
const PEP508_NAME = /^([A-Za-z0-9][A-Za-z0-9._-]{0,99})(?![A-Za-z0-9._-])\s*(?:\[[^\]]{0,200}\])?\s*/;

/** `name==1.2`, `name>=2,<3`, `name[extra]~=1.4` as name and specifier set; null without a specifier, or for a direct reference. */
function pep508(word) {
  if (word.includes("@") || word.includes("://")) return null;
  const m = PEP508_NAME.exec(word);
  if (!m) return null;
  const rest = word.slice(m[0].length).replace(/\s*;.*$/, "");
  const spec = PEP440_SPECIFIERS.exec(rest);
  return spec && spec[1].length === rest.trim().length ? { name: m[1], spec: spec[1].replace(/\s+/g, "") } : null;
}

/** Poetry's `name@^1.2` / `name@1.2.3` / `name==1.2.3` / `"name>=1.2"`; null for `@latest`, git, URL or path sources. */
function poetrySpec(word) {
  const at = /^([A-Za-z0-9][A-Za-z0-9._-]{0,99})(?:\[[^\]]{0,200}\])?@(.+)$/.exec(word);
  if (at) {
    const v = at[2].trim();
    if (v.toLowerCase() === "latest" || /[/:]/.test(v)) return null;
    if (exactFor("PyPI", v) || /^[~^]\s*\d/.test(v)) return { name: at[1], spec: v };
    const set = PEP440_SPECIFIERS.exec(v);
    return set && set[1].length === v.length ? { name: at[1], spec: v } : null;
  }
  return pep508(word);
}

const JS_VALUES = {
  npm: new Set(["--prefix", "-w", "--workspace", "--tag", "--loglevel", "--cache", "--userconfig", "--globalconfig", "--omit", "--include", "--install-strategy", "--before", "--otp", "--save-prefix", "--scope", "--script-shell", "-C"]),
  pnpm: new Set(["--filter", "-F", "-C", "--dir", "--reporter", "--store-dir", "--virtual-store-dir", "--modules-dir", "--lockfile-dir", "--config", "--save-catalog-name", "--loglevel", "--workspace-concurrency", "--network-concurrency", "--child-concurrency", "--resolution-mode", "--node-linker"]),
  yarn: new Set(["--cwd", "--network-timeout", "--mutex", "--cache-folder", "--modules-folder", "--global-folder", "--link-folder", "--use-yarnrc"]),
  bun: new Set(["--cwd", "--config", "-c", "--backend", "--cache-dir", "--network-concurrency", "--concurrent-scripts"]),
};
const JS_SUBCOMMANDS = { npm: new Set(["install", "i", "add", "in"]), pnpm: new Set(["add", "install", "i"]), yarn: new Set(["add"]), bun: new Set(["add"]) };
const REGISTRY = new Set(["--registry"]);
const CARGO_VALUES = new Set(["-F", "--features", "--rename", "-p", "--package", "--manifest-path", "--target", "--config", "-Z", "--color", "--lockfile-path"]);
const CARGO_REFUSE = new Set(["--git", "--path", "--registry", "--branch", "--tag", "--rev", "--index"]);
const PY_INDEX = new Set(["-i", "--index-url", "--extra-index-url", "--index", "--default-index", "-f", "--find-links"]);
const PIP_VALUES = new Set(["-r", "--requirement", "-c", "--constraint", "-e", "--editable", "-t", "--target", "--prefix", "--root", "--trusted-host", "--python-version", "--platform", "--implementation", "--abi", "--src", "--cache-dir", "--log", "--proxy", "--timeout", "--retries", "--progress-bar", "--upgrade-strategy", "--no-binary", "--only-binary", "--config-settings", "-C", "--global-option", "--report", "--python", "-p", "--exclude-newer", "--index-strategy", "--keyring-provider", "--resolution", "--prerelease", "--link-mode", "--override", "--overrides", "--group", "--extra", "--python-platform", "--torch-backend", "--build-constraint", "-b"]);
const UV_ADD_VALUES = new Set(["--group", "--optional", "--extra", "--package", "--project", "--directory", "--python", "-p", "--marker", "-m", "--bounds", "--script", "--config-file", "--cache-dir", "-r", "--requirements", "-c", "--constraints", "--tag", "--branch", "--rev", "--refresh-package", "--reinstall-package", "--upgrade-package", "-P", "--no-binary-package", "--no-build-package", "--exclude-newer", "--link-mode", "--keyring-provider", "--resolution", "--prerelease", "--fork-strategy", "--index-strategy", "--python-preference", "--color"]);
const POETRY_VALUES = new Set(["--group", "-G", "--extras", "-E", "--python", "--platform", "--markers", "--directory", "-C", "--project", "-P", "--optional"]);
const GO_VALUES = new Set(["-C", "-tags", "-modfile", "-ldflags", "-gcflags", "-asmflags", "-mod", "-o", "-p", "-pkgdir", "-toolexec"]);

/** A JS package manager's `add`/`install`: its global options, the subcommand, then the specs. */
function jsInstalls(manager, args) {
  const all = operands(args, { values: JS_VALUES[manager], refuse: REGISTRY });
  if (!all || all.length === 0 || !JS_SUBCOMMANDS[manager].has(all[0])) return [];
  const out = [];
  for (const word of all.slice(1)) {
    const m = NPM_SPEC.exec(word);
    const version = m ? jsVersion(m[2]) : null;
    if (version) out.push({ ecosystem: "npm", name: m[1], spec: version });
  }
  return out;
}

/** `pip install` (and `uv pip install`, `python -m pip install`) specs. */
function pipInstalls(args) {
  const all = operands(args, { values: PIP_VALUES, refuse: PY_INDEX });
  if (!all || all[0] !== "install") return [];
  return all.slice(1).flatMap((w) => {
    const r = pep508(w);
    return r ? [{ ecosystem: "PyPI", name: r.name, spec: r.spec }] : [];
  });
}

/** The dependency versions one simple command installs by name, or [] when it names none this hook reads. */
function commandInstalls(words) {
  let i = 0;
  for (;;) {
    while (i < words.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(words[i])) i++;
    if (i < words.length && WRAPPERS.has(programName(words[i]))) {
      i++;
      // A wrapper given options of its own (`sudo -u x`) is not read further.
      if (i < words.length && words[i].startsWith("-")) return [];
      continue;
    }
    break;
  }
  if (i >= words.length) return [];
  const program = programName(words[i]);
  const args = words.slice(i + 1);
  if (program === "npm" || program === "pnpm" || program === "yarn" || program === "bun") return jsInstalls(program, args);
  if (program === "cargo") {
    const all = operands(args, { values: CARGO_VALUES, refuse: CARGO_REFUSE });
    if (!all || all[0] !== "add") return [];
    return all.slice(1).flatMap((w) => {
      const m = CARGO_SPEC.exec(w);
      const v = m ? m[2].trim() : null;
      return v && (exactFor("crates.io", v) || specText(v) === v) ? [{ ecosystem: "crates.io", name: m[1], spec: v }] : [];
    });
  }
  if (/^pip(?:\d+(?:\.\d+)*)?$/.test(program)) return pipInstalls(args);
  if (/^python(?:\d+(?:\.\d+)*)?$/.test(program) || program === "py") {
    if (args[0] === "-m" && /^pip(?:\d+(?:\.\d+)*)?$/.test(args[1] ?? "")) return pipInstalls(args.slice(2));
    return [];
  }
  if (program === "uv") {
    if (args[0] === "pip") return pipInstalls(args.slice(1));
    const all = operands(args, { values: UV_ADD_VALUES, refuse: PY_INDEX });
    if (!all || all[0] !== "add") return [];
    return all.slice(1).flatMap((w) => {
      const r = pep508(w);
      return r ? [{ ecosystem: "PyPI", name: r.name, spec: r.spec }] : [];
    });
  }
  if (program === "poetry") {
    const all = operands(args, { values: POETRY_VALUES, refuse: new Set(["--source"]) });
    if (!all || all[0] !== "add") return [];
    return all.slice(1).flatMap((w) => {
      const r = poetrySpec(w);
      return r ? [{ ecosystem: "PyPI", name: r.name, spec: r.spec }] : [];
    });
  }
  if (program === "go") {
    const all = operands(args, { values: GO_VALUES });
    if (!all || all[0] !== "get") return [];
    return all.slice(1).flatMap((w) => {
      const m = GO_SPEC.exec(w);
      if (!m || m[1].includes("...")) return [];
      const v = m[2];
      return GO_EXACT.test(v) || /^v\d+(?:\.\d+)?$/.test(v) ? [{ ecosystem: "Go", name: m[1], spec: v }] : [];
    });
  }
  return [];
}

/** Every dependency version a command line installs by name; [] when it holds none, or anything this hook does not read. */
export function installsIn(command, dialect) {
  const commands = simpleCommands(command, dialect);
  if (!commands) return [];
  const seen = new Set();
  const out = [];
  for (const words of commands) {
    for (const r of commandInstalls(words)) {
      const key = `${r.ecosystem}\0${r.name}\0${r.spec}`;
      if (!seen.has(key)) {
        seen.add(key);
        out.push(r);
      }
    }
  }
  return out;
}

// =============================================================================
// The ledger
// =============================================================================

/** The server's data folder, as src/db.ts serverDataDir() finds it. */
export function dataDir(env = process.env, platform = process.platform, home = homedir()) {
  const override = env.FOURDA_MCP_HOME?.trim();
  if (override) return override;
  const base =
    platform === "win32"
      ? env.LOCALAPPDATA || join(home, "AppData", "Local")
      : platform === "darwin"
        ? join(home, "Library", "Application Support")
        : env.XDG_DATA_HOME || join(home, ".local", "share");
  return join(base, "4da-mcp");
}

/**
 * Whether `dir` holds a ledger file, of any size or content. A server from 6.5.0 on starts one when
 * it starts (src/check-ledger.ts startLedger); a folder without one has only had servers that
 * record no verdict, or none at all.
 */
function ledgerStarted(dir) {
  return LEDGER_FILES.some((file) => existsSync(join(dir, file)));
}

/**
 * The ledger entries of the last 24 hours in `dir`, oldest first; null when there is no ledger to
 * hold an edit to: the folder does not exist (no server has run with this data folder), or it
 * holds no ledger file (the servers that ran there are older than 6.5.0 and record no verdict, so
 * a call stopped here could never pass).
 */
function readLedger(dir, now) {
  if (!existsSync(dir) || !ledgerStarted(dir)) return null;
  const entries = [];
  for (const file of LEDGER_FILES) {
    let text;
    try {
      const path = join(dir, file);
      if (statSync(path).size > MAX_LEDGER_BYTES) continue;
      text = readFileSync(path, "utf8");
    } catch {
      continue;
    }
    for (const line of text.split("\n")) {
      if (!line) continue;
      let e;
      try {
        e = JSON.parse(line);
      } catch {
        continue;
      }
      if (!e || typeof e !== "object" || typeof e.package !== "string" || typeof e.version !== "string" || typeof e.verdict !== "string" || typeof e.ecosystem !== "string") continue;
      const t = Date.parse(e.t);
      if (!Number.isFinite(t) || t < now - LEDGER_WINDOW_MS || t > now + 5 * 60 * 1000) continue;
      entries.push(e);
    }
  }
  return entries;
}

/** A package name as its registry compares it: PEP 503 for PyPI; case and "-"/"_" folded for crates.io. */
function nameKey(ecosystem, name) {
  if (ecosystem === "PyPI") return name.toLowerCase().replace(/[-_.]+/g, "-");
  if (ecosystem === "crates.io") return name.toLowerCase().replace(/_/g, "-");
  return name;
}

/** A version as dependency_check records it: Go keeps (or gains) its `v`; PyPI trailing `.0`s and case folded. */
function versionKey(ecosystem, version) {
  let v = String(version).trim();
  if (ecosystem === "Go") return v.startsWith("v") ? v : `v${v}`;
  v = v.replace(/^={1,3}\s*/, "").replace(/^v(?=\d)/i, "");
  if (ecosystem === "PyPI") {
    v = v.toLowerCase();
    const m = /^(\d+(?:\.\d+)*)(.*)$/.exec(v);
    if (m) {
      const release = m[1].split(".").map(Number);
      while (release.length > 1 && release[release.length - 1] === 0) release.pop();
      v = release.join(".") + m[2];
    }
  }
  return v;
}

const HOLDS = new Set(["avoid", "wait"]);
const PASSES = new Set(["proceed", "review"]);

/** The ledger's entries by ecosystem and package name (as the registry compares names), oldest first. */
function byPackage(ledger) {
  const index = new Map();
  for (const e of ledger) {
    const eco = ["npm", "crates.io", "PyPI", "Go"].find((x) => x.toLowerCase() === e.ecosystem.toLowerCase());
    if (!eco) continue;
    const key = `${eco}\0${nameKey(eco, e.package)}`;
    const list = index.get(key);
    if (list) list.push(e);
    else index.set(key, [e]);
  }
  return index;
}

/**
 * What the ledger says about one introduced version: "allow", { deny: entry } (an avoid or wait
 * verdict), or { check: lastUnknownOrNull } (no verdict to go on).
 */
function judge(index, c) {
  const eco = c.ecosystem;
  const forPackage = index.get(`${eco}\0${nameKey(eco, c.name)}`) ?? [];
  // The server never looks a private name up: nothing will ever be recorded but this.
  if (forPackage.some((e) => e.not_checked === "private")) return "allow";
  const exactVersion = exactFor(eco, c.spec);
  if (exactVersion) {
    const want = versionKey(eco, exactVersion);
    const last = forPackage.filter((e) => versionKey(eco, e.version) === want).at(-1);
    if (last && PASSES.has(last.verdict)) return "allow";
    if (last && HOLDS.has(last.verdict)) return { deny: last };
    return { check: last ?? null };
  }
  const constraint = callTarget(eco, c.spec).replace(/\s+/g, "");
  const same = forPackage.filter((e) => typeof e.requested === "string" && e.requested.replace(/\s+/g, "") === constraint).at(-1);
  if (same && HOLDS.has(same.verdict)) return { deny: same };
  if (forPackage.some((e) => e.verdict !== "unknown")) return "allow";
  return { check: forPackage.at(-1) ?? null };
}

/** Server text repeated in a denial: one line, capped. */
function serverText(text, max = 400) {
  // eslint-disable-next-line no-control-regex -- replaces control characters on purpose: the reason must stay one line
  const flat = String(text ?? "").replace(/[\u0000-\u001f\u007f-\u009f\s]+/g, " ").trim();
  return flat.length > max ? `${flat.slice(0, max - 3)}...` : flat;
}

/** "2026-11-23 10:21 UTC" for an entry's time. */
const when = (entry) => `${new Date(Date.parse(entry.t)).toISOString().slice(0, 16).replace("T", " ")} UTC`;

/**
 * The denial for the versions a call introduces, or null when every one may go ahead. `what` is
 * "edit" or "command".
 */
function denialFor(introduced, ledger, dir, what) {
  const held = [];
  const unchecked = [];
  const index = byPackage(ledger);
  for (const c of introduced) {
    const verdict = judge(index, c);
    if (verdict === "allow") continue;
    if (verdict.deny) held.push({ c, entry: verdict.deny });
    else unchecked.push({ c, last: verdict.check });
  }
  if (held.length === 0 && unchecked.length === 0) return null;
  const lines = [`4DA guard: this ${what} was stopped before it ran.`];
  for (const { c, entry } of held.slice(0, 10)) {
    lines.push(`- ${c.name} ${c.spec} (${c.ecosystem}): dependency_check answered ${entry.verdict} at ${when(entry)}: ${serverText(entry.reason) || "no reason recorded"}. Write a version it answers proceed for.`);
  }
  if (held.length > 10) lines.push(`- ...and ${held.length - 10} more with an avoid or wait verdict.`);
  for (const { c, last } of unchecked.slice(0, 10)) {
    if (last) lines.push(`- ${c.name} ${c.spec} (${c.ecosystem}): the last dependency_check answer was unknown at ${when(last)}: ${serverText(last.reason, 240) || "no reason recorded"}`);
  }
  if (unchecked.length > 0) {
    const items = unchecked.slice(0, MAX_CALL_ITEMS).map(({ c }) => callItem(c.ecosystem, c.name, c.spec, c.from));
    const named = unchecked.slice(0, 8).map(({ c }) => `${c.name} ${c.spec}`).join(", ") + (unchecked.length > 8 ? `, and ${unchecked.length - 8} more` : "");
    const batches = unchecked.length > MAX_CALL_ITEMS ? ` (the first ${MAX_CALL_ITEMS}; this ${what} names ${unchecked.length}, so call again for the rest)` : "";
    lines.push(
      `- ${named}: no dependency_check verdict in the last 24 hours; call the 4da MCP tool dependency_check ${JSON.stringify({ items })}${batches}, and this ${what} will pass once that call answers proceed.`,
    );
    // A call that was made and left nothing behind would be stopped here for ever: say what that
    // means, once, where a version has no entry at all (an `unknown` answer is named above).
    if (unchecked.some(({ last }) => !last)) {
      const none = ledger.length === 0 ? `No dependency_check verdict at all is recorded in ${dir} for the last 24 hours. ` : "";
      lines.push(
        `(${none}If this stops again after dependency_check has answered for it, do not retry: the 4da server that answered left no verdict in ${dir}. Either it is older than 6.5.0, which keeps no record (update it), or it keeps its data folder elsewhere (Claude Code's environment needs the same FOURDA_MCP_HOME as the server). FOURDA_GUARD=advise makes this hook advise instead of block.)`,
      );
    }
  }
  return lines.join("\n");
}

// =============================================================================
// The hook
// =============================================================================

/** "block" (the default), "advise" or "off", from FOURDA_GUARD. */
function guardMode(value) {
  const v = String(value ?? "").trim().toLowerCase();
  return v === "off" || v === "advise" ? v : "block";
}

/** The versions a PreToolUse call would introduce, with the word for it; null when the call is not one this hook reads. */
function introducedBy(input) {
  const toolName = input.tool_name;
  const toolInput = input.tool_input;
  if (!toolInput || typeof toolInput !== "object") return null;
  if (toolName === "Bash" || toolName === "PowerShell") {
    const found = installsIn(toolInput.command, toolName === "PowerShell" ? "powershell" : "bash");
    return { what: "command", changes: found.map((r) => ({ ecosystem: r.ecosystem, name: r.name, spec: r.spec, from: null })) };
  }
  if (toolName !== "Edit" && toolName !== "MultiEdit" && toolName !== "Write") return null;
  if (typeof toolInput.file_path !== "string") return null;
  const kind = manifestKind(toolInput.file_path);
  if (!kind) return null;
  const changes = repeatable(introducedByEdit(kind, toolName, toolInput, toolInput.file_path));
  return { what: "edit", changes: changes.map((c) => ({ ecosystem: ECOSYSTEM[kind], name: c.name, spec: c.to, from: c.from })) };
}

/** PreToolUse: the denial JSON, or "" to let the call go ahead. */
function preToolUse(input, env, now) {
  const found = introducedBy(input);
  if (!found) return "";
  const changes = found.changes.filter((c) => NAME_TEXT.test(c.name) && specText(c.spec) === String(c.spec).trim());
  if (changes.length === 0) return "";
  const dir = dataDir(env);
  const ledger = readLedger(dir, now);
  if (ledger === null) return "";
  const reason = denialFor(changes, ledger, dir, found.what);
  if (!reason) return "";
  return JSON.stringify({ hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: reason } });
}

/** PostToolUse (FOURDA_GUARD=advise): the advice after a manifest edit, or "". */
function postToolUse(input) {
  const toolInput = input?.tool_input ?? {};
  if (typeof toolInput.file_path !== "string") return "";
  const file = manifestKind(toolInput.file_path);
  if (!file) return "";
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
  changes = repeatable(changes);
  // Write replaces the whole file and its payload carries no "before": stay quiet
  // rather than report every dependency as changed.
  if (changes.length === 0) return "";
  return JSON.stringify({ hookSpecificOutput: { hookEventName: "PostToolUse", additionalContext: adviceFor(file, changes) } });
}

/**
 * The hook's whole answer to one payload: the JSON to print, or "" for none. Pure apart from
 * reading the manifest and the ledger.
 */
export function respond(input, env = process.env, now = Date.now()) {
  if (!input || typeof input !== "object") return "";
  const mode = guardMode(env.FOURDA_GUARD);
  if (mode === "off") return "";
  if (input.hook_event_name === "PreToolUse") return mode === "block" ? preToolUse(input, env, now) : "";
  // Where nothing held the edit before it ran (FOURDA_GUARD=advise, or no ledger: an older server
  // or none), the advice follows it, as it did before 6.5.0.
  if (input.hook_event_name === "PostToolUse") return mode === "advise" || !ledgerStarted(dataDir(env)) ? postToolUse(input) : "";
  return "";
}

async function main() {
  // Past its own limit the hook ends silently: the call then goes ahead as if it had said nothing.
  setTimeout(() => process.exit(0), SELF_LIMIT_MS).unref();
  process.stdin.setEncoding("utf8");
  let raw = "";
  for await (const chunk of process.stdin) {
    raw += chunk;
    // A hook payload is kilobytes. One far beyond that is not one this hook reads.
    if (raw.length > MAX_INPUT_CHARS) return;
  }
  let input;
  try {
    input = JSON.parse(raw);
  } catch {
    return;
  }
  const out = respond(input);
  if (out) process.stdout.write(out);
}

if (basename(process.argv[1] ?? "") === "manifest-edit.mjs") {
  main().catch(() => {
    // The hook never fails the call it looks at: an error of its own is silence.
  });
}
