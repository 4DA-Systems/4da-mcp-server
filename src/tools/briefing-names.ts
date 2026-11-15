// SPDX-License-Identifier: Apache-2.0
/**
 * What a word in a task can and cannot be, as a package name (blind audit round 4): shared by the
 * briefing's readers of named versions (briefing-requested-versions.ts) and new packages
 * (briefing-new-packages.ts).
 */

import { POPULAR_PYPI } from "../live/popular-pypi.js";
import type { ResolvedDependency } from "../live/types.js";
import { editDistance } from "./dependency-check-malicious.js";

const POPULAR_PYPI_SET = new Set(POPULAR_PYPI);

/** A PyPI name as PyPI compares names: lower case, runs of `-`, `_` and `.` as one `-`. */
export function normalizePypiName(name: string): string {
  return name.trim().toLowerCase().replace(/[-_.]+/g, "-");
}

/**
 * The popular PyPI project a name is a near-miss of: the most popular one edit away (names of 5
 * characters or more), else two edits away (names of 8 or more). Null for a popular name itself
 * and for anything else. Deterministic and offline (live/popular-pypi.ts). `colourama` is
 * colorama, `jeIlyfish` jellyfish, `python3-dateutil` python-dateutil.
 */
export function closestPopularPypi(name: string): string | null {
  const n = normalizePypiName(name);
  if (n.length < 5 || POPULAR_PYPI_SET.has(n)) return null;
  const nearest = (max: number) => {
    let best: string | null = null;
    let bestDistance = max + 1;
    for (const p of POPULAR_PYPI) {
      if (Math.abs(p.length - n.length) >= bestDistance) continue;
      const d = editDistance(n, p, bestDistance - 1);
      if (d > 0 && d < bestDistance) {
        best = p;
        bestDistance = d;
      }
    }
    return best;
  };
  return nearest(1) ?? (n.length >= 8 ? nearest(2) : null);
}

/**
 * Manifest and lockfile names: where a version is written, never the package it is for ("lodash in
 * package.json to 4.17.20" was judged as a package named `package.json`).
 */
const MANIFEST_FILE =
  /^(?:package(?:-lock)?\.json|npm-shrinkwrap\.json|pnpm-(?:lock|workspace)\.yaml|yarn\.lock|bun\.lockb?|cargo\.(?:toml|lock)|requirements(?:[-_.][\w.-]+)?\.(?:txt|in)|constraints\.txt|pyproject\.toml|poetry\.lock|uv\.lock|pipfile(?:\.lock)?|setup\.(?:py|cfg)|go\.(?:mod|sum|work)|gemfile(?:\.lock)?|composer\.(?:json|lock))$/i;

/**
 * Adjectives a task puts before a package or a scope ("install the private @acme scope" reported a
 * new package called `private`): never a package name in prose; written `private@1.0` or quoted it is one.
 */
export const NOT_A_PACKAGE_ADJECTIVES: ReadonlySet<string> = new Set([
  "private", "internal", "proprietary", "in-house", "inhouse", "company", "corporate", "our", "public", "scoped", "vendored",
]);

/**
 * Everyday English a task puts after "add", "install" or "use" when it means a feature, a step or a
 * part of the code, not a package ("install steps", "add routes to the app", "install zqx omega risk"
 * looked up `steps` and `risk`; round 5 audits). In prose these are not read as a package to look up;
 * quoted, written `name@1.0`, called "the X package", put in a manifest, or given to a package
 * manager command they still are. Names on the bundled popular-package list are never treated as
 * English (briefing-new-packages.ts removes them), so a typo-squat target is always checked.
 */
export const ENGLISH_TASK_WORDS: ReadonlySet<string> = new Set([
  // the work itself
  "steps", "instructions", "guide", "guides", "readme", "notes", "changelog", "example", "examples", "sample", "samples", "demo", "tutorial", "walkthrough",
  "risk", "risks", "issue", "issues", "bug", "bugs", "fix", "fixes", "patch", "patches", "hotfix", "workaround", "todo", "todos", "task", "tasks", "ticket",
  "feature", "improvement", "improvements", "change", "changes", "update", "updates", "upgrade", "upgrades", "release", "releases", "migration", "migrations",
  "hook", "hooks", "helper", "helpers", "wrapper", "wrappers", "handler", "handlers", "listener", "listeners", "callback", "callbacks", "middleware",
  "routes", "router", "routing", "endpoints", "api", "apis", "controller", "controllers", "service", "services", "model", "models", "schema", "schemas",
  "view", "views", "component", "components", "screen", "screens", "pages", "layout", "layouts", "template", "templates", "theme", "themes", "styles", "style",
  "header", "footer", "sidebar", "navbar", "menu", "modal", "dialog", "tooltip", "spinner", "loader", "toggle", "dropdown", "tabs", "tab", "card", "cards",
  "form", "forms", "input", "inputs", "label", "labels", "icon", "icons", "image", "images", "logo", "banner", "link", "links", "list", "lists", "grid",
  "auth", "authentication", "authorization", "login", "logout", "signup", "session", "sessions", "token", "tokens", "password", "passwords", "permissions", "roles",
  "user", "users", "account", "accounts", "profile", "profiles", "settings", "preferences", "admin", "dashboard", "search", "filter", "filters", "sorting",
  "pagination", "cache", "caching", "retry", "retries", "timeout", "timeouts", "throttling", "debounce", "metrics", "telemetry", "analytics", "monitoring",
  "alerts", "alerting", "tracing", "logs", "logger", "warnings", "warning", "messages", "message", "notifications", "notification", "emails", "email",
  "database", "db", "migrations", "queries", "query", "indexes", "tables", "records", "rows", "fields", "columns", "keys", "key", "values", "value",
  "files", "file", "folder", "folders", "directory", "directories", "paths", "assets", "uploads", "upload", "downloads", "download", "exports", "imports",
  "tests", "specs", "spec", "fixtures", "fixture", "mocks", "mock", "stubs", "stub", "coverage", "benchmarks", "benchmark", "lint", "linting", "formatting",
  "ci", "pipeline", "pipelines", "workflow", "workflows", "job", "jobs", "deploy", "deployment", "deployments", "build", "builds", "scripts", "commands",
  "docker", "container", "containers", "server", "servers", "client", "clients", "worker", "workers", "cron", "scheduler", "queue", "queues",
  "security", "safety", "validation", "sanitization", "encryption", "compression", "localization", "translations", "translation", "i18n", "accessibility", "a11y",
  "comment", "comments", "docstrings", "docstring", "annotations", "typings", "interfaces", "interface", "constants", "constant", "variables", "variable", "enums",
  "support", "fallback", "fallbacks", "defaults", "default", "limits", "limit", "checks", "guard", "guards", "assertions", "invariants", "constraints",
  "something", "stuff", "things", "thing", "everything", "anything", "nothing", "more", "less", "them", "those", "it", "again", "back", "later", "soon",
  "properly", "correctly", "quickly", "here", "there", "now", "today", "tomorrow", "please", "first", "next", "last", "both", "either", "neither",
  "dark", "light", "mode", "colour", "colors", "blue", "red", "green", "black", "white", "spaces", "space", "newline", "newlines", "indentation",
  "omega", "alpha", "beta", "gamma", "delta", "stable", "nightly", "canary", "preview", "experimental", "legacy", "old", "new", "modern", "latest",
  "strict", "loose", "async", "sync", "parallel", "concurrency", "threads", "thread", "locks", "locking", "retrying", "polling", "streaming", "batching",
  "dependency", "dependencies", "package", "packages", "library", "libraries", "module", "modules", "plugin", "plugins", "extension", "extensions", "tooling",
  "app", "apps", "application", "project", "projects", "repo", "repository", "codebase", "monorepo", "workspace", "workspaces", "environment", "environments",
  "loop", "loops", "map", "maps", "array", "arrays", "object", "objects", "promise", "promises", "class", "classes", "function", "functions", "call", "calls",
  "machine", "computer", "system", "systems", "os", "windows", "linux", "macos", "mac", "browser", "browsers", "mobile", "desktop", "web", "frontend", "backend",
  // what a task says it needs, after "need" ("we need better error messages", "need help with the build")
  "better", "faster", "cleaner", "clearer", "simpler", "safer", "smaller", "bigger", "stronger", "help", "upstream", "downstream", "tool", "tools",
  "graceful", "structured", "proper", "consistent", "reliable", "robust", "clean", "clear", "simple", "fast", "slow", "time", "approval", "review", "feedback",
]);

/** Python standard-library modules "import X" names in a task: not a package anyone installs. */
export const PYTHON_STDLIB: ReadonlySet<string> = new Set([
  "abc", "argparse", "array", "ast", "asyncio", "base64", "bisect", "calendar", "collections", "concurrent", "contextlib", "copy", "csv", "ctypes", "dataclasses",
  "datetime", "decimal", "difflib", "enum", "functools", "getpass", "gettext", "glob", "gzip", "hashlib", "heapq", "hmac", "html", "http", "importlib", "inspect",
  "io", "ipaddress", "itertools", "json", "logging", "math", "mimetypes", "multiprocessing", "operator", "os", "pathlib", "pickle", "platform", "pprint", "queue",
  "random", "re", "secrets", "select", "shlex", "shutil", "signal", "socket", "sqlite3", "ssl", "statistics", "string", "struct", "subprocess", "sys", "tempfile",
  "textwrap", "threading", "time", "timeit", "tkinter", "traceback", "types", "typing", "unittest", "urllib", "uuid", "warnings", "weakref", "xml", "zipfile", "zlib",
]);

/**
 * package.json fields and manifest sections a task adds to a manifest ("add scripts to package.json",
 * "add an override to package.json"): not packages.
 */
export const MANIFEST_FIELDS: ReadonlySet<string> = new Set([
  "scripts", "script", "engines", "engine", "workspaces", "overrides", "override", "resolutions", "resolution", "exports", "imports", "main", "types", "bin",
  "files", "keywords", "repository", "author", "authors", "license", "description", "name", "version", "browser", "module", "sideeffects", "publishconfig",
  "peerdependencies", "devdependencies", "optionaldependencies", "dependencies", "packagemanager", "type", "homepage", "bugs", "funding", "private", "config",
  "comment", "comments", "entry", "entries", "section", "sections", "line", "lines", "field", "fields", "constraint", "constraints", "marker", "markers",
  "hash", "hashes", "extras", "extra", "classifiers", "metadata", "features", "feature", "profile", "profiles", "edition", "toolchain", "replace", "require",
]);

/**
 * A task with the version syntax a package manager takes, written the way the parsers read it:
 * quotes around a version dropped (`lodash@"4.17.20"`, `lodash@'4.17.20'`), and an npm alias
 * (`lodash@npm:event-stream@3.3.6`) read as the package it installs (`event-stream@3.3.6`). Both
 * came back safe_to_delegate with the version unread (round 5 audits).
 */
export function normalizeVersionSyntax(task: string): string {
  const toml = TOML_MANIFEST.test(task);
  return (
    task
      // A manifest entry written into the task (pre-publish audit of 5d709ff): `"dbg": "npm:debug@4.4.2"`
      // installs debug 4.4.2 under the name dbg, and was read as the packages dbg and npm, both clean.
      .replace(JSON_ALIAS_ENTRY, (_m, _q1, _key, _q2, name: string, spec: string | undefined) => (spec ? `${name}@${joinSpec(spec)}` : name))
      // `"lodash": "^4.17.20"`, `"minimist": ">=1.2.5 <1.2.6"`: the whole range is the package's (r8, B2:
      // only `<1.2.6` was read, and judged as the release 1.2.6).
      .replace(JSON_VERSION_ENTRY, (m, _q1, name: string, _q2, spec: string) => (NOT_DEPENDENCY_FIELDS.has(name.toLowerCase()) ? m : `${name}@${joinSpec(spec)}`))
      // Cargo.toml / Poetry: `serde = { version = "1.0.200", features = [...] }`.
      .replace(TOML_TABLE_ENTRY, (m, pre: string, name: string, _q, spec: string) => (NOT_DEPENDENCY_FIELDS.has(name.toLowerCase()) ? m : `${pre}${name}@${joinSpec(spec)}`))
      // `serde = "1.0.200"`, `serde = ">=1.0, <1.0.100"`: a dotted version, or any version in a task that
      // names a TOML manifest (`timeout = "30"` in prose is a setting, not a crate).
      .replace(TOML_VERSION_ENTRY, (m, pre: string, name: string, _q, spec: string) =>
        NOT_DEPENDENCY_FIELDS.has(name.toLowerCase()) || (!toml && !/\d\.\d/.test(spec)) ? m : `${pre}${name}@${joinSpec(spec)}`,
      )
      .replace(/((?:^|[\s`'"(])@?[\w.~-]+(?:\/[\w.~-]+)?)@npm:(?=@?[\w.~-])/gi, (_m, pre: string) => pre.replace(/@?[\w.~-]+(?:\/[\w.~-]+)?$/, ""))
      // `minimist@'>=1.2.5 <1.2.6'`, `lodash@"4.17.20"`.
      .replace(/@(["'])([^"'\n]+?)\1/g, (m, _q, spec: string) => (/\d/.test(spec) && QUOTED_SPEC_ONLY.test(spec) ? `@${joinSpec(spec)}` : m))
      // A constraint written in prose is one constraint (r8, B2): `minimist <1.2.6`, `chalk to >=5.6.1
      // <5.6.2`, `^1.2.0 || ^0.2.0`, `django>=2,<3`, `1.2.3 - 1.4.0`. Only `<5.6.2` (or `>=2` and `<3`
      // as two packages' versions) was read before.
      .replace(PROSE_CHAIN, (m) => joinSpec(m))
      // "chalk 5.6.1/debug 4.4.2": after a version, "/" separates two items, never a path.
      .replace(/(?<![\w/.-])((?:[<>=~^]=?)?v?\d+\.\d[\w.+-]*)\/(?=@?[A-Za-z])/g, "$1, ")
  );
}

/**
 * Joiners that keep a multi-part constraint one token in the normalized task (a space, a comma, an
 * `||`), so the readers bind the whole of it to its package; specText turns them back.
 * Private-use characters: never in a task (readableText keeps them out of names, and they are
 * invisible), so they cannot be forged into one.
 */
const JOIN_SPACE = "";
const JOIN_COMMA = "";
const JOIN_OR = "";
/** The joiners, as a regex character class body (for the tokenizers). */
export const SPEC_JOINERS = "-";

/** A constraint as one token: operators closed up to their versions, `||`, `,` and spaces joined. */
function joinSpec(spec: string): string {
  return spec
    .trim()
    .replace(/([<>=~^!]=?)\s+(?=v?\d)/g, "$1")
    .replace(/\s*\|\|\s*/g, JOIN_OR)
    .replace(/\s*,\s*/g, JOIN_COMMA)
    .replace(/\s+/g, JOIN_SPACE);
}

/** A version token as the package manager reads it: the joiners back to a space, a comma and ` || `. */
export function specText(token: string): string {
  return token.replaceAll(JOIN_SPACE, " ").replaceAll(JOIN_COMMA, ",").replaceAll(JOIN_OR, " || ");
}

/** One comparator: 4.17.20, v1.2.3, ^1.2, ~2.0, >=2, <3, ==3.3.6, ~=3.1, !=1.5, 7.x, 1.2.*. */
const ONE_SPEC = /^(?:={1,3}|~=|!=|[~^]|[<>]=?)?v?\d+(?:\.(?:\d+|x|\*))*(?:-[\w.-]+)?(?:\+[\w.-]+)?$/i;

/** Whether a token is a version or a constraint (a joined one included). */
export function isVersionSpec(token: string): boolean {
  if (!/[-]/.test(token)) return ONE_SPEC.test(token);
  const parts = token.split(/[-]/).filter((p) => p !== "" && p !== "-");
  return parts.length > 0 && parts.every((p) => ONE_SPEC.test(p));
}

/** A quoted spec that is only constraint text: comparators, versions, `||`, `,`, `-` and spaces. */
const QUOTED_SPEC_ONLY = /^\s*(?:[~^<>=!]=?|v?\d)[\w.*+<>=~^!|,\s-]*$/;
const OP_VERSION = String.raw`(?:[<>]=?|={1,3}|~=?|\^|!=)\s*v?\d[\w.*+-]*`;
const BARE_VERSION = String.raw`v?\d[\w.*+-]*`;
/**
 * Two or more comparators in prose that make one constraint: an operator version, or a bare one
 * before an operator, followed by more operator versions (space or `,` between), `|| version`, or
 * ` - version` (a hyphen range). A single operator version is joined too (`<1.2.6`, `>= 2`).
 */
const PROSE_CHAIN = new RegExp(
  String.raw`(?:(?<![-=])${OP_VERSION}|(?<![\w.])${BARE_VERSION}(?=(?:\s*\|\|\s*|\s+|\s*,\s*)(?:[<>=~^!]|v?\d)|\s+-\s+v?\d))(?:\s*\|\|\s*(?:${OP_VERSION}|${BARE_VERSION})|\s*,\s*${OP_VERSION}|\s+${OP_VERSION}|\s+-\s+${BARE_VERSION})*`,
  "g",
);

/** A package name as a manifest key: `lodash`, `@scope/name`. */
const KEY = String.raw`@?[\w.~-]+(?:\/[\w.~-]+)?`;
/** A version or range a manifest entry gives: `4.17.20`, `^1.2`, `~2.0.1`, `>=2`, `=1.0.0`, `7.x`, `>=1.2.5 <1.2.6`, `>=1.0, <2`. */
const SPEC = String.raw`(?:[~^]|[<>]=?|={1,2})?\s*v?\d[\w.*+<>=~^!|,\s-]*?`;
const JSON_ALIAS_ENTRY = new RegExp(String.raw`(["'])(${KEY})\1\s*:\s*(["'])npm:(${KEY})(?:@([^"'\s]+))?\3`, "g");
const JSON_VERSION_ENTRY = new RegExp(String.raw`(["'])(${KEY})\1\s*:\s*(["'])(${SPEC})\3`, "g");
const TOML_TABLE_ENTRY = new RegExp(String.raw`(^|[\s\x60(])([A-Za-z0-9][\w.-]*)\s*=\s*\{[^}]*?\bversion\s*=\s*(["'])(${SPEC})\3[^}]*\}`, "gm");
const TOML_VERSION_ENTRY = new RegExp(String.raw`(^|[\s\x60(])([A-Za-z0-9][\w.-]*)\s*=\s*(["'])(${SPEC})\3`, "gm");
const TOML_MANIFEST = /\b(?:cargo\.toml|pyproject\.toml|crates?|cargo|poetry)\b/i;
/** Manifest fields that hold a version but are not a dependency (`"version": "1.2.3"`, engines' `"node": ">=18"`, `edition = "2021"`). */
const NOT_DEPENDENCY_FIELDS: ReadonlySet<string> = new Set([
  "version", "node", "npm", "pnpm", "yarn", "bun", "deno", "vscode", "engines", "packagemanager", "edition", "rust-version", "requires-python", "python",
  "resolver", "lockfileversion", "lockfile-version", "schema", "manifest_version",
]);

/** A manifest or lockfile name, bare or with a directory ("web/package.json"), quotes and trailing punctuation aside. */
export function isManifestFile(token: string): boolean {
  const bare = token.replace(/^[`'"(]+/, "").replace(/[`'"),.;:!?]+$/, "");
  return MANIFEST_FILE.test(bare.split(/[\\/]/).pop() ?? "");
}

/**
 * The installed Go module a short name stands for: "gin" is github.com/gin-gonic/gin when go.mod
 * requires it ("Upgrade gin to v1.6.0" was judged as npm `gin`). The last path segment is matched,
 * a major-version suffix (`/v8`, gopkg.in's `.v3`) set aside. Two modules that end the same way are
 * not guessed between: null.
 */
export function installedGoModule(short: string, deps: readonly ResolvedDependency[]): string | null {
  const lower = short.toLowerCase();
  const hits = new Set<string>();
  for (const d of deps) {
    if (d.ecosystem !== "Go") continue;
    const segments = d.name.split("/").filter(Boolean);
    if (segments.length > 1 && /^v\d+$/.test(segments[segments.length - 1])) segments.pop();
    const last = (segments[segments.length - 1] ?? "").replace(/\.v\d+$/, "").toLowerCase();
    if (segments.length > 1 && last === lower) hits.add(d.name);
  }
  return hits.size === 1 ? [...hits][0] : null;
}
