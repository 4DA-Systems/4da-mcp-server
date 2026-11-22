// SPDX-License-Identifier: Apache-2.0
/**
 * Project Scanner for MCP Standalone Mode
 *
 * Lightweight project scanner that detects languages, frameworks,
 * dependencies, and topics from the current working directory.
 * Runs on startup when no existing 4DA database is found.
 *
 * Design goals:
 * - Fast (<2 seconds) — only checks immediate directory
 * - No recursion — reads manifest files at project root
 * - No dependencies — uses only Node.js built-ins
 */

import * as fs from "node:fs";
import * as path from "node:path";
import {
  cargoWorkspaceDeps,
  declaredRequirements,
  parseGoModDirectDeps,
  parsePyprojectDependencies,
} from "./project-manifests.js";
import { readTextFile } from "./live/text-file.js";
import { pushAll } from "./array-utils.js";

// =============================================================================
// Types
// =============================================================================

export interface ProjectScanResult {
  languages: string[];
  frameworks: string[];
  dependencies: string[];
  devDependencies: string[];
  topics: string[];
  projectName: string;
  projectPath: string;
  /** Per-ecosystem deps (correct ecosystem per manifest). Keys: "npm", "rust", "python", "go". */
  depsByEcosystem: Record<string, { deps: string[]; devDeps: string[] }>;
  /** dependency name -> target spec (e.g. "cfg(windows)") for platform-gated deps. */
  depTargets: Record<string, string>;
}

// =============================================================================
// Framework Detection Maps
// =============================================================================

/** npm package name -> framework label */
const NPM_FRAMEWORK_MAP: Record<string, string> = {
  react: "react",
  "react-dom": "react",
  vue: "vue",
  next: "next.js",
  nuxt: "nuxt",
  "@angular/core": "angular",
  svelte: "svelte",
  "@sveltejs/kit": "sveltekit",
  astro: "astro",
  remix: "remix",
  express: "express",
  fastify: "fastify",
  hono: "hono",
  elysia: "elysia",
  "react-native": "react-native",
  expo: "expo",
  electron: "electron",
  tauri: "tauri",
  "@tauri-apps/api": "tauri",
  "@tauri-apps/cli": "tauri",
};

/** npm devDependency name -> language/tool */
const NPM_DEVTOOL_MAP: Record<string, string> = {
  typescript: "typescript",
  vite: "vite",
  vitest: "vitest",
  jest: "jest",
  webpack: "webpack",
  esbuild: "esbuild",
  rollup: "rollup",
  tailwindcss: "tailwind",
  "@tailwindcss/vite": "tailwind",
  prisma: "prisma",
};

/** Rust crate name -> framework label */
const RUST_FRAMEWORK_MAP: Record<string, string> = {
  tauri: "tauri",
  "tauri-build": "tauri",
  actix: "actix",
  "actix-web": "actix",
  axum: "axum",
  rocket: "rocket",
  warp: "warp",
  tokio: "tokio",
  serde: "serde",
  diesel: "diesel",
  sqlx: "sqlx",
  rusqlite: "sqlite",
  reqwest: "reqwest",
  tonic: "grpc",
  leptos: "leptos",
  yew: "yew",
  dioxus: "dioxus",
};

// =============================================================================
// Node Built-in Modules (filtered from npm deps)
// =============================================================================

/** Node.js built-in modules — never belong in dependency lists. */
const NODE_BUILTINS = new Set([
  "assert", "buffer", "child_process", "cluster", "console", "crypto",
  "dgram", "dns", "domain", "events", "fs", "http", "http2", "https",
  "inspector", "module", "net", "os", "path", "perf_hooks", "process",
  "punycode", "querystring", "readline", "repl", "stream", "string_decoder",
  "sys", "timers", "tls", "tty", "url", "util", "v8", "vm", "wasi",
  "worker_threads", "zlib",
  // node: prefixed variants
  "node:assert", "node:buffer", "node:child_process", "node:cluster",
  "node:console", "node:crypto", "node:dgram", "node:dns", "node:domain",
  "node:events", "node:fs", "node:http", "node:http2", "node:https",
  "node:inspector", "node:module", "node:net", "node:os", "node:path",
  "node:perf_hooks", "node:process", "node:punycode", "node:querystring",
  "node:readline", "node:repl", "node:stream", "node:string_decoder",
  "node:sys", "node:timers", "node:tls", "node:tty", "node:url",
  "node:util", "node:v8", "node:vm", "node:wasi", "node:worker_threads",
  "node:zlib",
]);

// =============================================================================
// Scanner
// =============================================================================

/**
 * Scan a directory for project context.
 * Only reads manifest files at the root level — no recursion.
 */
export function scanCurrentProject(cwd: string): ProjectScanResult {
  const result: ProjectScanResult = {
    languages: [],
    frameworks: [],
    dependencies: [],
    devDependencies: [],
    topics: [],
    projectName: path.basename(cwd),
    projectPath: cwd,
    depsByEcosystem: {},
    depTargets: {},
  };

  const langSet = new Set<string>();
  const fwSet = new Set<string>();

  // -------------------------------------------------------------------------
  // 1. package.json (JavaScript / TypeScript ecosystem)
  // -------------------------------------------------------------------------
  const pkgPath = path.join(cwd, "package.json");
  if (fs.existsSync(pkgPath)) {
    try {
      const pkg = JSON.parse(readTextFile(pkgPath));
      langSet.add("javascript");

      if (pkg.name) {
        result.projectName = pkg.name;
      }

      // Production dependencies (filter Node.js built-ins)
      if (pkg.dependencies && typeof pkg.dependencies === "object") {
        const depNames = Object.keys(pkg.dependencies).filter(d => !NODE_BUILTINS.has(d));
        pushAll(result.dependencies, depNames);

        for (const dep of depNames) {
          if (dep in NPM_FRAMEWORK_MAP) {
            fwSet.add(NPM_FRAMEWORK_MAP[dep]);
          }
        }
      }

      // Dev dependencies (filter Node.js built-ins)
      if (pkg.devDependencies && typeof pkg.devDependencies === "object") {
        const devDepNames = Object.keys(pkg.devDependencies).filter(d => !NODE_BUILTINS.has(d));
        pushAll(result.devDependencies, devDepNames);

        for (const dep of devDepNames) {
          if (dep in NPM_DEVTOOL_MAP) {
            const tool = NPM_DEVTOOL_MAP[dep];
            if (tool === "typescript") {
              langSet.add("typescript");
            } else {
              fwSet.add(tool);
            }
          }
          // Also check frameworks in devDependencies (common for meta-frameworks)
          if (dep in NPM_FRAMEWORK_MAP) {
            fwSet.add(NPM_FRAMEWORK_MAP[dep]);
          }
        }
      }

      // Populate per-ecosystem tracking for npm
      const npmDeps = (pkg.dependencies && typeof pkg.dependencies === "object")
        ? Object.keys(pkg.dependencies).filter(d => !NODE_BUILTINS.has(d))
        : [];
      const npmDevDeps = (pkg.devDependencies && typeof pkg.devDependencies === "object")
        ? Object.keys(pkg.devDependencies).filter(d => !NODE_BUILTINS.has(d))
        : [];
      if (npmDeps.length > 0 || npmDevDeps.length > 0) {
        result.depsByEcosystem["npm"] = { deps: npmDeps, devDeps: npmDevDeps };
      }
    } catch {
      // Unparseable: what it declares is unknown, not empty. The npm group stays, so the
      // resolver reads the directory and reports the manifest as unreadable.
      langSet.add("javascript");
      result.depsByEcosystem["npm"] = { deps: [], devDeps: [] };
    }
  }

  // -------------------------------------------------------------------------
  // 2. Cargo.toml (Rust ecosystem)
  // -------------------------------------------------------------------------
  const cargoPath = path.join(cwd, "Cargo.toml");
  if (fs.existsSync(cargoPath)) {
    try {
      const content = readTextFile(cargoPath);
      langSet.add("rust");

      // Extract project name from [package] section
      const crateName = cargoPackageName(content);
      if (crateName) result.projectName = crateName;

      // [dependencies], [dev-dependencies], [build-dependencies] and their target forms, in every form cargo reads.
      const rustDeps: string[] = [];
      const rustDevDeps: string[] = [];
      parseCargoDependencies(content, rustDeps, rustDevDeps, result.depTargets, fwSet, RUST_FRAMEWORK_MAP);
      // A workspace root declares dependencies for its members; a virtual one
      // (no [package]) declares nothing else, and was scanned as empty.
      const workspace = cargoWorkspaceDeps(cwd, content);
      for (const dep of workspace.deps) {
        if (!rustDeps.includes(dep)) rustDeps.push(dep);
        if (dep in RUST_FRAMEWORK_MAP) fwSet.add(RUST_FRAMEWORK_MAP[dep]);
      }
      for (const dep of workspace.devDeps) {
        if (!rustDeps.includes(dep) && !rustDevDeps.includes(dep)) rustDevDeps.push(dep);
      }

      // Add to flat arrays for backward compat
      pushAll(result.dependencies, rustDeps);
      pushAll(result.devDependencies, rustDevDeps);

      // Populate per-ecosystem tracking for rust
      if (rustDeps.length > 0 || rustDevDeps.length > 0) {
        result.depsByEcosystem["rust"] = { deps: rustDeps, devDeps: rustDevDeps };
      }
    } catch {
      // Present and not readable: the ecosystem is here all the same, and its reader says why
      // nothing was read (resolveRust). With no group, the file went unmentioned.
      result.depsByEcosystem["rust"] ??= { deps: [], devDeps: [] };
    }
  }

  // -------------------------------------------------------------------------
  // 3. pyproject.toml / requirements.txt (Python ecosystem)
  // -------------------------------------------------------------------------
  const pyprojectPath = path.join(cwd, "pyproject.toml");
  const requirementsPath = path.join(cwd, "requirements.txt");
  const setupPyPath = path.join(cwd, "setup.py");

  // pyproject.toml (PEP 621, Poetry, uv) and requirements.txt are read
  // together: a project often has both, and the old else-if dropped the second.
  const pyDeps = new Set<string>();
  const pyDevDeps = new Set<string>();
  /** A manifest that is present and could not be read: the Python reader names it (resolvePython). */
  let pyUnread = false;
  if (fs.existsSync(pyprojectPath)) {
    langSet.add("python");
    try {
      const parsed = parsePyprojectDependencies(readTextFile(pyprojectPath));
      parsed.deps.forEach((d) => pyDeps.add(d));
      parsed.devDeps.forEach((d) => pyDevDeps.add(d));
    } catch {
      pyUnread = true;
    }
  }
  if (fs.existsSync(requirementsPath)) langSet.add("python");
  try {
    // Every requirements file declares what it lists, and so do the files it includes
    // (`-r sub/inner.txt`): requirements-dev.txt and requirements/*.txt as much as
    // requirements.txt. A name only dev files bring in is a dev dependency.
    const declared = declaredRequirements(cwd);
    if (declared.deps.length > 0 || declared.devDeps.length > 0) langSet.add("python");
    declared.deps.forEach((d) => pyDeps.add(d));
    declared.devDeps.forEach((d) => pyDevDeps.add(d));
  } catch {
    // Skip
  }
  if (fs.existsSync(setupPyPath)) {
    langSet.add("python");
  }
  for (const name of pyDeps) {
    pyDevDeps.delete(name);
    result.dependencies.push(name);
    detectPythonFramework(name, fwSet);
  }
  pushAll(result.devDependencies, pyDevDeps);
  if (pyDeps.size > 0 || pyDevDeps.size > 0 || pyUnread) {
    result.depsByEcosystem["python"] = { deps: [...pyDeps], devDeps: [...pyDevDeps] };
  }

  // -------------------------------------------------------------------------
  // 4. go.mod (Go ecosystem)
  // -------------------------------------------------------------------------
  const goModPath = path.join(cwd, "go.mod");
  if (fs.existsSync(goModPath)) {
    langSet.add("go");
    const goDeps: string[] = [];
    try {
      const content = readTextFile(goModPath);
      // Extract module name
      const moduleMatch = content.match(/^module\s+(\S+)/m);
      if (moduleMatch) {
        const parts = moduleMatch[1].split("/");
        result.projectName = parts[parts.length - 1];
      }
      // Direct requirements only: `// indirect` lines are transitive.
      for (const dep of parseGoModDirectDeps(content)) {
        result.dependencies.push(dep);
        goDeps.push(dep);
        detectGoFramework(dep, fwSet);
      }
    } catch {
      // Skip
    }
    if (goDeps.length > 0) {
      result.depsByEcosystem["go"] = { deps: goDeps, devDeps: [] };
    }
  }

  // -------------------------------------------------------------------------
  // 5. tsconfig.json presence (confirms TypeScript even without package.json)
  // -------------------------------------------------------------------------
  if (fs.existsSync(path.join(cwd, "tsconfig.json"))) {
    langSet.add("typescript");
  }

  // -------------------------------------------------------------------------
  // 6. Dockerfile / docker-compose.yml (container detection)
  // -------------------------------------------------------------------------
  if (
    fs.existsSync(path.join(cwd, "Dockerfile")) ||
    fs.existsSync(path.join(cwd, "docker-compose.yml")) ||
    fs.existsSync(path.join(cwd, "docker-compose.yaml"))
  ) {
    fwSet.add("docker");
  }

  // -------------------------------------------------------------------------
  // Finalize
  // -------------------------------------------------------------------------
  result.languages = [...langSet];
  result.frameworks = [...fwSet];

  // Deduplicate dependencies
  result.dependencies = [...new Set(result.dependencies)];
  result.devDependencies = [...new Set(result.devDependencies)];

  // Generate topics from detected stack
  result.topics = [
    ...new Set([
      ...result.languages,
      ...result.frameworks,
      // Add high-signal dependency names as topics (only well-known ones)
      ...result.dependencies.filter(isNotableTopic),
    ]),
  ];

  return result;
}

// =============================================================================
// Helpers
// =============================================================================

/**
 * The crate name: the first `name = "..."` line of the `[package]` table.
 *
 * One pass over the lines. This was a single multi-line regular expression
 * (`^\[package\]\s*\n(?:.*\n)*?name...`), which re-scanned the rest of the file
 * from every `[package]` line: a 200 KB Cargo.toml of repeated `[package]`
 * headers took 3.8 s, synchronously, in the startup walk, and 2 MB would take
 * minutes (measured 2026-11-11). A scanned repository's manifest is its own text.
 */
export function cargoPackageName(content: string): string | null {
  let inPackage = false;
  let start = 0;
  while (start <= content.length) {
    let end = content.indexOf("\n", start);
    if (end < 0) end = content.length;
    const line = content.slice(start, end).trim();
    start = end + 1;
    if (line.startsWith("[")) {
      if (inPackage) return null; // the [package] table ended without a name
      inPackage = line === "[package]";
      continue;
    }
    if (!inPackage || !line.startsWith("name")) continue;
    const eq = line.indexOf("=");
    if (eq < 0 || line.slice(4, eq).trim() !== "") continue;
    const value = line.slice(eq + 1).trim();
    const close = value.startsWith('"') ? value.indexOf('"', 1) : -1;
    if (close > 1) return value.slice(1, close);
  }
  return null;
}

/** A crate name as a Cargo.toml key or table name spells it (quoted or bare). */
const CRATE_KEY = /^(?:"([A-Za-z0-9_-]+)"|'([A-Za-z0-9_-]+)'|([A-Za-z_][\w-]*))$/;

/**
 * The dependency table a Cargo.toml header opens, or null for any other table: `dev` for
 * `[dev-dependencies]` (build-dependencies run on every machine that builds the crate: normal,
 * audit 6.2.5 F-3), `target` for a `[target.<spec>.…]` form (a cfg() predicate or a triple), and
 * `entry` for a table of one dependency (`[dependencies.git2]`). `[package.metadata.x.dependencies]`
 * is a tool's data and `[workspace.dependencies]` is read by cargoWorkspaceDeps.
 */
function cargoDependencyTable(line: string): { dev: boolean; target: string | null; entry: string | null } | null {
  const header = /^\[([^[\]]+)\]/.exec(line)?.[1]?.trim();
  if (!header) return null;
  let rest = header;
  let target: string | null = null;
  if (rest.startsWith("target.")) {
    const after = rest.slice("target.".length);
    const quoted = /^(['"])(.*?)\1\s*\.(.*)$/.exec(after);
    if (quoted) {
      target = quoted[2];
      rest = quoted[3];
    } else {
      const dot = after.indexOf(".");
      if (dot < 0) return null;
      target = after.slice(0, dot);
      rest = after.slice(dot + 1);
    }
  }
  const table = /^(dependencies|dev-dependencies|build-dependencies)(?:\s*\.\s*(.+))?$/.exec(rest.trim());
  if (!table) return null;
  const key = table[2] ? CRATE_KEY.exec(table[2].trim()) : null;
  if (table[2] && !key) return null;
  return { dev: table[1] === "dev-dependencies", target, entry: key ? (key[1] ?? key[2] ?? key[3]) : null };
}

/**
 * Every dependency a Cargo.toml's own dependency tables declare, in each form cargo reads: inline
 * (`name = "1"`, `name = { ... }`), dotted keys (`name.version = "1"`) and a table of its own
 * (`[dependencies.name]`), under `[dependencies]`, `[dev-dependencies]`, `[build-dependencies]`
 * and their `[target.<spec>.…]` forms, whose spec is recorded per dependency (`depTargets`) so
 * advisories can be flagged platform-relevant. Each name once per list.
 */
function parseCargoDependencies(
  content: string,
  deps: string[],
  devDeps: string[],
  depTargets: Record<string, string>,
  frameworkSet: Set<string>,
  frameworkMap: Record<string, string>,
): void {
  let table: ReturnType<typeof cargoDependencyTable> = null;
  const add = (name: string, dev: boolean, target: string | null) => {
    const list = dev ? devDeps : deps;
    if (!list.includes(name)) list.push(name);
    if (target) depTargets[name] = target;
    if (name in frameworkMap) frameworkSet.add(frameworkMap[name]);
  };
  for (const raw of content.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    if (line.startsWith("[")) {
      table = cargoDependencyTable(line);
      if (table?.entry) add(table.entry, table.dev, table.target);
      continue;
    }
    // Inside `[dependencies.name]` every key is a field of that one dependency.
    if (!table || table.entry) continue;
    const key = /^("[^"]+"|'[^']+'|[A-Za-z_][\w-]*)\s*(?:\.\s*[A-Za-z_][\w-]*\s*)?=/.exec(line)?.[1];
    const name = key ? CRATE_KEY.exec(key) : null;
    if (name) add(name[1] ?? name[2] ?? name[3], table.dev, table.target);
  }
}

/** Detect Python framework from package name */
function detectPythonFramework(name: string, fwSet: Set<string>): void {
  const pythonFrameworks: Record<string, string> = {
    django: "django",
    flask: "flask",
    fastapi: "fastapi",
    starlette: "starlette",
    uvicorn: "uvicorn",
    celery: "celery",
    sqlalchemy: "sqlalchemy",
    pytorch: "pytorch",
    torch: "pytorch",
    tensorflow: "tensorflow",
    numpy: "numpy",
    pandas: "pandas",
    streamlit: "streamlit",
  };
  if (name in pythonFrameworks) {
    fwSet.add(pythonFrameworks[name]);
  }
}

/** Detect Go framework from module path */
function detectGoFramework(dep: string, fwSet: Set<string>): void {
  if (dep.includes("gin-gonic")) fwSet.add("gin");
  if (dep.includes("gorilla/mux")) fwSet.add("gorilla");
  if (dep.includes("labstack/echo")) fwSet.add("echo");
  if (dep.includes("gofiber/fiber")) fwSet.add("fiber");
  if (dep.includes("grpc")) fwSet.add("grpc");
}

/**
 * Filter for well-known packages worth adding as topics.
 * Avoids noise from utility packages.
 */
function isNotableTopic(name: string): boolean {
  const notable = new Set([
    // Databases
    "sqlite3", "better-sqlite3", "pg", "mysql2", "mongodb", "mongoose", "redis",
    "prisma", "typeorm", "sequelize", "knex",
    // Auth
    "passport", "next-auth", "lucia", "clerk",
    // APIs
    "graphql", "trpc", "@trpc/server", "openapi",
    // AI/ML
    "openai", "@anthropic-ai/sdk", "langchain", "llamaindex",
    // Testing
    "vitest", "jest", "mocha", "playwright", "cypress",
    // Infrastructure
    "docker", "kubernetes",
    // Notable Rust crates
    "serde", "tokio", "axum", "actix-web", "sqlx", "diesel",
    "reqwest", "rusqlite", "clap", "tracing",
  ]);
  return notable.has(name);
}
