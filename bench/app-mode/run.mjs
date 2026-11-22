// SPDX-License-Identifier: Apache-2.0
/**
 * App-mode arm: the same project must get the same dependency answers with and without the
 * desktop app's database. Runs one scan (concise and detailed) and one plan, three ways, each
 * from a server started IN the project with no project_path (how 4DA's own .mcp.json and every
 * app user's configuration start it):
 *   A. no app database;
 *   B. an app database built from contract/app-schema.sql whose project_dependencies rows
 *      cover every sub-project of the project (as the app writes them after a full index);
 *   C. the same database with one sub-project's rows removed (an app index that has not seen
 *      that directory yet).
 * Fails unless all three give the same vulnerable packages, the same counts, the same advisory
 * rows and plan rows, and a coverage object in every scan answer. Says which differs and how.
 *
 *   node bench/app-mode/run.mjs --server <dist/index.js | package dir> [--project <dir>] [--drop <sub-dir>]
 *        [--work <dir>] [--out <dir>] [--offline] [--keep]
 *
 * Without --project it scans fixture.json's tree (public names, written to a temp folder).
 * --offline sends nothing (FOURDA_OFFLINE and a dead proxy): use it for a project with made-up
 * or private names. Exit 1 when the three disagree, 2 when the harness cannot run.
 */
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { hermeticEnv, openSession, resolveServer, rmTree } from "../lib/mcp-session.mjs";
import { findLockfiles, lockfileVersions } from "../plan-exec/lib.mjs";
import { loadAppSchema } from "../../scripts/app-schema-loader.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, "..", "..");
const argv = process.argv.slice(2);
const opt = (name) => {
  const i = argv.indexOf(`--${name}`);
  return i >= 0 ? argv[i + 1] : undefined;
};
const flag = (name) => argv.includes(`--${name}`);
const fail = (m) => {
  console.error(`app-mode: ${m}`);
  process.exit(2);
};

let server;
try {
  server = resolveServer(opt("server"));
} catch (e) {
  fail(e.message);
}
const parent = path.resolve(opt("work") ?? os.tmpdir());
fs.mkdirSync(parent, { recursive: true });
const work = fs.mkdtempSync(path.join(parent, "4da-app-mode-"));
const out = opt("out") ? path.resolve(opt("out")) : null;
const offline = flag("offline");

// The project: given, or the fixture tree written out.
let project;
if (opt("project")) {
  project = path.resolve(opt("project"));
  if (!fs.existsSync(project)) fail(`--project ${project} does not exist`);
} else {
  project = path.join(work, "appmode-fixture");
  const fixture = JSON.parse(fs.readFileSync(path.join(here, "fixture.json"), "utf8"));
  for (const [rel, body] of Object.entries(fixture.files)) {
    fs.mkdirSync(path.dirname(path.join(project, rel)), { recursive: true });
    fs.writeFileSync(path.join(project, rel), body);
  }
}

// ---------------------------------------------------------------------------------------------
// The app database: the contract schema, and project_dependencies rows as the app writes them.
// ---------------------------------------------------------------------------------------------

const LANGUAGE = { "package-lock.json": ["javascript", "package.json"], "pnpm-lock.yaml": ["javascript", "package.json"], "yarn.lock": ["javascript", "package.json"], "Cargo.lock": ["rust", "Cargo.toml"], "uv.lock": ["python", "pyproject.toml"], "poetry.lock": ["python", "pyproject.toml"], "go.mod": ["go", "go.mod"] };

/** Names a manifest declares directly (package.json dependency maps, Cargo.toml dependency tables, go.mod without `// indirect`). */
function declared(dir, base) {
  const read = (f) => (fs.existsSync(path.join(dir, f)) ? fs.readFileSync(path.join(dir, f), "utf8") : "");
  if (LANGUAGE[base][0] === "javascript") {
    try {
      const pkg = JSON.parse(read("package.json"));
      return { deps: Object.keys(pkg.dependencies ?? {}), dev: Object.keys(pkg.devDependencies ?? {}) };
    } catch {
      return { deps: [], dev: [] };
    }
  }
  if (base === "Cargo.lock") {
    const deps = [];
    const dev = [];
    let table = null;
    for (const line of read("Cargo.toml").split(/\r?\n/)) {
      const h = /^\s*\[([^\]]+)\]/.exec(line);
      if (h) table = h[1].trim();
      else if (table === "dependencies" || table === "dev-dependencies") {
        const m = /^\s*([A-Za-z0-9_-]+)\s*=/.exec(line);
        if (m) (table === "dependencies" ? deps : dev).push(m[1]);
      }
    }
    return { deps, dev };
  }
  if (base === "go.mod") return { deps: [...read("go.mod").matchAll(/^\s*(?:require\s+)?(\S+)\s+v\S+\s*$/gm)].map((m) => m[1]), dev: [] };
  return { deps: null, dev: [] };
}

/** One project_dependencies row per locked package of every lockfile under the project. */
function appRows(root) {
  const rows = [];
  for (const rel of findLockfiles(root)) {
    const base = path.posix.basename(rel);
    if (!LANGUAGE[base]) continue;
    const dir = path.join(root, path.posix.dirname(rel));
    const { deps, dev } = declared(dir, base);
    const [language, manifest] = LANGUAGE[base];
    for (const [name, versions] of lockfileVersions(base, fs.readFileSync(path.join(root, rel), "utf8"))) {
      const isDev = dev.includes(name);
      const isDirect = deps === null || deps.includes(name) || isDev;
      rows.push({ project_path: dir, sub: path.posix.dirname(rel), manifest, name, version: [...versions].sort().at(-1), is_dev: isDev ? 1 : 0, language, is_direct: isDirect ? 1 : 0 });
    }
  }
  return rows;
}

async function buildAppDb(file, rows) {
  const { DatabaseSync } = await import("node:sqlite");
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const db = new DatabaseSync(file);
  try {
    loadAppSchema(db, fs.readFileSync(path.join(repoRoot, "contract", "app-schema.sql"), "utf8"));
    const insert = db.prepare("INSERT INTO project_dependencies (project_path, manifest_type, package_name, version, is_dev, language, is_direct, detected_from) VALUES (?, ?, ?, ?, ?, ?, ?, 'lockfile')");
    for (const r of rows) insert.run(r.project_path, r.manifest, r.name, r.version, r.is_dev, r.language, r.is_direct);
  } finally {
    db.close();
  }
}

const rows = appRows(project);
const subs = [...new Set(rows.map((r) => r.sub))].sort();
if (subs.length < 2) fail(`${project} has ${subs.length} lockfile director${subs.length === 1 ? "y" : "ies"}; the arm needs a project with at least two sub-projects`);
const drop = opt("drop") ?? subs.find((s) => s !== ".") ?? subs[1];
if (!subs.includes(drop)) fail(`--drop ${drop} is not a lockfile directory of ${project} (${subs.join(", ")})`);
const fullDb = path.join(work, "app-full", "4da.db");
const partialDb = path.join(work, "app-partial", "4da.db");
await buildAppDb(fullDb, rows);
await buildAppDb(partialDb, rows.filter((r) => r.sub !== drop));

// ---------------------------------------------------------------------------------------------
// The three runs. One server data folder for all three, so their lookups share one cache.
// ---------------------------------------------------------------------------------------------

const home = path.join(work, "server-home");
const variants = [
  { id: "A", label: "no app database", dbPath: null },
  { id: "B", label: `app database covering ${subs.join(", ")}`, dbPath: fullDb },
  { id: "C", label: `app database without the rows of ${drop}`, dbPath: partialDb },
];

const NOT_CHECKED = /^\s*(NOT CHECKED|STALE)/;
async function run(v) {
  const s = await openSession({ server, cwd: project, env: hermeticEnv({ home, dbPath: v.dbPath, offline }) });
  try {
    let concise;
    for (let i = 0; i < 5; i++) {
      concise = await s.call("vulnerability_scan", {});
      if (offline || !NOT_CHECKED.test(String(concise.json?.summary ?? ""))) break;
    }
    const detailed = await s.call("vulnerability_scan", { response_format: "detailed", limit: 1000 });
    let plan;
    for (let i = 0; i < 5; i++) {
      plan = await s.call("upgrade_planner", { max_recommendations: 1000 });
      if (plan.json?.vulnerabilityDataAvailable !== false) break;
    }
    return { concise, detailed, plan, tools: (await s.tools()).length, stderr: s.state.stderr };
  } finally {
    await s.close();
  }
}

const facts = (r) => {
  const c = r.concise.json ?? {};
  const d = r.detailed.json ?? {};
  const p = r.plan.json ?? {};
  const key = (x) => `${x.ecosystem ? `${x.ecosystem}|` : ""}${x.package}@${x.current_version}`;
  return {
    errors: [r.concise, r.detailed, r.plan].filter((x) => x.isError).map((x) => x.text.slice(0, 200)),
    vulnerable_packages: (c.vulnerable_packages ?? []).map(key).sort(),
    total_dependencies_scanned: c.total_dependencies_scanned ?? null,
    total_vulnerable_packages: c.total_vulnerable_packages ?? null,
    by_severity: c.by_severity ?? null,
    by_advisory_severity: c.by_advisory_severity ?? null,
    advisory_rows: (d.vulnerabilities ?? []).map((v) => `${v.ecosystem}|${v.package}@${v.current_version}|${v.vuln_id}`).sort(),
    coverage_concise: c.coverage === undefined || c.coverage === null ? null : c.coverage,
    coverage_detailed: d.coverage === undefined || d.coverage === null ? null : d.coverage,
    plan_rows: (p.recommendations ?? []).map((x) => `${x.ecosystem}|${x.package}@${x.currentVersion}->${x.targetVersion ?? "none"} ${x.action}`).sort(),
    plan_mode: p.provenance?.mode ?? null,
    plan_vulnerability_data: p.vulnerabilityDataAvailable ?? null,
    summary: String(c.summary ?? r.concise.text).slice(0, 240),
  };
};

console.log(`app-mode: server ${server}\n  project ${project} (sub-projects ${subs.join(", ")}; C drops ${drop})${offline ? "\n  offline" : ""}`);
const results = {};
for (const v of variants) {
  const r = await run(v);
  results[v.id] = { ...v, tools: r.tools, facts: facts(r) };
  const f = results[v.id].facts;
  console.log(`  ${v.id} (${v.label}): ${f.total_dependencies_scanned} deps, ${f.total_vulnerable_packages} vulnerable, ${f.advisory_rows.length} advisory rows, ${f.plan_rows.length} plan rows, coverage ${f.coverage_concise ? "present" : "ABSENT"} / ${f.coverage_detailed ? "present" : "ABSENT"}, plan mode ${f.plan_mode}`);
}

// ---------------------------------------------------------------------------------------------
// The verdict: B and C against A, field by field, and coverage everywhere.
// ---------------------------------------------------------------------------------------------

const violations = [];
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const listDiff = (a, b) => ({ missing: a.filter((x) => !b.includes(x)), extra: b.filter((x) => !a.includes(x)) });
for (const v of variants) {
  const f = results[v.id].facts;
  for (const e of f.errors) violations.push(`${v.id} (${v.label}): error answer: ${e}`);
  if (!f.coverage_concise) violations.push(`${v.id} (${v.label}): the concise scan has no coverage object, so it does not say which lockfiles it read`);
  if (!f.coverage_detailed) violations.push(`${v.id} (${v.label}): the detailed scan has no coverage object`);
}
const a = results.A.facts;
if (a.vulnerable_packages.length === 0 && !offline) violations.push(`A (no app database) found no vulnerable package in a project built to have some: the comparison checks nothing (${a.summary})`);
for (const id of ["B", "C"]) {
  const v = results[id];
  const f = v.facts;
  for (const field of ["vulnerable_packages", "advisory_rows", "plan_rows"]) {
    if (same(a[field], f[field])) continue;
    const d = listDiff(a[field], f[field]);
    violations.push(`${id} (${v.label}): ${field} differ from A: missing ${d.missing.length ? d.missing.slice(0, 8).join(", ") : "none"}; extra ${d.extra.length ? d.extra.slice(0, 8).join(", ") : "none"}`);
  }
  for (const field of ["total_dependencies_scanned", "total_vulnerable_packages", "by_severity", "by_advisory_severity", "plan_vulnerability_data"]) {
    if (!same(a[field], f[field])) violations.push(`${id} (${v.label}): ${field} ${JSON.stringify(f[field])}, A ${JSON.stringify(a[field])}`);
  }
}

const body = { harness: "app-mode", server, project, sub_projects: subs, dropped: drop, offline, violations, results };
if (out) {
  fs.mkdirSync(out, { recursive: true });
  fs.writeFileSync(path.join(out, "app-mode.json"), JSON.stringify(body, null, 1));
}
console.log(violations.length ? `app-mode: FAILED, ${violations.length} violation(s)\n  ${violations.join("\n  ")}` : "app-mode: OK, the three agree and every scan states its coverage");
if (!flag("keep")) rmTree(work);
process.exitCode = violations.length ? 1 : 0;
