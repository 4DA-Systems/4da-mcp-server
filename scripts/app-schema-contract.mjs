// SPDX-License-Identifier: Apache-2.0
/**
 * App-schema contract runner: every SQL statement this server issues, checked
 * against the desktop app's real schema.
 *
 * The desktop app (github.com/4DA-Systems/4DA) owns the database this server
 * reads. It publishes the schema its migrations produce as
 * `src-tauri/contract/app-schema.sql`; `contract/app-schema.sql` here is a copy.
 *
 * What it does:
 *   1. Runs the whole test suite with statement recording on
 *      (FOURDA_SQL_CORPUS, see src/test-setup.ts). The suite includes
 *      app-schema-contract.test.ts, which calls every tool against the app
 *      schema; the other suites reach code paths that need specific data.
 *   2. Loads the app schema into an empty database, applies the tables this
 *      server creates for itself in the app's database (live_cache, ...), then
 *      re-prepares every statement server code issued. Preparing is enough:
 *      SQLite resolves every table and column at prepare time.
 *   3. Checks every hasColumn() probe against the schema: a probe that comes
 *      back false is a tool quietly running in a degraded mode.
 *   4. Reports how many of the server's `.prepare(` call sites the run
 *      reached, and fails below a floor so coverage cannot quietly erode.
 *
 * Usage:
 *   node scripts/app-schema-contract.mjs [--schema <app-schema.sql>] [--corpus <dir>] [--min-coverage 0.8]
 *     --schema  the schema to check against (default contract/app-schema.sql;
 *               the app's CI passes its own, freshly generated file)
 *     --corpus  reuse a recorded corpus instead of running the suite
 */
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, readdirSync, rmSync, existsSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import Database from "better-sqlite3";
import { loadAppSchema, SCHEMA_ERROR } from "./app-schema-loader.mjs";

const root = dirname(dirname(fileURLToPath(import.meta.url)));

/**
 * Functions that only ever run against this server's OWN standalone database
 * (created by createMinimalSchema when no desktop app is installed). Their SQL
 * is checked by the normal test suite against that schema, not against the
 * app's.
 */
const STANDALONE_ONLY = new Set([
  "FourDADatabase.createMinimalSchema",
  "FourDADatabase.populateFromScan",
  "detectStandalone",
]);

function arg(name, fallback) {
  const i = process.argv.indexOf(`--${name}`);
  return i > -1 && process.argv[i + 1] ? process.argv[i + 1] : fallback;
}

const schemaPath = resolve(arg("schema", join(root, "contract", "app-schema.sql")));
const minCoverage = Number(arg("min-coverage", "0.8"));
const allowlistPath = join(root, "contract", "allowlist.json");

if (!existsSync(schemaPath)) {
  console.error(`app-schema contract: no schema at ${schemaPath}`);
  process.exit(2);
}

// --- 1. Record --------------------------------------------------------------
let corpusDir = arg("corpus", null);
let ownCorpus = false;
if (!corpusDir) {
  corpusDir = mkdtempSync(join(tmpdir(), "4da-sql-corpus-"));
  ownCorpus = true;
  const vitest = join(root, "node_modules", "vitest", "vitest.mjs");
  console.log(`Recording the suite's SQL (vitest run) against ${relative(root, schemaPath) || schemaPath} ...`);
  const run = spawnSync(process.execPath, [vitest, "run", "--reporter=dot"], {
    cwd: root,
    stdio: "inherit",
    env: { ...process.env, FOURDA_SQL_CORPUS: corpusDir, FOURDA_APP_SCHEMA: schemaPath },
  });
  if (run.status !== 0) {
    console.error("\napp-schema contract: the test suite failed (see above); nothing to check.");
    process.exit(run.status ?? 1);
  }
}

const recorded = readdirSync(corpusDir)
  .filter((f) => f.endsWith(".jsonl"))
  .flatMap((f) =>
    readFileSync(join(corpusDir, f), "utf8")
      .split("\n")
      .filter(Boolean)
      .map((line) => JSON.parse(line)),
  );
const entries = recorded.filter((e) => !STANDALONE_ONLY.has(e.fn));
if (ownCorpus) rmSync(corpusDir, { recursive: true, force: true });
if (entries.length === 0) {
  console.error("app-schema contract: the run recorded no statements. Is src/test-setup.ts recording?");
  process.exit(1);
}

// --- 2. Check statements ----------------------------------------------------
const allowlist = existsSync(allowlistPath)
  ? JSON.parse(readFileSync(allowlistPath, "utf8"))
  : { statements: [], columns: {} };
const usedAllow = new Set();
const allowedStatement = (sql) => {
  const hit = (allowlist.statements ?? []).find((a) => sql.includes(a.match));
  if (hit) usedAllow.add(`statement:${hit.match}`);
  return Boolean(hit);
};

const db = new Database(":memory:");
const { schemaVersion } = loadAppSchema(db, readFileSync(schemaPath, "utf8"));

const failures = [];
const where = (e) => `${e.file}:${e.line} (${e.fn})`;

// What this server adds to the app's database for itself is applied first, as
// it is at runtime: its own tables (CREATE ... IF NOT EXISTS, which never
// replaces one of the app's) and the columns ensureColumn() adds to app tables
// (agent_memory/developer_decisions `embedding`, `embedding_model`).
const ddl = entries.filter(
  (e) => e.kind === "exec" && (/^\s*(--[^\n]*\n\s*)*CREATE\s/i.test(e.sql) || /^\s*ALTER TABLE \w+ ADD COLUMN /i.test(e.sql)),
);
for (const e of new Map(ddl.map((e) => [e.sql, e])).values()) {
  try {
    db.exec(e.sql);
  } catch (error) {
    // ensureColumn() only adds a missing column; on a schema that already has it this is a no-op at runtime.
    if (/duplicate column name/i.test(error.message)) continue;
    if (!allowedStatement(e.sql)) failures.push({ kind: "ddl", where: where(e), error: error.message, sql: e.sql });
  }
}

const statements = new Map();
for (const e of entries.filter((e) => e.kind === "prepare")) {
  if (!statements.has(e.sql)) statements.set(e.sql, e);
}
for (const [sql, e] of statements) {
  try {
    db.prepare(sql);
  } catch (error) {
    if (allowedStatement(sql)) continue;
    failures.push({
      kind: SCHEMA_ERROR.test(error.message) ? "schema" : "prepare",
      where: where(e),
      error: error.message,
      sql: sql.replace(/\s+/g, " ").trim(),
    });
  }
}

// --- 3. Check hasColumn() probes ---------------------------------------------
const columns = (table) => {
  try {
    return new Set(db.pragma(`table_info("${table}")`).map((c) => c.name));
  } catch {
    return new Set();
  }
};
const probes = new Map();
// ensureColumn()'s own probe asks "is it missing yet?"; a false there is the
// normal first run, not a degraded tool.
for (const e of entries.filter((e) => e.kind === "hasColumn" && e.fn !== "FourDADatabase.ensureColumn")) {
  probes.set(`${e.table}.${e.column}`, e);
}
for (const [key, e] of probes) {
  if (columns(e.table).has(e.column)) continue;
  if (key in (allowlist.columns ?? {})) {
    usedAllow.add(`column:${key}`);
    continue;
  }
  failures.push({ kind: "probe", where: where(e), error: `hasColumn("${e.table}", "${e.column}") is false on the app schema` });
}

// Allowlist entries that matched nothing are stale and must go.
for (const a of allowlist.statements ?? []) {
  if (!usedAllow.has(`statement:${a.match}`)) failures.push({ kind: "allowlist", where: "contract/allowlist.json", error: `stale statement entry: ${a.match}` });
}
for (const key of Object.keys(allowlist.columns ?? {})) {
  if (!usedAllow.has(`column:${key}`)) failures.push({ kind: "allowlist", where: "contract/allowlist.json", error: `stale column entry: ${key}` });
}

// --- 4. Coverage -------------------------------------------------------------
function walk(dir) {
  return readdirSync(dir).flatMap((name) => {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) return name === "__tests__" ? [] : walk(p);
    return p.endsWith(".ts") && !name.startsWith("test-setup") ? [p] : [];
  });
}
const callsites = walk(join(root, "src")).flatMap((file) =>
  readFileSync(file, "utf8")
    .split("\n")
    .flatMap((line, i) => (line.includes(".prepare(") ? [`${relative(root, file).replaceAll("\\", "/")}:${i + 1}`] : [])),
);
// Every call site counts, standalone-only ones included: the floor is about
// the suite reaching the code, and those are reported as "not reached" here.
const reached = new Set(recorded.filter((e) => e.kind === "prepare").map((e) => `${e.file}:${e.line}`));
const inScope = callsites;
const covered = inScope.filter((site) => reached.has(site));
const coverage = inScope.length ? covered.length / inScope.length : 1;

// --- Report -------------------------------------------------------------------
console.log(`\napp-schema contract — schema_version ${schemaVersion ?? "?"} (${relative(root, schemaPath) || schemaPath})`);
console.log(`  statements re-prepared: ${statements.size}`);
console.log(`  hasColumn probes checked: ${probes.size}`);
console.log(`  server-owned tables applied: ${new Set(ddl.map((e) => e.sql)).size} DDL batches`);
console.log(`  .prepare( call sites reached: ${covered.length}/${inScope.length} (${(coverage * 100).toFixed(0)}%, floor ${(minCoverage * 100).toFixed(0)}%)`);
const unreached = inScope.filter((site) => !reached.has(site));
if (unreached.length) console.log(`  not reached: ${unreached.join(" ")}`);

if (coverage < minCoverage) {
  failures.push({ kind: "coverage", where: "suite", error: `only ${covered.length}/${inScope.length} call sites reached, below the ${minCoverage} floor` });
}

if (failures.length) {
  console.error(`\n${failures.length} contract failure(s):`);
  for (const f of failures) {
    console.error(`  [${f.kind}] ${f.where}\n    ${f.error}${f.sql ? `\n    ${f.sql.slice(0, 400)}` : ""}`);
  }
  console.error(
    "\nThe server and the desktop app disagree about the database. Either the server must follow the app's schema change, or the app change must keep what the server reads. See contract/README.md.",
  );
  process.exit(1);
}
console.log("\nOK: every statement and probe matches the app schema.");
