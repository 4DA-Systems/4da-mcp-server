// SPDX-License-Identifier: Apache-2.0
/**
 * App-mode fixtures: a desktop-app database built from a real app schema file, and the BUILT server
 * run over stdio with that database attached (FOURDA_DB_PATH) and OSV.dev stubbed from records held
 * in a file. Every other request is refused and recorded, so nothing reaches the network.
 */
import { spawn } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import Database from "better-sqlite3";
import { serverEntry } from "./stdio-session.js";
// @ts-expect-error -- plain ESM helper shared with scripts/app-schema-contract.mjs
import { loadAppSchema } from "../../../scripts/app-schema-loader.mjs";

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
export const VENDORED_APP_SCHEMA = path.join(repo, "contract", "app-schema.sql");
export const RELEASED_V103_SCHEMA = path.join(repo, "contract", "released", "v1.0.3.sql");
export { serverEntry };

/** A database file holding the app schema in `schemaFile`, then whatever `seed` writes. vec0 tables are plain stubs (loader). */
export function buildAppDb(file: string, schemaFile: string, seed?: (raw: Database.Database) => void): { vecTables: string[]; schemaVersion: number | null } {
  const raw = new Database(file);
  raw.pragma("synchronous = OFF");
  let loaded: { vecTables: string[]; schemaVersion: number | null } = { vecTables: [], schemaVersion: null };
  raw.transaction(() => {
    loaded = loadAppSchema(raw, fs.readFileSync(schemaFile, "utf-8")) as typeof loaded;
    seed?.(raw);
  })();
  raw.close();
  return loaded;
}

/** One `project_dependencies` row as the app writes it. */
export function appDependency(raw: Database.Database, projectPath: string, name: string, version: string, opts: { dev?: boolean; language?: string; manifest?: string } = {}): void {
  raw
    .prepare("INSERT INTO project_dependencies (project_path, manifest_type, package_name, version, is_dev, language, is_direct) VALUES (?, ?, ?, ?, ?, ?, 1)")
    .run(projectPath, opts.manifest ?? "package.json", name, version, opts.dev ? 1 : 0, opts.language ?? "javascript");
}

/** An OSV record affecting `name` below `fixed` (or exactly `versions`). */
export function osvRecord(id: string, name: string, ecosystem: string, affected: { fixed?: string; versions?: string[] }, severity = "HIGH"): Record<string, unknown> {
  return {
    id,
    modified: "2026-11-01T00:00:00Z",
    aliases: [],
    summary: `${name} advisory ${id}`,
    database_specific: { severity },
    affected: [
      {
        package: { name, ecosystem },
        ...(affected.versions ? { versions: affected.versions } : {}),
        ranges: affected.versions ? [] : [{ type: "SEMVER", events: [{ introduced: "0" }, ...(affected.fixed ? [{ fixed: affected.fixed }] : [])] }],
      },
    ],
  };
}

/** The preload the child runs: OSV.dev answered from the records file, everything else refused and logged. */
const PRELOAD = `
const fs = require("node:fs");
const records = JSON.parse(fs.readFileSync(process.env.A1123_OSV_RECORDS, "utf8"));
const log = process.env.A1123_FETCH_LOG;
const parts = (v) => String(v).replace(/^v/, "").split(/[.+-]/).map((x) => Number.parseInt(x, 10) || 0);
const cmp = (a, b) => { const pa = parts(a), pb = parts(b); for (let i = 0; i < Math.max(pa.length, pb.length); i++) { const d = (pa[i] || 0) - (pb[i] || 0); if (d) return d; } return 0; };
const affects = (r, name, eco, version) => (r.affected || []).some((a) => {
  if (!a.package || a.package.name !== name || a.package.ecosystem !== eco) return false;
  if ((a.versions || []).includes(version)) return true;
  return (a.ranges || []).some((g) => {
    const intro = (g.events.find((e) => "introduced" in e) || {}).introduced || "0";
    const fixed = (g.events.find((e) => "fixed" in e) || {}).fixed;
    return (intro === "0" || cmp(version, intro) >= 0) && (!fixed || cmp(version, fixed) < 0);
  });
});
const json = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
globalThis.fetch = async (input, init) => {
  const url = String(input && input.url ? input.url : input);
  fs.appendFileSync(log, url + "\\n");
  if (url === "https://api.osv.dev/v1/querybatch") {
    const { queries } = JSON.parse(String(init && init.body));
    return json({ results: queries.map((q) => ({ vulns: records.filter((r) => affects(r, q.package.name, q.package.ecosystem, q.version)).map((r) => ({ id: r.id, modified: r.modified })) })) });
  }
  if (url.startsWith("https://api.osv.dev/v1/vulns/")) {
    const id = decodeURIComponent(url.slice("https://api.osv.dev/v1/vulns/".length));
    const found = records.find((r) => r.id === id);
    return found ? json(found) : json({}, 404);
  }
  if (url === "https://api.osv.dev/v1/query") {
    const q = JSON.parse(String(init && init.body));
    const name = q.package && q.package.name, eco = q.package && q.package.ecosystem;
    const all = records.filter((r) => (r.affected || []).some((a) => a.package && a.package.name === name && a.package.ecosystem === eco));
    return json({ vulns: q.version ? all.filter((r) => affects(r, name, eco, q.version)) : all });
  }
  throw new TypeError("fetch blocked in test: " + url);
};
`;

export interface AppModeSession {
  results: Array<Record<string, unknown> & { _isError?: boolean }>;
  stderr: string;
  fetches: string[];
}

/**
 * Start the built server in `cwd` (with `dbPath` as FOURDA_DB_PATH, or no app database when null),
 * make the calls in order, and return each result's structured payload.
 */
export async function appModeSession(
  cwd: string,
  dbPath: string | null,
  calls: Array<[string, Record<string, unknown>]>,
  osv: Array<Record<string, unknown>>,
): Promise<AppModeSession> {
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "4da-a1123-appmode-"));
  const preload = path.join(scratch, "osv-stub.cjs");
  const records = path.join(scratch, "osv.json");
  const fetchLog = path.join(scratch, "fetches.log");
  fs.writeFileSync(preload, PRELOAD);
  fs.writeFileSync(records, JSON.stringify(osv));
  const env: NodeJS.ProcessEnv = { ...process.env };
  for (const k of ["FOURDA_DB_PATH", "FOURDA_SQLITE_DRIVER", "FOURDA_SQL_CORPUS", "NODE_OPTIONS", "FOURDA_OFFLINE", "FOURDA_PROJECT_DIR", "FOURDA_TEST_SERVER_ENTRY"]) delete env[k];
  const home = path.join(scratch, "home");
  Object.assign(env, {
    APPDATA: home,
    LOCALAPPDATA: home,
    XDG_DATA_HOME: home,
    HOME: home,
    USERPROFILE: home,
    FOURDA_MCP_HOME: path.join(home, "4da-mcp"),
    FOURDA_DATA_DIR: path.join(home, "no-app"),
    A1123_OSV_RECORDS: records,
    A1123_FETCH_LOG: fetchLog,
    ...(dbPath ? { FOURDA_DB_PATH: dbPath } : {}),
  });
  const child = spawn(process.execPath, ["--require", preload, serverEntry], { cwd, env, stdio: ["pipe", "pipe", "pipe"] });
  let stderr = "";
  let buffer = "";
  const pending = new Map<number, (m: { result?: unknown; error?: unknown }) => void>();
  child.stderr.on("data", (d) => (stderr += d));
  child.stdout.on("data", (d) => {
    buffer += d;
    let i: number;
    while ((i = buffer.indexOf("\n")) >= 0) {
      const line = buffer.slice(0, i).trim();
      buffer = buffer.slice(i + 1);
      if (!line) continue;
      const message = JSON.parse(line) as { id?: number; result?: unknown; error?: unknown };
      if (message.id !== undefined) pending.get(message.id)?.(message);
    }
  });
  const exited = new Promise<never>((_, reject) => child.on("exit", (code) => reject(new Error(`server exited (${code}): ${stderr.slice(-2000)}`))));
  let id = 0;
  const rpc = (method: string, params: unknown) =>
    Promise.race([
      new Promise<{ result?: unknown; error?: unknown }>((resolve) => {
        pending.set(++id, resolve);
        child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
      }),
      exited,
    ]);
  try {
    await rpc("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "a1123-appmode", version: "1" } });
    child.stdin.write(JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) + "\n");
    const results: AppModeSession["results"] = [];
    for (const [name, args] of calls) {
      const r = (await rpc("tools/call", { name, arguments: args })) as { result?: { isError?: boolean; content?: Array<{ text?: string }>; structuredContent?: Record<string, unknown> }; error?: unknown };
      const text = r.result?.content?.map((c) => c.text ?? "").join("\n") ?? JSON.stringify(r.error);
      let payload: Record<string, unknown>;
      try {
        payload = (r.result?.structuredContent ?? JSON.parse(text)) as Record<string, unknown>;
      } catch {
        payload = { text };
      }
      results.push(r.result?.isError ? { ...payload, _isError: true } : payload);
    }
    const fetches = fs.existsSync(fetchLog) ? fs.readFileSync(fetchLog, "utf8").split("\n").filter(Boolean) : [];
    return { results, stderr, fetches };
  } finally {
    exited.catch(() => undefined);
    const gone = child.exitCode !== null ? Promise.resolve() : new Promise((resolve) => child.once("exit", resolve));
    child.kill();
    await gone;
    try {
      fs.rmSync(scratch, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
    } catch {
      // Windows can hold a just-exited child's files for a moment; left for the OS temp cleaner.
    }
  }
}

/** A package-lock.json (v3) installing `deps` at the root of `dir`, with its package.json. */
export function npmProject(dir: string, deps: Record<string, string>, devDeps: Record<string, string> = {}): void {
  fs.mkdirSync(dir, { recursive: true });
  const name = path.basename(dir).toLowerCase().replace(/[^a-z0-9-]/g, "-") || "fixture";
  fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ name, version: "1.0.0", dependencies: deps, devDependencies: devDeps }, null, 2));
  const packages: Record<string, unknown> = { "": { name, version: "1.0.0", dependencies: deps, devDependencies: devDeps } };
  for (const [dep, version] of Object.entries(deps)) packages[`node_modules/${dep}`] = { version, resolved: `https://registry.npmjs.org/${dep}/-/${dep}-${version}.tgz`, integrity: "sha512-AAAA" };
  for (const [dep, version] of Object.entries(devDeps)) packages[`node_modules/${dep}`] = { version, dev: true, resolved: `https://registry.npmjs.org/${dep}/-/${dep}-${version}.tgz`, integrity: "sha512-AAAA" };
  fs.writeFileSync(path.join(dir, "package-lock.json"), JSON.stringify({ name, version: "1.0.0", lockfileVersion: 3, requires: true, packages }, null, 2));
}
