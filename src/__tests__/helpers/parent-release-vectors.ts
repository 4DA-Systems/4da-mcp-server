// SPDX-License-Identifier: Apache-2.0
/**
 * The TypeScript side of the shared `parent_release` vectors (4DA #981, vectors/parent_release.jsonl;
 * the Rust runner is src-tauri/src/osv/parent_release_vectors.rs and parent_release_graph_vectors.rs).
 *
 * Each line is run through this server's own pipeline end to end, not a copy of the rule: a project
 * is built on disk from the line (package.json and a package-lock v3), the registry and OSV.dev are
 * answered from the line (npm abbreviated documents, `/v1/query` and `/v1/querybatch`), and
 * upgrade_planner plans it. What it names is compared with the line:
 * - per-row lines (pr-001..pr-006): the parent's own row target after the raise, and per row the
 *   parent's outcome, its smallest admitting release, the release named, `breaking`, the
 *   requirement, `peer`, `resolves_to`, the command (the declared operator kept) and the refresh;
 * - `mode: "graph"` lines (pr-007, pr-008): each declared package's own row, each vulnerable copy's
 *   target, and per parent link the release ({to, smallest, floor, brings}) and its levers.
 */

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import Database from "better-sqlite3";
import { LiveIntelligence } from "../../live/index.js";
import { advisoryAffects, advisoryRanges } from "../../live/osv-ranges.js";
import type { OsvVulnerability } from "../../live/types.js";
import { executeUpgradePlanner } from "../../tools/upgrade-planner.js";
import { parentOutcomes, type ParentUpgrade } from "../../tools/upgrade-planner-fixpaths.js";
import { compareVersions } from "../../live/version-compare.js";
import type { FourDADatabase } from "../../db.js";

type Json = Record<string, any>;
type Window = { introduced: string; fixed?: string; last_affected?: string };

/** `{id, ranges: [{introduced, fixed | last_affected}]}` as an OSV record for `name`. */
function record(id: string, name: string, ranges: Window[], ecosystem = "npm", extra: Json = {}): OsvVulnerability {
  // A line's optional aliases, cwe_ids and summary reach the malware predicate as OSV gives them.
  return {
    id,
    summary: typeof extra.summary === "string" ? extra.summary : `${name} advisory ${id}`,
    ...(Array.isArray(extra.aliases) ? { aliases: extra.aliases } : {}),
    database_specific: { severity: "HIGH", ...(Array.isArray(extra.cwe_ids) ? { cwe_ids: extra.cwe_ids } : {}) },
    affected: [
      {
        package: { name, ecosystem },
        ranges: ranges.map((w) => ({
          type: "SEMVER",
          events: [{ introduced: w.introduced }, ...(w.fixed ? [{ fixed: w.fixed }] : []), ...(w.last_affected ? [{ last_affected: w.last_affected }] : [])],
        })),
      },
    ],
  };
}

interface World {
  /** package -> npm abbreviated document */
  registry: Record<string, Json>;
  /** package -> OSV records */
  osv: Record<string, OsvVulnerability[]>;
  /** crate -> sparse index lines (index.crates.io) */
  crates?: Record<string, string>;
  ecosystem?: string;
}

async function withWorld<T>(world: World, run: () => Promise<T>): Promise<T> {
  const prior = globalThis.fetch;
  const priorOffline = process.env.FOURDA_OFFLINE;
  delete process.env.FOURDA_OFFLINE;
  globalThis.fetch = (async (input: string | URL, init?: RequestInit) => {
    const url = String(input);
    const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
    if (url.endsWith("/v1/querybatch")) {
      const { queries } = JSON.parse(String(init?.body)) as { queries: Array<{ package: { name: string }; version: string }> };
      return json({
        results: queries.map((q) => ({
          vulns: (world.osv[q.package.name] ?? [])
            .filter((v) => {
              const eco = world.ecosystem ?? "npm";
              const r = advisoryRanges(v, q.package.name, eco);
              return r !== null && advisoryAffects(r, q.version, eco);
            })
            .map((v) => ({ id: v.id })),
        })),
      });
    }
    if (url.includes("/v1/vulns/")) {
      const id = decodeURIComponent(url.split("/v1/vulns/")[1]);
      const found = Object.values(world.osv).flat().find((v) => v.id === id);
      return found ? json(found) : json({}, 404);
    }
    if (url === "https://api.osv.dev/v1/query") {
      const q = JSON.parse(String(init?.body)) as { package: { name: string } };
      return json({ vulns: world.osv[q.package.name] ?? [] });
    }
    const crate = /^https:\/\/index\.crates\.io\/.*\/([^/]+)$/.exec(url);
    if (crate) return world.crates?.[crate[1]] !== undefined ? new Response(world.crates[crate[1]], { status: 200 }) : new Response("", { status: 404 });
    const npm = /^https:\/\/registry\.npmjs\.org\/([^/]+)(?:\/(.+))?$/.exec(url);
    if (npm) {
      const name = decodeURIComponent(npm[1]);
      const doc = world.registry[name];
      if (!doc) return json({}, 404);
      if (npm[2]) return json(doc.versions?.[decodeURIComponent(npm[2])] ?? {});
      return json({ name, ...doc });
    }
    return json({}, 404);
  }) as typeof fetch;
  try {
    return await run();
  } finally {
    globalThis.fetch = prior;
    if (priorOffline === undefined) delete process.env.FOURDA_OFFLINE;
    else process.env.FOURDA_OFFLINE = priorOffline;
  }
}

async function planIn(dir: string): Promise<Json> {
  const li = new LiveIntelligence(new Database(":memory:"));
  const { scanProjectTree, treeResolutionGroups } = await import("../../project-tree.js");
  const { entries, discovery } = scanProjectTree(dir);
  li.initFromProjectTree(dir, treeResolutionGroups(entries), discovery);
  return (await executeUpgradePlanner(null as unknown as FourDADatabase, { project_path: dir, max_recommendations: 200, include_dev: true }, li)) as Json;
}

function writeProject(dir: string, declared: Record<string, string>, entries: Record<string, Json>): void {
  fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ name: "vector", dependencies: declared }));
  const packages: Record<string, Json> = { "": { name: "vector", dependencies: declared } };
  for (const [name, entry] of Object.entries(entries)) packages[`node_modules/${name}`] = entry;
  fs.writeFileSync(path.join(dir, "package-lock.json"), JSON.stringify({ name: "vector", lockfileVersion: 3, packages }));
}

const highest = (versions: string[]) => [...versions].sort((a, b) => compareVersions(a, b, "npm")).pop()!;

/** What a per-row or graph line compares for one parent link. */
function outcomeOf(step: Json, parent: string) {
  return parentOutcomes(step as never).find((o) => o.parent === parent) ?? null;
}

// ---------------------------------------------------------------------------
// Per-row lines
// ---------------------------------------------------------------------------

/** A Cargo project for a per-row line: the parent declared as written, the copies locked under it, the sparse index. */
function cargoWorld(v: Json, dir: string): World {
  const p = v.parent;
  const rows = v.rows as Json[];
  const reg = 'source = "registry+https://github.com/rust-lang/crates.io-index"';
  fs.writeFileSync(path.join(dir, "Cargo.toml"), `[package]\nname = "vector"\nversion = "0.1.0"\nedition = "2021"\n\n[dependencies]\n${p.lever === "direct" ? `${p.name} = "${p.declared}"\n` : ""}`);
  const pkgs = [
    `[[package]]\nname = "vector"\nversion = "0.1.0"\ndependencies = [\n ${JSON.stringify(p.name)},\n]`,
    `[[package]]\nname = "${p.name}"\nversion = "${p.installed}"\n${reg}\ndependencies = [\n${rows.map((r) => ` ${JSON.stringify(r.pkg)},`).join("\n")}\n]`,
    ...rows.map((r) => `[[package]]\nname = "${r.pkg}"\nversion = "${r.installed}"\n${reg}`),
  ];
  fs.writeFileSync(path.join(dir, "Cargo.lock"), `version = 3\n\n${pkgs.join("\n\n")}\n`);
  const index = (vers: string, deps: Array<{ name: string; req: string }>) => JSON.stringify({ name: "", vers, yanked: false, deps: deps.map((d) => ({ ...d, kind: "normal", optional: false })) });
  const parentVersions = [...new Set([p.installed, ...(p.releases as string[])])];
  const crates: Record<string, string> = {
    [p.name]: parentVersions
      .map((ver) => index(ver, rows.flatMap((r) => {
        const req = r.requires?.[ver];
        return typeof req === "string" ? [{ name: r.pkg, req }] : [];
      })))
      .join("\n"),
  };
  const osv: Record<string, OsvVulnerability[]> = { [p.name]: (p.advisories as Json[]).map((a) => record(a.id, p.name, a.ranges, "crates.io", a)) };
  for (const r of rows) {
    crates[r.pkg] = [...new Set([r.installed, ...(r.releases as string[])])].map((ver) => index(ver, [])).join("\n");
    osv[r.pkg] = (r.advisories as Json[]).map((a) => record(a.id, r.pkg, a.ranges, "crates.io", a));
  }
  return { registry: {}, osv, crates, ecosystem: "crates.io" };
}

async function checkRows(v: Json, dir: string): Promise<string | null> {
  return compareRows(v, await planRows(v, dir));
}

/** The planner's result for a per-row line's world (for tests that read the reason text too). */
async function planRows(v: Json, dir: string): Promise<Json> {
  if (v.tool === "cargo") return withWorld(cargoWorld(v, dir), () => planIn(dir));
  const p = v.parent;
  const versions: Record<string, Json> = {};
  const all = [...new Set([p.installed, ...(p.releases as string[]), ...(p.latest ? [p.latest] : [])])];
  for (const ver of all) {
    const deps: Record<string, string> = {};
    const peers: Record<string, string> = {};
    for (const r of v.rows as Json[]) {
      const req = r.requires?.[ver];
      if (typeof req === "string") deps[r.pkg] = req;
      else if (req && typeof req === "object" && typeof req.peer === "string") peers[r.pkg] = req.peer;
      else if (ver === p.installed) deps[r.pkg] = r.installed;
    }
    versions[ver] = { dependencies: deps, ...(Object.keys(peers).length > 0 ? { peerDependencies: peers } : {}), ...(p.deprecated && ver === p.latest ? { deprecated: "deprecated" } : {}) };
  }
  const world: World = { registry: { [p.name]: { "dist-tags": { latest: p.latest ?? highest(all) }, versions } }, osv: { [p.name]: (p.advisories as Json[]).map((a) => record(a.id, p.name, a.ranges, "npm", a)) } };
  const entries: Record<string, Json> = { [p.name]: { version: p.installed, dependencies: Object.fromEntries((v.rows as Json[]).map((r) => [r.pkg, versions[p.installed].dependencies[r.pkg] ?? r.installed])) } };
  for (const r of v.rows as Json[]) {
    const rel = [...new Set([r.installed, ...(r.releases as string[])])];
    world.registry[r.pkg] = { "dist-tags": { latest: highest(rel) }, versions: Object.fromEntries(rel.map((x) => [x, {}])) };
    world.osv[r.pkg] = (r.advisories as Json[]).map((a) => record(a.id, r.pkg, a.ranges, "npm", a));
    entries[r.pkg] = { version: r.installed };
  }
  writeProject(dir, p.lever === "direct" ? { [p.name]: p.declared } : {}, entries);
  return withWorld(world, () => planIn(dir));
}

/** The planned rows against a per-row line's expectations. */
function compareRows(v: Json, result: Json): string | null {
  const p = v.parent;
  const recs = result.recommendations as Json[];
  const own = recs.find((r) => r.package === p.name && r.scope === "direct" && (r.reasons as string[]).some((x) => /known vulnerabilit/.test(x)));
  const parentTarget = own?.targetVersion ?? null;
  if (parentTarget !== (v.expect.parent_target ?? null)) return `parent_target: got ${parentTarget}, want ${v.expect.parent_target}`;
  for (const [i, r] of (v.rows as Json[]).entries()) {
    const want = v.expect.rows[i];
    const step = recs.find((x) => x.package === r.pkg && x.currentVersion === r.installed);
    if (!step) return `${r.pkg}: no plan row`;
    const o = outcomeOf(step, p.name);
    const u: ParentUpgrade | undefined = o?.upgrade;
    const lever = u?.levers.find((l) => l.name === p.name);
    const got = {
      pkg: r.pkg,
      outcome: o?.outcome ?? null,
      smallest: u?.to ? (u.smallest ?? u.to) : null,
      to: u?.to ?? null,
      breaking: u?.to ? u.breaking : false,
      requirement: u?.to ? (u.requirement ?? null) : null,
      peer: u?.peer === true,
      resolves_to: u?.to ? (u.resolvesTo ?? null) : null,
      command: lever?.commands?.[0]?.command ?? null,
      refresh: u?.refreshCommands?.[0]?.command ?? null,
    };
    if (JSON.stringify(got) !== JSON.stringify(want)) return `${r.pkg}: got ${JSON.stringify(got)}, want ${JSON.stringify(want)}`;
  }
  return null;
}

// ---------------------------------------------------------------------------
// Graph lines
// ---------------------------------------------------------------------------

async function checkGraph(v: Json, dir: string, seen?: (result: Json) => void): Promise<string | null> {
  const nodes = v.nodes as Array<[string, string, boolean]>;
  const edges = v.edges as Array<[string, string, string, string]>;
  const entries: Record<string, Json> = {};
  for (const [name, version] of nodes) {
    const deps = Object.fromEntries(edges.filter((e) => e[0] === name && e[1] === version).map((e) => [e[2], e[3]]));
    entries[name] = { version, ...(Object.keys(deps).length > 0 ? { dependencies: deps } : {}) };
  }
  const declared = Object.fromEntries(nodes.filter((n) => n[2]).map((n) => [n[0], n[1]]));
  writeProject(dir, declared, entries);
  const world: World = { registry: v.registry, osv: {} };
  for (const a of v.advisories as Json[]) (world.osv[a.package] ??= []).push(record(a.id, a.package, a.ranges, "npm", a));
  const result = await withWorld(world, () => planIn(dir));
  seen?.(result);
  const recs = result.recommendations as Json[];
  for (const row of (v.expect.rows ?? []) as Json[]) {
    const rec = recs.find((x) => x.package === row.pkg && x.currentVersion === row.installed);
    if ((rec?.targetVersion ?? null) !== row.to) return `${row.pkg} row: got ${rec?.targetVersion ?? null}, want ${row.to}`;
  }
  const releaseOf = (o: ReturnType<typeof outcomeOf>) =>
    o?.outcome === "release" && o.upgrade
      ? { to: o.upgrade.to, smallest: o.upgrade.smallest ?? null, floor: null, brings: null }
      : (o?.outcome ?? "unread");
  for (const copy of v.expect.copies as Json[]) {
    const step = recs.find((x) => x.package === copy.pkg && x.currentVersion === copy.installed);
    if (!step) return `${copy.pkg}: no plan row`;
    if (step.targetVersion !== copy.target) return `${copy.pkg}: target ${step.targetVersion}, want ${copy.target}`;
    for (const want of copy.links as Json[]) {
      const o = outcomeOf(step, want.parent);
      const u = o?.upgrade;
      const direct = u?.levers.length === 1 && u.levers[0].name === want.parent;
      const got = {
        parent: want.parent,
        release: releaseOf(o),
        levers: direct || !u ? [] : u.levers.map((l) => ({ name: l.name, release: l.outcome ?? { to: l.to, smallest: l.smallest ?? null, floor: l.floor ?? null, brings: l.brings ?? null } })),
        lever_unknown: Boolean(u?.leverUnknown),
      };
      if (JSON.stringify(got) !== JSON.stringify(want)) return `${copy.pkg}: got ${JSON.stringify(got)}, want ${JSON.stringify(want)}`;
    }
  }
  return null;
}

/** A per-row or graph line's planner result, run in a fresh project (the recommendations, with their reasons). */
export async function planParentReleaseLine(v: Json): Promise<Json> {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "parent-release-vector-"));
  try {
    if (v.mode !== "graph") return await planRows(v, dir);
    let captured: Json = null;
    await checkGraph(v, dir, (r) => (captured = r));
    return captured;
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

export async function checkParentRelease(v: Json): Promise<string | null> {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "parent-release-vector-"));
  try {
    return v.mode === "graph" ? await checkGraph(v, dir) : await checkRows(v, dir);
  } catch (e) {
    return `error: ${(e as Error).message}`;
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}
