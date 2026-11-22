// SPDX-License-Identifier: Apache-2.0
/**
 * Shared by the a1123-advice suites: a project tree on disk, a live layer built from it as the
 * server builds one, OSV.dev and the registries stubbed at the HTTP boundary, and an app database
 * built from the vendored app schema.
 */

import { vi } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import Database from "better-sqlite3";
import { FourDADatabase } from "../../db.js";
import { LiveIntelligence } from "../../live/index.js";
import type { OsvVulnerability } from "../../live/types.js";
// @ts-expect-error -- plain ESM helper shared with scripts/app-schema-contract.mjs
import { loadAppSchema } from "../../../scripts/app-schema-loader.mjs";

type Ev = Record<string, string>;

/** An OSV.dev record for one package, with its own grade in `database_specific.severity`. */
export const adv = (id: string, name: string, events: Ev[], ecosystem = "npm", severity = "HIGH", extra: Partial<OsvVulnerability> = {}): OsvVulnerability => ({
  id,
  aliases: [],
  summary: `${name} advisory ${id}`,
  database_specific: { severity },
  affected: [{ package: { name, ecosystem }, ranges: [{ type: "SEMVER", events }] }],
  ...extra,
});
export const fixedIn = (v: string): Ev[] => [{ introduced: "0" }, { fixed: v }];

export interface Network {
  advisories: Record<string, OsvVulnerability[]>;
  /** index.crates.io: crate -> its sparse-index lines. */
  crates: Record<string, Array<{ vers: string; yanked?: boolean; deps?: Array<{ name: string; req: string; kind?: string }> }>>;
  npm: Record<string, { versions: Record<string, { dependencies?: Record<string, string> }>; latest: string }>;
  /** Every URL asked for. */
  asked: string[];
  /** When set, every OSV.dev request fails with this status. */
  osvDown?: number;
}

const cmp = (a: string, b: string) => a.replace(/^v/, "").localeCompare(b.replace(/^v/, ""), undefined, { numeric: true });
const affects = (v: OsvVulnerability, version: string) => {
  const events = v.affected![0].ranges![0].events;
  const fixed = events.find((e) => "fixed" in e)?.fixed;
  const introduced = events.find((e) => "introduced" in e)?.introduced;
  if (introduced && introduced !== "0" && cmp(version, introduced) < 0) return false;
  return fixed ? cmp(version, fixed) < 0 : true;
};

function sparsePath(name: string): string {
  const n = name.toLowerCase();
  return n.length <= 2 ? `${n.length}/${n}` : n.length === 3 ? `3/${n[0]}/${n}` : `${n.slice(0, 2)}/${n.slice(2, 4)}/${n}`;
}

/** Stubs fetch over `net` (read at call time). */
export function stubNetwork(net: Network): void {
  vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
    const url = String(input);
    net.asked.push(url);
    const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
    if (url.startsWith("https://api.osv.dev/") && net.osvDown) return json({ error: "unavailable" }, net.osvDown);
    if (url.endsWith("/v1/querybatch")) {
      const { queries } = JSON.parse(String(init?.body)) as { queries: Array<{ package: { name: string; ecosystem: string }; version: string }> };
      return json({
        results: queries.map((q) => ({
          vulns: (net.advisories[q.package.name] ?? [])
            .filter((v) => v.affected?.[0]?.package?.ecosystem === q.package.ecosystem && affects(v, q.version))
            .map((v) => ({ id: v.id, modified: "2026-11-01T00:00:00Z" })),
        })),
      });
    }
    if (url.includes("/v1/vulns/")) {
      const id = decodeURIComponent(url.split("/v1/vulns/")[1]);
      const found = Object.values(net.advisories).flat().find((v) => v.id === id);
      return found ? json(found) : json({}, 404);
    }
    if (url === "https://api.osv.dev/v1/query") {
      const q = JSON.parse(String(init?.body)) as { package: { name: string; ecosystem: string } };
      return json({ vulns: (net.advisories[q.package.name] ?? []).filter((v) => v.affected?.[0]?.package?.ecosystem === q.package.ecosystem) });
    }
    const npm = /^https:\/\/registry\.npmjs\.org\/([^/]+)(?:\/(.+))?$/.exec(url);
    if (npm) {
      const name = decodeURIComponent(npm[1]);
      const doc = net.npm[name];
      if (!doc) return json({}, 404);
      if (npm[2]) {
        const version = doc.versions[decodeURIComponent(npm[2])];
        return version ? json({ name, version: decodeURIComponent(npm[2]), ...version }) : json({ error: "version not found" }, 404);
      }
      return json({
        name,
        "dist-tags": { latest: doc.latest },
        versions: Object.fromEntries(Object.entries(doc.versions).map(([v, body]) => [v, { name, version: v, ...body }])),
        time: { created: "2015-01-01T00:00:00.000Z", ...Object.fromEntries(Object.keys(doc.versions).map((v, i) => [v, new Date(Date.UTC(2016, 0, 1 + i)).toISOString()])) },
      });
    }
    const crate = /^https:\/\/index\.crates\.io\/(.+)$/.exec(url);
    if (crate) {
      const name = Object.keys(net.crates).find((n) => sparsePath(n) === crate[1]);
      if (!name) return new Response("not found", { status: 404 });
      return new Response(
        net.crates[name].map((l) => JSON.stringify({ name, vers: l.vers, deps: (l.deps ?? []).map((d) => ({ kind: "normal", optional: false, ...d })), yanked: l.yanked === true })).join("\n"),
        { status: 200 },
      );
    }
    return json({}, 404);
  });
}

export function emptyNetwork(): Network {
  return { advisories: {}, crates: {}, npm: {}, asked: [] };
}

/** A fresh project directory. */
export function projectDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "4da-a1123-advice-"));
}

export function write(dir: string, file: string, body: string): void {
  fs.mkdirSync(path.dirname(path.join(dir, file)), { recursive: true });
  fs.writeFileSync(path.join(dir, file), body);
}

type LockEntry = { version: string; dev?: boolean; dependencies?: Record<string, string> };
/** A package-lock v3 project in `sub` of `dir`: `direct` is declared; `tree` is every installed entry. */
export function npmProject(dir: string, direct: Record<string, string>, tree: Record<string, LockEntry>, sub = "."): void {
  write(dir, path.join(sub, "package.json"), JSON.stringify({ name: "x", dependencies: direct }));
  const packages: Record<string, unknown> = { "": { name: "x", dependencies: direct } };
  for (const [n, e] of Object.entries(tree)) packages[`node_modules/${n}`] = e;
  write(dir, path.join(sub, "package-lock.json"), JSON.stringify({ name: "x", lockfileVersion: 3, packages }));
}

/** Cargo.lock as cargo writes it: the root package has no source. */
export function cargoLock(packages: Array<{ name: string; version: string; deps?: string[]; root?: boolean }>): string {
  return [
    "version = 4",
    "",
    ...packages.flatMap((p) => [
      "[[package]]",
      `name = "${p.name}"`,
      `version = "${p.version}"`,
      ...(p.root ? [] : ['source = "registry+https://github.com/rust-lang/crates.io-index"']),
      ...(p.deps && p.deps.length > 0 ? ["dependencies = [", ...p.deps.map((d) => ` "${d}",`), "]"] : []),
      "",
    ]),
  ].join("\n");
}

/**
 * zip 8.6.0 held by docx-rs 0.4.22 (4DA's own src-tauri): seven advisories fixed in 9.0.0 and
 * GHSA-m665-v7pm-7grj, rated critical by the advisory, fixed in 9.0.5; docx-rs's newest release
 * requires ^8.6.0, so the scan's verdict is blocked upstream.
 */
export function zipUnderDocx(dir: string, net: Network): void {
  net.advisories.zip = [
    ...["GHSA-9hj8-73fh-9963", "GHSA-hjqx-j4rw-g7xv", "GHSA-q7v9-x93c-xqv3", "RUSTSEC-2026-0367", "RUSTSEC-2026-0368", "GHSA-8hxf-qr8p-62x4", "RUSTSEC-2026-0430"].map((id) =>
      adv(id, "zip", fixedIn("9.0.0"), "crates.io", "HIGH"),
    ),
    adv("GHSA-m665-v7pm-7grj", "zip", fixedIn("9.0.5"), "crates.io", "CRITICAL", { aliases: ["CVE-2026-115905", "RUSTSEC-2026-0548"] }),
  ];
  net.crates.zip = [{ vers: "8.6.0" }, { vers: "9.0.0" }, { vers: "9.0.5" }, { vers: "9.5.1" }];
  net.crates["docx-rs"] = [{ vers: "0.4.22", deps: [{ name: "zip", req: "^8.6.0" }] }];
  write(dir, "Cargo.toml", '[package]\nname = "app"\nversion = "0.1.0"\n\n[dependencies]\ndocx-rs = "0.4"\n');
  write(
    dir,
    "Cargo.lock",
    cargoLock([
      { name: "app", version: "0.1.0", deps: ["docx-rs"], root: true },
      { name: "docx-rs", version: "0.4.22", deps: ["zip"] },
      { name: "zip", version: "8.6.0" },
    ]),
  );
}

/** The live layer as the server builds it for `dir`: the project tree walked, live lookups on. */
export async function liveFor(dir: string): Promise<LiveIntelligence> {
  const prior = process.env.FOURDA_OFFLINE;
  delete process.env.FOURDA_OFFLINE;
  try {
    const li = new LiveIntelligence(new Database(":memory:"));
    const { scanProjectTree, treeResolutionGroups } = await import("../../project-tree.js");
    const { entries, discovery } = scanProjectTree(dir);
    li.initFromProjectTree(dir, treeResolutionGroups(entries), discovery);
    return li;
  } finally {
    if (prior !== undefined) process.env.FOURDA_OFFLINE = prior;
  }
}

const here = path.dirname(fileURLToPath(import.meta.url));
const APP_SCHEMA = fs.readFileSync(path.resolve(here, "..", "..", "..", "contract", "app-schema.sql"), "utf-8");

/** An app database built from contract/app-schema.sql, with nothing in it. */
export function appDb(): { db: FourDADatabase; raw: Database.Database } {
  const raw = new Database(":memory:");
  loadAppSchema(raw, APP_SCHEMA);
  const db = Object.create(FourDADatabase.prototype) as FourDADatabase;
  (db as unknown as { db: Database.Database }).db = raw;
  return { db, raw };
}

/** A feed row as the app stores one: `hoursAgo` old, structured source rows unjudged. */
export function feedRow(
  raw: Database.Database,
  row: { source_type: string; source_id: string; title: string; content?: string; hoursAgo?: number; signal_type?: string | null; signal_priority?: string | null; relevance?: number; content_type?: string | null },
): number {
  const created = new Date(Date.now() - (row.hoursAgo ?? 1) * 3_600_000).toISOString().replace("T", " ").slice(0, 19);
  return Number(
    raw
      .prepare(
        `INSERT INTO source_items (source_type, source_id, url, title, content, content_hash, embedding, created_at, relevance_score, signal_type, signal_priority, content_type)
         VALUES (?, ?, ?, ?, ?, ?, X'00', ?, ?, ?, ?, ?)`,
      )
      .run(
        row.source_type,
        row.source_id,
        `https://example.com/${row.source_id}`,
        row.title,
        row.content ?? row.title,
        `h-${row.source_type}-${row.source_id}`,
        created,
        row.relevance ?? 0.7,
        row.signal_type === undefined ? "security_alert" : row.signal_type,
        row.signal_priority === undefined ? "advisory" : row.signal_priority,
        row.content_type === undefined ? "security_advisory" : row.content_type,
      ).lastInsertRowid,
  );
}
