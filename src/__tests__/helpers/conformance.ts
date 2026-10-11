// SPDX-License-Identifier: Apache-2.0
/**
 * The TypeScript engine, scored against the 4DA dependency-engine conformance
 * corpus (github.com/4DA-Systems/4DA, src-tauri/tests/conformance; format in
 * its README). A line-for-line mirror of the Rust reference harness,
 * src-tauri/src/osv/conformance_tests.rs: the same key normalisation, alias
 * grouping, counts, silent-drop rule and ratchet comparison, so the two
 * engines are measured on one truth with one ruler.
 *
 * The engine run is the server's own path, offline: the project-tree walk
 * (scanProjectTree + treeResolutionGroups) over each case directory, the
 * lockfile readers through LiveIntelligence, and a vulnerability scan whose
 * advisory source serves only the corpus's pinned OSV records
 * (PinnedRecordsSource). The scan covers direct devDependencies too
 * (include_dev): the truth is every package the lockfiles install.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { LiveIntelligence } from "../../live/index.js";
import { PinnedRecordsSource } from "../../live/pinned-advisories.js";
import type { OsvVulnerability } from "../../live/types.js";
import { scanProjectTree, treeResolutionGroups } from "../../project-tree.js";

// ============================================================================
// Corpus format (README "expected/<id>.json (schema 1)")
// ============================================================================

export interface LockfileRow {
  path: string;
  dir: string;
  format: string;
  ecosystem: string;
  status: "supported" | "unsupported";
  truth_packages?: number;
  reason?: string;
}

export interface Expected {
  schema: number;
  case: string;
  lockfiles: LockfileRow[];
  inventory: { count: number; packages: string[] };
  findings: Array<{ ecosystem: string; dir: string; package: string; version: string; ids: string[] }>;
}

export interface Case {
  id: string;
  dir: string;
  expected: Expected;
}

export interface EcoThreshold {
  findings_precision: number;
  findings_recall: number;
  inventory_precision: number;
  inventory_recall: number;
  max_silent_drops: number;
}

export interface Thresholds {
  schema: number;
  about?: string;
  ecosystems: Record<string, EcoThreshold>;
  /** Ecosystems whose lockfiles this engine does not read at all: scored and printed, never asserted. */
  unsupported_by_engine: Record<string, string>;
}

export interface DisagreementGroup {
  verdict: string;
  reason: string;
  /** `case<TAB>kind<TAB>MISSED|EXTRA<TAB>key`, as the diff prints them. */
  diffs: string[];
}

export interface DisagreementReport {
  schema: number;
  about?: string;
  engine_disagreements: DisagreementGroup[];
}

const readJson = <T>(file: string): T => JSON.parse(fs.readFileSync(file, "utf8")) as T;

export function loadCases(corpus: string): Case[] {
  return fs
    .readdirSync(path.join(corpus, "cases"))
    .filter((id) => fs.existsSync(path.join(corpus, "cases", id, "case.json")))
    .sort()
    .map((id) => ({
      id,
      dir: path.join(corpus, "cases", id),
      expected: readJson<Expected>(path.join(corpus, "expected", `${id}.json`)),
    }));
}

// ============================================================================
// Key normalisation (README "Key normalisation"; Rust norm_name/norm_version)
// ============================================================================

export function normName(eco: string, name: string): string {
  if (eco === "PyPI") {
    let out = "";
    for (const ch of name.toLowerCase()) {
      const sep = ch === "-" || ch === "_" || ch === ".";
      if (!(sep && out.endsWith("-"))) out += sep ? "-" : ch;
    }
    return out;
  }
  if (eco === "Go") return name;
  return name.toLowerCase();
}

/** Length of the leading `\d+(\.\d+)*` release segment of a PEP 440 version. */
function pep440ReleaseLen(v: string): number {
  let end = 0;
  let i = 0;
  while (i < v.length) {
    const start = i;
    while (i < v.length && v[i] >= "0" && v[i] <= "9") i++;
    if (i === start) break;
    end = i;
    if (i < v.length && v[i] === ".") i++;
    else break;
  }
  return end;
}

export function normVersion(eco: string, version: string): string {
  const v = version.trim();
  const stripV = (s: string) => (s.startsWith("v") && /^[0-9]/.test(s.slice(1)) ? s.slice(1) : s);
  if (eco === "Go" || eco === "Packagist") return stripV(v);
  if (eco === "PyPI") {
    const lower = v.toLowerCase();
    const w = lower.startsWith("v") ? lower.slice(1) : lower;
    const len = pep440ReleaseLen(w);
    const parts = w.slice(0, len).split(".");
    while (parts.length > 1 && /^0+$/.test(parts[parts.length - 1])) parts.pop();
    return `${parts.join(".")}${w.slice(len)}`;
  }
  return v;
}

export const invKey = (eco: string, dir: string, name: string, version: string) =>
  `${eco}|${dir}|${normName(eco, name)}|${normVersion(eco, version)}`;

// ============================================================================
// Alias grouping (Rust AliasUnion::canonical_map)
// ============================================================================

/** id -> its alias group's representative: the smallest non-CVE id, else the smallest. */
export function canonicalIds(records: OsvVulnerability[]): Map<string, string> {
  const parent = new Map<string, string>();
  const find = (x: string): string => {
    let root = x;
    while ((parent.get(root) ?? root) !== root) root = parent.get(root)!;
    let cur = x;
    while (cur !== root) {
      const next = parent.get(cur) ?? cur;
      parent.set(cur, root);
      cur = next;
    }
    if (!parent.has(root)) parent.set(root, root);
    return root;
  };
  for (const r of records) {
    find(r.id);
    for (const alias of r.aliases ?? []) {
      const [ra, rb] = [find(r.id), find(alias)];
      if (ra !== rb) parent.set(ra, rb);
    }
  }
  const rank = (s: string): [number, string] => [s.startsWith("CVE-") ? 1 : 0, s];
  const less = (a: string, b: string) => {
    const [x, y] = [rank(a), rank(b)];
    return x[0] !== y[0] ? x[0] < y[0] : x[1] < y[1];
  };
  const best = new Map<string, string>();
  const ids = [...parent.keys()];
  for (const id of ids) {
    const root = find(id);
    const slot = best.get(root);
    if (slot === undefined || less(id, slot)) best.set(root, id);
  }
  return new Map(ids.map((id) => [id, best.get(find(id))!]));
}

// ============================================================================
// Running the engine
// ============================================================================

export interface EngineRun {
  inventory: Map<string, Set<string>>;
  findings: Map<string, Set<string>>;
  /** Per case: the raw finding rows, for the dump. */
  raw: Map<string, Array<{ ecosystem: string; dir: string; package: string; version: string; id: string; aliases: string[] }>>;
}

const relDir = (root: string, dir: string) => {
  const rel = path.relative(root, dir).replace(/\\/g, "/");
  return rel === "" ? "." : rel;
};

export async function runEngine(cases: Case[], source: PinnedRecordsSource, canon: Map<string, string>): Promise<EngineRun> {
  const run: EngineRun = { inventory: new Map(), findings: new Map(), raw: new Map() };
  for (const c of cases) {
    const { entries, discovery } = scanProjectTree(c.dir);
    const live = new LiveIntelligence(null, { advisorySource: source });
    live.initFromProjectTree(c.dir, treeResolutionGroups(entries), discovery);
    const inv = new Set<string>();
    for (const dep of live.getAuditDeps()) {
      if (dep.version === null) continue;
      for (const dir of dep.sourceDirs) inv.add(invKey(dep.ecosystem, relDir(c.dir, dir), dep.name, dep.version));
    }
    run.inventory.set(c.id, inv);
    const findings = new Set<string>();
    const raw: NonNullable<ReturnType<EngineRun["raw"]["get"]>> = [];
    if (live.isInitialized()) {
      const scan = await live.scanVulnerabilities(c.dir, { includeDev: true });
      if (scan.offline) throw new Error(`conformance: the pinned scan of ${c.id} came back offline`);
      for (const v of scan.vulnerabilities) {
        const group = canon.get(v.vulnId) ?? v.vulnId;
        for (const dir of v.sourceDirs) {
          const d = relDir(c.dir, dir);
          findings.add(`${invKey(v.ecosystem, d, v.package, v.currentVersion)}|${group}`);
          raw.push({ ecosystem: v.ecosystem, dir: d, package: v.package, version: v.currentVersion, id: v.vulnId, aliases: v.aliases });
        }
      }
    }
    run.findings.set(c.id, findings);
    run.raw.set(c.id, raw);
  }
  return run;
}

// ============================================================================
// Scoring (Rust Counts / tally / score)
// ============================================================================

export class Counts {
  tp = 0;
  fp = 0;
  fn = 0;
  /** No claims at all is vacuously precise. */
  precision(): number {
    return this.tp + this.fp === 0 ? 1 : this.tp / (this.tp + this.fp);
  }
  /** Nothing to find is vacuously complete. */
  recall(): number {
    return this.tp + this.fn === 0 ? 1 : this.tp / (this.tp + this.fn);
  }
}

export interface Score {
  findings: Map<string, Counts>;
  inventory: Map<string, Counts>;
  /** Per ecosystem: `case/path (format)`. */
  silentDrops: Map<string, string[]>;
  diffs: string[];
}

const ecoOf = (key: string) => key.split("|")[0];

function tally(byEco: Map<string, Counts>, diffs: string[], id: string, kind: string, truth: Set<string>, engine: Set<string>) {
  const keys = [...new Set([...truth, ...engine])].sort();
  for (const k of keys) {
    const eco = ecoOf(k);
    let c = byEco.get(eco);
    if (!c) byEco.set(eco, (c = new Counts()));
    const [t, e] = [truth.has(k), engine.has(k)];
    if (t && e) c.tp++;
    else if (t) {
      c.fn++;
      diffs.push(`${id}\t${kind}\tMISSED\t${k}`);
    } else {
      c.fp++;
      diffs.push(`${id}\t${kind}\tEXTRA\t${k}`);
    }
  }
}

export function expectedFindingKeys(c: Case, canon: Map<string, string>): Set<string> {
  return new Set(
    c.expected.findings.map((f) => {
      const first = f.ids[0] ?? "";
      return `${invKey(f.ecosystem, f.dir, f.package, f.version)}|${canon.get(first) ?? first}`;
    }),
  );
}

export function score(cases: Case[], run: EngineRun, canon: Map<string, string>): Score {
  const s: Score = { findings: new Map(), inventory: new Map(), silentDrops: new Map(), diffs: [] };
  for (const c of cases) {
    const engineInv = run.inventory.get(c.id) ?? new Set<string>();
    tally(s.inventory, s.diffs, c.id, "inventory", new Set(c.expected.inventory.packages), engineInv);
    tally(s.findings, s.diffs, c.id, "finding", expectedFindingKeys(c, canon), run.findings.get(c.id) ?? new Set());
    for (const lf of c.expected.lockfiles.filter((l) => l.status === "supported")) {
      const prefix = `${lf.ecosystem}|${lf.dir}|`;
      if ((lf.truth_packages ?? 0) > 0 && ![...engineInv].some((k) => k.startsWith(prefix))) {
        const list = s.silentDrops.get(lf.ecosystem) ?? [];
        list.push(`${c.id}/${lf.path} (${lf.format})`);
        s.silentDrops.set(lf.ecosystem, list);
      }
    }
  }
  return s;
}

/** Truncated, not rounded, to 4 decimals: the ratchet value a measurement supports. */
export const truncate4 = (x: number) => Math.floor(x * 10_000 + 1e-9) / 10_000;

export function reportTable(s: Score, unsupported: Record<string, string>): string {
  const ecos = [...new Set([...s.findings.keys(), ...s.inventory.keys(), ...s.silentDrops.keys()])].sort();
  const pad = (v: string | number, n: number) => String(v).padStart(n);
  const lines = [
    `${"ecosystem".padEnd(11)} ${pad("f.TP", 6)} ${pad("FP", 5)} ${pad("FN", 5)} ${pad("prec", 8)} ${pad("recall", 8)} | ${pad("inv.TP", 7)} ${pad("FP", 6)} ${pad("FN", 6)} ${pad("prec", 8)} ${pad("recall", 8)} | drops`,
  ];
  for (const eco of ecos) {
    const f = s.findings.get(eco) ?? new Counts();
    const i = s.inventory.get(eco) ?? new Counts();
    const note = unsupported[eco] ? "  unsupported-by-engine" : "";
    lines.push(
      `${eco.padEnd(11)} ${pad(f.tp, 6)} ${pad(f.fp, 5)} ${pad(f.fn, 5)} ${pad(f.precision().toFixed(4), 8)} ${pad(f.recall().toFixed(4), 8)} | ${pad(i.tp, 7)} ${pad(i.fp, 6)} ${pad(i.fn, 6)} ${pad(i.precision().toFixed(4), 8)} ${pad(i.recall().toFixed(4), 8)} | ${pad(s.silentDrops.get(eco)?.length ?? 0, 5)}${note}`,
    );
  }
  return lines.join("\n");
}

/** Ratchet failures and "can rise" notes against thresholds.json. */
export function checkRatchet(s: Score, t: Thresholds): { failures: string[]; canRise: string[] } {
  const failures: string[] = [];
  const canRise: string[] = [];
  for (const [eco, floor] of Object.entries(t.ecosystems)) {
    const f = s.findings.get(eco) ?? new Counts();
    const i = s.inventory.get(eco) ?? new Counts();
    const measured: Array<[string, number, number]> = [
      ["findings_precision", f.precision(), floor.findings_precision],
      ["findings_recall", f.recall(), floor.findings_recall],
      ["inventory_precision", i.precision(), floor.inventory_precision],
      ["inventory_recall", i.recall(), floor.inventory_recall],
    ];
    for (const [name, got, min] of measured) {
      if (got + 1e-9 < min) failures.push(`${eco} ${name}: ${got.toFixed(4)} < ratchet ${min.toFixed(4)}`);
      else if (got > min + 0.0005) canRise.push(`${eco} ${name} ${min.toFixed(4)} -> ${truncate4(got).toFixed(4)}`);
    }
    const drops = s.silentDrops.get(eco)?.length ?? 0;
    if (drops > floor.max_silent_drops) failures.push(`${eco} silent drops ${drops} > ratchet ${floor.max_silent_drops}`);
    else if (drops < floor.max_silent_drops) canRise.push(`${eco} max_silent_drops ${floor.max_silent_drops} -> ${drops}`);
  }
  const measuredEcos = new Set([...s.findings.keys(), ...s.inventory.keys(), ...s.silentDrops.keys()]);
  for (const eco of measuredEcos) {
    if (!t.ecosystems[eco] && !t.unsupported_by_engine[eco]) {
      failures.push(`${eco}: in the corpus but neither ratcheted nor declared unsupported_by_engine in conformance/thresholds.json`);
    }
  }
  return { failures, canRise };
}

/** Diffs in supported ecosystems that no adjudicated group explains, and adjudicated diffs that no longer occur. */
export function checkDisagreements(
  s: Score,
  report: DisagreementReport,
  unsupported: Record<string, string>,
): { unexplained: string[]; resolved: string[] } {
  const listed = new Set(report.engine_disagreements.flatMap((g) => g.diffs));
  const supported = s.diffs.filter((d) => !unsupported[ecoOf(d.split("\t")[3] ?? "")]);
  const occurring = new Set(supported);
  return {
    unexplained: supported.filter((d) => !listed.has(d)),
    resolved: [...listed].filter((d) => !occurring.has(d)),
  };
}
