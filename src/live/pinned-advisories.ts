// SPDX-License-Identifier: Apache-2.0
/**
 * An advisory source that serves a fixed set of OSV records and decides
 * membership itself, with no network.
 *
 * The server asks OSV.dev which advisories affect a version (OsvHttpSource,
 * osv-scanner.ts). The 4DA conformance corpus pins every OSV record that names
 * one of its packages, byte for byte as api.osv.dev served it, and its truth
 * is OSV's own evaluation of each installed version. Scoring the engine
 * against that corpus offline needs the same question answered locally: which
 * pinned records affect this exact (ecosystem, name, version)? That is the
 * job of osv-ranges.ts (spans and explicit version lists, ordered the
 * ecosystem's way), so this also holds the local evaluator to OSV's answers.
 *
 * Withdrawn records are still returned by `query`: the scanner drops them
 * after reading the record, exactly as it does with OSV's answers.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import type { AdvisoryAnswer, AdvisorySource } from "./osv-scanner.js";
import { advisoryAffects, collectAffectedSpans } from "./osv-ranges.js";
import { samePackageName } from "./version-compare.js";
import type { OsvVulnerability, ResolvedDependency } from "./types.js";

/** The registry's identity for a package name, as an index key (samePackageName's rules). */
function nameKey(ecosystem: string, name: string): string {
  if (ecosystem === "PyPI") return name.toLowerCase().replace(/[-_.]+/g, "-");
  if (ecosystem === "crates.io") return name.toLowerCase().replace(/_/g, "-");
  return name;
}

/** Explicitly listed versions for one package of one record. */
function listedVersions(vuln: OsvVulnerability, name: string, ecosystem: string): string[] {
  return (vuln.affected ?? [])
    .filter((a) => a.package?.ecosystem === ecosystem && samePackageName(a.package.name, name, ecosystem))
    .flatMap((a) => a.versions ?? []);
}

export class PinnedRecordsSource implements AdvisorySource {
  readonly network = false;
  private readonly byId = new Map<string, OsvVulnerability>();
  private readonly byPackage = new Map<string, OsvVulnerability[]>();

  constructor(records: Iterable<OsvVulnerability>) {
    for (const record of records) {
      this.byId.set(record.id, record);
      const keys = new Set(
        (record.affected ?? []).flatMap((a) => (a.package ? [`${a.package.ecosystem}\0${nameKey(a.package.ecosystem, a.package.name)}`] : [])),
      );
      for (const key of keys) {
        const list = this.byPackage.get(key);
        if (list) list.push(record);
        else this.byPackage.set(key, [record]);
      }
    }
  }

  /** Every `*.json` OSV record in a directory (the corpus's `osv/`). */
  static fromDirectory(dir: string): PinnedRecordsSource {
    const files = fs.readdirSync(dir).filter((f) => f.endsWith(".json")).sort();
    return new PinnedRecordsSource(files.map((f) => JSON.parse(fs.readFileSync(path.join(dir, f), "utf8")) as OsvVulnerability));
  }

  get size(): number {
    return this.byId.size;
  }

  /** The ids of the pinned records that affect this exact version (withdrawn ones included). */
  affecting(ecosystem: string, name: string, version: string): string[] {
    const candidates = this.byPackage.get(`${ecosystem}\0${nameKey(ecosystem, name)}`) ?? [];
    return candidates
      .filter((vuln) =>
        advisoryAffects(
          { id: vuln.id, spans: collectAffectedSpans(vuln.affected, name, ecosystem), versions: listedVersions(vuln, name, ecosystem) },
          version,
          ecosystem,
        ),
      )
      .map((vuln) => vuln.id);
  }

  async query(deps: ResolvedDependency[]): Promise<AdvisoryAnswer> {
    return { ids: deps.map((dep) => (dep.version === null ? [] : this.affecting(dep.ecosystem, dep.name, dep.version))), failure: null };
  }

  async details(ids: string[]): Promise<Map<string, OsvVulnerability>> {
    const out = new Map<string, OsvVulnerability>();
    for (const id of ids) {
      const record = this.byId.get(id);
      if (record) out.set(id, record);
    }
    return out;
  }
}
