// SPDX-License-Identifier: Apache-2.0
// Version-spec semantics per ecosystem: what a written spec selects, against a pinned version list.
import { execFileSync } from "node:child_process";
import path from "node:path";
import semver from "semver";
import { HERE } from "./lib-truth.mjs";

const goStrip = (v) => v.replace(/^v/, "").replace(/\+incompatible$/, "");
const isPre = (v) => v.includes("-");

/** Cargo requirement -> npm semver range (Cargo's default operator is caret, same as npm's ^). */
export function cargoToRange(req) {
  return req.split(",").map((p) => p.trim()).filter(Boolean).map((p) => (/^\d/.test(p) ? `^${p}` : p)).join(" ");
}

/**
 * spec facts: { exact, literal, floor, maxSat, nSat, lowerBounded, error }
 *  exact   - the spec is an exact pin (that version)
 *  literal - the version literally written as the lower bound (may not exist)
 *  floor   - smallest PUBLISHED version the spec admits (lower-bounded specs only)
 *  maxSat  - largest published, non-yanked version the spec admits (what a fresh resolve picks)
 */
export function specFacts(eco, spec, truth) {
  const versions = truth.versions ?? [];
  const yanked = new Set(truth.yanked ?? []);
  if (eco === "PyPI") return pySpecFacts([{ spec, versions, yanked: [...yanked] }])[0];
  if (eco === "Go") {
    const v = spec.trim();
    return { exact: v, literal: v, floor: versions.includes(v) ? v : null, maxSat: versions.includes(v) ? v : null, nSat: versions.includes(v) ? 1 : 0, lowerBounded: true };
  }
  const range = eco === "crates.io" ? cargoToRange(spec) : spec.trim();
  if (!semver.validRange(range)) return { error: `unparseable spec ${spec}` };
  const exactV = semver.valid(range.replace(/^=/, "").trim());
  const minV = semver.minVersion(range)?.version ?? null;
  const pre = /-/.test(range);
  const sat = versions.filter((v) => semver.valid(v) && semver.satisfies(v, range, { includePrerelease: pre })).sort(semver.compare);
  const satUnyanked = sat.filter((v) => !yanked.has(v));
  const lowerBounded = !(range === "*" || range === "" || range === "latest" || minV === "0.0.0");
  return {
    exact: exactV && !/[\^~><*x]/.test(range) ? exactV : null,
    literal: minV,
    floor: lowerBounded ? sat[0] ?? null : null,
    maxSat: satUnyanked.at(-1) ?? sat.at(-1) ?? null,
    nSat: sat.length,
    lowerBounded,
  };
}

export function pySpecFacts(queries) {
  const out = execFileSync(process.env.G7_PYTHON || "python", ["-I", path.join(HERE, "pyspec.py")], { input: JSON.stringify(queries), encoding: "utf8", maxBuffer: 64 << 20 });
  return JSON.parse(out).map((r) => (r.error ? r : {
    exact: r.exact_registry ?? r.exact, literal: r.exact ?? r.floor, floor: r.floor, maxSat: r.max_sat, nSat: r.n_sat, lowerBounded: r.lower_bounded,
  }));
}

/** Does this concrete version meet the task's constraint (major / prefix)? */
export function meetsConstraint(eco, version, c = {}) {
  if (!version) return false;
  const v = eco === "Go" ? goStrip(version) : version;
  if (c.major !== undefined) {
    const m = Number(String(v).split(".")[0]);
    if (m !== c.major) return false;
  }
  if (c.prefix !== undefined && !(v === c.prefix || v.startsWith(c.prefix + "."))) return false;
  return true;
}

export function isStableVersion(eco, v) {
  if (eco === "PyPI") return !/(a|b|rc|dev)\d*/i.test(v.replace(/^\d+(\.\d+)*/, "")) ;
  return !isPre(eco === "Go" ? goStrip(v) : v);
}

export function cmpVersions(eco, a, b) {
  if (eco === "Go") return semver.compare(semver.coerce(goStrip(a), { includePrerelease: true }) ?? "0.0.0", semver.coerce(goStrip(b), { includePrerelease: true }) ?? "0.0.0");
  if (semver.valid(a) && semver.valid(b)) return semver.compare(a, b);
  return String(a).localeCompare(String(b), undefined, { numeric: true });
}
