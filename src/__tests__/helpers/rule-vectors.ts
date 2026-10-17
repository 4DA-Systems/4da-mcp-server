// SPDX-License-Identifier: Apache-2.0
/**
 * The TypeScript engine's side of the shared rule vectors (4DA repo,
 * src-tauri/tests/conformance/vectors/; the rule spec is its README.md). Each
 * check runs one vector line through the function this server uses for that
 * rule and returns null when the engine agrees, or why it does not. The Rust
 * reference runner is src-tauri/src/osv/vectors_tests.rs; the mapping here
 * mirrors it file by file.
 *
 *   version_order    compareVersions (version-compare.ts)
 *   osv_range        advisoryRanges + advisoryAffects (osv-ranges.ts)
 *   fix_target       extractFixedVersion per affecting advisory, then
 *                    smallestCleanVersion over every record (the
 *                    vulnerability_scan / upgrade_planner target)
 *   refresh_verdict  refreshRule (refresh-rule.ts), which refreshVerdict applies
 *   fix_command      refreshCommandFor on a directory holding that tool's files;
 *                    directFix for `kind: "direct"` lines (audit E8), on a project
 *                    built from the vector as the Rust runner's check_direct builds it
 *   (refresh_verdict `override`: overrideReaches over the blocking parents)
 *   range_check      parseTarget + checkRange (dependency_check)
 *   holding          isSecurityHoldingRelease (osv-scanner.ts): npm's `0.0.<n>-security`
 *                    placeholder, which no advisory applies to (audit L4)
 */

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { advisoryAffects, advisoryRanges, smallestCleanVersion, type AdvisoryRanges } from "../../live/osv-ranges.js";
import { extractFixedVersion, isSecurityHoldingRelease } from "../../live/osv-scanner.js";
import { directFix, overrideReaches, refreshCommandFor } from "../../live/fix-paths.js";
import { refreshRule, requirementAdmits, type RequirementDialect } from "../../live/refresh-rule.js";
import { compareVersions, isComparable } from "../../live/version-compare.js";
import type { OsvVulnerability } from "../../live/types.js";
import type { CheckEcosystem, PackageReleaseIndex } from "../../live/release-metadata.js";
import { checkRange, parseTarget } from "../../tools/dependency-check-versions.js";

export const VECTOR_FILES = ["version_order", "osv_range", "fix_target", "refresh_verdict", "fix_command", "range_check", "holding"] as const;
export type VectorFile = (typeof VECTOR_FILES)[number];

/** One vector line: every line has `id`, `rule` and `source`; the rest depends on the file. */
export type Vector = { id: string; rule: string; source: string } & Record<string, unknown>;

export function loadVectors(dir: string, file: VectorFile): Vector[] {
  const text = fs.readFileSync(path.join(dir, `${file}.jsonl`), "utf8");
  return text
    .split(/\r?\n/)
    .filter((l) => l.trim() !== "")
    .map((l, i) => {
      try {
        return JSON.parse(l) as Vector;
      } catch (e) {
        throw new Error(`vectors: ${file}.jsonl line ${i + 1}: ${(e as Error).message}`);
      }
    });
}

const str = (v: Vector, key: string): string => (typeof v[key] === "string" ? (v[key] as string) : "");
const optStr = (v: Vector, key: string): string | null => (typeof v[key] === "string" ? (v[key] as string) : null);

/** Pinned OSV records (`<corpus>/osv/<id>.json`), read once each. */
export class Records {
  private readonly cache = new Map<string, OsvVulnerability>();
  constructor(private readonly osvDir: string) {}

  get(id: string): OsvVulnerability {
    let record = this.cache.get(id);
    if (!record) {
      const file = path.join(this.osvDir, `${id}.json`);
      if (!fs.existsSync(file)) throw new Error(`record ${id} not pinned`);
      record = JSON.parse(fs.readFileSync(file, "utf8")) as OsvVulnerability;
      this.cache.set(id, record);
    }
    return record;
  }

  /** The record's ranges for one package, as the scanner reads them. */
  ranges(id: string, ecosystem: string, name: string): AdvisoryRanges {
    const ranges = advisoryRanges(this.get(id), name, ecosystem);
    if (!ranges) throw new Error(`record ${id} is withdrawn`);
    if (ranges.spans.length === 0 && ranges.versions.length === 0) throw new Error(`record ${id} names no ${ecosystem} ${name}`);
    return ranges;
  }
}

// ============================================================================
// Per-file checks: null when the engine agrees with the vector.
// ============================================================================

function checkVersionOrder(v: Vector): string | null {
  const [eco, a, b] = [str(v, "eco"), str(v, "a"), str(v, "b")];
  const want = { "<": -1, "=": 0, ">": 1 }[str(v, "cmp")];
  if (want === undefined) return `bad cmp ${JSON.stringify(v.cmp)}`;
  // compareVersions answers 0 for an unreadable pair too; that is not "equal".
  if (!isComparable(a, eco) || !isComparable(b, eco)) return `${a} vs ${b}: no ordering reads both`;
  const got = compareVersions(a, b, eco);
  return got === want ? null : `${a} vs ${b}: got ${got}, want ${want}`;
}

function checkOsvRange(v: Vector, records: Records): string | null {
  const ranges = records.ranges(str(v, "record_id"), str(v, "eco"), str(v, "name"));
  const got = advisoryAffects(ranges, str(v, "version"), str(v, "eco"));
  return got === v.affected ? null : `affected: got ${got}, want ${v.affected}`;
}

function sameVersion(a: string | null, b: string | null, ecosystem: string): boolean {
  if (a === null || b === null) return a === b;
  return a === b || (isComparable(a, ecosystem) && isComparable(b, ecosystem) && compareVersions(a, b, ecosystem) === 0);
}

function checkFixTarget(v: Vector, records: Records): string | null {
  const [eco, name, installed] = [str(v, "eco"), str(v, "name"), str(v, "installed")];
  const ids = (v.record_ids as string[] | undefined) ?? [];
  const advisories = ids.map((id) => records.ranges(id, eco, name));
  // Each advisory that affects the copy contributes its own fix, as the scan reports it.
  const fixes = ids
    .filter((_, i) => advisoryAffects(advisories[i], installed, eco))
    .map((id) => extractFixedVersion(records.get(id).affected, name, eco, installed))
    .filter((f): f is string => f !== null);
  const clean = smallestCleanVersion({ ecosystem: eco, fixes, advisories, published: null });
  const target = clean?.target ?? null;
  const clears = clean !== null && clean.target !== null && clean.stillAffectedBy.length === 0;
  const wantTarget = optStr(v, "target");
  if (!sameVersion(target, wantTarget, eco)) return `target: got ${target}, want ${wantTarget}`;
  // `clears` is only meaningful for a target.
  if (wantTarget !== null && clears !== v.clears) return `clears: got ${clears}, want ${v.clears}`;
  return null;
}

function checkRefreshVerdict(v: Vector): string | null {
  const reqs = ((v.requirements as Array<Record<string, string | boolean>> | undefined) ?? []).map((r) => ({
    parent: String(r.parent),
    text: String(r.text),
    dialect: (r.dialect === "cargo" ? "cargo" : "npm") as RequirementDialect,
    // A bundled copy's requirement is its owner's exact pin: `text` is the version shipped.
    bundled: r.bundled === true,
  }));
  const got = refreshRule(str(v, "installed"), str(v, "target"), reqs);
  const wantVia = (v.via as string[] | undefined) ?? [];
  if (typeof v.override === "boolean") {
    const blocking = reqs.filter((r) => requirementAdmits(r, str(v, "target")) === false);
    const offered = str(v, "eco") === "npm" && overrideReaches(blocking);
    if (offered !== v.override) return `override offered: got ${offered}, want ${v.override}`;
  }
  const same = got.verdict === v.verdict && got.inferred === v.inferred && JSON.stringify(got.via) === JSON.stringify(wantVia);
  return same
    ? null
    : `got (${got.verdict}, inferred ${got.inferred}, via ${JSON.stringify(got.via)}), want (${v.verdict}, inferred ${v.inferred}, via ${JSON.stringify(wantVia)})`;
}

/** The files a project of this tool holds (the Rust runner's `tool_files`); the first one is the lockfile. */
function toolFiles(tool: string, workspaceRoot: boolean): Array<[string, string]> {
  const files: Array<[string, string]> =
    (
      {
        npm: [["package-lock.json", '{"lockfileVersion": 3}\n']],
        pnpm: [["pnpm-lock.yaml", "lockfileVersion: '6.0'\n"]],
        yarn1: [["yarn.lock", "# yarn lockfile v1\n\n"]],
        "yarn-berry": [["yarn.lock", '# This file is generated by running "yarn install"\n\n__metadata:\n  version: 6\n']],
        cargo: [["Cargo.lock", "version = 3\n"]],
        pip: [["requirements.txt", "jinja2==1.0.0\n"]],
        poetry: [["poetry.lock", "[metadata]\n"]],
        uv: [["uv.lock", "version = 1\n"]],
        pipenv: [["Pipfile.lock", "{}\n"]],
        go: [["go.sum", ""], ["go.mod", "module example.com/m\n"]],
        bundler: [["Gemfile.lock", "GEM\n"]],
        composer: [["composer.lock", "{}\n"]],
      } as Record<string, Array<[string, string]>>
    )[tool] ?? [];
  if (workspaceRoot) {
    if (tool === "pnpm") files.push(["pnpm-workspace.yaml", "packages:\n  - 'packages/*'\n"]);
    if (tool === "npm") files.push(["package.json", '{"workspaces": ["packages/*"]}\n']);
    if (tool === "cargo") files.push(["Cargo.toml", '[workspace]\nmembers = ["crates/*"]\n']);
  }
  return files;
}

function checkFixCommand(v: Vector): string | null {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rule-vector-"));
  try {
    const files = toolFiles(str(v, "tool"), v.workspace_root === true);
    for (const [name, body] of files) fs.writeFileSync(path.join(dir, name), body);
    if (v.kind === "direct") return checkDirect(v, dir);
    const lockfile = files.length > 0 ? path.join(dir, files[0][0]) : path.join(dir, "none");
    const got = refreshCommandFor(lockfile, str(v, "pkg"), str(v, "installed"), str(v, "target"));
    const want = optStr(v, "command");
    return got === want ? null : `command: got ${JSON.stringify(got)}, want ${JSON.stringify(want)}`;
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

/**
 * `kind: "direct"` (audit E8): the fix for a DECLARED dependency, read by directFix from a project
 * built out of the vector, as the Rust runner's check_direct does: its declared npm spec
 * (`declared`), Cargo.toml (`manifest`), go.mod (`go_mod`) or requirements.txt
 * (`requirements`). `member: true` puts the manifest at packages/app, below the lockfile. A
 * command is checked against `command`, an instruction against `instruction`.
 */
function checkDirect(v: Vector, root: string): string | null {
  const pkg = str(v, "pkg");
  const project = v.member === true ? path.join(root, "packages", "app") : root;
  fs.mkdirSync(project, { recursive: true });
  const declared = optStr(v, "declared");
  if (declared !== null) fs.writeFileSync(path.join(project, "package.json"), JSON.stringify({ dependencies: { [pkg]: declared } }));
  for (const [field, file] of [["manifest", "Cargo.toml"], ["go_mod", "go.mod"], ["requirements", "requirements.txt"]] as const) {
    const body = optStr(v, field);
    if (body !== null) fs.writeFileSync(path.join(project, file), body);
  }
  const fix = directFix(project, str(v, "eco"), pkg, str(v, "installed"), str(v, "target"));
  const command = fix && "command" in fix ? fix.command : null;
  const instruction = fix && "instruction" in fix ? fix.instruction : null;
  const [wantC, wantI] = [optStr(v, "command"), optStr(v, "instruction")];
  return command === wantC && instruction === wantI
    ? null
    : `direct: got ${JSON.stringify(fix)}, want command ${JSON.stringify(wantC)} / instruction ${JSON.stringify(wantI)}`;
}

function checkRangeCheck(v: Vector, records: Records): string | null {
  const eco = str(v, "eco") as CheckEcosystem;
  const [name, constraint] = [str(v, "name"), str(v, "constraint")];
  const releases = (v.releases as string[] | undefined) ?? [];
  const index: PackageReleaseIndex = {
    ecosystem: eco,
    name,
    createdAt: null,
    releases: Object.fromEntries(
      releases.map((r) => [
        r,
        { version: r, publishedAt: null, trust: 0, trustEvidence: "", installScripts: null, deprecated: null, withdrawn: null, dependencies: null },
      ]),
    ),
  };
  const target = parseTarget(eco, constraint);
  if (!target) return `constraint ${JSON.stringify(constraint)} is unreadable`;
  // An exact pin ("==3.1.6") is a one-release constraint here.
  const range = target.kind === "range" || target.kind === "exact_or_series" ? target.range : constraint;
  const advisories = ((v.record_ids as string[] | undefined) ?? []).map((id) => records.ranges(id, eco, name));
  const from = optStr(v, "from");
  const rc = checkRange({ ecosystem: eco, index, range, basis: "requested", advisories, ...(from ? { from } : {}) });
  const got = {
    releases_in_range: rc.releases_in_range,
    vulnerable_in_range: rc.vulnerable_in_range,
    smallest_safe_in_range: rc.smallest_safe_in_range,
    newest_safe_in_range: rc.newest_safe_in_range,
    smallest_safe_upgrade: from ? (rc.smallest_safe_upgrade ?? null) : null,
  };
  const want = v.expected as Record<string, unknown>;
  const diff = Object.keys(want).filter((k) => JSON.stringify(got[k as keyof typeof got]) !== JSON.stringify(want[k]));
  return diff.length === 0 ? null : diff.map((k) => `${k}: got ${JSON.stringify(got[k as keyof typeof got])}, want ${JSON.stringify(want[k])}`).join("; ");
}

/** Run one vector; null = the engine agrees. A thrown error (unreadable input) counts as a disagreement. */
/** `holding.jsonl`: whether a release is npm's security holding placeholder (any advisory id). */
function checkHolding(v: Vector): string | null {
  const got = isSecurityHoldingRelease(String(v.eco), String(v.version));
  const want = v.holding === true;
  return got === want ? null : `holding: got ${got}, want ${want}`;
}

export function checkVector(file: VectorFile, v: Vector, records: Records): string | null {
  try {
    switch (file) {
      case "version_order":
        return checkVersionOrder(v);
      case "osv_range":
        return checkOsvRange(v, records);
      case "fix_target":
        return checkFixTarget(v, records);
      case "refresh_verdict":
        return checkRefreshVerdict(v);
      case "fix_command":
        return checkFixCommand(v);
      case "range_check":
        return checkRangeCheck(v, records);
      case "holding":
        return checkHolding(v);
    }
  } catch (e) {
    return `error: ${(e as Error).message}`;
  }
}
