// SPDX-License-Identifier: Apache-2.0
/**
 * dependency_health tool
 *
 * Assesses health of project dependencies by checking version freshness,
 * deprecation status, and known vulnerabilities across npm, crates.io,
 * PyPI, and Go ecosystems. Zero config — auto-detects from lock files.
 */

import type { FourDADatabase } from "../db.js";
import type { LiveIntelligence } from "../live/index.js";
import type { DependencyHealthResult, InstallDriftRecord, RegistryPackageInfo } from "../live/types.js";
import { isActionableVulnerability } from "../live/maintenance.js";
import { driftFor } from "./install-drift-notes.js";
import { discoveryNote, exclusionNotes, unreadableNotes } from "../project-tree.js";
import { vulnerabilityCoverage } from "../live/scan-coverage.js";

const capitalise = (text: string) => text.charAt(0).toUpperCase() + text.slice(1);

export interface DependencyHealthParams {
  include_dev?: boolean;
  ecosystem_filter?: string;
  sort_by?: "risk" | "name" | "outdated";
  limit?: number;
}

/** How the score is built, stated with every score. */
const HEALTH_SCORE_BASIS =
  "100 minus three capped penalties. Vulnerabilities: per advisory on the full installed tree (platform-inactive and maintenance notices excluded), critical 20, high 10, medium 4, low 1, unknown 2, a transitive one at a third, capped at 55. Outdated: over the direct dependencies, a major behind 1, a minor 0.35, a patch 0.1, as a share of them times 60, capped at 30. Deprecated: 8 per deprecated direct dependency, capped at 15.";

/** How long a health check waits for its own OSV scan before answering without CVE data (the scan keeps running). */
const HEALTH_SCAN_TIMEOUT_MS = 60_000;

export const dependencyHealthTool = {
  name: "dependency_health",
  description:
    "Assess health of project dependencies — version freshness, deprecation status, known CVEs. Auto-detects stack from lock files. Covers npm, Rust, Python, and Go. For npm, `installedVersion` appears beside `currentVersion` when node_modules holds a different version than the lockfile. " +
    "Two populations: `totalDeps`, `outdatedCount` and `deprecatedCount` are over the DIRECT dependencies (registry rows; devDependencies only with include_dev); `vulnerableCount` is distinct vulnerable packages in the full installed tree of `treeDeps` (the same set as vulnerability_scan), `vulnerableDirectCount` the direct ones among them, so it can exceed `totalDeps`. `healthScoreBasis` gives the penalties behind `healthScore`. " +
    "When the CVE check is missing or incomplete (OSV.dev unreachable, timed out, rate limited, or FOURDA_OFFLINE), the summary starts with \"NOT CHECKED: ...\", `vulnerabilityCoverage` says how many dependencies were not checked, and `healthScore` and `vulnerableCount` are null: that is not a healthy result.",
  inputSchema: {
    type: "object" as const,
    properties: {
      include_dev: {
        type: "boolean",
        description: "Include devDependencies. Default: false",
      },
      ecosystem_filter: {
        type: "string",
        enum: ["npm", "crates.io", "PyPI", "Go"],
        description: "Only show deps from this ecosystem. Default: all detected.",
      },
      sort_by: {
        type: "string",
        enum: ["risk", "name", "outdated"],
        description: "Sort order. 'risk' prioritizes vulnerable+deprecated+outdated. Default: risk",
      },
      limit: {
        type: "number",
        description: "Max dependencies to return. Default: 50",
      },
    },
  },
};

/** Stamp each npm row with the version node_modules holds, where it differs from the lockfile's. */
function withInstalledVersions(rows: RegistryPackageInfo[], drift: InstallDriftRecord[]): RegistryPackageInfo[] {
  if (drift.length === 0) return rows;
  return rows.map((row) => {
    if (row.ecosystem !== "npm") return row;
    const records = driftFor(drift, row.name, row.currentVersion);
    if (records.length === 0) return row;
    return { ...row, installedVersion: [...new Set(records.map((r) => r.installedVersion))].join(", ") };
  });
}

export async function executeDependencyHealth(
  _db: FourDADatabase | null,
  params: DependencyHealthParams,
  liveIntel: LiveIntelligence | null,
): Promise<DependencyHealthResult> {
  const start = Date.now();

  if (!liveIntel || !liveIntel.isInitialized()) {
    return {
      scannedAt: new Date().toISOString(),
      projectPath: process.cwd(),
      ecosystemsScanned: [],
      totalDeps: 0,
      outdatedCount: 0,
      deprecatedCount: 0,
      vulnerableCount: null,
      advisoryCount: 0,
      healthScore: null,
      dependencies: [],
      vulnerabilitySummary: null,
      summary: "Live intelligence not initialized. No project manifests detected.",
      scanDurationMs: Date.now() - start,
      cached: false,
    };
  }

  // A long-lived server must not answer from the versions it read at startup:
  // re-resolve if a lockfile (or node_modules) changed. Stat calls only.
  liveIntel.refreshIfLockfilesChanged();

  // Get resolved deps
  const includeDev = params.include_dev ?? false;
  let deps = liveIntel.getResolvedDeps();
  if (!includeDev) {
    deps = deps.filter((d) => !d.isDev);
  }
  if (params.ecosystem_filter) {
    deps = deps.filter((d) => d.ecosystem === params.ecosystem_filter);
  }

  const ecosystems = [...new Set(deps.map((d) => d.ecosystem))];

  // Fetch registry health for all deps
  const registryData = withInstalledVersions(
    await liveIntel.fetchRegistryHealth(deps),
    liveIntel.getInstallDrift(),
  );

  // Merge vulnerability data. "Vulnerable" means the actionable set — built
  // on this host and not a maintenance notice — which is exactly what
  // vulnerability_scan reports as `total_vulnerable_packages`. Counting every
  // row here made the two tools disagree over one scan (this one said 11
  // vulnerable packages where the scan listed 5 and filed the rest under
  // platform-inactive and maintenance notices). `advisoryCount` keeps the raw
  // row count visible so the filter hides nothing.
  // Loaded here (bounded) when no scan has run: telling the agent to "run
  // vulnerability_scan first" left a session's first health check CVE-blind.
  const root = liveIntel.getProjectRoot() ?? process.cwd();
  const vulnResult = (await liveIntel.ensureVulnerabilities(root, HEALTH_SCAN_TIMEOUT_MS, { includeDev })) ?? liveIntel.getVulnerabilities();
  // What OSV did NOT answer for. A score or a vulnerable count computed
  // without it reads as healthier than the project is (6.2.4 scored 75/100
  // with 10,568 dependencies unchecked), so both are withheld.
  const scopeTotal = liveIntel.getAuditDeps().filter((d) => includeDev || !(d.isDirect && d.isDev)).length;
  const coverage = vulnerabilityCoverage(vulnResult, {
    enabled: liveIntel.isEnabled(),
    expectedTotal: scopeTotal,
    notLoaded: `the OSV.dev scan did not finish within ${HEALTH_SCAN_TIMEOUT_MS / 1000} s or OSV.dev was unreachable`,
  });
  // ecosystem_filter narrows the vulnerability counts too, not only the registry rows.
  const allVulns = (vulnResult?.vulnerabilities ?? []).filter((v) => !params.ecosystem_filter || v.ecosystem === params.ecosystem_filter);
  const activeVulns = allVulns.filter(isActionableVulnerability);
  // Keyed by (ecosystem, name): a bare name let an npm advisory mark a
  // same-named crate as vulnerable, and counted the two as one package.
  const vulnKey = (ecosystem: string, name: string) => `${ecosystem}\u0000${name}`;
  const vulnMap = new Map<string, number>();
  for (const v of activeVulns) {
    const key = vulnKey(v.ecosystem, v.package);
    vulnMap.set(key, (vulnMap.get(key) || 0) + 1);
  }
  const advisoryCount = allVulns.length;

  // Compute stats
  let outdated = 0;
  let deprecated = 0;

  for (const dep of registryData) {
    if (dep.versionsBehind && dep.versionsBehind.label !== "up-to-date") outdated++;
    if (dep.deprecated) deprecated++;
  }

  // Count vulnerable packages from the full scanned set (the OSV scan covers
  // transitives), so the "N vulnerable" summary agrees with the severity
  // breakdown shown beside it. registryData is direct deps only — counting there
  // undercounts CVEs that live in transitive dependencies.
  const vulnerable = vulnMap.size;
  // Of those, the ones a manifest declares (fixable by a direct bump).
  const vulnerableDirect = new Set(activeVulns.filter((v) => v.isDirect).map((v) => vulnKey(v.ecosystem, v.package))).size;
  // The tree the vulnerability counts range over (every installed copy OSV was asked about).
  const treeDeps = vulnResult?.totalScanned ?? 0;
  // Direct devDependencies left out of the registry rows (include_dev: true adds them).
  const devExcluded = includeDev
    ? 0
    : liveIntel.getResolvedDeps().filter((d) => d.isDev && (!params.ecosystem_filter || d.ecosystem === params.ecosystem_filter)).length;
  const drifted = registryData.filter((d) => d.installedVersion).length;

  // Sort
  const sortBy = params.sort_by ?? "risk";
  const sorted = [...registryData].sort((a, b) => {
    if (sortBy === "name") return a.name.localeCompare(b.name);
    if (sortBy === "outdated") {
      const aD = a.versionsBehind ? a.versionsBehind.major * 100 + a.versionsBehind.minor * 10 + a.versionsBehind.patch : 0;
      const bD = b.versionsBehind ? b.versionsBehind.major * 100 + b.versionsBehind.minor * 10 + b.versionsBehind.patch : 0;
      return bD - aD;
    }
    // risk: vulnerable > deprecated > major outdated > minor > patch > current
    const riskScore = (dep: RegistryPackageInfo) => {
      let score = 0;
      if (vulnMap.has(vulnKey(dep.ecosystem, dep.name))) score += 1000;
      if (dep.deprecated) score += 500;
      if (dep.versionsBehind) {
        score += dep.versionsBehind.major * 100 + dep.versionsBehind.minor * 10 + dep.versionsBehind.patch;
      }
      return score;
    };
    return riskScore(b) - riskScore(a);
  });

  const limit = params.limit ?? 50;
  const limited = sorted.slice(0, limit);

  // Health score: 100 = perfect. Proportional and severity-weighted — the old
  // absolute-count formula (15 points per vulnerable package, 2 per outdated,
  // regardless of severity, degree, or project size) pinned any real-sized
  // project at 0/100: a patch-behind dep cost the same as a critical CVE and
  // the number informed nothing.
  const total = registryData.length;
  const denominator = total || 1;

  // Vulnerabilities: severity-weighted; transitive findings at one-third
  // weight (their fix arrives via a parent bump — the direct surface is what
  // the user controls directly).
  // Penalised over the same actionable set the count reports, so a score
  // below 100 always has a vulnerable package beside it.
  const sevWeight: Record<string, number> = { critical: 20, high: 10, medium: 4, low: 1 };
  let vulnPenaltyRaw = 0;
  for (const v of activeVulns) {
    const w = sevWeight[v.severity] ?? 2; // "unknown" severity with a real (non-maintenance) advisory
    vulnPenaltyRaw += v.isDirect ? w : w / 3;
  }
  const vulnPenalty = Math.min(Math.round(vulnPenaltyRaw), 55);

  // Staleness: degree-weighted and proportional to the tracked set — a major
  // behind is a real liability, a patch behind is routine drift.
  let stalenessWeight = 0;
  for (const dep of registryData) {
    const label = dep.versionsBehind?.label;
    if (label === "major") stalenessWeight += 1;
    else if (label === "minor") stalenessWeight += 0.35;
    else if (label === "patch") stalenessWeight += 0.1;
  }
  const outdatedPenalty = Math.min(30, Math.round((stalenessWeight / denominator) * 60));

  const deprecatedPenalty = Math.min(deprecated * 8, 15);
  const healthScore = coverage ? null : Math.max(0, 100 - vulnPenalty - deprecatedPenalty - outdatedPenalty);

  // Severity breakdown over the actionable set, matching the count above.
  const vulnSummary = vulnResult && !coverage ? { critical: 0, high: 0, medium: 0, low: 0 } : null;
  if (vulnSummary) {
    for (const v of activeVulns) {
      if (v.severity in vulnSummary) vulnSummary[v.severity as keyof typeof vulnSummary]++;
    }
  }

  // Summary. Two populations, each named: the direct dependencies checked
  // against their registries (freshness, deprecation), and the full installed
  // tree checked against OSV. 6.2.4 said "18 dependencies scanned, 26
  // vulnerable" for navcal: 18 direct runtime dependencies, 26 vulnerable
  // packages among 633 installed (2026-10-13 review).
  const parts: string[] = [];
  const plural = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`;
  parts.push(
    `${plural(total, "direct dependency", "direct dependencies")} checked against ${total === 1 ? "its registry" : "their registries"}` +
      (devExcluded > 0 ? ` (${plural(devExcluded, "devDependency", "devDependencies")} left out; include_dev: true adds them)` : ""),
  );
  if (vulnResult) {
    const found = `${plural(vulnerable, "vulnerable package", "vulnerable packages")} in the full tree of ${treeDeps.toLocaleString("en-US")} installed (${vulnerableDirect} direct, ${vulnerable - vulnerableDirect} transitive)`;
    parts.push(coverage ? `at least ${found}, in the checked part` : found);
  }
  if (deprecated > 0) parts.push(`${deprecated} deprecated (direct)`);
  if (outdated > 0) parts.push(`${outdated} outdated (direct)`);
  if (drifted > 0) {
    parts.push(`${drifted} installed at a different version than the lockfile pins (see installedVersion; vulnerability_scan lists install_drift)`);
  }
  // "All healthy" is a claim about CVEs too; it needs a scan behind it.
  if (vulnResult && !coverage && vulnerable === 0 && deprecated === 0 && outdated === 0 && drifted === 0) {
    parts.push("all healthy");
  }
  const hidden = advisoryCount - activeVulns.length;
  if (hidden > 0) {
    parts.push(`${hidden} advisor${hidden !== 1 ? "ies" : "y"} not counted (platform-inactive or maintenance notices)`);
  }
  // "all healthy" over a partial walk must say it is partial.
  const partial = discoveryNote(liveIntel.getDiscovery());
  if (partial) parts.push(partial.replace(/[.]$/, ""));
  // Ecosystems not read, test fixtures left out, lockfiles that could not be read: never silent.
  for (const note of [...exclusionNotes(liveIntel.getDiscovery()), ...unreadableNotes(liveIntel.getLockfileProblems())]) parts.push(note.replace(/[.]$/, ""));

  return {
    scannedAt: new Date().toISOString(),
    projectPath: liveIntel.getProjectRoot() ?? process.cwd(),
    ecosystemsScanned: ecosystems,
    totalDeps: total,
    treeDeps,
    vulnerableDirectCount: coverage ? null : vulnerableDirect,
    ...(healthScore !== null
      ? {
          healthScoreBasis: {
            vulnerabilities: vulnPenalty,
            outdated: outdatedPenalty,
            deprecated: deprecatedPenalty,
            note: HEALTH_SCORE_BASIS,
          },
        }
      : {}),
    outdatedCount: outdated,
    deprecatedCount: deprecated,
    vulnerableCount: coverage ? null : vulnerable,
    advisoryCount,
    healthScore,
    ...(coverage ? { vulnerabilityCoverage: coverage } : {}),
    dependencies: limited,
    vulnerabilitySummary: vulnSummary,
    summary: coverage
      ? `${coverage.note} Health score withheld until every dependency is checked. ${capitalise(parts.join("; "))}.`
      : `Health: ${healthScore}/100 (100 minus ${vulnPenalty} for vulnerabilities, ${outdatedPenalty} for outdated, ${deprecatedPenalty} for deprecated; see healthScoreBasis). ${capitalise(parts.join("; "))}.`,
    scanDurationMs: Date.now() - start,
    cached: false,
  };
}
