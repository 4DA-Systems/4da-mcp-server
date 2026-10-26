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
import type { DependencyHealthResult, InstallDriftRecord, RegistryPackageInfo, VulnerabilityEntry } from "../live/types.js";
import { groupAdvisories } from "../live/advisory-groups.js";
import { isActionableVulnerability } from "../live/maintenance.js";
import { driftFor } from "./install-drift-notes.js";
import { discoveryFor, discoveryNote, exclusionNotes, lockfileProblemNotes, splitLockfileProblems } from "../project-tree.js";
import { vulnerabilityCoverage } from "../live/scan-coverage.js";
import { uncheckedOfferNote, vetOfferedReleases } from "../live/offered-release.js";
import { computeSemverDistance } from "../live/semver-utils.js";
import { isDevOnlyCopy } from "../live/severity-scope.js";
import { compareVersions } from "../live/version-compare.js";

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

/** Time spent checking the newest releases the rows offer against their advisories. */
const OFFER_CHECK_BUDGET_MS = 10_000;

/**
 * Each row whose latest stable release is newer than the installed one: that release checked
 * against the package's advisories and the registry's withdrawals. A known-affected or withdrawn
 * one is not offered: `latestSafeVersion` names the newest release that is neither, and
 * `versionsBehind` is measured to it (so it is not "outdated" when nothing newer is safe).
 */
async function vetLatest(liveIntel: LiveIntelligence, rows: RegistryPackageInfo[]): Promise<RegistryPackageInfo[]> {
  const offered = (r: RegistryPackageInfo) => {
    const latest = r.latestStableVersion || r.latestVersion;
    return latest && r.currentVersion && compareVersions(latest, r.currentVersion, r.ecosystem) > 0 ? latest : null;
  };
  const key = (r: RegistryPackageInfo) => `${r.ecosystem}\u0000${r.name}\u0000${r.currentVersion}`;
  const sources = liveIntel.getFixPathSources();
  const vets = await vetOfferedReleases(
    sources,
    rows.filter((r) => offered(r) !== null).map((r) => ({ key: key(r), ecosystem: r.ecosystem, name: r.name, installed: r.currentVersion, offered: offered(r)! })),
    OFFER_CHECK_BUDGET_MS,
  );
  return rows.map((r) => {
    const latest = offered(r);
    if (!latest || !sources) return r;
    const vet = vets.get(key(r));
    if (!vet) return { ...r, latestStableNote: uncheckedOfferNote(r.name, latest) };
    if (!vet.note) return r;
    if (!vet.checked) return { ...r, latestStableNote: vet.note };
    const versionsBehind = vet.safe && r.currentVersion ? computeSemverDistance(r.currentVersion, vet.safe) : null;
    return { ...r, latestSafeVersion: vet.safe, latestStableNote: vet.note, versionsBehind };
  });
}

/** One entry per distinct advisory of each installed copy: the group's most severe record. */
function advisoriesPerCopy(rows: VulnerabilityEntry[]): VulnerabilityEntry[] {
  const byCopy = new Map<string, VulnerabilityEntry[]>();
  for (const v of rows) {
    const key = `${v.ecosystem}\u0000${v.package}\u0000${v.currentVersion}`;
    byCopy.set(key, [...(byCopy.get(key) ?? []), v]);
  }
  return [...byCopy.values()].flatMap((copy) => groupAdvisories(copy).map((g) => g.best));
}

/**
 * No dependency was resolved, so there is nothing to score: say what WAS
 * found (manifests of ecosystems this server does not read, test-fixture
 * lockfiles, unreadable lockfiles). Started inside spring-petclinic, 6.2.5
 * said "No project manifests detected" beside a pom.xml (audit H3).
 */
function nothingChecked(start: number, liveIntel: LiveIntelligence | null): DependencyHealthResult {
  const root = liveIntel?.getProjectRoot() ?? process.cwd();
  const discovery = liveIntel?.getDiscovery() ?? discoveryFor(root);
  const notes = [
    ...exclusionNotes(discovery),
    ...lockfileProblemNotes(liveIntel?.getLockfileProblems() ?? []),
    ...[discoveryNote(discovery)].filter((n): n is string => n !== null),
  ];
  return {
    scannedAt: new Date().toISOString(),
    projectPath: root,
    ecosystemsScanned: [],
    totalDeps: 0,
    outdatedCount: 0,
    deprecatedCount: 0,
    vulnerableCount: null,
    advisoryCount: 0,
    healthScore: null,
    withheldReason: "nothing_checked",
    dependencies: [],
    vulnerabilitySummary: null,
    summary:
      notes.length > 0
        ? `Nothing was checked, so there is no health score; this is not a healthy result. ${notes.join(" ")}`
        : `No manifest or lockfile of a supported ecosystem was found in ${root} (package.json, Cargo.toml, pyproject.toml, requirements*.txt, go.mod, Gemfile.lock, composer.lock), and none of an unsupported one either; no health score.`,
    scanDurationMs: Date.now() - start,
    cached: false,
  };
}

export async function executeDependencyHealth(
  _db: FourDADatabase | null,
  params: DependencyHealthParams,
  liveIntel: LiveIntelligence | null,
): Promise<DependencyHealthResult> {
  const start = Date.now();

  if (!liveIntel || !liveIntel.isInitialized()) return nothingChecked(start, liveIntel);

  // A long-lived server must not answer from the versions it read at startup:
  // re-resolve if a lockfile (or node_modules) changed. Stat calls only.
  liveIntel.refreshIfLockfilesChanged();
  if (liveIntel.getResolvedDeps().length === 0 && liveIntel.getAuditDeps().length === 0) return nothingChecked(start, liveIntel);

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

  // Fetch registry health for all deps. The newest release a row offers is checked as
  // dependency_check checks one (offered-release.ts): crossenv's latest stable is the malware.
  const registryData = await vetLatest(
    liveIntel,
    withInstalledVersions(await liveIntel.fetchRegistryHealth(deps), liveIntel.getInstallDrift()),
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
  const scopeTotal = liveIntel.getAuditDeps().filter((d) => includeDev || !isDevOnlyCopy(d)).length;
  const coverage = vulnerabilityCoverage(vulnResult, {
    enabled: liveIntel.isEnabled(),
    expectedTotal: scopeTotal,
    notLoaded: `the OSV.dev scan did not finish within ${HEALTH_SCAN_TIMEOUT_MS / 1000} s or OSV.dev was unreachable`,
  });
  // A lockfile that could not be read is a gap of the same kind: nothing it
  // pins was sent to OSV. 6.2.5 scored a merge-conflicted package-lock.json
  // 32/100 from package.json's pins alone (audit M5); the score and the
  // counts are withheld, as for an OSV gap. A file read with entries skipped
  // (PARTIAL) or a requirements include refused by policy (REFUSED) loses
  // only what it names: the checked part is scored, marked partial
  // (scoreCoverage), so a refusal that is permanent by design does not
  // withhold the score forever. ecosystem_filter narrows these too.
  const problems = liveIntel.getLockfileProblems().filter((p) => !params.ecosystem_filter || !p.ecosystem || p.ecosystem === params.ecosystem_filter);
  const { unreadable, partial: partialReads, refused } = splitLockfileProblems(problems);
  const readGap = unreadable.length > 0 ? `NOT CHECKED: ${lockfileProblemNotes(unreadable).join(" ")} This is not a complete result.` : null;
  const withheld = coverage !== null || readGap !== null;
  // Direct dependencies whose registry did not answer: their outdated and deprecated state is
  // unknown, not current. Under a registry outage the score counted them neither and the summary
  // said every one was "checked against its registry" (audit 6.2.5 B-7: 58/100, true 37).
  const registryFailed = registryData.filter((d) => d.fetchError);
  const registryNote =
    registryFailed.length > 0
      ? [
          `PARTIAL: ${registryFailed.length} of ${registryData.length} direct dependenc${registryData.length === 1 ? "y" : "ies"} could not be checked against ${registryFailed.length === 1 ? "its registry" : "their registries"} (${String(registryFailed[0].fetchError).slice(0, 120)}); whether ${registryFailed.length === 1 ? "it is" : "they are"} outdated or deprecated is unknown, not current.`,
        ]
      : [];
  const partialNotes = [...lockfileProblemNotes([...partialReads, ...refused]), ...registryNote];
  const scorePartial = !withheld && partialNotes.length > 0;
  // One population for every count: the stored scan can be vulnerability_scan's,
  // which includes direct devDependencies by default, while the registry rows
  // leave them out without include_dev. navcal read "4 direct" vulnerable, 3 of
  // them devDependencies, beside "25 devDependencies left out" (audit L2).
  // The same predicate scanVulnerabilities scopes by: without include_dev every dev-only copy is
  // left out (isDevOnlyCopy), not only direct devDependencies (final audit, finding 6).
  // ecosystem_filter narrows the vulnerability counts too, not only the registry rows.
  const inScope = (v: { isDirect: boolean; isDev: boolean; devScopeKnown?: boolean }) => includeDev || !isDevOnlyCopy(v);
  const allVulns = (vulnResult?.vulnerabilities ?? []).filter((v) => inScope(v) && (!params.ecosystem_filter || v.ecosystem === params.ecosystem_filter));
  const activeVulns = allVulns.filter(isActionableVulnerability);
  // Keyed by (ecosystem, name): a bare name let an npm advisory mark a
  // same-named crate as vulnerable, and counted the two as one package.
  const vulnKey = (ecosystem: string, name: string) => `${ecosystem}\u0000${name}`;
  const vulnMap = new Map<string, number>();
  for (const v of activeVulns) {
    const key = vulnKey(v.ecosystem, v.package);
    vulnMap.set(key, (vulnMap.get(key) || 0) + 1);
  }
  // Advisories, not OSV records: one issue as GHSA + PYSEC + CVE records is
  // one advisory, at its worst severity (audit M1: pygoat read 348 beside the
  // scan's 187). Grouped per installed copy, as vulnerability_scan's rows are.
  const activeAdvisories = advisoriesPerCopy(activeVulns);
  const advisoryCount = advisoriesPerCopy(allVulns).length;

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
  // A wider (dev-inclusive) scan counts exactly the dev-only copies more than this scope.
  // Counted as the scan counts: copies with a version.
  const versioned = liveIntel.getAuditDeps().filter((d) => d.version !== null);
  const devOnly = versioned.filter((d) => isDevOnlyCopy(d)).length;
  const runtimeScope = versioned.length - devOnly;
  const scannedAll = vulnResult?.totalScanned ?? 0;
  const treeDeps = !includeDev && devOnly > 0 && scannedAll === versioned.length ? runtimeScope : scannedAll;
  const devScope = devOnly > 0 ? (includeDev ? "; dev-only copies included" : `; ${devOnly.toLocaleString("en-US")} dev-only cop${devOnly === 1 ? "y" : "ies"} left out`) : "";
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
  for (const v of activeAdvisories) {
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
  const healthScore = withheld ? null : Math.max(0, 100 - vulnPenalty - deprecatedPenalty - outdatedPenalty);

  // Severity breakdown over the actionable set, matching the count above.
  const vulnSummary = vulnResult && !withheld ? { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 } : null;
  if (vulnSummary) {
    for (const v of activeAdvisories) {
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
    `${registryFailed.length > 0 ? `${total - registryFailed.length} of ` : ""}${plural(total, "direct dependency", "direct dependencies")} checked against ${total === 1 ? "its registry" : "their registries"}` +
      (devExcluded > 0 ? ` (${plural(devExcluded, "devDependency", "devDependencies")} left out; include_dev: true adds them)` : ""),
  );
  if (vulnResult) {
    const found = `${plural(vulnerable, "vulnerable package", "vulnerable packages")} in the full tree of ${treeDeps.toLocaleString("en-US")} installed (${vulnerableDirect} direct, ${vulnerable - vulnerableDirect} transitive${devScope})`;
    parts.push(withheld || scorePartial ? `at least ${found}, in the checked part` : found);
  }
  if (deprecated > 0) parts.push(`${deprecated} deprecated (direct)`);
  const unsafeLatest = registryData.filter((d) => d.latestSafeVersion !== undefined);
  if (unsafeLatest.length > 0) {
    const none = unsafeLatest.filter((d) => d.latestSafeVersion === null).length;
    parts.push(
      `${plural(unsafeLatest.length, "direct dependency whose", "direct dependencies whose")} latest release is affected by an advisory or withdrawn, so it is not offered (latestSafeVersion and latestStableNote say what is${none > 0 ? `; for ${none}, no newer release is safe` : ""})`,
    );
  }
  if (outdated > 0) parts.push(`${outdated} outdated (direct)`);
  if (drifted > 0) {
    parts.push(`${drifted} installed at a different version than the lockfile pins (see installedVersion; vulnerability_scan lists install_drift)`);
  }
  // "All healthy" is a claim about CVEs too; it needs a scan behind it.
  if (vulnResult && !withheld && !scorePartial && vulnerable === 0 && deprecated === 0 && outdated === 0 && drifted === 0) {
    parts.push("all healthy");
  }
  const hidden = advisoryCount - activeAdvisories.length;
  if (hidden > 0) {
    parts.push(`${hidden} advisor${hidden !== 1 ? "ies" : "y"} not counted (platform-inactive or maintenance notices)`);
  }
  // "all healthy" over a partial walk must say it is partial.
  const partial = discoveryNote(liveIntel.getDiscovery());
  if (partial) parts.push(partial.replace(/[.]$/, ""));
  // Ecosystems not read, test fixtures left out, lockfiles that could not be read: never silent.
  for (const note of [...exclusionNotes(liveIntel.getDiscovery()), ...partialNotes]) parts.push(note.replace(/[.]$/, ""));

  return {
    scannedAt: new Date().toISOString(),
    projectPath: liveIntel.getProjectRoot() ?? process.cwd(),
    ecosystemsScanned: ecosystems,
    totalDeps: total,
    treeDeps,
    vulnerableDirectCount: withheld ? null : vulnerableDirect,
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
    vulnerableCount: withheld ? null : vulnerable,
    advisoryCount,
    healthScore,
    ...(withheld ? { withheldReason: coverage ? ("vulnerability_data_incomplete" as const) : ("lockfile_unreadable" as const) } : {}),
    ...(scorePartial ? { scoreCoverage: { complete: false as const, basis: "checked_part" as const, notes: partialNotes } } : {}),
    ...(vulnResult?.aliasSeverity ? { aliasSeverity: vulnResult.aliasSeverity } : {}),
    ...(coverage ? { vulnerabilityCoverage: coverage } : {}),
    dependencies: limited,
    vulnerabilitySummary: vulnSummary,
    summary: withheld
      ? `${[coverage?.note, readGap].filter(Boolean).join(" ")} Health score withheld until every dependency is checked. ${capitalise(parts.join("; "))}.`
      : `Health: ${healthScore}/100${scorePartial ? " over the checked part only (see scoreCoverage)" : ""} (100 minus ${vulnPenalty} for vulnerabilities, ${outdatedPenalty} for outdated, ${deprecatedPenalty} for deprecated; see healthScoreBasis). ${capitalise(parts.join("; "))}.`,
    scanDurationMs: Date.now() - start,
    cached: false,
  };
}
