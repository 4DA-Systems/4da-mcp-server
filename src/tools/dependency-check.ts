// SPDX-License-Identifier: Apache-2.0
/**
 * dependency_check tool
 *
 * A pre-flight verdict for ONE proposed change per item: adding a dependency
 * at a version, pinning one, or moving an installed one to another version.
 * An agent calls this before it writes a version into a manifest and gets
 * `proceed | wait | review | avoid | unknown`, a one-line reason, and the
 * signals behind it, each with evidence. npm, crates.io, PyPI and Go.
 *
 * `to` is an exact version, "latest", or a constraint ("7.x", "^1.20",
 * "~=3.1", "v1"). For a constraint the item also returns `range_check`: every
 * release it admits judged against every advisory OSV.dev lists for the
 * package, with the smallest and newest safe one, and the verdict is given
 * for the version it recommends (the smallest safe upgrade above `from`, or
 * for a new dependency the newest safe release). An exact `to` that an
 * advisory affects gets the same `range_check` over its own release line, so
 * the answer to "is 7.5.10 safe?" names 7.5.11.
 *
 * Signals (see dependency-check-signals.ts): known advisories on the target
 * (OSV), release age (hold releases < 3 days unless they fix an advisory on
 * the installed version), publish-trust drop and newly added install scripts
 * (npm; trust also crates.io), newly introduced runtime dependencies that are
 * themselves < 30 days old (npm, crates.io), yanked / deprecated / unpublished
 * / retracted targets, and the upgrade type. A signal a registry cannot
 * supply says "not applicable", never a made-up value.
 *
 * Honesty contract: a registry or OSV that cannot be reached makes the item
 * `unknown`, never `proceed`. A package missing from the public registry is
 * `unknown` with that said (private package, or a misspelled/hallucinated
 * name), never treated as clean.
 *
 * Privacy: npm, crates.io and PyPI requests carry the package name only — the
 * installed and target versions are picked out of the full release list
 * locally. The Go proxy lists versions without dates, so the judged versions'
 * `.info` is read from it. OSV receives name + version, as vulnerability_scan
 * already does, and the package name for its advisory list.
 */

import type { FourDADatabase } from "../db.js";
import type { LiveIntelligence } from "../live/index.js";
import type { FixPathSources } from "../live/fix-paths.js";
import { isMaintenanceNotice } from "../live/maintenance.js";
import type { AdvisoryRanges } from "../live/osv-ranges.js";
import type { CheckEcosystem, PackageReleaseIndex, RegistryLookup, ReleaseMetadataSource } from "../live/release-metadata.js";
import type { ResolvedDependency, VulnerabilityEntry } from "../live/types.js";
import { goPathMajor, goVersionMajor } from "../live/upgrade-go.js";
import {
  advisoriesSignal,
  decide,
  installScriptSignal,
  introducedDependencies,
  newDependenciesSignal,
  publishTrustSignal,
  releaseAgeSignal,
  selectBaseline,
  upgradeTypeSignal,
  withdrawnSignal,
  WAIT_DAYS,
  type AdvisoryFacts,
  type AdvisoryRef,
  type CheckItem,
  type CreatedAtFact,
  type HoldWaiver,
  type Signal,
  type Verdict,
} from "./dependency-check-signals.js";
import { checkRange, compareIn, isPrereleaseIn, lineOf, parseTarget, rangeAdmits, type RangeCheck, type Target } from "./dependency-check-versions.js";

export interface DependencyCheckParams {
  items?: unknown;
}

const MAX_ITEMS = 25;
/** First-publish lookups for newly introduced dependencies, per call (each is a registry read). */
const MAX_NEW_DEP_LOOKUPS = 40;
const NPM_CONCURRENCY = 4;
const ECOSYSTEMS: readonly CheckEcosystem[] = ["npm", "crates.io", "PyPI", "Go"];
const DAY_MS = 86_400_000;

const PRIVACY_NOTE =
  "Registry requests carried package names only (npm full packument, crates.io versions API and sparse index, PyPI JSON API, Go proxy version list); " +
  "installed and target versions were never sent to a registry, except the Go proxy's per-version .info for the versions judged (the list has no dates). " +
  "OSV.dev received package names and versions, as vulnerability_scan does.";

const VERDICT_RULE =
  "avoid > review > unknown > wait > proceed. unknown = a registry or OSV.dev lookup failed (never read as proceed); " +
  "a concrete avoid/review finding still wins over a missing source.";

export const dependencyCheckTool = {
  name: "dependency_check",
  description: [
    "Is this dependency version safe to write? Call BEFORE you write any version into a manifest or lockfile: adding, pinning, upgrading, bumping or downgrading a package, or choosing a version (npm, crates.io, PyPI, Go). Pass the exact version you intend to write, or the constraint you were given (\"7.x\", \"^1.20\", \"~=3.1\", \"v1\") to get the smallest and newest safe release in it. Write only a version that came back `proceed`. Your memory of which release is safe is out of date; this reads the registry and OSV.dev now.",
    "",
    "Per item: `verdict` (proceed | wait | review | avoid | unknown), a one-line `reason`, `signals` (each with `id`, `value`, `evidence`, `effect`), and `range_check` when `to` is a constraint or an exact `to` has an advisory: `smallest_safe_in_range`, `newest_safe_in_range`, `safe_versions`, `smallest_safe_upgrade` (above `from`). For a constraint the verdict is for the version it picks: the smallest safe upgrade above `from`, else the newest safe release.",
    "- advisories: OSV advisories affecting `to` (high/critical -> avoid, other -> review) and those this change fixes on `from`.",
    "- release_age: under 3 days -> wait, unless `to` fixes an advisory affecting `from`, or every release on its line past the hold has an advisory and no safe one is past it (then proceed; tell the user its age).",
    "- yanked_or_deprecated: yanked, unpublished, retracted (Go) or deprecated -> avoid.",
    "- publish_trust (npm, crates.io): trusted publisher / provenance dropped -> review. install_script_added (npm): new install script -> review. new_dependencies (npm, crates.io): a new runtime dependency under 30 days old -> review. Not applicable elsewhere, and said so.",
    "- upgrade_type: major (0.x minor counts) -> review: call upgrade_impact for what it breaks.",
    "",
    "`unknown` = a lookup failed or the package is not on the public registry (private, misspelled or hallucinated name); never a silent proceed.",
    "",
    "Privacy: registries get the package name only (Go: also the judged versions' .info, as `go get` does); OSV.dev gets names and versions, as vulnerability_scan does. FOURDA_OFFLINE=true disables lookups (every item unknown).",
  ].join("\n"),
  inputSchema: {
    type: "object" as const,
    properties: {
      items: {
        type: "array",
        minItems: 1,
        maxItems: 25,
        description: "The proposed changes to check, 1 to 25.",
        items: {
          type: "object",
          properties: {
            ecosystem: { type: "string", enum: ["npm", "crates.io", "PyPI", "Go"], description: "Package registry." },
            package: {
              type: "string",
              description: 'Package name exactly as published ("axios", "@scope/pkg", "serde_json", "Jinja2", "golang.org/x/net", "github.com/labstack/echo/v4").',
            },
            to: {
              type: "string",
              description:
                'The version you intend to write ("7.5.10", "3.1.4", "v0.23.0"), "latest", or the constraint it must satisfy ("7.x", "^1.20", "=0.17", "~=3.1", ">=2,<3", "v1") to get the safe releases in it.',
            },
            from: { type: "string", description: "Exact version currently installed. Omit when adding a new dependency." },
          },
          required: ["ecosystem", "package", "to"],
        },
      },
    },
    required: ["items"],
  },
};

interface ItemResult {
  ecosystem: string;
  package: string;
  from: string | null;
  to: string;
  /** "latest" or the constraint, when the caller asked for one and `to` is what it resolved to. */
  to_requested?: string;
  verdict: Verdict;
  reason: string;
  signals: Signal[];
  range_check?: RangeCheck;
}

/** A validated request item. */
interface Requested {
  ecosystem: CheckEcosystem;
  package: string;
  /** What the caller passed as `to`, trimmed. */
  raw: string;
  target: Target;
  from?: string;
}

/** A request item with its `to` resolved to one version (or left unresolved with the reason). */
interface Resolved extends CheckItem {
  requested?: string;
  rangeCheck?: RangeCheck;
  /** Set when no single version could be chosen; the item is then blocked with this text. */
  unresolved?: string;
}

export async function executeDependencyCheck(
  _db: FourDADatabase | null,
  params: DependencyCheckParams,
  liveIntel: LiveIntelligence | null,
  opts: { now?: Date } = {},
) {
  const requested = validateItems(params.items);
  const now = opts.now ?? new Date();
  const checkedAt = now.toISOString();

  if (!liveIntel || !liveIntel.isEnabled()) {
    const reason = "Live lookups are disabled (FOURDA_OFFLINE=true); nothing about these versions could be checked.";
    return finish(
      checkedAt,
      requested.map((r) => ({ ...head(provisional(r)), verdict: "unknown" as const, reason, signals: [] })),
      { offline: true, osvCached: false },
    );
  }

  const sources = liveIntel.getReleaseSources();
  const fixSources = liveIntel.getFixPathSources();
  const indexes = await fetchIndexes(requested.map(provisional), sources, new Set(requested.filter(needsFullList).map(lookupKey)));

  // Constraints are judged against the package's whole advisory list.
  const advisoryLists = await packageAdvisoryLists(
    fixSources,
    requested.filter((r) => r.target.kind === "range" || r.target.kind === "exact_or_series"),
  );
  const items = requested.map((r) => resolveTarget(r, indexes.get(lookupKey(r))!, advisoryLists.get(lookupKey(r)), now));

  // Go dates come from per-version .info: read them for versions chosen from the list
  // (a constraint, "latest", or `v2.0.0` listed as `v2.0.0+incompatible`).
  const goRedo = items.filter((i) => {
    const lookup = indexes.get(lookupKey(i));
    return i.ecosystem === "Go" && !i.unresolved && lookup?.status === "ok" && lookup.data.releases[i.to] && !lookup.data.releases[i.to].publishedAt;
  });
  if (goRedo.length > 0) {
    for (const [key, lookup] of await fetchIndexes(goRedo, sources, new Set())) indexes.set(key, lookup);
    await settleGoPicks(goRedo, indexes, sources.Go, now);
  }

  const osvDeps: ResolvedDependency[] = items
    .filter((i) => !i.unresolved)
    .flatMap((item) => [item.to, item.from].filter((v): v is string => Boolean(v)).map((version) => osvDep(item, version)));
  const scan = await liveIntel.queryAdvisories(osvDeps);
  const byInstance = new Map<string, VulnerabilityEntry[]>();
  for (const v of scan.vulnerabilities) {
    const key = instanceKey(v.ecosystem, v.package, v.currentVersion);
    byInstance.set(key, [...(byInstance.get(key) ?? []), v]);
  }
  const advisoriesFor = (item: CheckItem): AdvisoryFacts =>
    scan.offline
      ? { available: false, detail: "lookup failed or was rate limited" }
      : {
          available: true,
          to: refs(byInstance.get(instanceKey(item.ecosystem, item.package, item.to))),
          from: item.from ? refs(byInstance.get(instanceKey(item.ecosystem, item.package, item.from))) : [],
        };

  // An exact `to` an advisory affects: the safe releases on its own line.
  const affectedExact = items.filter(
    (i) => !i.unresolved && !i.rangeCheck && advisoriesFor(i).available && hasRealAdvisory(advisoriesFor(i)),
  );
  const moreLists = await packageAdvisoryLists(fixSources, affectedExact.filter((i) => !advisoryLists.has(lookupKey(i))));
  for (const [k, v] of moreLists) advisoryLists.set(k, v);
  for (const item of affectedExact) {
    const lookup = indexes.get(lookupKey(item))!;
    const advisories = advisoryLists.get(lookupKey(item));
    const line = lineOf(item.ecosystem, item.to);
    if (lookup.status !== "ok" || !advisories || !line) continue;
    item.rangeCheck = checkRange({ ecosystem: item.ecosystem, index: lookup.data, range: line, basis: "same_line", advisories, from: item.from });
  }

  const holdWaivers = await findHoldWaivers(items, indexes, advisoryLists, fixSources, sources.Go, advisoriesFor, now);

  // Phase 2: first-publish dates of newly introduced dependencies.
  const plans = items.map((item) => planItem(item, indexes.get(lookupKey(item))!));
  const wantedCreated = new Map<string, { ecosystem: CheckEcosystem; name: string }>();
  for (const p of plans) {
    for (const name of p.introduced ?? []) {
      if (wantedCreated.size >= MAX_NEW_DEP_LOOKUPS) break;
      wantedCreated.set(`${p.item.ecosystem}\0${name}`, { ecosystem: p.item.ecosystem, name });
    }
  }
  const created = new Map<string, CreatedAtFact>();
  await mapLimit([...wantedCreated.entries()], NPM_CONCURRENCY, async ([key, { ecosystem, name }]) => {
    const lookup = await sources[ecosystem].getCreatedAt(name);
    created.set(key, lookup.status === "ok" ? { status: "ok", createdAt: lookup.data } : lookup);
  });

  const results: ItemResult[] = plans.map((p) => {
    const extra = p.item.rangeCheck ? { range_check: p.item.rangeCheck } : {};
    if (p.blocked) {
      // No release metadata: only the advisory lookup can still speak, and
      // only a negative finding is worth more than "unknown".
      if (p.item.unresolved) return { ...head(p.item), verdict: "unknown" as const, reason: p.blocked, signals: [], ...extra };
      const advisories = advisoriesSignal(p.item, advisoriesFor(p.item));
      const negative = advisories.effect === "avoid" || advisories.effect === "review";
      return {
        ...head(p.item),
        verdict: negative ? (advisories.effect as Verdict) : "unknown",
        reason: withAlternatives(negative ? `advisories: ${advisories.evidence} | ${p.blocked}` : p.blocked, p.item, negative),
        signals: [advisories],
        ...extra,
      };
    }
    const { item, index } = p;
    const to = index!.releases[item.to];
    const base = selectBaseline(index!, item);
    const advisories = advisoriesSignal(item, advisoriesFor(item));
    const createdForItem = new Map<string, CreatedAtFact>();
    for (const name of p.introduced ?? []) {
      const fact = created.get(`${item.ecosystem}\0${name}`);
      if (fact) createdForItem.set(name, fact);
    }
    const signals: Signal[] = [
      advisories,
      releaseAgeSignal(item, to, advisories, now, holdWaivers.get(item)),
      publishTrustSignal(item, to, base),
      installScriptSignal(item, to, item.from ? index!.releases[item.from] ?? null : null),
      newDependenciesSignal(item, to, base, p.introduced, createdForItem),
      withdrawnSignal(item, to),
      upgradeTypeSignal(item),
    ];
    const decided = decide(signals);
    const unsafe = decided.verdict === "avoid" || decided.verdict === "review";
    return { ...head(item), verdict: decided.verdict, reason: withAlternatives(decided.reason, item, unsafe), signals, ...extra };
  });

  return finish(checkedAt, results, { offline: scan.offline, osvCached: scan.cached });
}

/** The reason, plus the safe releases to write instead when the verdict is against `to`. */
function withAlternatives(reason: string, item: Resolved, unsafe: boolean): string {
  const rc = item.rangeCheck;
  if (!rc) return reason;
  const where = rc.basis === "requested" ? `in ${rc.range}` : `on ${item.to}'s line (${rc.range})`;
  if (rc.smallest_safe_in_range === null) {
    const ids = rc.affecting_all ?? [];
    const all = ids.length ? `: ${ids.slice(0, 3).join(", ")}${ids.length > 3 ? ` and ${ids.length - 3} more` : ""} affect every one` : "";
    const outside = rc.newest_safe_outside_range ? ` Newest safe release outside it: ${rc.newest_safe_outside_range}.` : "";
    return `${reason} | No release ${where} is free of known advisories${all}.${outside}`;
  }
  const upgrade = rc.smallest_safe_upgrade && rc.smallest_safe_upgrade !== rc.smallest_safe_in_range ? `, smallest above ${item.from} ${rc.smallest_safe_upgrade}` : "";
  const safe = `Safe ${where}: smallest ${rc.smallest_safe_in_range}${upgrade}, newest ${rc.newest_safe_in_range}.`;
  if (rc.basis === "same_line" && !unsafe) return reason;
  return `${reason} | ${safe}`;
}

function hasRealAdvisory(facts: AdvisoryFacts): boolean {
  return facts.available && facts.to.some((a) => !a.maintenance);
}

/** Before resolution: an exact `to` as is, anything else shown as the caller wrote it. */
function provisional(r: Requested): Resolved {
  const to = r.target.kind === "exact" ? r.target.version : r.raw;
  return { ecosystem: r.ecosystem, package: r.package, to, ...(r.from ? { from: r.from } : {}) };
}

function needsFullList(r: Requested): boolean {
  return r.target.kind !== "exact";
}

/**
 * One version per item: an exact `to` (Go: `+incompatible` when that is how
 * the proxy lists it), "latest" (newest stable, not withdrawn), or the
 * version a constraint recommends.
 */
function resolveTarget(
  r: Requested,
  lookup: RegistryLookup<PackageReleaseIndex>,
  advisories: AdvisoryRanges[] | null | undefined,
  now: Date,
): Resolved {
  const base = provisional(r);
  if (lookup.status !== "ok") return base;
  const index = lookup.data;
  let target = r.target;
  if (target.kind === "exact_or_series") target = index.releases[target.version] ? { kind: "exact", version: target.version } : { kind: "range", range: target.range };

  if (target.kind === "exact") {
    let version = target.version;
    if (r.ecosystem === "Go" && !index.releases[version] && index.releases[`${version}+incompatible`]) version = `${version}+incompatible`;
    // PEP 440 spellings differ ("3.1.06", "1.0-post1"); use the registry's.
    if (r.ecosystem === "PyPI" && !index.releases[version]) {
      version = Object.keys(index.releases).find((v) => compareIn("PyPI", v, version) === 0) ?? version;
    }
    return { ...base, to: version };
  }
  if (target.kind === "latest") {
    const newest = newestOf(r.ecosystem, Object.values(index.releases).filter((x) => !x.withdrawn).map((x) => x.version));
    return newest ? { ...base, to: newest, requested: "latest" } : base;
  }

  const range = target.range;
  const admitted = Object.values(index.releases)
    .filter((x) => !x.withdrawn && rangeAdmits(r.ecosystem, range, x.version) === true)
    .map((x) => x.version);
  if (admitted.length === 0) {
    return { ...base, requested: r.raw, unresolved: `No published, non-withdrawn release of ${r.package} matches ${range}.` };
  }
  if (!advisories) {
    // Without the advisory list no release can be called safe; judge the newest one on its own advisories.
    return { ...base, to: newestOf(r.ecosystem, admitted)!, requested: r.raw };
  }
  const rangeCheck = checkRange({ ecosystem: r.ecosystem, index, range, basis: "requested", advisories, from: r.from });
  const safe = rangeCheck.safe_versions;
  const settled = (v: string) => {
    const at = index.releases[v]?.publishedAt;
    return !at || (now.getTime() - Date.parse(at)) / DAY_MS >= WAIT_DAYS;
  };
  const pick = r.from
    ? rangeCheck.smallest_safe_upgrade
    : ([...safe].reverse().find(settled) ?? rangeCheck.newest_safe_in_range);
  return { ...base, to: pick ?? newestOf(r.ecosystem, admitted)!, requested: r.raw, rangeCheck };
}

/** `.info` reads spent looking for a Go release past the hold, per item. */
const GO_SETTLE_READS = 3;

/**
 * Go lists carry no dates, so a constraint's newest safe release was picked
 * blind to the 3-day hold. When it turns out to be inside it, step down the
 * safe list (newest first) to the newest one that is not, reading `.info`
 * for each step. A pick above `from` (the smallest fix) is left alone.
 */
async function settleGoPicks(
  items: Resolved[],
  indexes: Map<string, RegistryLookup<PackageReleaseIndex>>,
  go: ReleaseMetadataSource,
  now: Date,
): Promise<void> {
  const young = (at: string | null | undefined) => Boolean(at) && (now.getTime() - Date.parse(at!)) / DAY_MS < WAIT_DAYS;
  for (const item of items) {
    const rc = item.rangeCheck;
    const lookup = indexes.get(lookupKey(item));
    if (!rc || item.from || rc.basis !== "requested" || lookup?.status !== "ok") continue;
    if (!young(lookup.data.releases[item.to]?.publishedAt)) continue;
    const older = rc.safe_versions.filter((v) => compareIn("Go", v, item.to) < 0).reverse().slice(0, GO_SETTLE_READS);
    for (const v of older) {
      const next = await go.getReleases(item.package, [v, item.to]);
      if (next.status !== "ok") break;
      if (next.data.releases[v]) lookup.data.releases[v] = next.data.releases[v];
      if (!young(next.data.releases[v]?.publishedAt)) {
        item.to = v;
        break;
      }
    }
  }
}

/** Newest release, stable ones first. */
function newestOf(ecosystem: CheckEcosystem, versions: string[]): string | null {
  const stable = versions.filter((v) => !isPrereleaseIn(ecosystem, v));
  const pool = stable.length > 0 ? stable : versions;
  return pool.reduce<string | null>((max, v) => (max === null || compareIn(ecosystem, v, max) > 0 ? v : max), null);
}

/** Go publish dates read per item to decide a hold waiver (the list has none). */
const GO_WAIVER_READS = 8;

function isYoung(at: string | null | undefined, now: Date): boolean {
  return Boolean(at) && (now.getTime() - Date.parse(at!)) / DAY_MS < WAIT_DAYS;
}

/**
 * Clean `to` versions inside the release-age hold for which holding back
 * leaves nothing safe to write: every safe release on the line is inside the
 * hold as well, and the line has older releases, all with a known advisory.
 * A package whose only releases are new keeps the hold, which is what it is for.
 * An undated release (Go lists carry no dates) counts as old, never as safe.
 */
async function findHoldWaivers(
  items: Resolved[],
  indexes: Map<string, RegistryLookup<PackageReleaseIndex>>,
  advisoryLists: Map<string, AdvisoryRanges[] | null>,
  fixSources: FixPathSources | null,
  go: ReleaseMetadataSource,
  advisoriesFor: (item: CheckItem) => AdvisoryFacts,
  now: Date,
): Promise<Map<Resolved, HoldWaiver>> {
  const out = new Map<Resolved, HoldWaiver>();
  const held = items.filter((i) => {
    const lookup = indexes.get(lookupKey(i));
    if (i.unresolved || lookup?.status !== "ok") return false;
    const facts = advisoriesFor(i);
    return facts.available && !hasRealAdvisory(facts) && isYoung(lookup.data.releases[i.to]?.publishedAt, now);
  });
  if (held.length === 0) return out;
  const missing = held.filter((i) => !advisoryLists.has(lookupKey(i)));
  for (const [k, v] of await packageAdvisoryLists(fixSources, missing)) advisoryLists.set(k, v);

  for (const item of held) {
    const lookup = indexes.get(lookupKey(item));
    const advisories = advisoryLists.get(lookupKey(item));
    const line = lineOf(item.ecosystem, item.to);
    if (lookup?.status !== "ok" || !advisories || !line) continue;
    const index = lookup.data;
    const rc = checkRange({ ecosystem: item.ecosystem, index, range: line, basis: "same_line", advisories, from: item.from });
    // safe_versions holds the newest few; it must reach the smallest to cover them all.
    if (rc.smallest_safe_in_range === null || !rc.safe_versions.includes(rc.smallest_safe_in_range)) continue;
    if (item.ecosystem === "Go") {
      const undated = rc.safe_versions.filter((v) => !index.releases[v]?.publishedAt).slice(0, GO_WAIVER_READS);
      if (undated.length > 0) {
        const read = await go.getReleases(item.package, undated);
        if (read.status === "ok") {
          for (const v of undated) if (read.data.releases[v]) index.releases[v] = read.data.releases[v];
        }
      }
    }
    if (!rc.safe_versions.every((v) => isYoung(index.releases[v]?.publishedAt, now))) continue;
    const safe = new Set(rc.safe_versions);
    const older = Object.values(index.releases).filter(
      (r) =>
        !r.withdrawn &&
        !safe.has(r.version) &&
        !isPrereleaseIn(item.ecosystem, r.version) &&
        rangeAdmits(item.ecosystem, line, r.version) === true &&
        !isYoung(r.publishedAt, now),
    );
    if (older.length > 0) out.set(item, { line, olderVulnerable: older.length });
  }
  return out;
}

async function packageAdvisoryLists(
  fixSources: FixPathSources | null,
  items: Array<{ ecosystem: CheckEcosystem; package: string }>,
): Promise<Map<string, AdvisoryRanges[] | null>> {
  const out = new Map<string, AdvisoryRanges[] | null>();
  if (!fixSources) return out;
  const unique = new Map(items.map((i) => [lookupKey(i), i]));
  await mapLimit([...unique.entries()], NPM_CONCURRENCY, async ([key, i]) => {
    out.set(key, await fixSources.packageAdvisories(i.ecosystem, i.package).catch(() => null));
  });
  return out;
}

function planItem(item: Resolved, lookup: RegistryLookup<PackageReleaseIndex>) {
  if (lookup.status === "unreachable") {
    return { item, blocked: `Registry could not be reached (${lookup.detail}); nothing about ${item.to} was verified.`, index: null, introduced: null };
  }
  if (lookup.status === "not_found") {
    return {
      item,
      blocked: `${lookup.detail}. If it is a private package this tool cannot judge it; otherwise check the name for a typo or a hallucinated package before adding it.`,
      index: null,
      introduced: null,
    };
  }
  if (item.unresolved) return { item, blocked: item.unresolved, index: lookup.data, introduced: null };
  const index = lookup.data;
  const to = index.releases[item.to];
  if (!to) {
    return { item, blocked: `${item.package}@${item.to} is not a published version on ${item.ecosystem}.${goMajorHint(item)}`, index, introduced: null };
  }
  return { item, blocked: null, index, introduced: introducedDependencies(to, selectBaseline(index, item).record) };
}

/** Go majors 2+ live at their own module path. */
function goMajorHint(item: CheckItem): string {
  if (item.ecosystem !== "Go") return "";
  const major = goVersionMajor(item.to);
  const pathMajor = goPathMajor(item.package) ?? 1;
  if (major === null || major < 2 || major === pathMajor) return "";
  return ` Go major ${major} is a different module: ${item.package.replace(/\/v\d+$/, "")}/v${major}.`;
}

async function fetchIndexes(
  items: CheckItem[],
  sources: Record<CheckEcosystem, ReleaseMetadataSource>,
  fullList: Set<string>,
): Promise<Map<string, RegistryLookup<PackageReleaseIndex>>> {
  const wanted = new Map<string, { item: CheckItem; versions: Set<string> }>();
  for (const item of items) {
    const key = lookupKey(item);
    const entry = wanted.get(key) ?? { item, versions: new Set<string>() };
    entry.versions.add(item.to);
    if (item.from) entry.versions.add(item.from);
    wanted.set(key, entry);
  }
  const out = new Map<string, RegistryLookup<PackageReleaseIndex>>();
  await mapLimit([...wanted.entries()], NPM_CONCURRENCY, async ([key, { item, versions }]) => {
    // A reader that pages (crates.io) stops once it has the wanted versions; a constraint needs them all.
    const list = item.ecosystem === "crates.io" && fullList.has(key) ? [] : [...versions];
    out.set(key, await sources[item.ecosystem].getReleases(item.package, list));
  });
  return out;
}

function validateItems(raw: unknown): Requested[] {
  if (!Array.isArray(raw) || raw.length < 1 || raw.length > MAX_ITEMS) {
    throw new Error(`items must be an array of 1 to ${MAX_ITEMS} { ecosystem, package, to, from? } objects`);
  }
  return raw.map((r, i) => {
    const o = (r ?? {}) as Record<string, unknown>;
    const where = `items[${i}]`;
    const ecosystem = ECOSYSTEMS.find((e) => e === o.ecosystem || (typeof o.ecosystem === "string" && e.toLowerCase() === o.ecosystem.trim().toLowerCase()));
    if (!ecosystem) throw new Error(`${where}.ecosystem must be one of ${ECOSYSTEMS.map((e) => `"${e}"`).join(", ")}`);
    if (typeof o.package !== "string" || !o.package.trim()) throw new Error(`${where}.package must be a non-empty string`);
    const rawTo = typeof o.to === "string" ? o.to.trim() : "";
    const target = parseTarget(ecosystem, rawTo);
    if (!target) {
      throw new Error(
        `${where}.to must be an exact version, "latest", or a ${ecosystem} version constraint such as ${EXAMPLES[ecosystem]} (got ${JSON.stringify(o.to)})`,
      );
    }
    let from: string | undefined;
    if (o.from !== undefined && o.from !== null && o.from !== "") {
      const f = typeof o.from === "string" ? parseTarget(ecosystem, o.from) : null;
      if (!f || (f.kind !== "exact" && f.kind !== "exact_or_series")) {
        throw new Error(`${where}.from must be an exact version, the one installed (got ${JSON.stringify(o.from)}), not a range`);
      }
      from = f.version;
    }
    return { ecosystem, package: o.package.trim(), raw: rawTo, target, ...(from ? { from } : {}) };
  });
}

const EXAMPLES: Record<CheckEcosystem, string> = {
  npm: '"7.x" or "^1.20.0"',
  "crates.io": '"0.17" or "=0.23.x"',
  PyPI: '"3.1.*", "~=3.1" or ">=2,<3"',
  Go: '"v1" or "v0.23.x"',
};

function osvDep(item: CheckItem, version: string): ResolvedDependency {
  return {
    name: item.package,
    version,
    ecosystem: item.ecosystem,
    isDev: false,
    isDirect: true,
    devScopeKnown: true,
    target: null,
    platformActive: true,
    sourceDirs: [],
  };
}

function refs(entries: VulnerabilityEntry[] | undefined): AdvisoryRef[] {
  const seen = new Set<string>();
  return (entries ?? []).flatMap((v) => {
    if (seen.has(v.vulnId)) return [];
    seen.add(v.vulnId);
    return [{ id: v.vulnId, severity: v.severity, summary: v.summary, maintenance: isMaintenanceNotice(v) }];
  });
}

const instanceKey = (eco: string, name: string, version: string) => `${eco}\0${eco === "PyPI" ? normalizePypi(name) : name}\0${version}`;
const normalizePypi = (name: string) => name.toLowerCase().replace(/[-_.]+/g, "-");
const lookupKey = (item: { ecosystem: string; package: string }) =>
  `${item.ecosystem}\0${item.ecosystem === "PyPI" ? normalizePypi(item.package) : item.package}`;
const head = (item: Resolved) => ({
  ecosystem: item.ecosystem,
  package: item.package,
  from: item.from ?? null,
  to: item.to,
  ...(item.requested ? { to_requested: item.requested } : {}),
});

function finish(checkedAt: string, results: ItemResult[], meta: { offline: boolean; osvCached: boolean }) {
  const counts = new Map<Verdict, number>();
  for (const r of results) counts.set(r.verdict, (counts.get(r.verdict) ?? 0) + 1);
  const order: Verdict[] = ["avoid", "review", "unknown", "wait", "proceed"];
  const parts = order.filter((v) => counts.has(v)).map((v) => `${counts.get(v)} ${v}`);
  return {
    checked_at: checkedAt,
    summary: `${results.length} checked: ${parts.join(", ")}. Write only "proceed" versions; for the rest use range_check's safe versions or report the evidence.`,
    results,
    _meta: {
      sources: ["registry.npmjs.org", "crates.io", "index.crates.io", "pypi.org", "proxy.golang.org", "osv.dev"],
      verdict_rule: VERDICT_RULE,
      privacy: PRIVACY_NOTE,
      offline: meta.offline,
      osv_cached: meta.osvCached,
      provenance: {
        mode: "live_registry_check",
        note: "Point-in-time facts from the public registries and OSV.dev at checked_at. Says nothing about code behaviour; a proceed is the absence of known warning signs, not a review of the release.",
      },
    },
  };
}

async function mapLimit<T>(items: T[], limit: number, fn: (item: T) => Promise<void>): Promise<void> {
  let next = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) await fn(items[next++]);
  });
  await Promise.all(workers);
}
