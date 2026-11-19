// SPDX-License-Identifier: Apache-2.0
/**
 * dependency_check, the lookups of a pass (dependency-check.ts checkPass): what every later stage
 * reads (the release sources, the Python the project declares, the judges of what a release brings
 * with it, each package's OSV.dev advisory list), the first lookups, all started at once, and the
 * crates the registry publishes under another spelling.
 */

import type { LiveIntelligence } from "../live/index.js";
import type { FixPathSources } from "../live/fix-paths.js";
import type { AdvisoryRanges } from "../live/osv-ranges.js";
import { pushAll } from "../array-utils.js";
import type { CheckEcosystem, PackageReleaseIndex, RegistryLookup, ReleaseMetadataSource } from "../live/release-metadata.js";
import type { ResolvedDependency } from "../live/types.js";
import type { HeldCheck } from "../live/held-dependencies.js";
import { requirementSources } from "../live/release-requirements.js";
import { readProjectPython, readProjectPythonUnread, type ProjectPython } from "../live/project-python.js";
import { GO_VERSION, goVersion } from "../live/go-releases.js";
import { samePackageName } from "../live/version-compare.js";
import { noteListFacts } from "./dependency-check-facts.js";
import type { CheckItem } from "./dependency-check-signals.js";
import { compareIn } from "./dependency-check-versions.js";
import { HeldJudge, RequirementJudge, type ReleaseJudge } from "./dependency-check-held.js";
import { pythonRangeFilter } from "./dependency-check-python.js";
import { ECOSYSTEMS, lookupKey, provisional, type Requested } from "./dependency-check-items.js";

/** Registry reads in flight per ecosystem (each registry has its own pool: crates.io's one-a-second pacing never holds up npm or PyPI). */
export const REGISTRY_CONCURRENCY = 6;
/** OSV.dev package advisory lists (/v1/query) in flight at once. */
const OSV_LIST_CONCURRENCY = 8;

/** What every stage of a live pass reads, built once per pass (passContext). */
export interface PassContext {
  now: Date;
  liveIntel: LiveIntelligence;
  /** The items looked up, in the order asked (dependency-check-screen.ts left the others out). */
  requested: Requested[];
  sources: Record<CheckEcosystem, ReleaseMetadataSource>;
  fixSources: FixPathSources | null;
  /** PyPI: the Python versions the project declares, read from its own files; null when it declares none. */
  projectPython: ProjectPython | null;
  /** Where the project declares a Python that could not be read. */
  pythonUnreadAt: string | null;
  /** Whether a PyPI release supports the project's Python (true when nothing is judged). */
  supportsPython: (item: CheckItem, index: PackageReleaseIndex) => (v: string) => boolean;
  /** Each package's advisory list, requested once per pass however many stages ask for it. */
  packageAdvisoryLists: AdvisoryListReader;
  /** The releases held dependencies were asked about, so a contradicted answer can be dropped from the cache (B7). */
  heldAsked: ResolvedDependency[];
  /** npm: what each release holds. */
  held: HeldJudge;
  /** The judge of what an ecosystem's releases bring with them; null where nothing is read (a source without requirement lists). */
  judgeOf: (ecosystem: CheckEcosystem) => ReleaseJudge | null;
  /** One judge() per ecosystem, together. */
  judgeAll: (requests: Array<{ ecosystem: CheckEcosystem; pkg: string; versions: string[] }>) => Promise<unknown>;
  /** What `to` brings with it, as judged. */
  heldAt: (item: CheckItem) => HeldCheck | undefined;
  /** `to` brings in an affected dependency that keeps it out of the safe releases (never a Go minimum: that is a caveat). */
  heldAffected: (item: CheckItem) => boolean;
}

/** Each package's registry answer and advisory list, by lookupKey. Later stages add lists, and blank one found incomplete. */
export interface Lookups {
  indexes: Map<string, RegistryLookup<PackageReleaseIndex>>;
  advisoryLists: Map<string, AdvisoryRanges[] | null>;
}

/** What every stage of a live pass reads: built before any lookup is made. */
export function passContext(liveIntel: LiveIntelligence, requested: Requested[], now: Date): PassContext {
  const sources = liveIntel.getReleaseSources();
  const fixSources = liveIntel.getFixPathSources();
  // PyPI: the Python versions the project declares, read from its own files; null when it declares
  // none, and then nothing is judged against a Python version.
  const projectRoot = requested.some((r) => r.ecosystem === "PyPI") ? (liveIntel.getProjectRoot?.() ?? null) : null;
  const projectPython = projectRoot ? readProjectPython(projectRoot) : null;
  /** Where the project declares a Python that could not be read: the answer says so instead of judging nothing silently. */
  const pythonUnreadAt = projectRoot && !projectPython ? readProjectPythonUnread(projectRoot) : null;
  /** Whether a PyPI release supports the project's Python (true when nothing is judged). */
  const supportsPython = (item: CheckItem, index: PackageReleaseIndex) => {
    const filter = pythonRangeFilter(projectPython, item.ecosystem, index);
    return (v: string) => !filter?.unsupported(v);
  };
  const packageAdvisoryLists = advisoryListReader(fixSources);
  // The releases held dependencies were asked about, so a contradicted answer can be dropped from the cache (B7).
  const heldAsked: ResolvedDependency[] = [];
  const held = new HeldJudge(fixSources, (deps) => {
    pushAll(heldAsked, deps);
    return liveIntel.queryAdvisories(deps);
  });
  // crates.io, PyPI and Go: what a release requires comes with it too (live/release-requirements.ts).
  // Go's minimal version selection keeps the project's own newer selection of a required module.
  const reqs = new RequirementJudge(
    fixSources ? requirementSources(sources, fixSources) : null,
    (deps) => {
      pushAll(heldAsked, deps);
      return liveIntel.queryAdvisories(deps);
    },
    selectedGoVersions(liveIntel),
    projectPython?.covers ?? null,
  );
  /** The judge of what an ecosystem's releases bring with them; null where nothing is read (a source without requirement lists). */
  const judgeOf = (ecosystem: CheckEcosystem): ReleaseJudge | null => (ecosystem === "npm" ? held : reqs.of(ecosystem));
  /** One judge() per ecosystem, together. */
  const judgeAll = (requests: Array<{ ecosystem: CheckEcosystem; pkg: string; versions: string[] }>) =>
    Promise.all(ECOSYSTEMS.map((eco) => judgeOf(eco)?.judge(requests.filter((r) => r.ecosystem === eco))));
  const heldAt = (item: CheckItem) => judgeOf(item.ecosystem)?.at(item.package, item.to);
  /** `to` brings in an affected dependency that keeps it out of the safe releases (never a Go minimum: that is a caveat). */
  const heldAffected = (item: CheckItem) => item.ecosystem !== "Go" && Boolean(judgeOf(item.ecosystem)?.affected(item.package, item.to));
  return { now, liveIntel, requested, sources, fixSources, projectPython, pythonUnreadAt, supportsPython, packageAdvisoryLists, heldAsked, held, judgeOf, judgeAll, heldAt, heldAffected };
}

/** The first lookups of a pass, all started at once: the registry reads and the advisory lists the next stages need first. */
export async function firstLookups(ctx: PassContext): Promise<Lookups> {
  const { requested, sources, packageAdvisoryLists, held } = ctx;
  // Everything that depends only on the names starts at once: the registry reads, each package's
  // OSV advisory list (nearly every item needs it later: a constraint's range check, the malware
  // name check of a new dependency, the safe line of an affected exact version) and, for npm, what
  // each release holds. Later phases await the same requests instead of starting them one phase at
  // a time (a 25-item check took 32 s cold, most of it phases waiting on each other).
  void packageAdvisoryLists(requested);
  // r7: each concrete finding is kept for the call as soon as it is read, so a call that runs out
  // of time still answers avoid for a release already known to be malware (dependency-check-facts.ts).
  for (const r of requested) {
    if (r.target.kind !== "exact") continue;
    const to = r.target.version;
    void packageAdvisoryLists([r]).then((lists) => noteListFacts(r, to, lists.get(lookupKey(r))), () => undefined);
  }
  held.prefetch(requested.filter((r) => r.ecosystem === "npm").map((r) => r.package));
  const [indexes, advisoryLists] = await Promise.all([
    fetchIndexes(requested.map(provisional), sources, new Set(requested.filter(needsFullList).map(lookupKey))),
    // Constraints are judged against the package's whole advisory list.
    packageAdvisoryLists(requested.filter((r) => r.target.kind === "range")),
  ]);
  return { indexes, advisoryLists };
}

/** A crate asked under a spelling crates.io publishes under another is asked under the published one from here on. */
export async function adoptPublishedCrateNames(ctx: PassContext, lookups: Lookups): Promise<void> {
  const { requested, packageAdvisoryLists } = ctx;
  const { indexes, advisoryLists } = lookups;
  // crates.io and Cargo read `-` and `_` (and case) in a crate name as one crate; the registry's
  // answer names the published spelling (crates-versions.ts). Everything after this is asked under
  // it, OSV.dev included, and the answer says so: `serde-json` was unknown while `serde_json` was
  // proceed (pre-publish round 10, W2). A spelling the registry could not confirm stays unknown.
  const renamed: Requested[] = [];
  for (const r of requested) {
    const lookup = indexes.get(lookupKey(r));
    if (r.ecosystem !== "crates.io" || lookup?.status !== "ok") continue;
    const published = lookup.data.name;
    if (published === r.package || !samePackageName(published, r.package, "crates.io")) continue;
    r.asked = r.package;
    r.package = published;
    renamed.push(r);
  }
  for (const [k, v] of await packageAdvisoryLists(renamed.filter((r) => r.target.kind === "range"))) advisoryLists.set(k, v);
}

export async function fetchIndexes(
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
  // One pool per registry, all running at once.
  await Promise.all(
    ECOSYSTEMS.map((ecosystem) =>
      mapLimit(
        [...wanted.entries()].filter(([, { item }]) => item.ecosystem === ecosystem),
        REGISTRY_CONCURRENCY,
        async ([key, { item, versions }]) => {
          // A reader that pages (crates.io) stops once it has the wanted versions; a constraint needs them all.
          const list = item.ecosystem === "crates.io" && fullList.has(key) ? [] : [...versions];
          out.set(key, await sources[item.ecosystem].getReleases(item.package, list));
        },
      ),
    ),
  );
  return out;
}

function needsFullList(r: Requested): boolean {
  return r.target.kind !== "exact";
}

/**
 * Go: the version of each module the project's own go.mod / go.sum selects (the highest it holds).
 * Minimal version selection keeps it over a lower minimum a new requirement names.
 */
function selectedGoVersions(liveIntel: LiveIntelligence): (ecosystem: string, name: string) => string | null {
  const selected = new Map<string, string>();
  if (liveIntel.isInitialized?.()) {
    for (const d of [...liveIntel.getResolvedDeps(), ...liveIntel.getAuditDeps()]) {
      if (d.ecosystem !== "Go" || !d.version) continue;
      const v = goVersion(d.version);
      if (!GO_VERSION.test(v)) continue;
      const held = selected.get(d.name);
      if (!held || compareIn("Go", v, held) > 0) selected.set(d.name, v);
    }
  }
  return (ecosystem, name) => (ecosystem === "Go" ? (selected.get(name) ?? null) : null);
}

/** Each package's OSV advisory list (verdict view), by lookupKey; null where it could not be read. */
export type AdvisoryListReader = (items: Array<{ ecosystem: CheckEcosystem; package: string }>) => Promise<Map<string, AdvisoryRanges[] | null>>;

/**
 * One reader per call: each package's list is requested once, at most OSV_LIST_CONCURRENCY at a
 * time, and every later phase that asks for it awaits the same request (in flight or done).
 * Nothing (an empty map) without lookup sources.
 */
function advisoryListReader(fixSources: FixPathSources | null): AdvisoryListReader {
  const lists = new Map<string, Promise<AdvisoryRanges[] | null>>();
  const slots = limiter(OSV_LIST_CONCURRENCY);
  return async (items) => {
    const out = new Map<string, AdvisoryRanges[] | null>();
    if (!fixSources) return out;
    // A crate is asked for under the spelling given: one renamed to its published spelling asks
    // OSV.dev again under that one (round 10, W2). The answer is filed under the registry's identity.
    const requestKey = (i: { ecosystem: CheckEcosystem; package: string }) => (i.ecosystem === "crates.io" ? `${lookupKey(i)}\0${i.package}` : lookupKey(i));
    const unique = new Map(items.map((i) => [requestKey(i), i]));
    for (const [key, i] of unique) {
      if (!lists.has(key)) {
        lists.set(
          key,
          slots(() => fixSources.packageAdvisories(i.ecosystem, i.package))
            .then((list) => (list ? list.map(verdictView) : null))
            .catch(() => null),
        );
      }
    }
    for (const [key, i] of unique) out.set(lookupKey(i), await lists.get(key)!);
    return out;
  };
}

/**
 * An advisory as dependency_check's verdict reads it: a maintenance notice only when the record
 * itself declares the class and names no fixed release (osv-ranges.ts `declaredNotice`). A notice
 * the shared predicate reads from the summary wording alone counts as an advisory here, in the
 * range checks and in the verdict alike.
 */
function verdictView(a: AdvisoryRanges): AdvisoryRanges {
  return a.maintenance && !a.declaredNotice ? { ...a, maintenance: false } : a;
}

/** Run at most `limit` of the given tasks at once. */
function limiter(limit: number): <T>(task: () => Promise<T>) => Promise<T> {
  let running = 0;
  const queue: Array<() => void> = [];
  const release = () => {
    running--;
    queue.shift()?.();
  };
  return <T>(task: () => Promise<T>) =>
    new Promise<T>((resolve, reject) => {
      const start = () => {
        running++;
        task().then(resolve, reject).finally(release);
      };
      if (running < limit) start();
      else queue.push(start);
    });
}

export async function mapLimit<T>(items: T[], limit: number, fn: (item: T) => Promise<void>): Promise<void> {
  let next = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) await fn(items[next++]);
  });
  await Promise.all(workers);
}
