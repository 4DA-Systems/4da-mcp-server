// SPDX-License-Identifier: Apache-2.0
/**
 * what_should_i_know and the version a task names (black-box re-run of 96c16d2, 2026-11-14):
 * "add lodash 4.17.20 to package.json" came back safe_to_delegate, with lodash judged at `latest`
 * (4.18.1) instead of the 4.17.20 the task writes, which four advisories affect; "pin axios to
 * 0.21.1" did not see axios at all. The versions a task names are read here in every common form
 * and judged by dependency_check itself (the same engine), at that exact version or constraint:
 *
 *   name@1.2.3 / name@^1.2 (npm, Go `module@v1.2.3`), name==1.2.3 / name~=3.1 / name>=2,<3 (PyPI),
 *   "name to 1.2.3", "name from 1.0 to 1.2", "pin name 1.2.3", "add name 4.17.20".
 *
 * A named version that is not `proceed` keeps the briefing from safe_to_delegate.
 */

import type { LiveIntelligence } from "../live/index.js";
import type { CheckEcosystem } from "../live/release-metadata.js";
import type { ResolvedDependency } from "../live/types.js";
import { asName, projectEcosystems, proseEcosystem, statedEcosystem, type NameCheckLive } from "./briefing-new-packages.js";
import { executeDependencyCheck } from "./dependency-check.js";

export interface RequestedVersion {
  name: string;
  ecosystem: CheckEcosystem;
  /** The version or constraint the task names, as written. */
  to: string;
  /** The installed version, when the project has exactly one copy of it. */
  from?: string;
  /** Other ecosystems the project uses, tried when the guessed one has no such release. */
  alternatives?: CheckEcosystem[];
}

export interface RequestedVersionFinding extends RequestedVersion {
  /** dependency_check's verdict for exactly `to`. */
  verdict: "proceed" | "wait" | "review" | "avoid" | "unknown";
  /** The release a constraint resolved to (equal to `to` for an exact version). */
  resolved: string | null;
  reason: string;
  /** The safe releases dependency_check names, when it names any. */
  safe?: { smallest: string | null; newest: string | null };
  malicious: boolean;
  /** Critical advisories that affect exactly this release (event-stream 3.3.6: GHSA-mh6f-8j2x-4483). */
  critical?: string[];
}

const MAX_REQUESTED = 5;
const CHECK_BUDGET_MS = 10_000;
/** A version or constraint as tasks write them: 4.17.20, v1.2.3, ^1.2, ~2.0.1, >=2, 7.x, 1.2.*. */
const VERSIONISH = /^(?:[~^=]|[<>]=?)?v?\d+(?:\.(?:\d+|x|\*))*(?:-[\w.]+)?(?:\+[\w.]+)?$/i;
/** Words that come before a package name and are never one. */
const VERBS = new Set([
  "add", "adding", "install", "installing", "pin", "pinning", "bump", "bumping", "upgrade", "upgrading", "update", "updating", "downgrade", "downgrading",
  "move", "moving", "set", "setting", "use", "using", "change", "lock", "require", "version", "release", "it", "them", "everything", "all", "dependency", "package",
]);
const PYPI_SPEC = /^([A-Za-z0-9][A-Za-z0-9._-]*)((?:===?|~=|>=|<=|!=|>|<)[^\s]+)$/;

const GO_HOST_PATH = /^[a-z0-9][a-z0-9.-]*\.[a-z]{2,}\//i;

function nameFor(token: string, deps: readonly ResolvedDependency[], fallback: CheckEcosystem): { name: string; ecosystem: CheckEcosystem; guessed?: true } | null {
  const bare = token.replace(/[),.;:!?'"`]+$/, "").replace(/^[`'"(]+/, "");
  if (VERBS.has(bare.toLowerCase())) return null;
  const norm = (s: string) => s.toLowerCase().replace(/[-_.]+/g, "-");
  const installed = deps.find((d) => d.name.toLowerCase() === bare.toLowerCase() || (d.ecosystem === "PyPI" && norm(d.name) === norm(bare)));
  if (installed && (installed.ecosystem === "npm" || installed.ecosystem === "crates.io" || installed.ecosystem === "PyPI" || installed.ecosystem === "Go")) {
    return { name: installed.name, ecosystem: installed.ecosystem };
  }
  // A host-led path ("github.com/...") is a Go module whatever the project mostly holds, and a
  // malformed one ("github.com/gin-gonic/gin/") is passed on as written: dependency_check says it is
  // not a path the go command accepts, never a clean answer (pre-publish audit B1).
  if (GO_HOST_PATH.test(bare)) {
    const go = asName(bare, "Go");
    if (go) return { name: go, ecosystem: "Go" };
  }
  const name = asName(bare, fallback);
  return name ? { name, ecosystem: fallback, guessed: true } : null;
}

/** The (package, version) pairs a task names, in the order named. At most five. */
export function detectRequestedVersions(task: string, deps: readonly ResolvedDependency[]): RequestedVersion[] {
  const raw = task.match(/[@A-Za-z0-9`'"(^~<>=][\w./@*=<>~^!`'"-]*/g) ?? [];
  const words = raw.map((t) => t.replace(/[`'"(),.;:]+$/, "").replace(/^[`'"(]+/, "").toLowerCase());
  const fallback = proseEcosystem(words, deps);
  // The ecosystem of a bare name nobody installs is only a guess when the task names none and the
  // project uses several: the other ones are tried if the guess has no such release (a mixed npm +
  // Python repository read "add event-stream version 3.3.6" as PyPI; blind audit replay 2026-11-14).
  const others = statedEcosystem(words) ? [] : projectEcosystems(deps).filter((e) => e !== fallback);
  const out: RequestedVersion[] = [];
  const add = (who: { name: string; ecosystem: CheckEcosystem; guessed?: true } | null, version: string, guess = false) => {
    if (!who || !version) return;
    if (out.some((r) => r.ecosystem === who.ecosystem && r.name === who.name && r.to === version)) return;
    const copies = deps.filter((d) => d.ecosystem === who.ecosystem && d.name === who.name && d.version);
    const versions = [...new Set(copies.map((d) => d.version!))];
    const alternatives = guess && who.guessed && who.ecosystem === fallback ? others.filter((e) => asName(who.name, e) !== null) : [];
    out.push({
      name: who.name,
      ecosystem: who.ecosystem,
      to: version,
      ...(versions.length === 1 && versions[0] !== version ? { from: versions[0] } : {}),
      ...(alternatives.length > 0 ? { alternatives } : {}),
    });
  };
  const clean = (t: string) => t.replace(/[`'"),.;:]+$/, "").replace(/^[`'"(]+/, "");

  for (let i = 0; i < raw.length; i++) {
    const token = clean(raw[i]);
    // name@version (npm; Go module@v1.2.3); a scoped npm name keeps its leading @.
    const at = token.indexOf("@", 1);
    if (at > 0 && VERSIONISH.test(token.slice(at + 1))) {
      const name = token.slice(0, at);
      // `@` pins a version in npm and in `go get`; nowhere else.
      const eco: CheckEcosystem = /^[a-z0-9.-]+\.[a-z]{2,}\//i.test(name) ? "Go" : "npm";
      add(nameFor(name, deps, eco), token.slice(at + 1));
      continue;
    }
    // name==1.2.3, name~=3.1, name>=2,<3 (PyPI)
    const spec = PYPI_SPEC.exec(token);
    if (spec) {
      add(nameFor(spec[1], deps, "PyPI"), spec[2].replace(/^==(?!=)/, ""));
      continue;
    }
    const next = clean(raw[i + 1] ?? "");
    const after = clean(raw[i + 2] ?? "");
    // "name version 1.2.3", "set name version to 1.2.3" ("add event-stream version 3.3.6" was judged
    // at latest and came back safe_to_delegate; blind audit 2026-11-14, F4).
    if (words[i + 1] === "version" && VERSIONISH.test(after)) {
      add(nameFor(token, deps, fallback), after, true);
      continue;
    }
    if (words[i + 1] === "version" && words[i + 2] === "to" && VERSIONISH.test(clean(raw[i + 3] ?? ""))) {
      add(nameFor(token, deps, fallback), clean(raw[i + 3]), true);
      continue;
    }
    // "version 1.2.3 of name"
    if (words[i] === "version" && VERSIONISH.test(next) && words[i + 2] === "of" && raw[i + 3]) {
      add(nameFor(clean(raw[i + 3]), deps, fallback), next, true);
      continue;
    }
    // "name to 1.2.3"
    if (words[i + 1] === "to" && VERSIONISH.test(after)) {
      add(nameFor(token, deps, fallback), after, true);
      continue;
    }
    // "name from 1.0 to 1.2"
    if (words[i + 1] === "from" && VERSIONISH.test(after) && words[i + 3] === "to" && VERSIONISH.test(clean(raw[i + 4] ?? ""))) {
      add(nameFor(token, deps, fallback), clean(raw[i + 4]), true);
      continue;
    }
    // "pin name 1.2.3", "add name 4.17.20": a verb, the name, the version.
    if (i > 0 && VERBS.has(words[i - 1]) && VERSIONISH.test(next)) {
      add(nameFor(token, deps, fallback), next, true);
    }
  }
  return out.slice(0, MAX_REQUESTED);
}

/**
 * dependency_check's verdict for each named version, within the briefing's budget. Offline or past
 * the budget a version is `unknown`: never read as safe.
 */
export async function checkRequestedVersions(liveIntel: NameCheckLive | null, requested: RequestedVersion[], now?: Date): Promise<RequestedVersionFinding[]> {
  if (requested.length === 0) return [];
  const unknown = ({ alternatives: _a, ...r }: RequestedVersion, why: string): RequestedVersionFinding => ({
    ...r,
    verdict: "unknown",
    resolved: null,
    reason: `${r.name} ${r.to} could not be checked (${why}). Call dependency_check on it before writing it.`,
    malicious: false,
  });
  if (!liveIntel || !liveIntel.isEnabled()) return requested.map((r) => unknown(r, "live lookups are disabled"));
  if (!liveIntel.getReleaseSources || !liveIntel.getFixPathSources || !liveIntel.queryAdvisories) {
    return requested.map((r) => unknown(r, "the registry lookups are not available in this session"));
  }
  const deadline = Date.now() + CHECK_BUDGET_MS;
  /** One dependency_check run within what is left of the budget; null past it. */
  const run = async (list: RequestedVersion[]) => {
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      return await Promise.race([
        executeDependencyCheck(
          null,
          { items: list.map((r) => ({ ecosystem: r.ecosystem, package: r.name, to: r.to, ...(r.from ? { from: r.from } : {}) })) },
          liveIntel as LiveIntelligence,
          now ? { now } : {},
        ),
        new Promise<null>((resolve) => {
          timer = setTimeout(() => resolve(null), Math.max(0, deadline - Date.now()));
        }),
      ]);
    } finally {
      if (timer) clearTimeout(timer);
    }
  };
  type Answer = NonNullable<Awaited<ReturnType<typeof run>>>;
  const finding = (r: RequestedVersion, item: Answer["results"][number] | undefined): RequestedVersionFinding => {
    const { alternatives: _alternatives, ...own } = r;
    if (!item) return unknown(own, "no answer");
    const advisories = item.signals.find((s) => s.id === "advisories")?.value as { malicious_package?: unknown; critical_affecting_to?: string[] } | null | undefined;
    const rc = item.range_check;
    return {
      ...own,
      verdict: item.verdict,
      resolved: item.to,
      reason: item.reason,
      ...(rc ? { safe: { smallest: rc.smallest_safe_upgrade ?? rc.smallest_safe_in_range, newest: rc.newest_safe_in_range } } : {}),
      malicious: Boolean(advisories?.malicious_package),
      ...(advisories?.critical_affecting_to?.length ? { critical: advisories.critical_affecting_to } : {}),
    };
  };
  const unpublished = (item: Answer["results"][number] | undefined) => Boolean(item && item.verdict === "unknown" && /is not a published version on|a hallucinated package/.test(item.reason));
  try {
    const answer = await run(requested);
    if (!answer) return requested.map((r) => unknown(r, "the lookups did not finish in time"));
    const out = requested.map((r, i) => finding(r, answer.results[i]));
    // A guessed ecosystem with no such release: the project's other ecosystems, in one more run.
    const retries = requested.flatMap((r, i) => (unpublished(answer.results[i]) ? (r.alternatives ?? []).map((ecosystem) => ({ i, r: { ...r, ecosystem, alternatives: undefined } })) : []));
    if (retries.length > 0) {
      const again = await run(retries.map((x) => x.r)).catch(() => null);
      if (again) {
        for (const i of new Set(retries.map((x) => x.i))) {
          const hit = retries.findIndex((x, k) => x.i === i && again.results[k] && !unpublished(again.results[k]));
          if (hit >= 0) out[i] = finding(retries[hit].r, again.results[hit]);
        }
      }
    }
    return out;
  } catch (error) {
    // dependency_check refuses a malformed item (a version it cannot read): unknown, said.
    return requested.map((r) => unknown(r, `the check failed: ${String(error instanceof Error ? error.message : error).slice(0, 120)}`));
  }
}

/** How a finding reads in the delegation reason. */
export function sayRequested(r: RequestedVersionFinding): string {
  const safe = r.safe && (r.safe.smallest || r.safe.newest) ? `; safe: ${[r.safe.smallest, r.safe.newest].filter(Boolean).join(" to ")}` : "";
  return `${r.name} ${r.to} is ${r.verdict} by dependency_check${safe}`;
}
