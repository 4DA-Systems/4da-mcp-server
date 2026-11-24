// SPDX-License-Identifier: Apache-2.0
/**
 * What a release holds two levels down: the exact pins of the releases it holds.
 *
 * held-dependencies.ts judges what an npm release installs one level down. That is not the whole
 * of a fix target: @hey-api/openapi-ts 0.97.3 (the release that clears its own advisory) exact-pins
 * @hey-api/json-schema-ref-parser 1.4.2, which exact-pins js-yaml 4.1.1 (four advisories), while the
 * installed 0.96.0 holds no js-yaml at all. A plan named 0.97.3 "the smallest safe release",
 * checked against every advisory, and the copy it installs is one no lockfile refresh can move
 * (audit 2026-11-23, track B finding 5).
 *
 * Here each dependency a release holds is resolved as held-dependencies.ts resolves it (the pin, or
 * the newest release the range admits), and that release's own EXACT pins are the second level: an
 * exact pin installs as written whatever the lockfile holds. A range two levels down is not judged:
 * a refresh resolves it, and judging it would mean reading every package two levels down.
 * Bounded by the caller's deadline: the dependencies' registry facts are read FACTS_CONCURRENCY at a
 * time through the shared, cached reader; a release whose dependencies' facts could not be read in
 * time is named, so the caller fails closed (never calls it clean).
 */

import { byDeadline, exactPinVersion, type HeldFacts, type HeldSources } from "./held-dependencies.js";

/** A dependency a release holds (one level down), resolved: `version` null when it could not be. */
export interface FirstLevel {
  name: string;
  spec: string;
  exact: boolean;
  version: string | null;
}

/** An exact pin two levels down, with the dependency of the release that holds it. */
export interface SecondLevelPin {
  name: string;
  spec: string;
  version: string;
  via: { name: string; spec: string; exact: boolean; version: string };
}

/** Registry reads in flight at once for the dependencies' facts. */
const FACTS_CONCURRENCY = 8;

/**
 * Reads the registry facts of every first-level dependency not read yet (into `facts`), within
 * `deadline`, FACTS_CONCURRENCY at a time.
 */
export async function readFirstLevelFacts(sources: HeldSources, names: Iterable<string>, facts: Map<string, HeldFacts | null>, deadline: number): Promise<void> {
  const todo = [...new Set(names)].filter((n) => !facts.has(n));
  let next = 0;
  await Promise.all(
    Array.from({ length: Math.min(FACTS_CONCURRENCY, todo.length) }, async () => {
      while (next < todo.length && Date.now() < deadline) {
        const name = todo[next++];
        facts.set(name, await byDeadline(sources.releaseFacts("npm", name), deadline, null));
      }
    }),
  );
}

/**
 * For one release's resolved first-level dependencies: the exact pins their releases hold, and the
 * dependencies whose facts could not be read (what they pin is not known).
 */
export function secondLevelPins(deps: readonly FirstLevel[], facts: ReadonlyMap<string, HeldFacts | null>): { pins: SecondLevelPin[]; unread: string[] } {
  const pins: SecondLevelPin[] = [];
  const unread: string[] = [];
  const seen = new Set<string>();
  for (const d of deps) {
    if (!d.version) continue; // the first level already says this one could not be resolved
    const f = facts.get(d.name);
    if (!f) {
      unread.push(`${d.name} ${d.version}`);
      continue;
    }
    for (const [name, spec] of Object.entries(f.heldSpecs?.[d.version] ?? {})) {
      const version = exactPinVersion(spec);
      if (version === null) continue;
      const key = `${name}@${version}`;
      if (seen.has(key)) continue;
      seen.add(key);
      pins.push({ name, spec, version, via: { name: d.name, spec: d.spec, exact: d.exact, version: d.version } });
    }
  }
  return { pins, unread };
}

/** "what the releases a, b and 2 more pin could not be read from the npm registry ...". */
export function secondLevelUnreadText(unread: readonly string[]): string {
  const shown = unread.slice(0, 3).join(", ");
  const more = unread.length > 3 ? ` and ${unread.length - 3} more` : "";
  return `what ${shown}${more} exact-pin${unread.length === 1 ? "s" : ""} could not be read from the npm registry, so the copies two levels down were not checked`;
}
