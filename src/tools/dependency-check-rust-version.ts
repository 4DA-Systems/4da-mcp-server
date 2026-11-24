// SPDX-License-Identifier: Apache-2.0
/**
 * crates.io: a release that needs a newer Rust than the project's `rust-version` says so in
 * dependency_check's answer, as upgrade_planner's row does (`needsNewerRust`,
 * upgrade-planner-rust-version.ts). Claims review of the 6.5.1 candidate (2026-11-24): time 0.3.47
 * in a project declaring rust-version 1.64 was `proceed` with no mention, while the plan flagged it.
 * The verdict is not changed (the release has no advisory); the caveat is stated on the item.
 */

import type { FixPathSources } from "../live/fix-paths.js";
import { declaredRustVersion, rustNewer } from "./upgrade-planner-rust-version.js";
import type { ItemResult } from "./dependency-check-items.js";

/** Bound on one crates.io index read for this note. */
const READ_MS = 4_000;

/** `work`, or null when it fails or takes longer than READ_MS. */
async function within<T>(work: Promise<T>): Promise<T | null> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const late = new Promise<null>((resolve) => {
    timer = setTimeout(() => resolve(null), READ_MS);
    timer.unref?.();
  });
  try {
    return await Promise.race([work.catch(() => null), late]);
  } finally {
    clearTimeout(timer);
  }
}

export async function noteNewerRust(results: ItemResult[], projectRoot: string | null, sources: FixPathSources | null): Promise<void> {
  if (!projectRoot || !sources) return;
  const crates = results.filter((r) => r.ecosystem === "crates.io" && !r.not_checked && /^\d+\.\d+\.\d+/.test(r.to));
  if (crates.length === 0) return;
  const declared = declaredRustVersion(projectRoot);
  if (!declared) return;
  for (const r of crates) {
    let sparse = await within(sources.cratesSparse(r.package));
    // A record cached before rust-version was read carries none: read the index again.
    if (sparse && !sparse.rustVersions) sparse = await within(sources.cratesSparse(r.package, true));
    const needs = sparse?.rustVersions?.[r.to];
    if (!needs || rustNewer(needs, declared.version) !== true) continue;
    r.needs_newer_rust = { needs, declared: declared.version, manifest: declared.manifest };
    r.reason = `${r.reason.replace(/[.\s]+$/, "")}. Caveat: ${r.package} ${r.to} needs Rust ${needs} (its rust-version on crates.io), and this project declares rust-version ${declared.version}: installing it makes the build fail on Rust ${declared.version}; raise rust-version first, or pick a release that declares ${declared.version} or lower.`;
  }
}
