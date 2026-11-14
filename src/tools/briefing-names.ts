// SPDX-License-Identifier: Apache-2.0
/**
 * What a word in a task can and cannot be, as a package name (blind audit round 4): shared by the
 * briefing's readers of named versions (briefing-requested-versions.ts) and new packages
 * (briefing-new-packages.ts).
 */

import type { ResolvedDependency } from "../live/types.js";

/**
 * Manifest and lockfile names: where a version is written, never the package it is for ("lodash in
 * package.json to 4.17.20" was judged as a package named `package.json`).
 */
const MANIFEST_FILE =
  /^(?:package(?:-lock)?\.json|npm-shrinkwrap\.json|pnpm-(?:lock|workspace)\.yaml|yarn\.lock|bun\.lockb?|cargo\.(?:toml|lock)|requirements(?:[-_.][\w.-]+)?\.(?:txt|in)|constraints\.txt|pyproject\.toml|poetry\.lock|uv\.lock|pipfile(?:\.lock)?|setup\.(?:py|cfg)|go\.(?:mod|sum|work)|gemfile(?:\.lock)?|composer\.(?:json|lock))$/i;

/** A manifest or lockfile name, bare or with a directory ("web/package.json"), quotes and trailing punctuation aside. */
export function isManifestFile(token: string): boolean {
  const bare = token.replace(/^[`'"(]+/, "").replace(/[`'"),.;:!?]+$/, "");
  return MANIFEST_FILE.test(bare.split(/[\\/]/).pop() ?? "");
}

/**
 * The installed Go module a short name stands for: "gin" is github.com/gin-gonic/gin when go.mod
 * requires it ("Upgrade gin to v1.6.0" was judged as npm `gin`). The last path segment is matched,
 * a major-version suffix (`/v8`, gopkg.in's `.v3`) set aside. Two modules that end the same way are
 * not guessed between: null.
 */
export function installedGoModule(short: string, deps: readonly ResolvedDependency[]): string | null {
  const lower = short.toLowerCase();
  const hits = new Set<string>();
  for (const d of deps) {
    if (d.ecosystem !== "Go") continue;
    const segments = d.name.split("/").filter(Boolean);
    if (segments.length > 1 && /^v\d+$/.test(segments[segments.length - 1])) segments.pop();
    const last = (segments[segments.length - 1] ?? "").replace(/\.v\d+$/, "").toLowerCase();
    if (segments.length > 1 && last === lower) hits.add(d.name);
  }
  return hits.size === 1 ? [...hits][0] : null;
}
