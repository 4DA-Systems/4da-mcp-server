// SPDX-License-Identifier: Apache-2.0
/**
 * readPnpmLock checked each entry against the transitive list with `.some()`
 * inside a loop over every entry: O(n²). A 200k-entry pnpm-lock.yaml held the
 * single-threaded stdio server for 409 s, so every tool call on a large (or
 * hostile) pnpm project froze it (audit 6.2.5 C-8; 20k entries took 8 s).
 */
import { describe, expect, it } from "vitest";
import { readPnpmLock } from "../live/js-lockfile-readers.js";

function lockOf(n: number): string {
  const lines = ["lockfileVersion: '9.0'", "", "importers:", "  .:", "    dependencies:", "      pkg0:", "        specifier: ^1.0.0", "        version: 1.0.0", "", "packages:"];
  for (let i = 0; i < n; i++) lines.push(`  pkg${i}@1.0.${i % 50}:`, "    resolution: {integrity: sha512-AAAA}");
  lines.push("", "snapshots:");
  for (let i = 0; i < n; i++) lines.push(`  pkg${i}@1.0.${i % 50}: {}`);
  return lines.join("\n") + "\n";
}

describe("readPnpmLock scale", () => {
  it("reads 30,000 entries in well under the old quadratic time", () => {
    const text = lockOf(30_000);
    const versions = new Map<string, string>();
    let added = 0;
    const started = Date.now();
    readPnpmLock(text, versions, { add: () => added++ } as never, new Map());
    const ms = Date.now() - started;
    expect(versions.size).toBe(30_000);
    expect(added).toBeGreaterThanOrEqual(30_000);
    // Linear: ~0.1 s here. The O(n²) loop took ~15 s at this size.
    expect(ms).toBeLessThan(5_000);
  });
});
