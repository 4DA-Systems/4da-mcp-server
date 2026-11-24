// SPDX-License-Identifier: Apache-2.0
/**
 * Three items from the review of the 6.5.1 candidate (2026-11-24):
 * - the better-sqlite3 remedy printed `npx --allow-scripts=better-sqlite3 @4da/mcp-server`,
 *   unpinned: npx starts whatever it cached first or the newest release, not the server that is
 *   answering. It is pinned as every other printed command is (usage.ts pinnedNpx);
 * - `--help`'s `--version` row left one space before its description where the others leave two;
 * - a release that installs, two levels down, several affected pins through the same dependency
 *   repeated "X 1.4.2 (its exact pin), which exact-pins" once per pin; the pins are now listed
 *   under one via clause.
 */

import { describe, expect, it } from "vitest";

import type { HeldDependency } from "../live/held-dependencies.js";
import { heldText } from "../live/held-dependencies.js";
import { NATIVE_BINDING_FIX, nativeBindingMessage } from "../native-bindings.js";
import { RUNNING_VERSION, serverUsage } from "../usage.js";

/** An npx line that names this package with no version after it. */
const UNPINNED = /npx\s+(?:-\S+\s+)*@4da\/mcp-server(?!@)/;

describe("the better-sqlite3 remedy names the pinned server", () => {
  it("no unpinned npx line, and the pinned one with --allow-scripts", () => {
    expect(NATIVE_BINDING_FIX).not.toMatch(UNPINNED);
    expect(NATIVE_BINDING_FIX).toContain(`npx -y --prefer-offline --allow-scripts=better-sqlite3 @4da/mcp-server@${RUNNING_VERSION ?? "<version>"}`);
    expect(nativeBindingMessage(new Error("Could not locate the bindings file"))).not.toMatch(UNPINNED);
  });
});

describe("--help's usage rows", () => {
  it("every description starts in one column with at least two spaces before it", () => {
    const rows = serverUsage("6.5.1")
      .split("\n")
      .filter((l) => l.includes("npx -y --prefer-offline @4da/mcp-server@6.5.1"));
    expect(rows).toHaveLength(5);
    const columns = rows.map((r) => /\S\s{2,}(?=[A-Z])/.exec(r)?.index);
    expect(columns.every((c) => c !== undefined)).toBe(true);
    const starts = rows.map((r) => r.search(/(?<=\s)[A-Z][a-z]/));
    expect(new Set(starts).size).toBe(1);
  });
});

describe("two levels down, pins through one dependency share one via clause", () => {
  const via = { name: "@hey-api/json-schema-ref-parser", spec: "1.4.2", exact: true, version: "1.4.2" };
  const pin = (name: string, version: string, id: string): HeldDependency => ({ name, spec: version, exact: true, version, ids: [id], severity: "high", via });

  it("names the via dependency once", () => {
    const text = heldText("0.97.3", [pin("js-yaml", "4.1.1", "GHSA-a"), pin("lodash", "4.17.20", "GHSA-b")]);
    expect(text.match(/@hey-api\/json-schema-ref-parser 1\.4\.2 \(its exact pin\)/g)).toHaveLength(1);
    expect(text).toContain("0.97.3 installs, two levels down, @hey-api/json-schema-ref-parser 1.4.2 (its exact pin), which exact-pins js-yaml 4.1.1 (GHSA-a) and lodash 4.17.20 (GHSA-b)");
  });

  it("one pin reads as before", () => {
    expect(heldText("0.97.3", [pin("js-yaml", "4.1.1", "GHSA-a")])).toBe(
      "0.97.3 installs, two levels down, @hey-api/json-schema-ref-parser 1.4.2 (its exact pin), which exact-pins js-yaml 4.1.1 (GHSA-a)",
    );
  });
});
