// SPDX-License-Identifier: Apache-2.0
/**
 * The direct-upgrade command rules (readiness review 2026-10-17, finding 4): a direct row's
 * command keeps how the dependency is declared (an exact pin stays exact, `~` stays `~`), and
 * names nothing it cannot read with certainty. The rules are the 4DA app's
 * `osv/direct_upgrade.rs`; fixtures/direct-fix-vectors.jsonl is the `kind: "direct"` lines
 * fc-028..fc-053 of its shared fix_command.jsonl, copied from 4DA branch
 * fix/c2-direct-upgrade-commands at 46e4d3ef9 (PR #972), because conformance.lock pins a
 * corpus (635953cb) that predates them. Once the pin moves past #972, rule-vectors.test.ts runs
 * the same lines through the same check and this copy can go.
 */

import { describe, it, expect } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { Records, checkVector, type Vector } from "./helpers/rule-vectors.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const lines = fs
  .readFileSync(path.join(here, "fixtures", "direct-fix-vectors.jsonl"), "utf8")
  .split(/\r?\n/)
  .filter((l) => l.trim() !== "")
  .map((l) => JSON.parse(l) as Vector);

describe("direct-upgrade commands: 4DA rule vectors fc-028..fc-053", () => {
  it("holds every direct vector of the 4DA branch", () => {
    expect(lines.map((v) => v.id)).toEqual(Array.from({ length: 26 }, (_, i) => `fc-0${28 + i}`));
    expect(lines.every((v) => v.kind === "direct")).toBe(true);
  });

  it.each(lines.map((v) => [v.id, v] as const))("%s", (_id, v) => {
    expect(checkVector("fix_command", v, new Records(here))).toBeNull();
  });
});
