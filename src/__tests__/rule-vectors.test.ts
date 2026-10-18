// SPDX-License-Identifier: Apache-2.0
/**
 * Shared rule vectors: which fix this server recommends and why (version
 * order, OSV range evaluation, the fix target, the refresh-or-parent verdict,
 * the refresh command, dependency_check's range_check), held to the same
 * vector files as the 4DA desktop app's Rust engine. The files live beside the
 * conformance corpus (`<corpus>/vectors/`, spec in its README.md) and arrive
 * with it: `node scripts/fetch-conformance.mjs`. helpers/rule-vectors.ts maps
 * each file to the function that implements the rule here.
 *
 * conformance/vectors-skip.json lists the vector ids this engine does not
 * satisfy yet, each with a reason (4DA's engines_skip.json is read-only here;
 * its `ts` section stays empty). The gate is shrink-only, as in the Rust
 * runner:
 * - a vector that fails and is not skipped fails;
 * - a skipped vector that now passes fails (remove the entry);
 * - the list may not grow past TS_SKIP_BASELINE, and when it shrinks the
 *   baseline must come down with it;
 * - a skip entry that names no vector, or has no reason, fails.
 *
 * Without the corpus this suite skips with the fetch command, except where
 * FOURDA_REQUIRE_CONFORMANCE=1 (the CI conformance jobs), where it fails.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { describe, expect, it } from "vitest";
import { VECTOR_FILES, Records, checkVector, loadVectors, type Vector, type VectorFile } from "./helpers/rule-vectors.js";

/** The committed size of the skip list. Shrink-only: lower it in the change that removes entries; it may never rise. */
const TS_SKIP_BASELINE = 0;

const repoRoot = path.resolve(import.meta.dirname, "..", "..");
const lock = JSON.parse(fs.readFileSync(path.join(repoRoot, "conformance.lock"), "utf8")) as { repo: string; commit: string };
const corpus = path.resolve(process.env.FOURDA_CONFORMANCE_DIR ?? path.join(repoRoot, "conformance", "corpus"));
const vectorsDir = path.join(corpus, "vectors");
const present = VECTOR_FILES.every((f) => fs.existsSync(path.join(vectorsDir, `${f}.jsonl`)));
const required = process.env.FOURDA_REQUIRE_CONFORMANCE === "1";
const MISSING = `rule vectors not found at ${vectorsDir}: run \`node scripts/fetch-conformance.mjs\` (pinned ${lock.repo}@${lock.commit.slice(0, 12)})`;

if (!present && !required) {
  const bar = "!".repeat(78);
  console.warn(
    [
      "",
      bar,
      `WARNING [rule-vectors]: the shared fix-path rule vectors DID NOT RUN (skipped, not passed).`,
      `  ${MISSING}`,
      "  On Windows the fetch needs long paths; the script passes core.longpaths=true.",
      "  Set FOURDA_REQUIRE_CONFORMANCE=1 to make a missing corpus fail instead.",
      bar,
      "",
    ].join("\n"),
  );
}

const skipDoc = JSON.parse(fs.readFileSync(path.join(repoRoot, "conformance", "vectors-skip.json"), "utf8")) as { schema: number; skip: Record<string, string> };
const skips = new Map(Object.entries(skipDoc.skip));
const records = new Records(path.join(corpus, "osv"));
const vectors = new Map<VectorFile, Vector[]>(VECTOR_FILES.map((f) => [f, present ? loadVectors(vectorsDir, f) : []]));
const tally = new Map<VectorFile, { pass: number; skipped: number; fail: number }>(VECTOR_FILES.map((f) => [f, { pass: 0, skipped: 0, fail: 0 }]));

describe.skipIf(!present && !required)("shared rule vectors (4DA)", () => {
  it("the vector files are present, well-formed, with unique ids", () => {
    if (!present) throw new Error(MISSING);
    const seen = new Set<string>();
    for (const [file, list] of vectors) {
      expect(list.length, `${file}.jsonl is empty`).toBeGreaterThan(0);
      for (const v of list) {
        expect(v.id, `${file}.jsonl has a line without an id`).toBeTruthy();
        expect(seen.has(v.id), `duplicate vector id ${v.id}`).toBe(false);
        seen.add(v.id);
        expect(v.rule && v.source, `${v.id} needs a rule and a source`).toBeTruthy();
      }
    }
  });

  describe.each(VECTOR_FILES.map((f) => [f] as const))("%s", (file) => {
    const list = vectors.get(file)!;
    it.each(list.map((v) => [v.id, v] as const))("%s", async (id, v) => {
      const why = await checkVector(file, v, records);
      const t = tally.get(file)!;
      if (skips.has(id)) {
        if (why !== null) t.skipped++;
        expect(why, `${id} now PASSES: remove it from conformance/vectors-skip.json and lower TS_SKIP_BASELINE`).not.toBeNull();
        return;
      }
      if (why === null) t.pass++;
      else t.fail++;
      expect(why, `${id} (${file}): ${why} [${v.rule}]`).toBeNull();
    });
  });

  it("the skip list names real vectors, gives reasons, and only shrinks", () => {
    if (!present) throw new Error(MISSING);
    expect(skipDoc.schema).toBe(1);
    const ids = new Set([...vectors.values()].flat().map((v) => v.id));
    const problems: string[] = [];
    for (const [id, reason] of skips) {
      if (!ids.has(id)) problems.push(`skip entry ${id} names no vector`);
      if (typeof reason !== "string" || reason.trim() === "") problems.push(`skip entry ${id} has no reason`);
    }
    if (skips.size > TS_SKIP_BASELINE) problems.push(`the skip list grew to ${skips.size} (baseline ${TS_SKIP_BASELINE}): it is shrink-only`);
    else if (skips.size < TS_SKIP_BASELINE) problems.push(`the skip list shrank to ${skips.size}: lower TS_SKIP_BASELINE to match`);
    console.log(
      `rule vectors (ts):\n  ${VECTOR_FILES.map((f) => {
        const t = tally.get(f)!;
        return `${f}: ${vectors.get(f)!.length} vectors, ${t.pass} pass, ${t.skipped} skipped, ${t.fail} fail`;
      }).join("\n  ")}`,
    );
    expect(problems).toEqual([]);
  });
});
