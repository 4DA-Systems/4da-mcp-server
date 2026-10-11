// SPDX-License-Identifier: Apache-2.0
/**
 * Dependency-engine conformance: this server's lockfile discovery, readers and
 * advisory matching, scored against the 4DA corpus at the commit
 * conformance.lock pins (helpers/conformance.ts says how; conformance/README.md
 * says how to run it).
 *
 * The corpus is fetched, never vendored: `node scripts/fetch-conformance.mjs`.
 * Without it this suite skips with that instruction, except where
 * FOURDA_REQUIRE_CONFORMANCE=1 (the CI conformance jobs), where a missing
 * corpus fails.
 *
 *   FOURDA_CONFORMANCE_DIR=<dir>      read the corpus from elsewhere
 *   FOURDA_CONFORMANCE_UNPINNED=1     accept a corpus at another commit (the nightly 4DA-main job)
 *   FOURDA_CONFORMANCE_DUMP=<dir>     write each case's engine output and the full diff
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { describe, expect, it } from "vitest";
import { PinnedRecordsSource } from "../live/pinned-advisories.js";
import type { OsvVulnerability } from "../live/types.js";
import {
  canonicalIds,
  checkDisagreements,
  checkRatchet,
  loadCases,
  reportTable,
  runEngine,
  score,
  type DisagreementReport,
  type Thresholds,
} from "./helpers/conformance.js";

const repoRoot = path.resolve(import.meta.dirname, "..", "..");
const lock = JSON.parse(fs.readFileSync(path.join(repoRoot, "conformance.lock"), "utf8")) as { repo: string; commit: string; path: string };
const corpus = path.resolve(process.env.FOURDA_CONFORMANCE_DIR ?? path.join(repoRoot, "conformance", "corpus"));
const present = fs.existsSync(path.join(corpus, "cases")) && fs.existsSync(path.join(corpus, "osv"));
const required = process.env.FOURDA_REQUIRE_CONFORMANCE === "1";
const MISSING = `conformance corpus not found at ${corpus}: run \`node scripts/fetch-conformance.mjs\` (pinned ${lock.repo}@${lock.commit.slice(0, 12)})`;

if (!present && !required) console.warn(`[conformance] skipped: ${MISSING}`);

describe.skipIf(!present && !required)("dependency-engine conformance (4DA corpus)", () => {
  it("the corpus is present, and at the pinned commit", () => {
    if (!present) throw new Error(MISSING);
    const stamp = path.join(corpus, ".source.json");
    const source = fs.existsSync(stamp) ? (JSON.parse(fs.readFileSync(stamp, "utf8")) as { commit: string }) : null;
    if (process.env.FOURDA_CONFORMANCE_UNPINNED !== "1") {
      expect(source?.commit, `corpus is not the one conformance.lock pins; re-run scripts/fetch-conformance.mjs`).toBe(lock.commit);
    }
    expect(loadCases(corpus).length).toBeGreaterThanOrEqual(30);
  });

  it("meets the conformance ratchet, and every disagreement is adjudicated", async () => {
    if (!present) throw new Error(MISSING);
    const started = Date.now();
    const cases = loadCases(corpus);
    const osvDir = path.join(corpus, "osv");
    const records = fs
      .readdirSync(osvDir)
      .filter((f) => f.endsWith(".json"))
      .sort()
      .map((f) => JSON.parse(fs.readFileSync(path.join(osvDir, f), "utf8")) as OsvVulnerability);
    const canon = canonicalIds(records);
    const run = await runEngine(cases, new PinnedRecordsSource(records), canon);
    const s = score(cases, run, canon);

    const thresholds = JSON.parse(fs.readFileSync(path.join(repoRoot, "conformance", "thresholds.json"), "utf8")) as Thresholds;
    const report = JSON.parse(fs.readFileSync(path.join(repoRoot, "conformance", "engine-disagreements.json"), "utf8")) as DisagreementReport;
    const unsupported = thresholds.unsupported_by_engine;

    const out: string[] = [
      `\n=== Dependency-engine conformance (TypeScript MCP engine) — ${cases.length} cases, ${records.length} pinned records ===`,
      reportTable(s, unsupported),
    ];
    for (const [eco, drops] of [...s.silentDrops].sort()) {
      out.push(`silent drops, ${eco}${unsupported[eco] ? " (unsupported-by-engine)" : ""}: ${drops.join(", ")}`);
    }
    for (const [eco, reason] of Object.entries(unsupported)) out.push(`unsupported-by-engine: ${eco} — ${reason}`);
    const ratchet = checkRatchet(s, thresholds);
    const adjudication = checkDisagreements(s, report, unsupported);
    for (const note of ratchet.canRise) out.push(`ratchet can rise: ${note}`);
    for (const d of adjudication.resolved) out.push(`adjudicated disagreement no longer occurs (remove it): ${d}`);
    const shown = adjudication.unexplained.slice(0, 80);
    if (shown.length) out.push(`unadjudicated disagreements (${adjudication.unexplained.length}, first ${shown.length}):`, ...shown.map((d) => `  ${d}`));
    out.push(`conformance run: ${((Date.now() - started) / 1000).toFixed(1)}s`);
    console.log(out.join("\n"));

    const dump = process.env.FOURDA_CONFORMANCE_DUMP;
    if (dump) {
      fs.mkdirSync(dump, { recursive: true });
      for (const c of cases) {
        fs.writeFileSync(
          path.join(dump, `${c.id}.json`),
          JSON.stringify({ inventory: [...(run.inventory.get(c.id) ?? [])].sort(), findings: run.raw.get(c.id) ?? [] }),
        );
      }
      fs.writeFileSync(path.join(dump, "diff.tsv"), s.diffs.join("\n"));
    }

    expect(ratchet.failures, "conformance ratchet regressed").toEqual([]);
    expect(adjudication.unexplained, "engine disagreements not adjudicated in conformance/engine-disagreements.json").toEqual([]);
  }, 300_000);
});
