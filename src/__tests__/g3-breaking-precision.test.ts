// SPDX-License-Identifier: Apache-2.0
/**
 * Gate G3: precision of the entries `upgrade_impact` flags breaking, measured
 * on a held-out panel of real upgrades across npm, crates.io, PyPI and Go.
 *
 * The panel (fixtures/g3/, recorded 2026-10-11):
 * - panel.json: 40 upgrade pairs, 10 per ecosystem, chosen to cross a major
 *   (or a 0.x minor) or a release with documented removals, and none of them a
 *   package the 6.1 classifier rules were built on. Each pair records the
 *   changelog source the tool itself read live: the registry archive's file
 *   (npm tarball, .crate, sdist, Go module zip) or GitHub releases (the opt-in
 *   fallback), trimmed to the releases the range needs. Trimming was checked:
 *   the trimmed source parses to exactly the same in-range sections.
 * - labels.json: one gold label per entry the tool shows for the range
 *   (detailed mode, de-duplicated as in the tool). Gold is the majority of
 *   three blind raters who saw each entry's text, heading and nested details,
 *   never the classifier's kind, and labelled to rubric.txt; every rater label
 *   carries a verbatim evidence quote from the entry, checked mechanically.
 * - split: pairs alternate dev / test within each ecosystem, fixed before any
 *   label was compared with the classifier. Rule changes after the first
 *   measurement were made looking at dev-pair errors only; the test pairs are
 *   the held-out number.
 *
 * Precision = gold-breaking among flagged; recall = flagged among
 * gold-breaking, over the entries the parser extracts (an entry the parser
 * never produces is not counted here).
 *
 * An entry without a gold label fails the test: a parser change that alters
 * the entries must come with new labels, or the gate would quietly measure a
 * different set.
 */

import { describe, it, expect } from "vitest";
import { createHash } from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import { parseChangelog, selectRange } from "../live/changelog.js";
import { releasesToSections } from "../live/github-releases.js";
import { versionOrder, type UpgradeEcosystem } from "../live/upgrade-sources.js";
import { shapeChangelog } from "../tools/upgrade-impact-report.js";

const DIR = path.join(__dirname, "fixtures", "g3");

interface PanelItem {
  id: string;
  ecosystem: UpgradeEcosystem;
  package: string;
  from: string;
  to: string;
  first_in_range: string;
  split: "dev" | "test";
  source: { type: "file" | "github-releases"; path: string; tag_prefix?: string };
}

interface GoldLabel {
  key: string;
  id: string;
  gold: "breaking" | "not_breaking";
  votes: string[];
  evidence: string[];
}

/** Identity of one shown entry: pair, release, and its text with whitespace collapsed. */
export function entryKey(pair: string, version: string, text: string): string {
  return createHash("sha1").update(`${pair}|${version}|${text.replace(/\s+/g, " ").trim()}`).digest("hex").slice(0, 16);
}

interface Counts {
  tp: number;
  fp: number;
  fn: number;
  tn: number;
}
const empty = (): Counts => ({ tp: 0, fp: 0, fn: 0, tn: 0 });

/** Wilson score interval, 95%. */
function wilson(k: number, n: number): [number, number] {
  if (n === 0) return [0, 1];
  const z = 1.96;
  const p = k / n;
  const d = 1 + (z * z) / n;
  const c = (p + (z * z) / (2 * n)) / d;
  const h = (z * Math.sqrt((p * (1 - p)) / n + (z * z) / (4 * n * n))) / d;
  return [Math.max(0, c - h), Math.min(1, c + h)];
}

const pct = (x: number) => `${(100 * x).toFixed(1)}%`;

export function measureG3() {
  const panel = JSON.parse(fs.readFileSync(path.join(DIR, "panel.json"), "utf8")) as PanelItem[];
  const labels = new Map(
    (JSON.parse(fs.readFileSync(path.join(DIR, "labels.json"), "utf8")) as GoldLabel[]).map((l) => [l.key, l]),
  );
  const by: Record<string, Counts> = {};
  const add = (bucket: string, flagged: boolean, gold: boolean) => {
    const c = (by[bucket] ??= empty());
    if (flagged && gold) c.tp++;
    else if (flagged) c.fp++;
    else if (gold) c.fn++;
    else c.tn++;
  };
  const unlabeled: string[] = [];
  const falsePositives: string[] = [];
  const pairsWithBreaking = new Set<string>();
  for (const item of panel) {
    const raw = fs.readFileSync(path.join(DIR, "sources", path.basename(item.source.path)), "utf8");
    const sections =
      item.source.type === "github-releases"
        ? releasesToSections(JSON.parse(raw), item.package, item.source.tag_prefix ?? null)
        : parseChangelog(raw);
    const range = selectRange(sections, item.from, item.to, item.first_in_range, versionOrder(item.ecosystem));
    const shaped = shapeChangelog(range.sections, [], "detailed");
    for (const s of shaped.sections) {
      for (const e of s.entries) {
        const label = labels.get(entryKey(item.id, s.version, e.text));
        if (!label) {
          unlabeled.push(`${item.id} ${s.version}: ${e.text.slice(0, 80)}`);
          continue;
        }
        const flagged = e.kind === "breaking";
        const gold = label.gold === "breaking";
        if (gold) pairsWithBreaking.add(item.id);
        if (flagged && !gold) falsePositives.push(`${item.id} [${e.under ?? ""}] ${e.text.slice(0, 100)}`);
        for (const bucket of ["all", item.split, item.ecosystem]) add(bucket, flagged, gold);
      }
    }
  }
  const stats = Object.fromEntries(
    Object.entries(by).map(([k, c]) => {
      const precision = c.tp / Math.max(1, c.tp + c.fp);
      const recall = c.tp / Math.max(1, c.tp + c.fn);
      return [k, { ...c, precision, recall, precisionCI: wilson(c.tp, c.tp + c.fp), recallCI: wilson(c.tp, c.tp + c.fn) }];
    }),
  );
  return { stats, unlabeled, falsePositives, pairs: panel.length, pairsWithBreaking: pairsWithBreaking.size };
}

describe("G3: breaking-entry precision on the held-out panel", () => {
  it("flags breaking entries with at least 90% precision, and reports recall", () => {
    const m = measureG3();
    const lines = Object.entries(m.stats).map(
      ([k, s]) =>
        `${k.padEnd(9)} flagged ${String(s.tp + s.fp).padStart(4)}  gold-breaking ${String(s.tp + s.fn).padStart(4)}  ` +
        `precision ${pct(s.precision)} (95% CI ${pct(s.precisionCI[0])}-${pct(s.precisionCI[1])})  ` +
        `recall ${pct(s.recall)} (95% CI ${pct(s.recallCI[0])}-${pct(s.recallCI[1])})`,
    );
    console.log(`G3 panel: ${m.pairs} pairs (${m.pairsWithBreaking} with gold-breaking entries)\n${lines.join("\n")}`);
    if (m.falsePositives.length) console.log(`false positives:\n  ${m.falsePositives.join("\n  ")}`);

    expect(m.unlabeled).toEqual([]);
    expect(m.pairs).toBeGreaterThanOrEqual(30);
    expect(m.stats.all.precision).toBeGreaterThanOrEqual(0.9);
    expect(m.stats.test.precision).toBeGreaterThanOrEqual(0.9);
  });
});
