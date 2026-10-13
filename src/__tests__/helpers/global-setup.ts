// SPDX-License-Identifier: Apache-2.0
/**
 * Vitest global setup: runs once in the main process, where its output is
 * always shown. A test file's console.warn at import time is swallowed by the
 * default reporter, so a missing conformance corpus used to skip the
 * strongest engine tests with no visible trace ("4 skipped") on every
 * contributor machine that had not fetched it (audit B-19, 2026-10-12;
 * on Windows the fetch itself failed without long paths).
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

export default function setup(): void {
  const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
  const corpus = path.resolve(process.env.FOURDA_CONFORMANCE_DIR ?? path.join(repoRoot, "conformance", "corpus"));
  if (fs.existsSync(path.join(corpus, "cases")) || process.env.FOURDA_REQUIRE_CONFORMANCE === "1") return;
  const bar = "!".repeat(78);
  process.stderr.write(
    [
      "",
      bar,
      "WARNING: the conformance corpus is missing, so the dependency-engine conformance and",
      "shared rule-vector suites (the strongest engine tests) are SKIPPED, not passed.",
      `  expected at ${corpus}`,
      "  fetch it:   node scripts/fetch-conformance.mjs",
      "  make a missing corpus fail instead:   FOURDA_REQUIRE_CONFORMANCE=1",
      bar,
      "",
      "",
    ].join("\n"),
  );
}
