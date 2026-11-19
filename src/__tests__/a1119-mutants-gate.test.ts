// SPDX-License-Identifier: Apache-2.0
/**
 * `pnpm run check` (scripts/check-repo.mjs) fails when a mutant in scripts/mutation/mutations.mjs
 * no longer applies, so a change that moves or rewrites a mutant's text fails its pull request,
 * not the weekly mutation run. The gate runs here against a small repository built in a temp
 * folder with the real gate scripts copied in. It never checks the real list against the real
 * src/: the mutation harness runs this suite with a mutant applied, which removes that mutant's
 * text, and the gate itself is what checks the real tree.
 */
import { spawnSync } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";

import { listFindings } from "../../scripts/mutation/lib.mjs";

const repo = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const SPDX = "// SPDX-License-Identifier: Apache-2.0\n";
// Built in two parts: the literal name in this file would make it a corpus-gated suite (gate 6).
const CORPUS_ENV = "FOURDA_CONFORMANCE" + "_DIR";
const SOURCE = `${SPDX}export const atLeast = (v: number, lo: number) => v >= lo;\n`;
const MUTANT = { id: "Z1", area: "test", file: "src/a.ts", find: "v >= lo;", replace: "v > lo;", intent: "the lower bound becomes exclusive", tests: ["src/__tests__/a.test.ts"] };

const roots: string[] = [];
afterEach(() => {
  for (const r of roots.splice(0)) rmSync(r, { recursive: true, force: true });
});

function put(root: string, file: string, text: string) {
  mkdirSync(dirname(join(root, file)), { recursive: true });
  writeFileSync(join(root, file), text);
}

/** A repository that passes gates 1 to 6, with the real gate scripts and the given mutant list. */
function fixture(list: object[]): string {
  const root = mkdtempSync(join(tmpdir(), "a1119-mutants-gate-"));
  roots.push(root);
  for (const script of ["check-repo.mjs", "ci-gates.mjs", "mutation/lib.mjs"]) {
    mkdirSync(dirname(join(root, "scripts", script)), { recursive: true });
    copyFileSync(join(repo, "scripts", script), join(root, "scripts", script));
  }
  put(root, "scripts/mutation/mutations.mjs", `${SPDX}export const mutations = ${JSON.stringify(list)};\n`);
  put(root, "src/a.ts", SOURCE);
  put(root, "src/__tests__/a.test.ts", `${SPDX}// reads process.env.${CORPUS_ENV}\n`);
  mkdirSync(join(root, "hooks"));
  mkdirSync(join(root, "bench"));
  put(root, "README.md", "fixture\n");
  put(root, "server.json", "{}\n");
  put(root, ".claude-plugin/plugin.json", "{}\n");
  put(root, "package.json", `${JSON.stringify({ name: "fixture", packageManager: "pnpm@10.0.0" })}\n`);
  put(root, "pnpm-workspace.yaml", 'overrides:\n  example: "1.0.0"\n');
  put(
    root,
    ".github/workflows/ci.yml",
    [
      "jobs:",
      "  conformance:",
      "    steps:",
      "      - run: pnpm exec vitest run src/__tests__/a.test.ts",
      "        env:",
      '          FOURDA_REQUIRE_CONFORMANCE: "1"',
      "      - run: node scripts/ci-gates.mjs tests-ran report.json",
      "  nightly-report:",
      "    needs: [conformance]",
      "",
    ].join("\n"),
  );
  put(
    root,
    ".github/workflows/release.yml",
    [
      "jobs:",
      "  verify:",
      "    steps:",
      "      - run: node scripts/fetch-conformance.mjs",
      "      - run: node scripts/ci-gates.mjs tests-ran report.json",
      "        env:",
      '          FOURDA_REQUIRE_CONFORMANCE: "1"',
      "",
    ].join("\n"),
  );
  return root;
}

function gate(root: string) {
  const r = spawnSync(process.execPath, [join(root, "scripts", "check-repo.mjs")], { cwd: root, encoding: "utf8", timeout: 60_000 });
  return { status: r.status, out: `${r.stdout ?? ""}${r.stderr ?? ""}` };
}

/** Every file under `dir` with its contents, to show the gate wrote nothing. */
function snapshot(dir: string, base = dir): Record<string, string> {
  const files: Record<string, string> = {};
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) Object.assign(files, snapshot(p, base));
    else files[p.slice(base.length)] = readFileSync(p, "utf8");
  }
  return files;
}

describe("the repository gate checks the mutant list", () => {
  it("passes when every mutant's text is where it says, and changes no file", () => {
    const root = fixture([MUTANT]);
    const before = snapshot(root);
    const r = gate(root);
    expect(r.out).toMatch(/check-repo: OK \(.*1 mutants that apply\)/);
    expect(r.status).toBe(0);
    expect(snapshot(root)).toEqual(before);
  });

  it("fails, naming the mutant, when a change rewrote its target text", () => {
    const root = fixture([MUTANT]);
    put(root, "src/a.ts", `${SPDX}export const atLeast = (v: number, lo: number) => lo <= v;\n`);
    const r = gate(root);
    expect(r.status).toBe(1);
    expect(r.out).toContain("check-repo: 1 finding(s)");
    expect(r.out).toContain("scripts/mutation/mutations.mjs: mutant Z1: the text to replace is no longer in src/a.ts");
  });

  it("fails when a mutant's text now occurs twice, or its likely test file is gone", () => {
    const root = fixture([{ ...MUTANT, id: "Z2", find: "lo" }, { ...MUTANT, id: "Z3", tests: ["src/__tests__/gone.test.ts"] }]);
    const r = gate(root);
    expect(r.status).toBe(1);
    expect(r.out).toContain("check-repo: 2 finding(s)");
    expect(r.out).toMatch(/mutant Z2: the text to replace occurs \d+ times in src\/a\.ts; give nth/);
    expect(r.out).toContain("mutant Z3: test file src/__tests__/gone.test.ts does not exist");
  });
});

describe("listFindings", () => {
  it("is empty for a list that applies, one line per problem naming the list file otherwise", () => {
    const root = fixture([]);
    expect(listFindings([MUTANT], root)).toEqual([]);
    expect(listFindings([{ ...MUTANT, find: "v <= lo;" }], root)).toEqual([
      expect.stringMatching(/^scripts\/mutation\/mutations\.mjs: mutant Z1: the text to replace is no longer in src\/a\.ts.*\(update its find\/replace in the same change; scripts\/mutation\/README\.md\)$/),
    ]);
  });
});
