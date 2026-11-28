// SPDX-License-Identifier: Apache-2.0
/**
 * Round 16b (the docs lane's proof of round 16): 1. the word boundary is a property of each credential shape: a
 * distinctive prefix matches glued to what precedes it, an ordinary one (BOUNDARY_SHAPES) keeps a leading boundary;
 * no shape matches an ordinary name or word pair. 2. an installed npm security placeholder holds every briefing at
 * human_only (INSTALLED_PLACEHOLDER), by the scan's own detector.
 */
import * as fs from "node:fs";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { BOUNDARY_SHAPES, CREDENTIAL_SHAPES } from "../tools/briefing-task-screen.js";
import { hasCredentialShape, screenText } from "../output-screen.js";
import { screenArguments } from "../argument-screen.js";
import { POPULAR_NPM } from "../live/popular-npm.js";
import { POPULAR_PYPI } from "../live/popular-pypi.js";
import { executeWhatShouldIKnow } from "../tools/what-should-i-know.js";
import { INSTALLED_PLACEHOLDER } from "../tools/briefing-confirm.js";
import { adv, createHarness, type Harness } from "./helpers/a1119-planner-harness.js";
import { sample, topAlternatives } from "./helpers/credential-samples.js";
import { brokenTextRules } from "./helpers/a1137-text-rules.js";

const ALTS = topAlternatives(CREDENTIAL_SHAPES.source.replace(/^\(\?:/, "").replace(/\)$/, ""));
const lengthen = (s: string) => (s.startsWith("eyJ") ? s : `${s}Q9wE7rT5yU3iO1pAz8xC6vB4nM2`);

/** Ordinary text: the bundled popular npm and PyPI names, the bench world's names, and 50,000 words joined in pairs. */
function ordinaryTexts(): string[] {
  const words = new Set<string>();
  const walk = (d: string): string[] => fs.readdirSync(d, { withFileTypes: true }).flatMap((e) => (e.name === "fixtures" ? [] : e.isDirectory() ? walk(path.join(d, e.name)) : [path.join(d, e.name)]));
  for (const f of walk(path.join(__dirname, ".."))) if (f.endsWith(".ts")) for (const m of fs.readFileSync(f, "utf8").toLowerCase().matchAll(/[a-z]{2,}/g)) words.add(m[0]);
  const C = "bcdfghjklmnprstvwxyz";
  const V = "aeiou";
  let seed = 7;
  const r = () => (seed = (seed * 1664525 + 1013904223) >>> 0) / 2 ** 32;
  while (words.size < 50_000) {
    let w = "";
    const n = 1 + Math.floor(r() * 4);
    for (let k = 0; k < n; k++) w += C[Math.floor(r() * C.length)] + V[Math.floor(r() * V.length)] + (r() < 0.4 ? C[Math.floor(r() * C.length)] : "");
    words.add(w);
  }
  const W = [...words];
  const world = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "..", "bench", "g7c", "world.json"), "utf8")) as Record<string, Record<string, unknown> | string>;
  const out = [...POPULAR_NPM, ...POPULAR_PYPI];
  for (const pkgs of Object.values(world)) if (typeof pkgs === "object") out.push(...Object.keys(pkgs));
  for (let i = 0; i < W.length; i++) out.push(`${W[i]}-${W[(i * 7919 + 13) % W.length]}`, `${W[(i * 104729 + 1) % W.length]}-${W[i]}`, `${W[i]}_${W[(i * 31 + 5) % W.length]}`);
  return out;
}

describe("1: the boundary is a property of each shape", () => {
  it("BOUNDARY_SHAPES are alternatives of CREDENTIAL_SHAPES with a leading \\b; the others have none", () => {
    for (const b of BOUNDARY_SHAPES) expect(ALTS).toContain(`\\b${b}`);
    expect(ALTS.filter((a) => a.startsWith("\\b")).length).toBe(BOUNDARY_SHAPES.length);
  });
  it("no shape matches an ordinary name or word pair (generated: 1,822 npm, the PyPI list, the bench world, 150,000 pairs)", () => {
    const texts = ordinaryTexts();
    expect(texts.length).toBeGreaterThan(150_000);
    const hits = ALTS.map((a) => [a, texts.filter((t) => new RegExp(a).test(t)).slice(0, 3)] as const).filter(([, h]) => h.length > 0);
    expect(hits).toEqual([]);
  });
  const GLUE = ["x", "7", "_", "=", ":", "/", '"', "'"];
  it.each(ALTS.map((a) => [a.slice(0, 24), a] as const))("%s: its sample is matched glued after a letter, a digit, _, =, :, / and a quote (unless a boundary shape)", (_l, alt) => {
    const tok = lengthen(sample(alt));
    expect(new RegExp(alt).test(tok)).toBe(true);
    const bounded = alt.startsWith("\\b");
    for (const g of GLUE) {
      const text = `key ${g}${tok} here`;
      const word = /\w/.test(g);
      expect(hasCredentialShape(text), `${g}${tok.slice(0, 8)}`).toBe(!(bounded && word));
      expect(screenText(text).includes(tok), `${g}${tok.slice(0, 8)}`).toBe(bounded && word);
    }
  });
  it("decision_memory masks a token glued after a word character, and a package argument with one glued is refused", () => {
    const tok = lengthen(sample(ALTS.find((a) => a.startsWith("gh"))!));
    const masked = screenArguments("decision_memory", { action: "record", decision: `key x${tok} here` });
    expect("args" in masked && masked.masked).toBe(1);
    expect(JSON.stringify(masked).includes(tok)).toBe(false);
    expect("refused" in screenArguments("upgrade_impact", { package: `x${tok}` })).toBe(true);
  });
});

describe("2: an installed npm security placeholder", () => {
  let h: Harness;
  beforeEach(() => {
    h = createHarness();
    for (const n of ["zod", "ky"]) h.NPM[n] = { latest: "3.24.1", versions: { "1.7.4": {}, "3.24.1": {} } };
    h.ADVISORIES.lodahs = [adv("MAL-2026-90077", "lodahs", [{ introduced: "0" }], "npm", "CRITICAL")];
    h.npmProject({ zod: "3.24.1", lodahs: "0.0.1-security" }, {}, { zod: { version: "3.24.1" }, lodahs: { version: "0.0.1-security" } });
  });
  afterEach(() => h.dispose());
  it("the scan's detector lists it (vulnerability_scan says remove the dependency)", async () => {
    const r = await h.scan();
    expect(JSON.stringify(r.security_placeholders ?? r)).toContain("lodahs");
  });
  it.each([
    ["Refactor the config module.", []],
    ["Add ky for the HTTP calls.", [{ ecosystem: "npm", name: "ky", version: "1.7.4", public: true }]],
    ["Refactor the config module.", undefined],
  ] as const)("%j: human_only with INSTALLED_PLACEHOLDER, whatever the task", async (task, packages) => {
    const r = (await executeWhatShouldIKnow(null, { task, ...(packages ? { packages } : {}), project_path: h.dir } as never, await h.live())) as Record<string, any>;
    expect(r.delegation_assessment.level).toBe("human_only");
    expect(r.delegation_assessment.reason.startsWith(INSTALLED_PLACEHOLDER(["lodahs@0.0.1-security"]))).toBe(true);
    expect(INSTALLED_PLACEHOLDER(["lodahs@0.0.1-security"])).toBe("This project has lodahs@0.0.1-security installed, npm's placeholder for a name taken down as malware: a person must remove that dependency before any task is delegated.");
    expect(r.delegation_assessment.reason).not.toMatch(/nothing version-confirmed/);
    expect(brokenTextRules(r, { task, packages })).toEqual([]);
  });
});
