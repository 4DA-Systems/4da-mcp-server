// SPDX-License-Identifier: Apache-2.0
/**
 * Regression: the fourteenth independent check (review-confirm14, round 16), a sample of its own sets vendored under
 * fixtures/a1139-confirm/ with its canned world and templates (w2-measure/vendor-review14.mjs: r2-a and m-s8 whole,
 * every k-th case of b-s3b, b-s5, b-s2all and b-s911; its s17 cases are masked by the reviewer and rebuilt in
 * a1139-round16). Each call is held to the invariants of THE CONTRACT the case's clause names, and to TEXT_RULES.
 */
import { readFileSync } from "node:fs";
import * as fs from "node:fs";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { FourDADatabase } from "../../db.js";
import { executeWhatShouldIKnow } from "../../tools/what-should-i-know.js";
import { executeDecisionMemory } from "../../tools/decision-memory.js";
import { executeCheckDecisionAlignment } from "../../tools/decision-enforcement.js";
import type { OsvVulnerability } from "../../live/types.js";
import { createHarness, type Harness } from "./a1119-planner-harness.js";
import { validateToolArgs } from "../../tool-args.js";
import { screenValue } from "../../output-screen.js";
import { forbiddenKey, TASK_FOLDED } from "../../tools/briefing-confirm.js";
import { brokenTextRules } from "./a1137-text-rules.js";
import { TOOL_REGISTRY } from "../../schema-registry.js";

const DIR = path.join(__dirname, "..", "fixtures", "a1139-confirm");
const RAW = JSON.parse(readFileSync(path.join(DIR, "review14-cases.json"), "utf8")) as { holes: Record<string, [string, string]> };
const load = (file: string) =>
  JSON.parse(Object.entries(Object.fromEntries(Object.entries(RAW.holes).map(([k, [a, b]]) => [k, `${a}${b}`]))).reduce((s, [k, v]) => s.replaceAll(k, JSON.stringify(v).slice(1, -1)), readFileSync(path.join(DIR, file), "utf8")));

type Call = { tool: string; args: Record<string, any> };
type Case = { set: string; id: string; clause: string; template?: string; setup?: Record<string, string>; tool?: string; args?: Record<string, any>; seq?: Call[]; expect?: Record<string, any> };
type WorldPkg = { versions: string[]; vulns?: Array<{ id: string; severity?: string; fixed?: string; introduced?: string; malware?: boolean; summary?: string }> };
const SCHEMA = TOOL_REGISTRY.what_should_i_know.definition.inputSchema;
const WORLD = load("review14-world.json") as Record<string, Record<string, WorldPkg> | string>;
const TEMPLATES = Object.fromEntries(["npm", "py", "go", "rs"].map((t) => [t, load(`template-${t}.json`) as Record<string, string>]));
const ALL = (load("review14-cases.json") as { cases: Case[] }).cases;

const cmp = (a: string, b: string) => {
  const x = a.replace(/^v/, "").split(/[.+-]/).map(Number);
  const y = b.replace(/^v/, "").split(/[.+-]/).map(Number);
  for (let i = 0; i < Math.max(x.length, y.length); i++) if ((x[i] || 0) !== (y[i] || 0)) return (x[i] || 0) - (y[i] || 0);
  return 0;
};
const worldOf = (ecosystem: string): Record<string, WorldPkg> => (WORLD[ecosystem] as Record<string, WorldPkg>) ?? {};
const keyOf = (ecosystem: string, name: string) => (ecosystem === "PyPI" ? name.toLowerCase().replace(/[-_.]+/g, "-") : ecosystem === "Go" ? name : name.toLowerCase());
const findPkg = (ecosystem: string, name: string) => Object.entries(worldOf(ecosystem)).find(([n]) => keyOf(ecosystem, n) === keyOf(ecosystem, name));
function osv(ecosystem: string, name: string, v: NonNullable<WorldPkg["vulns"]>[number]): OsvVulnerability {
  const events = [{ introduced: v.introduced ?? "0" }, ...(v.fixed ? [{ fixed: v.fixed }] : [])];
  return { id: v.id, aliases: [], summary: v.summary ?? `${name} ${v.id}`, database_specific: { severity: v.severity ?? "CRITICAL" }, affected: [{ package: { name, ecosystem }, ranges: [{ type: ecosystem === "PyPI" ? "ECOSYSTEM" : "SEMVER", events }] }] } as OsvVulnerability;
}
const affects = (v: NonNullable<WorldPkg["vulns"]>[number], version: string) => v.malware === true || (cmp(version, v.introduced ?? "0") >= 0 && (!v.fixed || cmp(version, v.fixed) < 0));
const DEFAULT_IGNORABLE = /\p{Default_Ignorable_Code_Point}/u;
const HOOK_MS = 60_000;
const CASE_MS = 120_000;
const WATCH = /zqxpriv[\w-]*|zqxs3cr[\w-]*/gi;

/** Registers the regression for some of the fourteenth check's sets. */
export function runReview14(sets: readonly string[]): void {
  const SAMPLE: Record<string, number> = process.env.FOURDA_FULL_REVIEW === "1" ? {} : { "b-s3b": 2, "b-s5": 2, "b-s2all": 2, "b-s911": 2 };
  const CASES = ALL.filter((c) => sets.includes(c.set)).filter((c, i, all) => !SAMPLE[c.set] || all.filter((x) => x.set === c.set).indexOf(c) % SAMPLE[c.set] === 0);
  let h: Harness;
  let db: FourDADatabase;
  let sent: Array<{ url: string; body: string }>;
  let live: Awaited<ReturnType<Harness["live"]>> | null = null;
  const savedEnv = new Map<string, string | undefined>();
  const setEnv = (key: string, value: string | undefined) => {
    if (!savedEnv.has(key)) savedEnv.set(key, process.env[key]);
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  };

  beforeEach(() => {
    h = createHarness();
    sent = [];
    for (const [ecosystem, pkgs] of Object.entries(WORLD)) {
      if (typeof pkgs === "string") continue;
      for (const [name, p] of Object.entries(pkgs)) {
        const sorted = [...p.versions].sort(cmp);
        if (ecosystem === "npm") h.NPM[name] = { latest: sorted[sorted.length - 1], versions: Object.fromEntries(sorted.map((v) => [v, {}])) };
        if (ecosystem === "PyPI") h.PYPI[keyOf("PyPI", name)] = Object.fromEntries(sorted.map((v) => [v, {}]));
        if (ecosystem === "crates.io") h.CRATES[name] = sorted.map((vers) => ({ vers }));
        if (ecosystem === "Go") {
          h.GO[name] = sorted;
          for (const v of sorted) h.GOMOD[`${name}@${v}`] = "1.21";
        }
      }
    }
    const inner = globalThis.fetch;
    const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
    vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
      const url = String(input);
      const body = init?.body ? String(init.body) : "";
      sent.push({ url: (() => { try { return decodeURIComponent(url); } catch { return url; } })(), body });
      if (url.endsWith("/v1/querybatch")) {
        const { queries } = JSON.parse(body) as { queries: Array<{ package: { name: string; ecosystem: string }; version: string }> };
        return json({ results: queries.map((q) => ({ vulns: (findPkg(q.package.ecosystem, q.package.name)?.[1].vulns ?? []).filter((v) => affects(v, q.version)).map((v) => ({ id: v.id })) })) });
      }
      if (url.includes("/v1/vulns/")) {
        const id = decodeURIComponent(url.split("/v1/vulns/")[1]);
        for (const [eco, pkgs] of Object.entries(WORLD)) {
          if (typeof pkgs === "string") continue;
          for (const [name, p] of Object.entries(pkgs)) for (const v of p.vulns ?? []) if (v.id === id) return json(osv(eco, name, v));
        }
        return json({}, 404);
      }
      if (url === "https://api.osv.dev/v1/query") {
        const q = JSON.parse(body) as { package: { name: string; ecosystem: string } };
        const found = findPkg(q.package.ecosystem, q.package.name);
        return json({ vulns: found ? (found[1].vulns ?? []).map((v) => osv(q.package.ecosystem, found[0], v)) : [] });
      }
      if (/api\.openai\.com|\/api\/embeddings/.test(url)) return json({ data: [{ embedding: [1, 0, 0, 0] }], embedding: [1, 0, 0, 0] });
      return inner(input, init);
    });
    for (const key of ["PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL", "GOPROXY", "GOPRIVATE", "GONOPROXY", "GONOSUMDB", "GOFLAGS", "FOURDA_PRIVATE_PACKAGES", "FOURDA_EMBED_PROVIDER", "OPENAI_API_KEY", "OLLAMA_URL", "FOURDA_EMBED_MODEL", "UV_INDEX_URL", "UV_DEFAULT_INDEX", "UV_EXTRA_INDEX_URL", "NPM_CONFIG_REGISTRY", "npm_config_registry", "GOENV", "PIP_CONFIG_FILE", "UV_NO_CONFIG"]) setEnv(key, undefined);
    const prof = path.join(h.dir, "..", `${path.basename(h.dir)}-u`);
    fs.mkdirSync(path.join(prof, "Roaming"), { recursive: true });
    fs.mkdirSync(path.join(prof, "Local"), { recursive: true });
    for (const [k, v] of Object.entries({ HOME: prof, USERPROFILE: prof, APPDATA: path.join(prof, "Roaming"), LOCALAPPDATA: path.join(prof, "Local"), FOURDA_MCP_HOME: path.join(prof, "mcp-home"), XDG_CONFIG_HOME: path.join(prof, ".config") })) setEnv(k, v);
    for (const k of ["ProgramData", "PROGRAMDATA", "ALLUSERSPROFILE", "XDG_CONFIG_DIRS"]) setEnv(k, path.join(prof, "machine"));
    setEnv("NPM_CONFIG_USERCONFIG", path.join(prof, ".npmrc"));
    db = new FourDADatabase(path.join(prof, "standalone.db"));
  }, HOOK_MS);
  afterEach(() => {
    db.close();
    const prof = process.env.HOME;
    h.dispose();
    for (const [key, value] of savedEnv) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
    savedEnv.clear();
    try {
      if (prof) fs.rmSync(prof, { recursive: true, force: true });
    } catch {
      // Windows: left for the OS temp cleaner.
    }
  }, HOOK_MS);

  /** The package names in the requests of the call (registry documents and OSV single queries, not the scan's batch). */
  const namesRequested = (): string[] => {
    const out: string[] = [];
    for (const x of sent) {
      const npm = /registry\.npmjs\.org\/((?:@[^/]+\/)?[^/?]+)/.exec(x.url);
      if (npm) out.push(npm[1]);
      const pypi = /pypi\.org\/pypi\/([^/]+)\//.exec(x.url);
      if (pypi) out.push(pypi[1]);
      const go = /proxy\.golang\.org\/(.+?)\/@(?:v|latest)/.exec(x.url);
      if (go) out.push(go[1]);
      if (x.url.endsWith("/v1/query")) for (const m of x.body.matchAll(/"name"\s*:\s*"([^"]+)"/g)) out.push(m[1]);
    }
    return out;
  };
  const briefing = async (args: Record<string, any>) => {
    const problem = validateToolArgs("what_should_i_know", SCHEMA, args);
    if (problem !== null) return null;
    live ??= await h.live();
    return screenValue(await executeWhatShouldIKnow(db, { ...args, project_path: args.project_path ?? h.dir } as never, live), "task") as Record<string, any>;
  };

  describe(`review-confirm14 cases hold the invariants (${sets.join(", ")})`, () => {
    it.each(CASES.map((c) => [`${c.set}/${c.id}`, c] as const))("%s", async (_label, c) => {
      live = null;
      if (c.template && c.template !== "none") for (const [rel, body] of Object.entries(TEMPLATES[c.template] ?? {})) h.write(rel, body);
      for (const [rel, body] of Object.entries(c.setup ?? {})) h.write(rel, body);
      const calls: Call[] = c.seq ?? [{ tool: c.tool ?? "what_should_i_know", args: c.args ?? {} }];
      let aligned: boolean | null = null;
      for (const step of calls) {
        const args = JSON.parse(JSON.stringify(step.args).replaceAll("@@DIR@@", h.dir.replaceAll("\\", "/")));
        if (step.tool === "decision_memory") {
          await executeDecisionMemory(db, args as never);
          continue;
        }
        if (step.tool === "check_decision_alignment") {
          aligned = ((await executeCheckDecisionAlignment(db, args as never, { lexicalOnly: true })) as { aligned?: boolean }).aligned ?? null;
          continue;
        }
        sent.length = 0;
        const r = await briefing(args);
        if (!r) continue;
        const level = String(r.delegation_assessment?.level);
        const reason = String(r.delegation_assessment?.reason);
        // TEXT_RULES: each text said is true at its level.
        expect(brokenTextRules(r, args), c.id).toEqual([]);
        // Sentence 1: a public entry without `version` never leaves the call safe.
        const versionless = (Array.isArray(args.packages) ? args.packages : []).some((p: any) => p?.public === true && (p.version === undefined || p.version === ""));
        if (versionless) expect(level, c.id).not.toBe("safe_to_delegate");
        // Sentence 3: nothing dismissed or declared private is in a request the task's lookups made; no watched name
        // either unless the call declared it public.
        const forbidden = new Set<string>([...(Array.isArray(args.not_packages) ? args.not_packages : []), ...(Array.isArray(args.packages) ? args.packages.filter((d: any) => d?.public === false).map((d: any) => d.name) : [])].filter((x) => typeof x === "string").map(forbiddenKey));
        const projectText = JSON.stringify([c.setup ?? {}, TEMPLATES[c.template ?? "npm"] ?? {}]).toLowerCase();
        expect(namesRequested().filter((n) => forbidden.has(forbiddenKey(n)) && !projectText.includes(n.toLowerCase())), c.id).toEqual([]);
        const publicNames = (Array.isArray(args.packages) ? args.packages : []).filter((p: any) => p?.public === true).map((p: any) => String(p.name).toLowerCase());
        const hay = sent.map((x) => `${x.url} ${x.body}`).join("\n");
        expect([...new Set([...hay.matchAll(WATCH)].map((m) => m[0].toLowerCase()))].filter((w) => !publicNames.some((n: string) => n.includes(w) || w.includes(n)) && !projectText.includes(w)), c.id).toEqual([]);
        if (c.expect?.core && !publicNames.includes(String(c.expect.core).toLowerCase())) expect(namesRequested().map((n) => n.toLowerCase()).filter((n) => n === String(c.expect!.core).toLowerCase()), c.id).toEqual([]);
        // Sentence 2: a dismissed name the briefing read and reported (a read kind in the bare call's to_confirm)
        // holds the answer from safe.
        if ((c.clause === "s2-read" || c.clause === "s2-instead") && Array.isArray(args.not_packages)) {
          const bare = await briefing({ task: args.task });
          const readKinds = new Set(["operand of an install command", "entry of a manifest snippet", "a name with a version written in the task", "a line of a requirements file the task names"]);
          const wasRead = (bare?.task_packages?.to_confirm ?? []).some((w: any) => args.not_packages.some((n: string) => forbiddenKey(n) === forbiddenKey(w.name)) && [w.seen].flat().some((s: string) => readKinds.has(s) || /requirements file/.test(s)));
          if (wasRead) expect(level, c.id).not.toBe("safe_to_delegate");
        }
        // Sentence 9 / 11: an unreadable command or a held name holds the answer from safe.
        if (c.clause === "s9" || c.clause === "s11-held") expect(level, c.id).not.toBe("safe_to_delegate");
        // Sentence 5: the reading copy keeps no default-ignorable character, and a fold is said.
        if (c.clause === "s5") {
          expect(DEFAULT_IGNORABLE.test(String(r.task)), c.id).toBe(false);
          if (DEFAULT_IGNORABLE.test(String(args.task)) || String(args.task).normalize("NFKC") !== String(args.task)) expect(r.task_note, c.id).toBe(TASK_FOLDED);
        }
        // Sentence 8: installed malware holds human_only whatever the task; another project-wide finding is listed and
        // leaves the level as it is, and a safe reason then names it.
        if (c.clause === "s8-projvuln") {
          const scanMalware = /"fastifyy"/.test(JSON.stringify(c.setup ?? {}));
          if (scanMalware) {
            expect(level, c.id).toBe("human_only");
            expect(reason, c.id).toMatch(/fastifyy@1\.0\.1 installed, which is recorded as malware/);
          } else if (level === "safe_to_delegate") {
            expect(reason, c.id).toMatch(/nothing version-confirmed for the packages this task touches; \d+ project-wide finding/);
            expect((r.advisories ?? []).some((a: any) => a.scope === "project"), c.id).toBe(true);
          }
        }
        // Sentence 8: a decision that rejects a name the call declares, reads or touches is a conflict (human_only).
        let declaredRejected = false;
        for (const p of Array.isArray(args.packages) ? args.packages : []) if (typeof p?.name === "string" && ((await executeCheckDecisionAlignment(db, { technology: p.name } as never, { lexicalOnly: true })) as { aligned?: boolean }).aligned === false) declaredRejected = true;
        if (declaredRejected) expect(r.decision_conflicts.length, `${c.id}: a declared package a decision rejects`).toBeGreaterThan(0);
        if (c.clause === "s8-decision" && aligned === false && declaredRejected) {
          expect(r.decision_conflicts.length, c.id).toBeGreaterThan(0);
          expect(level, c.id).toBe("human_only");
        }
      }
    }, CASE_MS);
  });
}
