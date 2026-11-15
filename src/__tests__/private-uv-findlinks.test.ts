// SPDX-License-Identifier: Apache-2.0
/**
 * Pre-publish round 10, W12: uv's find-links and no-index make a project's PyPI names private.
 *
 * The reviewer's repro: `requests==2.31.0` beside `zqx-billing==1.0.0`, with uv told to take wheels
 * from https://pkgs.acme.dev/wheels (UV_FIND_LINKS, a project uv.toml, pyproject [tool.uv] or
 * [tool.uv.pip]) or from ./wheels with no index at all. uv may take ANY name from a find-links
 * location, exactly as pip does with --find-links, so the policy is pip's: every PyPI name of the
 * project is private (registry kind), with the reason naming the setting and FOURDA_PUBLIC_MIRRORS.
 * Before the fix five tools sent zqx-billing to api.osv.dev and pypi.org (14-18 requests per layout).
 *
 * Every request is recorded by a stubbed fetch: nothing leaves the process.
 */
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { FourDADatabase } from "../db.js";
import { LiveIntelligence } from "../live/index.js";
import { clearLiveIntelligence, setLiveIntelligence } from "../live-singleton.js";
import { dispatchTool } from "../tool-dispatch.js";
import { TOOL_REGISTRY } from "../schema-registry.js";
import { scanProjectTree, treeResolutionGroups } from "../project-tree.js";

vi.mock("../live/cargo-platform.js", async (importOriginal) => ({ ...(await importOriginal<typeof import("../live/cargo-platform.js")>()), activeCratesForHost: () => null }));

const UV_ENV = ["UV_FIND_LINKS", "UV_NO_INDEX", "UV_INDEX", "UV_DEFAULT_INDEX", "UV_INDEX_URL", "UV_EXTRA_INDEX_URL", "UV_CONFIG_FILE", "UV_NO_CONFIG", "PIP_FIND_LINKS"];
let scratch: string;
let home: string;
let project: string;
let sent: string[];
const savedEnv = new Map<string, string | undefined>();
const setEnv = (key: string, value: string | undefined) => {
  if (!savedEnv.has(key)) savedEnv.set(key, process.env[key]);
  if (value === undefined) delete process.env[key];
  else process.env[key] = value;
};
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
const writeFiles = (root: string, files: Record<string, string>) => {
  for (const [file, content] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(root, file)), { recursive: true });
    fs.writeFileSync(path.join(root, file), content);
  }
};
const leaks = (re: RegExp) => sent.filter((s) => re.test(s));

beforeAll(() => setEnv("FOURDA_OFFLINE", undefined));
afterAll(() => {
  for (const [key, value] of savedEnv) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
});
beforeEach(() => {
  scratch = fs.mkdtempSync(path.join(os.tmpdir(), "4da-private-uv-"));
  home = path.join(scratch, "home");
  project = path.join(scratch, "project");
  fs.mkdirSync(home, { recursive: true });
  fs.mkdirSync(project, { recursive: true });
  sent = [];
  setEnv("HOME", home);
  setEnv("USERPROFILE", home);
  setEnv("APPDATA", path.join(home, "AppData", "Roaming"));
  setEnv("LOCALAPPDATA", path.join(home, "AppData", "Local"));
  setEnv("XDG_CONFIG_HOME", undefined);
  setEnv("XDG_CONFIG_DIRS", path.join(home, "xdg-none"));
  setEnv("ProgramData", path.join(home, "ProgramData"));
  setEnv("VIRTUAL_ENV", undefined);
  setEnv("PIP_CONFIG_FILE", undefined);
  setEnv("PIP_INDEX_URL", undefined);
  setEnv("PIP_EXTRA_INDEX_URL", undefined);
  setEnv("GOPROXY", undefined);
  setEnv("GOPRIVATE", undefined);
  setEnv("GONOSUMDB", undefined);
  setEnv("GONOPROXY", undefined);
  setEnv("GOENV", "off");
  setEnv("CARGO_HOME", path.join(home, ".cargo"));
  setEnv("FOURDA_PUBLIC_MIRRORS", undefined);
  setEnv("FOURDA_PRIVATE_PACKAGES", undefined);
  // The developer's own uv settings never reach the test.
  for (const key of UV_ENV) setEnv(key, undefined);
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: string, init?: RequestInit) => {
      const url = String(input);
      const body = typeof init?.body === "string" ? init.body : "";
      let readable = url;
      for (let i = 0; i < 4; i++) {
        try {
          const next = decodeURIComponent(readable);
          if (next === readable) break;
          readable = next;
        } catch {
          break;
        }
      }
      sent.push(`${readable} ${body}`);
      const u = new URL(url);
      if (u.hostname === "api.osv.dev" && u.pathname === "/v1/querybatch") {
        const { queries } = JSON.parse(body) as { queries: unknown[] };
        return json({ results: queries.map(() => ({ vulns: [] })) });
      }
      if (u.hostname === "api.osv.dev") return json({ vulns: [] });
      if (u.hostname === "hn.algolia.com") return json({ hits: [] });
      return json({ error: "Not found" }, 404);
    }),
  );
});
afterEach(() => {
  vi.unstubAllGlobals();
  clearLiveIntelligence();
  for (const [key, value] of savedEnv) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
  savedEnv.clear();
  setEnv("FOURDA_OFFLINE", undefined);
  try {
    fs.rmSync(scratch, { recursive: true, force: true });
  } catch {
    // Windows: left for the OS temp cleaner.
  }
});

/** The project's live layer, made the server's. */
function liveFor(files: Record<string, string>, homeFiles: Record<string, string> = {}): LiveIntelligence {
  writeFiles(project, files);
  writeFiles(home, homeFiles);
  const live = new LiveIntelligence(null);
  const { entries, discovery } = scanProjectTree(project);
  live.initFromProjectTree(project, treeResolutionGroups(entries), discovery);
  setLiveIntelligence(live);
  return live;
}

async function call(tool: string, args: Record<string, unknown>): Promise<string> {
  const db = new FourDADatabase(path.join(scratch, `standalone-${Math.random().toString(36).slice(2)}.db`));
  try {
    const result = await dispatchTool(tool, db, args).catch((error: unknown) => ({ content: [{ type: "text", text: String(error) }] }));
    return JSON.stringify(result);
  } finally {
    db.close();
  }
}


const DEPS = "requests==2.31.0\nzqx-billing==1.0.0\n";
const pyproject = (uv: string) => `[project]\nname = "app"\nversion = "0.1.0"\ndependencies = ["requests==2.31.0", "zqx-billing==1.0.0"]\n\n${uv}`;

const TOOLS: Record<string, Record<string, unknown>> = {
  vulnerability_scan: { include_dev: true },
  dependency_health: {},
  dependency_check: { items: [{ ecosystem: "PyPI", package: "zqx-billing", to: "1.1.0" }, { ecosystem: "PyPI", package: "requests", to: "2.32.3" }] },
  what_should_i_know: { task: "upgrade zqx-billing to 1.1.0" },
  upgrade_impact: { package: "zqx-billing", to_version: "2.0.0", ecosystem: "PyPI" },
};

async function callAll(): Promise<Record<string, string>> {
  const answers: Record<string, string> = {};
  for (const tool of Object.keys(TOOLS)) {
    expect(Object.hasOwn(TOOL_REGISTRY, tool)).toBe(true);
    answers[tool] = await call(tool, TOOLS[tool]);
  }
  return answers;
}

/** A fresh project directory for each case of a table-driven test. */
function resetProject(): void {
  fs.rmSync(project, { recursive: true, force: true });
  fs.mkdirSync(project, { recursive: true });
  for (const key of UV_ENV) setEnv(key, undefined);
}

describe("W12: uv find-links and no-index keep every PyPI name of the project private", () => {
  const LAYOUTS: Array<{ name: string; files: Record<string, string>; env?: Record<string, string>; setting: RegExp }> = [
    { name: "UV_FIND_LINKS + requirements.txt", files: { "requirements.txt": DEPS }, env: { UV_FIND_LINKS: "https://pkgs.acme.dev/wheels" }, setting: /find-links, UV_FIND_LINKS/ },
    { name: "project uv.toml find-links", files: { "requirements.txt": DEPS, "uv.toml": 'find-links = ["https://pkgs.acme.dev/wheels"]\n' }, setting: /find-links, \S*uv\.toml/ },
    { name: "pyproject [tool.uv] find-links", files: { "pyproject.toml": pyproject('[tool.uv]\nfind-links = ["https://pkgs.acme.dev/wheels"]\n') }, setting: /find-links, \S*pyproject\.toml/ },
    { name: "pyproject [tool.uv.pip] find-links", files: { "pyproject.toml": pyproject('[tool.uv.pip]\nfind-links = ["https://pkgs.acme.dev/wheels"]\n') }, setting: /find-links, \S*pyproject\.toml/ },
    { name: "pyproject [tool.uv] no-index + local find-links", files: { "pyproject.toml": pyproject('[tool.uv]\nno-index = true\nfind-links = ["./wheels"]\n') }, setting: /(?:no-index|find-links), \S*pyproject\.toml/ },
  ];
  for (const layout of LAYOUTS) {
    it(`${layout.name}: zqx-billing is never sent, and the answer names the setting`, async () => {
      for (const [k, v] of Object.entries(layout.env ?? {})) setEnv(k, v);
      const live = liveFor(layout.files);
      expect(live.registryPrivate("PyPI")).toMatch(layout.setting);
      expect(live.registryPrivate("PyPI")).toMatch(/FOURDA_PUBLIC_MIRRORS/);
      const answers = await callAll();
      expect(leaks(/zqx/i)).toEqual([]);
      for (const [tool, answer] of Object.entries(answers)) {
        expect(answer, tool).toMatch(/NOT CHECKED \(private\)|not_checked\\":\\"private/);
        expect(answer, tool).toMatch(/FOURDA_PUBLIC_MIRRORS/);
      }
    });
  }

  it("uv's other index-shaped settings each make the project's PyPI names private", () => {
    const cases: Array<{ files: Record<string, string>; env?: Record<string, string>; setting: RegExp }> = [
      { files: { "requirements.txt": DEPS }, env: { UV_NO_INDEX: "1" }, setting: /no-index, UV_NO_INDEX/ },
      { files: { "requirements.txt": DEPS }, env: { UV_FIND_LINKS: "https://pkgs.acme.dev/a,./wheels" }, setting: /UV_FIND_LINKS/ },
      { files: { "requirements.txt": DEPS, "uv.toml": "no-index = true\n" }, setting: /no-index, \S*uv\.toml/ },
      { files: { "requirements.txt": DEPS, "uv.toml": '[pip]\nfind-links = ["https://pkgs.acme.dev/wheels"]\n' }, setting: /find-links, \S*uv\.toml/ },
      { files: { "pyproject.toml": pyproject("[tool.uv.pip]\nno-index = true\n") }, setting: /no-index, \S*pyproject\.toml/ },
      { files: { "pyproject.toml": pyproject('[tool.uv.pip]\nindex-url = "https://pkgs.acme.dev/simple"\n') }, setting: /pkgs\.acme\.dev/ },
      { files: { "pyproject.toml": pyproject('[tool.uv.pip]\nextra-index-url = ["https://pkgs.acme.dev/simple"]\n') }, setting: /pkgs\.acme\.dev/ },
      { files: { "pyproject.toml": pyproject('[tool.uv]\nindex-url = "https://pkgs.acme.dev/simple"\n') }, setting: /pkgs\.acme\.dev/ },
      { files: { "pyproject.toml": pyproject('[tool.uv]\nextra-index-url = ["https://pkgs.acme.dev/simple"]\n') }, setting: /pkgs\.acme\.dev/ },
      { files: { "requirements.txt": DEPS }, env: { UV_INDEX: "acme=https://pkgs.acme.dev/simple" }, setting: /UV_INDEX/ },
      { files: { "requirements.txt": DEPS }, env: { UV_DEFAULT_INDEX: "https://pkgs.acme.dev/simple" }, setting: /UV_DEFAULT_INDEX/ },
      { files: { "requirements.txt": DEPS }, env: { UV_INDEX_URL: "https://pkgs.acme.dev/simple" }, setting: /UV_INDEX_URL/ },
      { files: { "requirements.txt": DEPS }, env: { UV_EXTRA_INDEX_URL: "https://pkgs.acme.dev/simple" }, setting: /UV_EXTRA_INDEX_URL/ },
      { files: { "pyproject.toml": pyproject('[[tool.uv.index]]\nname = "acme"\nurl = "https://pkgs.acme.dev/simple"\ndefault = true\n') }, setting: /pkgs\.acme\.dev/ },
    ];
    for (const c of cases) {
      resetProject();
      for (const [k, v] of Object.entries(c.env ?? {})) setEnv(k, v);
      const live = liveFor(c.files);
      expect(live.registryPrivate("PyPI"), JSON.stringify(c)).toMatch(c.setting);
    }
  });

  it("an explicit [[tool.uv.index]], a public find-links location and UV_NO_INDEX=0 leave the project public", () => {
    setEnv("UV_NO_INDEX", "0");
    const live = liveFor({
      "pyproject.toml": pyproject('[tool.uv]\nfind-links = ["https://download.pytorch.org/whl/torch_stable.html"]\nno-index = false\n\n[[tool.uv.index]]\nname = "acme"\nurl = "https://pkgs.acme.dev/simple"\nexplicit = true\n'),
    });
    expect(live.registryPrivate("PyPI")).toBeNull();
  });

  it("FOURDA_PUBLIC_MIRRORS naming the find-links host lets the project be checked", () => {
    setEnv("UV_FIND_LINKS", "https://pkgs.acme.dev/wheels");
    setEnv("FOURDA_PUBLIC_MIRRORS", "pkgs.acme.dev");
    const live = liveFor({ "requirements.txt": "requests==2.31.0\n" });
    expect(live.registryPrivate("PyPI")).toBeNull();
  });

  it("a public-only uv project: requests is still checked", async () => {
    const live = liveFor({ "pyproject.toml": '[project]\nname = "app"\nversion = "0.1.0"\ndependencies = ["requests==2.31.0"]\n\n[tool.uv]\ndev-dependencies = []\n' });
    expect(live.registryPrivate("PyPI")).toBeNull();
    await call("vulnerability_scan", { include_dev: true });
    await call("dependency_check", { items: [{ ecosystem: "PyPI", package: "requests", to: "2.32.3" }] });
    expect(leaks(/requests/).length).toBeGreaterThan(0);
  });

  it("setting UV_FIND_LINKS or UV_NO_INDEX after the server started re-reads the rules (they are rule variables)", () => {
    for (const [key, value] of [["UV_FIND_LINKS", "https://pkgs.acme.dev/wheels"], ["UV_NO_INDEX", "1"]] as const) {
      resetProject();
      const live = liveFor({ "requirements.txt": "requests==2.31.0\n" });
      expect(live.registryPrivate("PyPI")).toBeNull();
      setEnv(key, value);
      // The server calls this at the top of every tool call (src/index.ts).
      expect(live.refreshPrivateRules(), key).toBe(true);
      expect(live.registryPrivate("PyPI")).toMatch(new RegExp(key));
    }
  });
});
