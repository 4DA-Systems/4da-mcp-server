// SPDX-License-Identifier: Apache-2.0
/**
 * Blind audit round 4 (pre-publish, main 776849d): private names that still left the machine.
 *
 * 1. ecosystem_pulse searched Hacker News for another project's private dependency: its terms came
 *    from every project in the shared database, and only the current project's private names were
 *    removed. get_context listed the other project's stack too.
 * 2. bun.lock (and bunfig.toml scopes): a package installed from a private registry was sent.
 * 3. Manifest-declared private sources with no lockfile (Cargo `registry =`, uv `index =`, Poetry
 *    `source =`): the exact pins were sent.
 * 4. A member directory's `.npmrc` (no lockfile) did not make its scope private for a server
 *    started at the monorepo root.
 * 5. Spellings: `acme/ui`, fullwidth `＠` and `／`, `github:acme/ui`, a Unicode hyphen.
 */
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import Database from "better-sqlite3";
import { FourDADatabase } from "../db.js";
import { LiveIntelligence } from "../live/index.js";
import { fetchWithTimeout } from "../live/http-utils.js";
import { nameForms, PrivateRequestRefused } from "../live/private-guard.js";
import { scanCurrentProject } from "../project-scanner.js";
import { scanProjectTree, treeResolutionGroups } from "../project-tree.js";
import { pipConfigFiles } from "../live/private-packages.js";
import { executeDependencyCheck } from "../tools/dependency-check.js";
import { executeUpgradeImpact } from "../tools/upgrade-impact.js";
import { executeUpgradePlanner } from "../tools/upgrade-planner.js";
import { deriveTechStackForHeadlines, executeEcosystemPulse } from "../tools/ecosystem-pulse.js";
import { executeGetContext } from "../tools/get-context.js";
import { executeWhatShouldIKnow } from "../tools/what-should-i-know.js";
import { setLiveIntelligence } from "../live-singleton.js";

const noDb = null as unknown as FourDADatabase;
let scratch: string;
let sent: string[];
let priorOffline: string | undefined;
let priorList: string | undefined;

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
const write = (rel: string, content: string) => {
  fs.mkdirSync(path.dirname(path.join(scratch, rel)), { recursive: true });
  fs.writeFileSync(path.join(scratch, rel), content);
};
const mentions = (needle: string) => sent.filter((s) => s.toLowerCase().includes(needle.toLowerCase()));
const liveFor = (dir: string) => {
  const live = new LiveIntelligence(new Database(":memory:"));
  const { entries, discovery } = scanProjectTree(dir);
  live.initFromProjectTree(dir, treeResolutionGroups(entries), discovery);
  return live;
};
const memoryDb = (): FourDADatabase => {
  const instance = Object.create(FourDADatabase.prototype) as FourDADatabase;
  (instance as unknown as { db: Database.Database }).db = new Database(":memory:");
  return instance;
};

beforeAll(() => {
  priorOffline = process.env.FOURDA_OFFLINE;
  priorList = process.env.FOURDA_PRIVATE_PACKAGES;
  delete process.env.FOURDA_OFFLINE;
});

afterAll(() => {
  if (priorOffline === undefined) delete process.env.FOURDA_OFFLINE;
  else process.env.FOURDA_OFFLINE = priorOffline;
  if (priorList === undefined) delete process.env.FOURDA_PRIVATE_PACKAGES;
  else process.env.FOURDA_PRIVATE_PACKAGES = priorList;
});

beforeEach(() => {
  scratch = fs.mkdtempSync(path.join(os.tmpdir(), "4da-private-r4-"));
  sent = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init?: RequestInit) => {
      const body = typeof init?.body === "string" ? init.body : "";
      sent.push(`${decodeURIComponent(url)} ${body}`);
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
  delete process.env.FOURDA_PRIVATE_PACKAGES;
  setLiveIntelligence(null);
  try {
    fs.rmSync(scratch, { recursive: true, force: true });
  } catch {
    // Windows: left for the OS temp cleaner.
  }
});

/** Project A: a private npm package (lockfile `resolved` on a private host) and a private crate, beside react and tokio. */
function projectA(): string {
  write("a/package.json", JSON.stringify({ name: "a", dependencies: { "acme-ledger": "1.0.0", react: "18.2.0" } }));
  write(
    "a/package-lock.json",
    JSON.stringify({
      lockfileVersion: 3,
      packages: {
        "": { name: "a", dependencies: { "acme-ledger": "1.0.0", react: "18.2.0" } },
        "node_modules/acme-ledger": { version: "1.0.0", resolved: "https://npm.acme.internal/acme-ledger/-/acme-ledger-1.0.0.tgz" },
        "node_modules/react": { version: "18.2.0", resolved: "https://registry.npmjs.org/react/-/react-18.2.0.tgz" },
      },
    }),
  );
  write("a/Cargo.toml", '[package]\nname = "a"\nversion = "0.1.0"\n\n[dependencies]\nacme-vault-core = "0.3"\ntokio = "1"\n');
  write(
    "a/Cargo.lock",
    [
      "version = 3",
      "",
      "[[package]]",
      'name = "a"',
      'version = "0.1.0"',
      'dependencies = ["acme-vault-core", "tokio"]',
      "",
      "[[package]]",
      'name = "acme-vault-core"',
      'version = "0.3.0"',
      'source = "sparse+https://cargo.acme.internal/index/"',
      "",
      "[[package]]",
      'name = "tokio"',
      'version = "1.40.0"',
      'source = "registry+https://github.com/rust-lang/crates.io-index"',
      "",
    ].join("\n"),
  );
  return path.join(scratch, "a");
}

/** Project B: public only (express, with a lockfile). */
function projectB(): string {
  write("b/package.json", JSON.stringify({ name: "b", dependencies: { express: "4.18.2", "zod-mini-thing": "1.0.0" } }));
  write(
    "b/package-lock.json",
    JSON.stringify({
      lockfileVersion: 3,
      packages: {
        "": { name: "b", dependencies: { express: "4.18.2", "zod-mini-thing": "1.0.0" } },
        "node_modules/express": { version: "4.18.2", resolved: "https://registry.npmjs.org/express/-/express-4.18.2.tgz" },
        "node_modules/zod-mini-thing": { version: "1.0.0", resolved: "https://registry.npmjs.org/zod-mini-thing/-/zod-mini-thing-1.0.0.tgz" },
      },
    }),
  );
  return path.join(scratch, "b");
}

/** The shared standalone database both projects' servers populate (same FOURDA_MCP_HOME). */
function sharedDb(...projects: string[]): FourDADatabase {
  const db = new FourDADatabase(path.join(scratch, "shared.db"));
  for (const p of projects) db.populateFromScan(scanCurrentProject(p));
  return db;
}

describe("1: ecosystem_pulse and get_context are scoped to the current project", () => {
  it("B's pulse sends nothing of A's, private or public", async () => {
    const a = projectA();
    const b = projectB();
    const db = sharedDb(a, b);
    const live = liveFor(b);
    await executeEcosystemPulse(db, {}, live);
    const hn = sent.filter((s) => s.includes("hn.algolia.com"));
    expect(hn.length).toBeGreaterThan(0);
    expect(mentions("acme")).toEqual([]);
    // A's public names (react, tokio) are not B's stack either.
    expect(hn.filter((s) => /query=(react|tokio)\b/.test(s))).toEqual([]);
    expect(hn.some((s) => s.includes("query=express"))).toBe(true);
    db.close();
  });

  it("a term private in another project the database knows is never sent, even when the current project also names it", async () => {
    const a = projectA();
    // B depends on a PUBLIC package that happens to share A's private crate name.
    write("b/package.json", JSON.stringify({ name: "b", dependencies: { "acme-vault-core": "1.0.0", express: "4.18.2" } }));
    write(
      "b/package-lock.json",
      JSON.stringify({
        lockfileVersion: 3,
        packages: {
          "": { name: "b", dependencies: { "acme-vault-core": "1.0.0", express: "4.18.2" } },
          "node_modules/acme-vault-core": { version: "1.0.0", resolved: "https://registry.npmjs.org/acme-vault-core/-/acme-vault-core-1.0.0.tgz" },
          "node_modules/express": { version: "4.18.2", resolved: "https://registry.npmjs.org/express/-/express-4.18.2.tgz" },
        },
      }),
    );
    const b = path.join(scratch, "b");
    const db = sharedDb(a, b);
    const terms = deriveTechStackForHeadlines(db, liveFor(b));
    expect(terms).toContain("express");
    expect(terms).not.toContain("acme-vault-core");
    db.close();
  });

  it("a term the current rules call private in any ecosystem is never sent", async () => {
    const b = projectB();
    process.env.FOURDA_PRIVATE_PACKAGES = "PyPI:zod-mini-*";
    const db = sharedDb(b);
    const live = liveFor(b);
    await executeEcosystemPulse(db, {}, live);
    expect(mentions("zod-mini")).toEqual([]);
    db.close();
  });

  it("desktop mode: rows stored under the app's paths are scoped by project root", () => {
    const db = memoryDb();
    const raw = db.getRawDb();
    raw.exec("CREATE TABLE project_dependencies (project_path TEXT, package_name TEXT, language TEXT, is_direct INTEGER DEFAULT 1)");
    raw.exec("CREATE TABLE detected_tech (name TEXT, category TEXT, confidence REAL)");
    const b = projectB();
    const appPath = b.replace(/\//g, "\\").toUpperCase();
    raw.prepare("INSERT INTO project_dependencies VALUES (?, 'express', 'javascript', 1)").run(appPath);
    raw.prepare("INSERT INTO project_dependencies VALUES (?, 'acme-ledger', 'javascript', 1)").run(path.join(scratch, "elsewhere"));
    raw.prepare("INSERT INTO detected_tech VALUES ('svelte', 'framework', 0.9)").run();
    const terms = deriveTechStackForHeadlines(db, liveFor(b));
    expect(terms).toContain("express");
    expect(terms).not.toContain("acme-ledger");
    expect(terms).not.toContain("svelte");
  });

  it("B's get_context does not list A's stack", () => {
    const a = projectA();
    const b = projectB();
    const db = sharedDb(a, b);
    setLiveIntelligence(liveFor(b));
    const context = executeGetContext(db, {});
    const text = JSON.stringify(context);
    expect(text).not.toContain('"react"');
    expect(text).not.toContain('"rust"');
    expect(text).not.toContain('"tokio"');
    expect(text).not.toContain("acme");
    expect(text).toContain("javascript");
    db.close();
  });
});

describe("2: bun.lock and bunfig.toml", () => {
  const bunLock = (registry: string) =>
    `{
  "lockfileVersion": 1,
  "workspaces": { "": { "name": "app", "dependencies": { "@acme/ui": "1.2.3", "left-pad": "1.3.0" } } },
  "packages": {
    "@acme/ui": ["@acme/ui@1.2.3", "${registry}", {}, "sha512-x"],
    "left-pad": ["left-pad@1.3.0", "", {}, "sha512-y"],
  }
}
`;

  it("a bun.lock package resolved on a private host is never sent", async () => {
    write("package.json", JSON.stringify({ name: "app", dependencies: { "@acme/ui": "1.2.3", "left-pad": "1.3.0" } }));
    write("bun.lock", bunLock("https://npm.acme.internal/@acme/ui/-/ui-1.2.3.tgz"));
    const live = liveFor(scratch);
    await live.scanVulnerabilities(scratch, { includeDev: true });
    await executeDependencyCheck(noDb, { items: [{ ecosystem: "npm", package: "@acme/ui", to: "1.2.4" }] }, live);
    expect(mentions("left-pad").length).toBeGreaterThan(0);
    expect(mentions("acme")).toEqual([]);
  });

  for (const [form, config] of [
    ["string", '[install.scopes]\n"@acme" = "https://npm.acme.internal/"\n'],
    ["table", '[install.scopes]\nacme = { url = "https://npm.acme.internal/", token = "x" }\n'],
    ["sub-table", '[install.scopes.acme]\nurl = "https://npm.acme.internal/"\n'],
  ] as const) {
    it(`bunfig.toml [install.scopes] (${form} form) makes the scope private`, async () => {
      write("package.json", JSON.stringify({ name: "app", dependencies: { "@acme/ui": "1.2.3", "left-pad": "1.3.0" } }));
      write("bunfig.toml", config);
      write("bun.lock", bunLock(""));
      const live = liveFor(scratch);
      await live.scanVulnerabilities(scratch, { includeDev: true });
      await executeDependencyCheck(noDb, { items: [{ ecosystem: "npm", package: "@acme/ui", to: "1.2.4" }] }, live);
      expect(mentions("left-pad").length).toBeGreaterThan(0);
      expect(mentions("acme")).toEqual([]);
    });
  }

  it("bunfig.toml [install] registry that is not public is said, like an .npmrc registry", () => {
    write("package.json", JSON.stringify({ name: "app", dependencies: { "left-pad": "1.3.0" } }));
    write("bunfig.toml", '[install]\nregistry = "https://npm.acme.internal/"\n');
    write("bun.lock", bunLock(""));
    const live = liveFor(scratch);
    expect(live.getRegistryNotice()).toContain("npm.acme.internal");
  });

  it("a yarn berry lockfile resolution on a private URL is never sent", async () => {
    write("package.json", JSON.stringify({ name: "app", dependencies: { "acme-berry": "1.0.0", "left-pad": "1.3.0" } }));
    write(
      "yarn.lock",
      [
        "__metadata:",
        "  version: 8",
        "",
        '"acme-berry@npm:1.0.0":',
        "  version: 1.0.0",
        '  resolution: "acme-berry@https://npm.acme.internal/acme-berry/-/acme-berry-1.0.0.tgz"',
        "",
        '"left-pad@npm:1.3.0":',
        "  version: 1.3.0",
        '  resolution: "left-pad@npm:1.3.0"',
        "",
      ].join("\n"),
    );
    const live = liveFor(scratch);
    await executeDependencyCheck(noDb, { items: [{ ecosystem: "npm", package: "acme-berry", to: "1.0.1" }] }, live);
    expect(mentions("acme")).toEqual([]);
  });
});

describe("3: private sources a manifest declares, with no lockfile", () => {
  it("Cargo.toml `registry = ...` other than crates-io", async () => {
    write("Cargo.toml", '[package]\nname = "app"\nversion = "0.1.0"\n\n[dependencies]\nomega-ledger = { version = "=1.2.0", registry = "acme" }\nserde = "=1.0.200"\nplain = { version = "=1.0.0", registry = "crates-io" }\n');
    const live = liveFor(scratch);
    await live.scanVulnerabilities(scratch, { includeDev: true });
    await executeDependencyCheck(noDb, { items: [{ ecosystem: "crates.io", package: "omega-ledger", to: "1.2.1" }] }, live);
    expect(mentions("serde").length).toBeGreaterThan(0);
    expect(mentions("plain").length).toBeGreaterThan(0);
    expect(mentions("omega")).toEqual([]);
  });

  it("pyproject [tool.uv.sources] `index = ...` with a declared [[tool.uv.index]]", async () => {
    write(
      "pyproject.toml",
      [
        "[project]",
        'name = "app"',
        'version = "0.1.0"',
        'dependencies = ["omega-quant==2.0.0", "requests==2.31.0"]',
        "",
        "[tool.uv.sources]",
        'omega-quant = { index = "acme" }',
        "",
        "[[tool.uv.index]]",
        'name = "acme"',
        'url = "https://pypi.acme.internal/simple"',
        "explicit = true",
        "",
      ].join("\n"),
    );
    const live = liveFor(scratch);
    await live.scanVulnerabilities(scratch, { includeDev: true });
    await executeDependencyCheck(noDb, { items: [{ ecosystem: "PyPI", package: "omega-quant", to: "2.0.1" }] }, live);
    expect(mentions("omega")).toEqual([]);
  });

  it("Poetry `source = ...` naming an explicit [[tool.poetry.source]]", async () => {
    write(
      "pyproject.toml",
      [
        "[tool.poetry]",
        'name = "app"',
        'version = "0.1.0"',
        "",
        "[tool.poetry.dependencies]",
        'python = "^3.11"',
        'omega-risk = { version = "1.4.0", source = "acme" }',
        'requests = "2.31.0"',
        "",
        "[[tool.poetry.source]]",
        'name = "acme"',
        'url = "https://pypi.acme.internal/simple"',
        'priority = "explicit"',
        "",
      ].join("\n"),
    );
    const live = liveFor(scratch);
    await live.scanVulnerabilities(scratch, { includeDev: true });
    await executeDependencyCheck(noDb, { items: [{ ecosystem: "PyPI", package: "omega-risk", to: "1.4.1" }] }, live);
    expect(mentions("omega")).toEqual([]);
  });
});

describe("4: a member directory's .npmrc, no lockfile", () => {
  it("services/api/.npmrc makes @acme private for a server at the root", async () => {
    write("package.json", JSON.stringify({ name: "root", private: true, dependencies: { "left-pad": "1.3.0" } }));
    write("services/api/package.json", JSON.stringify({ name: "api", dependencies: { "@acme/ui": "1.2.3", "is-odd": "3.0.1" } }));
    write("services/api/.npmrc", "@acme:registry=https://npm.acme.internal/\n");
    const live = liveFor(scratch);
    await executeDependencyCheck(noDb, { items: [{ ecosystem: "npm", package: "@acme/ui", to: "1.2.4" }] }, live);
    await executeWhatShouldIKnow(memoryDb(), { task: "upgrade @acme/ui to 1.2.4" }, live).catch(() => null);
    expect(mentions("acme")).toEqual([]);
  });

  it("services/api/.yarnrc.yml npmScopes, likewise", async () => {
    write("package.json", JSON.stringify({ name: "root", private: true, dependencies: { "left-pad": "1.3.0" } }));
    write("services/api/package.json", JSON.stringify({ name: "api", dependencies: { "@acme/ui": "1.2.3" } }));
    write("services/api/.yarnrc.yml", 'npmScopes:\n  acme:\n    npmRegistryServer: "https://npm.acme.internal/"\n');
    const live = liveFor(scratch);
    await executeDependencyCheck(noDb, { items: [{ ecosystem: "npm", package: "@acme/ui", to: "1.2.4" }] }, live);
    expect(mentions("acme")).toEqual([]);
  });
});

describe("A: every pip configuration file pip reads, and extra indexes", () => {
  const PIP_ENV = ["PIP_CONFIG_FILE", "PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL", "HOME", "USERPROFILE", "APPDATA", "ProgramData", "ALLUSERSPROFILE", "XDG_CONFIG_HOME", "XDG_CONFIG_DIRS", "VIRTUAL_ENV"];
  let saved: Record<string, string | undefined>;
  beforeEach(() => {
    saved = Object.fromEntries(PIP_ENV.map((k) => [k, process.env[k]]));
    // Every location under the fixture, so no file on this machine is read.
    for (const k of PIP_ENV) delete process.env[k];
    const home = path.join(scratch, "home");
    process.env.HOME = home;
    process.env.USERPROFILE = home;
    process.env.APPDATA = path.join(home, "AppData", "Roaming");
    process.env.ProgramData = path.join(scratch, "programdata");
    process.env.XDG_CONFIG_HOME = path.join(home, ".config");
    process.env.XDG_CONFIG_DIRS = path.join(scratch, "xdg");
  });
  afterEach(() => {
    for (const k of PIP_ENV) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
  });

  const PRIVATE = "https://pypi.corp-secret.example/simple";
  const conf = (key = "index-url") => `[global]\n${key} = ${PRIVATE}\n`;
  const win = process.platform === "win32";
  const cases: Array<[string, () => void]> = [
    ["PIP_EXTRA_INDEX_URL", () => void (process.env.PIP_EXTRA_INDEX_URL = PRIVATE)],
    ["a requirements file's --extra-index-url", () => write("requirements.txt", `--extra-index-url ${PRIVATE}\nomega-internal-risk==3.1.0\n`)],
    ["extra-index-url in the user's pip config", () => write(win ? "home/AppData/Roaming/pip/pip.ini" : "home/.config/pip/pip.conf", conf("extra-index-url"))],
    ["the virtualenv's pip config", () => {
      process.env.VIRTUAL_ENV = path.join(scratch, "venv");
      write(win ? "venv/pip.ini" : "venv/pip.conf", conf());
    }],
    ...(win
      ? ([
          ["the legacy per-user %USERPROFILE%\\pip\\pip.ini", () => write("home/pip/pip.ini", conf())],
          ["the site-wide %ProgramData%\\pip\\pip.ini", () => write("programdata/pip/pip.ini", conf())],
        ] as Array<[string, () => void]>)
      : ([
          ["~/.pip/pip.conf", () => write("home/.pip/pip.conf", conf())],
          ["$XDG_CONFIG_HOME/pip/pip.conf", () => write("home/.config/pip/pip.conf", conf())],
          ["$XDG_CONFIG_DIRS/pip/pip.conf", () => write("xdg/pip/pip.conf", conf())],
        ] as Array<[string, () => void]>)),
  ];
  for (const [where, arrange] of cases) {
    it(`a private index in ${where}: omega-internal-risk is sent nowhere, by any tool`, async () => {
      write("requirements.txt", "omega-internal-risk==3.1.0\nrequests==2.31.0\n");
      arrange();
      const live = liveFor(scratch);
      const scan = await live.scanVulnerabilities(scratch, { includeDev: true });
      expect(scan.privateExcluded?.dependencies.map((d) => d.name)).toContain("omega-internal-risk");
      await executeDependencyCheck(noDb, { items: [{ ecosystem: "PyPI", package: "omega-internal-risk", to: "3.2.0" }] }, live);
      await executeWhatShouldIKnow(memoryDb(), { task: "bump omega-internal-risk to 3.2.0" }, live).catch(() => null);
      await executeUpgradeImpact(noDb, { package: "omega-internal-risk", ecosystem: "PyPI", to_version: "3.2.0" }, live).catch(() => null);
      await executeUpgradePlanner(memoryDb(), {}, live).catch(() => null);
      expect(mentions("omega")).toEqual([]);
    });
  }

  it("pip's file list, per platform, from the environment", () => {
    const winFiles = pipConfigFiles({ USERPROFILE: "C:\\Users\\u", APPDATA: "C:\\Users\\u\\AppData\\Roaming", VIRTUAL_ENV: "C:\\v", PIP_CONFIG_FILE: "C:\\x.ini" }, "win32");
    expect(winFiles).toEqual(["C:\\ProgramData\\pip\\pip.ini", "C:\\Users\\u\\pip\\pip.ini", "C:\\Users\\u\\AppData\\Roaming\\pip\\pip.ini", "C:\\v\\pip.ini", "C:\\x.ini"]);
    const mac = pipConfigFiles({ HOME: "/Users/u" }, "darwin");
    expect(mac).toEqual(["/etc/xdg/pip/pip.conf", "/Library/Application Support/pip/pip.conf", "/etc/pip.conf", "/Users/u/.pip/pip.conf", "/Users/u/Library/Application Support/pip/pip.conf", "/Users/u/.config/pip/pip.conf"]);
    const linux = pipConfigFiles({ HOME: "/home/u", XDG_CONFIG_DIRS: "/a:/b", VIRTUAL_ENV: "/v" }, "linux");
    expect(linux).toEqual(["/a/pip/pip.conf", "/b/pip/pip.conf", "/etc/pip.conf", "/home/u/.pip/pip.conf", "/home/u/.config/pip/pip.conf", "/v/pip.conf"]);
    expect(pipConfigFiles({ PIP_CONFIG_FILE: "os.devnull", HOME: "/home/u" }, "linux")).toEqual([]);
  });

  it("a public extra index changes nothing", async () => {
    write("requirements.txt", "--extra-index-url https://pypi.org/simple\nrequests==2.31.0\n");
    process.env.PIP_EXTRA_INDEX_URL = "https://pypi.org/simple";
    const live = liveFor(scratch);
    await live.scanVulnerabilities(scratch, { includeDev: true });
    expect(mentions("requests").length).toBeGreaterThan(0);
  });

  it("a well-known public wheel index as an extra index (PyTorch) keeps the pins public", async () => {
    write("requirements.txt", "--extra-index-url https://download.pytorch.org/whl/cu121\nrequests==2.31.0\n");
    process.env.PIP_EXTRA_INDEX_URL = "https://pypi.nvidia.com";
    const live = liveFor(scratch);
    const scan = await live.scanVulnerabilities(scratch, { includeDev: true });
    expect(scan.privateExcluded?.dependencies.map((d) => d.name) ?? []).not.toContain("requests");
    expect(mentions("requests").length).toBeGreaterThan(0);
  });

  it("the same host as --index-url still replaces pypi.org, so its pins are private", async () => {
    write("requirements.txt", "--index-url https://download.pytorch.org/whl/cu121\nomega-internal-risk==3.1.0\n");
    const live = liveFor(scratch);
    const scan = await live.scanVulnerabilities(scratch, { includeDev: true });
    expect(scan.privateExcluded?.dependencies.map((d) => d.name)).toContain("omega-internal-risk");
    expect(mentions("omega")).toEqual([]);
  });
});

describe("B: ecosystem_pulse with no stack to search", () => {
  it("says nothing was searched, never 'no relevant headlines'", async () => {
    write("README.md", "nothing here\n");
    const db = sharedDb();
    const live = new LiveIntelligence(new Database(":memory:"));
    live.initFromProjectTree(scratch, [], null);
    const result = await executeEcosystemPulse(db, {}, live);
    expect(sent).toEqual([]);
    expect(result.note).toMatch(/^NOT CHECKED: no stack was detected/);
    expect(result.note).not.toMatch(/No relevant headlines/);
    db.close();
  });
});

describe("5: spellings of a listed private name", () => {
  const spellings: Array<[string, string]> = [
    ["npm", "acme/ui"],
    ["npm", "＠acme/ui"],
    ["npm", "@acme／ui"],
    ["npm", "github:acme/ui"],
    ["PyPI", "omega‐risk"],
    ["PyPI", "omega–risk"],
    ["PyPI", "ｏmega-risk"],
  ];
  for (const [ecosystem, name] of spellings) {
    it(`dependency_check on ${JSON.stringify(name)} sends nothing`, async () => {
      process.env.FOURDA_PRIVATE_PACKAGES = "npm:@acme/*, PyPI:omega-*";
      write("package.json", JSON.stringify({ name: "app", dependencies: { "left-pad": "1.3.0" } }));
      const live = liveFor(scratch);
      const result = await executeDependencyCheck(noDb, { items: [{ ecosystem: ecosystem as "npm", package: name, to: "1.0.0" }] }, live);
      expect(result.results[0].verdict).toBe("unknown");
      expect(mentions("acme")).toEqual([]);
      expect(mentions("mega")).toEqual([]);
    });
  }

  it("the request guard refuses the same spellings in URLs and bodies", async () => {
    process.env.FOURDA_PRIVATE_PACKAGES = "npm:@acme/*, PyPI:omega-*";
    write("package.json", JSON.stringify({ name: "app", dependencies: { "left-pad": "1.3.0" } }));
    liveFor(scratch);
    for (const url of [
      "https://registry.npmjs.org/acme%2fui",
      `https://registry.npmjs.org/${encodeURIComponent("＠acme/ui")}`,
      `https://registry.npmjs.org/@acme${encodeURIComponent("／")}ui`,
      `https://pypi.org/pypi/${encodeURIComponent("omega‐risk")}/json`,
    ]) {
      await expect(fetchWithTimeout(url)).rejects.toBeInstanceOf(PrivateRequestRefused);
    }
    await expect(
      fetchWithTimeout("https://api.osv.dev/v1/query", { method: "POST", body: JSON.stringify({ package: { ecosystem: "npm", name: "github:acme/ui" }, version: "1.0.0" }) }),
    ).rejects.toBeInstanceOf(PrivateRequestRefused);
    expect(mentions("acme")).toEqual([]);
  });

  it("public names that merely resemble a private one stay queryable", async () => {
    process.env.FOURDA_PRIVATE_PACKAGES = "npm:@acme/*, PyPI:omega-*";
    write("package.json", JSON.stringify({ name: "app", dependencies: { "left-pad": "1.3.0" } }));
    const live = liveFor(scratch);
    for (const [eco, name] of [["npm", "acme-ui"], ["npm", "@acmex/ui"], ["npm", "ui"], ["PyPI", "omegarisk"], ["Go", "github.com/acme/ui"]] as const) {
      expect(live.privateReason(eco, name)).toBeNull();
    }
    expect(nameForms("acme/ui")).toContain("@acme/ui");
    expect(nameForms("omega‐risk")).toContain("omega-risk");
  });
});
