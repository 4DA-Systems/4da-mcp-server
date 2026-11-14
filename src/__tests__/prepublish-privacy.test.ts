// SPDX-License-Identifier: Apache-2.0
/**
 * Pre-publish audit of MCP main 96c16d2 (2026-11-13): privacy findings S3 to S5.
 */
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import Database from "better-sqlite3";
import { FourDADatabase } from "../db.js";
import { LiveIntelligence } from "../live/index.js";
import { executeWhatShouldIKnow } from "../tools/what-should-i-know.js";
import { executeDependencyCheck } from "../tools/dependency-check.js";
import { scanProjectTree, treeResolutionGroups } from "../project-tree.js";

let scratch: string;
let sent: string[];
let priorOffline: string | undefined;
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
const write = (rel: string, content: string) => {
  fs.mkdirSync(path.dirname(path.join(scratch, rel)), { recursive: true });
  fs.writeFileSync(path.join(scratch, rel), content);
};
const mentions = (needle: string) => sent.filter((s) => s.toLowerCase().includes(needle));
const liveFor = (dir: string) => {
  const live = new LiveIntelligence(new Database(":memory:"));
  const { entries, discovery } = scanProjectTree(dir);
  live.initFromProjectTree(dir, treeResolutionGroups(entries), discovery);
  return live;
};

beforeAll(() => {
  priorOffline = process.env.FOURDA_OFFLINE;
  delete process.env.FOURDA_OFFLINE;
});
afterAll(() => {
  if (priorOffline === undefined) delete process.env.FOURDA_OFFLINE;
  else process.env.FOURDA_OFFLINE = priorOffline;
});
beforeEach(() => {
  scratch = fs.mkdtempSync(path.join(os.tmpdir(), "4da-prepublish-"));
  sent = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init?: RequestInit) => {
      const body = typeof init?.body === "string" ? init.body : "";
      sent.push(`${url} ${body}`);
      const u = new URL(url);
      if (u.hostname === "api.osv.dev" && u.pathname === "/v1/querybatch") {
        const { queries } = JSON.parse(body) as { queries: unknown[] };
        return json({ results: queries.map(() => ({ vulns: [] })) });
      }
      if (u.hostname === "api.osv.dev") return json({ vulns: [] });
      return json({ error: "Not found" }, 404);
    }),
  );
});
afterEach(() => {
  vi.unstubAllGlobals();
  try {
    fs.rmSync(scratch, { recursive: true, force: true });
  } catch {
    // Windows: left for the OS temp cleaner.
  }
});

describe("S3: what_should_i_know and private packages", () => {
  function npmProject() {
    write(".npmrc", "@acme:registry=https://npm.acme.dev/\n");
    write("package.json", JSON.stringify({ name: "app", dependencies: { "@acme/vault-core": "1.4.0", lodash: "4.17.21" } }));
    write(
      "package-lock.json",
      JSON.stringify({
        name: "app",
        lockfileVersion: 3,
        packages: {
          "": { name: "app", dependencies: { "@acme/vault-core": "1.4.0", lodash: "4.17.21" } },
          "node_modules/@acme/vault-core": { version: "1.4.0" },
          "node_modules/lodash": { version: "4.17.21" },
        },
      }),
    );
    return liveFor(scratch);
  }
  const testDb = () => new FourDADatabase(path.join(scratch, "standalone.db"));

  it("an upgrade of an installed private package leads with NOT CHECKED (private) and is never safe_to_delegate", async () => {
    const live = npmProject();
    const db = testDb();
    try {
      const result = await executeWhatShouldIKnow(db, { task: "upgrade @acme/vault-core to 2.0.0" }, live);
      expect(result.summary.startsWith("NOT CHECKED (private): the task touches @acme/vault-core 1.4.0")).toBe(true);
      expect(result.private_dependencies?.map((p) => p.package)).toEqual(["@acme/vault-core"]);
      expect(result.advisories[0].title).toContain("NOT CHECKED (private)");
      expect(result.delegation_assessment.level).not.toBe("safe_to_delegate");
      expect(result.delegation_assessment.reason).toContain("@acme/vault-core is private");
      expect(mentions("vault-core")).toEqual([]);
    } finally {
      db.close();
    }
  });

  // Black-box re-run 2026-11-14: a private PyPI name in a task was guessed npm and sent to
  // api.osv.dev and registry.npmjs.org, because the guard judges a name per ecosystem.
  it.each([
    ["mixed npm + PyPI", true, "bump omega-internal-risk to 3.2.0"],
    ["mixed npm + PyPI", true, "upgrade omega-internal-risk to 3.2.0"],
    ["mixed npm + PyPI", true, "bump omega-internal-risk to 3.2.0 and lodash to 4.18.1"],
    ["PyPI only", false, "bump omega-internal-risk to 3.2.0"],
    ["PyPI only", false, "add omega-internal-risk 3.2.0"],
  ])("%s: a private PyPI name in the task is never looked up under a guessed ecosystem (%s, %s)", async (_, withNpm, task) => {
    if (withNpm) npmProject();
    write("requirements.txt", "--index-url https://pypi.corp-secret.example/simple\nomega-internal-risk==3.1.0\n");
    const live = liveFor(scratch);
    const db = testDb();
    try {
      const result = await executeWhatShouldIKnow(db, { task }, live);
      expect(mentions("omega")).toEqual([]);
      expect(mentions("corp-secret")).toEqual([]);
      expect(result.private_dependencies?.map((p) => p.package)).toContain("omega-internal-risk");
      expect(result.delegation_assessment.level).not.toBe("safe_to_delegate");
      if (task.includes("lodash")) expect(mentions("lodash").length).toBeGreaterThan(0);
    } finally {
      db.close();
    }
  });

  // Black-box round 3 (2026-11-14): a percent-encoded private name in a task was split at the `%`
  // and its pieces sent: `2fvault-core` reached OSV.dev and npm.
  it.each([
    ["install %40acme%2Fui version 1.0.0", "@acme/ui"],
    ["install %40acme%2Fvault-core version 2.0.0", "@acme/vault-core"],
    ["upgrade @acme%2Fvault-core to 2.0.0", "@acme/vault-core"],
    ["upgrade @acme%2fui to 2.0.0", "@acme/ui"],
    ["add %40acme/ui 1.0.0", "@acme/ui"],
    ["upgrade @acme/vault​-core to 2.0.0", "@acme/vault-core"],
  ])("%s: read as %s, private, nothing about it sent", async (task, name) => {
    const live = npmProject();
    const db = testDb();
    try {
      const result = await executeWhatShouldIKnow(db, { task }, live);
      expect(sent.filter((s) => /acme|2fui|2fvault|vault-core|40acme/i.test(s))).toEqual([]);
      expect(result.private_dependencies?.map((p) => p.package)).toContain(name);
      expect(result.delegation_assessment.level).not.toBe("safe_to_delegate");
    } finally {
      db.close();
    }
  });

  it("a private name the project does not install yet is recognised by the rules", async () => {
    const live = npmProject();
    const db = testDb();
    try {
      const result = await executeWhatShouldIKnow(db, { task: "bump @acme/ledger-sdk to 3.1.0" }, live);
      expect(result.private_dependencies?.map((p) => p.package)).toEqual(["@acme/ledger-sdk"]);
      expect(result.delegation_assessment.level).not.toBe("safe_to_delegate");
      expect(mentions("ledger-sdk")).toEqual([]);
    } finally {
      db.close();
    }
  });
});

describe("S4: a private index named in a requirements file, or in pip's configuration", () => {
  it.each([
    ["--index-url", "--index-url https://pypi.corp-secret.example/simple\nomega-internal-risk==3.1.0\n"],
    ["-i", "-i https://pypi.corp-secret.example/simple\nomega-internal-risk==3.1.0\n"],
    ["--index-url=", "--index-url=https://pypi.corp-secret.example/simple\nomega-internal-risk==3.1.0\n"],
  ])("%s: every pin of that file is private and never sent", async (_, requirements) => {
    write("requirements.txt", requirements);
    const live = liveFor(scratch);
    await live.scanVulnerabilities(scratch, { includeDev: true });
    const check = await executeDependencyCheck(null, { items: [{ ecosystem: "PyPI", package: "omega-internal-risk", to: "3.2.0" }] }, live);
    expect(check.results[0].verdict).toBe("unknown");
    expect(mentions("omega-internal-risk")).toEqual([]);
  });

  it("--extra-index-url: pip still consults pypi.org for every name, so names stay public, and the answer says so", async () => {
    write("requirements.txt", "--extra-index-url https://pypi.corp-secret.example/simple\nrequests==2.32.3\n");
    const live = liveFor(scratch);
    const scan = await live.scanVulnerabilities(scratch, { includeDev: true });
    expect(mentions("requests").length).toBeGreaterThan(0);
    expect(scan.registryNotice).toContain("pip also installs from https://pypi.corp-secret.example/simple (an extra index)");
    expect(scan.registryNotice).toContain("FOURDA_PRIVATE_PACKAGES");
  });

  it("PIP_INDEX_URL and pip.conf name the index for every requirements file", async () => {
    write("requirements.txt", "omega-internal-risk==3.1.0\n");
    const prior = process.env.PIP_INDEX_URL;
    process.env.PIP_INDEX_URL = "https://pypi.corp-secret.example/simple";
    try {
      const live = liveFor(scratch);
      await live.scanVulnerabilities(scratch, { includeDev: true });
      expect(mentions("omega-internal-risk")).toEqual([]);
    } finally {
      if (prior === undefined) delete process.env.PIP_INDEX_URL;
      else process.env.PIP_INDEX_URL = prior;
    }
    const conf = path.join(scratch, "pip.conf");
    fs.writeFileSync(conf, "[global]\nindex-url = https://pypi.corp-secret.example/simple\n");
    const priorConf = process.env.PIP_CONFIG_FILE;
    process.env.PIP_CONFIG_FILE = conf;
    sent = [];
    try {
      const live = liveFor(scratch);
      await live.scanVulnerabilities(scratch, { includeDev: true });
      expect(mentions("omega-internal-risk")).toEqual([]);
    } finally {
      if (priorConf === undefined) delete process.env.PIP_CONFIG_FILE;
      else process.env.PIP_CONFIG_FILE = priorConf;
    }
  });

  it("a public --index-url changes nothing", async () => {
    write("requirements.txt", "--index-url https://pypi.org/simple\nrequests==2.32.3\n");
    const live = liveFor(scratch);
    await live.scanVulnerabilities(scratch, { includeDev: true });
    expect(mentions("requests").length).toBeGreaterThan(0);
  });
});

describe("blind audit 2026-11-14: a private name in any spelling, under any guessed ecosystem", () => {
  /** web/: an npm project installing acme-zeta-hidden from a private registry; api/: a Python service. */
  function monorepo() {
    write("web/package.json", JSON.stringify({ name: "web", dependencies: { "acme-zeta-hidden": "1.0.0", lodash: "4.17.21" } }));
    write(
      "web/package-lock.json",
      JSON.stringify({
        name: "web",
        lockfileVersion: 3,
        packages: {
          "": { name: "web", dependencies: { "acme-zeta-hidden": "1.0.0", lodash: "4.17.21" } },
          "node_modules/acme-zeta-hidden": { version: "1.0.0", resolved: "https://npm.acme.dev/acme-zeta-hidden/-/acme-zeta-hidden-1.0.0.tgz" },
          "node_modules/lodash": { version: "4.17.21", resolved: "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz" },
        },
      }),
    );
    write("api/requirements.txt", "requests==2.32.3\n");
    return liveFor(scratch);
  }

  it.each(["pip install requests and add the acme-zeta-hidden package", "upgrade lodash and add the acme-zeta-hidden package to the python service"])(
    "F1: %s: the private npm name is never sent under a guessed PyPI",
    async (task) => {
      const live = monorepo();
      const db = new FourDADatabase(path.join(scratch, "standalone.db"));
      try {
        const result = await executeWhatShouldIKnow(db, { task }, live);
        expect(mentions("acme-zeta-hidden")).toEqual([]);
        expect(result.delegation_assessment.level).not.toBe("safe_to_delegate");
      } finally {
        db.close();
      }
    },
  );

  it.each([
    ["npm", "npm:acme-zeta-hidden"],
    ["npm", "acme-zeta-hidden@1.0.0"],
    ["npm", "acme-zeta-hidden​"],
    ["npm", "%61cme-zeta-hidden"],
    ["npm", "https://npm.acme.dev/acme-zeta-hidden"],
    ["npm", "ACME-ZETA-HIDDEN"],
  ])("F2: dependency_check %s %s: refused, never sent", async (ecosystem, pkg) => {
    const live = monorepo();
    const check = await executeDependencyCheck(null, { items: [{ ecosystem, package: pkg, to: "1.0.1" }] }, live);
    expect(check.results[0].verdict).not.toBe("proceed");
    expect(mentions("acme-zeta-hidden")).toEqual([]);
    expect(mentions("acme.dev")).toEqual([]);
  });

  it.each(["omega-internal-risk[extra]", "omega-internal-risk==3.2.0", "Omega_Internal.Risk"])("F2: PyPI %s: refused, never sent", async (pkg) => {
    write("requirements.txt", "--index-url https://pypi.corp-secret.example/simple\nomega-internal-risk==3.1.0\n");
    const live = liveFor(scratch);
    const check = await executeDependencyCheck(null, { items: [{ ecosystem: "PyPI", package: pkg, to: "3.2.0" }] }, live);
    expect(check.results[0].verdict).not.toBe("proceed");
    expect(mentions("omega")).toEqual([]);
  });

  it("F2: a Go module under GOPRIVATE written with a capitalised host is refused, never sent", async () => {
    write("go.mod", "module example.com/app\n\ngo 1.22\n\nrequire git.acme.dev/team/secretmod v1.0.0\n");
    write("go.sum", "git.acme.dev/team/secretmod v1.0.0 h1:AAAA=\ngit.acme.dev/team/secretmod v1.0.0/go.mod h1:BBBB=\n");
    const prior = process.env.GOPRIVATE;
    process.env.GOPRIVATE = "git.acme.dev/*";
    try {
      const live = liveFor(scratch);
      const check = await executeDependencyCheck(null, { items: [{ ecosystem: "Go", package: "Git.Acme.Dev/team/secretmod", to: "v1.1.0" }] }, live);
      expect(check.results[0].verdict).not.toBe("proceed");
      expect(mentions("secretmod")).toEqual([]);
    } finally {
      if (prior === undefined) delete process.env.GOPRIVATE;
      else process.env.GOPRIVATE = prior;
    }
  });

  it("F3: deciding privacy is linear: 40,000 names against a 40,000-dependency lockfile in well under the old 34 s", () => {
    const N = 40_000;
    const packages: Record<string, unknown> = {
      "": { name: "big", dependencies: { "acme-zeta-hidden": "1.0.0" } },
      "node_modules/acme-zeta-hidden": { version: "1.0.0", resolved: "https://npm.acme.dev/acme-zeta-hidden/-/acme-zeta-hidden-1.0.0.tgz" },
    };
    for (let i = 0; i < N; i++) packages[`node_modules/pkg-${i}`] = { version: "1.0.0", resolved: `https://registry.npmjs.org/pkg-${i}/-/pkg-${i}-1.0.0.tgz` };
    write("package.json", JSON.stringify({ name: "big", dependencies: { "acme-zeta-hidden": "1.0.0" } }));
    write("package-lock.json", JSON.stringify({ name: "big", lockfileVersion: 3, packages }));
    const live = liveFor(scratch);
    const start = performance.now();
    let wrong = 0;
    for (let i = 0; i < N; i++) if (live.privateReason("npm", `pkg-${i}`)) wrong++;
    // 72 ms measured locally; quadratic (main 9a6d48e) took 7.8 s at half this size.
    expect(performance.now() - start).toBeLessThan(3_000);
    expect(wrong).toBe(0);
    expect(live.privateReason("npm", "acme-zeta-hidden@1.0.0")).not.toBeNull();
  });

  it("a public name in an alias form is still looked up: the forms only refuse what is private", async () => {
    const live = monorepo();
    await executeDependencyCheck(null, { items: [{ ecosystem: "npm", package: "lodash@4.17.21", to: "4.17.21" }] }, live);
    expect(mentions("lodash").length).toBeGreaterThan(0);
  });
});
