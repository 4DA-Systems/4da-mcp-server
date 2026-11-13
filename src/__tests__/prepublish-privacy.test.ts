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
