// SPDX-License-Identifier: Apache-2.0
/**
 * Round-9 blind check of the 6.3.0 candidate (B1): in a project whose every dependency comes from a
 * private index or registry, a briefing task naming a new package with no ecosystem ("add zqxpy-new")
 * guessed npm (the public dependency list it counted was empty) and sent the name to OSV.dev and
 * registry.npmjs.org. The guessed ecosystem now counts the private dependencies, and a name looked
 * up under a non-public registry is private: said so, never sent. Every request is recorded by a
 * stubbed fetch: nothing leaves the process.
 */
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import Database from "better-sqlite3";
import { FourDADatabase } from "../db.js";
import { LiveIntelligence } from "../live/index.js";
import { scanProjectTree, treeResolutionGroups } from "../project-tree.js";
import { executeWhatShouldIKnow } from "../tools/what-should-i-know.js";
import { clearLiveIntelligence } from "../live-singleton.js";
import { waitingWords } from "./helpers/a1127-task-packages.js";

let scratch: string;
let sent: string[];
let priorOffline: string | undefined;

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
const write = (rel: string, content: string) => {
  fs.mkdirSync(path.dirname(path.join(scratch, rel)), { recursive: true });
  fs.writeFileSync(path.join(scratch, rel), content);
};
const leaks = (needle: RegExp) => sent.filter((s) => needle.test(s));
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
  delete process.env.FOURDA_OFFLINE;
});
afterAll(() => {
  if (priorOffline === undefined) delete process.env.FOURDA_OFFLINE;
  else process.env.FOURDA_OFFLINE = priorOffline;
});
beforeEach(() => {
  scratch = fs.mkdtempSync(path.join(os.tmpdir(), "4da-private-r9-"));
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
  clearLiveIntelligence();
  try {
    fs.rmSync(scratch, { recursive: true, force: true });
  } catch {
    // Windows: left for the OS temp cleaner.
  }
});

const brief = async (task: string) => {
  const live = liveFor(scratch);
  return executeWhatShouldIKnow(memoryDb(), { task }, live);
};

describe("a guessed name in a project whose registries are all private (r9 B1)", () => {
  const python = () => write("requirements.txt", "--index-url https://pypi.zq.internal/simple\nzqxpy-core==1.0.0\nrequests==2.32.3\n");

  for (const task of ["add zqxpy-new", "use zqxpy-new for parsing", "add zqxpy-new==1.0", "add zqxpy_new"]) {
    it(`Python behind a private index: "${task}" sends nothing`, async () => {
      python();
      const result = await brief(task);
      expect(leaks(/zqxpy[-_]new/i)).toEqual([]);
      expect(JSON.stringify(result)).toMatch(/NOT CHECKED \(private\)/);
      expect(result.delegation_assessment.level).not.toBe("safe_to_delegate");
    });
  }

  it("Cargo with crates.io replaced by a private registry: \"add zqx-newcrate\" sends nothing", async () => {
    write(".cargo/config.toml", '[source.crates-io]\nreplace-with = "zq"\n\n[source.zq]\nregistry = "sparse+https://cargo.zq.internal/"\n');
    write("Cargo.toml", '[package]\nname = "app"\nversion = "0.1.0"\nedition = "2021"\n\n[dependencies]\nserde = "1"\n');
    write(
      "Cargo.lock",
      'version = 3\n\n[[package]]\nname = "app"\nversion = "0.1.0"\ndependencies = ["serde"]\n\n[[package]]\nname = "serde"\nversion = "1.0.200"\nsource = "sparse+https://cargo.zq.internal/"\n',
    );
    const result = await brief("add zqx-newcrate");
    expect(leaks(/zqx-newcrate/i)).toEqual([]);
    expect(JSON.stringify(result)).toMatch(/NOT CHECKED \(private\)/);
  });

  it("PIP_INDEX_URL naming a private index (the blind check's layout): \"add zqxpy-new\" sends nothing", async () => {
    const prior = process.env.PIP_INDEX_URL;
    process.env.PIP_INDEX_URL = "https://pypi.zq.internal/simple";
    try {
      write("requirements.txt", "zqxpy-core==1.0.0\nrequests==2.32.3\n");
      const result = await brief("add zqxpy-new");
      expect(leaks(/zqxpy[-_]new/i)).toEqual([]);
      expect(JSON.stringify(result)).toMatch(/NOT CHECKED \(private\)/);
    } finally {
      if (prior === undefined) delete process.env.PIP_INDEX_URL;
      else process.env.PIP_INDEX_URL = prior;
    }
  });

  it("a task that names the ecosystem: \"add zqxpy-new to requirements.txt\" sends nothing", async () => {
    python();
    const result = await brief("add zqxpy-new to requirements.txt");
    expect(leaks(/zqxpy[-_]new/i)).toEqual([]);
    expect(JSON.stringify(result)).toMatch(/NOT CHECKED \(private\)/);
  });

  it("public npm beside a private Python index: a new npm name is still checked, under npm only", async () => {
    python();
    const deps = { lodash: "4.17.21", express: "4.21.2" };
    write("package.json", JSON.stringify({ name: "app", dependencies: deps }));
    write(
      "package-lock.json",
      JSON.stringify({
        lockfileVersion: 3,
        packages: {
          "": { name: "app", dependencies: deps },
          "node_modules/lodash": { version: "4.17.21", resolved: "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz" },
          "node_modules/express": { version: "4.21.2", resolved: "https://registry.npmjs.org/express/-/express-4.21.2.tgz" },
        },
      }),
    );
    // Final design of the 2026-11-25 fixes: left-pad is on no bundled list: listed as npm's only.
    const r = await brief("npm install left-pad");
    expect(waitingWords(r)).toEqual([{ word: "left-pad", read_as: "npm" }]);
    expect(leaks(/left-pad/).filter((x) => /PyPI|pypi\.org/.test(x))).toEqual([]);
  });

  it("an ordinary npm project still checks a new package (no over-blocking)", async () => {
    const deps = { lodash: "4.17.21" };
    write("package.json", JSON.stringify({ name: "app", dependencies: deps }));
    write(
      "package-lock.json",
      JSON.stringify({
        lockfileVersion: 3,
        packages: { "": { name: "app", dependencies: deps }, "node_modules/lodash": { version: "4.17.21", resolved: "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz" } },
      }),
    );
    // Final design: a new name on no bundled list is handed back for dependency_check, never called private.
    const result = await brief("npm install left-pad");
    expect(JSON.stringify(result)).toMatch(/"name":"left-pad"/);
    expect(JSON.stringify(result)).not.toMatch(/NOT CHECKED \(private\)/);
  });
});
