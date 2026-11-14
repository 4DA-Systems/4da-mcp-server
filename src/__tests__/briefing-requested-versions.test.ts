// SPDX-License-Identifier: Apache-2.0
/**
 * what_should_i_know judges the version a task names (black-box re-run of 96c16d2, 2026-11-14):
 * "add lodash 4.17.20 to package.json" came back safe_to_delegate with lodash judged at latest,
 * and "pin axios to 0.21.1" did not see axios at all.
 */
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import Database from "better-sqlite3";
import { FourDADatabase } from "../db.js";
import { LiveIntelligence } from "../live/index.js";
import { executeWhatShouldIKnow } from "../tools/what-should-i-know.js";
import { detectRequestedVersions } from "../tools/briefing-requested-versions.js";
import type { ResolvedDependency } from "../live/types.js";

const NOW = new Date("2026-11-14T00:00:00Z");
const day = (n: number) => new Date(NOW.getTime() - n * 86_400_000).toISOString();

/** A full npm packument with these releases, all old enough to be past the hold. */
function packument(name: string, versions: string[], latest: string) {
  return {
    name,
    "dist-tags": { latest },
    time: Object.fromEntries([["created", day(4000)], ...versions.map((v, i) => [v, day(2000 - i)])]),
    versions: Object.fromEntries(versions.map((v) => [v, { name, version: v, dependencies: {}, dist: { tarball: `https://registry.npmjs.org/${name}/-/${name}-${v}.tgz` } }])),
  };
}

const ADVISORIES: Record<string, { id: string; fixed: string; vulnerable: string[] }> = {
  lodash: { id: "GHSA-test-lodash", fixed: "4.17.21", vulnerable: ["4.17.20"] },
  axios: { id: "GHSA-test-axios", fixed: "0.21.2", vulnerable: ["0.21.1"] },
  // The flatmap-stream compromise (GHSA-mh6f-8j2x-4483): critical.
  "event-stream": { id: "GHSA-test-event-stream", fixed: "4.0.0", vulnerable: ["3.3.6"] },
};
const record = (name: string) => ({
  id: ADVISORIES[name].id,
  modified: "2026-01-01T00:00:00Z",
  summary: `${name} prototype pollution`,
  database_specific: { severity: name === "event-stream" ? "CRITICAL" : "HIGH" },
  affected: [{ package: { ecosystem: "npm", name }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: ADVISORIES[name].fixed }] }] }],
});

let scratch: string;
let priorOffline: string | undefined;
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

beforeAll(() => {
  priorOffline = process.env.FOURDA_OFFLINE;
  delete process.env.FOURDA_OFFLINE;
});
afterAll(() => {
  if (priorOffline === undefined) delete process.env.FOURDA_OFFLINE;
  else process.env.FOURDA_OFFLINE = priorOffline;
});
beforeEach(() => {
  scratch = fs.mkdtempSync(path.join(os.tmpdir(), "4da-requested-"));
  const docs: Record<string, unknown> = {
    lodash: packument("lodash", ["4.17.20", "4.17.21", "4.18.1"], "4.18.1"),
    axios: packument("axios", ["0.21.1", "0.21.2", "1.6.0"], "1.6.0"),
    "event-stream": packument("event-stream", ["3.3.4", "3.3.6", "4.0.0", "4.0.1"], "4.0.1"),
  };
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init?: RequestInit) => {
      const u = new URL(url);
      const body = typeof init?.body === "string" ? init.body : "";
      if (u.hostname === "registry.npmjs.org") {
        const doc = docs[decodeURIComponent(u.pathname.slice(1))];
        return doc ? json(doc) : json({ error: "Not found" }, 404);
      }
      if (u.hostname === "api.osv.dev" && u.pathname === "/v1/querybatch") {
        const { queries } = JSON.parse(body) as { queries: Array<{ package: { name: string }; version: string }> };
        return json({
          results: queries.map((q) => ({ vulns: ADVISORIES[q.package.name]?.vulnerable.includes(q.version) ? [{ id: ADVISORIES[q.package.name].id, modified: "2026-01-01T00:00:00Z" }] : [] })),
        });
      }
      if (u.hostname === "api.osv.dev" && u.pathname.startsWith("/v1/vulns/")) {
        const name = Object.keys(ADVISORIES).find((n) => u.pathname.endsWith(ADVISORIES[n].id));
        return name ? json(record(name)) : json({}, 404);
      }
      if (u.hostname === "api.osv.dev" && u.pathname === "/v1/query") {
        const q = JSON.parse(body) as { package?: { name?: string } };
        return json({ vulns: q.package?.name && ADVISORIES[q.package.name] ? [record(q.package.name)] : [] });
      }
      if (u.hostname === "api.npmjs.org") return json({});
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

function project(deps: Record<string, string>) {
  fs.writeFileSync(path.join(scratch, "package.json"), JSON.stringify({ name: "app", dependencies: deps }));
  fs.writeFileSync(
    path.join(scratch, "package-lock.json"),
    JSON.stringify({
      name: "app",
      lockfileVersion: 3,
      packages: { "": { name: "app", dependencies: deps }, ...Object.fromEntries(Object.entries(deps).map(([n, v]) => [`node_modules/${n}`, { version: v }])) },
    }),
  );
  const live = new LiveIntelligence(new Database(":memory:"));
  live.initFromProject(scratch, Object.keys(deps), [], "javascript");
  return live;
}

async function brief(task: string, deps: Record<string, string>) {
  const live = project(deps);
  const db = new FourDADatabase(path.join(scratch, "standalone.db"));
  try {
    return await executeWhatShouldIKnow(db, { task }, live);
  } finally {
    db.close();
  }
}

describe("the version a task names is judged, at that version", () => {
  it('"add lodash 4.17.20 to package.json": 4.17.20 is avoid, and the task is not safe to delegate', async () => {
    const result = await brief("add lodash 4.17.20 to package.json", { react: "18.2.0" });
    const lodash = result.requested_versions?.find((r) => r.name === "lodash");
    expect(lodash).toMatchObject({ to: "4.17.20", verdict: "avoid" });
    expect(result.delegation_assessment.level).not.toBe("safe_to_delegate");
    expect(result.delegation_assessment.reason).toContain("lodash 4.17.20 is avoid");
  });

  it('"add github.com/gin-gonic/gin/ v1.6.0": a Go path the go command would not accept is never safe to delegate (audit B1)', async () => {
    const result = await brief("add github.com/gin-gonic/gin/ v1.6.0", { react: "18.2.0" });
    expect(result.delegation_assessment.level).not.toBe("safe_to_delegate");
    const gin = result.requested_versions?.find((r) => r.name.startsWith("github.com/gin-gonic/gin"));
    expect(gin).toMatchObject({ ecosystem: "Go", to: "v1.6.0", verdict: "unknown" });
    expect(gin?.reason).toMatch(/not a Go module path the go command accepts as written .* Check `github\.com\/gin-gonic\/gin` instead/);
  });

  it('"pin axios to 0.21.1": axios is seen, 0.21.1 is avoid', async () => {
    const result = await brief("pin axios to 0.21.1", { react: "18.2.0" });
    expect(result.requested_versions?.find((r) => r.name === "axios")).toMatchObject({ to: "0.21.1", verdict: "avoid" });
    expect(result.delegation_assessment.level).not.toBe("safe_to_delegate");
  });

  it.each(["add event-stream version 3.3.6", "install event-stream 3.3.6"])(
    '"%s": a release a critical advisory affects is a human call, never delegated (blind audit 2026-11-14, F4)',
    async (task) => {
      const result = await brief(task, { react: "18.2.0" });
      expect(result.requested_versions?.find((r) => r.name === "event-stream")).toMatchObject({ to: "3.3.6", verdict: "avoid", critical: ["GHSA-test-event-stream"] });
      expect(result.delegation_assessment.level).toBe("human_only");
      expect(result.delegation_assessment.reason).toContain("GHSA-test-event-stream");
    },
  );

  it('"upgrade lodash to 4.17.21" from an installed 4.17.20: judged as that move, and it clears', async () => {
    const result = await brief("upgrade lodash to 4.17.21", { lodash: "4.17.20" });
    expect(result.requested_versions?.find((r) => r.name === "lodash")).toMatchObject({ to: "4.17.21", from: "4.17.20", verdict: "proceed" });
  });
});

describe("the forms a task names a version in", () => {
  const dep = (name: string, version: string, ecosystem: ResolvedDependency["ecosystem"] = "npm") =>
    ({ name, version, ecosystem, isDev: false, isDirect: true, devScopeKnown: true, target: null, platformActive: true, sourceDirs: [] }) as ResolvedDependency;

  it.each([
    ["npm install lodash@4.17.20", [], { name: "lodash", ecosystem: "npm", to: "4.17.20" }],
    ["add @types/node@^20.1.0", [], { name: "@types/node", ecosystem: "npm", to: "^20.1.0" }],
    ["pip install Django==3.2.0", [], { name: "Django", ecosystem: "PyPI", to: "3.2.0" }],
    ["require requests>=2.31 in requirements.txt", [], { name: "requests", ecosystem: "PyPI", to: ">=2.31" }],
    ["bump axios from 0.21.1 to 1.6.0", [dep("axios", "0.21.1")], { name: "axios", ecosystem: "npm", to: "1.6.0", from: "0.21.1" }],
    ["pin serde 1.0.200 in Cargo.toml", [dep("serde", "1.0.150", "crates.io")], { name: "serde", ecosystem: "crates.io", to: "1.0.200", from: "1.0.150" }],
    ["go get golang.org/x/net@v0.23.0", [], { name: "golang.org/x/net", ecosystem: "Go", to: "v0.23.0" }],
    // blind audit 2026-11-14, F4: "version X" wording was not read, and latest was judged instead.
    ["add event-stream version 3.3.6", [], { name: "event-stream", ecosystem: "npm", to: "3.3.6" }],
    ["Add the package `event-stream` version 3.3.6 to package.json", [], { name: "event-stream", ecosystem: "npm", to: "3.3.6" }],
    ["set lodash version to 4.17.20", [dep("lodash", "4.17.21")], { name: "lodash", ecosystem: "npm", to: "4.17.20", from: "4.17.21" }],
    ["use version 4.17.20 of lodash", [], { name: "lodash", ecosystem: "npm", to: "4.17.20" }],
  ])("%s", (task, deps, expected) => {
    expect(detectRequestedVersions(task, deps as ResolvedDependency[])[0]).toEqual(expected);
  });

  it("names no version: nothing is requested", () => {
    expect(detectRequestedVersions("upgrade lodash to the latest release", [dep("lodash", "4.17.20")])).toEqual([]);
    expect(detectRequestedVersions("upgrade to node 20 and fix the tests", [])).toEqual([]);
  });
});
