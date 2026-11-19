// SPDX-License-Identifier: Apache-2.0
/**
 * A PEP 440 prefix match (`==2.32.*`) names a series of releases, not one: it
 * is listed as unpinned, never read as a version, and never sent to OSV.dev
 * (which would answer with every advisory it holds for the package).
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import Database from "better-sqlite3";
import { exactClause, parseRequirements, resolvePython, unpinnedRequirements } from "../live/lockfile-parsers-pygo.js";
import { LiveIntelligence } from "../live/index.js";
import { executeVulnerabilityScan } from "../tools/vulnerability-scan.js";

let dir: string;
let priorOffline: string | undefined;
let asked: string[];
const write = (rel: string, content: string) => fs.writeFileSync(path.join(dir, rel), content);

beforeEach(() => {
  priorOffline = process.env.FOURDA_OFFLINE;
  delete process.env.FOURDA_OFFLINE;
  dir = fs.mkdtempSync(path.join(os.tmpdir(), "a1119-wildcard-"));
  asked = [];
  vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
    const url = String(input);
    if (url.endsWith("/v1/querybatch")) {
      const { queries } = JSON.parse(String(init?.body)) as { queries: Array<{ package: { name: string }; version: string }> };
      for (const q of queries) asked.push(`${q.package.name}@${q.version}`);
      return new Response(JSON.stringify({ results: queries.map(() => ({})) }), { status: 200 });
    }
    throw new TypeError(`fetch failed (${url})`);
  });
});
afterEach(() => {
  vi.unstubAllGlobals();
  if (priorOffline === undefined) delete process.env.FOURDA_OFFLINE;
  else process.env.FOURDA_OFFLINE = priorOffline;
  fs.rmSync(dir, { recursive: true, force: true });
});

describe("a prefix-match pin is not an exact pin", () => {
  it("exactClause reads no version from a clause with a wildcard", () => {
    expect(exactClause("==2.32.*")).toBeNull();
    expect(exactClause(">=4.2,==4.2.*")).toBeNull();
    expect(exactClause("===1.0.*")).toBeNull();
    expect(exactClause("==4.2.*,==4.2.7")).toBe("4.2.7");
    expect(exactClause("==4.2.7")).toBe("4.2.7");
  });

  it("requirements.txt: listed as unpinned, not as a pin", () => {
    const text = "django==4.2.*\nflask>=2,==2.3.*\nrequests==2.31.0\n";
    expect(parseRequirements(text)).toEqual([{ name: "requests", version: "2.31.0" }]);
    expect(unpinnedRequirements(text).names.sort()).toEqual(["django", "flask"]);
  });

  it("pyproject.toml with no lockfile: listed as unpinned, not as a pin", () => {
    write("pyproject.toml", '[project]\nname = "fx"\nversion = "0.1.0"\ndependencies = ["requests==2.32.*", "idna==3.7"]\n');
    const read = resolvePython(dir);
    expect(read.instances).toEqual([{ name: "idna", version: "3.7" }]);
    expect(read.unpinned).toEqual([{ file: path.join(dir, "pyproject.toml"), names: ["requests"] }]);
  });

  it("the scan never sends the wildcard as a version", async () => {
    write("requirements.txt", "django==4.2.*\nidna==3.7\n");
    const result = (await executeVulnerabilityScan(null, { project_path: dir, response_format: "detailed", force_refresh: true }, new LiveIntelligence(new Database(":memory:")))) as Record<string, any>;
    expect(asked).toEqual(["idna@3.7"]);
    expect(JSON.stringify(result)).not.toContain("4.2.*");
    expect(result.coverage.unpinned_requirements).toEqual([{ file: "requirements.txt", count: 1, names: ["django"] }]);
  });
});
