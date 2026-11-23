// SPDX-License-Identifier: Apache-2.0
/**
 * A package-lock v1 records a dependency installed from a tarball URL with the URL as its
 * `version`. One on a registry-shaped path (`/<name>/-/<name>-<v>.tgz`) on a host that is not the
 * public registry vanished from every answer, which read complete and clean (jitsi-meet's
 * @matrix-org/olm from gitlab.matrix.org), while the same dependency in a v3 lockfile reads
 * "NOT CHECKED (private)". v1 now says the same as v3.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import Database from "better-sqlite3";
import { LiveIntelligence } from "../live/index.js";
import { readPackageLock } from "../live/lockfile-parsers.js";
import { executeVulnerabilityScan } from "../tools/vulnerability-scan.js";

const OLM = "https://gitlab.matrix.org/api/v4/projects/27/packages/npm/@matrix-org/olm/-/@matrix-org/olm-3.2.3.tgz";

describe("a1123 discovery: a package-lock v1 dependency whose version is a tarball URL", () => {
  let dir: string;
  let priorOffline: string | undefined;
  let asked: string[];

  beforeEach(() => {
    priorOffline = process.env.FOURDA_OFFLINE;
    delete process.env.FOURDA_OFFLINE;
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "4da-a1123-v1url-"));
    asked = [];
    vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/v1/querybatch")) {
        const { queries } = JSON.parse(String(init?.body)) as { queries: Array<{ package: { name: string }; version?: string }> };
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

  const v1 = (deps: Record<string, Record<string, unknown>>) => JSON.stringify({ name: "repro", version: "0.0.0", lockfileVersion: 1, requires: true, dependencies: deps });
  const v3 = (deps: Record<string, Record<string, unknown>>) =>
    JSON.stringify({
      name: "repro",
      lockfileVersion: 3,
      packages: { "": { name: "repro", dependencies: Object.fromEntries(Object.keys(deps).map((n) => [n, "*"])) }, ...Object.fromEntries(Object.entries(deps).map(([n, e]) => [`node_modules/${n}`, e])) },
    });
  const ms = { version: "2.1.3", resolved: "https://registry.npmjs.org/ms/-/ms-2.1.3.tgz", integrity: "sha512-x" };
  const scan = async () => (await executeVulnerabilityScan(null, { project_path: dir, force_refresh: true }, new LiveIntelligence(new Database(":memory:")))) as Record<string, any>;

  it("the reader keeps it: the release its tarball names, never a silent drop", () => {
    const read = readPackageLock(JSON.parse(v1({ "@matrix-org/olm": { version: OLM, integrity: "sha512-o" }, ms })));
    expect(read.instances.toArray()).toEqual(expect.arrayContaining([{ name: "@matrix-org/olm", version: "3.2.3", dev: false }]));
    // A registry-shaped URL whose file does not name the package's release is not checkable, and is listed.
    const odd = readPackageLock(JSON.parse(v1({ odd: { version: "https://pkgs.example.com/odd/-/something-else.tgz" } })));
    expect(odd.uncheckable).toEqual([{ name: "odd", version: null, kind: "url" }]);
  });

  it("v1 and v3 give the same answer: NOT CHECKED (private), and the name is never sent", async () => {
    const answers: Array<Record<string, any>> = [];
    for (const lock of [v1({ "@matrix-org/olm": { version: OLM, integrity: "sha512-o" }, ms }), v3({ "@matrix-org/olm": { version: "3.2.3", resolved: OLM, integrity: "sha512-o" }, ms })]) {
      fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ name: "repro", dependencies: { "@matrix-org/olm": OLM, ms: "2.1.3" } }));
      fs.writeFileSync(path.join(dir, "package-lock.json"), lock);
      asked = [];
      const result = await scan();
      expect(asked).toEqual(["ms@2.1.3"]);
      answers.push(result);
    }
    for (const result of answers) {
      expect(result.summary).toMatch(/^NOT CHECKED \(private\): 1 dependency is private \(@matrix-org\/olm\)/);
      expect(result.coverage).toMatchObject({ complete: false, private_dependencies: 1 });
    }
  });

  it("a v1 tarball URL on the public registry is the registry release it names, and is checked", () => {
    const read = readPackageLock(JSON.parse(v1({ "left-pad": { version: "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz" } })));
    expect(read.instances.toArray()).toEqual([{ name: "left-pad", version: "1.3.0", dev: false }]);
    expect(read.versions.get("left-pad")).toBe("1.3.0");
  });
});
