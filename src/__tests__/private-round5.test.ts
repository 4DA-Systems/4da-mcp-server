// SPDX-License-Identifier: Apache-2.0
/**
 * Blind audit round 5 (pre-publish, main a3c873e): private names that still left the machine.
 *
 * 1. Full-width characters in a briefing task (`＠zqxacme／vault-core`, `ｚｑｘ-omega-internal`) were
 *    tokenised as ASCII fragments: `zqxacme` and `omega-internal` reached OSV.dev and npm. And a bare
 *    scope (`zqxacme` for the private `@zqxacme/*`) passed the request guard.
 * 2. A mis-cased GOPRIVATE module (`github.com/Zqxcorp/Other` under `github.com/zqxcorp`) was not
 *    excluded by the scanner, the guard refused the whole OSV batch, and every public dependency
 *    came back NOT CHECKED with "OSV.dev unreachable".
 * 3. `{PyPI, ZQX_OMEGA_INTERNAL}` and `{PyPI, zqx.omega.internal}` reached OSV.dev: PEP 503.
 * 4. A name one project's scan found private was later sent for another project.
 * 5. The briefing's private_dependencies said `npm` for a PyPI name.
 */
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import Database from "better-sqlite3";
import { FourDADatabase } from "../db.js";
import { LiveIntelligence } from "../live/index.js";
import { fetchWithTimeout } from "../live/http-utils.js";
import { nameForms, PrivateRequestRefused, readableText } from "../live/private-guard.js";
import { goPrivateMatch } from "../live/private-packages.js";
import { scanProjectTree, treeResolutionGroups } from "../project-tree.js";
import { executeDependencyCheck } from "../tools/dependency-check.js";
import { executeUpgradeImpact } from "../tools/upgrade-impact.js";
import { executeWhatShouldIKnow } from "../tools/what-should-i-know.js";
import { setLiveIntelligence } from "../live-singleton.js";

const noDb = null as unknown as FourDADatabase;
let scratch: string;
let sent: string[];
let priorOffline: string | undefined;
let priorGoPrivate: string | undefined;

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
  priorGoPrivate = process.env.GOPRIVATE;
  delete process.env.FOURDA_OFFLINE;
});

afterAll(() => {
  if (priorOffline === undefined) delete process.env.FOURDA_OFFLINE;
  else process.env.FOURDA_OFFLINE = priorOffline;
  if (priorGoPrivate === undefined) delete process.env.GOPRIVATE;
  else process.env.GOPRIVATE = priorGoPrivate;
});

beforeEach(() => {
  scratch = fs.mkdtempSync(path.join(os.tmpdir(), "4da-private-r5-"));
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
      return json({ error: "Not found" }, 404);
    }),
  );
});

afterEach(() => {
  vi.unstubAllGlobals();
  delete process.env.FOURDA_PRIVATE_PACKAGES;
  delete process.env.GOPRIVATE;
  setLiveIntelligence(null);
  try {
    fs.rmSync(scratch, { recursive: true, force: true });
  } catch {
    // Windows: left for the OS temp cleaner.
  }
});

/** `.npmrc` maps @zqxacme privately; the lockfile installs @zqxacme/vault-core and zqx-omega-internal from private hosts. */
function zqxProject(dir = "p"): string {
  write(`${dir}/.npmrc`, "@zqxacme:registry=https://npm.zqxacme.dev/\n");
  const deps = { "@zqxacme/vault-core": "1.0.0", "zqx-omega-internal": "1.0.0", "left-pad": "1.3.0" };
  write(`${dir}/package.json`, JSON.stringify({ name: "app", dependencies: deps }));
  write(
    `${dir}/package-lock.json`,
    JSON.stringify({
      lockfileVersion: 3,
      packages: {
        "": { name: "app", dependencies: deps },
        "node_modules/@zqxacme/vault-core": { version: "1.0.0", resolved: "https://npm.zqxacme.dev/@zqxacme/vault-core/-/vault-core-1.0.0.tgz" },
        "node_modules/zqx-omega-internal": { version: "1.0.0", resolved: "https://npm.zqxacme.dev/zqx-omega-internal/-/zqx-omega-internal-1.0.0.tgz" },
        "node_modules/left-pad": { version: "1.3.0", resolved: "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz" },
      },
    }),
  );
  return path.join(scratch, dir);
}

describe("r5-1: full-width characters in a briefing task", () => {
  it("readableText folds full-width letters and Unicode dashes to their ASCII forms", () => {
    expect(readableText("install ＠zqxacme／vault-core version 2.0.0")).toBe("install @zqxacme/vault-core version 2.0.0");
    expect(readableText("bump ｚｑｘ-omega-internal to 1.1.0")).toBe("bump zqx-omega-internal to 1.1.0");
    for (const dash of ["‐", "‑", "‒", "–", "—", "−", "﹘", "﹣", "－"]) {
      expect(readableText(`bump zqx${dash}omega to 1.0.0`)).toBe("bump zqx-omega to 1.0.0");
    }
  });

  for (const task of ["install ＠zqxacme／vault-core version 2.0.0", "npm install ＠zqxacme／vault-core", "bump ｚｑｘ-omega-internal to 1.1.0"]) {
    it(`what_should_i_know on ${JSON.stringify(task)} sends no part of a private name`, async () => {
      const live = liveFor(zqxProject());
      await executeWhatShouldIKnow(memoryDb(), { task }, live).catch(() => null);
      expect(mentions("zqx")).toEqual([]);
      expect(mentions("omega")).toEqual([]);
    });
  }

  it("the request guard refuses a bare private scope as a package name", async () => {
    const live = liveFor(zqxProject());
    expect(live.privateReason("npm", "zqxacme")).toMatch(/@zqxacme/);
    await expect(live.runInContext(() => fetchWithTimeout("https://registry.npmjs.org/zqxacme"))).rejects.toBeInstanceOf(PrivateRequestRefused);
    await expect(
      live.runInContext(() => fetchWithTimeout("https://api.osv.dev/v1/query", { method: "POST", body: JSON.stringify({ package: { ecosystem: "npm", name: "ZQXACME" }, version: "1.0.0" }) })),
    ).rejects.toBeInstanceOf(PrivateRequestRefused);
    // Without a project context too (the union of every registered project).
    await expect(fetchWithTimeout("https://registry.npmjs.org/zqxacme")).rejects.toBeInstanceOf(PrivateRequestRefused);
    expect(mentions("zqx")).toEqual([]);
  });

  it("the bare-scope rule blocks no public package: other names, and the bare name a project installs publicly", async () => {
    const live = liveFor(zqxProject());
    for (const name of ["left-pad", "zqxacme-cli", "acme", "omega-internal"]) expect(live.privateReason("npm", name)).toBeNull();
    // The short name of a private package is private since round 6 (`zqsecretlib` for the private
    // `@zqvault/zqsecretlib` reached npm and OSV.dev): `vault-core` names `@zqxacme/vault-core`.
    expect(live.privateReason("npm", "vault-core")).not.toBeNull();
    // A project that installs the unscoped `zqxacme` from the public registry asks about it.
    write("q/.npmrc", "@zqxacme:registry=https://npm.zqxacme.dev/\n");
    write("q/package.json", JSON.stringify({ name: "q", dependencies: { zqxacme: "2.0.0" } }));
    write(
      "q/package-lock.json",
      JSON.stringify({ lockfileVersion: 3, packages: { "": { name: "q" }, "node_modules/zqxacme": { version: "2.0.0", resolved: "https://registry.npmjs.org/zqxacme/-/zqxacme-2.0.0.tgz" } } }),
    );
    const q = liveFor(path.join(scratch, "q"));
    expect(q.privateReason("npm", "zqxacme")).toBeNull();
  });
});

describe("r5-2: a mis-cased GOPRIVATE module", () => {
  function goProject(): string {
    write("g/go.mod", "module example.com/app\n\ngo 1.22\n\nrequire (\n\tgithub.com/Zqxcorp/Other v1.0.0\n\tgolang.org/x/net v0.20.0\n)\n");
    write(
      "g/go.sum",
      [
        "github.com/Zqxcorp/Other v1.0.0 h1:fixture=",
        "github.com/Zqxcorp/Other v1.0.0/go.mod h1:fixture=",
        "golang.org/x/net v0.20.0 h1:fixture=",
        "golang.org/x/net v0.20.0/go.mod h1:fixture=",
        "",
      ].join("\n"),
    );
    return path.join(scratch, "g");
  }

  it("GOPRIVATE patterns match module paths case-insensitively", () => {
    expect(goPrivateMatch("github.com/zqxcorp", "github.com/Zqxcorp/Other")).toBe("github.com/zqxcorp");
    expect(goPrivateMatch("GitHub.com/ZQXcorp/*", "github.com/zqxcorp/other")).toBe("GitHub.com/ZQXcorp/*");
    expect(goPrivateMatch("github.com/zqxcorp", "github.com/zqxcorpx/other")).toBeNull();
  });

  it("the module is excluded as private up front; the public dependencies are checked, never 'unreachable'", async () => {
    process.env.GOPRIVATE = "github.com/zqxcorp";
    const dir = goProject();
    const live = liveFor(dir);
    const result = await live.scanVulnerabilities(dir);
    expect(result.offline).toBe(false);
    expect(result.unchecked ?? 0).toBe(0);
    expect(result.privateExcluded?.dependencies.map((d) => d.name)).toEqual(["github.com/Zqxcorp/Other"]);
    expect(mentions("golang.org/x/net").length).toBeGreaterThan(0);
    expect(mentions("zqxcorp")).toEqual([]);
  });
});

describe("r5-3: every PyPI spelling of a private name", () => {
  const spellings = ["ZQX_OMEGA_INTERNAL", "zqx.omega.internal", "Zqx__Omega-.Internal"];

  it("nameForms includes the PEP 503 form", () => {
    for (const s of spellings) expect(nameForms(s)).toContain("zqx-omega-internal");
  });

  for (const setup of ["npm lockfile", "uv source", "FOURDA_PRIVATE_PACKAGES"] as const) {
    for (const name of spellings) {
      it(`${setup}: {PyPI, ${name}} reaches neither OSV.dev nor pypi.org`, async () => {
        let dir: string;
        if (setup === "npm lockfile") dir = zqxProject();
        else if (setup === "uv source") {
          write(
            "u/pyproject.toml",
            '[project]\nname = "u"\nversion = "0.1.0"\ndependencies = ["zqx-omega-internal==1.0.0", "requests==2.31.0"]\n\n[tool.uv.sources]\nzqx-omega-internal = { index = "corp" }\n\n[[tool.uv.index]]\nname = "corp"\nurl = "https://pypi.zqx.example/simple"\n',
          );
          dir = path.join(scratch, "u");
        } else {
          process.env.FOURDA_PRIVATE_PACKAGES = "PyPI:zqx-omega-internal";
          write("l/requirements.txt", "requests==2.31.0\n");
          dir = path.join(scratch, "l");
        }
        const live = liveFor(dir);
        const result = await executeDependencyCheck(noDb, { items: [{ ecosystem: "PyPI", package: name, to: "1.1.0" }] }, live);
        expect(result.results[0].verdict).toBe("unknown");
        await expect(
          live.runInContext(() => fetchWithTimeout("https://api.osv.dev/v1/query", { method: "POST", body: JSON.stringify({ package: { ecosystem: "PyPI", name }, version: "1.0.0" }) })),
        ).rejects.toBeInstanceOf(PrivateRequestRefused);
        await expect(live.runInContext(() => fetchWithTimeout(`https://pypi.org/pypi/${name}/json`))).rejects.toBeInstanceOf(PrivateRequestRefused);
        expect(mentions("omega")).toEqual([]);
      });
    }
  }
});

describe("r5-4: a name found private stays private for the whole process", () => {
  it("upgrade_impact and dependency_check for another project never send a name p1's scan found private", async () => {
    write("s/package.json", JSON.stringify({ name: "s", dependencies: { "left-pad": "1.3.0" } }));
    const startup = liveFor(path.join(scratch, "s"));
    setLiveIntelligence(startup);
    // A later call for project_path p1 finds zqx-omega-internal private there.
    const p1 = liveFor(zqxProject("p1"));
    expect(p1.getPrivateDependencies().map((d) => d.name)).toContain("zqx-omega-internal");
    p1.dispose();

    const impact = await executeUpgradeImpact(noDb, { package: "zqx-omega-internal", ecosystem: "npm", from_version: "1.0.0", to_version: "2.0.0" } as never, startup);
    expect(impact.not_checked).toBe("private");
    const check = await executeDependencyCheck(noDb, { items: [{ ecosystem: "npm", package: "zqx-omega-internal", to: "1.1.0" }] }, startup);
    expect(check.results[0].verdict).toBe("unknown");
    await expect(startup.runInContext(() => fetchWithTimeout("https://registry.npmjs.org/zqx-omega-internal"))).rejects.toBeInstanceOf(PrivateRequestRefused);
    expect(mentions("omega")).toEqual([]);
  });

  it("another project's scan takes the name out and says why, and still checks its public dependencies", async () => {
    const p1 = liveFor(zqxProject("p1"));
    expect(p1.getPrivateDependencies().length).toBeGreaterThan(0);
    // Project b installs the same name, in another spelling, from pypi.org.
    write("b/requirements.txt", "zqx_omega_internal==1.0.0\nrequests==2.31.0\n");
    const b = liveFor(path.join(scratch, "b"));
    const result = await b.scanVulnerabilities(path.join(scratch, "b"));
    expect(result.offline).toBe(false);
    expect(mentions("requests").length).toBeGreaterThan(0);
    expect(mentions("omega")).toEqual([]);
    const excluded = result.privateExcluded?.dependencies ?? [];
    expect(excluded.map((d) => d.name.replace(/[-_.]+/g, "-"))).toEqual(["zqx-omega-internal"]);
    expect(excluded[0].ecosystem).toBe("PyPI");
    expect(excluded[0].why).toMatch(/private/);
  });
});

describe("r5-5: the briefing reports the ecosystem that makes a name private", () => {
  it("a PyPI-private name is listed as PyPI", async () => {
    process.env.FOURDA_PRIVATE_PACKAGES = "PyPI:zqx-omega-*";
    write("package.json", JSON.stringify({ name: "app", dependencies: { "left-pad": "1.3.0" } }));
    const live = liveFor(scratch);
    const result = await executeWhatShouldIKnow(memoryDb(), { task: "bump zqx-omega-internal to 1.1.0" }, live);
    const priv = result.private_dependencies ?? [];
    expect(priv.map((p) => [p.package, p.ecosystem])).toEqual([["zqx-omega-internal", "PyPI"]]);
    expect(mentions("omega")).toEqual([]);
  });
});
