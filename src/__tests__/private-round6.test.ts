// SPDX-License-Identifier: Apache-2.0
/**
 * Black-box audit of 60c9edc (round 6): dependency_check and upgrade_impact sent private package
 * names to the public registries and OSV.dev when the name came in a slightly decorated spelling,
 * while what_should_i_know refused every one of them. The request guard's name forms (nameForms)
 * stripped no quotes, brackets, separators or ports, and the short name of a private package
 * (`zqsecretlib` for `@zqvault/zqsecretlib`) was deliberately read as public.
 *
 * Fixture: `.npmrc` maps `@zqvault` to a private registry; `package-lock.json` installs `zqlockpriv`
 * and `@zqvault/zqsecretlib` from `npm.zq.internal`; `requirements.txt` sets a private
 * `--index-url` and pins `zqpyinternal==3.1.0`; `GOPRIVATE=git.zq.internal,github.com/zqorg` and
 * go.mod requires `github.com/zqorg/zqgopriv` and `git.zq.internal/team/zqgomod`. Every request
 * is recorded by a stubbed fetch: nothing leaves the process.
 */
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import Database from "better-sqlite3";
import { FourDADatabase } from "../db.js";
import { LiveIntelligence } from "../live/index.js";
import { nameForms } from "../live/private-guard.js";
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
/** Every recorded request naming any of the fixture's private names (all start `zq`). */
const leaks = () => sent.filter((s) => /zq/i.test(s));
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
  scratch = fs.mkdtempSync(path.join(os.tmpdir(), "4da-private-r6-"));
  sent = [];
  process.env.GOPRIVATE = "git.zq.internal,github.com/zqorg";
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init?: RequestInit) => {
      const body = typeof init?.body === "string" ? init.body : "";
      let readable = url;
      try {
        readable = decodeURIComponent(url);
      } catch {
        // as written
      }
      sent.push(`${readable} ${body}`);
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
  delete process.env.GOPRIVATE;
  setLiveIntelligence(null);
  try {
    fs.rmSync(scratch, { recursive: true, force: true });
  } catch {
    // Windows: left for the OS temp cleaner.
  }
});

/** The audit's project, under `scratch`. */
function zqProject(): string {
  write(".npmrc", "@zqvault:registry=https://npm.zq.internal/\n");
  const deps = { zqlockpriv: "2.0.0", "@zqvault/zqsecretlib": "1.4.0", lodash: "4.17.21" };
  write("package.json", JSON.stringify({ name: "app", dependencies: deps }));
  write(
    "package-lock.json",
    JSON.stringify({
      lockfileVersion: 3,
      packages: {
        "": { name: "app", dependencies: deps },
        "node_modules/zqlockpriv": { version: "2.0.0", resolved: "https://npm.zq.internal/zqlockpriv/-/zqlockpriv-2.0.0.tgz" },
        "node_modules/@zqvault/zqsecretlib": { version: "1.4.0", resolved: "https://npm.zq.internal/@zqvault/zqsecretlib/-/zqsecretlib-1.4.0.tgz" },
        "node_modules/lodash": { version: "4.17.21", resolved: "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz" },
      },
    }),
  );
  write("requirements.txt", "--index-url https://pypi.zq.internal/simple\nzqpyinternal==3.1.0\n");
  write("go.mod", "module example.com/app\n\ngo 1.22\n\nrequire (\n\tgithub.com/zqorg/zqgopriv v1.2.0\n\tgit.zq.internal/team/zqgomod v0.3.0\n)\n");
  write(
    "go.sum",
    [
      "github.com/zqorg/zqgopriv v1.2.0 h1:fixture=",
      "github.com/zqorg/zqgopriv v1.2.0/go.mod h1:fixture=",
      "git.zq.internal/team/zqgomod v0.3.0 h1:fixture=",
      "git.zq.internal/team/zqgomod v0.3.0/go.mod h1:fixture=",
      "",
    ].join("\n"),
  );
  return scratch;
}

/** Every spelling the audit saw reach a public registry or OSV.dev, with the ecosystem it was asked under. */
const LEAKED: Array<[string, string]> = [
  ["npm", "`zqlockpriv`"],
  ["PyPI", "'zqpyinternal'"],
  ["PyPI", '"zqpyinternal"'],
  ["npm", "<zqlockpriv>"],
  ["npm", "&lt;zqlockpriv&gt;"],
  ["PyPI", "zqpyinternal 3.1.0"],
  ["PyPI", "zqpyinternal (3.1.0)"],
  ["npm", "zqlockpriv\t2.0.0"],
  ["npm", "zqlockpriv (npm)"],
  ["npm", "lodash zqlockpriv"],
  ["npm", "zqlockpriv,lodash"],
  ["PyPI", "-zqpyinternal"],
  ["PyPI", "zqpyinternal-"],
  ["PyPI", "zqpyinternal."],
  ["PyPI", "zqpyinternal.tar.gz"],
  ["npm", "@zqvault\\zqsecretlib"],
  ["npm", "@zqvault:zqsecretlib"],
  ["Go", "github.com:443/zqorg/zqgopriv"],
  ["Go", "git.zq.internal:443/team/zqgomod"],
  // Short names of private packages, under any ecosystem.
  ["npm", "zqsecretlib"],
  ["PyPI", "zqsecretlib"],
  ["Go", "zqgopriv"],
  ["npm", "zqgomod"],
  // Beyond the audit: the same decorations on other ecosystems' names.
  ["npm", "`@zqvault/zqsecretlib`"],
  ["Go", "<github.com/zqorg/zqgopriv>"],
  ["Go", "'git.zq.internal/team/zqgomod' v0.3.0"],
  ["PyPI", "zqpyinternal-3.1.0.tar.gz"],
  ["crates.io", "“zqlockpriv”"],
  ["npm", "zqlockpriv;lodash"],
];

describe("r6: decorated spellings of a private name are refused before any request", () => {
  for (const [ecosystem, name] of LEAKED) {
    it(`dependency_check {${ecosystem}, ${JSON.stringify(name)}}: NOT CHECKED (private), nothing sent`, async () => {
      const live = liveFor(zqProject());
      const out = (await executeDependencyCheck(noDb, { items: [{ ecosystem, package: name, to: "9.9.9" }] }, live)) as unknown as {
        results: Array<{ verdict: string; not_checked?: string }>;
      };
      expect(leaks()).toEqual([]);
      expect(out.results[0].not_checked).toBe("private");
    });
  }

  for (const [ecosystem, name] of LEAKED) {
    it(`upgrade_impact {${ecosystem}, ${JSON.stringify(name)}}: refused, nothing sent`, async () => {
      const live = liveFor(zqProject());
      const out = await executeUpgradeImpact(noDb, { package: name, ecosystem, to_version: "9.9.9" } as never, live).catch((e: Error) => ({ error: e.message }));
      expect(leaks()).toEqual([]);
      expect((out as { not_checked?: string }).not_checked).toBe("private");
    });
  }

  it("upgrade_impact {package: zqsecretlib, ecosystem: npm} (the audit's case) and with no ecosystem", async () => {
    const live = liveFor(zqProject());
    expect(await executeUpgradeImpact(noDb, { package: "zqsecretlib", ecosystem: "npm", to_version: "2.0.0" } as never, live)).toMatchObject({ not_checked: "private" });
    expect(await executeUpgradeImpact(noDb, { package: "zqsecretlib", to_version: "2.0.0" } as never, live)).toMatchObject({ not_checked: "private" });
    expect(leaks()).toEqual([]);
  });

  it("the briefing still refuses them (it and dependency_check read the same rule)", async () => {
    const live = liveFor(zqProject());
    for (const [, name] of LEAKED) {
      await executeWhatShouldIKnow(memoryDb(), { task: `upgrade ${name} to 9.9.9` }, live).catch(() => null);
    }
    expect(leaks()).toEqual([]);
  });
});

describe("r6: public names are checked as before", () => {
  const PUBLIC: Array<[string, string]> = [
    ["npm", "lodash"],
    ["npm", '"lodash"'],
    ["npm", "`lodash`"],
    ["PyPI", "requests 2.31.0"],
    ["PyPI", "requests"],
    ["Go", "golang.org/x/net"],
    ["npm", "@types/node"],
  ];
  for (const [ecosystem, name] of PUBLIC) {
    it(`{${ecosystem}, ${JSON.stringify(name)}} is not refused as private`, async () => {
      const live = liveFor(zqProject());
      const out = (await executeDependencyCheck(noDb, { items: [{ ecosystem, package: name, to: "4.17.21" }] }, live)) as unknown as {
        results: Array<{ not_checked?: string }>;
      };
      expect(out.results[0].not_checked).not.toBe("private");
      expect(live.privateReason(ecosystem, name)).toBeNull();
    });
  }

  it("lodash is still sent: the lookup for a public name goes out", async () => {
    const live = liveFor(zqProject());
    await executeDependencyCheck(noDb, { items: [{ ecosystem: "npm", package: "lodash", to: "4.17.21" }] }, live);
    expect(sent.some((s) => s.includes("lodash"))).toBe(true);
    expect(leaks()).toEqual([]);
  });

  it("the project's own scan still checks its public dependency, and only it", async () => {
    const live = liveFor(zqProject());
    const scan = await live.scanVulnerabilities(scratch, { includeDev: true });
    expect(sent.some((s) => s.includes("lodash"))).toBe(true);
    expect(leaks()).toEqual([]);
    const priv = (scan.privateExcluded?.dependencies ?? []).map((d) => d.name).sort();
    expect(priv).toEqual(expect.arrayContaining(["@zqvault/zqsecretlib", "zqlockpriv", "zqpyinternal"]));
  });

  it("a public package that shares a private package's short name is not refused when the project installs it", async () => {
    write(".npmrc", "@zqvault:registry=https://npm.zq.internal/\n");
    const deps = { "@zqvault/react": "1.0.0", react: "18.2.0" };
    write("package.json", JSON.stringify({ name: "app", dependencies: deps }));
    write(
      "package-lock.json",
      JSON.stringify({
        lockfileVersion: 3,
        packages: {
          "": { name: "app", dependencies: deps },
          "node_modules/@zqvault/react": { version: "1.0.0", resolved: "https://npm.zq.internal/@zqvault/react/-/react-1.0.0.tgz" },
          "node_modules/react": { version: "18.2.0", resolved: "https://registry.npmjs.org/react/-/react-18.2.0.tgz" },
        },
      }),
    );
    const live = liveFor(scratch);
    expect(live.privateReason("npm", "react")).toBeNull();
    expect(live.privateReason("npm", "@zqvault/react")).not.toBeNull();
  });
});

describe("r6: nameForms reads the name inside the decoration", () => {
  const cases: Array<[string, string]> = [
    ["`zqlockpriv`", "zqlockpriv"],
    ["&lt;zqlockpriv&gt;", "zqlockpriv"],
    ["zqpyinternal (3.1.0)", "zqpyinternal"],
    ["lodash zqlockpriv", "zqlockpriv"],
    ["zqlockpriv,lodash", "zqlockpriv"],
    ["-zqpyinternal", "zqpyinternal"],
    ["zqpyinternal.tar.gz", "zqpyinternal"],
    ["@zqvault\\zqsecretlib", "@zqvault/zqsecretlib"],
    ["@zqvault:zqsecretlib", "@zqvault/zqsecretlib"],
    ["github.com:443/zqorg/zqgopriv", "github.com/zqorg/zqgopriv"],
    ["&#96;zqlockpriv&#x60;", "zqlockpriv"],
  ];
  for (const [written, form] of cases) {
    it(`${JSON.stringify(written)} has the form ${form}`, () => {
      expect(nameForms(written)).toContain(form);
    });
  }
  it("a plain name's forms are what they were", () => {
    expect(nameForms("lodash")).toEqual(["lodash"]);
    expect(nameForms("@types/node")).toEqual(["@types/node"]);
  });
});
