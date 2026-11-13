// SPDX-License-Identifier: Apache-2.0
/**
 * Every tool, against a project whose private package is the PARENT of a vulnerable public one,
 * in npm, Cargo, PyPI and Go (review of #64, blocker): upgrade_planner looked the parent up by its
 * lockfile name and `@acme/api` reached registry.npmjs.org, `acme-core` index.crates.io. The fetch
 * stub records every request; none may name the private package, in its URL or its body.
 *
 * Both defences are exercised: the fix-path sources refuse the private parent (asserted through
 * getPrivateRefusals), and the HTTP choke point (private-guard.ts) refuses whatever else would
 * name it. A refused lookup is "not checked", so no answer about the parent may read as clean.
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

let scratch: string;
let sent: string[];
const saved: Record<string, string | undefined> = {};

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

/** A public advisory on the vulnerable child, so the planner has a fix path to look for. */
const ADVISORY = (id: string, ecosystem: string, name: string, fixed: string) => ({
  id,
  modified: "2026-01-01T00:00:00Z",
  summary: `${name} issue`,
  database_specific: { severity: "HIGH" },
  affected: [{ package: { ecosystem, name }, ranges: [{ type: ecosystem === "Go" ? "SEMVER" : "ECOSYSTEM", events: [{ introduced: "0" }, { fixed }] }] }],
});

interface Fixture {
  ecosystem: string;
  /** The private name, as it would appear in a request (lowercased for the search). */
  privateName: string;
  publicName: string;
  publicVersion: string;
  fixed: string;
  files: Record<string, string>;
  env?: Record<string, string>;
}

const FIXTURES: Fixture[] = [
  {
    ecosystem: "npm",
    privateName: "@acme/api",
    publicName: "qs",
    publicVersion: "6.5.2",
    fixed: "6.5.3",
    files: {
      ".npmrc": "@acme:registry=https://npm.acme.dev/\n",
      "package.json": JSON.stringify({ name: "app", dependencies: { "@acme/api": "1.0.0" } }),
      "package-lock.json": JSON.stringify({
        name: "app",
        lockfileVersion: 3,
        packages: {
          "": { name: "app", dependencies: { "@acme/api": "1.0.0" } },
          "node_modules/@acme/api": { version: "1.0.0", resolved: "https://npm.acme.dev/@acme/api/-/api-1.0.0.tgz", dependencies: { qs: "6.5.2" } },
          "node_modules/qs": { version: "6.5.2", resolved: "https://registry.npmjs.org/qs/-/qs-6.5.2.tgz" },
        },
      }),
    },
  },
  {
    ecosystem: "crates.io",
    privateName: "acme-core",
    publicName: "smallvec",
    publicVersion: "0.6.9",
    fixed: "0.6.10",
    files: {
      "Cargo.toml": '[package]\nname = "app"\nversion = "0.1.0"\n\n[dependencies]\nacme-core = { version = "0.1", registry = "acme" }\n',
      "Cargo.lock": [
        "version = 3",
        "",
        "[[package]]",
        'name = "app"',
        'version = "0.1.0"',
        'dependencies = ["acme-core"]',
        "",
        "[[package]]",
        'name = "acme-core"',
        'version = "0.1.0"',
        'source = "registry+https://dl.acme.dev/"',
        'dependencies = ["smallvec"]',
        "",
        "[[package]]",
        'name = "smallvec"',
        'version = "0.6.9"',
        'source = "registry+https://github.com/rust-lang/crates.io-index"',
        "",
      ].join("\n"),
    },
  },
  {
    ecosystem: "PyPI",
    privateName: "acme-auth",
    publicName: "requests",
    publicVersion: "2.25.1",
    fixed: "2.31.0",
    files: {
      "pyproject.toml": '[project]\nname = "app"\nversion = "0.1.0"\ndependencies = ["acme-auth"]\n',
      "uv.lock": [
        "version = 1",
        "",
        "[[package]]",
        'name = "acme-auth"',
        'version = "2.1.0"',
        'source = { registry = "https://pypi.acme.dev/simple" }',
        'dependencies = [{ name = "requests" }]',
        "",
        "[[package]]",
        'name = "requests"',
        'version = "2.25.1"',
        'source = { registry = "https://pypi.org/simple" }',
        "",
      ].join("\n"),
    },
  },
  {
    ecosystem: "Go",
    privateName: "github.com/acme-corp/ledger",
    publicName: "golang.org/x/net",
    publicVersion: "v0.0.1",
    fixed: "0.17.0",
    env: { GOPRIVATE: "github.com/acme-corp/*" },
    files: {
      "go.mod": "module example.com/app\n\ngo 1.22\n\nrequire (\n\tgithub.com/acme-corp/ledger v1.0.0\n\tgolang.org/x/net v0.0.1 // indirect\n)\n",
      "go.sum": [
        "github.com/acme-corp/ledger v1.0.0 h1:aaaa=",
        "github.com/acme-corp/ledger v1.0.0/go.mod h1:bbbb=",
        "golang.org/x/net v0.0.1 h1:cccc=",
        "golang.org/x/net v0.0.1/go.mod h1:dddd=",
      ].join("\n"),
    },
  },
];

beforeAll(() => {
  saved.FOURDA_OFFLINE = process.env.FOURDA_OFFLINE;
  delete process.env.FOURDA_OFFLINE;
});

afterAll(() => {
  if (saved.FOURDA_OFFLINE === undefined) delete process.env.FOURDA_OFFLINE;
  else process.env.FOURDA_OFFLINE = saved.FOURDA_OFFLINE;
});

beforeEach(() => {
  scratch = fs.mkdtempSync(path.join(os.tmpdir(), "4da-private-every-"));
  sent = [];
  saved.GOPRIVATE = process.env.GOPRIVATE;
});

afterEach(() => {
  vi.unstubAllGlobals();
  // The server's live layer is process state: never left for the next test file (single-worker runs).
  clearLiveIntelligence();
  if (saved.GOPRIVATE === undefined) delete process.env.GOPRIVATE;
  else process.env.GOPRIVATE = saved.GOPRIVATE;
  try {
    fs.rmSync(scratch, { recursive: true, force: true });
  } catch {
    // Windows: left for the OS temp cleaner.
  }
});

/** Arguments that make each tool do its work on the fixture. */
function argsFor(tool: string, f: Fixture): Record<string, unknown> {
  switch (tool) {
    case "dependency_check":
      return { items: [{ ecosystem: f.ecosystem, package: f.privateName, to: "1.0.1" }, { ecosystem: f.ecosystem, package: f.publicName, to: f.fixed }] };
    case "upgrade_impact":
      return { package: f.privateName, to_version: "2.0.0", ecosystem: f.ecosystem };
    case "what_should_i_know":
      return { task: `upgrade ${f.privateName} and ${f.publicName}` };
    case "check_decision_alignment":
      return { technology: f.privateName };
    case "decision_memory":
      return { action: "list" };
    case "agent_memory":
      return { action: "recall", query: f.privateName };
    case "record_feedback":
      return { item_id: 1, action: "save" };
    case "upgrade_planner":
    case "vulnerability_scan":
    case "dependency_health":
      return { include_dev: true };
    default:
      return {};
  }
}

describe.each(FIXTURES)("a private $ecosystem parent ($privateName) of a vulnerable $publicName", (f) => {
  it("no tool sends the private name anywhere, and upgrade_planner refuses to look it up", async () => {
    for (const [file, content] of Object.entries(f.files)) fs.writeFileSync(path.join(scratch, file), content);
    for (const [k, v] of Object.entries(f.env ?? {})) process.env[k] = v;
    const advisory = ADVISORY(`GHSA-test-${f.ecosystem.replace(/\W/g, "")}`, f.ecosystem, f.publicName, f.fixed);
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: string, init?: RequestInit) => {
        const url = String(input);
        const body = typeof init?.body === "string" ? init.body : "";
        sent.push(`${url} ${body}`);
        const u = new URL(url);
        if (u.hostname === "api.osv.dev" && u.pathname === "/v1/querybatch") {
          const { queries } = JSON.parse(body) as { queries: Array<{ package: { name: string }; version: string }> };
          return json({ results: queries.map((q) => ({ vulns: q.package.name === f.publicName ? [{ id: advisory.id, modified: advisory.modified }] : [] })) });
        }
        if (u.hostname === "api.osv.dev" && u.pathname.startsWith("/v1/vulns/")) return json(advisory);
        if (u.hostname === "api.osv.dev" && u.pathname === "/v1/query") {
          const q = JSON.parse(body) as { package?: { name?: string } };
          return json({ vulns: q.package?.name === f.publicName ? [advisory] : [] });
        }
        return json({ error: "Not found" }, 404);
      }),
    );

    const live = new LiveIntelligence(null);
    const { entries, discovery } = scanProjectTree(scratch);
    live.initFromProjectTree(scratch, treeResolutionGroups(entries), discovery);
    setLiveIntelligence(live);
    expect(live.getPrivateDependencies().map((d) => d.name)).toContain(f.ecosystem === "PyPI" ? "acme-auth" : f.privateName);

    const db = new FourDADatabase(path.join(scratch, "standalone.db"));
    const answers: Record<string, string> = {};
    try {
      for (const tool of Object.keys(TOOL_REGISTRY)) {
        const result = await dispatchTool(tool, db, argsFor(tool, f)).catch((error: unknown) => ({ content: [{ type: "text", text: String(error) }] }));
        answers[tool] = JSON.stringify(result);
      }
    } finally {
      db.close();
    }

    const needle = f.privateName.toLowerCase();
    const encoded = encodeURIComponent(f.privateName).toLowerCase();
    const leaks = sent.filter((s) => s.toLowerCase().includes(needle) || s.toLowerCase().includes(encoded));
    expect(leaks).toEqual([]);
    // The public child was looked up (the fixture is live, not inert).
    expect(sent.some((s) => s.includes(f.publicName))).toBe(true);
    // The planner's fix path met the private parent and refused it at the source.
    if (f.ecosystem === "npm" || f.ecosystem === "crates.io") {
      expect([...live.getPrivateRefusals().keys()]).toContain(f.privateName);
      // ...and the step says its fix path through the private parent was not checked.
      expect(answers.upgrade_planner).toContain(`NOT CHECKED (private): ${f.publicName} arrives through ${f.privateName}`);
      expect(answers.upgrade_planner).not.toMatch(/"action\\":\\"lockfile_refresh/);
    }
    // Nothing about the private package reads as clean: the scan says NOT CHECKED (private).
    expect(answers.vulnerability_scan).toContain("NOT CHECKED (private)");
    expect(answers.dependency_check).toContain('not_checked\\":\\"private');
  });
});
