// SPDX-License-Identifier: Apache-2.0
/**
 * pnpm-lock.yaml: a `tarball:` location belongs to the entry it is written in. A key that is a URL
 * (`ms@https://pkg.pr.new/vercel/ms@a1b2c3d:`) was not recognised as an entry, so its tarball was
 * read as the location of the entry above it, and a public `lodash` was reported private and never
 * checked. yarn.lock: an npm alias's location is recorded under the package the alias installs.
 *
 * Every request is recorded by a stubbed fetch: nothing leaves the process.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { FourDADatabase } from "../db.js";
import { LiveIntelligence } from "../live/index.js";
import { clearLiveIntelligence, setLiveIntelligence } from "../live-singleton.js";
import { dispatchTool } from "../tool-dispatch.js";
import { scanProjectTree, treeResolutionGroups } from "../project-tree.js";
import { npmLockPrivateSources } from "../live/private-packages.js";

let scratch: string;
let sent: string[];
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
const lockDir = (files: Record<string, string>): string => {
  const dir = fs.mkdtempSync(path.join(scratch, "lock-"));
  for (const [file, content] of Object.entries(files)) fs.writeFileSync(path.join(dir, file), content);
  return dir;
};
const sources = (dir: string) => npmLockPrivateSources(dir, new Set()).map((p) => `${p.name}@${p.version ?? "?"} <- ${p.registry}`);

/** A pnpm 9 lockfile with a public registry package first and a URL-tarball dependency after it. */
const PNPM9_URL_TARBALL = `lockfileVersion: '9.0'

settings:
  autoInstallPeers: true
  excludeLinksFromLockfile: false

importers:

  .:
    dependencies:
      lodash:
        specifier: 4.17.20
        version: 4.17.20
      ms:
        specifier: https://pkg.pr.new/vercel/ms@a1b2c3d
        version: https://pkg.pr.new/vercel/ms@a1b2c3d

packages:

  lodash@4.17.20:
    resolution: {integrity: sha512-PlhdFcillOINfeV7Ni6oF1TAEayyZBoZ8bcshTHqOYJYlrqzRK5hagpagky5o4HfCzzd1TRkXPMFq6cKk9rGmA==}

  ms@https://pkg.pr.new/vercel/ms@a1b2c3d:
    resolution: {tarball: https://pkg.pr.new/vercel/ms@a1b2c3d}
    version: 2.1.3
    engines: {node: '>=10'}

snapshots:

  lodash@4.17.20: {}

  ms@https://pkg.pr.new/vercel/ms@a1b2c3d: {}
`;

beforeEach(() => {
  scratch = fs.mkdtempSync(path.join(os.tmpdir(), "4da-a1119-pnpm-"));
  sent = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: string, init?: RequestInit) => {
      const body = typeof init?.body === "string" ? init.body : "";
      sent.push(`${String(input)} ${body}`);
      const u = new URL(String(input));
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

describe("pnpm-lock.yaml: a tarball marks the entry that carries it", () => {
  it("a URL-keyed entry's tarball is not the location of the package above it", () => {
    const dir = lockDir({ "pnpm-lock.yaml": PNPM9_URL_TARBALL });
    expect(sources(dir)).toEqual(["ms@2.1.3 <- https://pkg.pr.new/vercel/ms@a1b2c3d"]);
  });

  it("the scan asks OSV.dev about lodash 4.17.20 and does not call it private", async () => {
    const dir = lockDir({
      "package.json": JSON.stringify({ private: true, dependencies: { lodash: "4.17.20", ms: "https://pkg.pr.new/vercel/ms@a1b2c3d" } }),
      "pnpm-lock.yaml": PNPM9_URL_TARBALL,
    });
    const live = new LiveIntelligence(null);
    const { entries, discovery } = scanProjectTree(dir);
    live.initFromProjectTree(dir, treeResolutionGroups(entries), discovery);
    setLiveIntelligence(live);
    expect(live.getPrivateDependencies().map((d) => d.name)).not.toContain("lodash");
    expect(live.privateReason("npm", "lodash")).toBeNull();
    const db = new FourDADatabase(path.join(scratch, "standalone.db"));
    try {
      await dispatchTool("vulnerability_scan", db, { force_refresh: true });
    } finally {
      db.close();
    }
    const asked = sent.filter((s) => s.includes("/v1/querybatch")).join("\n");
    expect(asked).toContain('{"package":{"name":"lodash","ecosystem":"npm"},"version":"4.17.20"}');
    // The URL dependency is not a registry release of `ms`: it is never asked about as one.
    expect(asked).not.toContain('"name":"ms"');
  });

  it("a private tarball between two public entries marks only its own entry", () => {
    const dir = lockDir({
      "pnpm-lock.yaml": [
        "lockfileVersion: '9.0'",
        "",
        "packages:",
        "",
        "  alpha@1.0.0:",
        "    resolution: {integrity: sha512-a}",
        "",
        "  '@zqacme/beta@2.0.0':",
        "    resolution: {integrity: sha512-b, tarball: https://npm.zqacme.example/@zqacme/beta/-/beta-2.0.0.tgz}",
        "",
        "  gamma@3.0.0:",
        "    resolution: {integrity: sha512-c}",
        "",
      ].join("\n"),
    });
    expect(sources(dir)).toEqual(["@zqacme/beta@2.0.0 <- https://npm.zqacme.example/@zqacme/beta/-/beta-2.0.0.tgz"]);
  });

  it("an entry keyed by a URL takes its name and version from its own fields (pnpm 5), a multi-line resolution included", () => {
    const dir = lockDir({
      "pnpm-lock.yaml": [
        "lockfileVersion: 5.4",
        "",
        "packages:",
        "",
        "  /alpha/1.0.0:",
        "    resolution: {integrity: sha512-a}",
        "    dev: false",
        "",
        "  '@npm.zqacme.example/zq-delta/-/zq-delta-4.0.0.tgz':",
        "    resolution:",
        "      tarball: https://npm.zqacme.example/zq-delta/-/zq-delta-4.0.0.tgz",
        "    name: zq-delta",
        "    version: 4.0.0",
        "    dev: false",
        "",
        "  /gamma/3.0.0_peer@1.0.0:",
        "    resolution: {integrity: sha512-c}",
        "",
      ].join("\n"),
    });
    expect(sources(dir)).toEqual(["zq-delta@4.0.0 <- https://npm.zqacme.example/zq-delta/-/zq-delta-4.0.0.tgz"]);
  });

  it("a tarball under a key that names no package marks nothing, and never the entry above", () => {
    const dir = lockDir({
      "pnpm-lock.yaml": ["packages:", "", "  alpha@1.0.0:", "    resolution: {integrity: sha512-a}", "", "  'https://npm.zqacme.example/x.tgz':", "    resolution: {tarball: https://npm.zqacme.example/x.tgz}", ""].join("\n"),
    });
    expect(sources(dir)).toEqual([]);
  });

  it("v6 keys (a leading slash, peers in brackets) keep their own tarball", () => {
    const dir = lockDir({
      "pnpm-lock.yaml": ["lockfileVersion: '6.0'", "", "packages:", "", "  /@zqacme/ui@1.2.3(react@18.2.0):", "    resolution: {integrity: sha512-a, tarball: https://npm.zqacme.example/@zqacme/ui/-/ui-1.2.3.tgz}", "    dev: false", ""].join("\n"),
    });
    expect(sources(dir)).toEqual(["@zqacme/ui@1.2.3 <- https://npm.zqacme.example/@zqacme/ui/-/ui-1.2.3.tgz"]);
  });
});

describe("yarn.lock: a location marks the block that carries it, under every name the block installs", () => {
  it("v1 and berry blocks, each with its own location", () => {
    const v1 = lockDir({
      "yarn.lock": [
        "# yarn lockfile v1",
        "",
        "alpha@^1.0.0:",
        '  version "1.0.0"',
        '  resolved "https://registry.yarnpkg.com/alpha/-/alpha-1.0.0.tgz#aaa"',
        "",
        '"@zqacme/beta@^2.0.0", "@zqacme/beta@^2.1.0":',
        '  version "2.1.0"',
        '  resolved "https://npm.zqacme.example/@zqacme/beta/-/beta-2.1.0.tgz#bbb"',
        "  dependencies:",
        '    alpha "^1.0.0"',
        "",
      ].join("\n"),
    });
    expect(sources(v1)).toEqual(["@zqacme/beta@2.1.0 <- https://npm.zqacme.example/@zqacme/beta/-/beta-2.1.0.tgz"]);
    const berry = lockDir({
      "yarn.lock": [
        "__metadata:",
        "  version: 8",
        "",
        '"alpha@npm:^1.0.0":',
        "  version: 1.0.0",
        '  resolution: "alpha@npm:1.0.0"',
        "",
        '"zq-gamma@https://npm.zqacme.example/zq-gamma-3.0.0.tgz":',
        "  version: 3.0.0",
        '  resolution: "zq-gamma@https://npm.zqacme.example/zq-gamma-3.0.0.tgz"',
        "",
        '"zq-delta@npm:^4.0.0":',
        "  version: 4.0.0",
        '  resolution: "zq-delta@npm:4.0.0::__archiveUrl=https%3A%2F%2Fnpm.zqacme.example%2Fzq-delta%2F-%2Fzq-delta-4.0.0.tgz"',
        "",
      ].join("\n"),
    });
    expect(sources(berry)).toEqual([
      "zq-gamma@3.0.0 <- https://npm.zqacme.example/zq-gamma-3.0.0.tgz",
      "zq-delta@4.0.0 <- https://npm.zqacme.example/zq-delta/-/zq-delta-4.0.0.tgz",
    ]);
  });

  it("an npm alias: the package behind the alias is the private one, v1 and berry", () => {
    const v1 = lockDir({
      "yarn.lock": ['"zq-alias@npm:@zqacme/real@^1.0.0":', '  version "1.0.0"', '  resolved "https://npm.zqacme.example/@zqacme/real/-/real-1.0.0.tgz#x"', ""].join("\n"),
    });
    expect(npmLockPrivateSources(v1, new Set()).map((p) => p.name).sort()).toEqual(["@zqacme/real", "zq-alias"]);
    const berry = lockDir({
      "yarn.lock": ['"zq-alias@npm:@zqacme/real@^1.0.0":', "  version: 1.0.0", '  resolution: "@zqacme/real@npm:1.0.0::__archiveUrl=https%3A%2F%2Fnpm.zqacme.example%2Freal-1.0.0.tgz"', ""].join("\n"),
    });
    expect(npmLockPrivateSources(berry, new Set()).map((p) => p.name).sort()).toEqual(["@zqacme/real", "zq-alias"]);
  });
});
