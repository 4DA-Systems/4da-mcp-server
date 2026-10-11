// SPDX-License-Identifier: Apache-2.0
/**
 * The defects the first run against the 4DA conformance corpus found
 * (2026-10-12), each pinned by a small offline case shaped like the corpus
 * lockfile that exposed it, plus the pieces the conformance harness rests on:
 * the pinned advisory source and the scorer's key normalisation.
 *
 * | case                        | ecosystem | what was wrong                                             |
 * |-----------------------------|-----------|------------------------------------------------------------|
 * | go-hugo-legacy, go-node-exporter-legacy, poly-traefik-v2.6 | Go | go < 1.17: go.sum modules with only a /go.mod hash read as installed (728 extra) |
 * | py-*-certifi (4 cases)      | PyPI      | a listed version `2020.12.05` did not match installed `2020.12.5` |
 * | py-pydantic-uv              | PyPI      | a uv git source read as the PyPI release of the same number |
 * | js-hono-bun                 | npm       | a yarn npm alias (`string-width-cjs`) read as a package     |
 * | js-trpc-pnpm5               | npm       | pnpm 5 tarball-URL keys with name/version fields were dropped |
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { resolveGo, readTomlPackageLock } from "../live/lockfile-parsers-pygo.js";
import { readPnpmLock, readYarnLock } from "../live/js-lockfile-readers.js";
import { InstanceSet } from "../live/lockfile-types.js";
import { advisoryAffects, advisoryRanges } from "../live/osv-ranges.js";
import { OsvScanner } from "../live/osv-scanner.js";
import { PinnedRecordsSource } from "../live/pinned-advisories.js";
import { LiveCache } from "../live/cache.js";
import { RateLimiter, DEFAULT_RATE_LIMITS } from "../live/rate-limiter.js";
import type { OsvVulnerability, ResolvedDependency } from "../live/types.js";
import { canonicalIds, Counts, invKey, normName, normVersion, truncate4 } from "./helpers/conformance.js";

let dir: string;
beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), "4da-conf-drift-"));
});
afterEach(() => {
  fs.rmSync(dir, { recursive: true, force: true });
});

const instancesOf = (set: InstanceSet) => set.toArray().map((i) => `${i.name}@${i.version}`).sort();

describe("Go < 1.17: the build list, not every module go.sum visited", () => {
  it("drops /go.mod-only modules, applies replace to go.sum modules and version-specific replaces", () => {
    fs.writeFileSync(
      path.join(dir, "go.mod"),
      [
        "module example.com/app",
        "",
        "go 1.14",
        "",
        "require (",
        "\tgithub.com/direct/one v1.0.0",
        "\tgithub.com/pinned/two v1.1.0",
        ")",
        "",
        "replace github.com/pinned/two v1.1.0 => github.com/fork/two v1.1.5",
        "replace github.com/pinned/two v1.0.0 => github.com/never/used v9.9.9",
        "replace github.com/sum/only => github.com/sum/fork v2.0.0",
        "replace github.com/local/mod => ../mod",
      ].join("\n"),
    );
    fs.writeFileSync(
      path.join(dir, "go.sum"),
      [
        "github.com/direct/one v1.0.0 h1:a=",
        "github.com/direct/one v1.0.0/go.mod h1:a=",
        // built: its source is hashed at the selected version
        "github.com/transitive/built v0.3.0 h1:b=",
        "github.com/transitive/built v0.3.0/go.mod h1:b=",
        // graph-only: node_exporter's gogo/protobuf shape (older source hash, newer go.mod-only)
        "github.com/gogo/protobuf v1.1.1 h1:c=",
        "github.com/gogo/protobuf v1.1.1/go.mod h1:c=",
        "github.com/gogo/protobuf v1.2.1/go.mod h1:c=",
        "google.golang.org/grpc v1.21.0/go.mod h1:d=",
        // replaced in go.mod, completed from go.sum
        "github.com/sum/only v1.0.0 h1:e=",
        "github.com/local/mod v0.1.0 h1:f=",
      ].join("\n"),
    );
    const read = resolveGo(dir);
    expect(read.instances.map((i) => `${i.name}@${i.version}`).sort()).toEqual([
      "github.com/direct/one@v1.0.0",
      "github.com/fork/two@v1.1.5",
      "github.com/sum/fork@v2.0.0",
      "github.com/transitive/built@v0.3.0",
    ]);
  });
});

describe("OSV listed versions match the ecosystem's equal version", () => {
  const pysec: OsvVulnerability = {
    id: "PYSEC-2024-230",
    aliases: ["GHSA-248v-346w-9cwc"],
    affected: [
      {
        package: { name: "certifi", ecosystem: "PyPI" },
        ranges: [
          { type: "GIT", events: [{ introduced: "0" }, { fixed: "bd8153872e9c6fc98f4023df9c2deaffea2fa463" }] },
          { type: "ECOSYSTEM", events: [{ introduced: "2021.5.30" }, { fixed: "2024.7.4" }] },
        ],
        versions: ["2020.12.05", "2020.11.08", "2018.01.18", "v1.0.1"],
      },
    ],
  };

  it("certifi 2020.12.5 is the listed 2020.12.05 (PEP 440), as OSV answers", () => {
    const ranges = advisoryRanges(pysec, "certifi", "PyPI")!;
    for (const installed of ["2020.12.5", "2020.11.8", "2018.1.18", "2020.12.05"]) {
      expect(advisoryAffects(ranges, installed, "PyPI"), installed).toBe(true);
    }
    expect(advisoryAffects(ranges, "2020.12.6", "PyPI")).toBe(false);
    expect(advisoryAffects(ranges, "2021.10.8", "PyPI")).toBe(true); // the ECOSYSTEM range
    expect(advisoryAffects(ranges, "2024.7.4", "PyPI")).toBe(false);
  });
});

describe("uv and poetry: only package-index releases", () => {
  it("drops uv git/url/path/directory sources and poetry git/url/file/directory sources; keeps registry and legacy", () => {
    const { instances } = readTomlPackageLock(
      [
        "[[package]]",
        'name = "pydantic-extra-types"',
        'version = "2.10.0"',
        'source = { git = "https://github.com/pydantic/pydantic-extra-types.git?rev=main#f27a1325" }',
        "",
        "[[package]]",
        'name = "archive"',
        'version = "1.0.0"',
        'source = { url = "https://example.com/archive-1.0.0.tar.gz" }',
        "",
        "[[package]]",
        'name = "sibling"',
        'version = "0.1.0"',
        'source = { directory = "../sibling" }',
        "",
        "[[package]]",
        'name = "typing-extensions"',
        'version = "4.12.2"',
        'source = { registry = "https://pypi.org/simple" }',
        "",
        "[[package]]",
        'name = "poetry-git"',
        'version = "0.2.0"',
        "",
        "[package.source]",
        'type = "git"',
        'url = "https://github.com/x/poetry-git.git"',
        'reference = "main"',
        "",
        "[[package]]",
        'name = "private-index"',
        'version = "3.0.0"',
        "",
        "[package.dependencies]",
        'six = "*"',
        "",
        "[package.source]",
        'type = "legacy"',
        'url = "https://pypi.example.com/simple"',
        'reference = "private"',
        "",
        "[metadata]",
        'content-hash = "x"',
      ].join("\n"),
    );
    expect(instancesOf(instances)).toEqual(["private-index@3.0.0", "typing-extensions@4.12.2"]);
  });
});

describe("yarn npm aliases name the real package", () => {
  it("berry: the resolution's package, not the alias", () => {
    const versions = new Map<string, string>();
    const instances = new InstanceSet();
    readYarnLock(
      [
        "__metadata:",
        "  version: 6",
        "",
        '"string-width-cjs@npm:string-width@^4.2.0, string-width@npm:^4.1.0":',
        "  version: 4.2.3",
        '  resolution: "string-width@npm:4.2.3"',
        "",
        '"@isaacs/cliui-alias@npm:@isaacs/cliui@^8.0.2":',
        "  version: 8.0.2",
        '  resolution: "@isaacs/cliui@npm:8.0.2"',
        "",
        '"strip-ansi@npm:^7.0.1":',
        "  version: 7.1.0",
        '  resolution: "strip-ansi@npm:7.1.0"',
      ].join("\n"),
      versions,
      instances,
    );
    expect(instancesOf(instances)).toEqual(["@isaacs/cliui@8.0.2", "string-width@4.2.3", "strip-ansi@7.1.0"]);
  });

  it("v1: the alias spec's package", () => {
    const versions = new Map<string, string>();
    const instances = new InstanceSet();
    readYarnLock(
      [
        "# yarn lockfile v1",
        "",
        '"wrap-ansi-cjs@npm:wrap-ansi@^7.0.0":',
        '  version "7.0.0"',
        '  resolved "https://registry.yarnpkg.com/wrap-ansi/-/wrap-ansi-7.0.0.tgz"',
        "",
        "wrap-ansi@^8.1.0:",
        '  version "8.1.0"',
      ].join("\n"),
      versions,
      instances,
    );
    expect(instancesOf(instances)).toEqual(["wrap-ansi@7.0.0", "wrap-ansi@8.1.0"]);
  });
});

describe("pnpm entries keyed by a tarball URL", () => {
  it("reads name/version fields of a registry tarball; drops codeload and git resolutions", () => {
    const versions = new Map<string, string>();
    const instances = new InstanceSet();
    readPnpmLock(
      [
        "lockfileVersion: 5.4",
        "",
        "packages:",
        "",
        "  /left-pad/1.3.0:",
        "    resolution: {integrity: sha512-x}",
        "    dev: true",
        "",
        "  '@registry.npmjs.com/@prisma/client/-/client-4.7.1.tgz?id=%2540examples%252Flegacy-next-starter_prisma@4.7.1':",
        "    resolution:",
        "      {",
        "        tarball: https://registry.npmjs.com/@prisma/client/-/client-4.7.1.tgz?id=%40examples%2Flegacy-next-starter,",
        "      }",
        "    id: '@registry.npmjs.com/@prisma/client/-/client-4.7.1.tgz?id=%2540examples%252Flegacy-next-starter'",
        "    name: '@prisma/client'",
        "    version: 4.7.1",
        "    dev: false",
        "",
        "  codeload.github.com/user/forked/0123abc:",
        "    resolution: {tarball: https://codeload.github.com/user/forked/tar.gz/0123abc}",
        "    name: forked",
        "    version: 1.0.0",
        "",
        "  github.com/user/repo/4567def:",
        "    resolution: {commit: 4567def, repo: https://github.com/user/repo.git, type: git}",
        "    name: repo",
        "    version: 2.0.0",
      ].join("\n"),
      versions,
      instances,
    );
    expect(instancesOf(instances)).toEqual(["@prisma/client@4.7.1", "left-pad@1.3.0"]);
    expect(instances.toArray().find((i) => i.name === "@prisma/client")?.dev).toBe(false);
    expect(instances.toArray().find((i) => i.name === "left-pad")?.dev).toBe(true);
  });
});

describe("PinnedRecordsSource: OSV's question answered from pinned records", () => {
  const records: OsvVulnerability[] = [
    {
      id: "GHSA-aaaa",
      aliases: ["CVE-2024-1"],
      summary: "x",
      affected: [{ package: { name: "Jinja2", ecosystem: "PyPI" }, ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "3.1.4" }] }] }],
    },
    {
      id: "GHSA-withdrawn",
      withdrawn: "2024-01-01T00:00:00Z",
      affected: [{ package: { name: "jinja2", ecosystem: "PyPI" }, ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }] }] }],
    },
    {
      id: "RUSTSEC-2024-0001",
      affected: [{ package: { name: "tokio_util", ecosystem: "crates.io" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0.7.0" }, { fixed: "0.7.4" }] }] }],
    },
  ];
  const dep = (name: string, version: string, ecosystem: ResolvedDependency["ecosystem"]): ResolvedDependency => ({
    name, version, ecosystem, isDev: false, isDirect: true, devScopeKnown: true, target: null, platformActive: true, sourceDirs: ["/p"],
  });

  it("matches by the registry's name rules and the ecosystem's order; the scanner drops withdrawn records", async () => {
    const source = new PinnedRecordsSource(records);
    expect(source.network).toBe(false);
    expect(await source.query([dep("jinja2", "3.1.3", "PyPI"), dep("Jinja2", "3.1.4", "PyPI"), dep("tokio-util", "0.7.2", "crates.io")])).toEqual([
      ["GHSA-aaaa", "GHSA-withdrawn"],
      ["GHSA-withdrawn"],
      ["RUSTSEC-2024-0001"],
    ]);
    const scanner = new OsvScanner(new LiveCache(null), new RateLimiter(DEFAULT_RATE_LIMITS), source);
    const scan = await scanner.scan([dep("jinja2", "3.1.3", "PyPI"), dep("tokio-util", "0.7.2", "crates.io")], "/p");
    expect(scan.offline).toBe(false);
    expect(scan.vulnerabilities.map((v) => `${v.package}:${v.vulnId}:${v.fixedVersion}`).sort()).toEqual([
      "jinja2:GHSA-aaaa:3.1.4",
      "tokio-util:RUSTSEC-2024-0001:0.7.4",
    ]);
  });
});

describe("conformance scorer: the corpus README's rules, as the Rust harness applies them", () => {
  it("normalises names and versions per ecosystem", () => {
    expect(normName("PyPI", "Zope.Interface__x")).toBe("zope-interface-x");
    expect(normName("Go", "github.com/BurntSushi/toml")).toBe("github.com/BurntSushi/toml");
    expect(normName("npm", "@Babel/Core")).toBe("@babel/core");
    expect(normVersion("PyPI", "V2.0.0")).toBe("2");
    expect(normVersion("PyPI", "1.0rc1")).toBe("1rc1");
    expect(normVersion("PyPI", "1.10.0.post1")).toBe("1.10.post1");
    expect(normVersion("Go", "v0.0.0-2020-abc")).toBe("0.0.0-2020-abc");
    expect(normVersion("npm", "v1.0.0")).toBe("v1.0.0");
    expect(invKey("PyPI", ".", "Flask_Cors", "3.0.0")).toBe("PyPI|.|flask-cors|3");
  });

  it("groups aliases under the smallest non-CVE id", () => {
    const canon = canonicalIds([
      { id: "PYSEC-2024-230", aliases: ["CVE-2024-39689", "GHSA-248v-346w-9cwc"] },
      { id: "GHSA-248v-346w-9cwc", aliases: ["CVE-2024-39689"] },
      { id: "CVE-2020-1", aliases: [] },
    ]);
    expect(canon.get("PYSEC-2024-230")).toBe("GHSA-248v-346w-9cwc");
    expect(canon.get("CVE-2024-39689")).toBe("GHSA-248v-346w-9cwc");
    expect(canon.get("CVE-2020-1")).toBe("CVE-2020-1");
  });

  it("vacuous precision and recall are 1; ratchet values truncate", () => {
    const c = new Counts();
    expect([c.precision(), c.recall()]).toEqual([1, 1]);
    c.tp = 2;
    c.fp = 1;
    expect(truncate4(c.precision())).toBe(0.6666);
  });
});
