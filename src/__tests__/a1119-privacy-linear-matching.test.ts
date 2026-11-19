// SPDX-License-Identifier: Apache-2.0
/**
 * The private-name readers and matchers answer on long and odd input: a lockfile with a long run of
 * blank lines or one very long line, a configuration file with a long indented line, and a
 * GOPRIVATE or FOURDA_PRIVATE_PACKAGES pattern with many `*`. Each of these held the server for
 * tens of seconds (patterns that retried a run of characters from every position, and regular
 * expressions built from a user's glob).
 *
 * The tests assert what each call answers, on inputs large enough that the old code did not answer
 * within a test's time limit. No request is made anywhere here.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { goPrivateMatch, npmLockPrivateSources, parseYamlSubset, pnpmWorkspaceRegistries, PrivatePackageRules, yarnrcPrivateScopes } from "../live/private-packages.js";
import { yarnrcRegistry } from "../live/private-configs.js";

let scratch: string;
beforeEach(() => {
  scratch = fs.mkdtempSync(path.join(os.tmpdir(), "4da-a1119-linear-"));
});
afterEach(() => {
  try {
    fs.rmSync(scratch, { recursive: true, force: true });
  } catch {
    // Windows: left for the OS temp cleaner.
  }
});
const lockDir = (file: string, content: string): string => {
  const dir = fs.mkdtempSync(path.join(scratch, "lock-"));
  fs.writeFileSync(path.join(dir, file), content);
  return dir;
};
const names = (dir: string) => npmLockPrivateSources(dir, new Set()).map((p) => (p.unread ? `UNREAD ${path.basename(p.file)}` : p.name));
/** The rules of an empty project under an environment that reads no user configuration. */
const rulesWith = (env: Record<string, string>) => new PrivatePackageRules([], { GOENV: "off", PIP_CONFIG_FILE: "os.devnull", UV_NO_CONFIG: "1", HOME: scratch, USERPROFILE: scratch, NPM_CONFIG_USERCONFIG: path.join(scratch, "none"), NPM_CONFIG_GLOBALCONFIG: path.join(scratch, "none"), ...env });

const SIZE = 1_000_000;
const PRIVATE_ENTRY = '"zq-a@^1.0.0":\n  version "1.0.0"\n  resolved "https://npm.zqacme.example/zq-a/-/zq-a-1.0.0.tgz#x"\n';

describe("yarn.lock and pnpm-lock.yaml are read line by line, each line once", () => {
  it("yarn.lock: an entry followed by a megabyte of whitespace-only lines", () => {
    expect(names(lockDir("yarn.lock", `# yarn lockfile v1\n\n${PRIVATE_ENTRY}${"  \n".repeat(SIZE / 3)}`))).toEqual(["zq-a"]);
    expect(names(lockDir("yarn.lock", `# yarn lockfile v1\n\n${PRIVATE_ENTRY}${"  \t \n".repeat(SIZE / 5)}  integrity sha512-x\n`))).toEqual(["zq-a"]);
  });

  it("yarn.lock: one whitespace-only line of a megabyte inside an entry is a blank line", () => {
    expect(names(lockDir("yarn.lock", `"zq-a@^1.0.0":\n  version "1.0.0"\n${" ".repeat(SIZE)}\n  resolved "https://npm.zqacme.example/zq-a/-/zq-a-1.0.0.tgz#x"\n`))).toEqual(["zq-a"]);
  });

  it("yarn.lock: a field line too long to read inside an entry is said, never skipped silently", () => {
    const long = `  resolved "https://npm.zqacme.example/${"a".repeat(5000)}.tgz"`;
    expect(names(lockDir("yarn.lock", `"zq-a@^1.0.0":\n  version "1.0.0"\n${long}\n`))).toEqual(["UNREAD yarn.lock"]);
  });

  it("yarn.lock: an entry whose header is too long is skipped, as the lockfile reader skips it; the next entry is read", () => {
    const header = `${Array.from({ length: 400 }, (_, i) => `"zq-long@^1.0.${i}"`).join(", ")}:`;
    expect(header.length).toBeGreaterThan(4096);
    expect(names(lockDir("yarn.lock", `${header}\n  version "1.0.400"\n  resolved "https://npm.zqacme.example/zq-long/-/zq-long-1.0.400.tgz"\n\n${PRIVATE_ENTRY}`))).toEqual(["zq-a"]);
  });

  it("pnpm-lock.yaml: one package key line of a megabyte", () => {
    for (const key of [`a@${"b".repeat(SIZE)}`, `${"a".repeat(SIZE)}`, `a@1${"(b@1)".repeat(SIZE / 5)}:`, `'@zq/${"a".repeat(SIZE)}`]) {
      expect(names(lockDir("pnpm-lock.yaml", `lockfileVersion: '9.0'\n\npackages:\n\n  ${key}\n`))).toEqual(key.endsWith(":") ? [] : ["UNREAD pnpm-lock.yaml"]);
    }
  });

  it("pnpm-lock.yaml: a long key keeps its own tarball, and the entry before it keeps none", () => {
    const peers = "(peer-a@1.0.0)".repeat(400);
    expect(peers.length).toBeGreaterThan(4096);
    const lock = ["lockfileVersion: '9.0'", "", "packages:", "", "  lodash@4.17.20:", "    resolution: {integrity: sha512-a}", "", `  '@zqacme/ui@1.2.3${peers}':`, "    resolution: {integrity: sha512-b, tarball: https://npm.zqacme.example/@zqacme/ui/-/ui-1.2.3.tgz}", ""].join("\n");
    expect(npmLockPrivateSources(lockDir("pnpm-lock.yaml", lock), new Set()).map((p) => `${p.name}@${p.version}`)).toEqual(["@zqacme/ui@1.2.3"]);
  });

  it("pnpm-lock.yaml: a megabyte of blank or indented lines, and a field line too long to read", () => {
    const entry = "packages:\n\n  '@zqacme/ui@1.2.3':\n    resolution: {tarball: https://npm.zqacme.example/@zqacme/ui/-/ui-1.2.3.tgz}\n";
    expect(names(lockDir("pnpm-lock.yaml", `${entry}${"  \n".repeat(SIZE / 3)}`))).toEqual(["@zqacme/ui"]);
    expect(names(lockDir("pnpm-lock.yaml", `${entry}${" ".repeat(SIZE)}\n`))).toEqual(["@zqacme/ui"]);
    expect(names(lockDir("pnpm-lock.yaml", `packages:\n\n  a@1.0.0:\n    resolution: {integrity: ${"x".repeat(5000)}}\n`))).toEqual(["UNREAD pnpm-lock.yaml"]);
  });
});

describe("the YAML configuration readers walk a long line once", () => {
  const indentRun = `importers:\n${" ".repeat(SIZE)}x\n`;
  const spacedKey = `a${" ".repeat(SIZE)}b\n`;

  it(".yarnrc.yml: a megabyte of indentation before a word, and inside a key", () => {
    expect(parseYamlSubset(indentRun)).toEqual({ importers: {} });
    expect(parseYamlSubset(spacedKey)).toEqual({});
    expect(yarnrcPrivateScopes(`${indentRun}npmScopes:\n  zqacme:\n    npmRegistryServer: "https://npm.zqacme.example/"\n`)).toEqual(["@zqacme"]);
    expect(yarnrcRegistry(`npmRegistryServer: x${" ".repeat(SIZE)}y\n`)).toBe(`x${" ".repeat(SIZE)}y`);
    expect(yarnrcRegistry(`${indentRun}npmRegistryServer: "https://npm.zqacme.example/" # ours\n`)).toBe("https://npm.zqacme.example/");
  });

  it("pnpm-workspace.yaml: the same lines, and the settings after them are still read", () => {
    expect(pnpmWorkspaceRegistries(indentRun)).toEqual({ scopes: [], registry: null });
    expect(pnpmWorkspaceRegistries(`registries:\n${" ".repeat(SIZE)}x\n`).unread).toBeDefined();
    expect(pnpmWorkspaceRegistries(`${spacedKey}registries:\n  "@zqacme": https://npm.zqacme.example/\n`)).toEqual({ scopes: ["@zqacme"], registry: null });
  });

  it("the key readers answer as before on ordinary lines", () => {
    expect(parseYamlSubset('npmScopes:\n  "acme":\n    npmRegistryServer: "https://npm.acme.dev/"\nenableTelemetry: false\n\'quoted key\' : v\n')).toEqual({
      npmScopes: { acme: { npmRegistryServer: "https://npm.acme.dev/" } },
      enableTelemetry: "false",
      "quoted key": "v",
    });
    // A plain key ends at the first colon that whitespace or the line's end follows, so a URL key is read whole.
    expect(pnpmWorkspaceRegistries('registries:\n  https://npm.zqacme.example/:\n    scopes: ["@zqa"]\n  "https://registry.npmjs.org/":\n    scopes: ["@pub"]\n')).toEqual({ scopes: ["@zqa"], registry: null });
    expect(pnpmWorkspaceRegistries("registry: https://npm.zqacme.example/\n")).toEqual({ scopes: [], registry: "https://npm.zqacme.example/" });
  });
});

describe("GOPRIVATE patterns are matched as Go's path.Match matches them, in bounded time", () => {
  const stars = (n: number) => `${"a*".repeat(n)}b`;

  it("many `*` against a name that does not match, and one that does", () => {
    expect(goPrivateMatch(stars(40), "a".repeat(200))).toBeNull();
    expect(goPrivateMatch(stars(40), `${"a".repeat(200)}b`)).toBe(stars(40));
    expect(goPrivateMatch(`github.com/${stars(30)}/*`, `github.com/${"a".repeat(300)}/x`)).toBeNull();
    expect(goPrivateMatch(`github.com/${stars(30)}`, `github.com/${"a".repeat(300)}b/core/v2`)).toBe(`github.com/${stars(30)}`);
  });

  it("`*` and `?` stay inside one path element; classes, ranges and negation are read", () => {
    expect(goPrivateMatch("*.corp.example.com", "git.corp.example.com/team/x")).toBe("*.corp.example.com");
    expect(goPrivateMatch("*.corp.example.com", "corp.example.com/team/x")).toBeNull();
    expect(goPrivateMatch("github.com/acme*", "github.com/acme-tools/x")).toBe("github.com/acme*");
    expect(goPrivateMatch("github.com/acme*", "github.com/other/acme")).toBeNull();
    expect(goPrivateMatch("github.com/*", "github.com")).toBeNull();
    expect(goPrivateMatch("git?.zq.example", "git1.zq.example/a")).toBe("git?.zq.example");
    expect(goPrivateMatch("git?.zq.example", "git.zq.example/a")).toBeNull();
    expect(goPrivateMatch("git[0-9].zq.example", "git7.zq.example/a")).toBe("git[0-9].zq.example");
    expect(goPrivateMatch("git[0-9].zq.example", "gitx.zq.example/a")).toBeNull();
    expect(goPrivateMatch("git[^0-9].zq.example", "gitx.zq.example/a")).toBe("git[^0-9].zq.example");
    expect(goPrivateMatch("git[abc]*.zq.example/team", "gitb-eu.zq.example/team/core")).toBe("git[abc]*.zq.example/team");
    // A dot is a dot, never "any character"; a malformed class matches nothing.
    expect(goPrivateMatch("git.zq.example", "gitxzq.example/a")).toBeNull();
    expect(goPrivateMatch("git[0-9.zq.example", "git[0-9.zq.example/a")).toBeNull();
    // Case-insensitive, as before.
    expect(goPrivateMatch("GitHub.com/ZQcorp/*", "github.com/zqcorp/other")).toBe("GitHub.com/ZQcorp/*");
  });

  it("a pattern over the length cap is cut and ends in `*`: it can only match more", () => {
    const long = `git.zq.example/${"team-".repeat(300)}`;
    expect(long.length).toBeGreaterThan(1024);
    expect(goPrivateMatch(long, `git.zq.example/${"team-".repeat(300)}core`)).toMatch(/cut at 1,024 characters/);
    expect(goPrivateMatch(long, `git.zq.example/${"team-".repeat(250)}`)).toMatch(/cut at 1,024 characters/);
    expect(goPrivateMatch(long, "git.other.example/team-")).toBeNull();
  });

  it("the rules use it: GOPRIVATE with many `*` answers for every module", () => {
    const rules = rulesWith({ GOPRIVATE: `${stars(40)},git.zq.example/*` });
    expect(rules.reasonFor("Go", `${"a".repeat(200)}/x`)).toBeNull();
    expect(rules.reasonFor("Go", "git.zq.example/team/core")).toMatch(/GOPRIVATE/);
  });
});

describe("FOURDA_PRIVATE_PACKAGES entries are matched in bounded time", () => {
  it("many `*` against a name that does not match, and one that does", () => {
    const pattern = `${"a*".repeat(40)}b`;
    const rules = rulesWith({ FOURDA_PRIVATE_PACKAGES: pattern });
    for (const ecosystem of ["npm", "PyPI", "crates.io", "Go"]) {
      expect(rules.reasonFor(ecosystem, "a".repeat(200)), ecosystem).toBeNull();
      expect(rules.reasonFor(ecosystem, `${"a".repeat(200)}b`), ecosystem).toContain("FOURDA_PRIVATE_PACKAGES lists");
    }
  });

  it("`*` matches anything, `/` included; a bare scope is the whole scope; case does not matter", () => {
    const rules = rulesWith({ FOURDA_PRIVATE_PACKAGES: "@zqacme, zq-*, *-internal, npm:zqmid*core, PyPI:zq_py.*, crates.io:zq_crate*, Go:git.zq.example/*" });
    const hit = (ecosystem: string, name: string) => rules.reasonFor(ecosystem, name) !== null;
    expect(hit("npm", "@zqacme/ui")).toBe(true);
    expect(hit("npm", "@ZQacme/UI")).toBe(true);
    expect(hit("npm", "@zqacme")).toBe(true);
    expect(hit("npm", "@zqacme-other/ui")).toBe(false);
    expect(hit("npm", "zq-tools")).toBe(true);
    expect(hit("npm", "ZQ-Tools")).toBe(true);
    expect(hit("npm", "zq")).toBe(false);
    expect(hit("npm", "billing-internal")).toBe(true);
    expect(hit("npm", "internal")).toBe(false);
    expect(hit("npm", "zqmid-x-core")).toBe(true);
    expect(hit("npm", "zqmidcore")).toBe(true);
    expect(hit("npm", "zqmidcor")).toBe(false);
    expect(hit("PyPI", "zqmid-x-core")).toBe(false);
    // PyPI and crates.io names are compared as their registries compare them.
    expect(hit("PyPI", "Zq-Py_Lib")).toBe(true);
    expect(hit("crates.io", "zq-crate-core")).toBe(true);
    expect(hit("Go", "git.zq.example/team/core/v2")).toBe(true);
    expect(hit("Go", "git.zq.example")).toBe(false);
    // A regular-expression character in an entry is that character.
    const literal = rulesWith({ FOURDA_PRIVATE_PACKAGES: "zq.lib, zq+plus, zq(x)" });
    expect(literal.reasonFor("npm", "zq.lib")).not.toBeNull();
    expect(literal.reasonFor("npm", "zqxlib")).toBeNull();
    expect(literal.reasonFor("npm", "zq+plus")).not.toBeNull();
    expect(literal.reasonFor("npm", "zq(x)")).not.toBeNull();
  });

  it("an entry over the length cap is cut and ends in `*`: it can only match more", () => {
    const long = `zq-${"x".repeat(1100)}`;
    const rules = rulesWith({ FOURDA_PRIVATE_PACKAGES: long });
    expect(rules.reasonFor("npm", `${long}-and-more`)).not.toBeNull();
    expect(rules.reasonFor("npm", long)).not.toBeNull();
    expect(rules.reasonFor("npm", "zq-other")).toBeNull();
  });
});
