// SPDX-License-Identifier: Apache-2.0
/**
 * Every file the private-name rules are read from goes through one reader (readRuleFile,
 * live/text-file.ts): decoded as the lockfile readers decode it, and never "read as empty" when it
 * is there and could not be read.
 *
 * - A lockfile or configuration file saved with a byte-order mark or as UTF-16 names the same
 *   private packages as the plain file.
 * - A file that is over the size cap, fails to read, or is not text makes the names of ITS
 *   ecosystem under ITS folder private (never sent, NOT CHECKED, the file named), and leaves the
 *   other ecosystems and the sibling folders alone.
 *
 * Every request is recorded by a stubbed fetch: nothing leaves the process. Private-looking names
 * carry `zq`. HOME and the user's configuration directories point into the test's own directory.
 */
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import * as fs from "node:fs";
import fsModule from "node:fs";
import { syncBuiltinESMExports } from "node:module";
import * as os from "node:os";
import * as path from "node:path";

import { FourDADatabase } from "../db.js";
import { LiveIntelligence } from "../live/index.js";
import { clearLiveIntelligence, setLiveIntelligence } from "../live-singleton.js";
import { dispatchTool } from "../tool-dispatch.js";
import { scanProjectTree, treeResolutionGroups } from "../project-tree.js";
import { PrivatePackageRules, manifestPrivateSources, npmLockPrivateSources } from "../live/private-packages.js";
import { readRuleFile } from "../live/text-file.js";

vi.mock("../live/cargo-platform.js", async (importOriginal) => ({ ...(await importOriginal<typeof import("../live/cargo-platform.js")>()), activeCratesForHost: () => null }));

let scratch: string;
let home: string;
let project: string;
let sent: string[];
const savedEnv = new Map<string, string | undefined>();
const setEnv = (key: string, value: string | undefined) => {
  if (!savedEnv.has(key)) savedEnv.set(key, process.env[key]);
  if (value === undefined) delete process.env[key];
  else process.env[key] = value;
};
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

type Encoding = "utf8" | "utf8-bom" | "utf16le-bom" | "utf16be-bom" | "utf16le";
const ENCODINGS: Encoding[] = ["utf8-bom", "utf16le-bom", "utf16be-bom", "utf16le"];
function encode(text: string, encoding: Encoding): Buffer {
  if (encoding === "utf8") return Buffer.from(text, "utf8");
  if (encoding === "utf8-bom") return Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(text, "utf8")]);
  const le = Buffer.from(text, "utf16le");
  if (encoding === "utf16le") return le;
  if (encoding === "utf16le-bom") return Buffer.concat([Buffer.from([0xff, 0xfe]), le]);
  const be = Buffer.from(le);
  be.swap16();
  return Buffer.concat([Buffer.from([0xfe, 0xff]), be]);
}
const write = (root: string, file: string, content: string | Buffer) => {
  fs.mkdirSync(path.dirname(path.join(root, file)), { recursive: true });
  fs.writeFileSync(path.join(root, file), content);
};
const writeFiles = (root: string, files: Record<string, string | Buffer>) => {
  for (const [file, content] of Object.entries(files)) write(root, file, content);
};
const leaks = (re: RegExp) => sent.filter((s) => re.test(s));

/**
 * While `run` runs, reading a file named `io-error*` fails as a failing disk does (EIO), for every
 * module in the process: node's own `fs` is patched and its ES exports re-synchronised, then restored.
 */
function withReadErrors<T>(run: () => T): T {
  const real = fsModule.readFileSync;
  fsModule.readFileSync = ((file: unknown, ...rest: unknown[]) => {
    if (typeof file === "string" && path.basename(file).startsWith("io-error")) throw Object.assign(new Error("EIO: i/o error, read"), { code: "EIO" });
    return (real as (...a: unknown[]) => unknown)(file, ...rest);
  }) as typeof fsModule.readFileSync;
  syncBuiltinESMExports();
  try {
    return run();
  } finally {
    fsModule.readFileSync = real;
    syncBuiltinESMExports();
  }
}

beforeAll(() => setEnv("FOURDA_OFFLINE", undefined));
afterAll(() => {
  for (const [key, value] of savedEnv) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
});
beforeEach(() => {
  scratch = fs.mkdtempSync(path.join(os.tmpdir(), "4da-a1119-rules-"));
  home = path.join(scratch, "home");
  project = path.join(scratch, "project");
  fs.mkdirSync(home, { recursive: true });
  fs.mkdirSync(project, { recursive: true });
  sent = [];
  setEnv("HOME", home);
  setEnv("USERPROFILE", home);
  setEnv("APPDATA", path.join(home, "AppData", "Roaming"));
  setEnv("LOCALAPPDATA", path.join(home, "AppData", "Local"));
  setEnv("XDG_CONFIG_HOME", undefined);
  setEnv("XDG_CONFIG_DIRS", path.join(home, "xdg-none"));
  setEnv("ProgramData", path.join(home, "ProgramData"));
  setEnv("VIRTUAL_ENV", undefined);
  setEnv("PIP_CONFIG_FILE", undefined);
  setEnv("PIP_INDEX_URL", undefined);
  setEnv("PIP_EXTRA_INDEX_URL", undefined);
  setEnv("UV_NO_CONFIG", undefined);
  setEnv("UV_CONFIG_FILE", undefined);
  setEnv("GOPROXY", undefined);
  setEnv("GOPRIVATE", undefined);
  setEnv("GONOSUMDB", undefined);
  setEnv("GONOPROXY", undefined);
  setEnv("GOENV", "off");
  setEnv("CARGO_HOME", path.join(home, ".cargo"));
  setEnv("NPM_CONFIG_USERCONFIG", path.join(home, ".npmrc"));
  setEnv("NPM_CONFIG_GLOBALCONFIG", path.join(home, "global-npmrc"));
  setEnv("FOURDA_PUBLIC_MIRRORS", undefined);
  setEnv("FOURDA_PRIVATE_PACKAGES", undefined);
  setEnv("FOURDA_MAX_LOCKFILE_BYTES", undefined);
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: string, init?: RequestInit) => {
      const url = String(input);
      const body = typeof init?.body === "string" ? init.body : "";
      let readable = url;
      for (let i = 0; i < 4; i++) {
        try {
          const next = decodeURIComponent(readable);
          if (next === readable) break;
          readable = next;
        } catch {
          break;
        }
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
  clearLiveIntelligence();
  for (const [key, value] of savedEnv) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
  savedEnv.clear();
  setEnv("FOURDA_OFFLINE", undefined);
  try {
    fs.rmSync(scratch, { recursive: true, force: true });
  } catch {
    // Windows: left for the OS temp cleaner.
  }
});

/** The project's live layer, made the server's. */
function liveFor(files: Record<string, string | Buffer>, homeFiles: Record<string, string | Buffer> = {}): LiveIntelligence {
  writeFiles(project, files);
  writeFiles(home, homeFiles);
  const live = new LiveIntelligence(null);
  const { entries, discovery } = scanProjectTree(project);
  live.initFromProjectTree(project, treeResolutionGroups(entries), discovery);
  setLiveIntelligence(live);
  return live;
}

async function call(tool: string, args: Record<string, unknown>): Promise<string> {
  const db = new FourDADatabase(path.join(scratch, `standalone-${Math.random().toString(36).slice(2)}.db`));
  try {
    const result = await dispatchTool(tool, db, args).catch((error: unknown) => ({ content: [{ type: "text", text: String(error) }] }));
    return JSON.stringify(result);
  } finally {
    db.close();
  }
}

const PRIVATE_HOST = "https://npm.zqacme.example";
const publicNpm = (name: string, version: string) => `https://registry.npmjs.org/${name}/-/${name.split("/").pop()}-${version}.tgz`;
const privateNpm = (name: string, version: string) => `${PRIVATE_HOST}/${name}/-/${name.split("/").pop()}-${version}.tgz`;
const npmLock = (deps: Record<string, string>, resolved: (name: string, version: string) => string | undefined) =>
  JSON.stringify(
    {
      name: "app",
      lockfileVersion: 3,
      packages: {
        "": { name: "app", dependencies: deps },
        ...Object.fromEntries(Object.entries(deps).map(([name, version]) => [`node_modules/${name}`, { version, ...(resolved(name, version) ? { resolved: resolved(name, version) } : {}) }])),
      },
    },
    null,
    2,
  );
const pkgJson = (deps: Record<string, string>) => JSON.stringify({ name: "app", version: "1.0.0", dependencies: deps });
const MIXED = { lodash: "4.17.20", "@zqacme/secret-lib": "1.0.0" };
const mixedLock = () => npmLock(MIXED, (name, version) => (name.startsWith("@zqacme/") ? privateNpm(name, version) : publicNpm(name, version)));
const privateNames = (live: LiveIntelligence) => live.getPrivateDependencies().map((d) => d.name).sort();

describe("a lockfile saved with a byte-order mark or as UTF-16 names the same private packages", () => {
  it("control: the plain UTF-8 lockfile keeps the private name in, and lodash is asked about", async () => {
    const live = liveFor({ "package.json": pkgJson(MIXED), "package-lock.json": mixedLock() });
    expect(privateNames(live)).toEqual(["@zqacme/secret-lib"]);
    await call("vulnerability_scan", { force_refresh: true });
    expect(leaks(/zqacme/i)).toEqual([]);
    expect(leaks(/lodash/).length).toBeGreaterThan(0);
  });

  for (const encoding of ENCODINGS) {
    it(`package-lock.json as ${encoding}: the private name is never sent and is reported NOT CHECKED (private)`, async () => {
      const live = liveFor({ "package.json": pkgJson(MIXED), "package-lock.json": encode(mixedLock(), encoding) });
      expect(privateNames(live)).toEqual(["@zqacme/secret-lib"]);
      const scan = await call("vulnerability_scan", { force_refresh: true });
      expect(leaks(/zqacme/i)).toEqual([]);
      expect(leaks(/lodash/).length).toBeGreaterThan(0);
      expect(scan).toContain("NOT CHECKED (private)");
      await call("dependency_check", { items: [{ ecosystem: "npm", package: "@zqacme/secret-lib", to: "1.0.1" }] });
      expect(leaks(/zqacme/i)).toEqual([]);
    });
  }

  it("yarn.lock, pnpm-lock.yaml and bun.lock as UTF-16: the private entries are read", () => {
    const yarn = `# yarn lockfile v1\n\n"@zqacme/yarn-lib@^1.0.0":\n  version "1.0.0"\n  resolved "${PRIVATE_HOST}/@zqacme/yarn-lib/-/yarn-lib-1.0.0.tgz#abc"\n`;
    const pnpm = `lockfileVersion: '9.0'\n\npackages:\n\n  '@zqacme/pnpm-lib@1.0.0':\n    resolution: {integrity: sha512-x, tarball: ${PRIVATE_HOST}/@zqacme/pnpm-lib/-/pnpm-lib-1.0.0.tgz}\n`;
    const bun = JSON.stringify({ lockfileVersion: 1, packages: { "@zqacme/bun-lib": ["@zqacme/bun-lib@1.0.0", `${PRIVATE_HOST}/@zqacme/bun-lib/-/bun-lib-1.0.0.tgz`, {}, "sha512-x"] } });
    for (const encoding of ["utf16le-bom", "utf8-bom"] as const) {
      const dir = fs.mkdtempSync(path.join(scratch, "locks-"));
      writeFiles(dir, { "yarn.lock": encode(yarn, encoding), "pnpm-lock.yaml": encode(pnpm, encoding), "bun.lock": encode(bun, encoding) });
      expect(npmLockPrivateSources(dir, new Set()).map((p) => p.name).sort()).toEqual(["@zqacme/bun-lib", "@zqacme/pnpm-lib", "@zqacme/yarn-lib"]);
    }
  });
});

describe("a configuration file saved with a byte-order mark or as UTF-16 sets the same rules", () => {
  const rulesFor = (dir: string) => new PrivatePackageRules([dir], process.env);
  for (const encoding of ["utf8-bom", "utf16le-bom", "utf16be-bom"] as const) {
    it(`${encoding}: .npmrc, .yarnrc.yml, bunfig.toml, pnpm-workspace.yaml`, () => {
      const cases: Array<[string, string, string]> = [
        [".npmrc", "@zqnpm:registry=https://npm.zqacme.example/\n", "@zqnpm/x"],
        [".yarnrc.yml", 'npmScopes:\n  zqyarn:\n    npmRegistryServer: "https://npm.zqacme.example/"\n', "@zqyarn/x"],
        ["bunfig.toml", '[install.scopes]\n"@zqbun" = "https://npm.zqacme.example/"\n', "@zqbun/x"],
        ["pnpm-workspace.yaml", 'registries:\n  "@zqpnpm": https://npm.zqacme.example/\n', "@zqpnpm/x"],
      ];
      for (const [file, content, name] of cases) {
        const dir = fs.mkdtempSync(path.join(scratch, "cfg-"));
        write(dir, file, encode(content, encoding));
        expect(rulesFor(dir).reasonFor("npm", name), `${file} as ${encoding}`).toMatch(/mapped to a private registry/);
      }
    });

    it(`${encoding}: pip's config, uv.toml, pyproject.toml, a Pipfile, Cargo's config and the go env file`, () => {
      const dir = fs.mkdtempSync(path.join(scratch, "cfg-"));
      const pip = path.join(dir, "pip.conf");
      fs.writeFileSync(pip, encode("[global]\nindex-url = https://pypi.zqacme.example/simple\n", encoding));
      setEnv("PIP_CONFIG_FILE", pip);
      expect(rulesFor(dir).ecosystemWide("PyPI", dir, false)).toMatch(/pypi\.zqacme\.example/);
      setEnv("PIP_CONFIG_FILE", undefined);

      const uv = fs.mkdtempSync(path.join(scratch, "cfg-"));
      write(uv, "uv.toml", encode('index-url = "https://pypi.zqacme.example/simple"\n', encoding));
      expect(rulesFor(uv).ecosystemWide("PyPI", uv, false)).toMatch(/pypi\.zqacme\.example/);

      const pyproject = fs.mkdtempSync(path.join(scratch, "cfg-"));
      write(pyproject, "pyproject.toml", encode('[[tool.pdm.source]]\nname = "zq"\nurl = "https://pypi.zqacme.example/simple"\n', encoding));
      expect(rulesFor(pyproject).ecosystemWide("PyPI", pyproject, false)).toMatch(/pypi\.zqacme\.example/);

      const pipfile = fs.mkdtempSync(path.join(scratch, "cfg-"));
      write(pipfile, "Pipfile", encode('[[source]]\nname = "zq"\nurl = "https://pypi.zqacme.example/simple"\n\n[packages]\nzq-pylib = "*"\n', encoding));
      expect(rulesFor(pipfile).reasonFor("PyPI", "zq-pylib")).toMatch(/Pipfile/);

      const cargo = fs.mkdtempSync(path.join(scratch, "cfg-"));
      write(cargo, ".cargo/config.toml", encode('[source.crates-io]\nreplace-with = "zq"\n\n[source.zq]\nregistry = "sparse+https://cargo.zqacme.example/index/"\n', encoding));
      expect(rulesFor(cargo).ecosystemWide("crates.io", cargo, false)).toMatch(/cargo\.zqacme\.example/);

      const goEnv = path.join(dir, "go-env");
      fs.writeFileSync(goEnv, encode("GOPRIVATE=git.zqacme.example\n", encoding));
      setEnv("GOENV", goEnv);
      expect(rulesFor(dir).reasonFor("Go", "git.zqacme.example/team/core")).toMatch(/GOPRIVATE/);
    });
  }

  it("a Cargo.toml and a pyproject.toml as UTF-16 name the same private sources", () => {
    const dir = fs.mkdtempSync(path.join(scratch, "manifest-"));
    write(dir, "Cargo.toml", encode('[package]\nname = "app"\nversion = "0.1.0"\n\n[dependencies]\nzq-ledger = { version = "=1.2.0", registry = "zqacme" }\n', "utf16le-bom"));
    expect(manifestPrivateSources(dir, "crates.io").map((p) => p.name)).toContain("zq-ledger");
    write(dir, "pyproject.toml", encode('[project]\nname = "app"\ndependencies = ["zq-quant==2.0.0"]\n\n[tool.uv.sources]\nzq-quant = { index = "zqacme" }\n', "utf16le-bom"));
    expect(manifestPrivateSources(dir, "PyPI").map((p) => p.name)).toContain("zq-quant");
  });
});

describe("an .npmrc the old 1 MB limit skipped", () => {
  it("a scope mapping in an .npmrc over 1 MB is read: the private name is never sent", async () => {
    const padding = `${"# padding ".repeat(12)}\n`.repeat(9000);
    expect(Buffer.byteLength(padding)).toBeGreaterThan(1024 * 1024);
    const live = liveFor({ "package.json": pkgJson(MIXED), "package-lock.json": npmLock(MIXED, publicNpm), ".npmrc": `${padding}@zqacme:registry=${PRIVATE_HOST}/\n` });
    expect(privateNames(live)).toEqual(["@zqacme/secret-lib"]);
    await call("vulnerability_scan", { force_refresh: true });
    expect(leaks(/zqacme/i)).toEqual([]);
    expect(leaks(/lodash/).length).toBeGreaterThan(0);
  });
});

describe("a rule file that is there and cannot be read fails closed for its ecosystem and its folder", () => {
  const NPM_AND_PYPI = {
    "package.json": pkgJson(MIXED),
    "package-lock.json": npmLock(MIXED, publicNpm),
    "requirements.txt": "requests==2.31.0\n",
  };

  it("an .npmrc over the size cap: no npm name is sent, the reason names the file, PyPI beside it is checked", async () => {
    setEnv("FOURDA_MAX_LOCKFILE_BYTES", "20000");
    const live = liveFor({ ...NPM_AND_PYPI, ".npmrc": `${"# padding\n".repeat(3000)}@zqacme:registry=${PRIVATE_HOST}/\n` });
    const npmrc = path.join(project, ".npmrc");
    expect(privateNames(live)).toEqual(["@zqacme/secret-lib", "lodash"]);
    for (const dep of live.getPrivateDependencies()) {
      expect(dep.why).toContain(npmrc);
      expect(dep.why).toMatch(/over the .* this server reads/);
      expect(dep.kind).toBe("registry");
    }
    const scan = await call("vulnerability_scan", { force_refresh: true });
    expect(leaks(/zqacme|lodash/i)).toEqual([]);
    expect(leaks(/requests/).length).toBeGreaterThan(0);
    expect(scan).toContain("NOT CHECKED (private)");
    expect(scan).toContain(".npmrc");
    // A name not installed yet is not shown public either; another ecosystem's is.
    const check = await call("dependency_check", { items: [{ ecosystem: "npm", package: "zqnew-thing", to: "1.0.0" }, { ecosystem: "PyPI", package: "urllib3", to: "2.2.0" }] });
    expect(leaks(/zqnew/i)).toEqual([]);
    expect(leaks(/urllib3/).length).toBeGreaterThan(0);
    expect(check).toContain('not_checked\\":\\"private');
  });

  it("a read that fails with an I/O error is not an empty file", () => {
    const dir = fs.mkdtempSync(path.join(scratch, "io-"));
    const file = path.join(dir, "io-error.npmrc");
    fs.writeFileSync(file, "@zqacme:registry=https://npm.zqacme.example/\n");
    expect(withReadErrors(() => readRuleFile(file))).toEqual({ state: "unreadable", reason: "could not be read (EIO)" });
    expect(readRuleFile(file)).toEqual({ state: "read", text: "@zqacme:registry=https://npm.zqacme.example/\n" });
    expect(readRuleFile(path.join(dir, "missing.npmrc"))).toEqual({ state: "absent" });
    expect(readRuleFile(dir)).toEqual({ state: "absent" });
  });

  it("an .npmrc whose read fails: npm under it is private with the file and the error named", async () => {
    setEnv("NPM_CONFIG_USERCONFIG", path.join(home, "io-error.npmrc"));
    const live = withReadErrors(() => liveFor(NPM_AND_PYPI, { "io-error.npmrc": `@zqacme:registry=${PRIVATE_HOST}/\n` }));
    expect(privateNames(live)).toEqual(["@zqacme/secret-lib", "lodash"]);
    expect(live.getPrivateDependencies()[0].why).toMatch(/io-error\.npmrc could not be read \(EIO\)/);
    await call("vulnerability_scan", { force_refresh: true });
    expect(leaks(/zqacme|lodash/i)).toEqual([]);
    expect(leaks(/requests/).length).toBeGreaterThan(0);
  });

  it("a file that is not text (NUL characters) is unreadable, not empty", () => {
    const dir = fs.mkdtempSync(path.join(scratch, "nul-"));
    // UTF-16 with no mark and too short to recognise: every second character decodes to NUL.
    write(dir, ".npmrc", Buffer.from("@z:registry=https://npm.zqacme.example/\n", "utf16le").subarray(0, 6));
    expect(readRuleFile(path.join(dir, ".npmrc")).state).toBe("unreadable");
    const rules = new PrivatePackageRules([dir], process.env);
    expect(rules.ecosystemWide("npm", dir, false)).toMatch(/\.npmrc is not text/);
    expect(rules.ecosystemWide("PyPI", dir, false)).toBeNull();
  });

  it("each ecosystem's configuration: unreadable makes that ecosystem private under that folder only", () => {
    setEnv("FOURDA_MAX_LOCKFILE_BYTES", "4096");
    const big = "# padding\n".repeat(600);
    const cases: Array<{ file: string; ecosystem: string }> = [
      { file: ".npmrc", ecosystem: "npm" },
      { file: ".yarnrc.yml", ecosystem: "npm" },
      { file: "bunfig.toml", ecosystem: "npm" },
      { file: "pnpm-workspace.yaml", ecosystem: "npm" },
      { file: "uv.toml", ecosystem: "PyPI" },
      { file: "pyproject.toml", ecosystem: "PyPI" },
      { file: "Pipfile", ecosystem: "PyPI" },
      { file: ".cargo/config.toml", ecosystem: "crates.io" },
    ];
    for (const { file, ecosystem } of cases) {
      const root = fs.mkdtempSync(path.join(scratch, "unread-"));
      const a = path.join(root, "a");
      const b = path.join(root, "b");
      fs.mkdirSync(b, { recursive: true });
      write(a, file, big);
      const rules = new PrivatePackageRules([a, b], process.env);
      const why = rules.ecosystemWide(ecosystem, a, false);
      expect(why, file).toContain(path.join(a, file));
      expect(why, file).toMatch(/over the .* this server reads/);
      // The sibling folder, and every other ecosystem in this one, are not touched.
      expect(rules.ecosystemWide(ecosystem, b, false), file).toBeNull();
      for (const other of ["npm", "PyPI", "crates.io", "Go"].filter((e) => e !== ecosystem)) expect(rules.ecosystemWide(other, a, false), `${file} / ${other}`).toBeNull();
    }
    // pip's own configuration and the go env file apply everywhere.
    const dir = fs.mkdtempSync(path.join(scratch, "unread-"));
    const pip = path.join(dir, "pip.conf");
    fs.writeFileSync(pip, big);
    setEnv("PIP_CONFIG_FILE", pip);
    const withPip = new PrivatePackageRules([dir], process.env);
    expect(withPip.ecosystemWide("PyPI", dir, false)).toContain(pip);
    // A lockfile that records each package's index needs no configuration to show a package public.
    expect(withPip.ecosystemWide("PyPI", dir, true)).toBeNull();
    expect(withPip.ecosystemWide("npm", dir, false)).toBeNull();
    setEnv("PIP_CONFIG_FILE", undefined);
    const goEnv = path.join(dir, "go-env");
    fs.writeFileSync(goEnv, big);
    setEnv("GOENV", goEnv);
    const withGo = new PrivatePackageRules([dir], process.env);
    expect(withGo.ecosystemWide("Go", dir, false)).toContain(goEnv);
    expect(withGo.ecosystemWide("npm", dir, false)).toBeNull();
  });

  it("a readable file after an unreadable one is read again: the rules go stale with the file", () => {
    setEnv("FOURDA_MAX_LOCKFILE_BYTES", "4096");
    const dir = fs.mkdtempSync(path.join(scratch, "stale-"));
    write(dir, ".npmrc", "# padding\n".repeat(600));
    const rules = new PrivatePackageRules([dir], process.env);
    expect(rules.ecosystemWide("npm", dir, false)).not.toBeNull();
    write(dir, ".npmrc", "@zqacme:registry=https://npm.zqacme.example/\n");
    expect(rules.stale()).toBe(true);
    const again = rules.reread(process.env);
    expect(again.fingerprint()).not.toBe(rules.fingerprint());
    expect(again.ecosystemWide("npm", dir, false)).toBeNull();
    expect(again.reasonFor("npm", "@zqacme/x")).toMatch(/mapped to a private registry/);
  });
});

describe("a lockfile the private-source pass cannot read fails closed for its folder", () => {
  it("package-lock.json that is not JSON: the manifest's pins are not sent, and the lockfile is named", async () => {
    const live = liveFor({
      "package.json": pkgJson(MIXED),
      "package-lock.json": mixedLock().slice(0, 120),
      "requirements.txt": "requests==2.31.0\n",
    });
    const lock = path.join(project, "package-lock.json");
    for (const dep of live.getPrivateDependencies()) expect(dep.why).toContain(lock);
    expect(live.registryPrivate("npm")).toContain(lock);
    expect(live.registryPrivate("PyPI")).toBeNull();
    await call("vulnerability_scan", { force_refresh: true });
    await call("dependency_check", { items: [{ ecosystem: "npm", package: "@zqacme/secret-lib", to: "1.0.1" }] });
    expect(leaks(/zqacme|lodash/i)).toEqual([]);
    expect(leaks(/requests/).length).toBeGreaterThan(0);
  });

  it("a bun.lock that is not JSON is named too; a sibling folder's lockfile is still read", () => {
    const root = fs.mkdtempSync(path.join(scratch, "bun-"));
    write(root, "a/bun.lock", "{ not json");
    write(root, "b/package-lock.json", mixedLock());
    const a = npmLockPrivateSources(path.join(root, "a"), new Set());
    expect(a.filter((p) => p.unread).map((p) => p.file)).toEqual([path.join(root, "a", "bun.lock")]);
    const b = npmLockPrivateSources(path.join(root, "b"), new Set());
    expect(b.filter((p) => p.unread)).toEqual([]);
    expect(b.map((p) => p.name)).toEqual(["@zqacme/secret-lib"]);
  });

  it("a Cargo.toml that cannot be read is not a manifest with no private source", () => {
    setEnv("FOURDA_MAX_LOCKFILE_BYTES", "4096");
    const dir = fs.mkdtempSync(path.join(scratch, "cargo-"));
    write(dir, "Cargo.toml", `[package]\nname = "app"\nversion = "0.1.0"\n${"# padding\n".repeat(600)}`);
    const found = manifestPrivateSources(dir, "crates.io");
    expect(found.filter((p) => p.unread).map((p) => p.file)).toEqual([path.join(dir, "Cargo.toml")]);
  });
});

describe("no private-recognition module reads a file except through readRuleFile", () => {
  const src = path.resolve(__dirname, "..");
  /** Every module that decides which names are private (live/private-*.ts). */
  const modules = fs.readdirSync(path.join(src, "live")).filter((name) => /^private-.*\.ts$/.test(name));
  /** Any way of reading a file's contents; `existsSync`, `statSync` and `readdirSync` read none. */
  const DIRECT_READ = /\b(?:readFileSync|readFile|createReadStream|openSync|readSync|readvSync|promises\s*\.\s*(?:readFile|open))\b|from\s+["']node:fs\/promises["']/;

  it("the modules are the ones this test knows", () => {
    expect(modules.sort()).toEqual(["private-configs.ts", "private-fix-sources.ts", "private-guard.ts", "private-hosts.ts", "private-packages.ts"]);
  });

  it("none of them reads a file directly", () => {
    const offenders: string[] = [];
    for (const name of modules) {
      const code = fs.readFileSync(path.join(src, "live", name), "utf8").replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/.*$/gm, "");
      code.split("\n").forEach((line, i) => {
        if (DIRECT_READ.test(line)) offenders.push(`live/${name}:${i + 1}: ${line.trim()}`);
      });
    }
    expect(offenders).toEqual([]);
  });

  it("the ones that read rule files import the one reader, which decodes and never answers empty for a file it could not read", () => {
    for (const name of ["private-packages.ts"]) expect(fs.readFileSync(path.join(src, "live", name), "utf8")).toMatch(/import \{[^}]*\breadRuleFile\b[^}]*\} from "\.\/text-file\.js";/);
    const reader = fs.readFileSync(path.join(src, "live", "text-file.ts"), "utf8");
    expect(reader).toMatch(/export function readRuleFile\(file: string\): RuleFileRead/);
    expect(reader).toMatch(/decodeText\(fs\.readFileSync\(file\)\)/);
  });

  it("the check itself catches a direct read", () => {
    expect(DIRECT_READ.test('const text = fs.readFileSync(file, "utf8");')).toBe(true);
    expect(DIRECT_READ.test("const text = await fs.promises.readFile(file);")).toBe(true);
    expect(DIRECT_READ.test("if (fs.existsSync(manifest)) out.push(manifest);")).toBe(false);
  });
});

describe("a lockfile read whole that is not valid JSON (a merge conflict) is judged by the locations in its text", () => {
  const conflicted = (ours: string, theirs: string) => `<<<<<<< HEAD\n${ours}\n=======\n${theirs}\n>>>>>>> feature\n`;
  const publicLock = () => npmLock(MIXED, publicNpm);
  const bunLock = (location: (name: string, version: string) => string) =>
    JSON.stringify({ lockfileVersion: 1, packages: Object.fromEntries(Object.entries(MIXED).map(([name, version]) => [name, [`${name}@${version}`, location(name, version), {}, "sha512-x"]])) });

  it("package-lock.json: both sides install from the public registry, so nothing is private and lodash is asked about", async () => {
    const live = liveFor({ "package.json": pkgJson(MIXED), "package-lock.json": conflicted(publicLock(), publicLock()) });
    expect(npmLockPrivateSources(project, new Set())).toEqual([]);
    expect(privateNames(live)).toEqual([]);
  });

  it("package-lock.json: one side installs from a private registry, so the ecosystem here fails closed and nothing private is sent", async () => {
    const live = liveFor({ "package.json": pkgJson(MIXED), "package-lock.json": conflicted(publicLock(), mixedLock()) });
    expect(npmLockPrivateSources(project, new Set())).toEqual([expect.objectContaining({ file: path.join(project, "package-lock.json"), unread: "is not valid JSON" })]);
    expect(privateNames(live)).toEqual(["@zqacme/secret-lib", "lodash"]);
    const scan = await call("vulnerability_scan", { force_refresh: true });
    expect(leaks(/zqacme/i)).toEqual([]);
    expect(scan).toContain("NOT CHECKED (private)");
    expect(scan).toContain("not valid JSON");
  });

  it("bun.lock: the same rule, with the default registry written as an empty location", () => {
    write(project, "bun.lock", conflicted(bunLock(() => ""), bunLock(() => "")));
    expect(npmLockPrivateSources(project, new Set())).toEqual([]);
    write(project, "bun.lock", conflicted(bunLock(() => ""), bunLock((name, version) => (name.startsWith("@zqacme/") ? privateNpm(name, version) : ""))));
    expect(npmLockPrivateSources(project, new Set())).toEqual([expect.objectContaining({ file: path.join(project, "bun.lock"), unread: "is not valid JSON" })]);
  });

  it("a mirror the configuration declares is public here too", () => {
    write(project, "package-lock.json", conflicted(publicLock(), mixedLock()));
    expect(npmLockPrivateSources(project, new Set(["npm.zqacme.example"]))).toEqual([]);
  });

  it("a location written with JSON escapes is read as JSON reads it; one that cannot be read, or an unclosed block, fails closed", () => {
    const unread = () => npmLockPrivateSources(project, new Set()).filter((p) => p.unread).length;
    write(project, "package-lock.json", conflicted(publicLock(), mixedLock().replaceAll("https://npm.zqacme.example/", "https:\\/\\/npm.zqacme.example\\/")));
    expect(unread()).toBe(1);
    write(project, "package-lock.json", conflicted(publicLock(), `{"packages": {"node_modules/@zqacme/x": {"resolved": "${PRIVATE_HOST}/x.tgz\n}}}`));
    expect(unread()).toBe(1);
    write(project, "package-lock.json", `<<<<<<< HEAD\n${publicLock()}\n=======\n${publicLock()}\n`);
    expect(unread()).toBe(1);
  });
});
