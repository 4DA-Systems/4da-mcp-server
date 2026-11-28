// SPDX-License-Identifier: Apache-2.0
/**
 * Round 25b of the hook lane: a package manager's configuration file edited directly is no way
 * round S6. Each CONFIG_FILES entry x {add, change, remove} x {inert key, resolution key, unknown
 * key} x {Edit, Write}; pip-sync reads its files at the call; a TOML manifest with a lone CR is
 * not read.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import * as hook from "../../hooks/manifest-edit.mjs";
import { sandbox, type Sandbox } from "./helpers/a1123-hookfix-run.js";

let s: Sandbox;
beforeEach(() => {
  s = sandbox();
  s.ledger([{ ecosystem: "PyPI", package: "requests", version: "2.19.0", verdict: "avoid", reason: "test avoid" }]);
});
afterEach(() => s.dispose());

type Key = { key: string; a: string; b: string };
/** Per file: its path, how a key = value line is written, and an inert, a resolution and an unknown key. */
const FILES: Array<{ path: string; line: (k: string, v: string) => string; head?: string; inert: Key; resolution: Key; unknown: Key }> = [
  { path: ".npmrc", line: (k, v) => `${k}=${v}\n`, inert: { key: "fund", a: "false", b: "true" }, resolution: { key: "registry", a: "https://registry.npmjs.org/", b: "https://npm.example.com/" }, unknown: { key: "frobnicate", a: "1", b: "2" } },
  { path: ".yarnrc", line: (k, v) => `${k} "${v}"\n`, inert: { key: "save-exact", a: "true", b: "false" }, resolution: { key: "registry", a: "https://registry.yarnpkg.com", b: "https://npm.example.com" }, unknown: { key: "frobnicate", a: "1", b: "2" } },
  { path: ".yarnrc.yml", line: (k, v) => `${k}: ${v}\n`, inert: { key: "nodeLinker", a: "node-modules", b: "pnp" }, resolution: { key: "npmRegistryServer", a: '"https://registry.yarnpkg.com"', b: '"https://npm.example.com"' }, unknown: { key: "frobnicate", a: "1", b: "2" } },
  { path: "bunfig.toml", head: "[install]\n", line: (k, v) => `${k} = ${v}\n`, inert: { key: "exact", a: "true", b: "false" }, resolution: { key: "registry", a: '"https://registry.npmjs.org/"', b: '"https://npm.example.com/"' }, unknown: { key: "frobnicate", a: "1", b: "2" } },
  { path: ".cargo/config.toml", line: (k, v) => `[${k.split(" ")[0]}]\n${k.split(" ")[1]} = ${v}\n`, inert: { key: "build jobs", a: "4", b: "8" }, resolution: { key: "source.crates-io replace-with", a: '"a"', b: '"b"' }, unknown: { key: "frob x", a: "1", b: "2" } },
  { path: ".cargo/config", head: "[net]\n", line: (k, v) => `${k} = ${v}\n`, inert: { key: "zzz", a: "1", b: "2" }, resolution: { key: "git-fetch-with-cli", a: "true", b: "false" }, unknown: { key: "frobnicate", a: "1", b: "2" } },
  { path: "pip.conf", head: "[global]\n", line: (k, v) => `${k} = ${v}\n`, inert: { key: "timeout", a: "60", b: "30" }, resolution: { key: "index-url", a: "https://pypi.org/simple", b: "https://pypi.example.com/simple" }, unknown: { key: "frobnicate", a: "1", b: "2" } },
  { path: "pip.ini", head: "[global]\n", line: (k, v) => `${k} = ${v}\n`, inert: { key: "timeout", a: "60", b: "30" }, resolution: { key: "extra-index-url", a: "https://a.example.com/simple", b: "https://b.example.com/simple" }, unknown: { key: "frobnicate", a: "1", b: "2" } },
  { path: "uv.toml", line: (k, v) => `${k} = ${v}\n`, inert: { key: "cache-dir", a: '".a"', b: '".b"' }, resolution: { key: "index-url", a: '"https://pypi.org/simple"', b: '"https://pypi.example.com/simple"' }, unknown: { key: "frobnicate", a: "1", b: "2" } },
  { path: "poetry.toml", line: (k, v) => `[${k.split(" ")[0]}]\n${k.split(" ")[1]} = ${v}\n`, inert: { key: "virtualenvs in-project", a: "true", b: "false" }, resolution: { key: "repositories.x url", a: '"https://a.example.com"', b: '"https://b.example.com"' }, unknown: { key: "frob x", a: "1", b: "2" } },
];
// (.cargo/config's [net] has no inert key: its "inert" row there is an unlisted key, held like the others.)
const INERT_ROW_HELD = new Set([".cargo/config"]);
const OPS = ["add", "change", "remove"] as const;
const KINDS = ["inert", "resolution", "unknown"] as const;
const cases = FILES.flatMap((f) => OPS.flatMap((op) => KINDS.flatMap((kind) => (["Edit", "Write"] as const).map((tool) => [f.path, op, kind, tool] as const))));

describe("each config file x {add, change, remove} x {inert, resolution, unknown} x {Edit, Write}", () => {
  it.each(cases)("%s: %s an %s key with %s", (path, op, kind, tool) => {
    const f = FILES.find((x) => x.path === path)!;
    const k = f[kind];
    const base = `${f.head ?? ""}${f.line("zzkeep", "1").replace(/^zzkeep/, path === "poetry.toml" || path.endsWith(".toml") || path.endsWith("config") ? "zzkeep" : "zzkeep")}`;
    const before = op === "add" ? base : base + f.line(k.key, k.a);
    const after = op === "remove" ? base : base + f.line(k.key, op === "change" ? k.b : k.a);
    const file = s.file(path, before);
    const r = tool === "Write" ? s.write(file, after) : s.edit(file, before, after);
    const held = kind !== "inert" || INERT_ROW_HELD.has(path);
    expect(r.decision, r.text).toBe(held ? "deny" : "allow");
    if (held) expect(r.text).toContain("FOURDA_PRIVATE_PACKAGES");
  });
});

describe("the ordinary cases", () => {
  it("a comment, save-exact, fund and an auth token in .npmrc go ahead; a private scope line is held with the remedy", () => {
    const file = s.file(".npmrc", "fund=false\n");
    for (const add of ["# a comment\n", "save-exact=true\n", "fund=true\n", "//npm.acme.internal/:_authToken=x\n"]) expect(s.write(file, `fund=false\n${add}`).decision, add).toBe("allow");
    const r = s.write(file, "fund=false\n@acme:registry=https://npm.acme.internal/\n");
    expect(r.decision).toBe("deny");
    expect(r.text).toContain("the user's to set up");
  });
  it("proxy, strict-ssl and cafile are not inert", () => {
    const file = s.file(".npmrc", "");
    for (const add of ["proxy=http://p:8080\n", "strict-ssl=false\n", "cafile=/x.pem\n", "https-proxy=http://p:8080\n"]) expect(s.write(file, add).decision, add).toBe("deny");
  });
  it(".pnpmfile.cjs: any change is held; an unreadable config file is held", () => {
    expect(s.write(s.file(".pnpmfile.cjs", ""), "module.exports = {}\n").decision).toBe("deny");
    expect(s.write(s.file("uv.toml", ""), 'index-url = "https://x\n').decision).toBe("deny");
  });
  it("a config file named outside its folder is not a config file", () => {
    expect(s.write(s.file("docs/config.toml", ""), 'x = "1"\n').decision).toBe("allow");
  });
  it("CONFIG_FILES names each file with its managers", () => {
    for (const c of hook.CONFIG_FILES) expect(c.managers.length * c.name.length).toBeGreaterThan(0);
  });
});

describe("pip-sync reads its files at the call; pip-compile installs nothing", () => {
  const run = (command: string) => s.run({ session_id: "s", cwd: s.project, hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command } });
  it("judged, unreadable, and an option not on its list", () => {
    s.file("reqs.txt", "requests==2.19.0\n");
    s.file("ok.txt", "");
    expect(run("pip-sync reqs.txt").text).toContain("answered avoid");
    expect(run("pip-sync ok.txt").decision).toBe("allow");
    expect(run("pip-sync nope.txt").text).toContain("could not read");
    expect(run('pip-sync --pip-args "-i x" ok.txt').decision).toBe("deny");
    expect(run("pip-compile requirements.in").decision).toBe("allow");
  });
});

describe("a TOML manifest with a lone CR as a line end is not read", () => {
  it("Cargo.toml", () => {
    const r = s.write(s.file("Cargo.toml", ""), '[package]\rname = "a"\r[dependencies]\rregex = "=1.5.4"\n');
    expect(r.text).toContain("a carriage return alone");
  });
});
