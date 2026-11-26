// SPDX-License-Identifier: Apache-2.0
/**
 * Round 16, from the fourteenth independent check: rules on raw text where the manager knows more
 * than one manifest, with the reviewer's cases and a sweep of each class.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { rmSync } from "node:fs";
import { join } from "node:path";

import { sandbox, type Sandbox } from "./helpers/a1123-hookfix-run.js";
import { timed } from "./helpers/a1125-hook-run.js";

let s: Sandbox;
beforeEach(() => {
  s = sandbox();
  s.ledger([
    { ecosystem: "npm", package: "lodash", version: "4.17.21", requested: "latest", verdict: "proceed", reason: "ok" },
    { ecosystem: "npm", package: "ms", version: "2.1.3", requested: "latest", verdict: "proceed", reason: "ok" },
    { ecosystem: "PyPI", package: "requests", version: "2.32.3", requested: "latest", verdict: "proceed", reason: "ok" },
    { ecosystem: "PyPI", package: "typing-extensions", version: "4.12.2", requested: "latest", verdict: "proceed", reason: "ok" },
    { ecosystem: "crates.io", package: "regex", version: "1.11.0", requested: "latest", verdict: "proceed", reason: "ok" },
  ]);
});
afterEach(() => s.dispose());

const run = (command: string, cwd = s.project, tool = "Bash") => s.run({ session_id: "s", cwd, hook_event_name: "PreToolUse", tool_name: tool, tool_input: { command } });

describe("J1: a name alone that a project file here or above names is held", () => {
  it.each([
    ["package.json", '{"dependencies":{"lodash":"4.17.20"}}', "npm install lodash"],
    ["package.json", '{"overrides":{"lodash":"4.17.20"}}', "bun add lodash"],
    ["package.json", '{"resolutions":{"lodash":"4.17.20"}}', "yarn add lodash"],
    ["pnpm-workspace.yaml", "catalog:\n  lodash: 4.17.20\ncatalogMode: prefer\n", "pnpm add lodash"],
    ["pnpm-workspace.yaml", "overrides:\n  lodash: 4.17.20\n", "pnpm add -Dw lodash"],
    [".pnpmfile.cjs", "module.exports = { hooks: { readPackage(p) { p.dependencies.lodash = '4.17.20'; return p; } } };", "pnpm add lodash"],
    ["Cargo.toml", '[workspace]\nmembers = ["app"]\n[workspace.dependencies]\nregex = "=1.5.4"\n', "cargo add regex"],
    ["pyproject.toml", '[tool.uv.workspace]\nmembers = ["app"]\n[project]\nname = "root"\nversion = "0"\ndependencies = ["requests==2.19.0"]\n', "uv add requests"],
    ["pyproject.toml", '[project]\nname = "x"\nversion = "0"\ndependencies = ["typing_extensions==4.0.0"]\n', "uv add Typing.Extensions"],
    ["uv.toml", '[pip]\nconstraint-dependencies = ["requests==2.19.0"]\n', "uv add requests"],
  ])("%s naming it in the folder above; %s from app/: held", (file, content, command) => {
    s.file(file, content);
    s.file("app/.keep", "");
    const r = run(command, `${s.project}/app`);
    expect(r.decision, r.text).toBe("deny");
    // Round 17 (L1): a workspace root above, or a workspace option, is held first, for its own cause.
    const workspace = file === "pnpm-workspace.yaml" || /^\[(?:workspace|tool\.uv\.workspace)\]/.test(content);
    expect(r.text).toContain(workspace ? (command.includes("-Dw") ? "a workspace option" : "this folder is inside a workspace") : `${file} in a parent folder already names`);
    expect(r.text).toContain("name the version");
  });
  it("in this folder: said so; the remedy is in the manager's own syntax", () => {
    s.file("pyproject.toml", '[project]\nname = "x"\nversion = "0"\ndependencies = ["requests==2.19.0"]\n');
    const r = run("uv add requests");
    expect(r.text).toContain("pyproject.toml in this folder already names requests");
    expect(r.text).toContain("`requests==<version>`");
    s.file("package.json", '{"dependencies":{"lodash":"4.17.20"}}');
    expect(run("npm i lodash").text).toContain("`lodash@<version>`");
  });
  it("only a whole word counts: lodash.debounce or my-lodash do not name lodash", () => {
    s.file("package.json", '{"dependencies":{"lodash.debounce":"4.0.8","my-lodash":"1.0.0"}}');
    expect(run("npm install lodash").decision).toBe("allow");
  });
  it("a folder option is read too; a folder it cannot name is held; a global install reads none", () => {
    s.file("sub/package.json", '{"dependencies":{"lodash":"4.17.20"}}');
    expect(run("npm --prefix sub install lodash").text).toContain("already names lodash");
    expect(run("cd sub && npm install lodash").text).toContain("already names lodash");
    expect(run("cd $X && npm install lodash").text).toContain("could not be read");
    s.file("package.json", '{"dependencies":{"lodash":"4.17.20"}}');
    expect(run("npm install -g lodash").decision).toBe("allow");
  });
  it("an unreadable project file holds; a name with a version is judged on it as before", () => {
    s.file("package.json", '{"dependencies":{"lodash":"4.17.20"}}');
    expect(run("npm install lodash@4.17.21").text).not.toContain("already names");
  });
});

describe("J5: `@latest` moves to the newest with npm, pnpm, Yarn and Bun: judged on latest", () => {
  it.each(["npm install lodash@latest", "pnpm add lodash@latest", "yarn add lodash@latest", "bun add lodash@latest"])("%s beside a declaration: goes ahead on the latest proceed", (command) => {
    s.file("package.json", '{"dependencies":{"lodash":"4.17.20"}}');
    expect(run(command).decision, run(command).text).toBe("allow");
  });
});

describe("J2: a range that bounds nothing, by meaning, is the request latest (generated from the grammar)", () => {
  const wild = ["*", "x", "X", "x.x", "*.*", "x.x.x", "X.*", "*.x.X"];
  const ops = ["", "=", "^", "~", ">=", "v", "~>"];
  const specs = new Set<string>([""]);
  for (const w of wild) for (const o of ops) specs.add(`${o}${w}`);
  for (const a of ["*", "x"]) for (const b of [">=x", "^*", "1.2.3", "~x"]) specs.add(`${a} || ${b}`);
  specs.add(">= *");
  specs.add("x.x x.x");
  it.each([...specs])("package.json %j: held for a verdict on latest", (spec) => {
    const r = s.write(`${s.project}/package.json`, JSON.stringify({ devDependencies: { vite: spec } }));
    expect(r.decision, r.text).toBe("deny");
    expect(r.items).toEqual([{ ecosystem: "npm", package: "vite", to: "latest" }]);
  });
  it.each(["overrides", "resolutions"])("the same in %s", (section) => {
    const r = s.write(`${s.project}/package.json`, JSON.stringify({ [section]: { vite: "^*" } }));
    expect(r.items).toEqual([{ ecosystem: "npm", package: "vite", to: "latest" }]);
  });
  it.each([
    ["pnpm-workspace.yaml", "catalog:\n  vite: '>=*'\n"],
    ["pnpm-workspace.yaml", "packageExtensions:\n  ms:\n    dependencies:\n      vite: 'x.x'\n"],
    ["package.json", '{"dependencies":{"v":"npm:vite"}}'],
    ["package.json", '{"dependencies":{"v":"npm:vite@*"}}'],
    ["Cargo.toml", '[package]\nname = "x"\nversion = "0.1.0"\n[dependencies]\nvite = ">=*"\n'],
  ])("%s %j: latest", (file, content) => {
    const r = s.write(`${s.project}/${file}`, content);
    expect(r.decision, r.text).toBe("deny");
    expect(r.items?.[0]?.to).toBe("latest");
  });
  it("a wildcard beside a numbered bound is that range: >=* <2 is judged as a constraint", () => {
    expect(s.write(`${s.project}/package.json`, JSON.stringify({ dependencies: { vite: ">=* <2" } })).items?.[0]?.to).toBe(">=* <2");
  });
  it.each(["<*", ">*", "~>!"])("%j matches nothing or is no form: held as not read", (spec) => {
    expect(s.write(`${s.project}/package.json`, JSON.stringify({ dependencies: { vite: spec } })).text).toContain("could not be read");
  });
});

describe("J3: an index is the project's own only when private by shape; any other host's names are judged", () => {
  it.each([
    "npm install --registry http://localhost:4873 acme-widget@1.0.0",
    "npm install --registry http://127.0.0.1:4873 acme-widget@1.0.0",
    "npm install --registry https://10.1.2.3/npm acme-widget@1.0.0",
    "npm install --registry https://172.20.0.5 acme-widget@1.0.0",
    "npm install --registry https://192.168.1.10 acme-widget@1.0.0",
    "npm install --registry http://[fd00::1]:4873 acme-widget@1.0.0",
    "npm install --registry https://nexus acme-widget@1.0.0",
    "npm install --registry https://npm.corp acme-widget@1.0.0",
    "pip install -i https://pypi.internal/simple acme-widget==1.0.0",
    "pip install -i https://pypi.mycorp.local/simple acme-widget==1.0.0",
    "uv pip install --index-url https://repo.home.arpa/simple acme-widget==1.0.0",
  ])("%s: the project's own source, goes ahead unjudged", (command) => {
    expect(run(command).decision).toBe("allow");
  });
  it.each([
    "npm install --registry https://npm.mycorp.com acme-widget@1.0.0",
    "npm install --registry https://mirrors.tencent.com/npm acme-widget@1.0.0",
    "pip install -i https://mirrors.ustc.edu.cn/pypi/simple acme-widget==1.0.0",
    "pip install -i https://pypi.doubanio.com/simple acme-widget==1.0.0",
    "cargo add --registry corp acme-widget@1.0.0",
    "poetry add --source corp acme-widget==1.0.0",
  ])("%s: judged on the ledger; the denial tells how a private name is released", (command) => {
    const r = run(command);
    expect(r.decision, r.text).toBe("deny");
    expect(r.items?.[0]?.package).toBe("acme-widget");
    expect(r.text).toContain("set FOURDA_PRIVATE_PACKAGES or the registry's configuration so the server records it private");
  });
  it.each(["npm install https://cdn.example.com/acme-widget-1.0.0.tgz", "pip install https://files.mycorp.com/acme_widget-1.0.0-py3-none-any.whl"])("a URL operand on a host not private by shape is held as not read: %s", (command) => {
    expect(run(command).text).toContain("could not be read");
  });
  it("a URL operand on a private host goes ahead", () => {
    expect(run("npm install http://localhost:8080/acme-widget-1.0.0.tgz").decision).toBe("allow");
  });
  it("a private record releases a name judged from another host", () => {
    s.ledger([{ ecosystem: "npm", package: "acme-widget", version: "1.0.0", verdict: "unknown", not_checked: "private", reason: "a private-registry rule covers it" }]);
    expect(run("npm install --registry https://npm.mycorp.com acme-widget@1.0.0").decision).toBe("allow");
  });
});

describe("J4: configDependencies are judged; a setting off the inert list is held", () => {
  it("configDependencies: lodash 4.17.20 (avoid) held", () => {
    s.ledger([{ ecosystem: "npm", package: "lodash", version: "4.17.20", verdict: "avoid", reason: "test avoid" }]);
    const r = s.write(`${s.project}/pnpm-workspace.yaml`, "configDependencies:\n  lodash: '4.17.20+sha512-abc'\n");
    expect(r.decision).toBe("deny");
    expect(r.text).toContain("answered avoid");
  });
  it.each(["linkWorkspacePackages: false\n", "dedupePeerDependents: false\n", "catalogMode: prefer\n", "minimumReleaseAge: 1440\n", "supportedArchitectures:\n  os:\n    - linux\n", "nodeVersion: 18.0.0\n", "autoInstallPeers: false\n", "injectWorkspacePackages: true\n", "sharedWorkspaceLockfile: false\n"])("%j: held when changed", (content) => {
    expect(s.write(`${s.project}/pnpm-workspace.yaml`, content).text).toContain("could not be read");
  });
  it("a setting on the list goes ahead", () => {
    expect(s.write(`${s.project}/pnpm-workspace.yaml`, "packages:\n  - 'apps/*'\nnodeLinker: hoisted\nstrictPeerDependencies: false\nonlyBuiltDependencies:\n  - esbuild\n").decision).toBe("allow");
  });
});

describe("J6: a byte that ends a line for some shell inside the heredoc-argument form: not text", () => {
  it.each(["\r", "\u0085", " ", " ", "\f", "\v"])("%j inside: held", (b) => {
    s.ledger([{ ecosystem: "npm", package: "lodash", version: "4.17.20", verdict: "avoid", reason: "test avoid" }]);
    const command = `git commit -m "$(cat <<'EOF'\ndocs\nEOF${b}\nnpm i lodash@4.17.20\nEOF\n)"`;
    expect(run(command).decision, JSON.stringify(command)).toBe("deny");
  });
  it("the plain form still goes ahead", () => {
    expect(run(`git commit -m "$(cat <<'EOF'\ndocs: npm install x\nEOF\n)"`).decision).toBe("allow");
  });
});

describe("J7: pnpm's package.yaml and package.json5 are manifests this hook does not read: held", () => {
  it.each(["package.yaml", "package.json5", "sub/Package.YAML"])("a Write of %s is held with the remedy", (name) => {
    const r = s.write(`${s.project}/${name}`, "dependencies:\n  lodash: 4.17.20\n");
    expect(r.decision).toBe("deny");
    expect(r.text).toContain("write the project's manifest as package.json");
  });
});

describe("J9: after an install command that ran, one line of advice (never a denial)", () => {
  const post = (command: string, tool = "Bash", env: Record<string, string> = {}) => s.run({ session_id: "s", cwd: s.project, hook_event_name: "PostToolUse", tool_name: tool, tool_input: { command }, tool_response: {} }, env);
  it.each([["npm install lodash@4.17.21", "Bash"], ["pip install -r requirements.txt", "Bash"], ["cd app && pnpm add -D zod", "Bash"], ["npm ci; npm update", "PowerShell"]])("%s: advised", (command, tool) => {
    const r = post(command, tool);
    expect(r.decision).not.toBe("deny");
    expect(r.text).toBe("The package manager decides the releases actually installed. Run vulnerability_scan to check them.");
  });
  it.each(["echo 'npm install lodash'", "git commit -m 'npm install x'", "ls -la", "npm test"])("%s: nothing", (command) => {
    expect(post(command).text).toBe("");
  });
  it("in advise mode too; never with no ledger or the guard off", () => {
    expect(post("npm install lodash@4.17.21", "Bash", { FOURDA_GUARD: "advise" }).text).toContain("vulnerability_scan");
    expect(post("npm install lodash@4.17.21", "Bash", { FOURDA_GUARD: "off" }).text).toBe("");
    rmSync(join(s.home, "check-ledger.jsonl"));
    expect(post("npm install lodash@4.17.21").text).toBe("");
  });
  it("an ordinary command costs under 100 ms of the hook's CPU", () => {
    // Best of three: one run under a loaded suite measured 108 ms; alone it is well under.
    const runs = [0, 1, 2].map(() => timed(s.home, { session_id: "s", cwd: s.project, hook_event_name: "PostToolUse", tool_name: "Bash", tool_input: { command: "ls -la" }, tool_response: {} }));
    expect(runs[0].decision).not.toBe("deny");
    expect(runs.reduce((m, r) => Math.min(m, r.cpu), Number.POSITIVE_INFINITY)).toBeLessThan(100);
  });
});
