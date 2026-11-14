// SPDX-License-Identifier: Apache-2.0
/**
 * Pre-publish privacy audit of 5d709ff (R7): configuration layouts that still sent a private
 * package or module name to OSV.dev, a public registry or HN. Each layout below is a project whose
 * configuration makes `zqr7...` private, with a public control the scan must still check. Every
 * tool runs against it through dispatchTool; the fetch stub records every request, and none may
 * name a `zqr7` package. HOME, USERPROFILE, APPDATA and XDG_CONFIG_HOME point at a temporary
 * directory for every test, so a user-level file is the test's own and the real profile is never read.
 *
 * 1. pip: `-r` / `-c` includes (nested) whose INCLUDED file sets `--index-url` / `--extra-index-url`.
 * 2. uv / Poetry with no lockfile: a default or non-explicit `[[tool.uv.index]]`, `[tool.uv]`
 *    index-url / extra-index-url, `uv.toml` (project and user), UV_* variables, Poetry sources.
 * 3. PEP 508 direct references to a host that is not public (https, git+https, file:).
 * 4. Cargo: a workspace member's `registry =` or `git =`, `.cargo/config.toml` source replacement and `[patch]`.
 * 5. npm: the global npmrc, a quoted `"@scope:registry"` key, `npm_config_@scope:registry` in any
 *    case, the user's `~/.yarnrc.yml`, YARN_RC_FILENAME, YARN_NPM_SCOPES.
 * 6. GOPRIVATE and `.git` URL spellings of a private module.
 * 7. A registry, index or proxy that is not public (npm `registry=`, GOPROXY): one policy, private,
 *    unless FOURDA_PUBLIC_MIRRORS declares the host a mirror.
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
let home: string;
let sent: string[];
const savedEnv = new Map<string, string | undefined>();
const setEnv = (key: string, value: string | undefined) => {
  if (!savedEnv.has(key)) savedEnv.set(key, process.env[key]);
  if (value === undefined) delete process.env[key];
  else process.env[key] = value;
};

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

interface Layout {
  name: string;
  /** Project files, relative to the project directory. */
  files: Record<string, string>;
  /** Files under the temporary home directory (`~`); `$APPDATA/...` and `$XDG/...` resolve there too. */
  homeFiles?: Record<string, string>;
  /** Environment for the test; `$HOME` in a value is the temporary home directory. */
  env?: Record<string, string | undefined>;
  /** The private names dependency_check, upgrade_impact and the briefing are asked about. */
  ask: Array<{ ecosystem: string; name: string }>;
  /** A public package the scan must still look up. */
  control: { ecosystem: string; name: string; version: string };
  /** Only on this platform (a location only one platform's tools read). */
  platform?: NodeJS.Platform;
}

/** A public npm control: lodash from the public registry. */
const NPM_CONTROL = {
  "package.json": JSON.stringify({ name: "app", version: "1.0.0", dependencies: { lodash: "4.17.20" } }),
  "package-lock.json": JSON.stringify({
    name: "app",
    lockfileVersion: 3,
    packages: {
      "": { name: "app", dependencies: { lodash: "4.17.20" } },
      "node_modules/lodash": { version: "4.17.20", resolved: "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz" },
    },
  }),
};
const npmControl = { ecosystem: "npm", name: "lodash", version: "4.17.20" };
const pypiControl = { ecosystem: "PyPI", name: "requests", version: "2.25.1" };

/** A uv / Poetry project with no lockfile, declaring `zqr7-<tag>` and nothing pinned, beside the npm control. */
const pyproject = (tag: string, toolTables: string, deps = `"zqr7-${tag}==1.0.0"`): Record<string, string> => ({
  ...NPM_CONTROL,
  "pyproject.toml": `[project]\nname = "app"\nversion = "0.1.0"\ndependencies = [${deps}]\n\n${toolTables}\n`,
});
const poetry = (tag: string, source: string): Record<string, string> => ({
  ...NPM_CONTROL,
  "pyproject.toml": `[tool.poetry]\nname = "app"\nversion = "0.1.0"\n\n[tool.poetry.dependencies]\npython = "^3.11"\nzqr7-${tag} = "1.0.0"\n\n[[tool.poetry.source]]\nname = "corp"\nurl = "https://pypi.zq.internal/simple/"\n${source}\n`,
});
const pyAsk = (tag: string) => [{ ecosystem: "PyPI", name: `zqr7-${tag}` }];

/** An npm project installing `@zqr7/vault` (no `resolved` host in its lockfile) and lodash. */
const scopedNpm = (extra: Record<string, string> = {}): Record<string, string> => ({
  "package.json": JSON.stringify({ name: "app", version: "1.0.0", dependencies: { "@zqr7/vault": "1.0.0", lodash: "4.17.20" } }),
  "package-lock.json": JSON.stringify({
    name: "app",
    lockfileVersion: 3,
    packages: {
      "": { name: "app", dependencies: { "@zqr7/vault": "1.0.0", lodash: "4.17.20" } },
      "node_modules/@zqr7/vault": { version: "1.0.0" },
      "node_modules/lodash": { version: "4.17.20", resolved: "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz" },
    },
  }),
  ...extra,
});
const scopedAsk = [{ ecosystem: "npm", name: "@zqr7/vault" }];
const SCOPE_RC = "@zqr7:registry=https://npm.zq.internal/\n";
const SCOPE_YARNRC = 'npmScopes:\n  zqr7:\n    npmRegistryServer: "https://npm.zq.internal/"\n';

/** A Go module requiring the private `github.com/zqr7org/zqr7mod` and the public golang.org/x/net. */
const GO_PROJECT = {
  "go.mod": "module example.com/app\n\ngo 1.22\n\nrequire (\n\tgithub.com/zqr7org/zqr7mod v1.2.3\n\tgolang.org/x/net v0.0.1\n)\n",
  "go.sum": [
    "github.com/zqr7org/zqr7mod v1.2.3 h1:aaaa=",
    "github.com/zqr7org/zqr7mod v1.2.3/go.mod h1:bbbb=",
    "golang.org/x/net v0.0.1 h1:cccc=",
    "golang.org/x/net v0.0.1/go.mod h1:dddd=",
    "",
  ].join("\n"),
};
/** Only the public golang.org/x/net: a Go control beside another ecosystem's private package. */
const GO_CONTROL_PROJECT = {
  "go.mod": "module example.com/app\n\ngo 1.22\n\nrequire golang.org/x/net v0.0.1\n",
  "go.sum": "golang.org/x/net v0.0.1 h1:cccc=\ngolang.org/x/net v0.0.1/go.mod h1:dddd=\n",
};
const goControl = { ecosystem: "Go", name: "golang.org/x/net", version: "v0.0.1" };

/** A Cargo workspace whose member `crates/billing` declares `line`, beside the public smallvec. */
const cargoWorkspace = (line: string, extra: Record<string, string> = {}): Record<string, string> => ({
  "Cargo.toml": '[workspace]\nmembers = ["crates/*"]\nexclude = ["crates/skipped"]\nresolver = "2"\n',
  "crates/billing/Cargo.toml": `[package]\nname = "billing"\nversion = "0.1.0"\n\n[dependencies]\nsmallvec = "0.6.9"\n${line}\n`,
  "crates/billing/src/lib.rs": "",
  "Cargo.lock": [
    "version = 3",
    "",
    "[[package]]",
    'name = "billing"',
    'version = "0.1.0"',
    'dependencies = ["smallvec"]',
    "",
    "[[package]]",
    'name = "smallvec"',
    'version = "0.6.9"',
    'source = "registry+https://github.com/rust-lang/crates.io-index"',
    "",
  ].join("\n"),
  ...extra,
});
const cratesAsk = [{ ecosystem: "crates.io", name: "zqr7-ledger" }];
const cratesControl = { ecosystem: "crates.io", name: "smallvec", version: "0.6.9" };

const LAYOUTS: Layout[] = [
  // 1. pip includes.
  {
    name: "pip: `-r base.txt` whose base.txt sets --index-url",
    files: { "requirements.txt": "-r base.txt\nzqr7-py-top==2.0.0\n", "base.txt": "--index-url https://pypi.zq.internal/simple\nzqr7-py-base==1.0.0\n", ...NPM_CONTROL },
    ask: [{ ecosystem: "PyPI", name: "zqr7-py-top" }, { ecosystem: "PyPI", name: "zqr7-py-base" }],
    control: npmControl,
  },
  {
    name: "pip: `-c constraints.txt` whose constraints set --extra-index-url",
    files: { "requirements.txt": "-c constraints.txt\nzqr7-py-c\n", "constraints.txt": "--extra-index-url https://pypi.zq.internal/simple\nzqr7-py-c==1.0.0\n", ...NPM_CONTROL },
    ask: [{ ecosystem: "PyPI", name: "zqr7-py-c" }],
    control: npmControl,
  },
  {
    name: "pip: nested includes, each relative to the file that names it",
    files: {
      "requirements.txt": "-r reqs/a.txt\nzqr7-py-nest==1.0.0\n",
      "reqs/a.txt": "-r more/b.txt\n",
      "reqs/more/b.txt": "-i https://pypi.zq.internal/simple\n",
      ...NPM_CONTROL,
    },
    ask: [{ ecosystem: "PyPI", name: "zqr7-py-nest" }],
    control: npmControl,
  },
  // 2. uv and Poetry with no lockfile.
  { name: "uv: [[tool.uv.index]] default = true", files: pyproject("uvdef", '[[tool.uv.index]]\nname = "corp"\nurl = "https://pypi.zq.internal/simple"\ndefault = true'), ask: pyAsk("uvdef"), control: npmControl },
  { name: "uv: [[tool.uv.index]] without explicit", files: pyproject("uvidx", '[[tool.uv.index]]\nname = "corp"\nurl = "https://pypi.zq.internal/simple"'), ask: pyAsk("uvidx"), control: npmControl },
  { name: "uv: [tool.uv] index-url", files: pyproject("uvurl", '[tool.uv]\nindex-url = "https://pypi.zq.internal/simple"'), ask: pyAsk("uvurl"), control: npmControl },
  { name: "uv: [tool.uv] extra-index-url (multi-line)", files: pyproject("uvextra", '[tool.uv]\nextra-index-url = [\n  "https://pypi.zq.internal/simple",\n]'), ask: pyAsk("uvextra"), control: npmControl },
  { name: "uv: the project's uv.toml", files: { ...pyproject("uvtoml", ""), "uv.toml": '[[index]]\nurl = "https://pypi.zq.internal/simple"\ndefault = true\n' }, ask: pyAsk("uvtoml"), control: npmControl },
  {
    name: "uv: the user's uv.toml ($XDG_CONFIG_HOME/uv/uv.toml)",
    files: pyproject("uvuser", ""),
    homeFiles: { ".config/uv/uv.toml": 'index-url = "https://pypi.zq.internal/simple"\n' },
    env: { UV_NO_CONFIG: undefined, XDG_CONFIG_HOME: "$HOME/.config" },
    ask: pyAsk("uvuser"),
    control: npmControl,
  },
  {
    name: "uv: the user's uv.toml (%APPDATA%\\uv\\uv.toml)",
    platform: "win32",
    files: pyproject("uvappdata", ""),
    homeFiles: { "AppData/Roaming/uv/uv.toml": 'extra-index-url = ["https://pypi.zq.internal/simple"]\n' },
    env: { UV_NO_CONFIG: undefined },
    ask: pyAsk("uvappdata"),
    control: npmControl,
  },
  { name: "uv: UV_DEFAULT_INDEX", files: pyproject("uvenv1", ""), env: { UV_DEFAULT_INDEX: "https://pypi.zq.internal/simple" }, ask: pyAsk("uvenv1"), control: npmControl },
  { name: "uv: UV_INDEX_URL", files: pyproject("uvenv2", ""), env: { UV_INDEX_URL: "https://pypi.zq.internal/simple" }, ask: pyAsk("uvenv2"), control: npmControl },
  { name: "uv: UV_INDEX (name=url)", files: pyproject("uvenv3", ""), env: { UV_INDEX: "corp=https://pypi.zq.internal/simple" }, ask: pyAsk("uvenv3"), control: npmControl },
  { name: "uv: UV_EXTRA_INDEX_URL", files: pyproject("uvenv4", ""), env: { UV_EXTRA_INDEX_URL: "https://pypi.zq.internal/simple" }, ask: pyAsk("uvenv4"), control: npmControl },
  { name: 'Poetry: priority = "primary"', files: poetry("poprim", 'priority = "primary"'), ask: pyAsk("poprim"), control: npmControl },
  { name: 'Poetry: priority = "default"', files: poetry("podef", 'priority = "default"'), ask: pyAsk("podef"), control: npmControl },
  { name: 'Poetry: priority = "supplemental"', files: poetry("posup", 'priority = "supplemental"'), ask: pyAsk("posup"), control: npmControl },
  { name: "Poetry: legacy default = true", files: poetry("polegdef", "default = true"), ask: pyAsk("polegdef"), control: npmControl },
  { name: "Poetry: legacy secondary = true", files: poetry("polegsec", "secondary = true"), ask: pyAsk("polegsec"), control: npmControl },
  // 3. PEP 508 direct references (per name: the public control is PyPI itself).
  {
    name: "requirements: name @ https://private-host/...",
    files: { "requirements.txt": "zqr7-direct @ https://pkgs.zq.internal/zqr7_direct-1.0.0.tar.gz\nrequests==2.25.1\n" },
    ask: [{ ecosystem: "PyPI", name: "zqr7-direct" }],
    control: pypiControl,
  },
  {
    name: "requirements: name @ git+https://private-host/...",
    files: { "requirements.txt": "zqr7-gitdep @ git+https://git.zq.internal/team/zqr7-gitdep.git@v1\nrequests==2.25.1\n" },
    ask: [{ ecosystem: "PyPI", name: "zqr7-gitdep" }],
    control: pypiControl,
  },
  {
    name: "requirements: name @ file:",
    files: { "requirements.txt": "zqr7-local @ file:///opt/wheels/zqr7_local-1.0.0-py3-none-any.whl\nrequests==2.25.1\n" },
    ask: [{ ecosystem: "PyPI", name: "zqr7-local" }],
    control: pypiControl,
  },
  {
    name: "pyproject.toml: a PEP 508 direct reference",
    files: { "pyproject.toml": '[project]\nname = "app"\nversion = "0.1.0"\ndependencies = ["zqr7-pep @ https://pkgs.zq.internal/zqr7_pep-1.0.0-py3-none-any.whl"]\n', "requirements.txt": "requests==2.25.1\n" },
    ask: [{ ecosystem: "PyPI", name: "zqr7-pep" }],
    control: pypiControl,
  },
  // 4. Cargo.
  { name: "Cargo: a workspace member's registry = \"acme\"", files: cargoWorkspace('zqr7-ledger = { version = "1.0", registry = "acme" }'), ask: cratesAsk, control: cratesControl },
  { name: "Cargo: a workspace member's git = private", files: cargoWorkspace('zqr7-ledger = { git = "https://git.zq.internal/team/ledger" }'), ask: cratesAsk, control: cratesControl },
  {
    name: "Cargo: a workspace member's [dependencies.<name>] table with registry",
    files: cargoWorkspace('\n[dependencies.zqr7-ledger]\nversion = "1.0"\nregistry = "acme"'),
    ask: cratesAsk,
    control: cratesControl,
  },
  {
    name: "Cargo: .cargo/config.toml [patch] from a private git",
    files: { ...cargoWorkspace('zqr7-ledger = "1.0"'), ".cargo/config.toml": '[patch.crates-io]\nzqr7-ledger = { git = "https://git.zq.internal/team/ledger" }\n' },
    ask: cratesAsk,
    control: cratesControl,
  },
  {
    name: "Cargo: the user's CARGO_HOME config.toml replaces crates.io with a private registry",
    files: { ...cargoWorkspace('zqr7-ledger = "1.0"'), ...NPM_CONTROL },
    homeFiles: { ".cargo/config.toml": '[source.crates-io]\nreplace-with = "corp"\n\n[source.corp]\nregistry = "sparse+https://cargo.zq.internal/index/"\n' },
    env: { CARGO_HOME: "$HOME/.cargo" },
    ask: cratesAsk,
    control: npmControl,
  },
  // 5. npm configuration.
  { name: "npm: the global npmrc (NPM_CONFIG_GLOBALCONFIG)", files: scopedNpm(), homeFiles: { "global/npmrc": SCOPE_RC }, env: { NPM_CONFIG_GLOBALCONFIG: "$HOME/global/npmrc" }, ask: scopedAsk, control: npmControl },
  { name: "npm: the global npmrc ($PREFIX/etc/npmrc)", files: scopedNpm(), homeFiles: { "prefix/etc/npmrc": SCOPE_RC }, env: { NPM_CONFIG_GLOBALCONFIG: undefined, npm_config_prefix: "$HOME/prefix" }, ask: scopedAsk, control: npmControl },
  {
    name: "npm: the global npmrc (%APPDATA%\\npm\\etc\\npmrc)",
    platform: "win32",
    files: scopedNpm(),
    homeFiles: { "AppData/Roaming/npm/etc/npmrc": SCOPE_RC },
    env: { NPM_CONFIG_GLOBALCONFIG: undefined },
    ask: scopedAsk,
    control: npmControl,
  },
  { name: 'npm: a quoted "@scope:registry" key in .npmrc', files: scopedNpm({ ".npmrc": '"@zqr7:registry"=https://npm.zq.internal/\n' }), ask: scopedAsk, control: npmControl },
  { name: "npm: npm_config_@scope:registry", files: scopedNpm(), env: { "npm_config_@zqr7:registry": "https://npm.zq.internal/" }, ask: scopedAsk, control: npmControl },
  { name: "npm: NPM_CONFIG_@SCOPE:REGISTRY (upper case)", files: scopedNpm(), env: { "NPM_CONFIG_@ZQR7:REGISTRY": "https://npm.zq.internal/" }, ask: scopedAsk, control: npmControl },
  { name: "yarn: the user's ~/.yarnrc.yml npmScopes", files: scopedNpm(), homeFiles: { ".yarnrc.yml": SCOPE_YARNRC }, ask: scopedAsk, control: npmControl },
  { name: "yarn: YARN_RC_FILENAME names the project's rc file", files: scopedNpm({ ".corp-yarnrc.yml": SCOPE_YARNRC }), env: { YARN_RC_FILENAME: ".corp-yarnrc.yml" }, ask: scopedAsk, control: npmControl },
  { name: "yarn: YARN_NPM_SCOPES", files: scopedNpm(), env: { YARN_NPM_SCOPES: '{"zqr7": {"npmRegistryServer": "https://npm.zq.internal/"}}' }, ask: scopedAsk, control: npmControl },
  // 6. GOPRIVATE and git URL spellings.
  {
    name: "Go: GOPRIVATE and .git URL spellings of the private module",
    files: GO_PROJECT,
    env: { GOPRIVATE: "github.com/zqr7org/zqr7mod" },
    ask: [
      { ecosystem: "Go", name: "https://github.com/zqr7org/zqr7mod.git" },
      { ecosystem: "Go", name: "git+ssh://git@github.com/zqr7org/zqr7mod" },
      { ecosystem: "Go", name: "https://github.com/zqr7org/zqr7mod#v1.2.3" },
      { ecosystem: "Go", name: "https://github.com/zqr7org/zqr7mod/tree/main" },
      { ecosystem: "Go", name: "git@github.com:zqr7org/zqr7mod.git" },
      { ecosystem: "Go", name: "zqr7mod.git" },
    ],
    control: goControl,
  },
  // 7. A registry or proxy that is not public: private unless declared a mirror.
  { name: "Go: GOPROXY names a private proxy and nothing is in GOPRIVATE", files: { ...GO_PROJECT, ...NPM_CONTROL }, env: { GOPROXY: "https://athens.zq.internal,direct" }, ask: [{ ecosystem: "Go", name: "github.com/zqr7org/zqr7mod" }], control: npmControl },
  {
    name: "npm: .npmrc registry= names a private registry, unscoped private package",
    files: {
      ...GO_CONTROL_PROJECT,
      ".npmrc": "registry=https://npm.zq.internal/\n",
      "package.json": JSON.stringify({ name: "app", version: "1.0.0", dependencies: { "zqr7-unscoped": "1.0.0" } }),
      "package-lock.json": JSON.stringify({ name: "app", lockfileVersion: 3, packages: { "": { name: "app", dependencies: { "zqr7-unscoped": "1.0.0" } }, "node_modules/zqr7-unscoped": { version: "1.0.0" } } }),
    },
    ask: [{ ecosystem: "npm", name: "zqr7-unscoped" }],
    control: goControl,
  },
];

beforeAll(() => {
  setEnv("FOURDA_OFFLINE", undefined);
});

afterAll(() => {
  for (const [key, value] of savedEnv) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
});

beforeEach(() => {
  scratch = fs.mkdtempSync(path.join(os.tmpdir(), "4da-private-r7-"));
  home = path.join(scratch, "home");
  fs.mkdirSync(home, { recursive: true });
  sent = [];
  setEnv("HOME", home);
  setEnv("USERPROFILE", home);
  setEnv("APPDATA", path.join(home, "AppData", "Roaming"));
  setEnv("LOCALAPPDATA", path.join(home, "AppData", "Local"));
  setEnv("XDG_CONFIG_HOME", undefined);
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

function argsFor(tool: string, layout: Layout): Record<string, unknown> {
  const first = layout.ask[0];
  switch (tool) {
    case "dependency_check":
      return { items: [...layout.ask.map((a) => ({ ecosystem: a.ecosystem, package: a.name, to: "1.0.1" })), { ecosystem: layout.control.ecosystem, package: layout.control.name, to: layout.control.version }] };
    case "upgrade_impact":
      return { package: first.name, to_version: "2.0.0", ecosystem: first.ecosystem };
    case "what_should_i_know":
      return { task: `upgrade ${layout.ask.map((a) => a.name).join(" and ")} and ${layout.control.name}` };
    case "check_decision_alignment":
      return { technology: first.name };
    case "agent_memory":
      return { action: "recall", query: first.name };
    case "decision_memory":
      return { action: "list" };
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

/** Run every tool against the layout's project; returns each tool's answer as text. */
async function runEveryTool(layout: Layout): Promise<Record<string, string>> {
  const expand = (v: string) => v.replaceAll("$HOME", home);
  for (const [file, content] of Object.entries(layout.files)) {
    fs.mkdirSync(path.dirname(path.join(scratch, "project", file)), { recursive: true });
    fs.writeFileSync(path.join(scratch, "project", file), content);
  }
  for (const [file, content] of Object.entries(layout.homeFiles ?? {})) {
    fs.mkdirSync(path.dirname(path.join(home, file)), { recursive: true });
    fs.writeFileSync(path.join(home, file), content);
  }
  for (const [key, value] of Object.entries(layout.env ?? {})) setEnv(key, value === undefined ? undefined : expand(value));
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: string, init?: RequestInit) => {
      const url = String(input);
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
      if (u.hostname === "hn.algolia.com") return json({ hits: [] });
      return json({ error: "Not found" }, 404);
    }),
  );
  const project = path.join(scratch, "project");
  const live = new LiveIntelligence(null);
  const { entries, discovery } = scanProjectTree(project);
  live.initFromProjectTree(project, treeResolutionGroups(entries), discovery);
  setLiveIntelligence(live);
  const db = new FourDADatabase(path.join(scratch, "standalone.db"));
  const answers: Record<string, string> = {};
  try {
    for (const tool of Object.keys(TOOL_REGISTRY)) {
      const result = await dispatchTool(tool, db, argsFor(tool, layout)).catch((error: unknown) => ({ content: [{ type: "text", text: String(error) }] }));
      answers[tool] = JSON.stringify(result);
    }
  } finally {
    db.close();
  }
  return answers;
}

describe("R7: private names in every configuration layout never reach a public service", () => {
  for (const layout of LAYOUTS) {
    const run = layout.platform && layout.platform !== process.platform ? it.skip : it;
    run(layout.name, async () => {
      const answers = await runEveryTool(layout);
      expect(sent.filter((s) => /zqr7/i.test(s))).toEqual([]);
      // The public control was still looked up: the fixture is live, not inert.
      expect(sent.some((s) => s.includes(layout.control.name))).toBe(true);
      // And no tool reads the private name as clean.
      expect(answers.dependency_check).toContain('not_checked\\":\\"private');
    });
  }
});

describe("R7: what stays public, and the helpers' edges", () => {
  /** The private dependencies a project's live layer reports, with its env applied. */
  const privateOf = (files: Record<string, string>, env: Record<string, string | undefined> = {}) => {
    for (const [file, content] of Object.entries(files)) {
      fs.mkdirSync(path.dirname(path.join(scratch, "project", file)), { recursive: true });
      fs.writeFileSync(path.join(scratch, "project", file), content);
    }
    for (const [key, value] of Object.entries(env)) setEnv(key, value);
    const project = path.join(scratch, "project");
    const live = new LiveIntelligence(null);
    const { entries, discovery } = scanProjectTree(project);
    live.initFromProjectTree(project, treeResolutionGroups(entries), discovery);
    return live;
  };

  it("an explicit uv index, an explicit Poetry source and a public wheel index make nothing ecosystem-wide private", () => {
    const live = privateOf({
      "pyproject.toml": [
        '[project]\nname = "app"\nversion = "0.1.0"\ndependencies = ["requests==2.25.1"]\n',
        '[[tool.uv.index]]\nname = "corp"\nurl = "https://pypi.zq.internal/simple"\nexplicit = true\n',
        '[[tool.uv.index]]\nname = "torch"\nurl = "https://download.pytorch.org/whl/cpu"\n',
        '[tool.uv]\nextra-index-url = ["https://download.pytorch.org/whl/cu121"]\n',
        '[[tool.poetry.source]]\nname = "corp2"\nurl = "https://pypi.zq.internal/simple"\npriority = "explicit"\n',
      ].join("\n"),
      "requirements.txt": "requests==2.25.1\n",
    });
    expect(live.getPrivateDependencies()).toEqual([]);
    expect(live.privateReason("PyPI", "requests")).toBeNull();
  });

  it("a direct reference to pypi.org's files or a public code host is not private", () => {
    const live = privateOf({
      "requirements.txt": "wheelpkg @ https://files.pythonhosted.org/packages/x/wheelpkg-1.0-py3-none-any.whl\nforkpkg @ git+https://github.com/someone/forkpkg@v1\nrequests==2.25.1\n",
    });
    expect(live.privateReason("PyPI", "wheelpkg")).toBeNull();
    expect(live.privateReason("PyPI", "forkpkg")).toBeNull();
  });

  it("an include loop and a deep chain end, and an include outside the project is not read for options", () => {
    const outside = path.join(scratch, "outside.txt");
    fs.writeFileSync(outside, "--index-url https://pypi.zq.internal/simple\n");
    const live = privateOf({
      "requirements.txt": "-r a.txt\n-r ../outside.txt\nrequests==2.25.1\n",
      "a.txt": "-r b.txt\n",
      "b.txt": "-r a.txt\n",
    });
    // The outside file is refused (a coverage problem, never read), so its index applies to nothing.
    expect(live.privateReason("PyPI", "requests")).toBeNull();
    expect(live.getLockfileProblems().some((p) => p.refused)).toBe(true);
  });

  it("GOPROXY: the public proxies and `direct` are public; FOURDA_PUBLIC_MIRRORS declares a private one a mirror", () => {
    for (const proxy of ["https://proxy.golang.org,direct", "https://goproxy.cn|https://proxy.golang.org", "direct", "off"]) {
      const live = privateOf(GO_PROJECT, { GOPROXY: proxy });
      expect(live.getPrivateDependencies()).toEqual([]);
    }
    expect(privateOf(GO_PROJECT, { GOPROXY: "https://athens.zq.internal" }).getPrivateDependencies().map((d) => d.name).sort()).toEqual(["github.com/zqr7org/zqr7mod", "golang.org/x/net"]);
    expect(privateOf(GO_PROJECT, { GOPROXY: "https://athens.zq.internal", FOURDA_PUBLIC_MIRRORS: "athens.zq.internal" }).getPrivateDependencies()).toEqual([]);
  });

  it("pip --index-url to a declared mirror is checked; to another private host it is not", () => {
    const files = { "requirements.txt": "--index-url https://devpi.zq.internal/root/pypi/+simple/\nrequests==2.25.1\n" };
    expect(privateOf(files).getPrivateDependencies().map((d) => d.name)).toEqual(["requests"]);
    expect(privateOf(files, { FOURDA_PUBLIC_MIRRORS: "https://devpi.zq.internal/" }).getPrivateDependencies()).toEqual([]);
  });

  it("Cargo: a vendored source replacement is crates.io; an excluded member is not read", () => {
    const live = privateOf({
      ...cargoWorkspace('zqr7-ledger = "1.0"'),
      "crates/skipped/Cargo.toml": '[package]\nname = "skipped"\nversion = "0.1.0"\n\n[dependencies]\nzqr7-skipped = { version = "1", registry = "acme" }\n',
      ".cargo/config.toml": '[source.crates-io]\nreplace-with = "vendored-sources"\n\n[source.vendored-sources]\ndirectory = "vendor"\n',
    });
    expect(live.getPrivateDependencies()).toEqual([]);
    expect(live.privateReason("crates.io", "smallvec")).toBeNull();
    expect(live.privateReason("crates.io", "zqr7-skipped")).toBeNull();
  });

  it("a GOPRIVATE module's git spellings are refused, a public module's are not", () => {
    const live = privateOf(GO_PROJECT, { GOPRIVATE: "github.com/zqr7org/zqr7mod" });
    for (const spelling of ["https://github.com/zqr7org/zqr7mod.git", "ssh://git@github.com:22/zqr7org/zqr7mod.git", "https://user:tok@github.com/zqr7org/zqr7mod/blob/main/go.mod", "github.com/zqr7org/zqr7mod.git#v1.2.3"]) {
      expect(live.privateReason("Go", spelling), spelling).not.toBeNull();
    }
    expect(live.privateReason("Go", "https://github.com/golang/net.git")).toBeNull();
  });
});
