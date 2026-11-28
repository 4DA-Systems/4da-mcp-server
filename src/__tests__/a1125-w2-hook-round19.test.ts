// SPDX-License-Identifier: Apache-2.0
/**
 * Round 19, from the seventeenth independent check: the one URL rule in commands as in manifests
 * (N1, row by row), a range gets the name-alone guard (N2), a file: find-links is local (N3), the
 * advice line after a versioned runner and after `link` (N4).
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { sandbox, type Sandbox } from "./helpers/a1123-hookfix-run.js";

let s: Sandbox;
beforeEach(() => {
  s = sandbox();
  s.ledger([
    { ecosystem: "npm", package: "lodash", version: "4.17.20", verdict: "avoid", reason: "test avoid" },
    { ecosystem: "npm", package: "lodash", version: "4.17.21", requested: "^4.17.0", verdict: "proceed", reason: "ok" },
    { ecosystem: "npm", package: "@types/node", version: "26.6.11", verdict: "wait", reason: "too new" },
    { ecosystem: "PyPI", package: "requests", version: "==2.19.0", verdict: "avoid", reason: "test avoid" },
    { ecosystem: "PyPI", package: "requests", version: "2.32.3", requested: ">=2", verdict: "proceed", reason: "ok" },
    { ecosystem: "crates.io", package: "regex", version: "1.11.0", requested: "^1", verdict: "proceed", reason: "ok" },
    { ecosystem: "PyPI", package: "six", version: "1.17.0", verdict: "proceed", reason: "ok" },
  ]);
});
afterEach(() => s.dispose());

const run = (command: string, cwd = s.project, tool = "Bash") => s.run({ session_id: "s", cwd, hook_event_name: "PreToolUse", tool_name: tool, tool_input: { command } });

const LT = "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz";
const NPM_URLS: Record<string, string> = {
  tarball: LT,
  "tarball ?q": `${LT}?x=1`,
  "tarball #frag": `${LT}#sha512-abc`,
  "upper host": LT.replace("registry.npmjs.org", "REGISTRY.NPMJS.ORG"),
  "yarnpkg host": LT.replace("registry.npmjs.org", "registry.yarnpkg.com"),
  npmmirror: LT.replace("registry.npmjs.org", "registry.npmmirror.com"),
  "port 443": LT.replace("registry.npmjs.org", "registry.npmjs.org:443"),
  "double slash": LT.replace(".org/", ".org//"),
  "trailing-dot host": LT.replace("registry.npmjs.org", "registry.npmjs.org."),
  "scoped @types/node": "https://registry.npmjs.org/@types/node/-/node-26.6.11.tgz",
  "scoped %2f": "https://registry.npmjs.org/@types%2fnode/-/node-26.6.11.tgz",
  "scoped %2F": "https://registry.npmjs.org/@types%2Fnode/-/node-26.6.11.tgz",
  "other name in path": "https://registry.npmjs.org/lodash/-/ms-2.1.3.tgz",
  "taobao old": LT.replace("registry.npmjs.org", "registry.npm.taobao.org"),
  tencent: "https://mirrors.cloud.tencent.com/npm/lodash/-/lodash-4.17.20.tgz",
  huaweicloud: "https://repo.huaweicloud.com/repository/npm/lodash/-/lodash-4.17.20.tgz",
  jsdelivr: "https://cdn.jsdelivr.net/npm/lodash@4.17.20/lodash.min.js",
  codeload: "https://codeload.github.com/lodash/lodash/tar.gz/refs/tags/4.17.20",
  "github archive": "https://github.com/lodash/lodash/archive/refs/tags/4.17.20.tar.gz",
  "userinfo": LT.replace("https://", "https://u:p@"),
  "http scheme": LT.replace("https://", "http://"),
  "private shape": "http://localhost:4873/lodash/-/lodash-4.17.20.tgz",
  "verdaccio single label": "http://verdaccio:4873/lodash/-/lodash-4.17.20.tgz",
  "corp host": "https://npm.acme.corp/lodash/-/lodash-4.17.20.tgz",
};

describe("N1: one URL rule for a command operand and a manifest value, row by row", () => {
  const manifest = (url: string, name = "lodash") => s.write(`${s.project}/package.json`, JSON.stringify({ name: "x", dependencies: { [url.includes("node-26") ? "@types/node" : name]: url } })).decision;
  for (const [label, url] of Object.entries(NPM_URLS)) {
    const name = url.includes("node-26") ? "@types/node" : "lodash";
    it.each([
      [`npm install ${name}@${url}`],
      [`pnpm add ${name}@${url}`],
      [`yarn add ${name}@${url}`],
      [`bun add ${name}@${url}`],
      [`npm install my-alias@npm:${url}`],
    ])(`${label}: %s decides as package.json does`, (command) => {
      const want = manifest(url, name);
      expect(run(command).decision, `${command} vs package.json ${want}`).toBe(want);
    });
  }
  it("a private shape goes ahead; a registry file of an avoid release is judged (deny); another host is held", () => {
    expect(run(`npm install lodash@${NPM_URLS["private shape"]}`).decision).toBe("allow");
    expect(run(`npm install lodash@${NPM_URLS["port 443"]}`).text).toContain("answered avoid");
    expect(run(`pnpm add lodash@${NPM_URLS.tencent}`).text).toContain("could not be read");
    expect(run(`bun add @types/node@${NPM_URLS["scoped %2f"]}`).text).toContain("answered wait");
  });
  it("a local archive is local only with no scheme and no host", () => {
    expect(run("npm install ./vendor/lodash-4.17.20.tgz").decision).toBe("allow");
    expect(run("npm install lodash@file:./vendor/lodash-4.17.20.tgz").decision).toBe("allow");
  });

  const WH = "https://files.pythonhosted.org/packages/cc/15/abc/requests-2.19.0-py2.py3-none-any.whl";
  const PY_URLS: Record<string, string> = {
    wheel: WH,
    "wheel port 443": WH.replace("files.pythonhosted.org", "files.pythonhosted.org:443"),
    "wheel upper host": WH.replace("files.pythonhosted.org", "FILES.PYTHONHOSTED.ORG"),
    "wheel #sha256": `${WH}#sha256=abc`,
    "github archive": "https://github.com/psf/requests/archive/refs/tags/v2.19.0.zip",
    "aliyun mirror": WH.replace("files.pythonhosted.org/packages", "mirrors.aliyun.com/pypi/packages"),
    "private shape": "https://pypi.acme.corp/packages/requests-2.19.0-py2.py3-none-any.whl",
  };
  for (const [label, url] of Object.entries(PY_URLS)) {
    it.each([[`pip install "requests @ ${url}"`], [`uv add "requests @ ${url}"`], [`uv pip install "requests @ ${url}"`]])(`${label}: %s decides as requirements.txt does`, (command) => {
      const want = s.write(`${s.project}/requirements.txt`, `requests @ ${url}\n`).decision;
      expect(run(command).decision, `${command} vs requirements ${want}`).toBe(want);
    });
  }
});

describe("N2: a range gets the name-alone guard; the range verdict itself as before", () => {
  it.each([
    ["package.json", '{"dependencies":{"lodash":"4.17.20"}}', "pnpm add lodash@^4.17.0", "lodash"],
    ["package.json", '{"dependencies":{"lodash":"4.17.20"}}', "bun add lodash@^4.17.0", "lodash"],
    ["package.json", '{"dependencies":{"lodash":"4.17.20"}}', "npm install lodash@^4.17.0", "lodash"],
    ["pyproject.toml", '[project]\nname = "x"\nversion = "0"\ndependencies = ["requests==2.19.0"]\n', "uv add 'requests>=2'", "requests"],
    ["Cargo.toml", '[package]\nname = "x"\nversion = "0.1.0"\n[dependencies]\nregex = "=1.5.4"\n', "cargo add regex@^1", "regex"],
  ])("%s declaring it: `%s` is held with name the exact version", (file, content, command, name) => {
    s.file(file, content);
    const r = run(command);
    expect(r.decision, r.text).toBe("deny");
    expect(r.text).toContain(`already names ${name}`);
    expect(r.text).toContain("name the exact version");
  });
  it("in a clean folder the range goes ahead on its verdict; an exact version is never held by the guard", () => {
    expect(run("pnpm add lodash@^4.17.0").decision).toBe("allow");
    s.file("package.json", '{"dependencies":{"lodash":"4.17.20"}}');
    expect(run("pnpm add lodash@4.17.20").text).toContain("answered avoid");
  });
});

describe("N3: a file: find-links has no host: local", () => {
  it.each(["pip install six==1.17.0 --no-index --find-links=file:///C:/wheels", "pip install six==1.17.0 --no-index -f file:///opt/wheels", "pip install six==1.17.0 -i file:///C:/index"])("%s: goes ahead", (command) => {
    expect(run(command).decision).toBe("allow");
  });
});

describe("N4: the advice line after a versioned runner target and after link", () => {
  const post = (command: string) => s.run({ session_id: "s", cwd: s.project, hook_event_name: "PostToolUse", tool_name: "Bash", tool_input: { command }, tool_response: {} });
  it.each(["npx pnpm@9 install", "npx npm@10 ci", "npx -y yarn@1.22.22 install", "npm link lodash", "pnpm link lodash", "yarn link lodash", "bun link lodash", "npm link"])("%s: advised", (command) => {
    expect(post(command).text).toContain("Run vulnerability_scan");
  });
});
