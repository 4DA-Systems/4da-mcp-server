// SPDX-License-Identifier: Apache-2.0
/**
 * Round 18, from the sixteenth independent check: the name-alone rule is a guard (M1, each cause
 * tested), one URL rule for every reader (M2), `bun update x` read as an add (M3), go.mod versions
 * (M4), one source rule with a way through in every state (M5), exclusions bound nothing (M6), and
 * the advice line behind a runner (M7).
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { sandbox, type Sandbox } from "./helpers/a1123-hookfix-run.js";

let s: Sandbox;
beforeEach(() => {
  s = sandbox();
  s.ledger([
    { ecosystem: "npm", package: "lodash", version: "4.17.21", requested: "latest", verdict: "proceed", reason: "ok" },
    { ecosystem: "npm", package: "lodash", version: "4.17.20", verdict: "avoid", reason: "test avoid" },
    { ecosystem: "PyPI", package: "requests", version: "2.19.0", verdict: "avoid", reason: "test avoid" },
    { ecosystem: "PyPI", package: "requests", version: "2.34.2", verdict: "proceed", reason: "ok" },
    { ecosystem: "PyPI", package: "requests", version: "2.34.2", requested: "latest", verdict: "proceed", reason: "ok" },
    { ecosystem: "PyPI", package: "six", version: "1.17.0", verdict: "proceed", reason: "ok" },
    { ecosystem: "PyPI", package: "six", version: "1.16.0", verdict: "avoid", reason: "test avoid" },
    { ecosystem: "npm", package: "@types/node", version: "26.6.11", requested: "latest", verdict: "wait", reason: "too new" },
    { ecosystem: "Go", package: "github.com/google/go-cmp", version: "v0.7.0", requested: "latest", verdict: "proceed", reason: "ok" },
    { ecosystem: "crates.io", package: "regex", version: "1.11.0", requested: "latest", verdict: "proceed", reason: "ok" },
  ]);
});
afterEach(() => s.dispose());

const run = (command: string, cwd = s.project, tool = "Bash") => s.run({ session_id: "s", cwd, hook_event_name: "PreToolUse", tool_name: tool, tool_input: { command } });
const FOLLOW = "a directory change this hook does not follow";

describe("M1: the name-alone guard, each cause it lists", () => {
  beforeEach(() => {
    s.file("a/.keep", "");
    s.file("b/.keep", "");
  });
  it.each([
    'pwsh -WorkingDirectory a -Command "pnpm add lodash"',
    'pwsh -wd a -c "pnpm add lodash"',
    'pwsh -NoProfile -WorkingDirectory a -Command "pnpm add lodash"',
    "pnpm -C a exec pnpm add lodash",
    "pnpm --dir a exec pnpm add lodash",
    "npm --prefix a exec -- pnpm add lodash",
    "uv --directory a run uv add requests",
    "uv run --directory a uv add requests",
    "yarn --cwd a exec pnpm add lodash",
    "npx --prefix a pnpm add lodash",
  ])("(i) a wrapper with a directory option: %s", (command) => {
    expect(run(command).text).toContain(FOLLOW);
  });
  it.each(["true && cd a && pnpm add lodash", "false || cd a; pnpm add lodash", "cd a | true; pnpm add lodash", "cd a && cd b && pnpm add lodash"])("(ii) a cd that is not unconditional: %s", (command) => {
    expect(run(command).text).toContain(FOLLOW);
  });
  it.each([
    "pnpm add lodash --dir a --dir b",
    "pnpm -C a add lodash --dir b",
    "npm install lodash --prefix a --prefix b",
    "uv add requests --directory a --project b",
    "bun add lodash --cwd a --cwd b",
    "yarn --cwd a add lodash --cwd b",
  ])("(iii) the same or two directory options: %s", (command) => {
    expect(run(command).text).toContain(FOLLOW);
  });
  it("(iii) one directory option to a folder that exists: judged", () => {
    expect(run("pnpm add lodash --dir a").decision).toBe("allow");
  });
  it.each(["D:; npm install lodash", "D:\nnpm install lodash"])("(iv) a drive change: %j", (command) => {
    expect(run(command, s.project, "PowerShell").text).toContain(FOLLOW);
  });
  it.each([
    ["pnpm-workspace.yaml", "packages: []\n", "pnpm add lodash"],
    ["lerna.json", "{}", "npm install lodash"],
    ["nx.json", "{}", "npm install lodash"],
    ["rush.json", "{}", "pnpm add lodash"],
    ["package.json", '{"name":"r","workspaces":{"packages":["a"]}}', "npm install lodash"],
    ["pyproject.toml", '[tool.uv]\nworkspace = { members = ["a"] }\n', "uv add requests"],
    ["pyproject.toml", '[tool.uv.workspace]\nmembers = ["a"]\n', "uv add requests"],
    ["pyproject.toml", '[tool.uv . workspace]\nmembers = ["a"]\n', "uv add requests"],
    ["pyproject.toml", '[tool."uv".workspace]\nmembers = ["a"]\n', "uv add requests"],
    ["Cargo.toml", 'workspace = { members = ["a"] }\n', "cargo add regex"],
    ["Cargo.toml", '[ workspace ]\nmembers = ["a"]\n', "cargo add regex"],
    ["Cargo.toml", 'workspace.members = ["a"]\n', "cargo add regex"],
    ["go.work", "go 1.22\n", "npm install lodash"],
  ])("(v) %s holding %j: %s held", (file, content, command) => {
    s.file(file, content);
    const r = run(command, `${s.project}/a`);
    expect(r.decision, r.text).toBe("deny");
    expect(r.text).toContain("this folder is inside a workspace");
  });
  it("a clean folder: judged on latest", () => {
    expect(run("pnpm add lodash").decision).toBe("allow");
    expect(run("cd a && pnpm add lodash").decision).toBe("allow");
  });
});

describe("M2: one URL rule for every reader", () => {
  const WHEEL = "https://files.pythonhosted.org/packages/cc/15/abc/requests-2.19.0-py2.py3-none-any.whl";
  const SDIST = "https://files.pythonhosted.org/packages/source/r/requests/requests-2.19.0.tar.gz";
  const OTHER = ["https://github.com/psf/requests/archive/refs/tags/v2.19.0.zip", "https://example.org/requests-2.19.0.tar.gz", "https://pypi.acme.com/files/requests-2.19.0.tar.gz", "http://1.2.3.4/requests.whl"];
  const PRIVATE = ["http://localhost:8080/requests-2.19.0.tar.gz", "https://files.corp/requests-2.19.0.tar.gz"];
  const pj = (dep: string) => `[project]\nname = "x"\nversion = "0.1.0"\ndependencies = [${JSON.stringify(dep)}]\n`;
  const readers: Array<[string, (url: string) => [string, string]]> = [
    ["pep621", (u) => ["pyproject.toml", pj(`requests @ ${u}`)]],
    ["optional-dependencies", (u) => ["pyproject.toml", `[project]\nname = "x"\nversion = "0"\n[project.optional-dependencies]\nweb = [${JSON.stringify(`requests @ ${u}`)}]\n`]],
    ["dependency-groups", (u) => ["pyproject.toml", `[dependency-groups]\ndev = [${JSON.stringify(`requests @ ${u}`)}]\n`]],
    ["uv sources", (u) => ["pyproject.toml", `${pj("requests")}\n[tool.uv.sources]\nrequests = { url = ${JSON.stringify(u)} }\n`]],
    ["poetry", (u) => ["pyproject.toml", `[tool.poetry.dependencies]\nrequests = { url = ${JSON.stringify(u)} }\n`]],
    ["requirements", (u) => ["requirements.txt", `requests @ ${u}\n`]],
  ];
  for (const [reader, make] of readers) {
    it.each([WHEEL, SDIST])(`${reader}: a public registry file is that release, judged (avoid): %s`, (u) => {
      const [file, content] = make(u);
      const r = s.write(`${s.project}/${file}`, content);
      expect(r.decision, r.text).toBe("deny");
      expect(r.text).toContain("answered avoid");
    });
    it.each(OTHER)(`${reader}: another host is held as a source the hook cannot judge: %s`, (u) => {
      const [file, content] = make(u);
      const r = s.write(`${s.project}/${file}`, content);
      expect(r.decision, r.text).toBe("deny");
      expect(r.text).toMatch(/a source this hook cannot judge|could not be read/);
    });
    it.each(PRIVATE)(`${reader}: a host private by its shape goes ahead: %s`, (u) => {
      const [file, content] = make(u);
      expect(s.write(`${s.project}/${file}`, content).decision).toBe("allow");
    });
  }
  it("package.json: a registry tarball is that release, judged; another host is held; a private one goes ahead", () => {
    expect(s.write(`${s.project}/package.json`, JSON.stringify({ dependencies: { lodash: "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz" } })).text).toContain("answered avoid");
    expect(s.write(`${s.project}/package.json`, JSON.stringify({ dependencies: { lodash: "https://example.org/lodash.tgz" } })).text).toContain("a source this hook cannot judge");
    expect(s.write(`${s.project}/package.json`, JSON.stringify({ dependencies: { lodash: "http://localhost:4873/lodash.tgz" } })).decision).toBe("allow");
  });
  it("a URL source is released by a private record", () => {
    s.ledger([{ ecosystem: "PyPI", package: "acme-utils", version: "latest", verdict: "unknown", reason: "NOT CHECKED (private): acme-utils is a private package (FOURDA_PRIVATE_PACKAGES)", not_checked: "private" }]);
    const r = s.write(`${s.project}/pyproject.toml`, pj("acme-utils @ https://pypi.acme.com/files/acme_utils-1.0.0.tar.gz"));
    expect(r.decision, r.text).toBe("allow");
  });
  it("an unchanged URL is not judged again", () => {
    const content = pj(`requests @ ${OTHER[0]}`);
    s.file("pyproject.toml", content);
    expect(s.write(`${s.project}/pyproject.toml`, `${content}# a comment\n`).decision).toBe("allow");
  });
});

describe("M3: `bun update x` adds x when the project does not declare it", () => {
  it.each(["bun update @types/node", "bun update --latest @types/node"])("%s: judged on latest (a wait verdict holds)", (command) => {
    const r = run(command);
    expect(r.decision).toBe("deny");
    expect(r.text).toContain("answered wait");
  });
  it("bun update lodash: on its latest proceed", () => {
    expect(run("bun update lodash").decision).toBe("allow");
  });
  it.each(["npm update lodash", "pnpm up lodash", "yarn upgrade lodash", "bun update"])("%s: a stated limit, goes ahead", (command) => {
    expect(run(command).decision).toBe("allow");
  });
});

describe("M4: go.mod and go.work versions", () => {
  const mod = (v: string) => `module example.com/app\n\ngo 1.22\n\nrequire github.com/google/go-cmp ${v}\n`;
  it("latest needs the latest verdict", () => {
    expect(s.write(`${s.project}/go.mod`, mod("latest")).decision).toBe("allow");
  });
  it.each(["master", "upgrade", "patch", ">v0.5.0", "main"])("%s: held, name the version", (v) => {
    const r = s.write(`${s.project}/go.mod`, mod(v));
    expect(r.decision).toBe("deny");
    expect(r.text).toContain("name the exact version");
    expect(s.write(`${s.project}/go.work`, `go 1.22\nrequire (\n  github.com/google/go-cmp ${v}\n)\n`).decision).toBe("deny");
  });
  it("an exact version and a pseudo-version are judged as before", () => {
    expect(s.write(`${s.project}/go.mod`, mod("v0.5.0")).decision).toBe("deny");
    expect(s.write(`${s.project}/go.mod`, mod("v0.0.0-20240101000000-abcdefabcdef")).decision).toBe("deny");
  });
});

describe("M5: one source rule: no state without a way through, avoid always denied", () => {
  const OPTIONS: Record<string, string[]> = {
    pip: ["-i", "--index-url", "--extra-index-url", "-f", "--find-links"],
    uv: ["--index", "--index-url", "--default-index", "--extra-index-url", "-f", "--find-links"],
    uvpip: ["-i", "--index-url", "--default-index", "--extra-index-url", "--index", "-f", "--find-links"],
  };
  const base = { pip: "pip install", uv: "uv add", uvpip: "uv pip install" };
  const HOSTS = ["https://pypi.acme.com/simple", "https://pypi.org/simple"];
  const states: Array<[string, string, "allow" | "deny"]> = [
    ["proceed", "requests==2.34.2", "allow"],
    ["avoid", "requests==2.19.0", "deny"],
    ["none", "zzq-none==1.0.0", "deny"],
    ["private", "acme-utils==1.0.0", "allow"],
  ];
  const cases: Array<[string, "allow" | "deny", string]> = [];
  for (const [tool, opts] of Object.entries(OPTIONS)) {
    for (const o of opts) {
      for (const [state, spec, want] of states) {
        for (const host of HOSTS) {
          cases.push([`${base[tool as keyof typeof base]} ${spec} ${o} ${host}`, want, state]);
          cases.push([`${base[tool as keyof typeof base]} ${spec} ${o} ${host} --extra-index-url https://pypi.acme.com/simple`, want, state]);
        }
      }
    }
  }
  it.each(cases)("%s -> %s (%s)", (command, want) => {
    s.ledger([
      { ecosystem: "PyPI", package: "requests", version: "2.34.2", verdict: "proceed", reason: "ok" },
      { ecosystem: "PyPI", package: "requests", version: "2.19.0", verdict: "avoid", reason: "test avoid" },
      { ecosystem: "PyPI", package: "acme-utils", version: "1.0.0", verdict: "unknown", reason: "NOT CHECKED (private): acme-utils is a private package (FOURDA_PRIVATE_PACKAGES)", not_checked: "private" },
    ]);
    const r = run(command);
    expect(r.decision, r.text).toBe(want);
    if (want === "deny") expect(r.text).not.toContain("could not be read");
  });
  it.each(["pip install six==1.16.0 --no-index", "pip install six==1.16.0 --no-index --find-links ./wheels", "uv pip install six==1.16.0 --no-index -f ./wheels", "pip install six==1.16.0 -i http://localhost:4873/simple"])(
    "%s: no public release, goes ahead unjudged",
    (command) => {
      expect(run(command).decision).toBe("allow");
    },
  );
  it("--no-index beside a find-links on another host: held, with a way through", () => {
    const r = run("pip install six==1.17.0 --no-index --find-links https://example.org/wheels/");
    expect(r.decision).toBe("deny");
    expect(r.text).toContain("give --find-links that folder");
  });
});

describe("M6: a range of exclusions only bounds nothing", () => {
  it.each(['"!=1.0"', '"!=1.0, !=2.0"', '"!= 1.0"', '"!=1.0.0"', '{ version = "!=1.0" }', '"*, !=1.0"'])("poetry packaging = %s: latest", (v) => {
    const r = s.write(`${s.project}/pyproject.toml`, `[tool.poetry.dependencies]\npackaging = ${v}\n`);
    expect(r.items, r.text).toEqual([{ ecosystem: "PyPI", package: "packaging", to: "latest" }]);
  });
  it('">=1,!=2" is a bounded range, judged as written', () => {
    expect(s.write(`${s.project}/pyproject.toml`, '[tool.poetry.dependencies]\npackaging = ">=1,!=2"\n').items).not.toEqual([{ ecosystem: "PyPI", package: "packaging", to: "latest" }]);
  });
});

describe("M7: the advice line behind a runner", () => {
  const post = (command: string) => s.run({ session_id: "s", cwd: s.project, hook_event_name: "PostToolUse", tool_name: "Bash", tool_input: { command }, tool_response: {} });
  it.each(["npx npm ci", "npx -y pnpm install", "bunx npm install", "pnpx pnpm add zod"])("%s: advised", (command) => {
    expect(post(command).text).toContain("Run vulnerability_scan");
  });
  it("npx prettier --write .: none", () => {
    expect(post("npx prettier --write .").text).toBe("");
  });
});
