// SPDX-License-Identifier: Apache-2.0
/**
 * Round 25 of the hook lane (seam hunt 4, S1-S9; sentence check 21, W1-W5): what changes WHERE or
 * WHICH release resolves is read, not skipped. Requirements option lines and -r / -c files (S1, S2),
 * resolver settings in pyproject.toml and package.json (S3), Cargo entry keys (S4), duplicate keys
 * (S5), configuration writes (S6), fetch verbs (S7), data-folder spellings Windows accepts (S8), a
 * manager's first operand from an expansion (S9); a source is the project's own only when its
 * location is read and private by its shape (W1).
 */

import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import * as hook from "../../hooks/manifest-edit.mjs";
import { sandbox, type Sandbox } from "./helpers/a1123-hookfix-run.js";

let s: Sandbox;
beforeEach(() => {
  s = sandbox();
  s.ledger([
    { ecosystem: "PyPI", package: "requests", version: "2.19.0", verdict: "avoid", reason: "test avoid" },
    { ecosystem: "PyPI", package: "six", version: "1.17.0", verdict: "proceed" },
    { ecosystem: "npm", package: "lodash", version: "4.17.20", verdict: "avoid", reason: "test avoid" },
    { ecosystem: "crates.io", package: "regex", version: "1.5.4", requested: "=1.5.4", verdict: "avoid", reason: "test avoid" },
    { ecosystem: "Go", package: "golang.org/x/text", version: "v0.3.0", verdict: "avoid", reason: "test avoid" },
  ]);
});
afterEach(() => s.dispose());

const bash = (command: string) => s.run({ session_id: "s", cwd: s.project, hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command } });
const ps = (command: string) => s.run({ session_id: "s", cwd: s.project, hook_event_name: "PreToolUse", tool_name: "PowerShell", tool_input: { command } });

describe("S1: a requirements file's option lines and -r / -c files", () => {
  it.each(["--index-url https://x.example/simple", "-i https://x.example/simple", "--extra-index-url https://x.example/simple", "--find-links ./wheels", "-f ./wheels", "--trusted-host x.example", "--pre", "--prefer-binary", "--only-binary :all:", "--no-binary :all:", "--no-index", "--use-feature truststore", "--frobnicate"])(
    "a new option line %s is held",
    (line) => {
      const file = s.file("requirements.txt", "six==1.17.0\n");
      const r = s.edit(file, "six==1.17.0\n", `six==1.17.0\n${line}\n`);
      expect(r.decision, r.text).toBe("deny");
      expect(r.text).toContain("changes where or which releases pip resolves");
    },
  );
  it.each(["six==1.17.0 --hash=sha256:abc", "# a comment", "", "-e ./local"])("an inert line %j is not held", (line) => {
    const file = s.file("requirements.txt", "six==1.17.0\n");
    expect(s.write(file, `six==1.17.0\n${line}\n`).decision).toBe("allow");
  });
  it.each(["-r", "--requirement", "-c", "--constraint"])("%s <file> is read from disk, relative to the file that names it", (opt) => {
    s.file("reqs/base.txt", "requests==2.19.0\n");
    const file = s.file("requirements.txt", "six==1.17.0\n");
    const r = s.edit(file, "six==1.17.0\n", `six==1.17.0\n${opt} reqs/base.txt\n`);
    expect(r.decision).toBe("deny");
    expect(r.text).toContain("answered avoid");
  });
  it("nested includes are followed; a missing one, and one past the bound, are held", () => {
    s.file("a.txt", "-r b.txt\n");
    s.file("b.txt", "requests==2.19.0\n");
    const file = s.file("requirements.txt", "six==1.17.0\n");
    expect(s.edit(file, "six==1.17.0\n", "six==1.17.0\n-r a.txt\n").text).toContain("answered avoid");
    expect(s.edit(file, "six==1.17.0\n", "six==1.17.0\n-r nope.txt\n").text).toContain("could not read");
    for (let i = 0; i < 10; i++) s.file(`d${i}.txt`, `-r d${i + 1}.txt\n`);
    s.file("d10.txt", "six==1.17.0\n");
    expect(s.edit(file, "six==1.17.0\n", "six==1.17.0\n-r d0.txt\n").text).toContain("past 8 levels");
  });
});

describe("S2: a requirements file a command names is read at the call, whatever its name", () => {
  beforeEach(() => {
    s.file("deps.txt", "requests==2.19.0\n");
    s.file("ok.in", "six==1.17.0\n");
    s.file("idx.txt", "six==1.17.0\n--index-url https://x.example/simple\n");
  });
  it.each(["pip install -r deps.txt", "pip install --requirement=deps.txt", "uv pip install -r deps.txt", "uv pip sync deps.txt", "pip install -c deps.txt six==1.17.0", "python -m pip install -r deps.txt"])("%s: judged on the avoid", (command) => {
    const r = bash(command);
    expect(r.decision).toBe("deny");
  });
  it("a file of proceed lines goes ahead; an option line in it, or a missing file, is held", () => {
    expect(bash("pip install -r ok.in").decision).toBe("allow");
    expect(bash("pip install -r idx.txt").text).toContain("an option line that changes where or which releases pip resolves");
    expect(bash("pip install -r missing.txt").text).toContain("could not read");
    expect(bash("cd sub && pip install -r ok.in").text).toContain("in a folder the hook cannot follow");
  });
});

describe("S3: a resolver setting that is no dependency value", () => {
  const HEAD = '[project]\nname = "a"\nversion = "0.1.0"\ndependencies = ["six==1.17.0"]\n';
  it.each([
    '[tool.uv]\nexclude-newer = "2020-01-01"\n',
    '[tool.uv]\nprerelease = "allow"\n',
    '[tool.uv]\nresolution = "lowest"\n',
    '[tool.uv]\nindex-strategy = "unsafe-best-match"\n',
    '[tool.uv]\nindex-url = "https://x.example/simple"\n',
    '[tool.uv]\nextra-index-url = ["https://x.example/simple"]\n',
    '[tool.uv]\nfind-links = ["./wheels"]\n',
    "[tool.uv]\nno-index = true\n",
    '[[tool.uv.index]]\nname = "x"\nurl = "https://x.example/simple"\n',
    '[[tool.uv.index]]\nname = "x"\nurl = "https://pypi.corp.internal/simple"\ndefault = true\n',
    '[tool.uv.pip]\nindex-url = "https://x.example/simple"\n',
    '[[tool.poetry.source]]\nname = "x"\nurl = "https://x.example/simple"\n',
    '[[tool.pdm.source]]\nname = "x"\nurl = "https://x.example/simple"\n',
    '[tool.pdm.resolution]\nrespect-source-order = true\n',
  ])("held: %j", (table) => {
    const file = s.file("pyproject.toml", HEAD);
    const r = s.write(file, `${HEAD}\n${table}`);
    expect(r.decision, r.text).toBe("deny");
    expect(r.text).toContain("changes where or which releases the package manager resolves");
  });
  it.each(['[tool.ruff]\nline-length = 100\n', '[tool.pytest.ini_options]\naddopts = "-q"\n', "[tool.uv]\nmanaged = true\n", '[tool.uv]\ndefault-groups = ["dev"]\n', '[[tool.uv.index]]\nname = "pub"\nurl = "https://pypi.org/simple"\n', '[[tool.uv.index]]\nname = "corp"\nurl = "https://pypi.corp.internal/simple"\nexplicit = true\n'])(
    "not held: %j",
    (table) => {
      const file = s.file("pyproject.toml", HEAD);
      expect(s.write(file, `${HEAD}\n${table}`).decision).toBe("allow");
    },
  );
  it("setuptools dynamic dependencies are read from the files they name", () => {
    s.file("requirements.txt", "requests==2.19.0\n");
    const file = s.file("pyproject.toml", '[project]\nname = "a"\nversion = "0.1.0"\ndynamic = ["dependencies"]\n');
    expect(s.write(file, '[project]\nname = "a"\nversion = "0.1.0"\ndynamic = ["dependencies"]\n\n[tool.setuptools.dynamic]\ndependencies = { file = ["requirements.txt"] }\n').text).toContain("answered avoid");
  });
  it("package.json: an unknown pnpm key and patchedDependencies are held; inert pnpm keys and other top-level keys are not", () => {
    const file = s.file("package.json", '{"name":"a"}');
    expect(s.write(file, JSON.stringify({ name: "a", pnpm: { patchedDependencies: { "lodash@4.18.1": "p.patch" } } })).decision).toBe("deny");
    expect(s.write(file, JSON.stringify({ name: "a", patchedDependencies: { "lodash@4.18.1": "p.patch" } })).decision).toBe("deny");
    expect(s.write(file, JSON.stringify({ name: "a", pnpm: { onlyBuiltDependencies: ["esbuild"] }, eslintConfig: { root: true }, engines: { node: ">=22" }, publishConfig: { access: "public" } })).decision).toBe("allow");
  });
});

describe("S4: Cargo dependency entry keys, read on a known list", () => {
  const CARGO = (dep: string) => `[package]\nname = "a"\nversion = "0.1.0"\n\n[dependencies]\n${dep}\n`;
  it.each(['regex = { version = "=1.5.4", frob = "x" }', 'regex = { version = "=1.5.4", registry-index = "https://cargo.example.com/index" }'])("held: %s", (dep) => {
    expect(s.write(join(s.project, "Cargo.toml"), CARGO(dep)).decision).toBe("deny");
  });
  it("registry-index at crates.io is judged; registry = <name> follows .cargo/config.toml", () => {
    expect(s.write(join(s.project, "Cargo.toml"), CARGO('regex = { version = "=1.5.4", registry-index = "sparse+https://index.crates.io/" }')).text).toContain("answered avoid");
    s.file(".cargo/config.toml", '[registries.pub]\nindex = "sparse+https://index.crates.io/"\n[registries.corp]\nindex = "sparse+https://cargo.corp.internal/index/"\n');
    expect(s.write(join(s.project, "Cargo.toml"), CARGO('regex = { version = "=1.5.4", registry = "pub" }')).text).toContain("answered avoid");
    expect(s.write(join(s.project, "Cargo.toml"), CARGO('regex = { version = "=1.5.4", registry = "corp" }')).decision).toBe("allow");
    expect(s.write(join(s.project, "Cargo.toml"), CARGO('regex = { version = "=1.5.4", registry = "nowhere" }')).text).toContain("could not be read");
  });
});

describe("S5: a key given twice is not read", () => {
  it("package.json, at the top, in a section and in overrides", () => {
    for (const text of ['{"dependencies":{"lodash":"4.18.1"},"dependencies":{"lodash":"4.17.20"}}', '{"dependencies":{"lodash":"4.18.1","lodash":"4.17.20"}}', '{"overrides":{"lodash":"4.18.1","lodash":"4.17.20"}}']) {
      const r = s.write(join(s.project, "package.json"), text);
      expect(r.decision, text).toBe("deny");
      expect(r.text).toContain("given twice");
    }
    expect(s.write(join(s.project, "package.json"), '{"a":{"x":1},"b":{"x":1}}').decision).toBe("allow");
  });
  it("TOML and a pnpm catalog", () => {
    expect(s.write(join(s.project, "Cargo.toml"), '[package]\nname = "a"\nversion = "0.1.0"\n\n[dependencies]\nregex = "1"\nregex = "=1.5.4"\n').text).toContain("defined twice");
    expect(s.write(join(s.project, "Cargo.toml"), '[package]\nname = "a"\n\n[dependencies]\nregex = "1"\n\n[dependencies]\nserde = "1"\n').text).toContain("defined twice");
    expect(s.write(join(s.project, "pnpm-workspace.yaml"), "packages:\n  - 'a'\ncatalog:\n  lodash: 4.18.1\n  lodash: 4.17.20\n").text).toContain("given twice");
  });
});

describe("S6: a manager's configuration write", () => {
  it.each([
    "npm config set registry https://x.example/",
    "npm config set @acme:registry https://x.example/",
    "npm set before 2020-01-01",
    "npm config delete registry",
    "npm config edit",
    "pnpm config set minimum-release-age 0",
    "pnpm config set resolution-mode lowest",
    "yarn config set npmRegistryServer https://x.example/",
    "pip config set global.index-url https://x.example/simple",
    "pip config set global.extra-index-url https://x.example/simple",
    "poetry source add corp https://x.example/simple",
    "poetry config repositories.x https://x.example/",
    "go env -w GOPROXY=direct",
    "go env -w GOFLAGS=-mod=mod",
    "go env -w GONOSUMDB=*",
  ])("%s is held", (command) => {
    const r = bash(command);
    expect(r.decision, r.text).toBe("deny");
  });
  it.each(["npm config set fund false", "npm config set init-author-name x", "npm config get registry", "npm config list", "pip config list", "poetry config virtualenvs.in-project true", "go env -w GOBIN=/x", "go env GOPROXY"])("%s goes ahead", (command) => {
    expect(bash(command).decision).toBe("allow");
  });
  it("the constants", () => {
    expect(hook.CONFIG_WRITE_VERBS.npm).toContain("config");
    expect(hook.INERT_CONFIG_KEYS).toContain("fund");
    for (const k of ["registry", "audit", "before", "min-release-age", "minimum-release-age", "global.index-url", "goproxy", "goflags", "goprivate"]) expect(hook.INERT_CONFIG_KEYS).not.toContain(k);
  });
});

describe("S7: a fetch verb needs a verdict for the release it names", () => {
  it.each(["npm pack lodash@4.17.20", "npm cache add lodash@4.17.20", "pip download requests==2.19.0", "pip wheel requests==2.19.0 -w dist", "go mod download golang.org/x/text@v0.3.0"])("%s", (command) => {
    const r = bash(command);
    expect(r.decision).toBe("deny");
  });
  it("npm pack of the project itself names no release", () => {
    expect(bash("npm pack").decision).toBe("allow");
    expect(bash("npm pack --dry-run").decision).toBe("allow");
  });
});

describe("S8 and W2: the data folder as Windows names it", () => {
  const base = () => s.home.split(/[\\/]/).pop()!;
  it.each(["[IO.Directory]::Move('DATA.', 'x')", "cmd //c ren DATA. x", "rm -rf DATA.", "rm -rf 'DATA. '", "rm -rf DATA::$INDEX_ALLOCATION"])("%s is held", (t) => {
    expect(ps(t.replace("DATA", base())).decision).toBe("deny");
  });
  it("a name that continues past a dot is not", () => {
    expect(ps(`cat ${base()}.json`).decision).toBe("allow");
    expect(ps(`cat ${base()}.d`).decision).toBe("allow");
  });
  it("the 8.3 short name and a one- or two-letter base name", () => {
    const short = base().replace(/[^A-Za-z0-9_-]/g, "").slice(0, 6).toUpperCase();
    expect(ps(`rm -rf ${short}~1`).decision).toBe("deny");
    expect(hook.namesDataSegment("rm -rf ab", { FOURDA_MCP_HOME: join(s.home, "ab") })).toBe(true);
    expect(hook.namesDataSegment("rm -rf abc", { FOURDA_MCP_HOME: join(s.home, "ab") })).toBe(false);
  });
});

describe("S9: a manager whose first operand is an expansion is not read", () => {
  it.each(['a=(i lodash@4.17.20); npm "${a[@]}"', "v=install; npm $v lodash@4.17.20", 'set -- i lodash@4.17.20; npm "$@"'])("%s", (command) => {
    expect(bash(command).decision).toBe("deny");
  });
  it("PowerShell splat", () => {
    expect(ps("$a = 'i', 'lodash@4.17.20'; npm @a").decision).toBe("deny");
  });
});

describe("W1: a dependency's source is judged from where it points", () => {
  const P = '[project]\nname = "a"\nversion = "0.1.0"\ndependencies = ["requests==2.19.0"]\n';
  const where = {
    public: "https://pypi.org/simple",
    private: "https://pypi.corp.internal/simple",
  };
  const forms = {
    "uv table": (url: string) => `[[tool.uv.index]]\nname = "x"\nurl = "${url}"\nexplicit = true\n\n[tool.uv.sources]\nrequests = { index = "x" }\n`,
    "uv inline": (url: string) => `[tool.uv]\nindex = [{ name = "x", url = "${url}", explicit = true }]\n\n[tool.uv.sources]\nrequests = { index = "x" }\n`,
  };
  it.each(Object.entries(forms).flatMap(([form, make]) => Object.entries(where).map(([kind, url]) => [form, kind, make(url)] as const)))("%s, %s: public judged, private own", (_form, kind, table) => {
    const file = s.file("pyproject.toml", `${P.replace('"requests==2.19.0"', "")}\n${table}`);
    const r = s.write(file, `${P}\n${table}`);
    if (kind === "public") expect(r.text).toContain("answered avoid");
    else expect(r.decision).toBe("allow");
  });
  it("Poetry: a source named and declared at pypi.org is judged; undeclared, missing or duplicate is held", () => {
    const head = '[tool.poetry]\nname = "a"\n\n[tool.poetry.dependencies]\nrequests = { version = "2.19.0", source = "pub" }\n';
    const decl = (name: string, url: string) => `\n[[tool.poetry.source]]\nname = "${name}"\nurl = "${url}"\npriority = "explicit"\n`;
    const none = head.replace('requests = { version = "2.19.0", source = "pub" }\n', "");
    expect(s.write(s.file("pyproject.toml", none + decl("pub", "https://pypi.org/simple")), head + decl("pub", "https://pypi.org/simple")).text).toContain("answered avoid");
    expect(s.write(s.file("pyproject.toml", head), head + "\n").text).toContain("could not be read");
    expect(s.write(s.file("pyproject.toml", head + decl("pub", "https://a.example/x") + decl("pub", "https://b.example/x")), head + decl("pub", "https://a.example/x") + decl("pub", "https://b.example/x") + "\n").text).toContain("could not be read");
  });
  it("[[tool.uv.index]] tables are paired per table: a first table with no name names nothing", () => {
    const t = '[[tool.uv.index]]\nurl = "https://pypi.corp.internal/simple"\nexplicit = true\n\n[[tool.uv.index]]\nname = "x"\nurl = "https://pypi.org/simple"\nexplicit = true\n\n[tool.uv.sources]\nrequests = { index = "x" }\n';
    expect(s.write(s.file("pyproject.toml", `${P.replace('"requests==2.19.0"', "")}\n${t}`), `${P}\n${t}`).text).toContain("answered avoid");
  });
});

describe("W3: values outside the ecosystem's grammar are held", () => {
  const C = (dep: string) => `[package]\nname = "a"\nversion = "0.1.0"\n\n[dependencies]\n${dep}\n`;
  it.each(["regex = 1", "regex = true", 'regex = ["1.5.4"]', "regex = { version = 1 }"])("Cargo %s", (dep) => {
    expect(s.write(join(s.project, "Cargo.toml"), C(dep)).text).toContain("could not be read");
  });
  it("pyproject array item 42, Poetry requests = 2, an empty pnpm catalog value", () => {
    expect(s.write(join(s.project, "pyproject.toml"), '[project]\nname = "a"\nversion = "0.1.0"\ndependencies = [42]\n').text).toContain("could not be read");
    expect(s.write(join(s.project, "pyproject.toml"), '[tool.poetry]\nname = "a"\n\n[tool.poetry.dependencies]\nrequests = 2\n').text).toContain("could not be read");
    expect(s.write(join(s.project, "pnpm-workspace.yaml"), "packages:\n  - 'a'\ncatalog:\n  lodash:\n").text).toContain("could not be read");
  });
});

describe.runIf(process.platform === "win32")("W4: a bare name with a dot is looked up", () => {
  it("pip3.12 with only pip3.12.bat on PATH is not read", () => {
    const dir = join(s.home, "bin");
    mkdirSync(dir);
    writeFileSync(join(dir, "pip3.12.bat"), "");
    const r = s.run({ session_id: "s", cwd: s.project, hook_event_name: "PreToolUse", tool_name: "PowerShell", tool_input: { command: 'pip3.12 install "requests>=2.19"' } }, { Path: dir, PATH: dir });
    expect(r.text).toContain("cmd.exe rewrites");
  });
});

describe("W5 g: build metadata in a server version is ignored", () => {
  it("sv 6.6.0+build.1 counts", () => {
    s.ledger([]);
    writeFileSync(join(s.home, "check-ledger.jsonl"), JSON.stringify({ t: new Date(Date.now() - 60_000).toISOString(), sv: "6.6.0+build.1", ecosystem: "npm", package: "lodash", version: "4.18.1", verdict: "proceed" }) + "\n");
    expect(bash("npm i lodash@4.18.1").decision).toBe("allow");
  });
});
