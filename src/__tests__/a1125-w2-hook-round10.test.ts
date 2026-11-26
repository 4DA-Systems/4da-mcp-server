// SPDX-License-Identifier: Apache-2.0
/**
 * Round 10, from the eighth independent check: small fixes S1-S6.
 * S1 `name@<URL>` / `name @ <URL>` is the URL. S2 a constraints or overrides file beside a named
 * package: held, "name the version". S3 Poetry's `--source pypi` and crates.io's git index are the
 * public ones. S4 `poetry self add x==v` is an add. S5 a ledger line that names a package but is
 * not fully valid makes its verdict unknown; the budget hold says what happened. S6 an extra index
 * or find-links keeps the public index in play: the names are judged on their verdicts.
 */

import { writeFileSync } from "node:fs";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { sandbox, type Sandbox } from "./helpers/a1123-hookfix-run.js";
import { followRemedy, answerDenial } from "./helpers/a1125-hook-run.js";

let s: Sandbox;
beforeEach(() => {
  s = sandbox();
  s.ledger([]);
});
afterEach(() => s.dispose());

const run = (command: string, tool = "Bash") => s.run({ session_id: "s", cwd: s.project, hook_event_name: "PreToolUse", tool_name: tool, tool_input: { command } });

/** Held on its verdict with the dependency_check call; answered proceed, it goes ahead. */
function heldThenReleased(command: string, item: Record<string, string>): void {
  const r = run(command);
  expect(r.decision, r.text).toBe("deny");
  expect(r.text).not.toContain("could not be read");
  expect(r.items).toEqual([item]);
  answerDenial(s, r, "proceed");
  expect(run(command).decision).toBe("allow");
}

describe("S1: name@<URL> is the URL", () => {
  const TGZ = "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz";
  it.each([`npm i lodash@${TGZ}`, `pnpm add lodash@${TGZ}`, `yarn add lodash@${TGZ}`, `bun add lodash@${TGZ}`])("%s", (command) => {
    heldThenReleased(command, { ecosystem: "npm", package: "lodash", to: "4.17.20" });
  });

  it.each(["pip install requests@https://files.pythonhosted.org/packages/source/r/requests/requests-2.5.0.tar.gz", "pip install 'requests @ https://files.pythonhosted.org/packages/source/r/requests/requests-2.5.0.tar.gz'"])("%s", (command) => {
    heldThenReleased(command, { ecosystem: "PyPI", package: "requests", to: "2.5.0" });
  });

  it("another form on a public host is held as not read; another host is its own source", () => {
    expect(run("npm i lodash@https://registry.npmjs.org/lodash").text).toContain("could not be read");
    expect(run("npm i lodash@https://npm.corp.example/lodash-4.17.20.tgz").decision).toBe("allow");
  });
});

describe("S2: a constraints or overrides file beside a named package", () => {
  it.each(["pip install requests -c c.txt", "uv pip install requests --overrides o.txt", "uv add requests --constraints c.txt", "pip install requests==2.32.3 --constraint c.txt"])("%s: held, name the version", (command) => {
    const r = run(command);
    expect(r.decision).toBe("deny");
    // Round 13: the remedy names the file option; removed, the named package is judged on its own.
    expect(followRemedy(command, r.text)).toBe(command.replace(/\s+(?:-c|--constraints?|--overrides?)\s+\S+/, ""));
  });

  it.each(["pip install -r requirements.txt -c constraints.txt", "uv pip install -r requirements.txt --overrides o.txt", "pip install -c constraints.txt -e ."])("%s: a file-driven install goes ahead", (command) => {
    expect(run(command).decision).toBe("allow");
  });
});

// Round 14 (R2): an index or registry option beside a named package goes ahead unjudged only when it
// is the one source option on the line and its host is positively not public. A public index named
// another way, and a Poetry source (a name, no host), are held as not read now (they were judged, or
// let through, in round 10).
// Round 16 (J3): one replacing source on a host not private by shape (or named by a config name) is judged.
describe("S3 (round 16): a source named by another name, or by a config name, is judged", () => {
  it.each([
    "poetry add --source pypi requests==2.5.0",
    "poetry add --source corp requests==2.5.0",
    "cargo install serde@1.0.0 --index https://github.com/rust-lang/crates.io-index",
    "cargo install serde@1.0.0 --index sparse+https://index.crates.io/",
  ])("%s", (command) => {
    const r = run(command);
    expect(r.text).not.toContain("could not be read");
    expect(r.decision).toBe("deny");
  });
});

describe("S4: poetry self add", () => {
  it("poetry self add urllib3==2.5.0 is judged", () => {
    heldThenReleased("poetry self add urllib3==2.5.0", { ecosystem: "PyPI", package: "urllib3", to: "2.5.0" });
  });
});

describe("S5: a ledger line naming a package that is not fully valid", () => {
  const at = new Date(Date.now() - 60_000).toISOString();
  const proceed = JSON.stringify({ t: at, ecosystem: "npm", package: "lodash", version: "4.17.21", verdict: "proceed" });
  it.each([
    ["a t that is not a date", JSON.stringify({ t: "soon", ecosystem: "npm", package: "lodash", version: "4.17.21", verdict: "avoid" })],
    ["a verdict that is not one of the five", JSON.stringify({ t: at, ecosystem: "npm", package: "lodash", version: "4.17.21", verdict: "Avoid" })],
    ["no version", JSON.stringify({ t: at, ecosystem: "npm", package: "lodash", verdict: "avoid" })],
  ])("%s after a proceed: held", (_label, bad) => {
    writeFileSync(join(s.home, "check-ledger.jsonl"), `${proceed}\n${bad}\n`);
    expect(run("npm i lodash@4.17.21").decision).toBe("deny");
  });
});

describe("S6: an extra index keeps the public index in play", () => {
  // Round 14 (R2): a public index named as such is no "project's own source": held as not read.
  it("pip install --extra-index-url https://pypi.corp.example/simple requests==2.5.0: held (PyPI stays in play beside an extra index)", () => {
    expect(run("pip install --extra-index-url https://pypi.corp.example/simple requests==2.5.0").text).toContain("could not be read");
  });
  it("pip install --find-links https://pypi.org/simple requests==2.5.0: held as not read", () => {
    expect(run("pip install --find-links https://pypi.org/simple requests==2.5.0").text).toContain("could not be read");
  });
  it("a private primary index is the project's own source", () => {
    expect(run("pip install -i https://pypi.corp.example/simple requests==2.5.0").decision).toBe("allow");
    expect(run("uv add --default-index https://pypi.corp.example/simple requests==2.5.0").decision).toBe("allow");
    // uv's --index adds to PyPI (round 14, R2): held.
    expect(run("uv add --index https://pypi.corp.example/simple requests==2.5.0").text).toContain("could not be read");
  });
});

/** L1: the header's limits, each tested as it is written: these go ahead. */
describe("L1: commands that let the manager choose versions go ahead (a stated limit)", () => {
  it.each(["npm audit fix", "npm audit fix --force", "pnpm audit --fix", "npm update", "pnpm up", "yarn upgrade", "bun update", "cargo update", "cargo upgrade", "poetry update", "uv tool upgrade ruff", "go mod tidy", "go get", "go get -u ./..."])("%s", (command) => {
    expect(run(command).decision).toBe("allow");
  });
  it("uv lock --upgrade is held", () => {
    expect(run("uv lock --upgrade").decision).toBe("deny");
  });
});

describe("L2, L3, L5: the other limits as written", () => {
  it("a requirements file written by the shell, then installed: goes ahead", () => {
    expect(run("echo requests==2.5.0 > r.txt && pip install -r r.txt").decision).toBe("allow");
  });
  it("a private index serving public packages: not judged", () => {
    expect(run("npm i --registry https://npm.mirror.corp.example lodash@4.17.20").decision).toBe("allow");
  });
  it("uv run --with pkg (fetch-and-run, decision pending): goes ahead", () => {
    expect(run("uv run --with requests==2.5.0 python -c 1").decision).toBe("allow");
  });
  it("L4: cd to the data folder's parent in the same call, then a write by a relative name: goes ahead (stated)", () => {
    expect(run("cd .. && echo x > notes.txt").decision).toBe("allow");
  });
});
