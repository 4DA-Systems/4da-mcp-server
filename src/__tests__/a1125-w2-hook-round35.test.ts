// SPDX-License-Identifier: Apache-2.0
/**
 * Round 35 of the hook lane (sentence check 31): a negated value option is not read (C1, npm's nopt
 * gives it the next word); a cluster of short letters holding a letter that takes a value is not
 * read (C2, checked against pip's optparse over every 2- and 3-letter cluster); a requirements
 * comment ending in a backslash is not read and lines are joined as pip joins them (C3, checked
 * against pip's own reader over the variants in fixtures/a1125-pip-reqfiles.json, for commands and
 * edits); a go.mod edit that adds a toolchain line or raises the go line is held (C4). Fixtures:
 * scripts/gen-npm-option-spellings.cjs and scripts/gen-pip-clusters-and-reqfiles.py.
 */

import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { respond } from "../../hooks/manifest-edit.mjs";
// The hook's PATH lookups see a stub for each manager and runner word, whatever the machine (Windows).
import "./helpers/a1125-manager-stubs.js";

type Variant = { name: string; text: string; pip: { reqs?: string[]; index?: string | null; extra?: string[]; pre?: boolean; error?: string } };
const NPM = JSON.parse(readFileSync(join(__dirname, "fixtures", "a1125-npm-spellings.json"), "utf8")) as { npm: string; spellings: { opt: string; consumed: boolean }[] };
const CLUSTERS = JSON.parse(readFileSync(join(__dirname, "fixtures", "a1125-pip-clusters.json"), "utf8")) as {
  pip: string;
  letters: Record<string, boolean>;
  clusters: { word: string; ok: boolean; consumed: boolean | null }[];
};
const REQ = JSON.parse(readFileSync(join(__dirname, "fixtures", "a1125-pip-reqfiles.json"), "utf8")) as { pip: string; env: Record<string, string>; variants: Variant[] };

let home: string;
let project: string;
beforeAll(() => {
  home = mkdtempSync(join(tmpdir(), "a1125-r35-home-"));
  project = mkdtempSync(join(tmpdir(), "a1125-r35-proj-"));
  const t = new Date(Date.now() - 60_000).toISOString();
  const lines = [
    { ecosystem: "npm", package: "lodash", version: "4.17.20", verdict: "avoid", reason: "test avoid" },
    { ecosystem: "npm", package: "lodash", version: "4.17.21", verdict: "proceed" },
    { ecosystem: "PyPI", package: "requests", version: "2.19.0", verdict: "avoid", reason: "test avoid" },
    { ecosystem: "PyPI", package: "six", version: "1.16.0", verdict: "proceed" },
    { ecosystem: "PyPI", package: "x", version: "1", verdict: "proceed" },
  ];
  writeFileSync(join(home, "check-ledger.jsonl"), lines.map((l) => JSON.stringify({ t, sv: "6.6.0", ...l })).join("\n") + "\n");
  writeFileSync(join(project, "bad.txt"), "requests==2.19.0\n");
});
afterAll(() => {
  rmSync(home, { recursive: true, force: true });
  rmSync(project, { recursive: true, force: true });
});

const answer = (input: Record<string, unknown>, cwd = project) => {
  const out = respond({ hook_event_name: "PreToolUse", cwd, ...input }, { FOURDA_MCP_HOME: home, ...REQ.env }, Date.now());
  if (!out) return { d: "none", why: "" };
  const o = JSON.parse(out).hookSpecificOutput ?? {};
  return { d: (o.permissionDecision ?? "other") as string, why: String(o.permissionDecisionReason ?? "") };
};
const run = (command: string, cwd = project) => answer({ tool_name: "Bash", tool_input: { command } }, cwd);
const NOT_READ = "could not be read";
const JUDGED = /"requests" "==2\.19\.0" \(PyPI\): dependency_check answered avoid/;

describe(`C1: a negated option against npm ${NPM.npm}'s own parser (nopt)`, () => {
  const negated = NPM.spellings.filter((s) => s.opt.startsWith("--no-"));
  it("the fixture holds the 17 value options nopt gives the next word even when negated", () => {
    expect(negated.filter((s) => s.consumed).length).toBe(17);
  });
  it(`no negated spelling of ${negated.length} lets an install, a config write or a pkg write through`, () => {
    const wrong: string[] = [];
    for (const { opt, consumed } of negated) {
      const forms = consumed
        ? [`npm ${opt} x install lodash@4.17.20`, `npm ${opt} x config set registry=https://evil.example.cn/`, `npm ${opt} x pkg set dependencies.lodash=4.17.20`]
        : [`npm ${opt} install lodash@4.17.20`];
      for (const command of forms) if (run(command).d !== "deny") wrong.push(command);
      // A negated value option is not read at all (the word after it is its value).
      if (consumed && !run(`npm ${opt} x install lodash@4.17.21`).why.includes(NOT_READ)) wrong.push(`${opt}: not read`);
    }
    expect(wrong).toEqual([]);
  });
  it.each(["npm --no-cpu x install lodash@4.17.20", "npm --no-os x pkg set dependencies.lodash=4.17.20", "pnpm --no-registry x add lodash@4.17.20", "npm --no-bogus install lodash@4.17.21"])("%s: not read", (command) => {
    expect(run(command).why).toContain(NOT_READ);
  });
  it.each(["npm --no-audit install lodash@4.17.21", "npm --no-fund ci", "pnpm --no-frozen-lockfile install", "pnpm --no-optional install"])("%s: a negated switch is read", (command) => {
    expect(run(command).d).toBe("none");
  });
  it.each(["pip install --no-pre requests==2.19.0", "uv pip install --no-upgrade x==1", "cargo add --no-locked serde@1.0.0", "poetry add --no-lock x==1"])(
    "%s: a negation the manager does not document is not read",
    (command) => {
      expect(run(command).why).toContain(NOT_READ);
    },
  );
});

describe(`C2: every 2- and 3-letter cluster against pip ${CLUSTERS.pip}'s own parser (optparse)`, () => {
  it(`no cluster of ${CLUSTERS.clusters.length} lets the avoided release through, and a cluster holding a value letter is not read`, () => {
    const wrong: string[] = [];
    for (const { word, ok, consumed } of CLUSTERS.clusters) {
      if (!ok) continue;
      const valueLetter = [...word.slice(2)].some((l) => CLUSTERS.letters[l]);
      const command = consumed ? `pip install ${word} bad.txt requests==2.19.0` : `pip install ${word} requests==2.19.0`;
      const a = run(command);
      if (a.d !== "deny") wrong.push(`${command}: ${a.d}`);
      else if (valueLetter && !a.why.includes(NOT_READ)) wrong.push(`${command}: read`);
      // A cluster of switches only (as pip reads it): the requirement is judged (-V prints the version and stops).
      else if (!valueLetter && !CLUSTERS.letters[word[1]] && !word.includes("V") && !JUDGED.test(a.why)) wrong.push(`${command}: not judged`);
    }
    expect(wrong).toEqual([]);
  });
  it.each([
    "pip install -qr bad.txt",
    "pip install -Ur bad.txt",
    "pip install -vr bad.txt",
    "pip install -Ir bad.txt",
    "pip install -qrbad.txt",
    "pip download -qr bad.txt",
    "pip wheel -qr bad.txt",
    "uv pip install -qr bad.txt",
    "uv add -qr bad.txt",
    "uv sync -qP requests==2.19.0",
    "uv lock -qP requests==2.19.0",
    "uv pip install -qPrequests requests==2.19.0",
  ])("%s: not read", (command) => {
    expect(run(command).why).toContain(NOT_READ);
  });
  it.each(["pip install -rbad.txt", "pip install -r bad.txt", "uv pip install -rbad.txt", "uv add -rbad.txt"])("%s: an attached value is read by its option (the file is judged)", (command) => {
    expect(run(command).why).toMatch(JUDGED);
  });
  it.each(["pip install -qU six==1.16.0", "pip install -U -r ok.txt", "uv pip install -U six==1.16.0", "cargo build -vv", "pip install -qqU six==1.16.0", "uv pip install -qU six==1.16.0"])(
    "%s: an ordinary cluster goes ahead",
    (command) => {
      writeFileSync(join(project, "ok.txt"), "six==1.16.0\n");
      expect(run(command).d).toBe("none");
    },
  );
});

describe(`C3: requirements files against pip ${REQ.pip}'s own reader (${REQ.variants.length} variants)`, () => {
  // What pip reads that the hook must not let through: a requirement other than the proceed one,
  // an index, an extra index or --pre (`six==1.16.0;x`: what follows the semicolon is a marker).
  const risky = (v: Variant) => !v.pip.error && ((v.pip.reqs ?? []).some((r) => !/^six==1\.16\.0(?:;.*)?$/.test(r)) || !!v.pip.index || (v.pip.extra ?? []).length > 0 || !!v.pip.pre);
  it("the fixture holds the comment-and-backslash forms", () => {
    for (const name of ["comment-bs-lf", "comment-indent-bs-crlf", "trail-comment-bs-lf", "cont-then-comment-lf"]) expect(REQ.variants.some((v) => v.name === name), name).toBe(true);
  });
  it("a command that names the file: never goes ahead where pip reads a release that is not proceed", () => {
    const wrong: string[] = [];
    for (const v of REQ.variants) {
      const dir = join(project, `v-${v.name}`);
      mkdirSync(dir, { recursive: true });
      writeFileSync(join(dir, "r.txt"), v.text);
      writeFileSync(join(dir, "bad.txt"), "requests==2.19.0\n");
      for (const command of ["pip install -r r.txt", "uv pip install -r r.txt"]) {
        const a = run(command, dir);
        if (risky(v) && a.d !== "deny") wrong.push(`${v.name} ${command}: ${a.d}`);
      }
    }
    expect(wrong).toEqual([]);
  });
  it("an edit (Write) of requirements.txt: never goes ahead where pip reads a release that is not proceed", () => {
    const wrong: string[] = [];
    for (const v of REQ.variants) {
      const dir = join(project, `w-${v.name}`);
      mkdirSync(dir, { recursive: true });
      writeFileSync(join(dir, "bad.txt"), "requests==2.19.0\n");
      const a = answer({ tool_name: "Write", tool_input: { file_path: join(dir, "requirements.txt"), content: v.text } }, dir);
      if (risky(v) && a.d !== "deny") wrong.push(`${v.name}: ${a.d}`);
    }
    expect(wrong).toEqual([]);
  });
  it.each([
    ["# pinned below \\\nrequests==2.19.0\n", "a comment line"],
    ["   # note \\\r\nrequests==2.19.0\r\n", "an indented comment line"],
    ["six==1.16.0 # c \\\nrequests==2.19.0\n", "a comment at a line's end"],
  ])("%j (%s ending in a backslash): not read, as a command and as an edit", (text) => {
    writeFileSync(join(project, "c.txt"), text);
    expect(run("pip install -r c.txt").why).toContain("comment that ends in a backslash");
    expect(run("uv pip install -r c.txt").why).toContain("comment that ends in a backslash");
    expect(answer({ tool_name: "Write", tool_input: { file_path: join(project, "requirements.txt"), content: text } }).why).toContain("comment that ends in a backslash");
  });
  it("a continued requirement followed by a comment line is joined as pip joins it", () => {
    writeFileSync(join(project, "j.txt"), "six==1.16.0 \\\n# c\nrequests==2.19.0\n");
    expect(run("pip install -r j.txt").why).toMatch(JUDGED);
    writeFileSync(join(project, "k.txt"), "requ\\\nests==\\\n2.19.0\n");
    expect(run("pip install -r k.txt").why).toMatch(JUDGED);
  });
});

describe("C4: a go.mod edit that adds a toolchain line or raises the go line", () => {
  const dir = () => {
    const d = join(project, "gomod");
    mkdirSync(d, { recursive: true });
    return d;
  };
  const edit = (before: string, oldString: string, newString: string) => {
    const d = dir();
    const file = join(d, "go.mod");
    writeFileSync(file, before);
    return answer({ tool_name: "Edit", tool_input: { file_path: file, old_string: oldString, new_string: newString } }, d);
  };
  const BASE = "module example.com/m\n\ngo 1.21\n";
  it("adding a toolchain line is held", () => {
    expect(edit(BASE, "go 1.21\n", "go 1.21\n\ntoolchain go1.23.4\n").why).toContain("toolchain");
  });
  it("raising the go line is held", () => {
    expect(edit(BASE, "go 1.21", "go 1.23").why).toContain("go 1.23");
  });
  it("changing a toolchain line is held", () => {
    expect(edit(`${BASE}\ntoolchain go1.22.0\n`, "toolchain go1.22.0", "toolchain go1.23.4").d).toBe("deny");
  });
  it("lowering the go line, and an edit beside them, go ahead", () => {
    expect(edit("module example.com/m\n\ngo 1.23\n", "go 1.23", "go 1.21").d).toBe("none");
    expect(edit(`${BASE}\n// note\n`, "// note", "// other note").d).toBe("none");
  });
});
