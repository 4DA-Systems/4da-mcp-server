// SPDX-License-Identifier: Apache-2.0
/**
 * A private answer lets a version through only in the project it was given for.
 *
 * The 6.5.1 candidate's hook allowed every version of a name, in every project, for 24 hours, once
 * any ledger entry for that name said `not_checked: "private"` (blind review 2026-11-24, item 1):
 * (a) project A declares lodash from git (`lodash/lodash#4.17.20`), dependency_check answers it
 * private, and `npm i lodash@3.10.1` then went ahead in any other project; (b) beside an unreadable
 * package-lock.json the server withholds lodash as "possibly private" and the hook let
 * `npm i lodash@4.17.20` through; (c) a private entry 2 hours old followed by an `avoid` for the
 * exact version 1 minute old still allowed it.
 *
 * Now each entry records the project folder the answer was given for (check-ledger.ts), a name
 * withheld because a lockfile could not be read is recorded as `unreadable_lockfile` and holds,
 * a private entry with no project (a server before 6.5.1) lets nothing through, a command that
 * changes folder or installs globally is not "in" any project, and a verdict for the exact version
 * beats a private entry.
 */

import { spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { LEDGER_FILE, ledgerEntries, recordVerdicts, type LedgerEntry } from "../check-ledger.js";
import { FourDADatabase } from "../db.js";
import { LiveIntelligence } from "../live/index.js";
import { clearLiveIntelligence, setLiveIntelligence } from "../live-singleton.js";
import { scanProjectTree, treeResolutionGroups } from "../project-tree.js";
import { dispatchTool } from "../tool-dispatch.js";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const HOOK = path.join(root, "hooks", "manifest-edit.mjs");
const MIN = 60_000;
const HOUR = 60 * MIN;

let scratch: string;
let home: string;
let projectA: string;
let projectB: string;
const savedEnv = new Map<string, string | undefined>();
const setEnv = (key: string, value: string | undefined) => {
  if (!savedEnv.has(key)) savedEnv.set(key, process.env[key]);
  if (value === undefined) delete process.env[key];
  else process.env[key] = value;
};

beforeEach(() => {
  scratch = fs.mkdtempSync(path.join(os.tmpdir(), "a651-private-scope-"));
  home = path.join(scratch, "home");
  projectA = path.join(scratch, "a");
  projectB = path.join(scratch, "b");
  for (const d of [home, projectA, projectB]) fs.mkdirSync(d, { recursive: true });
  fs.writeFileSync(path.join(home, LEDGER_FILE), "");
});
afterEach(() => {
  vi.unstubAllGlobals();
  clearLiveIntelligence();
  for (const [key, value] of savedEnv) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
  savedEnv.clear();
  try {
    fs.rmSync(scratch, { recursive: true, force: true });
  } catch {
    // Windows: left for the OS temp cleaner.
  }
});

function hook(payload: unknown): { status: number | null; stdout: string } {
  const env: Record<string, string | undefined> = { ...process.env, FOURDA_MCP_HOME: home };
  delete env.FOURDA_GUARD;
  const res = spawnSync(process.execPath, [HOOK], { input: JSON.stringify(payload), encoding: "utf8", timeout: 20_000, env });
  return { status: res.status, stdout: res.stdout };
}
const pre = (cwd: string, tool_name: string, tool_input: Record<string, unknown>) => ({ session_id: "s", transcript_path: "t", cwd, hook_event_name: "PreToolUse", tool_name, tool_input });
const bash = (cwd: string, command: string) => pre(cwd, "Bash", { command, description: "install" });

function decisionOf(out: { status: number | null; stdout: string }): string {
  expect(out.status).toBe(0);
  if (out.stdout === "") return "allow";
  const parsed = JSON.parse(out.stdout) as { hookSpecificOutput: { permissionDecision: string; permissionDecisionReason: string } };
  return parsed.hookSpecificOutput.permissionDecision === "deny" ? `deny: ${parsed.hookSpecificOutput.permissionDecisionReason}` : "other";
}
const allows = (payload: unknown) => expect(decisionOf(hook(payload))).toBe("allow");
const denies = (payload: unknown): string => {
  const d = decisionOf(hook(payload));
  expect(d.startsWith("deny: "), d).toBe(true);
  return d.slice(6);
};

function ledger(entries: Array<Partial<LedgerEntry> & { package: string; version: string; verdict: string; ageMs?: number }>) {
  fs.writeFileSync(
    path.join(home, LEDGER_FILE),
    entries.map(({ ageMs = MIN, ...e }) => JSON.stringify({ t: new Date(Date.now() - ageMs).toISOString(), ecosystem: "npm", ...e })).join("\n") + "\n",
  );
}
const privateIn = (project: string | undefined, extra: Partial<LedgerEntry> = {}) => ({
  package: "lodash",
  version: "4.17.20",
  verdict: "unknown",
  not_checked: "private",
  reason: "NOT CHECKED (private): lodash is a private package (package.json installs it from git: lodash/lodash#4.17.20).",
  ...(project ? { project } : {}),
  ...extra,
});

describe("the hook: a private answer counts only in its own project", () => {
  it("(a) a private answer for project A does not let another project install any version of the name", () => {
    ledger([privateIn(projectA)]);
    const reason = denies(bash(projectB, "npm i lodash@3.10.1"));
    expect(reason).toContain("private");
    expect(reason).toContain(JSON.stringify(projectA));
  });

  it("in project A, and in a folder inside it, the private answer lets the version through; in A's parent it does not", () => {
    ledger([privateIn(projectA)]);
    allows(bash(projectA, "npm i lodash@3.10.1"));
    const inner = path.join(projectA, "packages", "web");
    fs.mkdirSync(inner, { recursive: true });
    allows(bash(inner, "npm i lodash@3.10.1"));
    denies(bash(scratch, "npm i lodash@3.10.1"));
  });

  it("a folder that only starts with A's name is not inside A", () => {
    ledger([privateIn(projectA)]);
    const sibling = `${projectA}-other`;
    fs.mkdirSync(sibling, { recursive: true });
    denies(bash(sibling, "npm i lodash@3.10.1"));
  });

  it("an edit of a manifest in project A goes ahead; the same edit in project B is held", () => {
    ledger([privateIn(projectA)]);
    for (const [dir, expectAllow] of [
      [projectA, true],
      [projectB, false],
    ] as const) {
      const file = path.join(dir, "package.json");
      fs.writeFileSync(file, '{\n  "dependencies": {\n    "lodash": "4.17.21"\n  }\n}\n');
      const payload = pre(projectA, "Edit", { file_path: file, old_string: '"lodash": "4.17.21"', new_string: '"lodash": "3.10.1"', replace_all: false });
      if (expectAllow) allows(payload);
      else denies(payload);
    }
  });

  it("a command that changes folder or installs globally is not in project A", () => {
    ledger([privateIn(projectA)]);
    for (const command of [
      `cd ${projectB.replace(/\\/g, "/")} && npm i lodash@3.10.1`,
      "pushd ../b && npm i lodash@3.10.1",
      "npm --prefix ../b i lodash@3.10.1",
      "npm i -g lodash@3.10.1",
      "npm install --global lodash@3.10.1",
      "pnpm -C ../b add lodash@3.10.1",
    ]) {
      expect(decisionOf(hook(bash(projectA, command))).startsWith("deny: "), command).toBe(true);
    }
    expect(decisionOf(hook(pre(projectA, "PowerShell", { command: "Set-Location ..\\b; npm i lodash@3.10.1" }))).startsWith("deny: ")).toBe(true);
  });

  it("an old-format private entry (no project: a server before 6.5.1) lets nothing through, and says why", () => {
    ledger([privateIn(undefined)]);
    const reason = denies(bash(projectA, "npm i lodash@3.10.1"));
    expect(reason).toMatch(/does not record the project/);
  });

  it("(b) a name withheld because a lockfile could not be read holds, with the repair named", () => {
    ledger([
      {
        package: "lodash",
        version: "4.17.20",
        verdict: "unknown",
        not_checked: "unreadable_lockfile",
        unreadable_file: path.join(projectA, "package-lock.json"),
        project: projectA,
        reason: "NOT CHECKED (unreadable lockfile): package-lock.json could not be read.",
      },
    ]);
    const reason = denies(bash(projectA, "npm i lodash@4.17.20"));
    expect(reason).toMatch(/could not be read/);
    expect(reason).toMatch(/[Rr]epair or regenerate/);
    expect(reason).toContain(JSON.stringify(path.join(projectA, "package-lock.json")));
  });

  it("a 6.5.0 server's unreadable-lockfile entry (private with unreadable_file) holds as well", () => {
    ledger([privateIn(projectA, { unreadable_file: path.join(projectA, "package-lock.json") })]);
    expect(denies(bash(projectA, "npm i lodash@4.17.20"))).toMatch(/[Rr]epair or regenerate/);
  });

  it("(c) an avoid for the exact version holds over a private entry, older or newer", () => {
    ledger([{ ...privateIn(projectA), ageMs: 2 * HOUR }, { package: "lodash", version: "4.17.20", verdict: "avoid", reason: "GHSA-35jh-r3h4-6jhm", ageMs: MIN, project: projectA }]);
    expect(denies(bash(projectA, "npm i lodash@4.17.20"))).toContain("GHSA-35jh-r3h4-6jhm");
    ledger([{ package: "lodash", version: "4.17.20", verdict: "avoid", reason: "GHSA-35jh-r3h4-6jhm", ageMs: 2 * HOUR, project: projectA }, { ...privateIn(projectA), ageMs: MIN }]);
    expect(denies(bash(projectA, "npm i lodash@4.17.20"))).toContain("GHSA-35jh-r3h4-6jhm");
  });

  it("an unknown answer that is not private, newer than the private one, holds (the server no longer calls it private)", () => {
    ledger([{ ...privateIn(projectA), ageMs: 2 * HOUR }, { package: "lodash", version: "4.17.20", verdict: "unknown", reason: "NOT CHECKED (time budget)", not_checked: "time_budget", project: projectA }]);
    denies(bash(projectA, "npm i lodash@4.17.20"));
  });
});

describe("the server: each ledger entry records the project it answered for", () => {
  it("ledgerEntries: project kept; a name withheld for an unreadable file is unreadable_lockfile, not private", () => {
    const entries = ledgerEntries(
      [
        { ecosystem: "npm", package: "a", to: "1.0.0", verdict: "unknown", not_checked: "private" },
        { ecosystem: "npm", package: "b", to: "1.0.0", verdict: "unknown", not_checked: "private", unreadable_file: "/p/package-lock.json" },
        { ecosystem: "npm", package: "c", to: "1.0.0", verdict: "proceed" },
      ],
      new Date(),
      "/p",
    );
    expect(entries.map((e) => [e.not_checked, e.project, e.unreadable_file])).toEqual([
      ["private", "/p", undefined],
      ["unreadable_lockfile", "/p", "/p/package-lock.json"],
      [undefined, "/p", undefined],
    ]);
  });

  it("a project folder with a control character in it is not recorded (the entry then unlocks nothing)", () => {
    const [e] = ledgerEntries([{ ecosystem: "npm", package: "a", to: "1.0.0", verdict: "unknown", not_checked: "private" }], new Date(), "/p\nq");
    expect(e.project).toBeUndefined();
  });

  describe("end to end through dependency_check (offline-stubbed: nothing leaves the process)", () => {
    beforeEach(() => {
      const userHome = path.join(scratch, "user");
      fs.mkdirSync(userHome, { recursive: true });
      setEnv("FOURDA_MCP_HOME", home);
      setEnv("FOURDA_OFFLINE", undefined);
      setEnv("HOME", userHome);
      setEnv("USERPROFILE", userHome);
      setEnv("APPDATA", path.join(userHome, "AppData", "Roaming"));
      setEnv("LOCALAPPDATA", path.join(userHome, "AppData", "Local"));
      setEnv("XDG_CONFIG_HOME", undefined);
      setEnv("XDG_CONFIG_DIRS", path.join(userHome, "xdg-none"));
      setEnv("ProgramData", path.join(userHome, "ProgramData"));
      setEnv("NPM_CONFIG_USERCONFIG", path.join(userHome, ".npmrc"));
      setEnv("NPM_CONFIG_GLOBALCONFIG", path.join(userHome, "global-npmrc"));
      setEnv("NPM_CONFIG_REGISTRY", undefined);
      setEnv("FOURDA_PUBLIC_MIRRORS", undefined);
      setEnv("FOURDA_PRIVATE_PACKAGES", undefined);
      vi.stubGlobal(
        "fetch",
        vi.fn(async () => new Response(JSON.stringify({ error: "Not found" }), { status: 404, headers: { "content-type": "application/json" } })),
      );
    });

    async function answerIn(project: string, files: Record<string, string>): Promise<LedgerEntry[]> {
      for (const [file, content] of Object.entries(files)) fs.writeFileSync(path.join(project, file), content);
      const live = new LiveIntelligence(null);
      const { entries, discovery } = scanProjectTree(project);
      live.initFromProjectTree(project, treeResolutionGroups(entries), discovery);
      setLiveIntelligence(live);
      const db = new FourDADatabase(path.join(scratch, `db-${Math.random().toString(36).slice(2)}.db`));
      try {
        await dispatchTool("dependency_check", db, { items: [{ ecosystem: "npm", package: "lodash", to: "4.17.20" }] });
      } finally {
        db.close();
      }
      await recordVerdicts([]);
      return fs
        .readFileSync(path.join(home, LEDGER_FILE), "utf8")
        .split("\n")
        .filter(Boolean)
        .map((l) => JSON.parse(l) as LedgerEntry);
    }

    it("a git shorthand dependency: private, for project A; the hook then allows in A and holds in B", async () => {
      const entries = await answerIn(projectA, { "package.json": JSON.stringify({ name: "a", version: "1.0.0", dependencies: { lodash: "lodash/lodash#4.17.20" } }) });
      expect(entries.at(-1)).toMatchObject({ package: "lodash", not_checked: "private", project: path.resolve(projectA) });
      allows(bash(projectA, "npm i lodash@3.10.1"));
      denies(bash(projectB, "npm i lodash@3.10.1"));
    });

    it("an unreadable package-lock.json: recorded as unreadable_lockfile, and the hook holds the install in the same project", async () => {
      const entries = await answerIn(projectA, {
        "package.json": JSON.stringify({ name: "a", version: "1.0.0", dependencies: { lodash: "^4.17.0" } }),
        "package-lock.json": '{"name":"a","lockfileVersion":3,"packages":{"":{',
      });
      expect(entries.at(-1)).toMatchObject({ package: "lodash", not_checked: "unreadable_lockfile", project: path.resolve(projectA) });
      expect(entries.at(-1)!.unreadable_file).toMatch(/package-lock\.json$/);
      expect(denies(bash(projectA, "npm i lodash@4.17.20"))).toMatch(/[Rr]epair or regenerate/);
    });
  });
});
