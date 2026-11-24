// SPDX-License-Identifier: Apache-2.0
/**
 * A private answer from a server started at a drive root, in an operating-system folder or in the
 * home folder counts nowhere.
 *
 * Independent re-check of 0d30b40 (S5): such a server recorded that folder as `project`, so its
 * private answers unlocked every folder below it (`project: "C:\\"` let installs through anywhere
 * on C:). The server already refuses to scan those folders (tools/project-scope.ts
 * systemDirectoryProblem); now it records no project there, and the hook refuses an entry whose
 * project is one, by the same rule (a filesystem or drive root, `/mnt/<letter>`, Windows' own
 * folders, the Program Files, ProgramData and Users roots and the shared profiles, the POSIX system
 * folders, the home folder). A project one level below a drive root (`D:\\work`) is a project.
 *
 * The working folder is also compared in the forms Git Bash and WSL write a Windows path in
 * (`/c/...`, `/mnt/c/...`) and as a long path (`\\?\C:\...`).
 */

import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join, parse } from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { respond } from "../../hooks/manifest-edit.mjs";
import { answeredFor, LEDGER_FILE } from "../check-ledger.js";

let home: string;
let project: string;
beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "a651-broad-home-"));
  project = mkdtempSync(join(tmpdir(), "a651-broad-proj-"));
});
afterEach(() => {
  rmSync(home, { recursive: true, force: true });
  rmSync(project, { recursive: true, force: true });
});

const NOW = Date.now();
function privateFor(projectFolder: string) {
  writeFileSync(join(home, LEDGER_FILE), JSON.stringify({ t: new Date(NOW - 60_000).toISOString(), ecosystem: "npm", package: "lodash", version: "4.17.20", verdict: "unknown", not_checked: "local_source", project: projectFolder }) + "\n");
}
const decide = (cwd: string) => (respond({ hook_event_name: "PreToolUse", tool_name: "Bash", cwd, tool_input: { command: "npm i lodash@3.10.1" } }, { FOURDA_MCP_HOME: home, USERPROFILE: process.env.USERPROFILE, HOME: process.env.HOME }, NOW) === "" ? "allow" : "deny");

describe("the hook: an entry whose project is a root, a system folder or the home folder unlocks nothing", () => {
  it("a drive or filesystem root", () => {
    const root = parse(project).root;
    privateFor(root);
    expect(decide(project)).toBe("deny");
  });

  it("the home folder", () => {
    privateFor(homedir());
    expect(decide(join(homedir(), "some-project"))).toBe("deny");
  });

  it.runIf(process.platform === "win32")("C:\\Users, C:\\Program Files, the Windows folder", () => {
    for (const folder of ["C:\\Users", "C:\\Program Files", "C:\\Windows\\System32", "C:\\ProgramData"]) {
      privateFor(folder);
      expect(decide(`${folder}\\x`), folder).toBe("deny");
    }
  });

  it("an ordinary project, one level below a drive root or deeper, still unlocks its own folder", () => {
    privateFor(project);
    expect(decide(project)).toBe("allow");
  });

  it.runIf(process.platform === "win32")("the working folder in Git Bash, WSL and long-path forms matches the Windows-form project", () => {
    privateFor(project);
    const m = /^([A-Za-z]):\\(.*)$/.exec(project)!;
    const rest = m[2].replace(/\\/g, "/");
    expect(decide(`/${m[1].toLowerCase()}/${rest}`)).toBe("allow");
    expect(decide(`/mnt/${m[1].toLowerCase()}/${rest}`)).toBe("allow");
    expect(decide(`\\\\?\\${project}`)).toBe("allow");
  });
});

describe("the server: no project is recorded for such a folder", () => {
  it("a root, the home folder: null; a project folder: itself", () => {
    expect(answeredFor(parse(project).root)).toBeNull();
    expect(answeredFor(homedir())).toBeNull();
    expect(answeredFor(project)).toBe(project);
  });

  it.runIf(process.platform === "win32")("Windows system folders: null", () => {
    for (const folder of ["C:\\Windows\\System32", "C:\\Users", "C:\\Program Files"]) expect(answeredFor(folder), folder).toBeNull();
  });
});
