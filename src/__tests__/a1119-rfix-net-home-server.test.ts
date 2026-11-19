// SPDX-License-Identifier: Apache-2.0
/**
 * A server started in the user's home directory is not started in a project: the home directory
 * holds every project the user has, and scanning it as one would send every dependency name under
 * it to OSV.dev and the registries. It scans nothing at startup, and a tool called without
 * project_path says why and asks for one.
 */

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { serverDirectoryRefusal, systemDirectoryProblem } from "../tools/project-scope.js";
import { resultText, serverEntry, stdioSession } from "./helpers/stdio-session.js";

const made: string[] = [];
afterEach(() => {
  for (const d of made.splice(0)) fs.rmSync(d, { recursive: true, force: true });
});

/** A home directory with one ordinary project below it. */
function homeWithProject(): string {
  const home = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "a1119-rfix-net-home-")));
  made.push(home);
  const project = path.join(home, "code", "app");
  fs.mkdirSync(project, { recursive: true });
  fs.writeFileSync(path.join(project, "package.json"), JSON.stringify({ name: "app", dependencies: { lodash: "4.17.20" } }));
  fs.writeFileSync(
    path.join(project, "package-lock.json"),
    JSON.stringify({ name: "app", lockfileVersion: 3, packages: { "": { name: "app", dependencies: { lodash: "4.17.20" } }, "node_modules/lodash": { version: "4.17.20" } } }),
  );
  return home;
}

describe("the server's own directory is the home directory", () => {
  it("the refusal names the server's directory as the home directory and asks for project_path", () => {
    const env = { USERPROFILE: "C:\\Users\\dev", SystemRoot: "C:\\Windows" };
    const refused = systemDirectoryProblem("C:\\Users\\dev", { platform: "win32", env });
    expect(refused).not.toBeNull();
    expect(serverDirectoryRefusal(refused!)).toMatch(
      /^The server's directory "C:\\Users\\dev" is your home directory, not a project, so it is not scanned: .* Pass project_path with the absolute path of your project's root/,
    );
  });

  it.skipIf(!fs.existsSync(serverEntry))("a server started there scans nothing at startup, and vulnerability_scan without project_path refuses", async () => {
    const home = homeWithProject();
    const { results, stderr, fetches } = await stdioSession(home, [["vulnerability_scan", {}]], { HOME: home, USERPROFILE: home });
    expect(stderr).toMatch(/\[4DA\] ".*" is your home directory, not a project, so it is not scanned/);
    expect(results[0].isError).toBe(true);
    const text = resultText(results[0]);
    expect(text).toMatch(/The server's directory \\?".*\\?" is your home directory, not a project, so it is not scanned/);
    expect(text).toContain("Pass project_path");
    expect(text).not.toContain("lodash");
    expect(fetches).toEqual([]);
  }, 120_000);
});
