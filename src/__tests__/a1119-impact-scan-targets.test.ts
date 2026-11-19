// SPDX-License-Identifier: Apache-2.0
/**
 * Where a scan may be pointed: not at another machine, and not at a home directory.
 */

import { describe, expect, it } from "vitest";

import { networkPathProblem, resolveProjectScope, systemDirectoryProblem } from "../tools/project-scope.js";

const env = { SystemDrive: "C:", SystemRoot: "C:\\Windows", ProgramFiles: "C:\\Program Files", "ProgramFiles(x86)": "C:\\Program Files (x86)", ProgramData: "C:\\ProgramData", COMPUTERNAME: "DEVBOX", USERPROFILE: "C:\\Users\\dev" };
const win = { platform: "win32" as const, env };

describe("a path on another machine is refused from its text", () => {
  it("refuses a share on another host, in every spelling", () => {
    for (const d of ["\\\\server\\share\\repo", "\\\\server\\share\\", "//server/share/repo", "\\\\10.0.0.7\\c$\\src", "\\\\?\\UNC\\files.example\\team\\app", "\\\\server"]) {
      expect(networkPathProblem(d, win), d).toMatch(/is a network path on another machine, not a local project, so it is not opened/);
      expect(systemDirectoryProblem(d, win), d).toMatch(/is a network path on another machine/);
    }
  });

  it("does not treat this machine's own spellings as another machine", () => {
    for (const d of ["C:\\src\\app", "\\\\?\\D:\\4DA", "\\\\localhost\\share\\repo", "\\\\127.0.0.1\\C$\\src", "\\\\DEVBOX\\share\\repo", "\\\\devbox\\share\\repo", "\\\\wsl$\\Ubuntu\\home\\me\\app", "\\\\wsl.localhost\\Debian\\home\\me\\app", "relative\\path", "/home/me/app"]) {
      expect(networkPathProblem(d, win), d).toBeNull();
    }
  });

  it("is a Windows rule only: on POSIX two leading slashes name a local path", () => {
    expect(networkPathProblem("//server/share/repo", { platform: "linux", env: {} })).toBeNull();
  });

  it.runIf(process.platform === "win32")("project_path is refused before the path is opened", () => {
    // A host under a reserved TLD: were the path opened, the call would wait on a name lookup
    // and then report "not a directory". The refusal comes from the text, with its own reason.
    const scope = resolveProjectScope("\\\\files.invalid\\team\\app");
    expect(scope.kind).toBe("error");
    expect(scope.kind === "error" && scope.error).toMatch(/^project_path "\\\\files\.invalid\\team\\app" is a network path on another machine/);
  });
});

describe("a home directory is not a project", () => {
  it("refuses the user's home directory, and nothing below it", () => {
    expect(systemDirectoryProblem("C:\\Users\\dev", win)).toMatch(/^"C:\\Users\\dev" is your home directory, not a project, so it is not scanned/);
    expect(systemDirectoryProblem("c:\\users\\DEV\\", win)).toMatch(/is your home directory/);
    expect(systemDirectoryProblem("C:\\Users\\dev\\code\\app", win)).toBeNull();
    expect(systemDirectoryProblem("C:\\Users\\other", win)).toBeNull();
  });

  it("reads HOME on POSIX", () => {
    const posix = { platform: "linux" as const, env: { HOME: "/home/dev" } };
    expect(systemDirectoryProblem("/home/dev", posix)).toMatch(/is your home directory/);
    expect(systemDirectoryProblem("/home/dev/src/app", posix)).toBeNull();
  });

  it("with an explicit environment that names no home, guesses none", () => {
    expect(systemDirectoryProblem("C:\\Users\\dev", { platform: "win32", env: { SystemDrive: "C:" } })).toBeNull();
  });
});
