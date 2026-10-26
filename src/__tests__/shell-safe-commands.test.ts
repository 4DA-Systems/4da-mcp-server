// SPDX-License-Identifier: Apache-2.0
/**
 * Audit 6.2.5 finding C-1: upgrade_planner spliced text from the scanned
 * project's own Cargo.toml into the command it tells an agent to run. A
 * `[target.'cfg(...)'.dependencies]` header went inside `--target "..."`, where
 * bash and PowerShell still expand substitutions, and a renamed dependency's
 * key went unquoted after `--rename`. A cloned repository controls both. A
 * command is now named only when every spliced value is a plain token; the
 * markers below are inert characters a shell reads specially, not payloads.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { directFix, goDirectCommand, manualRefreshSteps, npmDirectCommand, refreshCommand } from "../live/fix-paths.js";
import { isShellSafeCargoTarget, isShellSafeName, isShellSafeVersion } from "../live/shell-safe.js";

let dir: string;
beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), "4da-shell-safe-"));
});
afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

const cargoProject = (manifest: string) => fs.writeFileSync(path.join(dir, "Cargo.toml"), manifest);

describe("the validators", () => {
  it("accept real names, versions and targets", () => {
    for (const n of ["lodash", "@types/node", "serde_json", "Django", "zope.interface"]) expect(isShellSafeName(n, "npm")).toBe(true);
    expect(isShellSafeName("golang.org/x/net", "Go")).toBe(true);
    for (const v of ["1.2.3", "v0.33.0", "1.0.0-rc.1+build.5", "2.0.0b1", "0.0.2-security"]) expect(isShellSafeVersion(v)).toBe(true);
    for (const t of ["x86_64-pc-windows-msvc", "cfg(windows)", "cfg(not(unix))", "cfg(all(unix, target_pointer_width = 64))"]) {
      expect(isShellSafeCargoTarget(t)).toBe(true);
    }
  });

  it("refuse anything a shell reads specially", () => {
    for (const bad of ["a b", "a;b", "a$b", "a`b", 'a"b', "a'b", "a|b", "a&b", "a(b", "a\nb", "a%b", ""]) {
      expect(isShellSafeName(bad, "npm")).toBe(false);
      expect(isShellSafeVersion(bad)).toBe(false);
      expect(isShellSafeCargoTarget(`cfg(${bad})`) && /[$`"';|&%\n]/.test(bad)).toBe(false);
    }
    // A cfg string literal cannot sit inside double quotes on any shell.
    expect(isShellSafeCargoTarget('cfg(target_os = "linux")')).toBe(false);
  });
});

describe("cargo add from a project's own Cargo.toml", () => {
  it("a plain cfg target is still named", () => {
    cargoProject(`[package]\nname = "x"\nversion = "0.1.0"\n\n[target.'cfg(windows)'.dependencies]\nsmallvec = "=0.6.9"\n`);
    expect(directFix(dir, "crates.io", "smallvec", "0.6.9", "0.6.14")).toEqual({ command: 'cargo add "smallvec@=0.6.14" --target "cfg(windows)"' });
  });

  it("a target header holding a shell metacharacter gets words, never a command", () => {
    cargoProject(`[package]\nname = "x"\nversion = "0.1.0"\n\n[target.'cfg(unix) $marker'.dependencies]\nsmallvec = "=0.6.9"\n`);
    const fix = directFix(dir, "crates.io", "smallvec", "0.6.9", "0.6.14");
    expect((fix as { command?: string } | null)?.command).toBeUndefined();
    expect(JSON.stringify(fix)).not.toContain("$marker");
  });

  it("a cfg with a string literal gets words (its quotes broke the command anyway)", () => {
    cargoProject(`[package]\nname = "x"\nversion = "0.1.0"\n\n[target.'cfg(target_os = "linux")'.dependencies]\nsmallvec = "=0.6.9"\n`);
    expect((directFix(dir, "crates.io", "smallvec", "0.6.9", "0.6.14") as { command?: string } | null)?.command).toBeUndefined();
  });

  it("a renamed key holding a metacharacter gets words, never --rename", () => {
    cargoProject(`[package]\nname = "x"\nversion = "0.1.0"\n\n[dependencies]\n"sv;marker" = { package = "smallvec", version = "=0.6.9" }\n`);
    const fix = directFix(dir, "crates.io", "smallvec", "0.6.9", "0.6.14");
    expect((fix as { command?: string } | null)?.command).toBeUndefined();
    expect(JSON.stringify(fix)).not.toContain("marker");
  });
});

describe("the other command builders", () => {
  it("name no command for a name or version a shell reads specially", () => {
    expect(refreshCommand("package-lock", "left-pad;x", "1.0.0", "1.0.1")).toBeNull();
    expect(refreshCommand("cargo", "itoa", "1.0.5$x", "1.0.11")).toBeNull();
    expect(npmDirectCommand("npm", "1.0.0", "left`pad", "1.0.1")).toBeNull();
    expect(goDirectCommand("module x\n\nrequire golang.org/x/net v0.20.0\n", "golang.org/x/net", "0.20.0", "0.33.0 && x")).toBeNull();
    expect(manualRefreshSteps("yarn", 'a"b')).not.toContain('a"b');
  });

  it("still name them for ordinary values", () => {
    expect(refreshCommand("package-lock", "left-pad", "1.0.0", "1.0.1")).toBe("npm update left-pad");
    expect(npmDirectCommand("npm", "1.0.0", "@scope/pkg", "1.0.1")).toBe("npm install @scope/pkg@1.0.1 --save-exact");
    expect(goDirectCommand("module x\n\nrequire golang.org/x/net v0.20.0\n", "golang.org/x/net", "0.20.0", "0.33.0")).toBe("go get golang.org/x/net@v0.33.0");
  });
});
