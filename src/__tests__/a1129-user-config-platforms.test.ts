// SPDX-License-Identifier: Apache-2.0
/**
 * Round 6, CI: a1128-confirm-review2's nP/p27 failed on Linux and macOS because its fixture wrote the Go env file
 * where only Windows reads it (`%APPDATA%\go\env`). The product side, once per kind of per-user configuration
 * file, on each platform: with `process.platform` stubbed to linux, darwin and win32 and the user's directories
 * in a temp profile, a private rule written where that platform's tool reads it is found. Nothing outside the
 * temp folders is read (the machine-wide locations point into it too).
 */
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { pipConfigFiles, pipConfigIndexes, PrivatePackageRules } from "../live/private-packages.js";
import { uvConfigFiles } from "../live/private-configs.js";
import { userConfigFile } from "./helpers/a1129-user-config.js";

let prof: string;
const realPlatform = process.platform;
const setPlatform = (p: NodeJS.Platform) => Object.defineProperty(process, "platform", { value: p, configurable: true });
beforeEach(() => {
  prof = fs.mkdtempSync(path.join(os.tmpdir(), "4da-a1129-ucfg-"));
});
afterEach(() => {
  setPlatform(realPlatform);
  fs.rmSync(prof, { recursive: true, force: true });
});

const envFor = (platform: NodeJS.Platform): NodeJS.ProcessEnv => ({
  HOME: prof,
  USERPROFILE: prof,
  ...(platform === "win32" ? { APPDATA: path.join(prof, "Roaming"), LOCALAPPDATA: path.join(prof, "Local") } : {}),
  ...(platform === "linux" ? { XDG_CONFIG_HOME: path.join(prof, ".config") } : {}),
  ProgramData: path.join(prof, "machine"),
  PROGRAMDATA: path.join(prof, "machine"),
  ALLUSERSPROFILE: path.join(prof, "machine"),
  XDG_CONFIG_DIRS: path.join(prof, "machine"),
  NPM_CONFIG_GLOBALCONFIG: path.join(prof, "machine", "npmrc"),
});

const KINDS: Array<{ kind: string; key: string; body: string; ecosystem: string; name: string }> = [
  { kind: "go env file (GOPRIVATE)", key: "Roaming/go/env", body: "GOPRIVATE=github.com/zqxcorp\n", ecosystem: "Go", name: "github.com/zqxcorp/lib" },
  { kind: "user pip config (index-url)", key: "Roaming/pip/pip.ini", body: "[global]\nindex-url = https://pypi.zqxcorp.internal/simple\n", ecosystem: "PyPI", name: "zqxsecretpy" },
  { kind: "user uv config (index-url)", key: "Roaming/uv/uv.toml", body: 'index-url = "https://pypi.zqxcorp.internal/simple"\n', ecosystem: "PyPI", name: "zqxsecretpy" },
  { kind: "user .npmrc (scope registry)", key: ".npmrc", body: "@zqxcorp:registry=https://npm.zqxcorp.internal/\n", ecosystem: "npm", name: "@zqxcorp/ui" },
];

/**
 * Where a stubbed platform can truly run. pip's and uv's user-file lists are built with that platform's own path
 * flavour (`path.win32` for win32: pipConfigFiles, uvConfigFiles), so on a POSIX host a stubbed win32 yields
 * `\tmp\...\Roaming\pip\pip.ini`, a path no POSIX filesystem opens: that branch runs only on Windows. The go
 * env file and the user .npmrc are joined with the host's own `path`, so every stub runs everywhere, and the linux
 * and darwin stubs of every kind run on Windows too (that is the cross-platform proof). The running platform's
 * own case always runs.
 */
const runsHere = (platform: NodeJS.Platform, key: string) => platform === realPlatform || platform !== "win32" || !/\/(?:pip|uv)\//.test(key);
const lookedFor = (key: string, env: NodeJS.ProcessEnv, platform: NodeJS.Platform) =>
  key.includes("/pip/") ? pipConfigFiles(env, platform) : key.includes("/uv/") ? uvConfigFiles(env, platform) : [];

describe("a per-user private rule is found where each platform's tool reads it", () => {
  for (const platform of ["linux", "darwin", "win32"] as const) {
    for (const k of KINDS) {
      it.skipIf(!runsHere(platform, k.key))(`${platform}: ${k.kind}`, () => {
        const { key, body, ecosystem, name } = k;
        setPlatform(platform);
        const env = envFor(platform);
        const file = userConfigFile(key, env, platform);
        fs.mkdirSync(path.dirname(file), { recursive: true });
        fs.writeFileSync(file, body);
        const rules = new PrivatePackageRules([], env);
        // A private index makes the whole ecosystem's new names private (pythonIndexFor); a scope or a module pattern
        // names its packages (reasonFor). pip's user files are read by the live layer's index check (pipConfigFiles):
        // the file must be on its list for the platform, and its index read.
        const pip = key.includes("/pip/") ? (pipConfigFiles(env, platform).some((f) => path.resolve(f) === path.resolve(file)) ? pipConfigIndexes(fs.readFileSync(file, "utf8")).index : null) : undefined;
        const found = pip !== undefined ? pip : ecosystem === "PyPI" ? rules.pythonIndexFor(null) : (rules.reasonFor(ecosystem, name) ?? (rules.registryRuleCovers(ecosystem, name) ? "covered" : null));
        expect(found, `${platform}: wrote ${file}; the reader looked for ${JSON.stringify(lookedFor(key, env, platform))}`).not.toBeNull();
      });
    }
  }
});
