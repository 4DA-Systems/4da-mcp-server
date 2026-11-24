// SPDX-License-Identifier: Apache-2.0
/**
 * `--setup` writes the version it runs as, leaves an entry the user changed alone unless asked,
 * never rewrites a file it cannot read exactly, and tells a script when a config was not written.
 *
 * Every run here resolves its paths from a temp home (injected context for the in-process runs,
 * overridden home variables for the spawned bin): nothing reads or writes this machine's editors.
 */
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync, chmodSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { parseCliArgs, parseSetupArgs } from "../cli-args.js";
import {
  CLAUDE_CODE_COMMAND,
  PACKAGE_VERSION,
  SETUP_USAGE,
  editorTargets,
  planConfig,
  runSetup,
  runSetupCli,
  writeConfigAtomic,
  type SetupContext,
} from "../setup.js";
import { serverEntry } from "./helpers/stdio-session.js";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const VERSION = JSON.parse(readFileSync(path.join(root, "package.json"), "utf8")).version as string;
const PINNED = `@4da/mcp-server@${VERSION}`;
/** npx's own options before the pinned package (setup.ts NPX_OPTIONS). */
const NPX = ["-y", "--prefer-offline"];
const ENTRY = { command: "npx", args: [...NPX, PINNED] };
const VSCODE_ENTRY = { type: "stdio", ...ENTRY };

/** Entries a user wrote by hand, each a different way of running the server. */
const USER_ENTRIES: Array<[string, Record<string, unknown>]> = [
  ["another pin, with -y", { command: "npx", args: ["-y", "@4da/mcp-server@6.2.7"] }],
  ["a local build", { command: "node", args: ["C:/dev/4da-mcp-server/dist/index.js"] }],
  ["a cmd /c npx wrapper", { command: "cmd", args: ["/c", "npx", "-y", "@4da/mcp-server@6.2.7"] }],
  ["an unpinned command", { command: "npx", args: ["@4da/mcp-server"] }],
];

describe("the command setup writes", () => {
  it("pins the running package's version, read from package.json", () => {
    expect(PACKAGE_VERSION).toBe(VERSION);
    for (const platform of ["win32", "darwin", "linux"] as const) {
      const home = platform === "win32" ? "C:\\Users\\u" : "/home/u";
      for (const target of editorTargets({ platform, env: {}, home })) {
        expect(target.entry.command, target.name).toBe("npx");
        expect(target.entry.args, target.name).toEqual([...NPX, PINNED]);
      }
    }
    expect(CLAUDE_CODE_COMMAND).toBe(`claude mcp add --scope user 4da -- npx -y --prefer-offline ${PINNED}`);
  });

  it("pins whatever version it is given, and writes nothing when the version is unknown", () => {
    const home = mkdtempSync(path.join(tmpdir(), "4da-setup-a1119-"));
    try {
      const ctx: SetupContext = { platform: process.platform, env: { APPDATA: path.join(home, "Roaming"), XDG_CONFIG_HOME: path.join(home, ".config") }, home };
      mkdirSync(path.join(home, ".cursor"));
      const lines: string[] = [];
      const unknown = runSetup({ version: null }, ctx, (line) => lines.push(line));
      expect(unknown.exitCode).toBe(1);
      expect(readdirSync(path.join(home, ".cursor"))).toEqual([]);
      expect(lines.join("\n")).toMatch(/version could not be read/);
      expect(lines.join("\n")).not.toMatch(/Restart your editor/);

      const pinned = runSetup({ version: "9.8.7" }, ctx, () => {});
      expect(pinned.exitCode).toBe(0);
      expect(JSON.parse(readFileSync(path.join(home, ".cursor", "mcp.json"), "utf8")).mcpServers["4da"].args).toEqual([...NPX, "@4da/mcp-server@9.8.7"]);
    } finally {
      rmSync(home, { recursive: true, force: true });
    }
  });
});

describe("planConfig: an existing 4da entry", () => {
  it.each(USER_ENTRIES)("%s is kept, with its other fields, unless update is asked", (_label, theirs) => {
    const existing = JSON.stringify({ mcpServers: { "4da": { ...theirs, env: { FOURDA_OFFLINE: "1" }, disabled: false } } }, null, 2);
    const kept = planConfig(existing, "mcpServers", ENTRY);
    expect(kept.action).toBe("keep");
    expect(kept.content).toBeUndefined();
    expect(kept.previous).toEqual(theirs);

    const replaced = planConfig(existing, "mcpServers", ENTRY, { update: true });
    expect(replaced.action).toBe("replace");
    expect(replaced.previous).toEqual(theirs);
    expect(JSON.parse(replaced.content!).mcpServers["4da"]).toEqual({ ...ENTRY, env: { FOURDA_OFFLINE: "1" }, disabled: false });
  });

  it("keeps the comment and the pin beside it in a JSONC entry", () => {
    const existing = [
      "{",
      '  "mcpServers": {',
      '    "4da": {',
      "      // pinned on purpose: reviewed 6.2.7",
      '      "command": "npx",',
      '      "args": ["-y", "@4da/mcp-server@6.2.7"], // do not float',
      '      "env": { "FOURDA_OFFLINE": "1" }',
      "    }",
      "  }",
      "}",
      "",
    ].join("\n");
    expect(planConfig(existing, "mcpServers", ENTRY).action).toBe("keep");
    const replaced = planConfig(existing, "mcpServers", ENTRY, { update: true });
    expect(replaced.content).toContain("// pinned on purpose: reviewed 6.2.7");
    expect(replaced.content).toContain(PINNED);
    expect(replaced.content).not.toContain("@4da/mcp-server@6.2.7");
    expect(replaced.content).toContain('"FOURDA_OFFLINE": "1"');
  });

  it("an entry that already is what setup writes is unchanged, with or without update", () => {
    const existing = JSON.stringify({ servers: { "4da": { ...VSCODE_ENTRY, env: { A: "1" } } } }, null, 2);
    expect(planConfig(existing, "servers", VSCODE_ENTRY)).toEqual({ action: "unchanged" });
    expect(planConfig(existing, "servers", VSCODE_ENTRY, { update: true })).toEqual({ action: "unchanged" });
  });
});

describe("planConfig: files it must not guess about", () => {
  it("accepts a UTF-8 BOM and keeps it", () => {
    const existing = `\uFEFF${JSON.stringify({ mcpServers: { other: { command: "x" } } }, null, 2)}\n`;
    const plan = planConfig(existing, "mcpServers", ENTRY);
    expect(plan.action).toBe("update");
    expect(plan.content!.startsWith("\uFEFF{")).toBe(true);
    expect(JSON.parse(plan.content!.slice(1))).toEqual({ mcpServers: { other: { command: "x" }, "4da": ENTRY } });
    // A file that is only a BOM is an empty file with a BOM.
    const empty = planConfig("\uFEFF", "mcpServers", ENTRY);
    expect(empty.action).toBe("update");
    expect(empty.content!.startsWith("\uFEFF{")).toBe(true);
  });

  it("refuses a duplicate servers key: an editor reads only one of them", () => {
    const existing = '{\n  "mcpServers": { "first": { "command": "a" } },\n  "mcpServers": { "second": { "command": "b" } }\n}\n';
    const plan = planConfig(existing, "mcpServers", ENTRY);
    expect(plan.action).toBe("refuse");
    expect(plan.content).toBeUndefined();
    expect(plan.reason).toMatch(/"mcpServers".*2 times/);
  });

  it("refuses two 4da entries", () => {
    const existing = '{ "mcpServers": { "4da": { "command": "a" }, "4da": { "command": "b" } } }';
    const plan = planConfig(existing, "mcpServers", ENTRY, { update: true });
    expect(plan.action).toBe("refuse");
    expect(plan.reason).toMatch(/2 "4da" entries/);
  });

  it.each(["4DA", "4Da", "4dA"])('refuses to add a second entry beside one named "%s"', (name) => {
    const existing = JSON.stringify({ mcpServers: { [name]: { command: "npx", args: ["@4da/mcp-server@6.2.7"] } } }, null, 2);
    for (const update of [false, true]) {
      const plan = planConfig(existing, "mcpServers", ENTRY, { update });
      expect(plan.action).toBe("refuse");
      expect(plan.content).toBeUndefined();
      expect(plan.reason).toContain(`"${name}"`);
    }
  });
});

describe("runSetup against a temp home", () => {
  let home: string;
  let ctx: SetupContext;
  let lines: string[];
  const log = (line: string) => lines.push(line);
  const output = () => lines.join("\n");

  beforeEach(() => {
    home = mkdtempSync(path.join(tmpdir(), "4da-setup-a1119-"));
    ctx = {
      platform: process.platform,
      env: { APPDATA: path.join(home, "Roaming"), XDG_CONFIG_HOME: path.join(home, ".config") },
      home,
    };
    lines = [];
  });

  afterEach(() => {
    rmSync(home, { recursive: true, force: true });
  });

  const target = (name: string) => editorTargets(ctx).find((t) => t.name === name)!;

  /** Every file under the temp home with its bytes, to prove what was or was not touched. */
  function snapshot(): Record<string, string> {
    const out: Record<string, string> = {};
    const walk = (dir: string) => {
      for (const name of readdirSync(dir)) {
        const full = path.join(dir, name);
        if (statSync(full).isDirectory()) walk(full);
        else out[path.relative(home, full)] = readFileSync(full, "latin1");
      }
    };
    walk(home);
    return out;
  }

  function install(name: string, content?: string | Buffer): string {
    const t = target(name);
    mkdirSync(t.detectDir, { recursive: true });
    if (content !== undefined) {
      mkdirSync(path.dirname(t.configPath), { recursive: true });
      writeFileSync(t.configPath, content);
    }
    return t.configPath;
  }

  it("writes the pinned entry and prints pinned commands", () => {
    const cursor = install("Cursor");
    const vscode = install("VS Code (Copilot)");
    writeFileSync(path.join(home, ".claude.json"), "{}");

    const result = runSetup(false, ctx, log);

    expect(result.exitCode).toBe(0);
    expect(result.written).toEqual([cursor, vscode]);
    expect(JSON.parse(readFileSync(cursor, "utf8"))).toEqual({ mcpServers: { "4da": ENTRY } });
    expect(JSON.parse(readFileSync(vscode, "utf8"))).toEqual({ servers: { "4da": VSCODE_ENTRY } });
    expect(output()).toContain(`claude mcp add --scope user 4da -- npx -y --prefer-offline ${PINNED}`);
    expect(output()).toContain(`npx -y --prefer-offline ${PINNED} --doctor`);
    // No command in the output is left without its version.
    expect(output()).not.toMatch(/@4da\/mcp-server(?!@\d)/);
    expect(output()).toContain("Done. Restart your editor to activate 4DA.");
  });

  it("with no editor found, the manual entry it prints is pinned and nothing is called done", () => {
    const result = runSetup(false, ctx, log);
    expect(result.exitCode).toBe(0);
    expect(output()).toContain("No supported editors detected.");
    expect(output()).toContain(`"${PINNED}"`);
    expect(output()).not.toMatch(/@4da\/mcp-server(?!@\d)/);
    expect(output()).not.toContain("Done.");
    expect(output()).toContain("Nothing was written.");
    expect(snapshot()).toEqual({});
  });

  it.each(USER_ENTRIES)("%s: the file is left byte for byte, and the report says it was kept", (_label, theirs) => {
    const original = JSON.stringify({ mcpServers: { "4da": { ...theirs, env: { HTTPS_PROXY: "http://proxy.example:8080" }, disabled: false } } }, null, 2);
    const cursor = install("Cursor", original);
    const before = snapshot();

    for (const dryRun of [true, false]) {
      lines = [];
      const result = runSetup({ dryRun }, ctx, log);
      expect(snapshot()).toEqual(before);
      expect(result.exitCode).toBe(0);
      expect(result.kept).toEqual([cursor]);
      expect(output()).toContain(`Kept your existing entry: ${cursor}`);
      expect(output()).toContain([theirs.command, ...(theirs.args as string[])].join(" "));
      expect(output()).toContain("--update");
      expect(output()).not.toContain("Written:");
      expect(output()).not.toContain("Done.");
    }
  });

  it("--update replaces it, says so with the old and the new command, and keeps env and disabled", () => {
    const original = JSON.stringify(
      { mcpServers: { "4da": { command: "npx", args: ["-y", "@4da/mcp-server@6.2.7"], env: { FOURDA_OFFLINE: "1" }, disabled: true }, github: { command: "gh-mcp" } } },
      null,
      2,
    );
    const cursor = install("Cursor", original);

    const preview = runSetup({ dryRun: true, update: true }, ctx, log);
    expect(preview.exitCode).toBe(0);
    expect(readFileSync(cursor, "utf8")).toBe(original);
    expect(existsSync(`${cursor}.bak`)).toBe(false);
    expect(output()).toContain(`Would replace the 4da entry: ${cursor}`);
    expect(output()).toContain("was: npx -y @4da/mcp-server@6.2.7");
    expect(output()).toContain(`now: npx -y --prefer-offline ${PINNED}`);

    lines = [];
    const result = runSetup({ update: true }, ctx, log);
    expect(result.exitCode).toBe(0);
    expect(result.written).toEqual([cursor]);
    expect(output()).toContain(`Replacing the 4da entry: ${cursor}`);
    expect(output()).toContain("was: npx -y @4da/mcp-server@6.2.7");
    expect(output()).toContain(`now: npx -y --prefer-offline ${PINNED}`);
    expect(output()).toContain(`Backup:  ${cursor}.bak`);
    expect(JSON.parse(readFileSync(cursor, "utf8"))).toEqual({
      mcpServers: { "4da": { ...ENTRY, env: { FOURDA_OFFLINE: "1" }, disabled: true }, github: { command: "gh-mcp" } },
    });
    expect(readFileSync(`${cursor}.bak`, "utf8")).toBe(original);
  });

  it("a config with a UTF-8 BOM is written and keeps its BOM", () => {
    const original = Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(JSON.stringify({ mcpServers: { other: { command: "x" } } }, null, 2))]);
    const cursor = install("Cursor", original);

    const result = runSetup(false, ctx, log);

    expect(result.exitCode).toBe(0);
    expect(output()).toContain(`Written: ${cursor}`);
    const after = readFileSync(cursor);
    expect([...after.subarray(0, 3)]).toEqual([0xef, 0xbb, 0xbf]);
    expect(JSON.parse(after.subarray(3).toString("utf8"))).toEqual({ mcpServers: { other: { command: "x" }, "4da": ENTRY } });
  });

  it("a config that is not valid UTF-8 is refused and left byte for byte", () => {
    // Windows-1252: e-acute is the single byte E9, which is not UTF-8.
    const original = Buffer.from('{\n  "mcpServers": {\n    "files": { "command": "node", "args": ["C:/Users/Jos\xe9/tools/server.js"] }\n  }\n}\n', "latin1");
    const cursor = install("Cursor", original);
    const before = snapshot();

    for (const dryRun of [true, false]) {
      lines = [];
      const result = runSetup({ dryRun }, ctx, log);
      expect(snapshot()).toEqual(before);
      expect(result.exitCode).toBe(1);
      expect(result.notWritten).toEqual([cursor]);
      expect(output()).toContain(`Not modified: ${cursor}`);
      expect(output()).toMatch(/not valid UTF-8/);
      expect(output()).not.toContain("Done.");
    }
    expect(readFileSync(cursor).equals(original)).toBe(true);
  });

  it("UTF-16 is named as what it is", () => {
    const cursor = install("Cursor", Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from('{"mcpServers":{}}', "utf16le")]));
    const before = snapshot();
    expect(runSetup(false, ctx, log).exitCode).toBe(1);
    expect(snapshot()).toEqual(before);
    expect(output()).toContain(`Not modified: ${cursor}`);
    expect(output()).toMatch(/UTF-16/);
  });

  it.each([
    ["a duplicate mcpServers key", '{\n  "mcpServers": { "first": { "command": "a" } },\n  "mcpServers": { "second": { "command": "b" } }\n}\n', /2 times/],
    ["a 4DA entry in other casing", JSON.stringify({ mcpServers: { "4DA": { command: "npx", args: ["@4da/mcp-server@6.2.7"] } } }, null, 2), /"4DA"/],
  ])("%s: refused with the reason, nothing written", (_label, original, reason) => {
    const cursor = install("Cursor", original);
    const before = snapshot();

    const result = runSetup({ update: true }, ctx, log);

    expect(snapshot()).toEqual(before);
    expect(result.exitCode).toBe(1);
    expect(output()).toContain(`Not modified: ${cursor}`);
    expect(output()).toMatch(reason);
  });

  it("a refusal exits non-zero and is not called done, while the other editor is still written", () => {
    const vscode = install("VS Code (Copilot)", '{\n  "servers": {\n    "memory": { "command": "npx" }\n  \n'); // truncated
    const cursor = install("Cursor");

    const result = runSetup(false, ctx, log);

    expect(result.exitCode).toBe(1);
    expect(result.written).toEqual([cursor]);
    expect(result.notWritten).toEqual([vscode]);
    expect(output()).not.toContain("Done.");
    expect(output()).toContain("1 config file was not written");
    expect(output()).toContain("Restart your editor");
  });

  it("when the only config found is refused, nothing is said to be written or to need a restart", () => {
    install("Cursor", "{ not json");
    const result = runSetup(false, ctx, log);
    expect(result.exitCode).toBe(1);
    expect(output()).toContain("Nothing was written.");
    expect(output()).not.toContain("Done.");
    expect(output()).not.toContain("Restart your editor");
  });

  it("a failed write exits non-zero, leaves the original and no backup behind", () => {
    const original = JSON.stringify({ mcpServers: { other: { command: "x" } } }, null, 2);
    const cursor = install("Cursor", original);
    // The temp file setup writes beside the config cannot be created: its name is a directory.
    mkdirSync(`${cursor}.4da-${process.pid}.tmp`);

    const result = runSetup(false, ctx, log);

    expect(result.exitCode).toBe(1);
    expect(result.written).toEqual([]);
    expect(result.notWritten).toEqual([cursor]);
    expect(output()).toContain(`Could not write ${cursor}`);
    expect(output()).not.toContain("Done.");
    expect(output()).not.toContain("Restart your editor");
    expect(readFileSync(cursor, "utf8")).toBe(original);
    expect(readdirSync(path.dirname(cursor)).filter((name) => name.endsWith(".bak"))).toEqual([]);
  });

  it("a dry run and a run with nothing to change do not say done", () => {
    install("Cursor");
    expect(runSetup(true, ctx, log).exitCode).toBe(0);
    expect(output()).toContain("Dry run: nothing was written.");
    expect(output()).not.toContain("Done.");

    runSetup(false, ctx, () => {});
    lines = [];
    expect(runSetup(false, ctx, log).exitCode).toBe(0);
    expect(output()).toContain("Already configured:");
    expect(output()).toContain("Nothing was written:");
    expect(output()).not.toContain("Done.");
  });

  // Windows has no permission bits to keep.
  it.skipIf(process.platform === "win32")("keeps the original file's mode on the rewritten file and its backup", () => {
    const cursor = install("Cursor", JSON.stringify({ mcpServers: { github: { command: "gh-mcp", env: { TOKEN: "t" } } } }, null, 2));
    chmodSync(cursor, 0o600);

    expect(runSetup(false, ctx, log).exitCode).toBe(0);

    expect(JSON.parse(readFileSync(cursor, "utf8")).mcpServers["4da"]).toEqual(ENTRY);
    expect(statSync(cursor).mode & 0o777).toBe(0o600);
    expect(statSync(`${cursor}.bak`).mode & 0o777).toBe(0o600);
  });

  // A read-only file is the user's to unlock (root ignores permission bits, so not as root).
  it.skipIf(process.platform === "win32" || process.getuid?.() === 0)("does not replace a read-only config", () => {
    const original = JSON.stringify({ mcpServers: { other: { command: "x" } } }, null, 2);
    const cursor = install("Cursor", original);
    chmodSync(cursor, 0o444);

    const result = runSetup(false, ctx, log);

    expect(result.exitCode).toBe(1);
    expect(output()).toContain(`Could not write ${cursor}`);
    expect(readFileSync(cursor, "utf8")).toBe(original);
    expect(statSync(cursor).mode & 0o777).toBe(0o444);
    expect(existsSync(`${cursor}.bak`)).toBe(false);
  });
});

describe("writeConfigAtomic", () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(path.join(tmpdir(), "4da-atomic-a1119-"));
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it("removes the backup it made when the write fails, and never an earlier one", () => {
    const file = path.join(dir, "mcp.json");
    writeFileSync(file, "v1");
    writeFileSync(`${file}.bak`, "an earlier backup");
    mkdirSync(`${file}.4da-${process.pid}.tmp`);

    expect(() => writeConfigAtomic(file, "v2")).toThrow();

    expect(readFileSync(file, "utf8")).toBe("v1");
    expect(readFileSync(`${file}.bak`, "utf8")).toBe("an earlier backup");
    expect(readdirSync(dir).sort()).toEqual(["mcp.json", "mcp.json.bak", `mcp.json.4da-${process.pid}.tmp`].sort());
  });
});

describe("arguments", () => {
  it("the server binary: --update goes with --setup only", () => {
    expect(parseCliArgs(["--setup", "--update"])).toEqual({ ok: true, command: { kind: "setup", dryRun: false, update: true } });
    expect(parseCliArgs(["--setup", "--dry-run", "--update"])).toEqual({ ok: true, command: { kind: "setup", dryRun: true, update: true } });
    expect(parseCliArgs(["setup"])).toEqual({ ok: true, command: { kind: "setup", dryRun: false, update: false } });
    expect(parseCliArgs(["--update"])).toEqual({ ok: false, error: "--update is used only with --setup" });
    expect(parseCliArgs(["--doctor", "--update"]).ok).toBe(false);
    expect(parseCliArgs(["--http", "--update"]).ok).toBe(false);
  });

  it("the setup bin: known flags only", () => {
    expect(parseSetupArgs([])).toEqual({ ok: true, command: { kind: "setup", dryRun: false, update: false } });
    expect(parseSetupArgs(["--dry-run"])).toEqual({ ok: true, command: { kind: "setup", dryRun: true, update: false } });
    expect(parseSetupArgs(["--update", "--dry-run"])).toEqual({ ok: true, command: { kind: "setup", dryRun: true, update: true } });
    expect(parseSetupArgs(["--help"])).toEqual({ ok: true, command: { kind: "help" } });
    expect(parseSetupArgs(["-h"])).toEqual({ ok: true, command: { kind: "help" } });
    expect(parseSetupArgs(["--dry-run", "--help"])).toEqual({ ok: true, command: { kind: "help" } });
    expect(parseSetupArgs(["--version"])).toEqual({ ok: true, command: { kind: "version" } });
    for (const bad of ["--dryrun", "-n", "--dry-run=1", "--bogus", "setup", "--setup", ""]) {
      const parsed = parseSetupArgs([bad]);
      expect(parsed.ok, bad).toBe(false);
      if (!parsed.ok) expect(parsed.error).toContain("unknown argument");
    }
  });
});

describe("runSetupCli (the 4da-mcp-setup bin) against a temp home", () => {
  let home: string;
  let ctx: SetupContext;
  let out: string[];
  let err: string[];
  const cli = (argv: string[]) =>
    runSetupCli(
      argv,
      ctx,
      (line) => out.push(line),
      (line) => err.push(line),
    );

  beforeEach(() => {
    home = mkdtempSync(path.join(tmpdir(), "4da-setup-a1119-"));
    ctx = { platform: process.platform, env: { APPDATA: path.join(home, "Roaming"), XDG_CONFIG_HOME: path.join(home, ".config") }, home };
    mkdirSync(path.join(home, ".cursor"));
    out = [];
    err = [];
  });
  afterEach(() => {
    rmSync(home, { recursive: true, force: true });
  });
  const written = () => readdirSync(path.join(home, ".cursor"));

  it.each(["--help", "-h"])("%s prints the usage, exits 0 and writes nothing", (flag) => {
    expect(cli([flag])).toBe(0);
    expect(out.join("\n")).toBe(SETUP_USAGE);
    expect(SETUP_USAGE).toContain("--dry-run");
    expect(SETUP_USAGE).toContain("--update");
    expect(written()).toEqual([]);
  });

  it("--version prints the version and writes nothing", () => {
    expect(cli(["--version"])).toBe(0);
    expect(out.join("\n")).toBe(`@4da/mcp-server ${VERSION}`);
    expect(written()).toEqual([]);
  });

  it.each(["--dryrun", "-n", "--bogus", "--setup"])("the unknown argument %s prints the usage, exits 2 and writes nothing", (flag) => {
    expect(cli([flag])).toBe(2);
    expect(err.join("\n")).toContain(`unknown argument "${flag}"`);
    expect(err.join("\n")).toContain(SETUP_USAGE);
    expect(out).toEqual([]);
    expect(written()).toEqual([]);
  });

  it("--dry-run writes nothing; no argument writes the pinned entry", () => {
    expect(cli(["--dry-run"])).toBe(0);
    expect(out.join("\n")).toContain("[DRY RUN]");
    expect(written()).toEqual([]);
    expect(cli([])).toBe(0);
    expect(JSON.parse(readFileSync(path.join(home, ".cursor", "mcp.json"), "utf8"))).toEqual({ mcpServers: { "4da": ENTRY } });
  });

  it("exits 1 when a config could not be written", () => {
    writeFileSync(path.join(home, ".cursor", "mcp.json"), "{ not json");
    expect(cli([])).toBe(1);
    expect(readFileSync(path.join(home, ".cursor", "mcp.json"), "utf8")).toBe("{ not json");
  });
});

// The bins as installed: `dist/setup.js` is `4da-mcp-setup`, `dist/index.js --setup` the documented form.
const setupEntry = path.join(path.dirname(serverEntry), "setup.js");
describe.skipIf(!existsSync(serverEntry) || !existsSync(setupEntry))("the built bins against a temp home", () => {
  let home: string;
  beforeEach(() => {
    home = mkdtempSync(path.join(tmpdir(), "4da-setup-a1119-bin-"));
    mkdirSync(path.join(home, ".cursor"));
  });
  afterEach(() => {
    rmSync(home, { recursive: true, force: true });
  });

  /** Runs a built entry with every home variable pointed into the temp home. */
  function run(entry: string, args: string[]): { status: number | null; stdout: string; stderr: string } {
    const env: NodeJS.ProcessEnv = { ...process.env };
    for (const key of Object.keys(env)) if (/^(FOURDA_|CLAUDE_CONFIG_DIR$|XDG_)/i.test(key)) delete env[key];
    Object.assign(env, {
      HOME: home,
      USERPROFILE: home,
      APPDATA: path.join(home, "AppData", "Roaming"),
      LOCALAPPDATA: path.join(home, "AppData", "Local"),
      XDG_CONFIG_HOME: path.join(home, ".config"),
      FOURDA_MCP_HOME: path.join(home, "4da-mcp"),
    });
    const result = spawnSync(process.execPath, [entry, ...args], { env, cwd: home, encoding: "utf8", timeout: 120_000 });
    return { status: result.status, stdout: result.stdout ?? "", stderr: result.stderr ?? "" };
  }
  const cursorFiles = () => readdirSync(path.join(home, ".cursor"));

  it.each(["--help", "-h", "--version"])("4da-mcp-setup %s exits 0 and writes nothing", (flag) => {
    const result = run(setupEntry, [flag]);
    expect(result.status).toBe(0);
    expect(result.stdout).toContain(flag === "--version" ? `@4da/mcp-server ${VERSION}` : "Usage:");
    expect(cursorFiles()).toEqual([]);
  });

  it.each(["--dryrun", "-n"])("4da-mcp-setup %s exits 2 with the usage and writes nothing", (flag) => {
    const result = run(setupEntry, [flag]);
    expect(result.status).toBe(2);
    expect(result.stderr).toContain(`unknown argument "${flag}"`);
    expect(result.stderr).toContain("Usage:");
    expect(cursorFiles()).toEqual([]);
  });

  it("4da-mcp-setup writes the pinned entry into the temp home and exits 0", () => {
    const result = run(setupEntry, []);
    expect(result.status).toBe(0);
    expect(result.stdout).toContain(path.join(home, ".cursor", "mcp.json"));
    expect(JSON.parse(readFileSync(path.join(home, ".cursor", "mcp.json"), "utf8"))).toEqual({ mcpServers: { "4da": ENTRY } });
  });

  it("index.js --setup keeps a changed entry, --update replaces it, and a refusal exits 1", () => {
    const config = path.join(home, ".cursor", "mcp.json");
    const theirs = JSON.stringify({ mcpServers: { "4da": { command: "npx", args: ["-y", "@4da/mcp-server@6.2.7"], env: { A: "1" } } } }, null, 2);
    writeFileSync(config, theirs);

    const kept = run(serverEntry, ["--setup"]);
    expect(kept.status).toBe(0);
    expect(kept.stdout).toContain("Kept your existing entry");
    expect(readFileSync(config, "utf8")).toBe(theirs);

    const replaced = run(serverEntry, ["--setup", "--update"]);
    expect(replaced.status).toBe(0);
    expect(replaced.stdout).toContain("Replacing the 4da entry");
    expect(JSON.parse(readFileSync(config, "utf8")).mcpServers["4da"]).toEqual({ ...ENTRY, env: { A: "1" } });

    writeFileSync(config, "{ not json");
    const refused = run(serverEntry, ["--setup"]);
    expect(refused.status).toBe(1);
    expect(readFileSync(config, "utf8")).toBe("{ not json");
  });
});
