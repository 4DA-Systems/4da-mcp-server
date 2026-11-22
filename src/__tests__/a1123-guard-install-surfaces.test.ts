// SPDX-License-Identifier: Apache-2.0
/**
 * Every configuration this repository writes or ships for running the server through npx pins the
 * exact version and passes `--prefer-offline` to npx, before the package: a cached pinned version
 * then starts without waiting on the registry. Offline, without it, npx retried the registry for
 * about 72 s before starting a version it already had (past the 30-60 s editors allow); with it,
 * 1.7 s. Placed after the package, the flag goes to the server instead, which refuses it
 * ("unknown argument"), so the order is held too. Measured on 6.4.0 on Windows (npm 10.9.2) and
 * Linux (node:22-alpine, npm 10.9.9) behind a dead proxy.
 */

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { parseCliArgs } from "../cli-args.js";
import { CLAUDE_CODE_COMMAND, PACKAGE_VERSION, editorTargets } from "../setup.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const read = (file: string) => JSON.parse(readFileSync(join(root, file), "utf8"));
const version = read("package.json").version as string;
const ARGS = ["-y", "--prefer-offline", `@4da/mcp-server@${version}`];

describe("npx starts a cached pinned version without the registry", () => {
  it("the Claude Code plugin and the Gemini CLI extension run npx -y --prefer-offline <pinned>", () => {
    for (const file of [".claude-plugin/plugin.json", "gemini-extension.json"]) {
      expect(read(file).mcpServers["4da"], file).toEqual({ command: "npx", args: ARGS });
    }
  });

  it("setup writes the same command into every editor's config", () => {
    expect(PACKAGE_VERSION).toBe(version);
    const ctx = { platform: "linux" as NodeJS.Platform, env: {}, home: "/home/u" };
    for (const target of editorTargets(ctx, version)) {
      expect(target.entry.command, target.name).toBe("npx");
      expect(target.entry.args, target.name).toEqual(ARGS);
    }
  });

  it("the Claude Code command setup prints passes the flag to npx, not to the server", () => {
    expect(CLAUDE_CODE_COMMAND).toBe(`claude mcp add --scope user 4da -- npx ${ARGS.join(" ")}`);
  });

  it("the flag is npm's: after the package it would reach the server, which refuses it", () => {
    const server = parseCliArgs(["--prefer-offline"]);
    expect(server.ok).toBe(false);
    for (const args of [ARGS, ...editorTargets({ platform: "win32", env: {}, home: "C:\\Users\\u" }, version).map((t) => t.entry.args as string[])]) {
      expect(args).toContain("--prefer-offline");
      expect(args.indexOf("--prefer-offline")).toBeLessThan(args.findIndex((a) => a.startsWith("@4da/mcp-server")));
    }
  });
});
