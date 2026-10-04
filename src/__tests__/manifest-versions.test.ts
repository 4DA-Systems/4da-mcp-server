// SPDX-License-Identifier: Apache-2.0
/**
 * Every manifest that names this package's version must name the same one.
 *
 * Five files carry it: package.json (npm), server.json (MCP Registry, twice),
 * .claude-plugin/plugin.json (the plugin, which also pins the npx version),
 * .claude-plugin/marketplace.json and gemini-extension.json. 4.6.0 and 6.0.0
 * both shipped with one of them stale; `scripts/release.mjs` bumps them
 * together and this test keeps them together.
 */
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const read = (file: string) => JSON.parse(readFileSync(join(root, file), "utf8"));

describe("manifest versions", () => {
  const version = read("package.json").version as string;

  it("server.json declares the package version, for itself and its npm package", () => {
    const server = read("server.json");
    expect(server.version).toBe(version);
    expect(server.packages[0].version).toBe(version);
  });

  it("the Claude Code plugin and its marketplace entry declare it, and npx pins it", () => {
    const plugin = read(".claude-plugin/plugin.json");
    expect(plugin.version).toBe(version);
    expect(plugin.mcpServers["4da"].args).toContain(`@4da/mcp-server@${version}`);
    expect(read(".claude-plugin/marketplace.json").plugins[0].version).toBe(version);
  });

  it("the Gemini CLI extension declares it", () => {
    expect(read("gemini-extension.json").version).toBe(version);
  });

  it("the changelog has an entry for it", () => {
    expect(readFileSync(join(root, "CHANGELOG.md"), "utf8")).toMatch(new RegExp(`^## ${version.replaceAll(".", "\.")} `, "m"));
  });
});
