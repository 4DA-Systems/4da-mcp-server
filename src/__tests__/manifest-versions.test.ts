// SPDX-License-Identifier: Apache-2.0
/**
 * Every manifest that names this package's version must name the same one.
 *
 * Five files carry it: package.json (npm), server.json (MCP Registry, twice),
 * .claude-plugin/plugin.json (the plugin, which also pins the npx version),
 * .claude-plugin/marketplace.json and gemini-extension.json (which pins it
 * too). 4.6.0 and 6.0.0 both shipped with one of them stale; `scripts/release.mjs`
 * bumps them together and this test keeps them together.
 *
 * The docs carry it as well, as the pin in every command (README.md,
 * SECURITY.md). A pin there that names another release, a tag such as
 * `@latest`, or no version at all is a command that runs something other than
 * what the page says, so those are held to the version and bumped with it.
 */
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { VERSION_FILES, bumpVersionFiles } from "../../scripts/release.mjs";

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const text = (file: string) => readFileSync(join(root, file), "utf8");
const read = (file: string) => JSON.parse(text(file));
const PACKAGE = "@4da/mcp-server";

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

  it("the Gemini CLI extension declares it, and npx pins it", () => {
    const gemini = read("gemini-extension.json");
    expect(gemini.version).toBe(version);
    expect(gemini.mcpServers["4da"].args).toContain(`@4da/mcp-server@${version}`);
  });

  it.each([
    ["README.md", 10],
    ["SECURITY.md", 0],
  ])("every install and run command in %s pins it", (file, moreThan) => {
    // A command (`npx ...`, `claude mcp add ... -- npx ...`) or a config's `args` entry, with npx's
    // own `-y` / `--prefer-offline` before the package or not.
    const uses = [...text(file).matchAll(/(?:npx (?:(?:-y|--prefer-offline) )*|"args": \["(?:(?:-y|--prefer-offline)", ")*)@4da\/mcp-server(@[^\s"`]+)?/g)];
    expect(uses.length).toBeGreaterThan(moreThan);
    for (const use of uses) expect(use[1], use[0]).toBe(`@${version}`);
  });

  // The files whose text is shown to users as commands to copy, and the manifests an editor runs.
  describe.each(["README.md", "SECURITY.md", "gemini-extension.json", ".claude-plugin/plugin.json"])("%s", (file) => {
    it("every pin of the package names this version, never another release or a tag such as @latest", () => {
      const pins = [...text(file).matchAll(/@4da\/mcp-server@([^\s"'`),;]+)/g)].map((m) => m[1]);
      expect(pins.length).toBeGreaterThan(0);
      for (const pin of pins) expect(pin, `${file}: ${PACKAGE}@${pin}`).toBe(version);
    });

    it("no bare version literal names another release", () => {
      // "`@6.2.7`" in prose; not `lodash@4.17.20` or a URL, which belong to something else.
      const bare = [...text(file).matchAll(/(?<![\w/.-])@(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)/g)].map((m) => m[1]);
      for (const literal of bare) expect(literal, `${file}: @${literal}`).toBe(version);
    });
  });

  it.each(["gemini-extension.json", ".claude-plugin/plugin.json"])("%s runs the package with a version, never bare", (file) => {
    const args: string[] = read(file).mcpServers["4da"].args;
    expect(args.filter((arg) => arg.startsWith(PACKAGE))).toEqual([`${PACKAGE}@${version}`]);
  });

  it("the changelog has an entry for it", () => {
    expect(readFileSync(join(root, "CHANGELOG.md"), "utf8")).toMatch(new RegExp(`^## ${version.replaceAll(".", "\.")} `, "m"));
  });

  describe("scripts/release.mjs bumps every file that names the version", () => {
    const next = "97.98.99";
    const before: Record<string, string> = Object.fromEntries((VERSION_FILES as string[]).map((file) => [file, text(file)]));
    const after: Record<string, string> = bumpVersionFiles(before, version, next);
    const count = (haystack: string, needle: string) => haystack.split(needle).length - 1;

    it("covers the five manifests, the README and SECURITY.md", () => {
      expect([...(VERSION_FILES as string[])].sort()).toEqual(
        [".claude-plugin/marketplace.json", ".claude-plugin/plugin.json", "README.md", "SECURITY.md", "gemini-extension.json", "package.json", "server.json"].sort(),
      );
      expect(Object.keys(after).sort()).toEqual(Object.keys(before).sort());
    });

    it("sets every declared version", () => {
      const json = (file: string) => JSON.parse(after[file]);
      expect(json("package.json").version).toBe(next);
      expect(json("server.json").version).toBe(next);
      expect(json("server.json").packages[0].version).toBe(next);
      expect(json(".claude-plugin/plugin.json").version).toBe(next);
      expect(json(".claude-plugin/marketplace.json").plugins[0].version).toBe(next);
      expect(json("gemini-extension.json").version).toBe(next);
    });

    it("moves every pin, in the manifests and the docs, and leaves none on the old version", () => {
      let pins = 0;
      for (const file of VERSION_FILES as string[]) {
        expect(after[file], file).not.toContain(`${PACKAGE}@${version}`);
        expect(count(after[file], `${PACKAGE}@${next}`), file).toBe(count(before[file], `${PACKAGE}@${version}`));
        pins += count(after[file], `${PACKAGE}@${next}`);
      }
      expect(pins).toBeGreaterThan(15);
      for (const file of ["README.md", "SECURITY.md", "gemini-extension.json", ".claude-plugin/plugin.json"]) {
        expect(count(after[file], `${PACKAGE}@${next}`), file).toBeGreaterThan(0);
      }
    });

    it("changes nothing in the docs but the pins: a release named as history keeps its number", () => {
      for (const file of ["README.md", "SECURITY.md"]) {
        expect(after[file].replaceAll(`${PACKAGE}@${next}`, `${PACKAGE}@${version}`), file).toBe(before[file]);
      }
    });

    it("keeps npx's own options, and their place before the package, in the manifests that run it", () => {
      for (const file of [".claude-plugin/plugin.json", "gemini-extension.json"]) {
        expect(JSON.parse(after[file]).mcpServers["4da"].args, file).toEqual(["-y", "--prefer-offline", `${PACKAGE}@${next}`]);
      }
    });

    it("refuses a file set that is missing one of them", () => {
      const { "SECURITY.md": _dropped, ...missing } = before;
      expect(() => bumpVersionFiles(missing, version, next)).toThrow(/SECURITY\.md/);
    });
  });
});
