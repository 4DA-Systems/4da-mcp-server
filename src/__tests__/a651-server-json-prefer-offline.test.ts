// SPDX-License-Identifier: Apache-2.0
/**
 * The MCP Registry entry (server.json) tells a client to start the server as every other surface
 * does: `npx -y --prefer-offline @4da/mcp-server@<version>`. A client that builds its command from
 * the registry put nothing before the package (6.5.0 had no runtimeHint or runtimeArguments), so
 * an offline start waited on the registry for about 72 s, past the 30-60 s editors allow (measured
 * on 6.4.0; a1123-guard-install-surfaces.test.ts). The registry's schema (2025-12-11) writes a
 * fixed argument as `{"type": "positional", "value": ...}` and puts npx's own options in
 * `runtimeArguments`, with `runtimeHint` "npx" beside them.
 */

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const read = (file: string) => JSON.parse(readFileSync(join(root, file), "utf8"));

interface RegistryArgument {
  type: string;
  value?: string;
  name?: string;
}
interface RegistryPackage {
  registryType: string;
  identifier: string;
  version: string;
  runtimeHint?: string;
  runtimeArguments?: RegistryArgument[];
  packageArguments?: RegistryArgument[];
  transport: { type: string };
}

describe("server.json starts the server as the other install surfaces do", () => {
  const server = read("server.json") as { $schema: string; version: string; packages: RegistryPackage[] };
  const npm = server.packages.find((p) => p.registryType === "npm");

  it("the npm package entry runs through npx with -y and --prefer-offline before the package", () => {
    expect(npm, "server.json has an npm package").toBeDefined();
    expect(npm!.runtimeHint).toBe("npx");
    expect(npm!.runtimeArguments).toEqual([
      { type: "positional", value: "-y" },
      { type: "positional", value: "--prefer-offline" },
    ]);
    // After the package the flag would reach the server, which refuses it.
    expect(npm!.packageArguments ?? []).toEqual([]);
  });

  it("is the command the plugin and the Gemini extension run", () => {
    const command = ["npx", ...npm!.runtimeArguments!.map((a) => a.value), `${npm!.identifier}@${npm!.version}`];
    for (const file of [".claude-plugin/plugin.json", "gemini-extension.json"]) {
      const entry = read(file).mcpServers["4da"] as { command: string; args: string[] };
      expect([entry.command, ...entry.args], file).toEqual(command);
    }
  });

  it("keeps the shape the registry schema it names accepts", () => {
    expect(server.$schema).toBe("https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json");
    for (const a of npm!.runtimeArguments!) {
      // PositionalArgument: type "positional" with a value (or a valueHint); no name.
      expect(Object.keys(a).sort()).toEqual(["type", "value"]);
      expect(typeof a.value).toBe("string");
    }
    expect(npm!.transport).toEqual({ type: "stdio" });
  });
});
