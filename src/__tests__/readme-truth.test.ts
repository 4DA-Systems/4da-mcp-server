// SPDX-License-Identifier: Apache-2.0
/**
 * What the README says about paths and files matches what the server does (audit 2026-11-11 W1
 * M2-4): Windows paths had lost their backslashes on GitHub and npm (`%APPDATA%CodeUsermcp.json`),
 * and the README named `cache.db` as the cache while standalone mode cached inside
 * `standalone.db` (cache-location.test.ts pins the code side).
 */
import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const readme = readFileSync(join(dirname(fileURLToPath(import.meta.url)), "..", "..", "README.md"), "utf8");

describe("README paths", () => {
  it("every %APPDATA% / %LOCALAPPDATA% path keeps its backslash", () => {
    expect(readme.match(/%(?:LOCAL)?APPDATA%[A-Za-z0-9]/g) ?? []).toEqual([]);
    expect(readme).toContain(String.raw`%APPDATA%\Code\User\mcp.json`);
    expect(readme).toContain(String.raw`%APPDATA%\devin\mcp_config.json`);
  });

  it("says the cache is cache.db in every mode, and standalone.db holds no cache", () => {
    expect(readme).toMatch(/`cache\.db` \(registry, OSV and changelog responses, in every mode/);
    expect(readme).toMatch(/`standalone\.db` \([^)]*no cache\)/);
  });

  it("promises no file paths leave the machine, and says what an embedding provider receives", () => {
    expect(readme).toMatch(/Never the file paths you pass in `files`/);
  });
});
