// SPDX-License-Identifier: Apache-2.0
/**
 * Every command this server prints for a person to run starts the version that printed it: npx
 * with the package pinned and `--prefer-offline`, as setup writes into editor configs. 6.5.0's
 * `--help` printed `npx @4da/mcp-server --doctor` and four more unpinned lines, and the damaged
 * database message said "Run `npx @4da/mcp-server --doctor`": unpinned, npx starts whatever it
 * cached first or the newest release, which may not be the server that is answering (blind check
 * 2, SF9). `--help` also said FOURDA_OFFLINE covers "(OSV.dev, HN)"; it covers the registries too.
 */

import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { unreadableDbMessage } from "../db.js";
import { pinnedNpx, serverUsage } from "../usage.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const version = (JSON.parse(readFileSync(join(root, "package.json"), "utf8")) as { version: string }).version;
const PINNED = `npx -y --prefer-offline @4da/mcp-server@${version}`;
/** An npx line that names this package with no version after it. */
const UNPINNED = /npx\s+(?:-\S+\s+)*@4da\/mcp-server(?!@)/;

describe("the commands this server prints are pinned", () => {
  it("serverUsage pins every npx line to the given version", () => {
    const text = serverUsage("9.8.7");
    expect(text).not.toMatch(UNPINNED);
    expect(text).toContain("npx -y --prefer-offline @4da/mcp-server@9.8.7 --doctor");
    expect(text).toContain("npx -y --prefer-offline @4da/mcp-server@9.8.7 --setup");
    expect(text).toMatch(/FOURDA_OFFLINE\s+Set to 1 \/ true to disable all network calls \(OSV\.dev, the\s+package registries, Hacker News\)/);
  });

  it("pinnedNpx is the command setup writes, as one line", () => {
    expect(pinnedNpx("1.2.3")).toBe("npx -y --prefer-offline @4da/mcp-server@1.2.3");
  });

  it("the damaged-database message names the pinned --doctor command", () => {
    const text = unreadableDbMessage("/tmp/x/standalone.db", new Error("file is not a database"));
    expect(text).not.toMatch(UNPINNED);
    expect(text).toContain(`${PINNED} --doctor`);
  });
});

const entry = join(root, "dist", "index.js");

// 4DA's contract job runs this suite unbuilt: the spawn needs dist/.
describe.skipIf(!existsSync(entry))("the built server's --help", () => {
  it("prints no unpinned npx line, and the pinned one for this version", () => {
    const out = execFileSync(process.execPath, [entry, "--help"], { encoding: "utf8", env: { ...process.env, FOURDA_OFFLINE: "1" } });
    expect(out).not.toMatch(UNPINNED);
    expect(out).toContain(`${PINNED} --doctor`);
  });
});
