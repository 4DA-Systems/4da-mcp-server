// SPDX-License-Identifier: Apache-2.0
/**
 * Every command the server prints runs the pinned version the same way (pinnedNpx: `npx -y
 * --prefer-offline @4da/mcp-server@<version>`). Claims review of the 6.5.1 candidate (2026-11-24):
 * `--setup` ended with "Run: npx @4da/mcp-server@<v> --doctor" (no -y, no --prefer-offline) and the
 * update notice printed `npx -y @4da/mcp-server@<latest> --setup --update`.
 */

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { runSetup, type SetupContext } from "../setup.js";
import { updateNoticeText } from "../update-notice.js";
import { pinnedNpx } from "../usage.js";

describe("printed commands use pinnedNpx", () => {
  it("--setup's closing --doctor line", () => {
    const home = mkdtempSync(path.join(tmpdir(), "4da-setup-pin-"));
    const ctx: SetupContext = { platform: process.platform, env: { APPDATA: path.join(home, "Roaming"), XDG_CONFIG_HOME: path.join(home, ".config") }, home };
    const lines: string[] = [];
    try {
      runSetup(true, ctx, (line: string) => lines.push(line));
    } finally {
      rmSync(home, { recursive: true, force: true });
    }
    const doctor = lines.find((l) => l.includes("--doctor")) ?? "";
    expect(doctor).toMatch(/npx -y --prefer-offline @4da\/mcp-server@\S+ --doctor/);
  });

  it("the update notice's --setup --update command", () => {
    const text = updateNoticeText("6.5.0", "99.1.0") ?? "";
    expect(text).toContain(`${pinnedNpx("99.1.0")} --setup --update`);
    expect(pinnedNpx("99.1.0")).toBe("npx -y --prefer-offline @4da/mcp-server@99.1.0");
  });
});
