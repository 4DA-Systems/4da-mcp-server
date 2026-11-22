// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";
import { explainCommandlessRows, NO_COMMAND_REASON_START } from "../tools/upgrade-planner-commandless.js";

const row = (action: string, commands: unknown[] = []) => ({
  package: "starlette",
  ecosystem: "PyPI",
  currentVersion: "0.37.2",
  targetVersion: "0.47.2",
  action,
  reasons: ["Transitive dependency: fastapi requires it."],
  commands,
});

describe("a plan row has commands or a stated reason, whatever its action", () => {
  it("a parent upgrade that starts with a hand edit says no command runs on its own", () => {
    const rows = [row("upgrade_parent"), row("lockfile_refresh"), row("override_or_replace")];
    explainCommandlessRows(rows, () => true);
    for (const r of rows) expect(r.reasons.some((x) => x.startsWith(NO_COMMAND_REASON_START))).toBe(true);
  });

  it("a row with a command, and a row that offers nothing to do, are left as they are", () => {
    const rows = [row("upgrade_parent", [{ dir: ".", run: "uv lock --upgrade-package fastapi" }]), row("waiting_on_upstream")];
    explainCommandlessRows(rows, () => true);
    for (const r of rows) expect(r.reasons).toHaveLength(1);
  });
});
