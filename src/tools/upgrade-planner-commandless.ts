// SPDX-License-Identifier: Apache-2.0
/**
 * Every upgrade_planner row has `commands` or a stated reason, never neither.
 *
 * A direct upgrade the plan names no command for is, in the usual case, a freshness upgrade: no
 * known advisory affects the installed version, so no fix path was worked out and nothing says
 * which command reaches the newer release in this project. Such a row says so in its reasons, with
 * the hand step that takes it. A row whose fix starts with a hand edit (upgradeInstructions) says
 * that nothing runs before the edit. Rows with commands are left as they are.
 */

/** The row fields read and written here: a structural subset of upgrade_planner's row. */
export interface CommandlessRow {
  package: string;
  ecosystem: string;
  currentVersion: string | null;
  targetVersion: string | null;
  action: string;
  reasons: string[];
  commands: unknown[];
  upgradeInstructions?: unknown[];
}

/** The manifest a direct dependency's requirement is written in, per ecosystem. */
const MANIFEST: Record<string, string> = {
  npm: "package.json",
  "crates.io": "Cargo.toml",
  PyPI: "pyproject.toml or requirements file",
  Go: "go.mod",
};

/** Actions that name something to do for a copy: with no command, the row says its first move is by hand. */
const HAND_FIRST_ACTIONS = new Set(["upgrade_parent", "upgrade_parent_unverified", "lockfile_refresh", "override_or_replace", "reinstall"]);

/** The first words of the reason added here (a later pass can tell the row was already explained). */
export const NO_COMMAND_REASON_START = "No command is named for this upgrade";

/**
 * Add the reason to each direct upgrade that names no command. `vulnerable`
 * tells a security fix from a freshness upgrade (the row has advisories against its installed version).
 */
export function explainCommandlessRows<R extends CommandlessRow>(rows: R[], vulnerable: (row: R) => boolean): void {
  for (const r of rows) {
    if (r.commands.length > 0) continue;
    if (r.reasons.some((x) => x.startsWith(NO_COMMAND_REASON_START))) continue;
    if (HAND_FIRST_ACTIONS.has(r.action) && r.reasons.some((x) => x.includes("is NOT a clean fix"))) {
      // The release that would move the copy installs an affected dependency: there is no step to take yet.
      r.reasons.push(`${NO_COMMAND_REASON_START}: the release that would fix ${r.package} is NOT a clean fix (the reasons above say why), so no step is given and it is not in run_order.`);
      continue;
    }
    if (HAND_FIRST_ACTIONS.has(r.action)) {
      // A step the plan gives for this copy whose first move is not a command (a requirement or
      // override edit, a release the project cannot take yet).
      r.reasons.push(`${NO_COMMAND_REASON_START} on its own: this step for ${r.package} starts with an edit by hand, which the reasons and instructions on this row describe, so it is not in run_order.`);
      continue;
    }
    if (r.action !== "upgrade_direct" || !r.targetVersion) continue;
    const manifest = MANIFEST[r.ecosystem] ?? "manifest";
    const copy = `${r.package} ${r.currentVersion ?? ""}`.trimEnd();
    if ((r.upgradeInstructions?.length ?? 0) > 0) {
      // The instruction names the edit and the command after it: nothing runs before the edit.
      r.reasons.push(`${NO_COMMAND_REASON_START} on its own: moving ${copy} to ${r.targetVersion} starts with an edit of the ${manifest} by hand; upgradeInstructions says what to edit and what to run after it.`);
      continue;
    }
    const hand = `to take it, edit the ${manifest} so its requirement for ${r.package} admits ${r.targetVersion} (if it does not already), then refresh the lockfile`;
    r.reasons.push(
      vulnerable(r)
        ? `${NO_COMMAND_REASON_START}: this call did not work out which command moves ${copy} to ${r.targetVersion} here; ${hand}.`
        : `${NO_COMMAND_REASON_START}: it is not a security fix (no advisory affects ${copy}), so this plan does not work out which command reaches ${r.targetVersion} here and leaves it out of run_order; ${hand}.`,
    );
  }
}
