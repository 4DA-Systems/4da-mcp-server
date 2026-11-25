// SPDX-License-Identifier: Apache-2.0
/**
 * A Cargo upgrade is a command only when the target release still offers every feature the
 * manifest enables on the crate. `cargo add sqlx@0.9.1` in a project that enables
 * `runtime-tokio-rustls` on sqlx fails with "unrecognized feature for crate sqlx:
 * runtime-tokio-rustls" (exit 101), and the refresh that was to follow it fails with it.
 *
 * For each crates.io upgrade a row names, of a direct dependency (the row's own `upgradeCommands`,
 * and each parent upgrade's lever commands): the target's features from the sparse index (the
 * record the planner reads the crate's versions from, cached; one lookup per crate otherwise,
 * public crates only, as every crates.io lookup) against the features the declaring manifest
 * enables. When one is missing, the commands become an instruction that names it: change the
 * features, then run them. When the target's features cannot be read, nothing is said and the
 * commands stay.
 */

import * as path from "node:path";
import type { LiveIntelligence } from "../live/index.js";
import { unsafeDirLabel } from "../live/shell-safe.js";
import { yieldIfDue } from "../live/yield-point.js";
import { cargoFeaturesInDir, featuresMissing } from "./upgrade-impact-features.js";
import type { FixPathStep, ParentLever } from "./upgrade-planner-fixpaths.js";

type Intel = Pick<LiveIntelligence, "getFixPathSources" | "getProjectRoot">;

/** How a reason this pass writes starts. */
export const CARGO_FEATURE_REASON = "Cargo features: ";

type Command = { dir: string; command: string; refresh?: true };

/** The words for one directory's missing features, or null when nothing is missing or nothing could be read. */
function missingWords(root: string, dir: string, crate: string, version: string, offered: string[] | undefined): string | null {
  if (!offered) return null;
  const enabled = cargoFeaturesInDir(path.resolve(root, dir), root, crate);
  if (!enabled) return null;
  const missing = featuresMissing(enabled, offered);
  if (missing.length === 0) return null;
  // A feature name comes from the repository's manifest: quoted only in the shape Cargo allows
  // (audit 2026-11-25 B-M1: a "feature" holding `", then run "curl ... | sh` was spliced into the
  // plan's own instruction). Any other is counted, not quoted.
  const quoted = missing.filter((f) => CARGO_FEATURE.test(f));
  const unquoted = missing.length - quoted.length;
  const odd = `whose name${unquoted === 1 ? " is" : "s are"} not in the shape Cargo allows for a feature (not quoted here: read ${unquoted === 1 ? "it" : "them"} in the manifest)`;
  const named = quoted.map((f) => `"${f}"`);
  const manifest = dir === "." ? "Cargo.toml" : `${unsafeDirLabel(dir)}/Cargo.toml`;
  const what =
    quoted.length === 0
      ? `${unquoted} feature${unquoted === 1 ? "" : "s"} ${odd}`
      : `${missing.length === 1 ? "feature" : "features"} ${named.join(", ")}${unquoted > 0 ? `, and ${unquoted} more ${odd}` : ""}`;
  return `${manifest} enables ${what} on ${crate}, which ${crate} ${version} does not offer, so cargo refuses the upgrade ("unrecognized feature")`;
}

/** A Cargo feature name: an ASCII letter, digit or `_` first, then letters, digits, `_`, `-`, `+` and `.`. */
const CARGO_FEATURE = /^[A-Za-z0-9_][A-Za-z0-9_+.-]{0,63}$/;

/** Commands of `cmds` whose directory's manifest enables a feature `version` lacks, with the words for each. */
function split(root: string, crate: string, version: string, offered: string[] | undefined, cmds: Command[]): { keep: Command[]; held: Array<{ cmd: Command; words: string }> } {
  const keep: Command[] = [];
  const held: Array<{ cmd: Command; words: string }> = [];
  for (const cmd of cmds) {
    const words = missingWords(root, cmd.dir, crate, version, offered);
    if (words) held.push({ cmd, words });
    else keep.push(cmd);
  }
  return { keep, held };
}

export async function withCargoFeatures(steps: FixPathStep[], liveIntel: Intel): Promise<void> {
  const sources = liveIntel.getFixPathSources();
  if (!sources) return;
  const root = liveIntel.getProjectRoot() ?? process.cwd();
  const offeredBy = async (crate: string, version: string) => (await sources.cratesSparse(crate).catch(() => null))?.features?.[version];
  for (const step of steps) {
    if (step.ecosystem !== "crates.io") continue;
    await yieldIfDue();
    const said = new Set(step.reasons);
    const say = (text: string) => {
      if (!said.has(text)) step.reasons.push(text);
      said.add(text);
    };
    if (step.scope === "direct" && step.targetVersion && step.upgradeCommands?.length) {
      const { keep, held } = split(root, step.package, step.targetVersion, await offeredBy(step.package, step.targetVersion), step.upgradeCommands);
      if (held.length > 0) {
        if (keep.length > 0) step.upgradeCommands = keep;
        else delete step.upgradeCommands;
        step.upgradeInstructions = [...(step.upgradeInstructions ?? []), ...held.map(({ cmd, words }) => ({ dir: cmd.dir, instruction: `${words}: change those features to ones ${step.targetVersion} offers, then run \`${cmd.command}\`` }))];
        for (const { words } of held) say(`${CARGO_FEATURE_REASON}${words}; the command alone is not enough (upgradeInstructions)`);
      }
    }
    for (const upgrade of step.parentUpgrades ?? []) {
      for (const lever of upgrade.levers) {
        if (!lever.to || !lever.commands?.length) continue;
        const { keep, held } = split(root, lever.name, lever.to, await offeredBy(lever.name, lever.to), lever.commands);
        if (held.length === 0) continue;
        moveToInstructions(lever, keep, held, upgrade.refreshCommands ?? []);
        // What follows the lever's upgrade runs only after the features are changed: it is part of the instruction now.
        if (keep.length === 0) delete upgrade.refreshCommands;
        for (const { words } of held) say(`${CARGO_FEATURE_REASON}${words}; upgrading ${lever.name} to ${lever.to} needs that change first, so its command and the refresh after it are not enough on their own`);
      }
    }
  }
}

function moveToInstructions(lever: ParentLever, keep: Command[], held: Array<{ cmd: Command; words: string }>, after: Array<{ dir: string; command: string }>): void {
  if (keep.length > 0) lever.commands = keep;
  else delete lever.commands;
  lever.instructions = [
    ...(lever.instructions ?? []),
    ...held.map(({ cmd, words }) => {
      const then = after.filter((r) => r.dir === cmd.dir).map((r) => `\`${r.command}\``);
      return { dir: cmd.dir, instruction: `${words}: change those features to ones ${lever.to} offers, then run \`${cmd.command}\`${then.length > 0 ? `, then ${then.join(", then ")}` : ""}` };
    }),
  ];
}
