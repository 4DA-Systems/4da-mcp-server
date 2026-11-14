// SPDX-License-Identifier: Apache-2.0
/**
 * One command per move, however many paths lead to it.
 *
 * Black-box audit of 5d709ff (round 7): a vulnerable transitive that two parents pin, both
 * arriving through the same direct dependency (qs under express and under body-parser, which
 * express brings in), named `npm install express@4.16.5 --save-exact` once per parent: twice in
 * the reason and twice in `parentUpgrades[].levers[].commands`. An agent that runs every command
 * it reads runs the same upgrade twice, and a reader cannot tell it is one move.
 *
 * Here, per step, the first lever that carries a command keeps it; a later lever with the same
 * commands drops them and says whose they are (`sameCommandsAs`, the parent whose lever carries
 * them), and every repeat of a backticked command in a reason after its first is replaced by
 * "the same command as above".
 */

/** The planner fields this reads and rewrites (upgrade-planner-fixpaths.ts ParentUpgrade, a structural subset). */
interface Lever {
  name: string;
  to: string | null;
  commands?: Array<{ dir: string; command: string; refresh?: true }>;
  sameCommandsAs?: string;
}
interface Step {
  reasons: string[];
  parentUpgrades?: Array<{ parent: string; levers: Lever[] }>;
}

export function dedupeParentCommands(steps: Step[]): void {
  for (const step of steps) {
    const seen = new Map<string, string>();
    for (const up of step.parentUpgrades ?? []) {
      for (const lever of up.levers) {
        if (!lever.commands || lever.commands.length === 0) continue;
        const key = lever.commands.map((c) => `${c.dir}\0${c.command}`).sort().join("\n");
        const owner = seen.get(key);
        if (owner === undefined) {
          seen.set(key, up.parent);
          continue;
        }
        delete lever.commands;
        lever.sameCommandsAs = owner;
      }
    }
    step.reasons = step.reasons.map(onceEach);
  }
}

/** A reason with every backticked command after its first occurrence replaced. */
function onceEach(reason: string): string {
  const said = new Set<string>();
  return reason.replace(/\(`([^`]+)`\)/g, (whole, command: string) => {
    if (!said.has(command)) {
      said.add(command);
      return whole;
    }
    return "(the same command as above)";
  });
}
