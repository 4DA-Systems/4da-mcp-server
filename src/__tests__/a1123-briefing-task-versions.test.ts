// SPDX-License-Identifier: Apache-2.0
/**
 * what_should_i_know: a task that names several packages with versions gives each package its own
 * version. "upgrade minimist to 1.2.8 and install react 18.3.1" gave minimist
 * requested {"from":"1.2.8","to":"18.3.1"} and a next_step for `minimist 18.3.1`, while
 * requested_versions in the same answer was right. A version is never taken from another
 * package's clause.
 */
import { describe, expect, it } from "vitest";

import type { ResolvedDependency } from "../live/types.js";
import { detectTaskPackages } from "../tools/briefing-task-scope.js";
import { readTaskVersions } from "../tools/briefing-requested-versions.js";

function dep(name: string, version: string): ResolvedDependency {
  return { name, version, ecosystem: "npm", isDev: false, isDirect: true, devScopeKnown: true, target: null, platformActive: true, sourceDirs: ["d:/proj"] };
}

const DEPS = [dep("minimist", "1.2.5"), dep("lodash", "4.17.20"), dep("express", "4.17.1"), dep("chalk", "4.1.2")];

/** `name: from -> to` for each dependency the task names, in name order. */
const requested = (task: string) =>
  detectTaskPackages(task, [], DEPS, 10)
    .map((p) => `${p.name}: ${p.requested_from} -> ${p.requested_to}`)
    .sort();

describe("each package named in a task gets its own requested version", () => {
  it.each([
    // The audit's case: the second package is not installed.
    ["upgrade minimist to 1.2.8 and install react 18.3.1", ["minimist: null -> 1.2.8"]],
    ["upgrade lodash to 4.17.21 and add express 4.21.2", ["express: null -> 4.21.2", "lodash: null -> 4.17.21"]],
    ["bump lodash to 4.17.21, then add express 4.21.2", ["express: null -> 4.21.2", "lodash: null -> 4.17.21"]],
    // Two installed packages, and three.
    ["upgrade minimist to 1.2.8 and lodash to 4.17.21", ["lodash: null -> 4.17.21", "minimist: null -> 1.2.8"]],
    ["upgrade minimist to 1.2.8, lodash to 4.17.21 and express to 4.21.2", ["express: null -> 4.21.2", "lodash: null -> 4.17.21", "minimist: null -> 1.2.8"]],
    ["upgrade minimist to 1.2.8 then lodash to 4.17.21; express 4.21.2", ["express: null -> 4.21.2", "lodash: null -> 4.17.21", "minimist: null -> 1.2.8"]],
    // With "from X to Y".
    ["upgrade minimist from 1.2.5 to 1.2.8 and install react 18.3.1", ["minimist: 1.2.5 -> 1.2.8"]],
    ["upgrade minimist from 1.2.5 to 1.2.8 and lodash from 4.17.20 to 4.17.21", ["lodash: 4.17.20 -> 4.17.21", "minimist: 1.2.5 -> 1.2.8"]],
    [
      "move minimist from 1.2.5 to 1.2.8, lodash from 4.17.20 to 4.17.21 and chalk from 4.1.2 to 5.3.0",
      ["chalk: 4.1.2 -> 5.3.0", "lodash: 4.17.20 -> 4.17.21", "minimist: 1.2.5 -> 1.2.8"],
    ],
    // A package named with no version of its own takes none from the next clause.
    ["upgrade minimist and install react 18.3.1", ["minimist: null -> null"]],
    ["update lodash, then pin express to 4.21.2", ["express: null -> 4.21.2", "lodash: null -> null"]],
    // One package, unchanged.
    ["upgrade lodash to 4.17.21", ["lodash: null -> 4.17.21"]],
    ["bump lodash from 4.17.20 to 4.17.21", ["lodash: 4.17.20 -> 4.17.21"]],
  ])("%s", (task, expected) => {
    expect(requested(task)).toEqual(expected);
  });

  it("agrees with requested_versions on every version the task binds to an installed package", () => {
    for (const task of [
      "upgrade minimist to 1.2.8 and install react 18.3.1",
      "upgrade minimist to 1.2.8, lodash to 4.17.21 and express to 4.21.2",
      "upgrade minimist from 1.2.5 to 1.2.8 and lodash from 4.17.20 to 4.17.21",
    ]) {
      const bound = new Map(readTaskVersions(task, DEPS).requested.map((r) => [r.name, r.to]));
      for (const p of detectTaskPackages(task, [], DEPS, 10)) {
        if (bound.has(p.name)) expect(p.requested_to, `${task}: ${p.name}`).toBe(bound.get(p.name));
      }
    }
  });
});
