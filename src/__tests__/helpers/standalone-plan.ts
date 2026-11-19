// SPDX-License-Identifier: Apache-2.0
/**
 * upgrade_planner without the desktop app's plan: the server's own heuristic plan
 * (`recommendations`), never the app's (`steps`). Suites that read the heuristic plan's fields
 * call the planner through here, so a result of the other shape fails loudly instead of reading
 * as `undefined`.
 */

import { executeUpgradePlanner, type UpgradePlanResult } from "../../tools/upgrade-planner.js";

export async function standalonePlan(...args: Parameters<typeof executeUpgradePlanner>): Promise<UpgradePlanResult> {
  const result = await executeUpgradePlanner(...args);
  if (!("recommendations" in result)) throw new Error("upgrade_planner answered with the desktop app's plan; this suite expects the standalone one");
  return result;
}
