// SPDX-License-Identifier: Apache-2.0
/**
 * Facts run_order needs about what a command can do on this project, read from the project's own
 * files: the operator of an npm declaration (to write a holder's upgrade in the form the project
 * declares it).
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { npmDeclared } from "../live/fix-paths.js";

/** "^" or "~" when `dir`/package.json declares `name` with that operator on a plain version, "" for an exact pin; null otherwise. */
export function declaredNpmOperator(root: string, dir: string, name: string): string | null {
  let json: string;
  try {
    json = fs.readFileSync(path.join(path.resolve(root, dir), "package.json"), "utf-8");
  } catch {
    return null;
  }
  const spec = npmDeclared(json, name);
  if (spec === null) return null;
  const m = /^([\^~]?)\d+(?:\.\d+){0,2}$/.exec(spec.trim());
  return m ? m[1] : null;
}
