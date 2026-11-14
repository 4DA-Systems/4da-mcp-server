// SPDX-License-Identifier: Apache-2.0
/**
 * One reading of a package name as an agent writes it, shared by every tool that takes one.
 *
 * Black-box audit of 5d709ff (r7): upgrade_impact refused `"lodash"` (the name in double quotes,
 * as an agent copies it from package.json) as an invalid name while dependency_check accepted it.
 * Both now read it the same way: surrounding whitespace and matching quotes or backticks around
 * the whole name are removed ("lodash", 'lodash', `lodash`); nothing else changes. The privacy
 * gate (private-packages.ts) runs on what the caller wrote before this, as it always did, and
 * reads every name inside a decorated one.
 */

const PAIRS: Record<string, string> = { '"': '"', "'": "'", "`": "`" };

export function unquotePackageName(raw: string): string {
  let name = raw.trim();
  for (let i = 0; i < 3 && name.length >= 2; i++) {
    const close = PAIRS[name[0]];
    if (!close || name[name.length - 1] !== close) break;
    name = name.slice(1, -1).trim();
  }
  return name;
}
