// SPDX-License-Identifier: Apache-2.0
/**
 * Grow a real package-lock.json (v2/v3) to about N entries the way the round-6 audit did: copy
 * every installed package under other packages' node_modules, so the lockfile is larger while
 * the set of distinct (name, version) pairs, and so the OSV answers, stay the same.
 *
 *   node bench/scan-perf/grow.mjs <source package-lock.json> <out dir> <target entries>
 */
import * as fs from "node:fs";
import * as path from "node:path";

const [src, outDir, targetArg] = process.argv.slice(2);
const target = Number(targetArg);
const lock = JSON.parse(fs.readFileSync(src, "utf-8"));
const base = Object.entries(lock.packages).filter(([k]) => k.startsWith("node_modules/") && !k.slice(13).includes("/node_modules/"));
const hosts = base.map(([k]) => k);
let h = 0;
let count = Object.keys(lock.packages).length;
while (count < target && h < hosts.length) {
  const host = hosts[h++];
  for (const [k, entry] of base) {
    if (k === host) continue;
    const nested = `${host}/${k}`;
    if (!(nested in lock.packages)) {
      lock.packages[nested] = entry;
      count++;
    }
    if (count >= target) break;
  }
}
fs.mkdirSync(outDir, { recursive: true });
fs.writeFileSync(path.join(outDir, "package-lock.json"), JSON.stringify(lock, null, 2));
fs.copyFileSync(path.join(path.dirname(src), "package.json"), path.join(outDir, "package.json"));
console.log(`${Object.keys(lock.packages).length} entries -> ${outDir}`);
