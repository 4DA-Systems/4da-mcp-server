// SPDX-License-Identifier: Apache-2.0
// Self time and inclusive time per function from a .cpuprofile: node bench/scan-perf/top.mjs <file> [n]
import * as fs from "node:fs";

const prof = JSON.parse(fs.readFileSync(process.argv[2], "utf-8"));
const n = Number(process.argv[3] ?? 25);
const byId = new Map(prof.nodes.map((x) => [x.id, x]));
const parent = new Map();
for (const x of prof.nodes) for (const c of x.children ?? []) parent.set(c, x.id);
const dt = new Map();
for (let i = 0; i < prof.samples.length; i++) dt.set(prof.samples[i], (dt.get(prof.samples[i]) ?? 0) + (prof.timeDeltas[i] ?? 0));
const label = (x) => `${x.callFrame.functionName || "(anon)"} ${x.callFrame.url.split("/").slice(-1)[0]}:${x.callFrame.lineNumber + 1}`;
const self = new Map();
const incl = new Map();
for (const [id, t] of dt) {
  const x = byId.get(id);
  self.set(label(x), (self.get(label(x)) ?? 0) + t);
  const seen = new Set();
  for (let cur = id; cur !== undefined; cur = parent.get(cur)) {
    const l = label(byId.get(cur));
    if (seen.has(l)) continue;
    seen.add(l);
    incl.set(l, (incl.get(l) ?? 0) + t);
  }
}
const show = (m, title) => {
  console.log(`--- ${title}`);
  for (const [k, v] of [...m].sort((a, b) => b[1] - a[1]).slice(0, n)) console.log(`${(v / 1000).toFixed(0).padStart(7)} ms  ${k}`);
};
show(self, "self");
show(incl, "inclusive");
