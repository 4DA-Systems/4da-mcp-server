// SPDX-License-Identifier: Apache-2.0
// The longest stretches without an idle sample in a .cpuprofile, with the functions that fill each:
//   node bench/scan-perf/stalls.mjs <file> [stalls=5] [functions=12]
import * as fs from "node:fs";

const prof = JSON.parse(fs.readFileSync(process.argv[2], "utf-8"));
const nStalls = Number(process.argv[3] ?? 5);
const nFns = Number(process.argv[4] ?? 12);
const byId = new Map(prof.nodes.map((x) => [x.id, x]));
const parent = new Map();
for (const x of prof.nodes) for (const c of x.children ?? []) parent.set(c, x.id);
const label = (x) => `${x.callFrame.functionName || "(anon)"} ${x.callFrame.url.split("/").slice(-1)[0]}:${x.callFrame.lineNumber + 1}`;
const idle = (id) => byId.get(id).callFrame.functionName === "(idle)";
const runs = [];
let cur = null;
for (let i = 0; i < prof.samples.length; i++) {
  const id = prof.samples[i];
  const dt = prof.timeDeltas[i + 1] ?? 0;
  if (idle(id)) {
    if (cur) runs.push(cur);
    cur = null;
    continue;
  }
  cur ??= { ms: 0, samples: [] };
  cur.ms += dt / 1000;
  cur.samples.push([id, dt]);
}
if (cur) runs.push(cur);
for (const run of runs.sort((a, b) => b.ms - a.ms).slice(0, nStalls)) {
  const incl = new Map();
  for (const [id, dt] of run.samples) {
    const seen = new Set();
    for (let c = id; c !== undefined; c = parent.get(c)) {
      const l = label(byId.get(c));
      if (seen.has(l)) continue;
      seen.add(l);
      incl.set(l, (incl.get(l) ?? 0) + dt / 1000);
    }
  }
  console.log(`=== stall ${run.ms.toFixed(0)} ms`);
  for (const [k, v] of [...incl].filter(([k]) => !/^\((root|program)\)|node:internal|processTicksAndRejections|runMicrotasks|async_hooks/.test(k)).sort((a, b) => b[1] - a[1]).slice(0, nFns)) console.log(`  ${v.toFixed(0).padStart(6)} ms  ${k}`);
}
