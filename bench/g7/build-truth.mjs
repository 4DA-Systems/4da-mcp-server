// SPDX-License-Identifier: Apache-2.0
// Pins registry version lists + OSV advisories for every target/candidate package, and checks each
// task is well-posed (a non-vulnerable version exists inside its constraint).
import fs from "node:fs";
import path from "node:path";
import { HERE, packageTruth, countedVulns, saveVulnCache } from "./lib-truth.mjs";
import { meetsConstraint, isStableVersion, cmpVersions } from "./lib-versions.mjs";

const tasks = JSON.parse(fs.readFileSync(path.join(HERE, "tasks.json"), "utf8"));
const pkgs = new Map();
for (const t of tasks) for (const p of [t.target, ...(t.candidates ?? [])].filter(Boolean)) pkgs.set(`${t.eco}\0${p}`, { eco: t.eco, name: p });
console.log(`${pkgs.size} packages to pin`);
for (const { eco, name } of pkgs.values()) {
  const tr = await packageTruth(eco, name);
  const nv = tr.versions.length, nvuln = tr.versions.filter((v) => countedVulns(tr, v).length).length;
  console.log(`${eco.padEnd(9)} ${name.padEnd(32)} versions ${String(nv).padStart(4)} vulnerable ${String(nvuln).padStart(4)} latest ${tr.latest} latest-vuln ${tr.latest ? countedVulns(tr, tr.latest).length : "-"}`);
}
saveVulnCache();

const report = [];
for (const t of tasks) {
  const names = t.target ? [t.target] : t.candidates;
  const rows = [];
  for (const n of names) {
    const tr = await packageTruth(t.eco, n);
    const ok = tr.versions.filter((v) => isStableVersion(t.eco, v) && !tr.yanked.includes(v) && meetsConstraint(t.eco, v, t.constraint));
    const safe = ok.filter((v) => countedVulns(tr, v).length === 0).sort((a, b) => cmpVersions(t.eco, a, b));
    const vuln = ok.filter((v) => countedVulns(tr, v).length > 0);
    rows.push({ pkg: n, inConstraint: ok.length, vulnerableInConstraint: vuln.length, oldestSafe: safe[0] ?? null, newestSafe: safe.at(-1) ?? null });
  }
  report.push({ id: t.id, rows });
  console.log(t.id, rows.map((r) => `${r.pkg}: ${r.vulnerableInConstraint}/${r.inConstraint} vuln, safe ${r.oldestSafe}..${r.newestSafe}`).join(" | "));
}
fs.writeFileSync(path.join(HERE, "truth", "task-wellposed.json"), JSON.stringify(report, null, 2));
