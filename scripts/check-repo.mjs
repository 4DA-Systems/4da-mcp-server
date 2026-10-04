// SPDX-License-Identifier: Apache-2.0
/**
 * Repository gates. Run in CI and by `pnpm run check`.
 *
 * These came with the server from the 4DA monorepo, where they ran over its
 * `mcp-4da-server/` folder:
 *
 *   1. SPDX header. Every source file under src/ and scripts/ declares
 *      Apache-2.0, the package's licence. The desktop app is FSL-1.1, so a file
 *      copied across without its header would carry the wrong terms.
 *   2. Retired claims (4DA AD-030). The product promise "gets sharper every
 *      day" and its family were retired as unmeasurable, and the mechanism
 *      behind "learns from your activity" no longer exists. None of them may
 *      reappear in shipped text. `retired-ok: <reason>` on the line or the one
 *      above allows quoting one as history.
 *   3. REMOVE BY markers. `REMOVE BY YYYY-MM-DD` puts an expiry on temporary
 *      code; a marker on or past its date fails.
 *   4. pnpm overrides tripwire. pnpm 11 stops reading the `pnpm` field of
 *      package.json, which silently drops every security override in it. The
 *      pin must stay below 11 while the overrides live there.
 *
 * Exit 1 on any finding.
 */
import { readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const rel = (p) => relative(root, p).replaceAll("\\", "/");
const findings = [];

function walk(dir, keep) {
  return readdirSync(dir).flatMap((name) => {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) return name === "node_modules" || name === "dist" ? [] : walk(p, keep);
    return keep(p) ? [p] : [];
  });
}
const sources = [
  ...walk(join(root, "src"), (p) => /\.(ts|mts|js|mjs)$/.test(p)),
  ...walk(join(root, "scripts"), (p) => /\.(mjs|cjs|js)$/.test(p)),
  ...walk(join(root, "hooks"), (p) => /\.(mjs|cjs|js)$/.test(p)),
];

// 1. SPDX header ---------------------------------------------------------------
for (const file of sources) {
  const head = readFileSync(file, "utf8").split("\n").slice(0, 3).join("\n");
  if (!head.includes("SPDX-License-Identifier: Apache-2.0")) {
    findings.push(`${rel(file)}: missing "// SPDX-License-Identifier: Apache-2.0" in its first lines`);
  }
}

// 2. Retired claims ------------------------------------------------------------
const RETIRED = [
  /gets?\s+sharper\s+every\s+day/i,
  /sharper\s+every\s+day/i,
  /learns?\s+from\s+how\s+you\s+engage/i,
  /compound\s+intelligence/i,
  /intelligence\s+(that\s+)?compounds/i,
  /behaviou?r(al)?\s+learning/i,
  /compounds?\s+over\s+time/i,
  /(scoring|model|system)\s+(gets|becomes)\s+(smarter|sharper|more\s+accurate)\s+(over\s+time|with\s+use|every)/i,
  /(learns?|learning)\s+from\s+your\s+(activity|activities|interactions?|behaviou?r)/i,
  /will\s+learn\s+from\s+your/i,
  /train(s|ing)?\s+the\s+system/i,
  /teach(es|ing)?\s+the\s+system/i,
  /system\s+(learns|is\s+learning)\s+from\s+you/i,
  /sharpen(s|ing)?\s+future\s+scoring/i,
  /helps?\s+4DA\s+learn\s+user\s+preferences/i,
  /learn(ed)?\s+preferences?\s+from\s+past\s+interactions/i,
  /learned\s+preferences?\s+from\s+user\s+behaviou?r/i,
];
const shipped = [
  join(root, "README.md"),
  join(root, "server.json"),
  join(root, ".claude-plugin", "plugin.json"),
  join(root, "package.json"),
  ...walk(join(root, "src"), (p) => /\.ts$/.test(p) && !p.replaceAll("\\", "/").includes("/__tests__/")),
];
for (const file of shipped) {
  const lines = readFileSync(file, "utf8").split("\n");
  lines.forEach((line, i) => {
    if (/retired-ok:/.test(line) || (i > 0 && /retired-ok:/.test(lines[i - 1]))) return;
    const hit = RETIRED.find((re) => re.test(line));
    if (hit) findings.push(`${rel(file)}:${i + 1}: retired claim (AD-030) matches ${hit}`);
  });
}

// 3. REMOVE BY markers ---------------------------------------------------------
const today = process.env.REMOVE_BY_TODAY ?? new Date().toISOString().slice(0, 10);
for (const file of sources) {
  readFileSync(file, "utf8")
    .split("\n")
    .forEach((line, i) => {
      const m = line.match(/REMOVE BY (\d{4})[-/](\d{2})[-/](\d{2})/);
      if (m && `${m[1]}-${m[2]}-${m[3]}` <= today) {
        findings.push(`${rel(file)}:${i + 1}: REMOVE BY ${m[1]}-${m[2]}-${m[3]} has passed — delete the code or move the date with a reason`);
      }
    });
}

// 4. pnpm overrides tripwire ---------------------------------------------------
const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
const pnpmMajor = Number((pkg.packageManager ?? "").match(/^pnpm@(\d+)/)?.[1] ?? NaN);
if (!Number.isFinite(pnpmMajor)) {
  findings.push('package.json: "packageManager" must pin pnpm (CI and contributors install with it)');
} else if (pnpmMajor >= 11 && pkg.pnpm && Object.keys(pkg.pnpm.overrides ?? {}).length > 0) {
  findings.push(
    `package.json: pnpm ${pnpmMajor} ignores the "pnpm" field, so its ${Object.keys(pkg.pnpm.overrides).length} security overrides would be dropped. Move them to pnpm-workspace.yaml first.`,
  );
}

if (findings.length) {
  console.error(`check-repo: ${findings.length} finding(s)\n  ${findings.join("\n  ")}`);
  process.exit(1);
}
console.log(`check-repo: OK (${sources.length} source files, ${shipped.length} shipped text files)`);
