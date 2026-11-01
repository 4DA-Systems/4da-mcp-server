// SPDX-License-Identifier: Apache-2.0
/**
 * Build a Claude Desktop extension (.mcpb) for @4da/mcp-server.
 *
 * The bundle is PLATFORM-SPECIFIC: better-sqlite3 ships a native prebuild for
 * the platform that ran the install, so each OS/arch needs its own .mcpb
 * (built on that OS in CI). The manifest declares the platform accordingly.
 *
 * Usage:  node scripts/build-mcpb.mjs        (from the repo root, after `pnpm build`; needs pnpm and npm)
 * Output: dist-mcpb/4da-mcp-server-<version>-<platform>-<arch>.mcpb
 */
import { execSync } from "node:child_process";
import { cpSync, mkdirSync, rmSync, writeFileSync, readFileSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
const platform = process.platform; // win32 | darwin | linux
const arch = process.arch;

if (!existsSync(join(root, "dist", "index.js"))) {
  console.error("dist/index.js missing — run `pnpm build` first");
  process.exit(1);
}

const outDir = join(root, "dist-mcpb");
const stage = join(outDir, "stage");
rmSync(outDir, { recursive: true, force: true });
mkdirSync(join(stage, "server"), { recursive: true });

// 1. Built server code. SERVER_VERSION resolves join(__dirname, "..", "package.json")
//    → server/package.json below, which doubles as the npm-install manifest.
const server = join(stage, "server");
cpSync(join(root, "dist"), join(server, "dist"), { recursive: true });

// 2. Production node_modules FROM THE LOCKFILE: the versions CI tested, not
//    whatever the registry resolves today (audit 6.2.5 E-6). The stage gets the
//    real package.json, pnpm-lock.yaml and pnpm-workspace.yaml (its overrides
//    and supply-chain policy are part of what the frozen lockfile must match),
//    and pnpm installs with the hoisted linker: a flat, npm-style node_modules
//    with no symlinks, which survives zip packing. better-sqlite3's install
//    script (allowed in onlyBuiltDependencies) fetches this OS/arch's prebuild,
//    which is what pins the bundle to the platform.
for (const f of ["package.json", "pnpm-lock.yaml", "pnpm-workspace.yaml"]) cpSync(join(root, f), join(server, f));
execSync("pnpm install --prod --frozen-lockfile --config.node-linker=hoisted", { cwd: server, stdio: "inherit" });
rmSync(join(server, "pnpm-workspace.yaml"));
// Hold the result to the lockfile: each direct dependency in the bundle is the
// version the root importer of pnpm-lock.yaml resolved (the one CI tested).
{
  const lock = readFileSync(join(root, "pnpm-lock.yaml"), "utf8").replace(/\r\n/g, "\n");
  const importer = lock.slice(lock.indexOf("\nimporters:\n"), lock.indexOf("\npackages:\n"));
  const drift = [];
  for (const name of Object.keys({ ...pkg.dependencies, ...pkg.optionalDependencies })) {
    const esc = name.replace(/[.*+?^${}()|[\]\\/]/g, "\\$&");
    const m = importer.match(new RegExp(`\\n {6}'?${esc}'?:\\n {8}specifier: [^\\n]+\\n {8}version: ([^\\n(]+)`));
    const want = m?.[1].trim();
    const at = join(server, "node_modules", ...name.split("/"), "package.json");
    const got = existsSync(at) ? JSON.parse(readFileSync(at, "utf8")).version : "(missing)";
    console.log(`  ${name}: ${got} (lockfile ${want ?? "?"})`);
    if (!want || got !== want) drift.push(name);
  }
  if (drift.length) {
    console.error(`bundle dependencies differ from pnpm-lock.yaml: ${drift.join(", ")}`);
    process.exit(1);
  }
}
// pnpm's own install state; nothing reads it at runtime.
for (const f of [".modules.yaml", ".pnpm", ".pnpm-workspace-state-v1.json"]) rmSync(join(server, "node_modules", f), { recursive: true, force: true });
// The runtime manifest. SERVER_VERSION reads its version. better-sqlite3 is
// optional (node:sqlite comes first, src/sqlite-driver.ts); the bundle keeps
// its prebuild for a host Node older than 22.13. pnpm-lock.yaml stays in the
// bundle as the record of the tree it holds.
writeFileSync(
  join(server, "package.json"),
  JSON.stringify(
    { name: pkg.name, version: pkg.version, type: "module", dependencies: pkg.dependencies, optionalDependencies: pkg.optionalDependencies },
    null,
    2,
  ),
);

// 3. Manifest — generated from package.json so versions can never drift.
const standaloneTools = [
  { name: "upgrade_impact", description: "What changes between the installed and a target version of one dependency: breaking changes, deprecations, security fixes, and the files that import it." },
  { name: "vulnerability_scan", description: "Scan every installed copy in the project's lockfiles for known vulnerabilities via OSV.dev — severity, fix versions, where each is pinned." },
  { name: "dependency_health", description: "Version freshness, deprecations, and known issues across npm, Rust, Python, Go." },
  { name: "upgrade_planner", description: "Ranked upgrade plan: the smallest version that fixes each vulnerability, breaking majors flagged." },
  { name: "dependency_check", description: "Verdict with evidence before adding a dependency or applying a version bump (npm, crates.io)." },
  { name: "what_should_i_know", description: "Pre-task briefing scoped to the dependencies the task touches, with a delegation verdict." },
  { name: "ecosystem_pulse", description: "What moved in the project's ecosystem lately." },
  { name: "get_context", description: "The detected stack, so the agent stops guessing versions." },
  { name: "decision_memory", description: "Record and recall architecture decisions across sessions." },
  { name: "check_decision_alignment", description: "Check a proposed change against recorded decisions." },
  { name: "agent_memory", description: "Cross-session persistent memory for agent work." },
];

const manifest = {
  manifest_version: "0.2",
  name: "4da-mcp-server",
  display_name: "4DA — Developer Intelligence",
  version: pkg.version,
  description: "Upgrade intelligence: what an upgrade changes and where it touches your code, CVE scans, upgrade plans, decision memory. Only public package names and versions leave your machine.",
  long_description:
    "Point 4DA at a project folder and your agent gets eleven tools: upgrade impact (what changes between the version you run and the one you want, read from the package's own changelog, and which of your files import it), vulnerability scanning (every lockfile, every installed copy, against OSV.dev), a pre-install verdict on each dependency bump (advisories, release age, publish-trust drop, new install scripts), dependency health, ranked upgrade plans, pre-task briefings, ecosystem pulse, detected stack context, decision memory and alignment checks, and cross-session agent memory. The only data that ever leaves your machine is public package names and versions sent to OSV.dev and the packages' own registries — your code, paths, and prompts never do.",
  author: { name: "4DA Systems", url: "https://4da.ai" },
  homepage: "https://4da.ai/mcp/",
  documentation: "https://4da.ai/mcp/",
  support: "https://github.com/4DA-Systems/4da-mcp-server/issues",
  license: "Apache-2.0",
  keywords: ["security", "dependencies", "cve", "developer-intelligence", "privacy"],
  repository: { type: "git", url: "https://github.com/4DA-Systems/4da-mcp-server" },
  server: {
    type: "node",
    entry_point: "server/dist/index.js",
    mcp_config: {
      command: "node",
      args: ["${__dirname}/server/dist/index.js"],
      env: {
        FOURDA_PROJECT_DIR: "${user_config.project_dir}",
      },
    },
  },
  tools: standaloneTools,
  user_config: {
    project_dir: {
      type: "directory",
      title: "Project folder",
      description: "The code folder 4DA scans (manifests + lockfiles). Only public package names and versions are ever sent anywhere.",
      required: true,
    },
  },
  compatibility: {
    platforms: [platform],
    runtimes: { node: ">=22.0.0" },
  },
};
writeFileSync(join(stage, "manifest.json"), JSON.stringify(manifest, null, 2));

// 4. Pack with the official CLI (validates the manifest as part of packing).
//    tools/mcpb pins it, exact version and whole tree, in its own lockfile;
//    `npx -y @anthropic-ai/mcpb` ran whatever was newest on the day (E-6).
const tool = join(root, "tools", "mcpb");
execSync("npm ci --ignore-scripts --no-audit --no-fund", { cwd: tool, stdio: "inherit" });
const mcpbDir = join(tool, "node_modules", "@anthropic-ai", "mcpb");
const mcpbPkg = JSON.parse(readFileSync(join(mcpbDir, "package.json"), "utf8"));
const mcpbCli = join(mcpbDir, typeof mcpbPkg.bin === "string" ? mcpbPkg.bin : mcpbPkg.bin.mcpb);
console.log(`mcpb ${mcpbPkg.version}`);
const outFile = join(outDir, `4da-mcp-server-${pkg.version}-${platform}-${arch}.mcpb`);
execSync(`"${process.execPath}" "${mcpbCli}" pack "${stage}" "${outFile}"`, { stdio: "inherit" });
console.log(`\nBuilt ${outFile}`);
