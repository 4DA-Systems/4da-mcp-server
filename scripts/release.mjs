// SPDX-License-Identifier: Apache-2.0
/**
 * Prepare a release of @4da/mcp-server: bump every manifest, date the
 * changelog entry, build, test, run the gates, and commit on a release branch.
 *
 *   node scripts/release.mjs <patch|minor|major|X.Y.Z>
 *
 * Nothing is published here. After the release PR merges, tag the merge
 * commit on main:
 *
 *   git tag mcp-v<version> <merge-sha> && git push origin mcp-v<version>
 *
 * The tag starts .github/workflows/release.yml, which waits for a maintainer
 * to approve the `release` environment, then publishes to npm through trusted
 * publishing (with provenance), to the MCP Registry, and attaches the .mcpb
 * bundles to a GitHub release.
 */
import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const run = (cmd, args) => execFileSync(cmd, args, { cwd: root, stdio: "inherit", shell: process.platform === "win32" });
const out = (cmd, args) => execFileSync(cmd, args, { cwd: root, encoding: "utf8" }).trim();
const json = (file) => JSON.parse(readFileSync(join(root, file), "utf8"));
const write = (file, data) => writeFileSync(join(root, file), JSON.stringify(data, null, 2) + "\n");

const bump = process.argv[2];
if (!bump) {
  console.error("Usage: node scripts/release.mjs <patch|minor|major|X.Y.Z>");
  process.exit(1);
}
if (out("git", ["status", "--porcelain"])) {
  console.error("The working tree has uncommitted changes. Commit or discard them first.");
  process.exit(1);
}

const current = json("package.json").version;
let next = bump;
if (["patch", "minor", "major"].includes(bump)) {
  const [maj, min, pat] = current.split(".").map(Number);
  next = bump === "major" ? `${maj + 1}.0.0` : bump === "minor" ? `${maj}.${min + 1}.0` : `${maj}.${min}.${pat + 1}`;
}
if (!/^\d+\.\d+\.\d+$/.test(next)) {
  console.error(`Not a version: ${next}`);
  process.exit(1);
}

// The changelog entry is written by hand, before this runs; here it gets its date.
const changelog = readFileSync(join(root, "CHANGELOG.md"), "utf8");
const heading = new RegExp(`^## ${next.replaceAll(".", "\.")} — (unreleased|\d{4}-\d{2}-\d{2})$`, "m");
if (!heading.test(changelog)) {
  console.error(`CHANGELOG.md has no "## ${next} — unreleased" entry. Write it first.`);
  process.exit(1);
}
const today = new Date().toISOString().slice(0, 10);
writeFileSync(join(root, "CHANGELOG.md"), changelog.replace(heading, `## ${next} — ${today}`));

console.log(`@4da/mcp-server ${current} -> ${next}`);
const pkg = json("package.json");
pkg.version = next;
write("package.json", pkg);
const server = json("server.json");
server.version = next;
server.packages[0].version = next;
write("server.json", server);
const plugin = json(".claude-plugin/plugin.json");
plugin.version = next;
plugin.mcpServers["4da"].args = plugin.mcpServers["4da"].args.map((a) => (a.startsWith("@4da/mcp-server") ? `@4da/mcp-server@${next}` : a));
write(".claude-plugin/plugin.json", plugin);
const market = json(".claude-plugin/marketplace.json");
market.plugins[0].version = next;
write(".claude-plugin/marketplace.json", market);
const gemini = json("gemini-extension.json");
gemini.version = next;
write("gemini-extension.json", gemini);

run("pnpm", ["run", "build"]);
run("pnpm", ["test"]);
run("pnpm", ["run", "check"]);

const branch = `release/v${next}`;
run("git", ["switch", "-c", branch]);
run("git", ["commit", "-am", `release: @4da/mcp-server ${next}`]);
console.log(`
Committed on ${branch}. Next:
  1. git push -u origin ${branch}   and open a pull request; merge it when CI is green.
  2. git tag mcp-v${next} <merge-sha> && git push origin mcp-v${next}
  3. Approve the "release" environment on the workflow run.`);
