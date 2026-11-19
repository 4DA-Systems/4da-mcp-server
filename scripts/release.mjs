// SPDX-License-Identifier: Apache-2.0
/**
 * Prepare a release of @4da/mcp-server: bump every manifest, date the
 * changelog entry, build, test, run the gates, and commit on a release branch.
 *
 *   node scripts/release.mjs <patch|minor|major|X.Y.Z>
 *
 * Nothing is published here. After the release PR merges and CI is green on
 * the merge commit, tag that commit on main:
 *
 *   git tag mcp-v<version> <merge-sha> && git push origin mcp-v<version>
 *
 * The tag starts .github/workflows/release.yml, which requires CI's run of
 * that commit to have passed, waits for a maintainer to approve the `release`
 * environment, then publishes to npm through trusted publishing (with
 * provenance), to the MCP Registry, and attaches the .mcpb bundles to a GitHub
 * release.
 */
import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const PACKAGE = "@4da/mcp-server";

/**
 * Every file that names the version: five manifests, and the two documents
 * whose commands pin it. `manifest-versions.test.ts` holds each of them to
 * package.json, so a file added here needs its check there.
 */
export const VERSION_FILES = [
  "package.json",
  "server.json",
  ".claude-plugin/plugin.json",
  ".claude-plugin/marketplace.json",
  "gemini-extension.json",
  "README.md",
  "SECURITY.md",
];

/** An `args` list with the package's npx spec pinned to `next`. */
const pinArgs = (args, next) => args.map((arg) => (arg.startsWith(PACKAGE) ? `${PACKAGE}@${next}` : arg));

/**
 * The text of every version file after a release from `current` to `next`.
 * Pure: `files` maps each path of VERSION_FILES to its text, and the result
 * maps the same paths to the new text. The manifests get their version fields
 * and npx pins set; the documents get each `@4da/mcp-server@<current>` moved,
 * and nothing else (a release named in prose as history keeps its number).
 */
export function bumpVersionFiles(files, current, next) {
  for (const file of VERSION_FILES) {
    if (typeof files[file] !== "string") throw new Error(`bumpVersionFiles: ${file} is missing`);
  }
  const out = { ...files };
  const edit = (file, change) => {
    const data = JSON.parse(files[file]);
    change(data);
    out[file] = JSON.stringify(data, null, 2) + "\n";
  };
  edit("package.json", (pkg) => {
    pkg.version = next;
  });
  edit("server.json", (server) => {
    server.version = next;
    server.packages[0].version = next;
  });
  edit(".claude-plugin/plugin.json", (plugin) => {
    plugin.version = next;
    plugin.mcpServers["4da"].args = pinArgs(plugin.mcpServers["4da"].args, next);
  });
  edit(".claude-plugin/marketplace.json", (market) => {
    market.plugins[0].version = next;
  });
  edit("gemini-extension.json", (gemini) => {
    gemini.version = next;
    gemini.mcpServers["4da"].args = pinArgs(gemini.mcpServers["4da"].args, next);
  });
  // Every install and run command in the documents pins the version.
  for (const file of ["README.md", "SECURITY.md"]) {
    out[file] = files[file].replaceAll(`${PACKAGE}@${current}`, `${PACKAGE}@${next}`);
  }
  return out;
}

function main() {
  // Windows needs a shell only to find pnpm's .cmd shim. git runs without one:
  // through cmd.exe, `git commit -am "release: ..."` is split at its spaces.
  const run = (cmd, args) =>
    execFileSync(cmd, args, { cwd: root, stdio: "inherit", shell: process.platform === "win32" && cmd !== "git" });
  const out = (cmd, args) => execFileSync(cmd, args, { cwd: root, encoding: "utf8" }).trim();

  const bump = process.argv[2];
  if (!bump) {
    console.error("Usage: node scripts/release.mjs <patch|minor|major|X.Y.Z>");
    process.exit(1);
  }
  if (out("git", ["status", "--porcelain"])) {
    console.error("The working tree has uncommitted changes. Commit or discard them first.");
    process.exit(1);
  }

  const current = JSON.parse(readFileSync(join(root, "package.json"), "utf8")).version;
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
  // Escapes doubled: in a template literal "\." is just "." and "\d" is "d" (audit 6.2.5 E-10).
  const heading = new RegExp(`^## ${next.replaceAll(".", "\\.")} — (unreleased|\\d{4}-\\d{2}-\\d{2})$`, "m");
  if (!heading.test(changelog)) {
    console.error(`CHANGELOG.md has no "## ${next} — unreleased" entry. Write it first.`);
    process.exit(1);
  }
  const today = new Date().toISOString().slice(0, 10);
  writeFileSync(join(root, "CHANGELOG.md"), changelog.replace(heading, `## ${next} — ${today}`));

  console.log(`${PACKAGE} ${current} -> ${next}`);
  const files = Object.fromEntries(VERSION_FILES.map((file) => [file, readFileSync(join(root, file), "utf8")]));
  for (const [file, text] of Object.entries(bumpVersionFiles(files, current, next))) writeFileSync(join(root, file), text);

  run("pnpm", ["run", "build"]);
  run("pnpm", ["test"]);
  run("pnpm", ["run", "check"]);

  const branch = `release/v${next}`;
  run("git", ["switch", "-c", branch]);
  run("git", ["commit", "-am", `release: ${PACKAGE} ${next}`]);
  console.log(`
Committed on ${branch}. Next:
  1. git push -u origin ${branch}   and open a pull request; merge it when CI is green.
  2. When CI is green on the merge commit: git tag mcp-v${next} <merge-sha> && git push origin mcp-v${next}
     (the release workflow refuses a commit whose CI run did not pass, and waits for one still running)
  3. Approve the "release" environment on the workflow run.`);
}

/** True when this file is the script node was started with (drive-letter case differs between shells on Windows). */
function isMain() {
  if (!process.argv[1]) return false;
  const [a, b] = [resolve(process.argv[1]), fileURLToPath(import.meta.url)];
  return process.platform === "win32" ? a.toLowerCase() === b.toLowerCase() : a === b;
}

if (isMain()) main();
