// SPDX-License-Identifier: Apache-2.0
/**
 * Fetch the dependency-engine conformance corpus (4DA repo,
 * src-tauri/tests/conformance) into conformance/corpus/, which git ignores.
 *
 * The corpus is the desktop app's: its lockfiles, pinned OSV records and
 * adjudicated truth live there and are never edited or vendored here. This
 * server's harness (src/__tests__/conformance.test.ts) scores the TypeScript
 * engine against it, offline, at the commit conformance.lock pins.
 *
 *   node scripts/fetch-conformance.mjs              # the pinned commit (skips when already fetched)
 *   node scripts/fetch-conformance.mjs --ref main   # 4DA's current main (the nightly job)
 *   node scripts/fetch-conformance.mjs --dest <dir> # somewhere else
 *
 * A shallow, blob-filtered, sparse fetch of one commit: only the corpus
 * directory's blobs are downloaded. Git runs without a shell, with
 * core.autocrlf off so the lockfiles keep the bytes the truth was built from.
 */
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const lock = JSON.parse(readFileSync(join(root, "conformance.lock"), "utf8"));

function arg(name) {
  const i = process.argv.indexOf(`--${name}`);
  return i > -1 ? process.argv[i + 1] : undefined;
}

const ref = arg("ref") ?? lock.commit;
const pinned = arg("ref") === undefined;
const dest = resolve(arg("dest") ?? join(root, "conformance", "corpus"));
const stamp = join(dest, ".source.json");

if (pinned && existsSync(stamp)) {
  const have = JSON.parse(readFileSync(stamp, "utf8"));
  if (have.commit === lock.commit && have.path === lock.path) {
    console.log(`conformance corpus already at ${lock.commit.slice(0, 12)} (${dest})`);
    process.exit(0);
  }
}

const work = `${dest}.fetch-${process.pid}`;
rmSync(work, { recursive: true, force: true });
mkdirSync(work, { recursive: true });

function git(...args) {
  const r = spawnSync("git", ["-c", "core.autocrlf=false", "-c", "advice.detachedHead=false", ...args], {
    cwd: work,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "inherit"],
  });
  if (r.status !== 0) {
    rmSync(work, { recursive: true, force: true });
    console.error(`fetch-conformance: git ${args.join(" ")} failed (exit ${r.status ?? r.error?.message})`);
    process.exit(1);
  }
  return r.stdout.trim();
}

const started = Date.now();
git("init", "--quiet");
git("remote", "add", "origin", `https://github.com/${lock.repo}.git`);
git("sparse-checkout", "set", "--no-cone", `/${lock.path}/`);
git("fetch", "--quiet", "--depth", "1", "--filter=blob:none", "origin", ref);
git("checkout", "--quiet", "FETCH_HEAD");
const commit = git("rev-parse", "HEAD");

const corpus = join(work, ...lock.path.split("/"));
if (!existsSync(join(corpus, "cases"))) {
  rmSync(work, { recursive: true, force: true });
  console.error(`fetch-conformance: ${lock.repo}@${commit} has no ${lock.path}/cases`);
  process.exit(1);
}
rmSync(dest, { recursive: true, force: true });
mkdirSync(dirname(dest), { recursive: true });
renameSync(corpus, dest);
rmSync(work, { recursive: true, force: true });
writeFileSync(stamp, JSON.stringify({ repo: lock.repo, commit, path: lock.path, ref }, null, 2) + "\n");
console.log(
  `conformance corpus: ${lock.repo}@${commit.slice(0, 12)}${pinned ? " (pinned)" : ` (${ref})`} -> ${dest} in ${((Date.now() - started) / 1000).toFixed(1)}s`,
);
