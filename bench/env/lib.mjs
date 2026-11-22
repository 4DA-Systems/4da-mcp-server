// SPDX-License-Identifier: Apache-2.0
/**
 * Shared parts of the environment harnesses (concurrency.mjs, firstrun-kill.mjs,
 * firstrun-together.mjs): small projects with public package names and distinct stacks, a
 * single-process baseline of what each one answers, and the facts compared against it.
 *
 * Every session here is offline (FOURDA_OFFLINE=1 and a proxy on a port nothing listens on):
 * the answers compared are the ones that need no lookup (which project, which dependencies,
 * which stack, which tools, whether writes are kept), and nothing leaves the machine.
 */
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { hermeticEnv, openSession, resolveServer } from "../lib/mcp-session.mjs";

export { openSession, rmTree, sleep } from "../lib/mcp-session.mjs";

/** Command-line options shared by the three harnesses. */
export function options(argv = process.argv.slice(2)) {
  const opt = (name, fallback) => {
    const i = argv.indexOf(`--${name}`);
    return i >= 0 ? argv[i + 1] : fallback;
  };
  const server = resolveServer(opt("server"));
  // A fresh folder of our own, inside --work when given: removing it never touches the caller's files.
  const parent = path.resolve(opt("work", os.tmpdir()));
  fs.mkdirSync(parent, { recursive: true });
  const work = fs.mkdtempSync(path.join(parent, "4da-env-"));
  return { server, work, out: opt("out") ? path.resolve(opt("out")) : null, opt, keep: argv.includes("--keep") };
}

const lock = (deps) =>
  JSON.stringify(
    {
      name: "app",
      version: "1.0.0",
      lockfileVersion: 3,
      requires: true,
      packages: {
        "": { name: "app", version: "1.0.0", dependencies: Object.fromEntries(Object.entries(deps).map(([n, v]) => [n, v])) },
        ...Object.fromEntries(Object.entries(deps).map(([n, v]) => [`node_modules/${n}`, { version: v, resolved: `https://registry.npmjs.org/${n}/-/${n.split("/").pop()}-${v}.tgz`, license: "MIT" }])),
      },
    },
    null,
    2,
  );

/** The projects: one per stack, public names at old versions. */
export const PROJECTS = {
  "web-npm": {
    "package.json": JSON.stringify({ name: "web-npm", version: "1.0.0", dependencies: { lodash: "4.17.20", minimist: "1.2.5", debug: "4.3.1" } }, null, 2),
    "package-lock.json": lock({ lodash: "4.17.20", minimist: "1.2.5", debug: "4.3.1", ms: "2.1.2" }),
    "index.js": "require('lodash');\n",
  },
  "api-python": {
    "requirements.txt": "flask==2.0.0\njinja2==3.0.0\nwerkzeug==2.0.0\nrequests==2.25.0\n",
    "app.py": "import flask\n",
  },
  "cli-rust": {
    "Cargo.toml": '[package]\nname = "cli-rust"\nversion = "0.1.0"\nedition = "2021"\n\n[dependencies]\nsmallvec = "1.6.0"\ntime = "0.1.43"\n',
    "Cargo.lock":
      'version = 3\n\n[[package]]\nname = "cli-rust"\nversion = "0.1.0"\ndependencies = [\n "smallvec",\n "time",\n]\n\n' +
      '[[package]]\nname = "smallvec"\nversion = "1.6.0"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\nchecksum = "fe0f37c9e8f3c5a4a66ad655a93c74daac4ad00c441533bf5c6e7990bb42604e"\n\n' +
      '[[package]]\nname = "time"\nversion = "0.1.43"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\nchecksum = "ca8a50ef2360fbd1eeb0ecd46795a87a19024eb4b53c5dc916ca1fd95fe62438"\n',
    "src/main.rs": "fn main() {}\n",
  },
  "svc-go": {
    "go.mod": "module example.com/svc\n\ngo 1.21\n\nrequire (\n\tgolang.org/x/text v0.3.7\n\tgithub.com/spf13/cobra v1.6.0\n)\n",
    "go.sum": "golang.org/x/text v0.3.7 h1:olpwvP2KacW1ZWvsR7uQhoyTYvKAupfQrRGBFM352Gk=\ngolang.org/x/text v0.3.7/go.mod h1:u+2+/6zg+i71rQMx5EYifcz6MCKuco9NR6JIITiCfzQ=\ngithub.com/spf13/cobra v1.6.0 h1:42a0n6jwCot1pUmomAp4T7DeMD+20LFv4Q54pxLf2LI=\ngithub.com/spf13/cobra v1.6.0/go.mod h1:IOw/AERYS7UzyrGinqmz6HLUo219MORXGxhbaJUqzrY=\n",
    "main.go": "package main\n\nfunc main() {}\n",
  },
};

/** Write the projects under `root`; returns name -> absolute directory. */
export function writeProjects(root) {
  const dirs = {};
  for (const [name, files] of Object.entries(PROJECTS)) {
    const dir = path.join(root, name);
    for (const [rel, body] of Object.entries(files)) {
      fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
      fs.writeFileSync(path.join(dir, rel), body);
    }
    dirs[name] = dir;
  }
  return dirs;
}

/** An offline session environment on data folder `home`. */
export const offlineEnv = (home) => hermeticEnv({ home, offline: true });

/** The facts of a vulnerability_scan answer that need no lookup. */
export function scanFacts(r) {
  const j = r.json ?? {};
  return {
    isError: r.isError,
    project: j.project_root ?? j.project ?? null,
    deps: j.total_dependencies_scanned ?? null,
    head: String(j.summary ?? r.text).slice(0, 200),
  };
}

/** Texts that mean the data folder or the database failed, whatever the release words them as. */
export const BROKEN = /database is locked|SQLITE_BUSY|SQLITE_LOCKED|no such table|may be unsupported or corrupted|no dependency versions could be resolved|Failed to open 4DA database|unable to open database/i;

/** A tech stack, order-free. */
export const stack = (r) => (Array.isArray(r.json?.tech_stack) ? [...r.json.tech_stack].sort().join(",") : null);

/**
 * What each project answers from a single process on a fresh data folder: the tool list of a
 * session started in it, its scan's project and dependency count, and its stack.
 */
export async function baseline(server, work, dirs) {
  const out = {};
  for (const [name, dir] of Object.entries(dirs)) {
    const home = path.join(work, "baseline-home", name);
    const s = await openSession({ server, cwd: dir, env: offlineEnv(home) });
    try {
      const tools = (await s.tools()).sort();
      const scan = scanFacts(await s.call("vulnerability_scan", {}));
      const ctx = await s.call("get_context", {});
      out[name] = { tools: tools.join(","), toolCount: tools.length, scan, stack: stack(ctx) };
    } finally {
      await s.close();
    }
  }
  return out;
}

/** Print the findings, write the result, and exit 1 when there is a violation. */
export function finish(name, opts, result, violations) {
  const body = { harness: name, server: opts.server, violations, ...result };
  if (opts.out) {
    fs.mkdirSync(opts.out, { recursive: true });
    fs.writeFileSync(path.join(opts.out, `${name}.json`), JSON.stringify(body, null, 1));
  }
  console.log(violations.length ? `${name}: FAILED, ${violations.length} violation(s)\n  ${violations.slice(0, 40).join("\n  ")}` : `${name}: OK`);
  process.exitCode = violations.length ? 1 : 0;
}
