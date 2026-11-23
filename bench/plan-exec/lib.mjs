// SPDX-License-Identifier: Apache-2.0
/**
 * The pure parts of the plan-execution harness (run.mjs): which commands it will run and how,
 * which steps a plan gives, lockfile inventories and what changed between two, and the scoring
 * and gate. No process is started here; src/__tests__/a1123-gates-plan-exec.test.ts covers it.
 */
import * as fs from "node:fs";
import * as path from "node:path";

// ============================================================================
// Commands: parsed into argv, checked against what package managers may do, scripts disabled.
// ============================================================================

/** Characters a token may hold. Every token is re-quoted for the shell, so none of these can start another command. */
const SAFE_TOKEN = /^[A-Za-z0-9@^~<>=.:/_+\-,*|[\] ]+$/;

/**
 * Split a command line into `&&`-joined parts of argv tokens. Quotes (single or double) group;
 * an unquoted `;`, `|`, `&` (other than `&&`), `<`, `>`, `$`, backtick or backslash refuses the
 * whole line, as does a token outside SAFE_TOKEN.
 * @returns {{ parts: string[][] } | { refused: string }}
 */
export function tokenize(line) {
  const parts = [[]];
  let token = null;
  let quote = null;
  const push = () => {
    if (token !== null) parts[parts.length - 1].push(token);
    token = null;
  };
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (quote) {
      if (c === quote) quote = null;
      else token = (token ?? "") + c;
      continue;
    }
    if (c === '"' || c === "'") {
      quote = c;
      token = token ?? "";
      continue;
    }
    if (c === " " || c === "\t") {
      push();
      continue;
    }
    if (c === "&" && line[i + 1] === "&") {
      push();
      parts.push([]);
      i++;
      continue;
    }
    if (/[;|&<>$`\\\n\r]/.test(c)) return { refused: `the command has a shell operator (${JSON.stringify(c)}) outside quotes` };
    token = (token ?? "") + c;
  }
  if (quote) return { refused: "the command has an unclosed quote" };
  push();
  if (parts.some((p) => p.length === 0)) return { refused: "the command has an empty part" };
  for (const p of parts) for (const t of p) if (!SAFE_TOKEN.test(t)) return { refused: `the token ${JSON.stringify(t)} has characters this harness does not pass to a shell` };
  return { parts };
}

/** What each package manager may be asked to do here: lockfile and manifest changes only. */
const ALLOWED = {
  npm: ["install", "i", "update", "up", "uninstall", "un", "rm", "remove", "dedupe", "ddp", "pkg"],
  pnpm: ["install", "i", "update", "up", "upgrade", "add", "remove", "rm", "dedupe"],
  yarn: ["", "install", "upgrade", "up", "add", "remove", "dedupe"],
  bun: ["install", "i", "update", "add", "remove"],
  cargo: ["update", "add", "remove", "rm"],
  uv: ["lock", "add", "remove"],
  go: ["get", "mod"],
};
/** Package managers the plan may name that this harness does not run, and why. */
const REFUSED = {
  pip: "pip installs run a package's build code",
  pip3: "pip installs run a package's build code",
  poetry: "poetry can build source distributions to read their metadata, which runs a package's own code",
  npx: "npx runs a package's own code",
};

/**
 * Check one argv part and add the flags that keep package-manager scripts from running.
 * `yarnFlavor` is "classic" or "berry" for the directory the command runs in.
 * @returns {{ argv: string[], added: string[], env: Record<string,string> } | { refused: string }}
 */
export function prepareCommand(argv, { yarnFlavor = "classic" } = {}) {
  const [tool, sub = ""] = argv;
  if (REFUSED[tool]) return { refused: `${tool} is not run: ${REFUSED[tool]}` };
  const allowed = ALLOWED[tool];
  if (!allowed) return { refused: `${tool} is not a package manager this harness runs (it may run a package's own code)` };
  if (!allowed.includes(sub) && !(tool === "yarn" && sub.startsWith("-"))) return { refused: `\`${tool} ${sub}\` is not a lockfile or manifest change this harness runs` };
  if (tool === "npm" && sub === "pkg" && argv[2] !== "set") return { refused: "only `npm pkg set` is run" };
  if (tool === "go" && sub === "mod" && argv[2] !== "tidy") return { refused: "only `go mod tidy` is run" };
  const has = (f) => argv.includes(f);
  const added = [];
  const env = {};
  const add = (...flags) => {
    for (const f of flags) if (!has(f)) added.push(f);
  };
  if (tool === "npm" && sub !== "pkg") add("--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund");
  // A project's .pnpmfile.cjs is its own code: never loaded.
  if (tool === "pnpm") add(...(sub === "dedupe" ? [] : ["--lockfile-only"]), "--ignore-scripts", "--ignore-pnpmfile");
  if (tool === "yarn" && yarnFlavor === "classic") add("--ignore-scripts", "--ignore-engines", "--non-interactive");
  if (tool === "yarn" && yarnFlavor === "berry") {
    if (!has("--mode")) added.push("--mode", "update-lockfile");
    Object.assign(env, { YARN_ENABLE_SCRIPTS: "false", YARN_ENABLE_IMMUTABLE_INSTALLS: "false", YARN_ENABLE_TELEMETRY: "0" });
  }
  if (tool === "bun") add("--ignore-scripts");
  if (tool === "uv") {
    env.UV_NO_BUILD = "1";
    if (sub === "add" || sub === "remove") add("--no-sync");
  }
  if (tool === "go") env.GOFLAGS = "-mod=mod";
  return { argv: [...argv, ...added], added, env };
}

/**
 * One argv as a shell line: every argument double-quoted (SAFE_TOKEN holds nothing a shell
 * expands inside double quotes). The program stays bare: it is a plain allowlisted word, and
 * cmd.exe runs a quoted `.cmd` shim (npm, npx, corepack on Windows) with the wrong `%~dp0`.
 */
export function shellLine(argv) {
  const [program, ...args] = argv;
  if (!/^[A-Za-z0-9._-]+$/.test(program)) throw new Error(`not a plain program name: ${JSON.stringify(program)}`);
  return [program, ...args.map((t) => `"${t}"`)].join(" ");
}

/** The yarn classic refresh the planner gives as prose: "delete every yarn.lock entry that resolves to X ..., then run yarn install". */
export const YARN1_DELETE = /^delete every yarn\.lock entry that resolves to (\S+?)[ ,]/;

/** Remove every yarn.lock (classic) entry of `name`; returns how many were removed. */
export function yarn1DeleteEntries(lockfile, name) {
  const text = fs.readFileSync(lockfile, "utf8").split("\r").join("");
  const blocks = text.split(/\n\n/);
  let removed = 0;
  const keep = blocks.filter((b) => {
    const head = b.split("\n").find((l) => /^\S/.test(l) && !l.startsWith("#"));
    if (!head) return true;
    const keys = head.replace(/:\s*$/, "").split(/,\s*/).map((k) => k.replace(/^"|"$/g, ""));
    const hit = keys.some((k) => {
      const at = k.lastIndexOf("@");
      if (k.slice(0, at > 0 ? at : k.length) === name) return true;
      const alias = /@npm:((?:@[^@]+\/)?[^@]+)@/.exec(k);
      return alias !== null && alias[1] === name;
    });
    if (hit) removed++;
    return !hit;
  });
  fs.writeFileSync(lockfile, keep.join("\n\n"));
  return removed;
}

// ============================================================================
// Steps: what the plan says to run, in its order.
// ============================================================================

export const normName = (ecosystem, name) => (ecosystem === "PyPI" ? String(name).toLowerCase().replace(/[-_.]+/g, "-") : String(name));
export const copyKey = (ecosystem, name, version) => `${ecosystem}|${normName(ecosystem, name)}|${version}`;
export const fixKey = (ecosystem, name) => `${ecosystem}:${normName(ecosystem, name)}`;

/** The plan JSON of an upgrade_planner answer (structuredContent, or the JSON text). */
export function planJson(answer) {
  return answer?.result?.structuredContent ?? (answer?.result?.content?.[0]?.text ? JSON.parse(answer.result.content[0].text) : answer);
}

/** A 6.4.0-era row that is about a known advisory (the audit's selection). */
const legacyVulnerable = (row) => /known vulnerabilit/.test(row.reasons?.[0] ?? "");

/** An `add {"overrides": ...} to <file>[, then <install>]` instruction in a row's reasons. */
export function overrideInstruction(row) {
  const text = (row.reasons ?? []).join(" ");
  const m = text.match(/add (\{?\s*"(?:overrides|resolutions|pnpm)"\s*:\s*\{.*?\}\s*\}?)\s+to\s+(\S+)/);
  if (!m) return null;
  const then = text.match(/then (npm install|pnpm install|yarn install)\b/);
  return { snippet: m[1], file: m[2].replace(/[,.;]$/, ""), then: then ? then[1] : null };
}

/** A command entry of a row as data: `{ dir, run }` (6.5.0) or `{ dir, command }` (6.4.0). */
const asAction = (c) => {
  const run = c.run ?? c.command;
  const del = YARN1_DELETE.exec(run);
  return del ? { type: "yarn1-delete", dir: c.dir ?? ".", name: del[1] } : { type: "run", dir: c.dir ?? ".", run };
};

/**
 * The steps to run, in order, and where they came from:
 * - `run_order`: the plan's own script (`run_order[]` of `{ n, dir, run, fixes }`);
 * - `row_commands`: no `run_order`, but rows carry `commands[]`: each row with commands, in row order;
 * - `legacy_rows`: neither (6.4.0 and older): the audit's extraction from the row fields
 *   (upgradeCommands, refreshCommands, parentUpgrades levers, override snippets in the reasons),
 *   vulnerable rows only, in row order. A baseline mode: its order is the rows' order, which
 *   is what an agent following 6.4.0 row by row would run.
 * Every step carries `fixes` (`ecosystem:package` keys) and the rows it serves.
 */
export function extractSteps(plan) {
  const rows = Array.isArray(plan?.recommendations) ? plan.recommendations : [];
  const rowsByFix = new Map();
  for (const r of rows) {
    const k = fixKey(r.ecosystem, r.package);
    if (!rowsByFix.has(k)) rowsByFix.set(k, []);
    rowsByFix.get(k).push(r);
  }
  if (Array.isArray(plan?.run_order)) {
    const steps = plan.run_order.map((s, i) => {
      const fixes = (Array.isArray(s.fixes) ? s.fixes : []).map((f) => {
        const at = String(f).indexOf(":");
        return at > 0 ? fixKey(f.slice(0, at), f.slice(at + 1)) : String(f);
      });
      return { n: s.n ?? i + 1, fixes, rows: fixes.flatMap((f) => rowsByFix.get(f) ?? []), actions: [asAction(s)] };
    });
    return { source: "run_order", note: plan.run_order_note ?? null, steps, rows };
  }
  if (rows.some((r) => Array.isArray(r.commands))) {
    const steps = rows
      .filter((r) => Array.isArray(r.commands) && r.commands.length > 0)
      .map((r, i) => ({ n: i + 1, fixes: [fixKey(r.ecosystem, r.package)], rows: [r], actions: r.commands.map(asAction) }));
    return { source: "row_commands", note: "the plan has no run_order: each row's commands were run in row order", steps, rows };
  }
  const steps = [];
  for (const r of rows.filter(legacyVulnerable)) {
    const actions = [];
    if (r.action === "upgrade_direct") for (const c of r.upgradeCommands ?? []) actions.push(asAction(c));
    if (r.action === "lockfile_refresh" || (r.action !== "upgrade_direct" && r.refreshCommands)) for (const c of r.refreshCommands ?? []) actions.push(asAction(c));
    if (r.action === "upgrade_parent") {
      for (const p of r.parentUpgrades ?? []) {
        for (const l of p.levers ?? []) for (const c of l.commands ?? []) actions.push(asAction(c));
        for (const c of p.refreshCommands ?? []) actions.push(asAction(c));
      }
    }
    if (r.action === "override_or_replace") {
      const o = overrideInstruction(r);
      if (o) actions.push({ type: "override", dir: ".", file: o.file, snippet: o.snippet, then: o.then });
    }
    steps.push({ n: steps.length + 1, fixes: [fixKey(r.ecosystem, r.package)], rows: [r], actions });
  }
  return {
    source: "legacy_rows",
    note: "BASELINE MODE: the plan has neither run_order nor row commands (6.4.0 or older); steps are the audit's extraction from the vulnerable rows, in row order",
    steps,
    rows,
  };
}

/** Merge an override snippet (`"overrides": {...}` or `{ "resolutions": {...} }`) into a package.json object. */
export function mergeOverride(pkg, snippet) {
  const obj = JSON.parse(snippet.trim().startsWith("{") ? snippet : `{${snippet}}`);
  const merge = (a, b) => {
    for (const [k, v] of Object.entries(b)) a[k] = v && typeof v === "object" && !Array.isArray(v) ? merge(a[k] && typeof a[k] === "object" ? a[k] : {}, v) : v;
    return a;
  };
  return merge(pkg, obj);
}

// ============================================================================
// Inventory: every lockfile under a project, name -> versions, per lockfile directory.
// ============================================================================

const LOCKFILES = {
  "package-lock.json": "npm",
  "npm-shrinkwrap.json": "npm",
  "pnpm-lock.yaml": "npm",
  "yarn.lock": "npm",
  "Cargo.lock": "crates.io",
  "uv.lock": "PyPI",
  "poetry.lock": "PyPI",
  "go.mod": "Go",
};
const SKIP_DIRS = new Set(["node_modules", ".git", "target", ".venv", "venv", "__pycache__", ".yarn", ".pnpm-store"]);

/** Lockfiles under `root` (relative paths, forward slashes), skipping installed trees and build output. */
export function findLockfiles(root) {
  const out = [];
  const walk = (dir) => {
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      if (e.isSymbolicLink()) continue;
      if (e.isDirectory()) {
        if (!SKIP_DIRS.has(e.name)) walk(path.join(dir, e.name));
      } else if (LOCKFILES[e.name]) out.push(path.relative(root, path.join(dir, e.name)).split(path.sep).join("/"));
    }
  };
  walk(root);
  return out.sort();
}

/** `yarn.lock` flavour: berry lockfiles carry `__metadata:`. */
export const yarnFlavorOf = (lockText) => (/^__metadata:/m.test(lockText) ? "berry" : "classic");

/** name -> Set(version) from one lockfile's text. */
export function lockfileVersions(base, text) {
  return new Map([...lockfileCopies(base, text)].map(([n, counts]) => [n, new Set(counts.keys())]));
}

/**
 * name -> (version -> how many copies) from one lockfile's text: one per package-lock entry, pnpm
 * package key, yarn.lock block, Cargo/uv/Poetry `[[package]]` and go.mod requirement. A step that
 * moves one copy of a version another copy keeps (an npm-bundled one) changes the count, not the set.
 */
export function lockfileCopies(base, text) {
  const m = new Map();
  const add = (n, v) => {
    if (!n || !v) return;
    if (!m.has(n)) m.set(n, new Map());
    const counts = m.get(n);
    counts.set(String(v), (counts.get(String(v)) ?? 0) + 1);
  };
  text = text.split("\r").join("");
  if (base === "package-lock.json" || base === "npm-shrinkwrap.json") {
    const j = JSON.parse(text);
    for (const [k, v] of Object.entries(j.packages ?? {})) {
      if (!k || v.link) continue;
      add(v.name ?? k.slice(k.lastIndexOf("node_modules/") + 13), v.version);
    }
    const walkV1 = (deps) => {
      for (const [n, v] of Object.entries(deps ?? {})) {
        add(n, v.version);
        walkV1(v.dependencies);
      }
    };
    if (!j.packages) walkV1(j.dependencies);
  } else if (base === "pnpm-lock.yaml") {
    let inPackages = false;
    for (const line of text.split("\n")) {
      if (/^packages:\s*$/.test(line)) {
        inPackages = true;
        continue;
      }
      if (/^\S/.test(line)) {
        inPackages = false;
        continue;
      }
      if (!inPackages) continue;
      const mm = /^ {2}'?\/?((?:@[^/@\s]+\/)?[^/@\s:']+)[/@]([0-9][^:_('\s]*)/.exec(line);
      if (mm) add(mm[1], mm[2]);
    }
  } else if (base === "yarn.lock") {
    if (/^__metadata:/m.test(text)) {
      for (const mm of text.matchAll(/\n {2}resolution: "((?:@[^@"]+\/)?[^@"]+)@npm:([^"]+)"/g)) add(mm[1], mm[2]);
    } else {
      for (const block of text.split(/\n\s*\n/)) {
        const head = block.split("\n").find((l) => /^\S/.test(l) && !l.startsWith("#"));
        const ver = /\n\s+version "([^"]+)"/.exec("\n" + block)?.[1];
        if (!head || !ver) continue;
        const first = head.replace(/:$/, "").split(/,\s*/)[0].replace(/^"|"$/g, "");
        let name = first.slice(0, first.lastIndexOf("@"));
        const alias = /^((?:@[^@]+\/)?[^@]+)@npm:((?:@[^@]+\/)?[^@]+)@/.exec(first);
        if (alias) name = alias[2];
        add(name || first, ver);
      }
    }
  } else if (base === "Cargo.lock" || base === "uv.lock" || base === "poetry.lock") {
    for (const blk of text.split(/\n\[\[package\]\]\n/).slice(1)) {
      const n = /^name = "([^"]+)"/m.exec(blk)?.[1];
      const v = /^version = "([^"]+)"/m.exec(blk)?.[1];
      const src = /^source = (.*)$/m.exec(blk)?.[1] ?? "";
      if (!n) continue;
      if (base === "Cargo.lock" && !src) continue; // the workspace's own crates
      if (base === "uv.lock" && /editable|virtual|directory/.test(src)) continue;
      add(base === "Cargo.lock" ? n : normName("PyPI", n), v);
    }
  } else if (base === "go.mod") {
    let inRequire = false;
    for (const line of text.split("\n")) {
      const t = line.replace(/\/\/.*$/, "").trim();
      if (/^require\s*\($/.test(t)) {
        inRequire = true;
        continue;
      }
      if (inRequire && t === ")") {
        inRequire = false;
        continue;
      }
      const mm = inRequire ? /^(\S+)\s+(v\S+)/.exec(t) : /^require\s+(\S+)\s+(v\S+)/.exec(t);
      if (mm) add(mm[1], mm[2]);
    }
  }
  return m;
}

/** `ecosystem|lockfile dir|name` -> Set(version), over every lockfile under `root`. */
export function inventory(root) {
  return new Map([...copyInventory(root)].map(([k, counts]) => [k, new Set(counts.keys())]));
}

/** `ecosystem|lockfile dir|name` -> (version -> copies), over every lockfile under `root`. */
export function copyInventory(root) {
  const inv = new Map();
  for (const rel of findLockfiles(root)) {
    const base = path.posix.basename(rel);
    const dir = path.posix.dirname(rel);
    let copies;
    try {
      copies = lockfileCopies(base, fs.readFileSync(path.join(root, rel), "utf8"));
    } catch {
      continue;
    }
    for (const [n, counts] of copies) {
      const k = `${LOCKFILES[base]}|${dir}|${n}`;
      if (!inv.has(k)) inv.set(k, new Map());
      const into = inv.get(k);
      for (const [v, c] of counts) into.set(v, (into.get(v) ?? 0) + c);
    }
  }
  return inv;
}

/** The copy inventory reduced to versions (what `lowerings` and `addedVersions` read). */
export const versionsOf = (copies) => new Map([...copies].map(([k, counts]) => [k, new Set(counts.keys())]));

/**
 * The targets (`{ ecosystem, package, version }`) a step moved: some lockfile holds fewer copies of
 * that version after it than before. A copy the same version keeps elsewhere (npm's bundled
 * brace-expansion beside the hoisted one `npm update` moved) does not hide the move.
 */
export function movedTargets(before, after, targets) {
  return targets.filter((t) => {
    const want = normName(t.ecosystem, t.package);
    for (const [k, counts] of before) {
      const [eco, , n] = splitKey(k);
      if (eco !== t.ecosystem || n !== want) continue;
      const had = counts.get(String(t.version)) ?? 0;
      if (had > 0 && (after.get(k)?.get(String(t.version)) ?? 0) < had) return true;
    }
    return false;
  });
}

/** The targets some lockfile holds a copy of. */
export function presentTargets(copies, targets) {
  return targets.filter((t) => {
    const want = normName(t.ecosystem, t.package);
    for (const [k, counts] of copies) {
      const [eco, , n] = splitKey(k);
      if (eco === t.ecosystem && n === want && (counts.get(String(t.version)) ?? 0) > 0) return true;
    }
    return false;
  });
}

/** A step whose commands all edit a manifest only (`npm pkg set`): it changes no lockfile, and the install after it does. */
export const manifestEdit = (cmds) => cmds.length > 0 && cmds.every((c) => c.exit === 0 && /^npm pkg set /.test(c.run ?? ""));

/** Whether two copy inventories differ at all. */
export function inventoryChanged(before, after) {
  if (before.size !== after.size) return true;
  for (const [k, counts] of before) {
    const other = after.get(k);
    if (!other || other.size !== counts.size) return true;
    for (const [v, c] of counts) if (other.get(v) !== c) return true;
  }
  return false;
}

/**
 * A step's outcome. Without effect: it ran, some of its targets were still there before it, it
 * moved none of them, and either it changed nothing at all or it is the last step serving its rows
 * (a Cargo pre-update that frees the crates a later `--precise` moves has done its part when it
 * changes the lockfile). A step whose targets an earlier step already moved had nothing left to do.
 */
export function stepOutcome({ cmds, targets, pending = targets, moved, changed, laterServesSame }) {
  if (cmds.length === 0) return "nothing_to_run";
  if (cmds.some((c) => c.exit !== undefined && c.exit !== 0)) return "failed";
  if (cmds.some((c) => c.refused)) return "refused";
  if (pending.length > 0 && moved.length === 0 && (!changed || !laterServesSame)) return "without_effect";
  return "worked";
}

/** True when some lockfile under the project still holds `name@version` of `ecosystem`. */
export function presentAnywhere(inv, ecosystem, name, version) {
  const want = normName(ecosystem, name);
  for (const [k, vs] of inv) {
    const [eco, , n] = splitKey(k);
    if (eco === ecosystem && n === want && vs.has(String(version))) return true;
  }
  return false;
}

const splitKey = (k) => {
  const a = k.indexOf("|");
  const b = k.lastIndexOf("|");
  return [k.slice(0, a), k.slice(a + 1, b), k.slice(b + 1)];
};

/**
 * Order two versions loosely across ecosystems (semver, Go's v-prefix and pseudo-versions,
 * PEP 440's common forms): numeric release parts first, then a release beats its pre-release.
 */
export function compareLoose(a, b) {
  const parse = (v) => {
    const m = /^v?(\d+(?:\.\d+)*)(.*)$/.exec(String(v));
    return m ? { nums: m[1].split(".").map(Number), rest: m[2].replace(/^\+.*$/, "") } : { nums: [], rest: String(v) };
  };
  const x = parse(a);
  const y = parse(b);
  for (let i = 0; i < Math.max(x.nums.length, y.nums.length); i++) {
    const d = (x.nums[i] ?? 0) - (y.nums[i] ?? 0);
    if (d !== 0) return d < 0 ? -1 : 1;
  }
  if (x.rest === y.rest) return 0;
  const pre = (r) => r !== "" && !/^\.?post/i.test(r);
  if (x.rest === "") return pre(y.rest) ? 1 : -1;
  if (y.rest === "") return pre(x.rest) ? -1 : 1;
  return x.rest < y.rest ? -1 : 1;
}

/** A version's release line: its major, or major.minor below 1.0 (where a minor bump is a major one). */
export function releaseLine(v) {
  const m = /^v?(\d+)(?:\.(\d+))?/.exec(String(v));
  if (!m) return String(v);
  return m[1] === "0" ? `0.${m[2] ?? "0"}` : m[1];
}

/**
 * The versions one step lowered: a key where the step removed a version, added only lower ones,
 * and left no version at or above it on its release line. Several copies of one package on
 * different lines (semver 5.x, 6.x and 7.x) that each move up their own line, onto versions the
 * lockfile already held, are not a lowering. `earlier` holds what earlier steps set, `initial`
 * what was installed.
 * @returns {Array<{ key: string, from: string, to: string, set_by: "earlier_step" | "installed" | "other" }>}
 */
export function lowerings(before, after, earlier, initial) {
  const out = [];
  for (const k of new Set([...before.keys(), ...after.keys()])) {
    const b = before.get(k) ?? new Set();
    const a = after.get(k) ?? new Set();
    const removed = [...b].filter((v) => !a.has(v));
    const added = [...a].filter((v) => !b.has(v));
    if (removed.length === 0 || added.length === 0) continue;
    // Every added version only moves up a line the lockfile already held: the removed copies left
    // with whatever required them (esbuild 0.15.18's platform packages, once nothing needed 0.15).
    const top = (line) => [...b].filter((v) => releaseLine(v) === line).sort(compareLoose).at(-1);
    if (added.every((v) => top(releaseLine(v)) !== undefined && compareLoose(v, top(releaseLine(v))) >= 0)) continue;
    for (const r of removed) {
      const below = added.filter((v) => compareLoose(v, r) < 0).sort(compareLoose);
      if (below.length === 0 || added.some((v) => compareLoose(v, r) >= 0)) continue;
      if ([...a].some((v) => releaseLine(v) === releaseLine(r) && compareLoose(v, r) >= 0)) continue;
      const lowest = below.at(-1);
      const setBy = earlier.get(k)?.has(r) ? "earlier_step" : initial.get(k)?.has(r) ? "installed" : "other";
      out.push({ key: k, from: r, to: lowest, set_by: setBy });
    }
  }
  return out;
}

/** For the packages a step serves: each lockfile key whose versions it changed, with what left and what came. */
export function changesFor(before, after, step) {
  const names = new Set(step.fixes.map((f) => f.slice(f.indexOf(":") + 1)));
  const out = [];
  for (const k of new Set([...before.keys(), ...after.keys()])) {
    if (!names.has(splitKey(k)[2])) continue;
    const b = before.get(k) ?? new Set();
    const a = after.get(k) ?? new Set();
    const removed = [...b].filter((v) => !a.has(v)).sort(compareLoose);
    const added = [...a].filter((v) => !b.has(v)).sort(compareLoose);
    if (removed.length > 0 || added.length > 0) out.push({ key: k, removed, added, after: [...a].sort(compareLoose) });
  }
  return out;
}

/** Every `+key@version` a step added (for "which step set this"). */
export function addedVersions(before, after) {
  const out = new Map();
  for (const [k, a] of after) {
    const b = before.get(k) ?? new Set();
    for (const v of a) if (!b.has(v)) (out.get(k) ?? out.set(k, new Set()).get(k)).add(v);
  }
  return out;
}

// ============================================================================
// Scans: advisory rows and vulnerable copies of a detailed vulnerability_scan.
// ============================================================================

/** One advisory row's identity: package and every id it is known by. */
const rowIds = (v) => new Set([v.vuln_id, ...(v.aliases ?? [])].filter(Boolean));

/** The vulnerable copies (`ecosystem|name|version`) of a detailed scan's rows. */
export const vulnerableCopies = (rows) => new Set(rows.map((v) => copyKey(v.ecosystem, v.package, v.current_version)));

/**
 * Advisories cleared and introduced between two detailed scans. An advisory of a package is
 * cleared when no copy of that package still carries it (by id or alias), introduced when no
 * copy carried it before.
 */
export function advisoryDelta(beforeRows, afterRows) {
  const index = (rows) => {
    const m = new Map();
    for (const v of rows) {
      const k = `${v.ecosystem}|${normName(v.ecosystem, v.package)}`;
      if (!m.has(k)) m.set(k, []);
      m.get(k).push(rowIds(v));
    }
    return m;
  };
  const B = index(beforeRows);
  const A = index(afterRows);
  const carries = (m, k, ids) => (m.get(k) ?? []).some((s) => [...ids].some((i) => s.has(i)));
  const cleared = [];
  const introduced = [];
  for (const v of beforeRows) if (!carries(A, `${v.ecosystem}|${normName(v.ecosystem, v.package)}`, rowIds(v))) cleared.push(`${copyKey(v.ecosystem, v.package, v.current_version)}|${v.vuln_id}`);
  for (const v of afterRows) if (!carries(B, `${v.ecosystem}|${normName(v.ecosystem, v.package)}`, rowIds(v))) introduced.push(`${copyKey(v.ecosystem, v.package, v.current_version)}|${v.vuln_id}`);
  return { cleared, introduced };
}

/**
 * The plan's prediction against the result. A vulnerable copy is planned to clear when a row
 * for it has something run for it (a step serving that row ran at least one action); every
 * other vulnerable copy is predicted to remain.
 */
export function predictionCheck({ beforeRows, afterRows, steps }) {
  const planned = new Set();
  for (const s of steps) if (s.actions.length > 0) for (const r of s.rows) planned.add(copyKey(r.ecosystem, r.package, r.currentVersion));
  const before = vulnerableCopies(beforeRows);
  const after = vulnerableCopies(afterRows);
  const predictedRemaining = [...before].filter((k) => !planned.has(k));
  const remained = [...before].filter((k) => after.has(k));
  return {
    vulnerable_copies_before: before.size,
    predicted_remaining: predictedRemaining.length,
    remaining: remained.length,
    vulnerable_copies_after: after.size,
    new_vulnerable_copies: [...after].filter((k) => !before.has(k)).length,
    planned_but_remained: remained.filter((k) => planned.has(k)).sort(),
    not_planned_but_cleared: predictedRemaining.filter((k) => !after.has(k)).sort(),
  };
}

// ============================================================================
// Totals and the gate.
// ============================================================================

/** Totals over per-project results (run.mjs writes one per project). */
export function totals(projects) {
  const t = { projects: projects.length, errored: 0, steps: 0, steps_run: 0, steps_failed: 0, steps_refused: 0, steps_without_effect: 0, steps_lowering: 0, steps_lowering_earlier: 0, advisories_before: 0, advisories_after: 0, vulnerable_copies_before: 0, predicted_remaining: 0, remaining: 0, vulnerable_copies_after: 0, order_sources: {} };
  for (const p of projects) {
    if (p.error) {
      t.errored++;
      continue;
    }
    t.order_sources[p.order_source] = (t.order_sources[p.order_source] ?? 0) + 1;
    for (const k of ["steps", "steps_run", "steps_failed", "steps_refused", "steps_without_effect", "steps_lowering", "steps_lowering_earlier"]) t[k] += p.counts[k];
    t.advisories_before += p.advisories.before;
    t.advisories_after += p.advisories.after;
    for (const k of ["vulnerable_copies_before", "predicted_remaining", "remaining", "vulnerable_copies_after"]) t[k] += p.prediction[k];
  }
  t.net_cleared_ratio = t.advisories_before > 0 ? Math.trunc(((t.advisories_before - t.advisories_after) / t.advisories_before) * 10_000) / 10_000 : null;
  return t;
}

/** What the totals break of `thresholds` (bench/plan-exec/thresholds.json); empty when the run passes. */
export function gateFindings(t, thresholds, projects = []) {
  const f = [];
  const max = (key, value, what) => {
    if (typeof thresholds[key] === "number" && value > thresholds[key]) f.push(`${value} ${what} (allowed: ${thresholds[key]})`);
  };
  if (t.errored > 0) f.push(`${t.errored} project(s) could not be run: ${projects.filter((p) => p.error).map((p) => `${p.id} (${p.error})`).join("; ")}`);
  for (const p of projects) if (p.scan_incomplete) f.push(`${p.id}: a scan stayed NOT CHECKED, so its advisory counts are not evidence`);
  max("max_failed_steps", t.steps_failed, "step(s) failed");
  max("max_lowering_steps", t.steps_lowering, "step(s) lowered a version that was installed or that an earlier step set");
  max("max_refused_steps", t.steps_refused, "step(s) named a command this harness does not run");
  if (typeof thresholds.min_net_cleared_ratio === "number" && (t.net_cleared_ratio ?? 0) < thresholds.min_net_cleared_ratio) {
    f.push(`advisories ${t.advisories_before} -> ${t.advisories_after}: ${t.net_cleared_ratio} cleared, below ${thresholds.min_net_cleared_ratio}`);
  }
  if (thresholds.require_order_source) {
    const other = Object.entries(t.order_sources).filter(([s]) => s !== thresholds.require_order_source);
    if (other.length > 0) f.push(`plans without ${thresholds.require_order_source}: ${other.map(([s, n]) => `${n} from ${s}`).join(", ")}`);
  }
  return f;
}
