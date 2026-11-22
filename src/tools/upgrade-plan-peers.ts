// SPDX-License-Identifier: Apache-2.0
/**
 * Peer ranges installed packages declare, read from the lockfile where its format records them
 * (package-lock v2/v3 `packages`, pnpm `packages:`, Yarn Berry entries), for run_order's rule that
 * a target leaving a peer range an installed direct dependency holds never runs on its own: vite
 * 6.4.5 against @vitejs/plugin-react-swc 3.5.0's peer "^4 || ^5" exited 0 with a warning, and the
 * next eight npm commands of the plan failed with ERESOLVE.
 *
 * Package-lock v1 and Yarn classic record no peer ranges: nothing is said for them. No network.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { parsePnpmKey } from "../live/js-lockfile-readers.js";
import { requirementAdmits } from "../live/refresh-rule.js";

export interface PeerHolder {
  holder: string;
  holderVersion: string;
  range: string;
}

/** dependency name -> the installed packages that declare a peer range on it. */
export type PeerIndex = Map<string, PeerHolder[]>;

function push(index: PeerIndex, dep: string, h: PeerHolder): void {
  const list = index.get(dep);
  if (list) list.push(h);
  else index.set(dep, [h]);
}

const unquote = (s: string) => s.trim().replace(/^['"]|['"]$/g, "");

/** package-lock.json v2/v3: every `packages` entry's peerDependencies. */
function packageLockPeers(content: string): PeerIndex {
  const index: PeerIndex = new Map();
  let lock: { packages?: Record<string, { name?: string; version?: string; peerDependencies?: Record<string, unknown> }> };
  try {
    lock = JSON.parse(content);
  } catch {
    return index;
  }
  for (const [where, entry] of Object.entries(lock.packages ?? {})) {
    if (!where || !entry?.peerDependencies || typeof entry.version !== "string") continue;
    const at = where.lastIndexOf("node_modules/");
    const holder = entry.name ?? (at >= 0 ? where.slice(at + "node_modules/".length) : null);
    if (!holder) continue;
    for (const [dep, range] of Object.entries(entry.peerDependencies)) if (typeof range === "string") push(index, dep, { holder, holderVersion: entry.version, range });
  }
  return index;
}

/** pnpm-lock.yaml: the `peerDependencies:` block of each `packages:` entry (v5, v6 and v9 keys). */
function pnpmPeers(content: string): PeerIndex {
  const index: PeerIndex = new Map();
  let inPackages = false;
  let entry: [string, string] | null = null;
  let inPeers = false;
  for (const line of content.split(/\r?\n/)) {
    if (/^\S/.test(line)) {
      inPackages = line.trimEnd() === "packages:";
      entry = null;
      inPeers = false;
      continue;
    }
    if (!inPackages) continue;
    const top = /^ {2}(\S.*):\s*$/.exec(line);
    if (top) {
      entry = parsePnpmKey(top[1]);
      inPeers = false;
      continue;
    }
    const field = /^ {4}(\S[^:]*):/.exec(line);
    if (field) {
      inPeers = field[1] === "peerDependencies";
      continue;
    }
    const item = /^ {6}('[^']+'|"[^"]+"|[^\s:]+):\s*(.+)$/.exec(line);
    if (item && inPeers && entry) push(index, unquote(item[1]), { holder: entry[0], holderVersion: entry[1], range: unquote(item[2]) });
  }
  return index;
}

/** Yarn Berry yarn.lock: each entry's `peerDependencies:` block, named by its `resolution:`. */
function berryPeers(content: string): PeerIndex {
  const index: PeerIndex = new Map();
  for (const block of content.split(/\r?\n(?=\S)/)) {
    const resolution = /^ {2}resolution: "?((?:@[^\s/@"]+\/)?[^\s/@"]+)@npm:([^"\s]+)"?/m.exec(block);
    if (!resolution) continue;
    const peers = /^ {2}peerDependencies:\r?\n((?: {4}.*\r?\n?)+)/m.exec(block);
    if (!peers) continue;
    for (const line of peers[1].split(/\r?\n/)) {
      const item = /^ {4}('[^']+'|"[^"]+"|[^\s:]+):\s*(.+)$/.exec(line);
      if (item) push(index, unquote(item[1]), { holder: resolution[1], holderVersion: resolution[2], range: unquote(item[2]) });
    }
  }
  return index;
}

/** The peer ranges a lockfile records; empty for a format that records none or a file that cannot be read. */
export function lockfilePeers(lockfile: string): PeerIndex {
  let content: string;
  try {
    content = fs.readFileSync(lockfile, "utf-8");
  } catch {
    return new Map();
  }
  const base = path.basename(lockfile);
  if (base === "package-lock.json" || base === "npm-shrinkwrap.json") return packageLockPeers(content);
  if (base === "pnpm-lock.yaml") return pnpmPeers(content);
  if (base === "yarn.lock" && /^__metadata:/m.test(content)) return berryPeers(content);
  return new Map();
}

export interface PeerContext {
  root: string;
  /** The npm-family lockfile that holds the project at an absolute directory, or null. */
  lockfileFor: (dir: string) => string | null;
  /** Whether `name@version` is a direct dependency the project declares. */
  isDirect: (name: string, version: string) => boolean;
}

/**
 * Why setting `pkg` to `version` in `dir` breaks a peer range an installed direct dependency
 * declares on it, or null. Read once per lockfile per plan.
 */
export function peerConflictReader(ctx: PeerContext): (dir: string, pkg: string, version: string) => string | null {
  const indexes = new Map<string, PeerIndex>();
  return (dir, pkg, version) => {
    const lockfile = ctx.lockfileFor(path.resolve(ctx.root, dir));
    if (!lockfile) return null;
    let index = indexes.get(lockfile);
    if (!index) {
      index = lockfilePeers(lockfile);
      indexes.set(lockfile, index);
    }
    const held = (index.get(pkg) ?? []).filter(
      (h) => h.holder !== pkg && ctx.isDirect(h.holder, h.holderVersion) && requirementAdmits({ parent: h.holder, text: h.range, dialect: "npm" }, version) === false,
    );
    if (held.length === 0) return null;
    const who = [...new Set(held.map((h) => `${h.holder} ${h.holderVersion} declares "${h.range}"`))].join(", ");
    const names = [...new Set(held.map((h) => h.holder))].join(", ");
    return `${pkg} ${version} leaves a peer range an installed direct dependency holds on it (${who}): installing it alone breaks ${names}, and npm then refuses later installs with ERESOLVE. Upgrade ${names} in the same command to a release whose peer range admits ${pkg} ${version}; no such release was read in this call, so this step is left out of run_order`;
  };
}
