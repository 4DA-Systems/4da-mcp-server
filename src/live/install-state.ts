// SPDX-License-Identifier: Apache-2.0
/**
 * Install drift: what node_modules holds versus what the lockfile pins.
 *
 * Measured 2026-09-10: mcp-4da-server/pnpm-lock.yaml pinned hono 4.13.5 (PR
 * #632, the fix for CVE-2026-84363/-84364/-84365) while
 * mcp-4da-server/node_modules/hono held 4.13.1 for 25 days, because
 * activation ran `pnpm install` only at the repo root. Every 4DA surface
 * reported hono fixed, because every surface read the lockfile. A lockfile
 * says what SHOULD be installed; only node_modules says what IS, and the
 * installed copy is the one that runs.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { fileSignature, type FileSignature } from "./file-signature.js";
import type { InstallDriftRecord, InstallFixCommand, ResolvedDependency } from "./types.js";

/** Parent directories the lookup may climb for hoisted workspaces. */
const MAX_PARENT_LEVELS = 6;

/**
 * Files an install rewrites (pnpm, npm >= 7, yarn 1, yarn berry's
 * node-modules linker). A change to one is how a reinstall that fixes drift,
 * without touching the lockfile, gets noticed.
 */
const INSTALL_MARKERS = [".modules.yaml", ".package-lock.json", ".yarn-integrity", ".yarn-state.yml"];

/** The reinstall command for the lockfile a directory resolved from, or null for a non-npm file. */
export function installFixFor(lockfilePath: string): InstallFixCommand | null {
  switch (path.basename(lockfilePath)) {
    case "pnpm-lock.yaml":
      return "pnpm install";
    // Round 19, Q1: npm-shrinkwrap.json is a lockfile too (npm ci reads it).
    case "package-lock.json":
    case "npm-shrinkwrap.json":
      return "npm ci";
    case "yarn.lock":
      return "yarn install";
    case "bun.lock":
      return "bun install";
    default:
      return null;
  }
}

function isDirectory(p: string): boolean {
  try {
    return fs.statSync(p).isDirectory();
  } catch {
    return false;
  }
}

/**
 * The directories a lookup from `dir` visits, nearest first: `dir`, then its
 * parents, stopping at the directory that holds `.git` (the repository root)
 * or after MAX_PARENT_LEVELS parents.
 */
function lookupChain(dir: string): string[] {
  const chain: string[] = [];
  let current = path.resolve(dir);
  for (let level = 0; level <= MAX_PARENT_LEVELS; level++) {
    chain.push(current);
    if (fs.existsSync(path.join(current, ".git"))) break;
    const parent = path.dirname(current);
    if (parent === current) break;
    current = parent;
  }
  return chain;
}

/**
 * `<d>/node_modules/<name>/package.json` for the nearest `d` in the lookup
 * chain that has it (scoped names included), or null. This is the copy
 * Node's resolver would load from `dir`.
 */
export function findInstalledManifest(dir: string, name: string, chain: string[] = lookupChain(dir)): string | null {
  for (const d of chain) {
    const candidate = path.join(d, "node_modules", ...name.split("/"), "package.json");
    if (fs.existsSync(candidate)) return candidate;
  }
  return null;
}

function readManifestVersion(manifest: string): string | null {
  try {
    const parsed = JSON.parse(fs.readFileSync(manifest, "utf-8")) as { version?: unknown };
    const version = typeof parsed.version === "string" ? parsed.version.trim() : "";
    return version || null;
  } catch {
    return null;
  }
}

/** The installed version of `name` as seen from `dir`, or null when not installed or unreadable. Never throws. */
export function readInstalledVersion(dir: string, name: string): string | null {
  const manifest = findInstalledManifest(dir, name);
  return manifest ? readManifestVersion(manifest) : null;
}

/**
 * Round 19, Q1: the direct dependencies a folder's package.json declares, in every section (dependencies, devDependencies,
 * optionalDependencies, peerDependencies), as folder key -> package name: an npm alias (`"cart": "npm:qzx-cart-kit@1.0.2"`)
 * is installed under its key (node_modules/cart), and is the package it names.
 */
function manifestDirect(dir: string): Map<string, string> {
  const out = new Map<string, string>();
  try {
    const pj = JSON.parse(fs.readFileSync(path.join(dir, "package.json"), "utf-8")) as Record<string, unknown>;
    for (const section of ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"]) {
      const deps = pj[section];
      if (!deps || typeof deps !== "object") continue;
      for (const [key, spec] of Object.entries(deps as Record<string, unknown>)) {
        const alias = typeof spec === "string" ? /^npm:((?:@[^/@]+\/)?[^@]+)@/.exec(spec) : null;
        if (!out.has(key)) out.set(key, alias ? alias[1] : key);
      }
    }
  } catch {
    // No readable package.json: the lockfile's own direct flags are all there is.
  }
  return out;
}

export interface InstallCheck {
  /** The direct deps with `installedVersion` filled in; a new array, inputs untouched. */
  resolved: ResolvedDependency[];
  /** One record per direct dep whose installed copy differs from its lockfile version. */
  drift: InstallDriftRecord[];
  /** Audit entries for installed versions the lockfile does not pin, flagged `installDriftOf`. */
  driftAuditDeps: ResolvedDependency[];
  /** Signatures, taken BEFORE reading, of every file whose change means the install state moved. */
  signatures: Map<string, FileSignature>;
}

/**
 * Compare each npm direct dependency's lockfile version with node_modules.
 *
 * Skipped entirely when `dir` has no node_modules of its own: a checkout that
 * was never installed has no installed copy to disagree with the lockfile,
 * and borrowing a parent project's node_modules would compare against a
 * different project's install. The node_modules path is still tracked, so an
 * install that creates it is noticed.
 */
export function checkInstallState(
  dir: string,
  resolved: ResolvedDependency[],
  lockfilePath: string,
  /** Round 19, Q1: the lockfile's versions by name, for a direct name (optional, peer) the resolved list does not hold. */
  lockVersions: ReadonlyMap<string, string> = new Map(),
): InstallCheck {
  const nodeModules = path.join(dir, "node_modules");
  const signatures = new Map<string, FileSignature>([[nodeModules, fileSignature(nodeModules)]]);
  const fix = installFixFor(lockfilePath);
  if (!fix || !isDirectory(nodeModules)) {
    return { resolved, drift: [], driftAuditDeps: [], signatures };
  }

  const chain = lookupChain(dir);
  for (const d of chain) {
    const nm = path.join(d, "node_modules");
    if (!isDirectory(nm)) continue;
    signatures.set(nm, fileSignature(nm));
    for (const marker of INSTALL_MARKERS) {
      const markerPath = path.join(nm, marker);
      signatures.set(markerPath, fileSignature(markerPath));
    }
  }

  const drift: InstallDriftRecord[] = [];
  const driftAuditDeps: ResolvedDependency[] = [];
  // Round 19, Q1: every section's names are direct (optional and peer too), each read under its own folder key.
  const declared = manifestDirect(dir);
  const keysOf = new Map<string, string[]>();
  for (const [key, name] of declared) keysOf.set(name, [...(keysOf.get(name) ?? []), key]);
  const seenKeys = new Set<string>();
  const checked = resolved.map((dep) => {
    if (dep.ecosystem !== "npm" || !dep.version) return dep;
    const keys = (keysOf.get(dep.name) ?? (dep.isDirect ? [dep.name] : [])).filter((k) => !seenKeys.has(k));
    if (keys.length === 0) return dep;
    for (const k of keys) seenKeys.add(k);
    let result: ResolvedDependency = dep;
    for (const key of keys) result = driftOf(dep, key) ?? result;
    return result;
  });
  // Round 19, Q1: a direct name of the manifest (an optionalDependency, a peerDependency) that the resolved list does not
  // hold: compared with the lockfile's own version of it, for drift only.
  for (const [key, name] of declared) {
    if (seenKeys.has(key) || resolved.some((d) => d.name === name)) continue;
    const version = lockVersions.get(name) ?? lockVersions.get(name.toLowerCase());
    if (!version) continue;
    seenKeys.add(key);
    driftOf({ name, version, ecosystem: "npm", isDev: false, isDirect: true, devScopeKnown: true, target: null, platformActive: true, sourceDirs: [dir] }, key);
  }
  function driftOf(dep: ResolvedDependency, key: string): ResolvedDependency | null {
    const lockVersion = dep.version;
    const command = fix;
    if (!lockVersion || !command) return null;
    const manifest = findInstalledManifest(dir, key, chain);
    if (manifest) signatures.set(manifest, fileSignature(manifest));
    // A leading `v` is not part of the version: @upstash/* publish "v2.0.7",
    // which read as drift from the lockfile's 2.0.7 (audit L1), and would have
    // gone to OSV as "v2.0.7". The 4DA app drops it the same way.
    const raw = manifest ? readManifestVersion(manifest) : null;
    const installedVersion = raw ? raw.trim().replace(/^v(?=\d)/, "") : null;
    if (installedVersion && installedVersion !== lockVersion.replace(/^v(?=\d)/, "")) {
      drift.push({
        package: dep.name,
        dir,
        lockfileVersion: lockVersion,
        installedVersion,
        fix: command,
        isDev: dep.isDev,
      });
      driftAuditDeps.push({
        ...dep,
        version: installedVersion,
        installedVersion,
        installDriftOf: lockVersion,
        installFix: command,
      });
    }
    return { ...dep, installedVersion } as ResolvedDependency;
  }

  return { resolved: checked, drift, driftAuditDeps, signatures };
}
