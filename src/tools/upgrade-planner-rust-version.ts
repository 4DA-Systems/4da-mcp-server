// SPDX-License-Identifier: Apache-2.0
/**
 * A Cargo project that declares `rust-version` (its MSRV) promises to build with that Rust. A plan
 * step that installs a crate release whose own rust-version is newer breaks the promise: bat
 * v0.23.0 declares rust-version 1.64, and its plan moved time 0.3.14 to 0.3.47 with
 * `cargo update -p time@0.3.14 --precise 0.3.47`; time 0.3.47 declares rust-version 1.88 (blind
 * check 1 of 6.5.0, SF2). `--precise` and `cargo add x@version` install the release whatever
 * rust-version says (Cargo's MSRV-aware resolver, resolver "3", only steers a plain `cargo
 * update`), and the build then fails on the declared Rust.
 *
 * For each crates.io release a row installs (its target, per command directory, or the release a
 * range command installs; each lever release of a parent upgrade): its rust-version from the
 * sparse index (the record the fix paths already read, cached; public crates only, as every
 * crates.io lookup) against the rust-version the manifest of the command's directory declares
 * (`[package] rust-version`, or `rust-version.workspace = true` from the workspace's
 * `[workspace.package]`; at a virtual workspace root, `[workspace.package] rust-version`). Newer:
 * `needsNewerRust` names it and a reason says what to do; the step and its command stay, since
 * the release does fix what the row says and builds on a newer Rust. The target is not moved to an
 * older release: it is already the smallest that clears the row's advisories, and a crate's
 * rust-version in practice only rises with its releases.
 *
 * Said only where both are known: no declared rust-version, or a release that declares none, says
 * nothing. A release whose rust-version could not be read beside a declared one is said as not
 * checked.
 */

import { existsSync, readFileSync, statSync } from "node:fs";
import * as path from "node:path";
import type { LiveIntelligence } from "../live/index.js";
import { yieldIfDue } from "../live/yield-point.js";

/** One release a step installs that needs a newer Rust than the manifest declares. */
export interface RustVersionNeed {
  crate: string;
  version: string;
  /** The Rust the release declares it needs (its rust-version). */
  needs: string;
  /** The rust-version the manifest declares. */
  declared: string;
  /** The manifest that declares it, relative to the project root ("Cargo.toml", "crates/a/Cargo.toml"). */
  manifest: string;
}

/** How a reason this pass writes starts. */
export const RUST_VERSION_REASON = "Rust version: ";

type Command = { dir: string; command?: string; instruction?: string; installs?: string };
type Lever = { name: string; to: string | null; commands?: Command[]; instructions?: Command[] };

/** The row fields this pass reads and writes (upgrade_planner's row, structurally). */
export interface RustVersionRow {
  package: string;
  ecosystem: string;
  currentVersion: string | null;
  targetVersion: string | null;
  action: string;
  reasons: string[];
  upgradeCommands?: Command[];
  upgradeInstructions?: Command[];
  refreshCommands?: Command[];
  parentUpgrades?: Array<{ levers: Lever[]; refreshCommands?: Command[] }>;
  needsNewerRust?: RustVersionNeed[];
}

type Intel = Pick<LiveIntelligence, "getFixPathSources" | "getResolvedDeps">;

/** Rows whose target no step installs now. */
const NOTHING_INSTALLED = new Set(["no_fix_available", "hold_current", "remove_dependency", "not_determined", "waiting_on_upstream"]);

/** Time this pass may spend reading crates' index records it does not have yet. */
const READ_BUDGET_MS = 4_000;

const RUST_VERSION = /^(\d{1,4})\.(\d{1,4})(?:\.(\d{1,4}))?$/;

/** Whether Rust `needs` is newer than `declared` ("1.88.0" vs "1.64"); null when either is not a Rust version. */
export function rustNewer(needs: string, declared: string): boolean | null {
  const a = RUST_VERSION.exec(needs.trim());
  const b = RUST_VERSION.exec(declared.trim());
  if (!a || !b) return null;
  for (let i = 1; i <= 3; i++) {
    const d = Number(a[i] ?? 0) - Number(b[i] ?? 0);
    if (d !== 0) return d > 0;
  }
  return false;
}

interface ManifestFields {
  /** `[package] rust-version = "..."`. */
  own: string | null;
  /** `rust-version.workspace = true` (or `{ workspace = true }`) in `[package]`. */
  inherits: boolean;
  /** `[workspace.package] rust-version = "..."`. */
  workspace: string | null;
  hasPackage: boolean;
  hasWorkspace: boolean;
}

/** The rust-version fields of a Cargo.toml's text (a line reader: the keys are plain and one per line). */
export function rustVersionFields(text: string): ManifestFields {
  const out: ManifestFields = { own: null, inherits: false, workspace: null, hasPackage: false, hasWorkspace: false };
  let table = "";
  const value = (line: string) => /^\s*rust-version\s*=\s*["']([^"']*)["']/.exec(line)?.[1]?.trim() ?? null;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.replace(/^﻿/, "");
    if (/^\s*\[\[/.test(line)) {
      table = "[[array]]";
      continue;
    }
    const header = /^\s*\[([^\]]+)\]\s*(?:#.*)?$/.exec(line);
    if (header) {
      table = header[1].replace(/["'\s]/g, "");
      if (table === "package") out.hasPackage = true;
      if (table === "workspace" || table.startsWith("workspace.")) out.hasWorkspace = true;
      continue;
    }
    if (table === "") {
      // Dotted keys at the top: `package.rust-version = "1.64"`, `workspace.package.rust-version = ...`.
      const dotted = /^\s*(package|workspace\s*\.\s*package)\s*\.\s*rust-version\s*=\s*["']([^"']*)["']/.exec(line);
      if (dotted) {
        if (dotted[1] === "package") (out.hasPackage = true), (out.own = dotted[2].trim());
        else (out.hasWorkspace = true), (out.workspace = dotted[2].trim());
      }
      if (/^\s*package\s*\.\s*rust-version\s*\.\s*workspace\s*=\s*true\b/.test(line)) (out.hasPackage = true), (out.inherits = true);
    } else if (table === "package") {
      const v = value(line);
      if (v !== null) out.own = v;
      if (/^\s*rust-version\s*(?:\.\s*workspace\s*=\s*true\b|=\s*\{[^}]*\bworkspace\s*=\s*true\b)/.test(line)) out.inherits = true;
    } else if (table === "workspace.package") {
      const v = value(line);
      if (v !== null) out.workspace = v;
    }
  }
  return out;
}

function readManifest(file: string): string | null {
  try {
    if (!existsSync(file) || statSync(file).size > 4 * 1024 * 1024) return null;
    return readFileSync(file, "utf8");
  } catch {
    return null;
  }
}

/**
 * The rust-version the Cargo.toml in `dir` declares, with the manifest that holds it, or null when
 * it declares none (or it is not a Rust version). A member that inherits it reads the nearest
 * workspace root at or above it.
 */
export function declaredRustVersion(dir: string): { version: string; manifest: string } | null {
  const file = path.join(dir, "Cargo.toml");
  const text = readManifest(file);
  if (text === null) return null;
  const own = rustVersionFields(text);
  const ok = (version: string | null, manifest: string) => (version && RUST_VERSION.test(version) ? { version, manifest } : null);
  if (own.own !== null) return ok(own.own, file);
  if (own.inherits) {
    if (own.hasWorkspace) return ok(own.workspace, file);
    let up = path.dirname(dir);
    for (let i = 0; i < 8 && up !== path.dirname(up); i++, up = path.dirname(up)) {
      const rootFile = path.join(up, "Cargo.toml");
      const rootText = readManifest(rootFile);
      if (rootText === null) continue;
      const ws = rustVersionFields(rootText);
      if (ws.hasWorkspace) return ok(ws.workspace, rootFile);
    }
    return null;
  }
  // A virtual workspace root: the rust-version its members share.
  if (!own.hasPackage && own.workspace !== null) return ok(own.workspace, file);
  return null;
}

/** The releases a row installs, each with the directories its commands run in. */
function installsOf(row: RustVersionRow, root: string, intel: Intel): Array<{ crate: string; version: string; dirs: string[] }> {
  const out = new Map<string, { crate: string; version: string; dirs: Set<string> }>();
  const add = (crate: string, version: string | null | undefined, dir: string) => {
    if (!version) return;
    const k = `${crate}\0${version}`;
    const e = out.get(k) ?? { crate, version, dirs: new Set<string>() };
    e.dirs.add(dir);
    out.set(k, e);
  };
  const target = row.targetVersion;
  let placed = false;
  for (const c of row.upgradeCommands ?? []) (add(row.package, c.installs ?? target, c.dir), (placed = true));
  for (const c of [...(row.upgradeInstructions ?? []), ...(row.refreshCommands ?? [])]) (add(row.package, target, c.dir), (placed = true));
  for (const u of row.parentUpgrades ?? []) {
    for (const c of u.refreshCommands ?? []) (add(row.package, target, c.dir), (placed = true));
    for (const lever of u.levers) {
      if (!lever.to) continue;
      for (const c of [...(lever.commands ?? []), ...(lever.instructions ?? [])]) add(lever.name, c.installs ?? lever.to, c.dir);
    }
  }
  // A row with a target and no command yet (a newer release of a direct dependency): where the copy is declared.
  if (!placed && target) {
    const dirs = intel
      .getResolvedDeps()
      .filter((d) => d.ecosystem === "crates.io" && d.name === row.package && d.version === row.currentVersion)
      .flatMap((d) => d.sourceDirs ?? []);
    for (const d of dirs.length > 0 ? dirs : [root]) add(row.package, target, relativeDir(d, root));
  }
  return [...out.values()].map((e) => ({ crate: e.crate, version: e.version, dirs: [...e.dirs] }));
}

function relativeDir(dir: string, root: string): string {
  const rel = path.relative(root, path.resolve(root, dir)).replace(/\\/g, "/");
  return rel === "" ? "." : rel;
}

async function settle<T>(work: Promise<T>, deadline: number): Promise<T | null> {
  const left = deadline - Date.now();
  if (left <= 0) return null;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const late = new Promise<null>((resolve) => {
    timer = setTimeout(() => resolve(null), left);
    timer.unref?.();
  });
  try {
    return await Promise.race([work.catch(() => null), late]);
  } finally {
    clearTimeout(timer);
  }
}

/** Each crates.io row's releases that need a newer Rust than the project declares: `needsNewerRust` and a reason. */
export async function withRustVersions(rows: RustVersionRow[], root: string, intel: Intel, budgetMs = READ_BUDGET_MS): Promise<void> {
  const sources = intel.getFixPathSources();
  if (!sources) return;
  const deadline = Date.now() + budgetMs;
  const declaredAt = new Map<string, ReturnType<typeof declaredRustVersion>>();
  const declared = (dir: string) => {
    if (!declaredAt.has(dir)) declaredAt.set(dir, declaredRustVersion(path.resolve(root, dir)));
    return declaredAt.get(dir)!;
  };
  const records = new Map<string, Promise<Record<string, string> | null>>();
  const rustVersionsOf = (crate: string) => {
    if (!records.has(crate)) {
      records.set(
        crate,
        (async () => {
          const cached = await settle(sources.cratesSparse(crate), deadline);
          if (cached?.rustVersions) return cached.rustVersions;
          // A record cached before rust-version was read carries none: read the index again.
          return (await settle(sources.cratesSparse(crate, true), deadline))?.rustVersions ?? null;
        })(),
      );
    }
    return records.get(crate)!;
  };
  for (const row of rows) {
    if (row.ecosystem !== "crates.io" || !row.targetVersion || NOTHING_INSTALLED.has(row.action)) continue;
    await yieldIfDue();
    const said = new Set(row.reasons);
    const say = (text: string) => {
      if (!said.has(text)) row.reasons.push(text);
      said.add(text);
    };
    for (const { crate, version, dirs } of installsOf(row, root, intel)) {
      const decl = dirs.map((d) => ({ dir: d, at: declared(d) })).filter((x) => x.at !== null);
      if (decl.length === 0) continue;
      const rv = await rustVersionsOf(crate);
      for (const { at } of decl) {
        const manifest = relativeDir(path.dirname(at!.manifest), root) === "." ? "Cargo.toml" : `${relativeDir(path.dirname(at!.manifest), root)}/Cargo.toml`;
        if (rv === null) {
          say(`${RUST_VERSION_REASON}whether ${crate} ${version} builds with Rust ${at!.version} (rust-version in ${manifest}) was not checked: the crates.io index could not be read in this call, so check its rust-version before running this step`);
          continue;
        }
        const needs = rv[version];
        if (!needs || rustNewer(needs, at!.version) !== true) continue;
        const need: RustVersionNeed = { crate, version, needs, declared: at!.version, manifest };
        const list = (row.needsNewerRust ??= []);
        if (!list.some((n) => n.crate === crate && n.version === version && n.manifest === manifest)) list.push(need);
        say(
          `${RUST_VERSION_REASON}${crate} ${version} needs Rust ${needs} (its rust-version on crates.io), and ${manifest} declares rust-version ${at!.version}: after this step the project no longer builds with Rust ${at!.version}. ` +
            `\`cargo update --precise\` and \`cargo add\` with a version install it anyway (Cargo's MSRV-aware resolver, resolver "3", steers only a plain \`cargo update\`), and the build then fails on Rust ${at!.version}. ` +
            `Raise rust-version to ${needs} or later (and the toolchain that checks it) before this step, or leave the step out`,
        );
      }
    }
  }
}

/** The summary's sentence for the rows `withRustVersions` flagged, or null. */
export function rustVersionSummary(rows: RustVersionRow[]): string | null {
  const n = rows.filter((r) => (r.needsNewerRust?.length ?? 0) > 0).length;
  if (n === 0) return null;
  return `${n} row${n === 1 ? " plans" : "s plan"} a crate release that needs a newer Rust than the project's rust-version (needsNewerRust names the crate, the Rust it needs and the manifest): after ${n === 1 ? "it" : "them"} the project no longer builds with the Rust it declares, so raise rust-version first or leave ${n === 1 ? "it" : "them"} out`;
}

/** run_order_note's sentence for the steps that serve a flagged row, or null. */
export function rustVersionRunOrderNote(rows: RustVersionRow[], runOrder: Array<{ n: number; fixes: string[] }>): string | null {
  const flagged = new Set(rows.filter((r) => (r.needsNewerRust?.length ?? 0) > 0).map((r) => `${r.ecosystem}:${r.package}`));
  if (flagged.size === 0) return null;
  const steps = runOrder.filter((s) => s.fixes.some((f) => flagged.has(f))).map((s) => s.n);
  if (steps.length === 0) return null;
  return `Step${steps.length === 1 ? "" : "s"} ${steps.join(", ")} install${steps.length === 1 ? "s" : ""} a crate release that needs a newer Rust than its rust-version declares (needsNewerRust on the row): the project no longer builds with its declared Rust after ${steps.length === 1 ? "it" : "them"}.`;
}
