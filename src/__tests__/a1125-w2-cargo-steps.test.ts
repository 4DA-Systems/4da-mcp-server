// SPDX-License-Identifier: Apache-2.0
/**
 * Wave 2, design 2b (Cargo), from the executed starship v1.0.0 plan (audit 2026-11-25 Track B M2/M3):
 * - `cargo update -p tempfile@3.2.0 --precise 3.4.0` failed on fastrand (3.4.0 needs ^1.6.0, 1.5.0
 *   locked) and chrono 0.4.30 on core-foundation-sys: every `--precise` now gets the pre-update its
 *   target needs, or is words when that cannot be read;
 * - `cargo add git2@0.21.0` failed (libgit2-sys links "git2" on both lines while shadow-rs keeps git2
 *   0.13) and left Cargo.toml edited: no command, words naming the crate to move first;
 * - `crossbeam-utils@0.8.5 --precise 0.8.7` found nothing after crossbeam-epoch's step moved it: a
 *   crate is moved before the crates that depend on it.
 */

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { FixPathSources } from "../live/fix-paths.js";
import { cargoDependencyReader, hasCargoPrecondition, withCargoStepPreconditions, type CargoStepRow } from "../tools/upgrade-planner-cargo-steps.js";
import { buildRunOrder, type SequencedRow } from "../tools/upgrade-plan-sequence.js";

let root: string;
beforeEach(() => {
  root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "4da-w2-cargo-")));
});
afterEach(() => fs.rmSync(root, { recursive: true, force: true }));

type Pkg = { name: string; version: string; deps?: string[]; local?: boolean };
function lock(pkgs: Pkg[]) {
  const body = pkgs
    .map((p) => [
      "[[package]]",
      `name = "${p.name}"`,
      `version = "${p.version}"`,
      ...(p.local ? [] : ['source = "registry+https://github.com/rust-lang/crates.io-index"']),
      ...(p.deps && p.deps.length > 0 ? ["dependencies = [", ...p.deps.map((d) => ` "${d}",`), "]"] : []),
      "",
    ].join("\n"))
    .join("\n");
  fs.writeFileSync(path.join(root, "Cargo.lock"), `version = 3\n\n${body}`);
}

type Sparse = Record<string, { versions: string[]; reqs: Record<string, Record<string, Array<{ req: string; optional: boolean }>>>; links?: Record<string, string>; defaultDeps?: Record<string, string[]> }>;
const sources = (index: Sparse) => ({ cratesSparse: async (name: string) => (index[name] ? { yanked: [], rustVersions: {}, links: {}, ...index[name] } : null) }) as unknown as FixPathSources;
const row = (over: Partial<CargoStepRow>): CargoStepRow => ({ package: "x", ecosystem: "crates.io", currentVersion: "1.0.0", reasons: [], ...over });
const soon = () => Date.now() + 5_000;

describe("every --precise gets the pre-update its target needs", () => {
  it("a parent lever's step: tempfile 3.4.0 needs fastrand ^1.6.0 while 1.5.0 is locked", async () => {
    lock([
      { name: "app", version: "0.1.0", deps: ["tempfile", "other"], local: true },
      { name: "tempfile", version: "3.2.0", deps: ["remove_dir_all"] },
      { name: "remove_dir_all", version: "0.5.3" },
      { name: "other", version: "1.0.0", deps: ["fastrand"] },
      { name: "fastrand", version: "1.5.0" },
    ]);
    const index: Sparse = {
      tempfile: { versions: ["3.2.0", "3.4.0"], reqs: { "3.4.0": { fastrand: [{ req: "^1.6.0", optional: false }] } } },
      fastrand: { versions: ["1.5.0", "1.6.0", "1.9.0"], reqs: { "1.9.0": {} } },
    };
    const r = row({
      package: "remove_dir_all",
      currentVersion: "0.5.3",
      parentUpgrades: [{ levers: [{ name: "tempfile", version: "3.2.0", to: "3.4.0", commands: [{ dir: ".", command: "cargo update -p tempfile@3.2.0 --precise 3.4.0" }] }] }],
    });
    await withCargoStepPreconditions([r], root, sources(index), soon());
    expect(r.parentUpgrades![0].levers[0].commands).toEqual([{ dir: ".", command: "cargo update -p fastrand@1.5.0 && cargo update -p tempfile@3.2.0 --precise 3.4.0" }]);
    expect(hasCargoPrecondition(r)).toBe(false);
  });

  it("a direct upgrade's step: chrono 0.4.30 brings in iana-time-zone, which needs core-foundation-sys ^0.8.3", async () => {
    lock([
      { name: "app", version: "0.1.0", deps: ["chrono", "sysinfo"], local: true },
      { name: "chrono", version: "0.4.19" },
      { name: "sysinfo", version: "0.20.0", deps: ["core-foundation-sys"] },
      { name: "core-foundation-sys", version: "0.8.2" },
    ]);
    const index: Sparse = {
      // As the index has it: optional, and turned on by chrono's default `clock` feature.
      chrono: { versions: ["0.4.19", "0.4.30"], reqs: { "0.4.30": { "iana-time-zone": [{ req: "^0.1.45", optional: true }] } }, defaultDeps: { "0.4.30": ["iana-time-zone"] } },
      "iana-time-zone": { versions: ["0.1.45", "0.1.60"], reqs: { "0.1.60": { "core-foundation-sys": [{ req: "^0.8.3", optional: false }] } } },
      "core-foundation-sys": { versions: ["0.8.2", "0.8.7"], reqs: {} },
    };
    const r = row({ package: "chrono", currentVersion: "0.4.19", upgradeCommands: [{ dir: ".", command: "cargo update -p chrono@0.4.19 --precise 0.4.30", refresh: true }] });
    await withCargoStepPreconditions([r], root, sources(index), soon());
    expect(r.upgradeCommands![0].command).toBe("cargo update -p core-foundation-sys@0.8.2 && cargo update -p chrono@0.4.19 --precise 0.4.30");
  });

  it("when what the target requires cannot be read, the step is words with the reason, not a command", async () => {
    lock([{ name: "app", version: "0.1.0", deps: ["regex"], local: true }, { name: "regex", version: "1.5.4" }]);
    const r = row({ package: "regex", currentVersion: "1.5.4", upgradeCommands: [{ dir: ".", command: "cargo update -p regex@1.5.4 --precise 1.5.5" }] });
    await withCargoStepPreconditions([r], root, sources({}), soon());
    expect(r.upgradeCommands).toBeUndefined();
    expect(r.upgradeInstructions?.[0].instruction).toMatch(/^no command: `cargo update -p regex@1\.5\.4 --precise 1\.5\.5`: what regex 1\.5\.5 requires could not be compared/);
    expect(hasCargoPrecondition(r)).toBe(true);
  });

  it("a step that already carries its pre-update is left as it is", async () => {
    lock([{ name: "app", version: "0.1.0", local: true }]);
    const cmd = "cargo update -p quote@1.0.9 && cargo update -p openssl@0.10.36 --precise 0.10.80";
    const r = row({ refreshCommands: [{ dir: ".", command: cmd }] });
    await withCargoStepPreconditions([r], root, sources({}), soon());
    expect(r.refreshCommands).toEqual([{ dir: ".", command: cmd }]);
  });
});

describe("a cargo add whose two lines would link one native library", () => {
  const graph = () =>
    lock([
      { name: "starship", version: "1.0.0", deps: ["git2", "shadow-rs"], local: true },
      { name: "shadow-rs", version: "0.7.2", deps: ["git2"] },
      { name: "git2", version: "0.13.23", deps: ["libgit2-sys"] },
      { name: "libgit2-sys", version: "0.12.24+1.3.0" },
    ]);
  const index: Sparse = {
    git2: { versions: ["0.13.23", "0.21.0"], reqs: { "0.21.0": { "libgit2-sys": [{ req: "^0.18.4", optional: false }] } } },
    "libgit2-sys": { versions: ["0.12.24+1.3.0", "0.18.4+1.9.3"], reqs: { "0.18.4+1.9.3": {} }, links: { "0.12.24+1.3.0": "git2", "0.18.4+1.9.3": "git2" } },
  };

  it("git2 0.21 beside shadow-rs's git2 0.13: no command, and the words name the crate to move first", async () => {
    graph();
    const r = row({ package: "git2", currentVersion: "0.13.23", upgradeCommands: [{ dir: ".", command: "cargo add git2@0.21.0" }] });
    await withCargoStepPreconditions([r], root, sources(index), soon());
    expect(r.upgradeCommands).toBeUndefined();
    const words = r.upgradeInstructions![0].instruction;
    expect(words).toMatch(/shadow-rs 0\.7\.2 still requires git2 on its 0\.13 line/);
    expect(words).toMatch(/both link the native library "git2"/);
    expect(words).toMatch(/Upgrade shadow-rs first/);
    expect(hasCargoPrecondition(r)).toBe(true);
  });

  it("with no other crate keeping the old line, the command stays", async () => {
    lock([
      { name: "starship", version: "1.0.0", deps: ["git2"], local: true },
      { name: "git2", version: "0.13.23", deps: ["libgit2-sys"] },
      { name: "libgit2-sys", version: "0.12.24+1.3.0" },
    ]);
    const r = row({ package: "git2", currentVersion: "0.13.23", upgradeCommands: [{ dir: ".", command: "cargo add git2@0.21.0" }] });
    await withCargoStepPreconditions([r], root, sources(index), soon());
    expect(r.upgradeCommands).toEqual([{ dir: ".", command: "cargo add git2@0.21.0" }]);
  });

  it("when the lines do not link the same library, the command stays", async () => {
    graph();
    const noLinks: Sparse = { ...index, "libgit2-sys": { ...index["libgit2-sys"], links: {} } };
    const r = row({ package: "git2", currentVersion: "0.13.23", upgradeCommands: [{ dir: ".", command: "cargo add git2@0.21.0" }] });
    await withCargoStepPreconditions([r], root, sources(noLinks), soon());
    expect(r.upgradeCommands).toHaveLength(1);
  });
});

describe("a crate is moved before the crates that depend on it", () => {
  it("crossbeam-utils before crossbeam-epoch, whatever the names' order", () => {
    lock([
      { name: "app", version: "0.1.0", deps: ["crossbeam-epoch"], local: true },
      { name: "crossbeam-epoch", version: "0.9.5", deps: ["crossbeam-utils"] },
      { name: "crossbeam-utils", version: "0.8.5" },
    ]);
    const dependsOn = cargoDependencyReader(root);
    expect(dependsOn(".", "crossbeam-epoch@0.9.5", "crossbeam-utils@0.8.5")).toBe(true);
    expect(dependsOn(".", "crossbeam-utils@0.8.5", "crossbeam-epoch@0.9.5")).toBe(false);
    const seqRow = (pkg: string, from: string, to: string): SequencedRow => ({
      package: pkg,
      ecosystem: "crates.io",
      currentVersion: from,
      targetVersion: to,
      action: "lockfile_refresh",
      reasons: [],
      refreshCommands: [{ dir: ".", command: `cargo update -p ${pkg}@${from} --precise ${to}` }],
      commands: [{ dir: ".", run: `cargo update -p ${pkg}@${from} --precise ${to}` }],
    });
    const rows = [seqRow("crossbeam-epoch", "0.9.5", "0.9.20"), seqRow("crossbeam-utils", "0.8.5", "0.8.7")];
    const plain = buildRunOrder({ rows, totalRows: 2, heldUnclean: () => false });
    expect(plain.run_order.map((s) => s.run)[0]).toMatch(/crossbeam-epoch/);
    const ordered = buildRunOrder({ rows, totalRows: 2, heldUnclean: () => false, cargoDependsOn: dependsOn });
    expect(ordered.run_order.map((s) => s.run)).toEqual(["cargo update -p crossbeam-utils@0.8.5 --precise 0.8.7", "cargo update -p crossbeam-epoch@0.9.5 --precise 0.9.20"]);
  });
});
