// SPDX-License-Identifier: Apache-2.0
/**
 * Cargo's table form, `[dependencies.<name>]` (and the dev, build and target-specific ones), and
 * dotted keys (`name.version = "1"`) declare a dependency exactly as the inline form does. The
 * project scanner read only `name = ...` lines under the exact `[dependencies]` header, so bat's
 * `[dependencies.git2]` was no direct dependency: the planner said "not determined" for git2 0.15.0
 * and "no manifest this plan read declares git2", where `cargo add git2@0.21.0` fixes both rows.
 */

import { describe, it, expect, afterEach } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import Database from "better-sqlite3";
import { LiveIntelligence } from "../live/index.js";
import { scanCurrentProject } from "../project-scanner.js";
import { scanProjectTree, treeResolutionGroups } from "../project-tree.js";

const MANIFEST = `[package]
name = "bat"
version = "0.22.1"

[dependencies]
atty = "0.2"
serde.version = "1"
serde.features = ["derive"]

[dependencies.git2]
version = "0.15"
optional = true
default-features = false

[dependencies."unicode-width"]
version = "0.1"

[dev-dependencies.assert_cmd]
version = "2"

[build-dependencies.clap]
version = "4"

[target.'cfg(windows)'.dependencies.winapi]
version = "0.3"

[target.x86_64-unknown-linux-gnu.dev-dependencies.nix]
version = "0.26"

[package.metadata.deb.dependencies]
not-a-crate = "x"
`;

describe("a1123 discovery: Cargo dependency tables", () => {
  let dir: string | null = null;
  afterEach(() => {
    if (dir) fs.rmSync(dir, { recursive: true, force: true });
    dir = null;
  });

  it("[dependencies.<name>], its dev, build and target forms, and dotted keys are read as the inline form is", () => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "4da-a1123-cargo-"));
    fs.writeFileSync(path.join(dir, "Cargo.toml"), MANIFEST);
    const scan = scanCurrentProject(dir);
    const rust = scan.depsByEcosystem.rust;
    expect([...rust.deps].sort()).toEqual(["atty", "clap", "git2", "serde", "unicode-width", "winapi"]);
    expect([...rust.devDeps].sort()).toEqual(["assert_cmd", "nix"]);
    expect(scan.depTargets).toMatchObject({ winapi: "cfg(windows)", nix: "x86_64-unknown-linux-gnu" });
  });

  it("bat: git2 declared as a table is a direct dependency at the version the lockfile pins", () => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "4da-a1123-cargo-"));
    fs.writeFileSync(path.join(dir, "Cargo.toml"), '[package]\nname = "bat"\nversion = "0.22.1"\n\n[dependencies.git2]\nversion = "0.15"\noptional = true\n');
    const crate = (name: string, version: string, deps: string[] = [], source = true) =>
      `[[package]]\nname = "${name}"\nversion = "${version}"\n${source ? 'source = "registry+https://github.com/rust-lang/crates.io-index"\n' : ""}${deps.length > 0 ? `dependencies = [\n${deps.map((d) => ` "${d}",`).join("\n")}\n]\n` : ""}\n`;
    fs.writeFileSync(path.join(dir, "Cargo.lock"), `version = 3\n\n${crate("bat", "0.22.1", ["git2"], false)}${crate("git2", "0.15.0", ["libgit2-sys"])}${crate("libgit2-sys", "0.14.0+1.5.0")}`);
    const live = new LiveIntelligence(new Database(":memory:"));
    const { entries, discovery } = scanProjectTree(dir);
    live.initFromProjectTree(dir, treeResolutionGroups(entries), discovery);
    const git2 = live.getResolvedDeps().find((d) => d.name === "git2");
    expect(git2).toMatchObject({ ecosystem: "crates.io", version: "0.15.0", isDirect: true });
    expect(live.getAuditDeps().find((d) => d.name === "libgit2-sys")).toMatchObject({ isDirect: false });
  });
});
