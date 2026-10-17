// SPDX-License-Identifier: Apache-2.0
/**
 * upgrade_impact B-7 in a Cargo workspace (6.2.5 readiness audit M3,
 * 2026-10-16): victauri's members enable reqwest's `rustls-tls` (renamed
 * `rustls` in 0.13), and 0 breaking entries were flagged, because only the
 * root Cargo.toml and the lockfile's directory were read. Every
 * `[workspace] members` entry (globs included) is read now, less `exclude`.
 */
import { describe, expect, it, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { projectCargoFeatures } from "../tools/upgrade-impact-features.js";

let root: string;

function write(rel: string, content: string) {
  const file = path.join(root, rel);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, content);
}

const member = (name: string, features: string[]) =>
  `[package]\nname = "${name}"\n\n[dependencies]\nreqwest = { version = "0.12", default-features = false, features = [${features.map((f) => `"${f}"`).join(", ")}] }\n`;

beforeEach(() => {
  root = fs.mkdtempSync(path.join(os.tmpdir(), "4da-ws-features-"));
});
afterEach(() => fs.rmSync(root, { recursive: true, force: true }));

describe("projectCargoFeatures reads every workspace member", () => {
  it("victauri-shaped: members by path and by glob, the lockfile only at the root", () => {
    write(
      "Cargo.toml",
      `[workspace]\nresolver = "2"\nmembers = [\n    "crates/*",\n    "examples/demo-app",\n]\nexclude = ["crates/old"]\n\n[workspace.package]\nversion = "0.9.0"\n`,
    );
    write("crates/plugin/Cargo.toml", member("plugin", ["rustls-tls", "json"]));
    write("crates/watchdog/Cargo.toml", member("watchdog", ["rustls-tls"]));
    write("crates/old/Cargo.toml", member("old", ["native-tls-vendored"]));
    write("crates/notes.txt", "not a crate");
    write("examples/demo-app/Cargo.toml", member("demo", ["macos-system-configuration"]));
    write("examples/other/Cargo.toml", member("other", ["blocking"]));
    const installed = [{ name: "reqwest", ecosystem: "crates.io", isDirect: true, sourceDirs: [root] }];
    expect(projectCargoFeatures(root, "reqwest", installed)).toEqual(["json", "macos-system-configuration", "rustls-tls"]);
  });

  it("a workspace whose root is a source dir but not the project root, and a nested workspace in a member", () => {
    const ws = path.join(root, "rust");
    write("rust/Cargo.toml", `[workspace]\nmembers = ["a"]\n`);
    write("rust/a/Cargo.toml", member("a", ["rustls-tls"]));
    const installed = [{ name: "reqwest", ecosystem: "crates.io", isDirect: true, sourceDirs: [ws] }];
    expect(projectCargoFeatures(root, "reqwest", installed)).toEqual(["rustls-tls"]);
  });
});
