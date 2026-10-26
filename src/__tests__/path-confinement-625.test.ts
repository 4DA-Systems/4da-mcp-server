// SPDX-License-Identifier: Apache-2.0
/**
 * Audit 6.2.5 C-3 / C-4 / F-3.
 * - C-3: a symlinked requirements file (or junctioned requirements/ folder) at
 *   the project root was read even when it pointed outside the project; only
 *   `-r` includes were confined.
 * - C-4: Cargo workspace `members = ["../outside/*"]` was followed out of the
 *   project, and the outside manifests' dependency names went to the registries.
 * - F-3: [build-dependencies] were filed as dev-only, so their advisories were
 *   graded down and `include_dev: false` hid them.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { requirementFiles } from "../live/lockfile-parsers-pygo.js";
import { cargoWorkspaceDeps } from "../project-manifests.js";

let base: string;
beforeEach(() => {
  base = fs.mkdtempSync(path.join(os.tmpdir(), "4da-confine-"));
});
afterEach(() => fs.rmSync(base, { recursive: true, force: true }));

const write = (rel: string, body: string) => {
  fs.mkdirSync(path.dirname(path.join(base, rel)), { recursive: true });
  fs.writeFileSync(path.join(base, rel), body);
};

describe("C-3: requirement files resolve inside the project", () => {
  it("a symlinked requirements file pointing outside is not read; one pointing inside is", () => {
    write("outside/secret-requirements.txt", "internal-pkg==1.0.0\n");
    write("project/requirements.txt", "requests==2.19.1\n");
    write("project/vendor/pinned.txt", "idna==2.7\n");
    const project = path.join(base, "project");
    try {
      fs.symlinkSync(path.join(base, "outside", "secret-requirements.txt"), path.join(project, "requirements-dev.txt"));
      fs.symlinkSync(path.join(project, "vendor", "pinned.txt"), path.join(project, "requirements-test.txt"));
    } catch {
      return; // no symlink privilege on this host
    }
    const files = requirementFiles(project).map((f) => path.basename(f)).sort();
    expect(files).toEqual(["requirements-test.txt", "requirements.txt"]);
  });
});

describe("C-4 / F-3: Cargo workspace members and build-dependencies", () => {
  it("a member outside the project is not read", () => {
    write("outside/leak/Cargo.toml", '[package]\nname = "leak"\n\n[dependencies]\nprivate-crate = "1"\n');
    write("project/crates/a/Cargo.toml", '[package]\nname = "a"\n\n[dependencies]\nserde = "1"\n');
    const root = path.join(base, "project");
    const manifest = '[workspace]\nmembers = ["crates/*", "../outside/*"]\n';
    const { deps } = cargoWorkspaceDeps(root, manifest);
    expect(deps).toContain("serde");
    expect(deps).not.toContain("private-crate");
  });

  it("build-dependencies are normal dependencies, dev-dependencies stay dev", () => {
    write("project/crates/a/Cargo.toml", '[package]\nname = "a"\n\n[build-dependencies]\nmemoffset = "0.5"\n\n[dev-dependencies]\nrand = "0.8"\n');
    const { deps, devDeps } = cargoWorkspaceDeps(path.join(base, "project"), '[workspace]\nmembers = ["crates/*"]\n');
    expect(deps).toContain("memoffset");
    expect(devDeps).toEqual(["rand"]);
  });
});
