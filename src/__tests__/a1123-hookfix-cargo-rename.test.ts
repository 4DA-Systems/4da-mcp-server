// SPDX-License-Identifier: Apache-2.0
/**
 * A renamed Cargo dependency (`alias = { package = "real", version = "X" }`, or the table form
 * with a `package =` line) installs the crate `package =` names: the guard judges that crate, in
 * the ledger lookup and in the call its denial names. Judged as the alias, a checked version was
 * denied and the named call (for a crate that does not exist) could never answer proceed.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { sandbox, type Sandbox } from "./helpers/a1123-hookfix-run.js";

const CARGO = '[package]\nname = "demo"\nversion = "0.1.0"\n\n[dependencies]\nanyhow = "1.0.89"\n';

let s: Sandbox;
beforeEach(() => {
  s = sandbox();
});
afterEach(() => s.dispose());

describe("a renamed Cargo dependency is judged as the crate it installs", () => {
  it("inline form: a proceed verdict for the real crate lets it through", () => {
    s.ledger([{ ecosystem: "crates.io", package: "serde_json", version: "1.0.128", requested: "1.0.128", verdict: "proceed" }]);
    const file = s.file("Cargo.toml", CARGO);
    expect(s.edit(file, 'anyhow = "1.0.89"\n', 'anyhow = "1.0.89"\njson = { package = "serde_json", version = "1.0.128" }\n').decision).toBe("allow");
  });

  it("inline form, unchecked: the call names the real crate, never the alias", () => {
    const file = s.file("Cargo.toml", CARGO);
    const run = s.edit(file, 'anyhow = "1.0.89"\n', 'anyhow = "1.0.89"\njson = { version = "1.0.128", package = "serde_json" }\n');
    expect(run.decision).toBe("deny");
    expect(run.items).toEqual([{ ecosystem: "crates.io", package: "serde_json", to: "1.0.128" }]);
    expect(run.text).not.toMatch(/\bjson 1\.0\.128/);
  });

  it("table form: [dependencies.alias] with a package line", () => {
    const file = s.file("Cargo.toml", CARGO);
    const run = s.edit(file, 'anyhow = "1.0.89"\n', 'anyhow = "1.0.89"\n\n[dependencies.json]\npackage = "serde_json"\nversion = "1.0.128"\n');
    expect(run.items).toEqual([{ ecosystem: "crates.io", package: "serde_json", to: "1.0.128" }]);
    s.ledger([{ ecosystem: "crates.io", package: "serde_json", version: "1.0.128", requested: "1.0.128", verdict: "proceed" }]);
    expect(s.edit(file, 'anyhow = "1.0.89"\n', 'anyhow = "1.0.89"\n\n[dependencies.json]\npackage = "serde_json"\nversion = "1.0.128"\n').decision).toBe("allow");
  });

  it("a bump of a renamed dependency names the real crate with its old version", () => {
    const file = s.file("Cargo.toml", CARGO + 'json = { package = "serde_json", version = "1.0.120" }\n');
    const run = s.edit(file, 'version = "1.0.120"', 'version = "1.0.128"');
    expect(run.items).toEqual([{ ecosystem: "crates.io", package: "serde_json", to: "1.0.128", from: "1.0.120" }]);
  });

  it("dotted keys: json.package and json.version", () => {
    const file = s.file("Cargo.toml", CARGO);
    const run = s.edit(file, 'anyhow = "1.0.89"\n', 'anyhow = "1.0.89"\njson.package = "serde_json"\njson.version = "1.0.128"\n');
    expect(run.items).toEqual([{ ecosystem: "crates.io", package: "serde_json", to: "1.0.128" }]);
  });

  it("after the edit (FOURDA_GUARD=advise) the advice names the real crate too", () => {
    const after = CARGO + 'json = { package = "serde_json", version = "1.0.128" }\n';
    const file = s.file("Cargo.toml", after);
    const run = s.post(file, 'anyhow = "1.0.89"\n', 'anyhow = "1.0.89"\njson = { package = "serde_json", version = "1.0.128" }\n');
    expect(run.decision).toBe("advise");
    expect(run.items).toEqual([{ ecosystem: "crates.io", package: "serde_json", to: "1.0.128" }]);
  });
});
