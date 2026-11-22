// SPDX-License-Identifier: Apache-2.0
/**
 * A Cargo upgrade whose target no longer offers a feature the manifest enables is not a command on
 * its own. relay declares `sqlx = { version = "0.8", features = ["sqlite", "runtime-tokio-rustls"] }`;
 * sqlx 0.9 has no `runtime-tokio-rustls`, and `cargo add sqlx@0.9.1` failed with "unrecognized
 * feature for crate sqlx: runtime-tokio-rustls" (exit 101), and the refresh after it with it.
 */

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { releaseFeatureNames } from "../live/crates-versions.js";
import { createUpgradeNet } from "../live/upgrade-sources.js";
import { analyzeUpgradeImpact } from "../tools/upgrade-impact.js";
import { reconcileDirectTargets, type FixPathStep } from "../tools/upgrade-planner-fixpaths.js";
import { createHarness, type Harness } from "./helpers/a1119-planner-harness.js";

/** sqlx's sparse-index lines: 0.8.6 offers runtime-tokio-rustls, 0.9.1 does not. */
const SQLX_LINES = [
  { name: "sqlx", vers: "0.8.6", deps: [{ name: "sqlx-sqlite", req: "=0.8.6", optional: true, kind: "normal" }], features: { default: ["any", "macros"], sqlite: ["dep:sqlx-sqlite"], "runtime-tokio-rustls": ["runtime-tokio", "tls-rustls"], "runtime-tokio": [], "tls-rustls": [], any: [], macros: [] }, yanked: false },
  { name: "sqlx", vers: "0.9.1", deps: [{ name: "sqlx-sqlite", req: "=0.9.1", optional: true, kind: "normal" }], features: { default: ["any", "macros"], sqlite: ["dep:sqlx-sqlite"], "runtime-tokio": [], "tls-rustls-ring": [], any: [], macros: [] }, yanked: false },
];

describe("the features a release offers, from its sparse-index line", () => {
  it("names every declared feature and each optional dependency's implicit one", () => {
    expect(releaseFeatureNames({ features: { std: [], serde: ["dep:serde"] }, features2: { tls: ["rustls?/ring"] }, deps: [{ name: "serde", optional: true }, { name: "rustls", optional: true }, { name: "log" }] })).toEqual([
      "rustls",
      "serde",
      "std",
      "tls",
    ]);
    // `dep:x` removes x's implicit feature; here no feature is called "sqlx-sqlite".
    expect(releaseFeatureNames(SQLX_LINES[1])).not.toContain("sqlx-sqlite");
    expect(releaseFeatureNames({ vers: "1.0.0" } as never)).toBeNull();
  });
});

describe("upgrade_planner and vulnerability_scan: a Cargo upgrade into a release without an enabled feature", () => {
  let h: Harness;
  let withFeatures = true;
  beforeEach(() => {
    h = createHarness();
    withFeatures = true;
    const inner = globalThis.fetch;
    vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
      if (String(input) === "https://index.crates.io/sq/lx/sqlx") {
        const lines = SQLX_LINES.map((l) => (withFeatures ? l : { ...l, features: undefined }));
        return new Response(lines.map((l) => JSON.stringify(l)).join("\n"), { status: 200 });
      }
      return inner(input, init);
    });
    h.write("Cargo.toml", '[package]\nname = "relay"\nversion = "0.1.0"\nedition = "2021"\n\n[dependencies]\nsqlx = { version = "0.8", features = ["sqlite", "runtime-tokio-rustls"] }\n');
  });
  afterEach(() => h.dispose());

  const directRow = (): FixPathStep => ({
    package: "sqlx",
    ecosystem: "crates.io",
    currentVersion: "0.8.6",
    targetVersion: "0.9.1",
    upgradeType: "major",
    reasons: [],
    breaking: true,
    scope: "direct",
    action: "upgrade_direct",
    fixPathChecked: "all_advisories",
    upgradeCommands: [{ dir: ".", command: "cargo add sqlx@0.9.1" }],
  });
  const leverRow = (): FixPathStep => ({
    package: "libsqlite3-sys",
    ecosystem: "crates.io",
    currentVersion: "0.30.1",
    targetVersion: "0.39.0",
    upgradeType: "major",
    reasons: ["Transitive dependency: ... upgrade sqlx to 0.9.1 (a major upgrade) (`cargo add sqlx@0.9.1`)"],
    breaking: true,
    scope: "transitive",
    action: "upgrade_parent",
    fixPathChecked: "all_advisories",
    parentUpgrades: [
      {
        parent: "sqlx-sqlite",
        from: "0.8.6",
        to: "0.9.1",
        breaking: true,
        levers: [{ name: "sqlx", version: "0.8.6", to: "0.9.1", breaking: true, commands: [{ dir: ".", command: "cargo add sqlx@0.9.1" }] }],
        refreshCommands: [{ dir: ".", command: "cargo update -p libsqlite3-sys@0.30.1 --precise 0.39.0" }],
      },
    ],
  });

  it("a direct row: the command becomes the feature change, then the command", async () => {
    const row = directRow();
    await reconcileDirectTargets([row], [], await h.live());
    expect(row.upgradeCommands).toBeUndefined();
    expect(row.upgradeInstructions).toEqual([
      {
        dir: ".",
        instruction: 'Cargo.toml enables feature "runtime-tokio-rustls" on sqlx, which sqlx 0.9.1 does not offer, so cargo refuses the upgrade ("unrecognized feature"): change those features to ones 0.9.1 offers, then run `cargo add sqlx@0.9.1`',
      },
    ]);
    expect(row.reasons.join(" | ")).toMatch(/Cargo features: Cargo\.toml enables feature "runtime-tokio-rustls" on sqlx, which sqlx 0\.9\.1 does not offer/);
  });

  it("a parent upgrade through it: neither the lever's command nor the refresh after it is presented alone", async () => {
    const row = leverRow();
    await reconcileDirectTargets([row], [], await h.live());
    const up = row.parentUpgrades![0];
    expect(up.levers[0].commands).toBeUndefined();
    expect(up.refreshCommands).toBeUndefined();
    expect(up.levers[0].instructions).toEqual([
      {
        dir: ".",
        instruction:
          'Cargo.toml enables feature "runtime-tokio-rustls" on sqlx, which sqlx 0.9.1 does not offer, so cargo refuses the upgrade ("unrecognized feature"): change those features to ones 0.9.1 offers, then run `cargo add sqlx@0.9.1`, then `cargo update -p libsqlite3-sys@0.30.1 --precise 0.39.0`',
      },
    ]);
    expect(row.reasons.join(" | ")).toMatch(/upgrading sqlx to 0\.9\.1 needs that change first/);
  });

  it("keeps the command when the target offers every enabled feature", async () => {
    h.write("Cargo.toml", '[package]\nname = "relay"\nversion = "0.1.0"\nedition = "2021"\n\n[dependencies]\nsqlx = { version = "0.8", features = ["sqlite", "runtime-tokio"] }\n');
    const row = directRow();
    await reconcileDirectTargets([row], [], await h.live());
    expect(row.upgradeCommands).toEqual([{ dir: ".", command: "cargo add sqlx@0.9.1" }]);
    expect(row.upgradeInstructions).toBeUndefined();
  });

  it("says nothing false when the target's features cannot be read: the command stays", async () => {
    withFeatures = false;
    const row = directRow();
    await reconcileDirectTargets([row], [], await h.live());
    expect(row.upgradeCommands).toEqual([{ dir: ".", command: "cargo add sqlx@0.9.1" }]);
    expect(row.reasons.join(" | ")).not.toMatch(/Cargo features/);
  });
});

describe("upgrade_impact names the feature the target no longer offers", () => {
  let root: string;
  beforeEach(() => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), "4da-a1123-features-"));
    fs.writeFileSync(path.join(root, "Cargo.toml"), '[package]\nname = "relay"\nversion = "0.1.0"\n\n[dependencies]\nsqlx = { version = "0.8", features = ["sqlite", "runtime-tokio-rustls"] }\n');
  });
  afterEach(() => fs.rmSync(root, { recursive: true, force: true }));

  const fetchFn = (index: boolean) => async (url: string) => {
    const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
    if (url === "https://crates.io/api/v1/crates/sqlx") {
      return json({ crate: { name: "sqlx", repository: null }, versions: [{ num: "0.9.1", created_at: "2026-10-01T00:00:00Z" }, { num: "0.8.6", created_at: "2025-05-19T00:00:00Z" }] });
    }
    if (url === "https://index.crates.io/sq/lx/sqlx") return index ? new Response(SQLX_LINES.map((l) => JSON.stringify(l)).join("\n"), { status: 200 }) : new Response("unavailable", { status: 503 });
    if (url.startsWith("https://api.osv.dev/")) return json({ vulns: [] });
    return new Response("not found", { status: 404 });
  };
  const run = (index: boolean) =>
    analyzeUpgradeImpact(
      { package: "sqlx", ecosystem: "crates.io", from_version: "0.8.6", to_version: "0.9.1" },
      { net: createUpgradeNet(null, fetchFn(index)), projectRoot: root, installed: [{ name: "sqlx", version: "0.8.6", ecosystem: "crates.io", isDirect: true, sourceDirs: [root] } as never], offline: false },
    ) as Promise<Record<string, any>>;

  it("lists it in your_code and says it in the summary", async () => {
    const r = await run(true);
    expect(r.error).toBeUndefined();
    expect(r.your_code.cargo_features).toEqual(["runtime-tokio-rustls", "sqlite"]);
    expect(r.your_code.cargo_features_removed).toEqual(["runtime-tokio-rustls"]);
    expect(r.summary).toMatch(/This project enables feature "runtime-tokio-rustls" on sqlx, which sqlx 0\.9\.1 does not offer: cargo refuses the upgrade/);
  });

  it("is null, and says NOT CHECKED, when the index cannot be read", async () => {
    const r = await run(false);
    expect(r.your_code.cargo_features_removed).toBeNull();
    expect(r.your_code.cargo_features_note).toMatch(/NOT CHECKED/);
    expect(r.summary).not.toMatch(/does not offer/);
  });
});
