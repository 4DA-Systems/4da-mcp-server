// SPDX-License-Identifier: Apache-2.0
/**
 * A feed advisory is attached to a task package only on ecosystem and exact name. In app mode the
 * briefing listed the node-forge and fast-jwt advisories under the Rust crate `rsa`, because their
 * titles contain the word "RSA". An advisory row's package is what the app's copy of the advisory
 * (osv_advisories) or the row itself states ("rsa (crates.io)"), never a word in its text.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as fs from "node:fs";
import { executeWhatShouldIKnow } from "../tools/what-should-i-know.js";
import { appDb, cargoLock, emptyNetwork, feedRow, liveFor, projectDir, stubNetwork, write, type Network } from "./helpers/a1123-advice.js";

let dir: string;
let net: Network;

beforeEach(() => {
  dir = projectDir();
  net = emptyNetwork();
  write(dir, "Cargo.toml", '[package]\nname = "relay"\nversion = "0.1.0"\n\n[dependencies]\nrsa = "0.9"\n');
  write(dir, "Cargo.lock", cargoLock([{ name: "relay", version: "0.1.0", deps: ["rsa"], root: true }, { name: "rsa", version: "0.9.10" }]));
  // No scan completes: the feed rows are the only evidence, so every row attached is listed.
  net.osvDown = 503;
  stubNetwork(net);
});

afterEach(() => {
  vi.unstubAllGlobals();
  fs.rmSync(dir, { recursive: true, force: true });
});

function feed() {
  const { db, raw } = appDb();
  // Other packages' advisories whose text says "RSA".
  feedRow(raw, { source_type: "cve", source_id: "CVE-2026-119192", title: "[CVE-2026-119192] Forge: RSA PKCS#1 v1.5 signature forgery via non-canonical DigestInfo encoding", content: "### Summary\nnode-forge accepts forged RSA signatures", signal_priority: "alert" });
  feedRow(raw, { source_type: "cve", source_id: "CVE-2026-107722", title: "[CVE-2026-107722] fast-jwt: Incomplete patch of CVE-2026-34950: Non-whitespace key-prefix re-enables RSA→HS256", signal_priority: "alert" });
  // An npm package that happens to be called rsa: not the crate.
  feedRow(raw, { source_type: "osv", source_id: "GHSA-npmr-saaa-0001", title: "[GHSA-npmr-saaa-0001] rsa: weak padding in the npm rsa package", content: "rsa (npm)\nweak padding", signal_priority: "alert" });
  // The crate's own advisory, as the app's OSV feed writes it.
  feedRow(raw, { source_type: "osv", source_id: "RUSTSEC-2023-0071", title: "[RUSTSEC-2023-0071] rsa: Marvin Attack: potential key recovery through timing sidechannels", content: "rsa (crates.io)\nMarvin Attack", signal_priority: "advisory" });
  // The same advisory by its CVE id: the app's copy of the advisory says which package it is.
  feedRow(raw, { source_type: "cve", source_id: "CVE-2023-49092", title: "[CVE-2023-49092] Marvin Attack: potential key recovery through timing sidechannels", content: "### Summary\nThe RSA implementation is vulnerable", signal_priority: "advisory" });
  raw
    .prepare("INSERT INTO osv_advisories (advisory_id, summary, package_name, ecosystem, severity_label, aliases) VALUES (?, ?, ?, ?, ?, ?)")
    .run("RUSTSEC-2023-0071", "Marvin Attack", "rsa", "crates.io", "medium", JSON.stringify(["CVE-2023-49092", "GHSA-c38w-74pg-36hr"]));
  return db;
}

describe("feed advisories are attached on ecosystem and exact name", () => {
  it("the crate rsa gets its own advisories, never node-forge's, fast-jwt's or the npm rsa's", async () => {
    const briefing = await executeWhatShouldIKnow(feed(), { task: "bump rsa to 0.10" }, await liveFor(dir));

    expect(briefing.scan_status).toBe("unavailable");
    const rows = briefing.advisories.filter((a) => a.scope === "task" && !a.version_confirmed).map((a) => a.title);
    expect(rows.sort()).toEqual([
      "[CVE-2023-49092] Marvin Attack: potential key recovery through timing sidechannels",
      "[RUSTSEC-2023-0071] rsa: Marvin Attack: potential key recovery through timing sidechannels",
    ]);
  });
});
