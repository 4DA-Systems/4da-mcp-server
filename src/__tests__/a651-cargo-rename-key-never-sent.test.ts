// SPDX-License-Identifier: Apache-2.0
/**
 * A Cargo dependency renamed with `package =` is installed under its key: when it comes from a path,
 * git or a registry other than crates.io, neither the key nor the package name is ever sent.
 *
 * Privacy review of the 6.5.1 candidate (2026-11-24, projects/cargo-zoo):
 * `renamed-key = { package = "zqcrate-renamed", path = ... }` and
 * `zqcrate-renamed-reg = { package = "zqcrate-actual-reg", registry = "zqrev-registry" }` sent
 * index.crates.io/re/na/renamed-key and an hn.algolia.com query for each key:
 * cargoManifestPrivate recorded only the package name. Stubbed fetch: nothing leaves the machine.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { executeDependencyHealth } from "../tools/dependency-health.js";
import { executeDependencyCheck } from "../tools/dependency-check.js";
import { executeEcosystemPulse } from "../tools/ecosystem-pulse.js";
import { cargoManifestPrivate } from "../live/private-packages.js";
import { createHarness, type Harness } from "./helpers/a1119-planner-harness.js";

let h: Harness;
let bodies: string[];
const INVENTED = /acme/i;
const sent = () => [...h.requests, ...bodies].map((s) => decodeURIComponent(s));
const leaked = () => sent().filter((s) => INVENTED.test(s));

const MANIFEST = [
  "[package]",
  'name = "app"',
  'version = "0.1.0"',
  'edition = "2021"',
  "",
  "[dependencies]",
  'smallvec = "1.13.2"',
  'acme-key = { package = "acme-renamed", path = "crates/acme-renamed" }',
  'acme-reg-key = { package = "acme-actual-reg", version = "1", registry = "acme-registry" }',
  "",
  "[dependencies.acme-git-key]",
  'package = "acme-git-pkg"',
  'git = "https://git.acme.example/acme-git-pkg"',
  "",
].join("\n");

beforeEach(() => {
  h = createHarness();
  bodies = [];
  const inner = globalThis.fetch;
  vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
    if (init?.body) bodies.push(String(init.body));
    return inner(input, init);
  });
  h.CRATES = { smallvec: [{ vers: "1.13.2" }] };
});
afterEach(() => h.dispose());

describe("Cargo package = renames of non-crates.io dependencies", () => {
  it("cargoManifestPrivate names both the key and the package", () => {
    const names = cargoManifestPrivate(MANIFEST).map((p) => p.name).sort();
    expect(names).toEqual(["acme-actual-reg", "acme-git-key", "acme-git-pkg", "acme-key", "acme-reg-key", "acme-renamed"]);
  });

  it("no tool sends either name, with no Cargo.lock", async () => {
    h.write("Cargo.toml", MANIFEST);
    await executeDependencyHealth(null, {}, await h.live());
    await h.plan();
    await h.scan();
    const live = await h.live();
    await executeEcosystemPulse(null, {}, live);
    await executeDependencyCheck(null, { items: ["acme-key", "acme-reg-key", "acme-git-key"].map((p) => ({ ecosystem: "crates.io", package: p, to: "1.0.1" })) }, live);
    expect(leaked()).toEqual([]);
  });
});
