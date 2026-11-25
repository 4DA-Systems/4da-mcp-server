// SPDX-License-Identifier: Apache-2.0
/**
 * Audit 2026-11-25 (track A fixtures C1, C2): a Gemfile.lock or Pipfile.lock older than its
 * manifest (the manifest declares a package the lockfile has no entry for) read "Health: 100/100
 * ... over the checked part only". A score beside an unread declared dependency reads as
 * reassurance: the score and the counts are withheld (`withheldReason: "lockfile_partial"`) and the
 * summary leads with NOT CHECKED and what was not read. A whole lockfile is still scored.
 * Stubbed fetch: nothing leaves the machine.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { executeDependencyHealth } from "../tools/dependency-health.js";
import { createHarness, type Harness } from "./helpers/a1119-planner-harness.js";

let h: Harness;
const PROXY_VARS = ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"];
const saved: Record<string, string | undefined> = {};
beforeEach(() => {
  for (const k of PROXY_VARS) {
    saved[k] = process.env[k];
    delete process.env[k];
  }
  h = createHarness();
  h.PYPI = { six: { "1.16.0": {} }, django: { "2.2.0": {} } };
});
afterEach(() => {
  h.dispose();
  for (const [k, v] of Object.entries(saved)) if (v !== undefined) process.env[k] = v;
});

const health = async () => (await executeDependencyHealth(null, {}, await h.live())) as unknown as Record<string, any>;

const GEMFILE_LOCK_RAKE = "GEM\n  remote: https://rubygems.org/\n  specs:\n    rake (13.2.1)\n\nPLATFORMS\n  ruby\n\nDEPENDENCIES\n  rake (= 13.2.1)\n\nBUNDLED WITH\n   2.4.22\n";
const PIPFILE = '[[source]]\nurl = "https://pypi.org/simple"\nverify_ssl = true\nname = "pypi"\n\n[packages]\nsix = "==1.16.0"\n';
const pipfileLock = (pkgs: Record<string, string>) =>
  JSON.stringify({
    _meta: { hash: { sha256: "0".repeat(64) }, "pipfile-spec": 6, requires: {}, sources: [{ name: "pypi", url: "https://pypi.org/simple", verify_ssl: true }] },
    default: Object.fromEntries(Object.entries(pkgs).map(([n, v]) => [n, { hashes: [], index: "pypi", version: `==${v}` }])),
    develop: {},
  });

describe("dependency_health over a lockfile older than its manifest", () => {
  it("C1 Gemfile.lock: no score, NOT CHECKED first, naming what was not read", async () => {
    h.write("Gemfile", "source 'https://rubygems.org'\n\ngem 'rake', '13.2.1'\ngem 'carrierwave', '1.3.1'\n");
    h.write("Gemfile.lock", GEMFILE_LOCK_RAKE);
    const r = await health();
    expect(r.healthScore).toBeNull();
    expect(r.withheldReason).toBe("lockfile_partial");
    expect(r.vulnerableCount).toBeNull();
    expect(r.summary).toMatch(/^NOT CHECKED: PARTIAL: 1 lockfile is older than its manifest: .*Gemfile\.lock .*Gemfile declares carrierwave/);
    expect(r.summary).not.toMatch(/\d+\/100/);
    expect(r.summary).not.toMatch(/all healthy/);
  });

  it("C2 Pipfile.lock: the same", async () => {
    h.write("Pipfile", `${PIPFILE}django = "==2.2.0"\n`);
    h.write("Pipfile.lock", pipfileLock({ six: "1.16.0" }));
    const r = await health();
    expect(r.healthScore).toBeNull();
    expect(r.withheldReason).toBe("lockfile_partial");
    expect(r.summary).toMatch(/^NOT CHECKED: PARTIAL: 1 lockfile is older than its manifest: .*Pipfile\.lock .*Pipfile declares django/);
    expect(r.summary).not.toMatch(/\d+\/100/);
  });

  it("control: a whole Pipfile.lock is scored", async () => {
    h.write("Pipfile", PIPFILE);
    h.write("Pipfile.lock", pipfileLock({ six: "1.16.0" }));
    const r = await health();
    expect(r.healthScore).not.toBeNull();
    expect(r.withheldReason).toBeUndefined();
    expect(r.summary).toMatch(/^Health: \d+\/100/);
  });
});
