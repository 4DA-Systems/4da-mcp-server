// SPDX-License-Identifier: Apache-2.0
/**
 * A PyPI transitive copy held by a parent the project does not declare is "waiting on upstream"
 * only once the parent's newer releases were read and none admits a clean version.
 *
 * full-stack-fastapi-template's backend (uv): httpcore 1.0.5 requires h11 "<0.15,>=0.13", so no
 * refresh of h11 reaches 0.16.0 (CVE-2025-43859, critical). httpcore 1.0.9 requires h11 ">=0.16",
 * and httpx 0.27.2, which brings httpcore in, requires "httpcore==1.*", which admits 1.0.9:
 * `uv lock --upgrade-package httpcore` moves both (uv printed "Updated h11 v0.14.0 -> v0.16.0").
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { adv, createHarness, fixedIn, type Harness } from "./helpers/a1119-planner-harness.js";

let h: Harness;
beforeEach(() => {
  h = createHarness();
});
afterEach(() => h.dispose());

const reasonsOf = (step: Record<string, any>) => (step.reasons as string[]).join(" | ");

function fastapiBackend(httpxRequires = "httpcore==1.*") {
  h.ADVISORIES = { h11: [adv("GHSA-vqfr-h8mv-ghfj", "h11", fixedIn("0.16.0"), "PyPI", "CRITICAL")] };
  h.PYPI = {
    h11: { "0.14.0": { requiresPython: ">=3.7" }, "0.16.0": { requiresPython: ">=3.8" } },
    httpcore: {
      "1.0.5": { requiresPython: ">=3.8", requiresDist: ["certifi", "h11<0.15,>=0.13"] },
      "1.0.9": { requiresPython: ">=3.8", requiresDist: ["certifi", "h11>=0.16"] },
    },
    httpx: { "0.27.2": { requiresPython: ">=3.8", requiresDist: ["anyio", "certifi", httpxRequires, "idna", "sniffio"] } },
    uvicorn: { "0.30.6": { requiresPython: ">=3.8", requiresDist: ["click>=7.0", "h11>=0.8"] } },
  };
  h.write("pyproject.toml", '[project]\nname = "app"\nversion = "0.1.0"\nrequires-python = ">=3.10,<4.0"\ndependencies = ["httpx<1.0.0,>=0.25.1", "uvicorn>=0.30"]\n');
  h.write(
    "uv.lock",
    [
      'version = 1\nrequires-python = ">=3.10, <4.0"\n',
      '[[package]]\nname = "app"\nversion = "0.1.0"\nsource = { virtual = "." }\ndependencies = [\n    { name = "httpx" },\n    { name = "uvicorn" },\n]\n\n[package.metadata]\nrequires-dist = [\n    { name = "httpx", specifier = "<1.0.0,>=0.25.1" },\n    { name = "uvicorn", specifier = ">=0.30" },\n]\n',
      '[[package]]\nname = "h11"\nversion = "0.14.0"\nsource = { registry = "https://pypi.org/simple" }\n',
      '[[package]]\nname = "httpcore"\nversion = "1.0.5"\nsource = { registry = "https://pypi.org/simple" }\ndependencies = [\n    { name = "h11" },\n]\n',
      '[[package]]\nname = "httpx"\nversion = "0.27.2"\nsource = { registry = "https://pypi.org/simple" }\ndependencies = [\n    { name = "httpcore" },\n]\n',
      '[[package]]\nname = "uvicorn"\nversion = "0.30.6"\nsource = { registry = "https://pypi.org/simple" }\ndependencies = [\n    { name = "h11" },\n]\n',
    ].join("\n"),
  );
}

describe("a blocking parent the project does not declare (uv.lock)", () => {
  it("moves by its own refresh when what requires it admits a release that admits the fix", async () => {
    fastapiBackend();
    const { result, step } = await h.plan();
    const row = step("h11");
    expect(row).toMatchObject({ scope: "transitive", action: "lockfile_refresh", targetVersion: "0.16.0" });
    expect(row.refreshCommands).toEqual([{ dir: ".", command: "uv lock --upgrade-package httpcore" }]);
    const why = reasonsOf(row);
    expect(why).toMatch(/httpcore 1\.0\.5 requires h11 "<0\.15,>=0\.13", which excludes h11 0\.16\.0/);
    expect(why).toMatch(/httpx 0\.27\.2 requires httpcore "==1\.\*"/);
    expect(why).toMatch(/httpcore 1\.0\.9/);
    expect(why).not.toMatch(/waiting on upstream|blocked upstream|has to move first/i);
    expect(result.waitingOnUpstream).toBe(0);
  });

  it("is not waiting on upstream when a parent release admits the fix but what requires the parent holds it back", async () => {
    fastapiBackend("httpcore==1.0.5");
    const { result, step } = await h.plan();
    const row = step("h11");
    expect(row).toMatchObject({ scope: "transitive", action: "upgrade_parent_unverified" });
    expect(row.parentUpgrades).toMatchObject([{ parent: "httpcore", from: "1.0.5", to: "1.0.9", levers: [] }]);
    const why = reasonsOf(row);
    expect(why).toMatch(/httpx 0\.27\.2 requires httpcore "==1\.0\.5"/);
    expect(why).not.toMatch(/waiting on upstream/i);
    expect(result.waitingOnUpstream).toBe(0);
  });

  it("stays waiting on upstream when the parent's newer releases were read and none admits the fix", async () => {
    fastapiBackend();
    h.PYPI.httpcore["1.0.9"].requiresDist = ["certifi", "h11<0.15,>=0.13"];
    const { result, step } = await h.plan();
    const row = step("h11");
    expect(row).toMatchObject({ action: "waiting_on_upstream" });
    expect(row.refreshCommands).toBeUndefined();
    expect(reasonsOf(row)).toMatch(/blocked upstream: httpcore 1\.0\.5 requires h11 "<0\.15,>=0\.13"/);
    expect(result.waitingOnUpstream).toBe(1);
  });

  it("is NOT DETERMINED, never waiting on upstream, when a newer parent release's requirements cannot be read", async () => {
    fastapiBackend();
    // The release is listed, but PyPI does not answer for what it requires.
    const inner = globalThis.fetch;
    vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) =>
      String(input) === "https://pypi.org/pypi/httpcore/1.0.9/json" ? new Response("unavailable", { status: 503 }) : inner(input, init),
    );
    const { result, step } = await h.plan();
    const row = step("h11");
    expect(row.action).toBe("not_determined");
    expect(row.refreshCommands).toBeUndefined();
    expect(reasonsOf(row)).toMatch(/NOT DETERMINED/);
    expect(result.waitingOnUpstream).toBe(0);
  });
});
