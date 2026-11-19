// SPDX-License-Identifier: Apache-2.0
/**
 * deno.lock is not read (its npm: and jsr: packages are resolved nowhere), so
 * its presence is disclosed under NOT COVERED: an empty or clean answer beside
 * it is never read as "no dependencies".
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { unsupportedEcosystem } from "../project-tree.js";
import { npmAdvisory, removeProject, scanProject, stubOsv, tempProject } from "./helpers/a1119-readers.js";

const DENO_LOCK = JSON.stringify(
  {
    version: "4",
    specifiers: { "npm:lodash@4.17.15": "4.17.15", "jsr:@std/path@1": "1.0.8" },
    jsr: { "@std/path@1.0.8": { integrity: "548b1d" } },
    npm: { "lodash@4.17.15": { integrity: "sha512-AAAA" } },
  },
  null,
  2,
);

describe("deno.lock is listed as not covered", () => {
  let dirs: string[];
  let priorOffline: string | undefined;
  const project = (files: Record<string, string>) => {
    const dir = tempProject(files);
    dirs.push(dir);
    return dir;
  };

  beforeEach(() => {
    dirs = [];
    priorOffline = process.env.FOURDA_OFFLINE;
    delete process.env.FOURDA_OFFLINE;
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    if (priorOffline === undefined) delete process.env.FOURDA_OFFLINE;
    else process.env.FOURDA_OFFLINE = priorOffline;
    dirs.forEach(removeProject);
  });

  it("is named by file name as an ecosystem this server does not read", () => {
    expect(unsupportedEcosystem("deno.lock", ["deno.json", "deno.lock"])).toBe("Deno (deno.lock is not read)");
    expect(unsupportedEcosystem("deno.json", ["deno.json", "deno.lock"])).toBeNull();
  });

  it("a Deno project alone: nothing was checked, and the answer says why", async () => {
    stubOsv([]);
    const answer = await scanProject(project({ "deno.json": '{ "imports": { "lodash": "npm:lodash@4.17.15" } }', "deno.lock": DENO_LOCK }));
    const text = JSON.stringify(answer);
    expect(text).toMatch(/NOT COVERED: this project's dependencies are in ecosystems or formats this server does not read \(Deno \(deno\.lock is not read\)\): deno\.lock/);
    expect(text).not.toMatch(/No manifest or lockfile of a supported ecosystem was found/);
  });

  it("beside an npm lockfile that was read, deno.lock is still disclosed and the scan is not complete", async () => {
    stubOsv([npmAdvisory("GHSA-35jh-r3h4-6jhm", "lodash", "4.17.21")]);
    const manifest = { name: "x", dependencies: { ms: "2.0.0" } };
    const lock = { name: "x", lockfileVersion: 3, packages: { "": manifest, "node_modules/ms": { version: "2.0.0" } } };
    const answer = await scanProject(project({ "package.json": JSON.stringify(manifest), "package-lock.json": JSON.stringify(lock), "deno.lock": DENO_LOCK }));
    expect(answer.total_dependencies_scanned).toBe(1);
    expect(answer.coverage).toMatchObject({ complete: false, not_covered: [{ path: "deno.lock", ecosystem: "Deno (deno.lock is not read)" }] });
    expect(answer.coverage.note).toMatch(/NOT COVERED: 1 manifest\/lockfile of ecosystems or formats this server does not read \(Deno\): deno\.lock/);
  });
});
