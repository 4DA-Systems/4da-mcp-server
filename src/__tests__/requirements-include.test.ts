// SPDX-License-Identifier: Apache-2.0
/**
 * B-11 / B-10 (audit 2026-10-12): requirements `-r`/`-c` includes are confined
 * to the project, and a pathological long line parses in linear time.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { parseRequirements, readRequirementsFile, resolvePython } from "../live/lockfile-parsers-pygo.js";

let base: string;
let proj: string;
const write = (rel: string, content: string) => {
  const p = path.join(base, rel);
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, content);
  return p;
};

beforeEach(() => {
  base = fs.mkdtempSync(path.join(os.tmpdir(), "req-include-"));
  proj = path.join(base, "proj");
  fs.mkdirSync(proj);
});
afterEach(() => fs.rmSync(base, { recursive: true, force: true }));

describe("requirements includes stay inside the project", () => {
  it("does not read an include that climbs out of the project", () => {
    write("outside/secrets.txt", "secret-token==hunter2-abc\naws-key==AKIAEXAMPLE\n");
    write("proj/requirements.txt", "-r ../outside/secrets.txt\nrequests==2.0.0\n");
    const names = resolvePython(proj).instances.map((i) => i.name).sort();
    expect(names).toEqual(["requests"]);
  });

  it("does not read an absolute include, nor a constraint file outside", () => {
    const outside = write("outside/abs.txt", "leaked==1.0\nflask==9.9.9\n");
    write("proj/requirements.txt", `-r ${outside}\n-c ../outside/abs.txt\nflask\nrequests==2.0.0\n`);
    expect(readRequirementsFile(path.join(proj, "requirements.txt"), new Set(), proj)).toEqual([{ name: "requests", version: "2.0.0" }]);
  });

  it("refuses drive-letter and UNC includes without touching the filesystem", () => {
    write("proj/requirements.txt", "-r C:\\x.txt\n-r \\\\host\\share\\x.txt\n-r //host/share/x.txt\nrequests==2.0.0\n");
    expect(readRequirementsFile(path.join(proj, "requirements.txt"), new Set(), proj)).toEqual([{ name: "requests", version: "2.0.0" }]);
  });

  it("still follows an include inside the project, from a subfolder file to its sibling", () => {
    write("proj/sub/base.txt", "alembic==1.6.5\n");
    write("proj/requirements.txt", "-r sub/base.txt\npytest==7.1.2\n");
    write("proj/requirements/dev.txt", "-r ../sub/base.txt\n");
    const names = resolvePython(proj).instances.map((i) => i.name).sort();
    expect(names).toEqual(["alembic", "pytest"]);
  });

  it("refuses a symlinked include that points outside", () => {
    write("outside/secrets.txt", "secret-token==1\n");
    try {
      fs.symlinkSync(path.join(base, "outside", "secrets.txt"), path.join(proj, "link.txt"));
    } catch {
      return; // no symlink privilege on this host
    }
    write("proj/requirements.txt", "-r link.txt\nrequests==2.0.0\n");
    expect(readRequirementsFile(path.join(proj, "requirements.txt"), new Set(), proj)).toEqual([{ name: "requests", version: "2.0.0" }]);
  });
});

describe("requirements parsing is linear on long lines (B-10)", () => {
  it("a 64 KB line parses quickly", () => {
    const long = `a${" ".repeat(65_536)}x\n` + "requests==2.0.0\n";
    const t0 = Date.now();
    const pins = parseRequirements(long);
    expect(Date.now() - t0).toBeLessThan(200);
    expect(pins).toContainEqual({ name: "requests", version: "2.0.0" });
  });
});
