// SPDX-License-Identifier: Apache-2.0
/**
 * B-11 / B-10 (audit 2026-10-12): requirements `-r`/`-c` includes are confined
 * to the project, and a pathological long line parses in linear time.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import Database from "better-sqlite3";
import { parseRequirements, readRequirementsFile, resolvePython } from "../live/lockfile-parsers-pygo.js";
import { resolveVersionSource } from "../live/lockfile-parsers.js";
import { LiveIntelligence } from "../live/index.js";
import { executeVulnerabilityScan } from "../tools/vulnerability-scan.js";

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

/**
 * Readiness audit M4 (2026-10-16): the refusal stands, but it was silent.
 * django in `-r ../outside.txt` went unchecked, total_dependencies_scanned
 * read 2, and nothing said the result was partial. Each refused include is
 * now a coverage problem naming the include and why it was not read.
 */
describe("a refused include is named in the coverage, never silent (M4)", () => {
  it("resolveVersionSource lists each refused include with the file that names it", () => {
    write("outside.txt", "django==3.2.0\n");
    write("proj/sub/inner.txt", "jinja2==2.10\n");
    write("proj/requirements.txt", "requests==2.19.0\n-r ../outside.txt\n-c \\\\host\\share\\c.txt\n-r sub/inner.txt\n");
    const read = resolveVersionSource(proj, "PyPI");
    expect(read.instances.map((i) => i.name).sort()).toEqual(["jinja2", "requests"]);
    const problems = read.problems ?? [];
    expect(problems).toHaveLength(2);
    expect(problems[0].file).toBe(path.join(base, "outside.txt"));
    expect(problems[0].error).toMatch(/-r \.\.\/outside\.txt.*requirements\.txt.*outside the project/);
    expect(problems[1].file).toBe("\\\\host\\share\\c.txt");
    expect(problems[1].error).toMatch(/-c /);
  });

  it("vulnerability_scan's coverage names the refused include", async () => {
    write("outside.txt", "django==3.2.0\n");
    write("proj/requirements.txt", "requests==2.19.0\n-r ../outside.txt\n");
    const priorOffline = process.env.FOURDA_OFFLINE;
    delete process.env.FOURDA_OFFLINE;
    vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/v1/querybatch")) {
        const { queries } = JSON.parse(String(init?.body)) as { queries: unknown[] };
        return new Response(JSON.stringify({ results: queries.map(() => ({})) }), { status: 200 });
      }
      throw new TypeError(`fetch failed (${url})`);
    });
    try {
      const result = (await executeVulnerabilityScan(null, { project_path: proj }, new LiveIntelligence(new Database(":memory:")))) as Record<string, any>;
      expect(result.total_dependencies_scanned).toBe(1);
      expect(result.coverage?.complete).toBe(false);
      expect(result.coverage.note).toMatch(/outside\.txt/);
      expect(result.coverage.note).toMatch(/outside the project/);
    } finally {
      vi.unstubAllGlobals();
      if (priorOffline === undefined) delete process.env.FOURDA_OFFLINE;
      else process.env.FOURDA_OFFLINE = priorOffline;
    }
  });
});
/**
 * Found while fixing L5 (2026-10-17): the 4096-character cap applied to the
 * logical line AFTER backslash continuations were joined, so a
 * `pip-compile --generate-hashes` entry with many wheels was dropped
 * silently. aiohttp 3.8.0 (72 files) and pillow 10.0.0 (56) joined to 5.7 KB
 * and 4.4 KB: neither was scanned, and the scan reported nothing missing.
 * `--hash` options are not part of a pin and are dropped before the cap; a
 * line still past it is counted as a partial read.
 */
describe("hashed requirements keep every pin (pip-compile --generate-hashes)", () => {
  const hashes = (n: number) => Array.from({ length: n }, (_, i) => `    --hash=sha256:${i.toString(16).padStart(64, "0")}`).join(" \\\n");

  it("a pin with 72 hashes is read", () => {
    const content = `aiohttp==3.8.0 \\\n${hashes(72)}\n    # via -r requirements.in\nrequests==2.19.0 \\\n${hashes(2)}\n`;
    expect(parseRequirements(content)).toEqual([
      { name: "aiohttp", version: "3.8.0" },
      { name: "requests", version: "2.19.0" },
    ]);
  });

  it("the `--hash sha256:...` spelling is dropped too", () => {
    const content = `pillow==10.0.0 ${Array.from({ length: 60 }, (_, i) => `--hash sha256:${i.toString(16).padStart(64, "0")}`).join(" ")}\n`;
    expect(parseRequirements(content)).toEqual([{ name: "pillow", version: "10.0.0" }]);
  });

  it("a line that is still too long is named as a partial read, not dropped silently", () => {
    write("proj/requirements.txt", `${"a".repeat(5000)}==1.0\nrequests==2.0.0\n# ${"c".repeat(5000)}\n`);
    const read = resolveVersionSource(proj, "PyPI");
    expect(read.instances.map((i) => i.name)).toEqual(["requests"]);
    expect(read.problems).toEqual([
      { file: path.join(proj, "requirements.txt"), skipped: 1, ecosystem: "PyPI", error: expect.stringMatching(/1 line longer than 4096 characters/) },
    ]);
  });
});
describe("the scan names a refused include REFUSED, under its own key (review of M4)", () => {
  it("refused_includes, not unreadable_lockfiles", async () => {
    write("outside.txt", "django==3.2.0\n");
    write("proj/requirements.txt", "requests==2.19.0\n-r ../outside.txt\n");
    const priorOffline = process.env.FOURDA_OFFLINE;
    delete process.env.FOURDA_OFFLINE;
    vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
      if (String(input).endsWith("/v1/querybatch")) {
        const { queries } = JSON.parse(String(init?.body)) as { queries: unknown[] };
        return new Response(JSON.stringify({ results: queries.map(() => ({})) }), { status: 200 });
      }
      throw new TypeError(`fetch failed (${String(input)})`);
    });
    try {
      const result = (await executeVulnerabilityScan(null, { project_path: proj }, new LiveIntelligence(new Database(":memory:")))) as Record<string, any>;
      expect(result.coverage.note).toMatch(/REFUSED: 1 requirements include was not read: .*outside\.txt/);
      expect(result.coverage.note).not.toMatch(/UNREADABLE/);
      expect(result.coverage.refused_includes).toEqual([{ path: expect.stringMatching(/outside\.txt$/), reason: expect.stringMatching(/outside the project/) }]);
      expect(result.coverage.unreadable_lockfiles).toBeUndefined();
    } finally {
      vi.unstubAllGlobals();
      if (priorOffline === undefined) delete process.env.FOURDA_OFFLINE;
      else process.env.FOURDA_OFFLINE = priorOffline;
    }
  });
});

describe("the H3 walk is taken once per root (review of H3)", () => {
  it("discoveryFor returns the same report without walking again", async () => {
    const { discoveryFor } = await import("../project-tree.js");
    write("proj/pom.xml", "<project/>");
    const first = discoveryFor(proj);
    fs.writeFileSync(path.join(proj, "build.gradle"), "");
    expect(discoveryFor(proj)).toBe(first);
    expect(first.notCovered?.map((n) => n.path)).toEqual(["pom.xml"]);
  });
});