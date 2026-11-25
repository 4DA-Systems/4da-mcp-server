// SPDX-License-Identifier: Apache-2.0
/**
 * Audit 2026-11-25 B-B1, the scan side: a repository directory named `a$(PWN1)` or `c;PWN3;`
 * reached vulnerability_scan's `fix_targets.*.commands[].dir`, `source_dirs`, the recommendation
 * prose ("Upgrade lodash ... in a$(PWN1)") and the lockfile paths raw. As upgrade_planner does, a
 * command in such a directory is dropped (an `action_note` says why, the name escaped) and every
 * other mention is the escaped label. Ordinary directories are unchanged.
 *
 * The network is the harness's stubbed fetch: nothing leaves the process.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { isShellSafeDir, unsafeDirLabel } from "../live/shell-safe.js";
import { adv, createHarness, fixedIn, type Harness } from "./helpers/a1119-planner-harness.js";

let h: Harness;
const PROXY_VARS = ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"];
const saved: Record<string, string | undefined> = {};
beforeEach(() => {
  for (const k of PROXY_VARS) {
    saved[k] = process.env[k];
    delete process.env[k];
  }
  h = createHarness();
});
afterEach(() => {
  h.dispose();
  for (const [k, v] of Object.entries(saved)) if (v !== undefined) process.env[k] = v;
});

const LOCK = (name: string, lodash: string) =>
  JSON.stringify({ name, version: "1.0.0", lockfileVersion: 3, packages: { "": { name, version: "1.0.0", dependencies: { lodash } }, "node_modules/lodash": { version: lodash } } });

function project(dirs: string[], lodash = "4.17.20") {
  h.ADVISORIES.lodash = [adv("GHSA-35jh-r3h4-6jhm", "lodash", fixedIn("4.17.21"))];
  h.NPM = { lodash: { latest: "4.17.21", versions: { "4.17.20": {}, "4.17.21": {} } } };
  for (const [i, d] of dirs.entries()) {
    h.write(`${d}/package.json`, JSON.stringify({ name: `p${i}`, version: "1.0.0", dependencies: { lodash } }));
    h.write(`${d}/package-lock.json`, LOCK(`p${i}`, lodash));
  }
}

const commandDirs = (result: Record<string, any>): string[] =>
  Object.values((result.fix_targets ?? {}) as Record<string, { commands?: Array<{ dir: string }> }>).flatMap((t) => (t.commands ?? []).map((c) => c.dir));

describe("vulnerability_scan: a directory whose name is not a plain path", () => {
  it.each(["concise", "detailed"])("names no command there and shows the name only escaped (%s)", async (format) => {
    project(["a$(PWN1)", "c;PWN3;"]);
    const result = await h.scan({ response_format: format });
    const text = JSON.stringify(result);
    expect(text).toContain("lodash");
    expect(text).not.toContain("$(PWN1)");
    expect(text).not.toContain("c;PWN3;");
    expect(commandDirs(result).filter((d) => !isShellSafeDir(d))).toEqual([]);
    expect(text).toContain(JSON.stringify(unsafeDirLabel("a$(PWN1)")).slice(1, -1));
    if (format === "detailed") {
      // The concise answer names no commands at all; the detailed one says why it names none here.
      const target = (result.fix_targets as Record<string, { action_note?: string; commands?: unknown[] }>)["lodash@4.17.20"];
      expect(target).toBeDefined();
      expect(target.commands).toBeUndefined();
      expect(target.action_note ?? "").toMatch(/not safe to put in a command/);
    }
  });

  it.each(["b`PWN2`", "e %PWN5% x", "--registry=PWN7"])("the same for %j", async (d) => {
    project([d]);
    const text = JSON.stringify(await h.scan({ response_format: "detailed" }));
    expect(text).not.toContain(JSON.stringify(d).slice(1, -1));
    expect(text).toContain(/PWN\d+/.exec(d)![0]);
  });

  it("a safe directory beside an unsafe one keeps its command", async () => {
    project(["ok", "a$(PWN1)"]);
    const result = await h.scan({ response_format: "detailed" });
    expect(JSON.stringify(result)).not.toContain("$(PWN1)");
    expect(commandDirs(result)).toContain("ok");
    expect(commandDirs(result).filter((d) => !isShellSafeDir(d))).toEqual([]);
  });

  it("ordinary directories are unchanged", async () => {
    project(["apps/my app", "packages/@scope/ui"]);
    const result = await h.scan({ response_format: "detailed" });
    const text = JSON.stringify(result);
    expect(text).not.toContain("unsafe directory name");
    expect(text).not.toMatch(/not safe to put in a command/);
    const rows = result.vulnerabilities as Array<{ source_dirs: string[] }>;
    expect(rows.flatMap((r) => r.source_dirs).sort()).toEqual(["apps/my app", "packages/@scope/ui"]);
  });
});
