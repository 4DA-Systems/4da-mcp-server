// SPDX-License-Identifier: Apache-2.0
/**
 * Wave 2, design 2b (Python, Go), from the executed crewAI 0.86.0 and gh cli v2.14.0 plans (audit
 * 2026-11-25 Track B M6, M7, minor 1):
 * - `uv lock --upgrade-package mem0ai==2.0.18` lowered mem0ai 2.2.1, which the litellm step's
 *   resolution had brought in: every uv upgrade of one lockfile now runs as ONE `uv lock`, so uv
 *   resolves every pin at once and no pin lowers what another raised;
 * - `uv lock --upgrade-package crewai-tools==1.15.1` could not lock: crewai-tools 1.15.1 requires
 *   crewai==1.15.1 and the project is crewai 0.86.0: no command, words;
 * - gorilla/websocket v1.5.3 was listed under a go get's `fixes` while every advisory of the row
 *   still affects it: a target that clears none of the row's advisories is not a fix.
 */

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { FixPathSources } from "../live/fix-paths.js";
import { buildRunOrder, type SequencedRow } from "../tools/upgrade-plan-sequence.js";
import { hasSelfRequiringTarget, withoutSelfRequiringTargets, withPythonFloorHolds, type RunnableRow } from "../tools/upgrade-plan-runnable.js";
import { HELD_UNCLEAN_REASON } from "../live/fix-paths.js";
import type { VulnerabilityScanResult } from "../live/types.js";
import { adv, createHarness, type Harness } from "./helpers/a1119-planner-harness.js";
import { unpinnedInMergedUvLock } from "../tools/upgrade-planner.js";

const uvRow = (pkg: string, run: string): SequencedRow => ({
  package: pkg,
  ecosystem: "PyPI",
  currentVersion: "1.0.0",
  targetVersion: "2.0.0",
  action: "upgrade_direct",
  reasons: [],
  upgradeCommands: [{ dir: ".", command: run }],
  commands: [{ dir: ".", run }],
});

describe("every uv upgrade of one lockfile runs as one uv lock", () => {
  it("pins and plain upgrades merge, sorted; of two pins the higher stays; the note says what to do when it fails", () => {
    const rows = [
      uvRow("litellm", "uv lock --upgrade-package litellm==1.100.4"),
      uvRow("mem0ai", "uv lock --upgrade-package mem0ai==2.0.18"),
      uvRow("certifi", "uv lock --upgrade-package certifi"),
      uvRow("anyio", "uv lock --upgrade-package anyio==4.10.0"),
      uvRow("anyio", "uv lock --upgrade-package anyio==4.14.2"),
    ];
    const order = buildRunOrder({ rows, totalRows: rows.length, heldUnclean: () => false });
    expect(order.run_order).toHaveLength(1);
    expect(order.run_order[0].run).toBe("uv lock --upgrade-package anyio==4.14.2 --upgrade-package certifi --upgrade-package litellm==1.100.4 --upgrade-package mem0ai==2.0.18");
    expect(order.run_order[0].fixes).toEqual(["PyPI:anyio", "PyPI:certifi", "PyPI:litellm", "PyPI:mem0ai"]);
    expect(order.run_order_note).toMatch(/the 4 uv upgrades of the project root run as one `uv lock`, so no pin lowers a version another upgrade's resolution raised/);
    expect(order.run_order_note).toMatch(/run the rows' own commands one at a time and leave out the one that fails/);
  });

  it("a pin beats a plain upgrade of the same package; different lockfiles stay apart", () => {
    const a = uvRow("idna", "uv lock --upgrade-package idna");
    const b = uvRow("idna", "uv lock --upgrade-package idna==3.7");
    const c = { ...uvRow("idna", "uv lock --upgrade-package idna==3.7"), upgradeCommands: [{ dir: "svc", command: "uv lock --upgrade-package idna==3.7" }], commands: [{ dir: "svc", run: "uv lock --upgrade-package idna==3.7" }] };
    const order = buildRunOrder({ rows: [a, b, c], totalRows: 3, heldUnclean: () => false });
    expect(order.run_order.map((s) => [s.dir, s.run])).toEqual([
      [".", "uv lock --upgrade-package idna==3.7"],
      ["svc", "uv lock --upgrade-package idna==3.7"],
    ]);
  });
});

describe("a uv target that requires the project itself at another version is not a command", () => {
  let root: string;
  beforeEach(() => {
    root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "4da-w2-uv-")));
    fs.writeFileSync(
      path.join(root, "uv.lock"),
      'version = 1\nrequires-python = ">=3.10"\n\n[[package]]\nname = "crewai"\nversion = "0.86.0"\nsource = { editable = "." }\n\n[[package]]\nname = "crewai-tools"\nversion = "0.17.0"\nsource = { registry = "https://pypi.org/simple" }\n',
    );
  });
  afterEach(() => fs.rmSync(root, { recursive: true, force: true }));
  const row = (): RunnableRow => ({
    package: "crewai-tools",
    ecosystem: "PyPI",
    currentVersion: "0.17.0",
    targetVersion: "1.15.1",
    scope: "direct",
    reasons: ["Fixable now with a lockfile refresh (the declared range already admits the fix): `uv lock --upgrade-package crewai-tools==1.15.1`"],
    upgradeCommands: [{ dir: ".", command: "uv lock --upgrade-package crewai-tools==1.15.1" }],
  });
  const sources = (requires: string[] | null) => ({ pypiRequiresDist: async () => requires }) as unknown as Pick<FixPathSources, "pypiRequiresDist">;

  it("crewai-tools 1.15.1 requires crewai==1.15.1 and the project is crewai 0.86.0: words, not counted", async () => {
    const r = row();
    await withoutSelfRequiringTargets([r], root, sources(["crewai==1.15.1", "requests>=2.31"]));
    expect(r.upgradeCommands).toBeUndefined();
    expect(r.upgradeInstructions?.[0].instruction).toMatch(/^no command: crewai-tools 1\.15\.1 requires crewai "==1\.15\.1", and crewai is this project itself \(0\.86\.0 in uv\.lock\)/);
    expect(r.reasons.some((x) => x.startsWith("Fixable now with a lockfile refresh"))).toBe(false);
    expect(hasSelfRequiringTarget(r)).toBe(true);
  });

  it("a requirement the project's version satisfies, an extra, or unread requirements keep the command", async () => {
    for (const requires of [["crewai>=0.80"], ["crewai==1.15.1; extra == 'core'"], null]) {
      const r = row();
      await withoutSelfRequiringTargets([r], root, sources(requires));
      expect(r.upgradeCommands).toHaveLength(1);
      expect(hasSelfRequiringTarget(r)).toBe(false);
    }
  });
});

describe("a target that clears none of the row's advisories is not a fix", () => {
  let h: Harness;
  const saved: Record<string, string | undefined> = {};
  beforeEach(() => {
    for (const k of ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"]) {
      saved[k] = process.env[k];
      delete process.env[k];
    }
    h = createHarness();
  });
  afterEach(() => {
    h.dispose();
    for (const [k, v] of Object.entries(saved)) if (v !== undefined) process.env[k] = v;
  });

  const ws = "github.com/gorilla/websocket";
  const net = "golang.org/x/net";
  // GO-2026-6278 as OSV.dev records it: fixed in 1.5.1, introduced again in 1.5.3, fixed only in a pseudo-version.
  const goRecord = () => ({ ...adv("GO-2026-6278", ws, [{ introduced: "0" }, { fixed: "1.5.1" }, { introduced: "1.5.3" }, { fixed: "1.5.4-0.20240701034025-d67f41855da4" }], "Go"), aliases: ["GHSA-w67g-5rqw-f597"] });
  // Its alias GHSA-w67g-5rqw-f597 as OSV.dev records it: fixed in 1.5.3 (so 1.5.1 and 1.5.2 are affected by it).
  const ghsaRecord = () => ({ ...adv("GHSA-w67g-5rqw-f597", ws, [{ introduced: "0" }, { fixed: "1.5.3" }], "Go"), aliases: ["GO-2026-6278"] });
  const goProject = () => {
    h.ADVISORIES[net] = [adv("GO-2023-1495", net, [{ introduced: "0" }, { fixed: "0.7.0" }], "Go")];
    h.GO = { [ws]: ["v1.4.2", "v1.5.0", "v1.5.1", "v1.5.2", "v1.5.3"], [net]: ["v0.5.0", "v0.7.0"] };
    h.GOMOD = { [`${ws}@v1.5.1`]: "1.12", [`${ws}@v1.5.3`]: "1.12", [`${net}@v0.7.0`]: "1.17" };
    h.write("go.mod", `module example.com/app\n\ngo 1.18\n\nrequire (\n\t${ws} v1.4.2\n\t${net} v0.5.0\n)\n`);
    h.write("go.sum", `${ws} v1.4.2 h1:x=\n${ws} v1.4.2/go.mod h1:x=\n${net} v0.5.0 h1:x=\n${net} v0.5.0/go.mod h1:x=\n`);
  };
  const fixesOf = (result: Record<string, any>) => result.run_order.flatMap((s: { fixes: string[] }) => s.fixes);

  it("fixed, then introduced again: the target is the smallest clean release above the installed one (v1.5.1), never the affected newest", async () => {
    h.ADVISORIES[ws] = [goRecord()];
    goProject();
    const { result, step } = await h.plan();
    const row = step(ws);
    expect(row.targetVersion).toBe("v1.5.1");
    expect(row.commands).toEqual([{ dir: ".", run: `go get ${ws}@v1.5.1` }]);
    expect(fixesOf(result)).toContain(`Go:${ws}`);
  });

  it("the real pair of records disagrees (GHSA fixed in 1.5.3, GO affected from 1.5.3): no release clears both, so no step serves it and it is not counted", async () => {
    h.ADVISORIES[ws] = [goRecord(), ghsaRecord()];
    goProject();
    const { result, step } = await h.plan();
    const row = step(ws);
    expect(row).toBeDefined();
    expect(row.commands).toEqual([]);
    expect(row.reasons.join("\n")).toMatch(/it is NOT a fix, since github\.com\/gorilla\/websocket v1\.5\.3 is still affected by/);
    expect(fixesOf(result)).not.toContain(`Go:${ws}`);
    expect(result.run_order.map((s: { run: string }) => s.run).join("\n")).not.toContain("websocket");
    // The fix that is real still runs.
    expect(fixesOf(result)).toContain(`Go:${net}`);
  });
});

describe("a uv pin whose requirement resolves to an affected release on the project's lowest Python is held", () => {
  let root: string;
  beforeEach(() => {
    root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "4da-w2-floor-")));
    fs.writeFileSync(path.join(root, "uv.lock"), 'version = 1\nrequires-python = ">=3.10, <=3.13"\n');
  });
  afterEach(() => fs.rmSync(root, { recursive: true, force: true }));
  const row = (): RunnableRow => ({
    package: "virtualenv", ecosystem: "PyPI", currentVersion: "20.27.0", targetVersion: "21.14.13", scope: "transitive", reasons: [],
    refreshCommands: [{ dir: ".", command: "uv lock --upgrade-package virtualenv==21.14.13" }],
  });
  const requires = ['distlib<1,>=0.4.3', 'filelock<5,>=3.24.2; python_version >= "3.10"', 'filelock<=3.19.1,>=3.19.1; python_version < "3.10"'];
  const facts = { versions: ["3.16.1", "3.24.2", "4.1.0", "4.2.1"], withdrawn: [], withdrawnWhy: {}, latest: "4.2.1", requiresPython: { "4.1.0": ">=3.10", "4.2.1": ">=3.11" } };
  const sources = { pypiRequiresDist: async () => requires, releaseFacts: async (_e: string, n: string) => (n === "filelock" ? facts : { versions: [], withdrawn: [], withdrawnWhy: {}, latest: null }) } as unknown as Pick<FixPathSources, "pypiRequiresDist" | "releaseFacts">;
  // OSV.dev for filelock: 4.1.0 is affected (high, medium, low), 4.2.1 is clean.
  const v41 = [
    { package: "filelock", currentVersion: "4.1.0", vulnId: "GHSA-v4x8-3wr5-3wq8", aliases: [], severity: "high", maintenance: false },
    { package: "filelock", currentVersion: "4.1.0", vulnId: "GHSA-2g95-wg33-c5x2", aliases: [], severity: "medium", maintenance: false },
    { package: "filelock", currentVersion: "4.1.0", vulnId: "GHSA-567q-5qvw-pf92", aliases: [], severity: "low", maintenance: false },
  ];
  const answer = (affected: boolean) => async () => ({ vulnerabilities: affected ? v41 : [] }) as unknown as VulnerabilityScanResult;
  // The scan: virtualenv 20.27.0 has 2 advisories, the locked filelock 3.16.1 has 1.
  const scan = (name: string, version: string | null) =>
    (name === "virtualenv" && version === "20.27.0"
      ? [{ vulnId: "GHSA-aaaa-aaaa-aaaa", aliases: [] }, { vulnId: "GHSA-bbbb-bbbb-bbbb", aliases: [] }]
      : name === "filelock" && version === "3.16.1"
        ? [{ vulnId: "GHSA-cccc-cccc-cccc", aliases: [] }]
        : []) as never;

  it("virtualenv 21.14.13 on Python 3.10 brings filelock 4.1.0 (4.2.x needs 3.11): NOT a clean fix", async () => {
    const r = row();
    fs.writeFileSync(path.join(root, "uv.lock"), 'version = 1\nrequires-python = ">=3.10, <=3.13"\n\n[[package]]\nname = "filelock"\nversion = "3.16.1"\nsource = { registry = "https://pypi.org/simple" }\n');
    await withPythonFloorHolds([r], root, sources, answer(true), Date.now() + 5_000, scan);
    const held = r.reasons.find((x) => HELD_UNCLEAN_REASON.test(x));
    // One read: what it clears, what it installs on the lowest Python, what the clean release needs, the two ways out.
    expect(held).toBe(
      "virtualenv 21.14.13 is NOT a clean fix: confirm a release with dependency_check before pinning it. " +
        'It would clear 2 advisories on virtualenv 20.27.0 and 1 advisory on filelock 3.16.1, which it moves, but on this project\'s lowest supported Python (3.10, from uv.lock) it requires filelock "<5,>=3.24.2", and the newest filelock that Python can install is 4.1.0, which 3 advisories affect (worst: high; GHSA-v4x8-3wr5-3wq8, GHSA-2g95-wg33-c5x2, GHSA-567q-5qvw-pf92). ' +
        'The first clean filelock it admits is 4.2.1, which needs Python ">=3.11". Two ways out: raise requires-python in pyproject.toml to ">=3.11" (it is ">=3.10, <=3.13" now) and call upgrade_planner again; or take the upgrade knowingly by writing the requirement virtualenv==21.14.13 yourself (the command is `uv lock --upgrade-package virtualenv==21.14.13`; it is not in run_order).',
    );
  });

  it("a clean release on the floor, or a floor that changes nothing, keeps the step", async () => {
    const r = row();
    await withPythonFloorHolds([r], root, sources, answer(false), Date.now() + 5_000);
    expect(r.reasons).toEqual([]);
    fs.writeFileSync(path.join(root, "uv.lock"), 'version = 1\nrequires-python = ">=3.11"\n');
    const q = row();
    await withPythonFloorHolds([q], root, sources, answer(true), Date.now() + 5_000);
    expect(q.reasons).toEqual([]);
  });
});

describe("a uv refresh with no pin, inside the merged uv lock, never names an outcome it cannot promise", () => {
  it("cryptography: the row's words say the resolver decides and the scan after the run checks; the command is unchanged", () => {
    const row = {
      package: "cryptography",
      ecosystem: "PyPI",
      reasons: ["Transitive dependency: ... so then run `uv lock --upgrade-package cryptography` in . (a refresh resolves it to 50.0.2)"],
      commands: [{ dir: ".", run: "uv lock --upgrade-package cryptography" }],
    };
    const step = { n: 1, dir: ".", run: "uv lock --upgrade-package auth0-python==4.8.0 --upgrade-package cryptography", fixes: ["PyPI:auth0-python", "PyPI:cryptography"] };
    unpinnedInMergedUvLock([row] as never, [step]);
    expect(row.reasons[0]).toContain("(on its own, a refresh resolves it to 50.0.2; in run_order the resolver decides, see below)");
    expect(row.reasons[0]).not.toMatch(/\(a refresh resolves it to 50\.0\.2\)/);
    expect(row.reasons[1]).toMatch(/^uv: no version is pinned for cryptography in run_order's step 1: it runs in one `uv lock` with 1 other upgrade, where the resolver decides the version it lands on/);
    expect(row.reasons[1]).toMatch(/vulnerability_scan after the run says where it landed/);
    expect(row.commands).toEqual([{ dir: ".", run: "uv lock --upgrade-package cryptography" }]);
  });

  it("a pinned row, or a uv lock with one package, keeps its words", () => {
    const pinned = { package: "anyio", ecosystem: "PyPI", reasons: ["x (a refresh resolves it to 4.14.2)"], commands: [{ dir: ".", run: "uv lock --upgrade-package anyio==4.14.2" }] };
    const alone = { package: "idna", ecosystem: "PyPI", reasons: ["y (a refresh resolves it to 3.7)"], commands: [{ dir: ".", run: "uv lock --upgrade-package idna" }] };
    unpinnedInMergedUvLock([pinned, alone] as never, [
      { n: 1, dir: ".", run: "uv lock --upgrade-package anyio==4.14.2 --upgrade-package certifi", fixes: ["PyPI:anyio", "PyPI:certifi"] },
      { n: 2, dir: "svc", run: "uv lock --upgrade-package idna", fixes: ["PyPI:idna"] },
    ]);
    expect(pinned.reasons).toEqual(["x (a refresh resolves it to 4.14.2)"]);
    expect(alone.reasons).toEqual(["y (a refresh resolves it to 3.7)"]);
  });
});
