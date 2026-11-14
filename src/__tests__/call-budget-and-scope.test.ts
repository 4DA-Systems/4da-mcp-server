// SPDX-License-Identifier: Apache-2.0
/**
 * The bounds a tool call runs inside (audit 2026-11-11):
 *
 * - time: no call had an overall deadline. A cold `dependency_check` took 21 to 37 s, and with
 *   OSV.dev stalled 49 s, then said OSV "did not answer within 15 s";
 * - place: `project_path`, and the directory a host starts the server in, were unconfined. A scan
 *   of C:\Windows\System32 sent 2,122 package pairs;
 * - one lockfile's facts for another's: a stale lockfile switched the host-platform filter off for
 *   every crate it shares with the project's real one;
 * - and three answers that read as fine when nothing had been checked: `dependency_health` with an
 *   ecosystem filter that matches nothing (100/100 over 0 dependencies), a scan served from the
 *   cache with the network dead (`offline: false`), and a proxy the process silently ignores.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import Database from "better-sqlite3";
import { callBudgetMs, raceCallBudget, remainingCallBudgetMs, runWithCallBudget, scanUnfinishedText, settleWithin, withinCallBudget } from "../call-budget.js";
import { lateAnswer } from "../late-answer.js";
import { setLiveIntelligence } from "../live-singleton.js";
import { _resetCargoPlatformCache, activeCratesForHost } from "../live/cargo-platform.js";
import { dedupeDependencies } from "../live/dependency-set.js";
import { LiveIntelligence } from "../live/index.js";
import type { ResolvedDependency, VulnerabilityEntry, VulnerabilityScanResult } from "../live/types.js";
import { configureProxy } from "../proxy.js";
import { scanProjectTree, treeResolutionGroups } from "../project-tree.js";
import { dispatchTool } from "../tool-dispatch.js";
import { executeDependencyHealth } from "../tools/dependency-health.js";
import { resolveProjectScope, serverDirectoryRefusal, systemDirectoryProblem } from "../tools/project-scope.js";
import { executeUpgradePlanner } from "../tools/upgrade-planner.js";
import { executeVulnerabilityScan } from "../tools/vulnerability-scan.js";
import { formatScanResult } from "../tools/vulnerability-scan-format.js";
import type { FourDADatabase } from "../db.js";
import { resultText, serverEntry, stdioSession } from "./helpers/stdio-session.js";

const noDb = null as unknown as FourDADatabase;

let dir: string;
let priorOffline: string | undefined;
/** Requests a stalled network is holding; released after each test so nothing outlives it. */
let held: Array<(reason: Error) => void> = [];

beforeEach(() => {
  priorOffline = process.env.FOURDA_OFFLINE;
  delete process.env.FOURDA_OFFLINE;
  dir = fs.mkdtempSync(path.join(os.tmpdir(), "4da-bounds-"));
  held = [];
});

afterEach(() => {
  for (const release of held) release(new TypeError("fetch released at the end of the test"));
  vi.unstubAllGlobals();
  delete process.env.FOURDA_CALL_BUDGET_MS;
  if (priorOffline === undefined) delete process.env.FOURDA_OFFLINE;
  else process.env.FOURDA_OFFLINE = priorOffline;
  fs.rmSync(dir, { recursive: true, force: true });
});

/** A network that accepts every request and never answers. */
function stallNetwork(): { requests: string[] } {
  const requests: string[] = [];
  vi.stubGlobal("fetch", (input: string | URL) => {
    requests.push(String(input));
    return new Promise<Response>((_, reject) => held.push(reject));
  });
  return { requests };
}

function npmProject(at = dir) {
  fs.mkdirSync(at, { recursive: true });
  fs.writeFileSync(path.join(at, "package.json"), JSON.stringify({ name: "x", dependencies: { lodash: "4.17.21", ms: "2.1.3" } }));
  fs.writeFileSync(
    path.join(at, "package-lock.json"),
    JSON.stringify({ name: "x", lockfileVersion: 3, packages: { "": { name: "x", dependencies: { lodash: "4.17.21", ms: "2.1.3" } }, "node_modules/lodash": { version: "4.17.21" }, "node_modules/ms": { version: "2.1.3" } } }),
  );
}

function liveFor(root = dir): LiveIntelligence {
  const li = new LiveIntelligence(new Database(":memory:"));
  const { entries, discovery } = scanProjectTree(root);
  li.initFromProjectTree(root, treeResolutionGroups(entries), discovery);
  return li;
}

const parse = (result: { content: Array<{ type: string; text?: string }> }) => JSON.parse(result.content[0].text ?? "{}") as Record<string, any>;

// ---------------------------------------------------------------------------
// Time
// ---------------------------------------------------------------------------

describe("one time budget per tool call", () => {
  it("the budget: 20 s by default, FOURDA_CALL_BUDGET_MS overrides it, and there is none outside a call", async () => {
    expect(callBudgetMs()).toBe(20_000);
    process.env.FOURDA_CALL_BUDGET_MS = "750";
    expect(callBudgetMs()).toBe(750);
    expect(remainingCallBudgetMs()).toBe(Number.POSITIVE_INFINITY);
    expect(withinCallBudget(60_000)).toBe(60_000);
    await runWithCallBudget(Date.now() - 250, async () => {
      expect(remainingCallBudgetMs()).toBeGreaterThan(300);
      expect(remainingCallBudgetMs()).toBeLessThanOrEqual(500);
      // A wait is sized from what is left, less what the tool still has to do afterwards.
      expect(withinCallBudget(60_000, 200)).toBeLessThanOrEqual(300);
      expect(withinCallBudget(100, 200)).toBe(100);
      expect(withinCallBudget(60_000, 5_000)).toBe(0);
    });
  });

  it("work that finishes in time is returned; work that does not is answered for, and left running", async () => {
    process.env.FOURDA_CALL_BUDGET_MS = "150";
    const fast = await runWithCallBudget(Date.now(), () => raceCallBudget(Promise.resolve("done"), () => "late"));
    expect(fast).toBe("done");
    let finished = false;
    const slow = new Promise<string>((resolve) => setTimeout(() => ((finished = true), resolve("done")), 400));
    const started = Date.now();
    const answer = await runWithCallBudget(started, () => raceCallBudget(slow, (ms) => `late after ${ms}`));
    expect(answer).toBe("late after 150");
    expect(Date.now() - started).toBeLessThan(350);
    expect(finished).toBe(false);
    await slow;
    // A rejection after the budget is nobody's to handle; before it, it is the call's error.
    const failing = runWithCallBudget(Date.now(), () => raceCallBudget(Promise.reject(new Error("boom")), () => "late"));
    await expect(failing).rejects.toThrow("boom");
    expect(await settleWithin(new Promise<string>(() => undefined), 20, () => "late")).toBe("late");
    expect(await settleWithin(Promise.resolve("done"), Number.POSITIVE_INFINITY, () => "late")).toBe("done");
  });

  it("dependency_check with every lookup stalled answers at its budget: each item unknown, and the real time said", async () => {
    stallNetwork();
    setLiveIntelligence(new LiveIntelligence(new Database(":memory:")));
    process.env.FOURDA_CALL_BUDGET_MS = "300";
    const started = Date.now();
    const result = await dispatchTool(
      "dependency_check",
      null,
      { items: [{ ecosystem: "PyPI", package: "Django", to: "5.1.4" }, { ecosystem: "npm", package: "lodash", from: "4.17.20", to: "4.17.21" }] },
      { startedAt: started },
    );
    expect(Date.now() - started).toBeLessThan(1_500);
    const answer = parse(result);
    expect(result.isError).toBeUndefined();
    expect(answer.summary).toMatch(/^NOT CHECKED: dependency_check did not finish within 0\.3 s; 2 checked: 2 unknown\. Write none of these versions on this answer\./);
    expect(answer.results).toHaveLength(2);
    for (const item of answer.results) {
      expect(item.verdict).toBe("unknown");
      expect(item.reason).toMatch(/^NOT CHECKED: .* did not finish within 0\.3 s, so nothing about this version was verified\. This is not a proceed\./);
      expect(item.signals).toEqual([]);
    }
    expect(answer.results[1]).toMatchObject({ ecosystem: "npm", package: "lodash", from: "4.17.20", to: "4.17.21" });
    expect(answer._meta).toMatchObject({ call_budget_exceeded: true, call_budget_ms: 300 });
    // Never a proceed, anywhere in it.
    expect(JSON.stringify(answer)).not.toMatch(/"verdict":"proceed"/);
  });

  it("the time the request already spent before dispatch counts: a call that arrives late answers at once", async () => {
    stallNetwork();
    setLiveIntelligence(new LiveIntelligence(new Database(":memory:")));
    process.env.FOURDA_CALL_BUDGET_MS = "5000";
    const started = Date.now();
    const result = await dispatchTool("dependency_check", null, { items: [{ ecosystem: "npm", package: "lodash", to: "4.17.21" }] }, { startedAt: started - 4_900 });
    expect(Date.now() - started).toBeLessThan(1_000);
    expect(parse(result).summary).toMatch(/did not finish within 5 s/);
  });

  it("vulnerability_scan with OSV.dev stalled answers inside its budget, NOT CHECKED, with every dependency counted unchecked", async () => {
    npmProject();
    stallNetwork();
    setLiveIntelligence(liveFor());
    // 6 s are kept back for the fix targets, so this leaves the scan 0.4 s.
    process.env.FOURDA_CALL_BUDGET_MS = "6400";
    const started = Date.now();
    const result = await dispatchTool("vulnerability_scan", null, { response_format: "detailed" }, { startedAt: started });
    expect(Date.now() - started).toBeLessThan(3_000);
    const answer = parse(result);
    expect(answer.summary).toMatch(/^NOT CHECKED: the OSV\.dev scan did not finish within 0\.4 s, the time this call had for it \(it keeps running and its answers are cached: call again\)/);
    expect(answer.coverage).toMatchObject({ complete: false, unchecked_dependencies: 2 });
    expect(answer.total_vulnerable_packages).toBeNull();
    expect(answer.clean_dependencies).toBeNull();
  });

  it.each(["1", "50", "400"])(
    "vulnerability_scan with FOURDA_CALL_BUDGET_MS=%s says the budget was used up, never 'within 0 ms' (blind audit round 4)",
    async (budget) => {
      npmProject();
      stallNetwork();
      setLiveIntelligence(liveFor());
      process.env.FOURDA_CALL_BUDGET_MS = budget;
      const result = await dispatchTool("vulnerability_scan", null, { response_format: "detailed" }, { startedAt: Date.now() });
      const text = JSON.stringify(parse(result));
      expect(text).not.toMatch(/within 0 (ms|s)\b/);
      // A 1 ms budget can end before the tool runs at all: the dispatcher's own answer then names it.
      for (const tool of ["dependency_health"]) {
        setLiveIntelligence(liveFor());
        const other = JSON.stringify(parse(await dispatchTool(tool, null, {}, { startedAt: Date.now() })));
        expect(other, tool).not.toMatch(/within 0 (ms|s)\b/);
      }
      const said = budget === "1" ? "1 ms" : budget === "50" ? "0\\.1 s" : "0\\.4 s";
      expect(text).toMatch(new RegExp(`time budget \\(${said}, from FOURDA_CALL_BUDGET_MS\\) was used up before the OSV\\.dev scan could finish|vulnerability_scan did not finish within ${said}`));
    },
  );

  it("the scan's missing-answer sentence names the budget when the wait was about 0, and the wait otherwise (blind audit round 4)", async () => {
    process.env.FOURDA_CALL_BUDGET_MS = "400";
    await runWithCallBudget(Date.now(), async () => {
      expect(scanUnfinishedText(0)).toBe("this call's time budget (0.4 s, from FOURDA_CALL_BUDGET_MS) was used up before the OSV.dev scan could finish");
      expect(scanUnfinishedText(40)).not.toMatch(/within/);
      expect(scanUnfinishedText(400)).toBe("the OSV.dev scan did not finish within 0.4 s, the time this call had for it");
    });
    delete process.env.FOURDA_CALL_BUDGET_MS;
    expect(scanUnfinishedText(0)).toBe("this call's time budget (20 s) was used up before the OSV.dev scan could finish");
  });

  it("any other tool that outlives its budget gets an error that starts NOT CHECKED", () => {
    const late = lateAnswer("upgrade_impact", { package: "vite" }, 20_000);
    expect(late.error).toMatch(/^NOT CHECKED: upgrade_impact did not finish within 20 s, so this call verified nothing; the absence of findings here is not a clean result\./);
    expect(late.call_budget_exceeded).toBe(true);
    // A malformed dependency_check request still gets a well-formed answer.
    expect(lateAnswer("dependency_check", { items: "nope" }, 1_000).error).toMatch(/^NOT CHECKED: dependency_check/);
    expect((lateAnswer("dependency_check", { items: [null, { ecosystem: "npm", package: "a".repeat(900), to: 7 }] }, 1_000).results as unknown[]).length).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// Place
// ---------------------------------------------------------------------------

describe("an operating-system directory is never scanned", () => {
  it("Windows: drive roots, the Windows directory and everything below it, the roots of Program Files, ProgramData and Users", () => {
    const env = { SystemDrive: "C:", SystemRoot: "C:\\Windows", ProgramFiles: "C:\\Program Files", "ProgramFiles(x86)": "C:\\Program Files (x86)", ProgramData: "C:\\ProgramData" };
    const refused = (d: string) => systemDirectoryProblem(d, { platform: "win32", env });
    for (const d of ["C:\\", "D:\\", "c:\\", "C:\\Windows", "C:\\Windows\\System32", "c:\\windows\\system32\\drivers\\etc", "C:\\WINDOWS\\", "C:\\Program Files", "C:\\Program Files (x86)\\", "C:\\ProgramData", "C:\\Users", "\\\\server\\share\\"]) {
      expect(refused(d), d).toMatch(/is (a drive root|the Windows directory|an operating-system directory[^,]*), not a project, so it is not scanned/);
    }
    for (const d of ["C:\\Users\\dev\\code\\app", "D:\\4DA", "C:\\Program Files\\MyApp\\src", "C:\\WindowsApps-project", "C:\\Users\\dev", "relative\\path", "\\\\server\\share\\repo"]) {
      expect(refused(d), d).toBeNull();
    }
    expect(refused("C:\\Windows\\System32")).toBe(
      '"C:\\Windows\\System32" is an operating-system directory (inside C:\\Windows), not a project, so it is not scanned: a scan there would read every lockfile below it and send each package name and version to OSV.dev and the registries. ' +
        "Pass project_path with the absolute path of your project's root (or set FOURDA_PROJECT_DIR for the server).",
    );
  });

  it("Windows: every spelling of a system directory is refused, not just the plain one (blind audit round 3)", () => {
    const env = { SystemDrive: "C:", SystemRoot: "C:\\Windows", ProgramFiles: "C:\\Program Files", "ProgramFiles(x86)": "C:\\Program Files (x86)", ProgramData: "C:\\ProgramData" };
    const refused = (d: string) => systemDirectoryProblem(d, { platform: "win32", env });
    for (const d of ["\\\\127.0.0.1\\C$\\Windows\\System32", "\\\\localhost\\C$\\Windows", "\\\\?\\C:\\Windows", "\\\\?\\UNC\\localhost\\C$\\Windows", "\\\\host\\c$\\", "\\\\.\\C:\\Windows"]) {
      expect(refused(d), d).not.toBeNull();
    }
    expect(refused("\\\\localhost\\C$\\Windows")).toContain('"\\\\localhost\\C$\\Windows" (C:\\Windows) is the Windows directory');
    // A share that is not an administrative one, and a project on one, are ordinary paths.
    expect(refused("\\\\server\\share\\repo")).toBeNull();
    expect(refused("\\\\?\\D:\\4DA")).toBeNull();
  });

  it("Windows: the shared and template profiles, the recycle bin, and a WSL distribution's system directories are refused (blind audit round 4)", () => {
    const env = { SystemDrive: "C:", SystemRoot: "C:\\Windows", ProgramFiles: "C:\\Program Files", "ProgramFiles(x86)": "C:\\Program Files (x86)", ProgramData: "C:\\ProgramData" };
    const refused = (d: string) => systemDirectoryProblem(d, { platform: "win32", env });
    for (const d of [
      "C:\\Users\\Public",
      "c:\\users\\public\\",
      "C:\\Users\\Default",
      "C:\\Users\\All Users",
      "C:\\$Recycle.Bin",
      "C:\\$Recycle.Bin\\S-1-5-21-1",
      "D:\\$RECYCLE.BIN",
      "C:\\System Volume Information",
      "\\\\wsl$\\Ubuntu\\etc",
      "\\\\wsl$\\Ubuntu\\usr\\lib",
      "\\\\wsl.localhost\\Ubuntu-22.04\\etc",
      "\\\\wsl.localhost\\Debian\\proc\\1",
      "\\\\wsl$\\Ubuntu\\",
      "\\\\wsl$\\Ubuntu\\mnt\\c",
      "\\\\wsl$\\Ubuntu\\mnt\\c\\Windows\\System32",
    ]) {
      expect(refused(d), d).toMatch(/is (a drive root|the filesystem root|the Windows directory|an operating-system directory[^,]*), not a project, so it is not scanned/);
    }
    expect(refused("\\\\wsl$\\Ubuntu\\etc")).toContain('"\\\\wsl$\\Ubuntu\\etc" (/etc in WSL) is an operating-system directory');
    // Where projects live: a user's own profile, and a WSL home or /srv.
    for (const d of ["C:\\Users\\Public-Site", "C:\\Users\\dev\\Public", "C:\\Users\\Defaulted\\app", "\\\\wsl$\\Ubuntu\\home\\dev\\app", "\\\\wsl.localhost\\Ubuntu\\srv\\app", "\\\\wsl$\\Ubuntu\\mnt\\c\\code\\app"]) {
      expect(refused(d), d).toBeNull();
    }
  });

  it("the server's own directory is named in a sentence that reads naturally (blind audit round 4)", () => {
    const why = systemDirectoryProblem("C:\\Windows", { platform: "win32", env: { SystemDrive: "C:", SystemRoot: "C:\\Windows" } })!;
    expect(serverDirectoryRefusal(why)).toMatch(/^The server's directory "C:\\Windows" is the Windows directory, not a project, so it is not scanned/);
    expect(serverDirectoryRefusal(why)).not.toContain("started in");
  });

  it.runIf(process.platform === "win32")("Windows, live: an 8.3 short name is the directory it names (C:\\PROGRA~1)", () => {
    expect(systemDirectoryProblem("C:\\PROGRA~1")).toContain("operating-system directory");
  });

  it("POSIX: the root, the system's own directories by exact path, and the kernel and system trees whole", () => {
    const refused = (d: string, platform: NodeJS.Platform = "linux") => systemDirectoryProblem(d, { platform, env: {} });
    for (const d of ["/", "/usr", "/usr/", "/usr/lib", "/usr/local", "/bin", "/etc", "/var", "/opt", "/home", "/proc", "/proc/1/cwd", "/sys/kernel", "/dev/shm", "/mnt/c"]) {
      expect(refused(d), d).not.toBeNull();
    }
    for (const d of ["/System", "/System/Library/Frameworks", "/Library", "/Applications", "/Users", "/Volumes", "/private/var", "/system", "/APPLICATIONS"]) {
      expect(refused(d, "darwin"), d).not.toBeNull();
    }
    // Where projects do live: below the homes, /opt, /var, /usr/local/src, /srv, a mounted volume.
    for (const d of ["/home/dev/app", "/opt/app", "/var/www/site", "/usr/local/src/app", "/usr/src/app", "/srv/app", "/app", "/workspace", "/root/app", "/mnt/c/code/app", "/tmp/x"]) {
      expect(refused(d), d).toBeNull();
    }
    expect(refused("/Users/dev/code", "darwin")).toBeNull();
    expect(refused("/Volumes/Work/app", "darwin")).toBeNull();
    // Case decides on Linux.
    expect(refused("/USR")).toBeNull();
  });

  const SYSTEM_DIR = process.platform === "win32" ? path.join(process.env.SystemRoot ?? "C:\\Windows", "System32") : "/usr";
  /**
   * Generous on purpose: on a machine busy with other work a first tool call (which creates the
   * standalone database) has been seen to take over 15 s. Walking the directory would take far longer.
   */
  const REQUEST_BOUND_MS = 45_000;

  it("project_path at one is refused by every tool that takes it, before anything is read or sent", async () => {
    const { requests } = stallNetwork();
    const scope = resolveProjectScope(SYSTEM_DIR);
    expect(scope.kind).toBe("error");
    expect(scope.kind === "error" && scope.error).toMatch(/^project_path ".*" is (an operating-system directory|the Windows directory)/);
    const li = new LiveIntelligence(new Database(":memory:"));
    const scan = (await executeVulnerabilityScan(null, { project_path: SYSTEM_DIR }, li)) as { error?: string };
    expect(scan.error).toMatch(/^project_path ".*" is an operating-system directory.*not a project, so it is not scanned/);
    await expect(executeUpgradePlanner(noDb, { project_path: SYSTEM_DIR }, li)).rejects.toThrow(/is an operating-system directory/);
    const root = path.parse(dir).root;
    expect(((await executeVulnerabilityScan(null, { project_path: root }, li)) as { error?: string }).error).toMatch(/is (a drive root|the filesystem root), not a project/);
    expect(requests).toEqual([]);
  });

  // The built server is needed: skipped where only the source is checked out (the 4DA repo's
  // MCP schema contract job runs this suite without building it). MCP CI builds first, so it runs there.
  it.skipIf(!fs.existsSync(serverEntry))("a server STARTED in one scans nothing, says so on stderr, and each tool says why", async () => {
    const { results, stderr, timings } = await stdioSession(SYSTEM_DIR, [["vulnerability_scan", {}], ["dependency_health", {}]], {}, { requestTimeoutMs: REQUEST_BOUND_MS });
    expect(stderr).toMatch(/\[4DA\] ".*" is an operating-system directory.*not a project, so it is not scanned/);
    expect(results[0].isError).toBe(true);
    expect(resultText(results[0])).toMatch(/The server's directory \\?".*\\?" is an operating-system directory/);
    expect(resultText(results[1])).toMatch(/Nothing was checked, so there is no health score; this is not a healthy result\. The server's directory \\?"/);
    expect(resultText(results[0])).not.toContain("started in");
    expect(resultText(results[1])).toContain('"healthScore":null');
    for (const t of timings) expect(t.ms, t.method).toBeLessThan(REQUEST_BOUND_MS);
  }, 180_000);
});

// ---------------------------------------------------------------------------
// One lockfile's facts are not another's
// ---------------------------------------------------------------------------

describe("platform activity is tracked per lockfile", () => {
  const dep = (over: Partial<ResolvedDependency>): ResolvedDependency => ({
    name: "ring", version: "0.17.8", ecosystem: "crates.io", isDev: false, isDirect: false, devScopeKnown: false, target: null, platformActive: true, sourceDirs: [], ...over,
  });
  const REAL = "/repo/src-tauri";
  const STALE = "/repo/examples/demo";
  const inactiveInReal = dep({ platformActive: false, target: "not built for x86_64-pc-windows-msvc", sourceDirs: [REAL], isDirect: true, devScopeKnown: true });
  const activeInStale = dep({ sourceDirs: [STALE] });

  it("a copy one lockfile builds and another does not: both pin it, and the one that does not build it is named", () => {
    for (const order of [[inactiveInReal, activeInStale], [activeInStale, inactiveInReal]]) {
      const [merged] = dedupeDependencies(order.map((d) => ({ ...d })));
      // Reachable through a lockfile that may build it: counted, as before.
      expect(merged.platformActive).toBe(true);
      expect(merged.target).toBeNull();
      // Every directory that pins it (the inventory) ...
      expect([...merged.sourceDirs].sort()).toEqual([STALE, REAL].sort());
      // ... and, new, the one that pins it without building it. Nothing recorded this before.
      expect(merged.platformInactiveDirs).toEqual([REAL]);
    }
  });

  it("agreeing lockfiles merge as before: both building it, or neither", () => {
    const [both] = dedupeDependencies([dep({ sourceDirs: [REAL], isDirect: true }), dep({ sourceDirs: [STALE] })]);
    expect(both).toMatchObject({ platformActive: true, sourceDirs: [REAL, STALE], isDirect: true });
    expect(both.platformInactiveDirs).toBeUndefined();
    const [neither] = dedupeDependencies([{ ...inactiveInReal }, dep({ platformActive: false, target: "cfg(unix)", sourceDirs: [STALE] })]);
    expect(neither).toMatchObject({ platformActive: false, sourceDirs: [REAL, STALE], target: "not built for x86_64-pc-windows-msvc" });
    expect(neither.platformInactiveDirs).toBeUndefined();
    // Three lockfiles, the unbuilt one in the middle.
    const [three] = dedupeDependencies([dep({ sourceDirs: ["/a"] }), dep({ platformActive: false, sourceDirs: ["/b"] }), dep({ sourceDirs: ["/c"] })]);
    expect(three).toMatchObject({ platformActive: true, sourceDirs: ["/a", "/b", "/c"], platformInactiveDirs: ["/b"] });
    // Two that do not build it, then one that does: both earlier ones are named.
    const [late] = dedupeDependencies([dep({ platformActive: false, sourceDirs: ["/a"] }), dep({ platformActive: false, sourceDirs: ["/b"] }), dep({ sourceDirs: ["/c"] })]);
    expect(late).toMatchObject({ platformActive: true, sourceDirs: ["/a", "/b", "/c"], platformInactiveDirs: ["/a", "/b"] });
  });

  const entry = (over: Partial<VulnerabilityEntry>): VulnerabilityEntry => ({
    package: "ring", currentVersion: "0.17.8", ecosystem: "crates.io", isDev: false, isDirect: false, devScopeKnown: false, vulnId: "RUSTSEC-2025-0009", aliases: [],
    severity: "high", cvssScore: 7.5, summary: "ring advisory", fixedVersion: "0.17.12", published: "2025-03-01T00:00:00Z", references: [], target: null, platformActive: true, sourceDirs: [], ...over,
  });
  const scanOf = (vulnerabilities: VulnerabilityEntry[], over: Partial<VulnerabilityScanResult> = {}): VulnerabilityScanResult => ({
    scannedAt: new Date().toISOString(), projectPath: "/repo", ecosystemsScanned: ["crates.io"], totalScanned: 4, totalVulnerable: vulnerabilities.length, platformInactiveVulnerable: 0,
    bySeverity: { critical: 0, high: vulnerabilities.length, medium: 0, low: 0, unknown: 0 }, vulnerabilities, cleanCount: 4 - vulnerabilities.length, scanDurationMs: 1, cached: false, offline: false, unchecked: 0, uncheckedReason: null, staleAnswers: 0, ...over,
  });

  it("the scan row names where it is built, and where it is only locked", () => {
    const full = formatScanResult(scanOf([entry({ sourceDirs: [REAL, STALE], platformInactiveDirs: [REAL] })]), undefined, { resolution: null, reResolvedThisCall: false, drift: [], includeDev: true, discovery: null, unresolved: [], problems: [] });
    expect(full.vulnerabilities[0]).toMatchObject({ source_dirs: ["examples/demo", "src-tauri"], platform_active: true, platform_inactive_in: ["src-tauri"] });
    const agreed = formatScanResult(scanOf([entry({ sourceDirs: [STALE, REAL] })]), undefined, { resolution: null, reResolvedThisCall: false, drift: [], includeDev: true, discovery: null, unresolved: [], problems: [] });
    expect(agreed.vulnerabilities[0]).not.toHaveProperty("platform_inactive_in");
  });

  it("the plan's step says which lockfile it is NOT about", async () => {
    process.env.FOURDA_OFFLINE = "true";
    const real = path.join(dir, "src-tauri");
    const stale = path.join(dir, "examples", "demo");
    for (const d of [real, stale]) {
      fs.mkdirSync(d, { recursive: true });
      fs.writeFileSync(path.join(d, "Cargo.lock"), ['[[package]]', 'name = "ring"', 'version = "0.17.8"', 'source = "registry+https://github.com/rust-lang/crates.io-index"', ""].join("\n"));
    }
    const li = new LiveIntelligence(new Database(":memory:"));
    li.initFromDependencyGroups([{ dir: real, language: "rust", deps: [], devDeps: [] }, { dir: stale, language: "rust", deps: [], devDeps: [] }]);
    (li as unknown as { lastVulnScan: VulnerabilityScanResult }).lastVulnScan = scanOf([entry({ sourceDirs: [real, stale], platformInactiveDirs: [real] })], { projectPath: dir, offline: true });
    const plan = (await executeUpgradePlanner(noDb, {}, li)) as { recommendations: Array<{ package: string; reasons: string[]; platformActive: boolean }> };
    const ring = plan.recommendations.find((r) => r.package === "ring")!;
    expect(ring.platformActive).toBe(true);
    expect(ring.reasons).toContain("Built on this host in examples/demo only: src-tauri locks the same version without building it here, so this step is not about it");
  });

  const FIXTURE_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "test-fixtures", "cargo-platform");
  const cargo = (() => {
    try {
      execFileSync("cargo", ["--version"], { stdio: "ignore", timeout: 15_000, windowsHide: true });
      return true;
    } catch {
      return false;
    }
  })();

  it("with cargo: a lockfile cargo cannot resolve no longer makes the project's unbuilt crates count as the project's", () => {
    _resetCargoPlatformCache();
    const resolved = cargo ? activeCratesForHost(FIXTURE_DIR) : null;
    if (resolved === null) {
      // No cargo, or the fixture's crates are not in the local registry cache (CI fetches them first).
      if (process.env.FOURDA_REQUIRE_CARGO === "1") throw new Error("FOURDA_REQUIRE_CARGO=1 but `cargo tree` could not resolve test-fixtures/cargo-platform");
      return;
    }
    // The project's real lockfile locks itoa and never builds it (an optional dependency no feature enables).
    expect(resolved.has("itoa")).toBe(false);
    // An example beside it: the same Cargo.lock with no Cargo.toml, so cargo cannot say what it builds.
    const stale = path.join(dir, "examples", "old");
    fs.mkdirSync(stale, { recursive: true });
    fs.copyFileSync(path.join(FIXTURE_DIR, "Cargo.lock"), path.join(stale, "Cargo.lock"));
    const li = new LiveIntelligence(new Database(":memory:"));
    li.initFromDependencyGroups([{ dir: FIXTURE_DIR, language: "rust", deps: ["ryu"], devDeps: [] }, { dir: stale, language: "rust", deps: [], devDeps: [] }]);
    const itoa = li.getAuditDeps().find((d) => d.name === "itoa")!;
    // Counted, because the example may build it; and the entry now says the project's own lockfile does not.
    expect(itoa.platformActive).toBe(true);
    expect([...itoa.sourceDirs].sort()).toEqual([FIXTURE_DIR, stale].sort());
    expect(itoa.platformInactiveDirs).toEqual([FIXTURE_DIR]);
    // A crate both build is in both.
    const ryu = li.getAuditDeps().find((d) => d.name === "ryu")!;
    expect(ryu.sourceDirs.sort()).toEqual([FIXTURE_DIR, stale].sort());
    expect(ryu.platformInactiveDirs).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// Answers that read as fine when nothing was checked
// ---------------------------------------------------------------------------

describe("nothing checked is never a good score, an online claim, or a silent proxy", () => {
  /** OSV answers "no advisories" for everything; the registries answer 404. */
  function cleanNetwork(): { fail: () => void; requests: string[] } {
    let dead = false;
    const requests: string[] = [];
    vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
      const url = String(input);
      requests.push(url);
      if (dead) throw new TypeError("fetch failed");
      if (url.endsWith("/v1/querybatch")) {
        const { queries } = JSON.parse(String(init?.body)) as { queries: unknown[] };
        return new Response(JSON.stringify({ results: queries.map(() => ({})) }), { status: 200, headers: { "content-type": "application/json" } });
      }
      return new Response("{}", { status: 404, headers: { "content-type": "application/json" } });
    });
    return { fail: () => (dead = true), requests };
  }

  it("dependency_health with an ecosystem_filter that matches nothing: no score, and it says what the project does hold", async () => {
    npmProject();
    cleanNetwork();
    const li = liveFor();
    const health = await executeDependencyHealth(null, { ecosystem_filter: "PyPI" }, li);
    // It read 100/100, "all healthy", over 0 dependencies.
    expect(health.healthScore).toBeNull();
    expect(health.withheldReason).toBe("nothing_checked");
    expect(health.totalDeps).toBe(0);
    expect(health.vulnerableCount).toBeNull();
    expect(health.summary).toBe(
      'Nothing was checked, so there is no health score; this is not a healthy result: no PyPI dependency was read in this project (ecosystem_filter: "PyPI"). What was read is npm: drop the filter or pass one of those.',
    );
    // The filter that does match is scored as before.
    const npm = await executeDependencyHealth(null, { ecosystem_filter: "npm" }, li);
    expect(npm.withheldReason).not.toBe("nothing_checked");
    expect(npm.totalDeps).toBe(2);
  });

  it("a scan served from the cache is complete (`offline: false`, a boolean) and says OSV.dev was not contacted (pre-publish round 7)", async () => {
    npmProject();
    const network = cleanNetwork();
    const li = liveFor();
    const first = (await executeVulnerabilityScan(null, { response_format: "detailed" }, li)) as Record<string, any>;
    expect(first._meta).toMatchObject({ offline: false, osv_cached: false });
    expect(first._meta).not.toHaveProperty("osv_contacted");
    // The network dies. The same scan is answered from the cache, as it should be.
    network.fail();
    const before = network.requests.filter((u) => u.includes("osv.dev")).length;
    const second = (await executeVulnerabilityScan(null, { response_format: "detailed" }, li)) as Record<string, any>;
    expect(network.requests.filter((u) => u.includes("osv.dev")).length).toBe(before);
    expect(second._meta.osv_cached).toBe(true);
    expect(second._meta.offline).toBe(false);
    expect(second._meta.osv_contacted).toBe(false);
    expect(second._meta.offline_note).toMatch(/^Served from the advisory cache .* OSV\.dev was not contacted in this call, so whether it is reachable now is not known\./);
    // The concise form carries the same.
    const concise = (await executeVulnerabilityScan(null, {}, li)) as Record<string, any>;
    expect(concise._meta.offline).toBe(false);
    expect(concise._meta.osv_contacted).toBe(false);
    // Asked again with the network still dead, it says so.
    const forced = (await executeVulnerabilityScan(null, { force_refresh: true, response_format: "detailed" }, li)) as Record<string, any>;
    expect(forced.summary).toMatch(/^NOT CHECKED/);
    expect(forced._meta.offline).toBe(true);
  });

  it("proxy variables: every lookup goes through them (proxy-lookups.test.ts), and the startup line says so", () => {
    expect(configureProxy({})).toEqual({ state: "none", note: null });
    expect(configureProxy({ HTTPS_PROXY: "http://proxy.corp:8080" }).state).toBe("lookups");
  });
});
