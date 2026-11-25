// SPDX-License-Identifier: Apache-2.0
/**
 * Audit 2026-11-25, Track F, M2: `cargo tree` ran synchronously (execFileSync, 30 s timeout)
 * during the first scan of every Cargo project. While another cargo held the package cache
 * (rust-analyzer or `cargo build` fetching crates), the server answered nothing for 30 s: a ping
 * waited 29.9 s, the scan took 30.2 s against a 20 s budget, and closing stdin did not end it.
 *
 * Now cargo runs as a child process the server does not wait on synchronously: a stepped
 * resolution waits for it up to a bound, a synchronous one goes on without it, and an answer that
 * did not come in time leaves the platform filter off (every crate counted, "Not
 * platform-filtered"), never a wait and never a silent "all platforms". Shutdown kills it.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import Database from "better-sqlite3";
import {
  _resetCargoPlatformCache,
  _setCargoCommandForTests,
  _setCargoTreeWaitForTests,
  activeCratesForHost,
  activeCratesInFlight,
  hostTriple,
} from "../live/cargo-platform.js";
import { LiveIntelligence } from "../live/index.js";
import { platformFilterNote } from "../tools/vulnerability-scan-format.js";
import type { VulnerabilityEntry } from "../live/types.js";

const CARGO_TOML = '[package]\nname = "cli-rust"\nversion = "0.1.0"\nedition = "2021"\n\n[dependencies]\nsmallvec = "1.6.0"\ntime = "0.1.43"\n';
const CARGO_LOCK =
  'version = 3\n\n[[package]]\nname = "cli-rust"\nversion = "0.1.0"\ndependencies = [\n "smallvec",\n "time",\n]\n\n' +
  '[[package]]\nname = "smallvec"\nversion = "1.6.0"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n\n' +
  '[[package]]\nname = "time"\nversion = "0.1.43"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n';

let dir: string;

function project(): string {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), "a1125-cargo-"));
  fs.writeFileSync(path.join(d, "Cargo.toml"), CARGO_TOML);
  fs.writeFileSync(path.join(d, "Cargo.lock"), CARGO_LOCK);
  return fs.realpathSync(d);
}

/** A stand-in for cargo, run as a real child process: node with a script. */
function fakeCargo(script: string): void {
  _setCargoCommandForTests({ file: process.execPath, prefix: ["-e", script] });
}
/** Never answers (a cargo waiting for the package-cache lock). */
const HANGS = "setInterval(() => {}, 1000)";
/** Answers at once with the crates built here: smallvec only, so `time` is not built on this host. */
const ANSWERS = "process.stdout.write('cli-rust v0.1.0 (C:/x)\\nsmallvec v1.6.0\\n')";

function alive(pid: number | undefined): boolean {
  if (!pid) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

beforeEach(() => {
  _resetCargoPlatformCache();
  dir = project();
});

afterEach(() => {
  _setCargoCommandForTests(null);
  _resetCargoPlatformCache();
  _setCargoTreeWaitForTests(null);
  fs.rmSync(dir, { recursive: true, force: true });
});

describe.runIf(hostTriple() !== null)("cargo tree never holds the event loop (audit 2026-11-25, F-M2)", () => {
  it("answers at once while cargo is still running, and the event loop keeps turning", async () => {
    _setCargoTreeWaitForTests(1500);
    fakeCargo(HANGS);
    let ticks = 0;
    const ticker = setInterval(() => ticks++, 20);
    const t0 = performance.now();
    // Unknown for now, never a wait: the old code sat in execFileSync for its whole 30 s here.
    expect(activeCratesForHost(dir)).toBeNull();
    expect(performance.now() - t0).toBeLessThan(500);
    const pending = activeCratesInFlight(dir);
    expect(pending).not.toBeNull();
    await pending;
    clearInterval(ticker);
    const waited = performance.now() - t0;
    // Bounded by the wait, then given up on: no answer is "unknown", every crate counted.
    expect(waited).toBeLessThan(6000);
    expect(ticks).toBeGreaterThan(10);
    expect(activeCratesForHost(dir)).toBeNull();
    expect(activeCratesInFlight(dir)).toBeNull();
  });

  it("kills the cargo it gave up on", async () => {
    _setCargoTreeWaitForTests(800);
    fakeCargo(`require('fs').writeFileSync(${JSON.stringify(path.join(dir, "pid.txt"))}, String(process.pid)); setInterval(() => {}, 1000)`);
    activeCratesForHost(dir);
    await activeCratesInFlight(dir);
    const pidFile = path.join(dir, "pid.txt");
    const pid = fs.existsSync(pidFile) ? Number(fs.readFileSync(pidFile, "utf8")) : undefined;
    expect(pid).toBeGreaterThan(0);
    // Give the OS a moment to reap it.
    for (let i = 0; i < 50 && alive(pid); i++) await new Promise((r) => setTimeout(r, 50));
    expect(alive(pid)).toBe(false);
  });

  it("asks cargo once per lockfile state, not once per resolution, when it did not answer", async () => {
    _setCargoTreeWaitForTests(300);
    fakeCargo(HANGS);
    activeCratesForHost(dir);
    await activeCratesInFlight(dir);
    // The same files: the given-up answer stands; no second cargo is started and nothing waits.
    expect(activeCratesForHost(dir)).toBeNull();
    expect(activeCratesInFlight(dir)).toBeNull();
    // Right after a cargo was given up on, another workspace (or a changed lockfile) is not asked
    // either: it would wait for the same lock, its whole bound again. Unknown, never inactive.
    const other = project();
    try {
      expect(activeCratesForHost(other)).toBeNull();
      expect(activeCratesInFlight(other)).toBeNull();
      fs.appendFileSync(path.join(dir, "Cargo.lock"), "\n");
      expect(activeCratesForHost(dir)).toBeNull();
      expect(activeCratesInFlight(dir)).toBeNull();
    } finally {
      fs.rmSync(other, { recursive: true, force: true });
    }
  });

  it("a cargo that answers (even with an error) does not pause the next workspace", async () => {
    _setCargoTreeWaitForTests(5000);
    fakeCargo("process.exit(101)");
    activeCratesForHost(dir);
    await activeCratesInFlight(dir);
    expect(activeCratesForHost(dir)).toBeNull();
    const other = project();
    try {
      fakeCargo(ANSWERS);
      expect(activeCratesForHost(other)).toBeNull();
      expect(activeCratesInFlight(other)).not.toBeNull();
      await activeCratesInFlight(other);
      expect(activeCratesForHost(other)).toEqual(new Set(["cli-rust", "smallvec"]));
    } finally {
      fs.rmSync(other, { recursive: true, force: true });
    }
  });

  it("a stepped resolution waits for cargo's answer and filters by it", async () => {
    _setCargoTreeWaitForTests(20000);
    fakeCargo(ANSWERS);
    const li = new LiveIntelligence(new Database(":memory:"));
    // `time` as a transitive: a direct dependency is judged by its manifest target alone.
    expect(await li.initFromProjectTreeYielding(dir, [{ dir, language: "rust", deps: ["smallvec"], devDeps: [], targets: {} }])).toBe(true);
    expect(activeCratesForHost(dir)).toEqual(new Set(["cli-rust", "smallvec"]));
    const time = li.getAuditDeps().find((d) => d.name === "time")!;
    const smallvec = li.getAuditDeps().find((d) => d.name === "smallvec")!;
    expect(smallvec.platformActive).toBe(true);
    expect(time.platformActive).toBe(false);
    expect(time.target).toBe(`not built for ${hostTriple()}`);
  });

  it("a stepped resolution waits a bounded time when cargo does not answer, keeps the event loop free, and filters nothing", async () => {
    _setCargoTreeWaitForTests(700);
    fakeCargo(HANGS);
    let longestGap = 0;
    let last = performance.now();
    const ticker = setInterval(() => {
      const now = performance.now();
      longestGap = Math.max(longestGap, now - last);
      last = now;
    }, 20);
    const li = new LiveIntelligence(new Database(":memory:"));
    const t0 = performance.now();
    expect(await li.initFromProjectTreeYielding(dir, [{ dir, language: "rust", deps: ["smallvec", "time"], devDeps: [], targets: {} }])).toBe(true);
    clearInterval(ticker);
    expect(performance.now() - t0).toBeLessThan(6000);
    expect(longestGap).toBeLessThan(500);
    const deps = li.getAuditDeps().filter((d) => d.ecosystem === "crates.io");
    expect(deps.length).toBeGreaterThan(0);
    // Unknown is never "inactive": every crate is counted, and the answer says the filter did not run.
    expect(deps.every((d) => d.platformActive === true && d.target === null)).toBe(true);
    const rows = deps.map((d) => ({ package: d.name, platformActive: d.platformActive, target: d.target }) as unknown as VulnerabilityEntry);
    expect(platformFilterNote(rows)).toMatch(/^Not platform-filtered/);
  });

  it("a synchronous resolution never waits for cargo", () => {
    _setCargoTreeWaitForTests(20000);
    fakeCargo(HANGS);
    const li = new LiveIntelligence(new Database(":memory:"));
    const t0 = performance.now();
    li.initFromProjectTree(dir, [{ dir, language: "rust", deps: ["smallvec", "time"], devDeps: [], targets: {} }]);
    expect(performance.now() - t0).toBeLessThan(2000);
    expect(li.getAuditDeps().filter((d) => d.ecosystem === "crates.io").every((d) => d.platformActive === true)).toBe(true);
  });
});
