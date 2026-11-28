// SPDX-License-Identifier: Apache-2.0
/**
 * Audit 2026-11-25, Track F, M2: with cargo waiting for the package-cache lock, closing stdin did
 * not end the server (execFileSync held the event loop until cargo's 30 s timeout). A shutdown now
 * kills the cargo child at once. Its own file: the shutdown signal, once aborted, stays aborted.
 */
import { afterEach, describe, expect, it } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { _lastCargoChildForTests, _resetCargoPlatformCache, _setCargoCommandForTests, _setCargoTreeWaitForTests, activeCratesForHost, activeCratesInFlight, hostTriple } from "../live/cargo-platform.js";
import { abortBackgroundWork } from "../shutdown.js";

afterEach(() => {
  _setCargoCommandForTests(null);
  _resetCargoPlatformCache();
});

describe.runIf(hostTriple() !== null)("shutdown ends a waiting cargo (audit 2026-11-25, F-M2)", () => {
  it("kills the cargo child when the server shuts down, long before its own bound", async () => {
    const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "a1125-cargo-sd-")));
    fs.writeFileSync(path.join(dir, "Cargo.toml"), '[package]\nname = "x"\nversion = "0.1.0"\n');
    fs.writeFileSync(path.join(dir, "Cargo.lock"), 'version = 3\n\n[[package]]\nname = "x"\nversion = "0.1.0"\n');
    _setCargoTreeWaitForTests(30000);
    _setCargoCommandForTests({ file: process.execPath, prefix: ["-e", "setInterval(() => {}, 1000)"] });
    try {
      expect(activeCratesForHost(dir)).toBeNull();
      const pending = activeCratesInFlight(dir)!;
      const child = _lastCargoChildForTests()!;
      expect(child.pid).toBeGreaterThan(0);
      // The child's exit, as an event: no fixed delay, no pid file it may not have written yet.
      const exited = new Promise<{ code: number | null; signal: string | null } | "still running">((resolve) => {
        if (child.exitCode !== null || child.signalCode !== null) resolve({ code: child.exitCode, signal: child.signalCode });
        const timer = setTimeout(() => resolve("still running"), 20_000);
        timer.unref();
        child.once("exit", (code, signal) => {
          clearTimeout(timer);
          resolve({ code, signal });
        });
      });
      const t0 = performance.now();
      abortBackgroundWork("test");
      await pending;
      // The wait ends at the shutdown, not at the 30 s bound.
      expect(performance.now() - t0).toBeLessThan(3000);
      expect(await exited).not.toBe("still running");
      expect(child.killed).toBe(true);
      // After shutdown no new cargo is started.
      fs.appendFileSync(path.join(dir, "Cargo.lock"), "\n");
      expect(activeCratesForHost(dir)).toBeNull();
      expect(activeCratesInFlight(dir)).toBeNull();
    } finally {
      _setCargoTreeWaitForTests(null);
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
