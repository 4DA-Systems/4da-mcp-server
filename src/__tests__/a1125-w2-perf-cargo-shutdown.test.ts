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
import { _resetCargoPlatformCache, _setCargoCommandForTests, _setCargoTreeWaitForTests, activeCratesForHost, activeCratesInFlight, hostTriple } from "../live/cargo-platform.js";
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
    const pidFile = path.join(dir, "pid.txt");
    _setCargoTreeWaitForTests(30000);
    _setCargoCommandForTests({ file: process.execPath, prefix: ["-e", `require('fs').writeFileSync(${JSON.stringify(pidFile)}, String(process.pid)); setInterval(() => {}, 1000)`] });
    try {
      expect(activeCratesForHost(dir)).toBeNull();
      const pending = activeCratesInFlight(dir)!;
      for (let i = 0; i < 100 && !fs.existsSync(pidFile); i++) await new Promise((r) => setTimeout(r, 50));
      const pid = Number(fs.readFileSync(pidFile, "utf8"));
      const t0 = performance.now();
      abortBackgroundWork("test");
      await pending;
      expect(performance.now() - t0).toBeLessThan(3000);
      let gone = false;
      for (let i = 0; i < 60 && !gone; i++) {
        try {
          process.kill(pid, 0);
          await new Promise((r) => setTimeout(r, 50));
        } catch {
          gone = true;
        }
      }
      expect(gone).toBe(true);
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
