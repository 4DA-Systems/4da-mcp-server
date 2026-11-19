// SPDX-License-Identifier: Apache-2.0
/**
 * PyPI's latest stable release is the highest final release in PEP 440's order.
 *
 * It was the highest version with three numeric parts: `pytz==2023.3` was reported up to date
 * against "latest stable 2022.7.1" while PyPI served 2026.6, and pip 23.0 was sent to 26.2.2 with
 * 26.3 published. Two-part versions are ordinary PEP 440 releases, and a pre-release is what PEP 440
 * says it is (`a`/`b`/`rc` and `.dev`; a `.post` release is final).
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import Database from "better-sqlite3";
import { LiveCache } from "../live/cache.js";
import { PyPIRegistry } from "../live/pypi-registry.js";
import { RateLimiter } from "../live/rate-limiter.js";

type Files = Array<{ upload_time_iso_8601: string; yanked: boolean }>;
const file = (yanked = false): Files => [{ upload_time_iso_8601: "2026-06-01T00:00:00Z", yanked }];

function serve(name: string, latest: string, releases: Record<string, Files>) {
  vi.stubGlobal("fetch", async (input: string | URL) => {
    const ok = String(input) === `https://pypi.org/pypi/${name}/json`;
    return new Response(JSON.stringify(ok ? { info: { name, version: latest, license: "MIT", classifiers: [], summary: "", yanked: false, yanked_reason: null }, releases } : {}), {
      status: ok ? 200 : 404,
      headers: { "content-type": "application/json" },
    });
  });
}

const registry = () => new PyPIRegistry(new LiveCache(new Database(":memory:")), new RateLimiter({ pypi: { maxPerMinute: 100 } }));

afterEach(() => vi.unstubAllGlobals());

describe("PyPI latest stable release", () => {
  it("pytz 2023.3: the latest stable is 2026.6, a two-part version, and the pin is behind it", async () => {
    serve("pytz", "2026.6", {
      "2022.7.1": file(),
      "2023.3": file(),
      "2023.3.post1": file(),
      "2025.2": file(),
      "2026.6": file(),
    });
    const info = await registry().getPackageInfo("pytz", "2023.3", false);
    expect(info.latestStableVersion).toBe("2026.6");
    expect(info.versionsBehind).toMatchObject({ major: 3, label: "major" });
  });

  it("pip 23.0: 26.3, not the highest three-part release 26.2.2", async () => {
    serve("pip", "26.3", { "23.0": file(), "23.0.1": file(), "26.2.2": file(), "26.3": file() });
    const info = await registry().getPackageInfo("pip", "23.0", false);
    expect(info.latestStableVersion).toBe("26.3");
    expect(info.versionsBehind?.label).toBe("major");
  });

  it("a pre-release is PEP 440's: a, b, rc and .dev are not stable in any spelling; a .post release is", async () => {
    serve("demo", "3.0rc1", {
      "1.0": file(),
      "2.0": file(),
      "2.0.post1": file(),
      "2.1a1": file(),
      "2.1.0b2": file(),
      "2.1.dev3": file(),
      "3.0rc1": file(),
      "3.0-alpha": file(),
      "3.0.0.dev1": file(),
    });
    expect((await registry().getPackageInfo("demo", "1.0", false)).latestStableVersion).toBe("2.0.post1");
  });

  it("a release whose every file is yanked is passed over; ordering is PEP 440's, not the listing's", async () => {
    serve("demo", "1.10", { "1.10": file(), "1.9": file(), "1.2": file(), "2.0": file(true), "1.10.0.1": file() });
    expect((await registry().getPackageInfo("demo", "1.2", false)).latestStableVersion).toBe("1.10.0.1");
  });

  it("an epoch outranks every release without one", async () => {
    serve("demo", "1!1.0", { "2026.1": file(), "1!1.0": file() });
    expect((await registry().getPackageInfo("demo", "2026.1", false)).latestStableVersion).toBe("1!1.0");
  });

  it("no final release: none is named stable", async () => {
    serve("demo", "1.0rc1", { "1.0rc1": file(), "1.0.dev2": file(), "not-a-version": file() });
    expect((await registry().getPackageInfo("demo", null, false)).latestStableVersion).toBeNull();
  });
});
