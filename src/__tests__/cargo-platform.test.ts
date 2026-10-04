// SPDX-License-Identifier: Apache-2.0
/**
 * Regression tests for host-platform crate resolution.
 *
 * Live incident (2026-08-25 Signal audit): `vulnerability_scan` reported
 * `platform_inactive_packages: 0` and `_meta.relevance` claimed "Advisories are
 * filtered to the host platform" — while listing nine Linux-only GTK3 crates
 * (`gtk`, `gdk`, `atk`, `glib`, `gdkx11`, `gdkwayland-sys`, `gtk3-macros`,
 * `gdk-sys`, `atk-sys`) on a Windows host. Those crates are never compiled
 * there.
 *
 * Root cause: the only platform signal was `[target.'cfg(...)'.dependencies]`
 * parsed from a manifest, which covers DIRECT gated deps. The GTK3 cluster is
 * entirely transitive — Tauri pulls it in on Linux — and Cargo.lock does not
 * encode targets, so nothing could see it.
 */
import { describe, it, expect, beforeEach } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import {
  hostTriple,
  activeCratesForHost,
  parseTreeNames,
  cargoTreeInvocation,
  _resetCargoPlatformCache,
} from "../live/cargo-platform.js";
import { platformFilterNote } from "../tools/vulnerability-scan.js";
import type { VulnerabilityEntry } from "../live/types.js";

beforeEach(() => _resetCargoPlatformCache());

/**
 * A crate whose Cargo.lock locks crates this host never compiles: `itoa` is
 * behind a feature nothing enables, `windows-sys` is Windows-only and `libc`
 * unix-only (see its Cargo.toml). CI runs `cargo fetch` on it first, so the
 * offline `cargo tree` this module runs can answer.
 */
const FIXTURE_DIR = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
  "..",
  "test-fixtures",
  "cargo-platform",
);

function cargoAvailable(): boolean {
  try {
    execFileSync("cargo", ["--version"], { stdio: "ignore", timeout: 15_000, windowsHide: true });
    return true;
  } catch {
    return false;
  }
}

describe("hostTriple", () => {
  it("maps this host to a real Rust target triple", () => {
    const triple = hostTriple();
    if (triple === null) return; // unmapped platform — nothing to assert
    expect(triple).toMatch(/^(x86_64|aarch64)-(pc-windows-msvc|apple-darwin|unknown-linux-gnu)$/);
  });
});

describe("parseTreeNames", () => {
  it("reads one crate name per package line, ignoring decorations", () => {
    const names = parseTreeNames(
      [
        "fourda v1.0.2 (D:\\4DA\\src-tauri)",
        "ammonia v4.1.4",
        "cssparser-macros v0.7.0 (proc-macro)",
        "quote v1.0.45 (*)",
      ].join("\n"),
    );
    expect(names).toEqual(new Set(["fourda", "ammonia", "cssparser-macros", "quote"]));
  });

  it("skips blank lines and anything that is not a crate-name token", () => {
    expect(parseTreeNames("\n[dev-dependencies]\n   \nserde v1.0.0\n")).toEqual(
      new Set(["serde"]),
    );
  });

  it("returns an empty set for empty output — which the caller reads as unknown", () => {
    // Load-bearing: `computeActiveCrates` turns an empty set into `null`, and
    // callers then keep EVERY crate active. Believing an empty set would mark
    // the whole lockfile unreachable and bury every real advisory.
    expect(parseTreeNames("").size).toBe(0);
    expect(parseTreeNames("warning: nothing to print.\n").has("warning:")).toBe(false);
  });
});

describe("cargoTreeInvocation", () => {
  // cargo and rustup read their configuration from the working directory
  // upward, so the scanned project must never be cargo's working directory.
  const project = path.resolve("some-scanned-project");
  const inv = cargoTreeInvocation(project);
  /** True when `p` is `dir` or inside it (drive-aware on Windows). */
  const isInside = (dir: string, p: string): boolean => {
    const rel = path.relative(dir, p);
    return rel === "" || (!rel.startsWith("..") && !path.isAbsolute(rel));
  };

  it("runs cargo from a server-owned directory outside the scanned project", () => {
    expect(isInside(project, inv.cwd)).toBe(false);
    expect(isInside(os.tmpdir(), inv.cwd)).toBe(true);
  });

  it("names the project only through --manifest-path", () => {
    const at = inv.args.indexOf("--manifest-path");
    expect(at).toBeGreaterThan(-1);
    expect(inv.args[at + 1]).toBe(path.join(project, "Cargo.toml"));
  });

  it("keeps cargo's metadata writes out of the scanned project", () => {
    expect(isInside(project, inv.targetDir)).toBe(false);
  });

  it("stays read-only and offline", () => {
    expect(inv.args).toContain("--offline");
    expect(inv.args).toContain("--locked");
  });
});

describe("activeCratesForHost", () => {
  it("returns null — unknown, never empty — for a directory with no Cargo.toml", () => {
    const result = activeCratesForHost(path.join(process.cwd(), "src", "__tests__"));
    expect(result).toBeNull();
  });

  it("returns null rather than an empty set for a nonexistent path", () => {
    // The distinction is load-bearing: an empty set would mark EVERY crate
    // inactive and silently hide real advisories.
    expect(activeCratesForHost(path.join(process.cwd(), "no-such-dir-xyz"))).toBeNull();
  });

  const runnable = cargoAvailable() && hostTriple() !== null;

  // These shell out to real cargo. `cargo tree` normally answers in ~1s, but it
  // takes the same lock a concurrent `cargo build`/`cargo test` holds. The
  // default 5s test timeout made them flake under that contention; the work
  // itself is bounded by execFileSync's own 30s.
  const CARGO_TEST_TIMEOUT_MS = 90_000;

  /**
   * `null` means cargo declined to answer — `--offline` needs the fixture's
   * crates in the local registry cache (`cargo fetch`). That is a HANDLED
   * outcome (callers keep every crate active), not a defect. CI fetches first
   * and sets FOURDA_REQUIRE_CARGO=1, so there a `null` fails instead of hiding
   * the assertions.
   */
  function resolvedOrSkip(): Set<string> | null {
    const crates = activeCratesForHost(FIXTURE_DIR);
    if (crates === null) {
      if (process.env.FOURDA_REQUIRE_CARGO === "1") {
        throw new Error(
          "cargo tree --offline returned nothing for the fixture: run `cargo fetch --manifest-path test-fixtures/cargo-platform/Cargo.toml` first",
        );
      }
      console.warn("cargo tree --offline unavailable here — assertions skipped");
    }
    return crates;
  }

  it.runIf(runnable)(
    "excludes a crate no enabled feature ever compiles",
    () => {
      // 2026-09-08 divergence: `cargo metadata --filter-platform` resolves the
      // TARGET axis only, so it kept the `reqwest -> quinn` edge even though
      // `reqwest`'s enabled features contain no `http3`. `quinn-proto` — never
      // compiled on that machine — counted as built-on-host, and it was
      // Preemption's #1 HIGH on the founder instance. `cargo tree` resolves
      // features too, which is what the build does. The fixture locks `itoa`
      // behind a feature nothing enables.
      const crates = resolvedOrSkip();
      if (crates === null) return;
      expect(crates.has("ryu"), "a crate the build DOES compile").toBe(true);
      expect(crates.has("itoa"), "an optional dep of a disabled feature is not built here").toBe(false);
    },
    CARGO_TEST_TIMEOUT_MS,
  );

  it.runIf(runnable)(
    "excludes locked crates that never build on this host",
    () => {
      // The live incident: nine Linux-only GTK3 crates reported on a Windows
      // host. The fixture locks one crate per OS family.
      const crates = resolvedOrSkip();
      if (crates === null) return;
      if (process.platform === "win32") {
        expect(crates.has("windows-sys"), "windows-sys must be active on Windows").toBe(true);
        expect(crates.has("libc"), "libc is unix-only here and must not be active on Windows").toBe(false);
      } else {
        expect(crates.has("libc"), "libc must be active on unix").toBe(true);
        expect(crates.has("windows-sys"), "windows-sys must not be active off Windows").toBe(false);
      }
    },
    CARGO_TEST_TIMEOUT_MS,
  );

  it.runIf(runnable)(
    "memoizes per directory",
    () => {
      const first = activeCratesForHost(FIXTURE_DIR);
      const second = activeCratesForHost(FIXTURE_DIR);
      // Identity holds for a real answer; `null === null` also holds when cargo
      // declines, so this asserts the memo either way.
      expect(second).toBe(first);
    },
    CARGO_TEST_TIMEOUT_MS,
  );
});

function entry(over: Partial<VulnerabilityEntry> = {}): VulnerabilityEntry {
  return {
    package: "gtk",
    currentVersion: "0.18.2",
    ecosystem: "crates.io",
    isDev: false,
    isDirect: false,
    devScopeKnown: false,
    vulnId: "RUSTSEC-2024-0415",
    aliases: [],
    severity: "unknown",
    cvssScore: null,
    summary: "gtk-rs GTK3 bindings - no longer maintained",
    fixedVersion: null,
    published: "2024-03-04T12:00:00Z",
    references: [],
    target: null,
    platformActive: true,
    sourceDirs: ["d:/4da/src-tauri"],
    ...over,
  };
}

describe("platformFilterNote", () => {
  it("does NOT claim filtering when no target information was resolvable", () => {
    // This is the exact state that produced the false claim.
    const note = platformFilterNote([entry(), entry({ package: "gdk" })]);
    expect(note).toMatch(/^Not platform-filtered/);
    expect(note).not.toMatch(/Filtered to/);
  });

  it("reports the count when advisories were actually suppressed", () => {
    const note = platformFilterNote([
      entry({ platformActive: false, target: "not built for x86_64-pc-windows-msvc" }),
      entry({ package: "serde", platformActive: true, target: null }),
    ]);
    expect(note).toMatch(/^Filtered to /);
    expect(note).toContain("1 advisory is");
  });

  it("says so plainly when the filter ran and suppressed nothing", () => {
    const note = platformFilterNote([entry({ platformActive: true, target: "cfg(unix)" })]);
    expect(note).toMatch(/^Filtered to /);
    expect(note).toContain("every advisory below");
  });
});
