// SPDX-License-Identifier: Apache-2.0
/**
 * Which crates in a Cargo workspace are actually built on THIS host.
 *
 * Cargo.lock is target-agnostic: it lists every crate for every platform the
 * tree can compile for. So a Windows machine's lockfile still contains the
 * whole Linux GTK3 stack that Tauri pulls in — `gtk`, `gdk`, `atk`, `glib`,
 * `gdkx11`, `gdkwayland-sys`, `gtk3-macros` — none of which are ever compiled
 * there. Advisories against them are unreachable noise on that host.
 *
 * `vulnerability_scan` claimed to filter for exactly this ("Advisories are
 * filtered to the host platform") while reporting `platform_inactive_packages:
 * 0` and listing nine Linux-only crates on a Windows box. The gate it relied on
 * only ever saw `[target.'cfg(...)'.dependencies]` entries from a manifest,
 * which covers DIRECT platform-gated deps and cannot see transitives — and the
 * GTK3 cluster is entirely transitive.
 *
 * Cargo.lock is also FEATURE-agnostic: it lists every optional dependency,
 * including the ones no enabled feature turns on. `cargo tree` resolves both
 * axes — target AND features — and is what the build itself does.
 *
 * This used `cargo metadata --filter-platform <triple>`, which resolves only
 * the target axis. Measured on 4DA's own workspace, 2026-09-08, host
 * `x86_64-pc-windows-msvc`:
 *
 * | mechanism                                   | distinct crates | `quinn-proto` |
 * |---------------------------------------------|-----------------|---------------|
 * | `Cargo.lock`                                | 788             | present       |
 * | `cargo metadata --filter-platform <triple>` | 560             | **present**   |
 * | `cargo tree` (host, default features)       | 538             | absent        |
 *
 * `cargo metadata` keeps the `reqwest -> quinn` edge even though `reqwest`'s
 * enabled feature set contains no `http3` — so `quinn-proto`, a crate that has
 * never been compiled on this machine, counted as built-on-host. It was
 * Preemption's #1 item on 2026-09-07 (HIGH, "version-confirmed"). `cargo tree`
 * excludes it. Same predicate, same answer, as the app's
 * `src-tauri/src/ace/cargo_resolve.rs`.
 *
 * When cargo is unavailable the answer is `null` — *unknown*, never "nothing is
 * inactive". Callers surface that distinction rather than quietly asserting a
 * filter they did not run.
 */
import { spawn, type ChildProcess } from "node:child_process";
import * as fs from "node:fs";
import * as path from "node:path";
import { withinCallBudget } from "../call-budget.js";
import { serverDataDir } from "../db.js";
import { shutdownSignal } from "../shutdown.js";
import { fileSignature } from "./file-signature.js";

/** Rust target triple for the current host, or null for a platform we do not map. */
export function hostTriple(): string | null {
  const arch =
    process.arch === "x64" ? "x86_64" : process.arch === "arm64" ? "aarch64" : null;
  if (!arch) return null;

  switch (process.platform) {
    case "win32":
      return `${arch}-pc-windows-msvc`;
    case "darwin":
      return `${arch}-apple-darwin`;
    case "linux":
      return `${arch}-unknown-linux-gnu`;
    default:
      return null;
  }
}

/**
 * Per-directory memo, valid only while the workspace's Cargo.lock and
 * Cargo.toml are unchanged. The MCP server now re-resolves dependencies when a
 * lockfile changes, and server processes live for days (2026-09-10: two were
 * older than the lockfile they answered for). A memo keyed on the directory
 * alone would hand a re-resolution the OLD crate set, and every crate the new
 * lockfile added would read as not-built-on-host, hiding its advisories under
 * platform_inactive.
 */
const cache = new Map<string, { signature: string; crates: Set<string> | null }>();

/** The `cargo tree` runs not yet answered, per directory, with the file state each was asked about. */
const inFlight = new Map<string, { signature: string; done: Promise<void> }>();

/** Reset the memo. Tests only. */
export function _resetCargoPlatformCache(): void {
  cache.clear();
  inFlight.clear();
  gaveUpAt = Number.NEGATIVE_INFINITY;
  lastCargoChild = null;
}

/**
 * How long a `cargo tree` run may take before its answer is given up on and the child killed.
 * It normally answers in about a second (1,769 crates of the 4DA app's workspace: 0.8-1.0 s,
 * 2026-11-27). It takes the package-cache lock a concurrent `cargo build` or rust-analyzer holds
 * while it downloads crates, and then waits for as long as that takes (audit 2026-11-25, F-M2:
 * the synchronous run it replaces held the whole server for its 30 s timeout). Inside a tool call
 * the call's remaining budget, less CALL_RESERVE_MS for the lookups after it, bounds it further.
 */
const DEFAULT_CARGO_TREE_MS = 5_000;
const CALL_RESERVE_MS = 5_000;
let cargoTreeMs = DEFAULT_CARGO_TREE_MS;

export function cargoTreeWaitMs(): number {
  return cargoTreeMs;
}

/** Tests only: the bound of one `cargo tree` run; null restores the default. */
export function _setCargoTreeWaitForTests(ms: number | null): void {
  cargoTreeMs = ms ?? DEFAULT_CARGO_TREE_MS;
}

/** The program run as cargo; replaced in tests by a stand-in child process (never by configuration). */
let cargoCommand: { file: string; prefix: string[] } = { file: "cargo", prefix: [] };

/** Tests only: run `file prefix... <cargo tree args>` instead of cargo; null restores cargo. */
export function _setCargoCommandForTests(command: { file: string; prefix: string[] } | null): void {
  cargoCommand = command ?? { file: "cargo", prefix: [] };
}

/** The last cargo child started, kept so tests can wait on its exit instead of on a fixed delay. */
let lastCargoChild: ChildProcess | null = null;

/** Tests only: the last cargo child this module started (null when none since the last reset). */
export function _lastCargoChildForTests(): ChildProcess | null {
  return lastCargoChild;
}

function signatureOf(key: string): string {
  return `${fileSignature(path.join(key, "Cargo.lock"))}|${fileSignature(path.join(key, "Cargo.toml"))}`;
}

/**
 * Crate names cargo resolves for this host in the workspace at `dir`, as far as cargo has
 * answered for the files as they are now. Never waits: when cargo has not answered yet, it is
 * asked (once per state of Cargo.lock and Cargo.toml, as a child process) and the answer for now
 * is `null`. A caller that can wait waits for `activeCratesInFlight(dir)` and asks again; the
 * lockfile reader does so for a resolution run in steps (lockfile-parsers.ts), so a scan waits
 * for cargo's bounded answer while the server keeps answering.
 *
 * Returns `null` — meaning *unknown*, never "nothing" — when there is no
 * Cargo.toml, no host triple mapping, cargo is missing, fails, or did not answer
 * within cargoTreeWaitMs(). A `null` must never be treated as an empty set: that
 * would mark every crate inactive and silently hide real advisories. Callers
 * keep every crate active and say the scan is not platform-filtered.
 */
export function activeCratesForHost(dir: string): Set<string> | null {
  const key = path.resolve(dir);
  const signature = signatureOf(key);
  const memo = cache.get(key);
  if (memo !== undefined && memo.signature === signature) return memo.crates;
  if (!hostTriple() || !fs.existsSync(path.join(key, "Cargo.toml"))) {
    cache.set(key, { signature, crates: null });
    return null;
  }
  ask(key, signature);
  return null;
}

/**
 * The pending `cargo tree` answer for `dir` as its files are now, or null when none is pending.
 * It always settles, by cargoTreeWaitMs() at the latest (or at shutdown), and never rejects.
 */
export function activeCratesInFlight(dir: string): Promise<void> | null {
  const key = path.resolve(dir);
  const pending = inFlight.get(key);
  return pending && pending.signature === signatureOf(key) ? pending.done : null;
}

/**
 * activeCratesForHost, waiting for cargo (bounded by `timeoutMs`): for tests and callers off the
 * serving path. The serving path never calls it.
 */
export async function resolveActiveCratesForHost(dir: string, timeoutMs = 30_000): Promise<Set<string> | null> {
  const key = path.resolve(dir);
  const signature = signatureOf(key);
  const memo = cache.get(key);
  if (memo !== undefined && memo.signature === signature) return memo.crates;
  if (!hostTriple() || !fs.existsSync(path.join(key, "Cargo.toml"))) return activeCratesForHost(key);
  ask(key, signature, timeoutMs);
  await activeCratesInFlight(key);
  return cache.get(key)?.signature === signature ? cache.get(key)!.crates : null;
}

/**
 * Start one `cargo tree` for these files, unless one is already running for them. Its answer (or
 * `null` when it fails, is killed at its bound, or is cut off by shutdown) becomes the memo for
 * this file state, so a cargo that did not answer is not asked again until Cargo.lock or
 * Cargo.toml changes. Nothing is started during shutdown, or inside a call with no budget left.
 */
function ask(key: string, signature: string, boundMs?: number): void {
  if (inFlight.get(key)?.signature === signature) return;
  if (shutdownSignal.aborted) return;
  // A cargo that had to be killed at its bound is most likely waiting for a package-cache lock that
  // another cargo still holds: for a while the next workspaces are not asked, since each would wait
  // its whole bound too (50 Cargo workspaces would have held the first call for minutes). Their
  // answer stays unknown, and a later resolution asks again.
  if (boundMs === undefined && Date.now() - gaveUpAt < GIVE_UP_PAUSE_MS) return;
  const waitMs = boundMs ?? withinCallBudget(cargoTreeWaitMs(), CALL_RESERVE_MS);
  if (waitMs <= 0) return;
  const done: Promise<void> = runCargoTree(key, waitMs).then(({ out: raw, timedOut }) => {
    if (timedOut) gaveUpAt = Date.now();
    // A run for files that have changed since (a newer run started) leaves the memo to that one.
    if (inFlight.get(key)?.done !== done) return;
    inFlight.delete(key);
    const names = raw === null ? null : parseTreeNames(raw);
    // An empty result is not a credible answer for a real workspace; treat it
    // as unknown so nothing gets marked inactive on a parse quirk.
    cache.set(key, { signature, crates: names && names.size > 0 ? names : null });
  });
  inFlight.set(key, { signature, done });
}

/** When a `cargo tree` run was last killed at its bound, and how long after it no other one is started. */
let gaveUpAt = Number.NEGATIVE_INFINITY;
const GIVE_UP_PAUSE_MS = 60_000;

/** The most `cargo tree` output read (its crate list); past it the answer is unknown. */
const MAX_TREE_OUTPUT = 64 * 1024 * 1024;

/**
 * Run `cargo tree` for `dir` as a child process: its stdout when it exits 0 within `waitMs`,
 * otherwise null. A run past `waitMs`, or one still running at shutdown, is killed. On Windows the
 * rustup proxy ends the toolchain's cargo with it (measured 2026-11-27), and libuv's job object
 * ends both when the server exits.
 */
function runCargoTree(dir: string, waitMs: number): Promise<{ out: string | null; timedOut: boolean }> {
  return new Promise((resolve) => {
    let child: ChildProcess;
    try {
      const { args, cwd, targetDir } = cargoTreeInvocation(dir);
      fs.mkdirSync(cwd, { recursive: true });
      child = spawn(cargoCommand.file, [...cargoCommand.prefix, ...args], {
        cwd,
        env: { ...process.env, CARGO_TARGET_DIR: targetDir },
        stdio: ["ignore", "pipe", "ignore"],
        windowsHide: true,
      });
      lastCargoChild = child;
    } catch {
      resolve({ out: null, timedOut: false });
      return;
    }
    let settled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const chunks: Buffer[] = [];
    let size = 0;
    const onShutdown = () => stop(false);
    const finish = (out: string | null, timedOut = false) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      shutdownSignal.removeEventListener("abort", onShutdown);
      resolve({ out, timedOut });
    };
    function stop(timedOut: boolean): void {
      try {
        child.kill();
      } catch {
        // Already gone.
      }
      finish(null, timedOut);
    }
    // cargo absent, not a workspace, offline resolution impossible, a stale
    // lockfile: an error or a non-zero exit. A held package-cache lock: the bound.
    child.on("error", () => finish(null));
    child.stdout?.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (size > MAX_TREE_OUTPUT) stop(false);
      else chunks.push(chunk);
    });
    child.on("close", (code) => finish(code === 0 ? Buffer.concat(chunks).toString("utf8") : null));
    timer = setTimeout(() => stop(true), waitMs);
    timer.unref?.();
    shutdownSignal.addEventListener("abort", onShutdown, { once: true });
  });
}

/**
 * How `cargo tree` is invoked for the workspace at `dir`.
 *
 * cargo runs from a server-owned scratch directory and reaches the project
 * only through `--manifest-path`. cargo and rustup take their configuration
 * (`.cargo/config.toml`, `rust-toolchain.toml`) from the working directory and
 * its parents, so running inside the scanned project would let files in that
 * project configure the toolchain this server invokes. A scanned project is
 * untrusted input. `CARGO_TARGET_DIR` points at the same scratch directory so
 * cargo's metadata writes never land in the user's tree either.
 *
 * The scratch directory lives in the server's per-user data directory, not
 * the system temp directory. On a shared machine `/tmp` is writable by every
 * user, so a `/tmp/.cargo/config.toml` or a pre-created
 * `/tmp/4da-mcp-cargo-resolve/.cargo/config.toml` planted by another account
 * could set `build.rustc-wrapper` and run code as this user (audit 6.2.5 C-2).
 *
 * Exported for tests.
 */
export function cargoTreeInvocation(dir: string): {
  args: string[];
  cwd: string;
  targetDir: string;
} {
  const scratch = path.join(serverDataDir(), "cargo-resolve");
  return {
    args: [
      "tree",
      "--manifest-path",
      path.join(path.resolve(dir), "Cargo.toml"),
      // Never touch the network or mutate the lockfile from a read-only
      // scan. `--locked` also means a lockfile out of step with the manifest
      // fails loudly here rather than being silently re-resolved.
      "--offline",
      "--locked",
      // One package per line, no tree glyphs: `name vX.Y.Z [(...)]`.
      "--prefix",
      "none",
      // dev-dependencies are compiled by `cargo test`, so an advisory
      // against one is reachable. proc-macro deps ride along with normal.
      "--edges",
      "normal,build,dev",
    ],
    cwd: scratch,
    targetDir: scratch,
  };
}

/**
 * Crate names from `cargo tree --prefix none` output.
 *
 * Exported for tests: the parser is the part that can silently degrade to an
 * empty set, and an empty set is the one answer that must never be believed.
 */
export function parseTreeNames(stdout: string): Set<string> {
  const names = new Set<string>();
  for (const line of stdout.split(/\r?\n/)) {
    const token = line.split(/\s+/).find((t) => t.length > 0);
    // A package line starts with a crate name. Anything else — a blank line,
    // a `[dev-dependencies]` header from a future cargo, a warning — is not.
    if (token && /^[A-Za-z0-9._+-]+$/.test(token)) names.add(token);
  }
  return names;
}
