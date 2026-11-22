// SPDX-License-Identifier: Apache-2.0
/**
 * The update notice. Every configuration this server ships pins its version, and a pinned install
 * never updates itself, so the server says when a newer release of @4da/mcp-server is published.
 *
 * What it holds to:
 * - It asks the registry only after a tool call of this session has already made a registry
 *   lookup (noteFinishedCall): never at start-up, never in offline mode, and at most
 *   once per 24 hours per data folder (the answer, or the failed attempt, is kept in cache.db for
 *   that long). It asks through the registry client every npm lookup uses.
 * - The registry's `latest` is third-party text: it is used only when it is a plain release
 *   version, and then only as a version.
 * - Only get_context (tool-dispatch.ts) and --doctor carry it. The doctor reads what a session
 *   kept and asks nothing for it.
 */

import { existsSync } from "node:fs";

import { callHosts, settleWithin } from "./call-budget.js";
import { serverCacheDbPath } from "./db.js";
import { isOfflineMode } from "./env-flags.js";
import { LiveCache } from "./live/cache.js";
import type { LiveIntelligence } from "./live/index.js";
import { compareVersions } from "./live/version-compare.js";
import { readPackageVersion } from "./setup.js";

const PACKAGE = "@4da/mcp-server";
const CACHE_KEY = "mcp-server-latest:v1";
/** One registry read per data folder per this long, whether it answered or not. */
const CHECK_TTL_SECONDS = 24 * 3600;
/** How long get_context waits for a due read; a slower one finishes in the background and is kept. */
const WAIT_MS = 3000;
/** The hosts whose requests count as a registry lookup. */
const REGISTRY_HOSTS = new Set(["registry.npmjs.org", "api.npmjs.org", "crates.io", "index.crates.io", "static.crates.io", "pypi.org", "files.pythonhosted.org", "proxy.golang.org"]);
const RELEASE = /^\d{1,6}\.\d{1,6}\.\d{1,6}$/;
const RUNNING = /^\d{1,6}\.\d{1,6}\.\d{1,6}(?:-[0-9A-Za-z.-]{1,40})?$/;

interface LatestRecord {
  /** The registry's latest release, or null when the read failed or gave no plain version. */
  latest: string | null;
  checkedAt: string;
}

/** The running package's version (package.json beside dist/), or null when unreadable. */
const RUNNING_VERSION = readPackageVersion();

/** The line naming both versions and the command that moves the pin; null unless `latest` is newer. */
export function updateNoticeText(running: string, latest: string): string | null {
  if (!RUNNING.test(running) || !RELEASE.test(latest) || compareVersions(latest, running, "npm") <= 0) return null;
  return (
    `A newer ${PACKAGE} is published: ${latest}; this server runs ${running}, and a pinned install never updates itself. ` +
    `Update the pin from ${PACKAGE}@${running} to ${PACKAGE}@${latest} in your MCP configuration, or run: npx -y ${PACKAGE}@${latest} --setup --update`
  );
}

/** Whether a tool call of this session has sent a request to a package registry (noteFinishedCall). */
let registryLookupMade = false;

/** Inside a tool call, as it answers (tool-dispatch.ts): note whether it sent a request to a package registry. */
export function noteFinishedCall(): void {
  if (callHosts().some((host) => REGISTRY_HOSTS.has(host))) registryLookupMade = true;
}

/** Whether a tool call of this session has sent a request to a package registry. */
export function registryLookupMadeThisSession(): boolean {
  return registryLookupMade;
}

let shared: LiveCache | null = null;
const cacheOf = (): LiveCache => (shared ??= new LiveCache(null));
let inFlight: Promise<void> | null = null;

/** Read the registry's latest release once and keep the answer, or the failure, for a day. */
async function readLatest(liveIntel: LiveIntelligence, cache: LiveCache): Promise<void> {
  let latest: string | null = null;
  try {
    const lookup = await liveIntel.getReleaseSources().npm.getReleases(PACKAGE, []);
    if (lookup.status === "ok" && typeof lookup.data.latest === "string" && RELEASE.test(lookup.data.latest)) latest = lookup.data.latest;
  } catch {
    // No answer: kept as no answer for a day, like any other failed read.
  }
  try {
    cache.set(CACHE_KEY, { latest, checkedAt: new Date().toISOString() } satisfies LatestRecord, "npm", CHECK_TTL_SECONDS);
  } catch {
    // A cache that cannot be written: the next call reads again.
  }
}

export interface UpdateNoticeOptions {
  cache?: LiveCache;
  running?: string | null;
  /** Whether a tool call of this session has made a registry lookup (default: what call-budget.ts recorded). */
  lookupMade?: () => boolean;
}

/**
 * The notice get_context carries, or null. Reads the registry only when a read is due (none kept
 * from the last 24 hours) and a tool call of this session has already made a registry lookup;
 * waits for it at most WAIT_MS.
 */
export async function updateNotice(liveIntel: LiveIntelligence | null, options: UpdateNoticeOptions = {}): Promise<string | null> {
  const running = options.running === undefined ? RUNNING_VERSION : options.running;
  if (!running || !liveIntel || !liveIntel.isEnabled() || isOfflineMode()) return null;
  const cache = options.cache ?? cacheOf();
  const kept = (): string | null => {
    const record = cache.get<LatestRecord>(CACHE_KEY);
    return record?.latest ? updateNoticeText(running, record.latest) : null;
  };
  if (cache.get<LatestRecord>(CACHE_KEY)) return kept();
  if (!(options.lookupMade ?? registryLookupMadeThisSession)()) return null;
  const pending = (inFlight ??= readLatest(liveIntel, cache).finally(() => {
    inFlight = null;
  }));
  await settleWithin(pending, WAIT_MS, () => undefined);
  return kept();
}

/** get_context's answer with `update_notice` when a newer release is published; no other tool carries it. */
export async function withUpdateNotice<T extends object>(context: T, liveIntel: LiveIntelligence | null): Promise<T & { update_notice?: string }> {
  const notice = await updateNotice(liveIntel).catch(() => null);
  return notice ? { ...context, update_notice: notice } : context;
}

/**
 * The doctor's line: the notice from what a server session kept in cache.db, or null. It asks no
 * registry, and opens no cache that does not exist yet.
 */
export function doctorUpdateCheck(running: string | null = RUNNING_VERSION): { name: string; status: "warn"; detail: string } | null {
  if (!running || isOfflineMode()) return null;
  try {
    if (!existsSync(serverCacheDbPath())) return null;
    const record = cacheOf().get<LatestRecord>(CACHE_KEY);
    const text = record?.latest ? updateNoticeText(running, record.latest) : null;
    return text ? { name: "Server version", status: "warn", detail: text } : null;
  } catch {
    return null;
  }
}
