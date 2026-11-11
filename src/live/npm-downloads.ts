// SPDX-License-Identifier: Apache-2.0
/**
 * npm downloads over the last week, for dependency_check's name check: a name one or two edits
 * from a popular package is told from a typo-squat by whether anyone installs it, next to how
 * many install the package it resembles.
 *
 * The answer keeps "the registry has no record" apart from "the lookup failed": the first is a
 * fact about the package (nobody downloads it), the second is not, and a caller must never read
 * a failed lookup as either a high or a low count.
 *
 * Privacy: the request names the packages and nothing else (api.npmjs.org, the host
 * dependency_health already reads download counts from). Unscoped names go in one request (the
 * bulk form); a scoped name needs its own (the bulk form rejects them). Answers are kept in
 * memory for a few hours; a failure is not kept.
 */

import { fetchWithTimeout } from "./http-utils.js";

export type WeeklyDownloads =
  | { status: "ok"; downloads: number }
  /** The downloads API does not know the name: no recorded downloads. */
  | { status: "no_data" }
  | { status: "unreachable"; detail: string };

const NPM_DOWNLOADS_URL = "https://api.npmjs.org/downloads/point/last-week";
const TIMEOUT_MS = 8_000;
const FRESH_MS = 6 * 3_600_000;
const KEPT = 500;
/** The bulk form's limit per request. */
const BULK_MAX = 128;

const memo = new Map<string, { at: number; value: WeeklyDownloads }>();

function keep(name: string, value: WeeklyDownloads): WeeklyDownloads {
  if (value.status === "unreachable") return value;
  if (memo.size >= KEPT) memo.delete(memo.keys().next().value as string);
  memo.set(name, { at: Date.now(), value });
  return value;
}

function failure(error: unknown): WeeklyDownloads {
  const text = error instanceof Error ? error.message : String(error);
  return { status: "unreachable", detail: `api.npmjs.org: ${/abort/i.test(text) ? "timed out" : text.slice(0, 80)}` };
}

function count(body: unknown): WeeklyDownloads {
  const n = (body as { downloads?: unknown } | null)?.downloads;
  return typeof n === "number" && Number.isFinite(n) && n >= 0 ? { status: "ok", downloads: n } : { status: "unreachable", detail: "api.npmjs.org gave no download count" };
}

async function one(name: string): Promise<WeeklyDownloads> {
  // "@scope/pkg" is sent as written: the endpoint rejects an encoded "/".
  const path = name.startsWith("@") ? `@${name.slice(1).split("/").map(encodeURIComponent).join("/")}` : encodeURIComponent(name);
  try {
    const response = await fetchWithTimeout(`${NPM_DOWNLOADS_URL}/${path}`, { headers: { Accept: "application/json" } }, TIMEOUT_MS);
    if (response.status === 404) return { status: "no_data" };
    if (!response.ok) return { status: "unreachable", detail: `api.npmjs.org answered HTTP ${response.status}` };
    return count(await response.json());
  } catch (error) {
    return failure(error);
  }
}

async function bulk(names: string[]): Promise<Map<string, WeeklyDownloads>> {
  const out = new Map<string, WeeklyDownloads>();
  const all = (value: WeeklyDownloads) => {
    for (const n of names) out.set(n, value);
    return out;
  };
  try {
    const response = await fetchWithTimeout(`${NPM_DOWNLOADS_URL}/${names.map(encodeURIComponent).join(",")}`, { headers: { Accept: "application/json" } }, TIMEOUT_MS);
    if (!response.ok) return all({ status: "unreachable", detail: `api.npmjs.org answered HTTP ${response.status}` });
    const body = (await response.json()) as Record<string, unknown> | null;
    if (!body || typeof body !== "object") return all({ status: "unreachable", detail: "api.npmjs.org gave no download count" });
    // The bulk form answers one entry per name, null for a name it has no record of.
    for (const n of names) out.set(n, !Object.hasOwn(body, n) ? { status: "unreachable", detail: "api.npmjs.org left the name out of its answer" } : body[n] === null ? { status: "no_data" } : count(body[n]));
    return out;
  } catch (error) {
    return all(failure(error));
  }
}

/** Last week's downloads for each name, in as few requests as the API allows. */
export async function npmWeeklyDownloads(names: readonly string[]): Promise<Map<string, WeeklyDownloads>> {
  const out = new Map<string, WeeklyDownloads>();
  const wanted: string[] = [];
  for (const name of new Set(names)) {
    const hit = memo.get(name);
    if (hit && Date.now() - hit.at < FRESH_MS) out.set(name, hit.value);
    else wanted.push(name);
  }
  const unscoped = wanted.filter((n) => !n.startsWith("@"));
  const single = [...wanted.filter((n) => n.startsWith("@")), ...(unscoped.length === 1 ? unscoped : [])];
  const batches: string[][] = [];
  if (unscoped.length > 1) for (let i = 0; i < unscoped.length; i += BULK_MAX) batches.push(unscoped.slice(i, i + BULK_MAX));
  // A batch of one would be answered in the single form.
  while (batches.length > 0 && batches[batches.length - 1].length === 1) single.push(batches.pop()![0]);
  const [singles, bulks] = await Promise.all([Promise.all(single.map(async (n) => [n, await one(n)] as const)), Promise.all(batches.map(bulk))]);
  for (const [n, v] of singles) out.set(n, keep(n, v));
  for (const answers of bulks) for (const [n, v] of answers) out.set(n, keep(n, v));
  return out;
}

/** Forget every kept answer (tests). */
export function clearNpmDownloadsMemo(): void {
  memo.clear();
}
