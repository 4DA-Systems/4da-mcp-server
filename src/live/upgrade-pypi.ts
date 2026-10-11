// SPDX-License-Identifier: Apache-2.0
/**
 * PyPI for `upgrade_impact`: the version index from the PyPI JSON API
 * (`https://pypi.org/pypi/<name>/json`), each release's sdist as the archive
 * its changelog is read from (files.pythonhosted.org, PyPI's own file host),
 * and the links the project itself publishes in `project_urls`.
 *
 * Versions are PEP 440, not semver (`2.0`, `3.0.0rc1`, `1.0.post1`), so they
 * are ordered with version-compare.ts's PEP 440 comparator. A release's
 * publish time is its earliest file upload; it is yanked when every file is.
 *
 * `project_urls` is metadata, not a changelog: a "Changelog" link usually
 * points at an HTML docs page this server does not parse (it is reported as
 * the release-notes URL). Only a link to a raw changelog FILE on GitHub can be
 * read, and only when the GitHub fallback is enabled (github-releases.ts).
 */

import { parsePep440 } from "./version-compare.js";
import type { PublishedVersion, RegistryIndex, UpgradeNet } from "./upgrade-sources.js";

const PYPI_TIMEOUT_MS = 30_000;

interface PyPIFile {
  url?: string;
  packagetype?: string;
  filename?: string;
  upload_time_iso_8601?: string;
  yanked?: boolean;
  yanked_reason?: string | null;
}

interface PyPIProject {
  info?: {
    name?: string;
    home_page?: string | null;
    project_urls?: Record<string, string> | null;
  };
  releases?: Record<string, PyPIFile[]>;
}

/** PEP 503 normalised name: lowercase, runs of `-`, `_`, `.` read as one `-`. */
export function normalizePypiName(name: string): string {
  return name.toLowerCase().replace(/[-_.]+/g, "-");
}

/** PEP 508 distribution name. */
export const PYPI_NAME = /^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,198}[A-Za-z0-9])?$/;

/** The sdist to read a changelog from: a `.tar.gz` first, then a `.zip`. */
function pickSdist(files: PyPIFile[]): string | undefined {
  const sdists = files.filter((f) => f.packagetype === "sdist" && typeof f.url === "string");
  return (sdists.find((f) => /\.tar\.gz$/i.test(f.url!)) ?? sdists.find((f) => /\.zip$/i.test(f.url!)))?.url;
}

const REPO_KEY = /^(?:source(?: code)?|repository|repo|code|github|git|homepage|home|project)$/i;
const CHANGELOG_KEY = /change ?log|changes|release ?notes|releases|history|news|what'?s ?new/i;

/** The project's source repository from `project_urls` / `home_page`: a GitHub URL first, then any https one. */
export function pypiRepository(info: PyPIProject["info"]): string | null {
  const urls = Object.entries(info?.project_urls ?? {}).filter(([, v]) => typeof v === "string");
  const github = (v: string) => /^https?:\/\/(?:www\.)?github\.com\/[\w.-]+\/[\w.-]+/i.test(v);
  const keyed = urls.filter(([k]) => REPO_KEY.test(k.trim()));
  const pick =
    keyed.find(([, v]) => github(v))?.[1] ??
    urls.find(([, v]) => github(v))?.[1] ??
    (info?.home_page && github(info.home_page) ? info.home_page : null) ??
    keyed.find(([, v]) => /^https:\/\//i.test(v))?.[1] ??
    null;
  return pick;
}

/** Links the project labels as its changelog / release notes, in `project_urls` order. */
export function pypiChangelogLinks(info: PyPIProject["info"]): string[] {
  return Object.entries(info?.project_urls ?? {})
    .filter(([k, v]) => typeof v === "string" && CHANGELOG_KEY.test(k) && /^https:\/\//i.test(v))
    .map(([, v]) => v);
}

export async function loadPypiIndex(net: UpgradeNet, name: string): Promise<RegistryIndex | null> {
  const url = `https://pypi.org/pypi/${encodeURIComponent(normalizePypiName(name))}/json`;
  const res = await net.fetch(url, { headers: { Accept: "application/json" } }, PYPI_TIMEOUT_MS);
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`PyPI HTTP ${res.status} for ${name}`);
  const doc = (await res.json()) as PyPIProject;
  if (!doc.releases || typeof doc.releases !== "object") throw new Error(`PyPI returned no release list for ${name}`);
  const versions: PublishedVersion[] = [];
  for (const [version, files] of Object.entries(doc.releases)) {
    if (!parsePep440(version)) continue;
    const list = Array.isArray(files) ? files : [];
    const times = list.map((f) => f.upload_time_iso_8601).filter((t): t is string => typeof t === "string").sort();
    const entry: PublishedVersion = { version, published: times[0] ?? null };
    if (list.length > 0 && list.every((f) => f.yanked)) {
      entry.yanked = true;
      const reason = list.find((f) => f.yanked_reason)?.yanked_reason;
      if (reason) entry.deprecated = `yanked: ${reason}`;
    }
    const sdist = pickSdist(list);
    if (sdist) entry.tarball = sdist;
    versions.push(entry);
  }
  return {
    name: doc.info?.name ?? name,
    ecosystem: "PyPI",
    versions,
    repository: pypiRepository(doc.info),
    changelogLinks: pypiChangelogLinks(doc.info),
  };
}
