// SPDX-License-Identifier: Apache-2.0
/**
 * PyPI release index for dependency_check, from the JSON API
 * (`GET pypi.org/pypi/<name>/json`): every release with its upload time and
 * whether it is yanked.
 *
 * - A release's publish time is its EARLIEST file upload (later wheels for
 *   new platforms do not make it newer).
 * - A release is yanked when every one of its files is (PEP 592); pip then
 *   skips it unless pinned with `==`.
 * - A release with no files cannot be installed and is left out.
 * - Versions are PEP 440 and are kept as the registry spells them.
 *
 * Not read, and reported as not applicable by the signals: publisher identity
 * (the JSON API carries none), install-time hooks (PyPI exposes none in its
 * index; an sdist-only release runs its build backend at install), and
 * per-release dependency lists (one request per release).
 *
 * Privacy: the request names the package and nothing else.
 */

import type { LiveCache } from "./cache.js";
import type { RateLimiter } from "./rate-limiter.js";
import { fetchWithTimeout } from "./http-utils.js";
import { parsePep440 } from "./version-compare.js";
import { normalizePypiName } from "./upgrade-pypi.js";
import type { PackageReleaseIndex, RegistryLookup, ReleaseMetadataSource, ReleaseRecord } from "./release-metadata.js";

const PYPI_URL = "https://pypi.org/pypi";
const TIMEOUT_MS = 30_000;
const TTL_SECONDS = 3600;

interface PyPIFile {
  upload_time_iso_8601?: string;
  yanked?: boolean;
  yanked_reason?: string | null;
}

interface PyPIProject {
  info?: { name?: string };
  releases?: Record<string, PyPIFile[] | null>;
}

export const PYPI_NOT_APPLICABLE =
  "not applicable on PyPI: its JSON API carries no publisher identity or install-hook metadata";

/** The index the signals read, from one JSON API document. */
export function projectPypiProject(name: string, doc: PyPIProject): PackageReleaseIndex {
  const releases: Record<string, ReleaseRecord> = {};
  let createdAt: string | null = null;
  for (const [version, rawFiles] of Object.entries(doc.releases ?? {})) {
    const files = Array.isArray(rawFiles) ? rawFiles : [];
    if (files.length === 0 || !parsePep440(version)) continue;
    const times = files.map((f) => f.upload_time_iso_8601).filter((t): t is string => typeof t === "string").sort();
    const publishedAt = times[0] ?? null;
    if (publishedAt && (!createdAt || publishedAt < createdAt)) createdAt = publishedAt;
    const yanked = files.every((f) => f.yanked === true);
    const reason = yanked ? files.find((f) => f.yanked_reason)?.yanked_reason ?? null : null;
    releases[version] = {
      version,
      publishedAt,
      trust: 0,
      trustEvidence: PYPI_NOT_APPLICABLE,
      installScripts: null,
      deprecated: reason ? `yanked: ${reason}` : null,
      withdrawn: yanked ? "yanked" : null,
      dependencies: null,
    };
  }
  return { ecosystem: "PyPI", name: doc.info?.name ?? name, createdAt, releases };
}

export class PypiReleasesReader implements ReleaseMetadataSource {
  constructor(
    private cache: LiveCache,
    private rateLimiter: RateLimiter,
  ) {}

  async getReleases(name: string): Promise<RegistryLookup<PackageReleaseIndex>> {
    const normalized = normalizePypiName(name);
    const key = `pypi-releases:${normalized}`;
    const hit = this.cache.get<PackageReleaseIndex>(key);
    if (hit) return { status: "ok", data: hit };
    if (!this.rateLimiter.consume("pypi")) {
      return { status: "unreachable", detail: "PyPI rate limit reached for this minute" };
    }
    let response: Response;
    try {
      response = await fetchWithTimeout(
        `${PYPI_URL}/${encodeURIComponent(normalized)}/json`,
        { headers: { Accept: "application/json" } },
        TIMEOUT_MS,
      );
    } catch (err) {
      return { status: "unreachable", detail: `PyPI: ${errorText(err)}` };
    }
    if (response.status === 404) return { status: "not_found", detail: `"${name}" is not on PyPI` };
    if (!response.ok) return { status: "unreachable", detail: `PyPI answered HTTP ${response.status}` };
    let doc: PyPIProject;
    try {
      doc = (await response.json()) as PyPIProject;
    } catch (err) {
      return { status: "unreachable", detail: `PyPI: unreadable project document (${errorText(err)})` };
    }
    if (!doc.releases || typeof doc.releases !== "object") {
      return { status: "unreachable", detail: `PyPI returned no release list for ${name}` };
    }
    const index = projectPypiProject(name, doc);
    this.cache.set(key, index, "pypi", TTL_SECONDS);
    return { status: "ok", data: index };
  }

  async getCreatedAt(name: string): Promise<RegistryLookup<string | null>> {
    const lookup = await this.getReleases(name);
    return lookup.status === "ok" ? { status: "ok", data: lookup.data.createdAt } : lookup;
  }
}

function errorText(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
