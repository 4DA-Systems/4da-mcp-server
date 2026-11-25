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
 * - The Python versions a release supports are its files' `requires_python`.
 *
 * - What a judged release requires is its own document's `requires_dist`
 *   (`pypi.org/pypi/<name>/<version>/json`, getRequirements); the latest
 *   release's comes with the project document.
 *
 * Not read, and reported as not applicable by the signals: publisher identity
 * (the JSON API carries none), install-time hooks (PyPI exposes none in its
 * index; an sdist-only release runs its build backend at install), and which
 * dependencies a release adds.
 *
 * Privacy: the release list request names the package and nothing else. The
 * requirements of a release that is not the latest are read from that
 * release's own document, so that request carries the judged version too.
 */

import { sanitizeThirdParty } from "../untrusted-text.js";
import type { LiveCache } from "./cache.js";
import type { RateLimiter } from "./rate-limiter.js";
import { fetchWithTimeout } from "./http-utils.js";
import { parsePep440 } from "./version-compare.js";
import { normalizePypiName, PYPI_NAME } from "./upgrade-pypi.js";
import type { PackageReleaseIndex, RegistryLookup, ReleaseMetadataSource, ReleaseRecord, ReleaseRequirement, ReleaseRequirements } from "./release-metadata.js";
import { pep440SpecAdmits } from "../tools/dependency-check-versions.js";
import { readsAsPythonSpec, type ReleasePythonFacts } from "./project-python.js";
import { evaluateMarker, markerText, parseMarker } from "./pep508-marker.js";

const PYPI_URL = "https://pypi.org/pypi";
const TIMEOUT_MS = 30_000;
const TTL_SECONDS = 3600;
/** A published release's requirements never change. */
const REQUIREMENTS_TTL = 30 * 86_400;
// v2: a requirement keeps its environment marker; one cached without it is not read.
const requirementsKey = (normalized: string, version: string) => `pypi-requirements:v2:${normalized}@${version}`;

interface PyPIFile {
  upload_time_iso_8601?: string;
  yanked?: boolean;
  yanked_reason?: string | null;
  requires_python?: string | null;
}

/**
 * The Python versions a release supports: the `requires_python` of its files as one PEP 440
 * specifier set (every file's, when they differ), null when no file declares one. One that is not
 * a short specifier of version characters and operators is kept as unreadable, never printed.
 */
export function releaseRequiresPython(files: PyPIFile[]): ReleasePythonFacts {
  const declared = [...new Set(files.map((f) => (typeof f.requires_python === "string" ? f.requires_python.replace(/\s+/g, "") : "")).filter((s) => s !== ""))];
  if (declared.length === 0) return { requiresPython: null };
  const spec = declared.join(",");
  if (spec.length > 200 || !/^[0-9A-Za-z.,*!<>=~]+$/.test(spec) || !readsAsPythonSpec(spec)) return { requiresPython: null, requiresPythonUnreadable: true };
  return { requiresPython: spec };
}

interface PyPIProject {
  /** `version` and `requires_dist` are those of the project's latest release. */
  info?: { name?: string; version?: unknown; requires_dist?: unknown };
  releases?: Record<string, PyPIFile[] | null>;
}

/** A PEP 440 specifier set fit to print: short, of version characters and operators only, and one the specifier grammar reads. */
function isReadableSpecifier(spec: string): boolean {
  return spec === "" || (spec.length <= 200 && /^[0-9A-Za-z.,*!+<>=~_-]+$/.test(spec) && pep440SpecAdmits(spec, "1.0") !== null);
}

/**
 * What a release's `requires_dist` (PEP 508 strings) says an install of it brings: each entry's
 * project and version specifier. An entry whose marker is false when no extra is asked for
 * (`; extra == "socks"`, `; sys_platform == "win32" and extra == "y"`) is left out; one whose marker
 * holds then (`; extra != "y"`) is unconditional. One whose marker depends on the Python version or
 * the platform may be installed, so it is kept, flagged `conditional`, with the marker in canonical
 * form (release-requirements.ts judges it against the project's Pythons). A marker that does not
 * parse leaves the entry out when it names `extra` (as before), else keeps it conditional with no
 * marker text. A direct URL
 * reference, or a name or specifier that is not one, is counted `unreadable` and never passed on.
 */
export function parseRequiresDist(requiresDist: unknown): ReleaseRequirements {
  const out = new Map<string, ReleaseRequirement>();
  let unreadable = 0;
  for (const entry of Array.isArray(requiresDist) ? requiresDist : []) {
    if (typeof entry !== "string" || entry.length > 2_000) {
      unreadable++;
      continue;
    }
    const at = entry.indexOf(";");
    const head = at < 0 ? entry : entry.slice(0, at);
    const marker = at < 0 ? "" : entry.slice(at + 1).trim();
    let gate: { marker?: string } | null = null;
    if (marker) {
      const node = parseMarker(marker);
      const value = node ? evaluateMarker(node) : null;
      if (value === false || (!node && /\bextra\b/.test(marker))) continue;
      if (value === null) gate = node ? { marker: markerText(node) } : {};
    }
    const m = /^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(.*)$/.exec(head);
    const rest = m ? m[2].trim() : "";
    const spec = rest.replace(/^\(\s*/, "").replace(/\s*\)$/, "").replace(/\s+/g, "");
    if (!m || !PYPI_NAME.test(m[1]) || m[1].length > 100 || rest.startsWith("@") || !isReadableSpecifier(spec)) {
      unreadable++;
      continue;
    }
    const name = normalizePypiName(m[1]);
    out.set(`${name}\0${spec}`, { name, spec, ...(gate ? { conditional: true as const, ...gate } : {}) });
  }
  return { requirements: [...out.values()], unreadable };
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
      deprecated: reason ? `yanked: ${sanitizeThirdParty(reason)}` : null,
      withdrawn: yanked ? "yanked" : null,
      dependencies: null,
      ...releaseRequiresPython(files),
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
    // v2: each release carries its Python requirement; an index cached without it is not read.
    const key = `pypi-releases:v2:${normalized}`;
    const hit = this.cache.get<PackageReleaseIndex>(key);
    if (hit) return { status: "ok", data: hit };
    if (!this.rateLimiter.consume("pypi")) return ownLimit(this.rateLimiter, "pypi");
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
    // The project document carries its latest release's `requires_dist`: kept, so judging that
    // release needs no request of its own.
    const latest = doc.info?.version;
    if (typeof latest === "string" && index.releases[latest] && doc.info && "requires_dist" in doc.info) {
      this.cache.set(requirementsKey(normalized, latest), parseRequiresDist(doc.info.requires_dist), "pypi", REQUIREMENTS_TTL);
    }
    return { status: "ok", data: index };
  }

  /**
   * What one release requires: `info.requires_dist` of its own document
   * (`pypi.org/pypi/<name>/<version>/json`), the only place PyPI serves it for a release that is
   * not the latest. A published release's metadata never changes, so it is kept for a month.
   */
  async getRequirements(name: string, version: string): Promise<RegistryLookup<ReleaseRequirements>> {
    const normalized = normalizePypiName(name);
    const key = requirementsKey(normalized, version);
    const hit = this.cache.get<ReleaseRequirements>(key);
    if (hit) return { status: "ok", data: hit };
    if (!parsePep440(version)) return { status: "not_found", detail: "not a PEP 440 version" };
    // The registry-CDN bucket (as fix-path lookups): a requirement read never starves the release lists.
    if (!this.rateLimiter.consume("fixpath-registry")) return ownLimit(this.rateLimiter, "fixpath-registry");
    let response: Response;
    try {
      response = await fetchWithTimeout(`${PYPI_URL}/${encodeURIComponent(normalized)}/${encodeURIComponent(version)}/json`, { headers: { Accept: "application/json" } }, TIMEOUT_MS);
    } catch (err) {
      return { status: "unreachable", detail: `PyPI: ${errorText(err)}` };
    }
    if (response.status === 404) return { status: "not_found", detail: "PyPI does not serve this release" };
    if (!response.ok) return { status: "unreachable", detail: `PyPI answered HTTP ${response.status}` };
    let doc: PyPIProject;
    try {
      doc = (await response.json()) as PyPIProject;
    } catch (err) {
      return { status: "unreachable", detail: `PyPI: unreadable release document (${errorText(err)})` };
    }
    if (!doc.info || typeof doc.info !== "object") return { status: "unreachable", detail: "PyPI returned no metadata for this release" };
    const data = parseRequiresDist(doc.info.requires_dist);
    this.cache.set(key, data, "pypi", REQUIREMENTS_TTL);
    return { status: "ok", data };
  }

  async getCreatedAt(name: string): Promise<RegistryLookup<string | null>> {
    const lookup = await this.getReleases(name);
    return lookup.status === "ok" ? { status: "ok", data: lookup.data.createdAt } : lookup;
  }
}

/**
 * A PyPI read this server's own request limit held back: never sent, so PyPI is not blamed, and the
 * answer says when to ask again (pre-publish audit 2026-11-25, C-4, as 6.5.0 did for the Go proxy).
 */
function ownLimit(rateLimiter: RateLimiter, bucket: "pypi" | "fixpath-registry"): Extract<RegistryLookup<never>, { status: "unreachable" }> {
  const retryAfterSeconds = rateLimiter.retryAfterSeconds(bucket);
  return {
    status: "unreachable",
    detail: `this server's own request limit for PyPI was reached, so the read was not sent (it can be made in ${retryAfterSeconds} s)`,
    ownLimit: { registry: "PyPI", retryAfterSeconds },
  };
}

function errorText(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
