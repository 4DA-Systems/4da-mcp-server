// SPDX-License-Identifier: Apache-2.0
/**
 * Which changelog `upgrade_impact` reports, and what it says when there is none.
 *
 * Order: the changelog inside the target version's registry archive (always;
 * Decision 1 option A), then, only when the user opted in with
 * FOURDA_GITHUB_CHANGELOG and the archive does not cover the range, the
 * GitHub fallback (a changelog file the project links, then its releases;
 * Decision 1 option B). The GitHub result replaces the archive's only when it
 * covers the range or has more of its releases.
 *
 * With the fallback off and no usable changelog, the answer says the
 * changelog is unavailable and exactly how to enable the fallback, or that
 * enabling it would not help (no GitHub repository). It never fills the gap
 * with a guess.
 */

import { selectRange, type ChangelogSection, type VersionOrder } from "../live/changelog.js";
import { GITHUB_CHANGELOG_ENV, getGithubChangelog, parseGithubRepo } from "../live/github-releases.js";
import { getChangelog, type ChangelogResult, type PublishedVersion, type RegistryIndex, type UpgradeNet } from "../live/upgrade-sources.js";

export interface ResolvedChangelog {
  changelog: ChangelogResult;
  range: { sections: ChangelogSection[]; coversRange: boolean };
  /** Present when the archive did not cover the range: what the fallback did, or how to turn it on. */
  github_fallback?: Record<string, unknown>;
}

export interface ChangelogRequest {
  net: UpgradeNet;
  index: RegistryIndex;
  target: PublishedVersion;
  from: string;
  to: string;
  firstInRange: string;
  order: VersionOrder;
  githubEnabled: boolean;
  /** Repository to read releases from (Go: the proxy's VCS origin when known). */
  repository: string | null;
  /** Go: the module's tag prefix in its repository. */
  tagPrefix?: string | null;
}

function rangeOf(result: ChangelogResult, req: ChangelogRequest) {
  return result.found && result.sections
    ? selectRange(result.sections, req.from, req.to, req.firstInRange, req.order)
    : { sections: [], coversRange: false };
}

export async function resolveChangelog(req: ChangelogRequest): Promise<ResolvedChangelog> {
  const archive = await getChangelog(req.net, req.index, req.target);
  const archiveRange = rangeOf(archive, req);
  if (archiveRange.coversRange) return { changelog: archive, range: archiveRange };

  const repo = parseGithubRepo(req.repository);
  const pyLinks = (req.index.changelogLinks ?? []).filter((l) => /^https:\/\/(?:github\.com|raw\.githubusercontent\.com)\//i.test(l));
  const archiveState = !archive.found
    ? archive.reason ?? "no changelog in the archive"
    : archiveRange.sections.length === 0
      ? `${archive.file} has no section for these releases`
      : `${archive.file} covers only part of the range`;

  if (!req.githubEnabled) {
    const where = repo ? `github.com/${repo.owner}/${repo.repo}` : null;
    return {
      changelog: archive,
      range: archiveRange,
      github_fallback: where || pyLinks.length > 0
        ? {
            enabled: false,
            how_to_enable: `Set ${GITHUB_CHANGELOG_ENV}=true in this MCP server's environment to read the release notes ${where ? `on ${where}` : "the project links on GitHub"} when the archive has none. GitHub then receives the repository name and the version range only; GITHUB_TOKEN, if set, raises its rate limit.`,
          }
        : {
            enabled: false,
            note: `The package names no GitHub repository, so ${GITHUB_CHANGELOG_ENV} would not find release notes either; see release_notes_url.`,
          },
    };
  }

  const gh = await getGithubChangelog(req.net, {
    pkg: req.index.name,
    ecosystem: req.index.ecosystem,
    repository: req.repository,
    changelogLinks: req.index.changelogLinks,
    from: req.from,
    to: req.to,
    tagPrefix: req.tagPrefix ?? null,
    order: req.order,
  });
  if (!gh.found) {
    return { changelog: archive, range: archiveRange, github_fallback: { enabled: true, used: false, reason: gh.reason } };
  }
  const ghRange = rangeOf(gh, req);
  if (ghRange.coversRange || ghRange.sections.length > archiveRange.sections.length) {
    return {
      changelog: gh,
      range: ghRange,
      github_fallback: { enabled: true, used: true, source: gh.source, url: gh.url, archive: archiveState },
    };
  }
  return {
    changelog: archive,
    range: archiveRange,
    github_fallback: { enabled: true, used: false, reason: "the GitHub release notes cover no more of the range than the archive's changelog" },
  };
}
