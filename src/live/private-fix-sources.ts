// SPDX-License-Identifier: Apache-2.0
/**
 * Fix-path lookups that never name a private package (review of #64, blocker): upgrade_planner
 * reads parent and lever names straight from the lockfile and asked the registries about them
 * (`@acme/api` reached registry.npmjs.org; a crate from an Acme registry reached
 * index.crates.io). Every lookup about a private name answers null, the "could not be read"
 * every caller already treats as not checked (never clean), and the name is recorded so the
 * answer can say why: `refusals`.
 */

import { FixPathSources, type PackageReleaseFacts, type RequirementHistory } from "./fix-paths.js";
import type { LiveCache } from "./cache.js";
import type { AdvisoryRanges } from "./osv-ranges.js";
import type { RateLimiter } from "./rate-limiter.js";
import type { OsvEcosystem } from "./types.js";

type PrivateReason = (ecosystem: string, name: string) => string | null;

export class PrivateAwareFixPathSources extends FixPathSources {
  /** Private names a lookup was refused for, with why (most recent last). */
  readonly refusals = new Map<string, string>();

  constructor(
    cache: LiveCache,
    rateLimiter: RateLimiter,
    private readonly privateReason: PrivateReason,
  ) {
    super(cache, rateLimiter);
  }

  /** True (and recorded) when any of these names is private in `ecosystem`. */
  private refused(ecosystem: string, ...names: string[]): boolean {
    for (const name of names) {
      const why = this.privateReason(ecosystem, name);
      if (why) {
        this.refusals.set(name, why);
        return true;
      }
    }
    return false;
  }

  override async packageAdvisories(ecosystem: OsvEcosystem, name: string): Promise<AdvisoryRanges[] | null> {
    return this.refused(ecosystem, name) ? null : super.packageAdvisories(ecosystem, name);
  }

  override async publishedVersions(ecosystem: OsvEcosystem, name: string): Promise<string[] | null> {
    return this.refused(ecosystem, name) ? null : super.publishedVersions(ecosystem, name);
  }

  override async parentRequirements(ecosystem: OsvEcosystem, parent: string, parentVersion: string, dep: string): Promise<string[] | null> {
    return this.refused(ecosystem, parent, dep) ? null : super.parentRequirements(ecosystem, parent, parentVersion, dep);
  }

  override async requirementHistory(ecosystem: OsvEcosystem, parent: string, dep: string): Promise<RequirementHistory | null> {
    return this.refused(ecosystem, parent, dep) ? null : super.requirementHistory(ecosystem, parent, dep);
  }

  override async releaseFacts(ecosystem: OsvEcosystem, name: string): Promise<PackageReleaseFacts | null> {
    return this.refused(ecosystem, name) ? null : super.releaseFacts(ecosystem, name);
  }

  override async cratesSparse(name: string, fresh = false): ReturnType<FixPathSources["cratesSparse"]> {
    return this.refused("crates.io", name) ? null : super.cratesSparse(name, fresh);
  }

  override async versionExists(ecosystem: OsvEcosystem, name: string, version: string): Promise<boolean | null> {
    return this.refused(ecosystem, name) ? null : super.versionExists(ecosystem, name, version);
  }

  override async goModuleVersions(module: string): Promise<string[] | null> {
    return this.refused("Go", module) ? null : super.goModuleVersions(module);
  }
}
