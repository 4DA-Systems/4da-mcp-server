// SPDX-License-Identifier: Apache-2.0
/**
 * what_should_i_know and private packages (pre-publish audit 2026-11-13, S3). A task that upgrades
 * a private package (`@acme/vault-core`, private by the project's `.npmrc`) came back "No
 * dependency of this project is named in the task" and safe_to_delegate: private copies are kept
 * out of the dependency set every lookup reads, so the briefing never saw them. Nothing about a
 * private package is looked up, so the briefing says so first, and a task that touches one is
 * never safe to delegate on the scan's word.
 */

import type { ResolvedDependency } from "../live/types.js";
import { detectTaskPackages } from "./briefing-task-scope.js";

export interface PrivateTaskPackage {
  package: string;
  ecosystem: string;
  /** The installed versions, when the project installs it. */
  installed: string[];
  /** Which file or setting makes it private. */
  why: string;
}

export interface PrivateLookup {
  getPrivateAuditDeps?(): ResolvedDependency[];
  getPrivateDependencies?(): Array<{ ecosystem: string; name: string; version: string | null; why: string }>;
  privateReason?(ecosystem: string, name: string): string | null;
}

/** Tokens that can be a package name the project does not install yet: a scoped npm name, a module path, a plain name. */
const NAME_TOKEN = /(@[a-z0-9][\w.-]*\/[a-z0-9][\w.-]*|[a-z0-9][\w.-]*(?:\/[\w.-]+)+|[a-z0-9][\w.-]{2,})/gi;
const ECOSYSTEMS = ["npm", "crates.io", "PyPI", "Go", "RubyGems", "Packagist"];

/** The private packages a task names: installed private dependencies it touches, and any name the private rules cover. */
export function privateTaskPackages(task: string, files: string[], live: PrivateLookup | null): PrivateTaskPackage[] {
  if (!live) return [];
  const out = new Map<string, PrivateTaskPackage>();
  const why = new Map((live.getPrivateDependencies?.() ?? []).map((p) => [`${p.ecosystem}\0${p.name}`, p.why]));
  const installed = live.getPrivateAuditDeps?.() ?? [];
  for (const pkg of detectTaskPackages(task, files, installed, 20)) {
    const copies = installed.filter((d) => d.ecosystem === pkg.ecosystem && d.name === pkg.name);
    out.set(`${pkg.ecosystem}\0${pkg.name}`, {
      package: pkg.name,
      ecosystem: pkg.ecosystem,
      installed: [...new Set(copies.map((d) => d.version).filter((v): v is string => Boolean(v)))],
      why: why.get(`${pkg.ecosystem}\0${pkg.name}`) ?? "private",
    });
  }
  if (live.privateReason) {
    for (const token of task.match(NAME_TOKEN) ?? []) {
      const name = token.replace(/[.,;:]+$/, "");
      for (const ecosystem of ECOSYSTEMS) {
        const reason = live.privateReason(ecosystem, name);
        if (!reason) continue;
        const key = `${ecosystem}\0${name}`;
        if (![...out.values()].some((p) => p.ecosystem === ecosystem && p.package.toLowerCase() === name.toLowerCase())) {
          out.set(key, { package: name, ecosystem, installed: [], why: reason });
        }
        break;
      }
    }
  }
  return [...out.values()];
}

/**
 * Why `name` is private in ANY ecosystem this project's rules cover, or null. The briefing guesses
 * the ecosystem of a name a task mentions but the project does not visibly install, and private
 * copies are never visible to it: "bump omega-internal-risk to 3.2.0" (private by a pip
 * `--index-url`) was guessed npm and sent to OSV.dev and registry.npmjs.org, which the guard let
 * through because the name is private in PyPI, not npm (black-box re-run 2026-11-14). A guessed
 * ecosystem is only a guess, so a name private anywhere in the project is never looked up.
 */
export function privateAnywhere(live: PrivateLookup | null, name: string): string | null {
  if (!live?.privateReason) return null;
  for (const ecosystem of ECOSYSTEMS) {
    const why = live.privateReason(ecosystem, name);
    if (why) return why;
  }
  return null;
}

/** The advisory row the briefing leads with. */
export function privateAdvisoryText(found: PrivateTaskPackage[]): string {
  const names = found.map((p) => `${p.package}${p.installed.length ? ` ${p.installed.join("/")}` : ""}`).join(", ");
  return `NOT CHECKED (private): the task touches ${names}, ${found.length === 1 ? "a private package" : "private packages"}: nothing about ${found.length === 1 ? "it" : "them"} was looked up (no advisories, no releases, no breaking changes), so this briefing says nothing about ${found.length === 1 ? "it" : "them"}`;
}
