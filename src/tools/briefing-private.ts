// SPDX-License-Identifier: Apache-2.0
/**
 * what_should_i_know and private packages (pre-publish audit 2026-11-13, S3). A task that upgrades
 * a private package (`@acme/vault-core`, private by the project's `.npmrc`) came back "No
 * dependency of this project is named in the task" and safe_to_delegate: private copies are kept
 * out of the dependency set every lookup reads, so the briefing never saw them. Nothing about a
 * private package is looked up, so the briefing says so first, and a task that touches one is
 * never safe to delegate on the scan's word.
 */

import { AMBIGUOUS_SPEC_MARK, NOT_REGISTRY_MARK, UNREAD_CATALOG_MARK } from "../live/private-packages.js";
import type { ResolvedDependency } from "../live/types.js";
import { detectTaskPackages } from "./briefing-task-scope.js";

export interface PrivateTaskPackage {
  package: string;
  ecosystem: string;
  /** The installed versions, when the project installs it. */
  installed: string[];
  /** Which file or setting makes it private. */
  why: string;
  /** Set when it is withheld only because this lockfile or manifest could not be read (PrivateDependency.unreadable_file). */
  unreadable_file?: string;
}

export interface PrivateLookup {
  getPrivateAuditDeps?(): ResolvedDependency[];
  getAuditDeps?(): ResolvedDependency[];
  getPrivateDependencies?(): Array<{ ecosystem: string; name: string; version: string | null; why: string; unreadable_file?: string }>;
  privateReason?(ecosystem: string, name: string): string | null;
  /** privateReason with the ecosystem whose rule makes the name private. */
  privateMatch?(ecosystem: string, name: string): { ecosystem: string; why: string } | null;
}

/** Tokens that can be a package name the project does not install yet: a scoped npm name, a module path, a plain name. */
const NAME_TOKEN = /(@[a-z0-9][\w.-]*\/[a-z0-9][\w.-]*|[a-z0-9][\w.-]*(?:\/[\w.-]+)+|[a-z0-9][\w.-]{2,})/gi;
const ECOSYSTEMS = ["npm", "crates.io", "PyPI", "Go", "RubyGems", "Packagist"];

/** The private packages a task names: installed private dependencies it touches, and any name the private rules cover. */
export function privateTaskPackages(task: string, files: string[], live: PrivateLookup | null): PrivateTaskPackage[] {
  if (!live) return [];
  const out = new Map<string, PrivateTaskPackage>();
  const why = new Map((live.getPrivateDependencies?.() ?? []).map((p) => [`${p.ecosystem}\0${p.name}`, p.why]));
  const unread = new Map((live.getPrivateDependencies?.() ?? []).filter((p) => p.unreadable_file).map((p) => [`${p.ecosystem}\0${p.name}`, p.unreadable_file!]));
  const unreadOf = (ecosystem: string, name: string) => {
    const file = unread.get(`${ecosystem}\0${name}`);
    return file ? { unreadable_file: file } : {};
  };
  const installed = live.getPrivateAuditDeps?.() ?? [];
  for (const pkg of detectTaskPackages(task, files, installed, 20)) {
    const copies = installed.filter((d) => d.ecosystem === pkg.ecosystem && d.name === pkg.name);
    out.set(`${pkg.ecosystem}\0${pkg.name}`, {
      package: pkg.name,
      ecosystem: pkg.ecosystem,
      installed: [...new Set(copies.map((d) => d.version).filter((v): v is string => Boolean(v)))],
      why: why.get(`${pkg.ecosystem}\0${pkg.name}`) ?? "private",
      ...unreadOf(pkg.ecosystem, pkg.name),
    });
  }
  // A private dependency named by its short name: "upgrade telemetry-x to 3.1" for @sigma/telemetry-x,
  // "update secret-go" for github.com/acmecorp/secret-go (blind audit round 3).
  const words = new Set((task.match(NAME_TOKEN) ?? []).map((t) => t.replace(/[.,;:]+$/, "").toLowerCase()));
  // A short name the project also installs publicly (`react` beside a private `@acme/react`) is that public package.
  const publicNames = new Set((live.getAuditDeps?.() ?? []).map((d) => d.name.toLowerCase()));
  for (const p of live.getPrivateDependencies?.() ?? []) {
    const short = p.name.split("/").pop()!.toLowerCase();
    const byShort = words.has(short) && !publicNames.has(short);
    if (!words.has(p.name.toLowerCase()) && !byShort) continue;
    if ([...out.values()].some((o) => o.ecosystem === p.ecosystem && o.package === p.name)) continue;
    const copies = installed.filter((d) => d.ecosystem === p.ecosystem && d.name === p.name);
    out.set(`${p.ecosystem}\0${p.name}`, {
      package: p.name,
      ecosystem: p.ecosystem,
      installed: [...new Set(copies.map((d) => d.version).filter((v): v is string => Boolean(v)))],
      why: p.why,
      ...unreadOf(p.ecosystem, p.name),
    });
  }
  if (live.privateReason) {
    for (const token of task.match(NAME_TOKEN) ?? []) {
      const name = token.replace(/[.,;:]+$/, "");
      for (const asked of ECOSYSTEMS) {
        // The ecosystem that makes it private, not the first one asked (blind audit round 5, 5).
        const reason = live.privateReason(asked, name);
        if (!reason) continue;
        const ecosystem = live.privateMatch?.(asked, name)?.ecosystem ?? asked;
        const key = `${ecosystem}\0${name}`;
        // Once per name: a private PyPI dependency is not listed again as private under npm, nor a
        // private package already listed again by its short name (`telemetry-x` for `@sigma/telemetry-x`).
        const lower = name.toLowerCase();
        if (![...out.values()].some((p) => p.package.toLowerCase() === lower || p.package.split("/").pop()!.toLowerCase() === lower)) {
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
  const label = (p: PrivateTaskPackage) => `${p.package}${p.installed.length ? ` ${p.installed.join("/")}` : ""}`;
  const unread = found.filter((p) => p.unreadable_file);
  const notRegistry = (p: PrivateTaskPackage) => p.why.includes(NOT_REGISTRY_MARK) || p.why.includes(UNREAD_CATALOG_MARK) || p.why.includes(AMBIGUOUS_SPEC_MARK);
  const local = found.filter((p) => !p.unreadable_file && notRegistry(p));
  const priv = found.filter((p) => !p.unreadable_file && !notRegistry(p));
  const parts: string[] = [];
  if (unread.length > 0) {
    const one = unread.length === 1;
    const files = [...new Set(unread.map((p) => p.unreadable_file!))].join(", ");
    parts.push(
      `NOT CHECKED (unreadable lockfile): the task touches ${unread.map(label).join(", ")}, and ${files} could not be read, so where ${one ? "it is" : "they are"} installed from is not known: nothing about ${one ? "it" : "them"} was looked up (no advisories, no releases, no breaking changes), so this briefing says nothing about ${one ? "it" : "them"}`,
    );
  }
  if (priv.length > 0) {
    const one = priv.length === 1;
    parts.push(
      `NOT CHECKED (private): the task touches ${priv.map(label).join(", ")}, ${one ? "a private package" : "private packages"}: nothing about ${one ? "it" : "them"} was looked up (no advisories, no releases, no breaking changes), so this briefing says nothing about ${one ? "it" : "them"}`,
    );
  }
  if (local.length > 0) {
    const one = local.length === 1;
    parts.push(
      `NOT CHECKED: the task touches ${local.map(label).join(", ")}, which this server does not look up by name here (${local.map((p) => p.why).join("; ")}): nothing about ${one ? "it" : "them"} was looked up, so this briefing says nothing about ${one ? "it" : "them"}`,
    );
  }
  return parts.join(". ");
}
