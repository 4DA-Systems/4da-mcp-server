// SPDX-License-Identifier: Apache-2.0
/**
 * dependency_check, the first stage of a pass (dependency-check.ts checkPass): the items no lookup
 * may be made for (a private package name, a Go module path the go command does not accept as
 * written, an npm name no package can have) are answered in place, never looked up; and with live
 * lookups off, every item is answered without a lookup.
 */

import { checkGoModulePath, goModulePathGrammarProblem, goPathNotCheckedText, goPathShapeProblem, type GoPathVerdict } from "../live/go-path.js";
import type { LiveIntelligence } from "../live/index.js";
import type { CheckEcosystem } from "../live/release-metadata.js";
import { PYPI_NAME } from "../live/upgrade-pypi.js";
import { credentialShape } from "./briefing-task-screen.js";
import { isNpmPackageName, quoteThirdParty } from "../untrusted-text.js";
import { AMBIGUOUS_SPEC_MARK, NOT_REGISTRY_MARK, UNREAD_CATALOG_MARK, unreadFileKind } from "../live/private-packages.js";
import { cachedAdvisoryNotes } from "./dependency-check-offline.js";
import { head, provisional, type ItemResult, type Requested } from "./dependency-check-items.js";

/** A pass's items after screening: the ones to look up, and how to put every answer back in the order asked. */
export interface Screened {
  /** The items that may be looked up, in the order asked. */
  requested: Requested[];
  /** The count of private items and npm's registry notice, for the pass's `_meta`. */
  privateMeta: { private?: number; registryNotice?: string };
  /** The results in the order asked, private items in their places. */
  inOrder: (checked: ItemResult[]) => ItemResult[];
  /** Per-item extras in the order asked, null at the private items. */
  inOrderOf: <T>(checked: T[]) => Array<T | null>;
}

/** Which items of a pass may be looked up; the others are answered here, in their places. */
export async function screenItems(all: Requested[], liveIntel: LiveIntelligence | null): Promise<Screened> {
  // A private package name is never sent anywhere (live/private-packages.ts): such an item is
  // "not checked (private)", never clean, and nothing below sees it.
  // The item names its ecosystem, so a registry or proxy for it that is not public makes any name private (R8).
  const privateWhy = all.map((r) => (liveIntel?.lookupPrivateReason ?? liveIntel?.privateReason)?.call(liveIntel, r.ecosystem, r.package) ?? null);
  // A Go module path the go command would not accept as written (`..`, `//`, a trailing `/`, `@`,
  // or a case the module does not declare) matches no advisory at OSV.dev: it is NOT CHECKED, with
  // the canonical path named, never `proceed` (pre-publish audit 2026-11-12, B1).
  // A package that is no name its registry can have (a local path, a URL, a git source, a whole
  // requirement line, a Cargo inline table, `babel/core`) is refused as written and never sent: the
  // ecosystem's own name grammar decides, for every ecosystem (pre-publish audit 2026-11-25, E3:
  // PyPI, crates.io and Go items went whole to their registry and OSV.dev). A Go path the go command
  // would read as a misspelt module (`//`, `..`, a trailing `/`, `@`) keeps its own answer below.
  const badName = all.map((r, i) => (privateWhy[i] ? null : nameProblem(r.ecosystem, r.package)));
  const live = Boolean(liveIntel?.isEnabled());
  const goPath = await Promise.all(
    all.map((r, i) => (r.ecosystem === "Go" && !privateWhy[i] && !badName[i] ? checkGoModulePath(r.package, live && r.target.kind === "exact" ? r.target.version : null, live ? undefined : offlineFetch) : null)),
  );
  const requested = all.filter((_, i) => !privateWhy[i] && !(goPath[i] && !goPath[i]!.ok) && !badName[i]);
  const privateItems = all.flatMap((r, i) => {
    const why = privateWhy[i];
    if (why) return [{ at: i, result: privateResult(r, why, liveIntel?.withheldUnreadableFile?.(why) ?? null, privateKind(liveIntel, r)) }];
    const bad = badName[i];
    if (bad) return [{ at: i, result: badNameResult(r, bad) }];
    const g = goPath[i];
    return g && !g.ok ? [{ at: i, result: goPathResult(r, g) }] : [];
  });
  /** The results in the order asked, private items in their places. */
  const inOrder = (checked: ItemResult[]): ItemResult[] => {
    const out: ItemResult[] = [];
    let next = 0;
    for (let i = 0; i < all.length; i++) {
      const p = privateItems.find((x) => x.at === i);
      out.push(p ? p.result : checked[next++]);
    }
    return out;
  };
  const notice = all.some((r) => r.ecosystem === "npm") ? (liveIntel?.getRegistryNotice?.() ?? null) : null;
  const privateCount = privateWhy.filter(Boolean).length;
  const privateMeta = { ...(privateCount > 0 ? { private: privateCount } : {}), ...(notice ? { registryNotice: notice } : {}) };
  /** Per-item extras in the order asked, null at the private items. */
  const inOrderOf = <T>(checked: T[]): Array<T | null> => {
    const out: Array<T | null> = [];
    let next = 0;
    for (let i = 0; i < all.length; i++) out.push(privateItems.some((x) => x.at === i) ? null : (checked[next++] ?? null));
    return out;
  };
  return { requested, privateMeta, inOrder, inOrderOf };
}

/** Live lookups off (FOURDA_OFFLINE): every item `unknown`, with a cached answer named where one exists. */
export async function offlineResults(liveIntel: LiveIntelligence | null, requested: Requested[]): Promise<{ results: ItemResult[]; osvCached: boolean }> {
  const reason = "Live lookups are disabled (FOURDA_OFFLINE=true); nothing about these versions could be checked.";
  // An exact version OSV.dev answered for before is named with that cached answer and its age.
  // The verdict stays `unknown`: a cached answer is not a current one (pre-publish round 10, W5).
  const cached = liveIntel?.answersFromCache?.() ? await cachedAdvisoryNotes(liveIntel, requested) : new Map<Requested, string>();
  return {
    results: requested.map((r) => ({ ...head(provisional(r)), verdict: "unknown" as const, reason: cached.has(r) ? `Live lookups are disabled (FOURDA_OFFLINE=true), so this version was not checked now. ${cached.get(r)}` : reason, signals: [] })),
    osvCached: cached.size > 0,
  };
}

/** A fetch that never reaches the network (offline): the Go path check then reads nothing. */
const offlineFetch = (async () => {
  throw new Error("offline");
}) as unknown as typeof import("../live/http-utils.js").fetchWithTimeout;

function goPathResult(r: Requested, verdict: Extract<GoPathVerdict, { ok: false }>): ItemResult {
  // A spelling refused on its shape alone was never sent anywhere; one refused on its declared case was read from the proxy.
  const unsent = goPathShapeProblem(r.package) ? " Nothing was sent to the Go proxy or OSV.dev." : "";
  return {
    ...head(provisional(r)),
    verdict: "unknown",
    reason: `${goPathNotCheckedText(r.package, verdict)}${unsent}`,
    signals: [],
    not_checked: "module_path",
    ...(verdict.canonical ? { canonical_module_path: verdict.canonical } : {}),
  };
}

/**
 * Why an npm name shaped like a scope is no name npm can have (`babel/core`: a "/" without the
 * leading "@"; `@babel`: a scope with no name), or null. Other names are left to the registry.
 */
export function npmScopeProblem(name: string): string | null {
  const valid = (n: string): boolean => isNpmPackageName(n);
  if ((!name.includes("/") && !name.startsWith("@")) || valid(name)) return null;
  const guess = !name.startsWith("@") && name.split("/").length === 2 && valid(`@${name}`) ? ` (did you mean "@${name}"?)` : "";
  return `a scoped package is written "@scope/name"${guess}`;
}

/** What a name is called in each ecosystem, and the registry it would have been sent to. */
const NAME_KIND: Record<CheckEcosystem, { what: string; registry: string }> = {
  npm: { what: "npm package name", registry: "the npm registry" },
  PyPI: { what: "PyPI project name", registry: "PyPI" },
  "crates.io": { what: "crates.io crate name", registry: "crates.io" },
  Go: { what: "Go module path", registry: "the Go proxy" },
};

/** Not a name: a path, a URL, a git source, an option or a manifest line in place of one. */
const NOT_A_NAME = "pass the registry name alone (a local path, a URL, a git source, an install option or a manifest line is not one, and is checked by reviewing its source)";

/**
 * Why `name` is no name `ecosystem`'s registry can have, or null. npm: a scope written without "@"
 * (with the scoped spelling suggested) or anything else outside npm's name rules. PyPI: PEP 508
 * (letters, digits, `.`, `_`, `-`, starting and ending with a letter or digit). crates.io: a letter,
 * then letters, digits, `_` and `-`, at most 64. Go: a module path (goModulePathGrammarProblem);
 * a spelling the go command reads as a misspelt module is left to checkGoModulePath. Each test is
 * one anchored regex with no nested quantifier: linear in the name's length (validateItem bounds it).
 */
/**
 * Round 6b, item 6: a version (or constraint) whose label carries the shape of a credential: a token prefix as a
 * label part (`1.0.0-ghp-...`), a part a credential screen matches (`1.0.0-AKIA...`, `+glpat-...`, a UUID), or a
 * run of 16 or more characters mixing capitals, lower case and digits. Real version shapes are kept: numbers,
 * pre-release words, and the 7-12 lower-case hex digits of an abbreviated commit (a Go pseudo-version's
 * `-20191109021931-daa7c04131f5`, a `+g1a2b3c4` build label). A full 40-digit commit in a label is refused.
 */
export function versionLooksSecret(version: string): boolean {
  const v = version.trim();
  if (credentialShape(v.replace(/^[^-+]*[-+]?/, ""))) return !/^[0-9a-f]{7,12}$/.test(v.replace(/^[^-+]*[-+]?/, ""));
  const parts = v.replace(/^[v=^~<>!]*\d+(?:\.\d+)*/, "").split(/[-+._,\s]/).filter(Boolean);
  return parts.some(
    (p) =>
      (credentialShape(p) && !/^[0-9a-f]{7,12}$/.test(p) && !/^\d+$/.test(p)) ||
      /^(?:gh[pousr]|github|glpat|sk|akia|xox[bpa]|npm|pat|token)$/i.test(p) ||
      (p.length >= 16 && /[A-Z]/.test(p) && /[a-z]/.test(p) && /\d/.test(p)),
  );
}

export function nameProblem(ecosystem: CheckEcosystem, name: string): string | null {
  switch (ecosystem) {
    case "npm": {
      if (isNpmPackageName(name)) return null;
      // `lodash@4.17.21`, `@babel/core@7`: the version goes in `to`.
      const pinned = /^(@?[^@]+)@[^@]*$/.exec(name);
      if (pinned && isNpmPackageName(pinned[1])) return `a version goes in \`to\`, not in the name (did you mean ${JSON.stringify(pinned[1])}?)`;
      return npmScopeProblem(name) ?? `An npm name is letters, digits and "-._~", with an optional "@scope/"; ${NOT_A_NAME}`;
    }
    case "PyPI":
      return PYPI_NAME.test(name) ? null : `a PyPI name is letters, digits, ".", "_" and "-", starting and ending with a letter or digit (extras and version specifiers go elsewhere: the version in \`to\`); ${NOT_A_NAME}`;
    case "crates.io":
      return CRATE_NAME.test(name) ? null : `a crate name is a letter followed by letters, digits, "_" and "-", at most 64 characters; ${NOT_A_NAME}`;
    case "Go": {
      if (goPathShapeProblem(name)) return null;
      const why = goModulePathGrammarProblem(name);
      return why ? `${why}; ${NOT_A_NAME}` : null;
    }
  }
}

const CRATE_NAME = /^[A-Za-z][A-Za-z0-9_-]{0,63}$/;

/** An item whose name its registry cannot have: unknown, refused as written, nothing sent. */
function badNameResult(r: Requested, problem: string): ItemResult {
  const kind = NAME_KIND[r.ecosystem];
  return {
    ...head(provisional(r)),
    verdict: "unknown",
    reason: `NOT CHECKED: ${JSON.stringify(quoteThirdParty(r.package, 214))} is not a valid ${kind.what}: ${problem}. Nothing was sent to ${kind.registry} or OSV.dev: correct it and ask again. This is not a clean result.`,
    signals: [],
    not_checked: "input",
  };
}

/**
 * An item whose package is private: unknown, with why, and nothing about it looked up. The
 * agent is told how to check it instead (the private registry's own tooling). A name withheld only
 * because a lockfile (or manifest) could not be read is not called private: where it would be
 * installed from is not known, and the remedy is to repair that file (6.5.0 called lodash "a
 * private package" beside an unparseable package-lock.json and sent the agent to a private registry).
 */
/** Round 22 (S3): why a withheld name is private (LiveIntelligence.privateRecordScope), or null when it cannot be asked. */
function privateKind(liveIntel: LiveIntelligence | null, r: Requested): { rule: string; host: string | null } | null {
  try {
    const scope = (liveIntel as { privateRecordScope?: (e: string, n: string) => { rule: string; host: string | null } } | null)?.privateRecordScope;
    return scope ? scope.call(liveIntel, r.ecosystem, r.package) : null;
  } catch {
    return null;
  }
}

function privateResult(r: Requested, why: string, unreadFile: string | null, kind: { rule: string; host: string | null } | null = null): ItemResult {
  if (unreadFile) {
    const kind = unreadFileKind(unreadFile);
    return {
      ...head(provisional(r)),
      verdict: "unknown",
      reason: `NOT CHECKED (unreadable ${kind}): ${unreadFile} could not be read, so where ${r.package} would be installed from is not known. It was withheld as possibly private: nothing about it was sent to OSV.dev or a registry, and nothing about ${provisional(r).to} is known. This is not a clean result: repair or regenerate the ${kind} (reinstall), then call dependency_check again.`,
      signals: [],
      not_checked: "private",
      unreadable_file: unreadFile,
    };
  }
  // A name withheld because a project takes it from a path, git, a URL, its workspace or an alias is
  // not a private package, and private-registry tooling is no help with it (re-check 2026-11-24).
  if (why.includes(AMBIGUOUS_SPEC_MARK)) {
    return {
      ...head(provisional(r)),
      verdict: "unknown",
      reason: `NOT CHECKED (ambiguous npm: spec): ${r.package}: ${why}. Nothing about it was sent to OSV.dev or a registry, and nothing about ${provisional(r).to} is known. This is not a clean result: write the spec as npm:<package>@<range>, or check the package it installs.`,
      signals: [],
      not_checked: "private",
    };
  }
  if (why.includes(UNREAD_CATALOG_MARK)) {
    return {
      ...head(provisional(r)),
      verdict: "unknown",
      reason: `NOT CHECKED (catalog not read): ${r.package}: ${why}. Nothing about it was sent to OSV.dev or a registry, and nothing about ${provisional(r).to} is known. This is not a clean result: fix the catalog, then call dependency_check again.`,
      signals: [],
      not_checked: "private",
    };
  }
  if (why.includes(NOT_REGISTRY_MARK)) {
    return {
      ...head(provisional(r)),
      verdict: "unknown",
      reason: `NOT CHECKED (not a registry release): ${r.package}: ${why}. Nothing about it was sent to OSV.dev or a registry, and nothing about ${provisional(r).to} is known. This is not a clean result: review the code it comes from, or ask about the registry package it installs.`,
      signals: [],
      not_checked: "private",
    };
  }
  // S3: a public name withheld only because the project's default registry is not known as public
  // is no private package: the answer says what was not checked, and how to have it checked.
  if (kind?.rule === "registry-wide") {
    const where = kind.host ? `this project's default registry is ${kind.host}, which 4DA does not know as public (${why})` : `this project installs from a registry 4DA does not know as public (${why})`;
    return {
      ...head(provisional(r)),
      verdict: "unknown",
      reason: `NOT CHECKED (private): not checked: ${where}, so nothing about ${r.package} was sent to OSV.dev or a public registry, and nothing about ${provisional(r).to} is known. This is not a clean result: if that registry proxies the public one, add its host to FOURDA_PUBLIC_MIRRORS and the package is checked like any other; if ${r.package} is your organisation's own package, list it in FOURDA_PRIVATE_PACKAGES.`,
      signals: [],
      not_checked: "private",
    };
  }
  return {
    ...head(provisional(r)),
    verdict: "unknown",
    reason: `NOT CHECKED (private): ${r.package} is a private package (${why}), so nothing about it was sent to OSV.dev or a public registry, and nothing about ${provisional(r).to} is known. This is not a clean result: check it with your private registry's own tooling.`,
    signals: [],
    not_checked: "private",
  };
}
