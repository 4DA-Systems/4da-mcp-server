// SPDX-License-Identifier: Apache-2.0
/**
 * dependency_check's default answer: the verdict and what to write instead, per item.
 *
 * Head-to-head 2026-11-11 (audit W1 M2-5): a 25-item answer was 51 KB against GitHub's 11 KB for
 * the same question, most of it signals that came back `proceed` or `info` with their evidence
 * ("0.14.9 is neither yanked nor deprecated."). The concise form keeps every fact an agent acts on:
 * the verdict, the reason (which carries the evidence of every avoid / review / unknown / wait
 * finding and every NOT CHECKED source), the safe versions to write, the advisory ids, a malicious
 * package's records, the unmaintained notices, and every registry quote (third-party text, in its
 * own field). `response_format: "detailed"` returns every signal with its value and evidence, how
 * `to` was read, and the whole range check.
 */

import type { RangeCheck } from "./dependency-check-versions.js";
import type { Signal, Verdict } from "./dependency-check-signals.js";

export type DependencyCheckFormat = "concise" | "detailed";

/** The detailed item, as executeDependencyCheck returns it. */
export interface DetailedItem {
  ecosystem: string;
  package: string;
  /** crates.io: the spelling asked, when the crate is published under another. */
  package_requested?: string;
  /** Each release what was asked can install, judged, when that is more than one (dependency-check-resolution.ts). */
  resolution?: { reads_as: string; judged: Array<{ version: string; installed_when: string; verdict: Verdict; advisories: string[]; signals?: Signal[] }> };
  from: string | null;
  to: string;
  to_requested?: string;
  to_read_as?: string;
  verdict: Verdict;
  reason: string;
  signals: Signal[];
  range_check?: RangeCheck;
  maintenance_notices?: string[];
  needs_newer_rust?: { needs: string; declared: string; manifest: string };
  /** "private": the package name is private and was never looked up (live/private-packages.ts). */
  not_checked?: string;
  /** not_checked "private" only because this lockfile (or manifest) could not be read. */
  unreadable_file?: string;
  canonical_module_path?: string;
  retry_after_seconds?: number;
}

export interface DetailedAnswer {
  checked_at: string;
  summary: string;
  results: DetailedItem[];
  _meta: Record<string, unknown>;
}

const NOTE =
  'Concise answer: verdict, reason (the evidence of every avoid, review, unknown and wait finding), the safe versions to write, advisory ids and registry quotes. Pass response_format: "detailed" for every signal with its evidence, how `to` was read, and the full range check.';

export function conciseItem(item: DetailedItem): Record<string, unknown> {
  const advisories = item.signals.find((s) => s.id === "advisories");
  const value = (advisories?.value ?? null) as {
    affecting_to?: string[];
    fixed_by_this_change?: string[];
    malicious_package?: { ids: string[]; taken_down: boolean; did_you_mean: string | null };
    held_dependencies_affected?: unknown;
    required_minimums_affected?: unknown;
  } | null;
  const rc = item.range_check;
  const safe = rc
    ? {
        range: rc.range,
        smallest: rc.smallest_safe_in_range,
        newest: rc.newest_safe_in_range,
        ...(rc.smallest_safe_upgrade !== undefined ? { smallest_upgrade: rc.smallest_safe_upgrade } : {}),
        ...(rc.newest_safe_outside_range ? { newest_outside_range: rc.newest_safe_outside_range } : {}),
        ...(rc.too_new?.length ? { too_new: rc.too_new } : {}),
        // Go: a named pick whose own go.mod requires an affected minimum is never named without that said.
        ...(rc.requirement_caveats ? { caveats: rc.requirement_caveats } : {}),
      }
    : null;
  const quoted: Record<string, string> = {};
  for (const s of item.signals) if (s.quoted_from_registry) quoted[s.id] = s.quoted_from_registry;
  for (const [version, text] of Object.entries(rc?.quoted_from_registry ?? {})) quoted[version] = text;
  return {
    ecosystem: item.ecosystem,
    package: item.package,
    ...(item.package_requested ? { package_requested: item.package_requested } : {}),
    ...(item.from ? { from: item.from } : {}),
    to: item.to,
    ...(item.to_requested ? { to_requested: item.to_requested, to_read_as: item.to_read_as } : {}),
    verdict: item.verdict,
    reason: item.reason,
    ...(item.not_checked ? { not_checked: item.not_checked } : {}),
    ...(item.unreadable_file ? { unreadable_file: item.unreadable_file } : {}),
    ...(item.canonical_module_path ? { canonical_module_path: item.canonical_module_path } : {}),
    ...(item.retry_after_seconds ? { retry_after_seconds: item.retry_after_seconds } : {}),
    ...(value?.affecting_to?.length ? { advisories: value.affecting_to } : {}),
    ...(value?.fixed_by_this_change?.length ? { fixes: value.fixed_by_this_change } : {}),
    ...(value?.malicious_package ? { malicious_package: value.malicious_package } : {}),
    ...(value?.held_dependencies_affected ? { held_dependencies_affected: value.held_dependencies_affected } : {}),
    ...(value?.required_minimums_affected ? { required_minimums_affected: value.required_minimums_affected } : {}),
    ...(safe ? { safe } : {}),
    // Round 10, W2: every release the write can install, with its verdict (signals only in the detailed form).
    ...(item.resolution
      ? { resolution: { reads_as: item.resolution.reads_as, judged: item.resolution.judged.map(({ signals: _signals, ...j }) => j) } }
      : {}),
    ...(item.maintenance_notices?.length ? { maintenance_notices: item.maintenance_notices } : {}),
    ...(item.needs_newer_rust ? { needs_newer_rust: item.needs_newer_rust } : {}),
    ...(Object.keys(quoted).length > 0 ? { quoted_from_registry: quoted } : {}),
  };
}

/** The answer in the requested form; detailed is returned unchanged. */
export function shapeDependencyCheck(answer: DetailedAnswer, format: DependencyCheckFormat | undefined) {
  if (format === "detailed") return answer;
  const meta = answer._meta;
  return {
    checked_at: answer.checked_at,
    summary: answer.summary,
    results: answer.results.map(conciseItem),
    _meta: {
      response_format: "concise",
      note: NOTE,
      verdict_rule: meta.verdict_rule,
      untrusted_text: meta.untrusted_text,
      offline: meta.offline,
      osv_cached: meta.osv_cached,
      ...(meta.private_packages ? { private_packages: meta.private_packages } : {}),
      ...(meta.unreadable_lockfile ? { unreadable_lockfile: meta.unreadable_lockfile } : {}),
      ...(meta.registry_notice ? { registry_notice: meta.registry_notice } : {}),
    },
  };
}
