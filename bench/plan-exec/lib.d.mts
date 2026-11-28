// SPDX-License-Identifier: Apache-2.0
// Types for lib.mjs, so the test that imports it is type-checked.

export type Inventory = Map<string, Set<string>>;
/** `ecosystem|dir|name` -> (version -> copies). */
export type CopyInventory = Map<string, Map<string, number>>;
export interface PlanRow {
  package: string;
  ecosystem: string;
  currentVersion: string;
  [field: string]: unknown;
}
export type Action =
  | { type: "run"; dir: string; run: string }
  | { type: "yarn1-delete"; dir: string; name: string }
  | { type: "override"; dir: string; file: string; snippet: string; then: string | null };
export interface Step {
  n: number;
  fixes: string[];
  rows: PlanRow[];
  actions: Action[];
}
export interface ScanRow {
  package: string;
  ecosystem: string;
  current_version: string;
  vuln_id: string;
  aliases?: string[];
}

export function tokenize(line: string): { parts: string[][] } | { refused: string };
export function prepareCommand(argv: string[], options?: { yarnFlavor?: "classic" | "berry" }): { argv: string[]; added: string[]; env: Record<string, string> } | { refused: string };
export function shellLine(argv: string[]): string;
export const YARN1_DELETE: RegExp;
export function yarn1DeleteEntries(lockfile: string, name: string): number;
export function normName(ecosystem: string, name: string): string;
export function copyKey(ecosystem: string, name: string, version: string): string;
export function fixKey(ecosystem: string, name: string): string;
export function planJson(answer: unknown): Record<string, unknown>;
export function overrideInstruction(row: { reasons?: string[] }): { snippet: string; file: string; then: string | null } | null;
export function extractSteps(plan: unknown): { source: "run_order" | "row_commands" | "legacy_rows"; note: string | null; steps: Step[]; rows: PlanRow[] };
export function mergeOverride(pkg: Record<string, unknown>, snippet: string): Record<string, unknown>;
export function findLockfiles(root: string): string[];
export function yarnFlavorOf(lockText: string): "classic" | "berry";
export function yarnFlavorFor(copy: string, cwd: string): "classic" | "berry";
export function lockfileVersions(base: string, text: string): Map<string, Set<string>>;
export function inventory(root: string): Inventory;
export function lockfileCopies(base: string, text: string): Map<string, Map<string, number>>;
export function copyInventory(root: string): CopyInventory;
export function versionsOf(copies: CopyInventory): Inventory;
export function movedTargets<T extends { ecosystem: string; package: string; version: string }>(before: CopyInventory, after: CopyInventory, targets: T[]): T[];
export function manifestEdit(cmds: Array<{ exit?: unknown; run?: string }>): boolean;
export function inventoryChanged(before: CopyInventory, after: CopyInventory): boolean;
export function presentTargets<T extends { ecosystem: string; package: string; version: string }>(copies: CopyInventory, targets: T[]): T[];
export function stepOutcome(input: { cmds: Array<{ exit?: unknown; refused?: string }>; targets: unknown[]; pending?: unknown[]; moved: unknown[]; changed: boolean; laterServesSame: boolean }): "nothing_to_run" | "failed" | "refused" | "without_effect" | "worked";
export function releaseLine(version: string): string;
export function changesFor(before: Inventory, after: Inventory, step: { fixes: string[] }): Array<{ key: string; removed: string[]; added: string[]; after: string[] }>;
export function presentAnywhere(inv: Inventory, ecosystem: string, name: string, version: string): boolean;
export function compareLoose(a: string, b: string): -1 | 0 | 1;
export function lowerings(before: Inventory, after: Inventory, earlier: Inventory, initial: Inventory): Array<{ key: string; from: string; to: string; set_by: "earlier_step" | "installed" | "other" }>;
export function addedVersions(before: Inventory, after: Inventory): Inventory;
export function vulnerableCopies(rows: ScanRow[]): Set<string>;
export function advisoryDelta(beforeRows: ScanRow[], afterRows: ScanRow[]): { cleared: string[]; introduced: string[] };
export function predictionCheck(input: { beforeRows: ScanRow[]; afterRows: ScanRow[]; steps: Step[] }): {
  vulnerable_copies_before: number;
  predicted_remaining: number;
  remaining: number;
  vulnerable_copies_after: number;
  new_vulnerable_copies: number;
  planned_but_remained: string[];
  not_planned_but_cleared: string[];
};
export function scanComplete(scan: unknown): boolean;
export interface ProjectResult {
  id: string;
  error?: string;
  scan_incomplete?: boolean;
  /** Dependencies the scans never looked up because a lockfile takes them from a private index. */
  private_dependencies?: number;
  order_source?: string;
  counts: Record<"steps" | "steps_run" | "steps_failed" | "steps_refused" | "steps_without_effect" | "steps_lowering" | "steps_lowering_earlier", number>;
  advisories: { before: number; after: number };
  prediction: Record<"vulnerable_copies_before" | "predicted_remaining" | "remaining" | "vulnerable_copies_after", number> & { planned_but_remained?: string[]; new_vulnerable_copies?: number };
}
export function totals(projects: ProjectResult[]): Record<string, unknown> & { net_cleared_ratio: number | null; order_sources: Record<string, number> };
export function gateFindings(t: ReturnType<typeof totals>, thresholds: Record<string, unknown>, projects?: ProjectResult[]): string[];
