// SPDX-License-Identifier: Apache-2.0
// Types for lib.mjs, so the tests that import it are type-checked.
import type { Mutation } from "./mutations.mjs";

/** Where a mutant's `find` sits in its file. */
export interface Located {
  error?: undefined;
  path: string;
  text: string;
  at: number;
  line: number;
}

export function locate(m: Mutation, root: string): Located | { error: string };
export function applied(m: Mutation, loc: Located): string;
export function validate(list: readonly Mutation[], root: string): string[];
export function listFindings(list: readonly Mutation[], root: string): string[];

/** Failed tests of a vitest JSON report; totals are null when the report does not give them. */
export interface FailureReport {
  total: number | null;
  passed: number | null;
  failed: string[];
}
export function failures(reportText: null): null;
export function failures(reportText: string): FailureReport;
export function failures(reportText: string | null): FailureReport | null;
