// SPDX-License-Identifier: Apache-2.0
// Types for ci-gates.mjs, so the tests that import it are type-checked.

export function corpusGatedTests(repoRoot?: string): string[];
/** `report` is untrusted JSON (vitest's JSON reporter output, or anything else). */
export function testsRanFindings(report: unknown, files: readonly string[]): string[];
export function jobBlock(workflowText: string, job: string): string | null;
export function jobNames(workflowText: string): string[];
export function workflowGateFindings(input: { ci: string; release: string; gated: readonly string[] }): string[];
export interface ReleaseHarness {
  name: string;
  job: string;
  script: string;
  command: string;
  checks: string;
}
export const RELEASE_HARNESSES: readonly ReleaseHarness[];
export function harnessWorkflowFindings(workflowText: string, harnesses?: readonly ReleaseHarness[]): string[];
