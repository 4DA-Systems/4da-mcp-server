// SPDX-License-Identifier: Apache-2.0
// Types for release.mjs, so the tests that import it are type-checked.

export const VERSION_FILES: string[];
export function bumpVersionFiles(files: Record<string, string>, current: string, next: string): Record<string, string>;
