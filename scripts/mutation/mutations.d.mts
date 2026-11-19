// SPDX-License-Identifier: Apache-2.0
// Types for mutations.mjs, so the tests that import it are type-checked.

/** One exact-text mutant: `find` in `file` (its `nth` occurrence) becomes `replace`. */
export interface Mutation {
  id: string;
  area?: string;
  file: string;
  find: string;
  replace: string;
  nth?: number;
  intent: string;
  tests?: string[];
  equivalent?: string;
}

export const mutations: Mutation[];
