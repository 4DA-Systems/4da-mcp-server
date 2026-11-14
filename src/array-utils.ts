// SPDX-License-Identifier: Apache-2.0
/**
 * Array helpers that never spread an array into a call's arguments.
 *
 * `target.push(...items)`, `Math.max(...values)` and `String.fromCharCode(...codes)` pass every
 * element as an argument, and V8 puts arguments on the stack: past roughly 100,000 elements the
 * call throws "RangeError: Maximum call stack size exceeded". A 150,000-entry pnpm lockfile whose
 * lookups went unanswered (OSV.dev down, or the query budget spent) hit it in the scanner and came
 * back NOT CHECKED for the wrong reason (pre-publish round 7). Every unbounded spread-into-a-call
 * goes through these instead; `scripts/check-repo.mjs` refuses new ones.
 */

/** Appends every item of `items` to `target`, in order, and returns `target`. */
export function pushAll<T>(target: T[], items: Iterable<T>): T[] {
  for (const item of items) target.push(item);
  return target;
}

/** The largest of `values`, or `empty` when there are none (Math.max() of nothing is -Infinity). */
export function maxOf(values: Iterable<number>, empty = -Infinity): number {
  let max = empty;
  let any = false;
  for (const v of values) {
    if (!any || v > max || Number.isNaN(v)) max = v;
    any = true;
    if (Number.isNaN(max)) return NaN;
  }
  return max;
}
