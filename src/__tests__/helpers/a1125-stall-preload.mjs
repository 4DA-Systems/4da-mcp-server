// SPDX-License-Identifier: Apache-2.0
// Test preload: after the hook's STALL_AFTER-th clock read, performance.now() runs 3 s ahead, as a
// starved or suspended process sees it (the tenth independent check's stall case).
import { performance } from "node:perf_hooks";

const after = Number(process.env.STALL_AFTER ?? "0");
if (after > 0) {
  const real = performance.now.bind(performance);
  let n = 0;
  performance.now = () => real() + (++n > after ? 3000 : 0);
}
