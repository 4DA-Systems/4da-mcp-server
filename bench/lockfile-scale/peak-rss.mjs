// SPDX-License-Identifier: Apache-2.0
/** Preload for run.mjs: reports the process's peak resident set size on stderr whenever it grows. */
let last = 0;
const report = () => {
  const peak = process.resourceUsage().maxRSS; // KiB
  if (peak > last) {
    last = peak;
    process.stderr.write(`PEAKRSS ${peak}\n`);
  }
};
setInterval(report, 100).unref();
process.on("exit", report);
