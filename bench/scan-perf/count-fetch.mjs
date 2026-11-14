// SPDX-License-Identifier: Apache-2.0
// Preload for bench/scan-perf/run.mjs: logs every outbound fetch to stderr as `FETCH <method> <url>`
// (with the start of a POST body when SCAN_PERF_BODIES is set).
const real = globalThis.fetch;
globalThis.fetch = (input, init) => {
  const url = typeof input === "string" ? input : input?.url ?? String(input);
  const body = process.env.SCAN_PERF_BODIES && typeof init?.body === "string" ? ` ${init.body.slice(0, 300).replace(/\s+/g, " ")}` : "";
  process.stderr.write(`FETCH ${init?.method ?? "GET"} ${url}${body}\n`);
  return real(input, init);
};
