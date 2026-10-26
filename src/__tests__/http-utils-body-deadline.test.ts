// SPDX-License-Identifier: Apache-2.0
/**
 * fetchWithTimeout cleared its abort once the headers arrived, so a body that
 * stalled mid-stream had no deadline: vulnerability_scan and dependency_check
 * never answered (150 s and counting), and later scans joined the stuck one
 * until force_refresh. Audit 6.2.5 finding B-6.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { fetchWithTimeout } from "../live/http-utils.js";

/** Headers at once, then a body that sends one chunk and never ends (until aborted). */
function stallingFetch() {
  return async (_url: string | URL, init?: RequestInit) => {
    const signal = init?.signal;
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new TextEncoder().encode('{"results":['));
        signal?.addEventListener("abort", () => controller.error(new DOMException("aborted", "AbortError")));
      },
    });
    return new Response(body, { status: 200, headers: { "content-type": "application/json" } });
  };
}

afterEach(() => vi.unstubAllGlobals());

describe("fetchWithTimeout", () => {
  it("a body that stalls after the headers is aborted, not awaited forever", async () => {
    vi.stubGlobal("fetch", stallingFetch());
    const started = Date.now();
    const response = await fetchWithTimeout("https://api.osv.dev/v1/querybatch", {}, 100);
    await expect(response.json()).rejects.toThrow();
    expect(Date.now() - started).toBeLessThan(2_000);
  });

  it("a body that arrives in time is read normally", async () => {
    vi.stubGlobal("fetch", async () => new Response('{"ok":true}', { status: 200 }));
    const response = await fetchWithTimeout("https://example.test/", {}, 100);
    expect(await response.json()).toEqual({ ok: true });
  });
});
