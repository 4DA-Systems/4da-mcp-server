// SPDX-License-Identifier: Apache-2.0

const DEFAULT_TIMEOUT_MS = 10_000;

export async function fetchWithTimeout(
  url: string,
  options: RequestInit = {},
  timeoutMs: number = DEFAULT_TIMEOUT_MS,
): Promise<Response> {
  const controller = new AbortController();
  let timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, { ...options, signal: controller.signal });
    // The headers are in; the body is not read yet. Clearing the abort here left json(), text()
    // and arrayBuffer() with no deadline: a server that stalled mid-body hung vulnerability_scan
    // and dependency_check, and every later scan that joined the stuck one (audit 6.2.5 B-6).
    // The abort stays armed for the body, with its own allowance; unref'd, it never holds the
    // process open, and aborting a body already read does nothing.
    clearTimeout(timeout);
    timeout = setTimeout(() => controller.abort(), timeoutMs);
    timeout.unref?.();
    return response;
  } catch (error) {
    clearTimeout(timeout);
    throw error;
  }
}

export async function fetchJson<T>(
  url: string,
  options: RequestInit = {},
  timeoutMs: number = DEFAULT_TIMEOUT_MS,
): Promise<T> {
  const response = await fetchWithTimeout(url, options, timeoutMs);
  if (!response.ok) {
    throw new Error(`HTTP ${response.status}: ${url}`);
  }
  return (await response.json()) as T;
}
