// SPDX-License-Identifier: Apache-2.0
/**
 * Live Intelligence Singleton
 *
 * Separated from index.ts to avoid circular dependency with tool-dispatch.ts.
 */

import type { LiveIntelligence } from "./live/index.js";
import { registerPrivateNames, unregisterPrivateNames } from "./live/private-guard.js";

let instance: LiveIntelligence | null = null;

/** The server's live layer; its private rules are held strongly by the HTTP guard (private-guard.ts) while it is current. */
export function setLiveIntelligence(li: LiveIntelligence): void {
  if (instance && instance !== li) unregisterPrivateNames(instance);
  instance = li;
  registerPrivateNames(li, "server");
}

/** No server live layer (tests that set one restore the state they found). */
export function clearLiveIntelligence(): void {
  if (instance) unregisterPrivateNames(instance);
  instance = null;
}

export function getLiveIntelligence(): LiveIntelligence | null {
  return instance;
}
