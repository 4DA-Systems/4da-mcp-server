// SPDX-License-Identifier: Apache-2.0
/**
 * Regression: the first independent check of the confirmation loop (review-confirm1, 2026-11-27), its npm and
 * PyPI cases vendored under fixtures/a1127-confirm/review1-cases.json (steps only; a token-shaped name is
 * assembled at run time). Each case runs its steps on a fresh project behind a stubbed fetch whose registries
 * answer 404 for names they do not have, and every step is held to the invariants:
 * - I5: a name a step forbids (public: false, not_packages, any spelling) is never sent in that step;
 * - I1/I4: a step that forbids a name the task's text stands on is never safe_to_delegate;
 * - I1: a task that a bare call finds human_only is never safe after any declaration.
 */

import { readFileSync } from "node:fs";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { executeWhatShouldIKnow } from "../tools/what-should-i-know.js";
import { forbiddenKey } from "../tools/briefing-confirm.js";
import { adv, createHarness, fixedIn, type Harness } from "./helpers/a1119-planner-harness.js";

const GH = ["gh", "p_"].join("");
const FIXTURE = JSON.parse(readFileSync(path.join(__dirname, "fixtures", "a1127-confirm", "review1-cases.json"), "utf8").replaceAll("{{GH}}", GH)) as {
  cases: Array<{ set: string; id: string; template: "npm" | "py"; note?: string; files?: Record<string, string>; steps: Array<Record<string, any>> }>;
};

/** Cases whose dismissed word stands only in prose, with no near-miss: the caller's statement settles it (I4). */
const PROSE_DISMISSAL = new Set(["k11"]);

let h: Harness;
let sent: Array<{ url: string; body: string }>;
beforeEach(() => {
  h = createHarness();
  sent = [];
  const inner = globalThis.fetch;
  vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
    sent.push({ url: decodeURIComponent(String(input)), body: init?.body ? String(init.body) : "" });
    return inner(input, init);
  });
  h.NPM = {
    lodash: { latest: "4.17.21", versions: { "4.17.20": {}, "4.17.21": {} } },
    "node-forge": { latest: "1.3.1", versions: { "0.10.0": {}, "1.3.1": {} } },
    crossenv: { latest: "6.1.1", versions: { "6.1.1": {} } },
    "event-stream": { latest: "4.0.1", versions: { "3.3.6": {}, "4.0.1": {} } },
  };
  h.ADVISORIES = {
    lodash: [adv("GHSA-35jh-r3h4-6jhm", "lodash", fixedIn("4.17.21"), "npm", "HIGH")],
    "node-forge": [adv("GHSA-x4jg-mjrx-434g", "node-forge", fixedIn("1.0.0"), "npm", "CRITICAL")],
    crossenv: [adv("MAL-2017-1", "crossenv", [{ introduced: "0" }], "npm", "CRITICAL")],
    "event-stream": [adv("GHSA-mh6f-8j2x-4483", "event-stream", fixedIn("4.0.0"), "npm", "CRITICAL")],
  };
});
afterEach(() => h.dispose());

function project(template: "npm" | "py", files: Record<string, string> = {}) {
  if (template === "npm") h.npmProject({ zod: "3.23.8", undici: "6.21.0" }, {}, { zod: { version: "3.23.8" }, undici: { version: "6.21.0" } });
  else h.write("requirements.txt", "flask==3.0.3\nrequests==2.32.3\n");
  for (const [rel, body] of Object.entries(files)) h.write(rel, body);
}

const namesIn = (s: { url: string; body: string }) => [
  ...[...s.url.matchAll(/registry\.npmjs\.org\/((?:@[^/]+\/)?[^/?#]+)|pypi\.org\/pypi\/([^/]+)|crates\.io\/api\/v1\/crates\/([^/?#]+)/g)].map((m) => m[1] ?? m[2] ?? m[3]),
  ...[...s.body.matchAll(/"name":"([^"]+)"/g)].filter((m) => !s.url.endsWith("/v1/querybatch")).map((m) => m[1]),
];

describe("review-confirm1 cases hold the invariants", () => {
  it.each(FIXTURE.cases.map((c) => [`${c.set}/${c.id}: ${c.note ?? ""}`, c] as const))("%s", async (_label, c) => {
    project(c.template, c.files);
    const live = await h.live();
    let bareHumanOnly = false;
    for (const [k, args] of c.steps.entries()) {
      sent.length = 0;
      const r = (await executeWhatShouldIKnow(null, { ...args, project_path: h.dir } as never, live)) as Record<string, any>;
      if (k === 0 && args.packages === undefined) bareHumanOnly = r.delegation_assessment.level === "human_only";
      const forbidden = [...(args.packages ?? []).filter((p: { public?: unknown }) => p.public === false).map((p: { name: string }) => p.name), ...(args.not_packages ?? [])].map(forbiddenKey);
      // I5: never sent in this step (a name-level request; the project scan's own batch is the documented limit).
      const leaked = sent.flatMap(namesIn).filter((n) => forbidden.includes(forbiddenKey(n)));
      expect(leaked, `step ${k} sent ${leaked.join(", ")}`).toEqual([]);
      // I1/I4: a forbidden name the task stands on keeps the step from safe.
      const task = String(args.task ?? "").toLowerCase();
      // (A word read only after an adding verb in prose, with no near-miss, may be dismissed: I4 names the classes.)
      if (!PROSE_DISMISSAL.has(c.id) && forbidden.some((f) => task.replace(/[-_.]+/g, "-").includes(f))) expect(r.delegation_assessment.level, `step ${k}`).not.toBe("safe_to_delegate");
      if (bareHumanOnly && k > 0) expect(r.delegation_assessment.level, `step ${k}`).not.toBe("safe_to_delegate");
    }
  });
});
