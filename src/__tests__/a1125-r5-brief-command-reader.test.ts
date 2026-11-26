// SPDX-License-Identifier: Apache-2.0
/**
 * Third blind check of the 2026-11-25 fixes, item 5: details of the command reader. An option's value is
 * no package (`--network-timeout 100000`), Cargo's `--vers` / `--version` name the version of the crate
 * before them, an npm dist-tag is kept as written (`zustand@next`), and a version that is no version,
 * range or tag (`zustand@<uuid>`) is never replaced by latest: the item is listed with no `to`, and the
 * note says why. Stubbed fetch: nothing leaves the machine.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { executeWhatShouldIKnow } from "../tools/what-should-i-know.js";
import { createHarness, type Harness } from "./helpers/a1119-planner-harness.js";
import { waitingWords, notReadWords } from "./helpers/a1127-task-packages.js";

let h: Harness;
beforeEach(() => {
  h = createHarness();
  h.npmProject({ minimist: "1.2.5" }, {}, { minimist: { version: "1.2.5" } });
  h.write("Cargo.toml", '[package]\nname = "p"\nversion = "0.1.0"\n\n[dependencies]\nserde = "1.0.190"\n');
});
afterEach(() => h.dispose());

async function brief(task: string): Promise<Record<string, any>> {
  return (await executeWhatShouldIKnow(null, { task, project_path: h.dir }, await h.live())) as Record<string, any>;
}

// Round 7 (C1/C2): commands are read by the canonical grammar. A command with an option not on its manager's list
// (`--network-timeout`, Cargo's `--vers`), or an operand that is no plain name with a readable spec (a dist-tag, a
// hash, a UUID) is NOT READ WHOLE: nothing of it is offered or repeated, and the level is at most review_needed.
describe("the command reader", () => {
  it.each(["yarn add qzws@7.4.5 --network-timeout 100000", "cargo add hyper --vers 0.14.9", "cargo add hyper --version 0.14.9", "cargo add hyper --vers=0.14.9", "npm install qzstand@next"])(
    "%s: not read whole, nothing offered, never safe",
    async (task) => {
      const r = await brief(task);
      expect(waitingWords(r)).toBeUndefined();
      expect(JSON.stringify(r)).not.toMatch(/"(?:word|package|name)":"network-timeout"/);
      expect(r.delegation_assessment.level).not.toBe("safe_to_delegate");
      expect(r.delegation_assessment.reason).toMatch(/could not read whole/);
    },
  );

  it("npm install qzstand@<uuid>: the word is a credential shape: held, redacted, never listed at latest", async () => {
    const r = await brief("npm install qzstand@98e62aac-d9e2-44a1-946d-1fbf082c44aa");
    expect(waitingWords(r)).toBeUndefined();
    expect(JSON.stringify(notReadWords(r))).toMatch(/qzst... .*credential/);
  });

  it.each(["npm install qzstand@9d962429c6eeafce", "npm install zustand@9d962429c6eeafce"])("%s: never listed, never as latest", async (task) => {
    const r = await brief(task);
    expect(JSON.stringify(waitingWords(r) ?? [])).not.toContain("9d962429c6eeafce");
    expect(JSON.stringify(r)).not.toMatch(/"to":"latest"/);
    expect(r.delegation_assessment.level).not.toBe("safe_to_delegate");
  });
});
