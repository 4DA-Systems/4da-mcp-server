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

describe("the command reader", () => {
  it("an option's value is never a package", async () => {
    const r = await brief("yarn add qzws@7.4.5 --network-timeout 100000");
    expect(r.unverified_words).toEqual([{ word: "qzws", read_as: "npm", version: "7.4.5" }]);
    expect(JSON.stringify(r)).not.toMatch(/"(?:word|package)":"network-timeout"/);
  });

  it.each(["cargo add hyper --vers 0.14.9", "cargo add hyper --version 0.14.9", "cargo add hyper --vers=0.14.9"])("%s: the version of hyper", async (task) => {
    const r = await brief(task);
    expect(r.unverified_words).toEqual([{ word: "hyper", read_as: "crates.io", version: "0.14.9" }]);
  });

  it("an npm dist-tag is kept as written", async () => {
    const r = await brief("npm install qzstand@next");
    expect(r.unverified_words).toEqual([{ word: "qzstand", read_as: "npm", version: "next" }]);
  });

  it("npm install qzstand@<uuid>: the word is a credential shape: held, redacted, never listed at latest", async () => {
    const r = await brief("npm install qzstand@98e62aac-d9e2-44a1-946d-1fbf082c44aa");
    expect(r.unverified_words).toBeUndefined();
    expect(JSON.stringify(r.withheld_from_task)).toMatch(/qzst... .*credential/);
  });

  it.each(["npm install qzstand@9d962429c6eeafce", "npm install zustand@9d962429c6eeafce"])(
    "%s: listed with no version, never as latest",
    async (task) => {
      const r = await brief(task);
      const name = task.split(" ")[2].split("@")[0];
      expect(r.unverified_words).toEqual([{ word: name, read_as: "npm" }]);
      expect(JSON.stringify(r)).not.toMatch(/"to":"latest"/);
    },
  );
});
