// SPDX-License-Identifier: Apache-2.0
/**
 * A range is let through by an answer for that range, not by any answer for the package.
 *
 * The 6.5.1 candidate let a range or constraint through once the ledger held any verdict for the
 * package (blind review 2026-11-24, item 4): with `avoid` for lodash 4.17.20, `npm i
 * 'lodash@<=4.17.20'` went ahead, and with `proceed` for 4.17.21, `'lodash@<4.17.21'` and
 * `'lodash@4.17.20 - 4.17.20'`. The rule now (README, guard hook): a range goes ahead on a
 * proceed or review answered for that same constraint, or on a proceed or review for exactly the
 * version its inclusive ceiling names (`<=V`, `A - V`), the release a resolver picks from it; an
 * avoid or wait for either holds it.
 *
 * PyPI `==2.0.0+cpu` and `==5.0.0-rc1` are exact pins (PEP 440 local label, a spelled-out
 * pre-release), `==3.2.*` is a range; a range written with a space after `@` is read trimmed.
 */

import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { installsIn, respond } from "../../hooks/manifest-edit.mjs";
import { LEDGER_FILE, type LedgerEntry } from "../check-ledger.js";

let home: string;
beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "a651-hook-ranges-"));
});
afterEach(() => rmSync(home, { recursive: true, force: true }));

const NOW = Date.parse("2026-11-24T12:00:00Z");
function ledger(entries: Array<Partial<LedgerEntry> & { package: string; version: string; verdict: string }>) {
  const t = new Date(NOW - 60_000).toISOString();
  writeFileSync(join(home, LEDGER_FILE), entries.map((e) => JSON.stringify({ sv: "6.6.0", t, ecosystem: "npm", ...e })).join("\n") + "\n");
}
function decide(command: string): "allow" | "deny" {
  const out = respond({ hook_event_name: "PreToolUse", tool_name: "Bash", cwd: home, tool_input: { command } }, { FOURDA_MCP_HOME: home }, NOW);
  return out === "" ? "allow" : "deny";
}

describe("a range needs an answer that covers it", () => {
  it("an avoid for 4.17.20 does not let `<=4.17.20` through", () => {
    ledger([{ package: "lodash", version: "4.17.20", verdict: "avoid", reason: "GHSA-35jh-r3h4-6jhm" }]);
    expect(decide("npm i 'lodash@<=4.17.20'")).toBe("deny");
  });

  it("a proceed for 4.17.21 does not let `<4.17.21` or `4.17.20 - 4.17.20` through", () => {
    ledger([{ package: "lodash", version: "4.17.21", verdict: "proceed" }]);
    expect(decide("npm i 'lodash@<4.17.21'")).toBe("deny");
    expect(decide("npm i 'lodash@4.17.20 - 4.17.20'")).toBe("deny");
    expect(decide("npm i 'lodash@^4.17.0'")).toBe("deny");
  });

  it("an answer for another constraint does not cover this one", () => {
    ledger([{ package: "lodash", version: "4.18.1", verdict: "proceed", requested: "^4.18.0" }]);
    expect(decide("npm i 'lodash@^4.17.0'")).toBe("deny");
  });

  it("a proceed or review for the same constraint lets it through; an avoid or wait for it holds", () => {
    ledger([{ package: "lodash", version: "4.18.1", verdict: "proceed", requested: "^4.17.0" }]);
    expect(decide("npm i 'lodash@^4.17.0'")).toBe("allow");
    ledger([{ package: "lodash", version: "4.18.1", verdict: "review", requested: "^4.17.0" }]);
    expect(decide("npm i 'lodash@^4.17.0'")).toBe("allow");
    ledger([{ package: "lodash", version: "4.17.20", verdict: "avoid", requested: "^4.17.0" }]);
    expect(decide("npm i 'lodash@^4.17.0'")).toBe("deny");
  });

  it("a proceed for exactly the inclusive ceiling lets `<=V` and `A - V` through; an avoid for it holds them", () => {
    ledger([{ package: "lodash", version: "4.17.21", verdict: "proceed" }]);
    expect(decide("npm i 'lodash@<=4.17.21'")).toBe("allow");
    expect(decide("npm i 'lodash@>=4.17.0 <=4.17.21'")).toBe("allow");
    expect(decide("npm i 'lodash@4.17.0 - 4.17.21'")).toBe("allow");
    expect(decide("npm i 'lodash@<=4.17.21 || 5.0.0'")).toBe("deny");
    ledger([{ package: "lodash", version: "4.17.20", verdict: "avoid" }]);
    expect(decide("npm i 'lodash@<=4.17.20'")).toBe("deny");
  });

  it("PyPI: the ceiling of `<=V`, and `==3.2.*` is a range", () => {
    ledger([{ ecosystem: "PyPI", package: "django", version: "3.2.25", verdict: "proceed" }]);
    expect(decide("pip install 'django>=3.2,<=3.2.25'")).toBe("allow");
    expect(decide("pip install 'django==3.2.*'")).toBe("deny");
  });

  it("a clause that can exclude the ceiling (`!=`) leaves the range needing its own answer (re-check of 0d30b40, S3)", () => {
    ledger([
      { ecosystem: "PyPI", package: "requests", version: "2.0.0", verdict: "proceed" },
      { ecosystem: "PyPI", package: "requests", version: "1.9.0", verdict: "avoid" },
    ]);
    expect(decide("pip install 'requests<=2.0.0,!=2.0.0'")).toBe("deny");
    expect(decide("pip install 'requests<=2.0,!=2.0.0'")).toBe("deny");
    expect(decide("pip install 'requests>=1.0,!=1.5.0,<=2.0.0'")).toBe("deny");
    expect(decide("pip install 'requests>=1.0,<=2.0.0'")).toBe("allow");
  });

  it("an unknown answer for the same constraint is no answer", () => {
    ledger([{ package: "lodash", version: "^4.17.0", verdict: "unknown", reason: "NOT CHECKED (time budget)" }]);
    expect(decide("npm i 'lodash@^4.17.0'")).toBe("deny");
  });

  it("a range written with a space after `@` is read trimmed, and an avoid for it holds", () => {
    expect(installsIn("npm i 'lodash@ ^4.17.0'", "bash")).toEqual([{ ecosystem: "npm", name: "lodash", spec: "^4.17.0" }]);
    ledger([{ package: "lodash", version: "4.17.20", verdict: "avoid", requested: "^4.17.0" }]);
    expect(decide("npm i 'lodash@ ^4.17.0'")).toBe("deny");
  });
});

describe("PyPI exact pins", () => {
  it("`==2.0.0+cpu` is that local release: a verdict for another version does not cover it, one for it does", () => {
    ledger([{ ecosystem: "PyPI", package: "torch", version: "2.1.0", verdict: "proceed" }]);
    expect(decide("pip install torch==2.0.0+cpu")).toBe("deny");
    ledger([{ ecosystem: "PyPI", package: "torch", version: "2.0.0+cpu", verdict: "proceed" }]);
    expect(decide("pip install torch==2.0.0+cpu")).toBe("allow");
  });

  it("`==5.0.0-rc1` is the release 5.0rc1, not 5.0", () => {
    ledger([{ ecosystem: "PyPI", package: "django", version: "5.0", verdict: "proceed" }]);
    expect(decide("pip install django==5.0.0-rc1")).toBe("deny");
    ledger([{ ecosystem: "PyPI", package: "django", version: "5.0rc1", verdict: "proceed" }]);
    expect(decide("pip install django==5.0.0-rc1")).toBe("allow");
  });
});
