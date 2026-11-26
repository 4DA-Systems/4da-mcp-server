// SPDX-License-Identifier: Apache-2.0
/**
 * Round 7, C8 (check 5, M3): a task holding "constructor", "__proto__", "toString" or "hasOwnProperty" threw
 * "function is not iterable": recall's alias table was read as a plain object keyed by task words, so those
 * words found Object.prototype members (also in 6.5.1). Lookups keyed by task text use own properties only.
 */
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { FourDADatabase } from "../db.js";
import { recallTerms } from "../tools/recall.js";
import { executeWhatShouldIKnow } from "../tools/what-should-i-know.js";
import { executeDecisionMemory } from "../tools/decision-memory.js";
import { executeCheckDecisionAlignment } from "../tools/decision-enforcement.js";

let dir: string;
let db: FourDADatabase;
beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), "4da-a1130-c8-"));
  db = new FourDADatabase(path.join(dir, "standalone.db"));
});
afterEach(() => {
  db.close();
  fs.rmSync(dir, { recursive: true, force: true });
});

const WORDS = ["constructor", "__proto__", "toString", "hasOwnProperty", "valueOf", "prototype"];

describe("C8: task words that name Object.prototype members", () => {
  it.each(WORDS)("recallTerms(%s) does not throw", (w) => {
    expect(() => recallTerms(`refactor the ${w} of the parser`)).not.toThrow();
  });

  it("what_should_i_know with a stored decision and every such word answers", async () => {
    await executeDecisionMemory(db, { action: "record", subject: "Parser", decision: "Keep the parser class small", rationale: "test" } as never);
    process.env.FOURDA_OFFLINE = "true";
    try {
      const r = (await executeWhatShouldIKnow(db, { task: `move logic out of the constructor; avoid __proto__, toString, hasOwnProperty and npm install constructor`, packages: [] } as never, null)) as Record<string, any>;
      expect(r.delegation_assessment.level).toBeTypeOf("string");
    } finally {
      delete process.env.FOURDA_OFFLINE;
    }
  });

  it("check_decision_alignment with such a word answers", async () => {
    await executeDecisionMemory(db, { action: "record", subject: "Parser", decision: "Keep the parser class small", rationale: "test" } as never);
    const r = (await executeCheckDecisionAlignment(db, { technology: "constructor", pattern: "__proto__ toString" }, { lexicalOnly: true })) as unknown as Record<string, unknown>;
    expect(r).toHaveProperty("aligned");
  });
});
