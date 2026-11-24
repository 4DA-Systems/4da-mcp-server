// SPDX-License-Identifier: Apache-2.0
/**
 * tomlSyntaxProblem never rejects valid TOML. A false UNREADABLE on a healthy project is as bad as a
 * false clean. Re-check of 0d30b40 (2026-11-24, unit/toml.mjs, p-stale3.mjs): a basic multi-line
 * string closed by four or five quotes (`"""He said "hi""""`) and an escaped quote `\"""` inside one
 * were called "not closed", so a clean Cargo project read "NOT CHECKED: UNREADABLE". The reviewer's
 * 45 valid shapes (test-fixtures/toml-valid-shapes.json: real manifests, TOML 1.0 edge cases and a
 * TOML 1.1 multi-line inline table) must all pass; doubtful input is accepted, not rejected.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { tomlSyntaxProblem } from "../live/lockfile-parsers.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const shapes = JSON.parse(fs.readFileSync(path.join(here, "..", "..", "test-fixtures", "toml-valid-shapes.json"), "utf8")) as Record<string, string>;

describe("tomlSyntaxProblem accepts valid TOML", () => {
  it("has the 45 shapes", () => {
    expect(Object.keys(shapes).length).toBe(45);
  });
  it.each(Object.entries(shapes))("%s", (_name, text) => {
    expect(tomlSyntaxProblem(text)).toBeNull();
  });
  it("closing runs of four and five quotes, and escaped quotes", () => {
    expect(tomlSyntaxProblem('[package]\nname = "x"\ndescription = """He said "hi""""\n')).toBeNull();
    expect(tomlSyntaxProblem('[package]\nname = "x"\ndescription = """\nline\n""""" \n')).toBeNull();
    expect(tomlSyntaxProblem('[package]\nname = "x"\ndescription = """a \\""" b"""\n')).toBeNull();
    expect(tomlSyntaxProblem("[package]\nname = 'x'\ndescription = '''it''s'''''\n")).toBeNull();
  });
  it("still finds what a hand edit breaks", () => {
    expect(tomlSyntaxProblem('[package\nname = "x"\n')).not.toBeNull();
    expect(tomlSyntaxProblem('[package]\nname = "x"\nauthors = ["a",\n')).not.toBeNull();
    expect(tomlSyntaxProblem('[package]\ndescription = """\nnever closed\n')).not.toBeNull();
  });
});
