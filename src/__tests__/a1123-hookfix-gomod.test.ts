// SPDX-License-Identifier: Apache-2.0
/**
 * go.mod: `exclude` and `retract`, one-line and block form, keep versions out; they never count as
 * versions being introduced. The block form was read as a requirement, so excluding a version
 * dependency_check had answered avoid for was denied with "Write a version it answers proceed for".
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { sandbox, type Sandbox } from "./helpers/a1123-hookfix-run.js";

const GOMOD = "module example.com/demo\n\ngo 1.22\n\nrequire (\n\tgithub.com/google/uuid v1.6.0\n\tgolang.org/x/text v0.19.0 // indirect\n)\n";

let s: Sandbox;
beforeEach(() => {
  s = sandbox();
});
afterEach(() => s.dispose());

describe("exclude and retract introduce no version", () => {
  it.each([
    ["exclude, one line", "exclude golang.org/x/net v0.17.0\n"],
    ["exclude block", "exclude (\n\tgolang.org/x/net v0.17.0\n\tgolang.org/x/net v0.18.0\n)\n"],
    ["exclude block with a comment", "exclude ( // known bad\n\tgolang.org/x/net v0.17.0 // GO-2024-3333\n)\n"],
    ["retract, one line", "retract v1.0.1\n"],
    ["retract, a range", "retract [v1.0.0, v1.0.5] // broken release\n"],
    ["retract block", "retract (\n\tv1.0.1\n\t[v1.1.0, v1.1.3]\n)\n"],
  ])("%s, with an empty ledger", (_label, directive) => {
    const file = s.file("go.mod", GOMOD);
    const run = s.edit(file, "go 1.22\n", `go 1.22\n\n${directive}`);
    expect(run.decision, run.text).toBe("allow");
  });

  it("excluding a version dependency_check answered avoid for goes ahead", () => {
    s.ledger([{ ecosystem: "Go", package: "golang.org/x/net", version: "v0.17.0", verdict: "avoid", reason: "advisories" }]);
    const file = s.file("go.mod", GOMOD);
    expect(s.edit(file, "go 1.22\n", "go 1.22\n\nexclude (\n\tgolang.org/x/net v0.17.0\n)\n").decision).toBe("allow");
    expect(s.edit(file, "go 1.22\n", "go 1.22\n\nexclude golang.org/x/net v0.17.0\n").decision).toBe("allow");
  });

  it("a line added inside an exclude block on disk is not a requirement", () => {
    const file = s.file("go.mod", GOMOD + "\nexclude (\n\tgolang.org/x/net v0.17.0\n)\n");
    expect(s.edit(file, "\tgolang.org/x/net v0.17.0\n", "\tgolang.org/x/net v0.17.0\n\tgolang.org/x/net v0.18.0\n").decision).toBe("allow");
  });

  it("after the edit (FOURDA_GUARD=advise), a snippet inside an exclude block says nothing", () => {
    const after = GOMOD + "\nexclude (\n\tgolang.org/x/net v0.17.0\n\tgolang.org/x/net v0.18.0\n)\n";
    const file = s.file("go.mod", after);
    expect(s.post(file, "\tgolang.org/x/net v0.17.0\n", "\tgolang.org/x/net v0.17.0\n\tgolang.org/x/net v0.18.0\n").decision).toBe("allow");
  });
});

describe("requirements are still held", () => {
  it("a require after an exclude block, and one in the same edit", () => {
    const file = s.file("go.mod", GOMOD);
    const run = s.edit(file, "go 1.22\n", "go 1.22\n\nexclude (\n\tgolang.org/x/net v0.17.0\n)\n\nrequire github.com/pkg/errors v0.9.1\n");
    expect(run.items).toEqual([{ ecosystem: "Go", package: "github.com/pkg/errors", to: "v0.9.1" }]);
  });

  it("a require block line and a bump", () => {
    const file = s.file("go.mod", GOMOD);
    expect(s.edit(file, "\tgithub.com/google/uuid v1.6.0\n", "\tgithub.com/google/uuid v1.6.0\n\tgithub.com/pkg/errors v0.9.1\n").items).toEqual([{ ecosystem: "Go", package: "github.com/pkg/errors", to: "v0.9.1" }]);
    expect(s.edit(file, "golang.org/x/text v0.19.0", "golang.org/x/text v0.20.0").items).toEqual([{ ecosystem: "Go", package: "golang.org/x/text", to: "v0.20.0", from: "v0.19.0" }]);
  });
});
