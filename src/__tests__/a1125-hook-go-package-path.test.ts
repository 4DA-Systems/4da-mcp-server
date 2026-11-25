// SPDX-License-Identifier: Apache-2.0
/**
 * `go get <module>/<package>@<version>` (`golang.org/x/net/http2@v0.23.0`) names a package, not a
 * module. The hook took the whole path as the module and named a dependency_check call for it; the
 * server reads modules and answers unknown for a package path, so the command could never pass
 * (audit 2026-11-25, D-M3, seen in a live session). The hook cannot know module boundaries offline,
 * so it does not guess: a recorded proceed or review verdict for a path PREFIX of the package path,
 * at the same version, releases it (the module that contains the package was checked), and the
 * denial says so, with an example call for the likely module.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { sandbox, type Sandbox } from "./helpers/a1123-hookfix-run.js";
import { record, timedWithin } from "./helpers/a1125-hook-run.js";

let s: Sandbox;
beforeEach(() => {
  s = sandbox();
});
afterEach(() => s.dispose());

const bash = (command: string) => ({ session_id: "s", cwd: s.project, hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command } });
const UNKNOWN = (pkg: string, version: string) => ({ ecosystem: "Go", package: pkg, version, verdict: "unknown", reason: `"${pkg}" is not a module the Go proxy can resolve.` });

/** Every dependency_check call a denial names, in order. */
function calls(text: string): Array<Array<Record<string, string>>> {
  return [...text.matchAll(/dependency_check (\{"items":.*?\]\})/g)].map((m) => (JSON.parse(m[1]) as { items: Array<Record<string, string>> }).items);
}

describe("a package path is released by the verdict for the module that contains it", () => {
  it.each([
    ["golang.org/x/net/http2", "v0.23.0", "golang.org/x/net"],
    ["github.com/stretchr/testify/assert", "v1.9.0", "github.com/stretchr/testify"],
    ["github.com/jackc/pgx/v5/pgxpool", "v5.5.4", "github.com/jackc/pgx/v5"],
    ["go.uber.org/zap/zapcore", "v1.27.0", "go.uber.org/zap"],
    ["golang.org/x/text/language", "v0.14.0", "golang.org/x/text"],
  ])("%s@%s: the denial's module call, answered proceed, releases it", (path, version, module) => {
    s.ledger([]);
    const command = `go get ${path}@${version}`;
    const first = s.run(bash(command));
    expect(first.decision, first.text).toBe("deny");
    // The call for the path as written still comes first, and the module call is offered beside it.
    const named = calls(first.text);
    expect(named[0]).toEqual([{ ecosystem: "Go", package: path, to: version }]);
    expect(named[1]).toEqual([{ ecosystem: "Go", package: module, to: version }]);
    expect(first.text).toContain("check the module that contains this package");
    // The path as written answers unknown, as the server answers for a package path; then the module call is made.
    record(s, [UNKNOWN(path, version)]);
    const second = s.run(bash(command));
    expect(second.decision).toBe("deny");
    expect(calls(second.text)[1]).toEqual([{ ecosystem: "Go", package: module, to: version }]);
    record(s, [{ ecosystem: "Go", package: module, version, verdict: "proceed" }]);
    expect(s.run(bash(command)).decision).toBe("allow");
  });

  it("review for the module releases it; avoid for the module holds it with that reason", () => {
    s.ledger([{ ecosystem: "Go", package: "golang.org/x/net", version: "v0.23.0", verdict: "review", reason: "new release" }]);
    expect(s.run(bash("go get golang.org/x/net/http2@v0.23.0")).decision).toBe("allow");
    s.ledger([{ ecosystem: "Go", package: "golang.org/x/net", version: "v0.17.0", verdict: "avoid", reason: "GO-2023-2102" }]);
    const held = s.run(bash("go get golang.org/x/net/http2@v0.17.0"));
    expect(held.decision).toBe("deny");
    expect(held.text).toContain("answered avoid");
    expect(held.text).toContain("GO-2023-2102");
  });

  it("the innermost module decides: an avoid for a nested module outranks a proceed for its parent", () => {
    s.ledger([
      { ecosystem: "Go", package: "cloud.google.com/go", version: "v1.30.0", verdict: "proceed" },
      { ecosystem: "Go", package: "cloud.google.com/go/storage", version: "v1.30.0", verdict: "avoid", reason: "advisory" },
    ]);
    expect(s.run(bash("go get cloud.google.com/go/storage/internal@v1.30.0")).decision).toBe("deny");
  });

  it("the path's own verdict comes first: an avoid for the path as written is not released by its module", () => {
    s.ledger([
      { ecosystem: "Go", package: "golang.org/x/net", version: "v0.23.0", verdict: "proceed" },
      { ecosystem: "Go", package: "golang.org/x/net/http2", version: "v0.23.0", verdict: "avoid", reason: "x" },
    ]);
    expect(s.run(bash("go get golang.org/x/net/http2@v0.23.0")).decision).toBe("deny");
  });

  it("nothing is released without a verdict at that version: another version, another module, a longer path", () => {
    s.ledger([
      { ecosystem: "Go", package: "golang.org/x/net", version: "v0.22.0", verdict: "proceed" },
      { ecosystem: "Go", package: "golang.org/x/text", version: "v0.23.0", verdict: "proceed" },
      { ecosystem: "Go", package: "golang.org/x/net/http2/h2c", version: "v0.23.0", verdict: "proceed" },
      UNKNOWN("golang.org/x/net/http2", "v0.23.0"),
    ]);
    expect(s.run(bash("go get golang.org/x/net/http2@v0.23.0")).decision).toBe("deny");
    expect(s.run(bash("go get golang.org/x/netx/http2@v0.23.0")).decision).toBe("deny");
  });

  it("a module path itself is unchanged: its own verdict decides, and the denial offers no module call", () => {
    s.ledger([]);
    const run = s.run(bash("go get github.com/google/uuid@v1.6.0"));
    expect(run.decision).toBe("deny");
    expect(calls(run.text)).toEqual([[{ ecosystem: "Go", package: "github.com/google/uuid", to: "v1.6.0" }]]);
    expect(run.text).not.toContain("check the module that contains this package");
  });

  it("other ecosystems are not read by prefix", () => {
    s.ledger([{ ecosystem: "npm", package: "@scope", version: "1.0.0", verdict: "proceed" }]);
    expect(s.run(bash("npm i @scope/pkg@1.0.0")).decision).toBe("deny");
  });

  it("go.mod edits that change no version are not held, with a package-path verdict on record", () => {
    s.ledger([{ ecosystem: "Go", package: "golang.org/x/net", version: "v0.17.0", verdict: "avoid", reason: "x" }]);
    const text = "module example.com/demo\r\n\r\ngo 1.22\r\n\r\nrequire golang.org/x/net v0.17.0\r\n";
    const file = s.file("go.mod", text);
    expect(s.write(file, text).decision).toBe("allow");
    expect(s.edit(file, "go 1.22", "go 1.23").decision).toBe("allow");
  });

  it("a ledger of 1,000 entries for many modules, and 25 package paths, inside the CPU bound", () => {
    const entries = Array.from({ length: 1000 }, (_, i) => ({ ecosystem: "Go", package: `github.com/org${i}/mod${i}`, version: `v1.0.${i}`, verdict: "proceed" }));
    s.ledger(entries);
    const paths = Array.from({ length: 25 }, (_, i) => `github.com/org${i}/mod${i}/a/b/c/d/e/f/g/h/pkg@v1.0.${i}`).join(" ");
    const run = timedWithin(s.home, bash(`go get ${paths}`), 500);
    expect(run.decision, run.text).toBe("allow");
  });
});
