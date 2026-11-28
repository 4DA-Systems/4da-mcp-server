// SPDX-License-Identifier: Apache-2.0
/**
 * `go get <module>/<package>@<version>` (`golang.org/x/net/http2@v0.23.0`) names a package, not a
 * module; dependency_check reads modules and answers unknown for it, so the command could never
 * pass, and the denial pointed at no way through (audit 2026-11-25, D-M3). The hook cannot know
 * where a module ends, and a verdict for one module must never release a longer path: a nested
 * module starts with its parent's path (go.opentelemetry.io/otel/sdk, golang.org/x/tools/gopls,
 * aws-sdk-go-v2/service/s3), so releasing by prefix let unchecked modules through (blind check of
 * this lane). The denial now says the way through: check the module that contains the package and
 * name that module in the command, which the exact-path rule releases.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { sandbox, type Sandbox } from "./helpers/a1123-hookfix-run.js";
import { record } from "./helpers/a1125-hook-run.js";

let s: Sandbox;
beforeEach(() => {
  s = sandbox();
});
afterEach(() => s.dispose());

const bash = (command: string, tool = "Bash") => ({ session_id: "s", cwd: s.project, hook_event_name: "PreToolUse", tool_name: tool, tool_input: { command } });
const G = (pkg: string, version: string, verdict: string, extra: Record<string, string> = {}) => ({ ecosystem: "Go", package: pkg, version, verdict, ...extra });

describe("a verdict for one module never releases a longer path", () => {
  it.each([
    ["go get go.opentelemetry.io/otel/sdk@v1.30.0", G("go.opentelemetry.io/otel", "v1.30.0", "review")],
    ["go get go.opentelemetry.io/otel@v1.30.0 go.opentelemetry.io/otel/sdk@v1.30.0", G("go.opentelemetry.io/otel", "v1.30.0", "review")],
    ["go mod edit -require=go.opentelemetry.io/otel/sdk@v1.30.0", G("go.opentelemetry.io/otel", "v1.30.0", "review")],
    ["go work edit -replace=example.com/x=go.opentelemetry.io/otel/sdk@v1.30.0", G("go.opentelemetry.io/otel", "v1.30.0", "review")],
    ["go get github.com/go-chi/chi/v5@v5.0.12", G("github.com/go-chi/chi", "v5.0.12", "proceed")],
    ["go get golang.org/x/tools/gopls@v0.20.0", G("golang.org/x/tools", "v0.20.0", "proceed")],
    ["go get github.com/aws/aws-sdk-go-v2/service/s3@v1.30.0", G("github.com/aws/aws-sdk-go-v2", "v1.30.0", "proceed")],
    ["go get golang.org/x/net/http2@v0.23.0", G("golang.org/x/net", "v0.23.0", "proceed")],
    ["go get golang.org/x/net/http2@v0", G("golang.org/x/net", "v0.31.0", "proceed", { requested: "v0" })],
  ])("%s: held", (command, entry) => {
    s.ledger([entry]);
    expect(s.run(bash(command)).decision).toBe("deny");
    expect(s.run(bash(command, "PowerShell")).decision).toBe("deny");
  });
});

describe("the way through: the denial's own call (round 22, F3)", () => {
  it("a package path is held with the call for the path; the server's answer for it (the module judged in its place) releases it", () => {
    s.ledger([]);
    const pkg = "go get golang.org/x/net/http2@v0.23.0";
    const first = s.run(bash(pkg));
    expect(first.decision).toBe("deny");
    expect(first.items).toEqual([{ ecosystem: "Go", package: "golang.org/x/net/http2", to: "v0.23.0" }]);
    // The answer dependency_check records since round 22 (F3): the path, with the module that contains it.
    record(s, [G("golang.org/x/net/http2", "v0.23.0", "proceed", { go_module: "golang.org/x/net" })]);
    expect(s.run(bash(pkg)).decision).toBe("allow");
    // A verdict for the module alone still releases only the module (a nested module starts with its path).
    s.ledger([G("golang.org/x/net", "v0.23.0", "proceed")]);
    expect(s.run(bash(pkg)).decision).toBe("deny");
    expect(s.run(bash("go get golang.org/x/net@v0.23.0")).decision).toBe("allow");
  });

  it("a module the server answers avoid for stays held when named", () => {
    s.ledger([G("go.opentelemetry.io/otel/sdk", "v1.30.0", "avoid", { reason: "2 high advisories" })]);
    const run = s.run(bash("go get go.opentelemetry.io/otel/sdk@v1.30.0"));
    expect(run.decision).toBe("deny");
    expect(run.text).toContain("answered avoid");
  });

  it("go.mod edits keep their wording: a require names a module", () => {
    s.ledger([]);
    const file = s.file("go.mod", "module example.com/demo\n\ngo 1.22\n");
    const run = s.edit(file, "go 1.22\n", "go 1.22\n\nrequire github.com/aws/aws-sdk-go-v2/service/s3 v1.30.0\n");
    expect(run.decision).toBe("deny");
  });

  it("go.mod edits that change no version are not held", () => {
    s.ledger([G("golang.org/x/net", "v0.17.0", "avoid", { reason: "x" })]);
    const text = "module example.com/demo\r\n\r\ngo 1.22\r\n\r\nrequire golang.org/x/net v0.17.0\r\n";
    const file = s.file("go.mod", text);
    expect(s.write(file, text).decision).toBe("allow");
    // Round 35 (C4): raising the go line makes the go command fetch that toolchain release: held.
    expect(s.edit(file, "go 1.22", "go 1.23").decision).toBe("deny");
    expect(s.edit(file, "go 1.23", "go 1.21").decision).toBe("allow");
  });
});
