// SPDX-License-Identifier: Apache-2.0
/**
 * What a withheld answer lets through (round 3 of the hook review, item 1).
 *
 * A name a project takes from git, a path, its workspace, an alias, a catalog or another registry
 * (`local_source`) is never looked up by the server, and that source does not apply to
 * `npm i name@ver`, `pip install name==ver` or `cargo add name@ver`, which fetch the name from the
 * public registry: an unchecked public release of such a name is dependency confusion. The
 * round-2 hook let it through in the answer's project (`"acme-utils": "github:acme/acme-utils"`,
 * then `npm i acme-utils@9.9.9`), and a server started in project Y let `npm i lodash@3.10.1`
 * through in Y because project X takes lodash from git. Now such an answer HOLDS, everywhere, as
 * does one withheld for an unreadable lockfile. A private-registry answer (`private`) behaves as
 * in 6.5.0: any version, any project, unless a decisive verdict for that version came first. The
 * project-scoped unlock (and its path logic) is withdrawn.
 */

import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { respond } from "../../hooks/manifest-edit.mjs";
import { LEDGER_FILE } from "../check-ledger.js";

let dir: string;
let home: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "a651-withheld-"));
  home = join(dir, "home");
  mkdirSync(home);
});
afterEach(() => rmSync(dir, { recursive: true, force: true }));

const NOW = Date.now();
const MIN = 60_000;
function ledger(entries: Array<Record<string, unknown>>) {
  writeFileSync(
    join(home, LEDGER_FILE),
    entries.map(({ ago = 1, ...e }) => JSON.stringify({ sv: "6.6.0", t: new Date(NOW - (ago as number) * MIN).toISOString(), verdict: "unknown", ...e })).join("\n") + "\n",
  );
}
function decide(command: string): { decision: "allow" | "deny"; text: string } {
  const out = respond({ hook_event_name: "PreToolUse", tool_name: "Bash", cwd: dir, tool_input: { command } }, { FOURDA_MCP_HOME: home }, NOW);
  return out === "" ? { decision: "allow", text: "" } : { decision: "deny", text: (JSON.parse(out) as { hookSpecificOutput: { permissionDecisionReason: string } }).hookSpecificOutput.permissionDecisionReason };
}

describe("a local-source answer holds a registry install of that name, in any project", () => {
  it.each([
    ["npm git dependency", "npm", "acme-utils", "npm i acme-utils@9.9.9"],
    ["npm workspace member", "npm", "acme-utils", "npm i acme-utils@9.9.9"],
    ["uv git source", "PyPI", "acme-utils", "pip install acme-utils==9.9.9"],
    ["Cargo named registry", "crates.io", "acme-utils", "cargo add acme-utils@9.9.9"],
    ["Cargo git", "crates.io", "acme-utils", "cargo add acme-utils@9.9.9"],
    ["go replace to a directory", "Go", "github.com/pkg/errors", "go get github.com/pkg/errors@v0.8.0"],
  ])("%s", (_label, ecosystem, pkg, command) => {
    ledger([{ ecosystem, package: pkg, version: "1.0.0", not_checked: "local_source", reason: `NOT CHECKED (not a registry release): ${pkg} comes from git.` }]);
    const r = decide(command);
    expect(r.decision).toBe("deny");
    expect(r.text).toMatch(/from the public registry, which was not checked/);
    // The way that works (round 4 of the hook review, item 5): remove the non-registry spec first
    // (that edit goes ahead; putting a registry version in its place is held like the command), or
    // repair an unreadable catalog; then dependency_check looks the name up and this call is judged
    // on its verdict. No "ask the user" dead end.
    expect(r.text).toMatch(/remove that non-registry spec from the manifest that declares it \(that edit goes ahead; one that puts a registry version in its place is held like this command\)/);
    expect(r.text).toMatch(/if the recorded reason says a catalog could not be read, repair the catalog/);
    expect(r.text).toMatch(/then call dependency_check for this version: this command passes once it answers proceed/);
    expect(r.text).toMatch(/FOURDA_GUARD is the user's setting, not yours to change/);
    expect(r.text).not.toMatch(/ask the user\./);
  });

  it("an answer recorded by a server started in another project holds too (the round-2 c3 case)", () => {
    ledger([{ ecosystem: "npm", package: "lodash", version: "3.10.1", not_checked: "local_source", project: "C:\\elsewhere\\Y", reason: "in X, lodash comes from git (github:me/lodash)" }]);
    expect(decide("npm i lodash@3.10.1").decision).toBe("deny");
  });

  it("an unreadable lockfile holds, with the repair named", () => {
    ledger([{ ecosystem: "npm", package: "lodash", version: "4.17.20", not_checked: "unreadable_lockfile", unreadable_file: "/p/package-lock.json" }]);
    expect(decide("npm i lodash@4.17.20").text).toMatch(/Repair or regenerate/);
  });

  it("a later proceed for that exact version lets it through", () => {
    ledger([
      { ecosystem: "npm", package: "acme-utils", version: "9.9.9", not_checked: "local_source", ago: 10 },
      { ecosystem: "npm", package: "acme-utils", version: "9.9.9", verdict: "proceed", ago: 1 },
    ]);
    expect(decide("npm i acme-utils@9.9.9").decision).toBe("allow");
  });
});

describe("a private-registry answer behaves as in 6.5.0", () => {
  it("lets any version through, in any folder, with no project needed", () => {
    ledger([{ ecosystem: "npm", package: "@acme/widgets", version: "1.0.0", not_checked: "private", private_rule: "listed", reason: "NOT CHECKED (private): @acme is mapped to a private registry" }]);
    expect(decide("npm i @acme/widgets@2.0.0").decision).toBe("allow");
  });

  it("a decisive verdict for that exact version decides first, even an older avoid", () => {
    ledger([
      { ecosystem: "npm", package: "@acme/widgets", version: "2.0.0", verdict: "avoid", reason: "GHSA-x", ago: 30 },
      { ecosystem: "npm", package: "@acme/widgets", version: "2.0.0", not_checked: "private", private_rule: "listed", ago: 1 },
    ]);
    expect(decide("npm i @acme/widgets@2.0.0").decision).toBe("deny");
  });

  it("a 6.5.0 entry withheld for an unreadable file (private with unreadable_file) holds", () => {
    ledger([{ ecosystem: "npm", package: "lodash", version: "4.17.20", not_checked: "private", private_rule: "listed", unreadable_file: "/p/package-lock.json" }]);
    expect(decide("npm i lodash@4.17.20").text).toMatch(/Repair or regenerate/);
  });
});

describe("a manifest edit that keeps the non-registry spec is no registry install", () => {
  function edit(from: string, to: string): "allow" | "deny" {
    const file = join(dir, "package.json");
    writeFileSync(file, `{\n  "dependencies": {\n    "acme-utils": "${from}"\n  }\n}\n`);
    const out = respond(
      { hook_event_name: "PreToolUse", tool_name: "Edit", cwd: dir, tool_input: { file_path: file, old_string: `"acme-utils": "${from}"`, new_string: `"acme-utils": "${to}"` } },
      { FOURDA_MCP_HOME: home },
      NOW,
    );
    return out === "" ? "allow" : "deny";
  }

  it("git to another git ref, or to a path: goes ahead (nothing to check)", () => {
    ledger([{ ecosystem: "npm", package: "acme-utils", version: "1.0.0", not_checked: "local_source" }]);
    expect(edit("github:acme/acme-utils#v1", "github:acme/acme-utils#v2")).toBe("allow");
    expect(edit("github:acme/acme-utils#v1", "file:../acme-utils")).toBe("allow");
  });

  it("git to a registry version: held like any unchecked version", () => {
    ledger([{ ecosystem: "npm", package: "acme-utils", version: "1.0.0", not_checked: "local_source" }]);
    expect(edit("github:acme/acme-utils#v1", "9.9.9")).toBe("deny");
  });
});
