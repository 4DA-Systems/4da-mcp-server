// SPDX-License-Identifier: Apache-2.0
/**
 * Round 14, from the twelfth independent check: a cut. Fewer things go ahead, decided by positive
 * evidence. Each rule (R1-R12) with the reviewer's cases.
 */

import { spawn, spawnSync } from "node:child_process";
import { appendFileSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { sandbox, type Sandbox } from "./helpers/a1123-hookfix-run.js";
// The hook's PATH lookups see a stub for each manager and runner word, whatever the machine (Windows).
import "./helpers/a1125-manager-stubs.js";

const HOOK = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "hooks", "manifest-edit.mjs");

let s: Sandbox;
beforeEach(() => {
  s = sandbox();
  s.ledger([{ ecosystem: "npm", package: "lodash", version: "4.17.20", verdict: "avoid", reason: "test avoid" }]);
});
afterEach(() => s.dispose());

const run = (command: string, tool = "Bash") => s.run({ session_id: "s", cwd: s.project, hook_event_name: "PreToolUse", tool_name: tool, tool_input: { command } });

describe("R1 / R2: changes the round-14 cut makes to earlier rows", () => {
  it.each([
    "pnpm add --trust-policy no-downgrade lodash@4.17.21",
    "go get -u github.com/pkg/errors@upgrade",
  ])("%s: held as not read (off the allow list, or more than one source)", (command) => {
    expect(run(command).text).toContain("could not be read");
  });
});

describe("R7: pnpm-workspace.yaml is read only when every line is plain", () => {
  const write = (content: string) => s.write(`${s.project}/pnpm-workspace.yaml`, content);
  it.each([
    ["a tag", "catalog:\n  lodash: !!str 4.17.20\n"],
    ["an anchor and an alias", "x: &v 4.17.20\ncatalog:\n  lodash: *v\n"],
    ["a literal block scalar", "catalog:\n  lodash: |\n    4.17.20\n"],
    ["a folded block scalar", "catalog:\n  lodash: >-\n    4.17.20\n"],
    ["an explicit key at the top", "? lodash\n: 4.17.20\n"],
    ["an explicit key in a section", "catalog:\n  ? lodash\n  : 4.17.20\n"],
    ["a merge key", "base: &b\n  lodash: 4.17.20\ncatalog:\n  <<: *b\n"],
    ["a flow mapping", "catalog: { lodash: 4.17.20 }\n"],
    ["a flow sequence", "packages: ['a', 'b']\ncatalog:\n  lodash: 4.17.20\n"],
    ["a second document", "catalog:\n  ms: 2.1.3\n---\ncatalog:\n  lodash: 4.17.20\n"],
    ["a value on the next line", "catalog:\n  lodash:\n    4.17.20\n"],
    ["a range starting with an indicator, unquoted", "catalog:\n  lodash: >=4.17.20\n"],
    ["a lone CR before a flow line", "# note\rcatalog: { lodash: 4.17.20 }\n"],
  ])("%s: held, with the rewrite remedy", (_label, content) => {
    const r = write(content);
    expect(r.decision, content).toBe("deny");
    expect(r.text).toContain("rewrite as plain `name: version` lines");
  });
  it.each([
    ["plain lines", "packages:\n  - 'packages/*'\ncatalog:\n  lodash: 4.17.20\n"],
    ["quoted keys and values", "catalog:\n  'lodash': '4.17.20'\n  \"@types/node\": \"20.0.0\"\n"],
    ["a quoted range", "catalog:\n  lodash: '>=4.17.20'\n"],
    ["comments", "# top\ncatalog: # the catalog\n  lodash: 4.17.20 # pinned\n"],
    ["a document start first", "---\ncatalog:\n  lodash: 4.17.20\n"],
  ])("%s: read, the version judged", (_label, content) => {
    const r = write(content);
    expect(r.text).not.toContain("could not be read");
    expect(r.decision).toBe("deny");
  });
});

describe("check 12's manifest rows", () => {
  const write = (name: string, content: string) => s.write(`${s.project}/${name}`, content);
  it("a go.mod module path in backquotes is read", () => {
    const r = write("go.mod", "module example.com/x\n\ngo 1.22\n\nrequire `golang.org/x/text` v0.3.0\n");
    expect(r.decision).toBe("deny");
    expect(r.items?.[0]?.package).toBe("golang.org/x/text");
  });
  it.each([
    "urllib3 @ https://files.pythonhosted.org/packages/x/urllib3-2.2.3-py3-none-any.whl\n",
    "https://files.pythonhosted.org/packages/x/urllib3-2.2.3-py3-none-any.whl\n",
  ])("a requirements line naming a public registry's own file is that release: %s", (content) => {
    const r = write("requirements.txt", content);
    expect(r.decision).toBe("deny");
    expect(r.items).toEqual([{ ecosystem: "PyPI", package: "urllib3", to: "2.2.3" }]);
  });
  it.each(["package.json​", "package․json", "package.json\u0000"])("a manifest name with an invisible character or a dot look-alike is held as the manifest: %j", (name) => {
    expect(write(name, '{"dependencies":{"lodash":"4.17.20"}}').decision).toBe("deny");
  });
});

describe("R9: the ledger minors", () => {
  it("a line cut before its package after a proceed: the proceed does not stand", () => {
    s.ledger([{ ecosystem: "npm", package: "ms", version: "2.1.3", verdict: "proceed", reason: "ok" }]);
    expect(run("npm install ms@2.1.3").decision).toBe("allow");
    appendFileSync(join(s.home, "check-ledger.jsonl"), '{"t":"2026-11-26T10:00:00.000Z","ecos');
    expect(run("npm install ms@2.1.3").decision).toBe("deny");
  });
});

describe("R9: stdin left open with a whole payload is judged as any other (S71)", () => {
  it("an install with a proceed on record goes ahead; one with an avoid is held", async () => {
    s.ledger([
      { ecosystem: "npm", package: "ms", version: "2.1.3", verdict: "proceed", reason: "ok" },
      { ecosystem: "npm", package: "lodash", version: "4.17.20", verdict: "avoid", reason: "test avoid" },
    ]);
    const open = (command: string) =>
      new Promise<string>((done) => {
        const env: Record<string, string | undefined> = { ...process.env, FOURDA_MCP_HOME: s.home };
        delete env.FOURDA_GUARD;
        const p = spawn(process.execPath, [HOOK], { env });
        let o = "";
        p.stdout.on("data", (d: Buffer) => (o += d.toString()));
        p.on("exit", () => done(o));
        p.stdin.write(JSON.stringify({ session_id: "s", cwd: s.project, hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command } }));
        setTimeout(() => p.kill(), 15_000);
      });
    const [ok, avoid] = await Promise.all([open("npm i ms@2.1.3"), open("npm i lodash@4.17.20")]);
    expect(ok).toBe("");
    expect(avoid).toContain("answered avoid");
  }, 20_000);
});

describe.runIf(process.platform === "win32")("R9: a ledger file this process may not read (a deny-read ACL) is held, not absent", () => {
  it("held", () => {
    s.ledger([{ ecosystem: "npm", package: "ms", version: "2.1.3", verdict: "proceed", reason: "ok" }]);
    const file = join(s.home, "check-ledger.jsonl").replace(/\//g, "\\");
    const user = process.env.USERNAME ?? "";
    const set = spawnSync("icacls", [file, "/deny", `${user}:(R)`], { encoding: "utf8" });
    try {
      if (set.status !== 0) throw new Error(`icacls: ${set.stdout} ${set.stderr}`);
      // The ACL takes effect only where this process does not hold a privilege that reads past it.
      try {
        statSync(file);
        return;
      } catch {
        // unreadable, as meant
      }
      const r = run("npm install ms@2.1.3");
      expect(r.decision, r.text).toBe("deny");
      expect(r.text).toContain("could not be read");
    } finally {
      spawnSync("icacls", [file, "/remove:d", user], { encoding: "utf8" });
    }
  });
});
