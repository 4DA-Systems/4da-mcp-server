// SPDX-License-Identifier: Apache-2.0
/**
 * An install command that names a package without a version writes the registry's newest release
 * into the manifest and the lockfile, and the hook let it through with no verdict at all
 * (`npm install <a typosquat>`; lead's check of the confirmation system, 2026-11-27). Now a name
 * alone, `@latest`, or a version-less alias is the request "latest": it needs a dependency_check
 * verdict recorded for that request (the server writes `requested: "latest"`), at most 24 h old.
 * A dist-tag other than latest is held with "name the version" (no call clears a tag). What
 * installs no public package by name still goes ahead.
 */

import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { ledgerEntries } from "../check-ledger.js";
import { sandbox, type Sandbox } from "./helpers/a1123-hookfix-run.js";
import { record, timedWithin } from "./helpers/a1125-hook-run.js";

let s: Sandbox;
beforeEach(() => {
  s = sandbox();
});
afterEach(() => s.dispose());

const run = (command: string, tool = "Bash", env: Record<string, string> = {}) =>
  s.run({ session_id: "s", cwd: s.project, hook_event_name: "PreToolUse", tool_name: tool, tool_input: { command } }, env);

/** Ledger lines exactly as the server writes them for these dependency_check answers. */
function answer(items: Array<Record<string, string>>, privateRule: ((eco: string, name: string) => boolean) | null = null): void {
  const lines = ledgerEntries(items as never, new Date(Date.now() - 60_000), privateRule).map((e) => ({ ...e }) as Record<string, string>);
  record(s, lines.map(({ t: _t, ...rest }) => rest));
}

/** The lead's bypass list and its siblings: each with the call its denial names. */
const BARE: Array<[string, string, string]> = [
  ["npm install lodash", "npm", "lodash"],
  ["npm install lodash@latest", "npm", "lodash"],
  ["npm i -D @types/node", "npm", "@types/node"],
  ["yarn add lodash", "npm", "lodash"],
  ["yarn workspace web add lodash", "npm", "lodash"],
  ["pnpm add -D typescript", "npm", "typescript"],
  ["pnpm add lodash@latest --filter web", "npm", "lodash"],
  ["pnpm up -L react", "npm", "react"],
  ["pnpm up --latest react", "npm", "react"],
  ["yarn up react", "npm", "react"],
  ["yarn upgrade react --latest", "npm", "react"],
  ["bun add zod", "npm", "zod"],
  ["bun install zod", "npm", "zod"],
  ["npm i my-lodash@npm:lodash", "npm", "lodash"],
  ["pip install requests", "PyPI", "requests"],
  ["pip install requests[socks]", "PyPI", "requests"],
  ["pip install --no-deps -t out requests", "PyPI", "requests"],
  ["uv add httpx", "PyPI", "httpx"],
  ["uv pip install requests", "PyPI", "requests"],
  ["poetry add rich", "PyPI", "rich"],
  ["poetry add rich@latest", "PyPI", "rich"],
  ["cargo add serde", "crates.io", "serde"],
  ["cargo add serde --features derive", "crates.io", "serde"],
  ["go get github.com/pkg/errors", "Go", "github.com/pkg/errors"],
  ["go get github.com/pkg/errors@latest", "Go", "github.com/pkg/errors"],
  ["go get -u github.com/pkg/errors@upgrade", "Go", "github.com/pkg/errors"],
];
/** Installs that move a tool itself to its newest release: held until a latest verdict exists, by design. */
const SELF: Array<[string, string, string]> = [
  ["python -m pip install --upgrade pip", "PyPI", "pip"],
  ["npm i -g npm", "npm", "npm"],
  ["npm i -g pnpm", "npm", "pnpm"],
];

describe("a package named without a version is held with an empty ledger, and the denial's own call releases it", () => {
  it.each([...BARE, ...SELF])("%s", (command, ecosystem, pkg) => {
    s.ledger([]);
    const held = run(command);
    expect(held.decision, held.text).toBe("deny");
    expect(held.items).toEqual([{ ecosystem, package: pkg, to: "latest" }]);
    // The call made literally, answered as the server records it: the newest release, requested "latest".
    answer([{ ecosystem, package: pkg, to: "9.9.9", to_requested: "latest", verdict: "proceed", reason: "ok" }]);
    expect(run(command).decision).toBe("allow");
  });

  it("PowerShell reads it the same way", () => {
    s.ledger([]);
    expect(run("npm install lodash", "PowerShell").items).toEqual([{ ecosystem: "npm", package: "lodash", to: "latest" }]);
    answer([{ ecosystem: "npm", package: "lodash", to: "4.17.21", to_requested: "latest", verdict: "review" }]);
    expect(run("npm install lodash", "PowerShell").decision).toBe("allow");
  });
});

describe("what releases it, and what does not", () => {
  it("an avoid for the request latest holds it with the recorded reason (a malware name)", () => {
    s.ledger([]);
    const reason = "MAL-2025-25502 records lodahs as a malicious package: the name itself, not one release of it. Do not install it. Did you mean lodash?";
    answer([{ ecosystem: "npm", package: "lodahs", to: "0.0.1-security", to_requested: "latest", verdict: "avoid", reason }]);
    const held = run("npm install lodahs");
    expect(held.decision).toBe("deny");
    expect(held.text).toContain("dependency_check answered avoid");
    expect(held.text).toContain("MAL-2025-25502");
  });

  it("a proceed for an exact old version only is no verdict for latest", () => {
    s.ledger([]);
    answer([{ ecosystem: "npm", package: "lodash", to: "4.17.21", verdict: "proceed" }]);
    expect(run("npm install lodash@4.17.21").decision).toBe("allow");
    const held = run("npm install lodash");
    expect(held.decision).toBe("deny");
    expect(held.items).toEqual([{ ecosystem: "npm", package: "lodash", to: "latest" }]);
  });

  it("a verdict older than 24 hours is no verdict", () => {
    const t = new Date(Date.now() - 25 * 60 * 60 * 1000).toISOString();
    s.ledger([{ t, ecosystem: "npm", package: "lodash", version: "4.17.21", requested: "latest", verdict: "proceed" }]);
    expect(run("npm install lodash").decision).toBe("deny");
  });

  it("a name a private rule covers (the server's private record) goes ahead at any version, bare included", () => {
    s.ledger([]);
    answer([{ ecosystem: "npm", package: "@acme/internal", to: "latest", verdict: "unknown", not_checked: "private" }], () => true);
    expect(run("npm install @acme/internal").decision).toBe("allow");
    expect(run("npm install @acme/internal@2.0.0").decision).toBe("allow");
  });

  it("a declaration of the agent's own records nothing: only the server's private rules release a name", () => {
    s.ledger([]);
    const held = run("npm install acme-internal-thing");
    expect(held.text).toContain("must NOT be checked: the call would send its name to the public registry");
    expect(held.text).toContain("what_should_i_know's `public: false`) records nothing and releases nothing");
  });
});

describe("a dist-tag other than latest", () => {
  it.each([
    ["npm install lodash@next", "next"],
    ["yarn add react@canary", "canary"],
    ["pnpm add vite@beta", "beta"],
    ["go get github.com/pkg/errors@master", "master"],
  ])("%s: held with no call, saying to name the version; the named version, checked, passes", (command, tag) => {
    s.ledger([]);
    const held = run(command);
    expect(held.decision).toBe("deny");
    expect(held.items).toBeNull();
    expect(held.text).toContain(`"${tag}"`);
    expect(held.text).toContain("name the version the tag points to");
    const named = command.replace(`@${tag}`, command.startsWith("go ") ? "@v0.9.1" : "@1.2.3");
    const first = run(named);
    answer((first.items ?? []).map((i) => ({ ...i, verdict: "proceed" })));
    expect(run(named).decision).toBe("allow");
  });
});

describe("a workspace member: the local_source hold names three ways that release it", () => {
  it("the denial wording, and each of the three", () => {
    s.ledger([]);
    answer([{ ecosystem: "npm", package: "shared", to: "latest", verdict: "unknown", not_checked: "private", reason: "the project takes shared from its workspace" }], () => false);
    const held = run("pnpm add shared --filter web");
    expect(held.decision).toBe("deny");
    expect(held.text).toContain('install it as "shared@workspace:*"');
    expect(held.text).toContain('FOURDA_PRIVATE_PACKAGES="shared"');
    expect(held.text).toContain("as a file: path (that edit goes ahead)");
    // 1. The workspace protocol is not a registry install: it goes ahead.
    expect(run("pnpm add shared@workspace:* --filter web").decision).toBe("allow");
    expect(run("yarn workspace web add shared@workspace:^").decision).toBe("allow");
    // 3. A file: path in the manifest goes ahead.
    const file = s.file("package.json", '{\n  "name": "web",\n  "dependencies": {}\n}\n');
    expect(s.edit(file, '"dependencies": {}', '"dependencies": { "shared": "file:../shared" }').decision).toBe("allow");
    // 2. Marked private by the server's rule (FOURDA_PRIVATE_PACKAGES=shared), the next call records it private: it passes.
    answer([{ ecosystem: "npm", package: "shared", to: "latest", verdict: "unknown", not_checked: "private" }], (_e, n) => n === "shared");
    expect(run("pnpm add shared --filter web").decision).toBe("allow");
  });
});

/** Commands that install no public package by name, or install the lockfile: none may be held. */
const ORDINARY = [
  "npm install", "npm i", "npm ci", "npm install --frozen-lockfile", "pnpm install", "pnpm i --frozen-lockfile", "pnpm up", "pnpm up react", "pnpm update react",
  "yarn", "yarn install", "yarn install --immutable", "yarn upgrade react", "bun install", "bun i", "npm update lodash", "npm uninstall lodash", "npm rm lodash",
  "pnpm remove lodash", "yarn remove lodash", "npm run build", "npm test", "npm ls lodash", "npm view lodash version", "npm outdated", "npm audit", "npm dedupe",
  "npm i ./local-pkg", "npm i ../shared", "npm i file:../shared", "npm i user/repo", "npm i github:user/repo", "npm i git+https://example.com/r.git",
  "npm i https://example.com/a.tgz", "npm i a-1.0.0.tgz", "npm i --registry https://npm.internal.example x", "pnpm add shared@workspace:*", "npm pkg get name",
  "pip install -r requirements.txt", "pip install -r requirements-dev.txt -c constraints.txt", "pip install .", "pip install -e .", "pip install -e '.[dev]'",
  "pip install ./pkg", "pip install dist/x-1.0-py3-none-any.whl", "pip install x-1.0.tar.gz", "pip install git+https://github.com/a/b",
  "pip install -i https://pypi.internal.example/simple x", "pip download requests", "pip list", "pip show requests", "pip uninstall -y requests", "uv sync", "uv lock",
  "uv pip sync requirements.txt", "uv run pytest", "poetry install", "poetry lock", "cargo build", "cargo add --path ../x", "cargo add x --git https://example.com/x",
  "cargo update", "go get ./...", "go mod tidy", "go mod download", "go build ./...", "go get -u ./...", "go get github.com/pkg/errors@none",
  "npx cowsay hi", "pnpm dlx create-vite", "bunx tsc", "uvx ruff", "pipx install black", "cargo install ripgrep", "go install golang.org/x/tools/gopls@latest",
  "yarn global add typescript", "echo npm install lodash", "git commit -m 'npm install lodash'",
];

describe(`${ORDINARY.length} ordinary commands go ahead with an empty ledger`, () => {
  it.each(ORDINARY.map((c) => [c]))("%s", (command) => {
    s.ledger([]);
    expect(run(command).decision).toBe("allow");
  });
});

describe("settings and the ledger's absence are unchanged", () => {
  it("FOURDA_GUARD=advise and =off never deny; no ledger file, nothing is denied", () => {
    s.ledger([]);
    expect(run("npm install lodash", "Bash", { FOURDA_GUARD: "advise" }).decision).toBe("allow");
    expect(run("npm install lodash", "Bash", { FOURDA_GUARD: "off" }).decision).toBe("allow");
    expect(s.run({ session_id: "s", cwd: s.project, hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "npm install lodash" } }, { FOURDA_MCP_HOME: join(s.project, "no-such-home") }).decision).toBe("allow");
  });
});

describe("size", () => {
  it("a 60 KB install of names alone, inside the CPU bound", () => {
    s.ledger([]);
    const names = Array.from({ length: 6000 }, (_, i) => `pkg-${i}`).join(" ");
    const held = timedWithin(s.home, { hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: `npm install ${names}` } }, 500);
    expect(held.decision).toBe("deny");
    expect(held.text).toContain('"to":"latest"');
  });
});
