// SPDX-License-Identifier: Apache-2.0
/**
 * Round 26 of the hook lane (seam hunt 5).
 * R1: a configuration write is read operand by operand in each manager's grammar: held when any key
 *     is not inert, or when the operands do not fit the grammar; a configuration file named by an
 *     option is read.
 * R2: a package a runner fetches, named with a version or on a fetch option, is judged as an install.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import * as hook from "../../hooks/manifest-edit.mjs";
import { sandbox, type Sandbox } from "./helpers/a1123-hookfix-run.js";

let s: Sandbox;
beforeEach(() => {
  s = sandbox();
});
afterEach(() => s.dispose());

const bash = (command: string) => s.run({ session_id: "s", cwd: s.project, hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command } });

describe("R1: every key of a configuration write", () => {
  const INERT = [["fund", "false"], ["save-exact", "true"], ["loglevel", "warn"]];
  const RES = ["registry", "https://example.com/"];
  // npm and pnpm, both spellings, 1 to 3 pairs, the resolution key at each position.
  const forms: Array<[string, boolean]> = [];
  for (const head of ["npm config set", "npm set", "pnpm config set"]) {
    for (let n = 1; n <= 3; n++) {
      const inert = INERT.slice(0, n);
      forms.push([`${head} ${inert.map(([k, v]) => `${k}=${v}`).join(" ")}`, false]);
      forms.push([`${head} ${inert.map(([k, v]) => `${k} ${v}`).join(" ")}`, false]);
      for (let at = 0; at < n; at++) {
        const mixed = inert.map((kv, i) => (i === at ? RES : kv));
        forms.push([`${head} ${mixed.map(([k, v]) => `${k}=${v}`).join(" ")}`, true]);
        forms.push([`${head} ${mixed.map(([k, v]) => `${k} ${v}`).join(" ")}`, true]);
      }
    }
  }
  it.each(forms)("%s: held %s", (command, held) => {
    expect(bash(command).decision, command).toBe(held ? "deny" : "allow");
  });
  it.each([
    ["npm config set fund", true],
    ["npm config set fund=false --registry=https://x/", true],
    ["npm config delete fund", false],
    ["npm config delete fund registry", true],
    ["npm config set -g fund=false", false],
    ["npm config set --location=user fund=false", false],
    ["npm config edit", true],
    ["yarn config set enableTelemetry false", false],
    ["yarn config set npmRegistryServer https://x/", true],
    ["yarn config set enableTelemetry false extra", true],
    ["yarn config unset npmRegistryServer", true],
    ["pip config set global.timeout 60", false],
    ["pip config set global.index-url https://x/simple", true],
    ["pip config set global.timeout 60 extra", true],
    ["pip config unset global.index-url", true],
    ["poetry config virtualenvs.in-project true", false],
    ["poetry config repositories.x https://x/", true],
    ["poetry config --unset repositories.x", true],
    ["go env -w GOBIN=/x", false],
    ["go env -w GOBIN=/x GOPROXY=direct", true],
    ["go env -u GOPROXY", true],
  ])("%s: held %s", (command, held) => {
    expect(bash(command as string).decision, command as string).toBe(held ? "deny" : "allow");
  });
  it("a configuration file named by an option: read, held unless every key is inert", () => {
    s.file("ok.npmrc", "fund=false\n");
    s.file("bad.npmrc", "registry=https://x/\n");
    s.ledger([{ package: "lodash", version: "4.18.1", verdict: "proceed" }]);
    // Beside a named package the option is held by the allow list anyway; on a clean install the file is read.
    expect(bash("npm ci --userconfig ok.npmrc").decision).toBe("allow");
    expect(bash("npm ci --userconfig bad.npmrc").text).toContain("registry");
    expect(bash("npm ci --globalconfig=nope.npmrc").decision).toBe("deny");
    expect(bash("npm i lodash@4.18.1 --userconfig ok.npmrc").decision).toBe("deny");
  });
});

describe("R2: a runner's fetch is judged as an install", () => {
  const VERDICTS = {
    avoid: [{ package: "lodash", version: "4.17.20", verdict: "avoid", reason: "test avoid" }, { ecosystem: "PyPI", package: "requests", version: "2.19.0", verdict: "avoid", reason: "test avoid" }, { ecosystem: "Go", package: "golang.org/x/text/cmd/gotext", version: "v0.3.0", verdict: "avoid", reason: "test avoid" }, { package: "create-vite", version: "5.0.0", verdict: "avoid", reason: "test avoid" }],
    proceed: [{ package: "lodash", version: "4.17.20", verdict: "proceed" }, { ecosystem: "PyPI", package: "requests", version: "2.19.0", verdict: "proceed" }, { ecosystem: "Go", package: "golang.org/x/text/cmd/gotext", version: "v0.3.0", verdict: "proceed" }, { package: "create-vite", version: "5.0.0", verdict: "proceed" }],
    none: [],
  } as const;
  const FORMS = [
    "npm exec --yes --package=lodash@4.17.20 -- node -e 1",
    "npx -y -p lodash@4.17.20 node -e 1",
    "npx lodash@4.17.20",
    "pnpx lodash@4.17.20",
    "pnpm dlx lodash@4.17.20",
    "yarn dlx lodash@4.17.20",
    "bunx lodash@4.17.20",
    "bun x lodash@4.17.20",
    "npm create vite@5.0.0",
    "npm init vite@5.0.0",
    "pnpm create vite@5.0.0",
    "yarn create vite@5.0.0",
    "bun create vite@5.0.0",
    "uv run --with requests==2.19.0 python -c 1",
    "uvx --with requests==2.19.0 python -c 1",
    "uvx requests@2.19.0",
    "uv tool run --with requests==2.19.0 python",
    "uv tool install requests==2.19.0",
    "pipx run --spec requests==2.19.0 python",
    "pipx install requests==2.19.0",
    "pipx inject venv requests==2.19.0",
    "go run golang.org/x/text/cmd/gotext@v0.3.0",
  ];
  it.each(FORMS.flatMap((f) => (["avoid", "proceed", "none"] as const).map((v) => [f, v] as const)))("%s with %s", (command, verdict) => {
    s.ledger(VERDICTS[verdict].map((e) => ({ ecosystem: "npm", ...e })) as never);
    const r = bash(command);
    expect(r.decision, r.text).toBe(verdict === "proceed" ? "allow" : "deny");
    if (verdict === "avoid") expect(r.text).toContain("answered avoid");
  });
  it.each(["npx tsc", "bunx eslint", "uvx ruff", "pnpm dlx create-vite", "npm exec -- tsc", "npm init"])("a bare name with no fetch option is not judged (L2): %s", (command) => {
    expect(bash(command).decision).toBe("allow");
  });
  it("RUNNER_FETCH_FORMS is exported", () => {
    expect(hook.RUNNER_FETCH_FORMS.length).toBeGreaterThanOrEqual(8);
  });
});
