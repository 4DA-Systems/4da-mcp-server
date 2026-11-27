// SPDX-License-Identifier: Apache-2.0
/**
 * Round 13 (eleventh independent check, remedies): the reviewer's remedy lines (p1c-remedy). The
 * denial names the part of the line it did not read; followed mechanically (that part left out, or
 * written in the form named; a verdict answered where one is missing), the line (i) goes ahead and
 * (ii) still names the same operands, versions, extras and placement flags as the original.
 */

import "./helpers/a1125-poetry-on-path.js";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { sandbox, type Sandbox } from "./helpers/a1123-hookfix-run.js";
import { followRemedy, record } from "./helpers/a1125-hook-run.js";

const L = (ecosystem: string, p: string, v: string) => ({ ecosystem, package: p, version: v, verdict: "proceed", reason: "ok" });
const BASE = [
  L("npm", "lodash", "4.17.21"),
  L("npm", "typescript", "5.6.3"),
  L("npm", "react", "18.2.0"),
  L("npm", "chalk", "5.3.0"),
  L("npm", "@types/node", "20.11.0"),
  L("PyPI", "requests", "2.32.3"),
  L("PyPI", "flask", "3.0.3"),
  L("PyPI", "ruff", "0.6.9"),
  L("PyPI", "httpx", "0.27.2"),
  L("crates.io", "serde", "1.0.200"),
  L("crates.io", "ripgrep", "14.1.1"),
  L("Go", "rsc.io/quote", "v1.5.2"),
  L("Go", "golang.org/x/tools/gopls", "v0.16.2"),
];
const NAMES = BASE.map((e) => e.package);

/** The reviewer's placement flags: a remedy without them installs something else, or elsewhere. */
const SIG =
  /(^|\s)(-D|--save-dev|-d|--dev|-G|--group|-g|--global|global|-w|--workspace|--filter|-F|-C|--dir|--prefix|--cwd|workspace|-p|--package|--project|--save-peer|--peer|-O|--save-optional|--optional|--user|--target|-t|--system|-e|--editable|--features|--no-default-features|--build|--rename|--locked|--manifest-path|-tool|-U|cd)(?=[\s=]|$)/g;
const sig = (c: string) => [...c.matchAll(SIG)].map((m) => m[2]);
/** A setting written as its option keeps the placement it stood for. */
const placement = (c: string) => [...sig(c), ...(/npm_config_save_dev/i.test(c) ? ["--save-dev"] : [])];

const LINES: [string, string][] = [
  ["Bash", "npm i -D lodash@4.17.21 --before=2020-01-01"],
  ["Bash", "npm install --save-dev typescript@5.6.3 --tag beta"],
  ["Bash", "npm i -g typescript@5.6.3 --before 2024-01-01"],
  ["Bash", "npm i --workspace app lodash@4.17.21 --tag x"],
  ["Bash", "npm i -w app -D lodash@4.17.21 --before=2024-01-01"],
  ["Bash", "npm i --save-peer react@18.2.0 --tag x"],
  ["Bash", "npm i -O chalk@5.3.0 --tag x"],
  ["Bash", "npm i lodash@^4.17.0 --tag x"],
  ["Bash", "npm i 'lodash@>=4 <5' --tag x"],
  ["Bash", "npm i @types/node@20.11.0 lodash@4.17.21 --before=2024-01-01"],
  ["Bash", "npm_config_registry=https://registry.npmjs.org npm i lodash@4.17.21"],
  ["Bash", "NPM_CONFIG_USERCONFIG=x npm i -D lodash@4.17.21"],
  ["Bash", "sudo npm i -g typescript@5.6.3 --tag x"],
  ["Bash", "npm --prefix sub i lodash@4.17.21 --tag x"],
  ["Bash", "npm i lodash@4.17.21 --tag x && npm test"],
  ["Bash", "echo $(date); npm i -D lodash@4.17.21"],
  ["Bash", "npm i -E lodash@4.17.21 --tag latest"],
  ["Bash", "npm i lodash@3 --tag x"],
  ["Bash", "npm i lodash@4.17.21 typescript --before=2024-01-01"],
  ["Bash", "pnpm add -D lodash@4.17.21 --zzz"],
  ["Bash", "pnpm --filter app add lodash@4.17.21 --zzz"],
  ["Bash", "pnpm add -w lodash@4.17.21 --zzz"],
  ["Bash", "pnpm -C packages/app add lodash@4.17.21 --zzz"],
  ["Bash", "pnpm add -g typescript@5.6.3 --zzz"],
  ["Bash", "pnpm add --save-peer react@18.2.0 --zzz"],
  ["Bash", "pnpm up -L lodash --zzz"],
  ["Bash", "pnpm add lodash@~4.17.0 --zzz"],
  ["Bash", "pnpm add -O chalk@5.3.0 --zzz"],
  ["Bash", "yarn add -D lodash@4.17.21 --zzz"],
  ["Bash", "yarn workspace app add lodash@4.17.21 --zzz"],
  ["Bash", "yarn global add typescript@5.6.3 --zzz"],
  ["Bash", "yarn add --peer react@18.2.0 --zzz"],
  ["Bash", "yarn up lodash@4.17.21 --zzz"],
  ["Bash", "yarn add -O chalk@5.3.0 --zzz"],
  ["Bash", "bun add -d lodash@4.17.21 --zzz"],
  ["Bash", "bun add -g typescript@5.6.3 --zzz"],
  ["Bash", "bun add --optional chalk@5.3.0 --zzz"],
  ["Bash", "bun update lodash@4.17.21"],
  ["Bash", "bun add --peer react@18.2.0 --zzz"],
  ["Bash", "pip install --user requests==2.32.3 --pre"],
  ["Bash", "pip install 'requests[socks]==2.32.3' --pre"],
  ["Bash", "pip install 'requests>=2.31,<3' --pre"],
  ["Bash", "pip install --target vendor requests==2.32.3 --pre"],
  ["Bash", "python -m pip install -U requests==2.32.3 --pre"],
  ["Bash", "pip install -e . requests==2.32.3 --pre"],
  ["Bash", "PIP_INDEX_URL=https://pypi.org/simple pip install requests==2.32.3"],
  ["Bash", "pip install 'requests==2.32.3; python_version>\"3.8\"' --pre"],
  ["Bash", "pip3 install requests==2.32.3 flask==3.0.3 --pre"],
  ["Bash", "pip install --prefix /opt/x requests==2.32.3 --pre"],
  ["Bash", "uv add --dev requests==2.32.3 --upgrade"],
  ["Bash", "uv add --group lint ruff==0.6.9 --upgrade"],
  ["Bash", "uv add --optional socks requests==2.32.3 --upgrade"],
  ["Bash", "uv pip install --system requests==2.32.3 --upgrade"],
  ["Bash", "uv add 'requests[socks]==2.32.3' --upgrade"],
  ["Bash", "uv add --package app requests==2.32.3 --upgrade"],
  ["Bash", "uv pip install 'httpx[http2]>=0.27' --upgrade"],
  ["Bash", "uv add --project sub requests==2.32.3 --upgrade"],
  ["Bash", "poetry add -G dev requests==2.32.3 --zzz"],
  ["Bash", "poetry add --optional requests==2.32.3 --zzz"],
  ["Bash", "poetry add 'requests[socks]==2.32.3' --zzz"],
  ["Bash", "poetry add requests@^2.31 --zzz"],
  ["Bash", "poetry add -C sub requests==2.32.3 --zzz"],
  ["Bash", "cargo add --dev serde@1.0.200 --zzz"],
  ["Bash", "cargo add serde@1.0.200 --features derive --zzz"],
  ["Bash", "cargo add -p app serde@1.0.200 --zzz"],
  ["Bash", "cargo add --build serde@1.0.200 --zzz"],
  ["Bash", "cargo add serde@1.0.200 --no-default-features --zzz"],
  ["Bash", "cargo add --target x86_64-pc-windows-msvc serde@1.0.200 --zzz"],
  ["Bash", "cargo install ripgrep@14.1.1 --locked --zzz"],
  ["Bash", "cargo add serde@^1.0 --zzz"],
  ["Bash", "cargo add serde@1.0.200 --rename s --zzz"],
  ["Bash", "cargo add --manifest-path sub/Cargo.toml serde@1.0.200 --zzz"],
  ["Bash", "cargo add serde@1.0.200 -F derive --zzz"],
  ["Bash", "go get -t rsc.io/quote@v1.5.2 -zzz"],
  ["Bash", "GOFLAGS=-mod=mod go get rsc.io/quote@v1.5.2"],
  ["Bash", "go install golang.org/x/tools/gopls@v0.16.2 -zzz"],
  ["Bash", "go mod edit -require=rsc.io/quote@v1.5.2 -zzz"],
  ["Bash", "go get rsc.io/quote@v1.5 -zzz"],
  ["Bash", "go get -tool golang.org/x/tools/gopls@v0.16.2 -zzz"],
  ["Bash", "cd app && npm i -D lodash@4.17.21 --tag x"],
  ["Bash", "env CI=1 npm i lodash@4.17.21 --tag x"],
  ["Bash", "timeout 60 pnpm add -D lodash@4.17.21 --zzz"],
  ["Bash", "bash -c 'npm i -D lodash@4.17.21 --tag x'"],
  ["PowerShell", "npm i -D lodash@4.17.21 --tag x"],
  ["PowerShell", "$env:npm_config_save_dev='true'; npm i lodash@4.17.21"],
  ["PowerShell", "pnpm add -D lodash@4.17.21 --zzz"],
];

let s: Sandbox;
beforeEach(() => {
  s = sandbox();
  s.ledger(BASE);
});
afterEach(() => s.dispose());

const run = (command: string, tool: string) => s.run({ session_id: "s", cwd: s.project, hook_event_name: "PreToolUse", tool_name: tool, tool_input: { command } });

describe("p1c: the remedy, followed mechanically, releases the same install", () => {
  it.each(LINES)("%s> %s", (tool, original) => {
    let command = original;
    const named: string[] = [];
    const pinnedNames: string[] = [];
    let last = run(command, tool);
    for (let step = 0; step < 5 && last.decision === "deny"; step++) {
      if (last.text.includes("could not be read")) {
        const next = followRemedy(command, last.text, "x");
        expect(next, last.text).not.toBeNull();
        const removed = /Run the same command without `([^`]+)`/.exec(last.text)?.[1];
        if (removed) named.push(removed);
        // Round 16 (J1): a name alone a project file above names (this machine's home package.json
        // names typescript) is written with a version: that operand is the remedy's, not lost.
        const pinned = /already names (\S+);/.exec(last.text)?.[1];
        if (pinned) pinnedNames.push(pinned);
        command = next as string;
      } else {
        // The dependency_check call the denial names, answered as the server records it: an exact
        // version as itself, a constraint as the release it resolves to (requested: the constraint).
        expect(last.items, last.text).not.toBeNull();
        record(
          s,
          (last.items ?? []).map((i) => {
            // (round 20, Q1: a crates.io bare version is the caret range, recorded with requested)
            const exact = /^(?:==)?v?\d+\.\d+\.\d+$/.test(i.to) && i.ecosystem !== "crates.io";
            const known = BASE.find((e) => e.ecosystem === i.ecosystem && e.package === i.package)?.version ?? "1.0.0";
            return { ecosystem: i.ecosystem, package: i.package, version: exact ? i.to.replace(/^==/, "") : known, verdict: "proceed", ...(exact ? {} : { requested: i.to }) };
          }),
        );
      }
      last = run(command, tool);
    }
    // (i) it goes ahead
    expect(last.decision, `${command}: ${last.text}`).toBe("allow");
    // (ii) the same placement flags, and every operand naming a package as written
    for (const flag of placement(original)) expect(placement(command.replace(/--save-dev=true/, "--save-dev")), `${flag} kept in ${command}`).toContain(flag);
    for (const word of original.split(/\s+/)) {
      if (!NAMES.some((n) => word.includes(n)) || named.some((t) => t.includes(word)) || pinnedNames.includes(word)) continue;
      expect(command.split(/\s+/), `${word} kept in ${command}`).toContain(word);
    }
    // the named parts are none of those
    for (const t of named) {
      expect(sig(t), t).toEqual([]);
      expect(
        NAMES.some((n) => t.includes(n)),
        t,
      ).toBe(false);
    }
  });
});
