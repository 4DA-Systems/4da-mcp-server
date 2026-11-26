// SPDX-License-Identifier: Apache-2.0
/**
 * Round 14 (R3, R4, R5, R6, R8), from the twelfth independent check: rules decided on the raw text
 * of the call, with the reviewer's cases.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { sandbox, type Sandbox } from "./helpers/a1123-hookfix-run.js";

let s: Sandbox;
beforeEach(() => {
  s = sandbox();
  s.ledger([{ ecosystem: "npm", package: "lodash", version: "4.17.20", verdict: "avoid", reason: "test avoid" }]);
});
afterEach(() => s.dispose());

const run = (command: string, tool = "Bash") => s.run({ session_id: "s", cwd: s.project, hook_event_name: "PreToolUse", tool_name: tool, tool_input: { command } });

describe("R3: a blank the shell may split at that the hook's words do not", () => {
  const blanks = ["\u00a0", "\u2000", "\u2007", "\u200a", "\u202f", "\u3000", "\u000b", "\u000c", "\u0085", "\u200b", "\u200e", "\u2066", "\ufeff", "\u1680"];
  it.each(blanks.map((b) => [(b.codePointAt(0) ?? 0).toString(16), b]))("U+%s between the words of an install: held, with the retype remedy", (_cp, b) => {
    const rows: [string, string][] = [
      [`'npm${b}install lodash@4.17.20'`, "PowerShell"],
      [`npm${b}install${b}lodash@4.17.20`, "Bash"],
      [`echo a${b}npm install lodash@4.17.20`, "PowerShell"],
    ];
    for (const [command, tool] of rows) {
      const r = run(command, tool);
      expect(r.decision, command).toBe("deny");
      expect(r.text).toContain("invisible or unusual blank character");
      expect(r.text).toContain("retype it with plain spaces");
    }
  });
  it("a quoted string with plain spaces is still text when it begins with a quote", () => {
    expect(run("'npm install lodash' | Out-File -FilePath notes.txt", "PowerShell").decision).toBe("allow");
  });
  it("an unusual blank where no install is named goes ahead", () => {
    expect(run("echo caf\u00e9\u00a0au lait").decision).toBe("allow");
  });
});

describe("R4: a manager's setting named anywhere before or on the install line is held", () => {
  it.each([
    ["New-Item -Path Env: -Name npm_config_before -Value 2020-01-01; npm install lodash", "PowerShell"],
    ["New-Item Env:\\npm_config_before -Value 2020-01-01; npm install lodash", "PowerShell"],
    ["Set-Item -Path Env:\\npm_config_before -Value 2020-01-01; npm install lodash", "PowerShell"],
    ["cd env:; Set-Item npm_config_before 2020-01-01; cd C:\\; npm install lodash", "PowerShell"],
    ["builtin export npm_config_before=2020-01-01; npm install lodash", "Bash"],
    ["command export npm_config_before=2020-01-01; npm install lodash", "Bash"],
    ["eval export npm_config_before=2020-01-01; npm install lodash", "Bash"],
    ["eval 'export npm_config_before=2020-01-01'; npm install lodash", "Bash"],
    ["set -o allexport; printf -v npm_config_before 2020-01-01; npm install lodash", "Bash"],
    ["NPM_CONFIG_BEFORE=2020-01-01 npm install lodash", "Bash"],
    ["go env -w GOFLAGS=-mod=mod && go get rsc.io/quote", "Bash"],
  ])("%s", (command, tool) => {
    expect(run(command, tool).text, command).toContain("which a package manager reads");
  });
  it.each([
    ["export npm_config_save_dev=true; npm install ms@2.1.3", "--save-dev"],
    ["export npm_config_save_exact=true && npm install ms@2.1.3", "--save-exact"],
    ["npm_config_global=true npm install typescript@5.6.3", "--global"],
    ["NPM_CONFIG_SAVE_OPTIONAL=true npm install ms@2.1.3", "--save-optional"],
  ])("a placement setting (%s) is to be written as its option %s, in the export form too", (command, option) => {
    expect(run(command).text).toContain("written as `" + option + "` on the package manager's command");
  });
  it("a setting named only after the install line holds nothing", () => {
    expect(run("npm install lodash@4.17.21\nexport npm_config_before=2020-01-01").text).not.toContain("which a package manager reads");
  });
});

describe("R5: xargs, aliases, functions, iex and & with a string beside a manager's name", () => {
  it.each([
    ["echo 'install lodash@4.17.20' | xargs npm", "Bash"],
    ["xargs npm < args.txt", "Bash"],
    ["printf 'i\\nlodash@4.17.20\\n' | xargs npm", "Bash"],
    ["Set-Alias n npm; n install lodash@4.17.20", "PowerShell"],
    ["New-Alias -Name n -Value npm; n i lodash@4.17.20", "PowerShell"],
    ["alias n=npm; n install lodash@4.17.20", "Bash"],
    ["function n { npm @args }; n install lodash@4.17.20", "PowerShell"],
    ['n() { npm "$@"; }; n install lodash@4.17.20', "Bash"],
    ["iex 'npm install lodash@4.17.20'", "PowerShell"],
    ['Invoke-Expression "npm i lodash@4.17.20"', "PowerShell"],
    ["& 'npm' install lodash@4.17.20", "PowerShell"],
    ['& "C:/Program Files/nodejs/npm.cmd" install lodash@4.17.20', "PowerShell"],
  ])("%s: held", (command, tool) => {
    const r = run(command, tool);
    expect(r.decision, command).toBe("deny");
    expect(r.text).toContain("could not be read");
  });
  it("xargs with no manager's name goes ahead", () => {
    expect(run("find . -name '*.tmp' | xargs rm").decision).toBe("allow");
  });
});

describe("R6: pip spelled with more after it", () => {
  it.each([
    "python -m pip.__main__ install requests==2.25.0",
    "python -m pip._internal install requests==2.25.0",
    "py -m pip install requests==2.25.0",
    "python3.12 -m pip install requests==2.25.0",
    "python -mpip.__main__ install requests==2.25.0",
  ])("%s: read as pip, judged", (command) => {
    const r = run(command);
    expect(r.decision).toBe("deny");
    expect(r.text).not.toContain("could not be read");
    expect(r.items?.[0]?.package).toBe("requests");
  });
});

describe("R8: code given on the line is text only alone and not fed from a pipe", () => {
  it.each([
    `echo 'npm install lodash@4.17.20' | python -c "import os,sys;os.system(sys.stdin.read())"`,
    `echo 'npm install lodash@4.17.20' | node -e "require('child_process').execSync(require('fs').readFileSync(0,'utf8'))"`,
    `python -c "import subprocess,sys;subprocess.run(sys.argv[1:])" npm install lodash@4.17.20`,
    `node -e "require('child_process').execFileSync(process.argv[1],process.argv.slice(2))" npm install lodash@4.17.20`,
  ])("%s: held", (command) => {
    expect(run(command).decision, command).toBe("deny");
  });
  it("code alone that only mentions an install goes ahead", () => {
    expect(run(`node -e "console.log('run npm install first')"`).decision).toBe("allow");
  });
});

describe("npm's command word in capitals", () => {
  it.each(["npm I lodash@4.17.20", "npm INSTALL lodash@4.17.20"])("%s: held", (command) => {
    expect(run(command).decision).toBe("deny");
  });
});
