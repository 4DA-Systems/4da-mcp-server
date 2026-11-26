// SPDX-License-Identifier: Apache-2.0
/**
 * Round 12, from the tenth independent check (the header read sentence by sentence): each item
 * with the reviewer's cases.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { sandbox, type Sandbox } from "./helpers/a1123-hookfix-run.js";
import { answerDenial } from "./helpers/a1125-hook-run.js";

let s: Sandbox;
beforeEach(() => {
  s = sandbox();
  s.ledger([]);
});
afterEach(() => s.dispose());

const run = (command: string, tool = "Bash", env: Record<string, string> = {}) => s.run({ session_id: "s", cwd: s.project, hook_event_name: "PreToolUse", tool_name: tool, tool_input: { command } }, env);

/** Held; answered as the denial says (when it names a call), it goes ahead. */
function releases(command: string, tool = "Bash"): void {
  const r = run(command, tool);
  if (r.decision === "deny") {
    expect(r.text, command).not.toContain("could not be read");
    answerDenial(s, r, "proceed");
    expect(run(command, tool).decision, command).toBe("allow");
  }
}

const I = "npm i lodash@4.17.20";

describe("1: sed and awk are never text; git under an editor / pager / GIT_* setting, make with a makefile option, neither", () => {
  it.each([
    [`echo a | sed '/[/p;s]/!e ${I} #]x]'`, "Bash"],
    ["echo a | sed -n --expression='/[/p;s]/!e pip install requests==2.5.0 #]x]'", "Bash"],
    ["cat f | sed '/[/d;s]/!e cargo add serde@1.0.0 #]x]'", "Bash"],
    [`echo a | awk -v x='${I}' '/[/{print "]/;BEGIN{system(x)};#"}'`, "Bash"],
    [`echo a | awk --field-separator '/x/' 'BEGIN{system("${I}")}'`, "Bash"],
    [`echo a | awk --assign 'NR==1' 'BEGIN{system("${I}")}'`, "Bash"],
    [`GIT_EDITOR='${I} #' git commit -a`, "Bash"],
    [`GIT_EXTERNAL_DIFF='${I} #' git diff`, "Bash"],
    [`export GIT_PAGER='${I} #'; git log`, "Bash"],
    [`EDITOR='${I}' git commit`, "Bash"],
    [`$env:GIT_EDITOR='${I} #'; git tag -a v1`, "PowerShell"],
    [`Set-Item env:GIT_PAGER '${I}'; git log`, "PowerShell"],
    [`make -f /dev/stdin <<'EOF'\nall:\n\t${I}\nEOF`, "Bash"],
    [`make --file=Makefile.x ${I}`, "Bash"],
    [`make --eval='all: ; ${I}'`, "Bash"],
  ])("%s: held", (command, tool) => {
    expect(run(command, tool).decision, command).toBe("deny");
    releases(I);
  });

  it("sed and awk get the grep / Write remedy", () => {
    expect(run("sed -n '/npm install/p' README.md").text).toContain("use grep, rg or Select-String");
  });

  it.each(["git commit -m 'docs: npm install lodash'", "git log --grep 'pip install'", "make -C docs install", "grep -rn 'npm install' docs"])("%s: still text", (command) => {
    expect(run(command).decision).toBe("allow");
  });
});
