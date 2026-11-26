// SPDX-License-Identifier: Apache-2.0
/**
 * Round 14 (R1, R10b): every option on the allow lists, beside a named package, leaves the named
 * package and its version exactly as the command names them: the denial asks for that one item and
 * nothing else (no option value is ever offered to dependency_check as a package), and the call goes
 * ahead once it is answered. This is the tested property of the lists, not a proof: the tools' own
 * behaviour is taken from their help.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { NAMED_OPTIONS } from "../../hooks/manifest-edit.mjs";
import { sandbox, type Sandbox } from "./helpers/a1123-hookfix-run.js";
import { answerDenial } from "./helpers/a1125-hook-run.js";

let s: Sandbox;
beforeEach(() => {
  s = sandbox();
  s.ledger([]);
});
afterEach(() => s.dispose());

const run = (command: string) => s.run({ session_id: "s", cwd: s.project, hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command } });

/** Each list's command, and the one item it names. */
const COMMAND: Record<string, [string, { ecosystem: string; package: string; to: string }]> = {
  npm: ["npm install {} lodash@4.17.21", { ecosystem: "npm", package: "lodash", to: "4.17.21" }],
  pnpm: ["pnpm add {} lodash@4.17.21", { ecosystem: "npm", package: "lodash", to: "4.17.21" }],
  yarn: ["yarn add {} lodash@4.17.21", { ecosystem: "npm", package: "lodash", to: "4.17.21" }],
  bun: ["bun add {} lodash@4.17.21", { ecosystem: "npm", package: "lodash", to: "4.17.21" }],
  poetry: ["poetry add {} requests==2.32.3", { ecosystem: "PyPI", package: "requests", to: "2.32.3" }],
  pip: ["pip install {} requests==2.32.3", { ecosystem: "PyPI", package: "requests", to: "2.32.3" }],
  uvpip: ["uv pip install {} requests==2.32.3", { ecosystem: "PyPI", package: "requests", to: "2.32.3" }],
  uvadd: ["uv add {} requests==2.32.3", { ecosystem: "PyPI", package: "requests", to: "2.32.3" }],
  uvtool: ["uv tool install {} ruff==0.6.9", { ecosystem: "PyPI", package: "ruff", to: "0.6.9" }],
  cargoadd: ["cargo add {} serde@1.0.200", { ecosystem: "crates.io", package: "serde", to: "1.0.200" }],
  cargoinstall: ["cargo install {} ripgrep@14.1.1", { ecosystem: "crates.io", package: "ripgrep", to: "14.1.1" }],
  goget: ["go get {} rsc.io/quote@v1.5.2", { ecosystem: "Go", package: "rsc.io/quote", to: "v1.5.2" }],
  goinstall: ["go install {} golang.org/x/tools/gopls@v0.16.2", { ecosystem: "Go", package: "golang.org/x/tools/gopls", to: "v0.16.2" }],
  gomodedit: ["go mod edit {} -require=rsc.io/quote@v1.5.2", { ecosystem: "Go", package: "rsc.io/quote", to: "v1.5.2" }],
};

/** Options whose own meaning is another rule: a file, another named package, a non-registry source, a removal. */
const OWN_RULE = new Set([
  "pip -e", "pip --editable", "pip -r", "pip --requirement", "pip -c", "pip --constraint",
  "uvpip -e", "uvpip --editable", "uvpip -r", "uvpip --requirements", "uvpip -c", "uvpip --constraints", "uvpip -P", "uvpip --upgrade-package",
  "uvadd -c", "uvadd --constraints", "uvtool -c", "uvtool --constraints", "uvtool --with",
  "cargoinstall --version", "cargoinstall --vers", "cargoinstall --git", "cargoinstall --branch", "cargoinstall --tag", "cargoinstall --rev", "cargoinstall --path",
  "gomodedit -require", "gomodedit -droprequire", "poetry --optional", "pnpm -L", "pnpm --latest", "yarn -L", "yarn --latest",
]);

const ROWS: [string, string, string][] = [];
for (const [key, rows] of Object.entries(NAMED_OPTIONS as Record<string, [string, string][]>)) {
  for (const [spec] of rows) {
    for (const w of spec.split(" ")) {
      const name = w.replace(/[=?]$/, "");
      if (OWN_RULE.has(`${key} ${name}`)) continue;
      ROWS.push([key, name, w.endsWith("=") ? `${name} x1` : name]);
    }
  }
}

describe("each allowed option beside a named package names that package alone, and the call passes once answered", () => {
  it("the lists are not empty", () => {
    expect(ROWS.length).toBeGreaterThan(150);
  });
  it.each(ROWS)("%s %s", (key, _name, option) => {
    const [template, item] = COMMAND[key];
    const command = template.replace("{}", option);
    const r = run(command);
    expect(r.decision, r.text).toBe("deny");
    expect(r.text, command).not.toContain("could not be read");
    expect(r.items, command).toEqual([item]);
    answerDenial(s, r, "proceed");
    expect(run(command).decision, command).toBe("allow");
  });
});

describe("an option off the list beside a named package is held, and the remedy names the option alone", () => {
  it.each([
    ["npm install -D --offline ms@2.1.3", "--offline"],
    ["npm install -D --offl ms@2.1.3", "--offl"],
    ["npm install -D --no-offline ms@2.1.3", "--no-offline"],
    ["npm install -D --offline=false ms@2.1.3", "--offline=false"],
    ["npm install --userconfig x.npmrc ms@2.1.3", "--userconfig"],
    ["npm install --globalconfig x ms@2.1.3", "--globalconfig"],
    ["bun add --os linux ms@2.1.3", "--os"],
    ["bun add --cpu arm64 ms@2.1.3", "--cpu"],
    ["bun add --linker isolated ms@2.1.3", "--linker"],
    ["bun add --ca x ms@2.1.3", "--ca"],
    ["uv pip install --allow-insecure-host x six==1.17.0", "--allow-insecure-host"],
    ["uv add --config-file uv.toml six==1.17.0", "--config-file"],
    ["uv add --python 3.12 six==1.17.0", "--python"],
    ["pip install --prefer-binary six==1.17.0", "--prefer-binary"],
    ["pip install --python 3.12 six==1.17.0", "--python"],
    ["cargo install --offline ripgrep@14.1.1", "--offline"],
    ["cargo install --frozen ripgrep@14.1.1", "--frozen"],
    ["cargo add --config net.offline=true serde@1.0.200", "--config"],
    ["cargo install --config 'source.crates-io.replace-with=\"x\"' ripgrep@14.1.1", "--config"],
    ["yarn add --mode skip-build ms@2.1.3", "--mode"],
    ["uv add --only-binary :all: six==1.17.0", "--only-binary"],
  ])("%s", (command, token) => {
    const r = run(command);
    expect(r.text, command).toContain("could not be read");
    expect(r.text).toContain(`Run the same command without the option \`${token}\`; if that option takes a value, remove its value too`);
    expect(r.items ?? [], command).toEqual([]);
  });

  it("the remedy never takes a package with it: `npm install -D --offline ms@2.1.3`", () => {
    const r = run("npm install -D --offline ms@2.1.3");
    expect(r.text).not.toContain("`--offline ms@2.1.3`");
  });
});

describe("R2: index and registry options beside a named package", () => {
  it.each([
    "pip install -i https://pypi.corp.example/simple six==1.17.0",
    "uv pip install --index-url https://pypi.corp.example/simple six==1.17.0",
    "uv add --default-index https://pypi.corp.example/simple six==1.17.0",
    "npm install --registry https://npm.corp.example ms@2.1.3",
  ])("exactly one replacing index, positively not public: the project's own source, %s", (command) => {
    expect(run(command).decision).toBe("allow");
  });
  it.each([
    "pip install -i https://pypi.corp.example/simple --extra-index-url https://pypi.org/simple six==1.17.0",
    "pip install -i https://pypi.corp.example/simple --index https://pypi.org/simple six==1.17.0",
    "uv pip install --index-url https://pypi.corp.example/simple --extra-index-url https://pypi.org/simple six==1.17.0",
    "uv add --default-index https://pypi.corp.example/simple --index https://pypi.org/simple six==1.17.0",
    "pip install -i https://pypi.corp.example/simple -f https://pypi.org/simple six==1.17.0",
    "pip install --extra-index-url https://pypi.corp.example/simple six==1.17.0",
    "uv add --index https://pypi.corp.example/simple six==1.17.0",
    "pip install --no-index six==1.17.0",
    "pip install -i https://pypi.org/simple six==1.17.0",
    "cargo add --registry corp serde@1.0.200",
  ])("any other combination is held: %s", (command) => {
    expect(run(command).text).toContain("could not be read");
  });
});
