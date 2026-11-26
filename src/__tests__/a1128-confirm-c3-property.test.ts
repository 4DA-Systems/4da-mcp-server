// SPDX-License-Identifier: Apache-2.0
/**
 * Wave 2, C3: the reader is not trusted for safe_to_delegate. A property test of the raw-text command detector
 * (briefing-command-check.ts): a generated command, with options this server has never heard of and operands
 * it has never seen, is reported unread whenever one package operand is not accounted for. The detector reads
 * no list of each manager's options, so the 16 forms the second independent check found (and the next ones)
 * fall to it. Deterministic: a seeded generator, no network, nothing read outside the repository.
 */
import { describe, expect, it } from "vitest";
import { scanCommands, unreadCommand } from "../tools/briefing-command-check.js";
import type { CheckEcosystem } from "../live/release-metadata.js";

/** mulberry32: a small seeded generator, so a failure replays. */
function rng(seed: number) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const FORMS: Array<{ head: string; ecosystem: CheckEcosystem }> = [
  ...["npm install", "npm i", "npm add", "npm x", "npm exec", "npm init", "npm create", "npm update", "npm it", "npm isntall"].map((head) => ({ head, ecosystem: "npm" as const })),
  ...["pnpm add", "pnpm install", "pnpm dlx", "pnpm create", "pnpm up", "pnpm update", "yarn add", "yarn up", "yarn dlx", "yarn create", "bun add", "bun x", "bun create", "bunx", "npx", "pnpx"].map((head) => ({ head, ecosystem: "npm" as const })),
  ...["pip install", "pip3 install", "python -m pip install", "pipx install", "pipx inject black", "pipx run --spec", "uv add", "uv pip install", "uv tool install", "uv tool run", "uvx", "poetry add"].map((head) => ({ head, ecosystem: "PyPI" as const })),
  ...["cargo add", "cargo install", "cargo binstall"].map((head) => ({ head, ecosystem: "crates.io" as const })),
  ...["go get", "go install"].map((head) => ({ head, ecosystem: "Go" as const })),
];
const WRAP = [(c: string) => c, (c: string) => `Please run \`${c}\` for me.`, (c: string) => `First ${c}, then wire it into the router.`, (c: string) => `cd app && ${c} && npm test`];

function name(r: () => number, ecosystem: CheckEcosystem): string {
  const stem = `zq${Math.floor(r() * 1e6).toString(36)}`;
  if (ecosystem === "Go") return `example.com/zqx/${stem}`;
  return r() < 0.2 && ecosystem === "npm" ? `@zqs/${stem}` : stem;
}

function option(r: () => number): { text: string; hasValue: boolean } {
  const id = Math.floor(r() * 1e4).toString(36);
  const pick = r();
  // Short options no manager knows (round 6: a known switch such as -q takes no value; these do not hide a word).
  if (pick < 0.4) return { text: `-${"mZKjXk"[Math.floor(r() * 6)]}`, hasValue: false };
  if (pick < 0.8) return { text: `--zq-flag-${id}`, hasValue: false };
  return { text: `--zq-key-${id}=zqv${id}`, hasValue: true };
}

describe("C3: a command with unknown options and operands is never read whole unless every operand is accounted for", () => {
  it("2,000 generated commands", () => {
    const r = rng(20261128);
    for (let n = 0; n < 2000; n++) {
      const form = FORMS[Math.floor(r() * FORMS.length)];
      const opts = Array.from({ length: Math.floor(r() * 4) }, () => option(r));
      // A runner runs one package: the words after it are the program's arguments (round 4, contract K2).
      const runner = /^(?:npx|pnpx|bunx|uvx|npm x|npm exec|pnpm dlx|yarn dlx|bun x|pipx run --spec|uv tool run)$/.test(form.head);
      const operands = Array.from({ length: runner ? 1 : 1 + Math.floor(r() * 3) }, () => ({ name: name(r, form.ecosystem), accounted: r() < 0.5 }));
      const versioned = operands.map((o) => (r() < 0.3 ? (form.ecosystem === "PyPI" ? `${o.name}==1.0.1` : form.ecosystem === "Go" ? `${o.name}@v1.0.1` : `${o.name}@1.0.1`) : o.name));
      // Options and operands interleaved: an unknown option before an operand never hides it.
      const words: string[] = [];
      versioned.forEach((v, i) => {
        if (opts[i]) words.push(opts[i].text);
        words.push(v);
      });
      for (const o of opts.slice(versioned.length)) words.push(o.text);
      const command = `${form.head} ${words.join(" ")}`;
      const task = WRAP[Math.floor(r() * WRAP.length)](command);
      // `pipx inject black X`: black is an operand too (the app it injects into), accounted for here.
      const ok = new Set([...operands.filter((o) => o.accounted).map((o) => `${form.ecosystem}|${o.name}`), "PyPI|black"]);
      const accounted = (ecosystem: CheckEcosystem, x: string) => ok.has(`${ecosystem}|${x}`);
      const unread = unreadCommand(task, accounted);
      const label = `#${n}: ${task}`;
      // Round 6, item 3: the word after an option not known to take no value is that option's value: never an
      // operand, and the command is not read whole (it stands as "the word after <option>").
      const hides = versioned.some((_v, i) => opts[i] !== undefined && !opts[i].hasValue);
      if (operands.some((o) => !o.accounted) || hides) expect(unread, label).not.toBeNull();
      // Every operand accounted and no word taken as a value: the command is read whole.
      else expect(unread, label).toBeNull();
    }
  });

  it("the 16 forms the second independent check found are each a command with its operand", () => {
    const forms = [
      "pnpm add -w zqxevil", "pnpm add -D -w zqxevil", "npm i -m zqxevil", "npm i -c zqxevil", "pnpm add -L zqxevil", "yarn up zqxevil", "npm x zqxevil",
      "bun x zqxevil", "npm init zqxevil", "yarn create zqxevil", "pnpm create zqxevil", "bun create zqxevil", "uv run --with zqxevil s.py", "cargo binstall zqxevil",
      "pipx inject black zqxevil", "pipx run --spec zqxevil flask",
    ];
    for (const f of forms) {
      const unread = unreadCommand(f, (_e, n) => n !== "zqxevil");
      expect(unread?.text, f).toBe(f);
    }
  });

  it("prose installs, aliases and deno specifiers name their packages", () => {
    const none = () => false;
    expect(unreadCommand("Install zqxevil with npm.", none)?.operands).toEqual(["zqxevil"]);
    expect(unreadCommand("npm i lodash@npm:zqxevil", (_e, n) => n === "lodash")).not.toBeNull();
    expect(unreadCommand("deno run npm:zqxevil", none)).not.toBeNull();
    expect(unreadCommand("deno run main.ts", none)).toBeNull();
  });

  it("paths, URLs, requirement files, scripts and no operand at all are read whole", () => {
    const none = () => false;
    for (const t of ["npm install", "npm install ./packages/zqx-local", "pip install -r requirements.txt", "pip install -e .", "npm install https://example.com/zqx.tgz", "uv run --with requests s.py", "go get ./...", "cargo install --path ."]) {
      const unread = unreadCommand(t, (e, n) => n === "requests" && e === "PyPI");
      expect(unread, t).toBeNull();
    }
    expect(scanCommands("npm test and cargo build").length).toBe(0);
    expect(unreadCommand("Run npm test.", none)).toBeNull();
  });

  it("stays linear on a long run of punctuation", () => {
    const t0 = process.cpuUsage();
    unreadCommand(`npm install x${".".repeat(150_000)}:1 ${"y ".repeat(50_000)}`, () => false);
    const used = process.cpuUsage(t0);
    expect((used.user + used.system) / 1000).toBeLessThan(500);
  });
});
