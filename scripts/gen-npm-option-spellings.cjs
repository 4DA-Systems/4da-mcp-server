// SPDX-License-Identifier: Apache-2.0
// Round 34 (B1): generates src/__tests__/fixtures/a1125-npm-spellings.json from npm's own parser.
// Run with the npm whose parser is the reference: `node scripts/gen-npm-option-spellings.cjs <npm folder>`
// (for example D:/node.js/node_modules/npm). For every spelling of every npm option (the full name
// and each prefix, with one and with two dashes, and its negated form) and every two-letter cluster, nopt with npm's own
// definitions and shorthands says whether the word after it is consumed as its value.
const fs = require("node:fs");
const path = require("node:path");
const npm = process.argv[2];
if (!npm) throw new Error("usage: gen-npm-option-spellings.cjs <npm folder>");
const nopt = require(path.join(npm, "node_modules", "nopt"));
const { definitions, shorthands } = require(path.join(npm, "node_modules", "@npmcli", "config", "lib", "definitions"));
const types = Object.fromEntries(Object.entries(definitions).map(([k, d]) => [k, d.type]));
const short = { ...shorthands };
const spellings = new Set();
for (const name of Object.keys(types)) {
  for (let n = 2; n <= name.length; n++) {
    spellings.add(`--${name.slice(0, n)}`);
    spellings.add(`-${name.slice(0, n)}`);
  }
  // Round 35 (C1): the negated form of every option: nopt gives a value option its next word even then.
  spellings.add(`--no-${name}`);
}
const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
for (const a of letters) for (const b of letters) spellings.add(`-${a}${b}`);
for (const a of letters) spellings.add(`-${a}`);
const out = [];
for (const opt of [...spellings].sort()) {
  let consumed;
  try {
    const parsed = nopt(types, short, [opt, "ls", "install"], 0);
    consumed = parsed.argv.remain[0] !== "ls";
  } catch {
    consumed = null;
  }
  if (consumed !== null) out.push({ opt, consumed });
}
const version = require(path.join(npm, "package.json")).version;
const file = path.join(__dirname, "..", "src", "__tests__", "fixtures", "a1125-npm-spellings.json");
fs.writeFileSync(file, JSON.stringify({ npm: version, source: "nopt with npm's definitions and shorthands", spellings: out }) + "\n");
console.log(`${out.length} spellings, npm ${version}`);
