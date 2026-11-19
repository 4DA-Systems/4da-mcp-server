// SPDX-License-Identifier: Apache-2.0
/**
 * README statements a reader can check, each held to the code, workflow or data that
 * makes it true: the environment table against the variables the server reads, the
 * Node versions against CI's matrix, the agent-evaluation releases against the
 * published results, and the conformance corpus figures against the fetched corpus.
 */
import { describe, it, expect } from "vitest";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { SERVER_INSTRUCTIONS } from "../server-instructions.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const text = (file: string) => readFileSync(join(root, file), "utf8");
const readme = text("README.md");

/** Shipped sources: everything under src/ except tests and the test setup. */
function shippedSources(dir = join(root, "src")): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name !== "__tests__") out.push(...shippedSources(full));
    } else if (entry.name.endsWith(".ts") && entry.name !== "test-setup.ts" && !entry.name.endsWith(".test.ts")) {
      out.push(full);
    }
  }
  return out;
}

/** The rows of the "Environment Variables" table: every backticked name in a row's first cell. */
function envTableNames(): Set<string> {
  const section = readme.split("## Environment Variables")[1]?.split("\n## ")[0] ?? "";
  const names = new Set<string>();
  for (const line of section.split("\n")) {
    const first = line.startsWith("| `") ? line.split("|")[1] : undefined;
    for (const m of first?.matchAll(/`([A-Z][A-Z0-9_]+)`/g) ?? []) names.add(m[1]!);
  }
  return names;
}

function envRow(name: string): string {
  const row = readme.split("\n").find((l) => l.startsWith(`| \`${name}\``));
  expect(row, `README environment table has no row for ${name}`).toBeDefined();
  return row!;
}

// Read by the server but not for users to set: each with the reason it is left out.
const NOT_FOR_USERS: Record<string, string> = {
  FOURDA_MAX_LOCKFILE_BYTES: "lowers the 64 MB read cap in tests",
  FOURDA_SQLITE_DRIVER: "forces one SQLite driver in tests and diagnostics",
};

describe("README environment table", () => {
  it("lists every FOURDA_ / MCP_ variable the server reads directly", () => {
    const read = new Map<string, string>();
    for (const file of shippedSources()) {
      for (const m of readFileSync(file, "utf8").matchAll(/\b(?:process\.env|env)\.((?:FOURDA|MCP)_[A-Z0-9_]+)/g)) {
        if (!read.has(m[1]!)) read.set(m[1]!, relative(root, file));
      }
    }
    expect(read.size).toBeGreaterThan(10);
    const table = envTableNames();
    const missing = [...read].filter(([name]) => !table.has(name) && !(name in NOT_FOR_USERS));
    expect(missing.map(([name, file]) => `${name} (read in ${file})`)).toEqual([]);
    for (const name of Object.keys(NOT_FOR_USERS)) expect(read.has(name), `${name} is no longer read; drop it from NOT_FOR_USERS`).toBe(true);
  });

  it("documents the embedding variables with the defaults the code uses", () => {
    const source = text("src/embeddings.ts");
    for (const name of ["FOURDA_EMBED_PROVIDER", "FOURDA_EMBED_MODEL", "OLLAMA_URL", "OPENAI_API_KEY"]) {
      expect(source, `${name} is documented but src/embeddings.ts does not read it`).toContain(`process.env.${name}`);
      envRow(name);
    }
    const constant = (id: string) => {
      const m = source.match(new RegExp(`const ${id} = "([^"]+)"`));
      expect(m, `src/embeddings.ts no longer defines ${id}`).not.toBeNull();
      return m![1]!;
    };
    expect(envRow("FOURDA_EMBED_MODEL")).toContain(constant("DEFAULT_OLLAMA_EMBED_MODEL"));
    expect(envRow("FOURDA_EMBED_MODEL")).toContain(constant("DEFAULT_OPENAI_EMBED_MODEL"));
    expect(envRow("OLLAMA_URL")).toContain(constant("DEFAULT_OLLAMA_URL"));
  });

  it("documents FOURDA_DATA_DIR, which the database and settings lookups read", () => {
    expect(text("src/db.ts")).toContain("env.FOURDA_DATA_DIR");
    expect(envRow("FOURDA_DATA_DIR")).toMatch(/4da\.db/);
  });
});

describe("README statements against the repository", () => {
  it("names exactly the Node versions CI's test matrix runs", () => {
    const ci = text(".github/workflows/ci.yml");
    const matrix = ci.split(/\n {2}test:\n/)[1]?.split(/\n {2}[a-z-]+:\n/)[0] ?? "";
    const versions = [...new Set([...matrix.matchAll(/\bnode: "([0-9.]+)"/g)].map((m) => m[1]!))];
    expect(versions.length).toBeGreaterThan(0);
    const sentence = readme.split("\n").find((l) => l.includes("CI runs the suite on"));
    expect(sentence, "README no longer says which Node versions CI runs").toBeDefined();
    const named = new Set([...sentence!.matchAll(/\b(\d\d(?:\.\d+)?)\b/g)].map((m) => m[1]!));
    expect([...named].sort()).toEqual([...versions].sort());
  });

  it("dates the agent evaluation to the releases whose results are published", () => {
    const published = readdirSync(join(root, "bench/g7/results"))
      .map((f) => f.match(/^summary-final-(\d)(\d)(\d)\.json$/))
      .filter((m): m is RegExpMatchArray => m !== null)
      .map((m) => `${m[1]}.${m[2]}.${m[3]}`);
    expect(published.length).toBeGreaterThan(0);
    const sentence = readme.split("\n").find((l) => l.startsWith("Measured with a coding agent"));
    expect(sentence).toBeDefined();
    const named = [...sentence!.matchAll(/\b(\d+\.\d+\.\d+)\b/g)].map((m) => m[1]!);
    expect(named.sort()).toEqual(published.sort());
  });

  it("carries no figure that has no harness or result in this repository", () => {
    for (const gone of ["about 4k tokens", "290-advisory", "19 public repositories", "19,115", "Real output"]) {
      expect(readme, gone).not.toContain(gone);
    }
    // The breaking-change gold: the raters were model instances (CHANGELOG 6.2.0).
    expect(readme).toMatch(/three blind raters, each a model instance/);
    // The GitHub comparison is dated to the release it measured and says its cases are not here.
    const faq = readme.split("\n").find((l) => l.includes("216 identical cases"));
    expect(faq).toMatch(/6\.2\.7/);
    expect(faq).toMatch(/not published in this repository/);
  });

  it("tells agents that a STALE answer is not a clean one", () => {
    expect(SERVER_INSTRUCTIONS).toMatch(/NOT CHECKED or STALE\b[^\n]*? is incomplete, never clean/);
    expect(text("src/live/scan-coverage.ts")).toContain("`STALE: ");
  });
});

// Corpus-gated: CI's conformance job runs this file with the corpus fetched and fails it on a skip.
const corpus = resolve(process.env.FOURDA_CONFORMANCE_DIR ?? join(root, "conformance", "corpus"));

describe.skipIf(!existsSync(join(corpus, "osv-snapshot.json")))("README conformance figures against the fetched corpus", () => {
  it("counts the cases and the pinned records the corpus holds", () => {
    const cases = readdirSync(join(corpus, "cases"), { withFileTypes: true }).filter((d) => d.isDirectory());
    const synthetic = cases.filter((d) => JSON.parse(readFileSync(join(corpus, "cases", d.name, "case.json"), "utf8")).source === "synthetic");
    const snapshot = JSON.parse(readFileSync(join(corpus, "osv-snapshot.json"), "utf8")) as { records: number; synthetic: number };
    const n = (x: number) => x.toLocaleString("en-US");
    expect(readme).toContain(`${cases.length} cases (${cases.length - synthetic.length} public repositories at pinned commits, ${synthetic.length} synthetic)`);
    expect(readme).toContain(`${n(snapshot.records)} OSV records pinned as OSV.dev served them (and ${snapshot.synthetic} synthetic rule records)`);
    expect(readFileSync(join(corpus, "README.md"), "utf8")).toContain("osv-scanner 2.6.0");
    expect(readme).toContain("osv-scanner 2.6.0");
  });
});
