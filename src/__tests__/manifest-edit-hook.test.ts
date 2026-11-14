// SPDX-License-Identifier: Apache-2.0
/**
 * The plugin's PostToolUse hook (hooks/manifest-edit.mjs), exercised the way
 * Claude Code runs it: a separate Node process reading the edit on stdin.
 * It must speak only when a manifest edit changes a dependency version, and
 * must never fail or delay an edit it does not understand.
 */

import { describe, it, expect } from "vitest";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";

const HOOK = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "hooks", "manifest-edit.mjs");

function run(payload: unknown): { status: number | null; stdout: string } {
  const res = spawnSync(process.execPath, [HOOK], {
    input: typeof payload === "string" ? payload : JSON.stringify(payload),
    encoding: "utf8",
    timeout: 10_000,
  });
  return { status: res.status, stdout: res.stdout };
}

function context(stdout: string): string {
  const parsed = JSON.parse(stdout) as { hookSpecificOutput: { hookEventName: string; additionalContext: string } };
  expect(parsed.hookSpecificOutput.hookEventName).toBe("PostToolUse");
  return parsed.hookSpecificOutput.additionalContext;
}

describe("manifest-edit hook", () => {
  it("names a crate upgrade and the exact upgrade_impact call", () => {
    const { status, stdout } = run({
      tool_name: "Edit",
      tool_input: { file_path: "src-tauri/Cargo.toml", old_string: 'fastembed = "5"\nserde = "1"', new_string: 'fastembed = "7.1.0"\nserde = "1"' },
    });
    expect(status).toBe(0);
    const text = context(stdout);
    expect(text).toContain("fastembed: 5 -> 7.1.0");
    expect(text).toContain('upgrade_impact {"package":"fastembed","to_version":"7.1.0","ecosystem":"crates.io"}');
    expect(text).not.toContain("serde");
  });

  it("reads package.json ranges and table-form Cargo versions, across MultiEdit edits", () => {
    const npm = run({
      tool_name: "MultiEdit",
      tool_input: {
        file_path: "package.json",
        edits: [
          { old_string: '"vite": "^6.0.0"', new_string: '"vite": "^7.0.0"' },
          { old_string: '"@tauri-apps/api": "2.11.1"', new_string: '"@tauri-apps/api": "2.12.0"' },
        ],
      },
    });
    const text = context(npm.stdout);
    expect(text).toContain("vite: ^6.0.0 -> ^7.0.0");
    expect(text).toContain('upgrade_impact {"package":"@tauri-apps/api","to_version":"2.12.0","ecosystem":"npm"}');
    // The exact pin is checked as that version, the vite range as a constraint (its safe releases).
    expect(text).toContain(
      'dependency_check {"items":[{"ecosystem":"npm","package":"vite","to":"^7.0.0"},{"ecosystem":"npm","package":"@tauri-apps/api","to":"2.12.0","from":"2.11.1"}]}',
    );

    const cargo = run({
      tool_name: "Edit",
      tool_input: { file_path: "Cargo.toml", old_string: 'tokio = { version = "1.40", features = ["full"] }', new_string: 'tokio = { version = "1.47", features = ["full"] }' },
    });
    expect(context(cargo.stdout)).toContain("tokio: 1.40 -> 1.47");
    expect(context(cargo.stdout)).toContain('dependency_check {"items":[{"ecosystem":"crates.io","package":"tokio","to":"1.47"}]}');
  });

  it("names the dependency_check and upgrade_impact calls for Python and Go edits", () => {
    const py = context(
      run({
        tool_name: "Edit",
        tool_input: { file_path: "requirements.txt", old_string: "django==4.2.16", new_string: "django==5.1" },
      }).stdout,
    );
    expect(py).toContain('django: ==4.2.16 -> ==5.1; check with upgrade_impact {"package":"django","to_version":"5.1","ecosystem":"PyPI"}');
    expect(py).toContain('dependency_check {"items":[{"ecosystem":"PyPI","package":"django","to":"5.1","from":"4.2.16"}]}');

    const go = context(
      run({
        tool_name: "Edit",
        tool_input: { file_path: "go.mod", old_string: "\tgithub.com/spf13/cobra v1.8.0", new_string: "\tgithub.com/spf13/cobra v1.10.2" },
      }).stdout,
    );
    expect(go).toContain('upgrade_impact {"package":"github.com/spf13/cobra","to_version":"1.10.2","ecosystem":"Go"}');
    expect(go).toContain('dependency_check {"items":[{"ecosystem":"Go","package":"github.com/spf13/cobra","to":"v1.10.2","from":"v1.8.0"}]}');
  });

  it("stays silent for non-manifest files, unchanged versions, Write and bad input", () => {
    for (const payload of [
      { tool_name: "Edit", tool_input: { file_path: "src/main.rs", old_string: "a", new_string: "b" } },
      { tool_name: "Edit", tool_input: { file_path: "package.json", old_string: '"name": "x"', new_string: '"name": "y"' } },
      { tool_name: "Write", tool_input: { file_path: "package.json", content: '{"dependencies":{"vite":"^7.0.0"}}' } },
      "not json",
      {},
    ]) {
      const { status, stdout } = run(payload);
      expect(status).toBe(0);
      expect(stdout).toBe("");
    }
  });
});

describe("manifest-edit hook: only dependency sections declare dependencies (pre-publish audit of 5d709ff)", () => {
  const silent = (payload: unknown) => {
    const { status, stdout } = run(payload);
    expect(status).toBe(0);
    expect(stdout).toBe("");
  };

  it("package.json: the package's own version and engines are not dependencies", () => {
    silent({ tool_name: "Edit", tool_input: { file_path: "package.json", old_string: '"version": "1.0.0"', new_string: '"version": "1.1.0"' } });
    silent({ tool_name: "Edit", tool_input: { file_path: "package.json", old_string: '"engines": { "node": ">=18" }', new_string: '"engines": { "node": ">=20" }' } });
    const text = context(
      run({
        tool_name: "Edit",
        tool_input: {
          file_path: "package.json",
          old_string: '{\n  "name": "app",\n  "version": "1.0.0",\n  "dependencies": {\n    "vite": "^6.0.0"\n  }\n}',
          new_string: '{\n  "name": "app",\n  "version": "1.1.0",\n  "dependencies": {\n    "vite": "^7.0.0"\n  }\n}',
        },
      }).stdout,
    );
    expect(text).toContain("vite: ^6.0.0 -> ^7.0.0");
    expect(text).not.toMatch(/\bversion:/);
  });

  it("an edit that does not show its section is placed by the manifest on disk", () => {
    const dir = mkdtempSync(join(tmpdir(), "4da-hook-"));
    try {
      const pkg = join(dir, "package.json");
      writeFileSync(pkg, JSON.stringify({ name: "app", version: "1.1.0", engines: { node: ">=20" }, dependencies: { vite: "^7.0.0" } }, null, 2));
      silent({ tool_name: "Edit", tool_input: { file_path: pkg, old_string: '"node": ">=18"', new_string: '"node": ">=20"' } });
      expect(context(run({ tool_name: "Edit", tool_input: { file_path: pkg, old_string: '"vite": "^6.0.0"', new_string: '"vite": "^7.0.0"' } }).stdout)).toContain("vite: ^6.0.0 -> ^7.0.0");

      const cargo = join(dir, "Cargo.toml");
      writeFileSync(cargo, '[package]\nname = "app"\nversion = "0.2.0"\nedition = "2021"\n\n[dependencies]\nserde = "1.0.200"\n');
      silent({ tool_name: "Edit", tool_input: { file_path: cargo, old_string: 'version = "0.1.0"', new_string: 'version = "0.2.0"' } });
      expect(context(run({ tool_name: "Edit", tool_input: { file_path: cargo, old_string: 'serde = "1.0.100"', new_string: 'serde = "1.0.200"' } }).stdout)).toContain("serde: 1.0.100 -> 1.0.200");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("Cargo.toml and pyproject.toml: [package] / [project] fields are not dependencies; a [dependencies.x] version is x's", () => {
    silent({ tool_name: "Edit", tool_input: { file_path: "Cargo.toml", old_string: '[package]\nversion = "0.1.0"\nedition = "2018"\nrust-version = "1.70"', new_string: '[package]\nversion = "0.2.0"\nedition = "2021"\nrust-version = "1.80"' } });
    const one = context(run({ tool_name: "Edit", tool_input: { file_path: "Cargo.toml", old_string: '[dependencies.serde]\nversion = "1.0.100"', new_string: '[dependencies.serde]\nversion = "1.0.200"' } }).stdout);
    expect(one).toContain("serde: 1.0.100 -> 1.0.200");
    silent({ tool_name: "Edit", tool_input: { file_path: "pyproject.toml", old_string: '[project]\nversion = "1.0"\nrequires-python = ">=3.9"', new_string: '[project]\nversion = "1.1"\nrequires-python = ">=3.10"' } });
    const poetry = context(
      run({ tool_name: "Edit", tool_input: { file_path: "pyproject.toml", old_string: '[tool.poetry.dependencies]\npython = "^3.9"\nrequests = "^2.30"', new_string: '[tool.poetry.dependencies]\npython = "^3.10"\nrequests = "^2.31"' } }).stdout,
    );
    expect(poetry).toContain("requests: ^2.30 -> ^2.31");
    expect(poetry).not.toContain("python:");
  });

  // Pre-publish round 8 (blind audit of e3aba98).
  it("a [dependencies.x] `version =` edit counts when [package] has a version line too (it was ignored)", () => {
    const dir = mkdtempSync(join(tmpdir(), "4da-hook-r8-"));
    try {
      const cargo = join(dir, "Cargo.toml");
      writeFileSync(cargo, '[package]\nname = "app"\nversion = "0.2.0"\nedition = "2021"\n\n[dependencies.serde]\nversion = "1.0.210"\nfeatures = ["derive"]\n');
      const out = run({ tool_name: "Edit", tool_input: { file_path: cargo, old_string: 'version = "1.0.200"', new_string: 'version = "1.0.210"' } });
      expect(context(out.stdout)).toContain("serde: 1.0.200 -> 1.0.210");
      // The package's own version is still not a dependency.
      writeFileSync(cargo, '[package]\nname = "app"\nversion = "0.3.0"\n\n[dependencies.serde]\nversion = "1.0.210"\n');
      const own = run({ tool_name: "Edit", tool_input: { file_path: cargo, old_string: 'version = "0.2.0"', new_string: 'version = "0.3.0"' } });
      expect(own.stdout).toBe("");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("one malformed edit in a MultiEdit does not hide the valid one beside it", () => {
    const out = run({
      tool_name: "MultiEdit",
      tool_input: { file_path: "package.json", edits: [{ old_string: 42, new_string: { x: 1 } }, null, { old_string: '"vite": "^6.0.0"', new_string: '"vite": "^7.0.0"' }] },
    });
    expect(context(out.stdout)).toContain("vite: ^6.0.0 -> ^7.0.0");
  });

  it("a very large edit is read in linear time", () => {
    const n = 40_000;
    const deps = Array.from({ length: n }, (_, i) => `    "pkg-${i}": "1.0.${i}"`).join(",\n");
    const after = deps.replace('"pkg-0": "1.0.0"', '"pkg-0": "2.0.0"');
    const started = Date.now();
    const out = run({ tool_name: "Edit", tool_input: { file_path: "package.json", old_string: `"dependencies": {\n${deps}\n}`, new_string: `"dependencies": {\n${after}\n}` } });
    expect(Date.now() - started).toBeLessThan(8_000);
    expect(context(out.stdout)).toContain("pkg-0: 1.0.0 -> 2.0.0");
  });
});
