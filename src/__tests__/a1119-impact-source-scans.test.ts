// SPDX-License-Identifier: Apache-2.0
/**
 * upgrade_impact reads the project's own source files to find where a package is used. Those
 * files are whatever the repository holds, so each scan is bounded: a file of unterminated
 * `import` / `use` statements, of blank lines, or of thousands of string literals costs time in
 * proportion to its size, not to its square (400 KB of `import a ` took 46 s; the literal scan
 * of one project took 41 s).
 *
 * The pathological inputs below assert a result. Under the old patterns they do not return
 * within the test timeout, which is how a regression shows.
 */

import { describe, expect, it } from "vitest";

import { scanNpmSource, scanRustSource } from "../tools/upgrade-impact-callsites.js";
import { scanGoSource, scanPythonSource } from "../tools/upgrade-impact-imports.js";
import { stringLiterals } from "../tools/upgrade-impact-literals.js";

const scan = <A extends unknown[]>(fn: (source: string, ...rest: [...A, Set<string>]) => number, source: string, ...rest: A) => {
  const symbols = new Set<string>();
  const matches = fn(source, ...rest, symbols);
  return { matches, symbols: [...symbols].sort() };
};

describe("npm imports", () => {
  it("reads the ordinary statement shapes", () => {
    const source = [
      `import express, { Router, json as parseJson } from "express";`,
      `import * as ex from 'express';`,
      `import type { Request } from "express";`,
      `export { static as serveStatic } from "express";`,
      `import {\n  urlencoded,\n  raw,\n} from "express";`,
      `import "express";`,
      `const lazy = await import("express");`,
      `const { query } = require("express");`,
      `const whole = require('express');`,
      `import sub from "express/lib/router";`,
      `import other from "express-session";`,
      `const s = "import x from 'not-express'";`,
    ].join("\n");
    const { matches, symbols } = scan(scanNpmSource, source, "express");
    expect(matches).toBe(10);
    expect(symbols).toEqual(["Request", "Router", "ex", "express", "json", "query", "raw", "static", "sub", "urlencoded", "whole"]);
  });

  it("an `export * from` names no symbol but counts", () => {
    expect(scan(scanNpmSource, `export * from "express";`, "express")).toEqual({ matches: 1, symbols: [] });
  });

  it("a statement is not read across the end of the one before it", () => {
    const source = `import a from "left-pad";\nconst x = 1;\nfrom "express";\nimport { b } from "express";`;
    expect(scan(scanNpmSource, source, "express")).toEqual({ matches: 1, symbols: ["b"] });
  });

  it("returns for a large file of unterminated imports and braces", () => {
    const unterminated = `${"import a ".repeat(60_000)}\nimport { Router } from "express";\n${"const { ".repeat(60_000)}`;
    expect(scan(scanNpmSource, unterminated, "express")).toEqual({ matches: 1, symbols: ["Router"] });
  });
});

describe("Rust uses", () => {
  it("reads the ordinary statement shapes", () => {
    const source = ["use serde::{Deserialize, Serialize};", "use serde::de::DeserializeOwned;", "extern crate serde;", "fn f() { let x: serde::de::Error; }", "use serde_json::Value;"].join("\n");
    const { matches, symbols } = scan(scanRustSource, source, "serde");
    expect(matches).toBe(4);
    expect(symbols).toEqual(["Deserialize", "DeserializeOwned", "Error", "Serialize", "de"]);
  });

  it("returns for a large file of `use` lines with no semicolon", () => {
    const source = `${"use serde::a ".repeat(60_000)}\nuse serde::Serialize;\n`;
    const { symbols } = scan(scanRustSource, source, "serde");
    expect(symbols).toContain("Serialize");
  });
});

describe("Python imports", () => {
  it("reads the ordinary statement shapes", () => {
    const source = ["from yaml import (\n    safe_load,\n    dump as d,\n)", "import yaml", "import yaml.loader as yl", "x = yaml.load(s)", "y = yl.Loader"].join("\n");
    const { matches, symbols } = scan(scanPythonSource, source, ["yaml"]);
    expect(matches).toBe(3);
    expect(symbols).toEqual(["Loader", "dump", "load", "safe_load"]);
  });

  it("returns for a large file of unclosed import lists", () => {
    const source = `${"from yaml import (\n".repeat(40_000)}\nfrom yaml import safe_load\n`;
    const { symbols } = scan(scanPythonSource, source, ["yaml"]);
    expect(symbols).toContain("safe_load");
  });
});

describe("Go imports", () => {
  const mod = "github.com/gin-gonic/gin";
  it("reads single and block imports", () => {
    const source = ['package main', 'import (', '\t"fmt"', '\tg "github.com/gin-gonic/gin"', '\t"github.com/gin-gonic/gin/binding"', ')', 'import "github.com/gin-gonic/gin"', 'func main() { g.Default(); binding.JSON.Name(); gin.New() }'].join("\n");
    const { matches, symbols } = scan(scanGoSource, source, mod);
    expect(matches).toBe(3);
    expect(symbols).toEqual(["Default", "JSON", "New"]);
  });

  it("returns for a file of blank lines, and for unclosed import blocks", () => {
    const blank = `"${mod}"\n${"\n".repeat(300_000)}import "${mod}"\n`;
    expect(scan(scanGoSource, blank, mod).matches).toBe(1);
    const unclosed = `${"import (\n".repeat(40_000)}import "${mod}"\n`;
    expect(scan(scanGoSource, unclosed, mod).matches).toBeGreaterThanOrEqual(1);
  });
});

describe("string literals", () => {
  it("carry the line they stand on", () => {
    const source = `const a = "/users/:id";\n\n\nconst b = '/files/*path';\nconst c = \`/x\ny\`;\nconst d = "/after";`;
    expect(stringLiterals(source)).toEqual([
      { text: "/users/:id", line: 1 },
      { text: "/files/*path", line: 4 },
      { text: "/x\ny", line: 5 },
      { text: "/after", line: 7 },
    ]);
  });

  it("returns for a file of very many literals", () => {
    const n = 60_000;
    const literals = stringLiterals(Array.from({ length: n }, (_, i) => `r("/a/:b${i}");`).join("\n"));
    expect(literals).toHaveLength(n);
    expect(literals[n - 1]).toEqual({ text: `/a/:b${n - 1}`, line: n });
  });
});
