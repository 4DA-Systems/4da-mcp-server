// SPDX-License-Identifier: Apache-2.0
/**
 * The tool registry as hosts see it in tools/list.
 *
 * Locks in: the call-when trigger in every description (models select tools
 * more reliably with an explicit trigger), the description budget, the FULL
 * inputSchema for every tool (AD-032's slim `{type:"object"}` hid 30+ optional
 * parameters from every host that never reads MCP Resources), honest
 * annotations with a title, and the server instructions' length limit.
 */

import { describe, it, expect } from "vitest";
import { TOOL_REGISTRY, getSlimToolList, getToolSchemaDocument } from "../schema-registry.js";
import { SERVER_INSTRUCTIONS } from "../server-instructions.js";

// An explicit trigger: "Call [this] when/before/after/first/to ..." (case-insensitive).
const TRIGGER = /\bCall (this )?(when|after|before|first|to|BEFORE)\b/i;
const WRITE_TOOLS = new Set(["record_feedback", "decision_memory", "agent_memory"]);

describe("tool registry", () => {
  it("registers 16 tools (11 standalone, 5 that need the desktop app's database)", () => {
    expect(Object.keys(TOOL_REGISTRY)).toHaveLength(16);
    expect(getSlimToolList().length).toBe(16);
    expect(getSlimToolList(true).length).toBe(11);
    expect(getSlimToolList(false).length).toBe(5);
  });

  it("registry key, definition name and dispatch name agree", () => {
    for (const [name, entry] of Object.entries(TOOL_REGISTRY)) {
      expect(entry.definition.name, `${name}: definition.name`).toBe(name);
    }
  });

  it("every description carries an explicit call-when trigger", () => {
    for (const [name, entry] of Object.entries(TOOL_REGISTRY)) {
      expect(entry.summary, `${name}: description missing a 'Call ...' trigger`).toMatch(TRIGGER);
    }
  });

  it("descriptions stay within budget (Claude Code truncates at 2,048; tool search reads them)", () => {
    for (const [name, entry] of Object.entries(TOOL_REGISTRY)) {
      expect(entry.summary.length, `${name}: ${entry.summary.length} chars`).toBeLessThanOrEqual(300);
    }
    const total = Object.values(TOOL_REGISTRY).reduce((n, e) => n + e.summary.length, 0);
    expect(total, `combined descriptions are ${total} chars`).toBeLessThanOrEqual(3400);
  });

  it("tools/list serves every tool's FULL inputSchema, optional parameters included", () => {
    for (const tool of getSlimToolList()) {
      const definition = TOOL_REGISTRY[tool.name].definition;
      expect(tool.inputSchema, tool.name).toBe(definition.inputSchema);
      expect(tool.inputSchema.type, tool.name).toBe("object");
    }
    // The parameters AD-032 hid are now visible.
    const vuln = getSlimToolList().find((t) => t.name === "vulnerability_scan")!;
    expect(Object.keys(vuln.inputSchema.properties as object)).toEqual(
      expect.arrayContaining(["project_path", "severity_filter", "include_dev", "force_refresh", "response_format"]),
    );
  });

  it("the whole tools/list stays within a ~5k-token budget", () => {
    const chars = JSON.stringify(getSlimToolList()).length;
    expect(chars, `tools/list is ${chars} chars`).toBeLessThanOrEqual(20_000);
  });

  it("every tool has a title and honest read/write annotations", () => {
    for (const [name, entry] of Object.entries(TOOL_REGISTRY)) {
      expect(entry.annotations.title.length, `${name}: title`).toBeGreaterThan(0);
      expect(entry.annotations.readOnlyHint, `${name}: readOnlyHint`).toBe(!WRITE_TOOLS.has(name));
      if (WRITE_TOOLS.has(name)) expect(entry.annotations.destructiveHint, name).toBe(false);
    }
  });

  it("serves a schema document per tool as a resource", () => {
    for (const name of Object.keys(TOOL_REGISTRY)) {
      const doc = getToolSchemaDocument(name) as { name: string; inputSchema: unknown };
      expect(doc.name).toBe(name);
      expect(doc.inputSchema).toBe(TOOL_REGISTRY[name].definition.inputSchema);
    }
    expect(getToolSchemaDocument("no_such_tool")).toBeNull();
  });
});

describe("server instructions", () => {
  it("fit Claude Code's 2,048-character limit and lead with what the server is for", () => {
    expect(SERVER_INSTRUCTIONS.length).toBeLessThanOrEqual(2048);
    expect(SERVER_INSTRUCTIONS.slice(0, 512)).toMatch(/dependenc/i);
  });

  it("name only tools that exist", () => {
    const resultFields = new Set(["advisory_severity"]);
    const named = (SERVER_INSTRUCTIONS.match(/\b[a-z]+(?:_[a-z]+)+\b/g) ?? []).filter((n) => !resultFields.has(n));
    expect(named.length).toBeGreaterThan(5);
    for (const name of named) expect(Object.keys(TOOL_REGISTRY), name).toContain(name);
  });
});

/**
 * Readiness audit L6 (2026-10-16): in standalone mode resources/list
 * advertised the schemas of the 5 desktop-only tools that tools/list leaves
 * out, and with the database refused the startup banner said "16 tools"
 * while every call returned the database error.
 */
describe("resources and the startup line say what this mode serves (L6)", () => {
  const DESKTOP = ["get_relevant_content", "get_actionable_signals", "knowledge_gaps", "developer_dna", "record_feedback"];

  it("standalone: the schema resources and the categories list the 11 tools tools/list lists", async () => {
    const { listResources, readResource } = await import("../schema-registry.js");
    const uris = listResources(true).map((r) => r.uri);
    const tools = getSlimToolList(true).map((t) => t.name);
    expect(uris.filter((u) => u.startsWith("4da://schema/")).sort()).toEqual(tools.map((t) => `4da://schema/${t}`).sort());
    for (const name of DESKTOP) expect(uris).not.toContain(`4da://schema/${name}`);
    const manifest = JSON.parse(readResource("4da://categories", true).contents[0].text) as { total_tools: number; categories: Record<string, { tools: string[] }> };
    expect(manifest.total_tools).toBe(11);
    expect(Object.values(manifest.categories).flatMap((c) => c.tools)).not.toContain("knowledge_gaps");
  });

  it("with the desktop database: all 16", async () => {
    const { listResources } = await import("../schema-registry.js");
    expect(listResources().filter((r) => r.uri.startsWith("4da://schema/"))).toHaveLength(16);
  });

  it("the startup line never counts tools a refused database will not run", async () => {
    const { startupToolsLine } = await import("../schema-registry.js");
    expect(startupToolsLine({ valid: true, standalone: false }, true)).toBe("16 tools");
    expect(startupToolsLine({ valid: false, standalone: true }, true)).toBe("11 standalone tools");
    const refused = startupToolsLine({ valid: false, standalone: false }, true);
    expect(refused).not.toMatch(/^16 tools$/);
    expect(refused).toMatch(/no tool can run until the database problem above is fixed/);
    expect(startupToolsLine({ valid: false, standalone: false }, false, 5)).toMatch(/^5 dependency tools run without a database/);
  });
});