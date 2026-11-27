// SPDX-License-Identifier: Apache-2.0
/**
 * Round 14b: the arguments' side of the credential screen, at the dispatcher (tool-dispatch.ts dispatchTool), for
 * every tool. A string argument that matches a shape of CREDENTIAL_SHAPES (the same constant the output screen uses)
 * is never sent to a host or stored:
 * - a field that names a package, module, version, ecosystem or path (anything a tool sends to a registry, OSV.dev or
 *   GitHub, or writes to the ledger, the database or a cache) refuses the call before any lookup: "refused: a value of
 *   a credential's shape is not a <field>"; dependency_check refuses the one item (dependency-check.ts validateItem);
 *   what_should_i_know refuses the one declaration (briefing-confirm.ts declarationProblem) and never sends or stores
 *   its task text;
 * - free text a tool stores or sends on purpose (MASKED_TOOLS: decision_memory, check_decision_alignment,
 *   agent_memory) has each credential-shaped substring replaced by its shape before anything runs, and the answer
 *   says so (`_meta.credential_masked`).
 */
import { hasCredentialShape, maskCredentialShapes } from "./output-screen.js";

/** Round 15b: THE refusal of a credential-shaped argument, for every field and tool (a hint may follow it). */
export const CREDENTIAL_REFUSAL = (field: string) => `refused: a value of a credential's shape is not ${/^[aeiou]/i.test(field) ? "an" : "a"} ${field}; nothing was sent or stored`;

/** Tools whose free-text arguments are stored or sent on purpose: masked, not refused. */
export const MASKED_TOOLS: ReadonlySet<string> = new Set(["decision_memory", "check_decision_alignment", "agent_memory"]);
/** Tools that screen their own arguments item by item (per-item refusals; their free text is never sent or stored). */
const OWN_SCREEN: ReadonlySet<string> = new Set(["dependency_check", "what_should_i_know"]);

/** What a field holds, as a refusal names it. */
const FIELD_LABEL: Readonly<Record<string, string>> = {
  package: "package name",
  to_version: "version",
  from_version: "version",
  ecosystem: "ecosystem",
  project_path: "path",
};

export type ArgumentScreen = { refused: string } | { args: Record<string, unknown>; masked: number };

/** The dispatcher's argument stage (round 14b): refuse, mask, or pass the arguments as given. */
export function screenArguments(tool: string, args: Record<string, unknown>): ArgumentScreen {
  if (OWN_SCREEN.has(tool)) return { args, masked: 0 };
  if (MASKED_TOOLS.has(tool)) {
    let masked = 0;
    const walk = (v: unknown, depth: number): unknown => {
      if (typeof v === "string") {
        if (!hasCredentialShape(v)) return v;
        masked++;
        return maskCredentialShapes(v);
      }
      if (depth > 8 || v === null || typeof v !== "object") return v;
      if (Array.isArray(v)) return v.map((x) => walk(x, depth + 1));
      return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, walk(x, depth + 1)]));
    };
    const out = walk(args, 0) as Record<string, unknown>;
    return { args: out, masked };
  }
  for (const [key, value] of Object.entries(args)) {
    const strings = typeof value === "string" ? [value] : Array.isArray(value) ? value.filter((x): x is string => typeof x === "string") : [];
    if (strings.some(hasCredentialShape)) return { refused: CREDENTIAL_REFUSAL(FIELD_LABEL[key] ?? key.replace(/_/g, " ")) };
  }
  return { args, masked: 0 };
}

/** The note a masked call's answer carries. */
export const maskedNote = (n: number) => `${n} argument value${n === 1 ? "" : "s"} held a credential's shape: each such part was replaced by its first four characters and its length before anything was sent or stored.`;
