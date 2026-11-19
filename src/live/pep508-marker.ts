// SPDX-License-Identifier: Apache-2.0
/**
 * PEP 508 environment markers (`; python_version < "3.10" and sys_platform == "win32"`), read and
 * judged in three values: true (the requirement is installed), false (it is not), null (it depends
 * on something this server does not know, such as the platform).
 *
 * - `extra`: no extra is asked for, so `extra == "x"` is false and `extra != "x"` true.
 * - `python_version`, `python_full_version`: judged against a Python the project declares, when
 *   one is given; otherwise unknown.
 * - every other variable (`sys_platform`, `platform_system`, `os_name`, `implementation_name`, ...):
 *   unknown. A marker is never guessed true or false on those.
 *
 * A marker that does not parse is null from `parseMarker`; the caller decides what that means.
 * `markerText` rebuilds a parsed marker from its parts only (known variable names, short literals
 * of version and identifier characters), so it is fit to print in a sentence.
 */

import { pep440SpecAdmits } from "../tools/dependency-check-versions.js";

const VARIABLES = new Set([
  "python_version",
  "python_full_version",
  "os_name",
  "sys_platform",
  "platform_release",
  "platform_system",
  "platform_version",
  "platform_machine",
  "platform_python_implementation",
  "implementation_name",
  "implementation_version",
  "extra",
  "dependency_groups",
]);
const OPS = ["===", "==", "!=", "<=", ">=", "~=", "<", ">", "not in", "in"] as const;
type Op = (typeof OPS)[number];
const LITERAL = /^[A-Za-z0-9._*+!\-]{0,40}$/;

type Operand = { variable: string } | { literal: string };
export type MarkerNode = { kind: "and" | "or"; parts: MarkerNode[] } | { kind: "cmp"; left: Operand; op: Op; right: Operand };

function tokenize(text: string): string[] | null {
  const tokens: string[] = [];
  let i = 0;
  while (i < text.length) {
    const c = text[i];
    if (/\s/.test(c)) {
      i++;
      continue;
    }
    if (c === "(" || c === ")") {
      tokens.push(c);
      i++;
      continue;
    }
    if (c === '"' || c === "'") {
      const end = text.indexOf(c, i + 1);
      if (end < 0) return null;
      tokens.push(text.slice(i, end + 1));
      i = end + 1;
      continue;
    }
    const op = /^(===|==|!=|<=|>=|~=|<|>)/.exec(text.slice(i));
    if (op) {
      tokens.push(op[1]);
      i += op[1].length;
      continue;
    }
    const word = /^[A-Za-z_][A-Za-z0-9_.]*/.exec(text.slice(i));
    if (!word) return null;
    tokens.push(word[0]);
    i += word[0].length;
  }
  return tokens;
}

/** A marker's tree, or null when it is not a PEP 508 marker this reader knows. */
export function parseMarker(text: string): MarkerNode | null {
  if (text.length > 500) return null;
  const tokens = tokenize(text);
  if (!tokens || tokens.length === 0) return null;
  let at = 0;
  const operand = (): Operand | null => {
    const t = tokens[at];
    if (t === undefined) return null;
    if (t.startsWith('"') || t.startsWith("'")) {
      const value = t.slice(1, -1);
      if (!LITERAL.test(value)) return null;
      at++;
      return { literal: value };
    }
    if (!VARIABLES.has(t)) return null;
    at++;
    return { variable: t };
  };
  const expr = (): MarkerNode | null => {
    if (tokens[at] === "(") {
      at++;
      const inner = or();
      if (!inner || tokens[at] !== ")") return null;
      at++;
      return inner;
    }
    const left = operand();
    if (!left) return null;
    let op: string | undefined = tokens[at];
    if (op === "not" && tokens[at + 1] === "in") {
      op = "not in";
      at += 2;
    } else at++;
    if (!(OPS as readonly string[]).includes(op ?? "")) return null;
    const right = operand();
    if (!right) return null;
    // A comparison names exactly one variable.
    if (("variable" in left) === ("variable" in right)) return null;
    return { kind: "cmp", left, op: op as Op, right };
  };
  const chain = (kind: "and" | "or", part: () => MarkerNode | null): MarkerNode | null => {
    const parts: MarkerNode[] = [];
    for (;;) {
      const p = part();
      if (!p) return null;
      parts.push(p);
      if (tokens[at] !== kind) break;
      at++;
    }
    return parts.length === 1 ? parts[0] : { kind, parts };
  };
  const and = () => chain("and", expr);
  const or = () => chain("or", and);
  const tree = or();
  return tree && at === tokens.length ? tree : null;
}

/** The marker in canonical form: `python_version < "3.10" and extra != "y"`. */
export function markerText(node: MarkerNode, nested = false): string {
  if (node.kind === "cmp") {
    const side = (o: Operand) => ("variable" in o ? o.variable : `"${o.literal}"`);
    return `${side(node.left)} ${node.op} ${side(node.right)}`;
  }
  const text = node.parts.map((p) => markerText(p, true)).join(` ${node.kind} `);
  return nested ? `(${text})` : text;
}

/** What the marker is judged against. `python`: "3.10" (a minor series) or "3.9.1"; absent: not known. */
export interface MarkerEnvironment {
  python?: string;
}

const FLIP: Partial<Record<Op, Op>> = { "<": ">", ">": "<", "<=": ">=", ">=": "<=" };

/** `version op literal` on PEP 440 versions; null when it cannot be read. */
function versionCompare(version: string, op: Op, literal: string): boolean | null {
  if (op === "in" || op === "not in") return null;
  return pep440SpecAdmits(`${op}${literal}`, version);
}

function compare(node: Extract<MarkerNode, { kind: "cmp" }>, env: MarkerEnvironment): boolean | null {
  const varLeft = "variable" in node.left;
  const variable = (varLeft ? node.left : node.right) as { variable: string };
  const literal = ((varLeft ? node.right : node.left) as { literal: string }).literal;
  // `"x" op variable` is `variable op' "x"` for an ordering; `in` keeps its sides.
  const op = varLeft ? node.op : (FLIP[node.op] ?? node.op);
  if (variable.variable === "extra") {
    // No extra is asked for: the variable is the empty string.
    if (op === "==" || op === "===") return literal === "" ? true : false;
    if (op === "!=") return literal !== "";
    if (op === "in") return varLeft ? literal === "" : true;
    if (op === "not in") return varLeft ? literal !== "" : false;
    return null;
  }
  if (variable.variable !== "python_version" && variable.variable !== "python_full_version") return null;
  if (!env.python) return null;
  if ((op === "in" || op === "not in") && !varLeft) return null;
  const m = /^(\d+)\.(\d+)(?:\.(\d+))?$/.exec(env.python);
  if (!m) return null;
  if (variable.variable === "python_version") {
    const minor = `${m[1]}.${m[2]}`;
    if (op === "in" || op === "not in") return (op === "in") === literal.split(/[\s,]+/).includes(minor);
    return versionCompare(minor, op, literal);
  }
  // python_full_version: a minor series spans its patch releases; the answer holds only when both ends agree.
  if (op === "in" || op === "not in") return null;
  const low = versionCompare(`${m[1]}.${m[2]}.${m[3] ?? "0"}`, op, literal);
  const high = versionCompare(`${m[1]}.${m[2]}.999`, op, literal);
  return low !== null && low === high ? low : null;
}

/** The marker's value in `env`: true, false, or null when it depends on what is not known. */
export function evaluateMarker(node: MarkerNode, env: MarkerEnvironment = {}): boolean | null {
  if (node.kind === "cmp") return compare(node, env);
  const values = node.parts.map((p) => evaluateMarker(p, env));
  if (node.kind === "and") return values.includes(false) ? false : values.includes(null) ? null : true;
  return values.includes(true) ? true : values.includes(null) ? null : false;
}

/**
 * Whether a requirement gated by `marker` is installed for a project that declares `pythons`
 * (null: it declares none). `all`: on every one; `none`: on none; `some`: on `on` only; `unknown`:
 * it depends on what is not known (the platform, or a Python the project does not declare), and
 * `on` lists the declared Pythons it may apply to.
 */
export type MarkerApplies = { kind: "all" } | { kind: "none" } | { kind: "some"; on: string[] } | { kind: "unknown"; on?: string[] };

export function markerApplies(marker: string, pythons: readonly string[] | null | undefined): MarkerApplies {
  const node = parseMarker(marker);
  if (!node) return { kind: "unknown" };
  if (!pythons || pythons.length === 0) {
    const v = evaluateMarker(node);
    return v === true ? { kind: "all" } : v === false ? { kind: "none" } : { kind: "unknown" };
  }
  const values = pythons.map((p) => [p, evaluateMarker(node, { python: p })] as const);
  if (values.every(([, v]) => v === false)) return { kind: "none" };
  if (values.every(([, v]) => v === true)) return { kind: "all" };
  const on = values.filter(([, v]) => v !== false).map(([p]) => p);
  return values.some(([, v]) => v === null) ? { kind: "unknown", on } : { kind: "some", on };
}
