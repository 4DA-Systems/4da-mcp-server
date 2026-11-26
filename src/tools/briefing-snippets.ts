// SPDX-License-Identifier: Apache-2.0
/**
 * The manifest snippets of a task (round 11): requirements lines, pyproject arrays and tables, Poetry and Cargo
 * tables, package.json dependency objects and go.mod require blocks, read in ONE pass over the task.
 *
 * Best effort, never a promise (round 11, P1): the level rests on the caller's declaration, each public package
 * checked at the `version` it states. These readers add the versions they happen to read in a snippet; a version
 * written in a spelling they do not read is not checked. When a reader notices a line or entry it cannot read, it
 * says so (the snippet is "not read whole": review_needed at most). Silence says nothing about what was missed.
 *
 * Cost (round 11, P4): the task is split into lines once; fences are found in that pass, and every line belongs to
 * at most one segment (a fenced block, or a run of lines between fences). Each reader walks a segment once. At most
 * MAX_SNIPPETS snippets are read per call and the call's deadline is checked in every outer loop: past either, the
 * reading stops and the call is marked (call-budget.ts), which says "split the task" and holds review_needed.
 */
import type { CheckEcosystem } from "../live/release-metadata.js";
import { noteReadCut, readingStopped } from "../call-budget.js";
import { checkableSpec } from "./briefing-names.js";
import { credentialShape, looksLikeSecret } from "./briefing-task-screen.js";

/** At most this many snippets (blocks, tables, objects, require blocks) are read in one call. */
export const MAX_SNIPPETS = 100;
const MAX_ENTRIES = 200;

export interface SnippetPair {
  ecosystem: CheckEcosystem;
  name: string;
  version?: string;
  seen: "manifest";
}
export interface SnippetUnreadable {
  text: string;
  ecosystem: CheckEcosystem;
  operands: string[];
  manager: string;
  verb: string;
  unreadable: string;
}
export interface SnippetRead {
  pairs: SnippetPair[];
  unreadable: SnippetUnreadable[];
  privateNames: Array<{ ecosystem: CheckEcosystem; name: string }>;
  entryWords: Set<string>;
  keys: Set<string>;
  /** Words no reader may offer: PEP 508 marker names after a `;` (`python_version`). */
  consumed: Set<string>;
}

const OPS = "(?:===|==|~=|!=|>=|<=|<|>)";
const CLAUSE = `${OPS}\\s*[\\w.*+!-]+`;
const PEP508 = new RegExp(`^([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)\\s*(?:\\[\\s*[A-Za-z0-9._-]+(?:\\s*,\\s*[A-Za-z0-9._-]+)*\\s*\\])?\\s*(\\(\\s*)?(${CLAUSE}(?:\\s*,\\s*${CLAUSE})*)?(\\s*\\))?$`);

/**
 * A PEP 508 requirement line, as far as this reader reads one: a pair, "skip" (blank, a comment, an option line),
 * `{ url }` (a direct reference `name @ url`), or null (not read). Operators bare or with blanks, comma lists,
 * extras (blanks allowed), a parenthesised spec (`name (<2)`), markers after `;` and trailing `--hash` options.
 */
export function pep508(line: string): { name: string; spec?: string; url?: true } | "skip" | null {
  let l = line.trim();
  if (!l || l.startsWith("#")) return "skip";
  if (/^-(?:r|c|e|-requirement|-constraint|-editable|-index-url|-extra-index-url|-find-links|i|f|-pre|-trusted-host|-only-binary|-no-binary|-prefer-binary|-hash)\b/.test(l)) return "skip";
  l = l.replace(/(?:\s+--hash[= ]\S+)+\s*$/, "").trim();
  const semi = l.indexOf(";");
  if (semi >= 0) l = l.slice(0, semi).trim();
  const url = /^([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)\s*(?:\[[^\]]*\])?\s*@\s*\S+$/.exec(l);
  if (url) return { name: url[1], url: true };
  const m = PEP508.exec(l);
  if (!m || Boolean(m[2]) !== Boolean(m[4])) return null;
  const spec = m[3]?.replace(/\s+/g, "");
  if (spec !== undefined && checkableSpec("PyPI", spec) === null) return null;
  return { name: m[1], ...(spec ? { spec } : {}) };
}

/** A requirements line with its comment taken off (pip: `#` after a blank, or at the start). */
const uncomment = (line: string) => line.replace(/(?:^|\s)#.*$/, "");
const REQ_FILE = /\brequirements[\w.-]*\.(?:txt|in)\b/i;
const FENCE = /^\s*(`{3,}|~{3,})\s*([\w+.-]*)/;

interface Segment {
  fenced: boolean;
  label: string;
  /** For a fence: the last two non-blank lines before it, outside any fence. */
  context: string;
  lines: string[];
}

/** The task's segments, in one pass (each line in exactly one). */
function segmentsOf(text: string): Segment[] {
  const lines = text.split(/\r?\n/);
  const out: Segment[] = [];
  let loose: string[] = [];
  const recent: string[] = [];
  for (let i = 0; i < lines.length; i++) {
    const f = FENCE.exec(lines[i]);
    if (!f) {
      loose.push(lines[i]);
      if (lines[i].trim()) {
        recent.push(lines[i]);
        if (recent.length > 2) recent.shift();
      }
      continue;
    }
    if (loose.length) out.push({ fenced: false, label: "", context: "", lines: loose });
    loose = [];
    const mark = f[1];
    const body: string[] = [];
    let j = i + 1;
    for (; j < lines.length; j++) {
      const close = /^\s*(`{3,}|~{3,})\s*$/.exec(lines[j]);
      if (close && close[1][0] === mark[0] && close[1].length >= mark.length) break;
      body.push(lines[j]);
    }
    out.push({ fenced: true, label: f[2].toLowerCase(), context: recent.join("\n"), lines: body });
    recent.length = 0;
    i = j;
  }
  if (loose.length) out.push({ fenced: false, label: "", context: "", lines: loose });
  return out;
}

export function readSnippets(task: string): SnippetRead {
  const text = task.length > 200_000 ? task.slice(0, 200_000) : task;
  const out: SnippetPair[] = [];
  const unreadable: SnippetUnreadable[] = [];
  const privateNames: Array<{ ecosystem: CheckEcosystem; name: string }> = [];
  const entryWords = new Set<string>();
  const keys = new Set<string>();
  /** Words no reader may offer: marker names, group keys (round 12: a dependency-group name is no entry). */
  const consumed = new Set<string>();
  let snippets = 0;
  let stopped = false;
  /** One more snippet: false (and the call marked) past the cap or the deadline. */
  const another = () => {
    if (stopped) return false;
    if (++snippets > MAX_SNIPPETS) {
      noteReadCut("snippets");
      stopped = true;
    } else if (readingStopped()) stopped = true;
    return !stopped;
  };
  /** The deadline check of an outer loop, every 256 lines. */
  const late = (k: number) => {
    if (stopped) return true;
    if ((k & 255) === 255 && readingStopped()) stopped = true;
    return stopped;
  };
  const notWhole = (ecosystem: CheckEcosystem, why: string, entry = "") => {
    for (const w of entry.toLowerCase().split(/[^a-z0-9@/._-]+/)) if (w) entryWords.add(w);
    if (!unreadable.some((u) => u.unreadable === why && u.ecosystem === ecosystem)) unreadable.push({ text: "", ecosystem, operands: [], manager: "a manifest", verb: "", unreadable: why });
  };
  const push = (ecosystem: CheckEcosystem, name: string, version?: string) => {
    if (out.length >= MAX_ENTRIES || !name) return;
    if (ecosystem === "PyPI" && name.toLowerCase() === "python") return;
    // A file name is no package ("requirements.txt" on a line of its own).
    if (/\.(?:txt|in|toml|json|lock|cfg|ini|py|ya?ml|mod|sum)$/i.test(name)) return;
    if (credentialShape(name) || looksLikeSecret(name) || (version !== undefined && !/^(?:latest|\*)$/i.test(version) && checkableSpec(ecosystem, version) === null)) {
      notWhole(ecosystem, "an entry it cannot read", `${name} ${version ?? ""}`);
      return;
    }
    out.push({ ecosystem, name, ...(version ? { version } : {}), seen: "manifest" });
  };
  /** A requirements entry (a line of a block, or the one-line form). */
  const requirement = (raw: string): boolean => {
    const d = pep508(uncomment(raw));
    if (d === "skip") return true;
    if (!d) return false;
    if (d.url) privateNames.push({ ecosystem: "PyPI", name: d.name });
    else push("PyPI", d.name, d.spec);
    return true;
  };
  const requirementsBlock = (lines: readonly string[]) => {
    if (!another()) return;
    // Backslash continuations are one line.
    let line = "";
    for (let k = 0; k < lines.length && !late(k); k++) {
      const raw = lines[k];
      if (/\\\s*$/.test(raw)) {
        line += `${raw.replace(/\\\s*$/, "")} `;
        continue;
      }
      line += raw;
      if (!requirement(line)) notWhole("PyPI", "a line it cannot read", line.slice(0, 300));
      line = "";
    }
    if (line && !requirement(line)) notWhole("PyPI", "a line it cannot read", line.slice(0, 300));
  };
  const firstEntry = (lines: readonly string[]) => lines.find((l) => uncomment(l).trim() !== "") ?? "";

  for (const seg of segmentsOf(text)) {
    if (stopped) break;
    if (seg.fenced) {
      const named = REQ_FILE.test(seg.context) || /\brequirements\b/i.test(seg.context);
      const head = pep508(uncomment(firstEntry(seg.lines)));
      const looksRequirements = head !== null && head !== "skip" && (Boolean(head.spec) || Boolean(head.url));
      if (["requirements", "pip"].includes(seg.label) || (["", "txt", "text", "plain"].includes(seg.label) && (named || (seg.label !== "" && looksRequirements)))) {
        requirementsBlock(seg.lines);
        continue;
      }
      structured(seg.lines);
      continue;
    }
    // Lines outside fences: a requirements file named, then its lines; a heredoc into it; else the structured readers.
    const rest: string[] = [];
    for (let k = 0; k < seg.lines.length; k++) {
      if (late(k)) break;
      const line = seg.lines[k];
      const named = REQ_FILE.exec(line);
      if (!named) {
        rest.push(line);
        continue;
      }
      const heredoc = /<<-?\s*['"]?(\w+)['"]?/.exec(line.slice(named.index));
      if (heredoc) {
        const body: string[] = [];
        let j = k + 1;
        for (; j < seg.lines.length && seg.lines[j].trim() !== heredoc[1]; j++) body.push(seg.lines[j]);
        requirementsBlock(body);
        k = j;
        continue;
      }
      // The one-line form: "Add to requirements.txt: name ~= 1.0 (why)." A tail it cannot read is said.
      const tail = /^[^\n:]{0,40}:[ \t]*(\S.{0,300})$/.exec(line.slice(named.index + named[0].length));
      if (tail && another()) {
        const t = tail[1].replace(/\s*\([^()]*\)\s*[.!]?\s*$/, "").replace(/[.,;!]+\s*$/, "").replace(/`/g, "").trim();
        const parts = t.split(/\s*,\s+(?=[A-Za-z])|\s+and\s+/);
        if (!(t && (requirementOk(t) ? requirement(t) : parts.every(requirementOk) && parts.every(requirement)))) notWhole("PyPI", "a line it cannot read", t.slice(0, 300));
      }
      // The lines right after it, up to a blank line: a snippet when its first entry is a requirement.
      const body: string[] = [];
      let j = k + 1;
      for (; j < seg.lines.length && seg.lines[j].trim(); j++) body.push(seg.lines[j]);
      const head = pep508(uncomment(firstEntry(body)));
      if (body.length > 0 && head !== null && head !== "skip") {
        requirementsBlock(body);
        k = j - 1;
        continue;
      }
      rest.push(line);
    }
    structured(rest);
  }

  /** Whether a one-line tail reads as a requirement (no side effects). */
  function requirementOk(raw: string): boolean {
    const d = pep508(uncomment(raw));
    return d !== null && d !== "skip";
  }

  /** The TOML, JSON and go.mod readers over one segment's lines: each line once. */
  function structured(lines: readonly string[]): void {
    if (stopped || lines.length === 0) return;
    tomlReader(lines);
    jsonReader(lines.join("\n"));
    goReader(lines);
  }

  function tomlReader(lines: readonly string[]): void {
    type Table = { kind: "cargo" | "poetry" | "entry" | "project" | "optional" | "groups" | "other"; ecosystem: CheckEcosystem; name?: string; entry?: Map<string, string> };
    let table: Table | null = null;
    const closeEntry = () => {
      if (table?.kind !== "entry" || !table.entry) return;
      const e = table.entry;
      if (["git", "path", "registry", "workspace", "url", "source", "develop"].some((k) => e.has(k))) privateNames.push({ ecosystem: table.ecosystem, name: table.name! });
      else if ([...e.keys()].some((k) => !ENTRY_KEYS.has(k))) notWhole(table.ecosystem, "an entry it cannot read", table.name);
      else {
        const v = e.get("version");
        push(table.ecosystem, e.get("package")?.replace(/^"|"$/g, "") ?? table.name!, v === undefined ? undefined : v.replace(/^"|"$/g, ""));
      }
    };
    for (let k = 0; k < lines.length; k++) {
      if (late(k)) return;
      const l = tomlUncomment(lines[k]).trim();
      if (!l) continue;
      const header = /^\[\s*([^[\]]+?)\s*\]$/.exec(l);
      if (header) {
        closeEntry();
        table = classify(header[1]);
        if (table && table.kind !== "other" && !another()) return;
        if (table?.kind === "entry") keys.add(table.name!.toLowerCase());
        continue;
      }
      if (/^\[\[/.test(l)) {
        closeEntry();
        table = null;
        continue;
      }
      const kv = /^("?)([A-Za-z0-9][\w.-]*)\1\s*=\s*(.*)$/.exec(l);
      // An array value may run over the following lines.
      const arrayAt = (value: string): [string, number] => {
        let body = value;
        let j = k;
        while (!arrayClosed(body) && j + 1 < lines.length && body.length < 8000) body += `\n${tomlUncomment(lines[++j])}`;
        return [body, j];
      };
      if (!table || table.kind === "other") {
        // pyproject's `dependencies = [...]` read wherever it stands (a prose snippet without its table).
        if (kv && kv[2] === "dependencies" && kv[3].trim().startsWith("[")) {
          if (!another()) return;
          const [body, j] = arrayAt(kv[3]);
          k = j;
          arrayEntries(body, false);
        }
        continue;
      }
      if (!kv) {
        notWhole(table.ecosystem, "an entry it cannot read", l);
        continue;
      }
      const [, , key, rawValue] = kv;
      const value = rawValue.trim();
      if (table.kind === "entry") {
        table.entry!.set(key, value);
        continue;
      }
      if (table.kind === "project") {
        if (key === "dependencies" && value.startsWith("[")) {
          const [body, j] = arrayAt(value);
          k = j;
          arrayEntries(body, false);
        }
        continue;
      }
      if (table.kind === "optional" || table.kind === "groups") {
        consumed.add(key.toLowerCase());
        if (!value.startsWith("[")) {
          notWhole("PyPI", "an entry it cannot read", l);
          continue;
        }
        const [body, j] = arrayAt(value);
        k = j;
        arrayEntries(body, table.kind === "groups");
        continue;
      }
      keys.add(key.toLowerCase());
      const plain = /^"([^"]{0,100})"$/.exec(value) ?? /^'([^']{0,100})'$/.exec(value);
      if (plain) {
        push(table.ecosystem, key, plain[1]);
        continue;
      }
      const inline = /^\{(.*)\}$/.exec(value);
      if (!inline) {
        notWhole(table.ecosystem, "an entry it cannot read", l);
        continue;
      }
      const entry = inlineTable(inline[1]);
      if (!entry) {
        notWhole(table.ecosystem, "an entry it cannot read", l);
        continue;
      }
      if (["git", "path", "registry", "workspace", "url", "source", "develop"].some((x) => entry.has(x))) {
        privateNames.push({ ecosystem: table.ecosystem, name: entry.get("package")?.replace(/^"|"$/g, "") ?? key });
        continue;
      }
      if ([...entry.keys()].some((x) => !ENTRY_KEYS.has(x))) {
        notWhole(table.ecosystem, "an entry it cannot read", l);
        continue;
      }
      const v = entry.get("version");
      push(table.ecosystem, entry.get("package")?.replace(/^"|"$/g, "") ?? key, v === undefined ? undefined : v.replace(/^"|"$/g, ""));
    }
    closeEntry();
  }

  /** The quoted entries of a pyproject array (PEP 621, optional groups, PEP 735 groups). */
  function arrayEntries(body: string, groups: boolean): void {
    const inner = body.slice(body.indexOf("[") + 1, body.lastIndexOf("]") >= 0 ? body.lastIndexOf("]") : body.length);
    let leftover = inner;
    for (const e of inner.matchAll(/"([^"\n]{0,300})"|'([^'\n]{0,300})'/g)) {
      const d = pep508(e[1] ?? e[2]);
      if (d && d !== "skip") {
        if (d.url) privateNames.push({ ecosystem: "PyPI", name: d.name });
        else push("PyPI", d.name, d.spec);
      } else notWhole("PyPI", "an entry it cannot read", e[1] ?? e[2]);
    }
    leftover = leftover.replace(/"[^"\n]{0,300}"|'[^'\n]{0,300}'/g, "");
    // PEP 735: `{ include-group = "x" }` names another group, no package.
    if (groups) leftover = leftover.replace(/\{\s*include-group\s*=\s*\}/g, "");
    if (leftover.replace(/[\s,]/g, "") !== "") notWhole("PyPI", "an entry it cannot read", inner.slice(0, 300));
    if (!arrayClosed(body)) notWhole("PyPI", "an entry it cannot read", inner.slice(0, 300));
  }

  function jsonReader(segment: string): void {
    const opener = /"(?:dev|peer|optional)?[dD]ependencies"\s*:\s*\{/g;
    let m: RegExpExecArray | null;
    while ((m = opener.exec(segment)) !== null) {
      if (!another()) return;
      const from = m.index + m[0].length;
      // To the closing brace, quotes respected; a nested object or no close is not read whole.
      let j = from;
      let quoted = false;
      let nested = false;
      for (; j < segment.length && j - from < 4000; j++) {
        const c = segment[j];
        if (quoted) {
          if (c === "\\") j++;
          else if (c === '"') quoted = false;
        } else if (c === '"') quoted = true;
        else if (c === "{") nested = true;
        else if (c === "}") break;
      }
      const body = segment.slice(from, j).trim();
      opener.lastIndex = Math.max(opener.lastIndex, j);
      if (j >= segment.length || segment[j] !== "}" || nested) {
        notWhole("npm", "an entry it cannot read", body.slice(0, 300));
        continue;
      }
      const entry = /"((?:@[a-z0-9][\w.-]*\/)?[a-z0-9][\w.-]*)"\s*:\s*"([^"]{0,200})"/gi;
      if (body && body.replace(/"((?:@[a-z0-9][\w.-]*\/)?[a-z0-9][\w.-]*)"\s*:\s*"([^"]{0,200})"\s*,?/gi, "").trim() !== "") notWhole("npm", "an entry it cannot read", body.slice(0, 300));
      for (const e of body.matchAll(entry)) {
        keys.add(e[1].toLowerCase());
        const alias = /^npm:((?:@[a-z0-9][\w.-]*\/)?[a-z0-9][\w.-]*)(?:@(.+))?$/i.exec(e[2]);
        if (alias) push("npm", alias[1], alias[2]);
        else if (/^(?:git|github:|gitlab:|bitbucket:|file:|link:|workspace:|portal:|https?:|\.|\/|~[/\\])/i.test(e[2]) || e[2].includes("://") || e[2].includes("/")) privateNames.push({ ecosystem: "npm", name: e[1] });
        else push("npm", e[1], e[2]);
      }
    }
  }

  function goReader(lines: readonly string[]): void {
    for (let k = 0; k < lines.length; k++) {
      if (late(k)) return;
      const l = lines[k].replace(/\/\/.*$/, "").trim();
      // A require written in a line of its own or in prose ("Require x v1.0.0 in go.mod.").
      let single = false;
      for (const one of l.matchAll(/\brequire\s+([a-z0-9.-]+\.[a-z]{2,}\/[^\s]+?)\s+(v[\w.+-]+?)(?=[.,;:!?)]*(?:\s|$))/gi)) {
        if (!another()) return;
        push("Go", one[1], one[2]);
        single = true;
      }
      if (single) continue;
      if (!/^require\s*\($/.test(l)) continue;
      if (!another()) return;
      let j = k + 1;
      for (; j < lines.length && j - k < 2000; j++) {
        const line = lines[j].replace(/\/\/.*$/, "").trim();
        if (line === ")") break;
        if (!line) continue;
        const e = /^([a-z0-9.-]+\.[a-z]{2,}\/\S+)\s+(v\S+)$/i.exec(line);
        if (e && checkableSpec("Go", e[2]) !== null) push("Go", e[1], e[2]);
        else notWhole("Go", "a line it cannot read", line);
      }
      k = j;
    }
  }

  for (const m of text.matchAll(MARKER_NAMES)) {
    const lineStart = text.lastIndexOf("\n", m.index) + 1;
    if (text.slice(lineStart, m.index).includes(";")) consumed.add(m[0].toLowerCase());
  }
  const seen = new Set<string>();
  const pairs = out.filter((p) => {
    const key = `${p.ecosystem}\0${p.name}\0${p.version ?? ""}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
  return { pairs, unreadable, privateNames, entryWords, keys, consumed };
}

const MARKER_NAMES = /\b(?:python_version|python_full_version|os_name|sys_platform|platform_release|platform_system|platform_version|platform_machine|platform_python_implementation|implementation_name|implementation_version|extra)\b/gi;
const ENTRY_KEYS = new Set(["version", "features", "optional", "default-features", "default_features", "package", "extras", "markers", "python", "allow-prereleases"]);
const DEP_KINDS = new Set(["dependencies", "dev-dependencies", "build-dependencies"]);

/** A TOML comment taken off a line, outside quotes. */
function tomlUncomment(line: string): string {
  let quote = "";
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (quote) {
      if (c === quote) quote = "";
    } else if (c === '"' || c === "'") quote = c;
    else if (c === "#") return line.slice(0, i);
  }
  return line;
}

/** Whether a collected array value closes (its brackets balance outside quotes). */
function arrayClosed(body: string): boolean {
  let depth = 0;
  let quote = "";
  let opened = false;
  for (const c of body) {
    if (quote) {
      if (c === quote) quote = "";
    } else if (c === '"' || c === "'") quote = c;
    else if (c === "[") {
      depth++;
      opened = true;
    } else if (c === "]") {
      depth--;
      if (opened && depth === 0) return true;
    }
  }
  return false;
}

/** An inline table's keys and raw values, or null when it is not one this reader reads. */
function inlineTable(body: string): Map<string, string> | null {
  const out = new Map<string, string>();
  const rest = body.replace(/([\w-]+)\s*=\s*("[^"]*"|'[^']*'|true|false|\[[^\]]*\])\s*,?/g, (_m, k: string, v: string) => {
    out.set(k, v.replace(/^'|'$/g, '"'));
    return "";
  });
  return rest.trim() === "" ? out : null;
}

/** A table header's kind (blanks and quoted keys allowed: `[ dependencies ]`, `[target.'cfg(unix)'.dependencies]`). */
function classify(raw: string): { kind: "cargo" | "poetry" | "entry" | "project" | "optional" | "groups" | "other"; ecosystem: CheckEcosystem; name?: string; entry?: Map<string, string> } {
  const segs: string[] = [];
  let cur = "";
  let quote = "";
  for (const c of raw) {
    if (quote) {
      if (c === quote) quote = "";
      else cur += c;
    } else if (c === '"' || c === "'") quote = c;
    else if (c === ".") {
      segs.push(cur.trim());
      cur = "";
    } else cur += c;
  }
  segs.push(cur.trim());
  const at = (i: number) => segs[i] ?? "";
  const cargo = (base: number): ReturnType<typeof classify> | null => {
    if (!DEP_KINDS.has(at(base))) return null;
    if (segs.length === base + 1) return { kind: "cargo", ecosystem: "crates.io" };
    if (segs.length === base + 2) return { kind: "entry", ecosystem: "crates.io", name: at(base + 1), entry: new Map() };
    return null;
  };
  const found = cargo(0) ?? (at(0) === "workspace" ? cargo(1) : null) ?? (at(0) === "target" && segs.length >= 3 ? cargo(2) : null);
  if (found) return found;
  if (at(0) === "tool" && at(1) === "poetry") {
    if (segs.length === 3 && DEP_KINDS.has(at(2))) return { kind: "poetry", ecosystem: "PyPI" };
    if (segs.length === 5 && at(2) === "group" && at(4) === "dependencies") return { kind: "poetry", ecosystem: "PyPI" };
    if (segs.length === 4 && DEP_KINDS.has(at(2))) return { kind: "entry", ecosystem: "PyPI", name: at(3), entry: new Map() };
  }
  if (segs.length === 1 && at(0) === "project") return { kind: "project", ecosystem: "PyPI" };
  if (segs.length === 2 && at(0) === "project" && at(1) === "optional-dependencies") return { kind: "optional", ecosystem: "PyPI" };
  if (segs.length === 1 && at(0) === "dependency-groups") return { kind: "groups", ecosystem: "PyPI" };
  return { kind: "other", ecosystem: "PyPI" };
}
