// SPDX-License-Identifier: Apache-2.0
/**
 * The public registries and indexes, and the small TOML reader the private-name rules share
 * (private-packages.ts, private-configs.ts). No dependency on either, so both can import it.
 */

const PUBLIC_NPM_HOSTS = new Set(["registry.npmjs.org", "registry.npmjs.com", "registry.yarnpkg.com", "registry.npmmirror.com"]);
const PUBLIC_PYPI_HOSTS = new Set(["pypi.org", "pypi.python.org", "files.pythonhosted.org", "test.pypi.org"]);
const PUBLIC_CRATES_SOURCES = new Set(["registry+https://github.com/rust-lang/crates.io-index", "sparse+https://index.crates.io/"]);
/** Public Go module proxies (the default, and the two public mirrors in wide use). */
const PUBLIC_GO_PROXY_HOSTS = new Set(["proxy.golang.org", "goproxy.io", "goproxy.cn"]);
/**
 * Public wheel indexes projects add as an EXTRA index beside pypi.org (PyTorch, NVIDIA, PyG). They
 * host only their own public builds, so a name is never private because of them; judging them
 * private made every pin of a project with `--extra-index-url https://download.pytorch.org/whl/cu121`
 * NOT CHECKED. Never a replacement for pypi.org: as `--index-url` they still replace it.
 */
const PUBLIC_EXTRA_PYPI_HOSTS = new Set(["download.pytorch.org", "pypi.nvidia.com", "pypi.ngc.nvidia.com", "data.pyg.org"]);
/** Code hosts: a repository or archive there is publicly addressable (its git or URL dependency is reported as not checkable). */
export const CODE_HOSTS = /^(?:github\.com|codeload\.github\.com|api\.github\.com|raw\.githubusercontent\.com|gitlab\.com|bitbucket\.org)$/i;

/** The lowercase host of a URL (quotes around it allowed), or null. */
export const hostOf = (url: string): string | null => {
  try {
    return new URL(url.trim().replace(/^["']|["']$/g, "")).hostname.toLowerCase();
  } catch {
    return null;
  }
};

/** Whether `host` is one of the public npm registries. */
export const isPublicNpmHost = (host: string): boolean => PUBLIC_NPM_HOSTS.has(host.toLowerCase());

/** Whether an npm registry URL is the public registry (or a public mirror of it). */
export function isPublicNpmRegistry(url: string): boolean {
  const host = hostOf(url);
  return host !== null && PUBLIC_NPM_HOSTS.has(host);
}

/** Whether a Python index URL is pypi.org. */
export function isPublicPypiIndex(url: string): boolean {
  const host = hostOf(url);
  return host !== null && PUBLIC_PYPI_HOSTS.has(host);
}

/** Whether an extra index (beside pypi.org) is pypi.org or a well-known public wheel index. */
export function isPublicExtraPypiIndex(url: string): boolean {
  const host = hostOf(url);
  return isPublicPypiIndex(url) || (host !== null && PUBLIC_EXTRA_PYPI_HOSTS.has(host));
}

/** Whether a Cargo.lock `source` is crates.io. */
export function isPublicCratesSource(source: string): boolean {
  const bare = (s: string) => s.trim().replace(/\/+$/, "").toLowerCase();
  return [...PUBLIC_CRATES_SOURCES].some((s) => bare(s) === bare(source));
}

/** Whether a GOPROXY entry's URL is a public module proxy. */
export function isPublicGoProxy(url: string): boolean {
  const host = hostOf(url);
  return host !== null && PUBLIC_GO_PROXY_HOSTS.has(host);
}

/**
 * A registry, index or git URL as it may be shown: no credentials, no query, no fragment
 * (a lockfile URL can carry a token: `https://user:token@npm.acme.dev/`).
 */
export function sourceLabel(source: string): string {
  const m = /^([a-z]+\+)?(.*)$/i.exec(source.trim());
  const prefix = m?.[1] ?? "";
  try {
    const u = new URL(m?.[2] ?? source);
    return `${prefix}${u.protocol}//${u.host}${u.pathname}`.replace(/\/+$/, "");
  } catch {
    return prefix ? `${prefix}(unreadable URL)` : "(unreadable URL)";
  }
}

// ---------------------------------------------------------------------------------------------
// A small TOML reader: tables, arrays of tables, `key = value` lines, inline tables and arrays.
// ---------------------------------------------------------------------------------------------

/** A line without its `#` comment (a `#` inside quotes kept). */
export function stripComment(line: string): string {
  let quote: string | null = null;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (quote) {
      if (c === quote) quote = null;
    } else if (c === '"' || c === "'") quote = c;
    else if (c === "#" && (i === 0 || /\s/.test(line[i - 1]))) return line.slice(0, i);
  }
  return line;
}

/** A TOML string value (`"x"` or `'x'`), or null. */
export const tomlString = (raw: string): string | null => {
  const m = /^\s*(?:"((?:[^"\\]|\\.)*)"|'([^']*)')/.exec(raw);
  return m ? (m[1] ?? m[2] ?? "") : null;
};

/** Every string literal in a TOML value (an array `["a", 'b']`, or one string). */
export const tomlStrings = (raw: string): string[] => [...raw.matchAll(/"((?:[^"\\]|\\.)*)"|'([^']*)'/g)].map((m) => m[1] ?? m[2] ?? "");

/** A key of a TOML inline table (`{ url = "x", token = "y" }`), or null. */
export const inlineKey = (table: string, key: string): string | null => {
  const m = new RegExp(`(?:^|[{,])\\s*${key}\\s*=\\s*("(?:[^"\\\\]|\\\\.)*"|'[^']*')`).exec(table);
  return m ? tomlString(m[1]) : null;
};

/** A boolean key of a TOML inline table, or null. */
export const inlineBool = (table: string, key: string): boolean | null => {
  const m = new RegExp(`(?:^|[{,])\\s*${key}\\s*=\\s*(true|false)\\b`).exec(table);
  return m ? m[1] === "true" : null;
};

/** `[table]` or `[[array-of-tables]]` header name, or null. */
export const tomlHeader = (line: string): { name: string; array: boolean } | null => {
  const m = /^\[(\[)?\s*([^\]]+?)\s*\]\]?\s*$/.exec(line);
  return m ? { name: m[2].replace(/\s*\.\s*/g, ".").replace(/["']/g, ""), array: Boolean(m[1]) } : null;
};

/** `key = value` of one TOML line (comments stripped), or null. */
export const tomlKeyValue = (line: string): { key: string; value: string } | null => {
  const m = /^("(?:[^"\\]|\\.)*"|'[^']*'|[A-Za-z0-9_.-]+)\s*=\s*(.+)$/.exec(line);
  return m ? { key: tomlString(m[1]) ?? m[1], value: m[2].trim() } : null;
};

/**
 * The lines of a TOML file, comments stripped, blank ones dropped, and a value that spans lines
 * (an array or inline table left open) joined onto its key's line.
 */
export const tomlLines = (content: string): string[] => {
  const out: string[] = [];
  let open = 0;
  for (const raw of content.split(/\r?\n/)) {
    const line = stripComment(raw).trim();
    if (!line) continue;
    const depth = bracketDepth(line);
    // A table header ends any value left open (an unbalanced bracket in a multi-line string).
    if (open > 0 && /^\[\[?\s*[A-Za-z0-9_."' -]+?\s*\]\]?$/.test(line) && !/^\[\s*["']/.test(line)) open = 0;
    if (open > 0) {
      out[out.length - 1] += ` ${line}`;
      open += depth;
      continue;
    }
    out.push(line);
    // A header is balanced on its own line; only a value can stay open.
    if (!line.startsWith("[")) open = Math.max(0, depth);
  }
  return out;
};

/** Open minus closed brackets and braces outside quotes. */
function bracketDepth(line: string): number {
  let depth = 0;
  let quote: string | null = null;
  for (const c of line) {
    if (quote) {
      if (c === quote) quote = null;
    } else if (c === '"' || c === "'") quote = c;
    else if (c === "[" || c === "{") depth++;
    else if (c === "]" || c === "}") depth--;
  }
  return depth;
}
