// SPDX-License-Identifier: Apache-2.0
/**
 * What in a briefing task is never read as a package name, before either reader sees it (pre-publish
 * audit 2026-11-25, E1, E2, F-M3).
 *
 * E1: what_should_i_know took any word after an adding verb for a new package and looked it up on the
 * public registry and OSV.dev, so a credential written in the task ("add ghp_... as the GH_TOKEN
 * secret", `sk_live_...`, `AKIA...`, the user name in `https://user:pass@host`) was sent out.
 * E2: a command in the task that installs from a private registry, an index, a source, git, a path, a
 * file or a URL (`npm install --registry https://npm.x.internal x`, `pip install -i <url> x`,
 * `cargo add x --registry r`, `npm i file:../x`, `"x @ https://..."`, `x = { git = "..." }`) still had
 * its packages looked up publicly, and the option's VALUE (the private host, "https", "file") was
 * sent as a package name. F-M3: a task word of unbounded length reached quadratic patterns.
 *
 * So the task is screened first. Every span below is blanked (same length, so positions hold) and
 * nothing in it is read or sent:
 * - a word longer than any registry allows a name to be (MAX_TASK_WORD);
 * - a command that names a registry, index or source other than the public one (as the guard hook
 *   reads it, hooks/manifest-edit.mjs): the whole command, its packages withheld by name;
 * - an operand or manifest entry taken from git, a path, a file or a URL, its package withheld by name;
 * - a registry the task sets (`npm config set registry`, an .npmrc or pip.conf line, NPM_CONFIG_REGISTRY,
 *   PIP_INDEX_URL, GOPROXY / GOPRIVATE): every name of that ecosystem (or `@scope`) withheld;
 * - URLs, scp-style git remotes and email addresses;
 * - credentials: known token shapes, the value of a TOKEN / KEY / SECRET / PASSWORD assignment, and
 *   high-entropy words (long runs mixing capitals, small letters and digits, or long hex-like runs).
 * A withheld package is reported NOT CHECKED with the reason; a credential, URL or address is
 * reported (redacted) only when a reader would otherwise have taken a name from it.
 */

import type { CheckEcosystem } from "../live/release-metadata.js";

/**
 * The longest word read from a task. npm allows 214 characters, crates.io 64, PyPI no more in
 * practice, and the Go reader takes a module path up to 300 (briefing-new-packages.ts asName).
 */
export const MAX_TASK_WORD = 300;

export interface Withheld {
  /** What the answer names: the package, or a redacted description of the word. */
  label: string;
  why: string;
  /** Reported whatever the readers would have read; otherwise only when a reader lost a name to it. */
  always: boolean;
  start: number;
  end: number;
}

export interface TaskScreen {
  /** The task with every withheld span blanked. */
  text: string;
  withheld: Withheld[];
  /** Package names the task takes from somewhere other than the public registry (lower case). */
  names: Set<string>;
  /** npm scopes the task maps to another registry (`@acme`, lower case). */
  scopes: Set<string>;
  /** Ecosystems whose public registry the task replaces: none of their names is looked up. */
  ecosystems: Map<CheckEcosystem, string>;
}

const LEAD_QUOTES = "\"'`";
const LEAD_WRAP = "\"'`(";
const TRAIL_WRAP = "\"'`,;:.)";

/**
 * `s` without the characters of `lead` before it and of `trail` after it. A loop, not a regex: a
 * trailing run matched with `$` is rescanned from every position inside it (F-M3).
 */
function strip(s: string, lead: string, trail: string): string {
  let a = 0;
  let b = s.length;
  while (a < b && lead.includes(s[a])) a++;
  while (b > a && trail.includes(s[b - 1])) b--;
  return s.slice(a, b);
}

const PUBLIC_NPM_HOSTS = new Set(["registry.npmjs.org", "registry.npmjs.com", "registry.yarnpkg.com", "registry.npmmirror.com"]);

function hostOf(value: string): string | null {
  try {
    return new URL(strip(value, LEAD_QUOTES, "\"'`,;")).hostname.toLowerCase();
  } catch {
    return null;
  }
}
const publicNpm = (value: string | undefined) => value !== undefined && PUBLIC_NPM_HOSTS.has(hostOf(value) ?? "");
const publicPypi = (value: string | undefined) => value !== undefined && /^["'`]?https:\/\/pypi\.org\/simple\/?["'`]?$/i.test(value);
const publicGoProxy = (value: string) => value.split(/[,|]/).every((p) => /^(?:https:\/\/proxy\.golang\.org\/?|direct|off)$/i.test(strip(p, LEAD_QUOTES, LEAD_QUOTES)));

type Family = "js" | "py" | "poetry" | "cargo" | "go";
const FAMILIES: Record<string, Family> = {
  npm: "js", pnpm: "js", yarn: "js", bun: "js", npx: "js", pnpx: "js", bunx: "js",
  pip: "py", pip3: "py", uv: "py", pipenv: "py", pdm: "py", rye: "py", pipx: "py",
  poetry: "poetry", cargo: "cargo", go: "go",
};

/** Options that take the next word as their value, per family (hooks/manifest-edit.mjs's tables). */
const VALUE_OPTIONS: Record<Family, ReadonlySet<string>> = {
  js: new Set([
    "--prefix", "-w", "--workspace", "--tag", "--loglevel", "--cache", "--userconfig", "--globalconfig", "--omit", "--include", "--install-strategy", "--before", "--otp",
    "--save-prefix", "--scope", "--script-shell", "-C", "--location", "--audit-level", "--fetch-retries", "--fetch-timeout", "--auth-type", "--workspace-concurrency",
    "--filter", "-F", "--dir", "--reporter", "--store-dir", "--virtual-store-dir", "--modules-dir", "--lockfile-dir", "--config", "--save-catalog-name",
    "--network-concurrency", "--child-concurrency", "--resolution-mode", "--node-linker", "--depth", "--cwd", "--network-timeout", "--mutex", "--cache-folder",
    "--modules-folder", "--global-folder", "--link-folder", "--use-yarnrc", "-j", "--jobs", "--exclude", "--from", "-c", "--backend", "--cache-dir",
    "--concurrent-scripts", "-p", "--package", "--proxy", "--https-proxy", "--ca", "--cafile", "--cert", "--key", "--registry", "-L", "-m",
  ]),
  py: new Set([
    "-r", "--requirement", "-c", "--constraint", "-e", "--editable", "-t", "--target", "--prefix", "--root", "--trusted-host", "--python-version", "--platform",
    "--implementation", "--abi", "--src", "--cache-dir", "--log", "--proxy", "--timeout", "--retries", "--progress-bar", "--upgrade-strategy", "--no-binary",
    "--only-binary", "--config-settings", "-C", "--global-option", "--report", "--python", "-p", "--exclude-newer", "--index-strategy", "--keyring-provider",
    "--resolution", "--prerelease", "--link-mode", "--override", "--overrides", "--group", "--extra", "--python-platform", "--torch-backend", "--build-constraint",
    "-b", "--optional", "--package", "--project", "--directory", "--marker", "-m", "--bounds", "--script", "--config-file", "--requirements", "--constraints",
    "--tag", "--branch", "--rev", "--refresh-package", "--reinstall-package", "--upgrade-package", "-P", "--no-binary-package", "--no-build-package",
    "--fork-strategy", "--python-preference", "--color", "-i", "--index-url", "--extra-index-url", "--index", "--default-index", "-f", "--find-links", "--cert", "--client-cert",
  ]),
  poetry: new Set(["--group", "-G", "--extras", "-E", "--python", "--platform", "--markers", "--directory", "-C", "--project", "-P", "--optional", "--source"]),
  cargo: new Set(["-C", "-F", "--features", "--rename", "-p", "--package", "--manifest-path", "--target", "--config", "-Z", "--color", "--lockfile-path", "--git", "--path", "--registry", "--branch", "--tag", "--rev", "--index"]),
  go: new Set(["-C", "-tags", "-modfile", "-ldflags", "-gcflags", "-asmflags", "-mod", "-o", "-p", "-pkgdir", "-toolexec"]),
};

/** Whether option `flag` of a `manager` command takes the next word as its value (its value is never a package). */
export function optionTakesValue(manager: string, flag: string): boolean {
  const family = FAMILIES[manager.toLowerCase()];
  return family !== undefined && VALUE_OPTIONS[family].has(flag);
}

/** The kind of source a command's option names, or null when it names none (or the public one). */
function sourceOption(family: Family, flag: string, value: string | undefined): string | null {
  if (family === "js") {
    if (flag === "--registry") return publicNpm(value) ? null : "a registry named in its command";
    if (/^--@[^:]+:registry$/i.test(flag)) return "a registry named in its command";
    return null;
  }
  if (family === "py") {
    if (["-i", "--index-url", "--extra-index-url", "--index", "--default-index"].includes(flag)) return publicPypi(value?.replace(/^[\w-]+=/, "")) ? null : "a package index named in its command";
    if (flag === "-f" || flag === "--find-links") return "a find-links location named in its command";
    return null;
  }
  if (family === "poetry") return flag === "--source" ? "a source named in its command" : null;
  if (family === "cargo") {
    if (flag === "--registry") return value === "crates-io" ? null : "a registry named in its command";
    if (flag === "--git" || flag === "--branch" || flag === "--tag" || flag === "--rev") return "git";
    if (flag === "--path") return "a path";
    if (flag === "--index") return "a registry index named in its command";
  }
  return null;
}

/** The kind of non-registry source a package spec names (`file:../x`, `git+ssh://...`, `./x`, `user/repo`), or null. */
export function specSource(spec: string, family: Family | null): string | null {
  const s = strip(spec, LEAD_QUOTES, "\"'`,;)");
  const after = /^(?:@[^@/\s]+\/)?[^@/\s]+@(.+)$/.exec(s)?.[1];
  const value = after && !/^(?:npm:|v?\d|[~^<>=*]|latest$|next$)/i.test(after) ? after : s;
  if (/^(?:git\+|git:|github:|gitlab:|bitbucket:|gist:|ssh:)/i.test(value)) return "git";
  if (/^(?:file:|link:|portal:)/i.test(value)) return "a path";
  if (/^workspace:/i.test(value)) return "a workspace";
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(value)) return "a URL";
  // scp-style `git@host.tld:org/repo` (a dotted host: `alias@npm:target@1.0` is an npm alias, not a remote).
  if (/^[\w.-]+@[\w-]+(?:\.[\w-]+)+:/.test(value)) return "git";
  if (/^(?:\.{1,2}[\\/]|[\\/]|~[\\/]|[a-z]:[\\/])/i.test(value) || value === "." || value === "..") return "a path";
  if (/\.(?:tgz|tar\.gz|tar\.bz2|tar|whl|zip|egg|crate)$/i.test(value)) return "a local file";
  // npm reads a bare `user/repo` as a GitHub repository.
  if (family === "js" && /^[\w.-]+\/[\w.-]+(?:#\S*)?$/.test(value) && !value.startsWith("@")) return "git";
  return null;
}

/** The package name of an operand (`x@1.2.3`, `x==1.0`, `x[extra]>=2`), or null when none can be read. */
function operandName(spec: string): string | null {
  const s = strip(spec, LEAD_WRAP, TRAIL_WRAP);
  const scoped = /^(@[\w.~-]+\/[\w.~-]+)/.exec(s);
  const name = scoped ? scoped[1] : (/^([A-Za-z0-9][\w.~-]*)/.exec(s)?.[1] ?? null);
  return name && name.length <= MAX_TASK_WORD ? name : null;
}

/** Known credential shapes (GitHub, AWS, Stripe, Slack, npm, GitLab, OpenAI, Anthropic, Google, Hugging Face, PyPI, SendGrid, Shopify, DigitalOcean, JWT, PEM). */
const SECRET_SHAPES =
  /\b(?:gh[pousr]_[A-Za-z0-9]{10,}|github_pat_\w{10,}|(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[A-Z0-9]{12,}|[rs]k_(?:live|test)_\w{6,}|pk_live_\w{6,}|whsec_\w{10,}|xox[abposre]-[\w-]{6,}|npm_[A-Za-z0-9]{10,}|glpat-[\w-]{10,}|sk-(?:proj|ant|svcacct|admin)-[\w-]{6,}|sk-[A-Za-z0-9]{20,}|AIza[\w-]{20,}|hf_[A-Za-z0-9]{10,}|pypi-[\w-]{20,}|SG\.[\w-]{10,}\.[\w-]{10,}|shp(?:at|ss|ca|pa)_[a-fA-F0-9]{16,}|dop_v1_[a-f0-9]{20,}|eyJ[\w-]{8,}\.[\w-]{8,}(?:\.[\w-]*)?)/g;
/** The value of an assignment to a credential-named setting: `GITHUB_TOKEN=...`, `_authToken=...`, `"api_key": "..."`. */
const SECRET_ASSIGNMENT = /(?:\b[A-Za-z][\w.-]{0,60}?(?:token|secret|passw(?:or)?d|pwd|api[_-]?key|access[_-]?key|private[_-]?key|auth)\w{0,30}|\b_auth)(?:["'`]\s{0,4}:|\s{0,4}=)\s{0,4}["'`]?([^\s"'`]{4,})/gi;
const PEM = /-----BEGIN [A-Z ]{0,40}-----[\s\S]{0,8000}?(?:-----END [A-Z ]{0,40}-----|$)/g;

/** A word shaped like a generated credential rather than a package name. */
export function looksLikeSecret(word: string): boolean {
  const w = strip(word, LEAD_WRAP, TRAIL_WRAP);
  if (new RegExp(SECRET_SHAPES.source).test(w)) return true;
  for (const seg of w.split(/[-_.:/@=]+/)) {
    if (seg.length < 10) continue;
    const upper = (seg.match(/[A-Z]/g) ?? []).length;
    const lower = (seg.match(/[a-z]/g) ?? []).length;
    const digits = (seg.match(/\d/g) ?? []).length;
    // Mixed capitals, small letters and digits in one run: names are words, not this.
    if (upper >= 2 && lower >= 2 && digits >= 2) return true;
    // A long run of letters and many digits (hex, base32): no registry name looks like this.
    if (seg.length >= 20 && digits >= 4 && digits + upper + lower === seg.length && digits >= seg.length / 5) return true;
  }
  return false;
}

/** A credential as the answer names it: its first four characters and its length, never the rest. */
function redact(word: string): string {
  return `${word.slice(0, 4)}... (${word.length} characters)`;
}

const NOT_SENT = "nothing about it was sent";

/** Words that end a command in prose ("then", "&&", ";"), and verbs that start the next clause after "and". */
const COMMAND_ENDS = new Set(["then", "&&", "||", ";", "|", "and", "or", "but", "after", "before", "so"]);

export function screenTask(task: string): TaskScreen {
  const chars = task.split("");
  const withheld: Withheld[] = [];
  const names = new Set<string>();
  const scopes = new Set<string>();
  const ecosystems = new Map<CheckEcosystem, string>();
  const blanked = new Uint8Array(task.length);
  const blank = (start: number, end: number) => {
    for (let k = Math.max(0, start); k < Math.min(end, task.length); k++) {
      if (chars[k] !== "\n") chars[k] = " ";
      blanked[k] = 1;
    }
  };
  const hold = (label: string, why: string, start: number, end: number, always: boolean) => {
    withheld.push({ label, why, always, start, end });
    blank(start, end);
  };
  const holdPackage = (name: string, kind: string, start: number, end: number) => {
    names.add(name.toLowerCase());
    hold(name, `not looked up: the task takes it from ${kind}`, start, end, true);
  };
  const closeEcosystem = (ecosystem: CheckEcosystem, what: string, start: number, end: number) => {
    if (!ecosystems.has(ecosystem)) ecosystems.set(ecosystem, what);
    blank(start, end);
  };

  // 1. Words longer than any package name: never read (and no pattern runs over them).
  for (const m of task.matchAll(/\S{301,}/g)) {
    // A URL is read as one below, whatever its length.
    if (/^["'`(]*(?:[a-z][a-z0-9+.-]{0,30}:)?\/\//i.test(m[0])) continue;
    hold(`a word of ${m[0].length} characters`, "not read: longer than any package name", m.index!, m.index! + m[0].length, true);
  }
  const free = (start: number, end: number) => {
    for (let k = start; k < end; k++) if (blanked[k]) return false;
    return true;
  };

  // 2. Manifest entries taken from git, a path, a workspace or a URL, written into the task.
  const JSON_SOURCE = /(["'])(@?[\w.~-]{1,214}(?:\/[\w.~-]{1,214})?)\1\s{0,8}:\s{0,8}(["'])([^"'\n]{1,500})\3/g;
  for (const m of task.matchAll(JSON_SOURCE)) {
    const kind = specSource(m[4], "js");
    if (kind && free(m.index!, m.index! + m[0].length)) holdPackage(m[2], kind, m.index!, m.index! + m[0].length);
  }
  const TOML_SOURCE = /(^|[\s`(])([A-Za-z0-9][\w.-]{0,213})\s{0,8}=\s{0,8}\{([^}\n]{0,400})\}/gm;
  for (const m of task.matchAll(TOML_SOURCE)) {
    const fields = m[3];
    const kind = /\bgit\s{0,4}=/.test(fields) ? "git" : /\bpath\s{0,4}=/.test(fields) ? "a path" : /\burl\s{0,4}=/.test(fields) ? "a URL" : /\bworkspace\s{0,4}=\s{0,4}true/.test(fields) ? "a workspace" : /\bregistry\s{0,4}=\s{0,4}["'](?!crates-io["'])/.test(fields) || /\bsource\s{0,4}=/.test(fields) ? "a registry or source named in the entry" : null;
    const start = m.index! + m[1].length;
    if (kind && free(start, m.index! + m[0].length)) holdPackage(m[2], kind, start, m.index! + m[0].length);
  }
  // PEP 508 direct reference: `name @ https://...`, `name[extra] @ git+...`, `name @ file:///...`.
  const PEP508_URL = /(^|[\s"'`(,[])([A-Za-z0-9][\w.-]{0,99})(?:\[[^\]\n]{0,200}\])?\s{0,8}@\s{0,8}((?:git\+|https?:|file:|ssh:|ftp:)[^\s"'`,\]]{0,2000})/gim;
  for (const m of task.matchAll(PEP508_URL)) {
    const start = m.index! + m[1].length;
    const end = m.index! + m[0].length;
    if (free(start, end)) holdPackage(m[2], specSource(m[3], "py") ?? "a URL", start, end);
  }

  // 3. Registries the task sets: .npmrc / pip.conf lines, environment variables, config commands.
  for (const m of task.matchAll(/(^|[\s"'`])(@[\w.-]{1,214}):registry\s{0,4}[=\s]\s{0,4}(\S{1,2000})/gim)) {
    if (publicNpm(m[3])) continue;
    scopes.add(m[2].toLowerCase());
    blank(m.index! + m[1].length, m.index! + m[0].length);
  }
  for (const m of task.matchAll(/(^|[\s"'`])((?:npm_config_|NPM_CONFIG_)?registry|npmRegistryServer)\s{0,4}[=\s]\s{0,4}["'`]?((?:https?:)?\/\/\S{1,2000})/gm)) {
    if (!publicNpm(m[3])) closeEcosystem("npm", "a registry the task sets for npm", m.index! + m[1].length, m.index! + m[0].length);
  }
  for (const m of task.matchAll(/(^|[\s"'`])((?:PIP_|UV_)?(?:EXTRA_)?(?:INDEX_URL|DEFAULT_INDEX|INDEX)|(?:global\.)?(?:extra-)?index-url|index_url)\s{0,4}[=\s]\s{0,4}["'`]?(\S{1,2000})/gim)) {
    if (/^(?:https?:|\/\/|file:|\.|\/|[a-z]:)/i.test(m[3]) && !publicPypi(m[3])) closeEcosystem("PyPI", "a package index the task sets for PyPI", m.index! + m[1].length, m.index! + m[0].length);
  }
  for (const m of task.matchAll(/(^|[\s"'`])(GOPROXY|GOPRIVATE|GONOPROXY|GONOSUMDB|GOFLAGS)\s{0,4}=\s{0,4}["'`]?(\S{1,2000})/g)) {
    if (m[2] === "GOPROXY" && publicGoProxy(m[3])) continue;
    if (m[2] === "GOFLAGS" && !/-mod|insecure/.test(m[3])) continue;
    closeEcosystem("Go", "a module proxy or private module setting the task gives for Go", m.index! + m[1].length, m.index! + m[0].length);
  }
  for (const m of task.matchAll(/\breplace-with\s{0,4}=\s{0,4}["'`]?[\w-]{1,100}/g)) closeEcosystem("crates.io", "a source replacement the task sets for crates.io", m.index!, m.index! + m[0].length);

  // 4. Commands, word by word.
  const words = [...task.matchAll(/\S+/g)].map((m) => ({ text: m[0], start: m.index!, end: m.index! + m[0].length }));
  const bare = (w: string) => strip(w, LEAD_WRAP, TRAIL_WRAP);
  for (let i = 0; i < words.length; i++) {
    const manager = bare(words[i].text).toLowerCase();
    const family = FAMILIES[manager];
    if (!family || !free(words[i].start, words[i].end)) continue;
    // The command's words: to a clause break ("then", "&&", ";", a sentence end) or 40 words.
    let j = i + 1;
    let last = i;
    for (; j < words.length && j - i <= 40; j++) {
      const w = words[j].text;
      if (COMMAND_ENDS.has(w.toLowerCase())) break;
      last = j;
      // A sentence or clause ends with this word ("x.", "x;", "x`").
      if (/[;!?`]["')]*$/.test(w) || /[A-Za-z0-9"'`)]\.["')]*$/.test(w)) break;
    }
    const args = words.slice(i + 1, last + 1);
    // `npm config set registry <url>`, `npm config set @acme:registry <url>`, `pip config set global.index-url <url>`.
    const lowered = args.map((a) => bare(a.text).toLowerCase());
    const setAt = lowered[0] === "config" && lowered[1] === "set" ? 2 : lowered[0] === "set" && family === "js" ? 1 : -1;
    if (setAt >= 0 && args[setAt]) {
      const [key, inline] = bare(args[setAt].text).split(/=(.*)/s);
      const value = inline || bare(args[setAt + 1]?.text ?? "");
      const end = (inline ? args[setAt] : (args[setAt + 1] ?? args[setAt])).end;
      if (family === "js" && /^@[\w.-]+:registry$/i.test(key) && !publicNpm(value)) {
        scopes.add(key.slice(0, key.indexOf(":")).toLowerCase());
        blank(words[i].start, end);
      } else if (family === "js" && /^(?:registry|npmRegistryServer)$/i.test(key) && !publicNpm(value)) {
        closeEcosystem("npm", "a registry the task sets for npm", words[i].start, end);
      } else if (family === "py" && /index-url|index$/i.test(key) && !publicPypi(value)) {
        closeEcosystem("PyPI", "a package index the task sets for PyPI", words[i].start, end);
      }
      i = last;
      continue;
    }
    if (family === "poetry" && lowered[0] === "source" && lowered[1] === "add") {
      closeEcosystem("PyPI", "a package source the task adds for Poetry", words[i].start, (args[args.length - 1] ?? words[i]).end);
      i = last;
      continue;
    }
    // Options and operands; option values are never operands.
    let source: string | null = null;
    const operands: typeof args = [];
    for (let k = 0; k < args.length; k++) {
      const text = bare(args[k].text);
      if (text.startsWith("-") && text.length > 1 && text !== "--") {
        const eq = text.indexOf("=");
        const flag = eq > 0 ? text.slice(0, eq) : text;
        const value = eq > 0 ? text.slice(eq + 1) : args[k + 1] ? bare(args[k + 1].text) : undefined;
        source ??= sourceOption(family, flag, value);
        if (eq < 0 && VALUE_OPTIONS[family].has(flag)) k++;
        continue;
      }
      operands.push(args[k]);
    }
    // The subcommand (`install`, `add`, `pip install`) is no package. Only an install's operands are
    // packages: "go to https://..." or "npm run build" installs nothing (a runner, npx, runs a package).
    const runner = manager === "npx" || manager === "pnpx" || manager === "bunx";
    let installs = runner;
    while (operands.length > 0 && /^(?:install|i|add|a|get|require|in|ins|isntall|pip|exec|dlx|x|update|up|upgrade)$/i.test(bare(operands[0].text))) {
      if (!/^pip$/i.test(bare(operands[0].text))) installs = true;
      operands.shift();
    }
    if (!installs) operands.length = 0;
    if (source) {
      for (const o of operands) {
        const name = operandName(o.text);
        if (name && !/^(?:https?|file|git|ssh)$/i.test(name)) holdPackage(name, source, o.start, o.end);
      }
      blank(words[i].start, (args[args.length - 1] ?? words[i]).end);
      i = last;
      continue;
    }
    for (let k = 0; k < operands.length; k++) {
      const o = operands[k];
      if (!free(o.start, o.end)) continue;
      const kind = specSource(o.text, family);
      if (!kind) continue;
      // `name@file:../x` names the package; a bare path or URL names only the source.
      const named = /^(?:@[^@/\s]+\/)?[^@/\s:]+@/.test(bare(o.text)) ? operandName(o.text) : null;
      if (named) holdPackage(named, kind, o.start, o.end);
      else hold(bare(o.text).slice(0, 80), `not looked up: the task installs it from ${kind}, not by a registry name`, o.start, o.end, true);
    }
  }

  // 5. URLs, scp-style git remotes and email addresses: never a name (a user name or token inside one included).
  for (const m of task.matchAll(/(?:\b[a-z][a-z0-9+.-]{0,30}:)?\/\/[^\s"'`<>]+/gi)) {
    if (!free(m.index!, m.index! + m[0].length)) {
      blank(m.index!, m.index! + m[0].length);
      continue;
    }
    const host = /\/\/(?:[^@/\s]*@)?([^/:\s?#]+)/.exec(m[0])?.[1] ?? "";
    hold(`a URL (${host || "no host"})`, `not read: a URL is not a package name; ${NOT_SENT}`, m.index!, m.index! + m[0].length, false);
  }
  for (const m of task.matchAll(/\b[\w.-]{1,64}@[\w.-]{1,253}\.[a-z]{2,}:[\w./~-]{1,500}/gi)) hold("a git remote", `not read: a git remote is not a package name; ${NOT_SENT}`, m.index!, m.index! + m[0].length, false);
  for (const m of task.matchAll(/(?<![@\w.+-])[\w.+-]{1,64}@[a-z][a-z0-9-]{0,62}(?:\.[a-z0-9-]{1,63}){0,8}\.[a-z]{2,24}\b/gi)) {
    if (free(m.index!, m.index! + m[0].length)) hold("an email address", `not read: an address is not a package name; ${NOT_SENT}`, m.index!, m.index! + m[0].length, false);
  }

  // 6. Credentials.
  for (const m of task.matchAll(PEM)) hold("a private key block", `not read: it looks like a credential; ${NOT_SENT}`, m.index!, m.index! + m[0].length, false);
  for (const m of task.matchAll(SECRET_ASSIGNMENT)) {
    const start = m.index! + m[0].length - m[1].length;
    if (free(start, start + m[1].length)) hold(redact(m[1]), `not read: it is the value of a credential setting; ${NOT_SENT}`, start, start + m[1].length, false);
  }
  for (const w of words) {
    if (!free(w.start, w.end)) continue;
    // Each part of a word joined by `=` or `:` (`GITHUB_TOKEN=ghp_...`), judged on its own.
    let offset = 0;
    for (const part of w.text.split(/([=:,])/)) {
      if (part.length > 1 && looksLikeSecret(part)) hold(redact(bare(part)), `not read: it looks like a credential; ${NOT_SENT}`, w.start + offset, w.start + offset + part.length, false);
      offset += part.length;
    }
  }

  return { text: chars.join(""), withheld, names, scopes, ecosystems };
}

/** The task with only its over-long words blanked: what the readers read with no screen, bounded. */
export function boundWords(task: string): string {
  return task.replace(/\S{301,}/g, (w) => " ".repeat(w.length));
}

/** Whether a package a reader found is withheld by the screen, and why. */
export function screenedOut(screen: TaskScreen, name: string, ecosystems: readonly CheckEcosystem[]): string | null {
  const lower = name.toLowerCase();
  if (screen.names.has(lower)) return "not looked up: the task takes it from somewhere other than the public registry";
  const scope = lower.startsWith("@") ? lower.slice(0, lower.indexOf("/")) : null;
  if (scope && screen.scopes.has(scope)) return `not looked up: the task maps ${scope} to another registry`;
  for (const e of ecosystems) {
    const why = screen.ecosystems.get(e);
    if (why) return `not looked up: the task takes ${e} packages from ${why}`;
  }
  return null;
}
