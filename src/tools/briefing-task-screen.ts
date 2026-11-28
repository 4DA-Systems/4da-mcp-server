// SPDX-License-Identifier: Apache-2.0
/**
 * NOTES: how it reads; not part of the contract (what-should-i-know.ts THE CONTRACT).
 *
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

import { POPULAR_NPM } from "../live/popular-npm.js";
import { POPULAR_PYPI } from "../live/popular-pypi.js";
import type { CheckEcosystem } from "../live/release-metadata.js";
import { checkableSpec, closestPopularPypi, normalizePypiName } from "./briefing-names.js";
import { nearMissOf } from "./dependency-check-nearmiss.js";

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
  /**
   * It stands where a package stands: a package name the task takes from elsewhere, or a word among an
   * install command's operands. Only such a word keeps the briefing from clearing the task (wave 2, change B):
   * a setting or a value in prose is listed and weighs nothing.
   */
  standing?: true;
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
  const family = Object.hasOwn(FAMILIES, manager.toLowerCase()) ? FAMILIES[manager.toLowerCase()] : undefined;
  return family !== undefined && VALUE_OPTIONS[family].has(flag);
}

/** The kind of source a command's option names, or null when it names none (or the public one). */
function sourceOption(family: Family, flag: string, value: string | undefined): string | null {
  if (family === "js") {
    // npm takes an option by any unambiguous prefix (`--reg URL`), and a URL may be glued to a short one
    // (`-ihttps://...`): any option but a proxy whose value is a registry URL other than npm's names one
    // (fourth blind check).
    if (/^--reg(?:i(?:s(?:t(?:r(?:y)?)?)?)?)?$/i.test(flag)) return publicNpm(value) ? null : "a registry named in its command";
    if (/^--@[^:]+:registry$/i.test(flag)) return "a registry named in its command";
    const url = flag.includes("://") ? flag.replace(/^-{1,2}[A-Za-z]?/, "") : value;
    if (!/proxy/i.test(flag) && url && /^(?:https?:)?\/\//i.test(url) && !publicNpm(url)) return "a registry named in its command";
    return null;
  }
  // A long option given by a prefix of its name (`--inde`, `--extra-index`, `--reg`), as pip and npm take one.
  const prefixOf = (...full: string[]) => flag.startsWith("--") && flag.length >= 5 && full.some((f) => f.startsWith(flag.toLowerCase()));
  if (family === "py") {
    if (flag === "-i" || prefixOf("--index-url", "--extra-index-url", "--index", "--default-index")) return publicPypi(value?.replace(/^[\w-]+=/, "")) ? null : "a package index named in its command";
    if (flag === "-f" || prefixOf("--find-links")) return "a find-links location named in its command";
    // A URL glued to a short option (`-ihttps://...`), or any option but a proxy whose value is an index URL.
    const url = flag.includes("://") ? flag.replace(/^-{1,2}[A-Za-z]?/, "") : value;
    if (!/proxy|cert/i.test(flag) && url && /^(?:https?:)?\/\//i.test(url) && !publicPypi(url)) return "a package index named in its command";
    return null;
  }
  if (family === "poetry") return flag === "--source" ? "a source named in its command" : null;
  if (family === "cargo") {
    if (prefixOf("--registry")) return value === "crates-io" ? null : "a registry named in its command";
    if (flag === "--git" || flag === "--branch" || flag === "--tag" || flag === "--rev") return "git";
    if (flag === "--path") return "a path";
    if (prefixOf("--index")) return "a registry index named in its command";
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
  if (/^catalog:/i.test(value)) return "a catalog";
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

/**
 * Known credential shapes (GitHub, AWS, Stripe, Slack, npm, GitLab, OpenAI, Anthropic, Google, Hugging Face, PyPI,
 * SendGrid, Shopify, DigitalOcean, JWT). Round 16b: the word boundary is a property of each shape, decided by
 * measurement (a1139-round16b: the bundled popular npm and PyPI names, the bench world's names and 50,000 words joined
 * in pairs). A shape whose prefix is distinctive matches anywhere, glued to the text before it or not; a shape whose
 * prefix is ordinary text keeps a leading boundary (BOUNDARY_SHAPES: "sk-" sits inside "risk-", "task-", "desk-";
 * "sk_test_" inside "task_test_"). Round 16c: each body takes the issuer's documented length as its lower bound
 * (GitHub classic and npm 36, Hugging Face 34, GitLab 20, Stripe publishable 24 and webhook 32, Google 35, Shopify 32
 * hex, DigitalOcean 64 hex); a GitHub fine-grained token takes 22 word characters or more (its first part; any longer
 * spelling stays masked whole). Slack is digit-first (real ones xoxb-<digits>-...): with its old body ("xox?-" and six
 * word characters) it matched generated words even at a boundary ("xoxe-...").
 */
const ANYWHERE_SHAPES: readonly string[] = [
  "gh[pousr]_[A-Za-z0-9]{36,}",
  "github_pat_\\w{22,}",
  "(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[A-Z0-9]{12,}",
  "pk_live_[A-Za-z0-9]{24,}",
  "whsec_[A-Za-z0-9]{32,}",
  "xox[abposre]-[0-9][\\w-]{6,}",
  "npm_[A-Za-z0-9]{36,}",
  "glpat-[\\w-]{20,}",
  "AIza[\\w-]{35,}",
  "hf_[A-Za-z0-9]{34,}",
  // Round 19: a PyPI API token is a macaroon whose base64 opens "AgE" (version and location fields), 150+ characters;
  // "repypi-advisoryknowntoaffect", a pair of source words, matched the looser body.
  "pypi-AgE[\\w-]{50,}",
  "SG\\.[\\w-]{10,}\\.[\\w-]{10,}",
  "shp(?:at|ss|ca|pa)_[a-fA-F0-9]{32,}",
  "dop_v1_[a-f0-9]{64,}",
  "eyJ[\\w-]{8,}\\.[\\w-]{8,}(?:\\.[\\w-]*)?",
];
/** Round 16b: the shapes whose prefix is ordinary text: matched only at a word boundary (\b before the prefix). */
export const BOUNDARY_SHAPES: readonly string[] = ["[rs]k_(?:live|test)_\\w{6,}", "sk-(?:proj|ant|svcacct|admin)-[\\w-]{6,}", "sk-[A-Za-z0-9]{20,}"];
const SECRET_SHAPES = new RegExp(`(?:${[...ANYWHERE_SHAPES, ...BOUNDARY_SHAPES.map((x) => `\\b${x}`)].join("|")})`, "g");
/**
 * The credential shapes this server knows (round 14, X1): known token prefixes and a JWT. The output screen
 * (output-screen.ts) renders any substring of one of them by shape in every tool result and error.
 */
export const CREDENTIAL_SHAPES: RegExp = SECRET_SHAPES;
/** Round 19: one compiled, non-global copy for the per-word tests (a RegExp was built for every word). */
const SECRET_TEST = new RegExp(SECRET_SHAPES.source);
/** The value of an assignment to a credential-named setting: `GITHUB_TOKEN=...`, `_authToken=...`, `"api_key": "..."`. */
const SECRET_ASSIGNMENT = /(?:\b[A-Za-z][\w.-]{0,60}?(?:token|secret|passw(?:or)?d|pwd|api[_-]?key|access[_-]?key|private[_-]?key|auth)\w{0,30}|\b_auth)(?:["'`]\s{0,4}:|\s{0,4}=)\s{0,4}["'`]?([^\s"'`]{4,})/gi;
/** A value that is a version or a version constraint (`=3.2.0` after `oauthlib=`, `8.5.1`, `^4.10`, `>=2,<3`, `~=1.4`): an entry, not a secret. */
const SPEC_VALUE = /^(?:[=~<>!^]|v?\d+(?:\.(?:\d+|x|\*))+(?:[-+][\w.]+)?[,;)]?$|\*$|latest$)/i;
const PEM = /-----BEGIN [A-Z ]{0,40}-----[\s\S]{0,8000}?(?:-----END [A-Z ]{0,40}-----|$)/g;

/**
 * A declared package name that is a credential's shape beyond doubt (wave 2, step 3 of a `public: true`
 * entry): a known token prefix, a JWT, a PEM header, a UUID or twelve or more hex digits. Only the
 * high-precision shapes: a real package name never has one.
 */
export function credentialShape(name: string): boolean {
  const w = name.trim();
  return SECRET_TEST.test(w) || /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(w) || /^[0-9a-f]{12,}$/i.test(w) || w.includes("-----BEGIN ");
}

/** A word shaped like a generated credential rather than a package name. */
export function looksLikeSecret(word: string): boolean {
  const w = strip(word, LEAD_WRAP, TRAIL_WRAP);
  if (SECRET_TEST.test(w)) return true;
  // A UUID (an API key, a license, a header value; third blind check): no registry name is one.
  if (/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/i.test(w)) return true;
  for (const seg of w.split(/[-_.:/@=|^~<>,;]+/)) {
    if (seg.length < 10) continue;
    const upper = (seg.match(/[A-Z]/g) ?? []).length;
    const lower = (seg.match(/[a-z]/g) ?? []).length;
    const digits = (seg.match(/\d/g) ?? []).length;
    // Mixed capitals, small letters and digits in one run: names are words, not this.
    if (upper >= 2 && lower >= 2 && digits >= 2) return true;
    // A password shape: a capital, small letters, then a run of four digits and more letters (`Winter2026sfzp`).
    if (upper >= 1 && lower >= 4 && /[A-Za-z]\d{4,}[A-Za-z]/.test(seg)) return true;
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

/** A URL's user info (`https://user:secret@host/x.tgz`) is never repeated in what the answer shows (fourth blind check). */
function withoutUserInfo(text: string): string {
  return text.replace(/(\/\/)[^/@\s]{1,300}@/g, "$1(user info withheld)@");
}

/** Words that end a command in prose ("then", "&&", ";"), and verbs that start the next clause after "and". */
const COMMAND_ENDS = new Set(["then", "&&", "||", ";", "|", "and", "or", "but", "after", "before", "so"]);
/**
 * Plain connectives that end a command's words after its verb (round 6, item 8): "npm install hono to replace the
 * router in src/server.ts" held src/server.ts as a git source standing in the command. Not right after the
 * manager, where `npm in x` is npm's own verb.
 */
const LATE_COMMAND_ENDS = new Set(["to", "for", "with", "in", "into", "on", "from", "because", "when", "while", "using", "via", "once", "until"]);

/**
 * The name of a setting, not a package: one that is, or ends in `_` (or `-`, for the words no package
 * name ends in) plus, password, passwd, pwd, secret, token, apikey, api_key, auth, credential(s) or key
 * (fifth blind check, item 2: `password==hunter2`, `db_password==88419273`, `"password": "2024.11.26"`
 * were listed with the secret as their version). Measured on the 27 popular names the round-9 screen held
 * (google-auth, oauthlib, tiktoken, django-allauth ...): none is a setting name by this rule.
 */
const SETTING_NAME = /^(?:(?:[\w.-]*_)?(?:password|passwd|pwd|secret|token|apikey|api_key|auth|credentials?|key)|[\w.-]*-(?:password|passwd|pwd|secret|token|apikey|api-key|credentials?))$/i;

/** Whether `key` names a setting: never a bundled-list name or a dependency of the project. */
export function settingName(key: string, isDependency?: (name: string) => boolean): boolean {
  if (!SETTING_NAME.test(key)) return false;
  if ((["npm", "PyPI", "crates.io"] as const).some((e) => knownPublicName(key, e))) return false;
  return !isDependency?.(key);
}

/** A value that is a version or constraint in some ecosystem's grammar (`3.0.1`, `^1.2`, `0.48`, `v1.6.0`): not a secret's shape. */
function versionShaped(value: string): boolean {
  if (SPEC_VALUE.test(value)) return true;
  return (["npm", "PyPI", "crates.io", "Go"] as const).some((e) => checkableSpec(e, value) !== null || checkableSpec(e, `==${value}`) !== null);
}

export function screenTask(task: string, isDependency?: (name: string) => boolean): TaskScreen {
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
  /** The operands of every install command (after the manager word), as [start, end) spans. */
  const commandArgs: Array<[number, number]> = [];
  const packageHolds = new Set<Withheld>();
  const holdPackage = (name: string, kind: string, start: number, end: number) => {
    names.add(name.toLowerCase());
    hold(name, `not looked up: the task takes it from ${kind}`, start, end, true);
    packageHolds.add(withheld[withheld.length - 1]);
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
  // 1b. A word with a shell expansion in it (`P4ss$w0rd`, `${secret}`, `$(cmd)`, `%TOKEN%`): withheld whole and
  // never shown, so no reader takes one half for a name and the other for a version (fifth blind check, item 3).
  // A backtick is markdown, not shell: never an expansion (sixth blind check, item 1). A price ($5) or a
  // percentage (50%) is no expansion either.
  for (const m of task.matchAll(/\$\([^()\n]{0,300}\)?/g)) {
    if (free(m.index!, m.index! + m[0].length)) hold("a word with a shell expansion in it", `not read: its value is not in the task; ${NOT_SENT}`, m.index!, m.index! + m[0].length, true);
  }
  for (const m of task.matchAll(/\S{1,300}/g)) {
    const inner = m[0].replace(/^["'`([{*]+/, "").replace(/["'`)\]}.,;:!?*]+$/, "");
    if (/\$[A-Za-z_{(]|%[A-Za-z_]\w*%/.test(inner) && free(m.index!, m.index! + m[0].length)) {
      hold("a word with a shell expansion in it", `not read: its value is not in the task; ${NOT_SENT}`, m.index!, m.index! + m[0].length, true);
    }
  }

  // 2. Manifest entries taken from git, a path, a workspace or a URL, written into the task.
  const JSON_SOURCE = /(["'])(@?[\w.~-]{1,214}(?:\/[\w.~-]{1,214})?)\1\s{0,8}:\s{0,8}(["'])([^"'\n]{1,500})\3/g;
  for (const m of task.matchAll(JSON_SOURCE)) {
    const kind = specSource(m[4], "js");
    if (kind && free(m.index!, m.index! + m[0].length)) holdPackage(m[2], kind, m.index!, m.index! + m[0].length);
  }
  const TOML_SOURCE = /(^|[\s`(])([A-Za-z0-9][\w.-]{0,213})[ \t]{0,8}=[ \t]{0,8}\{([^{}\n]{0,400})\}/gm;
  for (const m of task.matchAll(TOML_SOURCE)) {
    const fields = m[3];
    const kind = /\bgit\s{0,4}=/.test(fields) ? "git" : /\bpath\s{0,4}=/.test(fields) ? "a path" : /\burl\s{0,4}=/.test(fields) ? "a URL" : /\bworkspace\s{0,4}=\s{0,4}true/.test(fields) ? "a workspace" : /\bregistry\s{0,4}=\s{0,4}["'](?!crates-io["'])/.test(fields) || /\bsource\s{0,4}=/.test(fields) ? "a registry or source named in the entry" : null;
    const start = m.index! + m[1].length;
    if (kind && free(start, m.index! + m[0].length)) holdPackage(m[2], kind, start, m.index! + m[0].length);
  }
  // PEP 508 direct reference: `name @ https://...`, `name[extra] @ git+...`, `name @ file:///...`.
  const PEP508_URL = /(^|[\s"'`(,[])([A-Za-z0-9][\w.-]{0,99})(?:\[[^\]\n]{0,200}\])?[ \t]{0,8}@[ \t]{0,8}((?:git\+|https?:|file:|ssh:|ftp:)[^\s"'`,\]]{0,2000})/gim;
  for (const m of task.matchAll(PEP508_URL)) {
    const start = m.index! + m[1].length;
    const end = m.index! + m[0].length;
    if (free(start, end)) holdPackage(m[2], specSource(m[3], "py") ?? "a URL", start, end);
  }

  // Whether only blanks (and a YAML list dash) stand between `at` and its line's start, or its end. Walked over
  // the blanks only: slicing the line per `key: value` match was quadratic on one long line (5.0 s on 199 KB of
  // " a:"; sixth blind check, item 3).
  const aloneBefore = (at: number) => {
    let k = at;
    while (k > 0 && at - k < MAX_TASK_WORD && (task[k - 1] === " " || task[k - 1] === "\t" || task[k - 1] === "-")) k--;
    return k === 0 || task[k - 1] === "\n";
  };
  const aloneAfter = (at: number) => {
    let k = at;
    while (k < task.length && k - at < MAX_TASK_WORD && (task[k] === " " || task[k] === "\t")) k++;
    return k === task.length || task[k] === "\n" || task[k] === "\r";
  };
  /** Whether the word at `at` is an operand of an install command on its line (looked back over at most 200 characters). */
  const installOperand = (at: number) => /\b(?:npm|pnpm|yarn|bun|pip3?|uv|poetry|cargo|go)\s+(?:install|i|add|get|require)\b[^;&|\n]{0,200}$/i.test(task.slice(Math.max(0, at - 200), at));
  // 2b. Settings: `password==x`, `DB_PASSWORD=x`, `"secret_token": "x"`, `api_key = "x"`. A setting is not a
  // package: neither read nor listed, and only its name is shown, never its value (fifth blind check, item 2).
  for (const m of task.matchAll(/(?<=^|[\s"'`{,(])(["'`]?)([A-Za-z_][\w.-]{0,60})\1[ \t]{0,4}(={1,3}|:)[ \t]{0,4}(["'`]?)([^\s"'`,}]{1,300})\4/g)) {
    const start = m.index!;
    const end = m.index! + m[0].length;
    // `key: value` only quoted (JSON) or alone on its line (YAML): "Auth: switch to passport" is prose.
    const colonOk = m[3] !== ":" || m[1] !== "" || m[4] !== "" || (aloneBefore(start) && aloneAfter(end));
    // A version or constraint as its value makes it a package (`"json-web-token": "3.0.1"`, `rusoto_credential =
    // "0.48.0"`), and an install command's operand is never a setting (sixth blind check, item 2).
    // The cheap tests first: the version grammar runs only for a key that names a setting (each match ran four
    // ecosystems' parsers: 1.4 s of CPU on 199 KB of " a:").
    if (!colonOk || !settingName(m[2], isDependency) || !free(start, end)) continue;
    if (versionShaped(m[5]) || installOperand(start)) continue;
    hold(`a setting named ${m[2].slice(0, 60)}`, `not read: a setting, not a package; its value is never repeated; ${NOT_SENT}`, start, end, true);
  }

  // 3. Registries the task sets: .npmrc / pip.conf lines, environment variables, config commands.
  for (const m of task.matchAll(/(^|[\s"'`])(@[\w.-]{1,214}):registry[ \t]{0,4}[= \t][ \t]{0,4}(\S{1,2000})/gim)) {
    if (publicNpm(m[3])) continue;
    scopes.add(m[2].toLowerCase());
    blank(m.index! + m[1].length, m.index! + m[0].length);
  }
  for (const m of task.matchAll(/(^|[\s"'`])((?:npm_config_|NPM_CONFIG_|BUN_CONFIG_|YARN_NPM_)?(?:registry|REGISTRY)|YARN_REGISTRY|YARN_NPM_REGISTRY_SERVER|npmRegistryServer)[ \t]{0,4}[= \t][ \t]{0,4}["'`]?((?:https?:)?\/\/\S{1,2000})/gm)) {
    if (!publicNpm(m[3])) closeEcosystem("npm", "a registry the task sets for npm", m.index! + m[1].length, m.index! + m[0].length);
  }
  for (const m of task.matchAll(/(^|[\s"'`])((?:PIP_|UV_)?(?:EXTRA_)?(?:INDEX_URL|DEFAULT_INDEX|INDEX)|(?:global\.)?(?:extra-)?index-url|index_url)[ \t]{0,4}[= \t][ \t]{0,4}["'`]?(\S{1,2000})/gim)) {
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
    // Own properties only: a task word such as "constructor" is no manager (round 7, C8).
    const family = Object.hasOwn(FAMILIES, manager) ? FAMILIES[manager] : undefined;
    if (!family || !free(words[i].start, words[i].end)) continue;
    // The command's words: to a clause break ("then", "&&", ";", a sentence end) or 40 words.
    let j = i + 1;
    let last = i;
    for (; j < words.length && j - i <= 40; j++) {
      const w = words[j].text;
      if (COMMAND_ENDS.has(w.toLowerCase()) || (j > i + 1 && LATE_COMMAND_ENDS.has(w.toLowerCase()))) break;
      // A shell or sentence separator ends the command too (fourth blind check, item 2): `&`, `|`, a
      // redirection, a comment, a new line, a parenthesis, a lone dash (an em dash folded), `$(`, a backtick.
      if (/^(?:[&|<>#(]|\d?>|\/\/|-$|\$\()/.test(w) || /\n/.test(task.slice(words[j - 1].end, words[j].start))) break;
      last = j;
      if (/[,()]["')]*$/.test(w)) break;
      // A sentence or clause ends with this word ("x.", "x;", "x`").
      if (/[;!?`]["')]*$/.test(w) || /[A-Za-z0-9"'`)]\.["')]*$/.test(w)) break;
    }
    const args = words.slice(i + 1, last + 1);
    if (args.length > 0) commandArgs.push([args[0].start, args[args.length - 1].end]);
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
      else hold(withoutUserInfo(bare(o.text)).slice(0, 80), `not looked up: the task installs it from ${kind}, not by a registry name`, o.start, o.end, true);
    }
    // Each word belongs to one command: "npm npm npm ..." was parsed forty words at a time from every word (re-check, item 3).
    i = Math.max(i, last);
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

  // A file hash (`--hash=sha256:...`, pip's option) and build metadata after a version (`4.17.15+<hex>`) are
  // neither names nor credentials: blanked, held as nothing, so they never make the package beside them
  // "not read whole" (third blind check: `pip install PyJWT==1.7.1 --hash=sha256:...` listed nothing).
  for (const m of task.matchAll(/\b(?:sha(?:1|224|256|384|512)|md5|blake2b)[:=][A-Za-z0-9+/=_-]{8,2000}|(?<=\d)\+[0-9A-Za-z][0-9A-Za-z.-]{0,300}/gi)) {
    if (free(m.index!, m.index! + m[0].length)) blank(m.index!, m.index! + m[0].length);
  }

  // 6. Credentials.
  for (const m of task.matchAll(PEM)) hold("a private key block", `not read: it looks like a credential; ${NOT_SENT}`, m.index!, m.index! + m[0].length, false);
  for (const m of task.matchAll(SECRET_ASSIGNMENT)) {
    // A requirement or manifest entry is not a credential setting, whatever its name holds:
    // `oauthlib==3.2.0`, `"jsonwebtoken": "8.5.1"`, `google-auth = ">=2"` named a package whose
    // version was blanked and then judged at latest (re-check of the 2026-11-25 fixes, item 1).
    if (SPEC_VALUE.test(m[1])) continue;
    const start = m.index! + m[0].length - m[1].length;
    if (free(start, start + m[1].length)) hold(redact(m[1]), `not read: it is the value of a credential setting; ${NOT_SENT}`, start, start + m[1].length, false);
  }
  for (const w of words) {
    if (!free(w.start, w.end)) continue;
    // Twelve or more hex digits: a hash or a key, never a package name (fifth blind check, item 2).
    const inner = bare(w.text);
    if (/^[0-9a-f]{12,}$/i.test(inner)) {
      hold(redact(inner), `not read: it looks like a credential; ${NOT_SENT}`, w.start, w.end, false);
      continue;
    }
    // Each part of a word joined by `=` or `:` (`GITHUB_TOKEN=ghp_...`), judged on its own.
    let offset = 0;
    for (const part of w.text.split(/([=:,])/)) {
      if (part.length > 1 && looksLikeSecret(part)) hold(redact(bare(part)), `not read: it looks like a credential; ${NOT_SENT}`, w.start + offset, w.start + offset + part.length, false);
      offset += part.length;
    }
  }

  // 7. PEP 508 extras: `requests[security,socks]==2.25.0` names requests at 2.25.0; an extra is never a name.
  // The requirement is moved over the brackets (its name stays where it was), so every reader binds the version.
  // A redirection with a descriptor (`2>&1`, `2> err.log`, `&> out`) ends the command: written as `;` so no
  // reader takes its `1` for a version or the next word for an operand (fourth blind check, B4).
  // A markdown code span that touches other text (`**`x@1.2.5`**`, `` `x`@1.2.5 ``, `` `x`'s ``, `` `a`,`b` ``) loses
  // its backticks, so the readers see the name and its version as they would without them (sixth blind
  // check, item 1). One with blanks on both sides keeps them: the readers take a backticked word as a name.
  const text = chars
    .join("")
    .replace(/`([^`\s]{1,300})`/g, (m: string, inner: string, at: number, all: string) => {
      const after = all[at + m.length];
      if (after === "@") return `  ${inner}`;
      const before = at > 0 ? all[at - 1] : undefined;
      return (before === undefined || /\s/.test(before)) && (after === undefined || /\s/.test(after)) ? m : ` ${inner} `;
    })
    .replace(/(^|\s)(?:\d?>&\d|\d>>?|&>>?)/g, (m: string, pre: string) => `${pre};${" ".repeat(m.length - pre.length - 1)}`)
    .replace(/(^|[\s"'`(])([A-Za-z0-9][\w.-]{0,200})\[[\w.,\s-]{1,400}\](\S{0,300})/g, (m: string, pre: string, name: string, rest: string) => `${pre}${name}${rest}${" ".repeat(m.length - pre.length - name.length - rest.length)}`);
  for (const w of withheld) if (packageHolds.has(w) || commandArgs.some(([a, b]) => w.start >= a && w.start < b)) w.standing = true;
  return { text, withheld, names, scopes, ecosystems };
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

/*
 * What the briefing itself looks up (final design of the 2026-11-25 fixes). Every list of private-source
 * spellings and every reading of package cues in prose was beatable by a spelling it did not know, so the
 * briefing stops guessing: it looks a name up on a public registry or OSV.dev only when the name is known
 * to be public without asking anyone, because the project already depends on it (the caller's check) or
 * because it is exactly a name in a bundled list (knownPublicName). A near-miss of a popular name is
 * judged offline (offlineNearMiss). Every other name is handed back as dependency_check arguments.
 */

const POPULAR_NPM_SET = new Set(POPULAR_NPM);
const POPULAR_PYPI_SET = new Set(POPULAR_PYPI.map(normalizePypiName));

/**
 * Public names that have shipped a malicious or hijacked release (public incident history): looking
 * one up names nothing private, and is what the briefing exists for ("bring in ua-parser-js 0.7.29",
 * "pull in node-ipc 10.1.1", "add ctx" in a Python project, "bring in rustdecimal").
 */
const KNOWN_COMPROMISED: Record<CheckEcosystem, ReadonlySet<string>> = {
  npm: new Set([
    "ua-parser-js", "node-ipc", "coa", "rc", "colors", "faker", "event-stream", "flatmap-stream", "eslint-scope", "eslint-config-eslint", "getcookies",
    "electron-native-notify", "bootstrap-sass", "purescript-installer", "peacenotwar", "crossenv", "@ctrl/tinycolor", "nx", "chalk", "debug",
    "ansi-styles", "strip-ansi", "color-convert", "supports-color", "is-arrayish", "error-ex", "duckdb", "@duckdb/node-api", "eslint-config-prettier",
    "eslint-plugin-prettier", "synckit", "@pkgr/core", "napi-postinstall", "is", "got-fetch", "rspack", "@rspack/core", "vant", "lottie-player",
    "@lottiefiles/lottie-player", "@solana/web3.js", "web3-utils",
  ]),
  PyPI: new Set(["ctx", "phpass", "jeilyfish", "python3-dateutil", "colourama", "ultralytics", "num2words", "aiocpa", "fastapi-toolkit", "pytorch-triton", "torchtriton"]),
  "crates.io": new Set(["rustdecimal", "faster_log", "async_println", "evm-units", "uniswap-utils"]),
  Go: new Set(),
};

/** Whether `name` is exactly a name of a bundled list of `eco`: the popular names, or a name with a known malicious or hijacked release. */
/** Whether a name is on the bundled list of names with a known malicious or hijacked release: known without a lookup. */
/**
 * Round 9 (docs lane 5): the names of KNOWN_COMPROMISED that are malware in every release (typosquats published as
 * malware), not packages that once shipped a hijacked release (chalk, debug, is): known offline, wherever they stand.
 */
const MALWARE_ONLY: Record<CheckEcosystem, ReadonlySet<string>> = {
  npm: new Set(["crossenv", "flatmap-stream", "getcookies", "electron-native-notify"]),
  PyPI: new Set(["jeilyfish", "python3-dateutil", "colourama"]),
  "crates.io": new Set(["rustdecimal", "faster_log", "async_println", "evm-units", "uniswap-utils"]),
  Go: new Set(),
};

/** Whether a name is malware in every release on the bundled list (round 9). */
export function knownMalwareOnly(name: string, eco: CheckEcosystem): boolean {
  const lower = name.toLowerCase();
  return MALWARE_ONLY[eco]?.has(eco === "PyPI" ? normalizePypiName(lower) : lower) ?? false;
}

export function knownCompromised(name: string, eco: CheckEcosystem): boolean {
  const lower = name.toLowerCase();
  return KNOWN_COMPROMISED[eco]?.has(eco === "PyPI" ? normalizePypiName(lower) : lower) ?? false;
}

export function knownPublicName(name: string, eco: CheckEcosystem): boolean {
  const lower = name.toLowerCase();
  if (KNOWN_COMPROMISED[eco].has(eco === "PyPI" ? normalizePypiName(lower) : lower)) return true;
  if (eco === "npm") return POPULAR_NPM_SET.has(lower);
  if (eco === "PyPI") return POPULAR_PYPI_SET.has(normalizePypiName(lower));
  return false;
}

/** The popular name `name` is a near-miss of in `eco`, judged offline from the bundled lists, or null. */
export function offlineNearMiss(name: string, eco: CheckEcosystem): string | null {
  // A name that is itself on a bundled list, in any ecosystem, is never a near-miss (fourth blind check, item 4).
  if ((["npm", "PyPI", "crates.io"] as const).some((e) => knownPublicName(name, e))) return null;
  if (eco === "npm") return nearMissOf(name.toLowerCase())?.of ?? null;
  if (eco === "PyPI") return closestPopularPypi(name);
  return null;
}


/**
 * Options known to take no value, per package manager (re-check of the 2026-11-25 fixes, item 2): after
 * any other option the next word may be that option's value (`--prefix ./x`, `--userconfig f`,
 * `pnpm -C dir`, `pip -t dir`, `cargo install --root d`), so it is never read as a package name.
 */
const SWITCHES: Record<string, ReadonlySet<string>> = (() => {
  const js = ["-D", "--save-dev", "-S", "--save", "-P", "--save-prod", "-O", "--save-optional", "--save-peer", "-E", "--save-exact", "-g", "--global", "--no-save", "--legacy-peer-deps", "--strict-peer-deps", "--force", "-f", "--ignore-scripts", "--no-audit", "--no-fund", "--dry-run", "--prefer-offline", "--prefer-online", "--offline", "--production", "--no-package-lock", "--package-lock-only", "--no-optional", "-B", "--save-bundle", "--install-links", "--foreground-scripts", "-q", "--quiet", "-s", "--silent", "--verbose", "-d", "--dev", "--peer", "--optional", "--exact", "-T", "--tilde", "-W", "--ignore-workspace-root-check", "--workspace-root", "--frozen-lockfile", "--no-frozen-lockfile", "--prod", "--trust", "-y", "--yes", "--interactive", "--recursive", "--latest"];
  const py = ["-U", "--upgrade", "--user", "--no-deps", "--pre", "-q", "--quiet", "-v", "--verbose", "--force-reinstall", "--no-cache-dir", "--break-system-packages", "-I", "--ignore-installed", "--no-build-isolation", "--require-hashes", "--no-input", "--isolated", "--dev", "-d", "--raw", "--raw-sources", "--frozen", "--locked", "--no-sync", "--no-install-project", "--editable-false", "--system", "--compile", "--compile-bytecode", "--allow-prereleases", "--lock", "--dry-run", "--no-binary-all", "--prefer-binary", "-e", "--editable", "--all-extras", "--refresh", "--reinstall", "--upgrade-all"];
  const cargo = ["--dev", "--build", "--optional", "--no-optional", "--no-default-features", "--default-features", "--offline", "--dry-run", "-q", "--quiet", "-v", "--verbose", "--locked", "--frozen", "--force", "-f", "--no-track", "--debug", "--all-features", "--list"];
  const go = ["-u", "-t", "-d", "-x", "-v", "-insecure", "-u=patch", "-n", "-a", "-race"];
  const set = (a: string[]) => new Set(a);
  const out: Record<string, ReadonlySet<string>> = {};
  for (const m of ["npm", "pnpm", "yarn", "bun"]) out[m] = set(js);
  for (const m of ["pip", "pip3", "uv", "poetry", "pipenv", "pdm", "pipx", "rye"]) out[m] = set(py);
  out.cargo = set(cargo);
  out.go = set(go);
  return out;
})();

/** Whether `flag` of a `manager` command is known to take no value: only then is the next word read as an operand. */
export function isKnownSwitch(manager: string, flag: string): boolean {
  return Object.hasOwn(SWITCHES, manager.toLowerCase()) ? SWITCHES[manager.toLowerCase()].has(flag) : false;
}

/**
 * Whether an operand is a path, a URL, a GitHub shorthand or anything else no registry name looks like:
 * a leading `.`, `/` or `~`, a drive letter, a `\`, or a `/` that is not an npm scope's or a Go module path's.
 */
export function pathLikeOperand(token: string, ecosystem: CheckEcosystem): boolean {
  const t = strip(token, "\"'`(", "\"'`,;:)");
  if (/^[./~]|^[a-z]:|\|:\/\//i.test(t)) return true;
  if (!t.includes("/")) return false;
  if (ecosystem === "Go") return !/^[a-z0-9][a-z0-9.-]*\.[a-z]{2,}\//i.test(t);
  if (ecosystem === "npm") return !/^@[^/@\s]+\/[^/\s]+$/.test(t.replace(/(?<=.)@[^@/]*$/, ""));
  return true;
}

/** The name-like pieces of a stretch of text, in lower case (`oauthlib==3.2.0` gives `oauthlib`, `3.2.0`; `x@1` gives `x@1`, `x`). */
export function namePieces(text: string): string[] {
  const out: string[] = [];
  for (const m of text.matchAll(/[A-Za-z0-9@._/~-]{1,300}/g)) {
    const piece = strip(m[0], "", ".:-").toLowerCase();
    if (!piece) continue;
    out.push(piece);
    const at = piece.indexOf("@", 1);
    if (at > 0) out.push(piece.slice(0, at));
  }
  return out;
}

/**
 * The names a span the screen withheld for what it looked like (a credential, a URL, an address)
 * touches: the pieces of the whitespace word it sits in, and for a credential's value the word before it. A package read
 * beside one (its name, its version or its specifier blanked) is not read whole and is not looked up:
 * `oauthlib==3.2.0` with `=3.2.0` blanked was judged at latest (re-check of the 2026-11-25 fixes, item 1).
 */
export function touchedNames(task: string, screen: TaskScreen): Set<string> {
  const out = new Set<string>();
  const isSpace = (c: string | undefined) => c === undefined || /\s/.test(c);
  for (const w of screen.withheld) {
    if (w.always) continue;
    // The word around the span, then one word either side (each scan stops at the next blank run).
    let a = w.start;
    // A markdown link's target (`[text](url)`) is not part of its text (sixth blind check, item 1).
    if (task.slice(Math.max(0, w.start - 2), w.start) !== "](") while (a > 0 && !isSpace(task[a - 1])) a--;
    let b = w.end;
    while (b < task.length && !isSpace(task[b])) b++;
    // A credential's value may be the version of the name before it (`"jsonwebtoken": "8.5.1"`): that word
    // too. A URL or an address is one word of its own.
    let a2 = a;
    if (w.why.includes("credential")) {
      while (a2 > 0 && isSpace(task[a2 - 1]) && a - a2 < 8) a2--;
      while (a2 > 0 && !isSpace(task[a2 - 1]) && a - a2 < MAX_TASK_WORD + 8) a2--;
    }
    for (const piece of namePieces(task.slice(a2, b))) out.add(piece);
  }
  return out;
}

/** The conditional spans (credential, URL, address) a lost name sits in: linear in the spans' text. */
export function spansHolding(task: string, screen: TaskScreen, lost: ReadonlySet<string>): Withheld[] {
  if (lost.size === 0) return [];
  return screen.withheld.filter((w) => !w.always && namePieces(task.slice(w.start, w.end)).some((p) => lost.has(p)));
}
