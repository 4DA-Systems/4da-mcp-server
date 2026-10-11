// SPDX-License-Identifier: Apache-2.0
/**
 * Python and Go import sites for `upgrade_impact`.
 *
 * Go is exact: a file imports a module by its path (`"github.com/jackc/pgx/v5"`
 * or a package below it), and the identifiers it reaches through the package
 * name (`pgx.Connect`) are the symbols a changelog entry can name.
 *
 * Python is not: a file imports a MODULE (`import yaml`), while an upgrade names
 * a DISTRIBUTION (`PyYAML`), and nothing in the source links the two. The
 * mapping comes, in order of trust, from:
 *   1. the installed distribution's own metadata in this project's virtualenv
 *      (`*.dist-info/top_level.txt`, else the top-level names in `RECORD`);
 *   2. a short table of well-known distributions whose import name differs
 *      (beautifulsoup4 -> bs4, Pillow -> PIL, PyYAML -> yaml, ...);
 *   3. the distribution name itself with `-` and `.` read as `_`, which is
 *      right for most packages and is reported as an ASSUMPTION every time,
 *      so a count of zero files is never mistaken for "not used".
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { normalizePypiName } from "../live/upgrade-pypi.js";
import { goBasePath, goPathMajor } from "../live/upgrade-go.js";

// ---------------------------------------------------------------- Python

export type ImportNameSource = "installed-metadata" | "known-mapping" | "assumed";

export interface PythonImportNames {
  names: string[];
  source: ImportNameSource;
  /** Where the installed metadata was read, relative to the project root. */
  evidence?: string;
}

/**
 * Distributions whose import name is not their normalised name. Each is the
 * package's documented import (PyPI page or the project's own docs); a
 * distribution that installs several top-level modules lists them all.
 */
const KNOWN_IMPORT_NAMES: Record<string, string[]> = {
  "beautifulsoup4": ["bs4"],
  "pillow": ["PIL"],
  "pyyaml": ["yaml"],
  "scikit-learn": ["sklearn"],
  "scikit-image": ["skimage"],
  "opencv-python": ["cv2"],
  "opencv-python-headless": ["cv2"],
  "opencv-contrib-python": ["cv2"],
  "opencv-contrib-python-headless": ["cv2"],
  "python-dateutil": ["dateutil"],
  "pyjwt": ["jwt"],
  "python-dotenv": ["dotenv"],
  "protobuf": ["google.protobuf"],
  "attrs": ["attr", "attrs"],
  "psycopg2-binary": ["psycopg2"],
  "mysqlclient": ["MySQLdb"],
  "pyserial": ["serial"],
  "pyopenssl": ["OpenSSL"],
  "pycryptodome": ["Crypto"],
  "pycryptodomex": ["Cryptodome"],
  "setuptools": ["setuptools", "pkg_resources"],
  "python-multipart": ["multipart", "python_multipart"],
  "djangorestframework": ["rest_framework"],
  "django-cors-headers": ["corsheaders"],
  "python-jose": ["jose"],
  "ruamel.yaml": ["ruamel.yaml"],
  "grpcio": ["grpc"],
  "google-api-python-client": ["googleapiclient"],
  "pymupdf": ["fitz", "pymupdf"],
  "python-docx": ["docx"],
  "python-pptx": ["pptx"],
  "websocket-client": ["websocket"],
  "pyzmq": ["zmq"],
  "faiss-cpu": ["faiss"],
  "faiss-gpu": ["faiss"],
  "discord.py": ["discord"],
  "py-cpuinfo": ["cpuinfo"],
  "pygobject": ["gi"],
  "pycairo": ["cairo"],
  "pyqt5": ["PyQt5"],
  "pyqt6": ["PyQt6"],
  "pyside6": ["PySide6"],
  "python-ldap": ["ldap"],
  "pyusb": ["usb"],
  "msgpack-python": ["msgpack"],
  "markdown-it-py": ["markdown_it"],
  "typing-extensions": ["typing_extensions"],
  "google-cloud-storage": ["google.cloud.storage"],
  "google-cloud-bigquery": ["google.cloud.bigquery"],
  "google-cloud-pubsub": ["google.cloud.pubsub", "google.cloud.pubsub_v1"],
  "apache-airflow": ["airflow"],
  "pywin32": ["win32api", "win32con", "win32com", "pythoncom", "pywintypes"],
};

const VENV_DIRS = [".venv", "venv", "env", ".env", "virtualenv"];

/** site-packages directories of virtualenvs at the project root (POSIX and Windows layouts). */
function sitePackagesDirs(root: string): string[] {
  const out: string[] = [];
  for (const v of VENV_DIRS) {
    const venv = path.join(root, v);
    const win = path.join(venv, "Lib", "site-packages");
    if (fs.existsSync(win)) out.push(win);
    const lib = path.join(venv, "lib");
    let entries: string[] = [];
    try {
      entries = fs.readdirSync(lib);
    } catch {
      continue;
    }
    for (const py of entries) {
      const sp = path.join(lib, py, "site-packages");
      if (/^python\d/.test(py) && fs.existsSync(sp)) out.push(sp);
    }
  }
  return out;
}

/** Top-level importable names a RECORD lists: `pkg/__init__.py` -> pkg, `mod.py` -> mod. */
function namesFromRecord(record: string): string[] {
  const names = new Set<string>();
  for (const line of record.split(/\r?\n/)) {
    const file = line.split(",")[0]?.trim();
    if (!file || file.startsWith("..") || file.startsWith("/")) continue;
    const first = file.split("/")[0];
    if (/\.(?:dist-info|egg-info|data)$/.test(first) || first === "__pycache__" || /\.pth$/.test(first)) continue;
    if (file.includes("/")) {
      if (/^[A-Za-z_]\w*$/.test(first)) names.add(first);
    } else {
      const mod = /^([A-Za-z_]\w*)(?:\.[\w-]+)?\.(?:py|pyd|so)$/.exec(first)?.[1];
      if (mod) names.add(mod);
    }
  }
  return [...names];
}

function readInstalledNames(root: string, dist: string): PythonImportNames | null {
  const want = normalizePypiName(dist);
  for (const sp of sitePackagesDirs(root)) {
    let entries: string[];
    try {
      entries = fs.readdirSync(sp);
    } catch {
      continue;
    }
    for (const entry of entries) {
      const m = /^(.+?)-[^-]+\.(?:dist-info|egg-info)$/.exec(entry);
      if (!m || normalizePypiName(m[1]) !== want) continue;
      const meta = path.join(sp, entry);
      const rel = path.relative(root, meta).split(path.sep).join("/");
      for (const [file, read] of [
        ["top_level.txt", (t: string) => t.split(/\r?\n/).map((l) => l.trim()).filter((l) => /^[A-Za-z_][\w.]*$/.test(l))],
        ["RECORD", namesFromRecord],
      ] as const) {
        try {
          const names = read(fs.readFileSync(path.join(meta, file), "utf8"));
          if (names.length > 0) return { names: [...new Set(names)].sort(), source: "installed-metadata", evidence: `${rel}/${file}` };
        } catch {
          // no such file: try the next
        }
      }
    }
  }
  return null;
}

/** The module name(s) a distribution is imported as, and how that was established. */
export function pythonImportNames(root: string | null, dist: string): PythonImportNames {
  const installed = root ? readInstalledNames(root, dist) : null;
  if (installed) return installed;
  const known = KNOWN_IMPORT_NAMES[normalizePypiName(dist)];
  if (known) return { names: known, source: "known-mapping" };
  return { names: [normalizePypiName(dist).replace(/-/g, "_")], source: "assumed" };
}

/** True when module `mod` is `name` or inside it (`yaml.loader` for `yaml`). */
const underModule = (mod: string, name: string) => mod === name || mod.startsWith(`${name}.`);

/**
 * Count imports of any of `names` in one Python file and collect the names it
 * reaches: `from x import A, B` gives A and B; `import x` / `import x as y`
 * gives the attributes used as `x.attr` / `y.attr`.
 */
export function scanPythonSource(source: string, names: string[], symbols: Set<string>): number {
  let matches = 0;
  const text = source.replace(/\\\r?\n/g, " ");
  const bindings: string[] = [];
  // `from x import (a, b,\n c)` and `from x import a, b as c`
  const fromRe = /^[ \t]*from[ \t]+([\w.]+)[ \t]+import[ \t]+(\([^)]*\)|[^\n#]+)/gm;
  for (const m of text.matchAll(fromRe)) {
    if (!names.some((n) => underModule(m[1], n))) continue;
    matches++;
    for (const part of m[2].replace(/[()]/g, "").split(",")) {
      const name = part.trim().split(/\s+as\s+/)[0].trim();
      if (/^[A-Za-z_]\w*$/.test(name)) symbols.add(name);
    }
  }
  const importRe = /^[ \t]*import[ \t]+([^\n#]+)/gm;
  for (const m of text.matchAll(importRe)) {
    for (const part of m[1].split(",")) {
      const [mod, alias] = part.trim().split(/\s+as\s+/).map((s) => s.trim());
      if (!mod || !names.some((n) => underModule(mod, n))) continue;
      matches++;
      bindings.push(alias ?? mod);
    }
  }
  // Attribute uses outside the import statements themselves (`from yaml.loader import` names a module, not an attribute).
  const body = text.replace(fromRe, "").replace(importRe, "");
  for (const binding of bindings) {
    const re = new RegExp(String.raw`(?<![\w.])${binding.replace(/\./g, "\\.")}\.([A-Za-z_]\w*)`, "g");
    for (const m of body.matchAll(re)) symbols.add(m[1]);
  }
  return matches;
}

// ---------------------------------------------------------------- Go

/** True when import path `imp` is module `mod` or a package inside it, not a different major (`mod/v2`). */
export function goImportInModule(imp: string, mod: string): boolean {
  if (imp === mod) return true;
  if (!imp.startsWith(`${mod}/`)) return false;
  const next = imp.slice(mod.length + 1).split("/")[0];
  return !/^v\d+$/.test(next) || goPathMajor(mod) !== null;
}

/** The package name an import path is used through: its last element, skipping a `/vN` suffix and gopkg.in's `.vN`. */
export function goPackageName(imp: string): string {
  const parts = goBasePath(imp).split("/");
  const last = parts[parts.length - 1] ?? imp;
  return last.replace(/\.v\d+$/, "").replace(/^go-/, "").replace(/[-.]/g, "_");
}

/**
 * Count imports of a Go module (or packages inside it) in one file and collect
 * the exported identifiers reached through each import's package name.
 */
export function scanGoSource(source: string, mod: string, symbols: Set<string>): number {
  const specs: Array<{ alias: string | null; path: string }> = [];
  const spec = /^\s*(?:([A-Za-z_]\w*|\.|_)\s+)?"([^"]+)"/;
  for (const m of source.matchAll(/^\s*import\s*\(([\s\S]*?)\)/gm)) {
    for (const line of m[1].split("\n")) {
      const s = spec.exec(line.replace(/\/\/.*$/, ""));
      if (s) specs.push({ alias: s[1] ?? null, path: s[2] });
    }
  }
  for (const m of source.matchAll(/^\s*import\s+(?:([A-Za-z_]\w*|\.|_)\s+)?"([^"]+)"/gm)) {
    specs.push({ alias: m[1] ?? null, path: m[2] });
  }
  let matches = 0;
  for (const s of specs) {
    if (!goImportInModule(s.path, mod)) continue;
    matches++;
    const local = s.alias ?? goPackageName(s.path);
    if (local === "_" || local === ".") continue;
    for (const m of source.matchAll(new RegExp(String.raw`(?<![\w.])${local}\.([A-Z]\w*)`, "g"))) symbols.add(m[1]);
  }
  return matches;
}
