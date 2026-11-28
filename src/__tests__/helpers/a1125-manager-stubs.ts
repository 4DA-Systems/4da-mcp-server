// SPDX-License-Identifier: Apache-2.0
/**
 * Every test that runs the guard hook is independent of the machine's PATH (round 24b, CI
 * a278af4): on Windows the hook looks a bare manager or runner name up on PATH before it reads an
 * install whose arguments hold a character cmd.exe rewrites, and a name it does not find (or that
 * resolves to a .cmd or .bat shim) is not read. GitHub's Windows runner has no uv and no bun, and its
 * pnpm resolves to pnpm.cmd, so tests written against a developer machine failed there.
 *
 * Importing this module puts, on Windows only, a fixture folder FIRST on this test file's PATH
 * (process.env.PATH, which the hook reads in-process and which every spawn that copies
 * process.env passes on): the folder holds an empty `<name>.exe` for every program word the hook
 * resolves, derived from the hook's exported constants (MANAGERS, JS_MANAGERS, PATH_LAUNCHERS, the
 * runner words of RUNNER_FETCH_FORMS, CONFIG_READERS) and the interpreters its `python -m` and
 * `node <script>` readers name in code. A test that sets its own PATH for the hook (the L2 / cmd.exe
 * suites pass `{ Path, PATH }` in the hook's environment) keeps it: the stub folder is never put in
 * front of a PATH a test chose. On POSIX nothing changes. Vitest runs each test file in its own
 * process, so the change stays inside the file that imports this module.
 */
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { CONFIG_READERS, JS_MANAGERS, MANAGERS, PATH_LAUNCHERS, RUNNER_FETCH_FORMS } from "../../../hooks/manifest-edit.mjs";

/** The interpreters the hook's readers name in code (`python -m pip`, `py -3 -m pip`, `node <npm-cli.js>`): no constant lists them. */
const INTERPRETERS = ["python", "python3", "py", "pythonw", "node"];

/** The program words the hook may look up on PATH, from its exported constants. */
export function stubbedProgramNames(): string[] {
  const names = new Set<string>();
  for (const m of MANAGERS as readonly string[]) names.add(m);
  for (const m of JS_MANAGERS as ReadonlySet<string>) names.add(m);
  for (const l of PATH_LAUNCHERS as ReadonlySet<string>) names.add(l);
  for (const [form] of RUNNER_FETCH_FORMS as ReadonlyArray<readonly [string, string]>) for (const w of form.split(/[\s,/|]+/)) if (/^[a-z][a-z0-9-]*$/.test(w)) names.add(w);
  for (const [k, readers] of Object.entries(CONFIG_READERS as Record<string, readonly string[]>)) for (const r of [k, ...readers]) names.add(r);
  // pip's numbered and pipx names, read as pip (`pip3`, `pip3.12`) and as a runner.
  for (const n of ["pip3", "pipx", "uvx"]) names.add(n);
  for (const n of INTERPRETERS) names.add(n);
  return [...names].sort();
}

let stubDir: string | null = null;
/**
 * The fixture folder, or null off Windows: one folder under the temp folder, shared by every test
 * file and kept between runs (each stub written once: creating new .exe files in every test file
 * woke the virus scanner, and the load it caused pushed the timing suites past their bounds).
 */
export function managerStubDir(): string | null {
  if (process.platform !== "win32") return null;
  if (stubDir === null) {
    const dir = join(tmpdir(), "a1125-manager-stubs-v1");
    mkdirSync(dir, { recursive: true });
    for (const name of stubbedProgramNames()) {
      const file = join(dir, `${name}.exe`);
      if (existsSync(file)) continue;
      try {
        writeFileSync(file, "", { flag: "wx" });
      } catch (error) {
        // Another test file wrote it first.
        if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
      }
    }
    stubDir = dir;
  }
  return stubDir;
}

/** On Windows, the fixture folder first on this process's PATH (once; idempotent). */
export function putManagerStubsFirst(): void {
  const dir = managerStubDir();
  if (dir === null) return;
  const current = process.env.PATH ?? process.env.Path ?? "";
  if (current.split(";")[0] === dir) return;
  // process.env is case-insensitive on Windows: this sets the one Path entry.
  process.env.PATH = `${dir};${current}`;
}

putManagerStubsFirst();
