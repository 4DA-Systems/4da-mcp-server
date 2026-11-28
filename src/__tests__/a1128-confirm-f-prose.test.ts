// SPDX-License-Identifier: Apache-2.0
/**
 * Round 4, F1-F3: the command check (briefing-command-check.ts) fires on a command shape or the explicit prose
 * shape only, and a command's operands are its contiguous run. The third real-agent run had four tasks, every
 * package declared and checked clean, end review_needed with "could not read whole" (g7c run3 a10, d04, d05,
 * d07): agents write tasks with parentheses, "and" and trailing clauses. Those calls, replayed here, are never
 * told so. F3: after a connective the rest is prose, where a name-shaped word still waits in to_confirm.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { executeWhatShouldIKnow } from "../tools/what-should-i-know.js";
import { scanCommands } from "../tools/briefing-command-check.js";
import { createHarness, type Harness } from "./helpers/a1119-planner-harness.js";

let h: Harness;
beforeEach(() => {
  h = createHarness();
  for (const n of ["hono", "papaparse", "ky", "fastify"]) h.NPM[n] = { latest: "1.2.0", versions: { "1.0.0": {}, "1.2.0": {} } };
  h.PYPI.litestar = { "2.13.0": {} };
  h.GO["github.com/go-chi/chi/v5"] = ["v5.2.0"];
  h.GO["github.com/rs/zerolog"] = ["v1.33.0"];
  h.GOMOD["github.com/go-chi/chi/v5@v5.2.0"] = "1.21";
  h.GOMOD["github.com/rs/zerolog@v1.33.0"] = "1.21";
});
afterEach(() => h.dispose());

const run3 = [
  {
    id: "a10",
    template: "go",
    task: "Add chi router (github.com/go-chi/chi/v5) for routing and zerolog (github.com/rs/zerolog) for logging to a Go project",
    packages: [{ ecosystem: "Go", name: "github.com/go-chi/chi/v5", public: true }, { ecosystem: "Go", name: "github.com/rs/zerolog", public: true }],
  },
  { id: "d04", template: "npm", task: "npm install hono (latest) in the project; no files will be edited or installed in this run, briefing only", packages: [{ ecosystem: "npm", name: "hono", public: true }] },
  { id: "d05", template: "py", task: "pip install litestar (PyPI) and set GITHUB_TOKEN env var so the build can read a private repo", packages: [{ ecosystem: "PyPI", name: "litestar", public: true }] },
  { id: "d07", template: "npm", task: "Add an AWS key to the uploader config and install papaparse (npm)", packages: [{ ecosystem: "npm", name: "papaparse", public: true }] },
];

function project(template: string) {
  if (template === "npm") h.npmProject({ zod: "3.23.8" }, {}, { zod: { version: "3.23.8" } });
  if (template === "py") h.write("requirements.txt", "flask==3.0.3\n");
  if (template === "go") h.write("go.mod", "module example.com/app\n\ngo 1.21\n");
}

// Round 7, C1: the canonical grammar replaced F1-F3. A command in an agent's sentence with a parenthetical, "and" or a
// trailing clause is named but not read whole (review_needed, said by manager and verb), and nothing of it is
// offered; a task that holds no command (a10, d07: "add ... to a Go project") is prose, settled by any declaration.
describe("round 7: agents' own wording (run3 a10, d04, d05, d07)", () => {
  it.each(run3)("$id", async (c) => {
    project(c.template);
    const r = (await executeWhatShouldIKnow(null, { task: c.task, packages: c.packages, project_path: h.dir } as never, await h.live())) as Record<string, any>;
    const named = scanCommands(c.task);
    if (named.some((x) => x.unreadable)) {
      expect(r.delegation_assessment.level).not.toBe("safe_to_delegate");
      expect(r.delegation_assessment.reason).toMatch(/This task holds a command \(\w+ \w+\) this briefing could not read whole/);
    } else expect(r.delegation_assessment.reason).not.toMatch(/could not read whole/);
  });
});

describe("a connective in a command: every word of a canonical command is an operand", () => {
  it("`npm install ky and fastifyy`: ky, and, fastifyy all wait; declaring ky alone stays confirmation_needed", async () => {
    project("npm");
    expect(scanCommands("npm install ky and fastifyy").map((c) => c.operands)).toEqual([["ky", "and", "fastifyy"]]);
    const r = (await executeWhatShouldIKnow(null, { task: "npm install ky and fastifyy", packages: [{ ecosystem: "npm", name: "ky", public: true }], project_path: h.dir } as never, await h.live())) as Record<string, any>;
    const names = (r.task_packages.to_confirm as Array<{ name: string }>).map((e) => e.name);
    expect(names).toEqual(expect.arrayContaining(["and", "fastifyy"]));
    expect(r.delegation_assessment.level).toBe("confirmation_needed");
  });
});
