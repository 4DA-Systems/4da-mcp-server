// SPDX-License-Identifier: Apache-2.0
/**
 * Sixth blind check of the 2026-11-25 fixes, item 4: with opt-in embeddings the task was sent whole to the
 * embedding provider, while the answer said of a withheld setting "nothing about it was sent". The provider
 * now gets the screened task: credentials, settings' values, URL user info and option values blanked.
 * Setup as in a1119-privacy-embeddings (a stubbed fetch records every request). Original note follows.
 *
 * Text that names a private package is never sent to an embedding provider that is not on this
 * machine. With a provider configured, `check_decision_alignment {technology: "@acme/ui"}` sent
 * `"prompt":"@acme/ui"` to the embedding endpoint: the embedding requests used the global fetch,
 * outside the private-name check and the proxy.
 *
 * - A remote provider (an Ollama URL that is not loopback, or OpenAI): a query that names a
 *   private package is not sent, semantic recall is skipped for the call, and the answer says so.
 *   A stored row that names one is not sent either and is ranked lexically.
 * - A loopback Ollama (127.0.0.1, localhost, ::1) is this machine: nothing is withheld from it.
 * - Remote embedding requests go through the guarded HTTP helper, so they use the proxy.
 *
 * Every request is recorded by a stubbed fetch: nothing leaves the process. Private-looking names
 * carry `zq`.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { FourDADatabase } from "../db.js";
import { LiveIntelligence } from "../live/index.js";
import { clearLiveIntelligence, setLiveIntelligence } from "../live-singleton.js";
import { dispatchTool } from "../tool-dispatch.js";
import { scanProjectTree, treeResolutionGroups } from "../project-tree.js";
import { notReadWords } from "./helpers/a1127-task-packages.js";

let scratch: string;
let project: string;
let db: FourDADatabase;
let sent: Array<{ url: string; body: string }>;
const savedEnv = new Map<string, string | undefined>();
const setEnv = (key: string, value: string | undefined) => {
  if (!savedEnv.has(key)) savedEnv.set(key, process.env[key]);
  if (value === undefined) delete process.env[key];
  else process.env[key] = value;
};
const REMOTE_OLLAMA = "http://ollama.zq-remote.example:11434";
const toEmbedder = () => sent.filter((s) => /\/api\/embeddings|\/v1\/embeddings/.test(s.url));
const promptsSent = () => toEmbedder().map((s) => (JSON.parse(s.body) as { prompt?: string; input?: string })).map((b) => b.prompt ?? b.input ?? "");

beforeEach(() => {
  scratch = fs.mkdtempSync(path.join(os.tmpdir(), "4da-a1119-embed-"));
  project = path.join(scratch, "project");
  fs.mkdirSync(project, { recursive: true });
  sent = [];
  for (const key of ["FOURDA_OFFLINE", "OPENAI_API_KEY", "OLLAMA_URL", "FOURDA_EMBED_MODEL", "HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY"]) setEnv(key, undefined);
  setEnv("FOURDA_EMBED_PROVIDER", "ollama");
  setEnv("FOURDA_EMBED_MODEL", "test-embed");
  setEnv("OLLAMA_URL", REMOTE_OLLAMA);
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: string, init?: RequestInit) => {
      const url = String(input);
      sent.push({ url, body: typeof init?.body === "string" ? init.body : "" });
      if (/\/api\/embeddings$/.test(url)) return new Response(JSON.stringify({ embedding: [1, 0, 0, 0] }), { status: 200, headers: { "content-type": "application/json" } });
      if (/\/v1\/embeddings$/.test(url)) return new Response(JSON.stringify({ data: [{ embedding: [1, 0, 0, 0] }] }), { status: 200, headers: { "content-type": "application/json" } });
      return new Response(JSON.stringify({ error: "Not found" }), { status: 404 });
    }),
  );
  // A project whose `.npmrc` maps @zqacme to a private registry, and which installs @zqacme/ui from it.
  const deps = { lodash: "4.17.20", "@zqacme/ui": "1.2.3" };
  fs.writeFileSync(path.join(project, ".npmrc"), "@zqacme:registry=https://npm.zqacme.example/\n");
  fs.writeFileSync(path.join(project, "package.json"), JSON.stringify({ name: "app", version: "1.0.0", dependencies: deps }));
  fs.writeFileSync(
    path.join(project, "package-lock.json"),
    JSON.stringify({
      name: "app",
      lockfileVersion: 3,
      packages: {
        "": { name: "app", dependencies: deps },
        "node_modules/lodash": { version: "4.17.20", resolved: "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz" },
        "node_modules/@zqacme/ui": { version: "1.2.3", resolved: "https://npm.zqacme.example/@zqacme/ui/-/ui-1.2.3.tgz" },
      },
    }),
  );
  const live = new LiveIntelligence(null);
  const { entries, discovery } = scanProjectTree(project);
  live.initFromProjectTree(project, treeResolutionGroups(entries), discovery);
  setLiveIntelligence(live);
  db = new FourDADatabase(path.join(scratch, "standalone.db"));
});
afterEach(() => {
  db.close();
  vi.unstubAllGlobals();
  clearLiveIntelligence();
  for (const [key, value] of savedEnv) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
  savedEnv.clear();
  try {
    fs.rmSync(scratch, { recursive: true, force: true });
  } catch {
    // Windows: left for the OS temp cleaner.
  }
});

async function call(tool: string, args: Record<string, unknown>): Promise<Record<string, unknown>> {
  const result = (await dispatchTool(tool, db, args)) as { content: Array<{ text: string }> };
  return JSON.parse(result.content[0].text) as Record<string, unknown>;
}
const recordDecision = (subject: string, decision: string) => call("decision_memory", { action: "record", subject, decision, rationale: "recorded by the test" });

describe("the embedding provider gets the screened task", () => {
  it.each([
    ["DB_PASSWORD=zqs77secret then npm install pg", "zqs77secret"],
    ["npm install lodash --_authToken zqxtok55", "zqxtok55"],
    ["npm install https://zquser:zqpass99@host.example/x.tgz", "zqpass99"],
    ["add ghp_ZQXTOK0123456789abcdefABCDEF012345 as the token", "ghp_ZQXTOK"],
  ])("%s", async (task, secret) => {
    await recordDecision("Component library", "Use the shared component library for every screen");
    const brief = await call("what_should_i_know", { task, packages: [] });
    // Wave 2, invariant I6: a call whose screen withheld a word sends the task to no embedding provider at all.
    // (Recording the decision above embeds the decision's own text; nothing of the task is sent.)
    expect(promptsSent().filter((p) => p.includes(secret) || /install|token/i.test(p))).toEqual([]);
    expect(JSON.stringify(notReadWords(brief) ?? [])).not.toContain(secret);
  });

  it("a clean declared call is not embedded either (wave 2, C1: no task text, ever)", async () => {
    await recordDecision("Component library", "Use the shared component library for every screen");
    const brief = await call("what_should_i_know", { task: "then npm install pg", packages: [] });
    expect(promptsSent().filter((p) => p.includes("npm install pg") || p.includes("pg"))).toEqual([]);
    expect(brief.wisdom_recall_mode).toBe("ranked_lexical");
    expect(String(brief.wisdom_recall_note)).toMatch(/^The task text is not sent for embedding/);
  });
});
