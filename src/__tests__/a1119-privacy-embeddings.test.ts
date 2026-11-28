// SPDX-License-Identifier: Apache-2.0
/**
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
import { embeddingEndpoint, embedText, getEmbeddingConfig, isLocalProvider, type EmbeddingConfig } from "../embeddings.js";
import { fetchLoopbackJson, isLoopbackUrl } from "../live/loopback-http.js";
import { privateNameInText, rememberPrivateName } from "../live/private-guard.js";

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
const storeMemory = (subject: string, content: string) => call("agent_memory", { action: "store", agent_type: "claude_code", session_id: "s1", subject, content });

describe("a remote embedding provider never receives text that names a private package", () => {
  it("check_decision_alignment for a private package: nothing is sent, recall is lexical, and the answer says why", async () => {
    await recordDecision("Component library", "Use the shared component library for every screen");
    const answer = await call("check_decision_alignment", { technology: "@zqacme/ui" });
    expect(toEmbedder().filter((s) => /zqacme/i.test(s.body))).toEqual([]);
    expect(toEmbedder()).toEqual([]);
    expect(answer.recall_mode).toBe("ranked_lexical");
    expect(String(answer.semantic_note)).toMatch(/Semantic recall was skipped/);
    expect(String(answer.semantic_note)).toMatch(/private package/);
    expect(String(answer.semantic_note)).toContain("ollama.zq-remote.example:11434");
  });

  it("the same call for a public technology is embedded, and says nothing about private packages", async () => {
    await recordDecision("Component library", "Use the shared component library for every screen");
    const answer = await call("check_decision_alignment", { technology: "react" });
    expect(promptsSent()).toContain("react");
    expect(toEmbedder().every((s) => s.url.startsWith(REMOTE_OLLAMA))).toBe(true);
    expect(answer.recall_mode).toBe("hybrid");
    expect(answer.semantic_note).toBeUndefined();
  });

  it("every spelling of the private name in the query is caught", async () => {
    await recordDecision("Component library", "Use the shared component library for every screen");
    for (const technology of ["@ZQAcme/UI", "the @zqacme/ui package", "%40zqacme%2Fui", "＠zqacme／ui", "zqacme", "npm:@zqacme/ui@1.2.3"]) {
      const answer = await call("check_decision_alignment", { technology });
      expect(toEmbedder(), technology).toEqual([]);
      expect(String(answer.semantic_note), technology).toMatch(/Semantic recall was skipped/);
    }
  });

  it("a stored decision that names a private package is not sent; the others are, and the answer counts it", async () => {
    await recordDecision("Component library", "Use @zqacme/ui for every screen");
    await recordDecision("Date handling", "Use date-fns for dates");
    const answer = await call("check_decision_alignment", { technology: "moment" });
    expect(toEmbedder().filter((s) => /zqacme/i.test(s.body))).toEqual([]);
    expect(promptsSent().some((p) => /date-fns/.test(p))).toBe(true);
    expect(promptsSent()).toContain("moment");
    expect(String(answer.semantic_note)).toMatch(/1 stored entry names a private package/);
    expect(answer.recall_mode).toBe("hybrid");
  });

  it("agent_memory recall and the briefing's wisdom: the same rule, said in the answer", async () => {
    await storeMemory("Release steps", "Run the smoke suite before publishing");
    const recall = await call("agent_memory", { action: "recall", agent_type: "claude_code", query: "how do we publish @zqacme/ui" });
    expect(toEmbedder()).toEqual([]);
    expect(recall.recall_mode).toBe("ranked_lexical");
    expect(String(recall.semantic_note)).toMatch(/Semantic recall was skipped/);
    const brief = await call("what_should_i_know", { task: "upgrade @zqacme/ui to 2.0.0", packages: [] });
    expect(toEmbedder().filter((s) => /zqacme/i.test(s.body))).toEqual([]);
    expect(brief.wisdom_recall_mode).toBe("ranked_lexical");
    expect(String(brief.wisdom_recall_note)).toMatch(/^The task text is not sent for embedding/);
    // Wave 2, C1: a public task is not embedded either; the briefing sends no task text, ever.
    await call("what_should_i_know", { task: "how do we run the smoke suite", packages: [] });
    expect(promptsSent()).not.toContain("how do we run the smoke suite");
  });

  it("OpenAI is remote too", async () => {
    setEnv("FOURDA_EMBED_PROVIDER", "openai");
    setEnv("OPENAI_API_KEY", "sk-test-not-a-key");
    setEnv("OLLAMA_URL", undefined);
    await recordDecision("Component library", "Use the shared component library for every screen");
    const blocked = await call("check_decision_alignment", { technology: "@zqacme/ui" });
    expect(toEmbedder()).toEqual([]);
    expect(String(blocked.semantic_note)).toContain("api.openai.com");
    await call("check_decision_alignment", { technology: "react" });
    expect(toEmbedder().every((s) => s.url === "https://api.openai.com/v1/embeddings")).toBe(true);
    expect(promptsSent()).toContain("react");
  });

  it("a name a scan in this session found private is caught with no project rule left", () => {
    clearLiveIntelligence();
    expect(privateNameInText("bump zq-omega-internal to 3.2.0")).toBeNull();
    rememberPrivateName("PyPI", "zq-omega-internal", "its index is private");
    expect(privateNameInText("bump zq-omega-internal to 3.2.0")?.name).toBe("zq-omega-internal");
    expect(privateNameInText("bump ZQ_Omega.Internal to 3.2.0")?.name).toBe("ZQ_Omega.Internal");
    expect(privateNameInText("bump requests to 2.32.0")).toBeNull();
  });

  it("the text is judged up to the end of the word the length cap cuts", async () => {
    const config = getEmbeddingConfig() as EmbeddingConfig;
    const filler = "word ".repeat(1598);
    expect(filler.length).toBe(7990);
    // "@zqacme/ui" starts before character 8,000 and ends after it: its start is not sent either.
    expect(await embedText(`${filler}@zqacme/ui is ours`, config)).toBeNull();
    expect(toEmbedder()).toEqual([]);
    // A private name wholly after the cut is not part of what is sent.
    expect(await embedText(`${"word ".repeat(1700)}@zqacme/ui`, config)).not.toBeNull();
    expect(toEmbedder().filter((s) => /zqacme/i.test(s.body))).toEqual([]);
  });
});

describe("a loopback Ollama is this machine: nothing is withheld from it, and no proxy is used", () => {
  for (const url of ["http://127.0.0.1:11434", "http://localhost:11434", "http://[::1]:11434"]) {
    it(`${url}: a query that names a private package is embedded locally`, async () => {
      setEnv("OLLAMA_URL", url);
      // A proxy is configured: a loopback request must not go to it.
      setEnv("HTTPS_PROXY", "http://127.0.0.1:9");
      setEnv("HTTP_PROXY", "http://127.0.0.1:9");
      await recordDecision("Component library", "Use @zqacme/ui for every screen");
      const answer = await call("check_decision_alignment", { technology: "@zqacme/ui" });
      expect(promptsSent()).toContain("@zqacme/ui");
      expect(toEmbedder().every((s) => s.url.startsWith(url))).toBe(true);
      expect(answer.recall_mode).toBe("hybrid");
      expect(answer.semantic_note).toBeUndefined();
    });
  }

  it("which addresses are this machine", () => {
    for (const url of ["http://localhost:11434/api/embeddings", "http://LOCALHOST:11434/x", "http://127.0.0.1/x", "http://127.8.9.10:1/x", "http://[::1]:11434/x", "https://localhost/x"]) expect(isLoopbackUrl(url), url).toBe(true);
    for (const url of [
      "http://ollama.zq-remote.example:11434/x",
      "http://localhost.zq-remote.example/x",
      "http://localhost@zq-remote.example/x",
      "http://10.0.0.5:11434/x",
      "http://192.168.1.10:11434/x",
      "http://0.0.0.0:11434/x",
      "http://[::ffff:10.0.0.5]/x",
      "https://api.openai.com/v1/embeddings",
      "file:///etc/hosts",
      "not a url",
    ])
      expect(isLoopbackUrl(url), url).toBe(false);
    expect(isLocalProvider({ provider: "ollama", model: "m", url: "http://127.0.0.1:11434" })).toBe(true);
    expect(isLocalProvider({ provider: "ollama", model: "m", url: REMOTE_OLLAMA })).toBe(false);
    expect(isLocalProvider({ provider: "openai", model: "m", apiKey: "k" })).toBe(false);
    expect(embeddingEndpoint({ provider: "ollama", model: "m", url: REMOTE_OLLAMA })).toBe(`${REMOTE_OLLAMA}/api/embeddings`);
  });

  it("the loopback helper refuses any other address before a request is made", async () => {
    await expect(fetchLoopbackJson("https://api.openai.com/v1/embeddings", { method: "POST", body: "{}" })).rejects.toThrow(/loopback/);
    await expect(fetchLoopbackJson(`${REMOTE_OLLAMA}/api/embeddings`, { method: "POST", body: "{}" })).rejects.toThrow(/loopback/);
    expect(sent).toEqual([]);
  });
});

describe("remote embedding requests use the guarded HTTP helper: the proxy applies, and FOURDA_OFFLINE sends nothing", () => {
  it("with a proxy configured the request goes to the proxy, never direct", async () => {
    // An unreachable local proxy: the request fails there, and the direct (stubbed) fetch is never used.
    setEnv("HTTPS_PROXY", "http://127.0.0.1:9");
    setEnv("HTTP_PROXY", "http://127.0.0.1:9");
    await recordDecision("Date handling", "Use date-fns for dates");
    const answer = await call("check_decision_alignment", { technology: "moment" });
    expect(sent).toEqual([]);
    expect(answer.recall_mode).toBe("ranked_lexical");
  });

  it("FOURDA_OFFLINE: no provider, no request", async () => {
    setEnv("FOURDA_OFFLINE", "1");
    await recordDecision("Date handling", "Use date-fns for dates");
    const answer = await call("check_decision_alignment", { technology: "moment" });
    expect(getEmbeddingConfig()).toBeNull();
    expect(sent).toEqual([]);
    expect(answer.recall_mode).toBe("ranked_lexical");
  });
});

describe("no file in src/ calls the global fetch except the two HTTP helpers", () => {
  const src = path.resolve(__dirname, "..");
  /** The only files that may call fetch, and what each guarantees before it does. */
  const HELPERS: Record<string, RegExp> = {
    // The choke point: the private-name check runs before any request.
    // Every hop of a request passes it (redirects are followed one hop at a time there).
    "live/http-utils.ts": /refusePrivateRequest\(current, options\);/,
    // This machine only: any other address is refused before any request.
    "live/loopback-http.ts": /if \(!isLoopbackUrl\(url\)\) throw /,
  };
  /** A call of the global: `fetch(` not after `.`, a word character or `async ` (a method named fetch), or `globalThis.fetch(`. */
  const BARE_FETCH = /(?<![.\w]|async )fetch\s*\(|globalThis\s*\.\s*fetch\s*\(/;
  const sourceFiles = (): string[] => {
    const files: string[] = [];
    const walk = (dir: string) => {
      for (const name of fs.readdirSync(dir)) {
        const p = path.join(dir, name);
        if (fs.statSync(p).isDirectory()) {
          if (name !== "__tests__") walk(p);
        } else if (p.endsWith(".ts") && !p.endsWith(".d.ts") && name !== "test-setup.ts") files.push(p);
      }
    };
    walk(src);
    return files;
  };
  const code = (file: string) => fs.readFileSync(file, "utf8").replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/.*$/gm, "");

  it("every bare fetch() is in a helper", () => {
    const offenders = sourceFiles()
      .map((file) => path.relative(src, file).replaceAll("\\", "/"))
      .filter((rel) => BARE_FETCH.test(code(path.join(src, rel))) && !HELPERS[rel]);
    expect(offenders).toEqual([]);
  });

  it("each helper checks before it calls fetch", () => {
    for (const [rel, guard] of Object.entries(HELPERS)) {
      const text = code(path.join(src, rel));
      const guardAt = text.search(guard);
      const fetchAt = text.search(BARE_FETCH);
      expect(guardAt, `${rel}: the check`).toBeGreaterThanOrEqual(0);
      expect(fetchAt, `${rel}: the fetch`).toBeGreaterThan(guardAt);
    }
  });

  it("the embedding module sends through the helpers and asks the private rules first", () => {
    const text = code(path.join(src, "embeddings.ts"));
    expect(text).toMatch(/fetchWithTimeout\(/);
    expect(text).toMatch(/fetchLoopbackJson\(/);
    expect(text).toMatch(/privateNameInText\(/);
  });

  it("the check itself catches a bare call and passes a method", () => {
    expect(BARE_FETCH.test("const res = await fetch(url);")).toBe(true);
    expect(BARE_FETCH.test("return globalThis.fetch(url);")).toBe(true);
    expect(BARE_FETCH.test("await fetchWithTimeout(url);")).toBe(false);
    expect(BARE_FETCH.test("async fetch(techStack: string[]) {")).toBe(false);
    expect(BARE_FETCH.test("await this.hnFetcher.fetch(stack);")).toBe(false);
  });
});
