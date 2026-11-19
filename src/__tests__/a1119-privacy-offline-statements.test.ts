// SPDX-License-Identifier: Apache-2.0
/**
 * Two statements now say what the server does:
 * - `--doctor`'s semantic recall line reports the provider the server will use
 *   (getEmbeddingConfig), not which variables are set: OPENAI_API_KEY alone, OLLAMA_HOST or a
 *   provider with no key printed "OpenAI API key set" / "Ollama endpoint configured" while
 *   semantic recall was off.
 * - ecosystem_pulse under FOURDA_OFFLINE says Hacker News was not searched, never "No relevant
 *   headlines found for your tech stack".
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { semanticRecallCheck } from "../doctor.js";
import { executeEcosystemPulse } from "../tools/ecosystem-pulse.js";

const KEYS = ["FOURDA_OFFLINE", "FOURDA_EMBED_PROVIDER", "FOURDA_EMBED_MODEL", "OPENAI_API_KEY", "OLLAMA_URL", "OLLAMA_HOST", "OLLAMA_BASE_URL", "FOURDA_SETTINGS_PATH", "FOURDA_DB_PATH"];
const saved = new Map<string, string | undefined>();
let scratch: string;

beforeEach(() => {
  for (const key of KEYS) {
    saved.set(key, process.env[key]);
    delete process.env[key];
  }
  // A settings file with no embedding block: the machine's own desktop-app settings are never read.
  scratch = fs.mkdtempSync(path.join(os.tmpdir(), "4da-a1119-stmt-"));
  fs.writeFileSync(path.join(scratch, "settings.json"), "{}");
  process.env.FOURDA_SETTINGS_PATH = path.join(scratch, "settings.json");
});
afterEach(() => {
  for (const [key, value] of saved) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
  saved.clear();
  fs.rmSync(scratch, { recursive: true, force: true });
});

describe("--doctor: the semantic recall line is what the server will do", () => {
  it.each([
    [{}, /^Off: no usable provider is configured/],
    [{ OPENAI_API_KEY: "sk-test" }, /^Off: .*OPENAI_API_KEY alone does not turn it on/],
    [{ OLLAMA_HOST: "127.0.0.1:11434" }, /^Off: .*OLLAMA_HOST is not read/],
    [{ OLLAMA_BASE_URL: "http://127.0.0.1:11434" }, /^Off: .*OLLAMA_BASE_URL is not read/],
    [{ FOURDA_EMBED_PROVIDER: "openai" }, /^Off: FOURDA_EMBED_PROVIDER=openai, but OPENAI_API_KEY is not set/],
    [{ FOURDA_EMBED_PROVIDER: "cohere" }, /^Off: FOURDA_EMBED_PROVIDER=cohere is not a provider this server knows/],
    [{ FOURDA_EMBED_PROVIDER: "ollama", FOURDA_OFFLINE: "1" }, /^Off: FOURDA_OFFLINE is set/],
  ])("%j: off, and says why", (env, detail) => {
    Object.assign(process.env, env);
    const check = semanticRecallCheck();
    expect(check.status).toBe("warn");
    expect(check.detail).toMatch(detail);
    expect(check.detail).toMatch(/Keyword recall is used/);
    expect(check.detail).not.toMatch(/API key set|endpoint configured/);
  });

  it.each([
    [{ FOURDA_EMBED_PROVIDER: "ollama" }, "ollama:nomic-embed-text at localhost:11434 (on this machine)"],
    [{ FOURDA_EMBED_PROVIDER: "ollama", OLLAMA_URL: "http://embed.zq-remote.example:11434" }, "ollama:nomic-embed-text at embed.zq-remote.example:11434 (not on this machine: text that names a private package is never sent to it)"],
    [{ FOURDA_EMBED_PROVIDER: "openai", OPENAI_API_KEY: "sk-test" }, "openai:text-embedding-3-small at api.openai.com (not on this machine: text that names a private package is never sent to it)"],
  ])("%j: on, with the provider, model and where it is", (env, detail) => {
    Object.assign(process.env, env);
    expect(semanticRecallCheck()).toEqual({ name: "Semantic recall provider", status: "pass", detail });
  });
});

describe("ecosystem_pulse under FOURDA_OFFLINE: nothing was searched, and the answer says so", () => {
  const db = { isStandalone: true, getRawDb: () => ({ prepare: () => ({ all: () => [{ name: "react" }], get: () => undefined }) }) };
  const live = (enabled: boolean) => ({ getHeadlines: () => [], isEnabled: () => enabled, fetchHeadlines: async () => [], getHeadlineError: () => null, getProjectRoot: () => scratch });

  for (const enabled of [false, true]) {
    it(`live layer ${enabled ? "on (a local advisory source)" : "off"}: NOT CHECKED, not "No relevant headlines"`, async () => {
      process.env.FOURDA_OFFLINE = "1";
      const result = await executeEcosystemPulse(db as never, {}, live(enabled) as never);
      expect(result.headlines).toEqual([]);
      expect(result.note).toMatch(/^NOT CHECKED: live lookups are off \(FOURDA_OFFLINE\), so Hacker News was not searched/);
      expect(result.note).not.toMatch(/No relevant headlines/);
    });
  }

  it("control: online, headlines read and none relevant is still 'No relevant headlines found'", async () => {
    const headline = { id: 1, title: "A post", url: "https://example.com", points: 5, comments: 0, published: "2026-11-19", relevanceScore: 0.1, relevanceReason: "react" };
    const result = await executeEcosystemPulse(db as never, { min_points: 100 }, { ...live(true), getHeadlines: () => [headline] } as never);
    expect(result.note).toMatch(/^No relevant headlines found/);
  });
});
