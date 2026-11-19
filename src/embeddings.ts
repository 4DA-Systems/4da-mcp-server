// SPDX-License-Identifier: Apache-2.0
/**
 * Optional, provider-backed semantic embeddings for local knowledge recall.
 *
 * The MCP server ships ZERO embedding dependencies — that is the whole point of
 * the `npx` zero-install promise. Semantic recall therefore lights up ONLY when
 * the user already has an embedding provider reachable:
 *   - Ollama  (local, private, free)  — set settings.embedding.provider = "ollama"
 *   - OpenAI  (cloud, explicit opt-in) — set settings.embedding.provider = "openai"
 *
 * When no provider is configured, the provider is unreachable, the embed model is
 * missing, or FOURDA_OFFLINE is set, every caller falls back to ranked lexical
 * recall and the response says so via `recall_mode`.
 *
 * Private package names never leave the machine here either. A provider on a
 * loopback address (the default Ollama) is this machine and is sent everything,
 * directly. Any other provider (OpenAI, an Ollama URL on another host) is sent
 * text only after the private-name rules have read it (privateNameInText): text
 * that names a private package is withheld, the caller ranks lexically, and the
 * answer says so. Its requests go through fetchWithTimeout, so the proxy applies.
 *
 * Critically, the server embeds
 * BOTH the query and the stored rows with the SAME provider/model, so the vector
 * space is always self-consistent — we never mix our vectors with the desktop
 * app's fastembed vectors.
 *
 * No sqlite-vec: similarity is a plain JS cosine over Float32 BLOBs, which is
 * trivially fast for the few-hundred-row local knowledge tables this serves.
 */

import { readFileSync, existsSync, statSync } from "node:fs";
import { join, dirname, resolve } from "node:path";
import { desktopAppDbPaths, type AppWritableTable, type FourDADatabase } from "./db.js";
import { isOfflineMode as offlineFlag } from "./env-flags.js";
import { fetchWithTimeout } from "./live/http-utils.js";
import { fetchLoopbackJson, isLoopbackUrl } from "./live/loopback-http.js";
import { privateNameInText } from "./live/private-guard.js";

// =============================================================================
// Config
// =============================================================================

export interface EmbeddingConfig {
  provider: "ollama" | "openai";
  model: string;
  /** Ollama base URL (ignored for openai). */
  url?: string;
  /** OpenAI API key (ignored for ollama). */
  apiKey?: string;
}

const DEFAULT_OLLAMA_EMBED_MODEL = "nomic-embed-text";
const DEFAULT_OPENAI_EMBED_MODEL = "text-embedding-3-small";
const DEFAULT_OLLAMA_URL = "http://localhost:11434";

/** True when network calls are disabled by the FOURDA_OFFLINE escape hatch (1 / true / yes / on). */
export function isOfflineMode(): boolean {
  return offlineFlag();
}

/**
 * Locate settings.json: FOURDA_SETTINGS_PATH, else the one beside an explicit
 * FOURDA_DB_PATH (relative paths resolve against cwd, as the database's do),
 * else the desktop app's own data directory.
 *
 * Never the working directory or its parent. Until 6.2.5 `cwd/data`,
 * `cwd/../data` and the package's own `../data` were searched, so a cloned
 * repository with `data/settings.json` could point semantic recall at any
 * host, and stored agent memory and decisions were sent there to be embedded
 * (audit 2026-10-12, B-3).
 */
function findSettingsFile(): string | null {
  const envPath = process.env.FOURDA_SETTINGS_PATH?.trim();
  if (envPath && existsSync(envPath)) return envPath;

  const dbPath = process.env.FOURDA_DB_PATH?.trim();
  if (dbPath) {
    const sibling = join(dirname(resolve(process.cwd(), dbPath)), "settings.json");
    if (existsSync(sibling)) return sibling;
  }

  for (const appDb of desktopAppDbPaths()) {
    const candidate = join(dirname(appDb), "settings.json");
    if (existsSync(candidate)) return candidate;
  }
  return null;
}

let _cached: { config: EmbeddingConfig | null; path: string | null; mtimeMs: number } | null = null;

/**
 * Resolve the embedding provider. Order of precedence:
 *   1. FOURDA_OFFLINE        -> always null (no network)
 *   2. environment variables -> FOURDA_EMBED_PROVIDER / FOURDA_EMBED_MODEL / ...
 *   3. settings.json         -> the `embedding` block
 *   4. (nothing)             -> null, callers stay lexical
 *
 * Deliberately does NOT auto-derive from the chat `llm` block: enabling semantic
 * recall is an explicit choice so a recall never makes a surprise network call.
 */
export function getEmbeddingConfig(): EmbeddingConfig | null {
  if (isOfflineMode()) return null;

  // 2. Environment override
  const envProvider = (process.env.FOURDA_EMBED_PROVIDER || "").toLowerCase();
  if (envProvider === "ollama" || envProvider === "openai") {
    return normalizeConfig({
      provider: envProvider,
      model: process.env.FOURDA_EMBED_MODEL,
      url: process.env.OLLAMA_URL,
      api_key: process.env.OPENAI_API_KEY,
    });
  }

  // 3. settings.json `embedding` block (mtime-cached)
  const settingsPath = findSettingsFile();
  if (!settingsPath) return null;

  try {
    const mtimeMs = statSync(settingsPath).mtimeMs;
    if (_cached && _cached.path === settingsPath && _cached.mtimeMs === mtimeMs) {
      return _cached.config;
    }

    const settings = JSON.parse(readFileSync(settingsPath, "utf-8")) as {
      embedding?: {
        provider?: string;
        model?: string;
        url?: string;
        base_url?: string;
        api_key?: string;
      };
    };
    const raw = settings.embedding;
    const config = raw
      ? normalizeConfig({
          provider: (raw.provider || "").toLowerCase(),
          model: raw.model,
          url: raw.url || raw.base_url,
          api_key: raw.api_key,
        })
      : null;

    _cached = { config, path: settingsPath, mtimeMs };
    return config;
  } catch {
    return null;
  }
}

function normalizeConfig(raw: {
  provider: string;
  model?: string;
  url?: string;
  api_key?: string;
}): EmbeddingConfig | null {
  if (raw.provider === "ollama") {
    return {
      provider: "ollama",
      model: raw.model || DEFAULT_OLLAMA_EMBED_MODEL,
      url: raw.url || DEFAULT_OLLAMA_URL,
    };
  }
  if (raw.provider === "openai") {
    if (!raw.api_key) return null; // openai needs a key — no key, no semantic
    return {
      provider: "openai",
      model: raw.model || DEFAULT_OPENAI_EMBED_MODEL,
      apiKey: raw.api_key,
    };
  }
  return null;
}

/** A short, stable identity for the active model, stored alongside each vector. */
export function modelTag(config: EmbeddingConfig): string {
  return `${config.provider}:${config.model}`;
}

// =============================================================================
// Embedding calls
// =============================================================================

/** Cap on the text length sent to the embedder, to bound payload size. */
const MAX_EMBED_CHARS = 8000;
/** How long one embedding request may take, a model's first load included. */
const EMBED_TIMEOUT_MS = 30_000;
/** How far past the cap a word that the cap cuts is followed, to judge it whole. */
const MAX_CUT_WORD = 512;

/** Where a provider's embedding requests go. */
export function embeddingEndpoint(config: EmbeddingConfig): string {
  return config.provider === "ollama" ? `${config.url || DEFAULT_OLLAMA_URL}/api/embeddings` : "https://api.openai.com/v1/embeddings";
}

/** Whether the provider is on this machine (an Ollama on a loopback address): what it is sent does not leave. */
export function isLocalProvider(config: EmbeddingConfig): boolean {
  return config.provider === "ollama" && isLoopbackUrl(embeddingEndpoint(config));
}

/** The host a provider's requests go to, for an answer that names it. */
function providerHost(config: EmbeddingConfig): string {
  try {
    return new URL(embeddingEndpoint(config)).host;
  } catch {
    return config.provider;
  }
}

/** One text's embedding, or why there is none: `withheld` names the private package the text names. */
interface EmbedOutcome {
  vector: Float32Array | null;
  withheld?: string;
}

/** `pending`, or a rejection as soon as `signal` aborts. */
function unlessAborted<T>(pending: Promise<T>, signal: AbortSignal | undefined): Promise<T> {
  if (!signal) return pending;
  if (signal.aborted) return Promise.reject(new Error("cancelled"));
  return new Promise<T>((resolve, reject) => {
    const stop = () => reject(new Error("cancelled"));
    signal.addEventListener("abort", stop, { once: true });
    pending.then(resolve, reject).finally(() => signal.removeEventListener("abort", stop));
  });
}

/**
 * Embed one text. The vector is null on ANY failure (provider down, model missing, bad response,
 * empty input) so callers degrade to lexical. For a provider that is not on this machine the text
 * is read by the private-name rules first, to the end of the word the length cap cuts: text that
 * names a private package is not sent, and `withheld` says which name.
 */
async function embed(text: string, config: EmbeddingConfig, signal?: AbortSignal): Promise<EmbedOutcome> {
  const whole = text || "";
  const input = whole.slice(0, MAX_EMBED_CHARS).trim();
  if (!input) return { vector: null };
  const url = embeddingEndpoint(config);
  const local = isLocalProvider(config);
  if (!local) {
    let end = Math.min(whole.length, MAX_EMBED_CHARS);
    while (end < whole.length && end < MAX_EMBED_CHARS + MAX_CUT_WORD && !/\s/.test(whole[end])) end++;
    const hit = privateNameInText(whole.slice(0, end));
    if (hit) return { vector: null, withheld: hit.name };
  }

  try {
    const init: RequestInit =
      config.provider === "ollama"
        ? {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            // The embedder runs on the CPU, as the 4DA app's does: on the GPU,
            // Ollama evicts and reloads the local judge model around each call.
            body: JSON.stringify({ model: config.model, prompt: input, options: { num_gpu: 0 } }),
          }
        : {
            method: "POST",
            headers: { "Content-Type": "application/json", Authorization: `Bearer ${config.apiKey}` },
            body: JSON.stringify({ model: config.model, input }),
          };
    let data: unknown;
    if (local) data = await fetchLoopbackJson(url, { ...init, signal }, EMBED_TIMEOUT_MS);
    else {
      const res = await unlessAborted(fetchWithTimeout(url, init, EMBED_TIMEOUT_MS), signal);
      data = res.ok ? await unlessAborted(res.json() as Promise<unknown>, signal) : null;
    }
    const body = (data ?? {}) as { embedding?: number[]; data?: Array<{ embedding?: number[] }> };
    const values = config.provider === "ollama" ? body.embedding : body.data?.[0]?.embedding;
    return { vector: values && values.length ? Float32Array.from(values) : null };
  } catch {
    return { vector: null };
  }
}

/**
 * Embed a single text. Returns null on ANY failure (provider down, model
 * missing, bad response, empty input) so callers degrade to lexical silently,
 * and for text a provider off this machine must not be sent (see embed).
 */
export async function embedText(
  text: string,
  config: EmbeddingConfig,
  signal?: AbortSignal,
): Promise<Float32Array | null> {
  return (await embed(text, config, signal)).vector;
}

// =============================================================================
// Vector helpers (BLOB <-> Float32Array, cosine)
// =============================================================================

/** Pack a vector into a little-endian Float32 BLOB for SQLite storage. */
export function vectorToBlob(vec: Float32Array): Buffer {
  return Buffer.from(vec.buffer, vec.byteOffset, vec.byteLength);
}

/**
 * Unpack a stored BLOB back into a Float32Array. Returns null for empty/
 * misaligned blobs so a corrupt cell never throws mid-recall. Copies the bytes
 * to guarantee 4-byte alignment regardless of the source buffer's offset.
 */
export function blobToVector(blob: Buffer | Uint8Array | null | undefined): Float32Array | null {
  if (!blob || blob.byteLength === 0 || blob.byteLength % 4 !== 0) return null;
  const copy = Buffer.from(blob);
  return new Float32Array(copy.buffer, copy.byteOffset, copy.byteLength / 4);
}

/** Cosine similarity in [-1, 1]; 0 for length mismatch or a zero vector. */
export function cosineSimilarity(a: Float32Array, b: Float32Array): number {
  if (a.length !== b.length || a.length === 0) return 0;
  let dot = 0;
  let na = 0;
  let nb = 0;
  for (let i = 0; i < a.length; i++) {
    dot += a[i] * b[i];
    na += a[i] * a[i];
    nb += b[i] * b[i];
  }
  if (na === 0 || nb === 0) return 0;
  return dot / (Math.sqrt(na) * Math.sqrt(nb));
}

// =============================================================================
// Generic semantic scoring over a local knowledge table
// =============================================================================

/** Default cap on rows embedded per call, so a cold cache cannot stall a response. */
const DEFAULT_MAX_NEW_EMBEDS = 48;

export interface SemanticScoreResult {
  /** id -> cosine similarity to the query (only for rows that have a vector). */
  semanticById: Map<number, number>;
  /** False when the query itself could not be embedded — caller stays lexical. */
  queryEmbedded: boolean;
  /** How many candidate rows contributed a semantic score this call. */
  embeddedCount: number;
  /** How many rows were embedded fresh this call (lazy backfill). */
  newlyEmbedded: number;
  /** The provider:model tag the scores were produced with. */
  model: string;
  /**
   * Set when text was kept from a provider that is not on this machine because it names a private
   * package: the query (semantic recall was then skipped for the call) or stored rows (ranked
   * lexically only). `note` is the sentence the answer carries.
   */
  privateWithheld?: { query: boolean; rows: number; note: string };
}

/** The sentence for a query that names a private package. */
function queryWithheldNote(name: string, config: EmbeddingConfig): string {
  return `Semantic recall was skipped for this call: the query names a private package (${name}), and text that names one is never sent to an embedding provider that is not on this machine (${providerHost(config)}). Lexical recall was used.`;
}

/** The sentence for stored rows that name a private package. */
function rowsWithheldNote(rows: number, config: EmbeddingConfig): string {
  return `${rows.toLocaleString("en-US")} stored entr${rows === 1 ? "y names" : "ies name"} a private package and ${rows === 1 ? "was" : "were"} not sent to the embedding provider (${providerHost(config)}): ${rows === 1 ? "it was" : "they were"} ranked lexically only.`;
}

/**
 * Score `items` (id + the text to embed) against a query using cached, lazily
 * backfilled embeddings stored in `<table>.embedding` / `<table>.embedding_model`.
 *
 * Shared by every semantic-recall surface (agent_memory, developer_decisions) so
 * the embed/cache/cosine logic lives in exactly one place. `table` is always a
 * server-controlled constant (never user input), so the interpolated SQL is safe.
 *
 * Returns `queryEmbedded: false` (and an empty map) when the provider is
 * unreachable, so callers fall back to pure lexical recall.
 */
export async function semanticScores(
  db: FourDADatabase,
  table: string,
  query: string,
  items: Array<{ id: number; text: string }>,
  config: EmbeddingConfig,
  opts: { maxNewEmbeds?: number } = {},
): Promise<SemanticScoreResult> {
  const tag = modelTag(config);
  const asked = await embed(query, config);
  const queryVec = asked.vector;
  if (!queryVec) {
    const privateWithheld = asked.withheld ? { privateWithheld: { query: true, rows: 0, note: queryWithheldNote(asked.withheld, config) } } : {};
    return { semanticById: new Map(), queryEmbedded: false, embeddedCount: 0, newlyEmbedded: 0, model: tag, ...privateWithheld };
  }

  // Cache columns are optional. This server's own database gets them lazily;
  // the desktop app's database is never altered, so there the cache is used
  // only when the app's table already has both columns (written through the
  // separate write connection, see FourDADatabase.writerFor), and vectors are
  // otherwise computed per call and not stored.
  const readOnly = (db as Partial<Pick<FourDADatabase, "isReadOnly">>).isReadOnly === true;
  let cacheDb: ReturnType<FourDADatabase["getRawDb"]> | null = null;
  if (!readOnly) {
    db.ensureColumn(table, "embedding", "BLOB");
    db.ensureColumn(table, "embedding_model", "TEXT");
    cacheDb = db.getRawDb();
  } else if (db.hasColumn(table, "embedding") && db.hasColumn(table, "embedding_model")) {
    const to = db.writerFor(table as AppWritableTable, ["id", "embedding", "embedding_model"]);
    cacheDb = to.target === "app" ? to.raw : null;
  }

  const stored = cacheDb ? loadStoredEmbeddings(db.getRawDb(), table, items.map((i) => i.id), tag) : new Map<number, Float32Array>();
  const updateStmt = cacheDb?.prepare(
    `UPDATE ${table} SET embedding = ?, embedding_model = ? WHERE id = ?`,
  );
  const maxNew = opts.maxNewEmbeds ?? DEFAULT_MAX_NEW_EMBEDS;

  const semanticById = new Map<number, number>();
  let embeddedCount = 0;
  let newlyEmbedded = 0;
  let withheldRows = 0;

  for (const item of items) {
    let vec = stored.get(item.id) ?? null;
    if (!vec && newlyEmbedded < maxNew) {
      const row = await embed(item.text, config);
      if (row.withheld) withheldRows++;
      vec = row.vector;
      if (vec) {
        try {
          updateStmt?.run(vectorToBlob(vec), tag, item.id);
        } catch {
          // Persisting the cache is best-effort; scoring still proceeds.
        }
        newlyEmbedded++;
      }
    }
    if (vec && vec.length === queryVec.length) {
      embeddedCount++;
      semanticById.set(item.id, cosineSimilarity(queryVec, vec));
    }
  }

  const privateWithheld = withheldRows > 0 ? { privateWithheld: { query: false, rows: withheldRows, note: rowsWithheldNote(withheldRows, config) } } : {};
  return { semanticById, queryEmbedded: true, embeddedCount, newlyEmbedded, model: tag, ...privateWithheld };
}

/**
 * Load cached embeddings for the given ids that were produced by the CURRENT model
 * (a model change invalidates old vectors). Returns a map of id -> vector.
 */
function loadStoredEmbeddings(
  rawDb: ReturnType<FourDADatabase["getRawDb"]>,
  table: string,
  ids: number[],
  modelTagValue: string,
): Map<number, Float32Array> {
  const out = new Map<number, Float32Array>();
  if (ids.length === 0) return out;
  try {
    const placeholders = ids.map(() => "?").join(",");
    const rows = rawDb
      .prepare(
        `SELECT id, embedding, embedding_model FROM ${table} WHERE id IN (${placeholders})`,
      )
      .all(...ids) as Array<{
        id: number;
        embedding: Buffer | null;
        embedding_model: string | null;
      }>;
    for (const row of rows) {
      if (row.embedding && row.embedding_model === modelTagValue) {
        const vec = blobToVector(row.embedding);
        if (vec) out.set(row.id, vec);
      }
    }
  } catch {
    // Defensive: a missing column simply means no cache, so everything re-embeds.
  }
  return out;
}
