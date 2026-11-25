// SPDX-License-Identifier: Apache-2.0
/**
 * Fifth blind check of the 2026-11-25 fixes, item 2: a setting is not a package. `password==hunter2`,
 * `db_password==88419273`, `secret_token==tok`, `{"config":{"password":"2024.11.26"}}` were listed in
 * unverified_words with the secret as the version. An option is any word that starts with `-`
 * (`--_authToken x` listed x), and twelve or more hex digits are never a name. Stubbed fetch.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { executeWhatShouldIKnow } from "../tools/what-should-i-know.js";
import { settingName } from "../tools/briefing-task-screen.js";
import { createHarness, type Harness } from "./helpers/a1119-planner-harness.js";

let h: Harness;
let bodies: string[];
const sent = () => [...h.requests, ...bodies].map((s) => decodeURIComponent(s));

beforeEach(() => {
  h = createHarness();
  bodies = [];
  const inner = globalThis.fetch;
  vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
    if (init?.body) bodies.push(String(init.body));
    return inner(input, init);
  });
  h.npmProject({ minimist: "1.2.5" }, {}, { minimist: { version: "1.2.5" } });
});
afterEach(() => h.dispose());

async function brief(task: string): Promise<Record<string, any>> {
  return (await executeWhatShouldIKnow(null, { task, project_path: h.dir }, await h.live())) as Record<string, any>;
}

/** The answer, the task's own echo aside. */
const shown = (r: Record<string, any>) => JSON.stringify({ ...r, task: undefined });

describe("a setting is neither looked up nor listed, and its value is never shown", () => {
  it.each([
    ["password==hunter2zqx030", "password", "hunter2zqx030"],
    ["db_password==88419273", "db_password", "88419273"],
    ["secret_token==tokzqx116", "secret_token", "tokzqx116"],
    ['{"config":{"password":"2024.11.26"}}', "password", "2024.11.26"],
    ["requirements:\nrequests==2.25.0\npassword==hunter2zqx031\nflask==2.0.0", "password", "hunter2zqx031"],
    ["settings:\n  db_password: zqx99\n", "db_password", "zqx99"],
    ["DB_PASSWORD=zqxpw1 npm install lodash", "DB_PASSWORD", "zqxpw1"],
  ])("%s", async (task, key, value) => {
    const r = await brief(task);
    expect(JSON.stringify(r.unverified_words ?? [])).not.toContain(key);
    expect(shown(r)).not.toContain(value);
    expect(r.withheld_from_task).toContainEqual(expect.objectContaining({ shown: `a setting named ${key}` }));
    expect(sent().some((s) => s.includes(value))).toBe(false);
  });

  it("prose with a colon is no setting", async () => {
    const r = await brief("Auth: switch to passport");
    expect(JSON.stringify(r.withheld_from_task ?? [])).not.toContain("a setting named");
  });

  it("no popular name the round-9 screen held is a setting name, nor a dependency of the project", () => {
    const popular = [
      "jsonwebtoken", "js-tokens", "@types/jsonwebtoken", "class-variance-authority", "@csstools/css-tokenizer", "google-auth", "requests-oauthlib",
      "oauthlib", "tiktoken", "google-auth-oauthlib", "asttokens", "pytokens", "requests-aws4auth", "azure-keyvault-secrets", "supabase-auth", "oauth2client",
      "aws-requests-auth", "pydata-google-auth", "keyrings-google-artifactregistry-auth", "gcloud-aio-auth", "detect-secrets", "webauthn",
      "mypy-boto3-secretsmanager", "django-allauth", "azure-mgmt-authorization", "bc-detect-secrets", "next-auth",
    ];
    expect(popular.filter((n) => settingName(n))).toEqual([]);
    expect(settingName("api_key", (n) => n === "api_key")).toBe(false);
  });

  it.each([
    ['Add "jsonwebtoken": "8.5.1" to package.json', "jsonwebtoken"],
    ["pip install oauthlib==3.2.0", "oauthlib"],
    ['Add "js-tokens": "4.0.0" to package.json', "js-tokens"],
  ])("%s is still a package", async (task, name) => {
    const r = await brief(task);
    expect(JSON.stringify(r.withheld_from_task ?? [])).not.toContain(name);
    expect(JSON.stringify([...(r.new_packages ?? []), ...(r.unverified_words ?? []), ...(r.requested_versions ?? [])])).toContain(name);
  });
});

describe("any word that starts with - is an option, and its value is never a name", () => {
  it.each([
    "npm install lodash --_authToken zqxa1",
    "npm install lodash --_auth zqxa2",
    "npm install lodash --_password zqxa3",
    "npm install lodash -_authToken zqxa4",
    "npm install lodash --token: zqxa5",
    "npm install lodash --@scope:_authToken zqxa6",
  ])("%s", async (task) => {
    const r = await brief(task);
    expect(shown(r)).not.toMatch(/zqxa\d/);
    expect(sent().some((s) => /zqxa\d/.test(s))).toBe(false);
  });

  it("cargo add hyper --vers 0.14.9 and --vers=0.14.9: still the version of hyper", async () => {
    for (const task of ["cargo add hyper --vers 0.14.9", "cargo add hyper --vers=0.14.9"]) {
      const r = await brief(task);
      expect(r.unverified_words).toEqual([{ word: "hyper", read_as: "crates.io", version: "0.14.9" }]);
    }
  });
});

describe("twelve or more hex digits are never a name", () => {
  it("npm install lodash 9d962429c6eeafce", async () => {
    const r = await brief("npm install lodash 9d962429c6eeafce");
    expect(JSON.stringify(r.unverified_words ?? [])).not.toContain("9d96");
    expect(shown(r)).not.toContain("9d962429c6eeafce");
    expect(sent().some((s) => s.includes("9d962429"))).toBe(false);
  });
});
