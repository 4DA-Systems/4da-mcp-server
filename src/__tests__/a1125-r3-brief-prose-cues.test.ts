// SPDX-License-Identifier: Apache-2.0
/**
 * Rule (iv) of what_should_i_know's lookup rule (re-check of the 2026-11-25 fixes, round 3): a word in
 * prose is looked up when a package cue stands beside it (a package noun, `@scope/name`, or the clause
 * naming the ecosystem's manager or registry with an adding verb), it has that registry's strict name
 * shape, passes the credential screen, and the task holds no private-source signal for that ecosystem.
 * A contrary cue (secret, token, key, file, user, host, value ...) beside it wins. Rounds 1-2 left most
 * prose unchecked, and the new-package malware check with it. Stubbed fetch: nothing leaves the machine.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { executeWhatShouldIKnow } from "../tools/what-should-i-know.js";
import { createHarness, type Harness } from "./helpers/a1119-planner-harness.js";

let h: Harness;
let bodies: string[];
const sent = () => [...h.requests, ...bodies].map((s) => decodeURIComponent(s));
const asked = (name: string, host: RegExp) => sent().some((s) => host.test(s) && s.includes(name));
const NPM = /registry\.npmjs\.org|"ecosystem":"npm"/;
const PYPI = /pypi\.org|"ecosystem":"PyPI"/;
const CRATES = /crates\.io|"ecosystem":"crates\.io"/;

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

describe("a package cue beside the word: looked up", () => {
  it.each([
    ["add the left-pad package", "left-pad", NPM],
    ["add the zustand library", "zustand", NPM],
    ["add qzflux as a dependency", "qzflux", NPM],
    ["add qzflux as a dev dependency", "qzflux", NPM],
    ["install the package qzflux", "qzflux", NPM],
    ["add @sentry/node", "@sentry/node", NPM],
    ["add zustand from npm", "zustand", NPM],
    ["add qzpy with pip", "qzpy", PYPI],
    ["add the time crate 0.1.43", "time", CRATES],
    ["add the openssl crate", "openssl", CRATES],
    ["use tokio from crates.io", "tokio", CRATES],
  ])("%s", async (task, name, host) => {
    await brief(task);
    expect(asked(name, host)).toBe(true);
  });

  it("a generic noun ties the word to its own ecosystem only, never to every registry", async () => {
    await brief("add the left-pad package");
    expect(asked("left-pad", PYPI)).toBe(false);
    expect(asked("left-pad", CRATES)).toBe(false);
  });
});

describe("no cue, a contrary cue, a bad shape or a private signal: not looked up", () => {
  it.each([
    "add zustand",
    "add qzflux to the project",
    "add the qzflux token to the package config",
    "add qzflux as the API key for the package",
    "add the qzflux package secret",
    "add the qzflux file from the package",
    "add the Qz9Flux2Key4Pq package",
    "set the qzflux user for the package",
    "add the qzflux package from npm.qzcorp.internal registry https://npm.qzcorp.internal",
    "npm config set registry https://npm.qzcorp.internal and add the qzflux package",
    "install qzfluxvalue12 with npm and set it as NPM_TOKEN",
    "add the dependency qzflux from ../qzflux",
    "deno add npm:qzflux",
  ])("%s", async (task) => {
    await brief(task);
    expect(sent().filter((s) => /qzflux|qz9flux|zustand/i.test(s))).toEqual([]);
  });

  it("the reason is actionable in one line, and says crates.io has no list to fall back on", async () => {
    const npm = await brief("add qzflux to the project");
    expect(npm.withheld_from_task).toEqual([
      { shown: "qzflux", reason: 'not looked up: nothing in the task shows qzflux is a public package; if it is one, call dependency_check {ecosystem: "npm", package: "qzflux", to: "latest"}' },
    ]);
    const crate = await brief("add qzcrate to Cargo.toml");
    expect(JSON.stringify(crate.withheld_from_task)).toMatch(/crates\.io has no bundled list of popular names/);
  });
});
