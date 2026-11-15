// SPDX-License-Identifier: Apache-2.0
/**
 * Pre-publish round 10, W9: the first tool call's init and the pnpm read.
 *
 * - The init runs after the event loop has had a turn (prepareDatabase in index.ts), so a `ping`
 *   read with the first `tools/call` is answered before it: it waited for the whole init (240 ms on
 *   41 dependencies, 2.6 s on a 150,000-entry pnpm-lock.yaml). index.ts starts the server when
 *   imported, so the wiring is pinned on its source; the timing is measured on the built server.
 * - readPnpmLock keeps one record per registry (name, version), not one per sighting: lockfile 9
 *   lists each package under `packages:` and `snapshots:`. What it reads must not change.
 */
import fs from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { readPnpmLock } from "../live/js-lockfile-readers.js";
import { InstanceSet } from "../live/lockfile-types.js";

const here = path.dirname(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1"));
const indexSource = fs.readFileSync(path.join(here, "..", "index.ts"), "utf8");

describe("the first tool call's init yields before it runs", () => {
  it("tools/call awaits prepareDatabase before databaseFor", () => {
    const call = indexSource.slice(indexSource.indexOf('setRequestHandler("tools/call"'));
    const prepare = call.indexOf("await prepareDatabase()");
    expect(prepare).toBeGreaterThan(0);
    expect(prepare).toBeLessThan(call.indexOf("databaseFor(name)"));
  });

  it("prepareDatabase gives the event loop a turn before each step", () => {
    const body = indexSource.slice(indexSource.indexOf("async function prepareDatabase"), indexSource.indexOf("function finishInit"));
    expect(body.match(/await yieldToEventLoop\(\)/g)?.length).toBe(2);
    expect(body).toMatch(/openInit\(\)/);
  });
});

describe("readPnpmLock reads each package once, as before", () => {
  const lock = [
    "lockfileVersion: '9.0'",
    "",
    "importers:",
    "  .:",
    "    dependencies:",
    "      a:",
    "        specifier: ^1.0.0",
    "        version: 1.0.0",
    "",
    "packages:",
    "  a@1.0.0:",
    "    resolution: {integrity: sha512-x}",
    "  b@2.0.0:",
    "    resolution: {integrity: sha512-y}",
    "  b@3.0.0:",
    "    resolution: {integrity: sha512-z}",
    "",
    "snapshots:",
    "  a@1.0.0: {}",
    "  b@2.0.0: {}",
    "  b@3.0.0: {}",
    "",
  ].join("\n");

  it("versions, instances and the install set are the same, with each copy once", () => {
    const versions = new Map<string, string>();
    const instances = new InstanceSet();
    const installs = readPnpmLock(lock, versions, instances, { missingDirect: [], uncheckable: [], incomplete: 0 });
    expect([...versions]).toEqual([["a", "1.0.0"], ["b", "2.0.0"]]);
    expect(instances.toArray()).toEqual([{ name: "a", version: "1.0.0" }, { name: "b", version: "2.0.0" }, { name: "b", version: "3.0.0" }]);
    expect([...installs]).toEqual(["a\0" + "1.0.0", "b\0" + "2.0.0", "b\0" + "3.0.0"]);
  });

  it("v6 dev flags merge as before: a copy dev in every sighting is dev", () => {
    const v6 = ["lockfileVersion: '6.0'", "", "packages:", "  /c@1.0.0:", "    resolution: {integrity: sha512-c}", "    dev: true", "  /d@1.0.0:", "    resolution: {integrity: sha512-d}", "    dev: false", ""].join("\n");
    const instances = new InstanceSet();
    readPnpmLock(v6, new Map(), instances);
    expect(instances.toArray()).toEqual([{ name: "c", version: "1.0.0", dev: true }, { name: "d", version: "1.0.0", dev: false }]);
  });
});
