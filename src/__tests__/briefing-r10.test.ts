// SPDX-License-Identifier: Apache-2.0
/**
 * what_should_i_know, pre-publish round 10 (W3): how the briefing reads a task's text. Each case
 * came back from the built ebd6391 server with a package unread, a verdict dependency_check would
 * not give, or contradictory rows for one package:
 *
 * 1. "add minimist >= 1.2.0, < 1.2.6": the comma range went to dependency_check as npm, which reads
 *    only npm's space-joined form and refused it: unknown / review_needed, where the range is avoid.
 * 2. `smallvec = { version = ">=1.6.0, <1.6.1" }`: the clause reader filed it under the project's
 *    ecosystems, the version reader under npm: one "(avoid)" row and one "(unknown)" row.
 * 3. "chalk 5.6.1/debug 4.4.2" (the September 2025 hijacked releases), no verb: neither version was
 *    read; "bump chalk to 5.6.1 / debug to 4.4.2" judged chalk at debug's 4.4.2.
 * 4. "add debug, chalk and ms": debug and ms read as prose; "add debug, then ..." named nothing.
 * 5. "use blueprints" sent blueprints to OSV.dev twice (/v1/query and /v1/querybatch).
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { clearNpmDownloadsMemo } from "../live/npm-downloads.js";
import type { ResolvedDependency } from "../live/types.js";
import { detectAllNewPackages } from "../tools/briefing-new-packages.js";
import { readTaskVersions } from "../tools/briefing-requested-versions.js";
import { checkableSpec } from "../tools/briefing-names.js";
import { executeWhatShouldIKnow } from "../tools/what-should-i-know.js";
import type { FourDADatabase } from "../db.js";
import { advisory, dep, installFetchStub, memoryDb, readyScan, stubIntel, type Stub } from "./helpers/briefing-stub.js";

const NPM = [dep("lodash", "4.17.20")];
const RUST = [dep("tokio", "1.40.0", "crates.io")];
/** package.json beside Cargo.toml, npm the larger: the case that gave two rows. */
const NPM_AND_RUST = [dep("lodash", "4.17.20"), dep("react", "18.2.0"), dep("tokio", "1.40.0", "crates.io")];
const PY = [dep("requests", "2.32.3", "PyPI")];
const MIXED_PY = [dep("lodash", "4.17.20"), dep("react", "18.2.0"), dep("requests", "2.32.3", "PyPI")];

const added = (task: string, deps: ResolvedDependency[] = NPM) => detectAllNewPackages(task, deps).map((p) => `${p.ecosystem}:${p.name}${p.version ? `@${p.version}` : ""}`);
const requested = (task: string, deps: ResolvedDependency[] = NPM) => readTaskVersions(task, deps).requested.map((r) => `${r.ecosystem}:${r.name}@${r.to}`);

/** crates.io in memory: `/api/v1/crates/<name>` with every version, nothing else. */
const CRATES: Record<string, string[]> = { smallvec: ["1.5.0", "1.6.0", "1.6.1", "1.13.2"] };

let stub: Stub;
let db: FourDADatabase;
let priorOffline: string | undefined;
beforeEach(() => {
  priorOffline = process.env.FOURDA_OFFLINE;
  delete process.env.FOURDA_OFFLINE;
  clearNpmDownloadsMemo();
  db = memoryDb();
  stub = {
    asked: [],
    npm: {
      chalk: { latest: "5.6.2", versions: ["5.6.0", "5.6.1", "5.6.2"] },
      debug: { latest: "4.4.3", versions: ["4.4.1", "4.4.2", "4.4.3"] },
      minimist: { latest: "1.2.8", versions: ["1.2.0", "1.2.5", "1.2.6", "1.2.8"] },
      ms: { latest: "2.1.3", versions: ["2.1.3"] },
      express: { latest: "4.21.2", versions: ["4.21.2"] },
      blueprints: { latest: "0.1.3", versions: ["0.1.3"] },
      crossenv: { latest: "0.0.1-security", versions: ["0.0.1-security"] },
      lodahs: { latest: "0.0.1-security", versions: ["0.0.1-security"] },
    },
    osv: [
      advisory("MAL-2025-chalk-5.6.1", "chalk", "CRITICAL", { versions: ["5.6.1"] }, "npm", true),
      advisory("MAL-2025-debug-4.4.2", "debug", "CRITICAL", { versions: ["4.4.2"] }, "npm", true),
      advisory("GHSA-vh95-rmgr-6w4m", "minimist", "CRITICAL", { versions: ["1.2.0", "1.2.5"] }),
      advisory("GHSA-43w2-9j62-hq99", "smallvec", "CRITICAL", { versions: ["1.6.0"] }, "crates.io"),
      advisory("GHSA-blueprints-old", "blueprints", "LOW", { fixed: "9.9.9" }),
      advisory("MAL-2017-crossenv", "crossenv", "CRITICAL", {}, "npm", true),
      advisory("MAL-2025-25502", "lodahs", "CRITICAL", {}, "npm", true),
      advisory("GHSA-ctx-pypi", "ctx", "CRITICAL", {}, "PyPI", true),
    ],
  };
  installFetchStub(stub);
  // crates.io beside the npm registry and OSV.dev the shared stub serves.
  const npmAndOsv = globalThis.fetch;
  vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
    const url = String(input);
    const crate = /^https:\/\/crates\.io\/api\/v1\/crates\/([^/?]+)$/.exec(url);
    if (crate) {
      stub.asked.push(url);
      const versions = CRATES[decodeURIComponent(crate[1])];
      if (!versions) return new Response(JSON.stringify({ errors: [{ detail: "Not Found" }] }), { status: 404 });
      return new Response(
        JSON.stringify({
          crate: { num_versions: versions.length, created_at: "2018-01-01T00:00:00Z" },
          versions: versions.map((num, i) => ({ num, created_at: new Date(Date.UTC(2019, 0, 1 + i)).toISOString(), yanked: false })),
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }
    return npmAndOsv(input, init);
  });
});
afterEach(() => {
  vi.unstubAllGlobals();
  if (priorOffline === undefined) delete process.env.FOURDA_OFFLINE;
  else process.env.FOURDA_OFFLINE = priorOffline;
});

const brief = (task: string, deps: ResolvedDependency[] = NPM) => executeWhatShouldIKnow(db, { task }, stubIntel(deps, {}, readyScan()));
/** The OSV.dev requests that name `pkg`. */
const osvAsks = (pkg: string) => stub.asked.filter((u) => u.startsWith("https://api.osv.dev/v1/query") && u.includes(`"name":"${pkg}"`));

describe("1. a comma-separated range is read the way dependency_check reads it", () => {
  it("each ecosystem gets the constraint in the form dependency_check accepts for it", () => {
    expect(checkableSpec("npm", ">=1.2.0,<1.2.6")).toBe(">=1.2.0 <1.2.6");
    expect(checkableSpec("npm", ">=1.2.0 <1.2.6")).toBe(">=1.2.0 <1.2.6");
    expect(checkableSpec("npm", ">=1.0,<2 || >=3")).toBe(">=1.0 <2 || >=3");
    expect(checkableSpec("crates.io", ">=1.6.0,<1.6.1")).toBe(">=1.6.0,<1.6.1");
    expect(checkableSpec("PyPI", ">=1.2.5 <1.2.6")).toBe(">=1.2.5,<1.2.6");
    expect(checkableSpec("PyPI", ">=2,<3")).toBe(">=2,<3");
    expect(checkableSpec("npm", "latest")).toBe("latest");
    // A hyphen range PyPI has no reading for: null, never a guess.
    expect(checkableSpec("PyPI", "1.2.3 - 1.4.0")).toBeNull();
  });

  it("add minimist >= 1.2.0, < 1.2.6: one row, dependency_check's avoid (it was unknown, review_needed)", async () => {
    const r = await brief("add minimist >= 1.2.0, < 1.2.6");
    expect(r.new_packages).toMatchObject([{ name: "minimist", version: ">=1.2.0,<1.2.6", verdict: "avoid" }]);
    expect(r.requested_versions).toMatchObject([{ name: "minimist", to: ">=1.2.0,<1.2.6", verdict: "avoid" }]);
    expect(r.summary).toContain("Task adds minimist >=1.2.0,<1.2.6 (avoid)");
    expect(r.summary).not.toContain("unknown");
    expect(r.summary).not.toContain("Task writes minimist");
    // 1.2.5, the newest release the range allows, has a critical advisory: the task writes it.
    expect(r.delegation_assessment.level).toBe("human_only");
  });

  it("a constraint one ecosystem cannot read no longer hides another package's malware", async () => {
    // The PyPI alternative of "1.2.3 - 1.4.0" made dependency_check refuse the whole batch: ctx was unknown.
    const r = await brief("add lodash-es 1.2.3 - 1.4.0 and ctx", MIXED_PY);
    expect(r.new_packages?.find((p) => p.name === "ctx")).toMatchObject({ malicious: true });
    expect(r.delegation_assessment.level).toBe("human_only");
  });
});

describe("2. a Cargo table entry is one package in one ecosystem", () => {
  const ENTRY = 'smallvec = { version = ">=1.6.0, <1.6.1" }';

  it.each([
    [`add ${ENTRY}`, RUST],
    [`add ${ENTRY}`, NPM_AND_RUST],
  ])("%s: both readers file it under crates.io", (task, deps) => {
    expect(added(task, deps)).toEqual(["crates.io:smallvec@>=1.6.0,<1.6.1"]);
    expect(requested(task, deps)).toEqual(["crates.io:smallvec@>=1.6.0,<1.6.1"]);
  });

  it("without a verb, the entry is still crates.io's, never npm's", () => {
    expect(requested(ENTRY, RUST)).toEqual(["crates.io:smallvec@>=1.6.0,<1.6.1"]);
    expect(requested(ENTRY, NPM_AND_RUST)).toEqual(["crates.io:smallvec@>=1.6.0,<1.6.1"]);
  });

  it("a Poetry entry in a Python project is PyPI's", () => {
    expect(requested('requests = { version = ">=2.19, <2.20" }', PY)).toEqual(["PyPI:requests@>=2.19,<2.20"]);
  });

  it("the briefing: one row, the same verdict in new_packages and requested_versions (they were avoid and unknown)", async () => {
    const r = await brief(`add ${ENTRY}`, NPM_AND_RUST);
    expect(r.new_packages).toMatchObject([{ name: "smallvec", ecosystem: "crates.io", verdict: "avoid" }]);
    expect(r.requested_versions).toMatchObject([{ name: "smallvec", ecosystem: "crates.io", verdict: "avoid" }]);
    expect(r.summary).toContain("Task adds smallvec >=1.6.0,<1.6.1 (avoid)");
    expect(r.summary).not.toContain("Task writes smallvec");
    expect(r.summary).not.toContain("unknown");
    expect(stub.asked.some((u) => u === "https://registry.npmjs.org/smallvec")).toBe(false);
  });
});

describe("3. name-version pairs with no verb are read, and each version stays with its own name", () => {
  it.each([
    "chalk 5.6.1/debug 4.4.2",
    "chalk 5.6.1 / debug 4.4.2",
    "chalk@5.6.1, debug@4.4.2",
    "bump chalk to 5.6.1 / debug to 4.4.2",
    "pin chalk 5.6.1 and debug 4.4.2",
    "chalk 5.6.1 + debug 4.4.2 in package.json",
  ])("%s: chalk 5.6.1 and debug 4.4.2", (task) => {
    expect(requested(task)).toEqual(["npm:chalk@5.6.1", "npm:debug@4.4.2"]);
  });

  it.each(["chalk 5.6.1/debug 4.4.2", "bump chalk to 5.6.1 / debug to 4.4.2", "chalk@5.6.1, debug@4.4.2", "pin chalk 5.6.1 and debug 4.4.2", "chalk 5.6.1 + debug 4.4.2 in package.json"])(
    "%s: both avoid, human_only",
    async (task) => {
      const r = await brief(task);
      expect(r.requested_versions?.map((v) => `${v.name}@${v.to}=${v.verdict}`)).toEqual(["chalk@5.6.1=avoid", "debug@4.4.2=avoid"]);
      expect(r.delegation_assessment.level).toBe("human_only");
    },
  );

  it("a name off the popular lists is not sent on a guess when nothing says it is a package", async () => {
    expect(requested("ship acme-billing 2.3.1, acme-auth 1.4.0")).toEqual([]);
    const r = await brief("ship acme-billing 2.3.1, acme-auth 1.4.0");
    expect(stub.asked.some((u) => u.includes("acme-"))).toBe(false);
    expect(r.delegation_assessment.level).toBe("review_needed");
  });

  it("an English word before `to` is still no package", () => {
    expect(requested("set the log level to debug")).toEqual([]);
    expect(readTaskVersions("update the docs to 2.0.1", NPM).unread).toEqual(["2.0.1"]);
  });
});

describe("4. a popular name that leads an add list is a package; English after the comma is not", () => {
  it.each([
    ["add debug, chalk and ms", ["npm:debug", "npm:chalk", "npm:ms"]],
    ["add debug, then wire it into the logger", ["npm:debug"]],
    ["add debug, it is tiny", ["npm:debug"]],
    ["add debug, express", ["npm:debug", "npm:express"]],
    ["add express, debug and ms", ["npm:express", "npm:debug", "npm:ms"]],
  ])("%s", (task, want) => {
    expect(added(task)).toEqual(want);
  });

  it.each([
    "add debug logging, then update the docs",
    "add debug output and tests",
    "add tests, debug and docs",
    "add debug mode to the app",
    "add async, error handling and retries",
    "add open, close and save buttons",
  ])("prose still names nothing: %s", (task) => {
    expect(added(task)).toEqual([]);
  });

  it("add debug, info and warn levels: debug leads an English list, so it is prose (the bare words after it stay weak, as before)", () => {
    expect(added("add debug, info and warn levels")).not.toContain("npm:debug");
    expect(detectAllNewPackages("add debug, info and warn levels", NPM).every((p) => p.weak)).toBe(true);
  });

  it("in a Python project debug is not npm's package", () => {
    expect(added("add debug, it is tiny", PY)).toEqual([]);
  });

  it("the briefing checks debug and reports it", async () => {
    const r = await brief("add debug, then wire it into the logger");
    expect(r.new_packages).toMatchObject([{ name: "debug", verdict: "proceed" }]);
    expect(r.summary).toContain("Task adds debug (proceed)");
  });

  it("add debug 4.4.2, it is tiny: the malicious release is human_only", async () => {
    const r = await brief("add debug 4.4.2, it is tiny");
    expect(r.delegation_assessment.level).toBe("human_only");
  });
});

describe("5. a loose name is looked up once", () => {
  it("use blueprints: one OSV.dev request for blueprints, and still nothing to report", async () => {
    // Re-check of the 2026-11-25 fixes, item 2: a word in prose nothing knows is not looked up at all; it is
    // held (withheld_from_task) and the task is review_needed. An install command's operand is looked up.
    const r = await brief("use blueprints");
    expect(osvAsks("blueprints")).toHaveLength(0);
    expect(stub.asked.some((u) => u.includes("/v1/vulns/GHSA-blueprints-old"))).toBe(false);
    expect(r.new_packages).toBeUndefined();
    expect(r.withheld_from_task).toMatchObject([{ shown: "blueprints" }]);
    expect(r.delegation_assessment.level).toBe("review_needed");
  });

  it("use pinguinlib: a malware name after `use` still stands, from one lookup", async () => {
    stub.npm.pinguinlib = { latest: "0.0.1-security", versions: ["0.0.1-security"] };
    stub.osv.push(advisory("MAL-2026-pinguinlib", "pinguinlib", "CRITICAL", {}, "npm", true));
    // Re-check of the 2026-11-25 fixes, item 2: a word in prose nothing knows is not looked up at all; it is
    // held (withheld_from_task) and the task is review_needed. An install command's operand is looked up.
    const r = await brief("use pinguinlib");
    expect(r.new_packages).toBeUndefined();
    expect(r.delegation_assessment.level).toBe("review_needed");
    expect(osvAsks("pinguinlib")).toHaveLength(0);
    const cmd = await brief("npm install pinguinlib");
    expect(cmd.new_packages).toMatchObject([{ name: "pinguinlib", malicious: true, verdict: "avoid" }]);
    expect(cmd.delegation_assessment.level).toBe("human_only");
  });

  // Near-misses of popular names are never loose: they get the full check, name_check included.
  it.each(["use crossenv", "use lodahs"])("%s: still human_only", async (task) => {
    const name = task.split(" ")[1];
    const r = await brief(task);
    expect(r.new_packages?.find((p) => p.name === name)).toMatchObject({ malicious: true, verdict: "avoid" });
    expect(r.delegation_assessment.level).toBe("human_only");
  });

  it("a loose name whose advisories could not be read is unknown, never clean", async () => {
    const real = globalThis.fetch;
    vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => (String(input).startsWith("https://api.osv.dev/") ? new Response("busy", { status: 503 }) : real(input, init)));
    const r = await brief("npm install blueprints");
    expect(r.new_packages).toMatchObject([{ name: "blueprints", verdict: "unknown" }]);
    expect(r.delegation_assessment.level).toBe("review_needed");
  });

  it("a name nobody publishes after `use` is prose (use memoizers)", async () => {
    // Re-check of the 2026-11-25 fixes, item 2: a word in prose nothing knows is not looked up at all; it is
    // held (withheld_from_task) and the task is review_needed. An install command's operand is looked up.
    const r = await brief("use memoizers");
    expect(r.new_packages).toBeUndefined();
    expect(r.withheld_from_task).toMatchObject([{ shown: "memoizers" }]);
    expect(r.delegation_assessment.level).toBe("review_needed");
  });
});
