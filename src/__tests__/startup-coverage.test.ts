// SPDX-License-Identifier: Apache-2.0
/**
 * Coverage notes when the server is STARTED INSIDE the project (readiness
 * audit H3, 2026-10-16). The startup walk's report (pom.xml / build.gradle
 * not covered, test-fixture lockfiles not scanned) was kept only when a
 * supported lockfile was found, so in spring-petclinic vulnerability_scan
 * said "none of an unsupported one either" and dependency_health "No
 * project manifests detected", while the same project passed as
 * project_path from elsewhere was correctly NOT COVERED.
 *
 * Runs dist/ (CI builds before testing); skipped when there is no build.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { resultText, serverEntry, stdioSession } from "./helpers/stdio-session.js";

let scratch: string;
const write = (rel: string, content: string) => {
  fs.mkdirSync(path.dirname(path.join(scratch, rel)), { recursive: true });
  fs.writeFileSync(path.join(scratch, rel), content);
};

const CALLS: Array<[string, Record<string, unknown>]> = [
  ["vulnerability_scan", {}],
  ["dependency_health", {}],
];

describe.skipIf(!fs.existsSync(serverEntry))("coverage notes when the server starts in the project", () => {
  beforeAll(() => {
    scratch = fs.mkdtempSync(path.join(os.tmpdir(), "4da-startup-cov-"));
    write("maven/pom.xml", "<project/>");
    write("maven/build.gradle", "");
    write("fixtures-only/test/app/package.json", JSON.stringify({ name: "app", dependencies: { lodash: "4.17.20" } }));
    write(
      "fixtures-only/test/app/package-lock.json",
      JSON.stringify({ name: "app", lockfileVersion: 3, packages: { "": { name: "app" }, "node_modules/lodash": { version: "4.17.20" } } }),
    );
  });

  afterAll(() => {
    fs.rmSync(scratch, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
  });

  it("a Maven project: every tool says NOT COVERED and names pom.xml and build.gradle", async () => {
    const { results } = await stdioSession(path.join(scratch, "maven"), CALLS);
    for (const r of results) {
      const t = resultText(r);
      expect(t).toMatch(/NOT COVERED/);
      expect(t).toMatch(/pom\.xml/);
      expect(t).toMatch(/build\.gradle/);
      expect(t).not.toMatch(/none of an unsupported one either/);
      expect(t).not.toMatch(/No project manifests detected/);
    }
    const health = JSON.parse(resultText(results[1])) as { healthScore: unknown; vulnerableCount: unknown };
    expect(health.healthScore).toBeNull();
    expect(health.vulnerableCount).toBeNull();
  }, 60_000);

  it("only test-fixture lockfiles: every tool says they were not scanned", async () => {
    const { results } = await stdioSession(path.join(scratch, "fixtures-only"), CALLS);
    for (const r of results) {
      const t = resultText(r);
      expect(t).toMatch(/test-fixture lockfile/);
      expect(t).toMatch(/include_test_fixtures/);
      expect(t).not.toMatch(/none of an unsupported one either/);
    }
  }, 60_000);
});

/** Readiness audit L6: the same, through the built server. */
describe.skipIf(!fs.existsSync(serverEntry))("resources/list and the startup line, through the built server (L6)", () => {
  it("standalone: resources/list has no desktop-only tool schema", async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "4da-l6-"));
    try {
      const { resources, tools } = await stdioSession(dir, []);
      const schemas = resources.map((r) => r.uri).filter((u) => u.startsWith("4da://schema/"));
      expect(schemas.sort()).toEqual(tools.map((t) => `4da://schema/${t}`).sort());
      expect(schemas).not.toContain("4da://schema/knowledge_gaps");
    } finally {
      fs.rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
    }
  }, 60_000);

  it("a refused database: the startup line does not claim 16 working tools", async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "4da-l6-"));
    try {
      const { stderr, results } = await stdioSession(dir, [["get_context", {}]], { FOURDA_DB_PATH: "./data/missing.db" });
      expect(resultText(results[0])).toMatch(/FOURDA_DB_PATH/);
      expect(stderr).not.toMatch(/started — 16 tools,/);
      expect(stderr).toMatch(/no tool can run until the database problem above is fixed/);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
    }
  }, 60_000);
});