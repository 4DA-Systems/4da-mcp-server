// SPDX-License-Identifier: Apache-2.0
/**
 * An override key with a version range that holds `>` names the package before the `@`. Re-check of
 * 0d30b40 (2026-11-24, projects-b/ovr-b, ovr-yaml): overrideKeyName cut every key at its last `>`,
 * so `"zqrev-o10@>=1.0.0 <2": "file:./v/o10"` (npm `overrides`) and `zqrev-o11@>=1 <2: link:./v/o11`
 * (pnpm-workspace.yaml) named "=1.0.0 <2" and "=1 <2", and the local override was sent. npm has no
 * `>` selector; in pnpm `parent>child` is one, but a `>` that begins or sits inside a range is not.
 */

import { describe, expect, it } from "vitest";
import { allOverrideSpecs, overrideKeyName } from "../live/overrides.js";

describe("override keys by format", () => {
  it("npm and Yarn keys never split at >", () => {
    expect(overrideKeyName("acme-o10@>=1.0.0 <2", "npm")).toBe("acme-o10");
    expect(overrideKeyName("acme-o10@>1", "yarn")).toBe("acme-o10");
    expect(overrideKeyName("**/@s/x@>=1", "yarn")).toBe("@s/x");
  });
  it("pnpm splits at a parent selector only", () => {
    expect(overrideKeyName("acme-o11@>=1 <2", "pnpm")).toBe("acme-o11");
    expect(overrideKeyName("foo>acme-o2", "pnpm")).toBe("acme-o2");
    expect(overrideKeyName("foo@1>acme-o2@>=2", "pnpm")).toBe("acme-o2");
    expect(overrideKeyName("foo@>1>acme-o2", "pnpm")).toBe("acme-o2");
    expect(overrideKeyName("acme-o3@^1", "pnpm")).toBe("acme-o3");
  });
  it("the tables are read with their own format", () => {
    const specs = allOverrideSpecs({ overrides: { "acme-o10@>=1.0.0 <2": "file:./v/o10" }, pnpm: { overrides: { "a@1>acme-o2": "link:./v/o2" } }, resolutions: { "acme-o7@>1": "file:./v/o7" } }, "overrides:\n  acme-o11@>=1 <2: link:./v/o11\n");
    expect(specs.map((s) => s.name).sort()).toEqual(["acme-o10", "acme-o11", "acme-o2", "acme-o7"]);
  });
});
