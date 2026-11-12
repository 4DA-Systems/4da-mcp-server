// SPDX-License-Identifier: Apache-2.0
/** The PEP 508, poetry-constraint and uv.lock readers behind the Python fix paths, and the release-line label (fix-advice-truth.test.ts). */

import { describe, expect, it } from "vitest";
import { lineLabel } from "../live/fix-paths.js";
import { lowestPython, parsePep508, poetryToPep440, pythonSpecAdmits, requirementsOn, requirementsOnGated, uvManifestNames } from "../live/pygo-parents.js";

describe("pygo-parents readers", () => {
  it("the PEP 508 and poetry readers", () => {
    expect(parsePep508("idna (<3,>=2.5)")).toEqual({ name: "idna", spec: "<3,>=2.5", extra: false, marker: false });
    expect(parsePep508("PySocks (!=1.5.7,>=1.5.6) ; extra == 'socks'")).toEqual({ name: "pysocks", spec: "!=1.5.7,>=1.5.6", extra: true, marker: false });
    expect(parsePep508('idna<3 ; python_version < "3.8"')).toEqual({ name: "idna", spec: "<3", extra: false, marker: true });
    expect(parsePep508("pkg @ https://example.com/x.whl")).toBeNull();
    expect(requirementsOn(["certifi>=2017.4.17", "certifi>=2020 ; extra == 'x'"], "certifi")).toEqual([">=2017.4.17"]);
    expect(requirementsOnGated(['idna<3 ; python_version < "3.8"', 'idna<4 ; python_version >= "3.8"'], "idna")).toEqual({ specs: ["<3", "<4"], gated: true });
    expect(requirementsOnGated(["idna<4"], "idna")).toEqual({ specs: ["<4"], gated: false });
    expect(poetryToPep440("^3.8")).toBe(">=3.8.0,<4.0");
    expect(poetryToPep440("~1.2")).toBe(">=1.2.0,<1.3");
    expect(poetryToPep440("*")).toBe("");
    expect(poetryToPep440(">=2.5,<3")).toBe(">=2.5,<3");
    expect(poetryToPep440("1.2.3")).toBe("==1.2.3");
    expect(poetryToPep440("^0.2.1")).toBe(">=0.2.1,<0.3");
    expect(poetryToPep440("weird")).toBeNull();
    expect(lowestPython(">=3.8,<4")).toBe("3.8");
    expect(lowestPython(">=3.8.0,<4.0")).toBe("3.8.0");
    expect(lowestPython(null)).toBeNull();
    expect(pythonSpecAdmits("", "1.0")).toBe(true);
    expect(pythonSpecAdmits(">=3.10", "3.8")).toBe(false);
    expect(pythonSpecAdmits("(<3,>=2.5)", "2.10")).toBe(true);
  });

  it("uv.lock [manifest] constraints and overrides, single-line and multi-line", () => {
    const lock = [
      'version = 1\nrequires-python = ">=3.8"\n',
      '[manifest]\nconstraints = [{ name = "certifi", specifier = "<2023" }]\noverrides = [\n    { name = "Idna", specifier = "==2.10" },\n]\n',
      '[[package]]\nname = "requests"\nversion = "2.25.0"\ndependencies = [\n    { name = "urllib3" },\n]\n',
    ].join("\n");
    expect([...uvManifestNames(lock)].sort()).toEqual(["certifi", "idna"]);
    expect(uvManifestNames('version = 1\n\n[[package]]\nname = "x"\n').size).toBe(0);
  });

  it("a calendar or epoch version has no release line to call dead", () => {
    expect(lineLabel("8.5.1")).toBe("8.x");
    expect(lineLabel("0.21.1")).toBe("0.21.x");
    expect(lineLabel("0.0.3")).toBeNull();
    expect(lineLabel("2020.12.5")).toBeNull();
    expect(lineLabel("1!2.0")).toBeNull();
  });
});
