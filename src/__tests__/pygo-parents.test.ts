// SPDX-License-Identifier: Apache-2.0
/** The PEP 508, poetry-constraint and go.mod readers behind the Python and Go fix paths (fix-advice-truth.test.ts). */

import { describe, expect, it } from "vitest";
import { lowestPython, parsePep508, poetryToPep440, pythonSpecAdmits, requirementsOn } from "../live/pygo-parents.js";

describe("pygo-parents readers", () => {
  it("the PEP 508 and poetry readers", () => {
    expect(parsePep508("idna (<3,>=2.5)")).toEqual({ name: "idna", spec: "<3,>=2.5", extra: false });
    expect(parsePep508("PySocks (!=1.5.7,>=1.5.6) ; extra == 'socks'")).toEqual({ name: "pysocks", spec: "!=1.5.7,>=1.5.6", extra: true });
    expect(parsePep508("pkg @ https://example.com/x.whl")).toBeNull();
    expect(requirementsOn(["certifi>=2017.4.17", "certifi>=2020 ; extra == 'x'"], "certifi")).toEqual([">=2017.4.17"]);
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
});
