// SPDX-License-Identifier: Apache-2.0
/**
 * A Python dependency installed from a local path, git or a URL is not the PyPI release of its name
 * and is never looked up by that name, whatever host the git or URL names.
 *
 * Privacy review of the 6.5.1 candidate (2026-11-24, projects/py-req): `-e ./libs/x`, `./libs/x`, a
 * local wheel file and `-e ../path` inside an `-r` include were looked up on pypi.org and OSV when
 * dependency_check, upgrade_impact or a briefing named them, and a bare URL line in requirements.txt
 * was read as a package named `https` (pypi.org/pypi/https/json and an HN query). Claims review
 * (projects/eco-py, eco-uv, eco-uvlock): `requests @ git+https://github.com/psf/requests@v2.31.0`,
 * a `[tool.uv.sources]` git entry and a uv.lock git source made a registry row and sent the name to
 * pypi.org and HN, because a git source on a public code host was taken for a public release.
 * Stubbed fetch: nothing leaves the machine.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { executeDependencyHealth } from "../tools/dependency-health.js";
import { executeDependencyCheck } from "../tools/dependency-check.js";
import { executeEcosystemPulse } from "../tools/ecosystem-pulse.js";
import { executeUpgradeImpact } from "../tools/upgrade-impact.js";
import { executeWhatShouldIKnow } from "../tools/what-should-i-know.js";
import { parseRequirementNames } from "../project-manifests.js";
import { createHarness, type Harness } from "./helpers/a1119-planner-harness.js";

let h: Harness;
let bodies: string[];
const INVENTED = /acme/i;
const sent = () => [...h.requests, ...bodies].map((s) => decodeURIComponent(s));
const leaked = () => sent().filter((s) => INVENTED.test(s));
const pypiAsked = (name: string) => sent().filter((s) => s.includes(`pypi.org/pypi/${name}/`) || s.includes(`"name":"${name}","ecosystem":"PyPI"`));

beforeEach(() => {
  h = createHarness();
  bodies = [];
  const inner = globalThis.fetch;
  vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
    if (init?.body) bodies.push(String(init.body));
    return inner(input, init);
  });
  h.PYPI = { idna: { "3.7": {} } };
});
afterEach(() => h.dispose());

describe("requirements.txt local paths and URL lines", () => {
  it("a URL or a path line is no requirement name", () => {
    expect(parseRequirementNames("https://files.acme.example/acme_bareurl-1.0.tar.gz\nvendor/acme_whl-1.0-py3-none-any.whl\n./libs/acme-dir\nidna==3.7\n")).toEqual(["idna"]);
  });

  it("asked directly, a local path, editable, wheel or include-local name is withheld; https is never a package", async () => {
    h.write(
      "requirements.txt",
      [
        "idna==3.7",
        "-e ./libs/acme-editable",
        "./libs/acme-localdir",
        "./dist/acme_wheelfile-2.0.0-py3-none-any.whl",
        "https://files.acme.example/acme_bareurl-1.0.tar.gz",
        "-r more-requirements.txt",
        "",
      ].join("\n"),
    );
    h.write("more-requirements.txt", "-e ../acme-included\n");
    await executeDependencyHealth(null, {}, await h.live());
    await h.plan();
    const live = await h.live();
    await executeEcosystemPulse(null, {}, live);
    const names = ["acme-editable", "acme-localdir", "acme-wheelfile", "acme-bareurl", "acme-included"];
    await executeDependencyCheck(null, { items: names.map((p) => ({ ecosystem: "PyPI", package: p, to: "1.0.1" })) }, live);
    await executeUpgradeImpact(null, { package: "acme-editable", to_version: "2.0.0", ecosystem: "PyPI" }, live);
    await executeWhatShouldIKnow(null, { task: "upgrade acme-localdir and acme-wheelfile", project_path: h.dir }, live);
    expect(leaked()).toEqual([]);
    expect(pypiAsked("https")).toEqual([]);
  });
});

describe("a git source on a public code host is not a PyPI release", () => {
  it("requirements.txt `name @ git+https://github.com/...`", async () => {
    h.write("requirements.txt", "idna==3.7\nrequests @ git+https://github.com/psf/requests@v2.31.0\n");
    const r = (await executeDependencyHealth(null, {}, await h.live())) as unknown as Record<string, any>;
    await h.plan();
    await executeEcosystemPulse(null, {}, await h.live());
    expect(pypiAsked("requests")).toEqual([]);
    expect(r.dependencies.map((d: { name: string }) => d.name)).not.toContain("requests");
  });

  it("pyproject.toml [tool.uv.sources] git, with and without a uv.lock git source", async () => {
    h.write("pyproject.toml", '[project]\nname = "app"\nversion = "0.1.0"\ndependencies = ["requests", "idna==3.7"]\n\n[tool.uv.sources]\nrequests = { git = "https://github.com/psf/requests", tag = "v2.31.0" }\n');
    await executeDependencyHealth(null, {}, await h.live());
    expect(pypiAsked("requests")).toEqual([]);
    h.write(
      "uv.lock",
      'version = 1\nrequires-python = ">=3.10"\n\n[[package]]\nname = "app"\nversion = "0.1.0"\nsource = { virtual = "." }\ndependencies = [{ name = "requests" }, { name = "idna" }]\n\n[[package]]\nname = "idna"\nversion = "3.7"\nsource = { registry = "https://pypi.org/simple" }\n\n[[package]]\nname = "requests"\nversion = "2.31.0"\nsource = { git = "https://github.com/psf/requests?tag=v2.31.0#0123456789abcdef0123456789abcdef01234567" }\n',
    );
    await executeDependencyHealth(null, {}, await h.live());
    await h.plan();
    expect(pypiAsked("requests")).toEqual([]);
  });
});
