// SPDX-License-Identifier: Apache-2.0
/**
 * A Go module remembered as private in lower case is recognised in any case. Module paths are
 * matched as their hosts match them (GitHub-style hosts ignore case), so `git.zq.example/ZqTeam/Core`
 * names the private `git.zq.example/zqteam/core`: the guard refuses it at the module proxy, under a
 * package path, and in free text bound for an embedding provider. Nothing leaves the process: fetch
 * is a spy that answers nothing.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fetchWithTimeout } from "../live/http-utils.js";
import { PrivateRequestRefused, privateNameInText, rememberedPrivate, rememberPrivateName } from "../live/private-guard.js";

const MODULE = "git.zq.example/zqteam/core";
let fetchSpy: ReturnType<typeof vi.fn>;

beforeEach(() => {
  fetchSpy = vi.fn(async () => new Response("{}"));
  vi.stubGlobal("fetch", fetchSpy);
  rememberPrivateName("Go", MODULE, "GOPRIVATE covers git.zq.example");
});
afterEach(() => vi.unstubAllGlobals());

describe("a Go module remembered private in lower case, asked in mixed case", () => {
  it("the module proxy request (capitals escaped as `!x`) is refused and never made", async () => {
    for (const url of [
      "https://proxy.golang.org/git.zq.example/!zq!team/!core/@v/list",
      "https://proxy.golang.org/git.zq.example/!zq!team/!core/@v/v1.2.0.info",
      "https://proxy.golang.org/git.zq.example/!z!q!t!e!a!m/!c!o!r!e/@latest",
    ]) {
      await expect(fetchWithTimeout(url), url).rejects.toBeInstanceOf(PrivateRequestRefused);
    }
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("an OSV.dev query naming it in mixed case is refused", async () => {
    const body = JSON.stringify({ queries: [{ package: { name: "git.zq.example/ZqTeam/Core", ecosystem: "Go" }, version: "v1.2.0" }] });
    await expect(fetchWithTimeout("https://api.osv.dev/v1/querybatch", { method: "POST", body })).rejects.toBeInstanceOf(PrivateRequestRefused);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("a package path under it, and free text naming it, are recognised", () => {
    expect(rememberedPrivate("git.zq.example/ZqTeam/Core")?.ecosystem).toBe("Go");
    expect(rememberedPrivate("git.zq.example/ZqTeam/Core/internal/ledger")?.why).toMatch(/a package of git\.zq\.example\/zqteam\/core/);
    expect(privateNameInText("upgrade git.zq.example/ZqTeam/Core to v1.3.0")?.name).toBe("git.zq.example/ZqTeam/Core");
  });

  it("control: a public module in mixed case is asked about", async () => {
    await fetchWithTimeout("https://proxy.golang.org/github.com/!azure/azure-sdk-for-go/@v/list");
    expect(fetchSpy).toHaveBeenCalledTimes(1);
  });
});
