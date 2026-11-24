// SPDX-License-Identifier: Apache-2.0
/**
 * An npm option before the subcommand takes the value npm's own parser gives it, so the install
 * after it is still read.
 *
 * Independent re-check of 0d30b40 (S6): npm options that take a value were read as switches, so
 * their value was taken for the subcommand and `npm --proxy http://p:8080 install x@1` went ahead
 * unread; 31 such options, and their abbreviations (`--prefi`, npm resolves any unique prefix).
 * The value-taking set is npm 10.9's own (@npmcli/config definitions, asked of nopt with npm's types
 * and shorthands: an option takes the next word when nopt leaves `install` as the command); an
 * option still unknown before the subcommand makes the reader look for the install subcommand in
 * the words after it rather than guess. `cargo -C <dir> add` the same.
 */

import { describe, expect, it } from "vitest";

import { installsIn } from "../../hooks/manifest-edit.mjs";

const read = (command: string, dialect: "bash" | "powershell" = "bash") => installsIn(command, dialect).map((r) => `${r.name}@${r.spec}`);

describe("npm options that take a value, before the subcommand", () => {
  it.each([
    "--proxy http://p:8080",
    "--https-proxy http://p:8080",
    "--cafile ca.pem",
    "--ca cert",
    "--cert c.pem",
    "--key k.pem",
    "--cpu x64",
    "--os linux",
    "--libc glibc",
    "--color always",
    "--maxsockets 4",
    "--fetch-retry-mintimeout 1000",
    "--depth 2",
    "--lockfile-version 3",
    "--logs-dir logs",
    "--umask 022",
    "--user-agent ua",
    "--local-address 127.0.0.1",
    "--noproxy example.com",
    "--heading npm",
    "--editor vi",
    "--shell bash",
    "--viewer man",
    "--node-gyp gyp",
    "--preid beta",
    "--sbom-format spdx",
    "--tag-version-prefix v",
    "--init-module init.js",
    "--searchopts x",
    "--replace-registry-host never",
    "--prefi ../b",
    "--pref ../b",
    "--loglev silent",
    "-C ../b",
    "-L project",
  ])("npm %s install lodash@4.17.20", (option) => {
    expect(read(`npm ${option} install lodash@4.17.20`)).toEqual(["lodash@4.17.20"]);
  });

  it("the same with --option=value, and from PowerShell", () => {
    expect(read("npm --proxy=http://p:8080 install lodash@4.17.20")).toEqual(["lodash@4.17.20"]);
    expect(read("npm --prefi ../b i lodash@4.17.20", "powershell")).toEqual(["lodash@4.17.20"]);
  });

  it("an option npm does not know is not guessed at: the install after it is still read", () => {
    expect(read("npm --no-such-option whatever install lodash@4.17.20")).toEqual(["lodash@4.17.20"]);
    expect(read("npm --no-such-option install lodash@4.17.20")).toEqual(["lodash@4.17.20"]);
  });

  it("switches stay switches", () => {
    expect(read("npm --color install lodash@4.17.20")).toEqual(["lodash@4.17.20"]);
    expect(read("npm --no-audit install lodash@4.17.20")).toEqual(["lodash@4.17.20"]);
    expect(read("npm -g install lodash@4.17.20")).toEqual(["lodash@4.17.20"]);
  });

  it("a word that is not an install is not made one", () => {
    expect(read("npm --proxy http://p:8080 run install")).toEqual([]);
    expect(read("npm --tag install view lodash@4.17.20")).toEqual([]);
  });
});

describe("cargo -C <dir> before the subcommand", () => {
  it("cargo -C ../b add serde@1.0.100", () => {
    expect(read("cargo -C ../b add serde@1.0.100")).toEqual(["serde@1.0.100"]);
  });
});
