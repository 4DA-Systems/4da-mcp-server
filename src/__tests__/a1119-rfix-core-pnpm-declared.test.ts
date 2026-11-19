// SPDX-License-Identifier: Apache-2.0
/**
 * A healthy pnpm-lock.yaml is not called partial for what pnpm legitimately
 * leaves out of the root importer: an optional dependency named in
 * `ignoredOptionalDependencies`, and a workspace member linked under
 * `excludeLinksFromLockfile: true`. Both lockfiles below are what pnpm 10.34.6
 * wrote (`pnpm install --lockfile-only --ignore-scripts`) for these manifests.
 */
import { afterEach, describe, expect, it } from "vitest";
import { resolveVersionSource } from "../live/lockfile-parsers.js";
import { removeProject, tempProject } from "./helpers/a1119-readers.js";

const MS = `packages:

  ms@2.1.3:
    resolution: {integrity: sha512-6FlzubTLZG3J2a/NVCAleEhjzq5oxgHyaCU9yYXvcLsvoVaHJq/s5xXI6/XXP6tz7R9xAOtHnSO/tXtF3WRTlA==}
`;
const IGNORED_LOCK = `lockfileVersion: '9.0'

settings:
  autoInstallPeers: true
  excludeLinksFromLockfile: false

importers:

  .:
    dependencies:
      ms:
        specifier: 2.1.3
        version: 2.1.3

${MS}
ignoredOptionalDependencies:
  - fsevents

snapshots:

  ms@2.1.3: {}
`;
const LINKS_LOCK = `lockfileVersion: '9.0'

settings:
  autoInstallPeers: true
  excludeLinksFromLockfile: true

importers:

  .:
    dependencies:
      ms:
        specifier: 2.1.3
        version: 2.1.3

  packages/ws-b: {}

${MS}
snapshots:

  ms@2.1.3: {}
`;

describe("pnpm: what pnpm leaves out of the importer is not damage", () => {
  const dirs: string[] = [];
  const problems = (files: Record<string, string>) => {
    const dir = tempProject(files);
    dirs.push(dir);
    return resolveVersionSource(dir, "npm").problems ?? [];
  };
  afterEach(() => dirs.splice(0).forEach(removeProject));
  const withFsevents = { name: "app", version: "1.0.0", dependencies: { ms: "2.1.3" }, optionalDependencies: { fsevents: "2.3.3" } };

  it("an optional dependency package.json's pnpm.ignoredOptionalDependencies names", () => {
    const pkg = JSON.stringify({ ...withFsevents, pnpm: { ignoredOptionalDependencies: ["fsevents"] } });
    expect(problems({ "package.json": pkg, "pnpm-lock.yaml": IGNORED_LOCK })).toEqual([]);
  });

  it("an optional dependency pnpm-workspace.yaml's ignoredOptionalDependencies names", () => {
    const lock = IGNORED_LOCK.replace("ignoredOptionalDependencies:\n  - fsevents\n", "");
    expect(problems({ "package.json": JSON.stringify(withFsevents), "pnpm-workspace.yaml": "ignoredOptionalDependencies:\n  - fsevents\n", "pnpm-lock.yaml": lock })).toEqual([]);
  });

  it("still reports an optional dependency nothing ignores", () => {
    const lock = IGNORED_LOCK.replace("ignoredOptionalDependencies:\n  - fsevents\n", "");
    const found = problems({ "package.json": JSON.stringify(withFsevents), "pnpm-lock.yaml": lock });
    expect(found).toHaveLength(1);
    expect(found[0].error).toMatch(/package\.json declares fsevents \(optionalDependencies\)/);
  });

  it("a workspace member declared by a plain range, under excludeLinksFromLockfile", () => {
    const files = {
      "package.json": JSON.stringify({ name: "app", version: "1.0.0", dependencies: { ms: "2.1.3", "ws-b": "^1.0.0" } }),
      "packages/ws-b/package.json": JSON.stringify({ name: "ws-b", version: "1.0.0" }),
      "pnpm-workspace.yaml": "packages:\n  - 'packages/*'\nexcludeLinksFromLockfile: true\nlinkWorkspacePackages: true\n",
      "pnpm-lock.yaml": LINKS_LOCK,
    };
    expect(problems(files)).toEqual([]);
    // The same declaration with no member of that name is still a missing entry.
    const notMember = { ...files, "packages/ws-b/package.json": JSON.stringify({ name: "other", version: "1.0.0" }) };
    expect(problems(notMember)[0]?.error).toMatch(/package\.json declares ws-b \(dependencies\)/);
  });
});
