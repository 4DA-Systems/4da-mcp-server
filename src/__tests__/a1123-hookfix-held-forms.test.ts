// SPDX-License-Identifier: Apache-2.0
/**
 * Version forms the README says the guard holds are held: the same name in two sections (each
 * section's change judged on its own, where the later section used to mask the earlier), npm
 * nested `overrides`, Yarn `resolutions` keyed by a glob or a parent path, pnpm's `parent>child`
 * overrides, Cargo dotted keys and quoted names. A dependency moved between sections at the same
 * version introduces nothing.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { sandbox, type Sandbox } from "./helpers/a1123-hookfix-run.js";

const PKG = '{\n  "name": "app",\n  "dependencies": {\n    "left-pad": "1.3.0"\n  },\n  "devDependencies": {\n    "typescript": "5.6.3"\n  }\n}\n';
const DEV_PEER = '{\n  "name": "lib",\n  "devDependencies": {\n    "react": "18.2.0"\n  },\n  "peerDependencies": {\n    "react": ">=17"\n  }\n}\n';
const CARGO = '[package]\nname = "demo"\nversion = "0.1.0"\n\n[dependencies]\nanyhow = "1.0.89"\n';
const CARGO_TWICE = '[package]\nname = "demo"\nversion = "0.1.0"\n\n[dependencies]\ntokio = "1.40.0"\n\n[dev-dependencies]\ntokio = { version = "1.40.0", features = ["full"] }\n';

let s: Sandbox;
beforeEach(() => {
  s = sandbox();
});
afterEach(() => s.dispose());

const overridesEdit = (block: string) => ['"devDependencies": {', `${block},\n  "devDependencies": {`] as const;

describe("the same name in two sections", () => {
  it("package.json: a devDependencies pin beside a peerDependencies range", () => {
    const file = s.file("package.json", DEV_PEER);
    expect(s.edit(file, '"react": "18.2.0"', '"react": "18.3.0"').items).toEqual([{ ecosystem: "npm", package: "react", to: "18.3.0", from: "18.2.0" }]);
  });

  it("package.json: the earlier section changed while the later one is unchanged, either order", () => {
    const file = s.file("package.json", DEV_PEER.replace('"devDependencies"', '"x"').replace('"peerDependencies"', '"devDependencies"').replace('"x"', '"peerDependencies"'));
    expect(s.edit(file, '"react": ">=17"', '"react": "18.3.0"').items).toEqual([{ ecosystem: "npm", package: "react", to: "18.3.0" }]);
  });

  it("Cargo.toml: [dependencies] beside [dev-dependencies]", () => {
    const file = s.file("Cargo.toml", CARGO_TWICE);
    expect(s.edit(file, 'tokio = "1.40.0"', 'tokio = "1.41.0"').items).toEqual([{ ecosystem: "crates.io", package: "tokio", to: "1.41.0", from: "1.40.0" }]);
    expect(s.edit(file, 'tokio = { version = "1.40.0"', 'tokio = { version = "1.41.0"').items).toEqual([{ ecosystem: "crates.io", package: "tokio", to: "1.41.0", from: "1.40.0" }]);
  });

  it("Cargo.toml: two target tables", () => {
    const file = s.file("Cargo.toml", CARGO + "\n[target.'cfg(windows)'.dependencies]\nwinapi = \"0.3.8\"\n\n[target.'cfg(unix)'.dependencies]\nwinapi = \"0.3.9\"\n");
    expect(s.edit(file, 'winapi = "0.3.8"', 'winapi = "0.3.7"').items).toEqual([{ ecosystem: "crates.io", package: "winapi", to: "0.3.7", from: "0.3.8" }]);
  });

  it("a dependency moved to another section at the same version is judged in its new section (round 23, W1)", () => {
    const file = s.file("package.json", PKG);
    const run = s.write(file, '{\n  "name": "app",\n  "dependencies": {},\n  "devDependencies": {\n    "left-pad": "1.3.0",\n    "typescript": "5.6.3"\n  }\n}\n');
    expect(run.decision, run.text).toBe("deny");
    expect(run.items).toEqual([{ ecosystem: "npm", package: "left-pad", to: "1.3.0", from: "1.3.0" }]);
    const cargo = s.file("Cargo.toml", CARGO);
    expect(s.edit(cargo, 'anyhow = "1.0.89"\n', '\n[dev-dependencies]\nanyhow = "1.0.89"\n').decision).toBe("deny");
  });
});

describe("npm overrides, pnpm overrides and Yarn resolutions", () => {
  it.each([
    ["nested override", '"overrides": {\n    "foo": {\n      "semver": "7.6.3"\n    }\n  }', "semver"],
    ["an override two levels down", '"overrides": {\n    "a": {\n      "b": {\n        "semver": "7.6.3"\n      }\n    }\n  }', "semver"],
    ['the "." key of a nested override sets the parent', '"overrides": {\n    "semver": {\n      ".": "7.6.3",\n      "lru-cache": "10.4.3"\n    }\n  }', "semver,lru-cache"],
    ["an override with a selector key", '"overrides": {\n    "semver@<7": "7.6.3"\n  }', "semver"],
    ["a flat override", '"overrides": {\n    "semver": "7.6.3"\n  }', "semver"],
    ["Yarn resolution with a glob", '"resolutions": {\n    "**/semver": "7.6.3"\n  }', "semver"],
    ["Yarn resolution under a parent", '"resolutions": {\n    "parent/semver": "7.6.3"\n  }', "semver"],
    ["Yarn resolution of a scoped child", '"resolutions": {\n    "parent/@types/node": "22.7.5"\n  }', "@types/node"],
    ["Yarn resolution of a scoped package", '"resolutions": {\n    "@types/node": "22.7.5"\n  }', "@types/node"],
    ["pnpm override parent>child", '"pnpm": {\n    "overrides": {\n      "foo>semver": "7.6.3"\n    }\n  }', "semver"],
  ])("%s", (_label, block, names) => {
    const file = s.file("package.json", PKG);
    const run = s.edit(file, ...overridesEdit(block));
    expect(run.items?.map((i) => i.package)).toEqual(names.split(","));
  });

  it("an override that refers to a dependency ($name) or names a glob is not read", () => {
    const file = s.file("package.json", PKG);
    expect(s.edit(file, ...overridesEdit('"overrides": {\n    "left-pad": "$left-pad"\n  }')).decision).toBe("allow");
    expect(s.edit(file, ...overridesEdit('"resolutions": {\n    "semver*": "7.6.3"\n  }')).decision).toBe("allow");
  });

  it("a nested override bump is held with its old version", () => {
    const file = s.file("package.json", PKG.replace('  "devDependencies"', '  "overrides": {\n    "foo": {\n      "semver": "7.6.2"\n    }\n  },\n  "devDependencies"'));
    expect(s.edit(file, '"semver": "7.6.2"', '"semver": "7.6.3"').items).toEqual([{ ecosystem: "npm", package: "semver", to: "7.6.3", from: "7.6.2" }]);
  });
});

describe("Cargo dotted keys and quoted names", () => {
  it.each([
    ["a dotted version key", 'git2.version = "0.19.0"', "git2"],
    ["a dotted key with features", 'git2.version = "0.19.0"\ngit2.default-features = false', "git2"],
    ["a quoted name", '"serde_yaml" = "0.9.34"', "serde_yaml"],
    ["a quoted name, inline table", "'serde_yaml' = { version = \"0.9.34\" }", "serde_yaml"],
  ])("%s", (_label, line, name) => {
    const file = s.file("Cargo.toml", CARGO);
    expect(s.edit(file, 'anyhow = "1.0.89"\n', `anyhow = "1.0.89"\n${line}\n`).items?.map((i) => i.package)).toEqual([name]);
  });

  it("a quoted table name: [dependencies.\"serde_yaml\"]", () => {
    const file = s.file("Cargo.toml", CARGO);
    expect(s.edit(file, 'anyhow = "1.0.89"\n', 'anyhow = "1.0.89"\n\n[dependencies."serde_yaml"]\nversion = "0.9.34"\n').items?.map((i) => i.package)).toEqual(["serde_yaml"]);
  });

  it("a dotted workspace key names no version", () => {
    const file = s.file("Cargo.toml", CARGO);
    expect(s.edit(file, 'anyhow = "1.0.89"\n', "anyhow.workspace = true\n").decision).toBe("allow");
  });
});
