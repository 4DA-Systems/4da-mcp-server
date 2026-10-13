// SPDX-License-Identifier: Apache-2.0
/**
 * upgrade_impact fixes from the 2026-10-12 audit:
 * - B-7: a breaking entry naming a Cargo feature the project enables touches
 *   the project (reqwest 0.12 -> 0.13 renamed `rustls-tls`, removed
 *   `macos-system-configuration`; 4DA's src-tauri enables both and nothing
 *   was flagged).
 * - B-7: GitHub release notes list each change twice (the tl;dr line and the
 *   "What's Changed" PR line); the PR line's `by @user in <url>` and
 *   conventional-commit prefix no longer make it a different entry.
 * - B-7: a raw identifier entry (thiserror 2: "`{r#type}` ... no longer
 *   accepted; simply use ... `{type}`") flagged every `{name}` format string,
 *   because the new syntax after "use" was read as the old.
 * - B-6: when the changelog covers only part of the range, the summary says
 *   how to turn on the GitHub fallback too.
 */
import { describe, expect, it } from "vitest";
import type { ChangelogSection } from "../live/changelog.js";
import { cargoFeaturesInManifest, matchFeatures } from "../tools/upgrade-impact-features.js";
import { oldSyntaxShapes } from "../tools/upgrade-impact-literals.js";
import { shapeChangelog, summarize } from "../tools/upgrade-impact-report.js";

const CARGO_TOML = `
[package]
name = "app"

[dependencies]
reqwest = { version = "0.12", default-features = false, features = ["json", "rustls-tls", "macos-system-configuration"] }
serde = "1"
http2 = { package = "hyper", version = "1", features = ["client"] }

[target.'cfg(windows)'.dependencies.tokio]
version = "1"
features = [
  "rt-multi-thread",
  "macros",
]

[workspace.dependencies]
reqwest = { version = "0.12", features = ["stream"] }
`;

describe("Cargo features a project enables (B-7)", () => {
  it("reads inline, table, target, workspace and renamed declarations", () => {
    expect(cargoFeaturesInManifest(CARGO_TOML, "reqwest").sort()).toEqual(["json", "macos-system-configuration", "rustls-tls", "stream"]);
    expect(cargoFeaturesInManifest(CARGO_TOML, "tokio").sort()).toEqual(["macros", "rt-multi-thread"]);
    expect(cargoFeaturesInManifest(CARGO_TOML, "hyper")).toEqual(["client"]);
    expect(cargoFeaturesInManifest(CARGO_TOML, "serde")).toEqual([]);
  });

  it("names a feature only as a feature", () => {
    const features = ["json", "rustls-tls", "macos-system-configuration", "default"];
    expect(matchFeatures("`rustls-tls` has been renamed to `rustls`.", features)).toEqual(["rustls-tls"]);
    expect(matchFeatures("remove deprecated features trust-dns and macos-system-configuration by @x in https://github.com/a/b/pull/1", features)).toEqual(["macos-system-configuration"]);
    expect(matchFeatures("rename rustls feature", ["rustls-tls"])).toEqual([]);
    expect(matchFeatures("Parse json bodies lazily", features)).toEqual([]);
    expect(matchFeatures("The default feature set changed", features)).toEqual([]);
  });

  it("flags reqwest 0.13's feature renames as touching this project", () => {
    const sections: ChangelogSection[] = [
      {
        version: "0.13.0",
        date: null,
        entries: [
          { kind: "breaking", text: "`rustls-tls` has been renamed to `rustls`." },
          { kind: "breaking", text: "remove deprecated features trust-dns and macos-system-configuration by @seanmonstar in https://github.com/seanmonstar/reqwest/pull/2901" },
          { kind: "breaking", text: "`query` and `form` are now crate features, disabled by default." },
        ],
      } as ChangelogSection,
    ];
    const shaped = shapeChangelog(sections, ["Client"], "concise", ["json", "rustls-tls", "macos-system-configuration"]);
    expect(shaped.touching).toBe(2);
    const flagged = shaped.sections[0].entries.filter((e) => e.touches_your_code);
    expect(flagged.map((e) => e.matched_features)).toEqual([["rustls-tls"], ["macos-system-configuration"]]);
    expect(shaped.touchingSymbols).toEqual(expect.arrayContaining(['feature "rustls-tls"', 'feature "macos-system-configuration"']));
  });
});

describe("changelog duplicates (B-7)", () => {
  it("a GitHub PR line repeating a tl;dr line is one entry", () => {
    const sections: ChangelogSection[] = [
      {
        version: "0.13.3",
        date: null,
        entries: [
          { kind: "change", text: "Upgrade rustls-platform-verifier." },
          { kind: "change", text: "Upgrade rustls-platform-verifier by @jplatte in https://github.com/seanmonstar/reqwest/pull/2990" },
          { kind: "change", text: "fix(tls): Upgrade rustls-platform-verifier (#2990)" },
        ],
      } as ChangelogSection,
    ];
    const shaped = shapeChangelog(sections, [], "detailed");
    expect(shaped.sections[0].entries).toHaveLength(1);
    expect(shaped.duplicates).toBe(2);
  });
});

describe("raw identifiers and replacement syntax (B-7)", () => {
  const entry =
    "Referencing keyword-named fields by a raw identifier like `{r#type}` inside a format string is no longer accepted; simply use the unraw name like `{type}` (#347)";

  it("the replacement after `use` is not the old syntax, and `r#` stays literal", () => {
    const shapes = oldSyntaxShapes(entry);
    for (const literal of ["{RELAY_FILENAME}.{}.tmp", "\"{pid}\"", "{type}"]) {
      expect(shapes.some((s) => s.test(literal)), literal).toBe(false);
    }
    expect(shapes.some((s) => s.test("{r#type}"))).toBe(true);
    expect(shapes.some((s) => s.test("{r#match}"))).toBe(true);
  });

  it("from ... to and instead of still pick the old side", () => {
    expect(oldSyntaxShapes("Path parameters changed from `/:single` to `/{single}`").some((s) => s.test("/users/:id"))).toBe(true);
    expect(oldSyntaxShapes("Use `/{param}` instead of `/:param`").some((s) => s.test("/users/:id"))).toBe(true);
    expect(oldSyntaxShapes("Use `/{param}` instead of `/:param`").some((s) => s.test("/users/{id}"))).toBe(false);
  });
});

describe("GitHub fallback hint (B-6)", () => {
  const base = { pkg: "x", from: "1.0.0", to: "2.0.0", releases: 3, breaking: 1, touching: 0, touchingSymbols: [], advisoriesFixed: 0 };
  it("says how to enable the fallback when the changelog is missing", () => {
    expect(summarize({ ...base, changelog: "missing", githubHint: "set FOURDA_GITHUB_CHANGELOG=true" })).toContain("FOURDA_GITHUB_CHANGELOG=true");
  });
  it("and when it covers only part of the range", () => {
    expect(summarize({ ...base, changelog: "partial", githubHint: "set FOURDA_GITHUB_CHANGELOG=true" })).toContain("FOURDA_GITHUB_CHANGELOG=true");
  });
});
