// SPDX-License-Identifier: Apache-2.0
/**
 * run_order rule (b), no step lowers what an earlier step set, from the candidate run of 2026-11-23:
 * - fastapi-frontend: `npm update js-yaml` (4.1.0 -> 4.3.2) ran first, then
 *   `npm install "@hey-api/openapi-ts@^0.97.3"`, whose release pins (through
 *   @hey-api/json-schema-ref-parser 1.4.2) js-yaml 4.1.1, took it back down. Upgrades now run before
 *   in-range refreshes: a refresh moves a copy up within the ranges that hold it.
 * - eslint-config: pnpm 7 moved vite to 8.3.8 with `pnpm up "vitest@^4.1.12"` (what a fresh resolve
 *   of vitest's "^6.0.0 || ^7.0.0 || ^8.0.0" picks), and the peer declaration
 *   `pnpm add -D "vite@^6.4.5"` then lowered it to 6.4.6. The declaration now names that release.
 * - fastapi-frontend: vite 6.4.5 against @vitejs/plugin-react-swc 3.5.0's peer "^4 || ^5" left vite
 *   and esbuild out, although esbuild's row moves the holder to 3.7.2 (peer "^4 || ^5 || ^6"): the
 *   two now install in one command.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { buildRunOrder, type SequencedRow } from "../tools/upgrade-plan-sequence.js";
import { adv, createHarness, fixedIn, type Harness } from "./helpers/a1119-planner-harness.js";

const cmd = (run: string, dir = ".") => ({ dir, run });
function row(pkg: string, action: string, runs: string[], fields: Partial<SequencedRow> = {}): SequencedRow {
  const commands = runs.map((r) => cmd(r));
  return { package: pkg, ecosystem: "npm", currentVersion: "1.0.0", targetVersion: "2.0.0", action, reasons: [], commands, refreshCommands: action === "lockfile_refresh" ? commands.map((c) => ({ dir: c.dir, command: c.run })) : undefined, ...fields };
}
const plan = (rows: SequencedRow[], extra: Partial<Parameters<typeof buildRunOrder>[0]> = {}) => buildRunOrder({ rows, totalRows: rows.length, heldUnclean: () => false, ...extra });

describe("upgrades run before in-range refreshes", () => {
  it("fastapi-frontend: the openapi-ts upgrade runs before the js-yaml refresh, so the refresh cannot be undone by it", () => {
    const rows = [
      row("js-yaml", "lockfile_refresh", ["npm update js-yaml"], { currentVersion: "4.1.0", targetVersion: "4.3.2" }),
      row("@hey-api/openapi-ts", "upgrade_direct", ['npm install "@hey-api/openapi-ts@^0.97.3"'], { currentVersion: "0.34.1", targetVersion: "0.97.3" }),
    ];
    const out = plan(rows);
    expect(out.run_order.map((s) => s.run)).toEqual(['npm install "@hey-api/openapi-ts@^0.97.3"', "npm update js-yaml"]);
    expect(out.run_order_note).toMatch(/upgrades first, then in-range refreshes \(which never lower what an upgrade set\)/);
  });
});

describe("a peer range a row's own lever moves the holder past", () => {
  const conflict = (_dir: string, pkg: string, version: string) =>
    pkg === "vite" && version === "6.4.5" ? { holders: ["@vitejs/plugin-react-swc"], who: '@vitejs/plugin-react-swc 3.5.0 declares "^4 || ^5"', text: "vite 6.4.5 leaves the peer range" } : null;
  const vite = () => row("vite", "upgrade_direct", ['npm install "vite@^6.4.5"'], { currentVersion: "5.0.13", targetVersion: "6.4.5", upgradeCommands: [{ dir: ".", command: 'npm install "vite@^6.4.5"' }] });
  const esbuild = () =>
    row("esbuild", "upgrade_parent", ['npm install "vite@^6.4.5"', "npm update @vitejs/plugin-react-swc", "npm update vite"], {
      currentVersion: "0.19.8",
      targetVersion: "0.25.0",
      parentUpgrades: [
        {
          parent: "vite",
          levers: [
            { name: "vite", version: "5.0.13", to: "6.4.5", commands: [{ dir: ".", command: 'npm install "vite@^6.4.5"' }] },
            { name: "@vitejs/plugin-react-swc", version: "3.5.0", to: "3.7.2", commands: [{ dir: ".", command: "npm update @vitejs/plugin-react-swc" }] },
          ],
          refreshCommands: [{ dir: ".", command: "npm update vite" }],
        },
      ],
    });

  it("installs the holder's release with the target in one command, in the form the project declares it", () => {
    const out = plan([vite(), esbuild()], { peerConflict: conflict, declaredOperator: (_d, name) => (name === "@vitejs/plugin-react-swc" ? "^" : null) });
    expect(out.peerBlocked.size).toBe(0);
    expect(out.run_order.map((s) => s.run)).toEqual(['npm install "@vitejs/plugin-react-swc@^3.7.2" "vite@^6.4.5"', "npm update @vitejs/plugin-react-swc", "npm update vite"]);
    expect(out.run_order[0].fixes).toEqual(["npm:esbuild", "npm:vite"]);
  });

  it("still leaves the step out when the holder's declaration cannot be written in the same form", () => {
    const out = plan([vite(), esbuild()], { peerConflict: conflict, declaredOperator: () => null });
    expect(out.peerBlocked.size).toBe(2);
    expect(out.run_order).toEqual([]);
  });
});

describe("pnpm: the peer declaration after a parent's major upgrade", () => {
  let h: Harness;
  beforeEach(() => {
    h = createHarness();
  });
  afterEach(() => h.dispose());

  it("names the release a fresh resolve of the parent's range picks, so it never lowers what the parent's upgrade set", async () => {
    h.write("package.json", JSON.stringify({ name: "x", version: "1.0.0", devDependencies: { vitest: "^0.25.7" } }));
    h.write(
      "pnpm-lock.yaml",
      [
        "lockfileVersion: '9.0'",
        "",
        "importers:",
        "",
        "  .:",
        "    devDependencies:",
        "      vitest:",
        "        specifier: ^0.25.7",
        "        version: 0.25.7",
        "",
        "packages:",
        "",
        "  vite@3.0.4:",
        "    resolution: {integrity: sha512-vite}",
        "",
        "  vitest@0.25.7:",
        "    resolution: {integrity: sha512-vitest}",
        "",
        "snapshots:",
        "",
        "  vite@3.0.4: {}",
        "",
        "  vitest@0.25.7:",
        "    dependencies:",
        "      vite: 3.0.4",
        "",
      ].join("\n"),
    );
    const range = "^6.0.0 || ^7.0.0 || ^8.0.0";
    h.ADVISORIES = { vite: [adv("GHSA-vite-0002", "vite", fixedIn("6.4.5"))] };
    h.NPM = {
      vitest: { latest: "4.1.12", versions: { "0.25.7": { dependencies: { vite: "^3.0.0 || ^4.0.0" } }, "4.1.12": { dependencies: { vite: range }, peerDependencies: { vite: range } } } },
      vite: { latest: "8.3.8", versions: { "3.0.4": {}, "6.4.5": {}, "6.4.6": {}, "8.3.8": {} } },
    };
    const { result, step } = await h.plan();
    const r = step("vite");
    expect(r.action).toBe("upgrade_parent");
    expect(r.commands).toEqual([
      { dir: ".", run: 'pnpm up "vitest@^4.1.12"' },
      { dir: ".", run: 'pnpm add -D "vite@^8.3.8"' },
    ]);
    expect(result.run_order.map((s: { run: string }) => s.run)).toEqual(['pnpm up "vitest@^4.1.12"', 'pnpm add -D "vite@^8.3.8"']);
  });
});
