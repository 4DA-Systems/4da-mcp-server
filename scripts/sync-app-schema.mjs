// SPDX-License-Identifier: Apache-2.0
/**
 * Refresh contract/app-schema.sql from the desktop app's repository.
 *
 *   node scripts/sync-app-schema.mjs [--ref main] [--check]
 *
 * --check  exit 1 if the vendored copy differs from the app's, without writing.
 *          CI's nightly contract job uses it to say the copy is behind.
 *
 * The app generates the file from its migrations (src-tauri/contract/app-schema.sql,
 * `UPDATE_APP_SCHEMA_CONTRACT=1 cargo test --lib app_schema_contract`), and the
 * repository is public, so this needs no token.
 */
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const refAt = process.argv.indexOf("--ref");
const ref = refAt > -1 ? process.argv[refAt + 1] : "main";
const check = process.argv.includes("--check");
const url = `https://raw.githubusercontent.com/4DA-Systems/4DA/${ref}/src-tauri/contract/app-schema.sql`;
const target = join(root, "contract", "app-schema.sql");

const res = await fetch(url);
if (!res.ok) {
  console.error(`sync-app-schema: ${url} -> HTTP ${res.status}`);
  process.exit(2);
}
const upstream = (await res.text()).replaceAll("\r\n", "\n");
const local = existsSync(target) ? readFileSync(target, "utf8").replaceAll("\r\n", "\n") : "";
const version = (s) => s.match(/^-- schema_version: (\d+)/m)?.[1] ?? "?";

if (upstream === local) {
  console.log(`contract/app-schema.sql is current (schema_version ${version(local)}, 4DA ${ref}).`);
  process.exit(0);
}
if (check) {
  console.error(
    `contract/app-schema.sql is behind 4DA ${ref}: schema_version ${version(local)} here, ${version(upstream)} upstream. Run \`pnpm run contract:sync\` and \`pnpm run contract\`.`,
  );
  process.exit(1);
}
writeFileSync(target, upstream);
console.log(`contract/app-schema.sql updated: schema_version ${version(local)} -> ${version(upstream)} (4DA ${ref}). Now run \`pnpm run contract\`.`);
