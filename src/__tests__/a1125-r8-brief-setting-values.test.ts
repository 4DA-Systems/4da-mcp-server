// SPDX-License-Identifier: Apache-2.0
/**
 * Sixth blind check of the 2026-11-25 fixes, item 2: the setting rule hid real packages: 150 real names
 * (json-web-token, generate-password, parse-passwd, csrf-token, credentials, gcp_auth, rusoto_credential,
 * requests_auth ...) written with a version were shown as "a setting named X" and never read;
 * `add "json-web-token": "3.0.1" to package.json` was avoid@3.0.1 in 6.5.1. A setting-named key is a
 * setting only when its value is no version or constraint, and an install command's operand never is.
 */

import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { screenTask } from "../tools/briefing-task-screen.js";

const SHAPED = JSON.parse(readFileSync(new URL("./fixtures/a1125-brief/setting-shaped.json", import.meta.url), "utf8")) as { npm: string[]; crates: string[] };
const VULN = JSON.parse(readFileSync(new URL("./fixtures/a1125-brief/setting-vuln.json", import.meta.url), "utf8")) as { py: string[]; vul: Array<[string, string, string[]]> };

const asSetting = (task: string) => screenTask(task).withheld.filter((w) => w.label.startsWith("a setting named"));

describe("a real name written with a version is never a setting", () => {
  const tasks = [
    ...SHAPED.npm.flatMap((n) => [`add "${n}": "3.0.1" to package.json`, `"${n}": "^1.2.0"`, `npm install ${n}@1.0.0`]),
    ...SHAPED.crates.flatMap((n) => [`add ${n} = "0.48.0" to Cargo.toml`, `cargo add ${n}@0.48.0`]),
    ...VULN.py.flatMap((n) => [`pip install ${n}==7.0.0`, `requirements:\n${n}==7.0.0\n`, `${n}>=1.0`]),
    ...VULN.vul.map(([, n]) => `add "${n}": "3.0.1"`),
  ];
  it(`${tasks.length} tasks: none shows a setting`, () => {
    expect(tasks.filter((t) => asSetting(t).length > 0)).toEqual([]);
  });
});

describe("a setting with a value that is no version stays a setting", () => {
  it.each(["password==hunter2zqx030", "secret_token==tokzqx116", "DB_PASSWORD=zqx1 npm install lodash", '"api_key": "zqxk1"', "password: hunter2zqx"])("%s", (task) => {
    expect(asSetting(task)).toHaveLength(1);
  });

  it("an install command's operand is never a setting", () => {
    expect(asSetting("pip install requests_auth==7.0.0")).toEqual([]);
    expect(asSetting("pip install api_key==hunterzqx")).toEqual([]);
  });
});
