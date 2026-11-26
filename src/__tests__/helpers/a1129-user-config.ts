// SPDX-License-Identifier: Apache-2.0
/**
 * Where a per-user configuration file lives on the running platform (round 6, CI). The vendored review cases name
 * user files by their Windows location under the profile (`Roaming/go/env`, `Roaming/pip/pip.ini`,
 * `Roaming/uv/uv.toml`); written there on Linux or macOS, the tool would never read them and the case would test
 * nothing (nP/p27 failed on CI). Each known key is written where that platform's tool reads it:
 * - go env: %APPDATA%\go\env; ~/Library/Application Support/go/env; $XDG_CONFIG_HOME/go/env (Go's os.UserConfigDir).
 * - pip: %APPDATA%\pip\pip.ini; ~/Library/Application Support/pip/pip.conf; $XDG_CONFIG_HOME/pip/pip.conf.
 * - uv: %APPDATA%\uv\uv.toml; ~/.config/uv/uv.toml on macOS (uv uses XDG paths there); $XDG_CONFIG_HOME/uv/uv.toml.
 * Any other key (`.npmrc`, `.bunfig.toml`) is relative to the home directory on every platform.
 */
import * as path from "node:path";

export function userConfigFile(key: string, env: NodeJS.ProcessEnv, platform: NodeJS.Platform = process.platform): string {
  const home = env.HOME || env.USERPROFILE || "";
  const xdg = env.XDG_CONFIG_HOME || path.join(home, ".config");
  const appdata = env.APPDATA || path.join(home, "Roaming");
  const tool = /^Roaming\/(go|pip|uv)\/(.+)$/.exec(key);
  if (!tool) return path.join(home, key);
  const [, name, file] = tool;
  if (platform === "win32") return path.join(appdata, name, file);
  const posixFile = name === "pip" ? "pip.conf" : file;
  if (platform === "darwin") return name === "uv" ? path.join(home, ".config", "uv", posixFile) : path.join(home, "Library", "Application Support", name, posixFile);
  return path.join(xdg, name, posixFile);
}
