# Security Policy

## Supported versions

Only the latest release of `@4da/mcp-server` receives security fixes. Run the
newest version (`npx @4da/mcp-server@latest`, or the version your Claude Code
plugin pins).

## Reporting a vulnerability

**Do not open a public issue for a security vulnerability.** Report it
privately, through either channel:

- **GitHub private vulnerability reporting:** this repository's **Security**
  tab, **Report a vulnerability**.
- **Email:** **security@4da.ai**

Include what you found, how to reproduce it, and the impact you see (for
example code execution through a scanned repository, data leaving the machine,
or an `--http` auth bypass). We acknowledge within 48 hours and triage within
five business days.

## What the server does that matters for security

- **It reads your project.** Lockfiles, manifests and source files (for
  `upgrade_impact`'s call-site scan) are read locally. Source code and file
  paths never leave the machine.
- **It runs `cargo tree`** to tell which crates a host actually compiles. It
  runs cargo from a directory the server owns, names the project only through
  `--manifest-path`, and passes `--offline --locked`, so a scanned repository's
  `.cargo/config.toml` (rustc wrappers, aliases) is never honoured.
- **Network:** package names and versions go to OSV.dev and the public package
  registries (npm, crates.io, PyPI, the Go proxy); `ecosystem_pulse` sends a
  few dependency names to the Hacker News search API. `FOURDA_OFFLINE=true`
  turns all of it off.
- **`--http`** binds to `127.0.0.1` with a DNS-rebinding `Host` check. A
  non-loopback bind is refused unless `MCP_AUTH_SECRET` is set, and every
  request then needs an HMAC-signed bearer token.
- **Releases** are published from this repository's `release.yml` through npm
  trusted publishing, with a provenance attestation; the package accepts no
  publish tokens. Check a version with `npm audit signatures`.

The 4DA desktop app has its own policy:
[4DA-Systems/4DA/SECURITY.md](https://github.com/4DA-Systems/4DA/blob/main/SECURITY.md).
