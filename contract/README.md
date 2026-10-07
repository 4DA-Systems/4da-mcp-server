# App-schema contract

The server reads, read-only, the database of the 4DA desktop
app, `4da.db`. The app lives in another repository
([4DA-Systems/4DA](https://github.com/4DA-Systems/4DA)), so a migration there
and a query here cannot see each other. This folder is where they meet.

## The files

- **`app-schema.sql`** is the schema a running app holds: its migrations plus
  the tables its context engine and ACE create at startup. It is GENERATED in
  the app repository (`src-tauri/contract/app-schema.sql`) by a Rust test that
  fails whenever a migration changes the schema without regenerating it. This
  is a copy. `pnpm run contract:sync` refreshes it.
- **`allowlist.json`** (optional, absent today) lists known disagreements, each
  with a reason:

  ```json
  {
    "statements": [{ "match": "substring of the SQL", "reason": "why it is fine" }],
    "columns": { "table.column": "why hasColumn() may be false" }
  }
  ```

  An entry that no longer matches anything fails the run, so the list cannot
  rot.

## The checks

`pnpm run contract` (also `node scripts/app-schema-contract.mjs --schema <file>`):

1. Runs the test suite with SQL recording on. Among the suites,
   `src/__tests__/app-schema-contract.test.ts` loads the app schema, seeds a
   row into every table, and calls every tool through the real dispatcher.
2. Applies the DDL the server runs on its own files (`live_cache` in its
   `cache.db`, the `embedding` columns in its store; since 6.1 it opens the
   app's database read-only and writes nothing there), then re-prepares every statement server code issued during the run. SQLite
   resolves every table and column at prepare time, so a dropped or renamed
   one fails here.
3. Checks every `hasColumn()` probe. A probe that comes back false means a tool
   is silently running a fallback query.
4. Reports how many of the server's `.prepare(` call sites the run reached and
   fails below 80%, so new SQL cannot go untested by default.

## Where it runs

| Where | Schema | When |
|---|---|---|
| This repo, `ci.yml` | `contract/app-schema.sql` (vendored) | every PR and push |
| This repo, `ci.yml` | the app's `main` | every PR and push, and nightly; a failure opens an issue |
| 4DA, `validate.yml` job `mcp-contract` | the PR's own regenerated file | every app PR that changes the schema, and every merge-queue run |

## When it fails

- **After an app migration:** decide which side moves. Either the server
  follows the schema (change the query, release), or the migration keeps what
  the server reads. Users run the app and the server at independent versions,
  so the server must also keep working against the previous schema: guard new
  columns with `hasColumn()`.
- **After a server change:** the new query names something the app does not
  have. Check `app-schema.sql` for the real name.
