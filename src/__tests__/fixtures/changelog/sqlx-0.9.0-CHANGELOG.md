# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.9.0 - 2026-05-06

### Important Announcements

#### New Github Organization
Shortly after this release is published, the SQLx repository will be transferred to a new GitHub organization:
https://github.com/transact-rs/

This is because SQLx has not been owned or maintained by LaunchBadge, LLC. for a few years now, and has since been
informally transferred to the collective ownership of its principal authors. Moving the repository to a new 
organization makes this change more clear, and also allows for potentially inviting outside collaborators.

#### `Cargo.lock` Removed from Tracking
The `Cargo.lock` has been removed from tracking in Git. CI should now always test with the latest versions of 
all dependencies by default, alongside our pass that checks with `cargo generate-lockfile -Z minimal-versions`.

This should eliminate the need for any PRs that update dependencies to also update `Cargo.lock` or
contend with an endless stream of merge conflicts against it.

**N.B.** `cargo install --locked sqlx-cli` will no longer work. However, `cargo install sqlx-cli` has _always_
used the latest dependencies by default, ignoring the lockfile, so most users should not be affected. For users
requiring reproducible builds, consider maintaining your own lockfile instead; historically, we only ran `cargo update`
sporadically, so relying on SQLx's lockfile offered few guarantees anyway.

See [the manual page for `cargo install`][man-cargo-install] for details.

### Breaking
As per our [MSRV policy](FAQ.md#MSRV), the supported Rust version for this release cycle is [`1.94.0`](https://doc.rust-lang.org/stable/releases.html#version-1940-2026-03-05).


* [[#3383]]: feat: create `sqlx.toml` format [[@abonander]]
  * SQLx and `sqlx-cli` now support per-crate configuration files (`sqlx.toml`)
  * New functionality includes, but is not limited to:
    * Rename `DATABASE_URL` for a crate (for multi-database workspaces) 
    * Set global type overrides for the macros (supporting custom types)
    * Rename or relocate the `_sqlx_migrations` table (for multiple crates using the same database)
    * Set characters to ignore when hashing migrations (e.g. ignore whitespace)
  * More to be implemented in future releases.
  * Enable feature `sqlx-toml` to use.
    * `sqlx-cli` has it enabled by default, but `sqlx` does **not**.
    * Default features of library crates can be hard to completely turn off because of [feature unification], 
      so it's better to keep the default feature set as limited as possible. 
      [This is something we learned the hard way.][preferred-crates]
  * Guide: see `sqlx::_config` module in documentation.
  * Reference: [[Link](sqlx-core/src/config/reference.toml)]
  * Examples (written for Postgres but can be adapted to other databases; PRs welcome!):
    * Multiple databases using `DATABASE_URL` renaming and global type overrides: [[Link](examples/postgres/multi-database)]
    * Multi-tenant database using `_sqlx_migrations` renaming and multiple schemas: [[Link](examples/postgres/multi-tenant)]
    * Force use of `chrono` when `time` is enabled (e.g. when using `tower-sessions-sqlx-store`): [[Link][preferred-crates]]
      * Forcing `bigdecimal` when `rust_decimal` is enabled is also shown, but problems with `chrono`/`time` are more common.
  * **Breaking changes**:
    * Significant changes to the `Migrate` trait
    * `sqlx::migrate::resolve_blocking()` is now `#[doc(hidden)]` and thus SemVer-exempt.
* [[#3486]]: fix(logs): Correct spelling of aquired_after_secs tracing field [[@iamjpotts]]
  * Breaking behavior change: implementations parsing `tracing` logs from SQLx will need to update the spelling.
* [[#3495]]: feat(postgres): remove lifetime from `PgAdvisoryLockGuard` [[@bonsairobo]]
* [[#3526]]: Return &mut Self from the migrator set_ methods [[@nipunn1313]]
  * Minor breaking change: `Migrator::set_ignore_missing` and `set_locking` now return `&mut Self` instead of `&Self`
    which may break code in rare circumstances.
* [[#3541]]: Postgres: force generic plan for better nullability inference. [[@joeydewaal]]
  * Breaking change: may alter the output of the `query!()` macros for certain queries in Postgres.
* [[#3613]]: fix: `RawSql` lifetime issues [[@abonander]]
  * Breaking change: adds `DB` type parameter to all methods of `RawSql`
* [[#3670]]: Bump ipnetwork to v0.21.1 [[@BeauGieskens]]
* [[#3674]]: Implement `Decode`, `Encode` and `Type` for `Box`, `Arc`, `Cow` and `Rc` [[@joeydewaal]]
  * Breaking change: `impl Decode for Cow` now always decodes `Cow::Owned`, lifetime is unlinked
  * See this discussion for motivation: https://github.com/launchbadge/sqlx/pull/3674#discussion_r2008611502
* [[#3723]]: Add SqlStr [[@joeydewaal]]
  * Breaking change: all `query*()` functions now take `impl SqlSafeStr` 
    which is only implemented for `&'static str` and `AssertSqlSafe`. 
    For all others, wrap in `AssertSqlSafe(<query>)`.
  * This, along with [[#3960]], finally allows returning owned queries as the type will be `Query<'static, DB>`.
  * `SqlSafeStr` trait is deliberately similar to `std::panic::UnwindSafe`, 
    serving as a speedbump to warn users about naïvely building queries with `format!()`
    while allowing a workaround for advanced usage that is easy to spot on code review. 
* [[#3800]]: Escape PostgreSQL Options [[@V02460]]
  * Breaking behavior change: options passed to `PgConnectOptions::options()` are now automatically escaped.
    Manual escaping of options is no longer necessary and may cause incorrect behavior.
* [[#3821]]: Groundwork for 0.9.0-alpha.1 [[@abonander]]
  * Increased MSRV to 1.86 and set rust-version
  * Deleted deprecated combination runtime+TLS features (e.g. `runtime-tokio-native-tls`)
  * Deleted re-export of unstable `TransactionManager` trait in `sqlx`.
    * Not technically a breaking change because it's `#[doc(hidden)]`,
      but [it _will_ break SeaORM][seaorm-2600] if not proactively fixed.
* [[#3924]]: breaking(mysql): assume all non-binary collations compatible with `str` [[@abonander]]
  * Text (or text-like) columns which previously were inferred to be `Vec<u8>` will be inferred to be `String` 
    (this should ultimately fix more code than it breaks).
  * `SET NAMES utf8mb4 COLLATE utf8_general_ci` is no longer sent by default; instead, `SET NAMES utf8mb4` is sent to
    allow the server to select the appropriate default collation (since this is version- and configuration-dependent).
  * `MySqlConnectOptions::charset()` and `::collation()` now imply `::set_names(true)` because they don't do anything otherwise.
  * Setting `charset` doesn't change what's sent in the `Protocol::HandshakeResponse41` packet as that normally only 
    matters for error messages before `SET NAMES` is sent. 
    The default collation if `set_names = false` is `utf8mb4_general_ci`.
  * See [this comment](https://github.com/launchbadge/sqlx/blob/388c424f486bf20542a8a37d296dbcf86bb6dffd/sqlx-mysql/src/collation.rs#L1-L37) for details.
  * Incidental breaking change: `RawSql::fetch_optional()` now returns `sqlx::Result<Option<DB::Row>>` 
    instead of `sqlx::Result<DB::Row>`. Whoops.
* [[#3928]]: breaking(sqlite): `libsqlite3-sys` versioning, feature flags, safety changes [[@abonander]]
  * SemVer policy changes: `libsqlite3-sys` version is now specified using a range.
    The maximum of the range may now be increased in any backwards-compatible release.
    The minimum of the range may only be increased in major releases.
    If you have `libsqlite3-sys` in your dependencies, Cargo should choose a compatible version automatically. 
    If otherwise unconstrained, Cargo should choose the latest version supported.
  * SQLite extension loading (including through the new `sqlx-toml` feature) is now `unsafe`. 
  * Added new **non-default** features corresponding to conditionally compiled SQLite APIs:
    * `sqlite-deserialize` enabling `SqliteConnection::serialize()` and `SqliteConnection::deserialize()`
    * `sqlite-load-extension` enabling `SqliteConnectOptions::extension()` and `::extension_with_entrypoint()`
    * `sqlite-unlock-notify` enables internal use of `sqlite3_unlock_notify()`
  * `SqliteValue` and `SqliteValueRef` changes:
    * The [`sqlite3_value*` interface](https://www.sqlite.org/c3ref/value_blob.html) reserves the right to be stateful. 
      Without protection, any call could theoretically invalidate values previously returned, leading to dangling pointers.
    * `SqliteValue` is now `!Sync` and `SqliteValueRef` is `!Send` to prevent data races from concurrent accesses.
      *  Instead, clone or wrap the `SqliteValue` in `Mutex`, or convert the `SqliteValueRef` to an owned value.
    * `SqliteValue` and any derived `SqliteValueRef`s now internally track if that value has been used to decode a 
      borrowed `&[u8]` or `&str` and errors if it's used to decode any other type.
    * This is not expected to affect the vast majority of usages, which should only decode a single type 
      per `SqliteValue`/`SqliteValueRef`.
    * See new docs on `SqliteValue` for details.
* [[#3949]]: Postgres: move `PgLTree::from` to `From<Vec<PgLTreeLabel>>` implementation [[@JerryQ17]]
* [[#3957]]: refactor(sqlite): do not borrow bound values, delete lifetime on `SqliteArguments` [[@iamjpotts]]
* [[#3958]]: refactor(any): Remove lifetime parameter from AnyArguments [[@iamjpotts]]
* [[#3960]]: refactor(core): Remove lifetime parameter from Arguments trait [[@iamjpotts]]
* [[#3993]]: Unescape PostgreSQL passfile password [[@V02460]]
  * Previously, `.pgpass` file handling did not process backslash-escapes in the password part. 
    Now it does, which may change what password is sent to the server.
* [[#4008]]: make `#[derive(sqlx::Type)]` automatically generate `impl PgHasArrayType` by default for newtype structs [[@papaj-na-wrotkach]]
  * Manual implementations of PgHasArrayType for newtypes will conflict with the generated one.
    Delete the manual impl or add `#[sqlx(no_pg_array)]` where conflicts occur.
* [[#4077]]: breaking: make `offline` optional to allow building without `serde` [[@CathalMullan]]
* [[#4094]]: Bump bit-vec to v0.8 [[@zennozenith]]
* [[#4142]]: feat(mysql): add mysql-rsa feature for non-TLS RSA auth [[@dertin]]
  * Connections requiring RSA password encryption now need to enable the `mysql-rsa` feature 
    or an error will be generated at runtime. RSA encryption is only used for plaintext (non-TLS) connections.
* [[#4255]]: breaking(any+mysql): correctly convert text and blob types to `AnyTypeInfo` [[@abonander]]

### Added
* [[#3641]]: feat(Postgres): support nested domain types [[@joeydewaal]]
* [[#3651]]: Add PgBindIter for encoding and use it as the implementation encoding &[T] [[@tylerhawkes]]
* [[#3675]]: feat: implement Encode, Decode, Type for `Arc<str>` and `Arc<[u8]>` (and `Rc` equivalents) [[@joeydewaal]]
* [[#3791]]: Smol+async global executor 1.80 dev [[@martin-kolarik]]
  * Adds `runtime-smol` and `runtime-async-global-executor` features to replace usages of the deprecated `async-std` crate.
* [[#3859]]: Add more JsonRawValue encode/decode impls. [[@Dirbaio]]
* [[#3881]]: CLi: made cli-lib modules publicly available for other crates [[@silvestrpredko]]
* [[#3889]]: Compile-time support for external drivers [[@bobozaur]]
* [[#3917]]: feat(sqlx.toml): support SQLite extensions in macros and sqlx-cli  [[@djarb]]
* [[#3918]]: Feature: Add exclusion violation error kind [[@barskern]]
* [[#3971]]: Allow single-field named structs to be transparent [[@Xiretza]]
* [[#4015]]: feat(sqlite): `no_tx` migration support [[@AlexTMjugador]]
* [[#4020]]: Add `Migrator::with_migrations()` constructor [[@xb284524239]]
* [[#3846]]: Add the possibility to skip migrations [[@Dosenpfand]]
* [[#4107]]: Add SQLite extension entrypoint config to `sqlx.toml`, update SQLite extension example [[@supleed2]]
* [[#4118]]: [postgres] Display line number in error message [[@mousetail]]
* [[#4123]]: feat: add `Json::into_inner()` [[@chrxn1c]]
* [[#4153]]: Add on unimplemented diagnostic to `SqlStr` [[@joeydewaal]]
* [[#4167]]: add sqlite serialize/deserialize example [[@mattrighetti]]
* [[#4228]]: sqlx-postgres: Make `PgNotification` struct clone [[@michaelvanstraten]]


### Changed
* [[#3525]]: Remove unnecessary boxfutures [[@joeydewaal]]
* [[#3867]]: sqlx-postgres: Bump etcetera to 0.10.0 [[@miniduikboot]]
* [[#3709]]: chore: replace once_cell `OnceCell`/`Lazy` with std `OnceLock`/`LazyLock` [[@paolobarbolini]]
* [[#3890]]: feat: Unify `Debug` implementations across `PgRow`, `MySqlRow` and `SqliteRow` [[@davidcornu]]
* [[#3911]]: chore: upgrade async-io to v2.4.1 [[@zebrapurring]]
* [[#3938]]: Move `QueryLogger` back [[@joeydewaal]]
* [[#3956]]: chore(sqlite): Remove unused test of removed git2 feature [[@iamjpotts]]
* [[#3962]]: Give SQLX_OFFLINE_DIR from environment precedence in macros [[@psionic-k]]
* [[#3968]]: chore(ci): Add timeouts to ci jobs [[@iamjpotts]]
* [[#4002]]: sqlx-postgres(tests): cleanup 2 unit tests. [[@joeydewaal]]
* [[#4022]]: refactor: tweaks after #3791 [[@abonander]]
* [[#4257]]: Prefer to give real data to `.bind()` in `README.md` [[@sobolevn]]
* [[#4042]]: Update to webpki-roots 1 [[@tottoto]]
* [[#4072]]: chore: update hashlink to v0.11.0 [[@anmolitor]]
* [[#4143]]: Bump whoami to v2 [[@tisonkun]]
* [[#4161]]: sqlx-sqlite: relax libsqlite3-sys constraint to allow 0.36.x [[@darioAnongba]]
* [[#4173]]: ci: check direct minimal versions [[@ricochet]]
  * Note: reverted in 0.9.0 release but still listed for contributor credit. See end of PR thread for details.
* [[#4189]]: Bump flume to 0.12.0 [[@opoplawski]]
* [[#4223]]: test(sqlite): add regression test for ORDER BY + LIMIT nullability (#4147) [[@barry3406]]
* [[#4230]]: chore: Update to cargo_metadata 0.23 [[@tottoto]]
* [[#4233]]: Change reference to dotenvy [[@graemer957]]
* [[#4235]]: chore: Update to validator 0.20 [[@tottoto]]
* [[#4253]]: chore: update example to axum 0.8 [[@tottoto]]
* Release PR:
  * Upgraded all Rust-Crypto crates, `rand`
  * Upgraded `etcetera` to `0.11.0`
  * Increased max of `libsqlite3-sys` version range to `<0.38.0`


### Fixed
* [[#3840]]: Fix docs.rs build of sqlx-sqlite [[@gferon]]
* [[#3848]]: fix(macros): don't mutate environment variables [[@joeydewaal]]
* [[#3856]]: fix(macros): slightly improve unsupported type error message [[@dyc3]]
* [[#3857]]: fix(mysql): validate parameter count for prepared statements [[@cvzx]]
* [[#3861]]: Fix NoHostnameTlsVerifier for rustls 0.23.24 and above [[@elichai]]
* [[#3863]]: Use unnamed statement in pg when not persistent [[@ThomWright]]
* [[#3874]]: Further reduce dependency on `futures` and `futures-util` [[@paolobarbolini]]
* [[#3886]]: fix: use Executor::fetch in QueryAs::fetch [[@bobozaur]]
* [[#3910]]: feat(ok): add correct handling of ok packets in MYSQL implementation [[@0xfourzerofour]]
* [[#3914]]: fix: regenerate test certificates [[@abonander]]
* [[#3915]]: fix: spec_error is used by try_from derive [[@saiintbrisson]]
* [[#3919]]: fix[sqlx-postgres]: do a checked_mul to prevent panic'ing [[@nhatcher-frequenz]]
* [[#3923]]: sqlx-mysql: Fix bug in cleanup test db's. [[@joeydewaal]]
* [[#3950]]: chore: Fix warnings for custom postgres_## cfg flags [[@iamjpotts]]
* [[#3952]]: `Pool.close`: close all connections before returning [[@jpmelos]]
* [[#3975]]: fix documentation for rustls native root certificates [[@2ndDerivative]]
* [[#3977]]: refactor(ci): Use separate job for postgres ssl auth tests [[@iamjpotts]]
* [[#3980]]: Correctly `ROLLBACK` transaction when dropped during `BEGIN`. [[@kevincox]]
* [[#3981]]: SQLite: fix transaction level accounting with bad custom command. [[@kevincox]]
* [[#3986]]: chore(core): Fix docstring for Query::try_bind [[@iamjpotts]]
* [[#3987]]: chore(deps): Resolve deprecation warning for chrono Date and ymd methods [[@iamjpotts]]
* [[#3988]]: refactor(sqlite): Resolve duplicate test target warning for macros.rs [[@iamjpotts]]
* [[#3989]]: chore(deps): Set default-features=false on sqlx in workspace.dependencies [[@iamjpotts]]
* [[#3991]]: fix(sqlite): regression when decoding nulls [[@abonander]]
* [[#4006]]: PostgreSQL SASL – run SHA256 in a blocking executor [[@ThomWright]]
* [[#4007]]: fix(compose): use OS-assigned ports for all conatiners [[@papaj-na-wrotkach]]
* [[#4009]]: Drop cached db connections in macros upon hitting an error [[@swlynch99]]
* [[#4024]]: fix(sqlite) Migrate revert with no-transaction [[@Dosenpfand]]
* [[#4027]]: native tls handshake: build TlsConnector in blocking threadpool [[@daviduebler]]
* [[#4053]]: fix(macros): smarter `.env` loading, caching, and invalidation [[@abonander]]
  * Additional credit to [[@AlexTMjugador]] ([[#4018]]) and [[@Diggsey]] ([[#4039]]) for their proposed solutions
    which served as a useful comparison.
* [[#4068]]: Fix typo in migration example from 'uesrs' to 'users' [[@squidpickles]]
* [[#4069]]: fix some spelling issues [[@joeydewaal]]
* [[#4086]]: fix(mysql): Work around for Issue #2206 (ColumnNotFound error when querying) [[@duelafn]]
* [[#4088]]: (Fix) Handle nullability of SQLite rowid alias columns [[@Lege19]]
* [[#4100]]: postgres: update pgpass path on windows [[@joeydewaal]]
* [[#4134]]: fix CI: replace removed macOS runner, deprecated use of `Command::cargo_bin()` [[@abonander]]
* [[#4136]]: Ensure Deterministic Migration Order  [[@aoengin]]
* [[#4158]]: Fix panic in JSONB decoder on invalid version byte [[@jrey8343]]
* [[#4165]]: sqlx-postgres: fix correct operator precedence in  byte length check [[@cuiweixie]]
* [[#4171]]: fix(postgres): remove home crate in favor of std::env::home_dir [[@ricochet]]
* [[#4172]]: fix(sqlx-cli): bump openssl minimum to 0.10.46 [[@ricochet]]
* [[#4176]]: fix(mysql): return error instead of panic on truncated OK packet [[@cvzx]]
* [[#4199]]: fix(postgres): make advisory lock cancel safe [[@joeydewaal]]
* [[#4201]]: Fix SCRAM password `SASLprep`  [[@var4yn]]
* [[#4202]]: fix: replace from_utf8_unchecked with from_utf8_lossy in SqliteError [[@joaquinhuigomez]]
* [[#4203]]: fix: use sqlite3_value_text for REGEXP to match SQLite coercion [[@joaquinhuigomez]]
* [[#4219]]: sqlite: lossily coerce invalid UTF-8 in custom collation callback [[@joaquinhuigomez]]
* [[#4221]]: fix: replace `from_utf8_unchecked` with `from_utf8` in SQLite column name handling [[@barry3406]]
* [[#4226]]: fix(postgres): use non-prepared statements for metadata queries [[@abonander]]
* [[#4227]]: fix(macros-core): update unstable proc_macro APIs for recent nightly [[@barry3406]]
* [[#4234]]: fix: Use correct path in error when failing to create tmp dir in prepare [[@Miesvanderlippe]]
* [[#4245]]: fix(mysql): repair caching_sha2_password fast-auth path [[@altmannmarcelo]]
* [[#4251]]: fix(tls): potential deadlock in `StdSocket::poll_ready()` [[@abonander]]

[seaorm-2600]: https://github.com/SeaQL/sea-orm/issues/2600
[feature unification]: https://doc.rust-lang.org/cargo/reference/features.html#feature-unification
[preferred-crates]: examples/postgres/preferred-crates
[man-cargo-install]: https://doc.rust-lang.org/cargo/commands/cargo-install.html#dealing-with-the-lockfile

[#3821]: https://github.com/launchbadge/sqlx/pull/3821
[#3383]: https://github.com/launchbadge/sqlx/pull/3383
[#3486]: https://github.com/launchbadge/sqlx/pull/3486
[#3495]: https://github.com/launchbadge/sqlx/pull/3495
[#3525]: https://github.com/launchbadge/sqlx/pull/3525
[#3526]: https://github.com/launchbadge/sqlx/pull/3526
[#3541]: https://github.com/launchbadge/sqlx/pull/3541
[#3613]: https://github.com/launchbadge/sqlx/pull/3613
[#3641]: https://github.com/launchbadge/sqlx/pull/3641
[#3651]: https://github.com/launchbadge/sqlx/pull/3651
[#3670]: https://github.com/launchbadge/sqlx/pull/3670
[#3674]: https://github.com/launchbadge/sqlx/pull/3674
[#3675]: https://github.com/launchbadge/sqlx/pull/3675
[#3709]: https://github.com/launchbadge/sqlx/pull/3709
[#3723]: https://github.com/launchbadge/sqlx/pull/3723
[#3791]: https://github.com/launchbadge/sqlx/pull/3791
[#3800]: https://github.com/launchbadge/sqlx/pull/3800
[#3821]: https://github.com/launchbadge/sqlx/pull/3821
[#3840]: https://github.com/launchbadge/sqlx/pull/3840
[#3848]: https://github.com/launchbadge/sqlx/pull/3848
[#3856]: https://github.com/launchbadge/sqlx/pull/3856
[#3857]: https://github.com/launchbadge/sqlx/pull/3857
[#3859]: https://github.com/launchbadge/sqlx/pull/3859
[#3861]: https://github.com/launchbadge/sqlx/pull/3861
[#3863]: https://github.com/launchbadge/sqlx/pull/3863
[#3867]: https://github.com/launchbadge/sqlx/pull/3867
[#3874]: https://github.com/launchbadge/sqlx/pull/3874
[#3881]: https://github.com/launchbadge/sqlx/pull/3881
[#3886]: https://github.com/launchbadge/sqlx/pull/3886
[#3889]: https://github.com/launchbadge/sqlx/pull/3889
[#3890]: https://github.com/launchbadge/sqlx/pull/3890
[#3910]: https://github.com/launchbadge/sqlx/pull/3910
[#3911]: https://github.com/launchbadge/sqlx/pull/3911
[#3914]: https://github.com/launchbadge/sqlx/pull/3914
[#3915]: https://github.com/launchbadge/sqlx/pull/3915
[#3917]: https://github.com/launchbadge/sqlx/pull/3917
[#3918]: https://github.com/launchbadge/sqlx/pull/3918
[#3919]: https://github.com/launchbadge/sqlx/pull/3919
[#3923]: https://github.com/launchbadge/sqlx/pull/3923
[#3924]: https://github.com/launchbadge/sqlx/pull/3924
[#3928]: https://github.com/launchbadge/sqlx/pull/3928
[#3938]: https://github.com/launchbadge/sqlx/pull/3938
[#3949]: https://github.com/launchbadge/sqlx/pull/3949
[#3950]: https://github.com/launchbadge/sqlx/pull/3950
[#3952]: https://github.com/launchbadge/sqlx/pull/3952
[#3956]: https://github.com/launchbadge/sqlx/pull/3956
[#3957]: https://github.com/launchbadge/sqlx/pull/3957
[#3958]: https://github.com/launchbadge/sqlx/pull/3958
[#3960]: https://github.com/launchbadge/sqlx/pull/3960
[#3962]: https://github.com/launchbadge/sqlx/pull/3962
[#3968]: https://github.com/launchbadge/sqlx/pull/3968
[#3971]: https://github.com/launchbadge/sqlx/pull/3971
[#3975]: https://github.com/launchbadge/sqlx/pull/3975
[#3977]: https://github.com/launchbadge/sqlx/pull/3977
[#3980]: https://github.com/launchbadge/sqlx/pull/3980
[#3981]: https://github.com/launchbadge/sqlx/pull/3981
[#3986]: https://github.com/launchbadge/sqlx/pull/3986
[#3987]: https://github.com/launchbadge/sqlx/pull/3987
[#3988]: https://github.com/launchbadge/sqlx/pull/3988
[#3989]: https://github.com/launchbadge/sqlx/pull/3989
[#3991]: https://github.com/launchbadge/sqlx/pull/3991
[#4002]: https://github.com/launchbadge/sqlx/pull/4002
[#4006]: https://github.com/launchbadge/sqlx/pull/4006
[#4007]: https://github.com/launchbadge/sqlx/pull/4007
[#4008]: https://github.com/launchbadge/sqlx/pull/4008
[#4009]: https://github.com/launchbadge/sqlx/pull/4009
[#4015]: https://github.com/launchbadge/sqlx/pull/4015
[#4018]: https://github.com/launchbadge/sqlx/pull/4018
[#4020]: https://github.com/launchbadge/sqlx/pull/4020
[#4022]: https://github.com/launchbadge/sqlx/pull/4022
[#4024]: https://github.com/launchbadge/sqlx/pull/4024
[#4027]: https://github.com/launchbadge/sqlx/pull/4027
[#4039]: https://github.com/launchbadge/sqlx/pull/4039
[#4053]: https://github.com/launchbadge/sqlx/pull/4053
[#3846]: https://github.com/launchbadge/sqlx/pull/3846
[#3993]: https://github.com/launchbadge/sqlx/pull/3993
[#4042]: https://github.com/launchbadge/sqlx/pull/4042
[#4068]: https://github.com/launchbadge/sqlx/pull/4068
[#4069]: https://github.com/launchbadge/sqlx/pull/4069
[#4072]: https://github.com/launchbadge/sqlx/pull/4072
[#4077]: https://github.com/launchbadge/sqlx/pull/4077
[#4086]: https://github.com/launchbadge/sqlx/pull/4086
[#4088]: https://github.com/launchbadge/sqlx/pull/4088
[#4094]: https://github.com/launchbadge/sqlx/pull/4094
[#4100]: https://github.com/launchbadge/sqlx/pull/4100
[#4107]: https://github.com/launchbadge/sqlx/pull/4107
[#4118]: https://github.com/launchbadge/sqlx/pull/4118
[#4123]: https://github.com/launchbadge/sqlx/pull/4123
[#4134]: https://github.com/launchbadge/sqlx/pull/4134
[#4136]: https://github.com/launchbadge/sqlx/pull/4136
[#4142]: https://github.com/launchbadge/sqlx/pull/4142
[#4143]: https://github.com/launchbadge/sqlx/pull/4143
[#4153]: https://github.com/launchbadge/sqlx/pull/4153
[#4158]: https://github.com/launchbadge/sqlx/pull/4158
[#4161]: https://github.com/launchbadge/sqlx/pull/4161
[#4165]: https://github.com/launchbadge/sqlx/pull/4165
[#4167]: https://github.com/launchbadge/sqlx/pull/4167
[#4171]: https://github.com/launchbadge/sqlx/pull/4171
[#4172]: https://github.com/launchbadge/sqlx/pull/4172
[#4173]: https://github.com/launchbadge/sqlx/pull/4173
[#4176]: https://github.com/launchbadge/sqlx/pull/4176
[#4189]: https://github.com/launchbadge/sqlx/pull/4189
[#4199]: https://github.com/launchbadge/sqlx/pull/4199
[#4201]: https://github.com/launchbadge/sqlx/pull/4201
[#4202]: https://github.com/launchbadge/sqlx/pull/4202
[#4203]: https://github.com/launchbadge/sqlx/pull/4203
[#4219]: https://github.com/launchbadge/sqlx/pull/4219
[#4221]: https://github.com/launchbadge/sqlx/pull/4221
[#4223]: https://github.com/launchbadge/sqlx/pull/4223
[#4226]: https://github.com/launchbadge/sqlx/pull/4226
[#4227]: https://github.com/launchbadge/sqlx/pull/4227
[#4228]: https://github.com/launchbadge/sqlx/pull/4228
[#4230]: https://github.com/launchbadge/sqlx/pull/4230
[#4233]: https://github.com/launchbadge/sqlx/pull/4233
[#4234]: https://github.com/launchbadge/sqlx/pull/4234
[#4235]: https://github.com/launchbadge/sqlx/pull/4235
[#4245]: https://github.com/launchbadge/sqlx/pull/4245
[#4251]: https://github.com/launchbadge/sqlx/pull/4251
[#4253]: https://github.com/launchbadge/sqlx/pull/4253
[#4255]: https://github.com/launchbadge/sqlx/pull/4255
[#4257]: https://github.com/launchbadge/sqlx/pull/4257

## 0.8.6 - 2025-05-19

9 pull requests were merged this release cycle.

### Added
* [[#3849]]: Add color and wrapping to cli help text [[@joshka]]

### Changed
* [[#3830]]: build: drop unused `tempfile` dependency [[@paolobarbolini]]
* [[#3845]]: chore: clean up no longer used imports [[@tisonkun]]
* [[#3863]]: Use unnamed statement in pg when not persistent [[@ThomWright]]
* [[#3866]]: chore(doc): clarify compile-time verification and case conversion behavior [[@duhby]]

### Fixed
* [[#3840]]: Fix docs.rs build of sqlx-sqlite [[@gferon]]
* [[#3848]]: fix(macros): don't mutate environment variables [[@joeydewaal]]
* [[#3855]]: fix `attrubute` typo in doc [[@kujeger]]
* [[#3856]]: fix(macros): slightly improve unsupported type error message [[@dyc3]]

[#3830]: https://github.com/launchbadge/sqlx/pull/3830
[#3840]: https://github.com/launchbadge/sqlx/pull/3840
[#3845]: https://github.com/launchbadge/sqlx/pull/3845
[#3848]: https://github.com/launchbadge/sqlx/pull/3848
[#3849]: https://github.com/launchbadge/sqlx/pull/3849
[#3855]: https://github.com/launchbadge/sqlx/pull/3855
[#3856]: https://github.com/launchbadge/sqlx/pull/3856
[#3863]: https://github.com/launchbadge/sqlx/pull/3863
[#3866]: https://github.com/launchbadge/sqlx/pull/3866

