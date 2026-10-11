This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 1.27.0 (20 Feb 2024)
Enhancements:
* [#1378][]: Add `WithLazy` method for `SugaredLogger`.
* [#1399][]: zaptest: Add `NewTestingWriter` for customizing TestingWriter with more flexibility than `NewLogger`.
* [#1406][]: Add `Log`, `Logw`, `Logln` methods for `SugaredLogger`.
* [#1416][]: Add `WithPanicHook` option for testing panic logs.

Thanks to @defval, @dimmo, @arxeiss, and @MKrupauskas for their contributions to this release.

[#1378]: https://github.com/uber-go/zap/pull/1378
[#1399]: https://github.com/uber-go/zap/pull/1399
[#1406]: https://github.com/uber-go/zap/pull/1406
[#1416]: https://github.com/uber-go/zap/pull/1416

## 1.26.0 (14 Sep 2023)
Enhancements:
* [#1297][]: Add Dict as a Field.
* [#1319][]: Add `WithLazy` method to `Logger` which lazily evaluates the structured
context.
* [#1350][]: String encoding is much (~50%) faster now.

Thanks to @hhk7734, @jquirke, and @cdvr1993 for their contributions to this release.

[#1297]: https://github.com/uber-go/zap/pull/1297
[#1319]: https://github.com/uber-go/zap/pull/1319
[#1350]: https://github.com/uber-go/zap/pull/1350

## 1.25.0 (1 Aug 2023)

This release contains several improvements including performance, API additions,
and two new experimental packages whose APIs are unstable and may change in the
future.

Enhancements:
* [#1246][]: Add `zap/exp/zapslog` package for integration with slog.
* [#1273][]: Add `Name` to `Logger` which returns the Logger's name if one is set.
* [#1281][]: Add `zap/exp/expfield` package which contains helper methods
`Str` and `Strs` for constructing String-like zap.Fields.
* [#1310][]: Reduce stack size on `Any`.

Thanks to @knight42, @dzakaammar, @bcspragu, and @rexywork for their contributions
to this release.

[#1246]: https://github.com/uber-go/zap/pull/1246
[#1273]: https://github.com/uber-go/zap/pull/1273
[#1281]: https://github.com/uber-go/zap/pull/1281
[#1310]: https://github.com/uber-go/zap/pull/1310

## 1.24.0 (30 Nov 2022)

Enhancements:
