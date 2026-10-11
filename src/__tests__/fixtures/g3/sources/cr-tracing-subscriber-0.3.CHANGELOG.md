# 0.3.0 (Oct 22, 2021)

This is a breaking release of `tracing-subscriber`. The primary breaking change
in this release is the removal of the dependency on the [`chrono` crate], due to
[RUSTSEC-2020-0159]. To replace `chrono`, support is added for formatting
timestamps using the [`time` crate] instead.

In addition, this release includes a number of other breaking API changes, such
as adding (limited) support for `#![no_std]` targets, removing previously
deprecated APIs, and more.

### Breaking Changes

- Removed APIs deprecated in the v0.2.x release series.
- Renamed `Layer::new_span` to `Layer::on_new_span` ([#1674])
- Removed `Layer` impl for `Arc<L: Layer<S>>` and `Arc<dyn Layer<S> + ...>`
  ([#1649])
- Replaced the [`chrono` crate] with the [`time` crate] for timestamp formatting, to
  resolve [RUSTSEC-2020-0159] ([#1646])
- Removed `json` and `env-filter` from default features. They must now be
  enabled explictly ([#1647])
- Changed `FormatEvent::format_event` and `FormatFields::format_fields`
  trait methods to take a `Writer` type, rather than a `&mut dyn fmt::Write`
  trait object ([#1661])
- Changed the signature of the `MakeWriter` trait by adding a lifetime parameter
  ([#781])
### Changed

- **layer**: Renamed `Layer::new_span` to `Layer::on_new_span` ([#1674])
- **fmt**: Changed `FormatEvent::format_event` and `FormatFields::format_fields`
  trait methods to take a `Writer` type, rather than a `&mut dyn fmt::Write`
  trait object ([#1661])
- **json**, **env-filter**: `json` and `env-filter` feature flags are no longer
  enabled by default ([#1647])
### Removed

- Removed deprecated `CurrentSpan` type ([#1320])
- **registry**: Removed deprecated `SpanRef::parents` iterator, replaced by
  `SpanRef::scope` in [#1431] ([#1648)])
- **layer**: Removed deprecated `Context::scope` iterator, replaced by
  `Context::span_scope` and `Context::event_scope` in [#1431] and [#1434]
  ([#1648)])
- **layer**: Removed `Layer` impl for `Arc<L: Layer<S>>` and
   `Arc<dyn Layer<S> + ...>`. These interfere with per-layer filtering. ([#1649])
- **fmt**: Removed deprecated `LayerBuilder` type ([#1673])
- **fmt**: Removed `fmt::Layer::on_event` (renamed to `fmt::Layer::fmt_event`)
  ([#1673])
- **fmt**, **chrono**: Removed the `chrono` feature flag and APIs for using the
  [`chrono` crate] for timestamp formatting ([#1646])
### Added

- **fmt**, **time**: `LocalTime` and `UtcTime` types for formatting timestamps
  using the [`time` crate] ([#1646])
- **fmt**: Added a lifetime parameter to the `MakeWriter` trait, allowing it to
  return a borrowed writer. This enables implementations of `MakeWriter` for
  types such as `Mutex<T: io::Write>` and `std::fs::File`. ([#781])
- **env-filter**: Documentation improvements ([#1637])
- Support for some APIs on `#![no_std]` targets, by disabling the `std` feature
  flag ([#1660])

Thanks to @Folyd and @nmathewson for contributing to this release!

[#1320]: https://github.com/tokio-rs/tracing/pull/1320
[#1673]: https://github.com/tokio-rs/tracing/pull/1673
[#1674]: https://github.com/tokio-rs/tracing/pull/1674
[#1646]: https://github.com/tokio-rs/tracing/pull/1646
[#1647]: https://github.com/tokio-rs/tracing/pull/1647
[#1648]: https://github.com/tokio-rs/tracing/pull/1648
[#1649]: https://github.com/tokio-rs/tracing/pull/1649
[#1660]: https://github.com/tokio-rs/tracing/pull/1660
[#1661]: https://github.com/tokio-rs/tracing/pull/1661
[#1431]: https://github.com/tokio-rs/tracing/pull/1431
[#1434]: https://github.com/tokio-rs/tracing/pull/1434
[#781]: https://github.com/tokio-rs/tracing/pull/781

[`chrono` crate]: https://crates.io/crates/chrono
[`time` crate]: https://crates.io/crates/time
[RUSTSEC-2020-0159]: https://rustsec.org/advisories/RUSTSEC-2020-0159.html

# 0.2.25 (October 5, 2021)

This release fixes an issue where a `Layer` implementation's custom
