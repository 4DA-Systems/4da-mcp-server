# Changelog

## 8.0.0

### Changed

- **Breaking:** `Strict-Transport-Security` now has a max-age of 365 days, up from 180
- **Breaking:** `Content-Security-Policy` middleware now throws an error if a directive should have quotes but does not, such as `self` instead of `'self'`. See [#454](https://github.com/helmetjs/helmet/issues/454)
- **Breaking:** `Content-Security-Policy`'s `getDefaultDirectives` now returns a deep copy. This only affects users who were mutating the result
- **Breaking:** `Strict-Transport-Security` now throws an error when "includeSubDomains" option is misspelled. This was previously a warning

### Removed

- **Breaking:** Drop support for Node 16 and 17. Node 18+ is now required

## 7.2.0 - 2024-09-28

### Changed
