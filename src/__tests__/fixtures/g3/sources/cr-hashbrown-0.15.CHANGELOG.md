## [Unreleased]

## [v0.15.0] - 2024-10-01

This update contains breaking changes that remove the `raw` API with the hope of
centralising on the `HashTable` API in the future. You can follow the discussion
and progress in #545 to discuss features you think should be added to this API
that were previously only possible on the `raw` API.

### Added

- Added `borsh` feature with `BorshSerialize` and `BorshDeserialize` impls. (#525)
- Added `Assign` impls for `HashSet` operators. (#529)
- Added `Default` impls for iterator types. (#542)
- Added `HashTable::iter_hash{,_mut}` methods. (#549)
- Added `Hash{Table,Map,Set}::allocation_size` methods. (#553)
- Implemented `Debug` and `FusedIterator` for all `HashTable` iterators. (#561)
- Specialized `Iterator::fold` for all `HashTable` iterators. (#561)

### Changed

- Changed `hash_set::VacantEntry::insert` to return `OccupiedEntry`. (#495)
- Improved`hash_set::Difference::size_hint` lower-bound. (#530)
- Improved `HashSet::is_disjoint` performance. (#531)
- `equivalent` feature is now enabled by default. (#532)
- `HashSet` operators now return a set with the same allocator. (#529)
- Changed the default hasher to foldhash. (#563)
- `ahash` feature has been renamed to `default-hasher`. (#533)
- Entry API has been reworked and several methods have been renamed. (#535)
- `Hash{Map,Set}::insert_unique_unchecked` is now unsafe. (#556)
- The signature of `get_many_mut` and related methods was changed. (#562)

### Fixed

* Fixed typos, stray backticks in docs. (#558, #560)

### Removed

- Raw entry API is now under `raw-entry` feature, to be eventually removed. (#534, #555)
- Raw table API has been made private and the `raw` feature is removed;
  in the future, all code should be using the `HashTable` API instead. (#531, #546)
- `rykv` feature was removed; this is now provided by the `rykv` crate instead. (#554)
- `HashSet::get_or_insert_owned` was removed in favor of `get_or_insert_with`. (#555)

## [v0.14.5] - 2024-04-28

### Fixed
