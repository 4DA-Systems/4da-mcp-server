and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [4.0.0] - 2021-01-03
### Changed
- Check [migration guide](migrate_v3_to_v4.md) to see details for all breaking changes.
- Breaking: "unsafe" tags `!!js/function`, `!!js/regexp`, `!!js/undefined` are
  moved to [js-yaml-js-types](https://github.com/nodeca/js-yaml-js-types) package.
- Breaking: removed `safe*` functions. Use `load`, `loadAll`, `dump`
  instead which are all now safe by default.
- `yaml.DEFAULT_SAFE_SCHEMA` and `yaml.DEFAULT_FULL_SCHEMA` are removed, use
  `yaml.DEFAULT_SCHEMA` instead.
- `yaml.Schema.create(schema, tags)` is removed, use `schema.extend(tags)` instead.
- `!!binary` now always mapped to `Uint8Array` on load.
- Reduced nesting of `/lib` folder.
- Parse numbers according to YAML 1.2 instead of YAML 1.1 (`01234` is now decimal,
  `0o1234` is octal, `1:23` is parsed as string instead of base60).
- `dump()` no longer quotes `:`, `[`, `]`, `(`, `)` except when necessary, #470, #557.
- Line and column in exceptions are now formatted as `(X:Y)` instead of
  `at line X, column Y` (also present in compact format), #332.
- Code snippet created in exceptions now contains multiple lines with line numbers.
- `dump()` now serializes `undefined` as `null` in collections and removes keys with
  `undefined` in mappings, #571.
- `dump()` with `skipInvalid=true` now serializes invalid items in collections as null.
- Custom tags starting with `!` are now dumped as `!tag` instead of `!<!tag>`, #576.
- Custom tags starting with `tag:yaml.org,2002:` are now shorthanded using `!!`, #258.

### Added
- Added `.mjs` (es modules) support.
- Added `quotingType` and `forceQuotes` options for dumper to configure
  string literal style, #290, #529.
- Added `styles: { '!!null': 'empty' }` option for dumper
  (serializes `{ foo: null }` as "`foo: `"), #570.
- Added `replacer` option (similar to option in JSON.stringify), #339.
- Custom `Tag` can now handle all tags or multiple tags with the same prefix, #385.

### Fixed
- Astral characters are no longer encoded by `dump()`, #587.
- "duplicate mapping key" exception now points at the correct column, #452.
- Extra commas in flow collections (e.g. `[foo,,bar]`) now throw an exception
  instead of producing null, #321.
- `__proto__` key no longer overrides object prototype, #164.
- Removed `bower.json`.
- Tags are now url-decoded in `load()` and url-encoded in `dump()`
  (previously usage of custom non-ascii tags may have led to invalid YAML that can't be parsed).
- Anchors now work correctly with empty nodes, #301.
- Fix incorrect parsing of invalid block mapping syntax, #418.
- Throw an error if block sequence/mapping indent contains a tab, #80.


## [3.14.1] - 2020-12-07
### Security
- Fix possible code execution in (already unsafe) `.load()` (in &anchor).
