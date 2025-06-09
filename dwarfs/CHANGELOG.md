# Change Log

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/)
and this project adheres to [Semantic Versioning](https://semver.org/).

## v0.2.1

### Changed

### Added

- FSST symtab serialization `fsst::to_bytes`.

- DwarFS metadata serialization `Metadata::to_schema_and_bytes`.
  
  This implements basic serialization support of Frozen. It uses fixed-width
  integers and does not yet support bit-packing.

- Missed `Metadata::reg_file_size_cache` field.

- `section::Header::update_size_and_checksum`

- `section::MagicVersion::LATEST`

### Others

- Switch from `xz2` to `liblzma` crate for LZMA decompression.

- Remove unused high-level wrapper crate `zstd` and use `zstd-safe` directly.

- Add more tests.

## v0.2.0

### Changed

- `metadata::Schema::to_bytes` is now gated under a disabled-by-default
  feature `serialize`.

- `fsst` module is refactored. Failable methods of `fsst::Decoder` now returns
  `Result<_, fsst::Error>` instead of `Option<_>`.

  `Decoder::parse_symtab` is now renamed to `parse` for consistency.

### Added

- Re-export of dependency `zerocopy`.
- `section::Header::calculate_{fast,slow}_checksum`.

### Fixed

- A bug causing any valid section index to be rejected.

- False errors when loading empty archives.

- Incorrect behavior of `Dir::get`.

- An off-by-one bug when unpacking string tables.

### Others

- Added more tests.

## v0.1.0

Initial release.
