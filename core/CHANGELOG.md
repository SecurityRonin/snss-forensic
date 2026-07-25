# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the crates adhere
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1](https://github.com/SecurityRonin/snss-forensic/compare/snss-core-v0.1.0...snss-core-v0.1.1) - 2026-07-25

### Fixed

- *(ci)* cover Tabs-dialect skip guard with a portable synthetic test
- *(ci)* annotate unreachable defensive match arm // cov:unreachable (nondeterministic coverage region)
- *(ci)* eliminate nondeterministic closing-brace coverage region in replay
- *(ci)* repair rustdoc link and cover unmodeled Session command arm

### Changed

- Extracted `snss-core` into its own standalone SecurityRonin workspace repo
  (`snss-forensic`), out of `browser-forensic` where it previously lived as an
  internal member crate. The crate name (`snss-core`), import path (`snss`), and
  public API are unchanged; `browser-forensic` now depends on it as an external
  crate. The two SNSS `cargo-fuzz` targets moved with it and were renamed
  `records` / `navigation`.

## [0.1.0]

### Added

- `snss-core` `0.1.0` — panic-free, read-only decoder for Chromium/Brave/Edge
  SNSS session files.
  - `read_records` — validate the `SNSS` magic + version header and split the
    command stream into length-prefixed `Record`s, surfacing a truncated final
    record as a non-fatal `Warning::TruncatedTail` rather than an error.
  - `decode_navigation` — decode a navigation command's `base::Pickle` payload
    (4-byte-aligned, length-prefixed fields) into a typed `NavCommand`.
  - `replay` — fold the command stream into the per-window `Window`/`Tab`/`Nav`
    tree (last-write-wins per `(tab, index)`, current-entry and pinned-state
    resolution), in the `Session` or `Tabs` dialect.
  - `SessionStore` — discover and read every session source in a profile
    directory, keeping per-source warnings.
  - `#![forbid(unsafe_code)]`, bounds-checked reads, a typed `SnssError`, and no
    write path. Fuzzed with `cargo-fuzz` (`records`, `navigation`).
