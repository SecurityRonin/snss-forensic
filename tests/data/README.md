# snss-forensic test data

This repo's decode tests use two sources, neither of which commits binary
fixtures:

## Real Brave SNSS fixtures — gitignored (personal data)

Real Brave `Session_*` / `Tabs_*` / `Apps_*` files contain personal browsing
history and are **never committed**. They live (when present locally) under
`core/tests/fixtures/`, which is gitignored except for a `.gitkeep` placeholder
(`core/tests/fixtures/*` ignored; `!…/.gitkeep` tracked).

- **Source / Identity**: the most recent session files from a locally installed
  Brave browser profile.
- **Generator (capture command)**: `scripts/copy-fixtures.sh` — copies the
  newest `Session_`/`Tabs_`/`Apps_` files from
  `$HOME/Library/Application Support/BraveSoftware/Brave-Browser/Default/Sessions`
  (override with `BRAVE_SESSIONS_DIR`) into `core/tests/fixtures/` as
  `Session_real` / `Tabs_real` / `Apps_real`.
- **MD5**: not applicable — host-specific, regenerated per machine, never
  committed.
- On CI or a fresh clone the fixtures are absent; the real-bytes tests
  (`open_fixture_or_skip` in `core/tests/common/mod.rs`) **skip loudly** rather
  than failing, and the synthetic builders still guard every decode path.

## Synthetic SNSS command streams — committed in code (no PII)

Byte-exact SNSS v3 files are assembled in-code by the builders in
`core/tests/common/mod.rs` (module `build`): `snss()` frames records the way
Chromium writes them (4-byte `SNSS` magic, LE version 3, `u16`-length records),
and `nav()` / `pair()` / `pinned()` / `last_active()` produce the
`base::Pickle` and POD payloads. There is no binary fixture to hash — the
generator is the Rust builder functions at
`core/tests/common/mod.rs` (module `build`).

See `docs/validation.md` for the validation methodology and the fleet catalog
`issen/docs/corpus-catalog.md` for the machine index.
