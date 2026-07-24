# 3. Crate naming: publish `snss-core`, import as `snss`

Date: 2026-07-24
Status: Accepted

## Context

The fleet Crate naming grammar (ronin-issen `CLAUDE.md`) fixes the single-format
shape: the reader is always `<x>-core` and the analyzer always `<x>-forensic`. It
also lets a `<x>-core` crate keep a clean **import path** by setting
`[lib] name = "<x>"`, so consumers write `use <x>::…` even though the published
package is `<x>-core`. The repo itself is named after the analyzer headline
(`snss-forensic`), which is the umbrella, not a crate.

## Decision

1. Publish the reader as package **`snss-core`** (`core/Cargo.toml`:
   `name = "snss-core"`), with **`[lib] name = "snss"`** so the import path is the
   short, natural `snss` (`use snss::read_records`). This is exactly the pattern
   the README and quick-start show (`snss-core = "0.1"` in `Cargo.toml`,
   `snss::read_records` in code) and the extraction commit records ("name
   unchanged, `[lib] name = "snss"`").
2. Reserve the `snss-forensic` **package** name for the future analyzer; the repo
   already bears it as the umbrella (ADR 0002).
3. Share the reader across the workspace through
   `snss = { version = "0.1", path = "core", package = "snss-core" }`
   (`[workspace.dependencies]`) so a future member links it by one line.

## Consequences

- External and internal consumers get the ergonomic `use snss::…` path while
  crates.io shows the self-describing `snss-core` name (grammar-compliant).
- The `-core`/`-forensic` split is reserved up front, so the analyzer lands without
  renaming the reader (a crates.io rename after the 72 h window is a permanent
  orphan).
- Rationale for the exact `-core`-suffix-with-`snss`-lib-name choice is the fleet
  naming grammar cited above; it is grammar-driven, not a response to a specific
  third-party collision recovered from history.
