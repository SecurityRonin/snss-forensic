# 8. Low CI-verified MSRV (1.81) separate from the pinned dev toolchain

Date: 2026-07-24
Status: Accepted

## Context

The fleet MSRV policy separates the **dev toolchain** (what the fleet builds,
formats, and lints with — one pinned current stable, the single source of truth in
`rust-toolchain.toml`) from the **declared MSRV** (`rust-version`, a
downstream-facing promise). Published libraries keep a **low, CI-verified MSRV** as
a deliberate compatibility feature; apps declare MSRV = the pinned toolchain.
`snss-core` is a published library (ADR 0001/0003), so it takes the library side of
this split.

## Decision

1. Declare **`rust-version = "1.81"`** once in `Cargo.toml [workspace.package]`,
   inherited by `snss-core`. The README badge (`Rust 1.81+`) and a dedicated CI MSRV
   job (from the segp-modeled hygiene set, commit `69c9fd9`) verify it — the low
   floor is a real, tested guarantee, not an aspiration.
2. Pin the **dev toolchain** to the current fleet stable in `rust-toolchain.toml`
   (`channel = "1.96.0"`, `components = ["clippy", "rustfmt"]`; commit `6650d5b`).
   Develop, format, and lint on 1.96.0; only *promise* 1.81.
3. Because the pinned toolchain overrides channel refs, `cargo-fuzz` is forced onto
   nightly explicitly (`cargo +nightly`, commit `2e4605c`) so its `-Z` flags are
   accepted.

## Consequences

- The crate stays consumable by older toolchains (a crates.io trust signal), while
  contributors and CI share one modern toolchain — no fmt/clippy drift.
- Raising the declared MSRV later is a near-breaking change requiring a real reason
  (a genuinely-needed newer-Rust feature), never a bump merely to match 1.96.0.
- Cross-cutting release gotchas that flow from the pin (e.g. matching a cross-build
  toolchain to avoid `E0463`) apply if this repo ever ships binaries; today it
  publishes only a library.
