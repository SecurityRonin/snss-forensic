# 4. Zero-dependency, std-only decoder

Date: 2026-07-24
Status: Accepted

## Context

SNSS is a self-contained binary format: a `SNSS` magic, a little-endian version
header, `u16`-length-prefixed records, and a Chromium `base::Pickle` field encoding
(4-byte alignment, LE integers, UTF-8 / UTF-16-LE strings). Decoding it needs
integer reads, bounds checks, UTF-8/UTF-16 conversion, and directory globbing —
all of which the Rust standard library provides.

The fleet's default for fixed-width integer reads is the audited `safe-read` crate
(ronin-issen `CLAUDE.md`, Paranoid Gatekeeper), specifically to avoid hand-rolled
`bytes.rs` copies that drift. That default assumes a crate is willing to take a
dependency.

## Decision

Keep `snss-core` **dependency-free**: `core/Cargo.toml` declares no `[dependencies]`
section at all, and `core/src/lib.rs` uses only `std` (`std::io::Read`,
`std::collections`, `std::path`, `std::time`, `String::from_utf8_lossy` /
`from_utf16_lossy`). The README states this as a property ("no C bindings, no write
path").

Consequently the bounds-checked field reads are written **inline** rather than
routed through `safe-read`: `Pickle::read_i32` / `read_string` / `read_string16`
use `checked_add` / `checked_mul` and explicit `end > len` guards, and the POD
readers (`pod_pair`, `pod_pinned`, `pod_last_active`) length-check before
`try_into`. The whole set is small, local, and fuzzed (ADR 0006).

## Consequences

- The crate compiles fast, has a trivial supply-chain surface (nothing for
  `cargo deny` / `cargo vet` to review beyond std), and imposes no transitive MSRV
  bump on consumers.
- It **diverges from the fleet `safe-read` default**: the bounds-checked reads are
  a hand-rolled, per-crate set. This is an accepted trade for zero dependencies on a
  small, fuzzed surface; migrating the integer reads onto `safe-read` (which would
  add the crate's first dependency) is the fleet-aligned follow-up if the surface
  grows.
- Adding the future `snss-forensic` analyzer (which must depend on
  `forensicnomicon`) does not disturb the reader's zero-dep posture — the dependency
  lives in the analyzer member, not `snss-core`.
