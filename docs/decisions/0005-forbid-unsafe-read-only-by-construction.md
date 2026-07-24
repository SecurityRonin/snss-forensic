# 5. `forbid(unsafe)` and read-only by construction

Date: 2026-07-24
Status: Accepted

## Context

SNSS files are untrusted, attacker-controllable input. The fleet's Paranoid
Gatekeeper standard makes `unsafe_code = "forbid"` the default and the goal — a
provable "zero places a crafted input can corrupt memory" — and downgrades to
`deny` + a bounded per-site `#[allow]` **only** for a real benefit such as an
`mmap` (as `ewf` and `memory-forensic` do). `snss-core` reads whole session files
into memory (`read_records` calls `read_to_end`; `decode_source` calls
`std::fs::read`), so it has **no mmap and no reason to relax the forbid**.

Separately, a forensic reader must never be able to mutate the evidence it reads.
The concern here is a live browser store — the same `Sessions/` directory Brave is
appending to.

## Decision

1. Set **`unsafe_code = "forbid"`** across the whole workspace
   (`Cargo.toml [workspace.lints.rust]`), inherited by `snss-core` via
   `[lints] workspace = true`. There are no `#[allow(unsafe_code)]` sites; the
   README carries the `unsafe forbidden` badge, which is honest because the crate is
   genuinely `forbid` (not `deny` + allow).
2. Make the API **read-only by construction**: the crate exposes **no write path**
   at all. `SessionStore` snapshots bytes into an immutable in-memory model
   (`decode_source` reads the file fully "so a concurrent Brave rewrite can't tear
   the decode"); there is no method that writes back to a session file. Mutating a
   browser's store through this API is structurally impossible, not merely
   discouraged (Secure by Design).

## Consequences

- Memory safety on crafted input is compiler-*proved*, not asserted — the strongest
  differentiator for an evidence parser.
- Evidence immutability holds by API shape, so no caller (or future maintainer) can
  accidentally introduce a write; the guarantee cannot be forgotten because there is
  nothing to call.
- Reading each file fully before decoding costs memory proportional to the largest
  session file, accepted as the price of a tear-free, immutable snapshot.
