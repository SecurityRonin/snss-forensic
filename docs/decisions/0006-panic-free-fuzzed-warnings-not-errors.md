# 6. Panic-free parsing, fuzzed, with warnings instead of hard failures

Date: 2026-07-24
Status: Accepted

## Context

A live SNSS file is routinely half-written: Brave appends to it, so the final
record can be truncated mid-write, and a single navigation `base::Pickle` can be
corrupt. A forensic reader must neither crash on such input nor silently drop the
usable records around the damage. The fleet Paranoid Gatekeeper standard requires
untrusted-input parsers to be panic-free statically (lints) and dynamically
(fuzzing), and to fail loud rather than emit a silent default.

## Decision

1. **Static panic-free posture.** The workspace denies `clippy::unwrap_used` and
   `clippy::expect_used` (`Cargo.toml [workspace.lints.clippy]`, priority 0), with
   tests opting out via `#![cfg_attr(test, allow(...))]` and `clippy.toml`
   (`allow-unwrap-in-tests`). Every length, offset, and alignment step is
   bounds-checked before use — `Pickle` reads use `checked_add`/`checked_mul` and
   `end > len` guards; the two remaining `unwrap_or([0u8;4])` fallbacks sit behind a
   proven-`>= len` guard and are documented as unreachable defence-in-depth.
2. **Dynamic fuzzing.** Two `cargo-fuzz` targets run over arbitrary bytes with the
   invariant "must not panic": `records` (header + `u16` record framing) and
   `navigation` (the `base::Pickle` field decode) — `fuzz/fuzz_targets/`.
3. **Non-fatal anomalies are surfaced, never dropped.** A truncated tail, a bad
   navigation Pickle, or an unreadable source becomes a typed `Warning`
   (`TruncatedTail` / `BadNavigation` / `UnreadableSource`) carried on the model,
   not an early return of empty. Only a bad magic or unsupported version is a hard
   `SnssError` (fail-loud on the container contract). The distinction is deliberate:
   a wrong container is a bootstrap failure; a torn tail is a per-record miss.

## Consequences

- Malformed evidence degrades to a typed error or a partial-plus-warnings result,
  never a crash or a silently-clean empty model (which would be indistinguishable
  from a genuinely empty session).
- The `// cov:unreachable` annotations keep the defensive guards in place under the
  100 %-line gate rather than deleting them to turn a line green.
- The two fuzz targets are maintained surface, built and smoke-run in CI
  (`fuzz.yml`), and are the empirical half of the "fuzzed + panic-free-by-lint"
  pairing the README claims (evidence, not a bare "panic-free" absolute).
