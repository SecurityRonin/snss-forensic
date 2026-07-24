# 1. Extract snss-core out of browser-forensic into a standalone fleet repo

Date: 2026-07-24
Status: Accepted

## Context

The Chromium/Brave/Edge SNSS session-file decoder was originally authored **inside
`browser-forensic`**, under that suite's aggregate coverage bar and lint set. The
`clippy.toml` note ("the set snss-core was authored under in browser-forensic") and
the workspace lint comment both still record this origin.

Two problems followed from that home. A downstream Rust tool that only wanted an
SNSS reader had to pull the whole browser-forensic suite; and the SNSS decoder sat
under browser-forensic's **89.4 % aggregate coverage** rather than the fleet's
per-`*-core` **100 % line** gate, so its own robustness was diluted into a suite
average. The fleet had already proven the standalone-single-format shape with
`segb-forensic`.

## Decision

Promote the decoder into its own SecurityRonin workspace, `snss-forensic`, modeled
on `segb-forensic` (commit `69c9fd9`, "extract snss-core into its own snss-forensic
fleet repo"):

1. The `core/` member is `snss-core` (name unchanged, `[lib] name = "snss"`), with
   full workspace inheritance of `version`/`edition`/`rust-version`/`license`/
   `authors`/`repository` (`Cargo.toml [workspace.package]`).
2. The full fleet hygiene set was copied and adapted from `segb-forensic`: CI
   (fmt/clippy/test/MSRV/100 %-line coverage/deny/fuzz/docs), `docs.yml` (mkdocs
   Pages), scheduled `fuzz.yml`, `deny.toml`, `clippy.toml`, `rustfmt.toml`,
   `.gitleaks.toml`, `.pre-commit-config.yaml`, `renovate.json`, `LICENSE`
   (Apache-2.0), README, CONTRIBUTING, SECURITY, and `docs/`.
3. Both SNSS `cargo-fuzz` targets were moved here and renamed `records` /
   `navigation` (`fuzz/fuzz_targets/`).
4. `core/tests/coverage.rs` was added to lift the crate to **100 % line coverage**
   under the fleet `*-core` gate; two genuinely-unreachable defensive arms are
   annotated `// cov:unreachable`.

## Consequences

- A consumer that needs only an SNSS reader depends on `snss-core` alone, decoupled
  from the browser-forensic suite (Dependency Preference / DRY: one reader, reused).
- The decoder is now held to the per-`*-core` 100 %-line gate rather than a suite
  average, so its own robustness is measured directly.
- The analyzer question is deferred, not answered here: no separable
  `forensicnomicon::report` SNSS findings existed in browser-forensic (its consumer
  was a `BrowserEvent` adapter), so `snss-forensic` the analyzer is documented as a
  planned follow-up, not fabricated (see ADR 0002).
- `browser-forensic` continues to consume the decoder through the published crate.
