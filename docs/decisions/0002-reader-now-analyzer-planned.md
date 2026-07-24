# 2. Repo shape: ship the reader now, keep the analyzer a documented plan

Date: 2026-07-24
Status: Accepted

## Context

The fleet's Crate-structure standard (ronin-issen `CLAUDE.md`, "reader/analyzer
split") makes a single-format repo a **Pattern A** pair: `<x>-core` (the raw
reader/parser, no findings) plus `<x>-forensic` (the anomaly auditor emitting
`forensicnomicon::report::Finding`). The repo is named after the analyzer headline
(`snss-forensic`) even when it also holds the core crate.

For SNSS, only the reader exists today. The workspace manifest declares a single
member (`Cargo.toml`: `members = ["core"]`), and no analyzer logic was carried over
from browser-forensic, where the SNSS consumer was a `BrowserEvent` adapter rather
than a set of separable graded findings (ADR 0001).

## Decision

Ship `snss-core` now and keep the `snss-forensic` analyzer an explicit, honestly
labelled plan rather than a stub:

1. The workspace has exactly one member, `core/` → `snss-core` — the raw reader
   (`read_records`, `decode_navigation`, `replay`, `SessionStore`), which makes no
   forensic judgments.
2. The `snss-forensic` analyzer — severity-graded `forensicnomicon::report`
   findings for session-restore anomalies (dangling/forward-referenced tab indices,
   truncated-tail recovery, replay inconsistencies) — is documented as a planned
   follow-up in both `README.md` ("Planned: the `snss-forensic` analyzer") and
   `docs/validation.md` ("Pending"). No analyzer logic is stubbed or fabricated.

## Consequences

- The repo already carries the analyzer-headline name and layout, so adding the
  `forensic/` member later is additive, not a restructure.
- Consumers that want graded findings today wire the reader's typed model
  (`Warning`, `Replayed`) themselves; the uniform `forensicnomicon::report`
  aggregation waits for the analyzer.
- The plan is stated as a plan (per the fleet anti-fabrication rule) — a reader is
  never misled into thinking analysis ships when only decoding does.
