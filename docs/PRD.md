# snss-forensic — Purpose & Scope

*A library-tier intent document, reverse-written from a same-session read of the repo
(`core/src/lib.rs`, `Cargo.toml`, `README.md`, `docs/validation.md`; 2026-07-24). The
load-bearing decisions live as ADRs under [`docs/decisions/`](decisions/); this file
states what the crate is, who links it, and where its boundaries sit. It is not a
product PRD — `snss-forensic` ships a linked library, not a binary an examiner runs.*

## What this is

`snss-forensic` is a SecurityRonin fleet workspace whose one shipping member,
**`snss-core`** (import path `snss`), is a **read-only decoder for Chromium-family
SNSS session files** — the `Session_*`, `Tabs_*`, and `Apps_*` files (and the modern
`Sessions/` folder) behind a browser's "restore your tabs". It:

- validates the `SNSS` magic + little-endian version header and splits the
  append-only stream into `u16`-length-prefixed command records (`read_records`);
- decodes navigation-command `base::Pickle` payloads into `NavCommand` (tab, index,
  URL, title) — `decode_navigation`;
- replays the command log into the per-window tab tree a browser would restore, with
  last-write-wins per `(tab, index)`, current-entry/pinned resolution, and
  Windows-epoch last-active timestamps (`replay`);
- globs a profile's `Sessions/` directory into typed, decoded `Source`s with
  per-source warnings (`SessionStore::open_dir` / `open_default_profile`).

The byte layout is taken from the Chromium `components/sessions` and `base::Pickle`
reference, not guessed (see [`docs/validation.md`](validation.md) and ADR
[0007](decisions/0007-snss-decode-contract.md)).

## Who links it

- **`browser-forensic`** — the suite this decoder was extracted from (ADR
  [0001](decisions/0001-extract-snss-core-into-standalone-repo.md)); it consumes the
  reader through a `BrowserEvent` adapter.
- **Issen orchestration** and any fleet analyzer that needs browser session/tab
  state, via the published `snss-core` crate.
- **Any third-party Rust tool** wanting a dependency-free SNSS reader — the crate is
  independently consumable (`snss-core = "0.1"`; `use snss::read_records`).

## Scope

- Decode SNSS container framing, `base::Pickle` navigation payloads, and the POD
  commands needed to reconstruct windows/tabs (`SetTabWindow`, `TabIndexInWindow`,
  selected-nav-index, `SetPinnedState`, `LastActiveTime`).
- Support both file-family dialects: `Session`/`Apps` and recently-closed `Tabs`.
- Discover and decode a whole profile `Sessions/` directory, keeping non-fatal
  anomalies as typed `Warning`s.
- Container version **3 only** — the version observed in the wild; anything else is a
  loud `SnssError`, never a silent decode.

## Non-goals

- **No write path.** The API cannot mutate a browser's session store; evidence
  immutability holds by construction (ADR
  [0005](decisions/0005-forbid-unsafe-read-only-by-construction.md)).
- **No forensic judgments yet.** `snss-core` reads and models; it emits no
  severity-graded findings. The `snss-forensic` **analyzer** —
  `forensicnomicon::report` findings for session-restore anomalies (dangling or
  forward-referenced tab indices, truncated-tail recovery, replay inconsistencies) —
  is a documented, unimplemented plan (ADR
  [0002](decisions/0002-reader-now-analyzer-planned.md)), not a stub.
- **No UI, no CLI/TUI/MCP binary.** This is a linked library; front ends live in
  consumer repos.
- **No `unsafe`, no C bindings, no third-party dependencies** in the reader (ADRs
  [0004](decisions/0004-zero-dependency-std-only-decoder.md),
  [0005](decisions/0005-forbid-unsafe-read-only-by-construction.md)).

## Artifact family

Chromium-family SNSS session files as written by Brave / Chrome / Edge: `Session_*`
(live/last windows), `Tabs_*` (recently-closed restore list), `Apps_*` (PWA/app
windows), and the modern per-source `Sessions/` folder. Filenames rotate while the
browser runs, so discovery globs the family prefix and ranks by the numeric
(Windows-epoch) filename suffix rather than mtime — a copied/imaged profile keeps its
names even when mtime is reset.

## Robustness & validation approach

SNSS files are untrusted, attacker-controllable input, so the crate is hardened by
construction and validated on real data:

- **Panic-free by lint + fuzzed** — `unwrap_used`/`expect_used` denied,
  bounds-checked reads, and two `cargo-fuzz` targets (`records`, `navigation`) whose
  invariant is "must not panic" (ADR
  [0006](decisions/0006-panic-free-fuzzed-warnings-not-errors.md)).
- **Real + synthetic legs** — real Brave `Session_*`/`Tabs_*`/`Apps_*` files are read
  and replayed (fixtures gitignored — they hold personal history; the tests skip
  loudly when absent), alongside byte-exact synthetic command streams that pin each
  decode path to a known answer. Full detail in
  [`docs/validation.md`](validation.md).
- **100 % line coverage** under the fleet `*-core` gate, with genuinely-unreachable
  defensive arms annotated `// cov:unreachable` rather than deleted.
- **Pending:** an independent differential oracle (reconciling replayed tabs against a
  second SNSS parser over a labelled public corpus) — noted honestly as a next step,
  not claimed as done.

## MSRV & toolchain

Declared MSRV **1.81** (low, CI-verified — a compatibility promise for downstream
consumers), separate from the pinned **1.96.0** dev toolchain (ADR
[0008](decisions/0008-low-msrv-floor-vs-pinned-toolchain.md)).
