# Validation Status

## Summary

**`snss-core` is validated against real Chromium/Brave SNSS files plus
byte-exact synthetic command streams. The container framing, record splitting,
`base::Pickle` navigation decode, and window/tab replay are exercised end to
end; the layout is sourced from the Chromium reference.**

`snss-core` is a read-only decoder. Its byte layout — the `SNSS` magic, the
little-endian version header, the `u16`-length-prefixed command records, and the
4-byte-aligned `base::Pickle` field encoding — is taken from the Chromium source
(see [Reference Implementations](#reference-implementations)), not guessed. Two
validation legs back it:

1. **Real on-disk bytes** — real Brave `Session_*` / `Tabs_*` / `Apps_*` files
   are read with `read_records` and replayed; the decoded URLs and titles match
   the live session they were captured from.
2. **Byte-exact synthetic streams** — the test builders in
   `core/tests/common/mod.rs` assemble known `(command_id, payload)` records the
   same way Chromium writes them (LE length headers, UTF-8 URLs, UTF-16-LE
   titles, POD pairs padded to alignment), so each decode path is pinned against
   a known-answer input.

## What has been validated

| Claim | Method | Status |
|---|---|---|
| `SNSS` magic + version header (v3) | `read_records` validates magic and version; `record_reader.rs` | ✅ |
| `u16`-length-prefixed record framing | Byte-exact synthetic streams + real files (`record_reader.rs`) | ✅ |
| Truncated final record → non-fatal `Warning::TruncatedTail` | Crafted truncated stream (`record_reader.rs`) | ✅ |
| Non-`SNSS` header → hard error, never a silent empty model | `record_reader.rs` | ✅ |
| `base::Pickle` navigation decode (4-byte-aligned, length-prefixed fields) | Byte-exact synthetic `UpdateTabNavigation` payloads + real files (`pickle.rs`) | ✅ |
| Window/tab replay (last-write-wins per `(tab, index)`, current-entry/pinned resolution) | Synthetic command logs in both dialects (`replay.rs`) | ✅ |
| Profile-directory discovery + per-source warnings | Synthetic SNSS files in a temp dir (`discovery.rs`) | ✅ |
| Real Brave session decode | `open_fixture_or_skip` over gitignored real fixtures | ✅ Real-data validated (locally) |

## Real fixtures are gitignored

Real Brave SNSS files hold personal browsing history, so they are **never
committed** (`core/tests/fixtures/*` is gitignored; only a `.gitkeep`
placeholder is tracked). On CI or a fresh clone they are absent, and the
real-bytes tests **skip loudly** (naming the missing file) rather than failing —
the synthetic builders still guard every decode path portably.

To run the real-bytes leg locally on a machine with Brave installed:

```bash
scripts/copy-fixtures.sh           # copies the newest Session_/Tabs_/Apps_ files
cargo test --workspace             # the *_real fixtures are now read and replayed
```

## Robustness

`snss-core` parses untrusted, attacker-controllable input:

- **`#![forbid(unsafe_code)]`** across the workspace.
- **Panic-free** — every record length, Pickle field length, and alignment step
  is bounds-checked before use; a crafted length cannot drive an out-of-bounds
  read or an allocation bomb. Malformed input surfaces as a typed `SnssError` or
  a non-fatal `Warning`, never a silent default.
- **Fuzzed** — `cargo-fuzz` targets `records` (header + record framing) and
  `navigation` (Pickle field decode) run over arbitrary bytes; the invariant is
  "must not panic."

## Reference Implementations

- **Chromium / `components/sessions`** — the canonical SNSS writer/reader:
  - `SessionCommand` framing (`u16` size + id + payload):
    <https://source.chromium.org/chromium/chromium/src/+/main:components/sessions/core/session_command.h>
  - `SessionFileReader` / `SessionBackend` (the `SNSS` magic + version header,
    append-only log):
    <https://source.chromium.org/chromium/chromium/src/+/main:components/sessions/core/command_storage_backend.cc>
  - `base::Pickle` field encoding (4-byte alignment, length-prefixed strings):
    <https://source.chromium.org/chromium/chromium/src/+/main:base/pickle.h>

## Pending

- A scripted differential oracle (e.g. reconciling `snss-core`'s replayed tabs
  against a second independent SNSS parser) over a labelled public corpus is a
  recommended next step; today the real-data leg is a local capture-and-compare
  against the live session rather than an automated reconciliation.
- The `snss-forensic` analyzer (graded `forensicnomicon::report` findings for
  session-restore anomalies) is a planned follow-up — no analyzer logic exists
  yet and none is fabricated.
