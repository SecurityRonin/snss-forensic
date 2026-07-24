# 7. SNSS decode contract: v3-only framing, base::Pickle fields, dialect maps, last-write-wins replay

Date: 2026-07-24
Status: Accepted

## Context

SNSS is Chromium's append-only session-command log. Its layout is not guessed — it
is taken from the Chromium reference (`components/sessions` and `base/pickle.h`,
linked in `docs/validation.md`): a `SNSS` magic, a little-endian `int32` version, a
stream of `u16`-length-prefixed command records, and navigation payloads encoded as
a `base::Pickle` (4-byte-aligned, length-prefixed fields, UTF-8 URLs, UTF-16-LE
titles). The `Session_*`/`Apps_*` files and the recently-closed `Tabs_*` files
number their commands differently. These are the load-bearing format choices a
decoder must commit to, and getting an offset, an endianness, or an alignment step
wrong ships silently-wrong output.

## Decision

Fix the decode contract to the Chromium encoding:

1. **Container framing** (`read_records`): require the 4-byte `MAGIC = b"SNSS"` and
   accept **only `SUPPORTED_VERSION = 3`** — the single version observed in the wild
   — rejecting anything else as `SnssError::UnsupportedVersion`. Records are
   `u16`-LE length prefixes where the size counts `id (1 byte) + payload`; a zero
   size or a length overrunning EOF terminates parsing as a `TruncatedTail` warning
   (ADR 0006).
2. **`base::Pickle` decode** (`decode_navigation` / `Pickle`): a 4-byte-LE length
   header followed by 4-byte-aligned fields; `i32` reads are inherently aligned,
   variable-length reads re-align to the next 4-byte boundary. URLs are
   length-prefixed **UTF-8**; titles are length-prefixed **UTF-16-LE** counted in
   code *units*, not bytes. Both decode **lossily** (`from_utf8_lossy` /
   `from_utf16_lossy`) so bad bytes become U+FFFD rather than crashing or hiding.
   The only public entry is the type-safe `decode_navigation`, so a caller cannot
   read fields out of order or forget alignment.
3. **Dialects** (`Dialect::Session` vs `Dialect::Tabs`): command-id maps differ by
   file family — navigation is command `6` in Session/Apps and `1` in Tabs; the
   selected-index command is `7` vs `4`. POD commands (`SetTabWindow`,
   `TabIndexInWindow`, `SetPinnedState`, `LastActiveTime`) carry meaning only in the
   Session dialect. `SourceKind::dialect()` picks the map per discovered file.
4. **Replay semantics** (`replay`): apply **last-write-wins per `(tab, index)`** via
   a `BTreeMap` inner key (a later append overwrites, and the tree keeps history
   sorted); resolve each tab's current entry from the selected-nav command (falling
   back to the last entry), its pinned state, and window/order; group tabs into
   windows (`Tabs` has no window mapping, so closed tabs land in a synthetic window
   `id 0`).
5. **Timestamps**: `LastActiveTime` is microseconds since the **Windows epoch**;
   `windows_micros_to_system_time` subtracts `WINDOWS_EPOCH_OFFSET_SECS =
   11_644_473_600` and rejects zero/pre-Unix values as meaningless.

## Consequences

- The decoder reproduces the per-window tab tree a browser would restore, validated
  against real Brave `Session_*`/`Tabs_*`/`Apps_*` files plus byte-exact synthetic
  streams (`docs/validation.md`).
- Restricting to version 3 is fail-loud: an unknown future version errors with the
  offending value rather than being decoded as garbage; supporting a new version is
  a deliberate, evidence-backed change, not a silent widening.
- The dialect map is the general rule for the two file families, keyed off the
  discovered `SourceKind` — not a special case per file.
- An independent differential oracle (reconciling replayed tabs against a second SNSS
  parser over a labelled public corpus) is noted as pending in `docs/validation.md`;
  today's real-data leg is a local capture-and-compare against the live session.
