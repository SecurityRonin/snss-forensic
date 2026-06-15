# snss-forensic

[![snss-core](https://img.shields.io/crates/v/snss-core.svg?label=snss-core)](https://crates.io/crates/snss-core)
[![Docs.rs](https://img.shields.io/docsrs/snss-core?label=docs.rs)](https://docs.rs/snss-core)
[![Rust 1.81+](https://img.shields.io/badge/rust-1.81%2B-orange.svg)](https://www.rust-lang.org)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

[![CI](https://github.com/SecurityRonin/snss-forensic/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/snss-forensic/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/badge/coverage-100%25%20lines-brightgreen.svg)](https://github.com/SecurityRonin/snss-forensic/actions/workflows/ci.yml)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/)
[![Security advisories](https://img.shields.io/badge/security-cargo--deny-informational.svg)](deny.toml)

**Chromium/Brave/Edge SNSS session-file forensics for Rust — a panic-free,
read-only decoder that validates the `SNSS` command stream, splits it into
length-prefixed records, decodes navigation-command `base::Pickle` payloads, and
replays them into the per-window tab state a browser restores on launch.**

SNSS is the append-only command-log format Chromium-family browsers use to persist
session and tab state — the `Session_*`, `Tabs_*`, and `Apps_*` files (and the
modern `Sessions/` folder) behind "restore your tabs". Each file is a 4-byte
`SNSS` magic plus a version header, followed by `u16`-length-prefixed command
records; navigation commands carry a Chromium `base::Pickle` payload.
[`snss-core`](https://crates.io/crates/snss-core) decodes that structure faithfully
and makes no judgments — no `unsafe`, no C bindings, no write path.

## Read a session file in 30 seconds

```toml
[dependencies]
snss-core = "0.1"
```

```rust
use std::io::Cursor;

// 1. Validate the SNSS header and split the command stream into records.
let stream = snss::read_records(Cursor::new(bytes))?;

// 2. Replay the commands into the per-window tab tree the browser would restore.
let replayed = snss::replay(&stream, snss::Dialect::Session);
for window in &replayed.windows {
    for tab in &window.tabs {
        let nav = tab.current_nav();   // the current entry of each open tab
        println!("tab {} -> {}  ({})", tab.id, nav.url, nav.title);
    }
}

// Non-fatal anomalies (a truncated live-file tail, a bad navigation Pickle) are
// surfaced, never silently dropped:
for w in &stream.warnings { eprintln!("{w:?}"); }
# Ok::<(), snss::SnssError>(())
```

`Tabs_*` files (the recently-closed restore list) use the `Tabs` dialect; pass
`snss::Dialect::Tabs`. To walk every session source in a profile directory at
once, use `snss::SessionStore::open_dir(profile_dir)` (or
`open_default_profile()`), which reads each source and keeps per-source warnings.

## What it decodes

| Entry point | Reads | Produces |
|---|---|---|
| `read_records` | `SNSS` magic + version header, `u16`-length records | `RecordStream { version, records, warnings }` |
| `decode_navigation` | a navigation command's `base::Pickle` payload | `NavCommand { tab_id, index, url, title }` |
| `replay` | a `RecordStream` + dialect | `Replayed { windows }` — `Window`/`Tab`/`Nav` tree |
| `SessionStore::open_dir` | a profile directory | every discovered `Source` + warnings |

The `base::Pickle` decoder is 4-byte-aligned and length-prefixed exactly as
Chromium writes it (UTF-8 URLs, UTF-16-LE titles); replay applies last-write-wins
per `(tab, index)` and resolves each tab's current entry and pinned state.

## Trust but verify

SNSS files are untrusted, attacker-controllable input, so the crate is hardened
by construction:

- **`#![forbid(unsafe_code)]`** across the whole workspace — no `unsafe`, anywhere.
- **Read-only by construction** — the decoder exposes **no write path**; mutating
  a browser's session store is structurally impossible through this API.
- **Panic-free** — every record length, Pickle field length, and alignment step
  is bounds-checked before use; a crafted length field cannot drive an
  out-of-bounds read or an allocation bomb. Malformed input surfaces as a typed
  `SnssError` or a non-fatal `Warning`, never a silent default.
- **Fuzzed** — `cargo-fuzz` targets cover the record-stream reader (`records`) and
  the navigation `base::Pickle` decoder (`navigation`); the invariant is "must not
  panic."
- **Validated against real Chromium data** — real Brave `Session_*`/`Tabs_*`/`Apps_*`
  files are read and replayed (the fixtures are gitignored — they hold personal
  history), alongside byte-exact synthetic command streams. See
  [`docs/validation.md`](docs/validation.md).

## Planned: the `snss-forensic` analyzer

This workspace ships the reader (`snss-core`) today. A sibling `snss-forensic`
analyzer crate — emitting severity-graded
[`forensicnomicon::report`](https://crates.io/crates/forensicnomicon) findings for
session-restore anomalies (e.g. dangling or forward-referenced tab indices,
truncated-tail recovery, replay inconsistencies) — is a planned follow-up so a
session file's anomalies aggregate uniformly with every other artifact layer. No
analyzer logic exists yet; it is not stubbed or fabricated here.

## References

- **Chromium `components/sessions`** — the canonical SNSS writer/reader (command
  framing, `SNSS` magic + version header, append-only log):
  <https://source.chromium.org/chromium/chromium/src/+/main:components/sessions/core/command_storage_backend.cc>
- **Chromium `base::Pickle`** — the field-encoding format navigation payloads use:
  <https://source.chromium.org/chromium/chromium/src/+/main:base/pickle.h>

---

[Privacy Policy](https://securityronin.github.io/snss-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/snss-forensic/terms/) · © 2026 Security Ronin Ltd
