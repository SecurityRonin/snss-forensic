# snss-forensic

**Chromium/Brave/Edge SNSS session-file forensics for Rust — a panic-free,
read-only decoder (`snss-core`) for the `SNSS` command stream.**

SNSS is the append-only command-log format Chromium-family browsers
(Chrome, Brave, Edge) use to persist session and tab state — the `Session_*`,
`Tabs_*`, and `Apps_*` files (and the modern `Sessions/` folder) that drive
"restore your tabs". Each file is a 4-byte `SNSS` magic + a version header
followed by length-prefixed command records; navigation commands carry a
Chromium `base::Pickle` payload. `snss-core` decodes that structure faithfully
and makes no judgments:

- **`read_records`** — validate the `SNSS` header and split the command stream
  into length-prefixed [`Record`]s, surfacing a truncated final record (Brave
  appends to live files) as a non-fatal `Warning` rather than an error.
- **`decode_navigation`** — decode a navigation command's `base::Pickle`
  payload (4-byte-aligned, length-prefixed fields) into a typed `NavCommand`.
- **`replay`** — fold the command stream into per-window tab state
  (`Replayed { windows }`), choosing the `Session` or `Tabs` dialect.
- **`SessionStore`** — discover and read every session source in a profile
  directory, keeping per-source warnings.

```rust
use std::io::Cursor;

let stream = snss::read_records(Cursor::new(bytes))?;
let replayed = snss::replay(&stream, snss::Dialect::Session);
for window in &replayed.windows {
    for tab in &window.tabs {
        println!("{}", tab.current_nav().url);
    }
}
# Ok::<(), snss::SnssError>(())
```

## Read-only by construction

`snss-core` is a pure decoder: it reads bytes and returns a typed model. It has
no UI, performs no clipboard or launch side effects, and exposes **no write
path** — mutating a browser's session store is structurally impossible through
this API.

## Trust but verify

`snss-core` is `#![forbid(unsafe_code)]`, panic-free against
attacker-controllable input (every length, offset, and Pickle field is
bounds-checked before use), and fuzzed with `cargo-fuzz` (the `records` and
`navigation` targets, invariant "must not panic"). See
[Validation](validation.md).

## Planned: the `snss-forensic` analyzer

The workspace ships `snss-core` (the reader) today. A sibling `snss-forensic`
analyzer crate — emitting graded
[`forensicnomicon::report`](https://crates.io/crates/forensicnomicon) findings
for session-restore anomalies (e.g. dangling/forward-referenced tab indices,
truncated-tail recovery, replay inconsistencies) — is a planned follow-up. No
analyzer logic exists yet; it is not fabricated here.

---

[Privacy Policy](https://securityronin.github.io/snss-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/snss-forensic/terms/) · © 2026 Security Ronin Ltd
