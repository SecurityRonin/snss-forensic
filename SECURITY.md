# Security Policy

`snss-forensic` is designed to parse **untrusted Chromium/Brave SNSS session
files** — including files acquired from compromised or actively hostile systems.
Hostile input is the expected case, not an edge case. Robustness against crafted
records is a core design goal, and we take reports of crashes, hangs, or
memory-safety issues seriously.

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x   | ✅ — current release line, receives security fixes |
| < 0.1   | ❌ — pre-release, unsupported |

Security fixes are released against the latest published `0.1.x` line.

## Reporting a vulnerability

**Do not open a public GitHub issue for a security vulnerability.**

Report privately, by either:

- **GitHub Security Advisories** — open a private advisory on the
  [`snss-forensic` repository](https://github.com/SecurityRonin/snss-forensic/security/advisories/new), or
- **Email** — [albert@securityronin.com](mailto:albert@securityronin.com).

Please include:

- the affected version and target triple,
- a minimal reproducing SNSS file or byte buffer (a fuzz corpus entry is ideal),
- the observed behaviour (panic, hang, excessive allocation, mis-parse) and the
  expected behaviour.

We aim to acknowledge a report within a few business days and to coordinate
disclosure once a fix is available.

## Security posture

`snss-forensic` is hardened against adversarial input by construction:

- **`#![forbid(unsafe_code)]`** across the whole workspace — no `unsafe`, anywhere.
- **No panics on malicious input** — every record length, Pickle field length,
  and alignment step is validated against both the declared size and the actual
  buffer; arithmetic is checked or saturating.
- **Bounded reads** — record framing and `base::Pickle` fields are length-checked
  before use, so a crafted length field cannot drive an out-of-bounds read or an
  allocation bomb.
- **Read-only by construction** — the decoder exposes no write path; mutating a
  browser's session store is structurally impossible through this API.

### Fuzzing

Continuous fuzzing with [`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz)
backs the hardening above. Two targets cover the code that consumes
attacker-controlled bytes:

| Target | Surface |
|---|---|
| `records`    | `SNSS` header + length-prefixed record framing |
| `navigation` | navigation-command `base::Pickle` field decode |

Each target's invariant is "must not panic." Any panic found by fuzzing is fixed
and pinned as a regression test.

For how to run the targets yourself, see
[CONTRIBUTING.md](CONTRIBUTING.md#quality-gates).
