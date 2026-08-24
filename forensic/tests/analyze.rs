//! Validate the SNSS analyzer against synthetic-but-real command streams.
//!
//! Tier-2: the byte streams here are assembled the same way `snss-core`'s own
//! tests build fixtures (real SNSS v3 container framing + real Chromium Pickle
//! nav payloads), so a well-formed session is genuinely well-formed. It must
//! yield **zero** findings — a non-empty result would be a false positive. Each
//! corrupted case is a positive control proving a check can go red.
//!
//! (The 108-real-Brave-fixtures path is gitignored personal data; the synthetic
//! streams exercise the same decode + replay logic portably, and are the
//! authoritative check here.)
#![allow(clippy::unwrap_used, clippy::expect_used)]

use snss_forensic::{
    analyze, analyze_store, read_records, replay, Dialect, SessionStore, SnssAnomalyKind,
};

// ─── minimal SNSS builder (mirrors snss-core/tests/common build::) ───────────

fn pad4(v: &mut Vec<u8>) {
    while v.len() % 4 != 0 {
        v.push(0);
    }
}

/// A valid Chromium Pickle `UpdateTabNavigation` payload.
fn nav(tab_id: i32, index: i32, url: &str, title: &str) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&tab_id.to_le_bytes());
    body.extend_from_slice(&index.to_le_bytes());
    body.extend_from_slice(&(url.len() as i32).to_le_bytes());
    body.extend_from_slice(url.as_bytes());
    pad4(&mut body);
    let units: Vec<u16> = title.encode_utf16().collect();
    body.extend_from_slice(&(units.len() as i32).to_le_bytes());
    for u in &units {
        body.extend_from_slice(&u.to_le_bytes());
    }
    pad4(&mut body);
    let mut out = (body.len() as u32).to_le_bytes().to_vec();
    out.extend_from_slice(&body);
    out
}

/// A `LastActiveTime` payload: `{tab_id: i32, _pad: i32, time: i64}` where `time`
/// is microseconds since the Windows epoch (1601-01-01).
fn last_active(tab_id: i32, win_micros: i64) -> Vec<u8> {
    let mut v = tab_id.to_le_bytes().to_vec();
    v.extend_from_slice(&0i32.to_le_bytes());
    v.extend_from_slice(&win_micros.to_le_bytes());
    v
}

/// Windows-epoch microseconds for a given Unix-seconds instant.
fn win_micros_for_unix(unix_secs: i64) -> i64 {
    (unix_secs + 11_644_473_600) * 1_000_000
}

/// Assemble a full SNSS v3 file from `(command_id, payload)` records.
fn snss(records: &[(u8, Vec<u8>)]) -> Vec<u8> {
    let mut out = b"SNSS".to_vec();
    out.extend_from_slice(&3i32.to_le_bytes());
    for (id, payload) in records {
        let size = (payload.len() + 1) as u16;
        out.extend_from_slice(&size.to_le_bytes());
        out.push(*id);
        out.extend_from_slice(payload);
    }
    out
}

const CMD_NAV: u8 = 6; // UpdateTabNavigation (Session dialect)
const CMD_LAST_ACTIVE: u8 = 21;

fn replayed(bytes: &[u8]) -> snss_forensic::Replayed {
    let stream = read_records(bytes).expect("valid SNSS header");
    replay(&stream, Dialect::Session)
}

// ─── true negative: a well-formed session produces no findings ───────────────

#[test]
fn a_clean_session_has_no_findings() {
    // One tab with a valid navigation and a plausible 2020 last-active time.
    let bytes = snss(&[
        (CMD_NAV, nav(1, 0, "https://example.com", "Example")),
        (
            CMD_LAST_ACTIVE,
            last_active(1, win_micros_for_unix(1_590_969_600)),
        ),
    ]);
    let findings = analyze(&replayed(&bytes));
    assert!(
        findings.is_empty(),
        "expected no anomalies on a well-formed session, got {:?}",
        findings.iter().map(|f| f.kind.clone()).collect::<Vec<_>>()
    );
}

// ─── positive control 1: a navigation record that fails to decode ────────────

#[test]
fn a_corrupt_navigation_record_is_caught() {
    // A CMD_NAV record whose Pickle payload is too short to hold even the length
    // header: replay records a BadNavigation warning, which the analyzer grades.
    let bytes = snss(&[
        (CMD_NAV, nav(1, 0, "https://example.com", "Example")),
        (CMD_NAV, vec![0x01]), // corrupt: 1 byte, cannot decode
    ]);
    let findings = analyze(&replayed(&bytes));
    assert!(
        findings
            .iter()
            .any(|f| matches!(f.kind, SnssAnomalyKind::NavigationDecodeFailed { .. })),
        "a nav record that fails to decode must trip the decode-integrity check"
    );
}

// ─── positive control 2: a last-active time before the format existed ────────

#[test]
fn a_pre_2008_last_active_is_caught() {
    let bytes = snss(&[
        (CMD_NAV, nav(1, 0, "https://example.com", "Example")),
        // 1990 — after the Unix epoch (so the reader keeps it) but before Brave.
        (
            CMD_LAST_ACTIVE,
            last_active(1, win_micros_for_unix(631_152_000)),
        ),
    ]);
    let findings = analyze(&replayed(&bytes));
    assert!(
        findings
            .iter()
            .any(|f| matches!(f.kind, SnssAnomalyKind::ImplausibleLastActive { .. })),
        "a pre-2008 last-active time must trip the timeline check"
    );
}

// ─── positive control 3: an absurd far-future last-active time ───────────────

#[test]
fn a_far_future_last_active_is_caught() {
    let bytes = snss(&[
        (CMD_NAV, nav(1, 0, "https://example.com", "Example")),
        // 2200 — well beyond any real session.
        (
            CMD_LAST_ACTIVE,
            last_active(1, win_micros_for_unix(7_258_118_400)),
        ),
    ]);
    let findings = analyze(&replayed(&bytes));
    assert!(
        findings
            .iter()
            .any(|f| matches!(f.kind, SnssAnomalyKind::ImplausibleLastActive { .. })),
        "a far-future last-active time must trip the timeline check"
    );
}

// ─── a truncated tail is normal (live file), never graded ────────────────────

#[test]
fn a_truncated_tail_is_not_graded() {
    // A dangling record-size marker with no body: replay reports TruncatedTail,
    // which the analyzer deliberately does NOT grade (a live session file is
    // routinely half-written at its tail).
    let mut bytes = snss(&[(CMD_NAV, nav(1, 0, "https://example.com", "Example"))]);
    bytes.extend_from_slice(&16u16.to_le_bytes()); // size says 16, no body follows
    let findings = analyze(&replayed(&bytes));
    assert!(
        findings.is_empty(),
        "a truncated tail must not be treated as an anomaly, got {:?}",
        findings.iter().map(|f| f.kind.clone()).collect::<Vec<_>>()
    );
}

// ─── store-level grading across sources ──────────────────────────────────────

#[test]
fn analyze_store_grades_warnings_and_windows() {
    // A discovered Session file carrying both a corrupt nav (→ a store-level
    // BadNavigation warning) and an implausibly early last-active time (→ a
    // graded window). analyze_store must surface both.
    let bytes = snss(&[
        (CMD_NAV, nav(1, 0, "https://example.com", "Example")),
        (CMD_NAV, vec![0x01]), // corrupt: cannot decode → BadNavigation
        (
            CMD_LAST_ACTIVE,
            last_active(1, win_micros_for_unix(631_152_000)), // 1990 → implausible
        ),
    ]);
    let dir = std::env::temp_dir().join("snss_forensic_analyze_store_cov");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp store dir");
    std::fs::write(dir.join("Session_100"), &bytes).expect("write session file");
    // An older, undecodable Session file becomes a store-level UnreadableSource
    // warning — which the analyzer deliberately does not grade (it is not a
    // content anomaly). This exercises the non-graded warning arm.
    std::fs::write(dir.join("Session_50"), b"not an SNSS file").expect("write bad file");

    let store = SessionStore::open_dir(&dir).expect("open session store");
    let findings = analyze_store(&store);
    assert!(
        findings
            .iter()
            .any(|f| matches!(f.kind, SnssAnomalyKind::NavigationDecodeFailed { .. })),
        "a store-level BadNavigation must be graded"
    );
    assert!(
        findings
            .iter()
            .any(|f| matches!(f.kind, SnssAnomalyKind::ImplausibleLastActive { .. })),
        "an implausible window in a discovered source must be graded"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
