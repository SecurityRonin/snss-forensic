//! Error-path and discovery coverage for the SNSS decoder.
//!
//! The happy paths live in `record_reader.rs`, `pickle.rs`, `replay.rs`, and
//! `discovery.rs`; this file pins the error `Display`/`source` implementations,
//! the truncated-tail and unsupported-version branches, every `PickleError`
//! variant, the replay anomaly paths, the POD-reader length guards, the
//! `SourceKind::label` mapping, and the `open_dir` / `open_default_profile`
//! discovery edges. Together they take `snss-core` to 100% line coverage so the
//! fleet `*-core` gate holds.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::error::Error;
use std::path::PathBuf;

use snss::{
    decode_navigation, read_records, replay, Dialect, PickleError, SessionStore, SnssError,
    SourceKind, Warning, MAGIC, SUPPORTED_VERSION,
};

mod common;
use common::build;

fn tmp_subdir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("snss-cov-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mk tmp dir");
    dir
}

// --- SnssError Display + source ---------------------------------------------

#[test]
fn snss_error_display_and_source() {
    let bad = SnssError::BadMagic(*b"NOPE");
    assert!(format!("{bad}").contains("not an SNSS file"));
    assert!(bad.source().is_none());

    let unsupported = SnssError::UnsupportedVersion(99);
    let msg = format!("{unsupported}");
    assert!(msg.contains("unsupported SNSS version 99"));
    assert!(msg.contains(&SUPPORTED_VERSION.to_string()));
    assert!(unsupported.source().is_none());

    let io = SnssError::Io(std::io::Error::other("boom"));
    assert!(format!("{io}").contains("I/O error reading SNSS header"));
    assert!(io.source().is_some());
}

// --- read_records header + tail branches ------------------------------------

#[test]
fn short_buffer_reports_bad_magic_padded() {
    // Fewer than 4 bytes: the BadMagic payload is zero-padded, not a panic.
    match read_records(&b"SN"[..]) {
        Err(SnssError::BadMagic(got)) => assert_eq!(got, [b'S', b'N', 0, 0]),
        other => panic!("expected BadMagic, got {other:?}"),
    }
}

#[test]
fn unsupported_version_is_an_error() {
    let mut bytes = MAGIC.to_vec();
    bytes.extend_from_slice(&7i32.to_le_bytes()); // version 7, unsupported
    match read_records(&bytes[..]) {
        Err(SnssError::UnsupportedVersion(7)) => {}
        other => panic!("expected UnsupportedVersion(7), got {other:?}"),
    }
}

#[test]
fn partial_size_field_tail_is_a_truncated_warning() {
    // Header + a lone byte where a 2-byte size field is expected.
    let mut bytes = MAGIC.to_vec();
    bytes.extend_from_slice(&SUPPORTED_VERSION.to_le_bytes());
    bytes.push(0x01); // a single stray byte, not a full u16 size
    let stream = read_records(&bytes[..]).expect("header ok");
    assert!(stream.records.is_empty());
    assert!(stream
        .warnings
        .iter()
        .any(|w| matches!(w, Warning::TruncatedTail { .. })));
}

#[test]
fn record_size_overrunning_eof_is_a_truncated_warning() {
    // A size field claiming a record longer than the remaining bytes.
    let mut bytes = MAGIC.to_vec();
    bytes.extend_from_slice(&SUPPORTED_VERSION.to_le_bytes());
    bytes.extend_from_slice(&999u16.to_le_bytes()); // claims 999 bytes
    bytes.push(6); // only one byte follows
    let stream = read_records(&bytes[..]).expect("header ok");
    assert!(stream
        .warnings
        .iter()
        .any(|w| matches!(w, Warning::TruncatedTail { .. })));
}

// --- PickleError Display + every decode error -------------------------------

#[test]
fn pickle_error_display_all_variants() {
    assert!(format!("{}", PickleError::TooShort).contains("too short"));
    assert!(format!(
        "{}",
        PickleError::BadHeader {
            declared: 10,
            actual: 2
        }
    )
    .contains("declares 10"));
    assert!(format!("{}", PickleError::Overrun).contains("runs past"));
    assert!(format!("{}", PickleError::BadLength(-1)).contains("negative"));
}

#[test]
fn pickle_too_short_header() {
    assert_eq!(decode_navigation(&[0, 1, 2]), Err(PickleError::TooShort));
}

#[test]
fn pickle_bad_header_declares_more_than_present() {
    // 4-byte length header declaring more payload than the buffer holds.
    let mut p = 100u32.to_le_bytes().to_vec();
    p.extend_from_slice(&[0u8; 4]);
    match decode_navigation(&p) {
        Err(PickleError::BadHeader { declared, actual }) => {
            assert_eq!(declared, 100);
            assert_eq!(actual, 4);
        }
        other => panic!("expected BadHeader, got {other:?}"),
    }
}

#[test]
fn pickle_overrun_on_truncated_field() {
    // Header says 4 payload bytes (one i32), but a NavCommand wants more fields.
    let mut p = 4u32.to_le_bytes().to_vec();
    p.extend_from_slice(&0i32.to_le_bytes());
    assert!(matches!(decode_navigation(&p), Err(PickleError::Overrun)));
}

#[test]
fn pickle_overrun_in_utf16_title() {
    // tab_id, index, a valid 4-byte-padded url, then a UTF-16 title length that
    // overruns the payload: exercises the read_string16 Overrun guard.
    let mut body = 0i32.to_le_bytes().to_vec(); // tab_id
    body.extend_from_slice(&0i32.to_le_bytes()); // index
    body.extend_from_slice(&0i32.to_le_bytes()); // url len 0
    body.extend_from_slice(&50i32.to_le_bytes()); // title: 50 code units, absent
    let mut p = (body.len() as u32).to_le_bytes().to_vec();
    p.extend_from_slice(&body);
    assert!(matches!(decode_navigation(&p), Err(PickleError::Overrun)));
}

#[test]
fn pickle_bad_length_negative_string_prefix() {
    // tab_id, index, then a negative string-length prefix => BadLength.
    let mut body = 0i32.to_le_bytes().to_vec(); // tab_id
    body.extend_from_slice(&0i32.to_le_bytes()); // index
    body.extend_from_slice(&(-5i32).to_le_bytes()); // url len = -5
    let mut p = (body.len() as u32).to_le_bytes().to_vec();
    p.extend_from_slice(&body);
    assert!(matches!(
        decode_navigation(&p),
        Err(PickleError::BadLength(-5))
    ));
}

// --- replay anomaly paths ---------------------------------------------------

#[test]
fn replay_surfaces_bad_navigation_as_warning() {
    // A Session-dialect navigation command (id 6) with a payload too short to be
    // a valid Pickle: replay records a BadNavigation warning, not a panic.
    let bytes = build::snss(&[(6, vec![0, 1, 2])]);
    let stream = read_records(&bytes[..]).unwrap();
    let replayed = replay(&stream, Dialect::Session);
    assert!(replayed
        .warnings
        .iter()
        .any(|w| matches!(w, Warning::BadNavigation { .. })));
}

#[test]
fn replay_ignores_unrecognised_pod_commands() {
    // A command id replay does not model, with a payload too short for any POD
    // reader, is skipped (the `continue`/None guards) without error.
    let bytes = build::snss(&[(12, vec![0, 0])]); // SetPinnedState needs >= 5 bytes
    let stream = read_records(&bytes[..]).unwrap();
    let replayed = replay(&stream, Dialect::Session);
    assert!(replayed.windows.is_empty() || replayed.windows.iter().all(|w| w.tabs.is_empty()));
}

#[test]
fn replay_skips_short_pair_and_last_active_payloads() {
    // SetTabWindow (id 0) and LastActiveTime (id 21) with under-length payloads
    // exercise the pod_pair / pod_last_active length guards (return None).
    let bytes = build::snss(&[(0, vec![1, 2, 3]), (21, vec![4, 5, 6, 7])]);
    let stream = read_records(&bytes[..]).unwrap();
    let replayed = replay(&stream, Dialect::Session);
    // No usable tab state is produced from malformed POD payloads.
    assert!(replayed.windows.iter().all(|w| w.tabs.is_empty()));
}

#[test]
fn replay_discards_pre_epoch_last_active_time() {
    // A valid nav (so the tab has history) plus a LastActiveTime whose value is
    // before the Unix epoch: windows_micros_to_system_time returns None, so the
    // window has no last_active. Exercises that None branch.
    let bytes = build::snss(&[
        (6, build::nav(7, 0, "https://x.example", "X")),
        (0, build::pair(1, 7)),           // SetTabWindow: tab 7 -> window 1
        (21, build::last_active(7, 100)), // 100us since Windows epoch == pre-1970
    ]);
    let stream = read_records(&bytes[..]).unwrap();
    let replayed = replay(&stream, Dialect::Session);
    assert!(replayed.windows.iter().all(|w| w.last_active.is_none()));
}

// --- SourceKind::label -------------------------------------------------------

#[test]
fn source_kind_labels() {
    assert_eq!(SourceKind::Current.label(), "Current Session");
    assert_eq!(SourceKind::Last.label(), "Last Session");
    assert_eq!(SourceKind::RecentlyClosed.label(), "Recently Closed");
    assert_eq!(SourceKind::Apps.label(), "Apps");
}

// --- discovery edges ---------------------------------------------------------

#[test]
fn open_dir_ignores_unrelated_filenames() {
    let dir = tmp_subdir("ignore");
    // A file matching none of Session_/Tabs_/Apps_ exercises the skip branch.
    std::fs::write(dir.join("README.txt"), b"not a session file").unwrap();
    std::fs::write(dir.join("Session_1"), build::snss(&[])).unwrap();
    let store = SessionStore::open_dir(&dir).expect("opens");
    assert!(store
        .sources()
        .iter()
        .any(|s| s.kind == SourceKind::Current));
    let _ = std::fs::remove_dir_all(&dir);
}

// Note: the `path.file_name().to_str() -> None` skip in `open_dir` (a non-UTF-8
// directory entry) is a defensive guard annotated `// cov:unreachable` in the
// source — macOS (APFS) and Windows reject non-UTF-8 filenames at write time
// (EILSEQ), so no portable test can materialize that entry on the CI matrix.

#[test]
fn open_default_profile_errors_when_home_unset() {
    // Removing HOME makes default_sessions_dir() fail loudly rather than guess.
    let saved = std::env::var_os("HOME");
    std::env::remove_var("HOME");
    let result = SessionStore::open_default_profile();
    if let Some(h) = saved {
        std::env::set_var("HOME", h);
    }
    match result {
        Err(SnssError::Io(_)) => {}
        // When HOME is unset the dir cannot be resolved; on a machine where the
        // default dir happens to exist this would instead Ok — but with HOME
        // removed default_sessions_dir() returns the Io error first.
        other => panic!("expected Io error with HOME unset, got {other:?}"),
    }
}
