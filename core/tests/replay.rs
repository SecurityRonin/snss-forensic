#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Milestone 3 — replay the command log into a Window/Tab/Nav tree.
//!
//! Synthetic streams pin the tree-building, dedup, current-entry and pinned logic
//! with known inputs; the real-fixture tests assert the verified counts (1619
//! tabs, 1797 deduped entries, 4 pinned) and structural invariants.

use snss::{read_records, replay, Dialect, Tab};

mod common;
use common::{build, open_fixture_or_skip};
use std::time::UNIX_EPOCH;

/// A Windows-epoch microsecond value that lands in 2026 (for last-active tests).
const T_2026: i64 = 13_425_000_000_000_000;

#[test]
fn synthetic_session_builds_window_tab_tree() {
    // Window 100 with two tabs: tab 10 pinned (2 entries, selected index 1) and
    // tab 20 unpinned (1 entry). Commands deliberately interleaved.
    let bytes = build::snss(&[
        (0, build::pair(100, 10)), // SetTabWindow: window 100 <- tab 10
        (6, build::nav(10, 0, "https://a/0", "A0")),
        (6, build::nav(10, 1, "https://a/1", "A1")),
        (12, build::pinned(10, true)),
        (7, build::pair(10, 1)), // SelectedNavigationIndex: tab 10 -> index 1
        (2, build::pair(10, 0)), // TabIndexInWindow: tab 10 -> position 0
        (21, build::last_active(10, T_2026)),
        (0, build::pair(100, 20)),
        (6, build::nav(20, 0, "https://b", "B")),
        (12, build::pinned(20, false)),
        (2, build::pair(20, 1)),
    ]);
    let stream = read_records(&bytes[..]).unwrap();
    let r = replay(&stream, Dialect::Session);

    assert!(r.warnings.is_empty(), "{:?}", r.warnings);
    assert_eq!(r.windows.len(), 1);
    let w = &r.windows[0];
    assert_eq!(w.id, 100);
    assert_eq!(w.tabs.len(), 2);

    // Ordered by TabIndexInWindow: tab 10 then tab 20.
    assert_eq!(w.tabs[0].id, 10);
    assert!(w.tabs[0].pinned, "tab 10 is pinned");
    assert_eq!(w.tabs[0].history.len(), 2);
    assert_eq!(w.tabs[0].current, 1, "resolves to selected index 1");
    assert_eq!(w.tabs[0].current_nav().url, "https://a/1");

    assert_eq!(w.tabs[1].id, 20);
    assert!(!w.tabs[1].pinned);
    assert_eq!(w.tabs[1].current, 0);
    assert!(w.last_active.is_some());
}

#[test]
fn synthetic_last_write_wins_for_same_index() {
    let bytes = build::snss(&[
        (6, build::nav(10, 0, "https://old", "Old")),
        (6, build::nav(10, 0, "https://new", "New")), // supersedes same (tab,index)
    ]);
    let stream = read_records(&bytes[..]).unwrap();
    let r = replay(&stream, Dialect::Session);
    let tab = &r.windows[0].tabs[0];
    assert_eq!(tab.history.len(), 1, "duplicate (tab,index) deduped");
    assert_eq!(tab.history[0].url, "https://new");
}

#[test]
fn synthetic_current_defaults_to_last_entry_without_selected() {
    let bytes = build::snss(&[
        (6, build::nav(10, 0, "https://x/0", "0")),
        (6, build::nav(10, 1, "https://x/1", "1")),
        (6, build::nav(10, 2, "https://x/2", "2")),
    ]);
    let stream = read_records(&bytes[..]).unwrap();
    let r = replay(&stream, Dialect::Session);
    let tab = &r.windows[0].tabs[0];
    assert_eq!(tab.current, 2, "no selected-index command -> last entry");
    assert_eq!(tab.current_nav().url, "https://x/2");
}

#[test]
fn synthetic_last_active_decodes_to_a_sane_time() {
    let bytes = build::snss(&[
        (6, build::nav(1, 0, "https://t", "t")),
        (21, build::last_active(1, T_2026)),
    ]);
    let stream = read_records(&bytes[..]).unwrap();
    let r = replay(&stream, Dialect::Session);
    let secs = r.windows[0]
        .last_active
        .expect("time present")
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    // Windows-epoch -> Unix conversion must land in a plausible range (2024-2033).
    assert!(
        (1_700_000_000..2_000_000_000).contains(&secs),
        "got unix secs {secs}"
    );
}

#[test]
fn tabs_dialect_skips_session_only_commands() {
    // In the Tabs (recently-closed) dialect, nav = cmd 1 and selected = cmd 4; the
    // ids Chromium uses for SetTabWindow/TabIndexInWindow/SetPinnedState/LastActive
    // in the Session dialect carry unrelated meaning here and must be ignored. This
    // pins the dialect guard so those commands never leak into the reconstructed
    // tree (and covers the guard portably, without the real Tabs fixture).
    let bytes = build::snss(&[
        (1, build::nav(10, 0, "https://closed/0", "Closed0")),
        (1, build::nav(10, 1, "https://closed/1", "Closed1")),
        (0, build::pair(100, 10)), // SetTabWindow id in Session -> ignored in Tabs
        (2, build::pair(10, 0)),   // TabIndexInWindow id -> ignored in Tabs
        (12, build::pinned(10, true)), // SetPinnedState id -> ignored in Tabs
        (21, build::last_active(10, T_2026)), // LastActiveTime id -> ignored in Tabs
        (4, build::pair(10, 0)),   // selected-index in Tabs -> current = index 0
    ]);
    let stream = read_records(&bytes[..]).unwrap();
    let r = replay(&stream, Dialect::Tabs);

    let tabs: Vec<&Tab> = r.windows.iter().flat_map(|w| &w.tabs).collect();
    assert_eq!(tabs.len(), 1, "one reconstructed closed tab");
    assert_eq!(tabs[0].id, 10);
    assert!(
        !tabs[0].pinned,
        "SetPinnedState is a Session-only command and is not honored in Tabs"
    );
    assert_eq!(tabs[0].history.len(), 2, "both navigations survive");
    assert_eq!(
        tabs[0].current, 0,
        "selected-index (cmd 4) resolves to index 0"
    );
    // Session-only LastActiveTime must not populate window recency in Tabs.
    assert!(
        r.windows.iter().all(|w| w.last_active.is_none()),
        "LastActiveTime is ignored in the Tabs dialect"
    );
}

#[test]
fn real_session_replay_matches_ground_truth() {
    let Some(stream) = open_fixture_or_skip("Session_real") else {
        return;
    };
    let r = replay(&stream, Dialect::Session);
    assert!(
        r.warnings.is_empty(),
        "zero bad navigations: {:?}",
        r.warnings
    );
    assert_eq!(r.windows.len(), 1, "one current window");

    let tabs: Vec<&Tab> = r.windows.iter().flat_map(|w| &w.tabs).collect();
    assert_eq!(tabs.len(), 1619, "distinct tabs with history");
    let entries: usize = tabs.iter().map(|t| t.history.len()).sum();
    assert_eq!(entries, 1797, "deduped (tab,index) history entries");
    assert_eq!(tabs.iter().filter(|t| t.pinned).count(), 4, "pinned tabs");

    for t in &tabs {
        assert!(!t.history.is_empty());
        assert!(t.current < t.history.len(), "current in range");
        assert!(
            t.history.windows(2).all(|w| w[0].index < w[1].index),
            "history strictly ascending by index"
        );
    }
    assert!(r.windows[0].last_active.is_some(), "window recency present");
}

#[test]
fn real_tabs_replay_lists_closed_tabs() {
    let Some(stream) = open_fixture_or_skip("Tabs_real") else {
        return;
    };
    let r = replay(&stream, Dialect::Tabs);
    let tabs: Vec<&Tab> = r.windows.iter().flat_map(|w| &w.tabs).collect();
    assert_eq!(tabs.len(), 35, "distinct closed tabs");
    let entries: usize = tabs.iter().map(|t| t.history.len()).sum();
    assert_eq!(entries, 51);
    assert!(tabs.iter().all(|t| t.current < t.history.len()));
}
