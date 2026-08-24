//! Chromium/Brave SNSS session-restore forensic analyzer, and the reader it
//! grades over.
//!
//! Emits [`forensicnomicon::report`] observations over the [`Replayed`] tree (or
//! a whole [`SessionStore`]) produced by the [`snss`] reader. Every finding is
//! grounded in the session's own recorded state — a navigation record the reader
//! itself could not decode, a window last-active timestamp outside the range the
//! format could have written — so it needs no external oracle, and each is an
//! *observation* ("consistent with"), never a conclusion.
//!
//! Only genuine anomalies are graded. A [`Warning::TruncatedTail`] is **not** an
//! anomaly — Brave appends to live session files, so the final record is normally
//! half-written; grading it would fire on every live profile. The reader also
//! guarantees `Tab::current` is in range, so there is no "current out of range"
//! finding to make — it could never fire on real output.
//!
//! The reader surface is re-exported, so `snss_forensic::` resolves the reader
//! types too.
#![forbid(unsafe_code)]

pub use snss::*;

use forensicnomicon::report::{Category, Observation, Severity};
use std::time::UNIX_EPOCH;

/// Unix seconds at 2008-01-01 UTC. Chrome shipped 2008-09-02 and Brave later, so
/// a session last-active time earlier than this cannot be one the format wrote.
/// Deliberately a few months before Chrome's launch — conservative, so a genuine
/// stamp never trips it.
const FLOOR_UNIX_SECS: i64 = 1_199_145_600;

/// Unix seconds at 2100-01-01 UTC. A fixed upper bound (no wall-clock needed, so
/// the check is deterministic) well beyond any real session, catching a grossly
/// corrupted or edited future stamp.
const CEIL_UNIX_SECS: i64 = 4_102_444_800;

/// A graded anomaly observed in a replayed SNSS session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnssAnomalyKind {
    /// A navigation record failed to decode during replay; the reader skipped it
    /// and recorded the record index and the Pickle error. Consistent with a
    /// corrupted, truncated, or tampered navigation record.
    NavigationDecodeFailed { record: usize, error: String },
    /// A window's last-active time falls outside the range the format could have
    /// written (before Brave/Chrome existed, or absurdly far in the future).
    /// Consistent with an edited or corrupted timestamp.
    ImplausibleLastActive { window_id: i32, unix_secs: i64 },
}

impl SnssAnomalyKind {
    /// Severity — the single source of truth.
    #[must_use]
    pub fn severity(&self) -> Severity {
        match self {
            // A record the format wrote but the reader cannot decode is a direct
            // content-integrity signal; a timestamp the format could not have
            // produced is a strong tamper signal. Both medium — each is often an
            // artifact rather than proven tampering.
            SnssAnomalyKind::NavigationDecodeFailed { .. }
            | SnssAnomalyKind::ImplausibleLastActive { .. } => Severity::Medium,
        }
    }

    /// Analytical lens.
    #[must_use]
    pub fn category(&self) -> Category {
        match self {
            SnssAnomalyKind::NavigationDecodeFailed { .. } => Category::Integrity,
            SnssAnomalyKind::ImplausibleLastActive { .. } => Category::History,
        }
    }

    /// Stable machine-readable code (published contract; never reused/renamed).
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            SnssAnomalyKind::NavigationDecodeFailed { .. } => "SNSS-NAV-DECODE-FAILED",
            SnssAnomalyKind::ImplausibleLastActive { .. } => "SNSS-TIME-IMPLAUSIBLE",
        }
    }

    /// Human-readable note (observation, not a conclusion).
    #[must_use]
    pub fn note(&self) -> String {
        match self {
            SnssAnomalyKind::NavigationDecodeFailed { record, error } => format!(
                "SNSS navigation record {record} failed to decode ({error}) and was skipped — \
                 consistent with a corrupted, truncated, or tampered navigation record"
            ),
            SnssAnomalyKind::ImplausibleLastActive {
                window_id,
                unix_secs,
            } => format!(
                "SNSS window {window_id} records a last-active time of {unix_secs} Unix seconds, \
                 outside the range the format could have written (before 2008 or after 2100) — \
                 consistent with an edited or corrupted timestamp"
            ),
        }
    }
}

/// A graded finding: a [`SnssAnomalyKind`] plus its derived severity/code/note.
#[derive(Debug, Clone)]
pub struct SnssAnomaly {
    pub kind: SnssAnomalyKind,
    severity: Severity,
    code: &'static str,
    note: String,
}

impl SnssAnomaly {
    #[must_use]
    pub fn new(kind: SnssAnomalyKind) -> Self {
        let severity = kind.severity();
        let code = kind.code();
        let note = kind.note();
        Self {
            kind,
            severity,
            code,
            note,
        }
    }
}

impl Observation for SnssAnomaly {
    fn severity(&self) -> Option<Severity> {
        Some(self.severity)
    }
    fn code(&self) -> &'static str {
        self.code
    }
    fn note(&self) -> String {
        self.note.clone()
    }
    fn category(&self) -> Category {
        self.kind.category()
    }
}

/// Grade one reader `Warning`, returning an anomaly only for genuine corruption.
///
/// [`Warning::TruncatedTail`] is normal (live-file append) and
/// [`Warning::UnreadableSource`] describes a rotated/partial file rather than the
/// session's content, so neither is graded — only a mid-stream decode failure is.
fn grade_warning(w: &Warning) -> Option<SnssAnomalyKind> {
    match w {
        Warning::BadNavigation { record, error } => Some(SnssAnomalyKind::NavigationDecodeFailed {
            record: *record,
            error: format!("{error:?}"),
        }),
        Warning::TruncatedTail { .. } | Warning::UnreadableSource { .. } => None,
    }
}

/// Grade one window's last-active timestamp against the plausible range.
fn grade_window(w: &Window) -> Option<SnssAnomalyKind> {
    let t = w.last_active?;
    let secs = match t.duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_secs() as i64,
        // The reader returns `None` for pre-Unix-epoch stamps, so this arm is
        // defensive; a negative value is unambiguously out of range.
        Err(e) => -(e.duration().as_secs() as i64),
    };
    if (FLOOR_UNIX_SECS..=CEIL_UNIX_SECS).contains(&secs) {
        None
    } else {
        Some(SnssAnomalyKind::ImplausibleLastActive {
            window_id: w.id,
            unix_secs: secs,
        })
    }
}

/// Grade one replayed session file, returning every anomaly it exhibits.
///
/// A clean session returns an empty vector: it replays without decode failures
/// and its window timestamps fall in the plausible range.
#[must_use]
pub fn analyze(replayed: &Replayed) -> Vec<SnssAnomaly> {
    let mut out = Vec::new();
    for w in &replayed.warnings {
        if let Some(kind) = grade_warning(w) {
            out.push(SnssAnomaly::new(kind));
        }
    }
    for win in &replayed.windows {
        if let Some(kind) = grade_window(win) {
            out.push(SnssAnomaly::new(kind));
        }
    }
    out
}

/// Grade a whole discovered [`SessionStore`], flattening findings across every
/// source. Store-level warnings (e.g. a source that failed to decode) and each
/// source's window timestamps are graded together.
#[must_use]
pub fn analyze_store(store: &SessionStore) -> Vec<SnssAnomaly> {
    let mut out = Vec::new();
    for w in store.warnings() {
        if let Some(kind) = grade_warning(w) {
            out.push(SnssAnomaly::new(kind));
        }
    }
    for source in store.sources() {
        for win in &source.windows {
            if let Some(kind) = grade_window(win) {
                out.push(SnssAnomaly::new(kind));
            }
        }
    }
    out
}
