//! Structured JSONL logging for captured evidence (hashes, creds, queries).
//!
//! Every finding is both printed for the operator and, if `--log <file>` is
//! given, appended as one JSON object per line — timestamped and sourced, so a
//! capture run leaves a reviewable artifact.

use std::fs::OpenOptions;
use std::io::Write;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct Logger {
    file: Option<Mutex<std::fs::File>>,
}

impl Logger {
    pub fn new(path: Option<&str>) -> Self {
        let file = path
            .and_then(|p| OpenOptions::new().create(true).append(true).open(p).ok())
            .map(Mutex::new);
        Logger { file }
    }

    /// Record an event: append JSONL to the log file (if any). Callers print
    /// their own human-friendly line to the console.
    pub fn event(&self, kind: &str, src: &str, data: serde_json::Value) {
        let Some(file) = &self.file else { return };
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let line = serde_json::json!({
            "ts": ts,
            "type": kind,
            "src": src,
            "data": data,
        });
        if let Ok(mut f) = file.lock() {
            let _ = writeln!(f, "{line}");
        }
    }
}
