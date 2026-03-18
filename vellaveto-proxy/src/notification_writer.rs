// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Lightweight notification writer for VellaVeto Desktop integration.
//!
//! Writes JSONL events to a file that the desktop app watches for
//! real-time deny/allow notifications.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

/// Truncate a string to at most `max_chars` characters (safe for multi-byte UTF-8).
fn truncate(s: &str, max_chars: usize) -> String {
    s.chars().take(max_chars).collect()
}

/// A notification event for the desktop app.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct NotificationEvent {
    pub ts: String,
    pub tool: String,
    pub action: String,
    pub params_summary: String,
    pub verdict: String,
    pub reason: String,
    pub policy: String,
    pub severity: String,
}

/// Thread-safe notification file writer.
pub struct NotificationWriter {
    file: Mutex<File>,
    path: PathBuf,
}

impl NotificationWriter {
    /// Open or create the notification file.
    pub fn new(path: PathBuf) -> Result<Self, String> {
        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| format!("Cannot create notification directory: {e}"))?;
            }
        }

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|e| format!("Cannot open notification file: {e}"))?;

        Ok(Self {
            file: Mutex::new(file),
            path,
        })
    }

    /// Write a notification event.
    pub fn write_event(&self, event: &NotificationEvent) {
        let json = match serde_json::to_string(event) {
            Ok(j) => j,
            Err(e) => {
                tracing::warn!("Failed to serialize notification event: {e}");
                return;
            }
        };

        if let Ok(mut file) = self.file.lock() {
            if let Err(e) = writeln!(file, "{json}") {
                tracing::warn!("Failed to write notification: {e}");
            }
        }
    }

    /// Write a deny notification.
    pub fn write_deny(
        &self,
        tool: &str,
        action: &str,
        params_summary: &str,
        reason: &str,
        policy: &str,
    ) {
        self.write_event(&NotificationEvent {
            ts: chrono::Utc::now().to_rfc3339(),
            tool: truncate(tool, 64),
            action: truncate(action, 64),
            params_summary: truncate(params_summary, 128),
            verdict: "Deny".to_string(),
            reason: truncate(reason, 128),
            policy: truncate(policy, 64),
            severity: if reason.contains("credential") || reason.contains("exfil") {
                "high"
            } else {
                "medium"
            }
            .to_string(),
        });
    }

    /// Write an allow notification.
    pub fn write_allow(&self, tool: &str, action: &str, params_summary: &str) {
        self.write_event(&NotificationEvent {
            ts: chrono::Utc::now().to_rfc3339(),
            tool: truncate(tool, 64),
            action: truncate(action, 64),
            params_summary: truncate(params_summary, 128),
            verdict: "Allow".to_string(),
            reason: String::new(),
            policy: String::new(),
            severity: "low".to_string(),
        });
    }

    pub fn path(&self) -> &PathBuf {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_path(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "vellaveto_notify_{}_{}_{}",
            name,
            std::process::id(),
            nanos
        ))
    }

    #[test]
    fn test_write_deny_and_allow() {
        let path = temp_path("deny_allow");
        let writer = NotificationWriter::new(path.clone()).unwrap();

        writer.write_deny(
            "fs_write",
            "tools/call",
            "path=/etc/passwd",
            "blocked path",
            "strict",
        );
        writer.write_allow("fs_read", "tools/call", "path=/tmp/data");

        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.trim().lines().collect();
        assert_eq!(lines.len(), 2);

        let deny: NotificationEvent = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(deny.verdict, "Deny");
        assert_eq!(deny.tool, "fs_write");
        assert_eq!(deny.severity, "medium");

        let allow: NotificationEvent = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(allow.verdict, "Allow");
        assert_eq!(allow.tool, "fs_read");
        assert_eq!(allow.severity, "low");

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_severity_high_for_credential_exfil() {
        let path = temp_path("severity");
        let writer = NotificationWriter::new(path.clone()).unwrap();

        writer.write_deny("net_send", "tools/call", "", "credential theft attempt", "");
        writer.write_deny(
            "net_send",
            "tools/call",
            "",
            "data exfiltration detected",
            "",
        );

        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.trim().lines().collect();

        let e1: NotificationEvent = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(e1.severity, "high");

        let e2: NotificationEvent = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(e2.severity, "high");

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_truncation_multibyte() {
        let path = temp_path("truncate");
        let writer = NotificationWriter::new(path.clone()).unwrap();

        // 70 chars of multi-byte — should truncate to 64 chars without panic.
        let long_tool: String = "ä".repeat(70);
        writer.write_allow(&long_tool, "tools/call", "");

        let content = std::fs::read_to_string(&path).unwrap();
        let event: NotificationEvent = serde_json::from_str(content.trim()).unwrap();
        assert_eq!(event.tool.chars().count(), 64);

        let _ = std::fs::remove_file(&path);
    }
}
