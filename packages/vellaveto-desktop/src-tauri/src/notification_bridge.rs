//! Notification bridge — watches proxy notification files and fires OS notifications.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// A proxy notification event (lightweight, separate from full audit).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyNotification {
    pub ts: String,
    pub tool: String,
    pub action: String,
    #[serde(default)]
    pub params_summary: String,
    pub verdict: String,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub policy: String,
    #[serde(default)]
    pub severity: String,
}

impl ProxyNotification {
    /// Human-readable one-line summary.
    pub fn summary(&self) -> String {
        match self.verdict.as_str() {
            "Deny" => format!(
                "Blocked: {}({}) — {}",
                self.action,
                &self.params_summary[..self.params_summary.len().min(40)],
                &self.reason[..self.reason.len().min(60)]
            ),
            "Allow" => format!("Allowed: {}({})", self.action, &self.params_summary[..self.params_summary.len().min(40)]),
            _ => format!("{}: {}", self.verdict, self.action),
        }
    }

    /// Whether this notification warrants an OS-level notification.
    pub fn is_high_severity(&self) -> bool {
        self.severity == "high" || self.severity == "critical" || self.verdict == "Deny"
    }

    /// Tray icon color for this event.
    pub fn tray_color(&self) -> &'static str {
        match self.verdict.as_str() {
            "Deny" if self.severity == "high" || self.severity == "critical" => "red",
            "Deny" => "yellow",
            _ => "green",
        }
    }
}

/// Watches a notification JSONL file for new events.
pub struct NotificationWatcher {
    path: PathBuf,
    last_position: u64,
}

impl NotificationWatcher {
    pub fn new(path: PathBuf) -> Self {
        let last_position = std::fs::metadata(&path)
            .map(|m| m.len())
            .unwrap_or(0);
        Self {
            path,
            last_position,
        }
    }

    /// Poll for new notifications since last check.
    pub fn poll(&mut self) -> Vec<ProxyNotification> {
        let content = match std::fs::read_to_string(&self.path) {
            Ok(c) => c,
            Err(_) => return Vec::new(),
        };

        let current_len = content.len() as u64;
        if current_len <= self.last_position {
            return Vec::new();
        }

        let new_content = &content[self.last_position as usize..];
        self.last_position = current_len;

        new_content
            .lines()
            .filter(|line| !line.trim().is_empty())
            .filter_map(|line| serde_json::from_str::<ProxyNotification>(line).ok())
            .collect()
    }

    /// Get the notification file path.
    pub fn path(&self) -> &PathBuf {
        &self.path
    }
}

/// Default notification file path.
pub fn default_notification_path() -> PathBuf {
    dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("vellaveto")
        .join("notifications.jsonl")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_parse_notification() {
        let json = r#"{"ts":"2026-03-17T12:00:00Z","tool":"filesystem","action":"read_file","params_summary":"/home/user/.ssh/id_ed25519","verdict":"Deny","reason":"Credential file protection","policy":"shield-credential-block","severity":"high"}"#;
        let notif: ProxyNotification = serde_json::from_str(json).unwrap();
        assert_eq!(notif.verdict, "Deny");
        assert!(notif.is_high_severity());
        assert_eq!(notif.tray_color(), "red");
        assert!(notif.summary().contains("Blocked"));
    }

    #[test]
    fn test_parse_allow_notification() {
        let json = r#"{"ts":"2026-03-17T12:01:00Z","tool":"filesystem","action":"read_file","params_summary":"/tmp/notes.txt","verdict":"Allow","reason":"","policy":"","severity":"low"}"#;
        let notif: ProxyNotification = serde_json::from_str(json).unwrap();
        assert!(!notif.is_high_severity());
        assert_eq!(notif.tray_color(), "green");
    }

    #[test]
    fn test_watcher_polls_new_lines() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("notifications.jsonl");
        std::fs::write(&path, "").unwrap();

        let mut watcher = NotificationWatcher::new(path.clone());

        // No new content
        assert!(watcher.poll().is_empty());

        // Add a line
        let mut f = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
        writeln!(f, r#"{{"ts":"now","tool":"t","action":"a","verdict":"Deny","reason":"r","severity":"high"}}"#).unwrap();

        let events = watcher.poll();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].verdict, "Deny");

        // Poll again — no new events
        assert!(watcher.poll().is_empty());
    }
}
