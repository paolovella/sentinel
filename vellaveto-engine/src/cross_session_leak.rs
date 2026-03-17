// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Cross-session data leak detection.
//!
//! Detects when data from one session appears in another session's
//! tool calls or responses, indicating shared state leakage.
//! This addresses the promptfoo "cross-session leak" test category.

use std::collections::{HashMap, HashSet};

/// Maximum fingerprints per session.
const MAX_FINGERPRINTS: usize = 1000;
/// Maximum tracked sessions.
const MAX_SESSIONS: usize = 10_000;

/// A cross-session leak finding.
#[derive(Debug, Clone)]
pub struct CrossSessionLeakFinding {
    /// The session that leaked data.
    pub source_session: String,
    /// The session that received leaked data.
    pub target_session: String,
    /// The leaked data fingerprint.
    pub fingerprint: String,
    /// Confidence (0-100).
    pub confidence: u32,
}

/// Tracks data fingerprints across sessions to detect leaks.
pub struct CrossSessionLeakDetector {
    /// Per-session data fingerprints: session_id → set of fingerprints.
    session_data: HashMap<String, HashSet<String>>,
}

impl CrossSessionLeakDetector {
    pub fn new() -> Self {
        Self {
            session_data: HashMap::new(),
        }
    }

    /// Record a data fingerprint for a session.
    /// Call this when a session produces or receives sensitive data.
    pub fn record_data(&mut self, session_id: &str, fingerprint: &str) {
        if self.session_data.len() >= MAX_SESSIONS && !self.session_data.contains_key(session_id) {
            return;
        }
        let entry = self.session_data.entry(session_id.to_string()).or_default();
        if entry.len() < MAX_FINGERPRINTS {
            entry.insert(fingerprint.to_string());
        }
    }

    /// Check if data from another session appears in this session's content.
    /// Returns findings for any cross-session matches.
    pub fn check_for_leaks(
        &self,
        current_session: &str,
        content_fingerprints: &[String],
    ) -> Vec<CrossSessionLeakFinding> {
        let mut findings = Vec::new();

        for (other_session, other_data) in &self.session_data {
            if other_session == current_session {
                continue;
            }
            for fp in content_fingerprints {
                if other_data.contains(fp) {
                    findings.push(CrossSessionLeakFinding {
                        source_session: other_session[..other_session.len().min(32)].to_string(),
                        target_session: current_session[..current_session.len().min(32)]
                            .to_string(),
                        fingerprint: fp[..fp.len().min(32)].to_string(),
                        confidence: 85,
                    });
                }
            }
        }

        findings
    }

    /// Remove a session's data (on session end).
    pub fn clear_session(&mut self, session_id: &str) {
        self.session_data.remove(session_id);
    }

    /// Number of tracked sessions.
    pub fn session_count(&self) -> usize {
        self.session_data.len()
    }
}

impl Default for CrossSessionLeakDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Generate a simple fingerprint for a piece of content.
/// Uses a truncated hash for privacy (doesn't store actual content).
pub fn fingerprint_content(content: &str) -> String {
    use sha2::Digest;
    let hash = sha2::Sha256::digest(content.as_bytes());
    let hex: String = hash[..8].iter().map(|b| format!("{b:02x}")).collect();
    format!("fp:{hex}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_leak_separate_sessions() {
        let mut detector = CrossSessionLeakDetector::new();
        detector.record_data("session-A", "fp:abc123");
        detector.record_data("session-B", "fp:def456");

        let findings = detector.check_for_leaks("session-B", &["fp:xyz789".to_string()]);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_detect_cross_session_leak() {
        let mut detector = CrossSessionLeakDetector::new();
        // Session A produces some data
        detector.record_data("session-A", "fp:secret_data");
        // Session B receives the same data → leak
        let findings = detector.check_for_leaks("session-B", &["fp:secret_data".to_string()]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].source_session, "session-A");
        assert_eq!(findings[0].target_session, "session-B");
    }

    #[test]
    fn test_same_session_not_flagged() {
        let mut detector = CrossSessionLeakDetector::new();
        detector.record_data("session-A", "fp:mydata");
        // Same session accessing its own data → not a leak
        let findings = detector.check_for_leaks("session-A", &["fp:mydata".to_string()]);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_clear_session_removes_data() {
        let mut detector = CrossSessionLeakDetector::new();
        detector.record_data("session-A", "fp:secret");
        detector.clear_session("session-A");
        let findings = detector.check_for_leaks("session-B", &["fp:secret".to_string()]);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_fingerprint_content() {
        let fp1 = fingerprint_content("hello world");
        let fp2 = fingerprint_content("hello world");
        let fp3 = fingerprint_content("different content");
        assert_eq!(fp1, fp2);
        assert_ne!(fp1, fp3);
        assert!(fp1.starts_with("fp:"));
    }

    #[test]
    fn test_capacity_bounded() {
        let mut detector = CrossSessionLeakDetector::new();
        for i in 0..MAX_SESSIONS + 100 {
            detector.record_data(&format!("s-{i}"), "fp:data");
        }
        assert!(detector.session_count() <= MAX_SESSIONS);
    }
}
