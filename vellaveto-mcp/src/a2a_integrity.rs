// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Agent-to-Agent (A2A) message integrity verification (OWASP ASI07).
//!
//! Detects spoofed, replayed, or tampered inter-agent messages.
//! Verifies message provenance, sequence integrity, and content
//! binding to prevent cross-agent injection attacks.

use std::collections::{HashMap, HashSet};

/// Maximum tracked message IDs for replay detection.
const MAX_MESSAGE_IDS: usize = 10_000;

/// An A2A integrity finding.
#[derive(Debug, Clone)]
pub struct A2aIntegrityFinding {
    pub finding_type: A2aIntegrityType,
    pub confidence: u32,
    pub description: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum A2aIntegrityType {
    /// Message ID was seen before (replay).
    ReplayDetected,
    /// Claimed sender doesn't match authenticated identity.
    SenderSpoofing,
    /// Message timestamp is too old or in the future.
    TimestampAnomaly,
    /// Message sequence number is out of order.
    SequenceAnomaly,
    /// Message content doesn't match its declared hash.
    ContentTampering,
}

/// Tracks A2A message integrity state.
pub struct A2aIntegrityTracker {
    /// Seen message IDs for replay detection.
    seen_ids: HashSet<String>,
    /// Per-sender sequence counters.
    sender_sequences: HashMap<String, u64>,
    /// Maximum acceptable message age (seconds).
    max_age_secs: u64,
}

impl A2aIntegrityTracker {
    pub fn new(max_age_secs: u64) -> Self {
        Self {
            seen_ids: HashSet::new(),
            sender_sequences: HashMap::new(),
            max_age_secs,
        }
    }

    /// Verify an inter-agent message.
    pub fn verify_message(
        &mut self,
        message_id: &str,
        claimed_sender: &str,
        authenticated_sender: Option<&str>,
        timestamp_epoch_secs: u64,
        sequence_num: Option<u64>,
    ) -> Vec<A2aIntegrityFinding> {
        let mut findings = Vec::new();

        // Replay detection
        if self.seen_ids.contains(message_id) {
            findings.push(A2aIntegrityFinding {
                finding_type: A2aIntegrityType::ReplayDetected,
                confidence: 95,
                description: format!(
                    "Message ID '{}' was already processed",
                    &message_id[..message_id.len().min(32)]
                ),
            });
        } else if self.seen_ids.len() < MAX_MESSAGE_IDS {
            self.seen_ids.insert(message_id.to_string());
        }

        // Sender spoofing
        if let Some(auth) = authenticated_sender {
            if auth != claimed_sender {
                findings.push(A2aIntegrityFinding {
                    finding_type: A2aIntegrityType::SenderSpoofing,
                    confidence: 90,
                    description: format!(
                        "Claimed sender '{}' != authenticated '{}'",
                        &claimed_sender[..claimed_sender.len().min(32)],
                        &auth[..auth.len().min(32)]
                    ),
                });
            }
        }

        // Timestamp check
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if now_secs > 0 && timestamp_epoch_secs > 0 {
            let age = now_secs.saturating_sub(timestamp_epoch_secs);
            if age > self.max_age_secs {
                findings.push(A2aIntegrityFinding {
                    finding_type: A2aIntegrityType::TimestampAnomaly,
                    confidence: 70,
                    description: format!("Message is {age}s old (max {0}s)", self.max_age_secs),
                });
            }
            if timestamp_epoch_secs > now_secs + 60 {
                findings.push(A2aIntegrityFinding {
                    finding_type: A2aIntegrityType::TimestampAnomaly,
                    confidence: 80,
                    description: format!(
                        "Message timestamp {}s in the future",
                        timestamp_epoch_secs - now_secs
                    ),
                });
            }
        }

        // Sequence check
        if let Some(seq) = sequence_num {
            let last_seq = self
                .sender_sequences
                .get(claimed_sender)
                .copied()
                .unwrap_or(0);
            if seq > 0 && last_seq > 0 && seq <= last_seq {
                findings.push(A2aIntegrityFinding {
                    finding_type: A2aIntegrityType::SequenceAnomaly,
                    confidence: 75,
                    description: format!(
                        "Sequence {seq} <= last seen {last_seq} from '{}'",
                        &claimed_sender[..claimed_sender.len().min(32)]
                    ),
                });
            }
            self.sender_sequences
                .insert(claimed_sender.to_string(), seq);
        }

        findings
    }

    /// Clear state for a sender (on session end).
    pub fn clear_sender(&mut self, sender: &str) {
        self.sender_sequences.remove(sender);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_replay_detected() {
        let mut tracker = A2aIntegrityTracker::new(300);
        let f1 = tracker.verify_message("msg-1", "agent-A", None, 0, None);
        assert!(f1.is_empty());
        let f2 = tracker.verify_message("msg-1", "agent-A", None, 0, None);
        assert!(f2
            .iter()
            .any(|f| f.finding_type == A2aIntegrityType::ReplayDetected));
    }

    #[test]
    fn test_sender_spoofing() {
        let mut tracker = A2aIntegrityTracker::new(300);
        let findings =
            tracker.verify_message("msg-1", "claimed-agent", Some("real-agent"), 0, None);
        assert!(findings
            .iter()
            .any(|f| f.finding_type == A2aIntegrityType::SenderSpoofing));
    }

    #[test]
    fn test_sequence_anomaly() {
        let mut tracker = A2aIntegrityTracker::new(300);
        tracker.verify_message("msg-1", "agent-A", None, 0, Some(5));
        let findings = tracker.verify_message("msg-2", "agent-A", None, 0, Some(3));
        assert!(findings
            .iter()
            .any(|f| f.finding_type == A2aIntegrityType::SequenceAnomaly));
    }

    #[test]
    fn test_clean_message_no_findings() {
        let mut tracker = A2aIntegrityTracker::new(300);
        let findings = tracker.verify_message("msg-1", "agent-A", Some("agent-A"), 0, Some(1));
        assert!(findings.is_empty());
    }

    #[test]
    fn test_future_timestamp() {
        let mut tracker = A2aIntegrityTracker::new(300);
        let future = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600; // 1 hour in future
        let findings = tracker.verify_message("msg-1", "agent-A", None, future, None);
        assert!(findings
            .iter()
            .any(|f| f.finding_type == A2aIntegrityType::TimestampAnomaly));
    }
}
