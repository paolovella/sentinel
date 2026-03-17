// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Denial of Wallet (DoW) / unbounded consumption detection (OWASP LLM10).
//!
//! Detects patterns that cause excessive resource consumption:
//! - Agentic loop amplification (tool calls that trigger more tool calls)
//! - High-cost inference patterns (very long outputs, many completions)
//! - Token exhaustion via repeated sampling
//! - Recursive tool invocation patterns

/// Maximum window size for rate tracking.
const MAX_WINDOW_ENTRIES: usize = 1000;

/// A denial of wallet finding.
#[derive(Debug, Clone)]
pub struct DoWFinding {
    pub finding_type: DoWType,
    pub severity: u32,
    pub description: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DoWType {
    /// Tool call rate exceeds normal bounds.
    RateSpike,
    /// Recursive tool pattern detected (A calls B calls A).
    RecursiveLoop,
    /// Sampling requests consuming excessive tokens.
    TokenExhaustion,
    /// Session duration exceeds bounds.
    SessionExhaustion,
}

/// Tracks resource consumption patterns per session.
pub struct DoWTracker {
    /// Tool call timestamps (ms).
    call_timestamps: Vec<u64>,
    /// Recent tool names for loop detection.
    recent_tools: Vec<String>,
    /// Total estimated tokens consumed.
    total_tokens: u64,
    /// Session start time (ms).
    session_start_ms: u64,
    /// Config thresholds.
    max_calls_per_minute: u32,
    max_tokens_per_session: u64,
    max_session_duration_ms: u64,
}

impl DoWTracker {
    pub fn new(
        max_calls_per_minute: u32,
        max_tokens_per_session: u64,
        max_session_duration_ms: u64,
    ) -> Self {
        Self {
            call_timestamps: Vec::new(),
            recent_tools: Vec::new(),
            total_tokens: 0,
            session_start_ms: now_ms(),
            max_calls_per_minute,
            max_tokens_per_session,
            max_session_duration_ms,
        }
    }

    /// Record a tool call and check for DoW patterns.
    pub fn record_call(&mut self, tool_name: &str, estimated_tokens: u64) -> Vec<DoWFinding> {
        let now = now_ms();
        let mut findings = Vec::new();

        // Record timestamp
        if self.call_timestamps.len() < MAX_WINDOW_ENTRIES {
            self.call_timestamps.push(now);
        }

        // Record tool name for loop detection
        if self.recent_tools.len() >= 20 {
            self.recent_tools.remove(0);
        }
        self.recent_tools
            .push(tool_name[..tool_name.len().min(256)].to_string());

        // Track tokens
        self.total_tokens = self.total_tokens.saturating_add(estimated_tokens);

        // Check rate spike
        let one_min_ago = now.saturating_sub(60_000);
        let calls_last_minute = self
            .call_timestamps
            .iter()
            .filter(|&&t| t >= one_min_ago)
            .count() as u32;
        if calls_last_minute > self.max_calls_per_minute {
            findings.push(DoWFinding {
                finding_type: DoWType::RateSpike,
                severity: 70,
                description: format!(
                    "{calls_last_minute} calls in last minute (max {0})",
                    self.max_calls_per_minute
                ),
            });
        }

        // Check recursive loop (A→B→A pattern)
        if self.recent_tools.len() >= 4 {
            let len = self.recent_tools.len();
            // Check for A-B-A-B pattern
            if self.recent_tools[len - 1] == self.recent_tools[len - 3]
                && self.recent_tools[len - 2] == self.recent_tools[len - 4]
                && self.recent_tools[len - 1] != self.recent_tools[len - 2]
            {
                findings.push(DoWFinding {
                    finding_type: DoWType::RecursiveLoop,
                    severity: 85,
                    description: format!(
                        "Recursive loop: {} ↔ {}",
                        &self.recent_tools[len - 1],
                        &self.recent_tools[len - 2]
                    ),
                });
            }
        }

        // Check token exhaustion
        if self.total_tokens > self.max_tokens_per_session {
            findings.push(DoWFinding {
                finding_type: DoWType::TokenExhaustion,
                severity: 75,
                description: format!(
                    "{} tokens consumed (max {})",
                    self.total_tokens, self.max_tokens_per_session
                ),
            });
        }

        // Check session exhaustion
        let duration = now.saturating_sub(self.session_start_ms);
        if duration > self.max_session_duration_ms {
            findings.push(DoWFinding {
                finding_type: DoWType::SessionExhaustion,
                severity: 60,
                description: format!(
                    "Session running {}ms (max {}ms)",
                    duration, self.max_session_duration_ms
                ),
            });
        }

        findings
    }

    /// Get total tokens consumed.
    pub fn total_tokens(&self) -> u64 {
        self.total_tokens
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_spike_detected() {
        let mut tracker = DoWTracker::new(5, 1_000_000, 3_600_000);
        for _ in 0..6 {
            tracker.record_call("tool", 10);
        }
        let findings = tracker.record_call("tool", 10);
        assert!(findings
            .iter()
            .any(|f| f.finding_type == DoWType::RateSpike));
    }

    #[test]
    fn test_recursive_loop_detected() {
        let mut tracker = DoWTracker::new(100, 1_000_000, 3_600_000);
        tracker.record_call("tool_a", 10);
        tracker.record_call("tool_b", 10);
        tracker.record_call("tool_a", 10);
        let findings = tracker.record_call("tool_b", 10);
        assert!(findings
            .iter()
            .any(|f| f.finding_type == DoWType::RecursiveLoop));
    }

    #[test]
    fn test_token_exhaustion() {
        let mut tracker = DoWTracker::new(100, 100, 3_600_000);
        tracker.record_call("tool", 60);
        let findings = tracker.record_call("tool", 60);
        assert!(findings
            .iter()
            .any(|f| f.finding_type == DoWType::TokenExhaustion));
    }

    #[test]
    fn test_normal_usage_no_findings() {
        let mut tracker = DoWTracker::new(100, 1_000_000, 3_600_000);
        let findings = tracker.record_call("read_file", 50);
        assert!(findings.is_empty());
    }
}
