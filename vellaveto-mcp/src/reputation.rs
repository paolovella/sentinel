// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Phase 2: Server and tool reputation scoring.
//!
//! Tracks behavioral signals from MCP server interactions and computes
//! a reputation score that can influence policy decisions. Signals include:
//! - Injection detection frequency
//! - DLP finding rate
//! - Rug-pull / schema drift events
//! - Tool squatting alerts
//! - Response error rates
//!
//! Scores are per-server and decay over time (configurable half-life).

use std::collections::HashMap;
use std::time::Instant;

/// Maximum number of tracked servers to prevent unbounded memory.
const MAX_TRACKED_SERVERS: usize = 1024;

/// Maximum signal events retained per server.
const MAX_SIGNALS_PER_SERVER: usize = 1000;

/// A negative behavioral signal from a server.
#[derive(Debug, Clone)]
pub struct ReputationSignal {
    /// Signal type (e.g., "injection", "dlp", "rug_pull", "squatting", "error").
    pub signal_type: SignalType,
    /// Severity weight (1-100). Higher = more damaging to reputation.
    pub weight: u32,
    /// When the signal was recorded.
    pub recorded_at: Instant,
}

/// Types of reputation-affecting signals.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SignalType {
    /// Injection pattern detected in server response.
    Injection,
    /// DLP finding (secrets in response).
    DlpFinding,
    /// Rug-pull or schema drift detected.
    RugPull,
    /// Tool squatting alert.
    Squatting,
    /// Server error response.
    ServerError,
    /// Memory poisoning detected.
    MemoryPoisoning,
    /// Schema poisoning detected.
    SchemaPoisoning,
}

impl SignalType {
    /// Default weight for each signal type.
    fn default_weight(self) -> u32 {
        match self {
            Self::Injection => 30,
            Self::DlpFinding => 20,
            Self::RugPull => 50,
            Self::Squatting => 40,
            Self::ServerError => 5,
            Self::MemoryPoisoning => 35,
            Self::SchemaPoisoning => 45,
        }
    }
}

/// Per-server reputation state.
struct ServerReputation {
    signals: Vec<ReputationSignal>,
    total_requests: u64,
    total_allows: u64,
    total_denies: u64,
}

impl ServerReputation {
    fn new() -> Self {
        Self {
            signals: Vec::new(),
            total_requests: 0,
            total_allows: 0,
            total_denies: 0,
        }
    }
}

/// Runtime reputation tracker.
pub struct ReputationTracker {
    servers: HashMap<String, ServerReputation>,
    /// Score decay half-life in seconds.
    decay_half_life_secs: u64,
}

/// Computed reputation score for a server.
#[derive(Debug, Clone)]
pub struct ReputationScore {
    /// Score from 0 (untrusted) to 100 (clean).
    pub score: u32,
    /// Total signals recorded.
    pub total_signals: usize,
    /// Signal breakdown by type.
    pub signal_counts: HashMap<SignalType, usize>,
    /// Total requests seen.
    pub total_requests: u64,
    /// Deny rate (0.0 - 1.0).
    pub deny_rate: f64,
}

impl ReputationTracker {
    /// Create a new reputation tracker.
    ///
    /// `decay_half_life_secs`: older signals contribute less to the score.
    /// Default recommendation: 3600 (1 hour).
    pub fn new(decay_half_life_secs: u64) -> Self {
        Self {
            servers: HashMap::new(),
            decay_half_life_secs: decay_half_life_secs.max(60),
        }
    }

    /// Record a negative behavioral signal for a server.
    pub fn record_signal(&mut self, server_id: &str, signal_type: SignalType) {
        if self.servers.len() >= MAX_TRACKED_SERVERS && !self.servers.contains_key(server_id) {
            return; // Capacity reached — fail-open for tracking (not a security gate)
        }
        let rep = self
            .servers
            .entry(server_id.to_string())
            .or_insert_with(ServerReputation::new);

        if rep.signals.len() >= MAX_SIGNALS_PER_SERVER {
            rep.signals.remove(0); // FIFO eviction
        }
        rep.signals.push(ReputationSignal {
            signal_type,
            weight: signal_type.default_weight(),
            recorded_at: Instant::now(),
        });
    }

    /// Record a request outcome for a server.
    pub fn record_request(&mut self, server_id: &str, allowed: bool) {
        if self.servers.len() >= MAX_TRACKED_SERVERS && !self.servers.contains_key(server_id) {
            return;
        }
        let rep = self
            .servers
            .entry(server_id.to_string())
            .or_insert_with(ServerReputation::new);
        rep.total_requests = rep.total_requests.saturating_add(1);
        if allowed {
            rep.total_allows = rep.total_allows.saturating_add(1);
        } else {
            rep.total_denies = rep.total_denies.saturating_add(1);
        }
    }

    /// Compute the current reputation score for a server.
    ///
    /// Returns None if the server has no recorded signals or requests.
    pub fn score(&self, server_id: &str) -> Option<ReputationScore> {
        let rep = self.servers.get(server_id)?;
        if rep.total_requests == 0 && rep.signals.is_empty() {
            return None;
        }

        let now = Instant::now();
        let half_life = self.decay_half_life_secs as f64;

        // Compute weighted signal score with exponential decay.
        let mut total_weight: f64 = 0.0;
        let mut signal_counts: HashMap<SignalType, usize> = HashMap::new();

        for signal in &rep.signals {
            let age_secs = now.duration_since(signal.recorded_at).as_secs_f64();
            let decay = 0.5_f64.powf(age_secs / half_life);
            total_weight += f64::from(signal.weight) * decay;
            *signal_counts.entry(signal.signal_type).or_default() += 1;
        }

        // Map weighted signals to a 0-100 score (100 = clean, 0 = untrusted).
        // Sigmoid-like curve: score = 100 / (1 + total_weight / 50)
        let score = (100.0 / (1.0 + total_weight / 50.0)) as u32;

        let deny_rate = if rep.total_requests > 0 {
            rep.total_denies as f64 / rep.total_requests as f64
        } else {
            0.0
        };

        Some(ReputationScore {
            score,
            total_signals: rep.signals.len(),
            signal_counts,
            total_requests: rep.total_requests,
            deny_rate,
        })
    }

    /// Check if a server's reputation is below a threshold.
    pub fn is_below_threshold(&self, server_id: &str, threshold: u32) -> bool {
        self.score(server_id)
            .map(|s| s.score < threshold)
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_server_has_no_score() {
        let tracker = ReputationTracker::new(3600);
        assert!(tracker.score("unknown").is_none());
    }

    #[test]
    fn test_clean_server_has_high_score() {
        let mut tracker = ReputationTracker::new(3600);
        tracker.record_request("server-a", true);
        tracker.record_request("server-a", true);
        tracker.record_request("server-a", true);
        let score = tracker.score("server-a").unwrap();
        assert_eq!(score.score, 100); // No signals → max score
        assert_eq!(score.total_requests, 3);
        assert!(score.deny_rate < 0.01);
    }

    #[test]
    fn test_signals_lower_score() {
        let mut tracker = ReputationTracker::new(3600);
        tracker.record_signal("server-b", SignalType::Injection);
        tracker.record_signal("server-b", SignalType::Injection);
        tracker.record_signal("server-b", SignalType::RugPull);
        let score = tracker.score("server-b").unwrap();
        assert!(score.score < 100, "Score should be lowered: {}", score.score);
        assert_eq!(score.total_signals, 3);
        assert_eq!(score.signal_counts[&SignalType::Injection], 2);
        assert_eq!(score.signal_counts[&SignalType::RugPull], 1);
    }

    #[test]
    fn test_is_below_threshold() {
        let mut tracker = ReputationTracker::new(3600);
        // Many heavy signals to push score low
        for _ in 0..20 {
            tracker.record_signal("bad-server", SignalType::RugPull);
        }
        assert!(tracker.is_below_threshold("bad-server", 50));
        assert!(!tracker.is_below_threshold("clean-server", 50));
    }

    #[test]
    fn test_deny_rate_computation() {
        let mut tracker = ReputationTracker::new(3600);
        tracker.record_request("server-c", true);
        tracker.record_request("server-c", false);
        tracker.record_request("server-c", true);
        tracker.record_request("server-c", false);
        let score = tracker.score("server-c").unwrap();
        assert!((score.deny_rate - 0.5).abs() < 0.01);
    }

    #[test]
    fn test_capacity_bounded() {
        let mut tracker = ReputationTracker::new(3600);
        for i in 0..MAX_TRACKED_SERVERS + 100 {
            tracker.record_signal(&format!("server-{i}"), SignalType::ServerError);
        }
        assert!(tracker.servers.len() <= MAX_TRACKED_SERVERS);
    }
}
