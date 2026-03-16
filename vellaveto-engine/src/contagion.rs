// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Phase 3: Context-learning contagion controls.
//!
//! When a tool response carries taint (injection detected, DLP finding, etc.),
//! subsequent actions within the same session inherit that taint — they cannot
//! claim "clean" status just because the immediate tool call is benign.
//!
//! This module provides the contagion policy engine that determines how taint
//! propagates through action chains and when it decays.

use vellaveto_types::{TrustTier, provenance::SinkClass};

/// Contagion propagation mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContagionMode {
    /// Taint persists for the entire session (strictest).
    SessionPersistent,
    /// Taint decays after N clean actions.
    DecayAfterClean(u32),
    /// Taint is cleared on explicit declassification only.
    ExplicitClearOnly,
}

/// Per-session contagion state.
pub struct ContagionTracker {
    mode: ContagionMode,
    /// Current taint labels active in this session.
    active_taints: Vec<TaintEntry>,
    /// Count of consecutive clean actions since last taint.
    clean_action_streak: u32,
    /// Whether any taint has ever been seen in this session.
    ever_tainted: bool,
}

#[derive(Debug, Clone)]
struct TaintEntry {
    source_tool: String,
    #[allow(dead_code)]
    taint_type: ContagionTaintType,
    trust_floor: TrustTier,
}

/// Types of contagion-tracked taint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ContagionTaintType {
    InjectionDetected,
    DlpFinding,
    SchemaPoisoning,
    MemoryPoisoning,
    OutputContractViolation,
    TrustDowngrade,
}

impl ContagionTaintType {
    /// Trust floor imposed by this taint type.
    pub fn trust_floor(self) -> TrustTier {
        match self {
            Self::InjectionDetected => TrustTier::Quarantined,
            Self::DlpFinding => TrustTier::Low,
            Self::SchemaPoisoning => TrustTier::Quarantined,
            Self::MemoryPoisoning => TrustTier::Quarantined,
            Self::OutputContractViolation => TrustTier::Untrusted,
            Self::TrustDowngrade => TrustTier::Low,
        }
    }
}

/// Result of a contagion check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContagionVerdict {
    /// No active contagion — action proceeds normally.
    Clean,
    /// Active contagion — trust is clamped to this floor.
    Tainted {
        trust_floor: TrustTier,
        active_taint_count: usize,
        sources: Vec<String>,
    },
}

/// Maximum taint entries per session.
const MAX_TAINT_ENTRIES: usize = 256;

impl ContagionTracker {
    pub fn new(mode: ContagionMode) -> Self {
        Self {
            mode,
            active_taints: Vec::new(),
            clean_action_streak: 0,
            ever_tainted: false,
        }
    }

    /// Record a taint event from a tool response.
    pub fn record_taint(&mut self, source_tool: &str, taint_type: ContagionTaintType) {
        self.ever_tainted = true;
        self.clean_action_streak = 0;
        if self.active_taints.len() < MAX_TAINT_ENTRIES {
            self.active_taints.push(TaintEntry {
                source_tool: source_tool[..source_tool.len().min(256)].to_string(),
                taint_type,
                trust_floor: taint_type.trust_floor(),
            });
        }
    }

    /// Record a clean action (no findings).
    pub fn record_clean_action(&mut self) {
        self.clean_action_streak = self.clean_action_streak.saturating_add(1);
        // In decay mode, remove taints after enough clean actions
        if let ContagionMode::DecayAfterClean(threshold) = self.mode {
            if self.clean_action_streak >= threshold {
                self.active_taints.clear();
            }
        }
    }

    /// Check if there's active contagion that should affect the next action.
    pub fn check(&self) -> ContagionVerdict {
        if self.active_taints.is_empty() {
            return ContagionVerdict::Clean;
        }

        // Find the strictest trust floor across all active taints
        let trust_floor = self
            .active_taints
            .iter()
            .map(|t| t.trust_floor)
            .min_by_key(|t| t.rank())
            .unwrap_or(TrustTier::Untrusted);

        let sources: Vec<String> = {
            let mut seen = Vec::new();
            for t in &self.active_taints {
                if !seen.contains(&t.source_tool) && seen.len() < 10 {
                    seen.push(t.source_tool.clone());
                }
            }
            seen
        };

        ContagionVerdict::Tainted {
            trust_floor,
            active_taint_count: self.active_taints.len(),
            sources,
        }
    }

    /// Explicitly clear all contagion (declassification).
    pub fn declassify(&mut self) {
        self.active_taints.clear();
    }

    /// Whether this session has ever been tainted.
    pub fn was_ever_tainted(&self) -> bool {
        self.ever_tainted
    }

    /// Check if a specific action to a privileged sink should be blocked
    /// due to contagion.
    pub fn should_block_privileged_sink(&self, sink: SinkClass) -> bool {
        if self.active_taints.is_empty() {
            return false;
        }
        let min_trust = self
            .active_taints
            .iter()
            .map(|t| t.trust_floor)
            .min_by_key(|t| t.rank())
            .unwrap_or(TrustTier::Untrusted);

        let required = vellaveto_types::provenance::minimum_trust_tier_for_sink(sink);
        min_trust.rank() < required.rank()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clean_session() {
        let tracker = ContagionTracker::new(ContagionMode::SessionPersistent);
        assert_eq!(tracker.check(), ContagionVerdict::Clean);
        assert!(!tracker.was_ever_tainted());
    }

    #[test]
    fn test_taint_persists_in_session_mode() {
        let mut tracker = ContagionTracker::new(ContagionMode::SessionPersistent);
        tracker.record_taint("bad_tool", ContagionTaintType::InjectionDetected);
        tracker.record_clean_action();
        tracker.record_clean_action();
        tracker.record_clean_action();
        // Still tainted — session persistent mode
        match tracker.check() {
            ContagionVerdict::Tainted { trust_floor, .. } => {
                assert_eq!(trust_floor, TrustTier::Quarantined);
            }
            _ => panic!("Expected tainted"),
        }
        assert!(tracker.was_ever_tainted());
    }

    #[test]
    fn test_taint_decays_after_clean_actions() {
        let mut tracker = ContagionTracker::new(ContagionMode::DecayAfterClean(3));
        tracker.record_taint("tool", ContagionTaintType::DlpFinding);
        assert!(matches!(tracker.check(), ContagionVerdict::Tainted { .. }));

        tracker.record_clean_action();
        tracker.record_clean_action();
        assert!(matches!(tracker.check(), ContagionVerdict::Tainted { .. }));

        tracker.record_clean_action(); // 3rd clean → decay
        assert_eq!(tracker.check(), ContagionVerdict::Clean);
    }

    #[test]
    fn test_explicit_declassification() {
        let mut tracker = ContagionTracker::new(ContagionMode::ExplicitClearOnly);
        tracker.record_taint("tool", ContagionTaintType::SchemaPoisoning);
        assert!(matches!(tracker.check(), ContagionVerdict::Tainted { .. }));

        // Clean actions don't help in explicit-clear mode
        for _ in 0..100 {
            tracker.record_clean_action();
        }
        assert!(matches!(tracker.check(), ContagionVerdict::Tainted { .. }));

        tracker.declassify();
        assert_eq!(tracker.check(), ContagionVerdict::Clean);
        assert!(tracker.was_ever_tainted()); // history preserved
    }

    #[test]
    fn test_multiple_taints_strictest_floor() {
        let mut tracker = ContagionTracker::new(ContagionMode::SessionPersistent);
        tracker.record_taint("tool_a", ContagionTaintType::DlpFinding); // Low floor
        tracker.record_taint("tool_b", ContagionTaintType::InjectionDetected); // Quarantined floor
        match tracker.check() {
            ContagionVerdict::Tainted { trust_floor, active_taint_count, .. } => {
                assert_eq!(trust_floor, TrustTier::Quarantined); // strictest
                assert_eq!(active_taint_count, 2);
            }
            _ => panic!("Expected tainted"),
        }
    }

    #[test]
    fn test_privileged_sink_blocked_when_tainted() {
        let mut tracker = ContagionTracker::new(ContagionMode::SessionPersistent);
        tracker.record_taint("tool", ContagionTaintType::InjectionDetected);
        // Quarantined trust cannot reach CodeExecution (requires Verified)
        assert!(tracker.should_block_privileged_sink(SinkClass::CodeExecution));
        // Quarantined is below Unknown (ReadOnly minimum), so even reads are blocked
        assert!(tracker.should_block_privileged_sink(SinkClass::ReadOnly));
    }

    #[test]
    fn test_new_taint_resets_clean_streak() {
        let mut tracker = ContagionTracker::new(ContagionMode::DecayAfterClean(3));
        tracker.record_taint("a", ContagionTaintType::DlpFinding);
        tracker.record_clean_action();
        tracker.record_clean_action();
        // 2 clean, almost at threshold... but new taint resets
        tracker.record_taint("b", ContagionTaintType::MemoryPoisoning);
        tracker.record_clean_action();
        tracker.record_clean_action();
        // Only 2 clean since last taint, not 3
        assert!(matches!(tracker.check(), ContagionVerdict::Tainted { .. }));
    }
}
