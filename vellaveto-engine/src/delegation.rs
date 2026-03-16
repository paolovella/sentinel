// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Phase 3: Multi-agent delegation control.
//!
//! Tracks and enforces delegation chains across servers and agents.
//! When agent A delegates to agent B, and B delegates to C, the chain
//! A → B → C must satisfy:
//! - Maximum depth limit (default: 5)
//! - No cycles (A → B → A)
//! - Trust monotonicity (each hop must not escalate trust)
//! - Policy-controlled delegation targets

use std::collections::{HashMap, HashSet};
use vellaveto_types::TrustTier;

/// Maximum delegation chain depth.
const MAX_CHAIN_DEPTH: usize = 10;

/// Maximum tracked chains to prevent unbounded memory.
const MAX_TRACKED_CHAINS: usize = 10_000;

/// A link in a delegation chain.
#[derive(Debug, Clone)]
pub struct DelegationLink {
    /// Source agent/server.
    pub source: String,
    /// Target agent/server.
    pub target: String,
    /// Trust tier of the source at delegation time.
    pub source_trust: TrustTier,
    /// Trust tier of the target.
    pub target_trust: TrustTier,
    /// Tool being delegated.
    pub tool: String,
}

/// Result of a delegation check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DelegationVerdict {
    /// Delegation is allowed.
    Allowed,
    /// Delegation denied — chain too deep.
    TooDeep { depth: usize, max: usize },
    /// Delegation denied — cycle detected.
    CycleDetected { cycle_at: String },
    /// Delegation denied — trust escalation.
    TrustEscalation {
        source_trust: TrustTier,
        target_trust: TrustTier,
    },
    /// Delegation denied — target not in allowed list.
    TargetNotAllowed { target: String },
}

/// Tracks active delegation chains per session.
pub struct DelegationTracker {
    /// Active chains: session_id → chain of delegation links.
    chains: HashMap<String, Vec<DelegationLink>>,
    /// Maximum allowed chain depth.
    max_depth: usize,
    /// Allowed delegation targets (glob patterns). Empty = all allowed.
    allowed_targets: Vec<String>,
    /// Blocked delegation targets (glob patterns).
    blocked_targets: Vec<String>,
    /// Whether trust escalation is forbidden (default: true).
    forbid_trust_escalation: bool,
}

impl DelegationTracker {
    /// Create a new delegation tracker.
    pub fn new(
        max_depth: usize,
        allowed_targets: Vec<String>,
        blocked_targets: Vec<String>,
        forbid_trust_escalation: bool,
    ) -> Self {
        Self {
            chains: HashMap::new(),
            max_depth: max_depth.min(MAX_CHAIN_DEPTH),
            allowed_targets,
            blocked_targets,
            forbid_trust_escalation,
        }
    }

    /// Check if a delegation is permitted before recording it.
    pub fn check_delegation(&self, session_id: &str, link: &DelegationLink) -> DelegationVerdict {
        // Check target against block/allow lists
        if self
            .blocked_targets
            .iter()
            .any(|p| pattern_matches(p, &link.target))
        {
            return DelegationVerdict::TargetNotAllowed {
                target: link.target.clone(),
            };
        }
        if !self.allowed_targets.is_empty()
            && !self
                .allowed_targets
                .iter()
                .any(|p| pattern_matches(p, &link.target))
        {
            return DelegationVerdict::TargetNotAllowed {
                target: link.target.clone(),
            };
        }

        // Check chain depth
        let current_depth = self.chains.get(session_id).map(|c| c.len()).unwrap_or(0);
        if current_depth >= self.max_depth {
            return DelegationVerdict::TooDeep {
                depth: current_depth + 1,
                max: self.max_depth,
            };
        }

        // Check for cycles
        if let Some(chain) = self.chains.get(session_id) {
            let mut visited: HashSet<&str> = HashSet::new();
            for l in chain {
                visited.insert(&l.source);
                visited.insert(&l.target);
            }
            if visited.contains(link.target.as_str()) {
                return DelegationVerdict::CycleDetected {
                    cycle_at: link.target.clone(),
                };
            }
        }

        // Check trust monotonicity
        if self.forbid_trust_escalation && link.target_trust.rank() > link.source_trust.rank() {
            return DelegationVerdict::TrustEscalation {
                source_trust: link.source_trust,
                target_trust: link.target_trust,
            };
        }

        DelegationVerdict::Allowed
    }

    /// Record a delegation link after it has been permitted.
    pub fn record_delegation(&mut self, session_id: &str, link: DelegationLink) {
        if self.chains.len() >= MAX_TRACKED_CHAINS && !self.chains.contains_key(session_id) {
            return;
        }
        self.chains
            .entry(session_id.to_string())
            .or_default()
            .push(link);
    }

    /// Get the current chain depth for a session.
    pub fn chain_depth(&self, session_id: &str) -> usize {
        self.chains.get(session_id).map(|c| c.len()).unwrap_or(0)
    }

    /// Clear a session's delegation chain (on session end).
    pub fn clear_session(&mut self, session_id: &str) {
        self.chains.remove(session_id);
    }
}

fn pattern_matches(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(star_pos) = pattern.find('*') {
        let prefix = &pattern[..star_pos];
        let suffix = &pattern[star_pos + 1..];
        value.starts_with(prefix) && value.ends_with(suffix)
    } else {
        pattern == value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn link(source: &str, target: &str, tool: &str) -> DelegationLink {
        DelegationLink {
            source: source.to_string(),
            target: target.to_string(),
            source_trust: TrustTier::Medium,
            target_trust: TrustTier::Medium,
            tool: tool.to_string(),
        }
    }

    #[test]
    fn test_delegation_allowed_simple() {
        let tracker = DelegationTracker::new(5, Vec::new(), Vec::new(), true);
        let l = link("agent-A", "agent-B", "read_file");
        assert_eq!(
            tracker.check_delegation("s1", &l),
            DelegationVerdict::Allowed
        );
    }

    #[test]
    fn test_delegation_depth_limit() {
        let mut tracker = DelegationTracker::new(2, Vec::new(), Vec::new(), true);
        tracker.record_delegation("s1", link("A", "B", "t1"));
        tracker.record_delegation("s1", link("B", "C", "t2"));
        let verdict = tracker.check_delegation("s1", &link("C", "D", "t3"));
        assert!(matches!(
            verdict,
            DelegationVerdict::TooDeep { depth: 3, max: 2 }
        ));
    }

    #[test]
    fn test_delegation_cycle_detected() {
        let mut tracker = DelegationTracker::new(5, Vec::new(), Vec::new(), true);
        tracker.record_delegation("s1", link("A", "B", "t1"));
        tracker.record_delegation("s1", link("B", "C", "t2"));
        // C trying to delegate back to A — cycle
        let verdict = tracker.check_delegation("s1", &link("C", "A", "t3"));
        assert_eq!(
            verdict,
            DelegationVerdict::CycleDetected {
                cycle_at: "A".to_string()
            }
        );
    }

    #[test]
    fn test_delegation_trust_escalation_blocked() {
        let tracker = DelegationTracker::new(5, Vec::new(), Vec::new(), true);
        let l = DelegationLink {
            source: "low-agent".to_string(),
            target: "high-agent".to_string(),
            source_trust: TrustTier::Low,
            target_trust: TrustTier::High, // escalation!
            tool: "sensitive_op".to_string(),
        };
        assert!(matches!(
            tracker.check_delegation("s1", &l),
            DelegationVerdict::TrustEscalation { .. }
        ));
    }

    #[test]
    fn test_delegation_trust_escalation_allowed_when_disabled() {
        let tracker = DelegationTracker::new(5, Vec::new(), Vec::new(), false);
        let l = DelegationLink {
            source: "low".to_string(),
            target: "high".to_string(),
            source_trust: TrustTier::Low,
            target_trust: TrustTier::High,
            tool: "op".to_string(),
        };
        assert_eq!(
            tracker.check_delegation("s1", &l),
            DelegationVerdict::Allowed
        );
    }

    #[test]
    fn test_delegation_blocked_target() {
        let tracker = DelegationTracker::new(5, Vec::new(), vec!["evil-*".to_string()], true);
        let l = link("A", "evil-agent", "op");
        assert!(matches!(
            tracker.check_delegation("s1", &l),
            DelegationVerdict::TargetNotAllowed { .. }
        ));
    }

    #[test]
    fn test_delegation_allowed_target_list() {
        let tracker = DelegationTracker::new(5, vec!["trusted-*".to_string()], Vec::new(), true);
        assert_eq!(
            tracker.check_delegation("s1", &link("A", "trusted-B", "op")),
            DelegationVerdict::Allowed
        );
        assert!(matches!(
            tracker.check_delegation("s1", &link("A", "untrusted-C", "op")),
            DelegationVerdict::TargetNotAllowed { .. }
        ));
    }

    #[test]
    fn test_clear_session() {
        let mut tracker = DelegationTracker::new(5, Vec::new(), Vec::new(), true);
        tracker.record_delegation("s1", link("A", "B", "t1"));
        assert_eq!(tracker.chain_depth("s1"), 1);
        tracker.clear_session("s1");
        assert_eq!(tracker.chain_depth("s1"), 0);
    }
}
