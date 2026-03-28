// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Agent behavioral baseline and rogue agent detection (OWASP ASI10).
//!
//! Tracks normal agent behavior patterns and detects deviations that
//! indicate a rogue or compromised agent. The baseline covers:
//! - Typical tool usage distribution
//! - Normal sink class distribution
//! - Expected call rate
//! - Typical session duration

use std::collections::HashMap;
use vellaveto_types::provenance::SinkClass;

/// Maximum tracked agents.
const MAX_AGENTS: usize = 1000;

/// SECURITY (R255-ENG-2): Maximum distinct tools per agent baseline.
const MAX_TOOLS_PER_BASELINE: usize = 1_000;

/// An agent's behavioral baseline.
#[derive(Debug, Clone, Default)]
pub struct AgentBaseline {
    /// Tool usage counts during baseline period.
    pub tool_counts: HashMap<String, u32>,
    /// Sink class usage counts.
    pub sink_counts: HashMap<u8, u32>,
    /// Total calls in baseline.
    pub total_calls: u32,
    /// Whether baseline is established (enough data).
    pub established: bool,
}

/// A behavioral deviation finding.
#[derive(Debug, Clone)]
pub struct DeviationFinding {
    pub deviation_type: DeviationType,
    pub agent_id: String,
    pub confidence: u32,
    pub description: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviationType {
    /// Agent using tools it never used before.
    NovelToolUsage,
    /// Agent targeting sink classes outside its normal pattern.
    SinkClassDeviation,
    /// Call rate significantly above baseline.
    RateAnomaly,
    /// Agent behavior changed abruptly (possible compromise).
    BehaviorShift,
}

/// Tracks agent baselines and detects deviations.
pub struct AgentBaselineTracker {
    baselines: HashMap<String, AgentBaseline>,
    /// Minimum calls before baseline is established.
    min_baseline_calls: u32,
}

impl AgentBaselineTracker {
    pub fn new(min_baseline_calls: u32) -> Self {
        Self {
            baselines: HashMap::new(),
            min_baseline_calls: min_baseline_calls.max(5),
        }
    }

    /// Record a tool call and check for deviations.
    pub fn record_and_check(
        &mut self,
        agent_id: &str,
        tool_name: &str,
        sink_class: SinkClass,
    ) -> Vec<DeviationFinding> {
        if self.baselines.len() >= MAX_AGENTS && !self.baselines.contains_key(agent_id) {
            return Vec::new();
        }

        let baseline = self.baselines.entry(agent_id.to_string()).or_default();

        let mut findings = Vec::new();

        if baseline.established {
            // Check for novel tool usage
            if !baseline.tool_counts.contains_key(tool_name) {
                findings.push(DeviationFinding {
                    deviation_type: DeviationType::NovelToolUsage,
                    agent_id: agent_id.to_string(),
                    confidence: 60,
                    description: format!(
                        "Agent '{}' using novel tool '{}' not in baseline ({} known tools)",
                        &agent_id[..agent_id.len().min(32)],
                        &tool_name[..tool_name.len().min(32)],
                        baseline.tool_counts.len()
                    ),
                });
            }

            // Check for sink class deviation
            let sink_rank = sink_class.rank();
            if !baseline.sink_counts.contains_key(&sink_rank)
                && sink_rank >= SinkClass::CodeExecution.rank()
            {
                findings.push(DeviationFinding {
                    deviation_type: DeviationType::SinkClassDeviation,
                    agent_id: agent_id.to_string(),
                    confidence: 75,
                    description: format!(
                        "Agent '{}' targeting {:?} — not in behavioral baseline",
                        &agent_id[..agent_id.len().min(32)],
                        sink_class
                    ),
                });
            }
        }

        // Update baseline
        // SECURITY (R255-ENG-2): Skip insertion if at capacity and tool is new.
        let tool_key = &tool_name[..tool_name.len().min(256)];
        if baseline.tool_counts.contains_key(tool_key)
            || baseline.tool_counts.len() < MAX_TOOLS_PER_BASELINE
        {
            *baseline
                .tool_counts
                .entry(tool_key.to_string())
                .or_insert(0) = baseline
                .tool_counts
                .get(tool_key)
                .copied()
                .unwrap_or(0)
                .saturating_add(1);
        }
        *baseline.sink_counts.entry(sink_class.rank()).or_insert(0) = baseline
            .sink_counts
            .get(&sink_class.rank())
            .copied()
            .unwrap_or(0)
            .saturating_add(1);
        baseline.total_calls = baseline.total_calls.saturating_add(1);

        if !baseline.established && baseline.total_calls >= self.min_baseline_calls {
            baseline.established = true;
        }

        findings
    }

    /// Get the baseline for an agent, if established.
    pub fn get_baseline(&self, agent_id: &str) -> Option<&AgentBaseline> {
        self.baselines.get(agent_id).filter(|b| b.established)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_baseline_not_established_no_findings() {
        let mut tracker = AgentBaselineTracker::new(10);
        let findings = tracker.record_and_check("agent-1", "read_file", SinkClass::ReadOnly);
        assert!(findings.is_empty());
        assert!(tracker.get_baseline("agent-1").is_none());
    }

    #[test]
    fn test_baseline_established_after_min_calls() {
        let mut tracker = AgentBaselineTracker::new(5);
        for _ in 0..5 {
            tracker.record_and_check("agent-1", "read_file", SinkClass::ReadOnly);
        }
        assert!(tracker.get_baseline("agent-1").is_some());
    }

    #[test]
    fn test_novel_tool_deviation() {
        let mut tracker = AgentBaselineTracker::new(5);
        for _ in 0..5 {
            tracker.record_and_check("agent-1", "read_file", SinkClass::ReadOnly);
        }
        // Now use a tool never seen before
        let findings =
            tracker.record_and_check("agent-1", "execute_command", SinkClass::CodeExecution);
        assert!(findings
            .iter()
            .any(|f| f.deviation_type == DeviationType::NovelToolUsage));
    }

    #[test]
    fn test_sink_class_deviation() {
        let mut tracker = AgentBaselineTracker::new(5);
        for _ in 0..5 {
            tracker.record_and_check("agent-1", "read_file", SinkClass::ReadOnly);
        }
        // Jump to CodeExecution — never seen before
        let findings = tracker.record_and_check("agent-1", "read_file", SinkClass::CodeExecution);
        assert!(findings
            .iter()
            .any(|f| f.deviation_type == DeviationType::SinkClassDeviation));
    }

    #[test]
    fn test_known_tool_no_finding() {
        let mut tracker = AgentBaselineTracker::new(5);
        for _ in 0..5 {
            tracker.record_and_check("agent-1", "read_file", SinkClass::ReadOnly);
        }
        // Use the same tool → no deviation
        let findings = tracker.record_and_check("agent-1", "read_file", SinkClass::ReadOnly);
        assert!(findings.is_empty());
    }
}
