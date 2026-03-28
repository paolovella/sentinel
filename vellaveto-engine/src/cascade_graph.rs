// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Cascading failure propagation graph (OWASP ASI08).
//!
//! Tracks error propagation across tool calls and agent interactions
//! to detect cascading failure patterns that could indicate systemic
//! compromise or denial-of-service propagation.

use std::collections::HashMap;

/// Maximum tracked nodes in the failure graph.
const MAX_NODES: usize = 500;

/// SECURITY (R255-ENG-3): Maximum failure events per tool within a window.
const MAX_EVENTS_PER_TOOL: usize = 10_000;

/// A failure propagation event.
#[derive(Debug, Clone)]
pub struct FailureEvent {
    pub source: String,
    pub failure_type: FailureType,
    pub timestamp_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureType {
    /// Tool call timed out.
    Timeout,
    /// Tool returned an error.
    ToolError,
    /// Policy denied the call.
    PolicyDenial,
    /// Circuit breaker tripped.
    CircuitBreaker,
    /// Rate limit exceeded.
    RateLimit,
}

/// A cascade finding.
#[derive(Debug, Clone)]
pub struct CascadeFinding {
    pub cascade_depth: usize,
    pub affected_tools: Vec<String>,
    pub trigger: String,
    pub description: String,
}

/// Tracks failure propagation across tool calls.
pub struct CascadeGraph {
    /// Per-tool failure counts in current window.
    failure_counts: HashMap<String, Vec<FailureEvent>>,
    /// Time window for cascade detection (ms).
    window_ms: u64,
    /// Threshold: failures in window to flag cascade.
    cascade_threshold: usize,
}

impl CascadeGraph {
    pub fn new(window_ms: u64, cascade_threshold: usize) -> Self {
        Self {
            failure_counts: HashMap::new(),
            window_ms,
            cascade_threshold: cascade_threshold.max(2),
        }
    }

    /// Record a failure and check for cascade patterns.
    pub fn record_failure(
        &mut self,
        tool_name: &str,
        failure_type: FailureType,
    ) -> Option<CascadeFinding> {
        let now = now_ms();

        // SECURITY (R255-ENG-4): Fail-closed on capacity exhaustion.
        // When at MAX_NODES and the tool is new, emit a capacity-exhaustion
        // finding instead of silently dropping the event (fail-open).
        if self.failure_counts.len() >= MAX_NODES && !self.failure_counts.contains_key(tool_name) {
            return Some(CascadeFinding {
                cascade_depth: self.failure_counts.len(),
                affected_tools: Vec::new(),
                trigger: tool_name.to_string(),
                description: format!(
                    "Cascade tracker at capacity ({MAX_NODES}) — possible evasion attack"
                ),
            });
        }

        let events = self
            .failure_counts
            .entry(tool_name[..tool_name.len().min(256)].to_string())
            .or_default();
        events.push(FailureEvent {
            source: tool_name[..tool_name.len().min(256)].to_string(),
            failure_type,
            timestamp_ms: now,
        });

        // Prune old events
        let cutoff = now.saturating_sub(self.window_ms);
        events.retain(|e| e.timestamp_ms >= cutoff);

        // SECURITY (R255-ENG-3): Truncate oldest entries if per-tool limit exceeded.
        if events.len() > MAX_EVENTS_PER_TOOL {
            let excess = events.len().saturating_sub(MAX_EVENTS_PER_TOOL);
            events.drain(..excess);
        }

        // Count distinct failing tools in the window
        let mut failing_tools = Vec::new();
        for (tool, tool_events) in &self.failure_counts {
            let recent = tool_events
                .iter()
                .filter(|e| e.timestamp_ms >= cutoff)
                .count();
            if recent > 0 {
                failing_tools.push(tool.clone());
            }
        }

        if failing_tools.len() >= self.cascade_threshold {
            Some(CascadeFinding {
                cascade_depth: failing_tools.len(),
                affected_tools: failing_tools,
                trigger: tool_name.to_string(),
                description: format!(
                    "Cascading failure: {} tools failing within {}ms window",
                    self.failure_counts
                        .values()
                        .filter(|v| v.iter().any(|e| e.timestamp_ms >= cutoff))
                        .count(),
                    self.window_ms
                ),
            })
        } else {
            None
        }
    }

    /// Get current failure count across all tools.
    pub fn total_failures_in_window(&self) -> usize {
        let cutoff = now_ms().saturating_sub(self.window_ms);
        self.failure_counts
            .values()
            .flat_map(|v| v.iter())
            .filter(|e| e.timestamp_ms >= cutoff)
            .count()
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
    fn test_single_failure_no_cascade() {
        let mut graph = CascadeGraph::new(60_000, 3);
        let finding = graph.record_failure("tool_a", FailureType::Timeout);
        assert!(finding.is_none());
    }

    #[test]
    fn test_cascade_detected() {
        let mut graph = CascadeGraph::new(60_000, 3);
        graph.record_failure("tool_a", FailureType::Timeout);
        graph.record_failure("tool_b", FailureType::ToolError);
        let finding = graph.record_failure("tool_c", FailureType::CircuitBreaker);
        assert!(finding.is_some());
        let f = finding.unwrap();
        assert!(f.cascade_depth >= 3);
    }

    #[test]
    fn test_total_failures() {
        let mut graph = CascadeGraph::new(60_000, 10);
        graph.record_failure("tool_a", FailureType::Timeout);
        graph.record_failure("tool_a", FailureType::Timeout);
        graph.record_failure("tool_b", FailureType::ToolError);
        assert_eq!(graph.total_failures_in_window(), 3);
    }

    #[test]
    fn test_capacity_bounded() {
        let mut graph = CascadeGraph::new(60_000, 1000);
        for i in 0..MAX_NODES + 50 {
            graph.record_failure(&format!("tool_{i}"), FailureType::Timeout);
        }
        assert!(graph.failure_counts.len() <= MAX_NODES);
    }
}
