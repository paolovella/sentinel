// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Phase 6.3: Behavioral sequence analysis.
//!
//! Tracks tool call sequences within a session and detects behavioral
//! anomalies that may indicate injection-provoked actions — even within
//! the allowed intent scope. Five deterministic heuristic detectors,
//! no ML, all auditable.

use vellaveto_types::provenance::SinkClass;

/// Maximum call log entries per session.
const MAX_CALL_LOG: usize = 1000;

/// SECURITY (R255-ENG-1): Maximum accumulated anomalies to prevent unbounded growth.
const MAX_ANOMALIES: usize = 10_000;

/// A recorded tool call in the sequence.
#[derive(Debug, Clone)]
struct SequenceEntry {
    tool_name: String,
    sink_class: SinkClass,
    timestamp_ms: u64,
    source_tainted: bool,
    is_novel: bool,
}

/// Configuration for sequence analysis.
#[derive(Debug, Clone)]
pub struct SequenceConfig {
    /// Minimum calls before anomaly detection activates.
    pub warmup_calls: u32,
    /// Max time (ms) between tainted source read and privileged action.
    pub read_to_act_window_ms: u64,
    /// Max new distinct tools after first taint before flagging.
    pub max_new_tools_after_taint: u32,
    /// Action on anomaly detection.
    pub anomaly_action: AnomalyAction,
}

impl Default for SequenceConfig {
    fn default() -> Self {
        Self {
            warmup_calls: crate::verified_sequence_gate::WARMUP_CALLS,
            read_to_act_window_ms: 5000,
            max_new_tools_after_taint: crate::verified_sequence_gate::MAX_NEW_TOOLS,
            anomaly_action: AnomalyAction::AuditOnly,
        }
    }
}

/// What to do when an anomaly is detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnomalyAction {
    Block,
    RequireApproval,
    AuditOnly,
}

/// A detected behavioral anomaly.
#[derive(Debug, Clone)]
pub struct SequenceAnomaly {
    pub anomaly_type: AnomalyType,
    pub confidence: u32,
    pub description: String,
}

/// Types of sequence anomalies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnomalyType {
    /// Sensitive read followed by network egress.
    ReadThenExfil,
    /// Sink class jump after source taint.
    PrivilegeEscalationAfterTaint,
    /// New tools cluster after taint event.
    ToolDiversitySpike,
    /// Never-seen tool targets privileged sink after untrusted content.
    NovelToolAfterUntrustedContent,
    /// Burst of privileged sink calls.
    PrivilegedActionCluster,
}

/// Tracks tool call sequences and detects anomalies.
pub struct SequenceTracker {
    call_log: Vec<SequenceEntry>,
    distinct_tools: Vec<String>,
    config: SequenceConfig,
    first_taint_idx: Option<usize>,
    tools_before_taint: usize,
    anomalies: Vec<SequenceAnomaly>,
}

impl SequenceTracker {
    pub fn new(config: SequenceConfig) -> Self {
        Self {
            call_log: Vec::new(),
            distinct_tools: Vec::new(),
            config,
            first_taint_idx: None,
            tools_before_taint: 0,
            anomalies: Vec::new(),
        }
    }

    /// Record a tool call and run all detectors.
    pub fn record_and_analyze(
        &mut self,
        tool_name: &str,
        sink_class: SinkClass,
        source_tainted: bool,
        now_ms: u64,
    ) -> Vec<SequenceAnomaly> {
        let is_novel = !self.distinct_tools.iter().any(|t| t == tool_name);
        if is_novel && self.distinct_tools.len() < MAX_CALL_LOG {
            self.distinct_tools.push(tool_name.to_string());
        }

        if source_tainted && self.first_taint_idx.is_none() {
            self.first_taint_idx = Some(self.call_log.len());
            self.tools_before_taint = self.distinct_tools.len().saturating_sub(1);
        }

        let entry = SequenceEntry {
            tool_name: tool_name[..tool_name.len().min(256)].to_string(),
            sink_class,
            timestamp_ms: now_ms,
            source_tainted,
            is_novel,
        };

        if self.call_log.len() < MAX_CALL_LOG {
            self.call_log.push(entry);
        }

        if (self.call_log.len() as u32) < self.config.warmup_calls {
            return Vec::new();
        }

        let mut new_anomalies = Vec::new();

        if let Some(a) = self.detect_read_then_exfil() {
            new_anomalies.push(a);
        }
        if let Some(a) = self.detect_privilege_escalation_after_taint() {
            new_anomalies.push(a);
        }
        if let Some(a) = self.detect_tool_diversity_spike() {
            new_anomalies.push(a);
        }
        if let Some(a) = self.detect_novel_tool_after_untrusted() {
            new_anomalies.push(a);
        }
        if let Some(a) = self.detect_privileged_action_cluster() {
            new_anomalies.push(a);
        }

        // SECURITY (R255-ENG-1): Cap accumulated anomalies to prevent unbounded growth.
        if self.anomalies.len() < MAX_ANOMALIES {
            let remaining = MAX_ANOMALIES.saturating_sub(self.anomalies.len());
            self.anomalies
                .extend(new_anomalies.iter().take(remaining).cloned());
        }
        new_anomalies
    }

    /// Get all anomalies detected so far.
    pub fn anomalies(&self) -> &[SequenceAnomaly] {
        &self.anomalies
    }

    /// Highest confidence anomaly, if any.
    pub fn max_confidence(&self) -> u32 {
        self.anomalies
            .iter()
            .map(|a| a.confidence)
            .max()
            .unwrap_or(0)
    }

    // ═══════════════════════════════════════════════════
    // Detectors
    // ═══════════════════════════════════════════════════

    /// Detector 1: Sensitive read followed by network egress within window.
    fn detect_read_then_exfil(&self) -> Option<SequenceAnomaly> {
        let len = self.call_log.len();
        if len < 2 {
            return None;
        }
        let current = &self.call_log[len - 1];
        if !matches!(current.sink_class, SinkClass::NetworkEgress) {
            return None;
        }
        // Look back for a tainted read within the window
        for i in (0..len - 1).rev() {
            let prev = &self.call_log[i];
            if current.timestamp_ms.saturating_sub(prev.timestamp_ms)
                > self.config.read_to_act_window_ms
            {
                break;
            }
            if prev.source_tainted && matches!(prev.sink_class, SinkClass::ReadOnly) {
                return Some(SequenceAnomaly {
                    anomaly_type: AnomalyType::ReadThenExfil,
                    confidence: 80,
                    description: format!(
                        "tainted read '{}' followed by network egress '{}'",
                        prev.tool_name, current.tool_name
                    ),
                });
            }
        }
        None
    }

    /// Detector 2: Privilege escalation after source taint.
    fn detect_privilege_escalation_after_taint(&self) -> Option<SequenceAnomaly> {
        let taint_idx = self.first_taint_idx?;
        let current = self.call_log.last()?;

        // Was the session only using low-privilege sinks before taint?
        let max_pre_taint_sink = self.call_log[..taint_idx]
            .iter()
            .map(|e| e.sink_class.rank())
            .max()
            .unwrap_or(0);

        if max_pre_taint_sink <= SinkClass::LowRiskWrite.rank()
            && current.sink_class.rank() >= SinkClass::CodeExecution.rank()
        {
            return Some(SequenceAnomaly {
                anomaly_type: AnomalyType::PrivilegeEscalationAfterTaint,
                confidence: 90,
                description: format!(
                    "privilege escalation to {:?} after source taint (pre-taint max: LowRiskWrite)",
                    current.sink_class
                ),
            });
        }
        None
    }

    /// Detector 3: Tool diversity spike after taint.
    fn detect_tool_diversity_spike(&self) -> Option<SequenceAnomaly> {
        let _taint_idx = self.first_taint_idx?;
        let new_tools_after_taint = self
            .distinct_tools
            .len()
            .saturating_sub(self.tools_before_taint);

        if new_tools_after_taint > self.config.max_new_tools_after_taint as usize {
            return Some(SequenceAnomaly {
                anomaly_type: AnomalyType::ToolDiversitySpike,
                confidence: 60,
                description: format!(
                    "{new_tools_after_taint} new tools after taint (max: {})",
                    self.config.max_new_tools_after_taint
                ),
            });
        }
        None
    }

    /// Detector 4: Novel tool targeting privileged sink after untrusted content.
    fn detect_novel_tool_after_untrusted(&self) -> Option<SequenceAnomaly> {
        let len = self.call_log.len();
        if len < 2 {
            return None;
        }
        let current = &self.call_log[len - 1];
        if !current.is_novel || current.sink_class.rank() < SinkClass::CodeExecution.rank() {
            return None;
        }
        // Check if previous call was tainted
        let prev = &self.call_log[len - 2];
        if prev.source_tainted {
            return Some(SequenceAnomaly {
                anomaly_type: AnomalyType::NovelToolAfterUntrustedContent,
                confidence: 85,
                description: format!(
                    "novel tool '{}' ({:?}) immediately after untrusted '{}'",
                    current.tool_name, current.sink_class, prev.tool_name
                ),
            });
        }
        None
    }

    /// Detector 5: Temporal clustering of privileged actions.
    fn detect_privileged_action_cluster(&self) -> Option<SequenceAnomaly> {
        // Don't duplicate this specific anomaly type
        if self
            .anomalies
            .iter()
            .any(|a| a.anomaly_type == AnomalyType::PrivilegedActionCluster)
        {
            return None;
        }
        let len = self.call_log.len();
        if len < 3 {
            return None;
        }
        // Has any taint?
        self.first_taint_idx?;
        // Count privileged calls in the last window
        let current_ts = self.call_log[len - 1].timestamp_ms;
        let privileged_count = self
            .call_log
            .iter()
            .rev()
            .take_while(|e| {
                current_ts.saturating_sub(e.timestamp_ms) <= self.config.read_to_act_window_ms
            })
            .filter(|e| e.sink_class.rank() >= SinkClass::FilesystemWrite.rank())
            .count();

        if privileged_count >= 3 {
            return Some(SequenceAnomaly {
                anomaly_type: AnomalyType::PrivilegedActionCluster,
                confidence: 70,
                description: format!(
                    "{privileged_count} privileged calls within {}ms window",
                    self.config.read_to_act_window_ms
                ),
            });
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tracker() -> SequenceTracker {
        SequenceTracker::new(SequenceConfig {
            warmup_calls: 2,
            read_to_act_window_ms: 5000,
            max_new_tools_after_taint: 2,
            anomaly_action: AnomalyAction::Block,
        })
    }

    #[test]
    fn test_no_anomaly_clean_session() {
        let mut t = tracker();
        let a = t.record_and_analyze("read_file", SinkClass::ReadOnly, false, 1000);
        assert!(a.is_empty());
        let a = t.record_and_analyze("read_file", SinkClass::ReadOnly, false, 2000);
        assert!(a.is_empty());
        let a = t.record_and_analyze("write_file", SinkClass::FilesystemWrite, false, 3000);
        assert!(a.is_empty());
    }

    #[test]
    fn test_read_then_exfil_detected() {
        let mut t = tracker();
        t.record_and_analyze("warmup", SinkClass::ReadOnly, false, 100);
        t.record_and_analyze("fetch_url", SinkClass::ReadOnly, true, 1000);
        let a = t.record_and_analyze("http_post", SinkClass::NetworkEgress, false, 2000);
        assert!(a
            .iter()
            .any(|x| x.anomaly_type == AnomalyType::ReadThenExfil));
    }

    #[test]
    fn test_privilege_escalation_after_taint() {
        let mut t = tracker();
        t.record_and_analyze("read_file", SinkClass::ReadOnly, false, 100);
        t.record_and_analyze("fetch_url", SinkClass::ReadOnly, true, 1000);
        let a = t.record_and_analyze("execute_cmd", SinkClass::CodeExecution, false, 2000);
        assert!(a
            .iter()
            .any(|x| x.anomaly_type == AnomalyType::PrivilegeEscalationAfterTaint));
    }

    #[test]
    fn test_tool_diversity_spike() {
        let mut t = SequenceTracker::new(SequenceConfig {
            warmup_calls: 1,
            max_new_tools_after_taint: 1,
            ..SequenceConfig::default()
        });
        t.record_and_analyze("tool_a", SinkClass::ReadOnly, true, 100); // taint fires, 1 tool before
        t.record_and_analyze("tool_b", SinkClass::ReadOnly, false, 200); // +1 new after taint
        let a = t.record_and_analyze("tool_c", SinkClass::ReadOnly, false, 300); // +2 new → spike
        assert!(a
            .iter()
            .any(|x| x.anomaly_type == AnomalyType::ToolDiversitySpike));
    }

    #[test]
    fn test_novel_tool_after_untrusted() {
        let mut t = tracker();
        t.record_and_analyze("warmup", SinkClass::ReadOnly, false, 100);
        t.record_and_analyze("fetch_url", SinkClass::ReadOnly, true, 1000);
        let a = t.record_and_analyze("never_seen_exec", SinkClass::CodeExecution, false, 1500);
        assert!(a
            .iter()
            .any(|x| x.anomaly_type == AnomalyType::NovelToolAfterUntrustedContent));
    }

    #[test]
    fn test_privileged_action_cluster() {
        let mut t = tracker();
        t.record_and_analyze("warmup", SinkClass::ReadOnly, true, 100); // taint
        t.record_and_analyze("write_1", SinkClass::FilesystemWrite, false, 1000);
        t.record_and_analyze("write_2", SinkClass::FilesystemWrite, false, 1500);
        let a = t.record_and_analyze("write_3", SinkClass::FilesystemWrite, false, 2000);
        assert!(a
            .iter()
            .any(|x| x.anomaly_type == AnomalyType::PrivilegedActionCluster));
    }

    #[test]
    fn test_warmup_suppresses_early_detection() {
        let mut t = SequenceTracker::new(SequenceConfig {
            warmup_calls: 5,
            ..SequenceConfig::default()
        });
        // Even with clear anomaly pattern, warmup suppresses
        t.record_and_analyze("fetch", SinkClass::ReadOnly, true, 100);
        let a = t.record_and_analyze("exec", SinkClass::CodeExecution, false, 200);
        assert!(a.is_empty(), "Should be suppressed during warmup");
    }

    #[test]
    fn test_max_confidence() {
        let mut t = tracker();
        assert_eq!(t.max_confidence(), 0);
        t.record_and_analyze("warmup", SinkClass::ReadOnly, false, 100);
        t.record_and_analyze("fetch", SinkClass::ReadOnly, true, 1000);
        t.record_and_analyze("exec", SinkClass::CodeExecution, false, 1500);
        assert!(t.max_confidence() >= 80);
    }
}
