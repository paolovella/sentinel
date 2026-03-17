// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! MCP server fingerprinting and version drift detection.
//!
//! Tracks server behavioral fingerprints (capabilities, tool sets,
//! response patterns) and detects when a server's behavior drifts
//! from its established baseline — indicating rug-pull, compromise,
//! or unauthorized modification.

use std::collections::HashMap;

/// A server fingerprint snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerFingerprint {
    /// Protocol version negotiated.
    pub protocol_version: String,
    /// Server name from initialize response.
    pub server_name: String,
    /// Sorted list of tool names.
    pub tool_names: Vec<String>,
    /// Tool count.
    pub tool_count: usize,
    /// Capabilities declared.
    pub capabilities: Vec<String>,
}

/// A fingerprint drift finding.
#[derive(Debug, Clone)]
pub struct FingerprintDrift {
    pub drift_type: DriftType,
    pub confidence: u32,
    pub description: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriftType {
    /// Server name changed.
    ServerNameChanged,
    /// Tools were added.
    ToolsAdded,
    /// Tools were removed.
    ToolsRemoved,
    /// Capabilities changed.
    CapabilitiesChanged,
    /// Protocol version changed.
    ProtocolVersionChanged,
}

/// Tracks server fingerprints and detects drift.
pub struct ServerFingerprintTracker {
    baselines: HashMap<String, ServerFingerprint>,
}

impl ServerFingerprintTracker {
    pub fn new() -> Self {
        Self {
            baselines: HashMap::new(),
        }
    }

    /// Record a server fingerprint and check for drift from baseline.
    pub fn record_and_check(
        &mut self,
        server_id: &str,
        current: ServerFingerprint,
    ) -> Vec<FingerprintDrift> {
        let mut findings = Vec::new();

        if let Some(baseline) = self.baselines.get(server_id) {
            // Check server name
            if baseline.server_name != current.server_name {
                findings.push(FingerprintDrift {
                    drift_type: DriftType::ServerNameChanged,
                    confidence: 90,
                    description: format!(
                        "Server name changed: '{}' → '{}'",
                        &baseline.server_name[..baseline.server_name.len().min(32)],
                        &current.server_name[..current.server_name.len().min(32)]
                    ),
                });
            }

            // Check tools added
            let added: Vec<&String> = current
                .tool_names
                .iter()
                .filter(|t| !baseline.tool_names.contains(t))
                .collect();
            if !added.is_empty() {
                findings.push(FingerprintDrift {
                    drift_type: DriftType::ToolsAdded,
                    confidence: 60,
                    description: format!("{} tools added", added.len()),
                });
            }

            // Check tools removed
            let removed: Vec<&String> = baseline
                .tool_names
                .iter()
                .filter(|t| !current.tool_names.contains(t))
                .collect();
            if !removed.is_empty() {
                findings.push(FingerprintDrift {
                    drift_type: DriftType::ToolsRemoved,
                    confidence: 70,
                    description: format!("{} tools removed", removed.len()),
                });
            }

            // Check capabilities
            if baseline.capabilities != current.capabilities {
                findings.push(FingerprintDrift {
                    drift_type: DriftType::CapabilitiesChanged,
                    confidence: 80,
                    description: "Server capabilities changed".to_string(),
                });
            }

            // Check protocol version
            if baseline.protocol_version != current.protocol_version {
                findings.push(FingerprintDrift {
                    drift_type: DriftType::ProtocolVersionChanged,
                    confidence: 50,
                    description: format!(
                        "Protocol version: '{}' → '{}'",
                        baseline.protocol_version, current.protocol_version
                    ),
                });
            }
        }

        // Update baseline
        if self.baselines.len() < 1000 || self.baselines.contains_key(server_id) {
            self.baselines.insert(server_id.to_string(), current);
        }

        findings
    }

    /// Get the baseline for a server.
    pub fn get_baseline(&self, server_id: &str) -> Option<&ServerFingerprint> {
        self.baselines.get(server_id)
    }
}

impl Default for ServerFingerprintTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_fp() -> ServerFingerprint {
        ServerFingerprint {
            protocol_version: "2025-11-25".to_string(),
            server_name: "test-server".to_string(),
            tool_names: vec!["read_file".to_string(), "write_file".to_string()],
            tool_count: 2,
            capabilities: vec!["tools".to_string()],
        }
    }

    #[test]
    fn test_first_fingerprint_no_drift() {
        let mut tracker = ServerFingerprintTracker::new();
        let findings = tracker.record_and_check("server-1", base_fp());
        assert!(findings.is_empty());
    }

    #[test]
    fn test_server_name_drift() {
        let mut tracker = ServerFingerprintTracker::new();
        tracker.record_and_check("server-1", base_fp());
        let mut changed = base_fp();
        changed.server_name = "different-server".to_string();
        let findings = tracker.record_and_check("server-1", changed);
        assert!(findings
            .iter()
            .any(|f| f.drift_type == DriftType::ServerNameChanged));
    }

    #[test]
    fn test_tools_added_drift() {
        let mut tracker = ServerFingerprintTracker::new();
        tracker.record_and_check("server-1", base_fp());
        let mut changed = base_fp();
        changed.tool_names.push("execute_command".to_string());
        let findings = tracker.record_and_check("server-1", changed);
        assert!(findings
            .iter()
            .any(|f| f.drift_type == DriftType::ToolsAdded));
    }

    #[test]
    fn test_tools_removed_drift() {
        let mut tracker = ServerFingerprintTracker::new();
        tracker.record_and_check("server-1", base_fp());
        let mut changed = base_fp();
        changed.tool_names = vec!["read_file".to_string()]; // removed write_file
        let findings = tracker.record_and_check("server-1", changed);
        assert!(findings
            .iter()
            .any(|f| f.drift_type == DriftType::ToolsRemoved));
    }

    #[test]
    fn test_no_drift_same_fingerprint() {
        let mut tracker = ServerFingerprintTracker::new();
        tracker.record_and_check("server-1", base_fp());
        let findings = tracker.record_and_check("server-1", base_fp());
        assert!(findings.is_empty());
    }
}
