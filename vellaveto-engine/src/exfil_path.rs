// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Data exfiltration path analysis.
//!
//! Combines signals from multiple detectors to identify complete
//! exfiltration paths: data acquisition → staging → transmission.
//! This is the integration layer that connects credential detection,
//! DLP, network egress, and behavioral analysis into end-to-end
//! exfiltration chain detection.

use vellaveto_types::provenance::SinkClass;

/// An exfiltration path finding.
#[derive(Debug, Clone)]
pub struct ExfilPathFinding {
    pub path_type: ExfilPathType,
    pub severity: u32,
    pub stages: Vec<ExfilStage>,
    pub description: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExfilPathType {
    /// Credential read → external transmission.
    CredentialExfil,
    /// Sensitive file read → encoding → network egress.
    FileExfil,
    /// System enumeration → data collection → batch transmission.
    ReconExfil,
    /// Memory/context extraction → external delivery.
    ContextExfil,
}

/// A stage in an exfiltration path.
#[derive(Debug, Clone)]
pub struct ExfilStage {
    pub stage_type: ExfilStageType,
    pub tool_name: String,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExfilStageType {
    /// Data acquisition (read sensitive data).
    Acquire,
    /// Data staging (encode, compress, split).
    Stage,
    /// Data transmission (network egress).
    Transmit,
}

/// Track tool calls and identify complete exfiltration paths.
pub struct ExfilPathTracker {
    /// Recent data acquisition events.
    acquisitions: Vec<AcquisitionEvent>,
    /// Recent transmission events.
    transmissions: Vec<TransmissionEvent>,
    /// Detected complete paths.
    findings: Vec<ExfilPathFinding>,
}

#[derive(Debug, Clone)]
struct AcquisitionEvent {
    tool_name: String,
    is_credential: bool,
    is_sensitive_file: bool,
    timestamp_ms: u64,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct TransmissionEvent {
    tool_name: String,
    has_external_domain: bool,
    timestamp_ms: u64,
}

/// Maximum tracked events.
const MAX_EVENTS: usize = 200;
/// Time window for path detection (ms).
const PATH_WINDOW_MS: u64 = 30_000;

impl ExfilPathTracker {
    pub fn new() -> Self {
        Self {
            acquisitions: Vec::new(),
            transmissions: Vec::new(),
            findings: Vec::new(),
        }
    }

    /// Record a tool call and check for exfiltration path completion.
    pub fn record_call(
        &mut self,
        tool_name: &str,
        sink_class: SinkClass,
        target_paths: &[String],
        target_domains: &[String],
    ) -> Vec<ExfilPathFinding> {
        let now = now_ms();
        let mut new_findings = Vec::new();

        let is_credential = is_credential_path(target_paths)
            || tool_name.contains("credential")
            || tool_name.contains("secret");
        let is_sensitive = is_sensitive_path(target_paths);
        let is_network =
            matches!(sink_class, SinkClass::NetworkEgress) || !target_domains.is_empty();

        // Record acquisition
        if (is_credential || is_sensitive) && self.acquisitions.len() < MAX_EVENTS {
            self.acquisitions.push(AcquisitionEvent {
                tool_name: tool_name[..tool_name.len().min(256)].to_string(),
                is_credential,
                is_sensitive_file: is_sensitive,
                timestamp_ms: now,
            });
        }

        // Record transmission and check for complete paths
        if is_network {
            if self.transmissions.len() < MAX_EVENTS {
                self.transmissions.push(TransmissionEvent {
                    tool_name: tool_name[..tool_name.len().min(256)].to_string(),
                    has_external_domain: !target_domains.is_empty(),
                    timestamp_ms: now,
                });
            }

            // Check for complete exfiltration paths
            let cutoff = now.saturating_sub(PATH_WINDOW_MS);
            for acq in &self.acquisitions {
                if acq.timestamp_ms < cutoff {
                    continue;
                }
                if acq.is_credential {
                    let finding = ExfilPathFinding {
                        path_type: ExfilPathType::CredentialExfil,
                        severity: 95,
                        stages: vec![
                            ExfilStage {
                                stage_type: ExfilStageType::Acquire,
                                tool_name: acq.tool_name.clone(),
                                detail: "credential acquisition".to_string(),
                            },
                            ExfilStage {
                                stage_type: ExfilStageType::Transmit,
                                tool_name: tool_name.to_string(),
                                detail: "network egress".to_string(),
                            },
                        ],
                        description: format!(
                            "Credential exfil: '{}' → '{}'",
                            acq.tool_name, tool_name
                        ),
                    };
                    new_findings.push(finding);
                } else if acq.is_sensitive_file {
                    let finding = ExfilPathFinding {
                        path_type: ExfilPathType::FileExfil,
                        severity: 85,
                        stages: vec![
                            ExfilStage {
                                stage_type: ExfilStageType::Acquire,
                                tool_name: acq.tool_name.clone(),
                                detail: "sensitive file read".to_string(),
                            },
                            ExfilStage {
                                stage_type: ExfilStageType::Transmit,
                                tool_name: tool_name.to_string(),
                                detail: "network egress".to_string(),
                            },
                        ],
                        description: format!("File exfil: '{}' → '{}'", acq.tool_name, tool_name),
                    };
                    new_findings.push(finding);
                }
            }
        }

        // Prune old events
        let cutoff = now.saturating_sub(PATH_WINDOW_MS * 2);
        self.acquisitions.retain(|e| e.timestamp_ms >= cutoff);
        self.transmissions.retain(|e| e.timestamp_ms >= cutoff);

        self.findings.extend(new_findings.clone());
        new_findings
    }

    /// Get all detected exfiltration paths.
    pub fn findings(&self) -> &[ExfilPathFinding] {
        &self.findings
    }

    /// Maximum severity across all findings.
    pub fn max_severity(&self) -> u32 {
        self.findings.iter().map(|f| f.severity).max().unwrap_or(0)
    }
}

impl Default for ExfilPathTracker {
    fn default() -> Self {
        Self::new()
    }
}

fn is_credential_path(paths: &[String]) -> bool {
    let cred_patterns = [
        ".aws",
        ".ssh",
        ".env",
        "credentials",
        "id_rsa",
        "id_ed25519",
        ".npmrc",
        ".netrc",
    ];
    paths
        .iter()
        .any(|p| cred_patterns.iter().any(|c| p.contains(c)))
}

fn is_sensitive_path(paths: &[String]) -> bool {
    let sensitive = [
        "/etc/shadow",
        "/etc/passwd",
        "secrets",
        "private",
        ".config",
        ".kube",
    ];
    paths
        .iter()
        .any(|p| sensitive.iter().any(|s| p.contains(s)))
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
    fn test_credential_exfil_path() {
        let mut tracker = ExfilPathTracker::new();
        tracker.record_call(
            "read_file",
            SinkClass::ReadOnly,
            &["/home/user/.aws/credentials".to_string()],
            &[],
        );
        let findings = tracker.record_call(
            "http_post",
            SinkClass::NetworkEgress,
            &[],
            &["evil.com".to_string()],
        );
        assert!(findings
            .iter()
            .any(|f| f.path_type == ExfilPathType::CredentialExfil));
        assert!(findings[0].severity >= 90);
    }

    #[test]
    fn test_file_exfil_path() {
        let mut tracker = ExfilPathTracker::new();
        tracker.record_call(
            "read_file",
            SinkClass::ReadOnly,
            &["/etc/shadow".to_string()],
            &[],
        );
        let findings = tracker.record_call(
            "send_data",
            SinkClass::NetworkEgress,
            &[],
            &["attacker.com".to_string()],
        );
        assert!(findings
            .iter()
            .any(|f| f.path_type == ExfilPathType::FileExfil));
    }

    #[test]
    fn test_no_path_without_acquisition() {
        let mut tracker = ExfilPathTracker::new();
        let findings = tracker.record_call(
            "http_post",
            SinkClass::NetworkEgress,
            &[],
            &["legit.com".to_string()],
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn test_benign_read_write_no_exfil() {
        let mut tracker = ExfilPathTracker::new();
        tracker.record_call(
            "read_file",
            SinkClass::ReadOnly,
            &["/tmp/notes.txt".to_string()],
            &[],
        );
        let findings = tracker.record_call(
            "write_file",
            SinkClass::FilesystemWrite,
            &["/tmp/output.txt".to_string()],
            &[],
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn test_max_severity() {
        let mut tracker = ExfilPathTracker::new();
        tracker.record_call(
            "get_secret",
            SinkClass::ReadOnly,
            &["/home/user/.ssh/id_rsa".to_string()],
            &[],
        );
        tracker.record_call(
            "upload",
            SinkClass::NetworkEgress,
            &[],
            &["evil.com".to_string()],
        );
        assert!(tracker.max_severity() >= 90);
    }
}
