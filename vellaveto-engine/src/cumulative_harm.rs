// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! STAC (Sequences of Tool-Chaining Attacks) cumulative harm scoring.
//!
//! Individual tool calls may each be benign, but their composition can be
//! harmful. This module scores cumulative harm from tool call sequences
//! that no individual-call analysis would flag.
//!
//! Based on: "Sequences of Tool-Chaining Attacks" (COLING 2025)
//!
//! Key insight: function calling creates a parallel path around safety
//! alignment. Tool descriptions serve as a privileged instruction channel.
//! Safety must consider cumulative impact, not individual actions.

use vellaveto_types::provenance::SinkClass;

/// Maximum chain entries to track.
const MAX_CHAIN_LEN: usize = 100;

/// A step in a tool chain.
#[derive(Debug, Clone)]
struct ChainStep {
    tool_name: String,
    sink_class: SinkClass,
    reads_sensitive: bool,
    #[allow(dead_code)]
    writes_external: bool,
    #[allow(dead_code)]
    executes_code: bool,
}

/// Harmful chain patterns and their scores.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HarmfulChainPattern {
    /// Read sensitive data then send externally.
    ReadThenExfiltrate,
    /// Read credentials then use them in another tool.
    CredentialHarvest,
    /// Modify config then execute code (persistence).
    ConfigThenExecute,
    /// Enumerate system then exploit findings.
    ReconThenExploit,
    /// Multiple privilege escalation steps.
    PrivilegeChain,
}

impl HarmfulChainPattern {
    pub fn severity(&self) -> u32 {
        match self {
            Self::ReadThenExfiltrate => 90,
            Self::CredentialHarvest => 95,
            Self::ConfigThenExecute => 85,
            Self::ReconThenExploit => 80,
            Self::PrivilegeChain => 75,
        }
    }
}

/// A detected harmful chain.
#[derive(Debug, Clone)]
pub struct HarmfulChainFinding {
    pub pattern: HarmfulChainPattern,
    pub severity: u32,
    pub chain_length: usize,
    pub description: String,
}

/// Tracks tool call chains and detects cumulative harm patterns.
pub struct CumulativeHarmTracker {
    chain: Vec<ChainStep>,
    findings: Vec<HarmfulChainFinding>,
}

impl CumulativeHarmTracker {
    pub fn new() -> Self {
        Self {
            chain: Vec::new(),
            findings: Vec::new(),
        }
    }

    /// Record a tool call and check for harmful chain patterns.
    pub fn record_and_check(
        &mut self,
        tool_name: &str,
        sink_class: SinkClass,
        target_paths: &[String],
        target_domains: &[String],
    ) -> Vec<HarmfulChainFinding> {
        let reads_sensitive = is_sensitive_read(tool_name, target_paths);
        let writes_external =
            !target_domains.is_empty() || matches!(sink_class, SinkClass::NetworkEgress);
        let executes_code = matches!(sink_class, SinkClass::CodeExecution);

        if self.chain.len() < MAX_CHAIN_LEN {
            self.chain.push(ChainStep {
                tool_name: tool_name[..tool_name.len().min(256)].to_string(),
                sink_class,
                reads_sensitive,
                writes_external,
                executes_code,
            });
        }

        let mut new_findings = Vec::new();

        // Check for ReadThenExfiltrate: read sensitive → send external
        if writes_external {
            for prev in self.chain.iter().rev().skip(1).take(5) {
                if prev.reads_sensitive {
                    let finding = HarmfulChainFinding {
                        pattern: HarmfulChainPattern::ReadThenExfiltrate,
                        severity: HarmfulChainPattern::ReadThenExfiltrate.severity(),
                        chain_length: 2,
                        description: format!(
                            "'{}' (sensitive read) → '{}' (external write)",
                            prev.tool_name, tool_name
                        ),
                    };
                    new_findings.push(finding);
                    break;
                }
            }
        }

        // Check for CredentialHarvest: read creds → use them
        if !target_domains.is_empty() || writes_external {
            for prev in self.chain.iter().rev().skip(1).take(3) {
                if is_credential_read(&prev.tool_name, &[]) {
                    let finding = HarmfulChainFinding {
                        pattern: HarmfulChainPattern::CredentialHarvest,
                        severity: HarmfulChainPattern::CredentialHarvest.severity(),
                        chain_length: 2,
                        description: format!(
                            "'{}' (credential read) → '{}' (credential use)",
                            prev.tool_name, tool_name
                        ),
                    };
                    new_findings.push(finding);
                    break;
                }
            }
        }

        // Check for ConfigThenExecute: write config → execute code
        if executes_code {
            for prev in self.chain.iter().rev().skip(1).take(5) {
                if is_config_write(&prev.tool_name) {
                    let finding = HarmfulChainFinding {
                        pattern: HarmfulChainPattern::ConfigThenExecute,
                        severity: HarmfulChainPattern::ConfigThenExecute.severity(),
                        chain_length: 2,
                        description: format!(
                            "'{}' (config write) → '{}' (code execution)",
                            prev.tool_name, tool_name
                        ),
                    };
                    new_findings.push(finding);
                    break;
                }
            }
        }

        // Check for PrivilegeChain: escalating sink classes
        if self.chain.len() >= 3 {
            let last_3: Vec<u8> = self
                .chain
                .iter()
                .rev()
                .take(3)
                .map(|s| s.sink_class.rank())
                .collect();
            if last_3.len() == 3
                && last_3[0] > last_3[1]
                && last_3[1] > last_3[2]
                && last_3[0] >= SinkClass::CodeExecution.rank()
            {
                new_findings.push(HarmfulChainFinding {
                    pattern: HarmfulChainPattern::PrivilegeChain,
                    severity: HarmfulChainPattern::PrivilegeChain.severity(),
                    chain_length: 3,
                    description: "escalating sink class chain detected".to_string(),
                });
            }
        }

        self.findings.extend(new_findings.clone());
        new_findings
    }

    /// Get the maximum severity across all findings.
    pub fn max_severity(&self) -> u32 {
        self.findings.iter().map(|f| f.severity).max().unwrap_or(0)
    }

    /// Get all findings.
    pub fn findings(&self) -> &[HarmfulChainFinding] {
        &self.findings
    }
}

impl Default for CumulativeHarmTracker {
    fn default() -> Self {
        Self::new()
    }
}

fn is_sensitive_read(tool_name: &str, paths: &[String]) -> bool {
    let sensitive_patterns = [
        ".aws",
        ".ssh",
        ".env",
        "credentials",
        "secret",
        "passwd",
        "shadow",
    ];
    paths
        .iter()
        .any(|p| sensitive_patterns.iter().any(|s| p.contains(s)))
        || tool_name.contains("credential")
        || tool_name.contains("secret")
}

fn is_credential_read(tool_name: &str, _paths: &[String]) -> bool {
    tool_name.contains("credential")
        || tool_name.contains("secret")
        || tool_name.contains("password")
        || tool_name.contains("token")
        || tool_name.contains("key")
}

fn is_config_write(tool_name: &str) -> bool {
    (tool_name.contains("write") || tool_name.contains("modify") || tool_name.contains("set"))
        && (tool_name.contains("config")
            || tool_name.contains("setting")
            || tool_name.contains("hook"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_then_exfiltrate() {
        let mut tracker = CumulativeHarmTracker::new();
        tracker.record_and_check(
            "read_file",
            SinkClass::ReadOnly,
            &["/home/user/.aws/credentials".to_string()],
            &[],
        );
        let findings = tracker.record_and_check(
            "http_post",
            SinkClass::NetworkEgress,
            &[],
            &["evil.com".to_string()],
        );
        assert!(findings
            .iter()
            .any(|f| f.pattern == HarmfulChainPattern::ReadThenExfiltrate));
    }

    #[test]
    fn test_credential_harvest() {
        let mut tracker = CumulativeHarmTracker::new();
        tracker.record_and_check("get_secret_key", SinkClass::ReadOnly, &[], &[]);
        let findings = tracker.record_and_check(
            "http_request",
            SinkClass::NetworkEgress,
            &[],
            &["api.target.com".to_string()],
        );
        assert!(findings
            .iter()
            .any(|f| f.pattern == HarmfulChainPattern::CredentialHarvest));
    }

    #[test]
    fn test_config_then_execute() {
        let mut tracker = CumulativeHarmTracker::new();
        tracker.record_and_check("write_config", SinkClass::FilesystemWrite, &[], &[]);
        let findings =
            tracker.record_and_check("execute_command", SinkClass::CodeExecution, &[], &[]);
        assert!(findings
            .iter()
            .any(|f| f.pattern == HarmfulChainPattern::ConfigThenExecute));
    }

    #[test]
    fn test_privilege_chain() {
        let mut tracker = CumulativeHarmTracker::new();
        tracker.record_and_check("list_files", SinkClass::ReadOnly, &[], &[]);
        tracker.record_and_check("write_file", SinkClass::FilesystemWrite, &[], &[]);
        let findings = tracker.record_and_check("execute_cmd", SinkClass::CodeExecution, &[], &[]);
        assert!(findings
            .iter()
            .any(|f| f.pattern == HarmfulChainPattern::PrivilegeChain));
    }

    #[test]
    fn test_benign_chain_no_findings() {
        let mut tracker = CumulativeHarmTracker::new();
        tracker.record_and_check(
            "read_file",
            SinkClass::ReadOnly,
            &["/tmp/readme.md".to_string()],
            &[],
        );
        tracker.record_and_check(
            "read_file",
            SinkClass::ReadOnly,
            &["/tmp/notes.txt".to_string()],
            &[],
        );
        let findings = tracker.record_and_check(
            "write_file",
            SinkClass::FilesystemWrite,
            &["/tmp/output.txt".to_string()],
            &[],
        );
        assert!(
            findings.is_empty(),
            "Benign read→read→write should not flag"
        );
    }

    #[test]
    fn test_max_severity() {
        let mut tracker = CumulativeHarmTracker::new();
        tracker.record_and_check("get_secret_key", SinkClass::ReadOnly, &[], &[]);
        tracker.record_and_check(
            "http_post",
            SinkClass::NetworkEgress,
            &[],
            &["evil.com".to_string()],
        );
        assert!(tracker.max_severity() >= 90);
    }
}
