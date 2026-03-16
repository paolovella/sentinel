// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Phase 4: EU AI Act Annex IV technical documentation generation.
//!
//! Generates structured documentation packages required by Annex IV of the
//! EU AI Act from runtime evidence. Each section maps to a specific Annex IV
//! requirement and is populated from the audit trail, policy config, and
//! security posture data.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Annex IV technical documentation package.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AnnexIvPackage {
    /// Generated timestamp (ISO 8601).
    pub generated_at: String,
    /// System version.
    pub system_version: String,
    /// Sections of the technical documentation.
    pub sections: Vec<AnnexIvSection>,
    /// Overall completeness score (0-100).
    pub completeness_score: u32,
    /// Missing or incomplete sections.
    pub gaps: Vec<String>,
}

/// A section of the Annex IV documentation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnnexIvSection {
    /// Section identifier (e.g., "1a", "1b", "2", "3").
    pub id: String,
    /// Section title from Annex IV.
    pub title: String,
    /// Annex IV requirement text (abbreviated).
    pub requirement: String,
    /// How Vellaveto addresses this requirement.
    pub evidence: Vec<EvidenceItem>,
    /// Completeness: complete, partial, or not_applicable.
    pub status: SectionStatus,
}

/// An evidence item supporting an Annex IV section.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceItem {
    /// Evidence type.
    pub evidence_type: EvidenceType,
    /// Human-readable description.
    pub description: String,
    /// Reference to source (file path, config key, audit entry ID).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum EvidenceType {
    Config,
    AuditLog,
    PolicyRule,
    FormalProof,
    TestResult,
    SecurityControl,
    Metric,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SectionStatus {
    Complete,
    Partial,
    NotApplicable,
    Missing,
}

/// Build an Annex IV package from runtime state.
///
/// This generates the documentation structure with evidence populated
/// from the provided context. Callers provide:
/// - `system_version`: current system version string
/// - `policy_count`: number of active policies
/// - `audit_entry_count`: total audit entries
/// - `formal_proof_count`: number of formal verification instances
/// - `test_count`: number of automated tests
/// - `compliance_frameworks`: list of mapped frameworks
/// - `custom_evidence`: additional evidence items keyed by section ID
pub fn build_annex_iv_package(
    system_version: &str,
    policy_count: usize,
    audit_entry_count: u64,
    formal_proof_count: usize,
    test_count: usize,
    compliance_frameworks: &[String],
    custom_evidence: &HashMap<String, Vec<EvidenceItem>>,
) -> AnnexIvPackage {
    let mut sections = Vec::new();
    let mut gaps = Vec::new();

    // Section 1(a): General description of the AI system
    sections.push(AnnexIvSection {
        id: "1a".to_string(),
        title: "General description of the AI system".to_string(),
        requirement: "Intended purpose, developer identity, version".to_string(),
        evidence: vec![
            EvidenceItem {
                evidence_type: EvidenceType::Config,
                description: format!("System version: {system_version}"),
                reference: None,
            },
            EvidenceItem {
                evidence_type: EvidenceType::SecurityControl,
                description: "Agent interaction firewall — runtime boundary enforcement for AI agent tool calls".to_string(),
                reference: None,
            },
        ],
        status: SectionStatus::Complete,
    });

    // Section 1(b): Interaction with other systems
    sections.push(AnnexIvSection {
        id: "1b".to_string(),
        title: "Interaction with other AI systems and hardware".to_string(),
        requirement: "How the system interacts with hardware or other AI systems".to_string(),
        evidence: vec![EvidenceItem {
            evidence_type: EvidenceType::SecurityControl,
            description: "Mediates MCP protocol interactions across stdio, HTTP, WebSocket, gRPC, and SSE transports".to_string(),
            reference: None,
        }],
        status: SectionStatus::Complete,
    });

    // Section 2: Risk management
    sections.push(AnnexIvSection {
        id: "2".to_string(),
        title: "Risk management system".to_string(),
        requirement: "Description of the risk management system (Art 9)".to_string(),
        evidence: {
            let mut ev = vec![
                EvidenceItem {
                    evidence_type: EvidenceType::PolicyRule,
                    description: format!("{policy_count} active policy rules"),
                    reference: None,
                },
                EvidenceItem {
                    evidence_type: EvidenceType::SecurityControl,
                    description: "Fail-closed evaluation: errors, missing policies, and unresolved context produce Deny".to_string(),
                    reference: None,
                },
                EvidenceItem {
                    evidence_type: EvidenceType::TestResult,
                    description: format!("{test_count} automated tests"),
                    reference: None,
                },
            ];
            if formal_proof_count > 0 {
                ev.push(EvidenceItem {
                    evidence_type: EvidenceType::FormalProof,
                    description: format!("{formal_proof_count} formal verification instances"),
                    reference: Some("formal/".to_string()),
                });
            }
            ev
        },
        status: SectionStatus::Complete,
    });

    // Section 3: Monitoring, functioning, and control
    sections.push(AnnexIvSection {
        id: "3".to_string(),
        title: "Monitoring, functioning, and control".to_string(),
        requirement: "Measures for human oversight (Art 14)".to_string(),
        evidence: vec![
            EvidenceItem {
                evidence_type: EvidenceType::AuditLog,
                description: format!("{audit_entry_count} audit entries in tamper-evident chain"),
                reference: None,
            },
            EvidenceItem {
                evidence_type: EvidenceType::SecurityControl,
                description: "Approval workflows for privileged sinks with human-readable fact summaries".to_string(),
                reference: None,
            },
            EvidenceItem {
                evidence_type: EvidenceType::SecurityControl,
                description: "ACIS decision envelopes on every verdict for structured observability".to_string(),
                reference: None,
            },
        ],
        status: SectionStatus::Complete,
    });

    // Section 4: Compliance with regulatory frameworks
    let mut framework_evidence: Vec<EvidenceItem> = compliance_frameworks
        .iter()
        .map(|f| EvidenceItem {
            evidence_type: EvidenceType::SecurityControl,
            description: format!("Mapped to {f}"),
            reference: None,
        })
        .collect();
    if framework_evidence.is_empty() {
        gaps.push("Section 4: No compliance frameworks configured".to_string());
    }
    let s4_status = if framework_evidence.is_empty() {
        SectionStatus::Missing
    } else {
        SectionStatus::Complete
    };
    // Merge custom evidence if provided
    if let Some(custom) = custom_evidence.get("4") {
        framework_evidence.extend(custom.iter().cloned());
    }
    sections.push(AnnexIvSection {
        id: "4".to_string(),
        title: "Relevant regulatory requirements".to_string(),
        requirement: "Standards and regulatory requirements applied".to_string(),
        evidence: framework_evidence,
        status: s4_status,
    });

    // Completeness score
    let total = sections.len() as u32;
    let complete = sections
        .iter()
        .filter(|s| s.status == SectionStatus::Complete)
        .count() as u32;
    let completeness_score = if total > 0 {
        (complete * 100) / total
    } else {
        0
    };

    AnnexIvPackage {
        generated_at: chrono::Utc::now().to_rfc3339(),
        system_version: system_version.to_string(),
        sections,
        completeness_score,
        gaps,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_annex_iv_complete() {
        let pkg = build_annex_iv_package(
            "6.0.8",
            42,
            10000,
            767,
            11279,
            &["EU AI Act".to_string(), "SOC 2".to_string()],
            &HashMap::new(),
        );
        assert_eq!(pkg.system_version, "6.0.8");
        assert_eq!(pkg.sections.len(), 5);
        assert_eq!(pkg.completeness_score, 100);
        assert!(pkg.gaps.is_empty());
    }

    #[test]
    fn test_build_annex_iv_missing_frameworks() {
        let pkg = build_annex_iv_package("6.0.8", 10, 0, 0, 0, &[], &HashMap::new());
        assert!(pkg.completeness_score < 100);
        assert!(!pkg.gaps.is_empty());
        assert!(pkg.gaps[0].contains("compliance frameworks"));
    }

    #[test]
    fn test_build_annex_iv_with_custom_evidence() {
        let mut custom = HashMap::new();
        custom.insert(
            "4".to_string(),
            vec![EvidenceItem {
                evidence_type: EvidenceType::Config,
                description: "Custom compliance mapping".to_string(),
                reference: Some("docs/COMPLIANCE.md".to_string()),
            }],
        );
        let pkg = build_annex_iv_package("6.0.8", 10, 100, 0, 100, &["NIS2".to_string()], &custom);
        let s4 = pkg.sections.iter().find(|s| s.id == "4").unwrap();
        assert_eq!(s4.evidence.len(), 2); // framework + custom
    }

    #[test]
    fn test_section_status_values() {
        let pkg = build_annex_iv_package("6.0.8", 10, 100, 0, 100, &[], &HashMap::new());
        let s4 = pkg.sections.iter().find(|s| s.id == "4").unwrap();
        assert_eq!(s4.status, SectionStatus::Missing);
        let s1 = pkg.sections.iter().find(|s| s.id == "1a").unwrap();
        assert_eq!(s1.status, SectionStatus::Complete);
    }
}
