// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Phase 4: Fundamental Rights Impact Assessment (FRIA) data export.
//!
//! EU AI Act Art 27 requires deployers of high-risk AI to conduct a FRIA
//! before deployment. This module generates structured data exports that
//! feed into FRIA workflows, covering:
//! - Scope of AI system usage
//! - Controls in place (policy rules, approval gates)
//! - Risk mitigation measures
//! - Monitoring and oversight mechanisms

use serde::{Deserialize, Serialize};

/// FRIA data export package.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FriaExport {
    /// Generated timestamp.
    pub generated_at: String,
    /// System identifier and version.
    pub system_id: String,
    /// Scope description.
    pub scope: FriaScope,
    /// Risk mitigation controls.
    pub controls: Vec<FriaControl>,
    /// Monitoring mechanisms.
    pub monitoring: Vec<FriaMonitoring>,
    /// Data protection measures.
    pub data_protection: Vec<FriaDataProtection>,
    /// Human oversight measures.
    pub oversight: FriaOversight,
}

/// Scope of the AI system deployment.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FriaScope {
    /// What the AI system does.
    pub purpose: String,
    /// Who is affected.
    pub affected_persons: String,
    /// Geographic scope.
    pub geographic_scope: String,
    /// Deployment context.
    pub deployment_context: String,
}

/// A risk mitigation control.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FriaControl {
    /// Control name.
    pub name: String,
    /// Which right this protects (privacy, non-discrimination, etc.).
    pub protects_right: String,
    /// How it works.
    pub mechanism: String,
    /// Whether it's automated or requires human action.
    pub automated: bool,
    /// Evidence reference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_ref: Option<String>,
}

/// Monitoring mechanism.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FriaMonitoring {
    /// What is monitored.
    pub subject: String,
    /// How it's monitored.
    pub method: String,
    /// Frequency.
    pub frequency: String,
}

/// Data protection measure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FriaDataProtection {
    /// Measure name.
    pub name: String,
    /// Description.
    pub description: String,
}

/// Human oversight mechanisms.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FriaOversight {
    /// Whether approval workflows are configured.
    pub approval_workflows_enabled: bool,
    /// Number of tools requiring approval.
    pub tools_requiring_approval: usize,
    /// Whether audit trail is tamper-evident.
    pub tamper_evident_audit: bool,
    /// Whether human reviewers get structured fact summaries.
    pub fact_summaries_available: bool,
}

/// Build a FRIA export from runtime state.
pub fn build_fria_export(
    system_id: &str,
    policy_count: usize,
    approval_tool_count: usize,
    has_dlp: bool,
    has_pii_sanitization: bool,
    has_audit_trail: bool,
) -> FriaExport {
    let mut controls = Vec::new();

    controls.push(FriaControl {
        name: "Policy-based access control".to_string(),
        protects_right: "privacy, security".to_string(),
        mechanism: format!("{policy_count} policy rules evaluated on every tool call"),
        automated: true,
        evidence_ref: None,
    });

    controls.push(FriaControl {
        name: "Fail-closed evaluation".to_string(),
        protects_right: "safety".to_string(),
        mechanism: "Errors, missing policies, and unresolved context produce Deny".to_string(),
        automated: true,
        evidence_ref: None,
    });

    if has_dlp {
        controls.push(FriaControl {
            name: "Data Loss Prevention".to_string(),
            protects_right: "privacy, data protection".to_string(),
            mechanism: "5-layer credential/secret scanning on tool parameters and responses".to_string(),
            automated: true,
            evidence_ref: None,
        });
    }

    if has_pii_sanitization {
        controls.push(FriaControl {
            name: "PII sanitization".to_string(),
            protects_right: "privacy, data protection".to_string(),
            mechanism: "Bidirectional PII replacement with placeholders before provider processing".to_string(),
            automated: true,
            evidence_ref: None,
        });
    }

    if approval_tool_count > 0 {
        controls.push(FriaControl {
            name: "Human-in-the-loop approval".to_string(),
            protects_right: "safety, non-discrimination".to_string(),
            mechanism: format!("{approval_tool_count} tools require human approval before execution"),
            automated: false,
            evidence_ref: None,
        });
    }

    let monitoring = vec![
        FriaMonitoring {
            subject: "All tool call decisions".to_string(),
            method: "Tamper-evident audit trail with ACIS decision envelopes".to_string(),
            frequency: "Every request".to_string(),
        },
        FriaMonitoring {
            subject: "Injection and poisoning attacks".to_string(),
            method: "20+ detection layers with behavioral analysis".to_string(),
            frequency: "Every request".to_string(),
        },
    ];

    let mut data_protection = Vec::new();
    if has_pii_sanitization {
        data_protection.push(FriaDataProtection {
            name: "Consumer Shield".to_string(),
            description: "PII stripped before reaching provider; encrypted local audit".to_string(),
        });
    }
    data_protection.push(FriaDataProtection {
        name: "Response metadata stripping".to_string(),
        description: "Security-sensitive _meta fields removed from server responses".to_string(),
    });

    FriaExport {
        generated_at: chrono::Utc::now().to_rfc3339(),
        system_id: system_id.to_string(),
        scope: FriaScope::default(),
        controls,
        monitoring,
        data_protection,
        oversight: FriaOversight {
            approval_workflows_enabled: approval_tool_count > 0,
            tools_requiring_approval: approval_tool_count,
            tamper_evident_audit: has_audit_trail,
            fact_summaries_available: true,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_fria_export_full() {
        let export = build_fria_export("vellaveto-v6.0.8", 42, 5, true, true, true);
        assert_eq!(export.system_id, "vellaveto-v6.0.8");
        assert!(export.controls.len() >= 4); // policy + fail-closed + DLP + PII + approval
        assert_eq!(export.monitoring.len(), 2);
        assert!(export.oversight.approval_workflows_enabled);
        assert_eq!(export.oversight.tools_requiring_approval, 5);
        assert!(export.oversight.tamper_evident_audit);
    }

    #[test]
    fn test_build_fria_export_minimal() {
        let export = build_fria_export("test", 10, 0, false, false, false);
        assert_eq!(export.controls.len(), 2); // policy + fail-closed only
        assert!(!export.oversight.approval_workflows_enabled);
    }

    #[test]
    fn test_fria_data_protection_with_shield() {
        let export = build_fria_export("test", 10, 0, false, true, true);
        assert!(export
            .data_protection
            .iter()
            .any(|dp| dp.name.contains("Consumer Shield")));
    }
}
