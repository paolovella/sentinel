// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella

//! Cross-regulation incident reporting (R226).
//!
//! Structures for generating incident reports that satisfy multiple regulatory
//! frameworks simultaneously: DORA (24h/72h timelines), NIS2 (sector
//! categories), and EU AI Act Art 62 (high-risk AI system obligations).
//!
//! A single security incident in a Vellaveto-protected system can trigger
//! reporting requirements across all three regulations. This module provides
//! a unified type that captures all required fields.

use serde::{Deserialize, Serialize};

// ── Validation Constants ────────────────────────────────────────────────────

/// Maximum number of affected systems in an incident report.
const MAX_AFFECTED_SYSTEMS: usize = 1_000;

/// Maximum number of findings in an incident report.
const MAX_FINDINGS: usize = 10_000;

/// Maximum number of recommendations in an incident report.
const MAX_RECOMMENDATIONS: usize = 1_000;

/// Maximum number of regulatory references in an incident report.
const MAX_REGULATORY_REFS: usize = 100;

/// Maximum length of a text field (description, summary, etc.).
const MAX_TEXT_FIELD_LEN: usize = 10_000;

// ── Types ───────────────────────────────────────────────────────────────────

/// Severity of an incident.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IncidentSeverity {
    /// Low-impact incident, no regulatory reporting required.
    Low,
    /// Medium-impact, may require internal escalation.
    Medium,
    /// High-impact, triggers DORA 24h initial notification.
    High,
    /// Critical-impact, triggers all regulatory reporting timelines.
    Critical,
}

/// NIS2 sector classification for incident categorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Nis2Sector {
    /// Essential entity — energy, transport, health, banking, etc.
    Essential,
    /// Important entity — digital providers, manufacturing, etc.
    Important,
}

/// NIS2 incident type classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Nis2IncidentType {
    /// Significant impact on service provision.
    SignificantImpact,
    /// Cross-border impact.
    CrossBorder,
    /// Supply chain impact.
    SupplyChain,
}

/// DORA reporting timeline stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DoraTimelineStage {
    /// Initial notification — within 24 hours of detection.
    InitialNotification,
    /// Intermediate report — within 72 hours of detection.
    IntermediateReport,
    /// Final report — within 1 month of resolution.
    FinalReport,
}

/// EU AI Act reporting obligation under Art 62.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EuAiActObligation {
    /// Serious incident involving high-risk AI system.
    SeriousIncident,
    /// Systemic risk identified in general-purpose AI.
    SystemicRisk,
    /// Malfunction causing rights violation.
    RightsViolation,
}

/// A regulatory reference for the incident.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegulatoryReference {
    /// Regulation name (e.g., "DORA", "NIS2", "EU AI Act").
    pub regulation: String,
    /// Specific article or section (e.g., "Art 19", "Art 23").
    pub reference: String,
    /// Reporting deadline description (e.g., "24h initial notification").
    pub deadline: String,
}

/// A unified cross-regulation incident report.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IncidentReport {
    /// Unique incident identifier.
    pub id: String,
    /// Incident title/summary.
    pub title: String,
    /// Detailed description of the incident.
    pub description: String,
    /// Severity classification.
    pub severity: IncidentSeverity,
    /// ISO 8601 timestamp of incident detection.
    pub detected_at: String,
    /// ISO 8601 timestamp of report generation.
    pub reported_at: String,
    /// Affected systems/services.
    pub affected_systems: Vec<String>,
    /// Security findings associated with the incident.
    pub findings: Vec<String>,
    /// Remediation recommendations.
    pub recommendations: Vec<String>,

    // ── DORA fields ─────────────────────────────────────────────────────
    /// Current DORA timeline stage.
    pub dora_stage: Option<DoraTimelineStage>,
    /// DORA deadline for next reporting action (ISO 8601).
    pub dora_deadline: Option<String>,

    // ── NIS2 fields ─────────────────────────────────────────────────────
    /// NIS2 sector classification.
    pub nis2_sector: Option<Nis2Sector>,
    /// NIS2 incident type.
    pub nis2_incident_type: Option<Nis2IncidentType>,

    // ── EU AI Act fields ────────────────────────────────────────────────
    /// EU AI Act Art 62 obligation triggered.
    pub eu_ai_act_obligation: Option<EuAiActObligation>,

    // ── Cross-regulation ────────────────────────────────────────────────
    /// All regulatory references applicable to this incident.
    pub regulatory_references: Vec<RegulatoryReference>,
}

/// Errors from incident report operations.
#[derive(Debug, Clone, PartialEq)]
pub enum IncidentReportError {
    /// Validation failed.
    Validation(String),
}

impl std::fmt::Display for IncidentReportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Validation(msg) => write!(f, "incident report validation failed: {msg}"),
        }
    }
}

impl std::error::Error for IncidentReportError {}

impl IncidentReport {
    /// Validate the incident report fields.
    pub fn validate(&self) -> Result<(), IncidentReportError> {
        if self.id.is_empty() || self.id.len() > MAX_TEXT_FIELD_LEN {
            return Err(IncidentReportError::Validation(
                "id must be non-empty and <= 10000 chars".to_string(),
            ));
        }
        if self.title.is_empty() || self.title.len() > MAX_TEXT_FIELD_LEN {
            return Err(IncidentReportError::Validation(
                "title must be non-empty and <= 10000 chars".to_string(),
            ));
        }
        if self.description.len() > MAX_TEXT_FIELD_LEN {
            return Err(IncidentReportError::Validation(
                "description exceeds maximum length".to_string(),
            ));
        }
        if self.affected_systems.len() > MAX_AFFECTED_SYSTEMS {
            return Err(IncidentReportError::Validation(format!(
                "affected_systems count {} exceeds maximum {}",
                self.affected_systems.len(),
                MAX_AFFECTED_SYSTEMS
            )));
        }
        if self.findings.len() > MAX_FINDINGS {
            return Err(IncidentReportError::Validation(format!(
                "findings count {} exceeds maximum {}",
                self.findings.len(),
                MAX_FINDINGS
            )));
        }
        if self.recommendations.len() > MAX_RECOMMENDATIONS {
            return Err(IncidentReportError::Validation(format!(
                "recommendations count {} exceeds maximum {}",
                self.recommendations.len(),
                MAX_RECOMMENDATIONS
            )));
        }
        if self.regulatory_references.len() > MAX_REGULATORY_REFS {
            return Err(IncidentReportError::Validation(format!(
                "regulatory_references count {} exceeds maximum {}",
                self.regulatory_references.len(),
                MAX_REGULATORY_REFS
            )));
        }
        // Validate control characters in text fields.
        for field in [&self.id, &self.title, &self.description] {
            if vellaveto_types::has_dangerous_chars(field) {
                return Err(IncidentReportError::Validation(
                    "text field contains control or Unicode format characters".to_string(),
                ));
            }
        }
        Ok(())
    }

    /// Get the list of regulations that require reporting for this incident.
    pub fn triggered_regulations(&self) -> Vec<&str> {
        let mut regs = Vec::new();
        if self.dora_stage.is_some() {
            regs.push("DORA");
        }
        if self.nis2_sector.is_some() {
            regs.push("NIS2");
        }
        if self.eu_ai_act_obligation.is_some() {
            regs.push("EU AI Act");
        }
        regs
    }

    /// Check if the incident triggers the DORA 24h initial notification deadline.
    pub fn requires_dora_24h_notification(&self) -> bool {
        matches!(
            self.severity,
            IncidentSeverity::High | IncidentSeverity::Critical
        ) && self.dora_stage.is_some()
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_report() -> IncidentReport {
        IncidentReport {
            id: "INC-2026-001".to_string(),
            title: "MCP tool injection detected".to_string(),
            description: "A rogue MCP server attempted tool poisoning via description injection"
                .to_string(),
            severity: IncidentSeverity::Critical,
            detected_at: "2026-02-26T10:00:00Z".to_string(),
            reported_at: "2026-02-26T10:30:00Z".to_string(),
            affected_systems: vec!["production-agent-pool".to_string()],
            findings: vec!["FIND-042: MCP-ITP cross-tool injection".to_string()],
            recommendations: vec!["Enable governance.require_server_registration".to_string()],
            dora_stage: Some(DoraTimelineStage::InitialNotification),
            dora_deadline: Some("2026-02-27T10:00:00Z".to_string()),
            nis2_sector: Some(Nis2Sector::Essential),
            nis2_incident_type: Some(Nis2IncidentType::SupplyChain),
            eu_ai_act_obligation: Some(EuAiActObligation::SeriousIncident),
            regulatory_references: vec![
                RegulatoryReference {
                    regulation: "DORA".to_string(),
                    reference: "Art 19".to_string(),
                    deadline: "24h initial notification".to_string(),
                },
                RegulatoryReference {
                    regulation: "NIS2".to_string(),
                    reference: "Art 23".to_string(),
                    deadline: "24h early warning".to_string(),
                },
                RegulatoryReference {
                    regulation: "EU AI Act".to_string(),
                    reference: "Art 62".to_string(),
                    deadline: "Serious incident notification".to_string(),
                },
            ],
        }
    }

    #[test]
    fn test_validate_valid_report() {
        let report = sample_report();
        assert!(report.validate().is_ok());
    }

    #[test]
    fn test_validate_empty_id_rejected() {
        let mut report = sample_report();
        report.id = String::new();
        assert!(report.validate().is_err());
    }

    #[test]
    fn test_validate_control_chars_rejected() {
        let mut report = sample_report();
        report.title = "Bad\x00title".to_string();
        assert!(report.validate().is_err());
    }

    #[test]
    fn test_validate_too_many_findings_rejected() {
        let mut report = sample_report();
        report.findings = (0..MAX_FINDINGS + 1)
            .map(|i| format!("finding-{i}"))
            .collect();
        assert!(report.validate().is_err());
    }

    #[test]
    fn test_triggered_regulations_all_three() {
        let report = sample_report();
        let regs = report.triggered_regulations();
        assert_eq!(regs.len(), 3);
        assert!(regs.contains(&"DORA"));
        assert!(regs.contains(&"NIS2"));
        assert!(regs.contains(&"EU AI Act"));
    }

    #[test]
    fn test_triggered_regulations_none() {
        let mut report = sample_report();
        report.dora_stage = None;
        report.nis2_sector = None;
        report.eu_ai_act_obligation = None;
        assert!(report.triggered_regulations().is_empty());
    }

    #[test]
    fn test_requires_dora_24h_critical() {
        let report = sample_report();
        assert!(report.requires_dora_24h_notification());
    }

    #[test]
    fn test_requires_dora_24h_low_severity_false() {
        let mut report = sample_report();
        report.severity = IncidentSeverity::Low;
        assert!(!report.requires_dora_24h_notification());
    }

    #[test]
    fn test_serialization_roundtrip() {
        let report = sample_report();
        let json = serde_json::to_string(&report).unwrap();
        let parsed: IncidentReport = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.id, report.id);
        assert_eq!(parsed.severity, report.severity);
        assert_eq!(parsed.regulatory_references.len(), 3);
    }

    #[test]
    fn test_deny_unknown_fields() {
        let json = r#"{"id":"x","title":"t","description":"d","severity":"Low","detected_at":"","reported_at":"","affected_systems":[],"findings":[],"recommendations":[],"unknown_field":true,"regulatory_references":[]}"#;
        let result: Result<IncidentReport, _> = serde_json::from_str(json);
        assert!(
            result.is_err(),
            "deny_unknown_fields should reject unknown fields"
        );
    }
}
