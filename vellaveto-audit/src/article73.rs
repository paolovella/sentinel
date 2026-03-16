// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Phase 4: EU AI Act Article 73 incident report generation.
//!
//! Generates structured incident reports with regulatory metadata for
//! serious incidents under Art 73. Each report includes:
//! - Incident classification and severity
//! - Timeline with regulatory notification deadlines
//! - Affected systems and scope
//! - Evidence references from the audit trail
//! - Cross-regulation mapping (NIS2, DORA, EU AI Act)

use serde::{Deserialize, Serialize};

/// An Article 73 incident report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentReport {
    /// Unique incident identifier.
    pub incident_id: String,
    /// Incident title.
    pub title: String,
    /// Incident classification.
    pub classification: IncidentClassification,
    /// Severity (1-5, where 5 is most severe).
    pub severity: u8,
    /// ISO 8601 timestamp when the incident was detected.
    pub detected_at: String,
    /// ISO 8601 timestamp when the incident occurred (if known).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub occurred_at: Option<String>,
    /// Description of what happened.
    pub description: String,
    /// Affected systems / tools / servers.
    pub affected_assets: Vec<String>,
    /// Number of affected users/sessions (if known).
    #[serde(default)]
    pub affected_scope: u64,
    /// Evidence references (audit entry IDs, log lines).
    pub evidence_refs: Vec<String>,
    /// Regulatory notification deadlines.
    pub notification_deadlines: Vec<NotificationDeadline>,
    /// Remediation actions taken.
    pub remediation: Vec<String>,
    /// Current status.
    pub status: IncidentStatus,
}

/// Incident classification categories.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum IncidentClassification {
    /// Security breach — unauthorized access, data exfiltration.
    SecurityBreach,
    /// Safety incident — harmful output, dangerous actions.
    SafetyIncident,
    /// Fundamental rights impact — discrimination, privacy violation.
    FundamentalRightsImpact,
    /// System malfunction — unexpected behavior, policy bypass.
    SystemMalfunction,
    /// Supply chain compromise — rug-pull, tool poisoning.
    SupplyChainCompromise,
}

/// Incident lifecycle status.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum IncidentStatus {
    Detected,
    Investigating,
    Contained,
    Remediated,
    Closed,
}

/// A regulatory notification deadline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationDeadline {
    /// Regulation name.
    pub regulation: String,
    /// Specific article/clause.
    pub article: String,
    /// Deadline description.
    pub description: String,
    /// Hours from detection to required notification.
    pub hours_from_detection: u32,
    /// ISO 8601 absolute deadline timestamp.
    pub deadline_at: String,
    /// Whether notification has been sent.
    pub notified: bool,
}

/// Parameters for building an incident report.
pub struct IncidentParams {
    pub incident_id: String,
    pub title: String,
    pub classification: IncidentClassification,
    pub severity: u8,
    pub detected_at: String,
    pub description: String,
    pub affected_assets: Vec<String>,
    pub evidence_refs: Vec<String>,
}

/// Build an incident report with cross-regulation notification deadlines.
pub fn build_incident_report(params: IncidentParams) -> IncidentReport {
    let deadlines = compute_notification_deadlines(&params.detected_at, &params.classification);

    IncidentReport {
        incident_id: params.incident_id,
        title: params.title,
        classification: params.classification,
        severity: params.severity.min(5),
        detected_at: params.detected_at,
        occurred_at: None,
        description: params.description,
        affected_assets: params.affected_assets,
        affected_scope: 0,
        evidence_refs: params.evidence_refs,
        notification_deadlines: deadlines,
        remediation: Vec::new(),
        status: IncidentStatus::Detected,
    }
}

/// Compute cross-regulation notification deadlines from detection time.
fn compute_notification_deadlines(
    detected_at: &str,
    classification: &IncidentClassification,
) -> Vec<NotificationDeadline> {
    let mut deadlines = Vec::new();

    // EU AI Act Art 73: serious incidents → notify within 15 days
    // (72 hours for initial notification per proposed implementing acts)
    deadlines.push(NotificationDeadline {
        regulation: "EU AI Act".to_string(),
        article: "Art 73".to_string(),
        description: "Initial serious incident notification to market surveillance authority"
            .to_string(),
        hours_from_detection: 72,
        deadline_at: offset_timestamp(detected_at, 72),
        notified: false,
    });

    // NIS2 Art 23: significant incidents → early warning within 24h
    if matches!(
        classification,
        IncidentClassification::SecurityBreach | IncidentClassification::SupplyChainCompromise
    ) {
        deadlines.push(NotificationDeadline {
            regulation: "NIS2".to_string(),
            article: "Art 23(4)(a)".to_string(),
            description: "Early warning to CSIRT/competent authority".to_string(),
            hours_from_detection: 24,
            deadline_at: offset_timestamp(detected_at, 24),
            notified: false,
        });
        deadlines.push(NotificationDeadline {
            regulation: "NIS2".to_string(),
            article: "Art 23(4)(b)".to_string(),
            description: "Incident notification with initial assessment".to_string(),
            hours_from_detection: 72,
            deadline_at: offset_timestamp(detected_at, 72),
            notified: false,
        });
        // NIS2 final report within 1 month
        deadlines.push(NotificationDeadline {
            regulation: "NIS2".to_string(),
            article: "Art 23(4)(d)".to_string(),
            description: "Final report".to_string(),
            hours_from_detection: 720, // ~30 days
            deadline_at: offset_timestamp(detected_at, 720),
            notified: false,
        });
    }

    // DORA Art 19: major ICT incidents → initial notification within 4h
    deadlines.push(NotificationDeadline {
        regulation: "DORA".to_string(),
        article: "Art 19(4)(a)".to_string(),
        description: "Initial ICT incident notification".to_string(),
        hours_from_detection: 4,
        deadline_at: offset_timestamp(detected_at, 4),
        notified: false,
    });

    deadlines
}

/// Offset an ISO 8601 timestamp by N hours (best-effort string manipulation).
fn offset_timestamp(base: &str, hours: u32) -> String {
    // Try to parse and offset; fall back to string concat
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(base) {
        let offset = chrono::Duration::hours(i64::from(hours));
        (dt + offset).to_rfc3339()
    } else {
        format!("{base} + {hours}h")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_incident_report_security_breach() {
        let report = build_incident_report(IncidentParams {
            incident_id: "INC-001".to_string(),
            title: "Credential exfiltration detected".to_string(),
            classification: IncidentClassification::SecurityBreach,
            severity: 4,
            detected_at: "2026-03-16T12:00:00Z".to_string(),
            description: "Agent attempted to read AWS credentials and exfiltrate via webhook"
                .to_string(),
            affected_assets: vec!["read_file".to_string(), "http_request".to_string()],
            evidence_refs: vec!["audit-entry-42".to_string()],
        });
        assert_eq!(report.incident_id, "INC-001");
        assert_eq!(report.severity, 4);
        assert_eq!(report.status, IncidentStatus::Detected);
        // Security breach → NIS2 + DORA + EU AI Act deadlines
        assert!(report.notification_deadlines.len() >= 4);
        // Check NIS2 24h deadline exists
        assert!(report
            .notification_deadlines
            .iter()
            .any(|d| d.regulation == "NIS2" && d.hours_from_detection == 24));
        // Check DORA 4h deadline exists
        assert!(report
            .notification_deadlines
            .iter()
            .any(|d| d.regulation == "DORA" && d.hours_from_detection == 4));
    }

    #[test]
    fn test_build_incident_report_safety_incident() {
        let report = build_incident_report(IncidentParams {
            incident_id: "INC-002".to_string(),
            title: "Dangerous command executed".to_string(),
            classification: IncidentClassification::SafetyIncident,
            severity: 3,
            detected_at: "2026-03-16T14:00:00Z".to_string(),
            description: "rm -rf / bypassed regex constraint".to_string(),
            affected_assets: vec!["execute_command".to_string()],
            evidence_refs: Vec::new(),
        });
        // Safety incident → EU AI Act + DORA, but NOT NIS2 (not a security breach)
        let nis2_count = report
            .notification_deadlines
            .iter()
            .filter(|d| d.regulation == "NIS2")
            .count();
        assert_eq!(nis2_count, 0);
    }

    #[test]
    fn test_severity_capped_at_5() {
        let report = build_incident_report(IncidentParams {
            incident_id: "INC-003".to_string(),
            title: "Test".to_string(),
            classification: IncidentClassification::SystemMalfunction,
            severity: 99,
            detected_at: "2026-03-16T00:00:00Z".to_string(),
            description: "Test".to_string(),
            affected_assets: Vec::new(),
            evidence_refs: Vec::new(),
        });
        assert_eq!(report.severity, 5);
    }

    #[test]
    fn test_offset_timestamp_valid() {
        let result = offset_timestamp("2026-03-16T12:00:00+00:00", 24);
        assert!(result.contains("2026-03-17"));
    }

    #[test]
    fn test_offset_timestamp_invalid_fallback() {
        let result = offset_timestamp("not-a-date", 24);
        assert!(result.contains("+ 24h"));
    }
}
