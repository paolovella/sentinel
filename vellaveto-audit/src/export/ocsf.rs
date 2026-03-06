// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella

//! OCSF (Open Cybersecurity Schema Framework) v1.3 export for audit entries.
//!
//! Maps Vellaveto [`AuditEntry`] records to OCSF Authorization events
//! (class\_uid 3002, category\_uid 3 — Identity & Access Management).
//!
//! Compatible with AWS Security Lake, Datadog, Splunk, and other OCSF-aware
//! consumers.
//!
//! # OCSF Mapping
//!
//! | Verdict            | activity\_id | severity\_id | status\_id |
//! |--------------------|-------------|-------------|-----------|
//! | Allow              | 1 (Access)  | 1 (Info)    | 1 (Success) |
//! | Deny               | 2 (Deny)    | 4 (High)    | 2 (Failure) |
//! | RequireApproval    | 99 (Other)  | 2 (Low)     | 99 (Other)  |

use crate::AuditEntry;
use serde::{Deserialize, Serialize};
use vellaveto_types::Verdict;

// ── Constants ────────────────────────────────────────────────────────────────

/// OCSF class UID for Authorization events.
const CLASS_UID: u32 = 3002;

/// OCSF category UID for Identity & Access Management.
const CATEGORY_UID: u32 = 3;

/// Maximum length for string fields to prevent unbounded output.
const MAX_FIELD_LEN: usize = 1024;

/// Product name included in OCSF metadata.
const PRODUCT_NAME: &str = "Vellaveto MCP Firewall";

/// Product vendor included in OCSF metadata.
const PRODUCT_VENDOR: &str = "Vellaveto";

/// OCSF schema version.
const SCHEMA_VERSION: &str = "1.3.0";

// ── OCSF Event Types ────────────────────────────────────────────────────────

/// An OCSF v1.3 Authorization event (class_uid 3002).
///
/// See <https://schema.ocsf.io/1.3.0/classes/authorization> for the full
/// schema definition.
// SECURITY (R231-AUD-4): Added deny_unknown_fields for project-wide consistency.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct OcsfEvent {
    /// OCSF class UID. Always 3002 (Authorization).
    pub class_uid: u32,

    /// OCSF category UID. Always 3 (Identity & Access Management).
    pub category_uid: u32,

    /// Severity of the event.
    /// - 1 = Informational (Allow)
    /// - 2 = Low (RequireApproval)
    /// - 4 = High (Deny)
    pub severity_id: u8,

    /// Activity type.
    /// - 1 = Access (Allow)
    /// - 2 = Deny
    /// - 99 = Other (RequireApproval)
    pub activity_id: u8,

    /// Compound type identifier: `class_uid * 100 + activity_id`.
    pub type_uid: u32,

    /// Event timestamp in Unix milliseconds.
    pub time: i64,

    /// Human-readable event summary.
    pub message: String,

    /// Disposition of the authorization decision.
    /// - 1 = Success (Allow)
    /// - 2 = Failure (Deny)
    /// - 99 = Other (RequireApproval)
    pub status_id: u8,

    /// The actor (agent) that requested the action.
    pub actor: OcsfActor,

    /// The source endpoint (tool being invoked).
    pub src_endpoint: OcsfEndpoint,

    /// The policy that produced the verdict.
    pub policy: OcsfPolicy,

    /// Event metadata (product, schema version, etc.).
    pub metadata: OcsfMetadata,

    /// Additional fields that do not map to standard OCSF properties.
    #[serde(default, skip_serializing_if = "is_null_or_empty_object")]
    pub unmapped: serde_json::Value,
}

/// OCSF Actor object — represents the entity requesting access.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct OcsfActor {
    /// Agent or tool identifier.
    pub user: OcsfUser,
}

/// OCSF User object — minimal identity representation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct OcsfUser {
    /// Agent tool name.
    pub name: String,

    /// Unique identifier (audit entry ID).
    pub uid: String,
}

/// OCSF Endpoint object — represents the tool/function being called.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct OcsfEndpoint {
    /// Tool name.
    pub name: String,

    /// Function being invoked.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub svc_name: String,
}

/// OCSF Policy object — the security policy that produced the verdict.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct OcsfPolicy {
    /// Policy name or description.
    pub name: String,

    /// Policy verdict as a human-readable string.
    pub desc: String,
}

/// OCSF Metadata object — event provenance information.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct OcsfMetadata {
    /// OCSF schema version (e.g. "1.3.0").
    pub version: String,

    /// Product information.
    pub product: OcsfProduct,

    /// Original audit entry ID.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub uid: String,
}

/// OCSF Product object.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct OcsfProduct {
    /// Product name.
    pub name: String,

    /// Product vendor.
    pub vendor_name: String,
}

// ── Conversion ───────────────────────────────────────────────────────────────

/// Convert an [`AuditEntry`] to an OCSF v1.3 Authorization event.
///
/// This is a pure, infallible function — all fields are derived from the
/// audit entry without I/O or allocation failures.
pub fn audit_entry_to_ocsf(entry: &AuditEntry) -> OcsfEvent {
    let (activity_id, severity_id, status_id, message) = match &entry.verdict {
        Verdict::Allow => (
            1u8,
            1u8,
            1u8,
            format!(
                "Allowed: {}:{} — access granted",
                truncate(&entry.action.tool, MAX_FIELD_LEN),
                truncate(&entry.action.function, MAX_FIELD_LEN),
            ),
        ),
        Verdict::Deny { reason } => (
            2u8,
            4u8,
            2u8,
            format!(
                "Denied: {}:{} — {}",
                truncate(&entry.action.tool, MAX_FIELD_LEN),
                truncate(&entry.action.function, MAX_FIELD_LEN),
                truncate(reason, MAX_FIELD_LEN),
            ),
        ),
        Verdict::RequireApproval { reason } => (
            99u8,
            2u8,
            99u8,
            format!(
                "Approval required: {}:{} — {}",
                truncate(&entry.action.tool, MAX_FIELD_LEN),
                truncate(&entry.action.function, MAX_FIELD_LEN),
                truncate(reason, MAX_FIELD_LEN),
            ),
        ),
        // Fail-closed: unknown verdict variants treated as high severity deny.
        _ => (
            2u8,
            4u8,
            2u8,
            format!(
                "Unknown verdict: {}:{}",
                truncate(&entry.action.tool, MAX_FIELD_LEN),
                truncate(&entry.action.function, MAX_FIELD_LEN),
            ),
        ),
    };

    let type_uid = CLASS_UID
        .saturating_mul(100)
        .saturating_add(activity_id as u32);

    let time = parse_timestamp_millis(&entry.timestamp);

    // Build unmapped fields from entry metadata and audit-specific fields.
    let mut unmapped = serde_json::Map::new();
    if let Some(hash) = &entry.entry_hash {
        unmapped.insert(
            "entry_hash".to_string(),
            serde_json::Value::String(hash.clone()),
        );
    }
    if let Some(prev) = &entry.prev_hash {
        unmapped.insert(
            "prev_hash".to_string(),
            serde_json::Value::String(prev.clone()),
        );
    }
    if let Some(tenant) = &entry.tenant_id {
        unmapped.insert(
            "tenant_id".to_string(),
            serde_json::Value::String(tenant.clone()),
        );
    }
    // SECURITY (R231-AUD-3): Always include sequence number, including 0.
    // The first entry (sequence 0) was previously excluded, creating an
    // information asymmetry between OCSF and JSONL/CEF exports.
    unmapped.insert(
        "sequence".to_string(),
        serde_json::Value::Number(serde_json::Number::from(entry.sequence)),
    );

    let verdict_desc = match &entry.verdict {
        Verdict::Allow => "Allow".to_string(),
        Verdict::Deny { reason } => format!("Deny: {}", truncate(reason, MAX_FIELD_LEN)),
        Verdict::RequireApproval { reason } => {
            format!("RequireApproval: {}", truncate(reason, MAX_FIELD_LEN))
        }
        _ => "Unknown".to_string(),
    };

    OcsfEvent {
        class_uid: CLASS_UID,
        category_uid: CATEGORY_UID,
        severity_id,
        activity_id,
        type_uid,
        time,
        message,
        status_id,
        actor: OcsfActor {
            user: OcsfUser {
                name: truncate(&entry.action.tool, MAX_FIELD_LEN).to_string(),
                uid: truncate(&entry.id, MAX_FIELD_LEN).to_string(),
            },
        },
        src_endpoint: OcsfEndpoint {
            name: truncate(&entry.action.tool, MAX_FIELD_LEN).to_string(),
            svc_name: truncate(&entry.action.function, MAX_FIELD_LEN).to_string(),
        },
        policy: OcsfPolicy {
            name: "Vellaveto Policy Evaluation".to_string(),
            desc: verdict_desc,
        },
        metadata: OcsfMetadata {
            version: SCHEMA_VERSION.to_string(),
            product: OcsfProduct {
                name: PRODUCT_NAME.to_string(),
                vendor_name: PRODUCT_VENDOR.to_string(),
            },
            uid: truncate(&entry.id, MAX_FIELD_LEN).to_string(),
        },
        unmapped: if unmapped.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::Value::Object(unmapped)
        },
    }
}

/// Serialize an [`OcsfEvent`] to a JSON string.
///
/// Returns a compact (non-pretty) JSON representation suitable for
/// ingestion by OCSF-aware consumers (AWS Security Lake, Datadog, etc.).
pub fn to_json(event: &OcsfEvent) -> Result<String, serde_json::Error> {
    serde_json::to_string(event)
}

// ── Internal Helpers ─────────────────────────────────────────────────────────

/// Truncate a string to `max_len` bytes on a valid UTF-8 boundary.
fn truncate(s: &str, max_len: usize) -> &str {
    if s.len() <= max_len {
        return s;
    }
    let mut end = max_len;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Parse an ISO 8601 timestamp string to Unix milliseconds.
///
/// Falls back to 0 on parse failure (fail-closed: a zero timestamp is
/// obviously invalid and will be flagged by any downstream consumer,
/// rather than silently producing a plausible-but-wrong value).
fn parse_timestamp_millis(ts: &str) -> i64 {
    chrono::DateTime::parse_from_rfc3339(ts)
        .map(|dt| dt.timestamp_millis())
        .unwrap_or_else(|_| {
            // Try common ISO 8601 variants (with/without timezone)
            chrono::NaiveDateTime::parse_from_str(ts, "%Y-%m-%dT%H:%M:%S")
                .map(|ndt| ndt.and_utc().timestamp_millis())
                .unwrap_or(0)
        })
}

/// Helper for `skip_serializing_if` on the `unmapped` field.
fn is_null_or_empty_object(v: &serde_json::Value) -> bool {
    match v {
        serde_json::Value::Null => true,
        serde_json::Value::Object(m) => m.is_empty(),
        _ => false,
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use vellaveto_types::Action;

    /// Helper to create a test AuditEntry with the given verdict.
    fn make_entry(tool: &str, function: &str, verdict: Verdict) -> AuditEntry {
        AuditEntry {
            id: "ocsf-test-001".to_string(),
            action: Action::new(tool, function, serde_json::json!({"path": "/tmp/test"})),
            verdict,
            timestamp: "2026-02-25T14:30:00Z".to_string(),
            metadata: serde_json::json!({"source": "test"}),
            sequence: 0,
            entry_hash: Some("abc123def456".to_string()),
            prev_hash: None,
            commitment: None,
            tenant_id: None,
        }
    }

    #[test]
    fn test_allow_event_mapping() {
        let entry = make_entry("read_file", "execute", Verdict::Allow);
        let event = audit_entry_to_ocsf(&entry);

        assert_eq!(event.class_uid, 3002);
        assert_eq!(event.category_uid, 3);
        assert_eq!(event.activity_id, 1);
        assert_eq!(event.severity_id, 1);
        assert_eq!(event.status_id, 1);
        assert_eq!(event.type_uid, 300201);
        assert!(event.message.contains("Allowed"));
        assert!(event.message.contains("read_file:execute"));
        assert_eq!(event.actor.user.name, "read_file");
        assert_eq!(event.src_endpoint.name, "read_file");
        assert_eq!(event.src_endpoint.svc_name, "execute");
        assert_eq!(event.policy.desc, "Allow");
        assert_eq!(event.metadata.version, "1.3.0");
        assert_eq!(event.metadata.product.name, "Vellaveto MCP Firewall");
        assert_eq!(event.metadata.product.vendor_name, "Vellaveto");
        assert_eq!(event.metadata.uid, "ocsf-test-001");
    }

    #[test]
    fn test_deny_event_mapping() {
        let entry = make_entry(
            "bash",
            "exec",
            Verdict::Deny {
                reason: "blocked by policy".to_string(),
            },
        );
        let event = audit_entry_to_ocsf(&entry);

        assert_eq!(event.class_uid, 3002);
        assert_eq!(event.activity_id, 2);
        assert_eq!(event.severity_id, 4);
        assert_eq!(event.status_id, 2);
        assert_eq!(event.type_uid, 300202);
        assert!(event.message.contains("Denied"));
        assert!(event.message.contains("bash:exec"));
        assert!(event.message.contains("blocked by policy"));
        assert!(event.policy.desc.contains("Deny"));
        assert!(event.policy.desc.contains("blocked by policy"));
    }

    #[test]
    fn test_approval_event_mapping() {
        let entry = make_entry(
            "deploy",
            "production",
            Verdict::RequireApproval {
                reason: "needs manager sign-off".to_string(),
            },
        );
        let event = audit_entry_to_ocsf(&entry);

        assert_eq!(event.class_uid, 3002);
        assert_eq!(event.activity_id, 99);
        assert_eq!(event.severity_id, 2);
        assert_eq!(event.status_id, 99);
        assert_eq!(event.type_uid, 300299);
        assert!(event.message.contains("Approval required"));
        assert!(event.message.contains("deploy:production"));
        assert!(event.message.contains("needs manager sign-off"));
        assert!(event.policy.desc.contains("RequireApproval"));
    }

    #[test]
    fn test_ocsf_json_roundtrip() {
        let entry = make_entry("read_file", "execute", Verdict::Allow);
        let event = audit_entry_to_ocsf(&entry);

        // Serialize to JSON
        let json_str = to_json(&event).expect("serialization must succeed");

        // Deserialize back
        let roundtripped: OcsfEvent =
            serde_json::from_str(&json_str).expect("deserialization must succeed");

        assert_eq!(event, roundtripped);
    }

    #[test]
    fn test_ocsf_json_roundtrip_deny() {
        let entry = make_entry(
            "rm",
            "recursive",
            Verdict::Deny {
                reason: "destructive operation".to_string(),
            },
        );
        let event = audit_entry_to_ocsf(&entry);
        let json_str = to_json(&event).expect("serialization must succeed");
        let roundtripped: OcsfEvent =
            serde_json::from_str(&json_str).expect("deserialization must succeed");
        assert_eq!(event, roundtripped);
    }

    #[test]
    fn test_ocsf_json_roundtrip_approval() {
        let entry = make_entry(
            "deploy",
            "prod",
            Verdict::RequireApproval {
                reason: "escalation required".to_string(),
            },
        );
        let event = audit_entry_to_ocsf(&entry);
        let json_str = to_json(&event).expect("serialization must succeed");
        let roundtripped: OcsfEvent =
            serde_json::from_str(&json_str).expect("deserialization must succeed");
        assert_eq!(event, roundtripped);
    }

    #[test]
    fn test_severity_mapping() {
        // Allow -> severity 1 (Informational)
        let allow = audit_entry_to_ocsf(&make_entry("t", "f", Verdict::Allow));
        assert_eq!(allow.severity_id, 1, "Allow should be severity 1 (Info)");

        // Deny -> severity 4 (High)
        let deny = audit_entry_to_ocsf(&make_entry(
            "t",
            "f",
            Verdict::Deny {
                reason: "x".to_string(),
            },
        ));
        assert_eq!(deny.severity_id, 4, "Deny should be severity 4 (High)");

        // RequireApproval -> severity 2 (Low)
        let approval = audit_entry_to_ocsf(&make_entry(
            "t",
            "f",
            Verdict::RequireApproval {
                reason: "x".to_string(),
            },
        ));
        assert_eq!(
            approval.severity_id, 2,
            "RequireApproval should be severity 2 (Low)"
        );
    }

    #[test]
    fn test_type_uid_calculation() {
        // type_uid = class_uid * 100 + activity_id
        // Allow: 3002 * 100 + 1 = 300201
        let allow = audit_entry_to_ocsf(&make_entry("t", "f", Verdict::Allow));
        assert_eq!(allow.type_uid, 3002 * 100 + 1);

        // Deny: 3002 * 100 + 2 = 300202
        let deny = audit_entry_to_ocsf(&make_entry(
            "t",
            "f",
            Verdict::Deny {
                reason: "x".to_string(),
            },
        ));
        assert_eq!(deny.type_uid, 3002 * 100 + 2);

        // RequireApproval: 3002 * 100 + 99 = 300299
        let approval = audit_entry_to_ocsf(&make_entry(
            "t",
            "f",
            Verdict::RequireApproval {
                reason: "x".to_string(),
            },
        ));
        assert_eq!(approval.type_uid, 3002 * 100 + 99);
    }

    #[test]
    fn test_timestamp_parsing() {
        // Valid RFC 3339 — just verify it's nonzero (positive)
        let millis = parse_timestamp_millis("2026-02-25T14:30:00Z");
        assert!(millis > 0, "Valid timestamp should produce positive millis");

        // Invalid timestamp -> 0 (fail-closed)
        assert_eq!(parse_timestamp_millis("not-a-timestamp"), 0);
        assert_eq!(parse_timestamp_millis(""), 0);
    }

    #[test]
    fn test_unmapped_fields_populated() {
        let mut entry = make_entry("t", "f", Verdict::Allow);
        entry.entry_hash = Some("hash123".to_string());
        entry.prev_hash = Some("prevhash456".to_string());
        entry.tenant_id = Some("tenant-abc".to_string());
        entry.sequence = 42;

        let event = audit_entry_to_ocsf(&entry);

        let unmapped = event
            .unmapped
            .as_object()
            .expect("unmapped should be an object");
        assert_eq!(unmapped["entry_hash"], "hash123");
        assert_eq!(unmapped["prev_hash"], "prevhash456");
        assert_eq!(unmapped["tenant_id"], "tenant-abc");
        assert_eq!(unmapped["sequence"], 42);
    }

    #[test]
    fn test_unmapped_fields_empty_when_defaults() {
        let mut entry = make_entry("t", "f", Verdict::Allow);
        entry.entry_hash = None;
        entry.prev_hash = None;
        entry.tenant_id = None;
        entry.sequence = 0;

        let event = audit_entry_to_ocsf(&entry);

        // SECURITY (R231-AUD-3): Sequence is now always included (including 0),
        // so unmapped should contain exactly {"sequence": 0}.
        let obj = event
            .unmapped
            .as_object()
            .expect("unmapped should be object");
        assert_eq!(
            obj.len(),
            1,
            "unmapped should contain only 'sequence' when defaults"
        );
        assert_eq!(obj.get("sequence").and_then(|v| v.as_u64()), Some(0));
    }

    #[test]
    fn test_truncation_long_tool_name() {
        let long_tool = "a".repeat(2000);
        let entry = make_entry(&long_tool, "f", Verdict::Allow);
        let event = audit_entry_to_ocsf(&entry);

        assert!(
            event.actor.user.name.len() <= MAX_FIELD_LEN,
            "Tool name should be truncated to MAX_FIELD_LEN"
        );
        assert!(
            event.src_endpoint.name.len() <= MAX_FIELD_LEN,
            "Endpoint name should be truncated to MAX_FIELD_LEN"
        );
    }

    #[test]
    fn test_json_output_contains_required_ocsf_fields() {
        let entry = make_entry("read_file", "execute", Verdict::Allow);
        let event = audit_entry_to_ocsf(&entry);
        let json_str = to_json(&event).expect("serialization must succeed");
        let parsed: serde_json::Value =
            serde_json::from_str(&json_str).expect("must be valid JSON");

        // Verify all required OCSF fields are present
        assert!(parsed.get("class_uid").is_some(), "missing class_uid");
        assert!(parsed.get("category_uid").is_some(), "missing category_uid");
        assert!(parsed.get("severity_id").is_some(), "missing severity_id");
        assert!(parsed.get("activity_id").is_some(), "missing activity_id");
        assert!(parsed.get("type_uid").is_some(), "missing type_uid");
        assert!(parsed.get("time").is_some(), "missing time");
        assert!(parsed.get("message").is_some(), "missing message");
        assert!(parsed.get("status_id").is_some(), "missing status_id");
        assert!(parsed.get("actor").is_some(), "missing actor");
        assert!(parsed.get("src_endpoint").is_some(), "missing src_endpoint");
        assert!(parsed.get("policy").is_some(), "missing policy");
        assert!(parsed.get("metadata").is_some(), "missing metadata");
    }
}
