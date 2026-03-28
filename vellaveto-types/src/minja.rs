// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Memory Injection Defense (MINJA) types — taint tracking, provenance,
//! quarantine, namespace isolation, and memory security statistics.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

/// Taint labels for tracking data provenance and trust level.
///
/// Memory entries are tagged with taint labels to indicate their source
/// and security properties. Taint propagates when derived data is created.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum TaintLabel {
    /// Data from an untrusted source (external tool response, notification).
    Untrusted,
    /// Data that has been sanitized or validated.
    Sanitized,
    /// Data that is quarantined due to security concerns.
    Quarantined,
    /// Data that contains sensitive information (PII, secrets).
    Sensitive,
    /// Data that originated from a different agent (cross-agent flow).
    CrossAgent,
    /// Data that has been replayed from a previous session.
    Replayed,
    /// Data derived from multiple sources with mixed trust levels.
    MixedProvenance,
    /// Data that failed integrity verification.
    IntegrityFailed,
}

impl fmt::Display for TaintLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TaintLabel::Untrusted => write!(f, "untrusted"),
            TaintLabel::Sanitized => write!(f, "sanitized"),
            TaintLabel::Quarantined => write!(f, "quarantined"),
            TaintLabel::Sensitive => write!(f, "sensitive"),
            TaintLabel::CrossAgent => write!(f, "cross_agent"),
            TaintLabel::Replayed => write!(f, "replayed"),
            TaintLabel::MixedProvenance => write!(f, "mixed_provenance"),
            TaintLabel::IntegrityFailed => write!(f, "integrity_failed"),
        }
    }
}

/// Maximum number of taint labels per memory entry.
pub const MAX_TAINT_LABELS: usize = 16;

/// A memory entry with provenance tracking for MINJA defense.
///
/// Represents a notable string or data fragment recorded from tool responses,
/// notifications, or other sources. Tracks access patterns, trust scores,
/// and provenance for detecting memory injection attacks.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct MemoryEntry {
    /// Unique identifier for this entry (UUID v4).
    pub id: String,
    /// SHA-256 fingerprint of the content.
    pub fingerprint: String,
    /// Truncated preview of the content (first 100 chars).
    pub preview: String,
    /// ISO 8601 timestamp when the entry was first recorded.
    pub recorded_at: String,
    /// ISO 8601 timestamp when the entry was last accessed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_accessed: Option<String>,
    /// Number of times this entry has been accessed (matched in parameters).
    #[serde(default)]
    pub access_count: u64,
    /// Taint labels associated with this entry.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub taint_labels: Vec<TaintLabel>,
    /// Current trust score (0.0 = no trust, 1.0 = full trust).
    /// Decays over time based on trust_decay_rate.
    #[serde(default = "default_trust_score")]
    pub trust_score: f64,
    /// ID of the provenance node that created this entry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance_id: Option<String>,
    /// Whether this entry is currently quarantined.
    #[serde(default)]
    pub quarantined: bool,
    /// Namespace this entry belongs to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// Session ID this entry belongs to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Agent ID that created this entry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    /// SHA-256 hash of the full content for integrity verification.
    pub content_hash: String,
}

fn default_trust_score() -> f64 {
    1.0
}

impl MemoryEntry {
    /// Maximum preview length in characters.
    pub const MAX_PREVIEW_LENGTH: usize = 100;
    /// Maximum length for `id` field.
    ///
    /// SECURITY (FIND-R113-018): Bound string fields to prevent memory exhaustion.
    const MAX_ID_LEN: usize = 256;
    /// Maximum length for `fingerprint` field (SHA-256 hex).
    ///
    /// SECURITY (FIND-R113-018): Bound string fields.
    const MAX_FINGERPRINT_LEN: usize = 128;
    /// Maximum length for `content_hash` field (SHA-256 hex).
    ///
    /// SECURITY (FIND-R113-018): Bound string fields.
    const MAX_CONTENT_HASH_LEN: usize = 128;
    /// Maximum length for timestamp fields (`recorded_at`, `last_accessed`).
    ///
    /// SECURITY (FIND-R113-018): Bound string fields.
    const MAX_TIMESTAMP_LEN: usize = 64;
    /// Maximum length for `provenance_id` field.
    ///
    /// SECURITY (FIND-R113-018): Bound string fields.
    const MAX_PROVENANCE_ID_LEN: usize = 256;
    /// Maximum length for `namespace` field.
    ///
    /// SECURITY (FIND-R113-018): Bound string fields.
    const MAX_NAMESPACE_LEN: usize = 256;
    /// Maximum length for `session_id` field.
    ///
    /// SECURITY (FIND-R113-018): Bound string fields.
    const MAX_SESSION_ID_LEN: usize = 256;
    /// Maximum length for `agent_id` field.
    ///
    /// SECURITY (FIND-R113-018): Bound string fields.
    const MAX_AGENT_ID_LEN: usize = 256;

    /// Helper: validate a string field for control/format characters.
    ///
    /// SECURITY (IMP-R126-011): Delegates to canonical `has_dangerous_chars()`.
    fn validate_no_control_chars(
        type_name: &str,
        field_name: &str,
        value: &str,
    ) -> Result<(), String> {
        if crate::core::has_dangerous_chars(value) {
            return Err(format!(
                "{type_name} {field_name} contains control or format characters"
            ));
        }
        Ok(())
    }

    /// Validate that all f64 fields are finite (not NaN or Infinity),
    /// that trust_score is consistent with taint_labels, and that
    /// string fields are within bounds and free of control/format characters.
    ///
    /// SECURITY (FIND-R46-018): Tainted memory entries (those with non-empty
    /// taint_labels containing security-relevant labels like Untrusted,
    /// Quarantined, IntegrityFailed, or MixedProvenance) must not have a
    /// perfect trust score of 1.0. A trust_score of 1.0 on tainted data
    /// could cause downstream consumers to skip security checks.
    /// SECURITY (FIND-R113-018): Length bounds and control/format char validation.
    pub fn validate(&self) -> Result<(), String> {
        // SECURITY (FIND-R113-018): String field length bounds.
        if self.id.len() > Self::MAX_ID_LEN {
            return Err(format!(
                "MemoryEntry id length {} exceeds max {}",
                self.id.len(),
                Self::MAX_ID_LEN
            ));
        }
        if self.fingerprint.len() > Self::MAX_FINGERPRINT_LEN {
            return Err(format!(
                "MemoryEntry '{}' fingerprint length {} exceeds max {}",
                self.id,
                self.fingerprint.len(),
                Self::MAX_FINGERPRINT_LEN
            ));
        }
        if self.preview.len() > Self::MAX_PREVIEW_LENGTH + 3 {
            // +3 for "..." suffix
            return Err(format!(
                "MemoryEntry '{}' preview length {} exceeds max {}",
                self.id,
                self.preview.len(),
                Self::MAX_PREVIEW_LENGTH + 3
            ));
        }
        if self.recorded_at.len() > Self::MAX_TIMESTAMP_LEN {
            return Err(format!(
                "MemoryEntry '{}' recorded_at length {} exceeds max {}",
                self.id,
                self.recorded_at.len(),
                Self::MAX_TIMESTAMP_LEN
            ));
        }
        if let Some(ref la) = self.last_accessed {
            if la.len() > Self::MAX_TIMESTAMP_LEN {
                return Err(format!(
                    "MemoryEntry '{}' last_accessed length {} exceeds max {}",
                    self.id,
                    la.len(),
                    Self::MAX_TIMESTAMP_LEN
                ));
            }
        }
        if self.content_hash.len() > Self::MAX_CONTENT_HASH_LEN {
            return Err(format!(
                "MemoryEntry '{}' content_hash length {} exceeds max {}",
                self.id,
                self.content_hash.len(),
                Self::MAX_CONTENT_HASH_LEN
            ));
        }
        if let Some(ref pid) = self.provenance_id {
            if pid.len() > Self::MAX_PROVENANCE_ID_LEN {
                return Err(format!(
                    "MemoryEntry '{}' provenance_id length {} exceeds max {}",
                    self.id,
                    pid.len(),
                    Self::MAX_PROVENANCE_ID_LEN
                ));
            }
        }
        if let Some(ref ns) = self.namespace {
            if ns.len() > Self::MAX_NAMESPACE_LEN {
                return Err(format!(
                    "MemoryEntry '{}' namespace length {} exceeds max {}",
                    self.id,
                    ns.len(),
                    Self::MAX_NAMESPACE_LEN
                ));
            }
        }
        if let Some(ref sid) = self.session_id {
            if sid.len() > Self::MAX_SESSION_ID_LEN {
                return Err(format!(
                    "MemoryEntry '{}' session_id length {} exceeds max {}",
                    self.id,
                    sid.len(),
                    Self::MAX_SESSION_ID_LEN
                ));
            }
        }
        if let Some(ref aid) = self.agent_id {
            if aid.len() > Self::MAX_AGENT_ID_LEN {
                return Err(format!(
                    "MemoryEntry '{}' agent_id length {} exceeds max {}",
                    self.id,
                    aid.len(),
                    Self::MAX_AGENT_ID_LEN
                ));
            }
        }

        // SECURITY (FIND-R113-018): Control/format character validation on key string fields.
        Self::validate_no_control_chars("MemoryEntry", "id", &self.id)?;
        Self::validate_no_control_chars("MemoryEntry", "fingerprint", &self.fingerprint)?;
        Self::validate_no_control_chars("MemoryEntry", "recorded_at", &self.recorded_at)?;
        Self::validate_no_control_chars("MemoryEntry", "content_hash", &self.content_hash)?;
        if let Some(ref la) = self.last_accessed {
            Self::validate_no_control_chars("MemoryEntry", "last_accessed", la)?;
        }
        if let Some(ref pid) = self.provenance_id {
            Self::validate_no_control_chars("MemoryEntry", "provenance_id", pid)?;
        }
        if let Some(ref ns) = self.namespace {
            Self::validate_no_control_chars("MemoryEntry", "namespace", ns)?;
        }
        if let Some(ref sid) = self.session_id {
            Self::validate_no_control_chars("MemoryEntry", "session_id", sid)?;
        }
        if let Some(ref aid) = self.agent_id {
            Self::validate_no_control_chars("MemoryEntry", "agent_id", aid)?;
        }
        // Note: preview is user content (truncated tool response) — control chars
        // may legitimately appear in tool output, so we do not validate it.

        // SECURITY (FIND-R112-006): Enforce MAX_TAINT_LABELS on deserialized data.
        if self.taint_labels.len() > MAX_TAINT_LABELS {
            return Err(format!(
                "MemoryEntry '{}' has {} taint_labels, max {}",
                self.id,
                self.taint_labels.len(),
                MAX_TAINT_LABELS
            ));
        }

        if !self.trust_score.is_finite() {
            return Err(format!(
                "MemoryEntry '{}' trust_score is not finite: {}",
                self.id, self.trust_score
            ));
        }
        // SECURITY (FIND-R51-001): Validate trust_score is in documented [0.0, 1.0] range.
        if self.trust_score < 0.0 || self.trust_score > 1.0 {
            return Err(format!(
                "MemoryEntry '{}' trust_score must be in [0.0, 1.0], got {}",
                self.id, self.trust_score
            ));
        }

        // Security-relevant taint labels that are incompatible with perfect trust
        let has_security_taint = self.taint_labels.iter().any(|label| {
            matches!(
                label,
                TaintLabel::Untrusted
                    | TaintLabel::Quarantined
                    | TaintLabel::IntegrityFailed
                    | TaintLabel::MixedProvenance
                    | TaintLabel::Replayed
            )
        });

        if has_security_taint && self.trust_score >= 1.0 {
            return Err(format!(
                "MemoryEntry '{}' has security-relevant taint labels {:?} but trust_score is {} (must be < 1.0)",
                self.id, self.taint_labels, self.trust_score
            ));
        }

        Ok(())
    }

    /// Validate that all f64 fields are finite (not NaN or Infinity).
    #[deprecated(
        since = "4.0.1",
        note = "use validate() which also checks taint/trust consistency"
    )]
    pub fn validate_finite(&self) -> Result<(), String> {
        if !self.trust_score.is_finite() {
            return Err(format!(
                "MemoryEntry '{}' trust_score is not finite: {}",
                self.id, self.trust_score
            ));
        }
        // SECURITY (FIND-R51-001): Validate trust_score is in documented [0.0, 1.0] range.
        if self.trust_score < 0.0 || self.trust_score > 1.0 {
            return Err(format!(
                "MemoryEntry '{}' trust_score must be in [0.0, 1.0], got {}",
                self.id, self.trust_score
            ));
        }
        Ok(())
    }

    /// Create a new memory entry with default values.
    pub fn new(
        id: String,
        fingerprint: String,
        content: &str,
        content_hash: String,
        recorded_at: String,
    ) -> Self {
        let preview = if content.len() > Self::MAX_PREVIEW_LENGTH {
            let mut end = Self::MAX_PREVIEW_LENGTH;
            while !content.is_char_boundary(end) && end > 0 {
                end -= 1;
            }
            format!("{}...", &content[..end])
        } else {
            content.to_string()
        };

        Self {
            id,
            fingerprint,
            preview,
            recorded_at,
            last_accessed: None,
            access_count: 0,
            taint_labels: vec![TaintLabel::Untrusted],
            // SECURITY (FIND-R46-018): New entries start Untrusted, so trust
            // must be < 1.0 to be consistent with the taint label. 0.5 is a
            // reasonable default for unverified data from external sources.
            trust_score: 0.5,
            provenance_id: None,
            quarantined: false,
            namespace: None,
            session_id: None,
            agent_id: None,
            content_hash,
        }
    }

    /// Check if this entry is tainted with a specific label.
    pub fn has_taint(&self, label: TaintLabel) -> bool {
        self.taint_labels.contains(&label)
    }

    /// Add a taint label if not already present and under the limit.
    pub fn add_taint(&mut self, label: TaintLabel) -> bool {
        if self.taint_labels.len() >= MAX_TAINT_LABELS {
            return false;
        }
        if !self.taint_labels.contains(&label) {
            self.taint_labels.push(label);
            true
        } else {
            false
        }
    }

    /// Check if the entry should be blocked based on quarantine status.
    pub fn is_blocked(&self) -> bool {
        self.quarantined || self.has_taint(TaintLabel::Quarantined)
    }

    /// Calculate the current trust score after decay.
    /// Uses exponential decay: trust(t) = initial_trust * e^(-λ * age_hours)
    ///
    /// SECURITY (FIND-P1-6): Returns `0.0` (minimum trust / fail-closed) when
    /// timestamps cannot be parsed. Previously returned the full undecayed trust
    /// score on parse failure, which meant corrupt timestamps bypassed trust decay.
    pub fn decayed_trust_score(&self, decay_rate: f64, current_time: &str) -> f64 {
        match Self::hours_since(&self.recorded_at, current_time) {
            Some(age_hours) => self.trust_score * (-decay_rate * age_hours).exp(),
            None => {
                // Fail-closed: corrupt/unparseable timestamps → minimum trust
                0.0
            }
        }
    }

    /// Calculate hours between two ISO 8601 timestamps.
    ///
    /// SECURITY (FIND-P1-6): Returns `None` if either timestamp fails to parse,
    /// rather than silently returning `0.0` which would bypass trust decay.
    fn hours_since(start: &str, end: &str) -> Option<f64> {
        let start_secs = Self::parse_timestamp(start)?;
        let end_secs = Self::parse_timestamp(end)?;

        if end_secs > start_secs {
            Some((end_secs - start_secs) as f64 / 3600.0)
        } else {
            // end <= start: zero elapsed time (not negative)
            Some(0.0)
        }
    }

    /// Parse an ISO 8601 timestamp to Unix seconds (approximate).
    ///
    /// Delegates to the shared `time_util::parse_iso8601_secs` to avoid
    /// duplicating validation logic across modules.
    ///
    /// SECURITY (FIND-P1-6): Validates that month >= 1, day >= 1, and
    /// year >= 1970 to prevent underflow in the epoch calculation.
    fn parse_timestamp(ts: &str) -> Option<u64> {
        crate::time_util::parse_iso8601_secs(ts).ok()
    }
}

/// Event types for provenance tracking.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ProvenanceEventType {
    /// Data received from a tool response.
    ToolResponse,
    /// Data received from a notification.
    Notification,
    /// Data derived from other entries (transformation, aggregation).
    Derivation,
    /// Data replayed from a previous request.
    Replay,
    /// Data received from external source (user input, API).
    ExternalInput,
    /// Data created by the agent itself.
    AgentGenerated,
    /// Data received from another agent.
    CrossAgentReceive,
    /// Data sent to another agent.
    CrossAgentSend,
    /// Data restored from persistent storage.
    Restore,
    /// Data sanitized or validated.
    Sanitization,
}

impl fmt::Display for ProvenanceEventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProvenanceEventType::ToolResponse => write!(f, "tool_response"),
            ProvenanceEventType::Notification => write!(f, "notification"),
            ProvenanceEventType::Derivation => write!(f, "derivation"),
            ProvenanceEventType::Replay => write!(f, "replay"),
            ProvenanceEventType::ExternalInput => write!(f, "external_input"),
            ProvenanceEventType::AgentGenerated => write!(f, "agent_generated"),
            ProvenanceEventType::CrossAgentReceive => write!(f, "cross_agent_receive"),
            ProvenanceEventType::CrossAgentSend => write!(f, "cross_agent_send"),
            ProvenanceEventType::Restore => write!(f, "restore"),
            ProvenanceEventType::Sanitization => write!(f, "sanitization"),
        }
    }
}

/// A node in the provenance graph tracking data lineage.
///
/// Forms a DAG (directed acyclic graph) where edges point from parent
/// entries to derived entries. Used to detect suspicious patterns like
/// notification→replay chains or cross-session data flows.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ProvenanceNode {
    /// Unique identifier for this node (UUID v4).
    pub id: String,
    /// Type of event that created this node.
    pub event_type: ProvenanceEventType,
    /// ISO 8601 timestamp when this node was created.
    pub timestamp: String,
    /// Source identifier (tool name, notification method, agent ID).
    pub source: String,
    /// Session ID where this event occurred.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Parent node IDs (entries this was derived from).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub parents: Vec<String>,
    /// SHA-256 hash of the content at this node.
    pub content_hash: String,
    /// Memory entry ID associated with this node.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry_id: Option<String>,
    /// Additional metadata about the provenance event.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub metadata: HashMap<String, String>,
}

impl ProvenanceNode {
    /// Maximum number of parent references per node.
    pub const MAX_PARENTS: usize = 64;

    /// Create a new provenance node.
    pub fn new(
        id: String,
        event_type: ProvenanceEventType,
        source: String,
        content_hash: String,
        timestamp: String,
    ) -> Self {
        Self {
            id,
            event_type,
            timestamp,
            source,
            session_id: None,
            parents: Vec::new(),
            content_hash,
            entry_id: None,
            metadata: HashMap::new(),
        }
    }

    /// Maximum number of metadata entries per node.
    pub const MAX_METADATA_ENTRIES: usize = 64;

    /// Maximum length of the `id` field.
    ///
    /// SECURITY (FIND-R51-014): Bound string fields to prevent memory exhaustion.
    pub const MAX_ID_LEN: usize = 256;

    /// Maximum length of the `source` field.
    ///
    /// SECURITY (FIND-R51-014): Bound string fields to prevent memory exhaustion.
    pub const MAX_SOURCE_LEN: usize = 1024;

    /// Maximum length of the `content_hash` field.
    ///
    /// SECURITY (FIND-R51-014): Bound string fields to prevent memory exhaustion.
    pub const MAX_CONTENT_HASH_LEN: usize = 256;

    /// Validate bounds on deserialized data.
    ///
    /// SECURITY (FIND-R48-003): MAX_PARENTS was declared but never enforced.
    /// Deserialized payloads can contain arbitrarily many parents/metadata.
    ///
    /// SECURITY (FIND-R51-014): Also validates string field lengths for id,
    /// source, and content_hash to prevent memory exhaustion via crafted payloads.
    pub fn validate(&self) -> Result<(), String> {
        if self.id.len() > Self::MAX_ID_LEN {
            return Err(format!(
                "ProvenanceNode id length {} exceeds max {}",
                self.id.len(),
                Self::MAX_ID_LEN
            ));
        }
        if self.source.len() > Self::MAX_SOURCE_LEN {
            return Err(format!(
                "ProvenanceNode '{}' source length {} exceeds max {}",
                self.id,
                self.source.len(),
                Self::MAX_SOURCE_LEN
            ));
        }
        if self.content_hash.len() > Self::MAX_CONTENT_HASH_LEN {
            return Err(format!(
                "ProvenanceNode '{}' content_hash length {} exceeds max {}",
                self.id,
                self.content_hash.len(),
                Self::MAX_CONTENT_HASH_LEN
            ));
        }
        if self.parents.len() > Self::MAX_PARENTS {
            return Err(format!(
                "ProvenanceNode '{}' has {} parents (max {})",
                self.id,
                self.parents.len(),
                Self::MAX_PARENTS
            ));
        }
        if self.metadata.len() > Self::MAX_METADATA_ENTRIES {
            return Err(format!(
                "ProvenanceNode '{}' has {} metadata entries (max {})",
                self.id,
                self.metadata.len(),
                Self::MAX_METADATA_ENTRIES
            ));
        }
        // SECURITY (R235-TYP-2): Validate dangerous chars on all string fields
        // (parity with MemoryEntry::validate() in the same module).
        for (field, value) in [
            ("id", self.id.as_str()),
            ("source", self.source.as_str()),
            ("content_hash", self.content_hash.as_str()),
            ("timestamp", self.timestamp.as_str()),
        ] {
            if crate::core::has_dangerous_chars(value) {
                return Err(format!(
                    "ProvenanceNode {field} contains control or format characters"
                ));
            }
        }
        if let Some(ref sid) = self.session_id {
            if crate::core::has_dangerous_chars(sid) {
                return Err(
                    "ProvenanceNode session_id contains control or format characters".to_string(),
                );
            }
        }
        if let Some(ref eid) = self.entry_id {
            if crate::core::has_dangerous_chars(eid) {
                return Err(
                    "ProvenanceNode entry_id contains control or format characters".to_string(),
                );
            }
        }
        for parent in &self.parents {
            if crate::core::has_dangerous_chars(parent) {
                return Err(
                    "ProvenanceNode parent contains control or format characters".to_string(),
                );
            }
        }
        for (key, val) in &self.metadata {
            if crate::core::has_dangerous_chars(key) || crate::core::has_dangerous_chars(val) {
                return Err(
                    "ProvenanceNode metadata contains control or format characters".to_string(),
                );
            }
        }
        Ok(())
    }

    /// Check if this node represents a suspicious pattern.
    pub fn is_suspicious(&self) -> bool {
        matches!(
            self.event_type,
            ProvenanceEventType::Replay | ProvenanceEventType::CrossAgentReceive
        )
    }
}

/// Reason for quarantining a memory entry.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineDetection {
    /// Entry matched injection patterns.
    InjectionPattern,
    /// Suspicious data flow pattern detected.
    SuspiciousDataFlow,
    /// Trust score below threshold.
    LowTrust,
    /// Cross-session data replay detected.
    CrossSessionReplay,
    /// Notification→tool_call chain detected.
    NotificationReplay,
    /// Content integrity verification failed.
    IntegrityFailure,
    /// Manual quarantine by administrator.
    ManualQuarantine,
    /// Entry from untrusted source exceeded access threshold.
    ExcessiveAccess,
    /// Entry contains sensitive data patterns.
    SensitiveData,
}

impl fmt::Display for QuarantineDetection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            QuarantineDetection::InjectionPattern => write!(f, "injection_pattern"),
            QuarantineDetection::SuspiciousDataFlow => write!(f, "suspicious_data_flow"),
            QuarantineDetection::LowTrust => write!(f, "low_trust"),
            QuarantineDetection::CrossSessionReplay => write!(f, "cross_session_replay"),
            QuarantineDetection::NotificationReplay => write!(f, "notification_replay"),
            QuarantineDetection::IntegrityFailure => write!(f, "integrity_failure"),
            QuarantineDetection::ManualQuarantine => write!(f, "manual_quarantine"),
            QuarantineDetection::ExcessiveAccess => write!(f, "excessive_access"),
            QuarantineDetection::SensitiveData => write!(f, "sensitive_data"),
        }
    }
}

/// Record of a quarantined memory entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct QuarantineEntry {
    /// ID of the quarantined memory entry.
    pub entry_id: String,
    /// Reason for quarantine.
    pub reason: QuarantineDetection,
    /// ISO 8601 timestamp when quarantine was applied.
    pub quarantined_at: String,
    /// Optional description of the quarantine reason.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Agent or system that triggered the quarantine.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub triggered_by: Option<String>,
    /// Whether the quarantine was lifted.
    #[serde(default)]
    pub released: bool,
    /// ISO 8601 timestamp when quarantine was released.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub released_at: Option<String>,
}

impl QuarantineEntry {
    /// Maximum length for `entry_id` field.
    const MAX_ENTRY_ID_LEN: usize = 256;
    /// Maximum length for timestamp fields (`quarantined_at`, `released_at`).
    const MAX_TIMESTAMP_LEN: usize = 64;
    /// Maximum length for `description` field.
    const MAX_DESCRIPTION_LEN: usize = 4096;
    /// Maximum length for `triggered_by` field.
    const MAX_TRIGGERED_BY_LEN: usize = 256;

    /// Create a new quarantine entry.
    pub fn new(entry_id: String, reason: QuarantineDetection, quarantined_at: String) -> Self {
        Self {
            entry_id,
            reason,
            quarantined_at,
            description: None,
            triggered_by: None,
            released: false,
            released_at: None,
        }
    }

    /// Validate structural bounds on string fields.
    ///
    /// SECURITY (FIND-R71-004): Prevents memory exhaustion via oversized quarantine entries.
    pub fn validate(&self) -> Result<(), String> {
        if self.entry_id.len() > Self::MAX_ENTRY_ID_LEN {
            return Err(format!(
                "QuarantineEntry entry_id length {} exceeds max {}",
                self.entry_id.len(),
                Self::MAX_ENTRY_ID_LEN,
            ));
        }
        // SECURITY (R235-TYP-3): Validate dangerous chars on all string fields.
        if crate::core::has_dangerous_chars(&self.entry_id) {
            return Err(
                "QuarantineEntry entry_id contains control or format characters".to_string(),
            );
        }
        if self.quarantined_at.len() > Self::MAX_TIMESTAMP_LEN {
            return Err(format!(
                "QuarantineEntry quarantined_at length {} exceeds max {}",
                self.quarantined_at.len(),
                Self::MAX_TIMESTAMP_LEN,
            ));
        }
        if crate::core::has_dangerous_chars(&self.quarantined_at) {
            return Err(
                "QuarantineEntry quarantined_at contains control or format characters".to_string(),
            );
        }
        if let Some(ref desc) = self.description {
            if desc.len() > Self::MAX_DESCRIPTION_LEN {
                return Err(format!(
                    "QuarantineEntry description length {} exceeds max {}",
                    desc.len(),
                    Self::MAX_DESCRIPTION_LEN,
                ));
            }
            if crate::core::has_dangerous_chars(desc) {
                return Err(
                    "QuarantineEntry description contains control or format characters".to_string(),
                );
            }
        }
        if let Some(ref tb) = self.triggered_by {
            if tb.len() > Self::MAX_TRIGGERED_BY_LEN {
                return Err(format!(
                    "QuarantineEntry triggered_by length {} exceeds max {}",
                    tb.len(),
                    Self::MAX_TRIGGERED_BY_LEN,
                ));
            }
            if crate::core::has_dangerous_chars(tb) {
                return Err(
                    "QuarantineEntry triggered_by contains control or format characters"
                        .to_string(),
                );
            }
        }
        if let Some(ref ra) = self.released_at {
            if ra.len() > Self::MAX_TIMESTAMP_LEN {
                return Err(format!(
                    "QuarantineEntry released_at length {} exceeds max {}",
                    ra.len(),
                    Self::MAX_TIMESTAMP_LEN,
                ));
            }
            if crate::core::has_dangerous_chars(ra) {
                return Err(
                    "QuarantineEntry released_at contains control or format characters".to_string(),
                );
            }
        }
        Ok(())
    }
}

/// Memory namespace for agent isolation.
///
/// Namespaces provide logical isolation between agents and sessions.
/// Access control policies determine which agents can read/write to
/// which namespaces.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct MemoryNamespace {
    /// Unique namespace identifier.
    pub id: String,
    /// Agent ID that owns this namespace.
    pub owner_agent: String,
    /// Agent IDs allowed to read from this namespace.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub read_allowed: Vec<String>,
    /// Agent IDs allowed to write to this namespace.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub write_allowed: Vec<String>,
    /// ISO 8601 timestamp when namespace was created.
    pub created_at: String,
    /// Isolation level for the namespace.
    #[serde(default)]
    pub isolation: NamespaceIsolation,
    /// Whether this namespace is the default for its owner.
    #[serde(default)]
    pub is_default: bool,
}

impl MemoryNamespace {
    /// Create a new namespace with the given owner.
    ///
    /// FIND-P3-017: Minimized clones — `owner_agent` is cloned once for
    /// `read_allowed`, once for `write_allowed`, and the original is moved
    /// into the `owner_agent` field.
    pub fn new(id: String, owner_agent: String, created_at: String) -> Self {
        let read_allowed = vec![owner_agent.clone()];
        let write_allowed = vec![owner_agent.clone()];
        Self {
            id,
            owner_agent,
            read_allowed,
            write_allowed,
            created_at,
            isolation: NamespaceIsolation::default(),
            is_default: false,
        }
    }

    /// Check if an agent can read from this namespace.
    pub fn can_read(&self, agent_id: &str) -> bool {
        self.owner_agent == agent_id || self.read_allowed.iter().any(|a| a == agent_id || a == "*")
    }

    /// Check if an agent can write to this namespace.
    pub fn can_write(&self, agent_id: &str) -> bool {
        self.owner_agent == agent_id || self.write_allowed.iter().any(|a| a == agent_id || a == "*")
    }

    /// Maximum ACL entries per namespace.
    pub const MAX_ACL_ENTRIES: usize = 1000;

    /// Maximum length of namespace id, owner_agent, created_at fields.
    pub const MAX_FIELD_LEN: usize = 256;

    /// Validate bounds on deserialized data.
    ///
    /// SECURITY (FIND-R48-008): Unbounded read_allowed/write_allowed from deserialization.
    /// SECURITY (R235-TYP-4): Validate id, owner_agent, created_at, and per-entry
    /// ACL strings for dangerous chars and length bounds.
    pub fn validate(&self) -> Result<(), String> {
        // Validate top-level string fields
        for (field, value) in [
            ("id", self.id.as_str()),
            ("owner_agent", self.owner_agent.as_str()),
            ("created_at", self.created_at.as_str()),
        ] {
            if value.len() > Self::MAX_FIELD_LEN {
                return Err(format!(
                    "MemoryNamespace {field} length {} exceeds max {}",
                    value.len(),
                    Self::MAX_FIELD_LEN
                ));
            }
            if crate::core::has_dangerous_chars(value) {
                return Err(format!(
                    "MemoryNamespace {field} contains control or format characters"
                ));
            }
        }
        if self.read_allowed.len() > Self::MAX_ACL_ENTRIES {
            return Err(format!(
                "MemoryNamespace '{}' has {} read_allowed entries (max {})",
                self.id,
                self.read_allowed.len(),
                Self::MAX_ACL_ENTRIES
            ));
        }
        if self.write_allowed.len() > Self::MAX_ACL_ENTRIES {
            return Err(format!(
                "MemoryNamespace '{}' has {} write_allowed entries (max {})",
                self.id,
                self.write_allowed.len(),
                Self::MAX_ACL_ENTRIES
            ));
        }
        // Validate per-entry ACL strings
        for entry in self.read_allowed.iter().chain(self.write_allowed.iter()) {
            if entry.len() > Self::MAX_FIELD_LEN {
                return Err(format!(
                    "MemoryNamespace ACL entry length {} exceeds max {}",
                    entry.len(),
                    Self::MAX_FIELD_LEN
                ));
            }
            if crate::core::has_dangerous_chars(entry) {
                return Err(
                    "MemoryNamespace ACL entry contains control or format characters".to_string(),
                );
            }
        }
        Ok(())
    }
}

/// Namespace isolation level.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
#[serde(rename_all = "snake_case")]
pub enum NamespaceIsolation {
    /// Isolated per session (default).
    #[default]
    Session,
    /// Isolated per agent (shared across sessions).
    Agent,
    /// Shared namespace (accessible by allowed agents).
    Shared,
}

impl fmt::Display for NamespaceIsolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NamespaceIsolation::Session => write!(f, "session"),
            NamespaceIsolation::Agent => write!(f, "agent"),
            NamespaceIsolation::Shared => write!(f, "shared"),
        }
    }
}

/// Decision for memory access requests.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MemoryAccessDecision {
    /// Access is allowed.
    Allow,
    /// Access is denied with a reason.
    Deny { reason: String },
    /// Access requires manual approval.
    RequireApproval { reason: String },
}

impl fmt::Display for MemoryAccessDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MemoryAccessDecision::Allow => write!(f, "allow"),
            MemoryAccessDecision::Deny { reason } => write!(f, "deny: {reason}"),
            MemoryAccessDecision::RequireApproval { reason } => {
                write!(f, "require_approval: {reason}")
            }
        }
    }
}

/// Request to share a namespace with another agent.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct NamespaceSharingRequest {
    /// Namespace ID to share.
    pub namespace_id: String,
    /// Agent ID requesting access.
    pub requester_agent: String,
    /// Requested access type.
    pub access_type: NamespaceAccessType,
    /// ISO 8601 timestamp of the request.
    pub requested_at: String,
    /// Tri-state approval status:
    /// - `None` — pending (not yet reviewed by an operator).
    /// - `Some(true)` — approved (access granted, ACL updated).
    /// - `Some(false)` — denied (access rejected, requester notified).
    #[serde(default)]
    pub approved: Option<bool>,
    /// ISO 8601 timestamp when the request was resolved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_at: Option<String>,
}

impl NamespaceSharingRequest {
    /// Maximum length for `namespace_id` field.
    const MAX_NAMESPACE_ID_LEN: usize = 256;
    /// Maximum length for `requester_agent` field.
    const MAX_REQUESTER_AGENT_LEN: usize = 256;
    /// Maximum length for timestamp fields (`requested_at`, `resolved_at`).
    const MAX_TIMESTAMP_LEN: usize = 64;

    /// Validate structural bounds and control character safety on string fields.
    ///
    /// SECURITY (FIND-R71-005): Prevents memory exhaustion via oversized sharing
    /// requests and rejects control/format characters in identity fields.
    pub fn validate(&self) -> Result<(), String> {
        if self.namespace_id.len() > Self::MAX_NAMESPACE_ID_LEN {
            return Err(format!(
                "NamespaceSharingRequest namespace_id length {} exceeds max {}",
                self.namespace_id.len(),
                Self::MAX_NAMESPACE_ID_LEN,
            ));
        }
        if self.requester_agent.len() > Self::MAX_REQUESTER_AGENT_LEN {
            return Err(format!(
                "NamespaceSharingRequest requester_agent length {} exceeds max {}",
                self.requester_agent.len(),
                Self::MAX_REQUESTER_AGENT_LEN,
            ));
        }
        if self.requested_at.len() > Self::MAX_TIMESTAMP_LEN {
            return Err(format!(
                "NamespaceSharingRequest requested_at length {} exceeds max {}",
                self.requested_at.len(),
                Self::MAX_TIMESTAMP_LEN,
            ));
        }
        if let Some(ref ra) = self.resolved_at {
            if ra.len() > Self::MAX_TIMESTAMP_LEN {
                return Err(format!(
                    "NamespaceSharingRequest resolved_at length {} exceeds max {}",
                    ra.len(),
                    Self::MAX_TIMESTAMP_LEN,
                ));
            }
        }
        // Control character validation on identity fields
        for c in self.namespace_id.chars() {
            if c.is_control() || crate::core::is_unicode_format_char(c) {
                return Err(format!(
                    "NamespaceSharingRequest namespace_id contains invalid character U+{:04X}",
                    c as u32,
                ));
            }
        }
        for c in self.requester_agent.chars() {
            if c.is_control() || crate::core::is_unicode_format_char(c) {
                return Err(format!(
                    "NamespaceSharingRequest requester_agent contains invalid character U+{:04X}",
                    c as u32,
                ));
            }
        }
        Ok(())
    }
}

/// Type of namespace access requested.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum NamespaceAccessType {
    /// Read-only access.
    Read,
    /// Write access (implies read).
    Write,
    /// Full access (read, write, and share).
    Full,
}

impl fmt::Display for NamespaceAccessType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NamespaceAccessType::Read => write!(f, "read"),
            NamespaceAccessType::Write => write!(f, "write"),
            NamespaceAccessType::Full => write!(f, "full"),
        }
    }
}

/// Aggregate statistics for MINJA memory security operations.
///
/// Exposed via the `/api/health` and governance endpoints.
/// All counters use `u64` and are incremented with `saturating_add`.
// SECURITY (R255-TYP-3): deny_unknown_fields on deserialized struct.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct MemorySecurityStats {
    /// Total [`MemoryEntry`] records currently tracked across all namespaces.
    pub total_entries: u64,
    /// Entries currently in quarantine (blocked from use in tool parameters).
    pub quarantined_entries: u64,
    /// Total [`ProvenanceNode`] records in the provenance DAG.
    pub provenance_nodes: u64,
    /// Number of [`MemoryNamespace`] instances created (including defaults).
    pub namespaces: u64,
    /// Cumulative count of injection patterns detected in memory content
    /// (matched by Aho-Corasick + NFKC normalization).
    pub injections_detected: u64,
    /// Cumulative count of cross-session data replays blocked by the
    /// session guard (prevents data exfiltration via session pivoting).
    pub cross_session_blocked: u64,
    /// Cumulative count of access denials due to trust score below the
    /// configured `trust_threshold` after time-based decay.
    pub low_trust_denials: u64,
    /// Number of [`NamespaceSharingRequest`] records awaiting operator approval.
    pub pending_shares: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Helper: minimal valid MemoryEntry ────────────────────────────────

    fn valid_entry() -> MemoryEntry {
        MemoryEntry {
            id: "entry-1".to_string(),
            fingerprint: "abc123".to_string(),
            preview: "hello world".to_string(),
            recorded_at: "2025-01-15T10:00:00Z".to_string(),
            last_accessed: None,
            access_count: 0,
            taint_labels: vec![],
            trust_score: 0.8,
            provenance_id: None,
            quarantined: false,
            namespace: None,
            session_id: None,
            agent_id: None,
            content_hash: "deadbeef".to_string(),
        }
    }

    // ── MemoryEntry::validate() — valid baseline ────────────────────────

    #[test]
    fn test_memory_entry_validate_valid_baseline_ok() {
        assert!(valid_entry().validate().is_ok());
    }

    // ── trust_score: NaN / Infinity / negative / above 1.0 ──────────────

    #[test]
    fn test_memory_entry_validate_trust_score_nan_rejected() {
        let mut e = valid_entry();
        e.trust_score = f64::NAN;
        let err = e.validate().unwrap_err();
        assert!(err.contains("not finite"), "got: {err}");
    }

    #[test]
    fn test_memory_entry_validate_trust_score_infinity_rejected() {
        let mut e = valid_entry();
        e.trust_score = f64::INFINITY;
        let err = e.validate().unwrap_err();
        assert!(err.contains("not finite"), "got: {err}");
    }

    #[test]
    fn test_memory_entry_validate_trust_score_neg_infinity_rejected() {
        let mut e = valid_entry();
        e.trust_score = f64::NEG_INFINITY;
        let err = e.validate().unwrap_err();
        assert!(err.contains("not finite"), "got: {err}");
    }

    #[test]
    fn test_memory_entry_validate_trust_score_negative_rejected() {
        let mut e = valid_entry();
        e.trust_score = -0.1;
        let err = e.validate().unwrap_err();
        assert!(err.contains("[0.0, 1.0]"), "got: {err}");
    }

    #[test]
    fn test_memory_entry_validate_trust_score_above_one_rejected() {
        let mut e = valid_entry();
        e.trust_score = 1.01;
        let err = e.validate().unwrap_err();
        assert!(err.contains("[0.0, 1.0]"), "got: {err}");
    }

    #[test]
    fn test_memory_entry_validate_trust_score_boundaries_ok() {
        let mut e = valid_entry();
        e.trust_score = 0.0;
        assert!(e.validate().is_ok());
        e.trust_score = 1.0;
        assert!(e.validate().is_ok());
    }

    // ── taint label / trust_score consistency ────────────────────────────

    #[test]
    fn test_memory_entry_validate_security_taint_with_perfect_trust_rejected() {
        let mut e = valid_entry();
        e.trust_score = 1.0;
        e.taint_labels = vec![TaintLabel::Untrusted];
        let err = e.validate().unwrap_err();
        assert!(err.contains("security-relevant taint"), "got: {err}");
    }

    #[test]
    fn test_memory_entry_validate_security_taint_with_low_trust_ok() {
        let mut e = valid_entry();
        e.trust_score = 0.5;
        e.taint_labels = vec![TaintLabel::Untrusted];
        assert!(e.validate().is_ok());
    }

    #[test]
    fn test_memory_entry_validate_non_security_taint_with_perfect_trust_ok() {
        let mut e = valid_entry();
        e.trust_score = 1.0;
        e.taint_labels = vec![TaintLabel::Sanitized, TaintLabel::Sensitive];
        assert!(e.validate().is_ok());
    }

    #[test]
    fn test_memory_entry_validate_all_security_taints_rejected_at_1() {
        for label in &[
            TaintLabel::Untrusted,
            TaintLabel::Quarantined,
            TaintLabel::IntegrityFailed,
            TaintLabel::MixedProvenance,
            TaintLabel::Replayed,
        ] {
            let mut e = valid_entry();
            e.trust_score = 1.0;
            e.taint_labels = vec![*label];
            assert!(e.validate().is_err(), "Expected error for {label:?}");
        }
    }

    // ── taint_labels overflow ────────────────────────────────────────────

    #[test]
    fn test_memory_entry_validate_taint_labels_over_max_rejected() {
        let mut e = valid_entry();
        e.taint_labels = vec![TaintLabel::Sanitized; MAX_TAINT_LABELS + 1];
        let err = e.validate().unwrap_err();
        assert!(err.contains("taint_labels"), "got: {err}");
    }

    #[test]
    fn test_memory_entry_validate_taint_labels_at_max_ok() {
        let mut e = valid_entry();
        e.taint_labels = vec![TaintLabel::Sanitized; MAX_TAINT_LABELS];
        assert!(e.validate().is_ok());
    }

    // ── string field length bounds ───────────────────────────────────────

    #[test]
    fn test_memory_entry_validate_id_too_long_rejected() {
        let mut e = valid_entry();
        e.id = "x".repeat(MemoryEntry::MAX_ID_LEN + 1);
        assert!(e.validate().unwrap_err().contains("id length"));
    }

    #[test]
    fn test_memory_entry_validate_fingerprint_too_long_rejected() {
        let mut e = valid_entry();
        e.fingerprint = "a".repeat(MemoryEntry::MAX_FINGERPRINT_LEN + 1);
        assert!(e.validate().unwrap_err().contains("fingerprint length"));
    }

    #[test]
    fn test_memory_entry_validate_content_hash_too_long_rejected() {
        let mut e = valid_entry();
        e.content_hash = "b".repeat(MemoryEntry::MAX_CONTENT_HASH_LEN + 1);
        assert!(e.validate().unwrap_err().contains("content_hash length"));
    }

    #[test]
    fn test_memory_entry_validate_preview_too_long_rejected() {
        let mut e = valid_entry();
        // MAX_PREVIEW_LENGTH + 3 (for "...") + 1 to exceed
        e.preview = "p".repeat(MemoryEntry::MAX_PREVIEW_LENGTH + 4);
        assert!(e.validate().unwrap_err().contains("preview length"));
    }

    // ── control character rejection ──────────────────────────────────────

    #[test]
    fn test_memory_entry_validate_id_control_char_rejected() {
        let mut e = valid_entry();
        e.id = "entry\x00bad".to_string();
        let err = e.validate().unwrap_err();
        assert!(err.contains("control or format"), "got: {err}");
    }

    #[test]
    fn test_memory_entry_validate_fingerprint_control_char_rejected() {
        let mut e = valid_entry();
        e.fingerprint = "fp\x07bell".to_string();
        let err = e.validate().unwrap_err();
        assert!(err.contains("control or format"), "got: {err}");
    }

    #[test]
    fn test_memory_entry_validate_optional_fields_control_chars_rejected() {
        // provenance_id
        let mut e = valid_entry();
        e.provenance_id = Some("prov\x01id".to_string());
        assert!(e.validate().unwrap_err().contains("control or format"));

        // namespace
        let mut e2 = valid_entry();
        e2.namespace = Some("ns\x08bad".to_string());
        assert!(e2.validate().unwrap_err().contains("control or format"));

        // session_id
        let mut e3 = valid_entry();
        e3.session_id = Some("sid\x0Cff".to_string());
        assert!(e3.validate().unwrap_err().contains("control or format"));

        // agent_id
        let mut e4 = valid_entry();
        e4.agent_id = Some("aid\x7F del".to_string());
        assert!(e4.validate().unwrap_err().contains("control or format"));
    }

    // ── MemoryEntry::new() ──────────────────────────────────────────────

    #[test]
    fn test_memory_entry_new_short_content_no_truncation() {
        let entry = MemoryEntry::new(
            "id1".into(),
            "fp".into(),
            "short",
            "hash".into(),
            "2025-01-01T00:00:00Z".into(),
        );
        assert_eq!(entry.preview, "short");
        assert_eq!(entry.trust_score, 0.5);
        assert!(entry.has_taint(TaintLabel::Untrusted));
        assert!(entry.validate().is_ok());
    }

    #[test]
    fn test_memory_entry_new_long_content_truncated() {
        let content = "a".repeat(200);
        let entry = MemoryEntry::new(
            "id2".into(),
            "fp2".into(),
            &content,
            "hash2".into(),
            "2025-06-01T12:00:00Z".into(),
        );
        assert!(entry.preview.ends_with("..."));
        assert!(entry.preview.len() <= MemoryEntry::MAX_PREVIEW_LENGTH + 3);
    }

    // ── add_taint / has_taint / is_blocked ──────────────────────────────

    #[test]
    fn test_memory_entry_add_taint_duplicate_returns_false() {
        let mut e = valid_entry();
        e.taint_labels = vec![TaintLabel::Sensitive];
        assert!(!e.add_taint(TaintLabel::Sensitive));
    }

    #[test]
    fn test_memory_entry_add_taint_at_capacity_returns_false() {
        let mut e = valid_entry();
        e.taint_labels = vec![TaintLabel::Sanitized; MAX_TAINT_LABELS];
        assert!(!e.add_taint(TaintLabel::Untrusted));
    }

    #[test]
    fn test_memory_entry_is_blocked_quarantined_flag() {
        let mut e = valid_entry();
        e.quarantined = true;
        assert!(e.is_blocked());
    }

    #[test]
    fn test_memory_entry_is_blocked_quarantined_taint() {
        let mut e = valid_entry();
        e.taint_labels = vec![TaintLabel::Quarantined];
        assert!(e.is_blocked());
    }

    // ── decayed_trust_score ─────────────────────────────────────────────

    #[test]
    fn test_memory_entry_decayed_trust_score_fail_closed_on_bad_timestamp() {
        let mut e = valid_entry();
        e.recorded_at = "not-a-timestamp".to_string();
        let score = e.decayed_trust_score(0.1, "2025-01-15T10:00:00Z");
        assert_eq!(score, 0.0);
    }

    // ── ProvenanceNode::validate() ──────────────────────────────────────

    #[test]
    fn test_provenance_node_validate_valid_ok() {
        let node = ProvenanceNode::new(
            "node-1".into(),
            ProvenanceEventType::ToolResponse,
            "my-tool".into(),
            "abc123".into(),
            "2025-01-01T00:00:00Z".into(),
        );
        assert!(node.validate().is_ok());
    }

    #[test]
    fn test_provenance_node_validate_too_many_parents_rejected() {
        let mut node = ProvenanceNode::new(
            "n1".into(),
            ProvenanceEventType::Derivation,
            "src".into(),
            "hash".into(),
            "2025-01-01T00:00:00Z".into(),
        );
        node.parents = vec!["p".to_string(); ProvenanceNode::MAX_PARENTS + 1];
        assert!(node.validate().unwrap_err().contains("parents"));
    }

    #[test]
    fn test_provenance_node_validate_too_many_metadata_rejected() {
        let mut node = ProvenanceNode::new(
            "n2".into(),
            ProvenanceEventType::ToolResponse,
            "src".into(),
            "hash".into(),
            "2025-01-01T00:00:00Z".into(),
        );
        for i in 0..=ProvenanceNode::MAX_METADATA_ENTRIES {
            node.metadata.insert(format!("key-{i}"), "val".into());
        }
        assert!(node.validate().unwrap_err().contains("metadata"));
    }

    #[test]
    fn test_provenance_node_validate_id_too_long_rejected() {
        let mut node = ProvenanceNode::new(
            "x".repeat(ProvenanceNode::MAX_ID_LEN + 1),
            ProvenanceEventType::ToolResponse,
            "src".into(),
            "hash".into(),
            "2025-01-01T00:00:00Z".into(),
        );
        assert!(node.validate().unwrap_err().contains("id length"));
        // source too long
        node.id = "ok".into();
        node.source = "s".repeat(ProvenanceNode::MAX_SOURCE_LEN + 1);
        assert!(node.validate().unwrap_err().contains("source length"));
    }

    // ── QuarantineEntry::validate() ─────────────────────────────────────

    #[test]
    fn test_quarantine_entry_validate_valid_ok() {
        let qe = QuarantineEntry::new(
            "e1".into(),
            QuarantineDetection::InjectionPattern,
            "2025-01-01T00:00:00Z".into(),
        );
        assert!(qe.validate().is_ok());
    }

    #[test]
    fn test_quarantine_entry_validate_entry_id_too_long_rejected() {
        let qe = QuarantineEntry::new(
            "x".repeat(257),
            QuarantineDetection::LowTrust,
            "2025-01-01T00:00:00Z".into(),
        );
        assert!(qe.validate().unwrap_err().contains("entry_id length"));
    }

    #[test]
    fn test_quarantine_entry_validate_description_too_long_rejected() {
        let mut qe = QuarantineEntry::new(
            "e2".into(),
            QuarantineDetection::ManualQuarantine,
            "2025-01-01T00:00:00Z".into(),
        );
        qe.description = Some("d".repeat(4097));
        assert!(qe.validate().unwrap_err().contains("description length"));
    }

    // ── MemoryNamespace::validate() + access control ────────────────────

    #[test]
    fn test_memory_namespace_validate_valid_ok() {
        let ns = MemoryNamespace::new(
            "ns-1".into(),
            "agent-a".into(),
            "2025-01-01T00:00:00Z".into(),
        );
        assert!(ns.validate().is_ok());
        assert!(ns.can_read("agent-a"));
        assert!(ns.can_write("agent-a"));
        assert!(!ns.can_read("agent-b"));
    }

    #[test]
    fn test_memory_namespace_validate_read_allowed_overflow_rejected() {
        let mut ns =
            MemoryNamespace::new("ns-2".into(), "owner".into(), "2025-01-01T00:00:00Z".into());
        ns.read_allowed = vec!["a".to_string(); MemoryNamespace::MAX_ACL_ENTRIES + 1];
        assert!(ns.validate().unwrap_err().contains("read_allowed"));
    }

    // ── NamespaceSharingRequest::validate() ──────────────────────────────

    #[test]
    fn test_namespace_sharing_request_validate_control_chars_rejected() {
        let req = NamespaceSharingRequest {
            namespace_id: "ns\x00id".to_string(),
            requester_agent: "agent".to_string(),
            access_type: NamespaceAccessType::Read,
            requested_at: "2025-01-01T00:00:00Z".to_string(),
            approved: None,
            resolved_at: None,
        };
        assert!(req.validate().unwrap_err().contains("invalid character"));
    }

    #[test]
    fn test_namespace_sharing_request_validate_requester_agent_too_long_rejected() {
        let req = NamespaceSharingRequest {
            namespace_id: "ns-ok".to_string(),
            requester_agent: "r".repeat(257),
            access_type: NamespaceAccessType::Write,
            requested_at: "2025-01-01T00:00:00Z".to_string(),
            approved: None,
            resolved_at: None,
        };
        assert!(req
            .validate()
            .unwrap_err()
            .contains("requester_agent length"));
    }
}
