// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Provenance and semantic-containment types shared across crates.

use crate::has_dangerous_chars;
use crate::minja::TaintLabel;
use serde::{Deserialize, Serialize};

const MAX_OPTIONAL_FIELD_LEN: usize = 256;
const MAX_SIGNATURE_LEN: usize = 4096;
const MAX_HASH_LEN: usize = 128;
const MAX_LINEAGE_REFS: usize = 64;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
#[serde(rename_all = "snake_case")]
pub enum SignatureVerificationStatus {
    #[default]
    Missing,
    Verified,
    Invalid,
    Expired,
    Error,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
#[serde(rename_all = "snake_case")]
pub enum WorkloadBindingStatus {
    #[default]
    Unknown,
    Bound,
    Missing,
    Mismatch,
    Unverified,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
#[serde(rename_all = "snake_case")]
pub enum SessionKeyScope {
    #[default]
    Unknown,
    EphemeralExecution,
    EphemeralSession,
    PersistedClient,
    PersistedService,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
#[serde(rename_all = "snake_case")]
pub enum ReplayStatus {
    #[default]
    NotChecked,
    Fresh,
    ReplayDetected,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
#[serde(rename_all = "snake_case")]
pub enum TrustTier {
    #[default]
    Unknown,
    Untrusted,
    Low,
    Medium,
    High,
    Verified,
    Quarantined,
}

impl TrustTier {
    /// Returns the total-order rank used for fail-closed flow checks.
    ///
    /// `Quarantined` and `Unknown` are intentionally ranked below
    /// `Untrusted` so that incomplete or explicitly contained provenance never
    /// qualifies for higher-trust flows without an explicit policy override.
    pub const fn rank(self) -> u8 {
        match self {
            Self::Quarantined => 0,
            Self::Unknown => 1,
            Self::Untrusted => 2,
            Self::Low => 3,
            Self::Medium => 4,
            Self::High => 5,
            Self::Verified => 6,
        }
    }

    /// Returns true when `self` is at least as trusted as `other`.
    pub const fn at_least_as_trusted_as(self, other: Self) -> bool {
        self.rank() >= other.rank()
    }

    /// Least upper bound in the trust lattice.
    pub const fn join(self, other: Self) -> Self {
        if self.rank() >= other.rank() {
            self
        } else {
            other
        }
    }

    /// Greatest lower bound in the trust lattice.
    pub const fn meet(self, other: Self) -> Self {
        if self.rank() <= other.rank() {
            self
        } else {
            other
        }
    }

    /// Returns true when data at `self` may flow to a target requiring
    /// `required_trust_tier`, or when explicit declassification is present.
    pub const fn can_flow_to(
        self,
        required_trust_tier: Self,
        explicitly_declassified: bool,
    ) -> bool {
        explicitly_declassified || self.at_least_as_trusted_as(required_trust_tier)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
#[serde(rename_all = "snake_case")]
pub enum SinkClass {
    #[default]
    ReadOnly,
    LowRiskWrite,
    FilesystemWrite,
    NetworkEgress,
    CodeExecution,
    MemoryWrite,
    ApprovalUi,
    CredentialAccess,
    PolicyMutation,
}

impl SinkClass {
    /// Returns the total-order rank from lowest to highest privilege.
    pub const fn rank(self) -> u8 {
        match self {
            Self::ReadOnly => 0,
            Self::LowRiskWrite => 1,
            Self::FilesystemWrite => 2,
            Self::NetworkEgress => 3,
            Self::MemoryWrite => 4,
            Self::ApprovalUi => 5,
            Self::CodeExecution => 6,
            Self::CredentialAccess => 7,
            Self::PolicyMutation => 8,
        }
    }

    /// Returns true when `self` is at least as privileged as `other`.
    pub const fn at_least_as_privileged_as(self, other: Self) -> bool {
        self.rank() >= other.rank()
    }

    /// Least upper bound in the sink-privilege lattice.
    pub const fn join(self, other: Self) -> Self {
        if self.rank() >= other.rank() {
            self
        } else {
            other
        }
    }

    /// Greatest lower bound in the sink-privilege lattice.
    pub const fn meet(self, other: Self) -> Self {
        if self.rank() <= other.rank() {
            self
        } else {
            other
        }
    }

    pub fn is_privileged(self) -> bool {
        matches!(
            self,
            Self::LowRiskWrite
                | Self::FilesystemWrite
                | Self::NetworkEgress
                | Self::CodeExecution
                | Self::MemoryWrite
                | Self::ApprovalUi
                | Self::CredentialAccess
                | Self::PolicyMutation
        )
    }

    /// Base semantic-risk contribution for this sink class.
    pub const fn semantic_risk_weight(self) -> u8 {
        match self {
            Self::ReadOnly => 5,
            Self::LowRiskWrite => 20,
            Self::FilesystemWrite => 30,
            Self::NetworkEgress => 35,
            Self::MemoryWrite => 45,
            Self::ApprovalUi => 50,
            Self::CodeExecution => 55,
            Self::CredentialAccess => 60,
            Self::PolicyMutation => 65,
        }
    }
}

/// Minimum trust floor required before content may reach the given sink
/// without an explicit containment gate.
pub const fn minimum_trust_tier_for_sink(sink_class: SinkClass) -> TrustTier {
    match sink_class {
        SinkClass::ReadOnly => TrustTier::Unknown,
        SinkClass::LowRiskWrite => TrustTier::Low,
        SinkClass::FilesystemWrite | SinkClass::NetworkEgress => TrustTier::Medium,
        SinkClass::MemoryWrite | SinkClass::ApprovalUi => TrustTier::High,
        SinkClass::CodeExecution | SinkClass::CredentialAccess | SinkClass::PolicyMutation => {
            TrustTier::Verified
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
#[serde(rename_all = "snake_case")]
pub enum ContextChannel {
    #[default]
    Data,
    FreeText,
    Url,
    CommandLike,
    ToolOutput,
    ResourceContent,
    ApprovalPrompt,
    Memory,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
#[serde(rename_all = "snake_case")]
pub enum ContainmentMode {
    #[default]
    Disabled,
    Observe,
    Enforce,
    Sanitize,
    Quarantine,
    RequireApproval,
}

pub type SemanticTaint = TaintLabel;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct RuntimeSecurityContext {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_provenance: Option<ClientProvenance>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub semantic_taint: Vec<SemanticTaint>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_trust_tier: Option<TrustTier>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sink_class: Option<SinkClass>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub lineage_refs: Vec<LineageRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub containment_mode: Option<ContainmentMode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub semantic_risk_score: Option<SemanticRiskScore>,
}

impl RuntimeSecurityContext {
    pub fn validate(&self) -> Result<(), String> {
        if let Some(ref provenance) = self.client_provenance {
            provenance.validate()?;
        }
        validate_lineage_refs(&self.lineage_refs)?;
        if let Some(ref risk_score) = self.semantic_risk_score {
            risk_score.validate()?;
        }
        Ok(())
    }

    /// Returns the lowest trust tier present in the effective context.
    pub fn most_restrictive_trust_tier(&self) -> Option<TrustTier> {
        let lineage_floor = self
            .lineage_refs
            .iter()
            .filter_map(|lineage| lineage.trust_tier)
            .reduce(TrustTier::meet);

        match (self.effective_trust_tier, lineage_floor) {
            (Some(explicit), Some(lineage)) => Some(explicit.meet(lineage)),
            (Some(explicit), None) => Some(explicit),
            (None, Some(lineage)) => Some(lineage),
            (None, None) => None,
        }
    }

    /// Returns true when the effective trust floor is below the minimum
    /// required for the target sink and therefore must be gated explicitly.
    pub fn requires_explicit_gate_for_sink(&self, sink_class: SinkClass) -> bool {
        let most_restrictive_trust_tier = self
            .most_restrictive_trust_tier()
            .unwrap_or(TrustTier::Unknown);
        !most_restrictive_trust_tier.can_flow_to(minimum_trust_tier_for_sink(sink_class), false)
    }

    /// Derives a bounded semantic-risk score for sending the current context
    /// into the target sink.
    pub fn recommended_semantic_risk_score_for_sink(
        &self,
        sink_class: SinkClass,
    ) -> SemanticRiskScore {
        let observed_trust_tier = self
            .most_restrictive_trust_tier()
            .unwrap_or(TrustTier::Unknown);
        let required_trust_tier = minimum_trust_tier_for_sink(sink_class);
        let trust_gap = required_trust_tier
            .rank()
            .saturating_sub(observed_trust_tier.rank())
            .saturating_mul(8);
        let taint_risk = self
            .semantic_taint
            .iter()
            .map(|taint| taint_semantic_risk_weight(*taint))
            .max()
            .unwrap_or(0);
        let lineage_channel_risk = self
            .lineage_refs
            .iter()
            .map(|lineage| lineage.channel.semantic_risk_weight())
            .max()
            .unwrap_or_else(|| if sink_class.is_privileged() { 15 } else { 0 });
        let score = sink_class
            .semantic_risk_weight()
            .saturating_add(trust_gap)
            .saturating_add(taint_risk)
            .saturating_add(lineage_channel_risk)
            .min(100);
        SemanticRiskScore { value: score }
    }

    /// Derives a bounded counterfactual-attribution score for privileged sinks.
    ///
    /// This is a lightweight proxy for "would this action still happen without
    /// the tainted upstream content?" and only rises when privileged actions
    /// are coupled to security-relevant taint and suspicious lineage channels.
    pub fn recommended_counterfactual_attribution_score_for_sink(
        &self,
        sink_class: SinkClass,
    ) -> SemanticRiskScore {
        if !sink_class.is_privileged() {
            return SemanticRiskScore { value: 0 };
        }

        let taint_risk = self
            .semantic_taint
            .iter()
            .copied()
            .filter(|taint| is_security_relevant_taint(*taint))
            .map(taint_semantic_risk_weight)
            .max()
            .unwrap_or(0);
        if taint_risk == 0 {
            return SemanticRiskScore { value: 0 };
        }

        let observed_trust_tier = self
            .most_restrictive_trust_tier()
            .unwrap_or(TrustTier::Unknown);
        let required_trust_tier = minimum_trust_tier_for_sink(sink_class);
        let trust_gap = required_trust_tier
            .rank()
            .saturating_sub(observed_trust_tier.rank())
            .saturating_mul(6);
        let lineage_signal = self
            .lineage_refs
            .iter()
            .map(|lineage| lineage.channel.counterfactual_attribution_weight())
            .max()
            .unwrap_or(0);
        let decision_driving_bonus = if self.lineage_refs.iter().any(|lineage| {
            matches!(
                lineage.channel,
                ContextChannel::CommandLike | ContextChannel::ApprovalPrompt
            )
        }) && self
            .semantic_taint
            .iter()
            .copied()
            .any(|taint| matches!(taint, TaintLabel::IntegrityFailed | TaintLabel::Quarantined))
        {
            20
        } else {
            0
        };

        SemanticRiskScore {
            value: trust_gap
                .saturating_add(taint_risk)
                .saturating_add(lineage_signal)
                .saturating_add(decision_driving_bonus)
                .min(100),
        }
    }

    /// Returns true when tainted upstream content appears likely to be
    /// decision-driving for the target privileged sink and therefore merits an
    /// explicit approval gate.
    pub fn requires_counterfactual_gate_for_sink(&self, sink_class: SinkClass) -> bool {
        sink_class.is_privileged()
            && self
                .recommended_counterfactual_attribution_score_for_sink(sink_class)
                .value
                >= 70
    }

    /// Keeps the higher of the existing semantic-risk score and `score`.
    pub fn merge_semantic_risk_score(&mut self, score: SemanticRiskScore) {
        match self.semantic_risk_score {
            Some(current) if current.value >= score.value => {}
            _ => self.semantic_risk_score = Some(score),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct RequestSignature {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

impl RequestSignature {
    pub fn validate(&self) -> Result<(), String> {
        validate_optional_field(&self.key_id, "request_signature.key_id")?;
        validate_optional_field(&self.algorithm, "request_signature.algorithm")?;
        validate_optional_field(&self.nonce, "request_signature.nonce")?;
        validate_optional_field(&self.created_at, "request_signature.created_at")?;
        if let Some(ref signature) = self.signature {
            if signature.len() > MAX_SIGNATURE_LEN {
                return Err("request_signature.signature exceeds maximum length".into());
            }
            if has_dangerous_chars(signature) {
                return Err("request_signature.signature contains dangerous characters".into());
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct WorkloadIdentity {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    pub workload_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_account: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_identity: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation_level: Option<String>,
}

impl WorkloadIdentity {
    pub fn validate(&self) -> Result<(), String> {
        if self.workload_id.is_empty() {
            return Err("workload_identity.workload_id must not be empty".into());
        }
        validate_bounded_field(
            &self.workload_id,
            "workload_identity.workload_id",
            MAX_OPTIONAL_FIELD_LEN,
        )?;
        validate_optional_field(&self.platform, "workload_identity.platform")?;
        validate_optional_field(&self.namespace, "workload_identity.namespace")?;
        validate_optional_field(&self.service_account, "workload_identity.service_account")?;
        validate_optional_field(&self.process_identity, "workload_identity.process_identity")?;
        validate_optional_field(
            &self.attestation_level,
            "workload_identity.attestation_level",
        )?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct ClientProvenance {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_signature: Option<RequestSignature>,
    #[serde(default)]
    pub signature_status: SignatureVerificationStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_key_id: Option<String>,
    #[serde(default)]
    pub session_key_scope: SessionKeyScope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload_identity: Option<WorkloadIdentity>,
    #[serde(default)]
    pub workload_binding_status: WorkloadBindingStatus,
    #[serde(default)]
    pub replay_status: ReplayStatus,
    /// Opaque session-scope binding generated by the transport runtime.
    ///
    /// This is intentionally distinct from any transport-facing session ID so
    /// persisted audit and approval scope never depend on the raw session
    /// identifier presented by a client or protocol peer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_scope_binding: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canonical_request_hash: Option<String>,
    #[serde(default)]
    pub execution_is_ephemeral: bool,
}

impl ClientProvenance {
    pub fn validate(&self) -> Result<(), String> {
        if let Some(ref sig) = self.request_signature {
            sig.validate()?;
        }
        validate_optional_field(&self.client_key_id, "client_provenance.client_key_id")?;
        if let Some(ref workload) = self.workload_identity {
            workload.validate()?;
        }
        validate_optional_field(
            &self.session_scope_binding,
            "client_provenance.session_scope_binding",
        )?;
        if let Some(ref hash) = self.canonical_request_hash {
            validate_bounded_field(
                hash,
                "client_provenance.canonical_request_hash",
                MAX_HASH_LEN,
            )?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LineageRef {
    pub id: String,
    pub channel: ContextChannel,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_tier: Option<TrustTier>,
}

impl LineageRef {
    pub fn validate(&self) -> Result<(), String> {
        if self.id.is_empty() {
            return Err("lineage_ref.id must not be empty".into());
        }
        validate_bounded_field(&self.id, "lineage_ref.id", MAX_OPTIONAL_FIELD_LEN)?;
        if let Some(ref hash) = self.content_hash {
            validate_bounded_field(hash, "lineage_ref.content_hash", MAX_HASH_LEN)?;
        }
        validate_optional_field(&self.source, "lineage_ref.source")?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
#[serde(deny_unknown_fields)]
pub struct SemanticRiskScore {
    pub value: u8,
}

impl SemanticRiskScore {
    pub fn new(value: u8) -> Result<Self, String> {
        if value > 100 {
            return Err("semantic_risk_score must be <= 100".into());
        }
        Ok(Self { value })
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.value > 100 {
            return Err("semantic_risk_score must be <= 100".into());
        }
        Ok(())
    }
}

impl ContextChannel {
    /// Channel-level semantic-risk contribution used for containment scoring.
    pub const fn semantic_risk_weight(self) -> u8 {
        match self {
            Self::Data => 0,
            Self::ToolOutput => 10,
            Self::ResourceContent => 15,
            Self::FreeText => 20,
            Self::Memory => 20,
            Self::Url => 25,
            Self::CommandLike => 35,
            Self::ApprovalPrompt => 35,
        }
    }

    /// Channel-level contribution for lightweight counterfactual attribution.
    pub const fn counterfactual_attribution_weight(self) -> u8 {
        match self {
            Self::Data => 0,
            Self::ToolOutput => 10,
            Self::ResourceContent => 10,
            Self::FreeText => 15,
            Self::Memory => 15,
            Self::Url => 20,
            Self::CommandLike => 35,
            Self::ApprovalPrompt => 35,
        }
    }

    /// Detect privilege-escalating semantic drift between an expected and observed channel.
    pub const fn violates_output_contract(self, observed: Self) -> bool {
        match self {
            Self::Data => matches!(
                observed,
                Self::FreeText | Self::Url | Self::CommandLike | Self::ApprovalPrompt
            ),
            Self::FreeText | Self::ToolOutput => matches!(
                observed,
                Self::Url | Self::CommandLike | Self::ApprovalPrompt
            ),
            Self::ResourceContent | Self::Url => {
                matches!(observed, Self::CommandLike | Self::ApprovalPrompt)
            }
            _ => false,
        }
    }
}

pub fn is_security_relevant_taint(taint: SemanticTaint) -> bool {
    matches!(
        taint,
        TaintLabel::Untrusted
            | TaintLabel::Quarantined
            | TaintLabel::CrossAgent
            | TaintLabel::Replayed
            | TaintLabel::MixedProvenance
            | TaintLabel::IntegrityFailed
    )
}

pub const fn taint_semantic_risk_weight(taint: SemanticTaint) -> u8 {
    match taint {
        TaintLabel::Sanitized => 0,
        TaintLabel::Sensitive => 10,
        TaintLabel::Untrusted => 15,
        TaintLabel::CrossAgent => 15,
        TaintLabel::MixedProvenance => 20,
        TaintLabel::Replayed => 20,
        TaintLabel::IntegrityFailed => 25,
        TaintLabel::Quarantined => 30,
    }
}

pub fn validate_lineage_refs(lineage_refs: &[LineageRef]) -> Result<(), String> {
    if lineage_refs.len() > MAX_LINEAGE_REFS {
        return Err("lineage_refs exceeds maximum count".into());
    }
    for lineage_ref in lineage_refs {
        lineage_ref.validate()?;
    }
    Ok(())
}

fn validate_optional_field(value: &Option<String>, field: &str) -> Result<(), String> {
    if let Some(ref value) = *value {
        validate_bounded_field(value, field, MAX_OPTIONAL_FIELD_LEN)?;
    }
    Ok(())
}

fn validate_bounded_field(value: &str, field: &str, max_len: usize) -> Result<(), String> {
    if value.len() > max_len {
        return Err(format!("{field} exceeds maximum length"));
    }
    if has_dangerous_chars(value) {
        return Err(format!("{field} contains dangerous characters"));
    }
    Ok(())
}

/// Phase 1: Compact signed token for cross-transport security context propagation.
///
/// When a request crosses transport boundaries (e.g., stdio proxy → HTTP backend),
/// the originating proxy can attach this token via `_meta.security_context_token`.
/// The receiving transport verifies the HMAC before ingesting the context,
/// preventing untrusted callers from injecting fake trust tiers or taint labels.
///
/// The token carries a summary of the session's security state — not the full
/// `RuntimeSecurityContext`, which is too large and contains internal fields.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SecurityContextToken {
    /// Opaque session scope binding from the originating transport.
    pub session_scope_binding: String,
    /// Effective trust tier at the time of token issuance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_trust_tier: Option<TrustTier>,
    /// Accumulated taint label names from the session.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub taint_labels: Vec<String>,
    /// Number of distinct tool sources in the session lineage.
    #[serde(default)]
    pub lineage_source_count: usize,
    /// Unix epoch seconds when the token was issued.
    pub issued_at_epoch_secs: u64,
    /// HMAC-SHA256 over the token fields using a shared secret.
    /// The receiving transport verifies this before ingesting.
    pub hmac_sha256: String,
}

/// Maximum taint labels in a security context token.
const MAX_TOKEN_TAINT_LABELS: usize = 64;

impl SecurityContextToken {
    /// Validate token field bounds and content.
    pub fn validate(&self) -> Result<(), String> {
        if self.session_scope_binding.is_empty() {
            return Err("security_context_token.session_scope_binding is empty".to_string());
        }
        if self.session_scope_binding.len() > 512 {
            return Err(format!(
                "security_context_token.session_scope_binding length {} exceeds max 512",
                self.session_scope_binding.len()
            ));
        }
        if has_dangerous_chars(&self.session_scope_binding) {
            return Err(
                "security_context_token.session_scope_binding contains dangerous characters"
                    .to_string(),
            );
        }
        if self.taint_labels.len() > MAX_TOKEN_TAINT_LABELS {
            return Err(format!(
                "security_context_token.taint_labels exceeds {MAX_TOKEN_TAINT_LABELS} entries"
            ));
        }
        for (i, label) in self.taint_labels.iter().enumerate() {
            if label.len() > 128 || has_dangerous_chars(label) {
                return Err(format!(
                    "security_context_token.taint_labels[{i}] invalid"
                ));
            }
        }
        if self.hmac_sha256.is_empty() {
            return Err("security_context_token.hmac_sha256 is empty".to_string());
        }
        if self.hmac_sha256.len() > 128 {
            return Err("security_context_token.hmac_sha256 too long".to_string());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_semantic_risk_score_bounds() {
        assert!(SemanticRiskScore::new(0).is_ok());
        assert!(SemanticRiskScore::new(100).is_ok());
    }

    #[test]
    fn test_workload_identity_requires_id() {
        let workload = WorkloadIdentity::default();
        let err = workload.validate().unwrap_err();
        assert!(err.contains("workload_id must not be empty"));
    }

    #[test]
    fn test_lineage_ref_requires_id() {
        let lineage = LineageRef {
            id: String::new(),
            channel: ContextChannel::FreeText,
            content_hash: None,
            source: None,
            trust_tier: None,
        };
        let err = lineage.validate().unwrap_err();
        assert!(err.contains("lineage_ref.id must not be empty"));
    }

    #[test]
    fn test_security_relevant_taint_subset() {
        assert!(is_security_relevant_taint(TaintLabel::Untrusted));
        assert!(!is_security_relevant_taint(TaintLabel::Sanitized));
    }

    #[test]
    fn test_trust_tier_ordering_is_fail_closed() {
        assert!(TrustTier::Verified.at_least_as_trusted_as(TrustTier::High));
        assert!(TrustTier::High.at_least_as_trusted_as(TrustTier::Low));
        assert!(TrustTier::Untrusted.at_least_as_trusted_as(TrustTier::Unknown));
        assert!(!TrustTier::Unknown.at_least_as_trusted_as(TrustTier::Untrusted));
        assert!(!TrustTier::Unknown.at_least_as_trusted_as(TrustTier::Low));
        assert!(!TrustTier::Quarantined.at_least_as_trusted_as(TrustTier::Unknown));
    }

    #[test]
    fn test_trust_tier_join_and_meet() {
        assert_eq!(TrustTier::Low.join(TrustTier::High), TrustTier::High);
        assert_eq!(
            TrustTier::Verified.join(TrustTier::Medium),
            TrustTier::Verified
        );
        assert_eq!(TrustTier::Low.meet(TrustTier::High), TrustTier::Low);
        assert_eq!(
            TrustTier::Quarantined.meet(TrustTier::Verified),
            TrustTier::Quarantined
        );
    }

    #[test]
    fn test_sink_class_join_and_meet() {
        assert!(SinkClass::PolicyMutation.at_least_as_privileged_as(SinkClass::ApprovalUi));
        assert!(SinkClass::NetworkEgress.at_least_as_privileged_as(SinkClass::ReadOnly));
        assert_eq!(
            SinkClass::ReadOnly.join(SinkClass::CredentialAccess),
            SinkClass::CredentialAccess
        );
        assert_eq!(
            SinkClass::CodeExecution.meet(SinkClass::PolicyMutation),
            SinkClass::CodeExecution
        );
    }

    #[test]
    fn test_trust_tier_flow_requires_declassification_for_lower_trust_sources() {
        assert!(TrustTier::High.can_flow_to(TrustTier::Medium, false));
        assert!(!TrustTier::Low.can_flow_to(TrustTier::High, false));
        assert!(TrustTier::Low.can_flow_to(TrustTier::High, true));
        assert!(!TrustTier::Unknown.can_flow_to(TrustTier::Low, false));
    }

    #[test]
    fn test_minimum_trust_tier_for_sink_is_monotonic() {
        assert!(minimum_trust_tier_for_sink(SinkClass::PolicyMutation)
            .at_least_as_trusted_as(minimum_trust_tier_for_sink(SinkClass::CredentialAccess)));
        assert!(minimum_trust_tier_for_sink(SinkClass::CredentialAccess)
            .at_least_as_trusted_as(minimum_trust_tier_for_sink(SinkClass::CodeExecution)));
        assert!(minimum_trust_tier_for_sink(SinkClass::CodeExecution)
            .at_least_as_trusted_as(minimum_trust_tier_for_sink(SinkClass::ApprovalUi)));
        assert!(minimum_trust_tier_for_sink(SinkClass::ApprovalUi)
            .at_least_as_trusted_as(minimum_trust_tier_for_sink(SinkClass::NetworkEgress)));
        assert!(minimum_trust_tier_for_sink(SinkClass::NetworkEgress)
            .at_least_as_trusted_as(minimum_trust_tier_for_sink(SinkClass::LowRiskWrite)));
    }

    #[test]
    fn test_runtime_security_context_uses_most_restrictive_trust_tier() {
        let ctx = RuntimeSecurityContext {
            effective_trust_tier: Some(TrustTier::High),
            lineage_refs: vec![
                LineageRef {
                    id: "trusted".into(),
                    channel: ContextChannel::Data,
                    content_hash: None,
                    source: None,
                    trust_tier: Some(TrustTier::Verified),
                },
                LineageRef {
                    id: "mixed".into(),
                    channel: ContextChannel::ToolOutput,
                    content_hash: None,
                    source: None,
                    trust_tier: Some(TrustTier::Low),
                },
            ],
            ..RuntimeSecurityContext::default()
        };

        assert_eq!(ctx.most_restrictive_trust_tier(), Some(TrustTier::Low));
    }

    #[test]
    fn test_runtime_security_context_requires_explicit_gate_for_low_trust_privileged_sink() {
        let ctx = RuntimeSecurityContext {
            effective_trust_tier: Some(TrustTier::Low),
            lineage_refs: vec![LineageRef {
                id: "upstream-low".into(),
                channel: ContextChannel::ToolOutput,
                content_hash: None,
                source: Some("low-tier-server".into()),
                trust_tier: Some(TrustTier::Low),
            }],
            ..RuntimeSecurityContext::default()
        };

        assert!(ctx.requires_explicit_gate_for_sink(SinkClass::CredentialAccess));
        assert!(!ctx.requires_explicit_gate_for_sink(SinkClass::LowRiskWrite));
    }

    #[test]
    fn test_runtime_security_context_allows_verified_privileged_sink_without_gate() {
        let ctx = RuntimeSecurityContext {
            effective_trust_tier: Some(TrustTier::Verified),
            lineage_refs: vec![LineageRef {
                id: "upstream-verified".into(),
                channel: ContextChannel::ToolOutput,
                content_hash: None,
                source: Some("verified-server".into()),
                trust_tier: Some(TrustTier::Verified),
            }],
            ..RuntimeSecurityContext::default()
        };

        assert!(!ctx.requires_explicit_gate_for_sink(SinkClass::CodeExecution));
    }

    #[test]
    fn test_context_channel_semantic_risk_weights_are_ordered() {
        assert!(
            ContextChannel::CommandLike.semantic_risk_weight()
                > ContextChannel::Url.semantic_risk_weight()
        );
        assert!(
            ContextChannel::ApprovalPrompt.semantic_risk_weight()
                >= ContextChannel::FreeText.semantic_risk_weight()
        );
        assert!(
            ContextChannel::ToolOutput.semantic_risk_weight()
                > ContextChannel::Data.semantic_risk_weight()
        );
    }

    #[test]
    fn test_output_contract_data_blocks_privilege_escalating_drift() {
        assert!(ContextChannel::Data.violates_output_contract(ContextChannel::FreeText));
        assert!(ContextChannel::Data.violates_output_contract(ContextChannel::Url));
        assert!(ContextChannel::Data.violates_output_contract(ContextChannel::CommandLike));
        assert!(ContextChannel::Data.violates_output_contract(ContextChannel::ApprovalPrompt));
        assert!(!ContextChannel::Data.violates_output_contract(ContextChannel::Data));
        assert!(!ContextChannel::Data.violates_output_contract(ContextChannel::ToolOutput));
    }

    #[test]
    fn test_output_contract_free_text_and_tool_output_matrix() {
        for expected in [ContextChannel::FreeText, ContextChannel::ToolOutput] {
            assert!(expected.violates_output_contract(ContextChannel::Url));
            assert!(expected.violates_output_contract(ContextChannel::CommandLike));
            assert!(expected.violates_output_contract(ContextChannel::ApprovalPrompt));
            assert!(!expected.violates_output_contract(ContextChannel::FreeText));
            assert!(!expected.violates_output_contract(ContextChannel::ToolOutput));
            assert!(!expected.violates_output_contract(ContextChannel::Data));
        }
    }

    #[test]
    fn test_output_contract_resource_and_url_only_block_high_risk_drift() {
        for expected in [ContextChannel::ResourceContent, ContextChannel::Url] {
            assert!(expected.violates_output_contract(ContextChannel::CommandLike));
            assert!(expected.violates_output_contract(ContextChannel::ApprovalPrompt));
            assert!(!expected.violates_output_contract(ContextChannel::ResourceContent));
            assert!(!expected.violates_output_contract(ContextChannel::Url));
            assert!(!expected.violates_output_contract(ContextChannel::FreeText));
            assert!(!expected.violates_output_contract(ContextChannel::Data));
        }
    }

    #[test]
    fn test_recommended_semantic_risk_score_increases_with_trust_gap() {
        let verified = RuntimeSecurityContext {
            effective_trust_tier: Some(TrustTier::Verified),
            lineage_refs: vec![LineageRef {
                id: "trusted".into(),
                channel: ContextChannel::ToolOutput,
                content_hash: None,
                source: Some("verified-server".into()),
                trust_tier: Some(TrustTier::Verified),
            }],
            ..RuntimeSecurityContext::default()
        };
        let low_trust = RuntimeSecurityContext {
            effective_trust_tier: Some(TrustTier::Low),
            lineage_refs: vec![LineageRef {
                id: "low".into(),
                channel: ContextChannel::ToolOutput,
                content_hash: None,
                source: Some("low-tier-server".into()),
                trust_tier: Some(TrustTier::Low),
            }],
            ..RuntimeSecurityContext::default()
        };

        let verified_score =
            verified.recommended_semantic_risk_score_for_sink(SinkClass::CredentialAccess);
        let low_trust_score =
            low_trust.recommended_semantic_risk_score_for_sink(SinkClass::CredentialAccess);

        assert!(low_trust_score.value > verified_score.value);
    }

    #[test]
    fn test_recommended_semantic_risk_score_increases_with_taint_and_command_like_lineage() {
        let baseline = RuntimeSecurityContext {
            effective_trust_tier: Some(TrustTier::Verified),
            lineage_refs: vec![LineageRef {
                id: "baseline".into(),
                channel: ContextChannel::Data,
                content_hash: None,
                source: Some("verified-server".into()),
                trust_tier: Some(TrustTier::Verified),
            }],
            ..RuntimeSecurityContext::default()
        };
        let suspicious = RuntimeSecurityContext {
            effective_trust_tier: Some(TrustTier::Verified),
            semantic_taint: vec![TaintLabel::IntegrityFailed],
            lineage_refs: vec![LineageRef {
                id: "command-like".into(),
                channel: ContextChannel::CommandLike,
                content_hash: None,
                source: Some("remote-free-text".into()),
                trust_tier: Some(TrustTier::Verified),
            }],
            ..RuntimeSecurityContext::default()
        };

        let baseline_score =
            baseline.recommended_semantic_risk_score_for_sink(SinkClass::CodeExecution);
        let suspicious_score =
            suspicious.recommended_semantic_risk_score_for_sink(SinkClass::CodeExecution);

        assert!(suspicious_score.value > baseline_score.value);
    }

    #[test]
    fn test_counterfactual_attribution_score_stays_low_for_incidental_tainted_tool_output() {
        let incidental = RuntimeSecurityContext {
            effective_trust_tier: Some(TrustTier::Verified),
            semantic_taint: vec![TaintLabel::Untrusted],
            lineage_refs: vec![LineageRef {
                id: "tool-output".into(),
                channel: ContextChannel::ToolOutput,
                content_hash: None,
                source: Some("search-web".into()),
                trust_tier: Some(TrustTier::Verified),
            }],
            ..RuntimeSecurityContext::default()
        };

        let score = incidental
            .recommended_counterfactual_attribution_score_for_sink(SinkClass::CodeExecution);

        assert!(score.value < 70);
        assert!(!incidental.requires_counterfactual_gate_for_sink(SinkClass::CodeExecution));
    }

    #[test]
    fn test_counterfactual_attribution_score_rises_for_quarantined_command_like_flow() {
        let suspicious = RuntimeSecurityContext {
            effective_trust_tier: Some(TrustTier::Low),
            semantic_taint: vec![TaintLabel::IntegrityFailed, TaintLabel::Quarantined],
            lineage_refs: vec![LineageRef {
                id: "command-like".into(),
                channel: ContextChannel::CommandLike,
                content_hash: None,
                source: Some("remote-output".into()),
                trust_tier: Some(TrustTier::Quarantined),
            }],
            ..RuntimeSecurityContext::default()
        };

        let score = suspicious
            .recommended_counterfactual_attribution_score_for_sink(SinkClass::CredentialAccess);

        assert!(score.value >= 70);
        assert!(suspicious.requires_counterfactual_gate_for_sink(SinkClass::CredentialAccess));
    }

    #[test]
    fn test_merge_semantic_risk_score_keeps_higher_value() {
        let mut ctx = RuntimeSecurityContext {
            semantic_risk_score: Some(SemanticRiskScore { value: 40 }),
            ..RuntimeSecurityContext::default()
        };

        ctx.merge_semantic_risk_score(SemanticRiskScore { value: 30 });
        assert_eq!(
            ctx.semantic_risk_score,
            Some(SemanticRiskScore { value: 40 })
        );

        ctx.merge_semantic_risk_score(SemanticRiskScore { value: 70 });
        assert_eq!(
            ctx.semantic_risk_score,
            Some(SemanticRiskScore { value: 70 })
        );
    }

    // ═══════════════════════════════════════════════════
    // Phase 1: SecurityContextToken tests
    // ═══════════════════════════════════════════════════

    #[test]
    fn test_security_context_token_validate_ok() {
        let token = SecurityContextToken {
            session_scope_binding: "scope-abc".to_string(),
            effective_trust_tier: Some(TrustTier::Medium),
            taint_labels: vec!["untrusted".to_string()],
            lineage_source_count: 3,
            issued_at_epoch_secs: 1710547200,
            hmac_sha256: "abcdef0123456789".to_string(),
        };
        assert!(token.validate().is_ok());
    }

    #[test]
    fn test_security_context_token_validate_empty_scope_rejected() {
        let token = SecurityContextToken {
            session_scope_binding: String::new(),
            effective_trust_tier: None,
            taint_labels: Vec::new(),
            lineage_source_count: 0,
            issued_at_epoch_secs: 0,
            hmac_sha256: "abc".to_string(),
        };
        assert!(token.validate().is_err());
    }

    #[test]
    fn test_security_context_token_validate_too_many_taints_rejected() {
        let token = SecurityContextToken {
            session_scope_binding: "scope".to_string(),
            effective_trust_tier: None,
            taint_labels: (0..65).map(|i| format!("taint_{i}")).collect(),
            lineage_source_count: 0,
            issued_at_epoch_secs: 0,
            hmac_sha256: "abc".to_string(),
        };
        assert!(token.validate().is_err());
    }

    #[test]
    fn test_security_context_token_validate_dangerous_chars_rejected() {
        let token = SecurityContextToken {
            session_scope_binding: "scope\x00bad".to_string(),
            effective_trust_tier: None,
            taint_labels: Vec::new(),
            lineage_source_count: 0,
            issued_at_epoch_secs: 0,
            hmac_sha256: "abc".to_string(),
        };
        assert!(token.validate().is_err());
    }
}
