// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Agent-Consumer Interaction Surface (ACIS) decision envelope.
//!
//! Every side-effecting runtime decision — policy evaluation, approval gate,
//! DLP finding, injection block — emits one [`AcisDecisionEnvelope`].  This is
//! the normalized contract shared by every enforcement path (stdio, HTTP,
//! WebSocket, gRPC, shield) and consumed by audit, metrics, and external
//! integrations.
//!
//! # Design constraints
//!
//! - **Fail-closed defaults:** [`DecisionKind::Deny`] is the default.
//! - **No secrets in fingerprints:** `action_fingerprint` hashes tool, function,
//!   and targets — never parameters.
//! - **Transport-agnostic:** Serializable via JSON across all surfaces.
//! - **Bounded fields:** All strings and collections are length-validated.

use serde::{Deserialize, Serialize};

use crate::core::Verdict;
use crate::has_dangerous_chars;
use crate::identity::AgentIdentity;
use crate::provenance::{
    validate_lineage_refs, ClientProvenance, ContainmentMode, LineageRef, SemanticRiskScore,
    SemanticTaint, SinkClass, TrustTier,
};

// ── Constants ────────────────────────────────────────────────────────────────

/// Maximum length of `decision_id` (UUID = 36 chars, but allow up to 64 for
/// future extensibility).
const MAX_DECISION_ID_LEN: usize = 64;

/// Maximum length of `session_id`.
const MAX_SESSION_ID_LEN: usize = 512;

/// Maximum length of `action_fingerprint` (SHA-256 hex = 64 chars).
const MAX_FINGERPRINT_LEN: usize = 128;

/// Maximum length of `matched_policy_id`.
const MAX_POLICY_ID_LEN: usize = 256;

/// Maximum length of `reason` string.
const MAX_REASON_LEN: usize = 4096;

/// Maximum length of `tenant_id`.
const MAX_TENANT_ID_LEN: usize = 256;

/// Maximum length of `transport` label.
const MAX_TRANSPORT_LEN: usize = 32;

/// Maximum length of `agent_id` (R244-ACIS-4).
const MAX_AGENT_ID_LEN: usize = 512;

/// Maximum length of `action_summary.tool` (R244-ACIS-3).
const MAX_TOOL_LEN: usize = 256;

/// Maximum length of `action_summary.function` (R244-ACIS-3).
const MAX_FUNCTION_LEN: usize = 256;

/// Maximum number of finding summaries per envelope.
const MAX_FINDINGS: usize = 64;

/// Maximum length of a single finding summary string.
const MAX_FINDING_LEN: usize = 512;

/// Maximum number of semantic taint labels per envelope.
const MAX_SEMANTIC_TAINT: usize = 32;

/// Maximum evaluation latency in microseconds (1 hour = 3,600,000,000 µs).
/// Any value beyond this indicates a measurement error or crafted input.
const MAX_EVALUATION_US: u64 = 3_600_000_000;

/// Maximum call chain depth (matches existing chain depth limits).
const MAX_CALL_CHAIN_DEPTH: u32 = 256;

/// Maximum allowed target path/domain count per action summary (R246-ACIS-1).
const MAX_TARGET_COUNT: u32 = 100_000;

// ── Core types ───────────────────────────────────────────────────────────────

/// The normalized decision kind — a simplified projection of [`Verdict`] for
/// indexing, filtering, and metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionKind {
    /// Action was permitted.
    Allow,
    /// Action was blocked.
    Deny,
    /// Action requires human/approval-flow consent before proceeding.
    RequireApproval,
}

impl Default for DecisionKind {
    /// Fail-closed: default is Deny.
    fn default() -> Self {
        Self::Deny
    }
}

impl From<&Verdict> for DecisionKind {
    fn from(v: &Verdict) -> Self {
        match v {
            Verdict::Allow => Self::Allow,
            Verdict::Deny { .. } => Self::Deny,
            Verdict::RequireApproval { .. } => Self::RequireApproval,
        }
    }
}

/// The origin of the decision — which enforcement layer produced it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionOrigin {
    /// Policy engine evaluation.
    PolicyEngine,
    /// DLP parameter or response scanning.
    Dlp,
    /// Injection detection (prompt injection, tool squatting, etc.).
    InjectionScanner,
    /// Memory poisoning detection (MINJA).
    MemoryPoisoning,
    /// Approval gate (RequireApproval verdict or approval timeout).
    ApprovalGate,
    /// Capability token enforcement.
    CapabilityEnforcement,
    /// Rate limiter enforcement.
    RateLimiter,
    /// Circuit breaker enforcement (tool failure threshold exceeded).
    CircuitBreaker,
    /// TopologyGuard (unknown tool denial).
    TopologyGuard,
    /// Session guard state violation.
    SessionGuard,
    /// Provenance verification or replay/binding enforcement.
    ProvenanceGuard,
    /// Semantic containment prevented the request from reaching a sink.
    SemanticContainment,
}

/// Summary of the action that triggered the decision.
///
/// Deliberately excludes `parameters` (may contain secrets) and full target
/// lists (may be large).  The `action_fingerprint` is the canonical identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcisActionSummary {
    /// Tool name (e.g. `"file_write"`).
    pub tool: String,
    /// Function name (e.g. `"write"`).
    pub function: String,
    /// Number of target paths.
    pub target_path_count: u32,
    /// Number of target domains.
    pub target_domain_count: u32,
}

impl AcisActionSummary {
    /// Validate all fields for length, content, and structural invariants.
    pub fn validate(&self) -> Result<(), String> {
        if self.tool.is_empty() {
            return Err("action_summary.tool must not be empty".into());
        }
        if self.tool.len() > MAX_TOOL_LEN {
            return Err("action_summary.tool exceeds maximum length".into());
        }
        if has_dangerous_chars(&self.tool) {
            return Err("action_summary.tool contains dangerous characters".into());
        }
        if self.function.is_empty() {
            return Err("action_summary.function must not be empty".into());
        }
        if self.function.len() > MAX_FUNCTION_LEN {
            return Err("action_summary.function exceeds maximum length".into());
        }
        if has_dangerous_chars(&self.function) {
            return Err("action_summary.function contains dangerous characters".into());
        }
        // R246-ACIS-1: Bound target counts to prevent metrics overflow.
        if self.target_path_count > MAX_TARGET_COUNT {
            return Err("action_summary.target_path_count exceeds maximum".into());
        }
        if self.target_domain_count > MAX_TARGET_COUNT {
            return Err("action_summary.target_domain_count exceeds maximum".into());
        }
        Ok(())
    }
}

/// The ACIS decision envelope — one per runtime decision.
///
/// Emitted by every enforcement path and consumed by audit logging, metrics,
/// external webhooks, and the admin console.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcisDecisionEnvelope {
    // ── Identity ─────────────────────────────────────────────────────────
    /// Unique decision identifier (UUID v4 hex string).
    pub decision_id: String,

    /// ISO 8601 timestamp of the decision (must end with `Z` or `+00:00`).
    pub timestamp: String,

    // ── Session & principal ──────────────────────────────────────────────
    /// Session identifier (from `Mcp-Session-Id` header or stateless blob).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,

    /// Tenant identifier for multi-tenant deployments.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,

    /// Cryptographically attested agent identity (from JWT).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_identity: Option<AgentIdentity>,

    /// Legacy agent identifier (when full `AgentIdentity` is unavailable).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    /// Provenance evidence collected for the request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_provenance: Option<ClientProvenance>,

    // ── Action ───────────────────────────────────────────────────────────
    /// Summary of the action (tool, function, target counts).
    pub action_summary: AcisActionSummary,

    /// SHA-256 hex of `tool || function || sorted(target_paths) ||
    /// sorted(target_domains)`.  Never includes parameters.
    pub action_fingerprint: String,

    // ── Decision ─────────────────────────────────────────────────────────
    /// Simplified decision kind for indexing and metrics.
    pub decision: DecisionKind,

    /// Which enforcement layer produced this decision.
    pub origin: DecisionOrigin,

    /// Human-readable reason (from Deny/RequireApproval verdict, or scanner
    /// finding summary).  Empty for Allow.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reason: String,

    /// Policy ID that matched (if decision originated from policy engine).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched_policy_id: Option<String>,

    // ── Transport ────────────────────────────────────────────────────────
    /// Transport surface that intercepted the action (`"stdio"`, `"http"`,
    /// `"websocket"`, `"grpc"`, `"sse"`).
    pub transport: String,

    // ── Security findings ────────────────────────────────────────────────
    /// Brief finding summaries (e.g. `"DLP: API key detected"`,
    /// `"injection: prompt override pattern"`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub findings: Vec<String>,
    /// Semantic taint labels that contributed to the decision.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub semantic_taint: Vec<SemanticTaint>,
    /// Lineage references that explain upstream semantic sources.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub lineage_refs: Vec<LineageRef>,
    /// Effective trust tier assigned to the context.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_trust_tier: Option<TrustTier>,
    /// Sink class the request attempted to drive.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sink_class: Option<SinkClass>,
    /// Containment mode in force when the decision was made.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub containment_mode: Option<ContainmentMode>,
    /// Bounded semantic risk score for the effective context.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub semantic_risk_score: Option<SemanticRiskScore>,

    // ── Timing ───────────────────────────────────────────────────────────
    /// Wall-clock evaluation latency in microseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evaluation_us: Option<u64>,

    // ── Depth ────────────────────────────────────────────────────────────
    /// Number of entries in the current call chain (multi-agent depth).
    #[serde(default)]
    pub call_chain_depth: u32,
}

// ── Validation ───────────────────────────────────────────────────────────────

impl AcisDecisionEnvelope {
    /// Validate all fields for length, content, and structural invariants.
    pub fn validate(&self) -> Result<(), String> {
        // decision_id
        if self.decision_id.is_empty() {
            return Err("acis: decision_id must not be empty".into());
        }
        if self.decision_id.len() > MAX_DECISION_ID_LEN {
            return Err("acis: decision_id exceeds maximum length".into());
        }
        if has_dangerous_chars(&self.decision_id) {
            return Err("acis: decision_id contains dangerous characters".into());
        }

        // timestamp
        if self.timestamp.is_empty() {
            return Err("acis: timestamp must not be empty".into());
        }
        if !self.timestamp.ends_with('Z')
            && !self.timestamp.ends_with('z')
            && !self.timestamp.ends_with("+00:00")
        {
            return Err("acis: timestamp must be UTC (end with Z or +00:00)".into());
        }

        // session_id
        if let Some(ref sid) = self.session_id {
            if sid.len() > MAX_SESSION_ID_LEN {
                return Err("acis: session_id exceeds maximum length".into());
            }
            if has_dangerous_chars(sid) {
                return Err("acis: session_id contains dangerous characters".into());
            }
        }

        // tenant_id
        if let Some(ref tid) = self.tenant_id {
            if tid.len() > MAX_TENANT_ID_LEN {
                return Err("acis: tenant_id exceeds maximum length".into());
            }
            if has_dangerous_chars(tid) {
                return Err("acis: tenant_id contains dangerous characters".into());
            }
        }

        // agent_id (R244-ACIS-4)
        if let Some(ref aid) = self.agent_id {
            if aid.is_empty() {
                return Err("acis: agent_id must not be empty when present".into());
            }
            if aid.len() > MAX_AGENT_ID_LEN {
                return Err("acis: agent_id exceeds maximum length".into());
            }
            if has_dangerous_chars(aid) {
                return Err("acis: agent_id contains dangerous characters".into());
            }
        }

        // agent_identity (R244-ACIS-5): delegate to nested validate()
        if let Some(ref identity) = self.agent_identity {
            if let Err(e) = identity.validate() {
                return Err(format!("acis: agent_identity validation failed: {e}"));
            }
        }
        if let Some(ref provenance) = self.client_provenance {
            provenance
                .validate()
                .map_err(|e| format!("acis: client_provenance validation failed: {e}"))?;
        }

        // action_fingerprint
        if self.action_fingerprint.is_empty() {
            return Err("acis: action_fingerprint must not be empty".into());
        }
        if self.action_fingerprint.len() > MAX_FINGERPRINT_LEN {
            return Err("acis: action_fingerprint exceeds maximum length".into());
        }

        // action_summary (R244-ACIS-3/8, R246-ACIS-1): delegate to standalone validate
        self.action_summary
            .validate()
            .map_err(|e| format!("acis: {e}"))?;

        // ACIS-DENY-REASON-1: a Deny must say why. The Verus kernel
        // (`lemma_acis_deny_has_nonempty_reason`) proves this as a structural
        // invariant of the envelope, and `validate()` did not enforce it — the
        // gap was found by the differential binding below. A denial recorded
        // without a reason is an audit entry that cannot be acted on.
        if matches!(self.decision, DecisionKind::Deny) && self.reason.is_empty() {
            return Err("acis: Deny decision must carry a non-empty reason".into());
        }

        // reason (R244-ACIS-2: add dangerous chars check)
        if self.reason.len() > MAX_REASON_LEN {
            return Err("acis: reason exceeds maximum length".into());
        }
        if has_dangerous_chars(&self.reason) {
            return Err("acis: reason contains dangerous characters".into());
        }

        // matched_policy_id
        if let Some(ref pid) = self.matched_policy_id {
            if pid.len() > MAX_POLICY_ID_LEN {
                return Err("acis: matched_policy_id exceeds maximum length".into());
            }
            if has_dangerous_chars(pid) {
                return Err("acis: matched_policy_id contains dangerous characters".into());
            }
        }

        // transport
        if self.transport.is_empty() {
            return Err("acis: transport must not be empty".into());
        }
        if self.transport.len() > MAX_TRANSPORT_LEN {
            return Err("acis: transport exceeds maximum length".into());
        }
        if has_dangerous_chars(&self.transport) {
            return Err("acis: transport contains dangerous characters".into());
        }

        // findings
        if self.findings.len() > MAX_FINDINGS {
            return Err("acis: findings exceeds maximum count".into());
        }
        for (i, f) in self.findings.iter().enumerate() {
            if f.len() > MAX_FINDING_LEN {
                return Err(format!("acis: findings[{i}] exceeds maximum length"));
            }
            // R244-ACIS-3: findings may echo attacker input; validate chars.
            if has_dangerous_chars(f) {
                return Err(format!("acis: findings[{i}] contains dangerous characters"));
            }
        }
        if self.semantic_taint.len() > MAX_SEMANTIC_TAINT {
            return Err("acis: semantic_taint exceeds maximum count".into());
        }
        validate_lineage_refs(&self.lineage_refs).map_err(|e| format!("acis: {e}"))?;
        if let Some(ref risk_score) = self.semantic_risk_score {
            risk_score.validate().map_err(|e| format!("acis: {e}"))?;
        }

        // evaluation_us (R244-ACIS-7): reject absurdly large latency values
        if let Some(us) = self.evaluation_us {
            if us > MAX_EVALUATION_US {
                return Err("acis: evaluation_us exceeds maximum (1 hour)".into());
            }
        }

        // call_chain_depth (R244-ACIS-7): reject unreasonable depth
        if self.call_chain_depth > MAX_CALL_CHAIN_DEPTH {
            return Err("acis: call_chain_depth exceeds maximum (256)".into());
        }

        Ok(())
    }
}

// ── Fingerprint ──────────────────────────────────────────────────────────────

// `compute_action_fingerprint()` (SHA-256) lives in `vellaveto-engine` to avoid
// pulling sha2+hex into this leaf crate.  See `vellaveto_engine::acis`.

#[cfg(test)]
mod verus_spec_differential {
    //! Differential binding for `PARITY-HAND-1` (see
    //! `formal/ASSUMPTION_REGISTRY.md`), covering both ACIS kernels:
    //! `formal/verus/verified_acis_action_summary.rs` and
    //! `formal/verus/verified_acis_envelope.rs`.
    //!
    //! **Necessary-condition binding.** The kernels model a *subset* of what
    //! `validate()` checks — lengths, dangerous characters, target counts and
    //! the Deny-implies-reason invariant, but not the timestamp format, the
    //! session or tenant identifiers, or the transport. So the assertion is one
    //! directional: **whatever the kernel rejects, production must also
    //! reject.** Production rejecting more is expected and is not a failure.
    //!
    //! The reverse direction is checked only where the kernel accepts *and*
    //! every unmodelled field is left at a known-good value, which is what
    //! `modelled_envelope` provides.
    //!
    //! The kernel bounds are literals (256, 256, 100_000, 256, 3_600_000_000)
    //! where production reads named constants, so this binds those too.

    use super::*;

    const K_MAX_TOOL_LEN: usize = 256;
    const K_MAX_FUNCTION_LEN: usize = 256;
    const K_MAX_TARGET_COUNT: u32 = 100_000;
    const K_MAX_CALL_CHAIN_DEPTH: u32 = 256;
    const K_MAX_EVALUATION_US: u64 = 3_600_000_000;

    /// Transcription of `spec_action_summary_valid`.
    fn spec_action_summary_valid(
        tool_len: usize,
        function_len: usize,
        tool_has_dangerous_chars: bool,
        function_has_dangerous_chars: bool,
        target_path_count: u32,
        target_domain_count: u32,
    ) -> bool {
        tool_len > 0
            && tool_len <= K_MAX_TOOL_LEN
            && function_len > 0
            && function_len <= K_MAX_FUNCTION_LEN
            && !tool_has_dangerous_chars
            && !function_has_dangerous_chars
            && target_path_count <= K_MAX_TARGET_COUNT
            && target_domain_count <= K_MAX_TARGET_COUNT
    }

    /// Transcription of `spec_acis_envelope_fields_valid`.
    fn spec_envelope_fields_valid(
        decision_id_len: usize,
        fingerprint_len: usize,
        call_chain_depth: u32,
        evaluation_us: Option<u64>,
        is_deny: bool,
        reason_len: usize,
    ) -> bool {
        decision_id_len > 0
            && fingerprint_len > 0
            && call_chain_depth <= K_MAX_CALL_CHAIN_DEPTH
            && evaluation_us.is_none_or(|v| v <= K_MAX_EVALUATION_US)
            && (!is_deny || reason_len > 0)
    }

    /// Transcription of `spec_deny_has_reason`.
    fn spec_deny_has_reason(is_deny: bool, reason_len: usize) -> bool {
        !is_deny || reason_len > 0
    }

    fn summary(tool: &str, function: &str, paths: u32, domains: u32) -> AcisActionSummary {
        AcisActionSummary {
            tool: tool.into(),
            function: function.into(),
            target_path_count: paths,
            target_domain_count: domains,
        }
    }

    /// An envelope whose unmodelled fields are all known-good, so acceptance is
    /// decided purely by what the kernels model.
    fn modelled_envelope(
        decision_id: &str,
        fingerprint: &str,
        decision: DecisionKind,
        reason: &str,
        call_chain_depth: u32,
        evaluation_us: Option<u64>,
        action_summary: AcisActionSummary,
    ) -> AcisDecisionEnvelope {
        AcisDecisionEnvelope {
            decision_id: decision_id.into(),
            timestamp: "2026-03-09T10:00:00Z".into(),
            session_id: None,
            tenant_id: None,
            agent_identity: None,
            agent_id: None,
            client_provenance: None,
            action_summary,
            action_fingerprint: fingerprint.into(),
            decision,
            origin: DecisionOrigin::PolicyEngine,
            reason: reason.into(),
            matched_policy_id: None,
            transport: "stdio".into(),
            findings: vec![],
            semantic_taint: vec![],
            lineage_refs: vec![],
            effective_trust_tier: None,
            sink_class: None,
            containment_mode: None,
            semantic_risk_score: None,
            evaluation_us,
            call_chain_depth,
        }
    }

    /// Lengths chosen at and either side of every bound the kernel names.
    const LENGTHS: [usize; 6] = [0, 1, 2, 255, 256, 257];
    const COUNTS: [u32; 5] = [0, 1, 99_999, 100_000, 100_001];

    #[test]
    fn test_action_summary_rejection_is_at_least_as_strict_as_the_kernel() {
        let mut checked = 0usize;
        for &tool_len in &LENGTHS {
            for &fn_len in &LENGTHS {
                for &paths in &COUNTS {
                    for &domains in &COUNTS {
                        let s = summary(&"t".repeat(tool_len), &"f".repeat(fn_len), paths, domains);
                        let spec_ok = spec_action_summary_valid(
                            tool_len, fn_len, false, false, paths, domains,
                        );
                        let shipped_ok = s.validate().is_ok();
                        if !spec_ok {
                            assert!(
                                !shipped_ok,
                                "PARITY-HAND-1: the kernel rejects (tool_len={tool_len}, \
                                 fn_len={fn_len}, paths={paths}, domains={domains}) but \
                                 validate() accepted it"
                            );
                        } else {
                            // No unmodelled field can reject here, so acceptance
                            // must agree in both directions.
                            assert!(
                                shipped_ok,
                                "PARITY-HAND-1: the kernel accepts (tool_len={tool_len}, \
                                 fn_len={fn_len}, paths={paths}, domains={domains}) but \
                                 validate() rejected it"
                            );
                        }
                        checked += 1;
                    }
                }
            }
        }
        assert_eq!(checked, 6 * 6 * 5 * 5, "enumeration collapsed");
    }

    #[test]
    fn test_dangerous_characters_are_rejected_as_the_kernel_requires() {
        // The kernel models this as a boolean; production computes it. Both
        // halves are checked: a dangerous tool or function must be refused.
        for probe in ["a\u{0}b", "a\u{7}b", "a\u{202e}b", "a\u{feff}b"] {
            assert!(
                summary(probe, "write", 0, 0).validate().is_err(),
                "PARITY-HAND-1: dangerous tool name {probe:?} was accepted"
            );
            assert!(
                summary("file_write", probe, 0, 0).validate().is_err(),
                "PARITY-HAND-1: dangerous function name {probe:?} was accepted"
            );
            assert!(
                !spec_action_summary_valid(3, 5, true, false, 0, 0),
                "PARITY-HAND-1: the kernel must reject a dangerous tool name"
            );
        }
    }

    #[test]
    fn test_envelope_rejection_is_at_least_as_strict_as_the_kernel() {
        let depths = [0u32, 1, 255, 256, 257];
        let evals = [None, Some(0u64), Some(3_600_000_000), Some(3_600_000_001)];
        let mut checked = 0usize;

        for &decision_id_len in &[0usize, 1, 36] {
            for &fp_len in &[0usize, 1, 64] {
                for &depth in &depths {
                    for &eval in &evals {
                        for decision in [DecisionKind::Allow, DecisionKind::Deny] {
                            for reason in ["", "blocked by policy"] {
                                let env = modelled_envelope(
                                    &"d".repeat(decision_id_len),
                                    &"f".repeat(fp_len),
                                    decision,
                                    reason,
                                    depth,
                                    eval,
                                    summary("file_write", "write", 0, 0),
                                );
                                let spec_ok = spec_envelope_fields_valid(
                                    decision_id_len,
                                    fp_len,
                                    depth,
                                    eval,
                                    decision == DecisionKind::Deny,
                                    reason.len(),
                                );
                                if !spec_ok {
                                    assert!(
                                        env.validate().is_err(),
                                        "PARITY-HAND-1: the kernel rejects an envelope \
                                         (id_len={decision_id_len}, fp_len={fp_len}, \
                                         depth={depth}, eval={eval:?}, {decision:?}, \
                                         reason={reason:?}) that validate() accepted"
                                    );
                                }
                                checked += 1;
                            }
                        }
                    }
                }
            }
        }
        assert_eq!(checked, 3 * 3 * 5 * 4 * 2 * 2, "enumeration collapsed");
    }

    #[test]
    fn test_deny_without_reason_is_refused_in_both() {
        let denied = modelled_envelope(
            "550e8400-e29b-41d4-a716-446655440000",
            "a1b2c3",
            DecisionKind::Deny,
            "",
            0,
            None,
            summary("file_write", "write", 0, 0),
        );
        assert!(
            denied.validate().is_err(),
            "PARITY-HAND-1: a Deny with no reason must be refused — the structural \
             invariant the kernel proves"
        );
        assert!(!spec_deny_has_reason(true, 0));
        assert!(spec_deny_has_reason(true, 1));
        assert!(spec_deny_has_reason(false, 0));
    }

    #[test]
    fn test_spec_oracle_can_reject() {
        // Every bound the kernel names is exact, not approximate.
        assert!(spec_action_summary_valid(
            256, 256, false, false, 100_000, 100_000
        ));
        assert!(!spec_action_summary_valid(257, 256, false, false, 0, 0));
        assert!(!spec_action_summary_valid(256, 257, false, false, 0, 0));
        assert!(!spec_action_summary_valid(0, 1, false, false, 0, 0));
        assert!(!spec_action_summary_valid(1, 1, false, false, 100_001, 0));
        assert!(spec_envelope_fields_valid(
            1,
            1,
            256,
            Some(3_600_000_000),
            false,
            0
        ));
        assert!(!spec_envelope_fields_valid(1, 1, 257, None, false, 0));
        assert!(!spec_envelope_fields_valid(
            1,
            1,
            0,
            Some(3_600_000_001),
            false,
            0
        ));
        assert!(!spec_envelope_fields_valid(0, 1, 0, None, false, 0));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_envelope() -> AcisDecisionEnvelope {
        AcisDecisionEnvelope {
            decision_id: "550e8400-e29b-41d4-a716-446655440000".into(),
            timestamp: "2026-03-09T10:00:00Z".into(),
            session_id: None,
            tenant_id: None,
            agent_identity: None,
            agent_id: None,
            client_provenance: None,
            action_summary: AcisActionSummary {
                tool: "file_write".into(),
                function: "write".into(),
                target_path_count: 1,
                target_domain_count: 0,
            },
            // Fingerprint is computed by vellaveto-engine; use a placeholder here.
            action_fingerprint: "a1b2c3d4e5f6".into(),
            decision: DecisionKind::Allow,
            origin: DecisionOrigin::PolicyEngine,
            reason: String::new(),
            matched_policy_id: Some("policy-001".into()),
            transport: "stdio".into(),
            findings: vec![],
            semantic_taint: vec![],
            lineage_refs: vec![],
            effective_trust_tier: None,
            sink_class: None,
            containment_mode: None,
            semantic_risk_score: None,
            evaluation_us: Some(42),
            call_chain_depth: 0,
        }
    }

    #[test]
    fn test_minimal_envelope_validates() {
        let env = minimal_envelope();
        assert!(env.validate().is_ok());
    }

    #[test]
    fn test_decision_kind_default_is_deny() {
        assert_eq!(DecisionKind::default(), DecisionKind::Deny);
    }

    #[test]
    fn test_decision_kind_from_verdict() {
        assert_eq!(DecisionKind::from(&Verdict::Allow), DecisionKind::Allow);
        assert_eq!(
            DecisionKind::from(&Verdict::Deny { reason: "x".into() }),
            DecisionKind::Deny
        );
        assert_eq!(
            DecisionKind::from(&Verdict::RequireApproval { reason: "x".into() }),
            DecisionKind::RequireApproval
        );
    }

    #[test]
    fn test_empty_decision_id_rejected() {
        let mut env = minimal_envelope();
        env.decision_id = String::new();
        let err = env.validate().unwrap_err();
        assert!(err.contains("decision_id must not be empty"));
    }

    #[test]
    fn test_non_utc_timestamp_rejected() {
        let mut env = minimal_envelope();
        env.timestamp = "2026-03-09T10:00:00+01:00".into();
        let err = env.validate().unwrap_err();
        assert!(err.contains("timestamp must be UTC"));
    }

    #[test]
    fn test_dangerous_chars_in_session_id_rejected() {
        let mut env = minimal_envelope();
        env.session_id = Some("sess\x00ion".into());
        let err = env.validate().unwrap_err();
        assert!(err.contains("session_id contains dangerous"));
    }

    #[test]
    fn test_empty_transport_rejected() {
        let mut env = minimal_envelope();
        env.transport = String::new();
        let err = env.validate().unwrap_err();
        assert!(err.contains("transport must not be empty"));
    }

    #[test]
    fn test_too_many_findings_rejected() {
        let mut env = minimal_envelope();
        env.findings = vec!["f".into(); 65];
        let err = env.validate().unwrap_err();
        assert!(err.contains("findings exceeds maximum count"));
    }

    #[test]
    fn test_empty_fingerprint_rejected() {
        let mut env = minimal_envelope();
        env.action_fingerprint = String::new();
        let err = env.validate().unwrap_err();
        assert!(err.contains("action_fingerprint must not be empty"));
    }

    #[test]
    fn test_oversized_fingerprint_rejected() {
        let mut env = minimal_envelope();
        env.action_fingerprint = "x".repeat(129);
        let err = env.validate().unwrap_err();
        assert!(err.contains("action_fingerprint exceeds maximum length"));
    }

    #[test]
    fn test_envelope_serialization_roundtrip() {
        let env = minimal_envelope();
        let json = serde_json::to_string(&env).expect("serialize");
        let decoded: AcisDecisionEnvelope = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded.decision_id, env.decision_id);
        assert_eq!(decoded.action_fingerprint, env.action_fingerprint);
        assert_eq!(decoded.decision, env.decision);
    }

    #[test]
    fn test_deny_unknown_fields_rejects_extra() {
        let json = r#"{
            "decision_id": "abc",
            "timestamp": "2026-03-09T00:00:00Z",
            "action_summary": {"tool":"t","function":"f","target_path_count":0,"target_domain_count":0},
            "action_fingerprint": "abc123",
            "decision": "allow",
            "origin": "policy_engine",
            "transport": "http",
            "call_chain_depth": 0,
            "evil_field": true
        }"#;
        assert!(serde_json::from_str::<AcisDecisionEnvelope>(json).is_err());
    }

    #[test]
    fn test_dangerous_chars_in_tenant_id_rejected() {
        let mut env = minimal_envelope();
        env.tenant_id = Some("tenant\x07id".into());
        let err = env.validate().unwrap_err();
        assert!(err.contains("tenant_id contains dangerous"));
    }

    #[test]
    fn test_oversized_reason_rejected() {
        let mut env = minimal_envelope();
        env.reason = "x".repeat(4097);
        let err = env.validate().unwrap_err();
        assert!(err.contains("reason exceeds maximum length"));
    }

    #[test]
    fn test_finding_too_long_rejected() {
        let mut env = minimal_envelope();
        env.findings = vec!["x".repeat(513)];
        let err = env.validate().unwrap_err();
        assert!(err.contains("findings[0] exceeds maximum length"));
    }

    #[test]
    fn test_utc_plus_zero_timestamp_accepted() {
        let mut env = minimal_envelope();
        env.timestamp = "2026-03-09T10:00:00+00:00".into();
        assert!(env.validate().is_ok());
    }

    // ── R244-ACIS-1: agent_id validation ─────────────────────────────────

    #[test]
    fn test_r244_agent_id_dangerous_chars_rejected() {
        let mut env = minimal_envelope();
        env.agent_id = Some("agent\x00id".into());
        let err = env.validate().unwrap_err();
        assert!(err.contains("agent_id contains dangerous"));
    }

    #[test]
    fn test_r244_agent_id_oversized_rejected() {
        let mut env = minimal_envelope();
        env.agent_id = Some("a".repeat(513));
        let err = env.validate().unwrap_err();
        assert!(err.contains("agent_id exceeds maximum length"));
    }

    #[test]
    fn test_r244_agent_id_valid_accepted() {
        let mut env = minimal_envelope();
        env.agent_id = Some("claude-agent-v4".into());
        assert!(env.validate().is_ok());
    }

    #[test]
    fn test_r244_agent_id_empty_rejected() {
        let mut env = minimal_envelope();
        env.agent_id = Some(String::new());
        let err = env.validate().unwrap_err();
        assert!(err.contains("agent_id must not be empty"));
    }

    // ── R244-ACIS-3: tool/function length bounds ────────────────────────

    #[test]
    fn test_r244_tool_oversized_rejected() {
        let mut env = minimal_envelope();
        env.action_summary.tool = "t".repeat(257);
        let err = env.validate().unwrap_err();
        assert!(err.contains("action_summary.tool exceeds maximum length"));
    }

    #[test]
    fn test_r244_function_oversized_rejected() {
        let mut env = minimal_envelope();
        env.action_summary.function = "f".repeat(257);
        let err = env.validate().unwrap_err();
        assert!(err.contains("action_summary.function exceeds maximum length"));
    }

    #[test]
    fn test_r244_function_empty_rejected() {
        let mut env = minimal_envelope();
        env.action_summary.function = String::new();
        let err = env.validate().unwrap_err();
        assert!(err.contains("action_summary.function must not be empty"));
    }

    // ── R244-ACIS-5: agent_identity nested validation ───────────────────

    #[test]
    fn test_r244_agent_identity_validation_delegated() {
        let mut env = minimal_envelope();
        let mut identity = AgentIdentity::default();
        // Exceed MAX_CLAIMS to trigger AgentIdentity::validate() failure
        for i in 0..65 {
            identity
                .claims
                .insert(format!("claim_{i}"), serde_json::json!("v"));
        }
        env.agent_identity = Some(identity);
        let err = env.validate().unwrap_err();
        assert!(
            err.contains("agent_identity validation failed"),
            "expected nested validation delegation: {err}"
        );
    }

    // ── R244-ACIS-2: reason dangerous chars ──────────────────────────────

    #[test]
    fn test_r244_reason_dangerous_chars_rejected() {
        let mut env = minimal_envelope();
        env.reason = "denied\x07bell".into();
        let err = env.validate().unwrap_err();
        assert!(err.contains("reason contains dangerous"));
    }

    // ── R244-ACIS-3: findings dangerous chars ────────────────────────────

    #[test]
    fn test_r244_finding_dangerous_chars_rejected() {
        let mut env = minimal_envelope();
        env.findings = vec!["DLP: found key\x00 in params".into()];
        let err = env.validate().unwrap_err();
        assert!(err.contains("findings[0] contains dangerous"));
    }

    #[test]
    fn test_r244_finding_bidi_chars_rejected() {
        let mut env = minimal_envelope();
        // U+202E = RIGHT-TO-LEFT OVERRIDE
        env.findings = vec!["injection: found \u{202E}override".into()];
        let err = env.validate().unwrap_err();
        assert!(err.contains("findings[0] contains dangerous"));
    }

    // ── R244-ACIS-7: numeric range bounds ────────────────────────────────

    #[test]
    fn test_r244_evaluation_us_max_rejected() {
        let mut env = minimal_envelope();
        env.evaluation_us = Some(3_600_000_001);
        let err = env.validate().unwrap_err();
        assert!(err.contains("evaluation_us exceeds maximum"));
    }

    #[test]
    fn test_r244_evaluation_us_max_accepted() {
        let mut env = minimal_envelope();
        env.evaluation_us = Some(3_600_000_000);
        assert!(env.validate().is_ok());
    }

    #[test]
    fn test_r244_call_chain_depth_max_rejected() {
        let mut env = minimal_envelope();
        env.call_chain_depth = 257;
        let err = env.validate().unwrap_err();
        assert!(err.contains("call_chain_depth exceeds maximum"));
    }

    #[test]
    fn test_r244_call_chain_depth_max_accepted() {
        let mut env = minimal_envelope();
        env.call_chain_depth = 256;
        assert!(env.validate().is_ok());
    }

    // ── R246-ACIS-1: target count bounds ─────────────────────────────────

    #[test]
    fn test_r246_target_path_count_max_rejected() {
        let mut env = minimal_envelope();
        env.action_summary.target_path_count = 100_001;
        let err = env.validate().unwrap_err();
        assert!(err.contains("target_path_count exceeds maximum"));
    }

    #[test]
    fn test_r246_target_domain_count_max_rejected() {
        let mut env = minimal_envelope();
        env.action_summary.target_domain_count = 100_001;
        let err = env.validate().unwrap_err();
        assert!(err.contains("target_domain_count exceeds maximum"));
    }

    #[test]
    fn test_r246_target_counts_at_max_accepted() {
        let mut env = minimal_envelope();
        env.action_summary.target_path_count = 100_000;
        env.action_summary.target_domain_count = 100_000;
        assert!(env.validate().is_ok());
    }

    // ── R246-TYPES-1: standalone AcisActionSummary validate ──────────────

    #[test]
    fn test_r246_action_summary_standalone_validate_ok() {
        let summary = AcisActionSummary {
            tool: "file_write".into(),
            function: "write".into(),
            target_path_count: 5,
            target_domain_count: 0,
        };
        assert!(summary.validate().is_ok());
    }

    #[test]
    fn test_r246_action_summary_standalone_empty_tool_rejected() {
        let summary = AcisActionSummary {
            tool: String::new(),
            function: "write".into(),
            target_path_count: 0,
            target_domain_count: 0,
        };
        let err = summary.validate().unwrap_err();
        assert!(err.contains("tool must not be empty"));
    }

    #[test]
    fn test_r246_action_summary_standalone_dangerous_chars_rejected() {
        let summary = AcisActionSummary {
            tool: "file\x00write".into(),
            function: "write".into(),
            target_path_count: 0,
            target_domain_count: 0,
        };
        let err = summary.validate().unwrap_err();
        assert!(err.contains("dangerous characters"));
    }

    // ── R254: DecisionOrigin serialization roundtrip ──────────────────────

    #[test]
    fn test_r254_decision_origin_all_variants_roundtrip() {
        let origins = [
            DecisionOrigin::PolicyEngine,
            DecisionOrigin::Dlp,
            DecisionOrigin::InjectionScanner,
            DecisionOrigin::MemoryPoisoning,
            DecisionOrigin::ApprovalGate,
            DecisionOrigin::CapabilityEnforcement,
            DecisionOrigin::RateLimiter,
            DecisionOrigin::CircuitBreaker,
            DecisionOrigin::TopologyGuard,
            DecisionOrigin::SessionGuard,
            DecisionOrigin::ProvenanceGuard,
            DecisionOrigin::SemanticContainment,
        ];
        for origin in &origins {
            let json = serde_json::to_string(origin).expect("serialize");
            let decoded: DecisionOrigin = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(
                *origin, decoded,
                "roundtrip failed for {origin:?}: serialized as {json}"
            );
        }
    }

    #[test]
    fn test_r254_decision_origin_snake_case_format() {
        assert_eq!(
            serde_json::to_string(&DecisionOrigin::PolicyEngine).unwrap(),
            "\"policy_engine\""
        );
        assert_eq!(
            serde_json::to_string(&DecisionOrigin::InjectionScanner).unwrap(),
            "\"injection_scanner\""
        );
        assert_eq!(
            serde_json::to_string(&DecisionOrigin::CircuitBreaker).unwrap(),
            "\"circuit_breaker\""
        );
        assert_eq!(
            serde_json::to_string(&DecisionOrigin::SessionGuard).unwrap(),
            "\"session_guard\""
        );
        assert_eq!(
            serde_json::to_string(&DecisionOrigin::ProvenanceGuard).unwrap(),
            "\"provenance_guard\""
        );
        assert_eq!(
            serde_json::to_string(&DecisionOrigin::SemanticContainment).unwrap(),
            "\"semantic_containment\""
        );
    }

    // ── R254: boundary tests ──────────────────────────────────────────────

    #[test]
    fn test_r254_findings_exactly_at_max_accepted() {
        let mut env = minimal_envelope();
        env.findings = vec!["f".into(); 64];
        assert!(env.validate().is_ok());
    }

    #[test]
    fn test_r254_session_id_exactly_at_max_accepted() {
        let mut env = minimal_envelope();
        env.session_id = Some("s".repeat(512));
        assert!(env.validate().is_ok());
    }

    #[test]
    fn test_r254_session_id_over_max_rejected() {
        let mut env = minimal_envelope();
        env.session_id = Some("s".repeat(513));
        let err = env.validate().unwrap_err();
        assert!(err.contains("session_id exceeds maximum"));
    }

    #[test]
    fn test_r254_decision_id_exactly_at_max_accepted() {
        let mut env = minimal_envelope();
        env.decision_id = "d".repeat(64);
        assert!(env.validate().is_ok());
    }

    #[test]
    fn test_r254_decision_id_over_max_rejected() {
        let mut env = minimal_envelope();
        env.decision_id = "d".repeat(65);
        let err = env.validate().unwrap_err();
        assert!(err.contains("decision_id exceeds maximum"));
    }

    #[test]
    fn test_r254_matched_policy_id_dangerous_chars_rejected() {
        let mut env = minimal_envelope();
        env.matched_policy_id = Some("policy\x00id".into());
        let err = env.validate().unwrap_err();
        assert!(err.contains("matched_policy_id contains dangerous"));
    }

    #[test]
    fn test_r254_transport_dangerous_chars_rejected() {
        let mut env = minimal_envelope();
        env.transport = "http\x07".into();
        let err = env.validate().unwrap_err();
        assert!(err.contains("transport contains dangerous"));
    }

    #[test]
    fn test_r254_transport_oversized_rejected() {
        let mut env = minimal_envelope();
        env.transport = "x".repeat(33);
        let err = env.validate().unwrap_err();
        assert!(err.contains("transport exceeds maximum"));
    }

    #[test]
    fn test_r254_both_target_counts_at_max_accepted() {
        let mut env = minimal_envelope();
        env.action_summary.target_path_count = 100_000;
        env.action_summary.target_domain_count = 100_000;
        assert!(env.validate().is_ok());
    }
}
