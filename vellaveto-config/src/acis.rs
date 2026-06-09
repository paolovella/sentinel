// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! ACIS (Agent-Consumer Interaction Surface) configuration.
//!
//! Controls how ACIS decision envelopes are emitted, which fields are
//! populated, and session/identity binding behavior.

use crate::validation::validate_ed25519_pubkey;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use vellaveto_types::{has_dangerous_chars, ContainmentMode, SessionKeyScope, WorkloadIdentity};

// ── Constants ────────────────────────────────────────────────────────────────

/// Maximum length of `default_transport` label.
const MAX_TRANSPORT_LEN: usize = 32;

/// Maximum length of `tenant_id` override.
const MAX_TENANT_ID_LEN: usize = 256;

/// Maximum number of custom finding labels allowed.
const MAX_CUSTOM_FINDING_LABELS: usize = 64;
/// Maximum number of trusted detached request signers.
const MAX_TRUSTED_REQUEST_SIGNERS: usize = 64;

/// Maximum length of a single custom finding label.
const MAX_FINDING_LABEL_LEN: usize = 128;
/// Maximum length of a detached request signer key id.
const MAX_SIGNER_KEY_ID_LEN: usize = 256;
/// Maximum allowed detached request-signature freshness window (24 hours).
const MAX_DETACHED_REQUEST_SIGNATURE_MAX_AGE_SECS: u64 = 86_400;
/// Maximum allowed detached request-signature future-skew allowance (1 hour).
const MAX_DETACHED_REQUEST_SIGNATURE_MAX_FUTURE_SKEW_SECS: u64 = 3_600;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TrustedRequestSignerConfig {
    /// Logical key identifier carried in detached request signatures.
    pub key_id: String,
    /// Hex-encoded Ed25519 verifying key (32 bytes).
    pub public_key: String,
    /// Optional session key scope projected when this signer verifies a request.
    #[serde(default)]
    pub session_key_scope: SessionKeyScope,
    /// Whether verified requests from this signer should be treated as ephemeral.
    #[serde(default)]
    pub execution_is_ephemeral: bool,
    /// Optional workload identity expectation or fallback projection for this signer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload_identity: Option<WorkloadIdentity>,
}

impl TrustedRequestSignerConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.key_id.is_empty() {
            return Err("trusted_request_signers.key_id must not be empty".into());
        }
        if self.key_id.len() > MAX_SIGNER_KEY_ID_LEN {
            return Err(format!(
                "trusted_request_signers.key_id length {} exceeds max {}",
                self.key_id.len(),
                MAX_SIGNER_KEY_ID_LEN
            ));
        }
        if has_dangerous_chars(&self.key_id) {
            return Err("trusted_request_signers.key_id contains dangerous characters".into());
        }
        validate_ed25519_pubkey(&self.public_key)
            .map_err(|err| format!("trusted_request_signers.public_key invalid: {err}"))?;
        if let Some(workload_identity) = &self.workload_identity {
            workload_identity.validate().map_err(|err| {
                format!("trusted_request_signers.workload_identity invalid: {err}")
            })?;
        }
        if self.execution_is_ephemeral
            && matches!(
                self.session_key_scope,
                SessionKeyScope::PersistedClient | SessionKeyScope::PersistedService
            )
        {
            return Err(
                "trusted_request_signers execution_is_ephemeral cannot be combined with persisted session_key_scope"
                    .into(),
            );
        }
        Ok(())
    }
}

// ── Config ───────────────────────────────────────────────────────────────────

/// ACIS configuration section.
///
/// Controls envelope emission, session binding, and identity requirements
/// across all transport surfaces.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AcisConfig {
    /// Enable ACIS decision envelope emission on every enforcement decision.
    /// Default: `true` (fail-closed — always emit).
    #[serde(default = "default_emit_envelopes")]
    pub emit_envelopes: bool,

    /// Require a session ID on every ACIS envelope.  When `true`, requests
    /// without a session ID produce a Deny verdict.
    /// Default: `false` (session binding is opt-in).
    #[serde(default)]
    pub require_session_id: bool,

    /// Require an authenticated agent identity on every ACIS envelope.
    /// When `true`, unauthenticated requests produce a Deny verdict.
    /// Default: `false`.
    #[serde(default)]
    pub require_agent_identity: bool,

    /// Require a verified client request signature before mediation.
    /// Default: `false`.
    #[serde(default)]
    pub require_verified_signature: bool,

    /// Trusted detached request-signature signers keyed by `RequestSignature.key_id`.
    /// These keys are used by transports that accept detached signature metadata
    /// to promote a request from `missing` to `verified`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trusted_request_signers: Vec<TrustedRequestSignerConfig>,

    /// Maximum age in seconds for verified detached request signatures.
    /// Signatures older than this are marked `expired`.
    #[serde(default = "default_detached_request_signature_max_age_secs")]
    pub detached_request_signature_max_age_secs: u64,

    /// Maximum future clock skew tolerated for verified detached signatures.
    /// Signatures created beyond this skew are marked `expired`.
    #[serde(default = "default_detached_request_signature_max_future_skew_secs")]
    pub detached_request_signature_max_future_skew_secs: u64,

    /// Require workload binding evidence to succeed when provenance is present.
    /// Default: `false`.
    #[serde(default)]
    pub require_workload_binding: bool,

    /// Require client provenance to represent an ephemeral execution context.
    /// Default: `false`.
    #[serde(default)]
    pub require_ephemeral_client_provenance: bool,

    /// Deny requests marked as replays by the transport security context.
    /// Default: `false`.
    #[serde(default)]
    pub deny_replay: bool,

    /// Block privileged sinks when the request carries security-relevant taint.
    /// Default: `false`.
    #[serde(default)]
    pub block_tainted_privileged_sinks: bool,

    /// Require lineage evidence before privileged sinks may proceed.
    /// Default: `false`.
    #[serde(default)]
    pub require_lineage_for_privileged_sinks: bool,

    /// Default semantic containment mode applied to privileged sink gates when
    /// the runtime security context does not carry a request-specific mode.
    /// Default: unset, so the mediation layer uses its built-in fail-closed mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub containment_mode: Option<ContainmentMode>,

    /// Include evaluation timing (`evaluation_us`) in envelopes.
    /// Default: `true`.
    #[serde(default = "default_include_timing")]
    pub include_timing: bool,

    /// Include security findings (DLP, injection, etc.) in envelopes.
    /// Default: `true`.
    #[serde(default = "default_include_findings")]
    pub include_findings: bool,

    /// Default transport label when the intercepting surface does not
    /// provide one.  Must be one of: `stdio`, `http`, `websocket`, `grpc`,
    /// `sse`.
    #[serde(default = "default_transport")]
    pub default_transport: String,

    /// Static tenant ID override.  When set, every envelope uses this
    /// tenant ID instead of deriving it from the request context.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,

    /// Custom finding labels to include in envelopes (e.g., for downstream
    /// SIEM enrichment).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub custom_finding_labels: Vec<String>,
}

fn default_emit_envelopes() -> bool {
    true
}

fn default_include_timing() -> bool {
    true
}

fn default_include_findings() -> bool {
    true
}

fn default_transport() -> String {
    "stdio".into()
}

fn default_detached_request_signature_max_age_secs() -> u64 {
    600
}

fn default_detached_request_signature_max_future_skew_secs() -> u64 {
    300
}

impl Default for AcisConfig {
    fn default() -> Self {
        Self {
            emit_envelopes: default_emit_envelopes(),
            require_session_id: false,
            require_agent_identity: false,
            require_verified_signature: false,
            trusted_request_signers: vec![],
            detached_request_signature_max_age_secs:
                default_detached_request_signature_max_age_secs(),
            detached_request_signature_max_future_skew_secs:
                default_detached_request_signature_max_future_skew_secs(),
            require_workload_binding: false,
            require_ephemeral_client_provenance: false,
            deny_replay: false,
            block_tainted_privileged_sinks: false,
            require_lineage_for_privileged_sinks: false,
            containment_mode: None,
            include_timing: default_include_timing(),
            include_findings: default_include_findings(),
            default_transport: default_transport(),
            tenant_id: None,
            custom_finding_labels: vec![],
        }
    }
}

impl AcisConfig {
    /// Validate all fields for length, content, and structural invariants.
    pub fn validate(&self) -> Result<(), String> {
        // default_transport
        if self.default_transport.is_empty() {
            return Err("default_transport must not be empty".into());
        }
        if self.default_transport.len() > MAX_TRANSPORT_LEN {
            return Err(format!(
                "default_transport length {} exceeds max {}",
                self.default_transport.len(),
                MAX_TRANSPORT_LEN
            ));
        }
        if has_dangerous_chars(&self.default_transport) {
            return Err("default_transport contains dangerous characters".into());
        }
        match self.default_transport.as_str() {
            "stdio" | "http" | "websocket" | "grpc" | "sse" => {}
            other => {
                return Err(format!(
                    "default_transport must be one of: stdio, http, websocket, grpc, sse — got '{other}'"
                ));
            }
        }

        // tenant_id
        if let Some(ref tid) = self.tenant_id {
            if tid.is_empty() {
                return Err("tenant_id must not be empty when set".into());
            }
            if tid.len() > MAX_TENANT_ID_LEN {
                return Err(format!(
                    "tenant_id length {} exceeds max {}",
                    tid.len(),
                    MAX_TENANT_ID_LEN
                ));
            }
            if has_dangerous_chars(tid) {
                return Err("tenant_id contains dangerous characters".into());
            }
        }

        // custom_finding_labels
        if self.custom_finding_labels.len() > MAX_CUSTOM_FINDING_LABELS {
            return Err(format!(
                "custom_finding_labels has {} entries, max is {}",
                self.custom_finding_labels.len(),
                MAX_CUSTOM_FINDING_LABELS
            ));
        }
        for (i, label) in self.custom_finding_labels.iter().enumerate() {
            if label.is_empty() {
                return Err(format!("custom_finding_labels[{i}] must not be empty"));
            }
            if label.len() > MAX_FINDING_LABEL_LEN {
                return Err(format!(
                    "custom_finding_labels[{i}] length {} exceeds max {}",
                    label.len(),
                    MAX_FINDING_LABEL_LEN
                ));
            }
            if has_dangerous_chars(label) {
                return Err(format!(
                    "custom_finding_labels[{i}] contains dangerous characters"
                ));
            }
        }

        if self.trusted_request_signers.len() > MAX_TRUSTED_REQUEST_SIGNERS {
            return Err(format!(
                "trusted_request_signers has {} entries, max is {}",
                self.trusted_request_signers.len(),
                MAX_TRUSTED_REQUEST_SIGNERS
            ));
        }
        let mut seen_trusted_signer_ids =
            HashSet::with_capacity(self.trusted_request_signers.len());
        let mut seen_trusted_signer_keys =
            HashSet::with_capacity(self.trusted_request_signers.len());
        for signer in &self.trusted_request_signers {
            signer.validate()?;
            if !seen_trusted_signer_ids.insert(signer.key_id.as_str()) {
                return Err(format!(
                    "trusted_request_signers contains duplicate key_id '{}'",
                    signer.key_id
                ));
            }
            if !seen_trusted_signer_keys.insert(signer.public_key.as_str()) {
                return Err(format!(
                    "trusted_request_signers contains duplicate public_key for key_id '{}'",
                    signer.key_id
                ));
            }
        }

        if self.detached_request_signature_max_age_secs == 0
            || self.detached_request_signature_max_age_secs
                > MAX_DETACHED_REQUEST_SIGNATURE_MAX_AGE_SECS
        {
            return Err(format!(
                "detached_request_signature_max_age_secs must be between 1 and {}",
                MAX_DETACHED_REQUEST_SIGNATURE_MAX_AGE_SECS
            ));
        }
        if self.detached_request_signature_max_future_skew_secs
            > MAX_DETACHED_REQUEST_SIGNATURE_MAX_FUTURE_SKEW_SECS
        {
            return Err(format!(
                "detached_request_signature_max_future_skew_secs must be <= {}",
                MAX_DETACHED_REQUEST_SIGNATURE_MAX_FUTURE_SKEW_SECS
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_is_fail_closed() {
        let cfg = AcisConfig::default();
        assert!(cfg.emit_envelopes, "emit_envelopes must default to true");
        assert!(cfg.include_timing);
        assert!(cfg.include_findings);
        assert!(!cfg.require_session_id);
        assert!(!cfg.require_agent_identity);
        assert!(!cfg.require_verified_signature);
        assert!(cfg.trusted_request_signers.is_empty());
        assert_eq!(cfg.detached_request_signature_max_age_secs, 600);
        assert_eq!(cfg.detached_request_signature_max_future_skew_secs, 300);
        assert!(!cfg.require_workload_binding);
        assert!(!cfg.deny_replay);
        assert!(!cfg.block_tainted_privileged_sinks);
        assert!(!cfg.require_lineage_for_privileged_sinks);
        assert_eq!(cfg.default_transport, "stdio");
    }

    #[test]
    fn test_default_validates() {
        assert!(AcisConfig::default().validate().is_ok());
    }

    #[test]
    fn test_empty_transport_rejected() {
        let cfg = AcisConfig {
            default_transport: String::new(),
            ..AcisConfig::default()
        };
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("default_transport must not be empty"));
    }

    #[test]
    fn test_invalid_transport_rejected() {
        let cfg = AcisConfig {
            default_transport: "smoke_signal".into(),
            ..AcisConfig::default()
        };
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("must be one of"));
    }

    #[test]
    fn test_all_valid_transports_accepted() {
        for t in &["stdio", "http", "websocket", "grpc", "sse"] {
            let cfg = AcisConfig {
                default_transport: (*t).into(),
                ..AcisConfig::default()
            };
            assert!(cfg.validate().is_ok(), "transport '{t}' should be valid");
        }
    }

    #[test]
    fn test_dangerous_chars_in_tenant_id_rejected() {
        let cfg = AcisConfig {
            tenant_id: Some("tenant\x00id".into()),
            ..AcisConfig::default()
        };
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("tenant_id contains dangerous"));
    }

    #[test]
    fn test_empty_tenant_id_rejected() {
        let cfg = AcisConfig {
            tenant_id: Some(String::new()),
            ..AcisConfig::default()
        };
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("tenant_id must not be empty"));
    }

    #[test]
    fn test_too_many_finding_labels_rejected() {
        let cfg = AcisConfig {
            custom_finding_labels: vec!["label".into(); 65],
            ..AcisConfig::default()
        };
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("custom_finding_labels has 65"));
    }

    #[test]
    fn test_empty_finding_label_rejected() {
        let cfg = AcisConfig {
            custom_finding_labels: vec![String::new()],
            ..AcisConfig::default()
        };
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("custom_finding_labels[0] must not be empty"));
    }

    #[test]
    fn test_toml_roundtrip() {
        let cfg = AcisConfig {
            emit_envelopes: true,
            require_session_id: true,
            require_agent_identity: false,
            require_verified_signature: true,
            trusted_request_signers: vec![TrustedRequestSignerConfig {
                key_id: "client-key-1".into(),
                public_key: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                    .into(),
                session_key_scope: SessionKeyScope::EphemeralSession,
                execution_is_ephemeral: true,
                workload_identity: Some(WorkloadIdentity {
                    platform: Some("spiffe".into()),
                    workload_id: "spiffe://cluster/ns/prod/sa/api".into(),
                    namespace: Some("prod".into()),
                    service_account: Some("api".into()),
                    process_identity: None,
                    attestation_level: Some("jwt".into()),
                }),
            }],
            detached_request_signature_max_age_secs: 900,
            detached_request_signature_max_future_skew_secs: 120,
            require_workload_binding: true,
            require_ephemeral_client_provenance: true,
            deny_replay: true,
            block_tainted_privileged_sinks: true,
            require_lineage_for_privileged_sinks: true,
            containment_mode: Some(ContainmentMode::RequireApproval),
            include_timing: true,
            include_findings: true,
            default_transport: "http".into(),
            tenant_id: Some("acme-corp".into()),
            custom_finding_labels: vec!["siem-enrichment".into()],
        };
        let toml_str = toml::to_string(&cfg).expect("serialize");
        let decoded: AcisConfig = toml::from_str(&toml_str).expect("deserialize");
        assert_eq!(cfg, decoded);
    }

    #[test]
    fn test_invalid_trusted_request_signer_rejected() {
        let cfg = AcisConfig {
            trusted_request_signers: vec![TrustedRequestSignerConfig {
                key_id: "client-key-1".into(),
                public_key: "not-hex".into(),
                session_key_scope: SessionKeyScope::Unknown,
                execution_is_ephemeral: false,
                workload_identity: None,
            }],
            ..AcisConfig::default()
        };
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("trusted_request_signers.public_key invalid"));
    }

    #[test]
    fn test_trusted_request_signer_invalid_workload_identity_rejected() {
        let cfg = AcisConfig {
            trusted_request_signers: vec![TrustedRequestSignerConfig {
                key_id: "client-key-1".into(),
                public_key: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                    .into(),
                session_key_scope: SessionKeyScope::Unknown,
                execution_is_ephemeral: false,
                workload_identity: Some(WorkloadIdentity {
                    platform: Some("spiffe".into()),
                    workload_id: String::new(),
                    namespace: None,
                    service_account: None,
                    process_identity: None,
                    attestation_level: None,
                }),
            }],
            ..AcisConfig::default()
        };
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("trusted_request_signers.workload_identity invalid"));
    }

    #[test]
    fn test_trusted_request_signer_rejects_persisted_ephemeral_mismatch() {
        let cfg = AcisConfig {
            trusted_request_signers: vec![TrustedRequestSignerConfig {
                key_id: "client-key-1".into(),
                public_key: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                    .into(),
                session_key_scope: SessionKeyScope::PersistedClient,
                execution_is_ephemeral: true,
                workload_identity: None,
            }],
            ..AcisConfig::default()
        };
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("execution_is_ephemeral"));
    }

    #[test]
    fn test_trusted_request_signer_rejects_duplicate_key_ids() {
        let cfg = AcisConfig {
            trusted_request_signers: vec![
                TrustedRequestSignerConfig {
                    key_id: "client-key-1".into(),
                    public_key: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                        .into(),
                    session_key_scope: SessionKeyScope::Unknown,
                    execution_is_ephemeral: false,
                    workload_identity: None,
                },
                TrustedRequestSignerConfig {
                    key_id: "client-key-1".into(),
                    public_key: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
                        .into(),
                    session_key_scope: SessionKeyScope::Unknown,
                    execution_is_ephemeral: false,
                    workload_identity: None,
                },
            ],
            ..AcisConfig::default()
        };
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("duplicate key_id"));
    }

    #[test]
    fn test_trusted_request_signer_rejects_duplicate_public_keys() {
        let cfg = AcisConfig {
            trusted_request_signers: vec![
                TrustedRequestSignerConfig {
                    key_id: "client-key-1".into(),
                    public_key: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                        .into(),
                    session_key_scope: SessionKeyScope::Unknown,
                    execution_is_ephemeral: false,
                    workload_identity: None,
                },
                TrustedRequestSignerConfig {
                    key_id: "client-key-2".into(),
                    public_key: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                        .into(),
                    session_key_scope: SessionKeyScope::Unknown,
                    execution_is_ephemeral: false,
                    workload_identity: None,
                },
            ],
            ..AcisConfig::default()
        };
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("duplicate public_key"));
    }

    #[test]
    fn test_detached_request_signature_max_age_zero_rejected() {
        let cfg = AcisConfig {
            detached_request_signature_max_age_secs: 0,
            ..AcisConfig::default()
        };
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("detached_request_signature_max_age_secs"));
    }

    #[test]
    fn test_detached_request_signature_max_age_over_cap_rejected() {
        let cfg = AcisConfig {
            detached_request_signature_max_age_secs: MAX_DETACHED_REQUEST_SIGNATURE_MAX_AGE_SECS
                + 1,
            ..AcisConfig::default()
        };
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("detached_request_signature_max_age_secs"));
    }

    #[test]
    fn test_detached_request_signature_future_skew_over_cap_rejected() {
        let cfg = AcisConfig {
            detached_request_signature_max_future_skew_secs:
                MAX_DETACHED_REQUEST_SIGNATURE_MAX_FUTURE_SKEW_SECS + 1,
            ..AcisConfig::default()
        };
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("detached_request_signature_max_future_skew_secs"));
    }

    #[test]
    fn test_deny_unknown_fields() {
        let toml_str = r#"
            emit_envelopes = true
            evil_field = "pwned"
        "#;
        assert!(toml::from_str::<AcisConfig>(toml_str).is_err());
    }
}
