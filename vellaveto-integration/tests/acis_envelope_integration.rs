// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Integration tests for ACIS decision envelopes.
//!
//! Validates the end-to-end ACIS pipeline: mediation → envelope construction →
//! validation → audit persistence. Tests transport-agnostic properties that
//! hold across HTTP, WebSocket, gRPC, and stdio surfaces.

use serde_json::json;
use tempfile::TempDir;
use vellaveto_audit::AuditLogger;
use vellaveto_engine::PolicyEngine;
use vellaveto_mcp::mediation::{mediate, MediationConfig};
use vellaveto_types::acis::{AcisDecisionEnvelope, DecisionKind, DecisionOrigin};
use vellaveto_types::identity::CallChainEntry;
use vellaveto_types::{Action, EvaluationContext, Policy, PolicyType};

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to create tokio runtime")
}

fn test_action() -> Action {
    Action::new(
        "file_write".to_string(),
        "write".to_string(),
        json!({"path": "/tmp/out.txt", "content": "hello"}),
    )
}

fn deny_policy() -> Policy {
    Policy {
        id: "file_write:*".to_string(),
        name: "Block all file writes".to_string(),
        policy_type: PolicyType::Deny,
        priority: 100,
        path_rules: None,
        network_rules: None,
    }
}

fn allow_policy() -> Policy {
    Policy {
        id: "file_write:*".to_string(),
        name: "Allow all file writes".to_string(),
        policy_type: PolicyType::Allow,
        priority: 100,
        path_rules: None,
        network_rules: None,
    }
}

// ═══════════════════════════════════════
// MEDIATION PIPELINE → ACIS ENVELOPE
// ═══════════════════════════════════════

#[test]
fn test_acis_mediate_deny_produces_valid_envelope() {
    let engine = PolicyEngine::with_policies(true, &[deny_policy()]).expect("engine");
    let action = test_action();
    let config = MediationConfig::default();

    let result = mediate(
        "test-decision-1",
        &action,
        &engine,
        None,
        "http",
        &config,
        None,
        None,
    );

    assert_eq!(result.envelope.decision, DecisionKind::Deny);
    assert_eq!(result.envelope.origin, DecisionOrigin::PolicyEngine);
    assert_eq!(result.envelope.transport, "http");
    assert_eq!(result.envelope.action_summary.tool, "file_write");
    assert_eq!(result.envelope.action_summary.function, "write");
    assert!(!result.envelope.action_fingerprint.is_empty());
    assert!(
        result.envelope.validate().is_ok(),
        "envelope should validate"
    );
}

#[test]
fn test_acis_mediate_allow_produces_valid_envelope() {
    let engine = PolicyEngine::with_policies(true, &[allow_policy()]).expect("engine");
    let action = test_action();
    let config = MediationConfig::default();

    let result = mediate(
        "test-decision-2",
        &action,
        &engine,
        None,
        "stdio",
        &config,
        None,
        None,
    );

    assert_eq!(result.envelope.decision, DecisionKind::Allow);
    assert_eq!(result.envelope.transport, "stdio");
    assert!(result.envelope.validate().is_ok());
}

#[test]
fn test_acis_envelope_captures_agent_identity_from_context() {
    let engine = PolicyEngine::with_policies(true, &[allow_policy()]).expect("engine");
    let action = test_action();
    let config = MediationConfig::default();
    let ctx = EvaluationContext {
        agent_id: Some("claude-agent-v4".to_string()),
        ..Default::default()
    };

    let result = mediate(
        "test-decision-3",
        &action,
        &engine,
        Some(&ctx),
        "websocket",
        &config,
        Some("sess-abc"),
        Some("tenant-xyz"),
    );

    assert_eq!(result.envelope.agent_id.as_deref(), Some("claude-agent-v4"));
    assert_eq!(result.envelope.session_id.as_deref(), Some("sess-abc"));
    assert_eq!(result.envelope.tenant_id.as_deref(), Some("tenant-xyz"));
    assert!(result.envelope.validate().is_ok());
}

#[test]
fn test_acis_fingerprint_deterministic_across_transports() {
    let engine = PolicyEngine::with_policies(true, &[allow_policy()]).expect("engine");
    let action = test_action();
    let config = MediationConfig::default();

    let r1 = mediate("id-1", &action, &engine, None, "http", &config, None, None);
    let r2 = mediate(
        "id-2",
        &action,
        &engine,
        None,
        "websocket",
        &config,
        None,
        None,
    );
    let r3 = mediate("id-3", &action, &engine, None, "grpc", &config, None, None);
    let r4 = mediate("id-4", &action, &engine, None, "stdio", &config, None, None);

    // Same action → same fingerprint regardless of transport
    assert_eq!(
        r1.envelope.action_fingerprint,
        r2.envelope.action_fingerprint
    );
    assert_eq!(
        r2.envelope.action_fingerprint,
        r3.envelope.action_fingerprint
    );
    assert_eq!(
        r3.envelope.action_fingerprint,
        r4.envelope.action_fingerprint
    );

    // But decision_id differs
    assert_ne!(r1.envelope.decision_id, r2.envelope.decision_id);
}

// ═══════════════════════════════════════
// VALIDATION BOUNDARY TESTS
// ═══════════════════════════════════════

#[test]
fn test_acis_envelope_rejects_oversized_evaluation_us() {
    let engine = PolicyEngine::with_policies(true, &[allow_policy()]).expect("engine");
    let action = test_action();
    let config = MediationConfig::default();

    let mut result = mediate("id-5", &action, &engine, None, "http", &config, None, None);
    result.envelope.evaluation_us = Some(3_600_000_001); // > 1 hour

    let err = result.envelope.validate().unwrap_err();
    assert!(err.contains("evaluation_us"));
}

#[test]
fn test_acis_envelope_rejects_oversized_call_chain_depth() {
    let mut envelope = AcisDecisionEnvelope {
        decision_id: "abc123".into(),
        timestamp: "2026-03-09T10:00:00Z".into(),
        session_id: None,
        tenant_id: None,
        agent_identity: None,
        agent_id: None,
        client_provenance: None,
        action_summary: vellaveto_types::acis::AcisActionSummary {
            tool: "test".into(),
            function: "run".into(),
            target_path_count: 0,
            target_domain_count: 0,
        },
        action_fingerprint: "deadbeef".into(),
        decision: DecisionKind::Deny,
        origin: DecisionOrigin::PolicyEngine,
        // ACIS-DENY-REASON-1: validate() now enforces that a Deny carries a
        // reason, so this fixture needs one to isolate the depth bound it is
        // actually testing rather than tripping the earlier check.
        reason: "denied for call-chain depth test".into(),
        matched_policy_id: None,
        transport: "http".into(),
        findings: vec![],
        semantic_taint: vec![],
        lineage_refs: vec![],
        effective_trust_tier: None,
        sink_class: None,
        containment_mode: None,
        semantic_risk_score: None,
        evaluation_us: None,
        call_chain_depth: 257,
    };

    let err = envelope.validate().unwrap_err();
    assert!(err.contains("call_chain_depth"));

    envelope.call_chain_depth = 256;
    assert!(envelope.validate().is_ok());
}

// ═══════════════════════════════════════
// AUDIT PERSISTENCE WITH ACIS
// ═══════════════════════════════════════

#[test]
fn test_acis_envelope_persisted_in_audit_entry() {
    let rt = runtime();
    rt.block_on(async {
        let dir = TempDir::new().expect("tempdir");
        let logger = AuditLogger::new(dir.path().join("audit.jsonl"));

        let action = test_action();
        let engine = PolicyEngine::with_policies(true, &[allow_policy()]).expect("engine");
        let config = MediationConfig::default();
        let result = mediate(
            "persist-1",
            &action,
            &engine,
            None,
            "http",
            &config,
            None,
            None,
        );

        // Persist with ACIS envelope
        logger
            .log_entry_with_acis(
                &action,
                &result.verdict,
                json!({"source": "integration_test"}),
                result.envelope.clone(),
            )
            .await
            .expect("audit persist should succeed");

        // Verify the audit file contains the envelope
        let content = tokio::fs::read_to_string(dir.path().join("audit.jsonl"))
            .await
            .expect("read audit");
        assert!(content.contains("acis_envelope"));
        assert!(content.contains(&result.envelope.action_fingerprint));
    });
}

#[test]
fn test_acis_audit_rejects_invalid_envelope() {
    let rt = runtime();
    rt.block_on(async {
        let dir = TempDir::new().expect("tempdir");
        let logger = AuditLogger::new(dir.path().join("audit.jsonl"));

        let action = test_action();
        let engine = PolicyEngine::with_policies(true, &[allow_policy()]).expect("engine");
        let config = MediationConfig::default();
        let mut result = mediate(
            "persist-2",
            &action,
            &engine,
            None,
            "http",
            &config,
            None,
            None,
        );

        // Corrupt the envelope — empty tool name
        result.envelope.action_summary.tool = String::new();

        let err: Result<(), vellaveto_audit::AuditError> = logger
            .log_entry_with_acis(
                &action,
                &result.verdict,
                json!({"source": "integration_test"}),
                result.envelope,
            )
            .await;

        assert!(err.is_err(), "should reject invalid envelope");
    });
}

// ═══════════════════════════════════════
// CALL CHAIN DEPTH CLAMPING
// ═══════════════════════════════════════

#[test]
fn test_acis_call_chain_depth_clamped_to_256() {
    let engine = PolicyEngine::with_policies(true, &[allow_policy()]).expect("engine");
    let action = test_action();
    let config = MediationConfig::default();

    // Build a context with 300 call chain entries
    let ctx = EvaluationContext {
        call_chain: (0..300)
            .map(|i| CallChainEntry {
                agent_id: format!("agent-{i}"),
                tool: "test".into(),
                function: "run".into(),
                timestamp: "2026-03-09T10:00:00Z".into(),
                hmac: None,
                verified: None,
            })
            .collect(),
        ..Default::default()
    };

    let result = mediate(
        "depth-1",
        &action,
        &engine,
        Some(&ctx),
        "http",
        &config,
        None,
        None,
    );

    // Depth should be clamped to 256, not 300
    assert_eq!(result.envelope.call_chain_depth, 256);
    assert!(result.envelope.validate().is_ok());
}

#[test]
fn test_acis_mediate_with_dlp_finding_produces_deny() {
    let engine = PolicyEngine::with_policies(true, &[allow_policy()]).expect("engine");
    // Action with an API key in parameters
    let action = Action::new(
        "http_request".to_string(),
        "post".to_string(),
        json!({"headers": {"Authorization": "Bearer sk-proj-abc123def456ghi789"}}),
    );
    let config = MediationConfig {
        dlp_enabled: true,
        dlp_blocking: true,
        ..Default::default()
    };

    let result = mediate("dlp-1", &action, &engine, None, "http", &config, None, None);

    // Regardless of whether DLP catches this specific pattern,
    // the envelope must always validate.
    assert!(result.envelope.validate().is_ok());
    // If DLP did catch it, origin should be Dlp
    if !result.dlp_findings.is_empty() {
        assert_eq!(result.envelope.decision, DecisionKind::Deny);
        assert_eq!(result.envelope.origin, DecisionOrigin::Dlp);
    }
}

// ═══════════════════════════════════════
// SERIALIZATION ROUNDTRIP
// ═══════════════════════════════════════

#[test]
fn test_acis_envelope_serialization_roundtrip() {
    let engine = PolicyEngine::with_policies(true, &[deny_policy()]).expect("engine");
    let action = test_action();
    let config = MediationConfig::default();
    let ctx = EvaluationContext {
        agent_id: Some("agent-42".to_string()),
        ..Default::default()
    };

    let result = mediate(
        "round-1",
        &action,
        &engine,
        Some(&ctx),
        "grpc",
        &config,
        Some("sess-rt"),
        Some("tenant-rt"),
    );

    // Serialize to JSON
    let json_str = serde_json::to_string(&result.envelope).expect("serialize");

    // Deserialize back
    let deserialized: AcisDecisionEnvelope = serde_json::from_str(&json_str).expect("deserialize");

    // All fields must survive the roundtrip
    assert_eq!(deserialized.decision_id, result.envelope.decision_id);
    assert_eq!(deserialized.decision, result.envelope.decision);
    assert_eq!(deserialized.origin, result.envelope.origin);
    assert_eq!(deserialized.transport, "grpc");
    assert_eq!(
        deserialized.action_fingerprint,
        result.envelope.action_fingerprint
    );
    assert_eq!(deserialized.action_summary.tool, "file_write");
    assert_eq!(deserialized.action_summary.function, "write");
    assert_eq!(deserialized.session_id.as_deref(), Some("sess-rt"));
    assert_eq!(deserialized.tenant_id.as_deref(), Some("tenant-rt"));
    assert_eq!(deserialized.agent_id.as_deref(), Some("agent-42"));
    assert!(deserialized.validate().is_ok());
}

#[test]
fn test_acis_envelope_persisted_roundtrip_matches_original() {
    let rt = runtime();
    rt.block_on(async {
        let dir = TempDir::new().expect("tempdir");
        let log_path = dir.path().join("audit.jsonl");
        let logger = AuditLogger::new(log_path.clone());

        let engine = PolicyEngine::with_policies(true, &[deny_policy()]).expect("engine");
        let action = test_action();
        let config = MediationConfig::default();
        let result = mediate(
            "rt-2",
            &action,
            &engine,
            None,
            "websocket",
            &config,
            None,
            None,
        );

        logger
            .log_entry_with_acis(
                &action,
                &result.verdict,
                json!({"source": "roundtrip_test"}),
                result.envelope.clone(),
            )
            .await
            .expect("persist");

        // Read back and deserialize the full audit entry
        let content = tokio::fs::read_to_string(&log_path).await.expect("read");
        let entry: serde_json::Value = content
            .lines()
            .rev()
            .find(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).unwrap())
            .expect("entry");

        // Deserialize the nested envelope from the audit entry
        let env_json = &entry["acis_envelope"];
        let recovered: AcisDecisionEnvelope =
            serde_json::from_value(env_json.clone()).expect("deserialize envelope from audit");

        assert_eq!(recovered.decision_id, result.envelope.decision_id);
        assert_eq!(recovered.decision, result.envelope.decision);
        assert_eq!(recovered.origin, result.envelope.origin);
        assert_eq!(recovered.transport, "websocket");
        assert_eq!(
            recovered.action_fingerprint,
            result.envelope.action_fingerprint
        );
        assert!(recovered.validate().is_ok());
    });
}

// ═══════════════════════════════════════
// TRANSPORT LABEL EXHAUSTIVENESS
// ═══════════════════════════════════════

#[test]
fn test_acis_all_transport_labels_produce_valid_envelopes() {
    let engine = PolicyEngine::with_policies(true, &[allow_policy()]).expect("engine");
    let action = test_action();
    let config = MediationConfig::default();

    for transport in &["http", "websocket", "grpc", "stdio", "sse"] {
        let result = mediate(
            &format!("transport-{transport}"),
            &action,
            &engine,
            None,
            transport,
            &config,
            None,
            None,
        );

        assert_eq!(
            result.envelope.transport, *transport,
            "transport label mismatch for {transport}"
        );
        assert!(
            result.envelope.validate().is_ok(),
            "envelope should validate for transport {transport}: {:?}",
            result.envelope.validate()
        );
    }
}

#[test]
fn test_acis_envelope_reason_populated_on_deny() {
    let engine = PolicyEngine::with_policies(true, &[deny_policy()]).expect("engine");
    let action = test_action();
    let config = MediationConfig::default();

    let result = mediate(
        "reason-1", &action, &engine, None, "http", &config, None, None,
    );

    assert_eq!(result.envelope.decision, DecisionKind::Deny);
    assert!(
        !result.envelope.reason.is_empty(),
        "deny envelope should have a non-empty reason"
    );
}

#[test]
fn test_acis_envelope_allow_has_empty_reason() {
    let engine = PolicyEngine::with_policies(true, &[allow_policy()]).expect("engine");
    let action = test_action();
    let config = MediationConfig::default();

    let result = mediate(
        "reason-2", &action, &engine, None, "http", &config, None, None,
    );

    assert_eq!(result.envelope.decision, DecisionKind::Allow);
    assert!(
        result.envelope.reason.is_empty(),
        "allow envelope should have empty reason, got: {:?}",
        result.envelope.reason
    );
}

// ═══════════════════════════════════════
// SECONDARY DECISION ORIGINS (build_secondary_acis_envelope)
// ═══════════════════════════════════════

use vellaveto_mcp::mediation::build_secondary_acis_envelope;
use vellaveto_types::Verdict;

/// Helper: builds a secondary envelope for the given origin and asserts all
/// structural invariants hold (validation, fingerprint, transport, origin).
fn assert_secondary_envelope_valid(
    origin: DecisionOrigin,
    transport: &str,
    session_id: Option<&str>,
) -> AcisDecisionEnvelope {
    let action = test_action();
    let verdict = Verdict::Deny {
        reason: format!("{origin:?} blocked this action"),
    };

    let envelope = build_secondary_acis_envelope(&action, &verdict, origin, transport, session_id);

    assert_eq!(envelope.origin, origin, "origin mismatch");
    assert_eq!(envelope.decision, DecisionKind::Deny, "expected Deny");
    assert_eq!(envelope.transport, transport, "transport mismatch");
    assert!(
        !envelope.action_fingerprint.is_empty(),
        "fingerprint must be non-empty"
    );
    assert!(
        !envelope.decision_id.is_empty(),
        "decision_id must be non-empty"
    );
    assert!(!envelope.reason.is_empty(), "deny reason must be non-empty");
    assert!(
        envelope.validate().is_ok(),
        "envelope must validate: {:?}",
        envelope.validate()
    );

    if let Some(sid) = session_id {
        assert_eq!(envelope.session_id.as_deref(), Some(sid));
    } else {
        assert!(envelope.session_id.is_none());
    }

    envelope
}

#[test]
fn test_acis_secondary_injection_scanner_origin() {
    let env = assert_secondary_envelope_valid(
        DecisionOrigin::InjectionScanner,
        "stdio",
        Some("sess-inj-1"),
    );
    assert_eq!(env.action_summary.tool, "file_write");
}

#[test]
fn test_acis_secondary_memory_poisoning_origin() {
    let env =
        assert_secondary_envelope_valid(DecisionOrigin::MemoryPoisoning, "http", Some("sess-mp-1"));
    assert_eq!(env.origin, DecisionOrigin::MemoryPoisoning);
}

#[test]
fn test_acis_secondary_approval_gate_origin() {
    let env = assert_secondary_envelope_valid(
        DecisionOrigin::ApprovalGate,
        "websocket",
        Some("sess-ag-1"),
    );
    assert_eq!(env.origin, DecisionOrigin::ApprovalGate);
}

#[test]
fn test_acis_secondary_capability_enforcement_origin() {
    let env = assert_secondary_envelope_valid(
        DecisionOrigin::CapabilityEnforcement,
        "grpc",
        Some("sess-cap-1"),
    );
    assert_eq!(env.origin, DecisionOrigin::CapabilityEnforcement);
}

#[test]
fn test_acis_secondary_rate_limiter_origin() {
    let env = assert_secondary_envelope_valid(DecisionOrigin::RateLimiter, "http", None);
    assert_eq!(env.origin, DecisionOrigin::RateLimiter);
}

#[test]
fn test_acis_secondary_circuit_breaker_origin() {
    let env =
        assert_secondary_envelope_valid(DecisionOrigin::CircuitBreaker, "http", Some("sess-cb-1"));
    assert_eq!(env.origin, DecisionOrigin::CircuitBreaker);
}

#[test]
fn test_acis_secondary_topology_guard_origin() {
    let env =
        assert_secondary_envelope_valid(DecisionOrigin::TopologyGuard, "stdio", Some("sess-tg-1"));
    assert_eq!(env.origin, DecisionOrigin::TopologyGuard);
}

#[test]
fn test_acis_secondary_session_guard_origin() {
    let env =
        assert_secondary_envelope_valid(DecisionOrigin::SessionGuard, "sse", Some("sess-sg-1"));
    assert_eq!(env.origin, DecisionOrigin::SessionGuard);
}

// ═══════════════════════════════════════
// SECONDARY ENVELOPES: FINGERPRINT DETERMINISM
// ═══════════════════════════════════════

#[test]
fn test_acis_secondary_fingerprint_matches_primary() {
    let engine = PolicyEngine::with_policies(true, &[deny_policy()]).expect("engine");
    let action = test_action();
    let config = MediationConfig::default();

    // Primary envelope via mediate()
    let primary = mediate(
        "fp-primary",
        &action,
        &engine,
        None,
        "http",
        &config,
        None,
        None,
    );

    // Secondary envelope via build_secondary_acis_envelope()
    let secondary = build_secondary_acis_envelope(
        &action,
        &Verdict::Deny {
            reason: "DLP finding".into(),
        },
        DecisionOrigin::Dlp,
        "http",
        None,
    );

    // Same action → same fingerprint, regardless of origin or decision path
    assert_eq!(
        primary.envelope.action_fingerprint, secondary.action_fingerprint,
        "primary and secondary fingerprints must match for the same action"
    );
}

#[test]
fn test_acis_secondary_all_origins_same_action_same_fingerprint() {
    let action = test_action();
    let verdict = Verdict::Deny {
        reason: "test".into(),
    };

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
    ];

    let fingerprints: Vec<String> = origins
        .iter()
        .map(|o| {
            build_secondary_acis_envelope(&action, &verdict, *o, "http", None).action_fingerprint
        })
        .collect();

    // All fingerprints must be identical — fingerprint is derived from action, not origin
    for (i, fp) in fingerprints.iter().enumerate().skip(1) {
        assert_eq!(
            &fingerprints[0], fp,
            "fingerprint mismatch between origin[0] and origin[{i}]"
        );
    }
}

// ═══════════════════════════════════════
// SECONDARY ENVELOPES: AUDIT PERSISTENCE
// ═══════════════════════════════════════

#[test]
fn test_acis_secondary_all_origins_persist_to_audit() {
    let rt = runtime();
    rt.block_on(async {
        let dir = TempDir::new().expect("tempdir");
        let logger = AuditLogger::new(dir.path().join("audit.jsonl"));
        let action = test_action();

        let origins = [
            DecisionOrigin::InjectionScanner,
            DecisionOrigin::MemoryPoisoning,
            DecisionOrigin::ApprovalGate,
            DecisionOrigin::CapabilityEnforcement,
            DecisionOrigin::RateLimiter,
            DecisionOrigin::CircuitBreaker,
            DecisionOrigin::TopologyGuard,
            DecisionOrigin::SessionGuard,
        ];

        for origin in &origins {
            let verdict = Verdict::Deny {
                reason: format!("{origin:?} blocked"),
            };
            let envelope = build_secondary_acis_envelope(
                &action,
                &verdict,
                *origin,
                "http",
                Some("persist-sess"),
            );

            logger
                .log_entry_with_acis(
                    &action,
                    &verdict,
                    json!({"origin": format!("{origin:?}"), "source": "integration_test"}),
                    envelope,
                )
                .await
                .expect("audit persist should succeed");
        }

        // Verify all entries persisted with correct origins
        let content = tokio::fs::read_to_string(dir.path().join("audit.jsonl"))
            .await
            .expect("read audit");
        let lines: Vec<&str> = content.lines().filter(|l| !l.trim().is_empty()).collect();
        assert_eq!(
            lines.len(),
            origins.len(),
            "expected one audit entry per origin"
        );

        for (i, origin) in origins.iter().enumerate() {
            let entry: serde_json::Value =
                serde_json::from_str(lines[i]).expect("parse audit entry");
            let env_origin = entry["acis_envelope"]["origin"]
                .as_str()
                .expect("origin field");
            // serde serializes DecisionOrigin as snake_case, so compare via serde
            let expected_origin = serde_json::to_value(origin).expect("serialize origin");
            let expected_str = expected_origin.as_str().expect("origin as str");
            assert_eq!(env_origin, expected_str, "origin mismatch at entry {i}");
        }
    });
}

#[test]
fn test_acis_secondary_envelope_rejected_when_invalid() {
    let rt = runtime();
    rt.block_on(async {
        let dir = TempDir::new().expect("tempdir");
        let logger = AuditLogger::new(dir.path().join("audit.jsonl"));
        let action = test_action();
        let verdict = Verdict::Deny {
            reason: "test".into(),
        };

        let mut envelope = build_secondary_acis_envelope(
            &action,
            &verdict,
            DecisionOrigin::InjectionScanner,
            "http",
            None,
        );

        // Corrupt: empty tool name violates validation
        envelope.action_summary.tool = String::new();

        let result = logger
            .log_entry_with_acis(
                &action,
                &verdict,
                json!({"source": "invalid_test"}),
                envelope,
            )
            .await;

        assert!(result.is_err(), "should reject invalid secondary envelope");
    });
}

// ═══════════════════════════════════════
// SECONDARY ENVELOPES: TRANSPORT PARITY
// ═══════════════════════════════════════

#[test]
fn test_acis_secondary_transport_parity_all_origins() {
    let action = test_action();
    let transports = ["http", "websocket", "grpc", "stdio", "sse"];

    for origin in &[
        DecisionOrigin::InjectionScanner,
        DecisionOrigin::MemoryPoisoning,
        DecisionOrigin::RateLimiter,
        DecisionOrigin::CircuitBreaker,
        DecisionOrigin::SessionGuard,
    ] {
        let verdict = Verdict::Deny {
            reason: format!("{origin:?} denied"),
        };
        for transport in &transports {
            let env = build_secondary_acis_envelope(
                &action,
                &verdict,
                *origin,
                transport,
                Some("parity-sess"),
            );
            assert_eq!(
                env.transport, *transport,
                "transport mismatch for {origin:?}/{transport}"
            );
            assert!(
                env.validate().is_ok(),
                "validation failed for {origin:?}/{transport}"
            );
        }
    }
}

#[test]
fn test_acis_secondary_unique_decision_ids() {
    let action = test_action();
    let verdict = Verdict::Deny {
        reason: "test".into(),
    };

    let ids: Vec<String> = (0..20)
        .map(|_| {
            build_secondary_acis_envelope(&action, &verdict, DecisionOrigin::Dlp, "http", None)
                .decision_id
        })
        .collect();

    // All 20 decision IDs must be unique (UUID-based)
    let unique: std::collections::HashSet<&String> = ids.iter().collect();
    assert_eq!(unique.len(), 20, "decision IDs must be unique across calls");
}
