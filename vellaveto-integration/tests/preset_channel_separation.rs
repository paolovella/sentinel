// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Behavioral coverage for preset ACIS channel-separation defaults.

use serde_json::json;
use vellaveto_config::PolicyConfig;
use vellaveto_engine::PolicyEngine;
use vellaveto_mcp::mediation::{mediate_with_security_context, MediationConfig};
use vellaveto_types::acis::DecisionOrigin;
use vellaveto_types::{
    Action, ContainmentMode, ContextChannel, LineageRef, Policy, PolicyType,
    RuntimeSecurityContext, SemanticTaint, SinkClass, TrustTier, Verdict,
};

fn allow_policy() -> Policy {
    Policy {
        id: "*:*".to_string(),
        name: "Allow all for containment isolation".to_string(),
        policy_type: PolicyType::Allow,
        priority: 1,
        path_rules: None,
        network_rules: None,
    }
}

fn mediation_config(policy_config: &PolicyConfig) -> MediationConfig {
    MediationConfig {
        dlp_enabled: false,
        dlp_blocking: false,
        injection_enabled: false,
        injection_blocking: false,
        include_timing: policy_config.acis.include_timing,
        include_findings: policy_config.acis.include_findings,
        require_session_id: policy_config.acis.require_session_id,
        require_agent_identity: policy_config.acis.require_agent_identity,
        require_verified_signature: policy_config.acis.require_verified_signature,
        require_workload_binding: policy_config.acis.require_workload_binding,
        require_ephemeral_client_provenance: policy_config.acis.require_ephemeral_client_provenance,
        deny_replay: policy_config.acis.deny_replay,
        block_tainted_privileged_sinks: policy_config.acis.block_tainted_privileged_sinks,
        require_lineage_for_privileged_sinks: policy_config
            .acis
            .require_lineage_for_privileged_sinks,
        containment_mode: policy_config.acis.containment_mode,
    }
}

fn tainted_privileged_context() -> RuntimeSecurityContext {
    RuntimeSecurityContext {
        semantic_taint: vec![SemanticTaint::Untrusted],
        effective_trust_tier: Some(TrustTier::Untrusted),
        sink_class: Some(SinkClass::CodeExecution),
        lineage_refs: vec![LineageRef {
            id: "tool-output-1".into(),
            channel: ContextChannel::ToolOutput,
            content_hash: Some("abc123".into()),
            source: Some("untrusted-web-tool".into()),
            trust_tier: Some(TrustTier::Untrusted),
        }],
        ..RuntimeSecurityContext::default()
    }
}

fn privileged_action() -> Action {
    Action::new(
        "execute_command".to_string(),
        "run".to_string(),
        json!({"command": "deploy"}),
    )
}

fn parse_config(toml: &str) -> PolicyConfig {
    PolicyConfig::from_toml(toml).expect("preset TOML should parse")
}

fn assert_preset_verdict(
    preset_name: &str,
    toml: &str,
    expected_mode: ContainmentMode,
    expected_verdict: ExpectedVerdict,
) {
    let policy_config = parse_config(toml);
    assert!(policy_config.acis.block_tainted_privileged_sinks);
    assert_eq!(policy_config.acis.containment_mode, Some(expected_mode));

    let engine = PolicyEngine::with_policies(true, &[allow_policy()]).expect("engine");
    let security_context = tainted_privileged_context();
    let result = mediate_with_security_context(
        preset_name,
        &privileged_action(),
        &engine,
        None,
        Some(&security_context),
        "stdio",
        &mediation_config(&policy_config),
        Some("session-1"),
        None,
    );

    assert_eq!(result.envelope.containment_mode, Some(expected_mode));
    match expected_verdict {
        ExpectedVerdict::AllowObserved => {
            assert_eq!(result.verdict, Verdict::Allow);
            assert_eq!(result.origin, DecisionOrigin::PolicyEngine);
        }
        ExpectedVerdict::RequireApproval => {
            assert!(
                matches!(result.verdict, Verdict::RequireApproval { .. }),
                "{preset_name} should require approval, got {:?}",
                result.verdict
            );
            assert_eq!(result.origin, DecisionOrigin::SemanticContainment);
        }
        ExpectedVerdict::DenyContaining(fragment) => {
            let Verdict::Deny { reason } = result.verdict else {
                panic!("{preset_name} should deny, got {:?}", result.verdict);
            };
            assert!(
                reason.contains(fragment),
                "{preset_name} deny reason {reason:?} should contain {fragment:?}"
            );
            assert_eq!(result.origin, DecisionOrigin::SemanticContainment);
        }
    }
}

#[derive(Clone, Copy)]
enum ExpectedVerdict {
    AllowObserved,
    RequireApproval,
    DenyContaining(&'static str),
}

#[test]
fn shield_preset_gates_tainted_privileged_sink_with_approval() {
    for toml in [
        include_str!("../../vellaveto-proxy/presets/shield.toml"),
        include_str!("../../examples/presets/shield.toml"),
    ] {
        assert_preset_verdict(
            "shield",
            toml,
            ContainmentMode::RequireApproval,
            ExpectedVerdict::RequireApproval,
        );
    }
}

#[test]
fn fortress_preset_observes_tainted_privileged_sink_for_migration_window() {
    for toml in [
        include_str!("../../vellaveto-proxy/presets/fortress.toml"),
        include_str!("../../examples/presets/fortress.toml"),
    ] {
        assert_preset_verdict(
            "fortress",
            toml,
            ContainmentMode::Observe,
            ExpectedVerdict::AllowObserved,
        );
    }
}

#[test]
fn vault_preset_denies_tainted_privileged_sink() {
    for toml in [
        include_str!("../../vellaveto-proxy/presets/vault.toml"),
        include_str!("../../examples/presets/vault.toml"),
    ] {
        assert_preset_verdict(
            "vault",
            toml,
            ContainmentMode::Quarantine,
            ExpectedVerdict::DenyContaining("quarantine"),
        );
    }
}

#[test]
fn consumer_shield_preset_requires_sanitization_for_tainted_privileged_sink() {
    for toml in [
        include_str!("../../vellaveto-proxy/presets/consumer-shield.toml"),
        include_str!("../../examples/presets/consumer-shield.toml"),
    ] {
        assert_preset_verdict(
            "consumer-shield",
            toml,
            ContainmentMode::Sanitize,
            ExpectedVerdict::DenyContaining("sanitization"),
        );
    }
}

#[test]
fn every_shipped_example_preset_declares_acis_tainted_sink_guard() {
    for (name, toml) in [
        (
            "api-gateway-agent",
            include_str!("../../examples/presets/api-gateway-agent.toml"),
        ),
        (
            "browser-agent",
            include_str!("../../examples/presets/browser-agent.toml"),
        ),
        (
            "ci-agent",
            include_str!("../../examples/presets/ci-agent.toml"),
        ),
        (
            "code-review-agent",
            include_str!("../../examples/presets/code-review-agent.toml"),
        ),
        (
            "compliance-starter",
            include_str!("../../examples/presets/compliance-starter.toml"),
        ),
        (
            "consumer-shield",
            include_str!("../../examples/presets/consumer-shield.toml"),
        ),
        (
            "customer-support-agent",
            include_str!("../../examples/presets/customer-support-agent.toml"),
        ),
        (
            "data-science-agent",
            include_str!("../../examples/presets/data-science-agent.toml"),
        ),
        (
            "database-agent",
            include_str!("../../examples/presets/database-agent.toml"),
        ),
        (
            "dev-laptop",
            include_str!("../../examples/presets/dev-laptop.toml"),
        ),
        (
            "devops-agent",
            include_str!("../../examples/presets/devops-agent.toml"),
        ),
        (
            "financial-agent",
            include_str!("../../examples/presets/financial-agent.toml"),
        ),
        (
            "fortress",
            include_str!("../../examples/presets/fortress.toml"),
        ),
        (
            "healthcare-agent",
            include_str!("../../examples/presets/healthcare-agent.toml"),
        ),
        (
            "rag-agent",
            include_str!("../../examples/presets/rag-agent.toml"),
        ),
        (
            "sandworm-hardened",
            include_str!("../../examples/presets/sandworm-hardened.toml"),
        ),
        ("shield", include_str!("../../examples/presets/shield.toml")),
        ("vault", include_str!("../../examples/presets/vault.toml")),
    ] {
        let config = parse_config(toml);
        assert!(
            config.acis.block_tainted_privileged_sinks,
            "{name} must enable tainted privileged sink blocking"
        );
        assert!(
            config.acis.containment_mode.is_some(),
            "{name} must declare an ACIS containment mode"
        );
    }
}
