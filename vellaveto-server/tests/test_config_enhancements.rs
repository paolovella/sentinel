// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Tests for the enhanced vellaveto-config crate:
//! from_toml, load_file, to_policies, priority/id defaults.

use serde_json::json;
use tempfile::TempDir;
use vellaveto_config::{PolicyConfig, PolicyRule};
use vellaveto_types::PolicyType;

// ═════════════════════════════
// from_toml BASIC PARSING
// ═════════════════════════════

#[test]
fn from_toml_parses_allow_policy() {
    let toml_str = r#"
[[policies]]
name = "test"
tool_pattern = "file"
function_pattern = "read"
policy_type = "Allow"
"#;
    let config = PolicyConfig::from_toml(toml_str).unwrap();
    assert_eq!(config.policies.len(), 1);
    assert_eq!(config.policies[0].name, "test");
    assert!(matches!(config.policies[0].policy_type, PolicyType::Allow));
}

#[test]
fn from_toml_parses_deny_policy() {
    let toml_str = r#"
[[policies]]
name = "block"
tool_pattern = "bash"
function_pattern = "*"
policy_type = "Deny"
"#;
    let config = PolicyConfig::from_toml(toml_str).unwrap();
    assert!(matches!(config.policies[0].policy_type, PolicyType::Deny));
}

#[test]
fn from_toml_parses_conditional_policy() {
    let toml_str = r#"
[[policies]]
name = "conditional"
tool_pattern = "net"
function_pattern = "*"
priority = 50

[policies.policy_type.Conditional]
conditions = { require_approval = true }
"#;
    let config = PolicyConfig::from_toml(toml_str).unwrap();
    assert_eq!(config.policies.len(), 1);
    match &config.policies[0].policy_type {
        PolicyType::Conditional { conditions } => {
            assert_eq!(conditions.get("require_approval").unwrap(), true);
        }
        other => panic!("Expected Conditional, got {other:?}"),
    }
}

// ═════════════════════════════
// PRIORITY AND ID DEFAULTS
// ════════════════════════════

#[test]
fn priority_defaults_to_zero_when_omitted() {
    // SECURITY (R19-CFG-1): Default priority is 0 (lowest) so that
    // omitting priority makes policies match last.
    let toml_str = r#"
[[policies]]
name = "no priority"
tool_pattern = "file"
function_pattern = "read"
policy_type = "Allow"
"#;
    let config = PolicyConfig::from_toml(toml_str).unwrap();
    let rule = &config.policies[0];
    assert_eq!(
        rule.effective_priority(),
        0,
        "Default priority should be 0 (lowest)"
    );
}

#[test]
fn explicit_priority_is_respected() {
    let toml_str = r#"
[[policies]]
name = "custom priority"
tool_pattern = "file"
function_pattern = "read"
policy_type = "Allow"
priority = 42
"#;
    let config = PolicyConfig::from_toml(toml_str).unwrap();
    assert_eq!(config.policies[0].effective_priority(), 42);
}

#[test]
fn id_defaults_to_tool_colon_function() {
    let toml_str = r#"
[[policies]]
name = "no id"
tool_pattern = "bash"
function_pattern = "execute"
policy_type = "Deny"
"#;
    let config = PolicyConfig::from_toml(toml_str).unwrap();
    assert_eq!(config.policies[0].effective_id(), "bash:execute");
}

#[test]
fn explicit_id_overrides_default() {
    let toml_str = r#"
[[policies]]
name = "custom id"
tool_pattern = "bash"
function_pattern = "execute"
policy_type = "Deny"
id = "my-custom-id"
"#;
    let config = PolicyConfig::from_toml(toml_str).unwrap();
    assert_eq!(config.policies[0].effective_id(), "my-custom-id");
}

// ═════════════════════════════
// to_policies CONVERSION
// ═════════════════════════════

#[test]
fn to_policies_produces_correct_policy_structs() {
    let config = PolicyConfig {
        policies: vec![PolicyRule {
            name: "test rule".to_string(),
            tool_pattern: "file".to_string(),
            function_pattern: "delete".to_string(),
            policy_type: PolicyType::Deny,
            priority: Some(200),
            id: None,
            path_rules: None,
            network_rules: None,
        }],
        injection: Default::default(),
        dlp: Default::default(),
        multimodal: Default::default(),
        rate_limit: Default::default(),
        audit: Default::default(),
        supply_chain: Default::default(),
        manifest: Default::default(),
        memory_tracking: Default::default(),
        elicitation: Default::default(),
        sampling: Default::default(),
        audit_export: Default::default(),
        max_path_decode_iterations: None,
        known_tool_names: vec![],
        tool_registry: Default::default(),
        allowed_origins: Default::default(),
        behavioral: Default::default(),
        data_flow: Default::default(),
        semantic_detection: Default::default(),
        cluster: Default::default(),
        async_tasks: Default::default(),
        resource_indicator: Default::default(),
        cimd: Default::default(),
        step_up_auth: Default::default(),
        circuit_breaker: Default::default(),
        deputy: Default::default(),
        shadow_agent: Default::default(),
        schema_poisoning: Default::default(),
        sampling_detection: Default::default(),
        cross_agent: Default::default(),
        advanced_threat: Default::default(),
        tls: Default::default(),
        spiffe: Default::default(),
        opa: Default::default(),
        threat_intel: Default::default(),
        etdi: Default::default(),
        jit_access: Default::default(),
        memory_security: Default::default(),
        nhi: Default::default(),
        semantic_guardrails: Default::default(),
        rag_defense: Default::default(),
        a2a: Default::default(),
        observability: Default::default(),
        metrics_require_auth: true,
        limits: Default::default(),
        compliance: Default::default(),
        extension: Default::default(),
        transport: Default::default(),
        gateway: Default::default(),
        abac: Default::default(),
        fips: Default::default(),
        governance: Default::default(),
        deployment: Default::default(),
        streamable_http: Default::default(),
        discovery: Default::default(),
        projector: Default::default(),
        zk_audit: Default::default(),
        licensing: Default::default(),
        iam: Default::default(),
        billing: Default::default(),
        audit_store: Default::default(),
        policy_lifecycle: Default::default(),
        metering: Default::default(),
        topology: Default::default(),
        shield: Default::default(),
        acis: Default::default(),
        tool_quotas: Default::default(),
        secret_substitutions: Default::default(),
        policy_templates: Default::default(),
        source_trust: Default::default(),
        sink_classification: Default::default(),
        intent_scope: Default::default(),
    };
    let policies = config.to_policies();
    assert_eq!(policies.len(), 1);
    assert_eq!(policies[0].id, "file:delete");
    assert_eq!(policies[0].name, "test rule");
    assert_eq!(policies[0].priority, 200);
    assert!(matches!(policies[0].policy_type, PolicyType::Deny));
}

#[test]
fn to_policies_uses_default_priority_when_none() {
    // SECURITY (R19-CFG-1): Default priority is 0 (lowest)
    let config = PolicyConfig {
        policies: vec![PolicyRule {
            name: "test".to_string(),
            tool_pattern: "a".to_string(),
            function_pattern: "b".to_string(),
            policy_type: PolicyType::Allow,
            priority: None,
            id: None,
            path_rules: None,
            network_rules: None,
        }],
        injection: Default::default(),
        dlp: Default::default(),
        multimodal: Default::default(),
        rate_limit: Default::default(),
        audit: Default::default(),
        supply_chain: Default::default(),
        manifest: Default::default(),
        memory_tracking: Default::default(),
        elicitation: Default::default(),
        sampling: Default::default(),
        audit_export: Default::default(),
        max_path_decode_iterations: None,
        known_tool_names: vec![],
        tool_registry: Default::default(),
        allowed_origins: Default::default(),
        behavioral: Default::default(),
        data_flow: Default::default(),
        semantic_detection: Default::default(),
        cluster: Default::default(),
        async_tasks: Default::default(),
        resource_indicator: Default::default(),
        cimd: Default::default(),
        step_up_auth: Default::default(),
        circuit_breaker: Default::default(),
        deputy: Default::default(),
        shadow_agent: Default::default(),
        schema_poisoning: Default::default(),
        sampling_detection: Default::default(),
        cross_agent: Default::default(),
        advanced_threat: Default::default(),
        tls: Default::default(),
        spiffe: Default::default(),
        opa: Default::default(),
        threat_intel: Default::default(),
        etdi: Default::default(),
        jit_access: Default::default(),
        memory_security: Default::default(),
        nhi: Default::default(),
        semantic_guardrails: Default::default(),
        rag_defense: Default::default(),
        a2a: Default::default(),
        observability: Default::default(),
        metrics_require_auth: true,
        limits: Default::default(),
        compliance: Default::default(),
        extension: Default::default(),
        transport: Default::default(),
        gateway: Default::default(),
        abac: Default::default(),
        fips: Default::default(),
        governance: Default::default(),
        deployment: Default::default(),
        streamable_http: Default::default(),
        discovery: Default::default(),
        projector: Default::default(),
        zk_audit: Default::default(),
        licensing: Default::default(),
        iam: Default::default(),
        billing: Default::default(),
        audit_store: Default::default(),
        policy_lifecycle: Default::default(),
        metering: Default::default(),
        topology: Default::default(),
        shield: Default::default(),
        acis: Default::default(),
        tool_quotas: Default::default(),
        secret_substitutions: Default::default(),
        policy_templates: Default::default(),
        source_trust: Default::default(),
        sink_classification: Default::default(),
        intent_scope: Default::default(),
    };
    let policies = config.to_policies();
    assert_eq!(
        policies[0].priority, 0,
        "None priority should default to 0 (lowest)"
    );
}

#[test]
fn to_policies_roundtrip_through_engine() {
    // Config → Policies → Engine evaluation
    let config = PolicyConfig::from_toml(
        r#"
[[policies]]
name = "Block bash"
tool_pattern = "bash"
function_pattern = "*"
policy_type = "Deny"
priority = 500
id = "bash:*"

[[policies]]
name = "Allow all"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Allow"
priority = 1
"#,
    )
    .unwrap();

    let policies = config.to_policies();
    let engine = vellaveto_engine::PolicyEngine::new(false);

    let action = vellaveto_types::Action::new("bash".to_string(), "execute".to_string(), json!({}));
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(verdict, vellaveto_types::Verdict::Deny { .. }),
        "bash:execute should be denied. Got: {verdict:?}"
    );

    let safe_action =
        vellaveto_types::Action::new("file".to_string(), "read".to_string(), json!({}));
    let verdict = engine.evaluate_action(&safe_action, &policies).unwrap();
    assert!(
        matches!(verdict, vellaveto_types::Verdict::Allow),
        "file:read should be allowed. Got: {verdict:?}"
    );
}

// ═════════════════════════════
// load_file
// ════════════════════════════

#[test]
fn load_file_toml_extension() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("config.toml");
    std::fs::write(
        &path,
        r#"
[[policies]]
name = "test"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Allow"
"#,
    )
    .unwrap();

    let config = PolicyConfig::load_file(path.to_str().unwrap()).unwrap();
    assert_eq!(config.policies.len(), 1);
}

#[test]
fn load_file_json_extension() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("config.json");
    std::fs::write(&path, r#"{"policies": [{"name": "test", "tool_pattern": "*", "function_pattern": "*", "policy_type": "Allow"}]}"#).unwrap();

    let config = PolicyConfig::load_file(path.to_str().unwrap()).unwrap();
    assert_eq!(config.policies.len(), 1);
}

#[test]
fn load_file_nonexistent_returns_error() {
    let result = PolicyConfig::load_file("/no/such/file.toml");
    assert!(result.is_err());
}

// SECURITY (FIND-R46-014): Unknown extension now returns an error.
#[test]
fn load_file_unknown_extension_returns_error() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("config.yaml"); // .yaml extension but TOML content
    std::fs::write(
        &path,
        r#"
[[policies]]
name = "test"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Allow"
"#,
    )
    .unwrap();

    let result = PolicyConfig::load_file(path.to_str().unwrap());
    assert!(result.is_err(), "Unknown extension should be rejected");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("unsupported extension"),
        "Error should mention unsupported extension, got: {err}"
    );
}

// ═════════════════════════════
// TOML SERIALIZATION ROUNDTRIP
// ═════════════════════════════

#[test]
fn policy_config_toml_roundtrip() {
    let original = PolicyConfig {
        policies: vec![PolicyRule {
            name: "test".to_string(),
            tool_pattern: "file".to_string(),
            function_pattern: "read".to_string(),
            policy_type: PolicyType::Allow,
            priority: Some(50),
            id: Some("file:read".to_string()),
            path_rules: None,
            network_rules: None,
        }],
        injection: Default::default(),
        dlp: Default::default(),
        multimodal: Default::default(),
        rate_limit: Default::default(),
        audit: Default::default(),
        supply_chain: Default::default(),
        manifest: Default::default(),
        memory_tracking: Default::default(),
        elicitation: Default::default(),
        sampling: Default::default(),
        audit_export: Default::default(),
        max_path_decode_iterations: None,
        known_tool_names: vec![],
        tool_registry: Default::default(),
        allowed_origins: Default::default(),
        behavioral: Default::default(),
        data_flow: Default::default(),
        semantic_detection: Default::default(),
        cluster: Default::default(),
        async_tasks: Default::default(),
        resource_indicator: Default::default(),
        cimd: Default::default(),
        step_up_auth: Default::default(),
        circuit_breaker: Default::default(),
        deputy: Default::default(),
        shadow_agent: Default::default(),
        schema_poisoning: Default::default(),
        sampling_detection: Default::default(),
        cross_agent: Default::default(),
        advanced_threat: Default::default(),
        tls: Default::default(),
        spiffe: Default::default(),
        opa: Default::default(),
        threat_intel: Default::default(),
        etdi: Default::default(),
        jit_access: Default::default(),
        memory_security: Default::default(),
        nhi: Default::default(),
        semantic_guardrails: Default::default(),
        rag_defense: Default::default(),
        a2a: Default::default(),
        observability: Default::default(),
        metrics_require_auth: true,
        limits: Default::default(),
        compliance: Default::default(),
        extension: Default::default(),
        transport: Default::default(),
        gateway: Default::default(),
        abac: Default::default(),
        fips: Default::default(),
        governance: Default::default(),
        deployment: Default::default(),
        streamable_http: Default::default(),
        discovery: Default::default(),
        projector: Default::default(),
        zk_audit: Default::default(),
        licensing: Default::default(),
        iam: Default::default(),
        billing: Default::default(),
        audit_store: Default::default(),
        policy_lifecycle: Default::default(),
        metering: Default::default(),
        topology: Default::default(),
        shield: Default::default(),
        acis: Default::default(),
        tool_quotas: Default::default(),
        secret_substitutions: Default::default(),
        policy_templates: Default::default(),
        source_trust: Default::default(),
        sink_classification: Default::default(),
        intent_scope: Default::default(),
    };
    let toml_str = toml::to_string(&original).unwrap();
    let parsed = PolicyConfig::from_toml(&toml_str).unwrap();
    assert_eq!(parsed.policies.len(), 1);
    assert_eq!(parsed.policies[0].name, "test");
    assert_eq!(parsed.policies[0].effective_priority(), 50);
}

// ═════════════════════════════
// EDGE CASES / ADVERSARIAL
// ═════════════════════════════

#[test]
fn toml_with_missing_required_fields_fails() {
    let bad_toml = r#"
[[policies]]
name = "incomplete"
"#;
    let result = PolicyConfig::from_toml(bad_toml);
    assert!(
        result.is_err(),
        "Missing tool_pattern/function_pattern/policy_type should fail"
    );
}

#[test]
fn toml_with_empty_policies_array() {
    let toml_str = "policies = []\n";
    let config = PolicyConfig::from_toml(toml_str).unwrap();
    assert!(config.policies.is_empty());
    assert!(config.to_policies().is_empty());
}

#[test]
fn toml_multiple_conditional_policies() {
    // Test that multiple policies with mixed types parse correctly in TOML.
    // This is tricky because TOML's [[policies]] + inline tables can be finicky.
    let toml_str = r#"
[[policies]]
name = "allow reads"
tool_pattern = "file"
function_pattern = "read"
policy_type = "Allow"

[[policies]]
name = "deny deletes"
tool_pattern = "file"
function_pattern = "delete"
policy_type = "Deny"
priority = 200
"#;
    let config = PolicyConfig::from_toml(toml_str).unwrap();
    assert_eq!(config.policies.len(), 2);
    assert!(matches!(config.policies[0].policy_type, PolicyType::Allow));
    assert!(matches!(config.policies[1].policy_type, PolicyType::Deny));
}
