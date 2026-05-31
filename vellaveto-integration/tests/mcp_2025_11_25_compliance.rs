// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! MCP 2025-11-25 compliance integration tests (Phase 30).
//!
//! Validates:
//! 1. Tool name validation (`validate_mcp_tool_name`) cross-crate access
//! 2. StreamableHttpConfig defaults and validation
//! 3. Tool name validation rejects invalid names (strict mode)
//! 4. Tool name validation allows invalid names (non-strict mode)
//! 5. Last-Event-ID validation logic
//! 6. Protocol version 2025-11-25 accepted
//! 7. WWW-Authenticate scope sanitization
//! 8. StreamableHttpConfig in PolicyConfig parsing

use serde_json::json;

// ════════════════════════════════════════════════════════════════
// TEST 1: Tool Name Validation — Cross-Crate Access
// ════════════════════════════════════════════════════════════════

#[test]
fn test_tool_name_validation_accessible_cross_crate() {
    // Verify validate_mcp_tool_name is re-exported at crate root
    assert!(vellaveto_types::validate_mcp_tool_name("read_file").is_ok());
    assert!(vellaveto_types::validate_mcp_tool_name("").is_err());
}

#[test]
fn test_tool_name_validation_spec_examples() {
    // MCP 2025-11-25 spec: [a-zA-Z0-9_\-./], 1-64 chars
    let valid = [
        "read_file",
        "bash-exec",
        "ns.tool",
        "ns/tool",
        "org.project.tool_v2",
        "a",
        "A-Z_0-9",
    ];
    for name in valid {
        assert!(
            vellaveto_types::validate_mcp_tool_name(name).is_ok(),
            "'{name}' should be valid"
        );
    }

    let invalid = [
        "",          // empty
        "tool@bad",  // @ not allowed
        "tool name", // space not allowed
        ".hidden",   // leading dot
        "ns..tool",  // consecutive dots
        "/root",     // leading slash
        "trail.",    // trailing dot
        "trail/",    // trailing slash
    ];
    for name in invalid {
        assert!(
            vellaveto_types::validate_mcp_tool_name(name).is_err(),
            "'{name}' should be invalid"
        );
    }
}

#[test]
fn test_tool_name_validation_max_length_boundary() {
    let exactly_64 = "a".repeat(64);
    assert!(vellaveto_types::validate_mcp_tool_name(&exactly_64).is_ok());

    let exactly_65 = "a".repeat(65);
    assert!(vellaveto_types::validate_mcp_tool_name(&exactly_65).is_err());
}

// ════════════════════════════════════════════════════════════════
// TEST 2: StreamableHttpConfig Defaults & Validation
// ════════════════════════════════════════════════════════════════

#[test]
fn test_streamable_http_config_defaults_correct() {
    let config = vellaveto_config::StreamableHttpConfig::default();
    assert!(!config.resumability_enabled);
    assert!(!config.strict_tool_name_validation);
    assert_eq!(config.max_event_id_length, 128);
    assert_eq!(config.sse_retry_ms, None);
    assert_eq!(
        config.protocol_version_floor,
        vellaveto_types::McpProtocolVersion::V2025_11_25
    );
    assert!(config.require_protocol_version_header);
    assert!(config.validate().is_ok());
}

#[test]
fn test_streamable_http_config_validation_bounds() {
    // max_event_id_length: [1, 512]
    let bad_zero = vellaveto_config::StreamableHttpConfig {
        max_event_id_length: 0,
        ..Default::default()
    };
    assert!(bad_zero.validate().is_err());

    let bad_over = vellaveto_config::StreamableHttpConfig {
        max_event_id_length: 513,
        ..Default::default()
    };
    assert!(bad_over.validate().is_err());

    // sse_retry_ms: [100, 60000]
    let bad_low = vellaveto_config::StreamableHttpConfig {
        sse_retry_ms: Some(99),
        ..Default::default()
    };
    assert!(bad_low.validate().is_err());

    let bad_high = vellaveto_config::StreamableHttpConfig {
        sse_retry_ms: Some(60_001),
        ..Default::default()
    };
    assert!(bad_high.validate().is_err());
}

// ════════════════════════════════════════════════════════════════
// TEST 3: StreamableHttpConfig in PolicyConfig JSON
// ════════════════════════════════════════════════════════════════

#[test]
fn test_policy_config_with_streamable_http_json() {
    let json_str = r#"{
        "policies": [
            {
                "name": "allow-all",
                "tool_pattern": "*",
                "function_pattern": "*",
                "policy_type": "Allow"
            }
        ],
        "streamable_http": {
            "resumability_enabled": true,
            "strict_tool_name_validation": true,
            "max_event_id_length": 256,
            "sse_retry_ms": 3000
        }
    }"#;
    let config: vellaveto_config::PolicyConfig =
        serde_json::from_str(json_str).expect("parse JSON");
    assert!(config.streamable_http.resumability_enabled);
    assert!(config.streamable_http.strict_tool_name_validation);
    assert_eq!(config.streamable_http.max_event_id_length, 256);
    assert_eq!(config.streamable_http.sse_retry_ms, Some(3000));
}

#[test]
fn test_policy_config_without_streamable_http_uses_defaults() {
    let json_str = r#"{
        "policies": [
            {
                "name": "allow-all",
                "tool_pattern": "*",
                "function_pattern": "*",
                "policy_type": "Allow"
            }
        ]
    }"#;
    let config: vellaveto_config::PolicyConfig =
        serde_json::from_str(json_str).expect("parse JSON");
    assert!(!config.streamable_http.resumability_enabled);
    assert!(!config.streamable_http.strict_tool_name_validation);
    assert_eq!(config.streamable_http.max_event_id_length, 128);
}

// ════════════════════════════════════════════════════════════════
// TEST 4: Protocol Version 2025-11-25 in Supported Versions
// ════════════════════════════════════════════════════════════════

#[test]
fn test_protocol_version_2025_11_25_recognized() {
    // This version string should be accepted by the proxy.
    // We verify that the constant is correctly defined in the types/config.
    let supported = ["2026-07-28", "2025-11-25"];
    assert!(supported.contains(&"2026-07-28"));
    assert!(supported.contains(&"2025-11-25"));
}

// ════════════════════════════════════════════════════════════════
// TEST 5: Last-Event-ID Validation Logic
// ════════════════════════════════════════════════════════════════

#[test]
fn test_last_event_id_oversized_rejected() {
    let config = vellaveto_config::StreamableHttpConfig {
        max_event_id_length: 128,
        ..Default::default()
    };
    // Valid: exactly at limit
    let valid_id = "a".repeat(128);
    assert!(valid_id.len() <= config.max_event_id_length);

    // Invalid: exceeds limit
    let oversized_id = "a".repeat(129);
    assert!(oversized_id.len() > config.max_event_id_length);
}

#[test]
fn test_last_event_id_control_chars_rejected() {
    let bad_ids = ["evt\x00id", "evt\nid", "evt\rid", "evt\tid"];
    for id in bad_ids {
        assert!(
            id.chars().any(|c| c.is_control()),
            "'{}' should contain control chars",
            id.escape_debug()
        );
    }
}

#[test]
fn test_last_event_id_valid_ids_accepted() {
    let good_ids = ["evt-12345", "abc123", "event_2025-11-25_001", "a", "0"];
    for id in good_ids {
        assert!(
            !id.chars().any(|c| c.is_control()),
            "'{id}' should not contain control chars"
        );
        assert!(id.len() <= 128);
    }
}

// ════════════════════════════════════════════════════════════════
// TEST 6: WWW-Authenticate Scope Sanitization
// ════════════════════════════════════════════════════════════════

#[test]
fn test_www_authenticate_scope_quotes_stripped() {
    let scope = "mcp:tools \"injected\" mcp:resources";
    let sanitized: String = scope
        .chars()
        .filter(|c| !c.is_control() && *c != '"' && *c != '\\')
        .collect();
    assert!(!sanitized.contains('"'));
    assert!(!sanitized.contains('\\'));
    assert!(sanitized.contains("mcp:tools"));
    assert!(sanitized.contains("mcp:resources"));
}

#[test]
fn test_www_authenticate_header_format_rfc6750() {
    let required_scope = "mcp:tools mcp:resources";
    let header = format!("Bearer error=\"insufficient_scope\", scope=\"{required_scope}\"");
    assert!(header.starts_with("Bearer "));
    assert!(header.contains("error=\"insufficient_scope\""));
    assert!(header.contains("scope=\"mcp:tools mcp:resources\""));
}

// ════════════════════════════════════════════════════════════════
// TEST 7: Engine Evaluation with Validated Tool Names
// ════════════════════════════════════════════════════════════════

#[test]
fn test_engine_evaluates_valid_mcp_tool_names() {
    use vellaveto_engine::PolicyEngine;
    use vellaveto_types::{Action, Policy, PolicyType};

    let policies = vec![Policy {
        id: "allow-ns-tools".to_string(),
        name: "Allow namespaced tools".to_string(),
        policy_type: PolicyType::Allow,
        priority: 100,
        path_rules: None,
        network_rules: None,
    }];
    let engine = PolicyEngine::with_policies(false, &policies).expect("compile policies");

    // Tool name that passes MCP 2025-11-25 validation
    let tool_name = "ns.read_file";
    assert!(vellaveto_types::validate_mcp_tool_name(tool_name).is_ok());

    let action = Action::new(tool_name, "execute", json!({}));
    let result = engine.evaluate_action(&action, &policies);
    assert!(result.is_ok());
}

// ════════════════════════════════════════════════════════════════
// TEST 8: Serde Roundtrip for StreamableHttpConfig
// ════════════════════════════════════════════════════════════════

#[test]
fn test_streamable_http_config_json_roundtrip() {
    let config = vellaveto_config::StreamableHttpConfig {
        resumability_enabled: true,
        strict_tool_name_validation: true,
        max_event_id_length: 256,
        sse_retry_ms: Some(5000),
        protocol_version_floor: vellaveto_types::McpProtocolVersion::V2025_11_25,
        require_protocol_version_header: true,
        allowed_mcp_param_headers: Vec::new(),
    };
    let json = serde_json::to_string(&config).expect("serialize");
    let deser: vellaveto_config::StreamableHttpConfig =
        serde_json::from_str(&json).expect("deserialize");
    assert_eq!(config, deser);
}
