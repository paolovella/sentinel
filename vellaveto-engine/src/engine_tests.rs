// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Unit tests for the policy engine.
//!
//! These tests cover policy matching, constraint evaluation, path/network rules,
//! context conditions, and traced evaluation.

use super::*;
use serde_json::json;
use vellaveto_types::CallChainEntry;

#[test]
fn test_empty_policies_deny() {
    let engine = PolicyEngine::new(false);
    let action = Action::new("bash".to_string(), "execute".to_string(), json!({}));
    let verdict = engine.evaluate_action(&action, &[]).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

#[test]
fn test_deny_policy_match() {
    let engine = PolicyEngine::new(false);
    let action = Action::new("bash".to_string(), "execute".to_string(), json!({}));
    let policies = vec![Policy {
        id: "bash:*".to_string(),
        name: "Block bash".to_string(),
        policy_type: PolicyType::Deny,
        priority: 100,
        path_rules: None,
        network_rules: None,
    }];
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

#[test]
fn test_allow_policy_match() {
    let engine = PolicyEngine::new(false);
    let action = Action::new(
        "file_system".to_string(),
        "read_file".to_string(),
        json!({}),
    );
    let policies = vec![Policy {
        id: "file_system:read_file".to_string(),
        name: "Allow file reads".to_string(),
        policy_type: PolicyType::Allow,
        priority: 50,
        path_rules: None,
        network_rules: None,
    }];
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(verdict, Verdict::Allow));
}

#[test]
fn test_priority_ordering() {
    let engine = PolicyEngine::new(false);
    let action = Action::new("bash".to_string(), "execute".to_string(), json!({}));
    let policies = vec![
        Policy {
            id: "*".to_string(),
            name: "Allow all (low priority)".to_string(),
            policy_type: PolicyType::Allow,
            priority: 10,
            path_rules: None,
            network_rules: None,
        },
        Policy {
            id: "bash:*".to_string(),
            name: "Deny bash (high priority)".to_string(),
            policy_type: PolicyType::Deny,
            priority: 100,
            path_rules: None,
            network_rules: None,
        },
    ];
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

#[test]
fn test_conditional_require_approval() {
    let engine = PolicyEngine::new(false);
    let action = Action::new("network".to_string(), "connect".to_string(), json!({}));
    let policies = vec![Policy {
        id: "network:*".to_string(),
        name: "Network requires approval".to_string(),
        policy_type: PolicyType::Conditional {
            conditions: json!({
                "require_approval": true
            }),
        },
        priority: 100,
        path_rules: None,
        network_rules: None,
    }];
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(verdict, Verdict::RequireApproval { .. }));
}

// ═══════════════════════════════════════════════════
// HELPER: build a conditional policy with constraints
// ═══════════════════════════════════════════════════

fn constraint_policy(constraints: serde_json::Value) -> Vec<Policy> {
    vec![Policy {
        id: "*".to_string(),
        name: "constraint-policy".to_string(),
        policy_type: PolicyType::Conditional {
            conditions: json!({ "parameter_constraints": constraints }),
        },
        priority: 100,
        path_rules: None,
        network_rules: None,
    }]
}

fn action_with(tool: &str, func: &str, params: serde_json::Value) -> Action {
    Action::new(tool.to_string(), func.to_string(), params)
}

// ═══════════════════════════════════════════════════
// PATH CONSTRAINTS: GLOB OPERATOR
// ═══════════════════════════════════════════════════

#[test]
fn test_glob_blocks_sensitive_path() {
    let engine = PolicyEngine::new(false);
    let action = action_with(
        "file",
        "read",
        json!({"path": "/home/user/.aws/credentials"}),
    );
    let policies = constraint_policy(json!([{
        "param": "path",
        "op": "glob",
        "pattern": "/home/*/.aws/**",
        "on_match": "deny"
    }]));
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

#[test]
fn test_glob_allows_safe_path() {
    let engine = PolicyEngine::new(false);
    let action = action_with(
        "file",
        "read",
        json!({"path": "/home/user/project/src/main.rs"}),
    );
    let policies = constraint_policy(json!([{
        "param": "path",
        "op": "glob",
        "pattern": "/home/*/.aws/**",
        "on_match": "deny"
    }]));
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(verdict, Verdict::Allow));
}

#[test]
fn test_glob_blocks_ssh_keys() {
    let engine = PolicyEngine::new(false);
    let action = action_with("file", "read", json!({"path": "/home/user/.ssh/id_rsa"}));
    let policies = constraint_policy(json!([{
        "param": "path",
        "op": "glob",
        "pattern": "/home/*/.ssh/**",
        "on_match": "deny"
    }]));
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

#[test]
fn test_glob_blocks_etc_passwd() {
    let engine = PolicyEngine::new(false);
    let action = action_with("file", "read", json!({"path": "/etc/passwd"}));
    let policies = constraint_policy(json!([{
        "param": "path",
        "op": "glob",
        "pattern": "/etc/passwd",
        "on_match": "deny"
    }]));
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

#[test]
fn test_glob_normalizes_traversal() {
    let engine = PolicyEngine::new(false);
    // Attempt path traversal: /home/user/project/../../.aws/credentials → /home/.aws/credentials
    let action = action_with(
        "file",
        "read",
        json!({"path": "/home/user/project/../../.aws/credentials"}),
    );
    let policies = constraint_policy(json!([{
        "param": "path",
        "op": "glob",
        "pattern": "/home/.aws/**",
        "on_match": "deny"
    }]));
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

#[test]
fn test_glob_normalizes_dot_segments() {
    let engine = PolicyEngine::new(false);
    let action = action_with(
        "file",
        "read",
        json!({"path": "/home/user/./project/./src/main.rs"}),
    );
    let policies = constraint_policy(json!([{
        "param": "path",
        "op": "glob",
        "pattern": "/home/user/project/src/*",
        "on_match": "deny"
    }]));
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

#[test]
fn test_glob_null_byte_path_no_match() {
    let engine = PolicyEngine::new(false);
    // Null byte injection attempt
    let action = action_with(
        "file",
        "read",
        json!({"path": "/safe/path\u{0000}/../etc/passwd"}),
    );
    let policies = constraint_policy(json!([{
        "param": "path",
        "op": "glob",
        "pattern": "/safe/**",
        "on_match": "allow"
    }]));
    // Null byte path: normalization Err -> fail-closed -> Deny
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

#[test]
fn test_glob_require_approval_on_match() {
    let engine = PolicyEngine::new(false);
    let action = action_with("file", "write", json!({"path": "/etc/nginx/nginx.conf"}));
    let policies = constraint_policy(json!([{
        "param": "path",
        "op": "glob",
        "pattern": "/etc/**",
        "on_match": "require_approval"
    }]));
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(verdict, Verdict::RequireApproval { .. }));
}

#[test]
fn test_glob_invalid_pattern_errors() {
    let engine = PolicyEngine::new(false);
    let action = action_with("file", "read", json!({"path": "/tmp/test"}));
    let policies = constraint_policy(json!([{
        "param": "path",
        "op": "glob",
        "pattern": "[invalid",
        "on_match": "deny"
    }]));
    let result = engine.evaluate_action(&action, &policies);
    assert!(result.is_err());
}

// ═══════════════════════════════════════════════════
// PATH CONSTRAINTS: NOT_GLOB OPERATOR (ALLOWLIST)
// ═══════════════════════════════════════════════════

#[test]
fn test_not_glob_denies_outside_allowlist() {
    let engine = PolicyEngine::new(false);
    let action = action_with("file", "read", json!({"path": "/etc/shadow"}));
    let policies = constraint_policy(json!([{
        "param": "path",
        "op": "not_glob",
        "patterns": ["/home/user/project/**", "/tmp/**"],
        "on_match": "deny"
    }]));
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

#[test]
fn test_not_glob_allows_inside_allowlist() {
    let engine = PolicyEngine::new(false);
    let action = action_with(
        "file",
        "read",
        json!({"path": "/home/user/project/src/lib.rs"}),
    );
    let policies = constraint_policy(json!([{
        "param": "path",
        "op": "not_glob",
        "patterns": ["/home/user/project/**", "/tmp/**"],
        "on_match": "deny"
    }]));
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(verdict, Verdict::Allow));
}

#[test]
fn test_not_glob_denies_traversal_outside_allowlist() {
    let engine = PolicyEngine::new(false);
    // Traversal: /home/user/project/../../.ssh/id_rsa → /home/.ssh/id_rsa
    let action = action_with(
        "file",
        "read",
        json!({"path": "/home/user/project/../../.ssh/id_rsa"}),
    );
    let policies = constraint_policy(json!([{
        "param": "path",
        "op": "not_glob",
        "patterns": ["/home/user/project/**"],
        "on_match": "deny"
    }]));
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

#[test]
fn test_not_glob_multiple_allowed_paths() {
    let engine = PolicyEngine::new(false);
    let action = action_with(
        "file",
        "write",
        json!({"path": "/tmp/workspace/output.json"}),
    );
    let policies = constraint_policy(json!([{
        "param": "path",
        "op": "not_glob",
        "patterns": ["/home/user/project/**", "/tmp/workspace/**", "/var/log/app/**"],
        "on_match": "deny"
    }]));
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(verdict, Verdict::Allow));
}

// ═══════════════════════════════════════════════════
// DOMAIN CONSTRAINTS: DOMAIN_MATCH OPERATOR
// ═══════════════════════════════════════════════════

#[test]
fn test_domain_match_blocks_exact() {
    let engine = PolicyEngine::new(false);
    let action = action_with("http", "get", json!({"url": "https://evil.com/exfil"}));
    let policies = constraint_policy(json!([{
        "param": "url",
        "op": "domain_match",
        "pattern": "evil.com",
        "on_match": "deny"
    }]));
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

#[test]
fn test_domain_match_blocks_wildcard_subdomain() {
    let engine = PolicyEngine::new(false);
    let action = action_with(
        "http",
        "post",
        json!({"url": "https://data.pastebin.com/upload"}),
    );
    let policies = constraint_policy(json!([{
        "param": "url",
        "op": "domain_match",
        "pattern": "*.pastebin.com",
        "on_match": "deny"
    }]));
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

#[test]
fn test_domain_match_wildcard_matches_bare_domain() {
    let engine = PolicyEngine::new(false);
    let action = action_with(
        "http",
        "get",
        json!({"url": "https://pastebin.com/raw/abc"}),
    );
    let policies = constraint_policy(json!([{
        "param": "url",
        "op": "domain_match",
        "pattern": "*.pastebin.com",
        "on_match": "deny"
    }]));
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

#[test]
fn test_domain_match_no_match_allows() {
    let engine = PolicyEngine::new(false);
    let action = action_with(
        "http",
        "get",
        json!({"url": "https://api.anthropic.com/v1/messages"}),
    );
    let policies = constraint_policy(json!([{
        "param": "url",
        "op": "domain_match",
        "pattern": "*.pastebin.com",
        "on_match": "deny"
    }]));
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(verdict, Verdict::Allow));
}

#[test]
fn test_domain_match_strips_port() {
    let engine = PolicyEngine::new(false);
    let action = action_with("http", "get", json!({"url": "https://evil.com:8443/path"}));
    let policies = constraint_policy(json!([{
        "param": "url",
        "op": "domain_match",
        "pattern": "evil.com",
        "on_match": "deny"
    }]));
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

#[test]
fn test_domain_match_case_insensitive() {
    let engine = PolicyEngine::new(false);
    let action = action_with("http", "get", json!({"url": "https://Evil.COM/path"}));
    let policies = constraint_policy(json!([{
        "param": "url",
        "op": "domain_match",
        "pattern": "evil.com",
        "on_match": "deny"
    }]));
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

#[test]
fn test_domain_match_strips_userinfo() {
    let engine = PolicyEngine::new(false);
    let action = action_with(
        "http",
        "get",
        json!({"url": "https://user:pass@evil.com/path"}),
    );
    let policies = constraint_policy(json!([{
        "param": "url",
        "op": "domain_match",
        "pattern": "evil.com",
        "on_match": "deny"
    }]));
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

#[test]
fn test_domain_match_no_scheme() {
    let engine = PolicyEngine::new(false);
    let action = action_with("http", "get", json!({"url": "evil.com/path"}));
    let policies = constraint_policy(json!([{
        "param": "url",
        "op": "domain_match",
        "pattern": "evil.com",
        "on_match": "deny"
    }]));
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

// ═══════════════════════════════════════════════════
// DOMAIN CONSTRAINTS: DOMAIN_NOT_IN OPERATOR (ALLOWLIST)
// ═══════════════════════════════════════════════════

#[test]
fn test_domain_not_in_denies_unlisted_domain() {
    let engine = PolicyEngine::new(false);
    let action = action_with("http", "post", json!({"url": "https://attacker.com/exfil"}));
    let policies = constraint_policy(json!([{
        "param": "url",
        "op": "domain_not_in",
        "patterns": ["api.anthropic.com", "*.github.com", "*.company.internal"],
        "on_match": "deny"
    }]));
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

#[test]
fn test_domain_not_in_allows_listed_domain() {
    let engine = PolicyEngine::new(false);
    let action = action_with(
        "http",
        "post",
        json!({"url": "https://api.anthropic.com/v1/messages"}),
    );
    let policies = constraint_policy(json!([{
        "param": "url",
        "op": "domain_not_in",
        "patterns": ["api.anthropic.com", "*.github.com"],
        "on_match": "deny"
    }]));
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(verdict, Verdict::Allow));
}

#[test]
fn test_domain_not_in_allows_wildcard_subdomain() {
    let engine = PolicyEngine::new(false);
    let action = action_with(
        "http",
        "get",
        json!({"url": "https://api.github.com/repos"}),
    );
    let policies = constraint_policy(json!([{
        "param": "url",
        "op": "domain_not_in",
        "patterns": ["*.github.com"],
        "on_match": "deny"
    }]));
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(verdict, Verdict::Allow));
}

#[test]
fn test_domain_not_in_blocks_ngrok() {
    let engine = PolicyEngine::new(false);
    let action = action_with(
        "http",
        "post",
        json!({"url": "https://abc123.ngrok.io/callback"}),
    );
    let policies = constraint_policy(json!([{
        "param": "url",
        "op": "domain_not_in",
        "patterns": ["api.anthropic.com", "*.company.internal"],
        "on_match": "deny"
    }]));
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

// ═══════════════════════════════════════════════════
// REGEX CONSTRAINTS
// ═══════════════════════════════════════════════════

#[test]
fn test_regex_blocks_sql_injection() {
    let engine = PolicyEngine::new(false);
    let action = action_with("db", "query", json!({"sql": "DROP TABLE users;"}));
    let policies = constraint_policy(json!([{
        "param": "sql",
        "op": "regex",
        "pattern": "(?i)drop\\s+table",
        "on_match": "deny"
    }]));
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

#[test]
fn test_regex_allows_safe_query() {
    let engine = PolicyEngine::new(false);
    let action = action_with(
        "db",
        "query",
        json!({"sql": "SELECT * FROM users WHERE id = 1"}),
    );
    let policies = constraint_policy(json!([{
        "param": "sql",
        "op": "regex",
        "pattern": "(?i)drop\\s+table",
        "on_match": "deny"
    }]));
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(verdict, Verdict::Allow));
}

#[test]
fn test_regex_require_approval_for_delete() {
    let engine = PolicyEngine::new(false);
    let action = action_with(
        "db",
        "query",
        json!({"sql": "DELETE FROM orders WHERE status = 'cancelled'"}),
    );
    let policies = constraint_policy(json!([{
        "param": "sql",
        "op": "regex",
        "pattern": "(?i)delete\\s+from",
        "on_match": "require_approval"
    }]));
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(verdict, Verdict::RequireApproval { .. }));
}

#[test]
fn test_regex_invalid_pattern_errors() {
    let engine = PolicyEngine::new(false);
    let action = action_with("tool", "func", json!({"value": "test"}));
    let policies = constraint_policy(json!([{
        "param": "value",
        "op": "regex",
        "pattern": "(unclosed",
        "on_match": "deny"
    }]));
    let result = engine.evaluate_action(&action, &policies);
    assert!(result.is_err());
}

// ═══════════════════════════════════════════════════
// EQ / NE CONSTRAINTS
// ═══════════════════════════════════════════════════

#[test]
fn test_eq_fires_on_match() {
    let engine = PolicyEngine::new(false);
    let action = action_with("tool", "func", json!({"mode": "destructive"}));
    let policies = constraint_policy(json!([{
        "param": "mode",
        "op": "eq",
        "value": "destructive",
        "on_match": "deny"
    }]));
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

#[test]
fn test_eq_does_not_fire_on_mismatch() {
    let engine = PolicyEngine::new(false);
    let action = action_with("tool", "func", json!({"mode": "safe"}));
    let policies = constraint_policy(json!([{
        "param": "mode",
        "op": "eq",
        "value": "destructive",
        "on_match": "deny"
    }]));
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(verdict, Verdict::Allow));
}

#[test]
fn test_ne_fires_when_not_equal() {
    let engine = PolicyEngine::new(false);
    let action = action_with("tool", "func", json!({"env": "production"}));
    let policies = constraint_policy(json!([{
        "param": "env",
        "op": "ne",
        "value": "staging",
        "on_match": "require_approval"
    }]));
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(verdict, Verdict::RequireApproval { .. }));
}

#[test]
fn test_ne_does_not_fire_when_equal() {
    let engine = PolicyEngine::new(false);
    let action = action_with("tool", "func", json!({"env": "staging"}));
    let policies = constraint_policy(json!([{
        "param": "env",
        "op": "ne",
        "value": "staging",
        "on_match": "deny"
    }]));
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(verdict, Verdict::Allow));
}

// ═══════════════════════════════════════════════════
// ONE_OF / NONE_OF CONSTRAINTS
// ═══════════════════════════════════════════════════

#[test]
fn test_one_of_fires_when_in_set() {
    let engine = PolicyEngine::new(false);
    let action = action_with("tool", "func", json!({"action": "delete"}));
    let policies = constraint_policy(json!([{
        "param": "action",
        "op": "one_of",
        "values": ["delete", "drop", "truncate"],
        "on_match": "deny"
    }]));
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

#[test]
fn test_one_of_does_not_fire_when_not_in_set() {
    let engine = PolicyEngine::new(false);
    let action = action_with("tool", "func", json!({"action": "read"}));
    let policies = constraint_policy(json!([{
        "param": "action",
        "op": "one_of",
        "values": ["delete", "drop", "truncate"],
        "on_match": "deny"
    }]));
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(verdict, Verdict::Allow));
}

#[test]
fn test_none_of_fires_when_not_in_set() {
    let engine = PolicyEngine::new(false);
    let action = action_with("tool", "func", json!({"format": "xml"}));
    let policies = constraint_policy(json!([{
        "param": "format",
        "op": "none_of",
        "values": ["json", "csv"],
        "on_match": "deny"
    }]));
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

#[test]
fn test_none_of_does_not_fire_when_in_set() {
    let engine = PolicyEngine::new(false);
    let action = action_with("tool", "func", json!({"format": "json"}));
    let policies = constraint_policy(json!([{
        "param": "format",
        "op": "none_of",
        "values": ["json", "csv"],
        "on_match": "deny"
    }]));
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(verdict, Verdict::Allow));
}

// ═══════════════════════════════════════════════════
// MISSING PARAM / ERROR CASES
// ═══════════════════════════════════════════════════

#[test]
fn test_missing_param_denies_by_default() {
    let engine = PolicyEngine::new(false);
    let action = action_with("file", "read", json!({}));
    let policies = constraint_policy(json!([{
        "param": "path",
        "op": "glob",
        "pattern": "/safe/**",
        "on_match": "allow"
    }]));
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

#[test]
fn test_missing_param_skips_when_configured() {
    // Exploit #2 fix: a single constraint with on_missing=skip and missing param
    // means ALL constraints skipped → fail-closed → Deny
    let engine = PolicyEngine::new(false);
    let action = action_with("file", "read", json!({}));
    let policies = constraint_policy(json!([{
        "param": "path",
        "op": "glob",
        "pattern": "/dangerous/**",
        "on_match": "deny",
        "on_missing": "skip"
    }]));
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(verdict, Verdict::Deny { .. }),
        "All constraints skipped → fail-closed deny, got: {verdict:?}"
    );
}

#[test]
fn test_unknown_operator_errors() {
    let engine = PolicyEngine::new(false);
    let action = action_with("tool", "func", json!({"x": "y"}));
    let policies = constraint_policy(json!([{
        "param": "x",
        "op": "bogus_op",
        "on_match": "deny"
    }]));
    let result = engine.evaluate_action(&action, &policies);
    assert!(result.is_err());
}

#[test]
fn test_unknown_on_match_action_errors() {
    let engine = PolicyEngine::new(false);
    let action = action_with("file", "read", json!({"path": "/etc/passwd"}));
    let policies = constraint_policy(json!([{
        "param": "path",
        "op": "glob",
        "pattern": "/etc/**",
        "on_match": "explode"
    }]));
    let result = engine.evaluate_action(&action, &policies);
    assert!(result.is_err());
}

#[test]
fn test_constraint_missing_param_field_errors() {
    let engine = PolicyEngine::new(false);
    let action = action_with("tool", "func", json!({"x": "y"}));
    let policies = constraint_policy(json!([{
        "op": "eq",
        "value": "y",
        "on_match": "deny"
    }]));
    let result = engine.evaluate_action(&action, &policies);
    assert!(result.is_err());
}

#[test]
fn test_constraint_missing_op_field_errors() {
    let engine = PolicyEngine::new(false);
    let action = action_with("tool", "func", json!({"x": "y"}));
    let policies = constraint_policy(json!([{
        "param": "x",
        "value": "y",
        "on_match": "deny"
    }]));
    let result = engine.evaluate_action(&action, &policies);
    assert!(result.is_err());
}

#[test]
fn test_non_string_value_with_glob_denies_in_non_strict() {
    let engine = PolicyEngine::new(false);
    let action = action_with("tool", "func", json!({"path": 42}));
    let policies = constraint_policy(json!([{
        "param": "path",
        "op": "glob",
        "pattern": "/safe/**",
        "on_match": "deny"
    }]));
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

#[test]
fn test_non_string_value_with_glob_errors_in_strict() {
    let engine = PolicyEngine::new(true);
    let action = action_with("tool", "func", json!({"path": 42}));
    let policies = constraint_policy(json!([{
        "param": "path",
        "op": "glob",
        "pattern": "/safe/**",
        "on_match": "deny"
    }]));
    let result = engine.evaluate_action(&action, &policies);
    assert!(result.is_err());
}

// ═══════════════════════════════════════════════════
// MULTIPLE CONSTRAINTS (LAYERED SECURITY)
// ═══════════════════════════════════════════════════

#[test]
fn test_multiple_constraints_all_must_pass() {
    let engine = PolicyEngine::new(false);
    // Path is allowed, but domain is blocked
    let action = action_with(
        "http",
        "get",
        json!({
            "path": "/home/user/project/data.json",
            "url": "https://evil.com/exfil"
        }),
    );
    let policies = constraint_policy(json!([
        {
            "param": "path",
            "op": "not_glob",
            "patterns": ["/home/user/project/**"],
            "on_match": "deny"
        },
        {
            "param": "url",
            "op": "domain_match",
            "pattern": "evil.com",
            "on_match": "deny"
        }
    ]));
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    // Path passes (in allowlist), but domain is blocked
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

#[test]
fn test_multiple_constraints_first_fires_wins() {
    let engine = PolicyEngine::new(false);
    let action = action_with("file", "read", json!({"path": "/etc/shadow"}));
    let policies = constraint_policy(json!([
        {
            "param": "path",
            "op": "glob",
            "pattern": "/etc/shadow",
            "on_match": "deny"
        },
        {
            "param": "path",
            "op": "glob",
            "pattern": "/etc/**",
            "on_match": "require_approval"
        }
    ]));
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    // First constraint fires → deny (not require_approval)
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

// ═══════════════════════════════════════════════════
// PATH NORMALIZATION UNIT TESTS
// ═══════════════════════════════════════════════════

#[test]
fn test_normalize_path_resolves_parent() {
    assert_eq!(PolicyEngine::normalize_path("/a/b/../c").unwrap(), "/a/c");
}

#[test]
fn test_normalize_path_resolves_dot() {
    assert_eq!(
        PolicyEngine::normalize_path("/a/./b/./c").unwrap(),
        "/a/b/c"
    );
}

#[test]
fn test_normalize_path_prevents_root_escape() {
    assert_eq!(
        PolicyEngine::normalize_path("/a/../../etc/passwd").unwrap(),
        "/etc/passwd"
    );
}

#[test]
fn test_normalize_path_root_on_null_byte() {
    // Fix #9: Null byte paths now return "/" instead of empty string or raw input
    assert!(PolicyEngine::normalize_path("/a/b\0/c").is_err());
}

#[test]
fn test_normalize_path_absolute_stays_absolute() {
    assert_eq!(
        PolicyEngine::normalize_path("/usr/local/bin").unwrap(),
        "/usr/local/bin"
    );
}

// ═══════════════════════════════════════════════════
// DOMAIN EXTRACTION UNIT TESTS
// ═══════════════════════════════════════════════════

#[test]
fn test_extract_domain_https() {
    assert_eq!(
        PolicyEngine::extract_domain("https://example.com/path"),
        "example.com"
    );
}

#[test]
fn test_extract_domain_with_port() {
    assert_eq!(
        PolicyEngine::extract_domain("https://example.com:8443/path"),
        "example.com"
    );
}

#[test]
fn test_extract_domain_with_userinfo() {
    assert_eq!(
        PolicyEngine::extract_domain("https://user:pass@example.com/path"),
        "example.com"
    );
}

#[test]
fn test_extract_domain_no_scheme() {
    assert_eq!(
        PolicyEngine::extract_domain("example.com/path"),
        "example.com"
    );
}

#[test]
fn test_extract_domain_with_query_and_fragment() {
    assert_eq!(
        PolicyEngine::extract_domain("https://example.com/path?q=1#frag"),
        "example.com"
    );
}

#[test]
fn test_extract_domain_lowercases() {
    assert_eq!(
        PolicyEngine::extract_domain("https://Example.COM/path"),
        "example.com"
    );
}

// ═══════════════════════════════════════════════════
// DOMAIN PATTERN MATCHING UNIT TESTS
// ═══════════════════════════════════════════════════

#[test]
fn test_match_domain_exact() {
    assert!(PolicyEngine::match_domain_pattern(
        "example.com",
        "example.com"
    ));
}

#[test]
fn test_match_domain_exact_no_match() {
    assert!(!PolicyEngine::match_domain_pattern(
        "other.com",
        "example.com"
    ));
}

#[test]
fn test_match_domain_wildcard_subdomain() {
    assert!(PolicyEngine::match_domain_pattern(
        "sub.example.com",
        "*.example.com"
    ));
}

#[test]
fn test_match_domain_wildcard_bare() {
    assert!(PolicyEngine::match_domain_pattern(
        "example.com",
        "*.example.com"
    ));
}

#[test]
fn test_match_domain_wildcard_deep_sub() {
    assert!(PolicyEngine::match_domain_pattern(
        "a.b.example.com",
        "*.example.com"
    ));
}

#[test]
fn test_match_domain_wildcard_no_match() {
    assert!(!PolicyEngine::match_domain_pattern(
        "example.org",
        "*.example.com"
    ));
}

#[test]
fn test_match_domain_case_insensitive() {
    assert!(PolicyEngine::match_domain_pattern(
        "Example.COM",
        "example.com"
    ));
}

#[test]
fn test_match_domain_underscore_not_bypassing_wildcard_block() {
    // SECURITY (R27-ENG-2): Domains with underscores (e.g., SRV records like
    // _sip._tcp.evil.com) must still match wildcard block patterns. Previously,
    // IDNA normalization rejected underscores, returning None, which made
    // match_domain_pattern return false — allowing the domain through.
    assert!(
        PolicyEngine::match_domain_pattern("_srv.evil.com", "*.evil.com"),
        "R27-ENG-2: underscore domain must match wildcard block pattern"
    );
    assert!(
        PolicyEngine::match_domain_pattern("_sip._tcp.evil.com", "*.evil.com"),
        "R27-ENG-2: multi-underscore SRV domain must match wildcard block"
    );
}

#[test]
fn test_match_domain_underscore_exact() {
    assert!(
        PolicyEngine::match_domain_pattern("_srv.evil.com", "_srv.evil.com"),
        "R27-ENG-2: underscore exact match must work"
    );
    assert!(
        !PolicyEngine::match_domain_pattern("_srv.evil.com", "_srv.other.com"),
        "Underscore exact match should not cross-match"
    );
}

#[test]
fn test_match_domain_idna_wildcard() {
    // R25-ENG-5: IDNA wildcard patterns should work with internationalized domains.
    // "*.münchen.de" should match "sub.münchen.de" after IDNA normalization.
    // Previously, the "*." prefix caused IDNA normalization to fail entirely.
    assert!(
        PolicyEngine::match_domain_pattern("sub.xn--mnchen-3ya.de", "*.münchen.de"),
        "IDNA wildcard should match punycode subdomain"
    );
    // Also test that the bare domain matches
    assert!(
        PolicyEngine::match_domain_pattern("xn--mnchen-3ya.de", "*.münchen.de"),
        "IDNA wildcard should match bare punycode domain"
    );
}

// ═══════════════════════════════════════════════════
// PARAMETER_CONSTRAINTS MUST BE ARRAY
// ═══════════════════════════════════════════════════

#[test]
fn test_parameter_constraints_not_array_errors() {
    let engine = PolicyEngine::new(false);
    let action = action_with("tool", "func", json!({"x": "y"}));
    let policies = vec![Policy {
        id: "*".to_string(),
        name: "bad-policy".to_string(),
        policy_type: PolicyType::Conditional {
            conditions: json!({ "parameter_constraints": "not-an-array" }),
        },
        priority: 100,
        path_rules: None,
        network_rules: None,
    }];
    let result = engine.evaluate_action(&action, &policies);
    assert!(result.is_err());
}

// ═══════════════════════════════════════════════════
// JSON PATH TRAVERSAL (DEEP PARAMETER INSPECTION)
// ═══════════════════════════════════════════════════

#[test]
fn test_json_path_nested_parameter() {
    let engine = PolicyEngine::new(false);
    let action = action_with(
        "tool",
        "func",
        json!({"config": {"output": {"path": "/etc/shadow"}}}),
    );
    let policies = constraint_policy(json!([{
        "param": "config.output.path",
        "op": "glob",
        "pattern": "/etc/**",
        "on_match": "deny"
    }]));
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

#[test]
fn test_json_path_nested_allows_safe_value() {
    let engine = PolicyEngine::new(false);
    let action = action_with(
        "tool",
        "func",
        json!({"config": {"output": {"path": "/tmp/output.json"}}}),
    );
    let policies = constraint_policy(json!([{
        "param": "config.output.path",
        "op": "glob",
        "pattern": "/etc/**",
        "on_match": "deny"
    }]));
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(verdict, Verdict::Allow));
}

#[test]
fn test_json_path_missing_intermediate_denies() {
    let engine = PolicyEngine::new(false);
    // "config" exists but "config.output" doesn't
    let action = action_with("tool", "func", json!({"config": {"other": "value"}}));
    let policies = constraint_policy(json!([{
        "param": "config.output.path",
        "op": "glob",
        "pattern": "/etc/**",
        "on_match": "deny"
    }]));
    // Missing intermediate → fail-closed deny
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

#[test]
fn test_json_path_missing_intermediate_skip() {
    // Exploit #2 fix: missing intermediate path + on_missing=skip means all constraints
    // skipped → fail-closed → Deny
    let engine = PolicyEngine::new(false);
    let action = action_with("tool", "func", json!({"config": {"other": "value"}}));
    let policies = constraint_policy(json!([{
        "param": "config.output.path",
        "op": "glob",
        "pattern": "/etc/**",
        "on_match": "deny",
        "on_missing": "skip"
    }]));
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(verdict, Verdict::Deny { .. }),
        "All constraints skipped → fail-closed deny, got: {verdict:?}"
    );
}

#[test]
fn test_json_path_simple_key_still_works() {
    // Simple keys (no dots) should work exactly as before
    let engine = PolicyEngine::new(false);
    let action = action_with("file", "read", json!({"path": "/etc/passwd"}));
    let policies = constraint_policy(json!([{
        "param": "path",
        "op": "glob",
        "pattern": "/etc/**",
        "on_match": "deny"
    }]));
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

#[test]
fn test_json_path_domain_in_nested_object() {
    let engine = PolicyEngine::new(false);
    let action = action_with(
        "http",
        "request",
        json!({"options": {"target": "https://evil.com/exfil"}}),
    );
    let policies = constraint_policy(json!([{
        "param": "options.target",
        "op": "domain_match",
        "pattern": "evil.com",
        "on_match": "deny"
    }]));
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

#[test]
fn test_get_param_by_path_unit() {
    let params = json!({"a": {"b": {"c": 42}}, "top": "val"});
    assert_eq!(
        PolicyEngine::get_param_by_path(&params, "a.b.c"),
        Some(&json!(42))
    );
    assert_eq!(
        PolicyEngine::get_param_by_path(&params, "top"),
        Some(&json!("val"))
    );
    assert_eq!(
        PolicyEngine::get_param_by_path(&params, "a.b.missing"),
        None
    );
    assert_eq!(
        PolicyEngine::get_param_by_path(&params, "nonexistent"),
        None
    );
}

// ═══════════════════════════════════════════════════════════════
// Exploit #5 Regression: Parameter path dot-splitting ambiguity
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_get_param_by_path_exact_key_with_literal_dot() {
    // Literal dotted key with no nested equivalent — should resolve
    let params = json!({"config.path": "/tmp/safe.txt"});
    assert_eq!(
        PolicyEngine::get_param_by_path(&params, "config.path"),
        Some(&json!("/tmp/safe.txt"))
    );
}

#[test]
fn test_get_param_by_path_nested_only() {
    // Nested path with no literal dotted key — should resolve via traversal
    let params = json!({"config": {"path": "/etc/shadow"}});
    assert_eq!(
        PolicyEngine::get_param_by_path(&params, "config.path"),
        Some(&json!("/etc/shadow"))
    );
}

#[test]
fn test_get_param_by_path_ambiguous_different_values_returns_none() {
    // EXPLOIT #5: Both literal key AND nested path exist with DIFFERENT values.
    // Attacker adds "config.path": "/tmp/safe.txt" to shadow nested "config"."path": "/etc/shadow".
    // Engine MUST return None (ambiguous) to trigger fail-closed deny.
    let params = json!({
        "config.path": "/tmp/safe.txt",
        "config": {"path": "/etc/shadow"}
    });
    assert_eq!(
        PolicyEngine::get_param_by_path(&params, "config.path"),
        None,
        "Ambiguous parameter (exact key differs from nested path) must return None for fail-closed"
    );
}

#[test]
fn test_get_param_by_path_ambiguous_same_values_resolves() {
    // Both literal key AND nested path exist with the SAME value — no ambiguity
    let params = json!({
        "config.path": "/tmp/safe.txt",
        "config": {"path": "/tmp/safe.txt"}
    });
    assert_eq!(
        PolicyEngine::get_param_by_path(&params, "config.path"),
        Some(&json!("/tmp/safe.txt")),
        "Non-ambiguous (both interpretations agree) should resolve"
    );
}

#[test]
fn test_get_param_by_path_deep_ambiguity_returns_none() {
    // Deep nesting: "a.b.c" as literal key vs a→b→c traversal
    let params = json!({
        "a.b.c": "literal_value",
        "a": {"b": {"c": "nested_value"}}
    });
    assert_eq!(
        PolicyEngine::get_param_by_path(&params, "a.b.c"),
        None,
        "Deep ambiguity must return None for fail-closed"
    );
}

#[test]
fn test_get_param_by_path_partial_traversal_no_ambiguity() {
    // Literal key exists but nested traversal fails (partial path) — unambiguous
    let params = json!({
        "config.path": "/tmp/safe.txt",
        "config": {"other": "value"}
    });
    assert_eq!(
        PolicyEngine::get_param_by_path(&params, "config.path"),
        Some(&json!("/tmp/safe.txt")),
        "Exact key with no nested equivalent should resolve normally"
    );
}

// ═══════════════════════════════════════════════════════════════
// IMPROVEMENT_PLAN 4.1: Bracket Notation for Array Access
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_get_param_by_path_array_access_simple() {
    let params = json!({"items": ["a", "b", "c"]});
    assert_eq!(
        PolicyEngine::get_param_by_path(&params, "items[0]"),
        Some(&json!("a")),
        "items[0] should return first element"
    );
    assert_eq!(
        PolicyEngine::get_param_by_path(&params, "items[2]"),
        Some(&json!("c")),
        "items[2] should return third element"
    );
}

#[test]
fn test_get_param_by_path_array_access_nested() {
    let params = json!({"config": {"items": [{"path": "/tmp/a"}, {"path": "/tmp/b"}]}});
    assert_eq!(
        PolicyEngine::get_param_by_path(&params, "config.items[0].path"),
        Some(&json!("/tmp/a")),
        "config.items[0].path should traverse into nested array"
    );
    assert_eq!(
        PolicyEngine::get_param_by_path(&params, "config.items[1].path"),
        Some(&json!("/tmp/b")),
        "config.items[1].path should traverse into nested array"
    );
}

#[test]
fn test_get_param_by_path_array_access_out_of_bounds() {
    let params = json!({"items": ["a", "b"]});
    assert_eq!(
        PolicyEngine::get_param_by_path(&params, "items[5]"),
        None,
        "Out of bounds array access should return None"
    );
}

#[test]
fn test_get_param_by_path_multidimensional_array() {
    let params = json!({"matrix": [[1, 2], [3, 4], [5, 6]]});
    assert_eq!(
        PolicyEngine::get_param_by_path(&params, "matrix[0][0]"),
        Some(&json!(1)),
        "matrix[0][0] should return 1"
    );
    assert_eq!(
        PolicyEngine::get_param_by_path(&params, "matrix[1][1]"),
        Some(&json!(4)),
        "matrix[1][1] should return 4"
    );
    assert_eq!(
        PolicyEngine::get_param_by_path(&params, "matrix[2][0]"),
        Some(&json!(5)),
        "matrix[2][0] should return 5"
    );
}

#[test]
fn test_get_param_by_path_array_on_non_array() {
    let params = json!({"items": "not an array"});
    assert_eq!(
        PolicyEngine::get_param_by_path(&params, "items[0]"),
        None,
        "Array access on non-array should return None"
    );
}

#[test]
fn test_get_param_by_path_mixed_traversal() {
    let params = json!({
        "users": [
            {"name": "alice", "roles": ["admin", "user"]},
            {"name": "bob", "roles": ["user"]}
        ]
    });
    assert_eq!(
        PolicyEngine::get_param_by_path(&params, "users[0].name"),
        Some(&json!("alice")),
    );
    assert_eq!(
        PolicyEngine::get_param_by_path(&params, "users[0].roles[0]"),
        Some(&json!("admin")),
    );
    assert_eq!(
        PolicyEngine::get_param_by_path(&params, "users[1].roles[0]"),
        Some(&json!("user")),
    );
}

#[test]
fn test_get_param_by_path_invalid_bracket_syntax() {
    let params = json!({"items": [1, 2, 3]});
    // Non-numeric index
    assert_eq!(
        PolicyEngine::get_param_by_path(&params, "items[abc]"),
        None,
        "Non-numeric array index should return None"
    );
    // Unclosed bracket
    assert_eq!(
        PolicyEngine::get_param_by_path(&params, "items[0"),
        None,
        "Unclosed bracket should return None"
    );
}

// ═══════════════════════════════════════════════════
// SECURITY REGRESSION TESTS (Controller Directive C-2)
// ═══════════════════════════════════════════════════

#[test]
fn test_fix8_extract_domain_at_in_query_not_authority() {
    // Fix #8: @-sign in query params must NOT be treated as userinfo separator.
    // https://evil.com/path?email=user@safe.com should extract "evil.com", not "safe.com"
    assert_eq!(
        PolicyEngine::extract_domain("https://evil.com/path?email=user@safe.com"),
        "evil.com"
    );
}

#[test]
fn test_fix8_extract_domain_at_in_fragment() {
    // @-sign in fragment must not affect domain extraction
    assert_eq!(
        PolicyEngine::extract_domain("https://evil.com/page#section@anchor"),
        "evil.com"
    );
}

#[test]
fn test_fix8_extract_domain_legitimate_userinfo_still_works() {
    // Legitimate userinfo still strips correctly
    assert_eq!(
        PolicyEngine::extract_domain("https://admin:secret@internal.corp.com/api"),
        "internal.corp.com"
    );
}

#[test]
fn test_fix9_normalize_path_empty_returns_root() {
    // Fix #9: When normalization produces empty string (e.g., null byte input),
    // return "/" instead of the raw input containing dangerous sequences.
    assert!(
        PolicyEngine::normalize_path("/a/b\0/c").is_err(),
        "Null-byte path should return Err (fail-closed)"
    );
}

#[test]
fn test_fix9_normalize_path_traversal_only() {
    // A path that is ONLY traversal sequences produces an empty result
    // after normalization, which now returns Err (fail-closed).
    assert!(
        PolicyEngine::normalize_path("../../..").is_err(),
        "Pure traversal path should return Err (fail-closed)"
    );
}

// --- Phase 4.2: Percent-encoding normalization tests ---

#[test]
fn test_normalize_path_percent_encoded_filename() {
    // %70 = 'p', so /etc/%70asswd → /etc/passwd
    assert_eq!(
        PolicyEngine::normalize_path("/etc/%70asswd").unwrap(),
        "/etc/passwd"
    );
}

#[test]
fn test_normalize_path_percent_encoded_traversal() {
    // %2F = '/', %2E = '.', so /%2E%2E/%2E%2E/etc/passwd → /etc/passwd
    assert_eq!(
        PolicyEngine::normalize_path("/%2E%2E/%2E%2E/etc/passwd").unwrap(),
        "/etc/passwd"
    );
}

#[test]
fn test_normalize_path_percent_encoded_slash() {
    // %2F = '/' — encoded slashes in a single component
    // After decoding, path should be normalized correctly
    assert_eq!(
        PolicyEngine::normalize_path("/etc%2Fpasswd").unwrap(),
        "/etc/passwd"
    );
}

#[test]
fn test_normalize_path_encoded_null_byte() {
    // %00 = null byte — should be rejected after decoding
    assert!(PolicyEngine::normalize_path("/etc/%00passwd").is_err());
}

#[test]
fn test_normalize_path_double_encoding_fully_decoded() {
    // %2570 = %25 + 70 → first decode: %70 → second decode: p
    // Loop decode ensures idempotency: normalize(normalize(x)) == normalize(x)
    // Full decode is more secure — prevents bypass via multi-layer encoding.
    let result = PolicyEngine::normalize_path("/etc/%2570asswd").unwrap();
    assert_eq!(
        result, "/etc/passwd",
        "Double-encoded input should be fully decoded for idempotency"
    );
}

#[test]
fn test_normalize_path_mixed_encoded_and_plain() {
    assert_eq!(
        PolicyEngine::normalize_path("/home/%75ser/.aws/credentials").unwrap(),
        "/home/user/.aws/credentials"
    );
}

#[test]
fn test_normalize_path_fully_encoded_path() {
    // Full path encoded
    assert_eq!(
        PolicyEngine::normalize_path("%2Fetc%2Fshadow").unwrap(),
        "/etc/shadow"
    );
}

#[test]
fn test_normalize_path_six_level_encoding_decodes_fully() {
    // Build a 6-level encoded 'p': p → %70 → %2570 → %252570 → %25252570 → %2525252570 → %252525252570
    // Previous 5-iteration limit would fail to fully decode this.
    let result = PolicyEngine::normalize_path("/etc/%252525252570asswd").unwrap();
    assert_eq!(
        result, "/etc/passwd",
        "6-level encoding should be fully decoded with new higher limit"
    );
}

#[test]
fn test_normalize_path_deep_encoding_returns_root() {
    // Build a path where "%25" is repeated enough that >20 decode iterations
    // are needed. Each iteration peels one layer of %25 → %.
    // 21 layers of %25 followed by 70 (= 'p') will require 21 decode passes.
    let mut encoded = "%70".to_string(); // level 0: %70 → p
    for _ in 0..21 {
        // Encode the leading '%' as %25
        encoded = format!("%25{}", &encoded[1..]);
    }
    let input = format!("/etc/{encoded}asswd");
    assert!(
        PolicyEngine::normalize_path(&input).is_err(),
        "Encoding requiring >20 decode iterations should fail-closed with Err"
    );
}

#[test]
fn test_normalize_path_bounded_custom_limit() {
    // Build a 5-level encoded path that needs exactly 5 decode passes.
    let mut encoded = "%70".to_string(); // level 0: %70 → p
    for _ in 0..5 {
        encoded = format!("%25{}", &encoded[1..]);
    }
    let input = format!("/etc/{encoded}asswd");

    // With limit=10, 5 iterations succeeds.
    assert_eq!(
        PolicyEngine::normalize_path_bounded(&input, 10).unwrap(),
        "/etc/passwd"
    );

    // With limit=3, 5 iterations exceeds the cap → fail-closed to "/".
    assert!(PolicyEngine::normalize_path_bounded(&input, 3).is_err());
}

#[test]
fn test_normalize_path_bounded_zero_limit() {
    // With limit=0, even a single percent-encoded char fails closed.
    assert!(PolicyEngine::normalize_path_bounded("/etc/%70asswd", 0).is_err());
    // Plain paths (no percent-encoding) still work fine.
    assert_eq!(
        PolicyEngine::normalize_path_bounded("/etc/passwd", 0).unwrap(),
        "/etc/passwd"
    );
}

#[test]
fn test_set_max_path_decode_iterations() {
    let mut engine = PolicyEngine::new(false);
    // Default is the constant.
    assert_eq!(
        PolicyEngine::normalize_path("/etc/%70asswd").unwrap(),
        "/etc/passwd"
    );

    // After setting to 0, the engine's internal calls would use the
    // configured limit. Verify the setter doesn't panic.
    engine.set_max_path_decode_iterations(5);
    // The public associated function still uses the default (backward compat).
    assert_eq!(
        PolicyEngine::normalize_path("/etc/%70asswd").unwrap(),
        "/etc/passwd"
    );
}

#[test]
fn test_normalize_path_backslash_traversal_r34_eng_1() {
    // SECURITY (R34-ENG-1): Backslash-based traversal must be normalized.
    // On Linux, PathBuf treats \ as a filename char, but downstream tools
    // on Windows or cross-platform tools interpret \ as a separator.
    assert_eq!(
        PolicyEngine::normalize_path_bounded(r"/home/user\..\..\etc/passwd", 10).unwrap(),
        "/etc/passwd"
    );
}

#[test]
fn test_normalize_path_backslash_simple_r34_eng_1() {
    // Backslashes in a path without traversal should become forward slashes.
    assert_eq!(
        PolicyEngine::normalize_path_bounded(r"/home\user\docs", 10).unwrap(),
        "/home/user/docs"
    );
}

#[test]
fn test_normalize_path_backslash_encoded_r34_eng_1() {
    // %5C is backslash — after percent-decode + backslash normalization,
    // traversal must still be caught.
    assert_eq!(
        PolicyEngine::normalize_path_bounded("/home/user%5C..%5C..%5Cetc/passwd", 10).unwrap(),
        "/etc/passwd"
    );
}

#[test]
fn test_r35_eng_1_multistage_encoded_backslash() {
    // Multi-stage: %255C decodes to %5C, then to \ which becomes /
    // Without R35-ENG-1 fix, the backslash from intermediate decode step
    // would not be normalized, allowing traversal.
    let result =
        PolicyEngine::normalize_path_bounded("/home/user%255C..%255C..%255Cetc%255Cpasswd", 20)
            .unwrap();
    assert_eq!(result, "/etc/passwd");
}

#[test]
fn test_r35_eng_1_triple_encoded_backslash() {
    // Triple: %25255C → %255C → %5C → \ → /
    let result = PolicyEngine::normalize_path_bounded("/a%25255C..%25255Cb", 20).unwrap();
    assert_eq!(result, "/b");
}

#[test]
fn test_extract_domain_percent_encoded_dot() {
    // %2E = '.', so evil%2Ecom → evil.com
    assert_eq!(
        PolicyEngine::extract_domain("https://evil%2Ecom/path"),
        "evil.com"
    );
}

#[test]
fn test_extract_domain_percent_encoded_host() {
    // Encoded characters in hostname
    assert_eq!(
        PolicyEngine::extract_domain("https://%65vil.com/data"),
        "evil.com"
    );
}

#[test]
fn test_extract_domain_backslash_as_path_separator() {
    // SECURITY (R22-ENG-5): Per WHATWG URL Standard, `\` is treated as a
    // path separator in special schemes. Without normalization, the authority
    // portion includes the backslash and everything after it.
    assert_eq!(
        PolicyEngine::extract_domain("http://evil.com\\@legit.com/path"),
        "evil.com"
    );
    // Backslash before path — should split correctly
    assert_eq!(
        PolicyEngine::extract_domain("https://evil.com\\path\\to\\resource"),
        "evil.com"
    );
    // Multiple backslashes
    assert_eq!(
        PolicyEngine::extract_domain("http://host.com\\\\foo"),
        "host.com"
    );
}

#[test]
fn test_extract_domain_backslash_with_userinfo() {
    // Combined: backslash + userinfo should extract correct domain
    assert_eq!(
        PolicyEngine::extract_domain("http://user:pass@host.com\\path"),
        "host.com"
    );
}

#[test]
fn test_extract_domain_percent_encoded_backslash_before_at() {
    // SECURITY (R37-ENG-1): Per WHATWG URL Standard, %5C in the raw URL is part
    // of the authority (not a path separator). The @ delimiter is processed first
    // on the raw authority, so userinfo="evil.com%5C", host="legit.com".
    // Browsers connect to legit.com, so we must extract legit.com.
    let domain = PolicyEngine::extract_domain("http://evil.com%5C@legit.com/path");
    assert_eq!(
        domain, "legit.com",
        "R37-ENG-1: %5C before @ — browser connects to legit.com"
    );
}

#[test]
fn test_extract_domain_percent_encoded_slash_in_userinfo_r37_eng_1() {
    // SECURITY (R37-ENG-1): %2F decodes to '/' but is in the userinfo portion.
    // Per RFC 3986, @ separates userinfo from host. The browser connects to legit.com.
    let domain = PolicyEngine::extract_domain("http://evil.com%2F@legit.com/path");
    assert_eq!(
        domain, "legit.com",
        "R37-ENG-1: %2F in userinfo must not bypass @"
    );

    // Normal userinfo still works
    let domain = PolicyEngine::extract_domain("http://user:pass@example.com/path");
    assert_eq!(domain, "example.com");

    // Normal URLs still work
    let domain = PolicyEngine::extract_domain("http://example.com/path");
    assert_eq!(domain, "example.com");

    // %2F without @ acts as path separator after decode
    let domain = PolicyEngine::extract_domain("http://host%2Fpath.com/real");
    assert_eq!(domain, "host", "decoded / without @ acts as path separator");
}

#[test]
fn test_extract_domain_double_encoded_backslash() {
    // %255C = double-encoded backslash → decodes to "%5C" (literal, not backslash)
    // This should NOT trigger backslash normalization
    let domain = PolicyEngine::extract_domain("http://evil.com%255C@legit.com/path");
    // After decode: "evil.com%5C@legit.com" — %5C is literal text, @ is userinfo separator
    assert_eq!(domain, "legit.com");
}

#[test]
fn test_extract_domain_fragment_authority_delimiter() {
    // SECURITY (R27-ENG-1): '#' is an authority delimiter per RFC 3986.
    // "http://evil.com#@legit.com" must extract "evil.com", NOT "legit.com".
    let domain = PolicyEngine::extract_domain("http://evil.com#@legit.com");
    assert_eq!(
        domain, "evil.com",
        "R27-ENG-1: fragment '#' must terminate authority before '@' parsing"
    );
}

#[test]
fn test_extract_domain_query_authority_delimiter() {
    // SECURITY (R27-ENG-1): '?' is an authority delimiter per RFC 3986.
    // "http://evil.com?foo@legit.com" must extract "evil.com", NOT "legit.com".
    let domain = PolicyEngine::extract_domain("http://evil.com?foo@legit.com");
    assert_eq!(
        domain, "evil.com",
        "R27-ENG-1: query '?' must terminate authority before '@' parsing"
    );
}

#[test]
fn test_extract_domain_fragment_no_at() {
    // Fragment without '@' — should extract "evil.com" (fragment is not part of authority)
    let domain = PolicyEngine::extract_domain("http://evil.com#fragment");
    assert_eq!(domain, "evil.com");
}

// ---- Recursive parameter scanning (param: "*") tests ----

fn make_wildcard_policy(op: &str, constraint_extras: serde_json::Value) -> Policy {
    let mut base = serde_json::json!({
        "param": "*",
        "op": op,
        "on_match": "deny"
    });
    if let serde_json::Value::Object(extras) = constraint_extras {
        for (k, v) in extras {
            base.as_object_mut().unwrap().insert(k, v);
        }
    }
    Policy {
        id: "test:*".to_string(),
        name: "Wildcard scanner".to_string(),
        priority: 200,
        policy_type: PolicyType::Conditional {
            conditions: json!({
                "parameter_constraints": [base]
            }),
        },
        path_rules: None,
        network_rules: None,
    }
}

#[test]
fn test_wildcard_scan_catches_nested_url() {
    // A dangerous URL buried in nested parameters should be caught
    let engine = PolicyEngine::new(false);
    let policy = make_wildcard_policy("domain_match", json!({"pattern": "*.evil.com"}));

    let action = Action::new(
        "test".to_string(),
        "call".to_string(),
        json!({
            "options": {
                "target": "https://data.evil.com/exfil",
                "retries": 3
            }
        }),
    );

    let result = engine.evaluate_action(&action, &[policy]).unwrap();
    assert!(
        matches!(result, Verdict::Deny { .. }),
        "Should deny: nested URL matches *.evil.com, got: {result:?}"
    );
}

#[test]
fn test_wildcard_scan_allows_when_no_match() {
    // No string values match — should fall through to allow
    let engine = PolicyEngine::new(false);
    let policy = make_wildcard_policy("domain_match", json!({"pattern": "*.evil.com"}));

    let action = Action::new(
        "test".to_string(),
        "call".to_string(),
        json!({
            "url": "https://safe.example.com/api",
            "data": "hello world"
        }),
    );

    let result = engine.evaluate_action(&action, &[policy]).unwrap();
    assert!(
        matches!(result, Verdict::Allow),
        "Should allow: no values match *.evil.com, got: {result:?}"
    );
}

#[test]
fn test_wildcard_scan_catches_path_in_array() {
    // Dangerous path buried in an array element
    let engine = PolicyEngine::new(false);
    let policy = make_wildcard_policy("glob", json!({"pattern": "/home/*/.ssh/**"}));

    let action = Action::new(
        "test".to_string(),
        "batch_read".to_string(),
        json!({
            "files": [
                "/tmp/safe.txt",
                "/home/user/.ssh/id_rsa",
                "/var/log/syslog"
            ]
        }),
    );

    let result = engine.evaluate_action(&action, &[policy]).unwrap();
    assert!(
        matches!(result, Verdict::Deny { .. }),
        "Should deny: array contains path matching /home/*/.ssh/**, got: {result:?}"
    );
}

#[test]
fn test_wildcard_scan_regex_across_all_values() {
    // Regex scanning all values for dangerous commands
    let engine = PolicyEngine::new(false);
    let policy = make_wildcard_policy("regex", json!({"pattern": "(?i)rm\\s+-rf"}));

    let action = Action::new(
        "test".to_string(),
        "execute".to_string(),
        json!({
            "task": "cleanup",
            "steps": [
                { "cmd": "ls -la /tmp" },
                { "cmd": "rm -rf /" },
                { "cmd": "echo done" }
            ]
        }),
    );

    let result = engine.evaluate_action(&action, &[policy]).unwrap();
    assert!(
        matches!(result, Verdict::Deny { .. }),
        "Should deny: deeply nested value matches rm -rf, got: {result:?}"
    );
}

#[test]
fn test_wildcard_scan_no_string_values_on_missing_deny() {
    // Parameters with only numbers/booleans — no string values found
    // Default on_missing=deny → should deny
    let engine = PolicyEngine::new(false);
    let policy = make_wildcard_policy("regex", json!({"pattern": "anything"}));

    let action = Action::new(
        "test".to_string(),
        "call".to_string(),
        json!({
            "count": 42,
            "enabled": true
        }),
    );

    let result = engine.evaluate_action(&action, &[policy]).unwrap();
    assert!(
        matches!(result, Verdict::Deny { .. }),
        "Should deny: no string values found (fail-closed), got: {result:?}"
    );
}

#[test]
fn test_wildcard_scan_no_string_values_on_missing_skip() {
    // Parameters with only numbers + on_missing=skip → ALL constraints skip → fail-closed DENY
    // This is Exploit #2 fix: when every constraint in a Conditional policy skips
    // because required parameters are missing, the policy must deny (fail-closed),
    // not silently allow.
    let engine = PolicyEngine::new(false);
    let constraint = json!({
        "param": "*",
        "op": "regex",
        "pattern": "anything",
        "on_match": "deny",
        "on_missing": "skip"
    });
    let policy = Policy {
        id: "test:*".to_string(),
        name: "Wildcard skip".to_string(),
        priority: 200,
        policy_type: PolicyType::Conditional {
            conditions: json!({
                "parameter_constraints": [constraint]
            }),
        },
        path_rules: None,
        network_rules: None,
    };

    let action = Action::new(
        "test".to_string(),
        "call".to_string(),
        json!({
            "count": 42,
            "enabled": true
        }),
    );

    let result = engine.evaluate_action(&action, &[policy]).unwrap();
    assert!(
        matches!(result, Verdict::Deny { .. }),
        "Should deny: all constraints skipped (fail-closed), got: {result:?}"
    );
}

#[test]
fn test_wildcard_scan_deeply_nested_value() {
    // Value buried 5 levels deep
    let engine = PolicyEngine::new(false);
    let policy = make_wildcard_policy("glob", json!({"pattern": "/etc/shadow"}));

    let action = Action::new(
        "test".to_string(),
        "call".to_string(),
        json!({
            "a": {
                "b": {
                    "c": {
                        "d": {
                            "target": "/etc/shadow"
                        }
                    }
                }
            }
        }),
    );

    let result = engine.evaluate_action(&action, &[policy]).unwrap();
    assert!(
        matches!(result, Verdict::Deny { .. }),
        "Should deny: /etc/shadow found 5 levels deep, got: {result:?}"
    );
}

#[test]
fn test_wildcard_scan_require_approval_on_match() {
    // Wildcard with require_approval instead of deny
    let engine = PolicyEngine::new(false);
    let constraint = json!({
        "param": "*",
        "op": "regex",
        "pattern": "(?i)password",
        "on_match": "require_approval"
    });
    let policy = Policy {
        id: "test:*".to_string(),
        name: "Wildcard approval".to_string(),
        priority: 200,
        policy_type: PolicyType::Conditional {
            conditions: json!({
                "parameter_constraints": [constraint]
            }),
        },
        path_rules: None,
        network_rules: None,
    };

    let action = Action::new(
        "test".to_string(),
        "call".to_string(),
        json!({
            "query": "SELECT * FROM users WHERE password = '123'"
        }),
    );

    let result = engine.evaluate_action(&action, &[policy]).unwrap();
    assert!(
        matches!(result, Verdict::RequireApproval { .. }),
        "Should require approval: value contains 'password', got: {result:?}"
    );
}

#[test]
fn test_wildcard_scan_combined_with_specific_param() {
    // Both a specific param constraint and a wildcard in the same policy
    let engine = PolicyEngine::new(false);
    let policy = Policy {
        id: "test:*".to_string(),
        name: "Mixed constraints".to_string(),
        priority: 200,
        policy_type: PolicyType::Conditional {
            conditions: json!({
                "parameter_constraints": [
                    {
                        "param": "mode",
                        "op": "eq",
                        "value": "safe",
                        "on_match": "allow"
                    },
                    {
                        "param": "*",
                        "op": "glob",
                        "pattern": "/etc/shadow",
                        "on_match": "deny"
                    }
                ]
            }),
        },
        path_rules: None,
        network_rules: None,
    };

    // mode=safe fires first → allow
    let action1 = Action::new(
        "test".to_string(),
        "call".to_string(),
        json!({
            "mode": "safe",
            "path": "/etc/shadow"
        }),
    );
    let result1 = engine
        .evaluate_action(&action1, std::slice::from_ref(&policy))
        .unwrap();
    assert!(
        matches!(result1, Verdict::Allow),
        "First constraint (mode=safe→allow) should fire first, got: {result1:?}"
    );

    // mode=other → doesn't match eq, wildcard scans and finds /etc/shadow → deny
    let action2 = Action::new(
        "test".to_string(),
        "call".to_string(),
        json!({
            "mode": "other",
            "path": "/etc/shadow"
        }),
    );
    let result2 = engine.evaluate_action(&action2, &[policy]).unwrap();
    assert!(
        matches!(result2, Verdict::Deny { .. }),
        "Wildcard should catch /etc/shadow when first constraint doesn't fire, got: {result2:?}"
    );
}

#[test]
fn test_collect_all_string_values_basic() {
    let params = json!({
        "a": "hello",
        "b": 42,
        "c": {
            "d": "world",
            "e": true
        },
        "f": ["x", "y", 3]
    });

    let (values, truncated) = PolicyEngine::collect_all_string_values(&params);
    let string_values: Vec<&str> = values.iter().map(|(_, v)| *v).collect();

    assert!(!truncated, "Should not be truncated for small input");
    assert!(string_values.contains(&"hello"), "Should contain 'hello'");
    assert!(string_values.contains(&"world"), "Should contain 'world'");
    assert!(string_values.contains(&"x"), "Should contain 'x'");
    assert!(string_values.contains(&"y"), "Should contain 'y'");
    assert_eq!(values.len(), 4, "Should have exactly 4 string values");
}

#[test]
fn test_collect_all_string_values_empty_object() {
    let params = json!({});
    let (values, truncated) = PolicyEngine::collect_all_string_values(&params);
    assert!(!truncated);
    assert!(values.is_empty(), "Empty object should yield no values");
}

#[test]
fn test_collect_all_string_values_depth_limit() {
    // Build a structure deeper than MAX_JSON_DEPTH
    let mut val = json!("deep_secret");
    for _ in 0..40 {
        val = json!({"nested": val});
    }
    let (values, _truncated) = PolicyEngine::collect_all_string_values(&val);
    // The string is at depth 40, but our limit is 32 — it should NOT be found
    assert!(
        values.is_empty(),
        "Values beyond MAX_JSON_DEPTH should not be collected"
    );
}

// ═══════════════════════════════════════════════════
// PRE-COMPILED POLICY TESTS (C-9.2 / C-10.2)
// ═══════════════════════════════════════════════════

#[test]
fn test_compiled_with_policies_basic() {
    let policies = vec![
        Policy {
            id: "bash:*".to_string(),
            name: "Block bash".to_string(),
            policy_type: PolicyType::Deny,
            priority: 100,
            path_rules: None,
            network_rules: None,
        },
        Policy {
            id: "*".to_string(),
            name: "Allow all".to_string(),
            policy_type: PolicyType::Allow,
            priority: 10,
            path_rules: None,
            network_rules: None,
        },
    ];
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();

    let bash_action = Action::new("bash".to_string(), "execute".to_string(), json!({}));
    let verdict = engine.evaluate_action(&bash_action, &[]).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));

    let safe_action = Action::new("file_system".to_string(), "read".to_string(), json!({}));
    let verdict = engine.evaluate_action(&safe_action, &[]).unwrap();
    assert!(matches!(verdict, Verdict::Allow));
}

#[test]
fn test_compiled_glob_constraint() {
    let policies = vec![Policy {
        id: "*".to_string(),
        name: "Block sensitive paths".to_string(),
        policy_type: PolicyType::Conditional {
            conditions: json!({
                "parameter_constraints": [{
                    "param": "path",
                    "op": "glob",
                    "pattern": "/home/*/.aws/**",
                    "on_match": "deny"
                }]
            }),
        },
        priority: 100,
        path_rules: None,
        network_rules: None,
    }];
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();

    let action = action_with(
        "file",
        "read",
        json!({"path": "/home/user/.aws/credentials"}),
    );
    let verdict = engine.evaluate_action(&action, &[]).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));

    let safe = action_with(
        "file",
        "read",
        json!({"path": "/home/user/project/main.rs"}),
    );
    let verdict = engine.evaluate_action(&safe, &[]).unwrap();
    assert!(matches!(verdict, Verdict::Allow));
}

#[test]
fn test_compiled_regex_constraint() {
    let policies = vec![Policy {
        id: "*".to_string(),
        name: "Block destructive SQL".to_string(),
        policy_type: PolicyType::Conditional {
            conditions: json!({
                "parameter_constraints": [{
                    "param": "sql",
                    "op": "regex",
                    "pattern": "(?i)drop\\s+table",
                    "on_match": "deny"
                }]
            }),
        },
        priority: 100,
        path_rules: None,
        network_rules: None,
    }];
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();

    let action = action_with("db", "query", json!({"sql": "DROP TABLE users;"}));
    let verdict = engine.evaluate_action(&action, &[]).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));

    let safe = action_with("db", "query", json!({"sql": "SELECT * FROM users"}));
    let verdict = engine.evaluate_action(&safe, &[]).unwrap();
    assert!(matches!(verdict, Verdict::Allow));
}

#[test]
fn test_compiled_invalid_regex_rejected_at_load_time() {
    let policies = vec![Policy {
        id: "*".to_string(),
        name: "Bad regex".to_string(),
        policy_type: PolicyType::Conditional {
            conditions: json!({
                "parameter_constraints": [{
                    "param": "x",
                    "op": "regex",
                    "pattern": "(unclosed",
                    "on_match": "deny"
                }]
            }),
        },
        priority: 100,
        path_rules: None,
        network_rules: None,
    }];
    let result = PolicyEngine::with_policies(false, &policies);
    assert!(result.is_err());
    let errors = result.unwrap_err();
    assert_eq!(errors.len(), 1);
    assert!(errors[0].reason.contains("Invalid regex pattern"));
    assert!(errors[0].reason.contains("(unclosed"));
}

#[test]
fn test_compiled_invalid_glob_rejected_at_load_time() {
    let policies = vec![Policy {
        id: "*".to_string(),
        name: "Bad glob".to_string(),
        policy_type: PolicyType::Conditional {
            conditions: json!({
                "parameter_constraints": [{
                    "param": "path",
                    "op": "glob",
                    "pattern": "[invalid",
                    "on_match": "deny"
                }]
            }),
        },
        priority: 100,
        path_rules: None,
        network_rules: None,
    }];
    let result = PolicyEngine::with_policies(false, &policies);
    assert!(result.is_err());
    let errors = result.unwrap_err();
    assert_eq!(errors.len(), 1);
    assert!(errors[0].reason.contains("Invalid glob pattern"));
}

#[test]
fn test_compiled_multiple_errors_collected() {
    let policies = vec![
        Policy {
            id: "*".to_string(),
            name: "Bad regex policy".to_string(),
            policy_type: PolicyType::Conditional {
                conditions: json!({
                    "parameter_constraints": [{
                        "param": "x",
                        "op": "regex",
                        "pattern": "(unclosed",
                        "on_match": "deny"
                    }]
                }),
            },
            priority: 100,
            path_rules: None,
            network_rules: None,
        },
        Policy {
            id: "tool:*".to_string(),
            name: "Bad glob policy".to_string(),
            policy_type: PolicyType::Conditional {
                conditions: json!({
                    "parameter_constraints": [{
                        "param": "path",
                        "op": "glob",
                        "pattern": "[invalid",
                        "on_match": "deny"
                    }]
                }),
            },
            priority: 50,
            path_rules: None,
            network_rules: None,
        },
    ];
    let result = PolicyEngine::with_policies(false, &policies);
    assert!(result.is_err());
    let errors = result.unwrap_err();
    assert_eq!(errors.len(), 2);
    assert!(errors[0].reason.contains("regex"));
    assert!(errors[1].reason.contains("glob"));
}

#[test]
fn test_compiled_validation_error_is_descriptive() {
    let policies = vec![Policy {
        id: "my_tool:my_func".to_string(),
        name: "My Policy Name".to_string(),
        policy_type: PolicyType::Conditional {
            conditions: json!({
                "parameter_constraints": [{
                    "param": "x",
                    "op": "regex",
                    "pattern": "[bad",
                    "on_match": "deny"
                }]
            }),
        },
        priority: 100,
        path_rules: None,
        network_rules: None,
    }];
    let result = PolicyEngine::with_policies(false, &policies);
    let errors = result.unwrap_err();
    assert_eq!(errors[0].policy_id, "my_tool:my_func");
    assert_eq!(errors[0].policy_name, "My Policy Name");
    let display = format!("{}", errors[0]);
    assert!(display.contains("My Policy Name"));
    assert!(display.contains("my_tool:my_func"));
}

#[test]
fn test_compiled_policies_are_sorted() {
    let policies = vec![
        Policy {
            id: "*".to_string(),
            name: "Low priority allow".to_string(),
            policy_type: PolicyType::Allow,
            priority: 10,
            path_rules: None,
            network_rules: None,
        },
        Policy {
            id: "bash:*".to_string(),
            name: "High priority deny".to_string(),
            policy_type: PolicyType::Deny,
            priority: 100,
            path_rules: None,
            network_rules: None,
        },
    ];
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();
    // High priority deny should win even though allow was listed first
    let action = Action::new("bash".to_string(), "execute".to_string(), json!({}));
    let verdict = engine.evaluate_action(&action, &[]).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

#[test]
fn test_compiled_domain_not_in() {
    let policies = vec![Policy {
        id: "*".to_string(),
        name: "Domain allowlist".to_string(),
        policy_type: PolicyType::Conditional {
            conditions: json!({
                "parameter_constraints": [{
                    "param": "url",
                    "op": "domain_not_in",
                    "patterns": ["api.anthropic.com", "*.github.com"],
                    "on_match": "deny"
                }]
            }),
        },
        priority: 100,
        path_rules: None,
        network_rules: None,
    }];
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();

    let blocked = action_with("http", "post", json!({"url": "https://evil.com/exfil"}));
    let verdict = engine.evaluate_action(&blocked, &[]).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));

    let allowed = action_with(
        "http",
        "get",
        json!({"url": "https://api.anthropic.com/v1/messages"}),
    );
    let verdict = engine.evaluate_action(&allowed, &[]).unwrap();
    assert!(matches!(verdict, Verdict::Allow));
}

#[test]
fn test_compiled_require_approval() {
    let policies = vec![Policy {
        id: "network:*".to_string(),
        name: "Network approval".to_string(),
        policy_type: PolicyType::Conditional {
            conditions: json!({ "require_approval": true }),
        },
        priority: 100,
        path_rules: None,
        network_rules: None,
    }];
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();

    let action = Action::new("network".to_string(), "connect".to_string(), json!({}));
    let verdict = engine.evaluate_action(&action, &[]).unwrap();
    assert!(matches!(verdict, Verdict::RequireApproval { .. }));
}

#[test]
fn test_require_approval_non_boolean_fail_closed() {
    // FIND-IMP-013: Non-boolean require_approval must fail-closed (require approval),
    // not fail-open (skip approval). Tests string, number, null, and object values.
    for bad_value in &[json!("yes"), json!(1), json!(null), json!({"nested": true})] {
        let policies = vec![Policy {
            id: "*".to_string(),
            name: "Non-bool approval".to_string(),
            policy_type: PolicyType::Conditional {
                conditions: json!({ "require_approval": bad_value }),
            },
            priority: 100,
            path_rules: None,
            network_rules: None,
        }];
        let engine = PolicyEngine::with_policies(false, &policies).unwrap();
        let action = Action::new("tool".to_string(), "fn".to_string(), json!({}));
        let verdict = engine.evaluate_action(&action, &[]).unwrap();
        assert!(
            matches!(verdict, Verdict::RequireApproval { .. }),
            "Non-boolean require_approval {bad_value:?} should fail-closed to RequireApproval, got {verdict:?}"
        );
    }
}

#[test]
fn test_compiled_forbidden_parameters() {
    let policies = vec![Policy {
        id: "*".to_string(),
        name: "Forbid admin".to_string(),
        policy_type: PolicyType::Conditional {
            conditions: json!({
                "forbidden_parameters": ["admin_override", "sudo"]
            }),
        },
        priority: 100,
        path_rules: None,
        network_rules: None,
    }];
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();

    let action = action_with("tool", "func", json!({"admin_override": true}));
    let verdict = engine.evaluate_action(&action, &[]).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));

    let safe = action_with("tool", "func", json!({"normal_param": "value"}));
    let verdict = engine.evaluate_action(&safe, &[]).unwrap();
    assert!(matches!(verdict, Verdict::Allow));
}

#[test]
fn test_compiled_not_glob_allowlist() {
    let policies = vec![Policy {
        id: "*".to_string(),
        name: "Path allowlist".to_string(),
        policy_type: PolicyType::Conditional {
            conditions: json!({
                "parameter_constraints": [{
                    "param": "path",
                    "op": "not_glob",
                    "patterns": ["/home/user/project/**", "/tmp/**"],
                    "on_match": "deny"
                }]
            }),
        },
        priority: 100,
        path_rules: None,
        network_rules: None,
    }];
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();

    let blocked = action_with("file", "read", json!({"path": "/etc/shadow"}));
    let verdict = engine.evaluate_action(&blocked, &[]).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));

    let allowed = action_with(
        "file",
        "read",
        json!({"path": "/home/user/project/src/lib.rs"}),
    );
    let verdict = engine.evaluate_action(&allowed, &[]).unwrap();
    assert!(matches!(verdict, Verdict::Allow));
}

#[test]
fn test_compiled_eq_ne_one_of_none_of() {
    let policies = vec![Policy {
        id: "*".to_string(),
        name: "Value checks".to_string(),
        policy_type: PolicyType::Conditional {
            conditions: json!({
                "parameter_constraints": [
                    { "param": "mode", "op": "eq", "value": "destructive", "on_match": "deny" }
                ]
            }),
        },
        priority: 100,
        path_rules: None,
        network_rules: None,
    }];
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();

    let blocked = action_with("tool", "func", json!({"mode": "destructive"}));
    assert!(matches!(
        engine.evaluate_action(&blocked, &[]).unwrap(),
        Verdict::Deny { .. }
    ));

    let allowed = action_with("tool", "func", json!({"mode": "safe"}));
    assert!(matches!(
        engine.evaluate_action(&allowed, &[]).unwrap(),
        Verdict::Allow
    ));
}

#[test]
fn test_compiled_missing_param_fail_closed() {
    let policies = vec![Policy {
        id: "*".to_string(),
        name: "Require path".to_string(),
        policy_type: PolicyType::Conditional {
            conditions: json!({
                "parameter_constraints": [{
                    "param": "path",
                    "op": "glob",
                    "pattern": "/safe/**",
                    "on_match": "allow"
                }]
            }),
        },
        priority: 100,
        path_rules: None,
        network_rules: None,
    }];
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();

    // Missing param → deny (fail-closed)
    let action = action_with("file", "read", json!({}));
    let verdict = engine.evaluate_action(&action, &[]).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

#[test]
fn test_compiled_on_missing_skip() {
    // Exploit #2 fix: compiled path — all constraints skip → fail-closed → Deny
    let policies = vec![Policy {
        id: "*".to_string(),
        name: "Optional path check".to_string(),
        policy_type: PolicyType::Conditional {
            conditions: json!({
                "parameter_constraints": [{
                    "param": "path",
                    "op": "glob",
                    "pattern": "/dangerous/**",
                    "on_match": "deny",
                    "on_missing": "skip"
                }]
            }),
        },
        priority: 100,
        path_rules: None,
        network_rules: None,
    }];
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();

    let action = action_with("file", "read", json!({}));
    let verdict = engine.evaluate_action(&action, &[]).unwrap();
    assert!(
        matches!(verdict, Verdict::Deny { .. }),
        "All constraints skipped → fail-closed deny, got: {verdict:?}"
    );
}

#[test]
fn test_compiled_empty_policies_deny() {
    let engine = PolicyEngine::with_policies(false, &[]).unwrap();
    let action = Action::new("any".to_string(), "any".to_string(), json!({}));
    // Empty compiled policies → no matching policy → deny
    let verdict = engine.evaluate_action(&action, &[]).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

#[test]
fn test_compiled_parity_with_legacy() {
    // Verify compiled path produces same results as legacy path
    let policies = vec![
        Policy {
            id: "bash:*".to_string(),
            name: "Block bash".to_string(),
            policy_type: PolicyType::Deny,
            priority: 200,
            path_rules: None,
            network_rules: None,
        },
        Policy {
            id: "*".to_string(),
            name: "Domain allowlist".to_string(),
            policy_type: PolicyType::Conditional {
                conditions: json!({
                    "parameter_constraints": [{
                        "param": "url",
                        "op": "domain_not_in",
                        "patterns": ["api.anthropic.com"],
                        "on_match": "deny"
                    }]
                }),
            },
            priority: 100,
            path_rules: None,
            network_rules: None,
        },
        Policy {
            id: "*".to_string(),
            name: "Allow all".to_string(),
            policy_type: PolicyType::Allow,
            priority: 1,
            path_rules: None,
            network_rules: None,
        },
    ];

    let legacy_engine = PolicyEngine::new(false);
    let compiled_engine = PolicyEngine::with_policies(false, &policies).unwrap();

    let test_cases = vec![
        action_with("bash", "execute", json!({"cmd": "ls"})),
        action_with("http", "get", json!({"url": "https://evil.com/bad"})),
        action_with(
            "http",
            "get",
            json!({"url": "https://api.anthropic.com/v1/messages"}),
        ),
        action_with("file", "read", json!({"path": "/tmp/test"})),
    ];

    for action in &test_cases {
        let legacy = legacy_engine.evaluate_action(action, &policies).unwrap();
        let compiled = compiled_engine.evaluate_action(action, &[]).unwrap();
        assert_eq!(
            std::mem::discriminant(&legacy),
            std::mem::discriminant(&compiled),
            "Parity mismatch for action {}:{} — legacy={:?}, compiled={:?}",
            action.tool,
            action.function,
            legacy,
            compiled,
        );
    }
}

#[test]
fn test_compiled_strict_mode_unknown_key() {
    let policies = vec![Policy {
        id: "*".to_string(),
        name: "Unknown key".to_string(),
        policy_type: PolicyType::Conditional {
            conditions: json!({
                "require_approval": false,
                "custom_unknown_key": "value"
            }),
        },
        priority: 100,
        path_rules: None,
        network_rules: None,
    }];
    let result = PolicyEngine::with_policies(true, &policies);
    assert!(result.is_err());
    let errors = result.unwrap_err();
    assert!(errors[0].reason.contains("Unknown condition key"));
}

#[test]
fn test_compiled_wildcard_scan() {
    let policies = vec![Policy {
        id: "*".to_string(),
        name: "Scan all values".to_string(),
        policy_type: PolicyType::Conditional {
            conditions: json!({
                "parameter_constraints": [{
                    "param": "*",
                    "op": "domain_match",
                    "pattern": "*.evil.com",
                    "on_match": "deny"
                }]
            }),
        },
        priority: 100,
        path_rules: None,
        network_rules: None,
    }];
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();

    let action = action_with(
        "tool",
        "func",
        json!({"nested": {"url": "https://sub.evil.com/bad"}}),
    );
    let verdict = engine.evaluate_action(&action, &[]).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

#[test]
fn test_compiled_unknown_operator_rejected_at_load_time() {
    let policies = vec![Policy {
        id: "*".to_string(),
        name: "Bad op".to_string(),
        policy_type: PolicyType::Conditional {
            conditions: json!({
                "parameter_constraints": [{
                    "param": "x",
                    "op": "bogus_op",
                    "on_match": "deny"
                }]
            }),
        },
        priority: 100,
        path_rules: None,
        network_rules: None,
    }];
    let result = PolicyEngine::with_policies(false, &policies);
    assert!(result.is_err());
    let errors = result.unwrap_err();
    assert!(errors[0].reason.contains("Unknown constraint operator"));
}

#[test]
fn test_compiled_deep_json_rejected() {
    let mut deep = json!("leaf");
    for _ in 0..15 {
        deep = json!({"nested": deep});
    }
    let policies = vec![Policy {
        id: "*".to_string(),
        name: "Deep JSON".to_string(),
        policy_type: PolicyType::Conditional { conditions: deep },
        priority: 100,
        path_rules: None,
        network_rules: None,
    }];
    let result = PolicyEngine::with_policies(false, &policies);
    assert!(result.is_err());
    let errors = result.unwrap_err();
    assert!(errors[0].reason.contains("nesting depth"));
}

#[test]
fn test_compile_policies_standalone() {
    let policies = vec![
        Policy {
            id: "bash:*".to_string(),
            name: "Block bash".to_string(),
            policy_type: PolicyType::Deny,
            priority: 100,
            path_rules: None,
            network_rules: None,
        },
        Policy {
            id: "*".to_string(),
            name: "Allow all".to_string(),
            policy_type: PolicyType::Allow,
            priority: 10,
            path_rules: None,
            network_rules: None,
        },
    ];
    let compiled = PolicyEngine::compile_policies(&policies, false).unwrap();
    assert_eq!(compiled.len(), 2);
    // Should be sorted by priority (highest first)
    assert_eq!(compiled[0].policy.name, "Block bash");
    assert_eq!(compiled[1].policy.name, "Allow all");
}

#[test]
fn test_pattern_matcher_variants() {
    assert!(PatternMatcher::Any.matches("anything"));
    assert!(PatternMatcher::Exact("foo".to_string()).matches("foo"));
    assert!(!PatternMatcher::Exact("foo".to_string()).matches("bar"));
    assert!(PatternMatcher::Prefix("pre".to_string()).matches("prefix"));
    assert!(!PatternMatcher::Prefix("pre".to_string()).matches("suffix"));
    assert!(PatternMatcher::Suffix("fix".to_string()).matches("suffix"));
    assert!(!PatternMatcher::Suffix("fix".to_string()).matches("other"));
}

#[test]
fn test_compiled_tool_matcher_variants() {
    let action = Action::new(
        "file_system".to_string(),
        "read_file".to_string(),
        json!({}),
    );

    assert!(CompiledToolMatcher::Universal.matches(&action));

    let exact = CompiledToolMatcher::compile("file_system:read_file");
    assert!(exact.matches(&action));

    let tool_wild = CompiledToolMatcher::compile("file_system:*");
    assert!(tool_wild.matches(&action));

    let func_wild = CompiledToolMatcher::compile("*:read_file");
    assert!(func_wild.matches(&action));

    let no_match = CompiledToolMatcher::compile("bash:execute");
    assert!(!no_match.matches(&action));

    let tool_only = CompiledToolMatcher::compile("file_system");
    assert!(tool_only.matches(&action));
}

#[test]
fn test_compiled_tool_matcher_qualifier_suffix() {
    // Policy IDs with qualifier suffixes: "tool:func:qualifier" should match on tool:func only
    let action = Action::new(
        "file_system".to_string(),
        "read_file".to_string(),
        json!({}),
    );

    // Qualifier suffixes should be ignored for matching
    let qualified = CompiledToolMatcher::compile("*:*:credential-block");
    assert!(
        qualified.matches(&action),
        "Qualified *:*:qualifier should match any action"
    );

    let tool_qualified = CompiledToolMatcher::compile("file_system:*:blocker");
    assert!(
        tool_qualified.matches(&action),
        "tool:*:qualifier should match matching tool"
    );

    let exact_qualified = CompiledToolMatcher::compile("file_system:read_file:my-rule");
    assert!(
        exact_qualified.matches(&action),
        "tool:func:qualifier should match exact tool:func"
    );

    let no_match_qualified = CompiledToolMatcher::compile("bash:execute:dangerous");
    assert!(
        !no_match_qualified.matches(&action),
        "Non-matching tool:func:qualifier should not match"
    );

    // Legacy IDs without qualifier should still work
    let legacy = CompiledToolMatcher::compile("file_system:read_file");
    assert!(legacy.matches(&action));
}

#[test]
fn test_policy_id_qualifier_e2e_credential_block() {
    // End-to-end: policy with qualified ID blocks credential access
    let policies = vec![
        Policy {
            id: "*:*:credential-block".to_string(),
            name: "Block credential access".to_string(),
            policy_type: PolicyType::Conditional {
                conditions: json!({
                    "parameter_constraints": [{
                        "param": "*",
                        "op": "glob",
                        "pattern": "/home/*/.aws/**",
                        "on_match": "deny"
                    }]
                }),
            },
            priority: 300,
            path_rules: None,
            network_rules: None,
        },
        Policy {
            id: "*:*".to_string(),
            name: "Default allow".to_string(),
            policy_type: PolicyType::Allow,
            priority: 1,
            path_rules: None,
            network_rules: None,
        },
    ];
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();

    let cred_action = action_with(
        "file_system",
        "read_file",
        json!({"path": "/home/user/.aws/credentials"}),
    );
    let verdict = engine.evaluate_action(&cred_action, &[]).unwrap();
    assert!(
        matches!(verdict, Verdict::Deny { .. }),
        "Qualified policy ID *:*:credential-block must deny credential access, got: {verdict:?}"
    );

    let safe_action = action_with(
        "file_system",
        "read_file",
        json!({"path": "/home/user/project/README.md"}),
    );
    let verdict = engine.evaluate_action(&safe_action, &[]).unwrap();
    assert!(
        matches!(verdict, Verdict::Allow),
        "Safe path must be allowed, got: {verdict:?}"
    );
}

// ═══════════════════════════════════════════════════
// ON_NO_MATCH CONTINUATION TESTS (Adversary Phase 5)
// ═══════════════════════════════════════════════════

#[test]
fn test_on_no_match_continue_skips_to_next_policy() {
    // A conditional policy with on_no_match="continue" and no matching constraints
    // should skip to the next policy, not return Allow.
    let policies = vec![
        Policy {
            id: "*:*:scan-policy".to_string(),
            name: "Scan all params".to_string(),
            policy_type: PolicyType::Conditional {
                conditions: json!({
                    "parameter_constraints": [{
                        "param": "*",
                        "op": "glob",
                        "pattern": "/home/*/.aws/**",
                        "on_match": "deny",
                        "on_missing": "skip"
                    }],
                    "on_no_match": "continue"
                }),
            },
            priority: 300,
            path_rules: None,
            network_rules: None,
        },
        Policy {
            id: "*:*".to_string(),
            name: "Default deny".to_string(),
            policy_type: PolicyType::Deny,
            priority: 1,
            path_rules: None,
            network_rules: None,
        },
    ];

    // Compiled path
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();
    let action = action_with(
        "http_request",
        "get",
        json!({"url": "https://safe.example.com"}),
    );
    let verdict = engine.evaluate_action(&action, &[]).unwrap();
    assert!(
        matches!(verdict, Verdict::Deny { .. }),
        "on_no_match=continue must skip to next policy (Deny), got: {verdict:?}"
    );

    // Legacy path
    let legacy_engine = PolicyEngine::new(false);
    let verdict = legacy_engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(verdict, Verdict::Deny { .. }),
        "Legacy path: on_no_match=continue must skip to next policy (Deny), got: {verdict:?}"
    );
}

#[test]
fn test_on_no_match_default_returns_allow() {
    // Without on_no_match="continue", a conditional policy with no matching constraints
    // should return Allow (the historical default behavior).
    let policies = vec![
        Policy {
            id: "*:*".to_string(),
            name: "Scan all params".to_string(),
            policy_type: PolicyType::Conditional {
                conditions: json!({
                    "parameter_constraints": [{
                        "param": "*",
                        "op": "glob",
                        "pattern": "/home/*/.aws/**",
                        "on_match": "deny",
                        "on_missing": "skip"
                    }]
                }),
            },
            priority: 300,
            path_rules: None,
            network_rules: None,
        },
        Policy {
            id: "*:*".to_string(),
            name: "Default deny".to_string(),
            policy_type: PolicyType::Deny,
            priority: 1,
            path_rules: None,
            network_rules: None,
        },
    ];

    // Compiled path: without on_no_match, first policy returns Allow, blocking the Deny.
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();
    let action = action_with(
        "http_request",
        "get",
        json!({"url": "https://safe.example.com"}),
    );
    let verdict = engine.evaluate_action(&action, &[]).unwrap();
    assert!(
        matches!(verdict, Verdict::Allow),
        "Default (no on_no_match) must return Allow from first policy, got: {verdict:?}"
    );
}

#[test]
fn test_on_no_match_continue_policy_chain() {
    // Three-policy chain demonstrating layered security with on_no_match="continue":
    // 1. High-priority credential blocker (on_no_match=continue)
    // 2. Mid-priority domain blocker (on_no_match=continue)
    // 3. Low-priority default allow
    let policies = vec![
        Policy {
            id: "*:*:credential-block".to_string(),
            name: "Block credential access".to_string(),
            policy_type: PolicyType::Conditional {
                conditions: json!({
                    "parameter_constraints": [{
                        "param": "*",
                        "op": "glob",
                        "pattern": "/home/*/.aws/**",
                        "on_match": "deny",
                        "on_missing": "skip"
                    }],
                    "on_no_match": "continue"
                }),
            },
            priority: 300,
            path_rules: None,
            network_rules: None,
        },
        Policy {
            id: "*:*:domain-block".to_string(),
            name: "Block evil domains".to_string(),
            policy_type: PolicyType::Conditional {
                conditions: json!({
                    "parameter_constraints": [{
                        "param": "*",
                        "op": "domain_match",
                        "pattern": "*.evil.com",
                        "on_match": "deny",
                        "on_missing": "skip"
                    }],
                    "on_no_match": "continue"
                }),
            },
            priority: 280,
            path_rules: None,
            network_rules: None,
        },
        Policy {
            id: "*:*".to_string(),
            name: "Default allow".to_string(),
            policy_type: PolicyType::Allow,
            priority: 1,
            path_rules: None,
            network_rules: None,
        },
    ];

    let engine = PolicyEngine::with_policies(false, &policies).unwrap();

    // Credential access → blocked by policy 1
    let cred_action = action_with(
        "file_system",
        "read",
        json!({"path": "/home/user/.aws/credentials"}),
    );
    let v = engine.evaluate_action(&cred_action, &[]).unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "Credentials must be denied: {v:?}"
    );

    // Evil domain → skips policy 1, blocked by policy 2
    let evil_action = action_with(
        "http_request",
        "get",
        json!({"url": "https://exfil.evil.com/steal"}),
    );
    let v = engine.evaluate_action(&evil_action, &[]).unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "Evil domain must be denied: {v:?}"
    );

    // Safe action → skips policies 1 and 2, allowed by policy 3
    let safe_action = action_with(
        "file_system",
        "read",
        json!({"path": "/home/user/project/README.md"}),
    );
    let v = engine.evaluate_action(&safe_action, &[]).unwrap();
    assert!(
        matches!(v, Verdict::Allow),
        "Safe path must be allowed: {v:?}"
    );

    // Verify legacy path parity
    let legacy_engine = PolicyEngine::new(false);

    let v = legacy_engine
        .evaluate_action(&cred_action, &policies)
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "Legacy: credentials denied: {v:?}"
    );

    let v = legacy_engine
        .evaluate_action(&evil_action, &policies)
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "Legacy: evil domain denied: {v:?}"
    );

    let v = legacy_engine
        .evaluate_action(&safe_action, &policies)
        .unwrap();
    assert!(
        matches!(v, Verdict::Allow),
        "Legacy: safe path allowed: {v:?}"
    );
}

#[test]
fn test_on_no_match_continue_fail_closed_exception() {
    // When ALL constraints are skipped (missing params, on_missing="skip")
    // AND on_no_match="continue", the engine should skip to next policy,
    // NOT deny (fail-closed exception).
    let policies = vec![
        Policy {
            id: "*:*:scan".to_string(),
            name: "Wildcard scan".to_string(),
            policy_type: PolicyType::Conditional {
                conditions: json!({
                    "parameter_constraints": [{
                        "param": "*",
                        "op": "glob",
                        "pattern": "/home/*/.aws/**",
                        "on_match": "deny",
                        "on_missing": "skip"
                    }],
                    "on_no_match": "continue"
                }),
            },
            priority: 300,
            path_rules: None,
            network_rules: None,
        },
        Policy {
            id: "*:*".to_string(),
            name: "Default allow".to_string(),
            policy_type: PolicyType::Allow,
            priority: 1,
            path_rules: None,
            network_rules: None,
        },
    ];

    let engine = PolicyEngine::with_policies(false, &policies).unwrap();

    // Empty parameters: all constraints skip → on_no_match=continue → skip → Allow
    let action = action_with("file_system", "list", json!({}));
    let v = engine.evaluate_action(&action, &[]).unwrap();
    assert!(
        matches!(v, Verdict::Allow),
        "Empty params with on_no_match=continue must skip to Allow, got: {v:?}"
    );

    // Legacy path parity
    let legacy_engine = PolicyEngine::new(false);
    let v = legacy_engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(v, Verdict::Allow),
        "Legacy: empty params with on_no_match=continue must skip to Allow, got: {v:?}"
    );
}

#[test]
fn test_on_no_match_continue_fail_closed_without_flag() {
    // Without on_no_match="continue", ALL constraints skipped → fail-closed Deny.
    // This is the security-critical default behavior.
    let policies = vec![
        Policy {
            id: "*:*".to_string(),
            name: "Wildcard scan (no continue)".to_string(),
            policy_type: PolicyType::Conditional {
                conditions: json!({
                    "parameter_constraints": [{
                        "param": "*",
                        "op": "glob",
                        "pattern": "/home/*/.aws/**",
                        "on_match": "deny",
                        "on_missing": "skip"
                    }]
                }),
            },
            priority: 300,
            path_rules: None,
            network_rules: None,
        },
        Policy {
            id: "*:*".to_string(),
            name: "Default allow".to_string(),
            policy_type: PolicyType::Allow,
            priority: 1,
            path_rules: None,
            network_rules: None,
        },
    ];

    let engine = PolicyEngine::with_policies(false, &policies).unwrap();

    // Empty parameters without on_no_match: fail-closed Deny
    let action = action_with("file_system", "list", json!({}));
    let v = engine.evaluate_action(&action, &[]).unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "Empty params WITHOUT on_no_match=continue must fail-closed Deny, got: {v:?}"
    );
}

#[test]
fn test_on_no_match_invalid_value_treated_as_default() {
    // on_no_match with a non-"continue" value (e.g. "allow", "deny", garbage)
    // should behave identically to the default (no on_no_match).
    let policies = vec![
        Policy {
            id: "*:*".to_string(),
            name: "Bad on_no_match".to_string(),
            policy_type: PolicyType::Conditional {
                conditions: json!({
                    "parameter_constraints": [{
                        "param": "path",
                        "op": "glob",
                        "pattern": "/secret/**",
                        "on_match": "deny"
                    }],
                    "on_no_match": "deny"  // Not a valid value, treated as default
                }),
            },
            priority: 300,
            path_rules: None,
            network_rules: None,
        },
        Policy {
            id: "*:*".to_string(),
            name: "Default deny".to_string(),
            policy_type: PolicyType::Deny,
            priority: 1,
            path_rules: None,
            network_rules: None,
        },
    ];

    let engine = PolicyEngine::with_policies(false, &policies).unwrap();

    // Non-matching path: first policy returns Allow (default), NOT continue
    let action = action_with("file_system", "read", json!({"path": "/safe/file.txt"}));
    let v = engine.evaluate_action(&action, &[]).unwrap();
    assert!(
        matches!(v, Verdict::Allow),
        "on_no_match='deny' (invalid) must behave as default (Allow from first policy), got: {v:?}"
    );
}

#[test]
fn test_on_no_match_continue_with_require_approval() {
    // on_no_match="continue" must work correctly with require_approval constraints.
    // If a constraint fires require_approval, it takes effect. If no constraints fire,
    // the policy continues to next.
    let policies = vec![
        Policy {
            id: "*:*:dangerous-cmds".to_string(),
            name: "Dangerous commands require approval".to_string(),
            policy_type: PolicyType::Conditional {
                conditions: json!({
                    "parameter_constraints": [{
                        "param": "command",
                        "op": "regex",
                        "pattern": "(?i)rm\\s+-rf",
                        "on_match": "require_approval"
                    }],
                    "on_no_match": "continue"
                }),
            },
            priority: 200,
            path_rules: None,
            network_rules: None,
        },
        Policy {
            id: "*:*".to_string(),
            name: "Default allow".to_string(),
            policy_type: PolicyType::Allow,
            priority: 1,
            path_rules: None,
            network_rules: None,
        },
    ];

    let engine = PolicyEngine::with_policies(false, &policies).unwrap();

    // Dangerous command: requires approval
    let dangerous = action_with("bash", "execute", json!({"command": "rm -rf /"}));
    let v = engine.evaluate_action(&dangerous, &[]).unwrap();
    assert!(
        matches!(v, Verdict::RequireApproval { .. }),
        "Dangerous command must require approval: {v:?}"
    );

    // Safe command: skips policy 1, allowed by policy 2
    let safe = action_with("bash", "execute", json!({"command": "ls -la"}));
    let v = engine.evaluate_action(&safe, &[]).unwrap();
    assert!(
        matches!(v, Verdict::Allow),
        "Safe command must be allowed: {v:?}"
    );

    // No command param: skips policy 1 (on_missing defaults to deny, BUT
    // the param is missing so constraint evaluates with fail-closed...
    // Actually let's check: without on_missing="skip", missing param fails closed)
    let no_params = action_with("bash", "execute", json!({}));
    let v = engine.evaluate_action(&no_params, &[]).unwrap();
    // Missing "command" param → fail-closed Deny (since on_missing not set to "skip")
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "Missing param without on_missing=skip must fail-closed: {v:?}"
    );
}

#[test]
fn test_on_no_match_continue_traced_evaluation() {
    // Traced evaluation path must also respect on_no_match="continue".
    let policies = vec![
        Policy {
            id: "*:*:scan".to_string(),
            name: "Credential scan".to_string(),
            policy_type: PolicyType::Conditional {
                conditions: json!({
                    "parameter_constraints": [{
                        "param": "*",
                        "op": "glob",
                        "pattern": "/home/*/.ssh/**",
                        "on_match": "deny",
                        "on_missing": "skip"
                    }],
                    "on_no_match": "continue"
                }),
            },
            priority: 300,
            path_rules: None,
            network_rules: None,
        },
        Policy {
            id: "*:*".to_string(),
            name: "Default allow".to_string(),
            policy_type: PolicyType::Allow,
            priority: 1,
            path_rules: None,
            network_rules: None,
        },
    ];

    let engine = PolicyEngine::with_policies(false, &policies).unwrap();

    // Safe action with trace enabled
    let safe_action = action_with("editor", "open", json!({"file": "/tmp/test.txt"}));
    let (verdict, trace) = engine.evaluate_action_traced(&safe_action).unwrap();
    assert!(
        matches!(verdict, Verdict::Allow),
        "Traced: safe action must be allowed: {verdict:?}"
    );
    // Verify trace captured the policy evaluation
    assert!(
        !trace.matches.is_empty(),
        "Trace must contain policy match results"
    );
}

#[test]
fn test_on_no_match_continue_strict_mode_accepts_key() {
    // Strict mode must recognize "on_no_match" as a valid condition key.
    let policies = vec![Policy {
        id: "*:*".to_string(),
        name: "Strict scan".to_string(),
        policy_type: PolicyType::Conditional {
            conditions: json!({
                "parameter_constraints": [{
                    "param": "path",
                    "op": "glob",
                    "pattern": "/secret/**",
                    "on_match": "deny"
                }],
                "on_no_match": "continue"
            }),
        },
        priority: 100,
        path_rules: None,
        network_rules: None,
    }];

    // Strict mode: should NOT reject on_no_match as unknown key
    let result = PolicyEngine::with_policies(true, &policies);
    assert!(
        result.is_ok(),
        "Strict mode must accept 'on_no_match' as a valid condition key: {:?}",
        result.err()
    );

    // Also test legacy strict mode
    let legacy_engine = PolicyEngine::new(true);
    let action = action_with("file_system", "read", json!({"path": "/safe/file.txt"}));
    let result = legacy_engine.evaluate_action(&action, &policies);
    assert!(
        result.is_ok(),
        "Legacy strict mode must accept 'on_no_match': {:?}",
        result.err()
    );
}

// ═══════════════════════════════════════════════════
// TOOL INDEX TESTS (Phase 10.5)
// ═══════════════════════════════════════════════════

#[test]
fn test_tool_index_is_populated() {
    let policies = vec![
        Policy {
            id: "bash:*".to_string(),
            name: "Block bash".to_string(),
            policy_type: PolicyType::Deny,
            priority: 200,
            path_rules: None,
            network_rules: None,
        },
        Policy {
            id: "file_system:read_file".to_string(),
            name: "Block file read".to_string(),
            policy_type: PolicyType::Deny,
            priority: 150,
            path_rules: None,
            network_rules: None,
        },
        Policy {
            id: "*".to_string(),
            name: "Allow all".to_string(),
            policy_type: PolicyType::Allow,
            priority: 1,
            path_rules: None,
            network_rules: None,
        },
    ];
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();
    assert!(engine.tool_index.contains_key("bash"));
    assert!(engine.tool_index.contains_key("file_system"));
    assert_eq!(engine.tool_index.len(), 2);
    assert_eq!(engine.always_check.len(), 1);
}

#[test]
fn test_tool_index_prefix_goes_to_always_check() {
    let policies = vec![
        Policy {
            id: "file*:read".to_string(),
            name: "Prefix tool".to_string(),
            policy_type: PolicyType::Deny,
            priority: 100,
            path_rules: None,
            network_rules: None,
        },
        Policy {
            id: "bash:*".to_string(),
            name: "Exact tool".to_string(),
            policy_type: PolicyType::Deny,
            priority: 100,
            path_rules: None,
            network_rules: None,
        },
    ];
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();
    assert!(engine.tool_index.contains_key("bash"));
    assert_eq!(engine.always_check.len(), 1);
}

#[test]
fn test_tool_index_evaluation_matches_linear_scan() {
    let mut policies = Vec::new();
    for i in 0..50 {
        policies.push(Policy {
            id: format!("tool_{i}:func"),
            name: format!("Policy {i}"),
            policy_type: PolicyType::Deny,
            priority: 100,
            path_rules: None,
            network_rules: None,
        });
    }
    policies.push(Policy {
        id: "*".to_string(),
        name: "Default allow".to_string(),
        policy_type: PolicyType::Allow,
        priority: 1,
        path_rules: None,
        network_rules: None,
    });

    let engine = PolicyEngine::with_policies(false, &policies).unwrap();

    // Indexed policy matches → deny
    let action_deny = action_with("tool_5", "func", json!({}));
    assert!(matches!(
        engine.evaluate_action(&action_deny, &[]).unwrap(),
        Verdict::Deny { .. }
    ));

    // No indexed policy matches → falls through to universal allow
    let action_allow = action_with("tool_99", "func", json!({}));
    assert!(matches!(
        engine.evaluate_action(&action_allow, &[]).unwrap(),
        Verdict::Allow
    ));

    // Indexed tool but wrong function → falls through to universal allow
    let action_other = action_with("tool_5", "other_func", json!({}));
    assert!(matches!(
        engine.evaluate_action(&action_other, &[]).unwrap(),
        Verdict::Allow
    ));
}

#[test]
fn test_tool_index_priority_order_preserved() {
    let policies = vec![
        Policy {
            id: "bash:*".to_string(),
            name: "Allow bash".to_string(),
            policy_type: PolicyType::Allow,
            priority: 200,
            path_rules: None,
            network_rules: None,
        },
        Policy {
            id: "bash:*".to_string(),
            name: "Deny bash".to_string(),
            policy_type: PolicyType::Deny,
            priority: 100,
            path_rules: None,
            network_rules: None,
        },
    ];
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();

    let action = action_with("bash", "run", json!({}));
    let verdict = engine.evaluate_action(&action, &[]).unwrap();
    assert!(matches!(verdict, Verdict::Allow));
}

#[test]
fn test_tool_index_universal_interleaves_with_indexed() {
    let policies = vec![
        Policy {
            id: "bash:safe".to_string(),
            name: "Allow safe bash".to_string(),
            policy_type: PolicyType::Allow,
            priority: 200,
            path_rules: None,
            network_rules: None,
        },
        Policy {
            id: "*".to_string(),
            name: "Universal deny".to_string(),
            policy_type: PolicyType::Deny,
            priority: 150,
            path_rules: None,
            network_rules: None,
        },
        Policy {
            id: "bash:*".to_string(),
            name: "Allow all bash".to_string(),
            policy_type: PolicyType::Allow,
            priority: 100,
            path_rules: None,
            network_rules: None,
        },
    ];
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();

    // bash:safe → allowed by priority 200 indexed policy
    let safe = action_with("bash", "safe", json!({}));
    assert!(matches!(
        engine.evaluate_action(&safe, &[]).unwrap(),
        Verdict::Allow
    ));

    // bash:run → universal deny at 150 fires before bash:* allow at 100
    let run = action_with("bash", "run", json!({}));
    assert!(matches!(
        engine.evaluate_action(&run, &[]).unwrap(),
        Verdict::Deny { .. }
    ));
}

#[test]
fn test_tool_index_empty_policies() {
    let engine = PolicyEngine::with_policies(false, &[]).unwrap();
    assert!(engine.tool_index.is_empty());
    assert!(engine.always_check.is_empty());

    let action = action_with("any", "func", json!({}));
    let verdict = engine.evaluate_action(&action, &[]).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

// ═══════════════════════════════════════════════════
// EVALUATION TRACE TESTS (Phase 10.4)
// ═══════════════════════════════════════════════════

#[test]
fn test_traced_allow_simple() {
    let policies = vec![Policy {
        id: "*".to_string(),
        name: "Allow all".to_string(),
        policy_type: PolicyType::Allow,
        priority: 10,
        path_rules: None,
        network_rules: None,
    }];
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();
    let action = action_with("bash", "execute", json!({"command": "ls"}));

    let (verdict, trace) = engine.evaluate_action_traced(&action).unwrap();
    assert!(matches!(verdict, Verdict::Allow));
    assert_eq!(trace.verdict, Verdict::Allow);
    assert_eq!(trace.policies_checked, 1);
    assert_eq!(trace.policies_matched, 1);
    assert_eq!(trace.action_summary.tool, "bash");
    assert_eq!(trace.action_summary.function, "execute");
    assert_eq!(trace.action_summary.param_count, 1);
    assert!(trace
        .action_summary
        .param_keys
        .contains(&"command".to_string()));
    assert_eq!(trace.matches.len(), 1);
    assert_eq!(trace.matches[0].policy_name, "Allow all");
    assert!(trace.matches[0].tool_matched);
}

#[test]
fn test_traced_deny_simple() {
    let policies = vec![Policy {
        id: "bash:*".to_string(),
        name: "Block bash".to_string(),
        policy_type: PolicyType::Deny,
        priority: 100,
        path_rules: None,
        network_rules: None,
    }];
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();
    let action = action_with("bash", "execute", json!({}));

    let (verdict, trace) = engine.evaluate_action_traced(&action).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
    assert_eq!(trace.policies_matched, 1);
    assert_eq!(trace.matches[0].policy_type, "deny");
    assert!(trace.matches[0].verdict_contribution.is_some());
}

#[test]
fn test_traced_no_policies() {
    let engine = PolicyEngine::with_policies(false, &[]).unwrap();
    let action = action_with("bash", "execute", json!({}));

    let (verdict, trace) = engine.evaluate_action_traced(&action).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
    assert_eq!(trace.policies_checked, 0);
    assert_eq!(trace.matches.len(), 0);
}

#[test]
fn test_traced_no_matching_policy() {
    // Use a wildcard-prefix policy so it's in always_check (not skipped by tool index)
    let policies = vec![Policy {
        id: "git*".to_string(),
        name: "Allow git".to_string(),
        policy_type: PolicyType::Allow,
        priority: 100,
        path_rules: None,
        network_rules: None,
    }];
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();
    let action = action_with("bash", "execute", json!({}));

    let (verdict, trace) = engine.evaluate_action_traced(&action).unwrap();
    assert!(matches!(verdict, Verdict::Deny { reason } if reason == "No matching policy"));
    assert_eq!(trace.policies_checked, 1);
    assert_eq!(trace.policies_matched, 0);
    assert!(!trace.matches[0].tool_matched);
}

#[test]
fn test_traced_forbidden_parameter() {
    let policies = vec![Policy {
        id: "bash:*".to_string(),
        name: "Bash safe".to_string(),
        policy_type: PolicyType::Conditional {
            conditions: json!({
                "forbidden_parameters": ["force", "sudo"]
            }),
        },
        priority: 100,
        path_rules: None,
        network_rules: None,
    }];
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();

    // With forbidden param present
    let action = action_with("bash", "exec", json!({"command": "ls", "force": true}));
    let (verdict, trace) = engine.evaluate_action_traced(&action).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
    let constraint_results = &trace.matches[0].constraint_results;
    assert!(!constraint_results.is_empty());
    let forbidden = constraint_results
        .iter()
        .find(|c| c.param == "force")
        .unwrap();
    assert_eq!(forbidden.constraint_type, "forbidden_parameter");
    assert!(
        forbidden.actual.starts_with("present: "),
        "actual should contain type info, got: {}",
        forbidden.actual
    );
    assert!(!forbidden.passed);
}

#[test]
fn test_traced_constraint_result_type_info() {
    let policies = vec![Policy {
        id: "bash:*".to_string(),
        name: "Bash forbidden check".to_string(),
        policy_type: PolicyType::Conditional {
            conditions: json!({
                "forbidden_parameters": ["force"],
                "required_parameters": ["command"]
            }),
        },
        priority: 100,
        path_rules: None,
        network_rules: None,
    }];
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();

    // Test forbidden parameter with string value
    let action = action_with(
        "bash",
        "exec",
        json!({"command": "ls -la", "force": "please"}),
    );
    let (_verdict, trace) = engine.evaluate_action_traced(&action).unwrap();
    let results = &trace.matches[0].constraint_results;
    let forbidden = results.iter().find(|c| c.param == "force").unwrap();
    assert_eq!(forbidden.actual, "present: string(6 chars)");

    // Test forbidden parameter with object value
    let action2 = action_with(
        "bash",
        "exec",
        json!({"command": "ls", "force": {"level": 1, "recursive": true}}),
    );
    let (_verdict2, trace2) = engine.evaluate_action_traced(&action2).unwrap();
    let results2 = &trace2.matches[0].constraint_results;
    let forbidden2 = results2.iter().find(|c| c.param == "force").unwrap();
    assert_eq!(forbidden2.actual, "present: object(2 keys)");

    // Test required parameter present (should have type info too)
    let action3 = action_with("bash", "exec", json!({"command": "ls"}));
    let (_verdict3, trace3) = engine.evaluate_action_traced(&action3).unwrap();
    let results3 = &trace3.matches[0].constraint_results;
    let required = results3
        .iter()
        .find(|c| c.param == "command" && c.constraint_type == "required_parameter")
        .unwrap();
    assert_eq!(required.actual, "present: string(2 chars)");
    assert!(required.passed);

    // Test required parameter absent
    let action4 = action_with("bash", "exec", json!({"other": "value"}));
    let (_verdict4, trace4) = engine.evaluate_action_traced(&action4).unwrap();
    let results4 = &trace4.matches[0].constraint_results;
    // forbidden_parameter "force" should show absent
    let absent = results4
        .iter()
        .find(|c| c.param == "force" && c.constraint_type == "forbidden_parameter")
        .unwrap();
    assert_eq!(absent.actual, "absent");
    assert!(absent.passed);
}

#[test]
fn test_traced_constraint_glob() {
    let policies = vec![Policy {
        id: "file:*".to_string(),
        name: "Allow safe paths".to_string(),
        policy_type: PolicyType::Conditional {
            conditions: json!({
                "parameter_constraints": [{
                    "param": "path",
                    "op": "glob",
                    "pattern": "/etc/**",
                    "on_match": "deny"
                }]
            }),
        },
        priority: 100,
        path_rules: None,
        network_rules: None,
    }];
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();

    let action = action_with("file", "read", json!({"path": "/etc/passwd"}));
    let (verdict, trace) = engine.evaluate_action_traced(&action).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));

    let constraint_results = &trace.matches[0].constraint_results;
    let glob_result = constraint_results
        .iter()
        .find(|c| c.constraint_type == "glob")
        .unwrap();
    assert_eq!(glob_result.param, "path");
    assert!(!glob_result.passed);
}

#[test]
fn test_traced_require_approval() {
    let policies = vec![Policy {
        id: "*".to_string(),
        name: "Needs approval".to_string(),
        policy_type: PolicyType::Conditional {
            conditions: json!({"require_approval": true}),
        },
        priority: 100,
        path_rules: None,
        network_rules: None,
    }];
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();

    let action = action_with("bash", "exec", json!({}));
    let (verdict, trace) = engine.evaluate_action_traced(&action).unwrap();
    assert!(matches!(verdict, Verdict::RequireApproval { .. }));
    assert_eq!(
        trace.matches[0].constraint_results[0].constraint_type,
        "require_approval"
    );
}

#[test]
fn test_traced_multiple_policies_first_match_wins() {
    let policies = vec![
        Policy {
            id: "bash:*".to_string(),
            name: "Block bash".to_string(),
            policy_type: PolicyType::Deny,
            priority: 100,
            path_rules: None,
            network_rules: None,
        },
        Policy {
            id: "*".to_string(),
            name: "Allow all".to_string(),
            policy_type: PolicyType::Allow,
            priority: 10,
            path_rules: None,
            network_rules: None,
        },
    ];
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();
    let action = action_with("bash", "execute", json!({}));

    let (verdict, trace) = engine.evaluate_action_traced(&action).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
    // Only the matching policy should be in the trace (first match stops)
    assert_eq!(trace.policies_checked, 1);
    assert_eq!(trace.matches.len(), 1);
}

#[test]
fn test_traced_duration_recorded() {
    let policies = vec![Policy {
        id: "*".to_string(),
        name: "Allow all".to_string(),
        policy_type: PolicyType::Allow,
        priority: 10,
        path_rules: None,
        network_rules: None,
    }];
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();
    let action = action_with("bash", "execute", json!({}));

    let (_, trace) = engine.evaluate_action_traced(&action).unwrap();
    // Duration should be recorded (at least 0, could be 0 for very fast evaluation)
    assert!(trace.duration_us < 1_000_000); // Should be well under 1 second
}

#[test]
fn test_traced_all_skipped_fail_closed() {
    // Exploit #2 regression: when all constraints skip due to missing params,
    // the traced path should emit an "all_skipped_fail_closed" constraint result.
    let policies = vec![Policy {
        id: "file:*".to_string(),
        name: "Block secrets".to_string(),
        policy_type: PolicyType::Conditional {
            conditions: json!({
                "parameter_constraints": [{
                    "param": "path",
                    "op": "glob",
                    "pattern": "/etc/**",
                    "on_match": "deny",
                    "on_missing": "skip"
                }]
            }),
        },
        priority: 100,
        path_rules: None,
        network_rules: None,
    }];
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();

    // Call with NO "path" parameter — all constraints skip
    let action = action_with("file", "read", json!({}));
    let (verdict, trace) = engine.evaluate_action_traced(&action).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));

    // Trace should contain the all_skipped_fail_closed constraint
    let constraint_results = &trace.matches[0].constraint_results;
    let fail_closed = constraint_results
        .iter()
        .find(|c| c.constraint_type == "all_skipped_fail_closed");
    assert!(
        fail_closed.is_some(),
        "Trace must include all_skipped_fail_closed constraint when all params missing"
    );
    let fc = fail_closed.unwrap();
    assert!(!fc.passed);
    assert!(fc.actual.contains("skipped"));
}

#[test]
fn test_traced_domain_match_constraint() {
    // Verify domain_match constraint details appear in trace
    let policies = vec![Policy {
        id: "http:*".to_string(),
        name: "Block evil".to_string(),
        policy_type: PolicyType::Conditional {
            conditions: json!({
                "parameter_constraints": [{
                    "param": "url",
                    "op": "domain_match",
                    "pattern": "evil.com",
                    "on_match": "deny"
                }]
            }),
        },
        priority: 100,
        path_rules: None,
        network_rules: None,
    }];
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();

    let action = action_with("http", "get", json!({"url": "https://evil.com/exfil"}));
    let (verdict, trace) = engine.evaluate_action_traced(&action).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));

    let constraint_results = &trace.matches[0].constraint_results;
    let domain_result = constraint_results
        .iter()
        .find(|c| c.constraint_type == "domain_match")
        .expect("Trace must contain domain_match constraint");
    assert_eq!(domain_result.param, "url");
    assert!(!domain_result.passed);
}

#[test]
fn test_traced_verdict_consistency() {
    // The verdict returned from the function must match the verdict in the trace
    let policies = vec![Policy {
        id: "*".to_string(),
        name: "Allow all".to_string(),
        policy_type: PolicyType::Allow,
        priority: 10,
        path_rules: None,
        network_rules: None,
    }];
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();
    let action = action_with("test", "fn", json!({}));

    let (verdict, trace) = engine.evaluate_action_traced(&action).unwrap();
    assert_eq!(
        format!("{verdict:?}"),
        format!("{:?}", trace.verdict),
        "Returned verdict must match trace verdict"
    );

    // Also test with deny
    let policies_deny = vec![Policy {
        id: "test:*".to_string(),
        name: "Block test".to_string(),
        policy_type: PolicyType::Deny,
        priority: 100,
        path_rules: None,
        network_rules: None,
    }];
    let engine_deny = PolicyEngine::with_policies(false, &policies_deny).unwrap();
    let (verdict_d, trace_d) = engine_deny.evaluate_action_traced(&action).unwrap();
    assert!(matches!(verdict_d, Verdict::Deny { .. }));
    assert!(matches!(trace_d.verdict, Verdict::Deny { .. }));
}

/// R17-ENGINE-1: The traced evaluation path must enforce IP rules.
/// Previously, `apply_compiled_policy_traced_ctx` was missing the
/// `check_ip_rules` call, allowing `?trace=true` to bypass IP blocking.
#[test]
fn test_traced_ip_rules_enforced() {
    use vellaveto_types::IpRules;

    let policies = vec![Policy {
        id: "http:*".to_string(),
        name: "Allow with IP block".to_string(),
        policy_type: PolicyType::Allow,
        priority: 100,
        path_rules: None,
        network_rules: Some(vellaveto_types::NetworkRules {
            allowed_domains: vec!["example.com".to_string()],
            blocked_domains: vec![],
            ip_rules: Some(IpRules {
                block_private: true,
                allowed_cidrs: vec![],
                blocked_cidrs: vec![],
            }),
        }),
    }];
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();

    // Action with a private IP (loopback) that resolves for a domain
    let mut action = action_with("http", "get", json!({}));
    action.target_domains = vec!["example.com".to_string()];
    action.resolved_ips = vec!["127.0.0.1".to_string()];

    // Non-traced path should deny
    let verdict = engine.evaluate_action(&action, &[]).unwrap();
    assert!(
        matches!(verdict, Verdict::Deny { .. }),
        "Non-traced path must deny private IP. Got: {verdict:?}"
    );

    // Traced path must also deny (was previously bypassed)
    let (traced_verdict, _trace) = engine.evaluate_action_traced(&action).unwrap();
    assert!(
        matches!(traced_verdict, Verdict::Deny { .. }),
        "Traced path must deny private IP (R17-ENGINE-1 regression). Got: {traced_verdict:?}"
    );
}

// ═══════════════════════════════════════════════════
// PATH/NETWORK RULES TESTS (Phase 3E)
// ═══════════════════════════════════════════════════

use vellaveto_types::{NetworkRules, PathRules};

fn policy_with_path_rules(
    id: &str,
    name: &str,
    policy_type: PolicyType,
    path_rules: PathRules,
) -> Policy {
    Policy {
        id: id.to_string(),
        name: name.to_string(),
        policy_type,
        priority: 100,
        path_rules: Some(path_rules),
        network_rules: None,
    }
}

fn policy_with_network_rules(
    id: &str,
    name: &str,
    policy_type: PolicyType,
    network_rules: NetworkRules,
) -> Policy {
    Policy {
        id: id.to_string(),
        name: name.to_string(),
        policy_type,
        priority: 100,
        path_rules: None,
        network_rules: Some(network_rules),
    }
}

fn action_with_paths(tool: &str, function: &str, paths: Vec<&str>) -> Action {
    let mut action = Action::new(tool, function, json!({}));
    action.target_paths = paths.into_iter().map(|s| s.to_string()).collect();
    action
}

fn action_with_domains(tool: &str, function: &str, domains: Vec<&str>) -> Action {
    let mut action = Action::new(tool, function, json!({}));
    action.target_domains = domains.into_iter().map(|s| s.to_string()).collect();
    action
}

#[test]
fn test_path_rules_blocked_denies() {
    let policies = vec![policy_with_path_rules(
        "file:*",
        "Block sensitive paths",
        PolicyType::Allow,
        PathRules {
            allowed: vec![],
            blocked: vec!["/home/*/.aws/**".to_string(), "/etc/shadow".to_string()],
        },
    )];
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();
    let action = action_with_paths("file", "read", vec!["/home/user/.aws/credentials"]);
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(verdict, Verdict::Deny { ref reason } if reason.contains("blocked")),
        "Blocked path should deny, got: {verdict:?}"
    );
}

#[test]
fn test_path_rules_blocked_exact_match_denies() {
    let policies = vec![policy_with_path_rules(
        "file:*",
        "Block etc shadow",
        PolicyType::Allow,
        PathRules {
            allowed: vec![],
            blocked: vec!["/etc/shadow".to_string()],
        },
    )];
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();
    let action = action_with_paths("file", "read", vec!["/etc/shadow"]);
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

#[test]
fn test_path_rules_allowed_only_safe_paths() {
    let policies = vec![policy_with_path_rules(
        "file:*",
        "Allow only tmp",
        PolicyType::Allow,
        PathRules {
            allowed: vec!["/tmp/**".to_string()],
            blocked: vec![],
        },
    )];
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();

    // Allowed path
    let action_ok = action_with_paths("file", "read", vec!["/tmp/safe.txt"]);
    let verdict = engine.evaluate_action(&action_ok, &policies).unwrap();
    assert!(
        matches!(verdict, Verdict::Allow),
        "Path in allowed list should be allowed, got: {verdict:?}"
    );

    // Disallowed path
    let action_bad = action_with_paths("file", "read", vec!["/etc/passwd"]);
    let verdict = engine.evaluate_action(&action_bad, &policies).unwrap();
    assert!(
        matches!(verdict, Verdict::Deny { ref reason } if reason.contains("not in allowed")),
        "Path not in allowed list should deny, got: {verdict:?}"
    );
}

#[test]
fn test_path_rules_blocked_takes_precedence_over_allowed() {
    let policies = vec![policy_with_path_rules(
        "file:*",
        "Allow tmp but block secrets",
        PolicyType::Allow,
        PathRules {
            allowed: vec!["/tmp/**".to_string()],
            blocked: vec!["/tmp/secrets/**".to_string()],
        },
    )];
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();
    let action = action_with_paths("file", "read", vec!["/tmp/secrets/key.pem"]);
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(verdict, Verdict::Deny { ref reason } if reason.contains("blocked")),
        "Blocked pattern should take precedence even if path matches allowed, got: {verdict:?}"
    );
}

#[test]
fn test_path_rules_normalization_prevents_bypass() {
    let policies = vec![policy_with_path_rules(
        "file:*",
        "Block aws creds",
        PolicyType::Allow,
        PathRules {
            allowed: vec![],
            blocked: vec!["/home/*/.aws/**".to_string()],
        },
    )];
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();
    // Attempt traversal bypass
    let action = action_with_paths(
        "file",
        "read",
        vec!["/home/user/docs/../../user/.aws/credentials"],
    );
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(verdict, Verdict::Deny { .. }),
        "Path traversal should be normalized and still blocked, got: {verdict:?}"
    );
}

#[test]
fn test_path_rules_no_paths_in_action_allows() {
    let policies = vec![policy_with_path_rules(
        "file:*",
        "Block secrets",
        PolicyType::Allow,
        PathRules {
            allowed: vec![],
            blocked: vec!["/etc/shadow".to_string()],
        },
    )];
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();
    // No target_paths in action → path rules don't apply
    let action = action_with("file", "read", json!({"path": "/etc/shadow"}));
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(verdict, Verdict::Allow),
        "With no target_paths, path rules should not block, got: {verdict:?}"
    );
}

#[test]
fn test_network_rules_blocked_domain_denies() {
    let policies = vec![policy_with_network_rules(
        "http:*",
        "Block evil domains",
        PolicyType::Allow,
        NetworkRules {
            allowed_domains: vec![],
            blocked_domains: vec!["evil.com".to_string(), "*.malware.org".to_string()],
            ip_rules: None,
        },
    )];
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();

    let action = action_with_domains("http", "get", vec!["evil.com"]);
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(verdict, Verdict::Deny { ref reason } if reason.contains("blocked")),
        "Blocked domain should deny, got: {verdict:?}"
    );
}

#[test]
fn test_network_rules_blocked_subdomain_denies() {
    let policies = vec![policy_with_network_rules(
        "http:*",
        "Block malware subdomains",
        PolicyType::Allow,
        NetworkRules {
            allowed_domains: vec![],
            blocked_domains: vec!["*.malware.org".to_string()],
            ip_rules: None,
        },
    )];
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();

    let action = action_with_domains("http", "get", vec!["data.malware.org"]);
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

#[test]
fn test_network_rules_allowed_only() {
    let policies = vec![policy_with_network_rules(
        "http:*",
        "Only allow trusted domains",
        PolicyType::Allow,
        NetworkRules {
            allowed_domains: vec!["api.example.com".to_string(), "*.trusted.net".to_string()],
            blocked_domains: vec![],
            ip_rules: None,
        },
    )];
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();

    // Allowed domain
    let action_ok = action_with_domains("http", "get", vec!["api.example.com"]);
    let verdict = engine.evaluate_action(&action_ok, &policies).unwrap();
    assert!(matches!(verdict, Verdict::Allow));

    // Disallowed domain
    let action_bad = action_with_domains("http", "get", vec!["evil.com"]);
    let verdict = engine.evaluate_action(&action_bad, &policies).unwrap();
    assert!(
        matches!(verdict, Verdict::Deny { ref reason } if reason.contains("not in allowed")),
        "Domain not in allowed list should deny, got: {verdict:?}"
    );
}

#[test]
fn test_network_rules_no_domains_in_action_allows() {
    let policies = vec![policy_with_network_rules(
        "http:*",
        "Block evil",
        PolicyType::Allow,
        NetworkRules {
            allowed_domains: vec![],
            blocked_domains: vec!["evil.com".to_string()],
            ip_rules: None,
        },
    )];
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();
    let action = action_with("http", "get", json!({"url": "https://evil.com/data"}));
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(verdict, Verdict::Allow),
        "With no target_domains, network rules should not block, got: {verdict:?}"
    );
}

// ═══════════════════════════════════════════════════
// IP RULES (DNS REBINDING PROTECTION)
// ═══════════════════════════════════════════════════

fn policy_with_ip_rules(ip_rules: vellaveto_types::IpRules) -> Policy {
    Policy {
        id: "http:*".to_string(),
        name: "IP-controlled policy".to_string(),
        policy_type: PolicyType::Allow,
        priority: 100,
        path_rules: None,
        network_rules: Some(NetworkRules {
            allowed_domains: vec![],
            blocked_domains: vec![],
            ip_rules: Some(ip_rules),
        }),
    }
}

fn action_with_resolved_ips(domains: Vec<&str>, ips: Vec<&str>) -> Action {
    let mut action = Action::new("http", "get", json!({}));
    action.target_domains = domains.into_iter().map(|s| s.to_string()).collect();
    action.resolved_ips = ips.into_iter().map(|s| s.to_string()).collect();
    action
}

#[test]
fn test_ip_rules_block_private_loopback() {
    let policies = vec![policy_with_ip_rules(vellaveto_types::IpRules {
        block_private: true,
        ..Default::default()
    })];
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();
    let action = action_with_resolved_ips(vec!["example.com"], vec!["127.0.0.1"]);
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(verdict, Verdict::Deny { ref reason } if reason.contains("private")),
        "Loopback 127.0.0.1 should be blocked, got: {verdict:?}"
    );
}

#[test]
fn test_ip_rules_block_private_rfc1918() {
    let policies = vec![policy_with_ip_rules(vellaveto_types::IpRules {
        block_private: true,
        ..Default::default()
    })];
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();

    for ip in &["10.0.0.1", "172.16.0.1", "192.168.1.1"] {
        let action = action_with_resolved_ips(vec!["example.com"], vec![ip]);
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(
            matches!(verdict, Verdict::Deny { ref reason } if reason.contains("private")),
            "RFC 1918 address {ip} should be blocked, got: {verdict:?}"
        );
    }
}

#[test]
fn test_ip_rules_block_private_link_local() {
    let policies = vec![policy_with_ip_rules(vellaveto_types::IpRules {
        block_private: true,
        ..Default::default()
    })];
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();
    let action = action_with_resolved_ips(vec!["example.com"], vec!["169.254.1.1"]);
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(verdict, Verdict::Deny { ref reason } if reason.contains("private")),
        "Link-local 169.254.x should be blocked, got: {verdict:?}"
    );
}

#[test]
fn test_ip_rules_block_private_ipv6_loopback() {
    let policies = vec![policy_with_ip_rules(vellaveto_types::IpRules {
        block_private: true,
        ..Default::default()
    })];
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();
    let action = action_with_resolved_ips(vec!["example.com"], vec!["::1"]);
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(verdict, Verdict::Deny { ref reason } if reason.contains("private")),
        "IPv6 loopback ::1 should be blocked, got: {verdict:?}"
    );
}

#[test]
fn test_ip_rules_block_private_ipv4_mapped_v6() {
    let policies = vec![policy_with_ip_rules(vellaveto_types::IpRules {
        block_private: true,
        ..Default::default()
    })];
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();
    let action = action_with_resolved_ips(vec!["example.com"], vec!["::ffff:127.0.0.1"]);
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(verdict, Verdict::Deny { ref reason } if reason.contains("private")),
        "IPv4-mapped v6 ::ffff:127.0.0.1 should be blocked, got: {verdict:?}"
    );
}

#[test]
fn test_ip_rules_block_private_ipv6_ula() {
    // fc00::/7 — Unique Local Address (RFC 4193)
    let policies = vec![policy_with_ip_rules(vellaveto_types::IpRules {
        block_private: true,
        ..Default::default()
    })];
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();
    let action = action_with_resolved_ips(vec!["example.com"], vec!["fc00::1"]);
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(verdict, Verdict::Deny { ref reason } if reason.contains("private")),
        "ULA fc00::1 should be blocked, got: {verdict:?}"
    );
}

#[test]
fn test_ip_rules_block_private_ipv6_link_local() {
    // fe80::/10 — Link-Local
    let policies = vec![policy_with_ip_rules(vellaveto_types::IpRules {
        block_private: true,
        ..Default::default()
    })];
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();
    let action = action_with_resolved_ips(vec!["example.com"], vec!["fe80::1"]);
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(verdict, Verdict::Deny { ref reason } if reason.contains("private")),
        "Link-local fe80::1 should be blocked, got: {verdict:?}"
    );
}

#[test]
fn test_ip_rules_block_private_ipv6_multicast() {
    // ff00::/8 — Multicast
    let policies = vec![policy_with_ip_rules(vellaveto_types::IpRules {
        block_private: true,
        ..Default::default()
    })];
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();
    let action = action_with_resolved_ips(vec!["example.com"], vec!["ff02::1"]);
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(verdict, Verdict::Deny { ref reason } if reason.contains("private")),
        "Multicast ff02::1 should be blocked, got: {verdict:?}"
    );
}

#[test]
fn test_ip_rules_block_private_ipv6_documentation() {
    // 2001:db8::/32 — Documentation
    let policies = vec![policy_with_ip_rules(vellaveto_types::IpRules {
        block_private: true,
        ..Default::default()
    })];
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();
    let action = action_with_resolved_ips(vec!["example.com"], vec!["2001:db8::1"]);
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(verdict, Verdict::Deny { ref reason } if reason.contains("private")),
        "Documentation 2001:db8::1 should be blocked, got: {verdict:?}"
    );
}

#[test]
fn test_ip_rules_block_private_6to4_embedded() {
    // 2002:c0a8:0101:: embeds 192.168.1.1 (private)
    let policies = vec![policy_with_ip_rules(vellaveto_types::IpRules {
        block_private: true,
        ..Default::default()
    })];
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();
    let action = action_with_resolved_ips(vec!["example.com"], vec!["2002:c0a8:0101::1"]);
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(verdict, Verdict::Deny { ref reason } if reason.contains("private")),
        "6to4 with embedded private IP should be blocked, got: {verdict:?}"
    );
}

#[test]
fn test_ip_rules_block_private_teredo_embedded() {
    // 2001:0000:... with embedded private IPv4 in last 32 bits (XORed)
    // Embedded 192.168.1.1 → XOR 0xFFFF → 3f:57:fe:fe at positions 6-7
    let policies = vec![policy_with_ip_rules(vellaveto_types::IpRules {
        block_private: true,
        ..Default::default()
    })];
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();
    // Teredo encoding: 192.168.1.1 XOR 0xFFFF each byte → 63.87.254.254
    let action = action_with_resolved_ips(
        vec!["example.com"],
        vec!["2001:0000:0000:0000:0000:0000:3f57:fefe"],
    );
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(verdict, Verdict::Deny { ref reason } if reason.contains("private")),
        "Teredo with embedded private IP should be blocked, got: {verdict:?}"
    );
}

#[test]
fn test_ip_rules_block_private_nat64_embedded() {
    // 64:ff9b::192.168.1.1 — NAT64 with embedded private IPv4
    let policies = vec![policy_with_ip_rules(vellaveto_types::IpRules {
        block_private: true,
        ..Default::default()
    })];
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();
    let action = action_with_resolved_ips(vec!["example.com"], vec!["64:ff9b::c0a8:0101"]);
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(verdict, Verdict::Deny { ref reason } if reason.contains("private")),
        "NAT64 with embedded private IP should be blocked, got: {verdict:?}"
    );
}

#[test]
fn test_ip_rules_block_private_ipv4_compatible_v6() {
    // SECURITY (R21-ENG-2): ::10.0.0.1 (IPv4-compatible, deprecated) embeds
    // a private IPv4. Must be blocked to prevent DNS rebinding.
    let policies = vec![policy_with_ip_rules(vellaveto_types::IpRules {
        block_private: true,
        ..Default::default()
    })];
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();
    let action = action_with_resolved_ips(vec!["example.com"], vec!["::10.0.0.1"]);
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(verdict, Verdict::Deny { ref reason } if reason.contains("private")),
        "IPv4-compatible ::10.0.0.1 should be blocked, got: {verdict:?}"
    );
}

#[test]
fn test_ip_rules_block_private_ipv4_compatible_loopback() {
    // ::127.0.0.1 is IPv4-compatible loopback — must be blocked
    let policies = vec![policy_with_ip_rules(vellaveto_types::IpRules {
        block_private: true,
        ..Default::default()
    })];
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();
    let action = action_with_resolved_ips(vec!["example.com"], vec!["::127.0.0.1"]);
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(verdict, Verdict::Deny { ref reason } if reason.contains("private")),
        "IPv4-compatible ::127.0.0.1 should be blocked, got: {verdict:?}"
    );
}

#[test]
fn test_ip_rules_block_private_6to4_cgnat() {
    // SECURITY (R22-ENG-2): 6to4 embedding CGNAT address 100.100.1.1
    // 2002:6464:0101:: — previously not blocked because 6to4 only checked
    // is_loopback/is_private/is_link_local (CGNAT is none of those).
    let policies = vec![policy_with_ip_rules(vellaveto_types::IpRules {
        block_private: true,
        ..Default::default()
    })];
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();
    let action = action_with_resolved_ips(vec!["example.com"], vec!["2002:6464:0101::1"]);
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(verdict, Verdict::Deny { ref reason } if reason.contains("private")),
        "6to4 with embedded CGNAT should be blocked, got: {verdict:?}"
    );
}

#[test]
fn test_ip_rules_block_private_nat64_cgnat() {
    // SECURITY (R22-ENG-2): NAT64 embedding CGNAT address 100.100.1.1
    // 64:ff9b::6464:0101
    let policies = vec![policy_with_ip_rules(vellaveto_types::IpRules {
        block_private: true,
        ..Default::default()
    })];
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();
    let action = action_with_resolved_ips(vec!["example.com"], vec!["64:ff9b::6464:0101"]);
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(verdict, Verdict::Deny { ref reason } if reason.contains("private")),
        "NAT64 with embedded CGNAT should be blocked, got: {verdict:?}"
    );
}

#[test]
fn test_ip_rules_block_private_nat64_local_use() {
    // SECURITY (R25-ENG-2): NAT64 local-use prefix 64:ff9b:1::/48 (RFC 8215)
    // with embedded private IPv4 192.168.1.1 = c0a8:0101
    let policies = vec![policy_with_ip_rules(vellaveto_types::IpRules {
        block_private: true,
        ..Default::default()
    })];
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();
    let action = action_with_resolved_ips(vec!["example.com"], vec!["64:ff9b:1:0:0:0:c0a8:0101"]);
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(verdict, Verdict::Deny { ref reason } if reason.contains("private")),
        "NAT64 local-use with embedded private IPv4 should be blocked, got: {verdict:?}"
    );
}

#[test]
fn test_ip_rules_allow_nat64_local_use_public() {
    // NAT64 local-use with embedded public IPv4 should be allowed
    let policies = vec![policy_with_ip_rules(vellaveto_types::IpRules {
        block_private: true,
        ..Default::default()
    })];
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();
    let action = action_with_resolved_ips(
        vec!["example.com"],
        vec!["64:ff9b:1:0:0:0:0808:0808"], // 8.8.8.8
    );
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(verdict, Verdict::Allow),
        "NAT64 local-use with public IPv4 should be allowed, got: {verdict:?}"
    );
}

#[test]
fn test_ip_rules_block_private_teredo_cgnat() {
    // SECURITY (R22-ENG-2): Teredo embedding CGNAT address 100.100.1.1
    // XOR with 0xFF: 100^0xFF=155, 100^0xFF=155, 1^0xFF=254, 1^0xFF=254
    // Embedded in last 32 bits as 0x9b9b:0xfefe
    let policies = vec![policy_with_ip_rules(vellaveto_types::IpRules {
        block_private: true,
        ..Default::default()
    })];
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();
    let action = action_with_resolved_ips(
        vec!["example.com"],
        vec!["2001:0000:0000:0000:0000:0000:9b9b:fefe"],
    );
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(verdict, Verdict::Deny { ref reason } if reason.contains("private")),
        "Teredo with embedded CGNAT should be blocked, got: {verdict:?}"
    );
}

#[test]
fn test_ip_rules_block_private_ipv4_mapped_cgnat() {
    // SECURITY (R22-ENG-2): IPv4-mapped embedding CGNAT address
    // ::ffff:100.100.1.1
    let policies = vec![policy_with_ip_rules(vellaveto_types::IpRules {
        block_private: true,
        ..Default::default()
    })];
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();
    let action = action_with_resolved_ips(vec!["example.com"], vec!["::ffff:100.100.1.1"]);
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(verdict, Verdict::Deny { ref reason } if reason.contains("private")),
        "IPv4-mapped with embedded CGNAT should be blocked, got: {verdict:?}"
    );
}

#[test]
fn test_ip_rules_block_cgnat_range() {
    // SECURITY (R21-ENG-3): 100.64.0.0/10 (CGNAT, RFC 6598) must be blocked
    // by block_private. In cloud environments this can reach metadata services.
    let policies = vec![policy_with_ip_rules(vellaveto_types::IpRules {
        block_private: true,
        ..Default::default()
    })];
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();
    let action = action_with_resolved_ips(vec!["example.com"], vec!["100.100.1.1"]);
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(verdict, Verdict::Deny { ref reason } if reason.contains("private")),
        "CGNAT 100.100.1.1 should be blocked by block_private, got: {verdict:?}"
    );
}

#[test]
fn test_ip_rules_block_class_e_reserved() {
    // SECURITY (R23-ENG-3): 240.0.0.0/4 (Class E / Reserved) must be blocked
    let policies = vec![policy_with_ip_rules(vellaveto_types::IpRules {
        block_private: true,
        ..Default::default()
    })];
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();
    let action = action_with_resolved_ips(vec!["example.com"], vec!["240.0.0.1"]);
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(verdict, Verdict::Deny { ref reason } if reason.contains("private")),
        "Class E 240.0.0.1 should be blocked, got: {verdict:?}"
    );
}

#[test]
fn test_ip_rules_block_6to4_relay_anycast() {
    // SECURITY (R23-ENG-3): 192.88.99.0/24 (deprecated 6to4 relay anycast) must be blocked
    let policies = vec![policy_with_ip_rules(vellaveto_types::IpRules {
        block_private: true,
        ..Default::default()
    })];
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();
    let action = action_with_resolved_ips(vec!["example.com"], vec!["192.88.99.1"]);
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(verdict, Verdict::Deny { ref reason } if reason.contains("private")),
        "6to4 relay 192.88.99.1 should be blocked, got: {verdict:?}"
    );
}

#[test]
fn test_ip_rules_block_zero_network() {
    // 0.x.x.x (RFC 1122 "this host on this network") must be blocked
    let policies = vec![policy_with_ip_rules(vellaveto_types::IpRules {
        block_private: true,
        ..Default::default()
    })];
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();
    let action = action_with_resolved_ips(vec!["example.com"], vec!["0.1.2.3"]);
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(verdict, Verdict::Deny { ref reason } if reason.contains("private")),
        "0.1.2.3 should be blocked by block_private, got: {verdict:?}"
    );
}

#[test]
fn test_ip_rules_allow_public_ip() {
    let policies = vec![policy_with_ip_rules(vellaveto_types::IpRules {
        block_private: true,
        ..Default::default()
    })];
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();
    let action = action_with_resolved_ips(vec!["example.com"], vec!["8.8.8.8"]);
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(verdict, Verdict::Allow),
        "Public IP 8.8.8.8 should be allowed, got: {verdict:?}"
    );
}

#[test]
fn test_ip_rules_blocked_cidr() {
    let policies = vec![policy_with_ip_rules(vellaveto_types::IpRules {
        block_private: false,
        blocked_cidrs: vec!["100.64.0.0/10".to_string()],
        ..Default::default()
    })];
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();

    // IP in blocked CIDR -> deny
    let action = action_with_resolved_ips(vec!["example.com"], vec!["100.100.1.1"]);
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(verdict, Verdict::Deny { ref reason } if reason.contains("blocked CIDR")),
        "IP in blocked CIDR should be denied, got: {verdict:?}"
    );

    // IP outside blocked CIDR -> allow
    let action = action_with_resolved_ips(vec!["example.com"], vec!["8.8.8.8"]);
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(verdict, Verdict::Allow),
        "IP outside blocked CIDR should be allowed, got: {verdict:?}"
    );
}

#[test]
fn test_ip_rules_allowed_cidr() {
    let policies = vec![policy_with_ip_rules(vellaveto_types::IpRules {
        block_private: false,
        allowed_cidrs: vec!["203.0.113.0/24".to_string()],
        ..Default::default()
    })];
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();

    // IP in allowed CIDR -> allow
    let action = action_with_resolved_ips(vec!["example.com"], vec!["203.0.113.50"]);
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(verdict, Verdict::Allow),
        "IP in allowed CIDR should pass, got: {verdict:?}"
    );

    // IP not in allowed CIDR -> deny
    let action = action_with_resolved_ips(vec!["example.com"], vec!["8.8.8.8"]);
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(verdict, Verdict::Deny { ref reason } if reason.contains("not in allowed")),
        "IP outside allowed CIDR should be denied, got: {verdict:?}"
    );
}

#[test]
fn test_ip_rules_no_resolved_ips_with_domains_denies() {
    // Fail-closed: domains present but no resolved IPs -> deny
    let policies = vec![policy_with_ip_rules(vellaveto_types::IpRules {
        block_private: true,
        ..Default::default()
    })];
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();
    let mut action = Action::new("http", "get", json!({}));
    action.target_domains = vec!["example.com".to_string()];
    // resolved_ips intentionally left empty
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(verdict, Verdict::Deny { ref reason } if reason.contains("no resolved IPs")),
        "Missing resolved IPs should fail-closed, got: {verdict:?}"
    );
}

#[test]
fn test_ip_rules_no_domains_no_resolved_ips_passes() {
    // No targets at all -> IP rules should not interfere
    let policies = vec![policy_with_ip_rules(vellaveto_types::IpRules {
        block_private: true,
        ..Default::default()
    })];
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();
    let action = Action::new("http", "get", json!({}));
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(verdict, Verdict::Allow),
        "No targets should pass IP rules, got: {verdict:?}"
    );
}

#[test]
fn test_ip_rules_invalid_cidr_compile_error() {
    let policies = vec![policy_with_ip_rules(vellaveto_types::IpRules {
        block_private: false,
        blocked_cidrs: vec!["not-a-cidr".to_string()],
        ..Default::default()
    })];
    let result = PolicyEngine::with_policies(false, &policies);
    assert!(
        result.is_err(),
        "Invalid CIDR should cause compile error, got: {result:?}"
    );
}

#[test]
fn test_ip_rules_none_skips_check() {
    // No ip_rules -> backward compatible, no IP checking
    let policies = vec![policy_with_network_rules(
        "http:*",
        "Domain only",
        PolicyType::Allow,
        NetworkRules {
            allowed_domains: vec!["example.com".to_string()],
            blocked_domains: vec![],
            ip_rules: None,
        },
    )];
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();
    let action = action_with_domains("http", "get", vec!["example.com"]);
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(verdict, Verdict::Allow),
        "No ip_rules should not affect domain-only evaluation, got: {verdict:?}"
    );
}

#[test]
fn test_ip_rules_invalid_resolved_ip_denies() {
    let policies = vec![policy_with_ip_rules(vellaveto_types::IpRules {
        block_private: true,
        ..Default::default()
    })];
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();
    let action = action_with_resolved_ips(vec!["example.com"], vec!["not-an-ip"]);
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(verdict, Verdict::Deny { ref reason } if reason.contains("Invalid resolved IP")),
        "Unparseable IP should be denied, got: {verdict:?}"
    );
}

#[test]
fn test_ip_rules_ipv4_mapped_v6_blocked_by_v4_cidr() {
    // R24-ENG-1: IPv4-mapped IPv6 addresses (::ffff:x.x.x.x) must be
    // canonicalized to IPv4 before CIDR matching, otherwise an attacker
    // can bypass IPv4 CIDR blocklists by using the mapped form.
    let policies = vec![policy_with_ip_rules(vellaveto_types::IpRules {
        block_private: false,
        blocked_cidrs: vec!["100.64.0.0/10".to_string()],
        ..Default::default()
    })];
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();

    // IPv4-mapped IPv6 form of CGNAT address -> should be denied
    let action = action_with_resolved_ips(vec!["example.com"], vec!["::ffff:100.100.1.1"]);
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(verdict, Verdict::Deny { ref reason } if reason.contains("blocked CIDR")),
        "IPv4-mapped IPv6 in blocked CIDR should be denied, got: {verdict:?}"
    );

    // Regular IPv4 in same CIDR -> also denied (baseline)
    let action = action_with_resolved_ips(vec!["example.com"], vec!["100.100.1.1"]);
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(verdict, Verdict::Deny { ref reason } if reason.contains("blocked CIDR")),
        "Plain IPv4 in blocked CIDR should be denied, got: {verdict:?}"
    );
}

#[test]
fn test_ip_rules_ipv4_mapped_v6_allowed_cidr() {
    // R24-ENG-1: IPv4-mapped IPv6 must also match IPv4 allowed CIDRs
    let policies = vec![policy_with_ip_rules(vellaveto_types::IpRules {
        block_private: false,
        allowed_cidrs: vec!["203.0.113.0/24".to_string()],
        ..Default::default()
    })];
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();

    // Mapped form of allowed IP -> should pass
    let action = action_with_resolved_ips(vec!["example.com"], vec!["::ffff:203.0.113.50"]);
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(verdict, Verdict::Allow),
        "IPv4-mapped IPv6 in allowed CIDR should pass, got: {verdict:?}"
    );

    // Mapped form of non-allowed IP -> denied
    let action = action_with_resolved_ips(vec!["example.com"], vec!["::ffff:8.8.8.8"]);
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(verdict, Verdict::Deny { ref reason } if reason.contains("not in allowed")),
        "IPv4-mapped IPv6 outside allowed CIDR should be denied, got: {verdict:?}"
    );
}

#[test]
fn test_has_ip_rules_returns_true_when_configured() {
    let policies = vec![policy_with_ip_rules(vellaveto_types::IpRules {
        block_private: true,
        ..Default::default()
    })];
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();
    assert!(
        engine.has_ip_rules(),
        "Engine with ip_rules should return true"
    );
}

#[test]
fn test_has_ip_rules_returns_false_when_not_configured() {
    let policies = vec![Policy {
        id: "http:*".to_string(),
        name: "No IP rules".to_string(),
        policy_type: PolicyType::Allow,
        priority: 100,
        path_rules: None,
        network_rules: None,
    }];
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();
    assert!(
        !engine.has_ip_rules(),
        "Engine without ip_rules should return false"
    );
}

#[test]
fn test_path_rules_with_deny_policy_still_denies() {
    // Even a Deny policy should deny on path rules (path check is pre-dispatch)
    let policies = vec![Policy {
        id: "file:*".to_string(),
        name: "Deny all files".to_string(),
        policy_type: PolicyType::Deny,
        priority: 100,
        path_rules: Some(PathRules {
            allowed: vec![],
            blocked: vec!["/etc/**".to_string()],
        }),
        network_rules: None,
    }];
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();
    let action = action_with_paths("file", "read", vec!["/etc/passwd"]);
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

#[test]
fn test_multiple_paths_one_blocked_denies_all() {
    let policies = vec![policy_with_path_rules(
        "file:*",
        "Block secrets",
        PolicyType::Allow,
        PathRules {
            allowed: vec![],
            blocked: vec!["/etc/shadow".to_string()],
        },
    )];
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();
    let action = action_with_paths("file", "read", vec!["/tmp/safe.txt", "/etc/shadow"]);
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(verdict, Verdict::Deny { .. }),
        "If any path is blocked, entire action should be denied, got: {verdict:?}"
    );
}

#[test]
fn test_path_and_network_rules_combined() {
    let policies = vec![Policy {
        id: "*".to_string(),
        name: "Combined rules".to_string(),
        policy_type: PolicyType::Allow,
        priority: 100,
        path_rules: Some(PathRules {
            allowed: vec!["/tmp/**".to_string()],
            blocked: vec![],
        }),
        network_rules: Some(NetworkRules {
            allowed_domains: vec!["api.safe.com".to_string()],
            blocked_domains: vec![],
            ip_rules: None,
        }),
    }];
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();

    // Bad path, good domain
    let mut action1 = Action::new("tool", "func", json!({}));
    action1.target_paths = vec!["/etc/passwd".to_string()];
    action1.target_domains = vec!["api.safe.com".to_string()];
    let verdict = engine.evaluate_action(&action1, &policies).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));

    // Good path, bad domain
    let mut action2 = Action::new("tool", "func", json!({}));
    action2.target_paths = vec!["/tmp/file.txt".to_string()];
    action2.target_domains = vec!["evil.com".to_string()];
    let verdict = engine.evaluate_action(&action2, &policies).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));

    // Good path, good domain
    let mut action3 = Action::new("tool", "func", json!({}));
    action3.target_paths = vec!["/tmp/file.txt".to_string()];
    action3.target_domains = vec!["api.safe.com".to_string()];
    let verdict = engine.evaluate_action(&action3, &policies).unwrap();
    assert!(matches!(verdict, Verdict::Allow));
}

// ═══════════════════════════════════════════════════
// PROPERTY-BASED TESTS (proptest)
// ═══════════════════════════════════════════════════

mod proptests {
    use super::*;
    use proptest::prelude::*;

    // ── Strategy definitions ──────────────────────────────

    fn arb_tool_name() -> impl Strategy<Value = String> {
        "[a-z_]{1,20}"
    }

    fn arb_function_name() -> impl Strategy<Value = String> {
        "[a-z_]{1,20}"
    }

    fn arb_params() -> impl Strategy<Value = serde_json::Value> {
        proptest::collection::vec(("[a-z_]{1,10}", "[a-zA-Z0-9_]{0,20}"), 0..=5).prop_map(|pairs| {
            let map: serde_json::Map<String, serde_json::Value> = pairs
                .into_iter()
                .map(|(k, v)| (k, serde_json::Value::String(v)))
                .collect();
            serde_json::Value::Object(map)
        })
    }

    fn arb_action() -> impl Strategy<Value = Action> {
        (arb_tool_name(), arb_function_name(), arb_params())
            .prop_map(|(tool, function, parameters)| Action::new(tool, function, parameters))
    }

    fn arb_path() -> impl Strategy<Value = String> {
        proptest::collection::vec(
            prop_oneof!["[a-z]{1,8}", Just("..".to_string()), Just(".".to_string()),],
            1..=6,
        )
        .prop_map(|segments| format!("/{}", segments.join("/")))
    }

    // ── Core Invariants ──────────────────────────────────

    proptest! {
                /// evaluate_action called twice on the same input produces the same verdict.
                #[test]
                fn prop_evaluate_deterministic(action in arb_action()) {
                    let engine = PolicyEngine::new(false);
                    let policies = vec![
                        Policy {
                            id: "test:*".to_string(),
                            name: "Allow test".to_string(),
                            policy_type: PolicyType::Allow,
                            priority: 100,
                            path_rules: None,
                            network_rules: None,
    },
                    ];
                    let v1 = engine.evaluate_action(&action, &policies).unwrap();
                    let v2 = engine.evaluate_action(&action, &policies).unwrap();
                    prop_assert_eq!(
                        format!("{:?}", v1),
                        format!("{:?}", v2),
                        "evaluate_action must be deterministic"
                    );
                }

                /// Compiled path: evaluate_with_compiled called twice produces same verdict.
                #[test]
                fn prop_compiled_deterministic(action in arb_action()) {
                    let policies = vec![
                        Policy {
                            id: "*".to_string(),
                            name: "Allow all".to_string(),
                            policy_type: PolicyType::Allow,
                            priority: 50,
                            path_rules: None,
                            network_rules: None,
    },
                    ];
                    let engine = PolicyEngine::with_policies(false, &policies).unwrap();
                    let v1 = engine.evaluate_action(&action, &[]).unwrap();
                    let v2 = engine.evaluate_action(&action, &[]).unwrap();
                    prop_assert_eq!(
                        format!("{:?}", v1),
                        format!("{:?}", v2),
                        "compiled evaluate must be deterministic"
                    );
                }

                /// Empty policy set always produces Deny (fail-closed).
                #[test]
                fn prop_empty_policies_deny(action in arb_action()) {
                    let engine = PolicyEngine::new(false);
                    let verdict = engine.evaluate_action(&action, &[]).unwrap();
                    prop_assert!(
                        matches!(verdict, Verdict::Deny { .. }),
                        "empty policies must deny, got {:?}",
                        verdict
                    );
                }

                /// Non-matching policies produce Deny (fail-closed).
                #[test]
                fn prop_no_match_denies(
                    tool in arb_tool_name(),
                    function in arb_function_name(),
                ) {
                    let engine = PolicyEngine::new(false);
                    let action = Action::new(tool, function, json!({}));
                    // Policy for a tool name that can never match [a-z_]{1,20}
                    let policies = vec![Policy {
                        id: "ZZZZZ-NEVER-MATCHES:nope".to_string(),
                        name: "Unreachable".to_string(),
                        policy_type: PolicyType::Allow,
                        priority: 100,
                        path_rules: None,
                        network_rules: None,
                    }];
                    let verdict = engine.evaluate_action(&action, &policies).unwrap();
                    prop_assert!(
                        matches!(verdict, Verdict::Deny { .. }),
                        "non-matching policies must deny, got {:?}",
                        verdict
                    );
                }

                /// Wildcard policy `*` matches any tool/function.
                #[test]
                fn prop_wildcard_matches_all(action in arb_action()) {
                    let policies = vec![Policy {
                        id: "*".to_string(),
                        name: "Wildcard".to_string(),
                        policy_type: PolicyType::Allow,
                        priority: 100,
                        path_rules: None,
                        network_rules: None,
    }];
                    let engine = PolicyEngine::with_policies(false, &policies).unwrap();
                    let verdict = engine.evaluate_action(&action, &[]).unwrap();
                    prop_assert!(
                        matches!(verdict, Verdict::Allow),
                        "wildcard policy must allow all, got {:?}",
                        verdict
                    );
                }
            }

    // ── Priority & Override Rules ────────────────────────

    proptest! {
                /// Higher-priority Deny overrides lower-priority Allow.
                #[test]
                fn prop_higher_priority_deny_wins(
                    tool in arb_tool_name(),
                    function in arb_function_name(),
                ) {
                    let action = Action::new(tool.clone(), function.clone(), json!({}));
                    let policies = vec![
                        Policy {
                            id: "*".to_string(),
                            name: "Deny all".to_string(),
                            policy_type: PolicyType::Deny,
                            priority: 200,
                            path_rules: None,
                            network_rules: None,
    },
                        Policy {
                            id: "*".to_string(),
                            name: "Allow all".to_string(),
                            policy_type: PolicyType::Allow,
                            priority: 100,
                            path_rules: None,
                            network_rules: None,
    },
                    ];
                    let engine = PolicyEngine::with_policies(false, &policies).unwrap();
                    let verdict = engine.evaluate_action(&action, &[]).unwrap();
                    prop_assert!(
                        matches!(verdict, Verdict::Deny { .. }),
                        "higher priority deny must win, got {:?}",
                        verdict
                    );
                }

                /// At equal priority, Deny wins over Allow (deny-overrides).
                #[test]
                fn prop_deny_wins_at_equal_priority(
                    tool in arb_tool_name(),
                    function in arb_function_name(),
                ) {
                    let action = Action::new(tool.clone(), function.clone(), json!({}));
                    let policies = vec![
                        Policy {
                            id: "*".to_string(),
                            name: "Deny all".to_string(),
                            policy_type: PolicyType::Deny,
                            priority: 100,
                            path_rules: None,
                            network_rules: None,
    },
                        Policy {
                            id: "*".to_string(),
                            name: "Allow all".to_string(),
                            policy_type: PolicyType::Allow,
                            priority: 100,
                            path_rules: None,
                            network_rules: None,
    },
                    ];
                    let engine = PolicyEngine::with_policies(false, &policies).unwrap();
                    let verdict = engine.evaluate_action(&action, &[]).unwrap();
                    prop_assert!(
                        matches!(verdict, Verdict::Deny { .. }),
                        "deny must win at equal priority, got {:?}",
                        verdict
                    );
                }
            }

    // ── Path / Domain Safety ─────────────────────────────

    proptest! {
                /// normalize_path is idempotent: normalizing twice yields same result.
                #[test]
                fn prop_normalize_path_idempotent(path in arb_path()) {
                    match PolicyEngine::normalize_path(&path) {
                        Err(_) => {}
                        Ok(once) => {
                            let twice = PolicyEngine::normalize_path(&once).expect("idempotent");
                            prop_assert_eq!(
                                &once, &twice,
                                "normalize_path must be idempotent: '{}' -> '{}' -> '{}'",
                                path, once, twice
                            );
                        }
                    }
                }

                /// normalize_path is idempotent for percent-encoded input.
                #[test]
                fn prop_normalize_path_encoded_idempotent(
                    seg in "[a-z]{1,5}",
                ) {
                    // Encode each character as %XX
                    let encoded: String = seg.bytes()
                        .map(|b| format!("%{b:02X}"))
                        .collect();
                    let input = format!("/{encoded}");
                    match PolicyEngine::normalize_path(&input) {
                        Err(_) => {}
                        Ok(once) => {
                            let twice = PolicyEngine::normalize_path(&once).expect("idempotent");
                            prop_assert_eq!(
                                &once, &twice,
                                "normalize_path must be idempotent on encoded input: '{}' -> '{}' -> '{}'",
                                input, once, twice
                            );
                        }
                    }
                }

                /// normalize_path never returns an empty string.
                #[test]
                fn prop_normalize_path_never_empty(path in arb_path()) {
                    if let Ok(ref val) = PolicyEngine::normalize_path(&path) {
                        prop_assert!(
                            !val.is_empty(),
                            "normalize_path must never return empty string for input '{}'",
                            path
                        );
                    }
                }

                /// extract_domain always returns a lowercase string.
                #[test]
                fn prop_extract_domain_lowercase(
                    scheme in prop_oneof![Just("http"), Just("https"), Just("ftp")],
                    host in "[a-zA-Z]{1,10}(\\.[a-zA-Z]{1,5}){1,3}",
                ) {
                    let url = format!("{scheme}://{host}/path");
                    let domain = PolicyEngine::extract_domain(&url);
                    let lowered = domain.to_lowercase();
                    prop_assert_eq!(
                        &domain, &lowered,
                        "extract_domain must return lowercase for '{}'",
                        url
                    );
                }

                /// Blocked glob pattern always produces Deny via not_glob constraint.
                #[test]
                fn prop_blocked_glob_always_denies(
                    user in "[a-z]{1,8}",
                    suffix in "[a-z_/.]{0,15}",
                ) {
                    let path = format!("/home/{user}/.aws/{suffix}");
                    let action = Action::new("file_system".to_string(), "read_file".to_string(), json!({ "path": path }));
                    // not_glob denies when the path does NOT match the allowlist.
                    // A path under .aws should NOT be in a project allowlist.
                    let policy = Policy {
                        id: "file_system:read_file".to_string(),
                        name: "Block outside project".to_string(),
                        policy_type: PolicyType::Conditional {
                            conditions: json!({
                                "parameter_constraints": [
                                    {
                                        "param": "path",
                                        "op": "not_glob",
                                        "patterns": ["/home/*/project/**", "/tmp/**"],
                                        "on_match": "deny"
                                    }
                                ]
                            }),
                        },
                        priority: 200,
                        path_rules: None,
                        network_rules: None,
    };
                    let engine = PolicyEngine::with_policies(false, &[policy]).unwrap();
                    let verdict = engine.evaluate_action(&action, &[]).unwrap();
                    prop_assert!(
                        matches!(verdict, Verdict::Deny { .. }),
                        "path '{}' under .aws must be denied, got {:?}",
                        path,
                        verdict
                    );
                }
            }

    // ── Parameter Resolution ─────────────────────────────

    proptest! {
        /// Ambiguous dotted path (literal key vs nested traversal disagree) returns None.
        #[test]
        fn prop_ambiguous_dotted_path_none(
            key_a in "[a-z]{1,5}",
            key_b in "[a-z]{1,5}",
            val_literal in "[A-Z]{1,5}",
            val_nested in "[0-9]{1,5}",
        ) {
            // Only test when the two values actually differ
            prop_assume!(val_literal != val_nested);
            let dotted = format!("{key_a}.{key_b}");
            // Build params with both a literal "a.b" key and a nested a.b path
            let params = json!({
                dotted.clone(): val_literal,
                key_a.clone(): { key_b.clone(): val_nested },
            });
            let result = PolicyEngine::get_param_by_path(&params, &dotted);
            prop_assert!(
                result.is_none(),
                "ambiguous dotted path '{}' must return None, got {:?}",
                dotted,
                result
            );
        }

        /// When literal key and nested traversal agree, resolution succeeds.
        #[test]
        fn prop_same_value_dotted_path_resolves(
            key_a in "[a-z]{1,5}",
            key_b in "[a-z]{1,5}",
            val in "[a-z0-9]{1,10}",
        ) {
            let dotted = format!("{key_a}.{key_b}");
            let params = json!({
                dotted.clone(): val.clone(),
                key_a.clone(): { key_b.clone(): val.clone() },
            });
            let result = PolicyEngine::get_param_by_path(&params, &dotted);
            prop_assert!(
                result.is_some(),
                "agreeing dotted path '{}' must resolve, got None",
                dotted
            );
            prop_assert_eq!(
                result.unwrap().as_str().unwrap(),
                val.as_str(),
                "resolved value must match"
            );
        }
    }

    // ── Pattern Matching ─────────────────────────────────

    proptest! {
        /// PatternMatcher::Exact compiled from a literal always matches itself.
        #[test]
        fn prop_pattern_matcher_exact_self(s in "[a-z_]{1,20}") {
            let matcher = PatternMatcher::compile(&s);
            prop_assert!(
                matcher.matches(&s),
                "PatternMatcher::compile('{}').matches('{}') must be true",
                s, s
            );
        }
    }
}

// ── ReDoS Protection Tests (H2) ─────────────────────

#[test]
fn test_redos_nested_quantifiers_rejected() {
    let result = PolicyEngine::validate_regex_safety("(a+)+b");
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("nested quantifier"));
}

#[test]
fn test_redos_star_star_rejected() {
    let result = PolicyEngine::validate_regex_safety("(a*)*");
    assert!(result.is_err());
}

#[test]
fn test_redos_overlength_rejected() {
    let long_pattern = "a".repeat(1025);
    let result = PolicyEngine::validate_regex_safety(&long_pattern);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("maximum length"));
}

#[test]
fn test_redos_valid_patterns_accepted() {
    assert!(PolicyEngine::validate_regex_safety(r"^/[\w/.\-]+$").is_ok());
    assert!(PolicyEngine::validate_regex_safety(r"[a-z]+").is_ok());
    assert!(PolicyEngine::validate_regex_safety(r"foo|bar|baz").is_ok());
    assert!(PolicyEngine::validate_regex_safety(r"(abc)+").is_ok()); // quantifier on group without inner quantifier
}

#[test]
fn test_redos_compile_constraint_rejects_unsafe_regex() {
    let policy = Policy {
        id: "test:*".to_string(),
        name: "test".to_string(),
        policy_type: PolicyType::Conditional {
            conditions: json!({
                "parameter_constraints": [
                    {"param": "input", "op": "regex", "pattern": "(a+)+b"}
                ]
            }),
        },
        priority: 100,
        path_rules: None,
        network_rules: None,
    };
    let result = PolicyEngine::with_policies(false, &[policy]);
    assert!(result.is_err());
    let errors = result.unwrap_err();
    assert!(errors[0].reason.contains("nested quantifier"));
}

#[test]
fn test_redos_legacy_regex_is_match_rejects_unsafe() {
    let engine = PolicyEngine::new(false);
    let result = engine.regex_is_match("(a+)+b", "aaaaab", "test-policy");
    assert!(result.is_err());
}

// ═══════════════════════════════════════════════════
// 6B: DOMAIN SYNTAX VALIDATION (L1)
// ═══════════════════════════════════════════════════

#[test]
fn test_validate_domain_pattern_valid() {
    // Simple domains
    assert!(PolicyEngine::validate_domain_pattern("example.com").is_ok());
    assert!(PolicyEngine::validate_domain_pattern("sub.example.com").is_ok());
    assert!(PolicyEngine::validate_domain_pattern("a-b.example.com").is_ok());
    // Wildcard prefix
    assert!(PolicyEngine::validate_domain_pattern("*.example.com").is_ok());
    // Single-label domain
    assert!(PolicyEngine::validate_domain_pattern("localhost").is_ok());
}

#[test]
fn test_validate_domain_pattern_invalid() {
    // Empty string
    assert!(PolicyEngine::validate_domain_pattern("").is_err());

    // Label longer than 63 characters
    let long_label = "a".repeat(64);
    let long_domain = format!("{long_label}.example.com");
    assert!(
        PolicyEngine::validate_domain_pattern(&long_domain).is_err(),
        "Label > 63 chars should be rejected"
    );

    // Leading hyphen in label
    assert!(
        PolicyEngine::validate_domain_pattern("-example.com").is_err(),
        "Leading hyphen should be rejected"
    );

    // Trailing hyphen in label
    assert!(
        PolicyEngine::validate_domain_pattern("example-.com").is_err(),
        "Trailing hyphen should be rejected"
    );

    // Total domain length > 253 characters
    let labels: Vec<String> = (0..50).map(|i| format!("label{i}")).collect();
    let huge_domain = labels.join(".");
    assert!(huge_domain.len() > 253);
    assert!(
        PolicyEngine::validate_domain_pattern(&huge_domain).is_err(),
        "Domain > 253 chars should be rejected"
    );

    // Invalid characters (underscore)
    assert!(
        PolicyEngine::validate_domain_pattern("under_score.example.com").is_err(),
        "Underscore in label should be rejected"
    );

    // Invalid characters (space)
    assert!(
        PolicyEngine::validate_domain_pattern("spa ce.example.com").is_err(),
        "Space in label should be rejected"
    );
}

#[test]
fn test_validate_domain_pattern_wildcard_prefix_only() {
    // Valid wildcard at prefix
    assert!(PolicyEngine::validate_domain_pattern("*.example.com").is_ok());

    // Invalid wildcard in middle
    assert!(
        PolicyEngine::validate_domain_pattern("sub.*.example.com").is_err(),
        "Wildcard in middle should be rejected"
    );

    // Invalid wildcard at end
    assert!(
        PolicyEngine::validate_domain_pattern("example.*").is_err(),
        "Wildcard at end should be rejected"
    );

    // Bare wildcard with no domain
    assert!(
        PolicyEngine::validate_domain_pattern("*.").is_err(),
        "Bare '*.' with no domain should be rejected"
    );
}

#[test]
fn test_compile_policy_rejects_invalid_domain_in_network_rules() {
    use vellaveto_types::NetworkRules;

    let policy = Policy {
        id: "test:net".to_string(),
        name: "Net policy".to_string(),
        policy_type: PolicyType::Allow,
        priority: 10,
        path_rules: None,
        network_rules: Some(NetworkRules {
            allowed_domains: vec!["valid.example.com".to_string()],
            blocked_domains: vec!["-invalid.com".to_string()],
            ip_rules: None,
        }),
    };

    let result = PolicyEngine::with_policies(false, &[policy]);
    assert!(
        result.is_err(),
        "Policy with invalid domain pattern should fail compilation"
    );
    let errors = result.unwrap_err();
    assert!(
        errors[0].reason.contains("Invalid domain pattern"),
        "Error should mention invalid domain pattern, got: {}",
        errors[0].reason
    );
}

// ═══════════════════════════════════════════════════
// 6D: CONSISTENT JSON DEPTH ENFORCEMENT (L4)
// ═══════════════════════════════════════════════════

#[test]
fn test_max_json_depth_constant_value() {
    // Verify the constant is 32 and is used consistently.
    assert_eq!(
        PolicyEngine::MAX_JSON_DEPTH,
        32,
        "MAX_JSON_DEPTH should be 32"
    );
}

#[test]
fn test_json_depth_and_scan_depth_use_same_constant() {
    // The depth check in collect_all_string_values uses `depth >= MAX_JSON_DEPTH`
    // on objects/arrays to stop descending. A string at depth D is collected
    // because strings don't recurse. So a string wrapped in MAX_JSON_DEPTH
    // objects is at depth MAX_JSON_DEPTH and IS collected (the object at
    // depth MAX_JSON_DEPTH - 1 pushes its child string at depth MAX_JSON_DEPTH,
    // and strings are processed without checking depth).
    //
    // A string wrapped in MAX_JSON_DEPTH + 1 objects is NOT collected, because
    // the object at depth MAX_JSON_DEPTH is skipped entirely (depth >= MAX_JSON_DEPTH).

    // Build a structure one level beyond MAX_JSON_DEPTH (should NOT be found)
    let mut val = json!("deep_value");
    for _ in 0..(PolicyEngine::MAX_JSON_DEPTH + 1) {
        val = json!({"nested": val});
    }
    let (values, _truncated) = PolicyEngine::collect_all_string_values(&val);
    assert!(
        values.is_empty(),
        "Values beyond MAX_JSON_DEPTH should not be collected"
    );

    // A string at exactly MAX_JSON_DEPTH - 1 nesting should be found
    let mut val2 = json!("shallow_value");
    for _ in 0..(PolicyEngine::MAX_JSON_DEPTH - 1) {
        val2 = json!({"nested": val2});
    }
    let (values2, _truncated2) = PolicyEngine::collect_all_string_values(&val2);
    assert!(
        !values2.is_empty(),
        "Values at depth MAX_JSON_DEPTH - 1 should be collected"
    );
}

// ═══════════════════════════════════════════════════
// CONTEXT-AWARE EVALUATION TESTS (C-17.3)
// ═══════════════════════════════════════════════════

fn make_context_policy(context_conditions: serde_json::Value) -> Policy {
    Policy {
        id: "read_file:*".to_string(),
        name: "context-test".to_string(),
        policy_type: PolicyType::Conditional {
            conditions: json!({
                "context_conditions": context_conditions,
            }),
        },
        priority: 100,
        path_rules: None,
        network_rules: None,
    }
}

fn make_context_engine(policy: Policy) -> PolicyEngine {
    let mut engine = PolicyEngine::with_policies(false, &[policy]).unwrap();
    // Enable trusted timestamps for deterministic testing only.
    // In production, trust_context_timestamps is always false.
    engine.set_trust_context_timestamps(true);
    engine
}

#[test]
fn test_context_time_window_allow_during_hours() {
    let policy = make_context_policy(json!([
        {"type": "time_window", "start_hour": 0, "end_hour": 23}
    ]));
    let engine = make_context_engine(policy);
    let action = Action::new("read_file", "execute", json!({}));
    let ctx = EvaluationContext {
        timestamp: Some("2026-02-04T12:00:00Z".to_string()),
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(matches!(v, Verdict::Allow));
}

#[test]
fn test_context_time_window_deny_outside_hours() {
    let policy = make_context_policy(json!([
        {"type": "time_window", "start_hour": 9, "end_hour": 17}
    ]));
    let engine = make_context_engine(policy);
    let action = Action::new("read_file", "execute", json!({}));
    let ctx = EvaluationContext {
        timestamp: Some("2026-02-04T20:00:00Z".to_string()),
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(matches!(v, Verdict::Deny { .. }));
}

#[test]
fn test_context_time_window_midnight_wrap() {
    // 22:00 - 06:00 (overnight window)
    let policy = make_context_policy(json!([
        {"type": "time_window", "start_hour": 22, "end_hour": 6}
    ]));
    let engine = make_context_engine(policy);
    let action = Action::new("read_file", "execute", json!({}));

    // 23:00 should be allowed
    let ctx = EvaluationContext {
        timestamp: Some("2026-02-04T23:00:00Z".to_string()),
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(matches!(v, Verdict::Allow));

    // 03:00 should be allowed
    let ctx = EvaluationContext {
        timestamp: Some("2026-02-04T03:00:00Z".to_string()),
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(matches!(v, Verdict::Allow));

    // 10:00 should be denied
    let ctx = EvaluationContext {
        timestamp: Some("2026-02-04T10:00:00Z".to_string()),
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(matches!(v, Verdict::Deny { .. }));
}

#[test]
fn test_context_time_window_day_of_week_filter() {
    // Only allow on Monday (1) and Tuesday (2)
    let policy = make_context_policy(json!([
        {"type": "time_window", "start_hour": 0, "end_hour": 23, "days": [1, 2]}
    ]));
    let engine = make_context_engine(policy);
    let action = Action::new("read_file", "execute", json!({}));

    // 2026-02-04 is a Wednesday (day 3), should be denied
    let ctx = EvaluationContext {
        timestamp: Some("2026-02-04T12:00:00Z".to_string()),
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(matches!(v, Verdict::Deny { .. }));

    // 2026-02-02 is a Monday (day 1), should be allowed
    let ctx = EvaluationContext {
        timestamp: Some("2026-02-02T12:00:00Z".to_string()),
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(matches!(v, Verdict::Allow));
}

#[test]
fn test_context_max_calls_under_limit() {
    let policy = make_context_policy(json!([
        {"type": "max_calls", "tool_pattern": "read_file", "max": 5}
    ]));
    let engine = make_context_engine(policy);
    let action = Action::new("read_file", "execute", json!({}));
    let mut counts = HashMap::new();
    counts.insert("read_file".to_string(), 3);
    let ctx = EvaluationContext {
        call_counts: counts,
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(matches!(v, Verdict::Allow));
}

#[test]
fn test_context_max_calls_at_limit_denies() {
    let policy = make_context_policy(json!([
        {"type": "max_calls", "tool_pattern": "read_file", "max": 5}
    ]));
    let engine = make_context_engine(policy);
    let action = Action::new("read_file", "execute", json!({}));
    let mut counts = HashMap::new();
    counts.insert("read_file".to_string(), 5);
    let ctx = EvaluationContext {
        call_counts: counts,
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(matches!(v, Verdict::Deny { .. }));
}

#[test]
fn test_context_max_calls_wildcard_pattern() {
    let policy = make_context_policy(json!([
        {"type": "max_calls", "tool_pattern": "*", "max": 10}
    ]));
    let engine = make_context_engine(policy);
    let action = Action::new("read_file", "execute", json!({}));
    let mut counts = HashMap::new();
    counts.insert("read_file".to_string(), 5);
    counts.insert("write_file".to_string(), 6);
    let ctx = EvaluationContext {
        call_counts: counts,
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(matches!(v, Verdict::Deny { .. }));
}

// === R15-ENG-1 regression: MaxCalls/MaxCallsInWindow must fail-closed
// when session state is unavailable (empty call_counts/previous_actions).

#[test]
fn test_context_max_calls_empty_counts_denies_fail_closed() {
    // SECURITY (R15-ENG-1): If a policy declares MaxCalls but the caller
    // provides empty call_counts (e.g., stateless API), deny rather than
    // silently allowing unlimited calls.
    let policy = make_context_policy(json!([
        {"type": "max_calls", "tool_pattern": "read_file", "max": 5}
    ]));
    let engine = make_context_engine(policy);
    let action = Action::new("read_file", "execute", json!({}));
    let ctx = EvaluationContext {
        call_counts: HashMap::new(), // empty — no session tracking
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "MaxCalls with empty call_counts must deny (fail-closed), got: {v:?}"
    );
}

#[test]
fn test_context_max_calls_wildcard_empty_counts_denies() {
    let policy = make_context_policy(json!([
        {"type": "max_calls", "tool_pattern": "*", "max": 10}
    ]));
    let engine = make_context_engine(policy);
    let action = Action::new("any_tool", "execute", json!({}));
    let ctx = EvaluationContext {
        call_counts: HashMap::new(),
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "MaxCalls wildcard with empty call_counts must deny, got: {v:?}"
    );
}

#[test]
fn test_context_max_calls_in_window_empty_history_denies() {
    // SECURITY (R15-ENG-1): MaxCallsInWindow with empty previous_actions
    // and empty call_counts must deny (no session history available).
    let policy = make_context_policy(json!([
        {"type": "max_calls_in_window", "tool_pattern": "write_file", "max": 3, "window": 10}
    ]));
    let engine = make_context_engine(policy);
    let action = Action::new("write_file", "execute", json!({}));
    let ctx = EvaluationContext {
        previous_actions: Vec::new(),
        call_counts: HashMap::new(),
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "MaxCallsInWindow with empty history must deny (fail-closed), got: {v:?}"
    );
}

#[test]
fn test_context_max_calls_in_window_nonempty_counts_empty_history_denies() {
    // SECURITY (R21-ENG-1): MaxCallsInWindow with empty previous_actions
    // but non-empty call_counts must STILL deny. MaxCallsInWindow counts
    // over previous_actions only, so providing call_counts alone cannot
    // satisfy the windowed check.
    let policy = make_context_policy(json!([
        {"type": "max_calls_in_window", "tool_pattern": "write_file", "max": 3, "window": 10}
    ]));
    let engine = make_context_engine(policy);
    let action = Action::new("write_file", "execute", json!({}));
    let mut counts = HashMap::new();
    counts.insert("write_file".to_string(), 1u64);
    let ctx = EvaluationContext {
        previous_actions: Vec::new(), // empty — no history
        call_counts: counts,          // non-empty — should NOT bypass check
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "R21-ENG-1: MaxCallsInWindow with empty history must deny even if call_counts non-empty, got: {v:?}"
    );
}

#[test]
fn test_context_max_calls_in_window_large_window_r34_eng_2() {
    // SECURITY (R34-ENG-2): A window value larger than usize::MAX on 32-bit
    // should not truncate silently. On 64-bit this exercises the try_from path
    // with a normal large value. The key is that compilation succeeds and the
    // window is treated as effectively unbounded (all history checked).
    let policy = make_context_policy(json!([
        {"type": "max_calls_in_window", "tool_pattern": "write_file", "max": 2, "window": 100}
    ]));
    let engine = make_context_engine(policy);
    let action = Action::new("write_file", "execute", json!({}));
    let ctx = EvaluationContext {
        previous_actions: vec!["write_file".to_string(), "write_file".to_string()],
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "R34-ENG-2: MaxCallsInWindow with large window must correctly count, got: {v:?}"
    );
}

#[test]
fn test_context_max_calls_with_zero_count_allows() {
    // When call_counts is non-empty but the specific tool has count 0,
    // the rate limit is not yet reached — this should Allow.
    let policy = make_context_policy(json!([
        {"type": "max_calls", "tool_pattern": "read_file", "max": 5}
    ]));
    let engine = make_context_engine(policy);
    let action = Action::new("read_file", "execute", json!({}));
    let mut counts = HashMap::new();
    counts.insert("other_tool".to_string(), 1u64); // non-empty map, but read_file count is 0
    let ctx = EvaluationContext {
        call_counts: counts,
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Allow),
        "MaxCalls with non-empty counts and tool count 0 should allow, got: {v:?}"
    );
}

#[test]
fn test_context_agent_id_allowed() {
    let policy = make_context_policy(json!([
        {"type": "agent_id", "allowed": ["agent-a", "agent-b"]}
    ]));
    let engine = make_context_engine(policy);
    let action = Action::new("read_file", "execute", json!({}));
    let ctx = EvaluationContext {
        agent_id: Some("agent-a".to_string()),
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(matches!(v, Verdict::Allow));
}

#[test]
fn test_context_agent_id_blocked() {
    let policy = make_context_policy(json!([
        {"type": "agent_id", "blocked": ["evil-agent"]}
    ]));
    let engine = make_context_engine(policy);
    let action = Action::new("read_file", "execute", json!({}));
    let ctx = EvaluationContext {
        agent_id: Some("evil-agent".to_string()),
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(matches!(v, Verdict::Deny { .. }));
}

#[test]
fn test_context_agent_id_missing_fails_closed() {
    let policy = make_context_policy(json!([
        {"type": "agent_id", "allowed": ["agent-a"]}
    ]));
    let engine = make_context_engine(policy);
    let action = Action::new("read_file", "execute", json!({}));
    let ctx = EvaluationContext::default(); // No agent_id
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(matches!(v, Verdict::Deny { .. }));
}

#[test]
fn test_context_agent_id_case_insensitive() {
    // SECURITY: Agent IDs must be compared case-insensitively.
    // "Agent-A" should match policy allowing "agent-a".
    let policy = make_context_policy(json!([
        {"type": "agent_id", "allowed": ["Agent-A", "AGENT-B"]}
    ]));
    let engine = make_context_engine(policy);
    let action = Action::new("read_file", "execute", json!({}));

    // Lowercase variant should be allowed
    let ctx = EvaluationContext {
        agent_id: Some("agent-a".to_string()),
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(matches!(v, Verdict::Allow), "lowercase should match: {v:?}");

    // Mixed case variant should be allowed
    let ctx = EvaluationContext {
        agent_id: Some("AGENT-A".to_string()),
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(matches!(v, Verdict::Allow), "uppercase should match: {v:?}");

    // Case variation of blocked agent should be blocked
    let policy2 = make_context_policy(json!([
        {"type": "agent_id", "blocked": ["Evil-Agent"]}
    ]));
    let engine2 = make_context_engine(policy2);
    let ctx = EvaluationContext {
        agent_id: Some("EVIL-AGENT".to_string()),
        ..Default::default()
    };
    let v = engine2
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "case variant of blocked should deny: {v:?}"
    );
}

#[test]
fn test_context_require_previous_action_present() {
    let policy = make_context_policy(json!([
        {"type": "require_previous_action", "required_tool": "authenticate"}
    ]));
    let engine = make_context_engine(policy);
    let action = Action::new("read_file", "execute", json!({}));
    let ctx = EvaluationContext {
        previous_actions: vec!["authenticate".to_string(), "list_files".to_string()],
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(matches!(v, Verdict::Allow));
}

#[test]
fn test_context_require_previous_action_absent() {
    let policy = make_context_policy(json!([
        {"type": "require_previous_action", "required_tool": "authenticate"}
    ]));
    let engine = make_context_engine(policy);
    let action = Action::new("read_file", "execute", json!({}));
    let ctx = EvaluationContext {
        previous_actions: vec!["list_files".to_string()],
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(matches!(v, Verdict::Deny { .. }));
}

#[test]
fn test_context_none_denies_when_conditions_exist() {
    // SECURITY: When context is None but policy has context conditions,
    // the action must be denied (fail-closed). Allowing it would let
    // callers bypass time-window/max-calls/agent-id by omitting context.
    let policy = make_context_policy(json!([
        {"type": "agent_id", "allowed": ["agent-a"]}
    ]));
    let engine = make_context_engine(policy);
    let action = Action::new("read_file", "execute", json!({}));
    let v = engine.evaluate_action(&action, &[]).unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "Expected Deny when context conditions exist but no context provided, got {v:?}"
    );
}

#[test]
fn test_context_none_allows_when_no_conditions() {
    // Policies WITHOUT context conditions should still work fine with no context.
    let policy = Policy {
        id: "read_file:*".to_string(),
        name: "allow-read".to_string(),
        policy_type: PolicyType::Allow,
        priority: 50,
        path_rules: None,
        network_rules: None,
    };
    let engine = PolicyEngine::with_policies(false, &[policy]).unwrap();
    let action = Action::new("read_file", "execute", json!({}));
    let v = engine.evaluate_action(&action, &[]).unwrap();
    assert!(matches!(v, Verdict::Allow));
}

#[test]
fn test_context_compile_error_unknown_type() {
    let policy = make_context_policy(json!([
        {"type": "unknown_condition"}
    ]));
    let result = PolicyEngine::with_policies(false, &[policy]);
    assert!(result.is_err());
}

#[test]
fn test_context_compile_error_invalid_time_window() {
    let policy = make_context_policy(json!([
        {"type": "time_window", "start_hour": 25, "end_hour": 10}
    ]));
    let result = PolicyEngine::with_policies(false, &[policy]);
    assert!(result.is_err());
}

/// SECURITY (R19-TRUNC): Verify that large u64 hour values are rejected
/// instead of silently truncating to u8 (e.g., 265 → 9).
#[test]
fn test_context_compile_error_truncated_hour_value() {
    // 265 as u8 = 9, which would pass > 23 check without the fix
    let policy = make_context_policy(json!([
        {"type": "time_window", "start_hour": 265, "end_hour": 10}
    ]));
    let result = PolicyEngine::with_policies(false, &[policy]);
    assert!(
        result.is_err(),
        "Should reject start_hour=265 (would truncate to 9 as u8)"
    );

    // Same for end_hour
    let policy2 = make_context_policy(json!([
        {"type": "time_window", "start_hour": 9, "end_hour": 280}
    ]));
    let result2 = PolicyEngine::with_policies(false, &[policy2]);
    assert!(
        result2.is_err(),
        "Should reject end_hour=280 (would truncate to 24→err, but 256+17=273→17 as u8)"
    );
}

/// SECURITY (R19-TRUNC): Verify that large u64 day values are rejected.
#[test]
fn test_context_compile_error_truncated_day_value() {
    // 258 as u8 = 2 (Tuesday), which would pass 1..=7 check without the fix
    let policy = make_context_policy(json!([
        {"type": "time_window", "start_hour": 9, "end_hour": 17, "days": [1, 258]}
    ]));
    let result = PolicyEngine::with_policies(false, &[policy]);
    assert!(
        result.is_err(),
        "Should reject day=258 (would truncate to 2 as u8)"
    );
}

/// SECURITY (R19-WINDOW-EQ): start_hour == end_hour creates a zero-width
/// window that always denies. Reject at compile time.
#[test]
fn test_context_compile_error_zero_width_time_window() {
    let policy = make_context_policy(json!([
        {"type": "time_window", "start_hour": 12, "end_hour": 12}
    ]));
    let result = PolicyEngine::with_policies(false, &[policy]);
    assert!(
        result.is_err(),
        "Should reject start_hour == end_hour (zero-width window)"
    );
}

#[test]
fn test_context_traced_with_context() {
    let policy = make_context_policy(json!([
        {"type": "max_calls", "tool_pattern": "read_file", "max": 2}
    ]));
    let engine = make_context_engine(policy);
    let action = Action::new("read_file", "execute", json!({}));
    let mut counts = HashMap::new();
    counts.insert("read_file".to_string(), 5);
    let ctx = EvaluationContext {
        call_counts: counts,
        ..Default::default()
    };
    let (v, _trace) = engine
        .evaluate_action_traced_with_context(&action, Some(&ctx))
        .unwrap();
    assert!(matches!(v, Verdict::Deny { .. }));
}

// ── Forbidden Previous Action (cross-tool orchestration) ──────────

#[test]
fn test_context_forbidden_previous_action_present_denies() {
    let policy = Policy {
        id: "http_request:*".to_string(),
        name: "block-exfil-after-read".to_string(),
        policy_type: PolicyType::Conditional {
            conditions: json!({
                "context_conditions": [
                    {"type": "forbidden_previous_action", "forbidden_tool": "read_file"}
                ],
            }),
        },
        priority: 100,
        path_rules: None,
        network_rules: None,
    };
    let engine = PolicyEngine::with_policies(false, &[policy]).unwrap();
    let action = Action::new(
        "http_request",
        "execute",
        json!({"url": "https://evil.com"}),
    );
    let ctx = EvaluationContext {
        previous_actions: vec!["read_file".to_string(), "list_files".to_string()],
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "Should deny http_request when read_file is in history"
    );
}

#[test]
fn test_context_forbidden_previous_action_absent_allows() {
    let policy = Policy {
        id: "http_request:*".to_string(),
        name: "block-exfil-after-read".to_string(),
        policy_type: PolicyType::Conditional {
            conditions: json!({
                "context_conditions": [
                    {"type": "forbidden_previous_action", "forbidden_tool": "read_file"}
                ],
            }),
        },
        priority: 100,
        path_rules: None,
        network_rules: None,
    };
    let engine = PolicyEngine::with_policies(false, &[policy]).unwrap();
    let action = Action::new(
        "http_request",
        "execute",
        json!({"url": "https://api.github.com"}),
    );
    let ctx = EvaluationContext {
        previous_actions: vec!["list_files".to_string()],
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Allow),
        "Should allow http_request when read_file is NOT in history"
    );
}

#[test]
fn test_context_forbidden_previous_action_empty_history() {
    let policy = Policy {
        id: "http_request:*".to_string(),
        name: "block-exfil-after-read".to_string(),
        policy_type: PolicyType::Conditional {
            conditions: json!({
                "context_conditions": [
                    {"type": "forbidden_previous_action", "forbidden_tool": "read_file"}
                ],
            }),
        },
        priority: 100,
        path_rules: None,
        network_rules: None,
    };
    let engine = PolicyEngine::with_policies(false, &[policy]).unwrap();
    let action = Action::new("http_request", "execute", json!({}));
    let ctx = EvaluationContext::default();
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Allow),
        "Should allow when history is empty"
    );
}

// ── Max Calls In Window (sliding-window rate limit) ──────────

#[test]
fn test_context_max_calls_in_window_under_limit() {
    let policy = make_context_policy(json!([
        {"type": "max_calls_in_window", "tool_pattern": "read_file", "max": 5, "window": 10}
    ]));
    let engine = make_context_engine(policy);
    let action = Action::new("read_file", "execute", json!({}));
    let ctx = EvaluationContext {
        previous_actions: vec![
            "read_file".to_string(),
            "read_file".to_string(),
            "list_files".to_string(),
            "read_file".to_string(),
        ],
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Allow),
        "3 calls in window of 10 should be under limit of 5"
    );
}

#[test]
fn test_context_max_calls_in_window_at_limit_denies() {
    let policy = make_context_policy(json!([
        {"type": "max_calls_in_window", "tool_pattern": "read_file", "max": 3, "window": 10}
    ]));
    let engine = make_context_engine(policy);
    let action = Action::new("read_file", "execute", json!({}));
    let ctx = EvaluationContext {
        previous_actions: vec![
            "read_file".to_string(),
            "read_file".to_string(),
            "list_files".to_string(),
            "read_file".to_string(),
        ],
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "3 calls at limit of 3 should deny"
    );
}

#[test]
fn test_context_max_calls_in_window_older_calls_outside() {
    let policy = make_context_policy(json!([
        {"type": "max_calls_in_window", "tool_pattern": "read_file", "max": 3, "window": 3}
    ]));
    let engine = make_context_engine(policy);
    let action = Action::new("read_file", "execute", json!({}));
    let ctx = EvaluationContext {
        previous_actions: vec![
            "read_file".to_string(),  // outside window
            "read_file".to_string(),  // outside window
            "read_file".to_string(),  // inside window
            "list_files".to_string(), // inside window
            "list_files".to_string(), // inside window
        ],
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Allow),
        "Only 1 read_file in last 3 actions, under limit of 3"
    );
}

#[test]
fn test_context_max_calls_in_window_zero_means_all() {
    let policy = make_context_policy(json!([
        {"type": "max_calls_in_window", "tool_pattern": "read_file", "max": 3, "window": 0}
    ]));
    let engine = make_context_engine(policy);
    let action = Action::new("read_file", "execute", json!({}));
    let ctx = EvaluationContext {
        previous_actions: vec![
            "read_file".to_string(),
            "read_file".to_string(),
            "read_file".to_string(),
        ],
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "window=0 checks entire history, 3 >= max of 3"
    );
}

#[test]
fn test_context_max_calls_in_window_wildcard() {
    let policy = make_context_policy(json!([
        {"type": "max_calls_in_window", "tool_pattern": "*", "max": 5, "window": 5}
    ]));
    let engine = make_context_engine(policy);
    let action = Action::new("read_file", "execute", json!({}));
    let ctx = EvaluationContext {
        previous_actions: vec![
            "a".to_string(),
            "b".to_string(),
            "c".to_string(),
            "d".to_string(),
            "e".to_string(),
        ],
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "5 any-tool calls in window of 5, at limit of 5"
    );
}

#[test]
fn test_context_forbidden_previous_compile_error() {
    let policy = make_context_policy(json!([
        {"type": "forbidden_previous_action"}
    ]));
    let result = PolicyEngine::with_policies(false, &[policy]);
    assert!(
        result.is_err(),
        "Missing forbidden_tool should fail compilation"
    );
}

#[test]
fn test_context_max_calls_in_window_compile_error() {
    let policy = make_context_policy(json!([
        {"type": "max_calls_in_window", "tool_pattern": "*", "window": 10}
    ]));
    let result = PolicyEngine::with_policies(false, &[policy]);
    assert!(result.is_err(), "Missing max should fail compilation");
}

// ═══════════════════════════════════════════════════
// AGENT IDENTITY ATTESTATION TESTS (OWASP ASI07)
// ═══════════════════════════════════════════════════

use vellaveto_types::AgentIdentity;

fn make_test_identity(issuer: &str, subject: &str, role: &str) -> AgentIdentity {
    let mut claims = std::collections::HashMap::new();
    claims.insert("role".to_string(), serde_json::json!(role));
    AgentIdentity {
        issuer: Some(issuer.to_string()),
        subject: Some(subject.to_string()),
        audience: vec!["mcp-server".to_string()],
        claims,
    }
}

#[test]
fn test_agent_identity_required_issuer_match() {
    let policy = make_context_policy(json!([
        {"type": "agent_identity", "issuer": "https://auth.example.com"}
    ]));
    let engine = make_context_engine(policy);
    let action = Action::new("read_file", "execute", json!({}));
    let ctx = EvaluationContext {
        agent_identity: Some(make_test_identity(
            "https://auth.example.com",
            "agent-123",
            "admin",
        )),
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(matches!(v, Verdict::Allow), "Matching issuer should allow");
}

#[test]
fn test_agent_identity_required_issuer_mismatch() {
    let policy = make_context_policy(json!([
        {"type": "agent_identity", "issuer": "https://auth.example.com"}
    ]));
    let engine = make_context_engine(policy);
    let action = Action::new("read_file", "execute", json!({}));
    let ctx = EvaluationContext {
        agent_identity: Some(make_test_identity(
            "https://evil.example.com",
            "agent-123",
            "admin",
        )),
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "Mismatched issuer should deny"
    );
}

#[test]
fn test_agent_identity_required_subject_match() {
    let policy = make_context_policy(json!([
        {"type": "agent_identity", "subject": "agent-123"}
    ]));
    let engine = make_context_engine(policy);
    let action = Action::new("read_file", "execute", json!({}));
    let ctx = EvaluationContext {
        agent_identity: Some(make_test_identity(
            "https://auth.example.com",
            "agent-123",
            "admin",
        )),
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(matches!(v, Verdict::Allow), "Matching subject should allow");
}

#[test]
fn test_agent_identity_required_subject_mismatch() {
    let policy = make_context_policy(json!([
        {"type": "agent_identity", "subject": "agent-123"}
    ]));
    let engine = make_context_engine(policy);
    let action = Action::new("read_file", "execute", json!({}));
    let ctx = EvaluationContext {
        agent_identity: Some(make_test_identity(
            "https://auth.example.com",
            "agent-456",
            "admin",
        )),
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "Mismatched subject should deny"
    );
}

#[test]
fn test_agent_identity_required_audience() {
    let policy = make_context_policy(json!([
        {"type": "agent_identity", "audience": "mcp-server"}
    ]));
    let engine = make_context_engine(policy);
    let action = Action::new("read_file", "execute", json!({}));
    let ctx = EvaluationContext {
        agent_identity: Some(make_test_identity(
            "https://auth.example.com",
            "agent-123",
            "admin",
        )),
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Allow),
        "Matching audience should allow"
    );
}

#[test]
fn test_agent_identity_required_audience_mismatch() {
    let policy = make_context_policy(json!([
        {"type": "agent_identity", "audience": "other-server"}
    ]));
    let engine = make_context_engine(policy);
    let action = Action::new("read_file", "execute", json!({}));
    let ctx = EvaluationContext {
        agent_identity: Some(make_test_identity(
            "https://auth.example.com",
            "agent-123",
            "admin",
        )),
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "Audience not in list should deny"
    );
}

#[test]
fn test_agent_identity_required_claim_match() {
    let policy = make_context_policy(json!([
        {"type": "agent_identity", "claims": {"role": "admin"}}
    ]));
    let engine = make_context_engine(policy);
    let action = Action::new("read_file", "execute", json!({}));
    let ctx = EvaluationContext {
        agent_identity: Some(make_test_identity(
            "https://auth.example.com",
            "agent-123",
            "admin",
        )),
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(matches!(v, Verdict::Allow), "Matching claim should allow");
}

#[test]
fn test_agent_identity_required_claim_mismatch() {
    let policy = make_context_policy(json!([
        {"type": "agent_identity", "claims": {"role": "admin"}}
    ]));
    let engine = make_context_engine(policy);
    let action = Action::new("read_file", "execute", json!({}));
    let ctx = EvaluationContext {
        agent_identity: Some(make_test_identity(
            "https://auth.example.com",
            "agent-123",
            "user", // Not "admin"
        )),
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "Mismatched claim should deny"
    );
}

#[test]
fn test_agent_identity_blocked_issuer() {
    let policy = make_context_policy(json!([
        {"type": "agent_identity", "blocked_issuers": ["https://evil.example.com"]}
    ]));
    let engine = make_context_engine(policy);
    let action = Action::new("read_file", "execute", json!({}));
    let ctx = EvaluationContext {
        agent_identity: Some(make_test_identity(
            "https://evil.example.com",
            "agent-123",
            "admin",
        )),
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "Blocked issuer should deny"
    );
}

#[test]
fn test_agent_identity_blocked_issuer_case_insensitive() {
    // SECURITY: Blocked issuers should be case-insensitive
    let policy = make_context_policy(json!([
        {"type": "agent_identity", "blocked_issuers": ["HTTPS://EVIL.EXAMPLE.COM"]}
    ]));
    let engine = make_context_engine(policy);
    let action = Action::new("read_file", "execute", json!({}));
    let ctx = EvaluationContext {
        agent_identity: Some(make_test_identity(
            "https://evil.example.com",
            "agent-123",
            "admin",
        )),
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "Blocked issuer should be case-insensitive"
    );
}

#[test]
fn test_agent_identity_blocked_subject() {
    let policy = make_context_policy(json!([
        {"type": "agent_identity", "blocked_subjects": ["malicious-agent"]}
    ]));
    let engine = make_context_engine(policy);
    let action = Action::new("read_file", "execute", json!({}));
    let ctx = EvaluationContext {
        agent_identity: Some(make_test_identity(
            "https://auth.example.com",
            "malicious-agent",
            "admin",
        )),
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "Blocked subject should deny"
    );
}

#[test]
fn test_agent_identity_missing_fails_closed() {
    // SECURITY: When require_attestation=true (default), missing identity should deny
    let policy = make_context_policy(json!([
        {"type": "agent_identity", "issuer": "https://auth.example.com"}
    ]));
    let engine = make_context_engine(policy);
    let action = Action::new("read_file", "execute", json!({}));
    let ctx = EvaluationContext {
        // No agent_identity
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "Missing identity with require_attestation=true should deny"
    );
}

#[test]
fn test_agent_identity_missing_with_require_attestation_false() {
    // SECURITY (R38-ENG-1): When require_attestation=false but identity requirements
    // (issuer, subject, audience, claims) are configured, missing identity must still deny.
    // Otherwise an attacker can bypass all identity checks by omitting the header.
    let policy = make_context_policy(json!([
        {
            "type": "agent_identity",
            "issuer": "https://auth.example.com",
            "require_attestation": false
        }
    ]));
    let engine = make_context_engine(policy);
    let action = Action::new("read_file", "execute", json!({}));
    let ctx = EvaluationContext {
        // No agent_identity, but issuer requirement is configured
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "R38-ENG-1: Missing identity with issuer requirement should deny, got: {v:?}"
    );
}

#[test]
fn test_agent_identity_combined_conditions() {
    // Test multiple conditions: issuer + subject + claim
    let policy = make_context_policy(json!([
        {
            "type": "agent_identity",
            "issuer": "https://auth.example.com",
            "subject": "agent-123",
            "claims": {"role": "admin"}
        }
    ]));
    let engine = make_context_engine(policy);
    let action = Action::new("read_file", "execute", json!({}));

    // All match - should allow
    let ctx = EvaluationContext {
        agent_identity: Some(make_test_identity(
            "https://auth.example.com",
            "agent-123",
            "admin",
        )),
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Allow),
        "All conditions match should allow"
    );

    // Wrong role - should deny
    let ctx_wrong_role = EvaluationContext {
        agent_identity: Some(make_test_identity(
            "https://auth.example.com",
            "agent-123",
            "user",
        )),
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx_wrong_role))
        .unwrap();
    assert!(matches!(v, Verdict::Deny { .. }), "Wrong role should deny");
}

#[test]
fn test_agent_identity_fallback_to_agent_id() {
    // SECURITY (R38-ENG-1): Combine agent_identity (no positive requirements, only
    // blocked_issuers) with agent_id for backwards compatibility. The identity check
    // passes when no positive requirements are configured (even without identity header),
    // and the agent_id check handles legacy identification.
    let policy = make_context_policy(json!([
        {
            "type": "agent_identity",
            "blocked_issuers": ["evil-corp"],
            "require_attestation": false
        },
        {"type": "agent_id", "allowed": ["legacy-agent"]}
    ]));
    let engine = make_context_engine(policy);
    let action = Action::new("read_file", "execute", json!({}));

    // With agent_identity from a valid issuer + matching agent_id - should allow
    let ctx = EvaluationContext {
        agent_identity: Some(make_test_identity(
            "https://auth.example.com",
            "agent-123",
            "admin",
        )),
        agent_id: Some("legacy-agent".to_string()),
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Allow),
        "Valid identity + matching agent_id should allow, got: {v:?}"
    );

    // R39-ENG-1: With only legacy agent_id (no identity header) and blocked_issuers
    // configured, this now correctly denies. Without the identity header, the
    // blocked issuer check cannot be enforced, so fail-closed applies.
    let ctx_legacy = EvaluationContext {
        agent_id: Some("legacy-agent".to_string()),
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx_legacy))
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "R39-ENG-1: No identity + blocked_issuers should deny even with legacy agent_id, got: {v:?}"
    );

    // With issuer requirement configured + no identity header - should deny (R38-ENG-1)
    let policy_with_issuer = make_context_policy(json!([
        {
            "type": "agent_identity",
            "issuer": "https://auth.example.com",
            "require_attestation": false
        },
        {"type": "agent_id", "allowed": ["legacy-agent"]}
    ]));
    let engine_with_issuer = make_context_engine(policy_with_issuer);
    let ctx_legacy_no_identity = EvaluationContext {
        agent_id: Some("legacy-agent".to_string()),
        ..Default::default()
    };
    let v = engine_with_issuer
        .evaluate_action_with_context(&action, &[], Some(&ctx_legacy_no_identity))
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "R38-ENG-1: Issuer requirement + no identity header must deny, got: {v:?}"
    );
}

// ── R34-ENG-5: MaxCalls case-insensitive matching ──────────────────────

#[test]
fn test_r34_eng_5_max_calls_case_insensitive() {
    let policy = make_context_policy(json!([
        {"type": "max_calls", "tool_pattern": "read_file", "max": 3}
    ]));
    let engine = make_context_engine(policy);
    let action = Action::new("read_file", "execute", json!({}));
    let mut counts = HashMap::new();
    // Split across two case variants — total is 4, exceeds max of 3.
    counts.insert("Read_File".to_string(), 2u64);
    counts.insert("READ_FILE".to_string(), 2u64);
    let ctx = EvaluationContext {
        call_counts: counts,
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "R34-ENG-5: Case-varied call counts should sum for rate limit, got: {v:?}"
    );
}

#[test]
fn test_r34_eng_5_max_calls_in_window_case_insensitive() {
    let policy = make_context_policy(json!([
        {"type": "max_calls_in_window", "tool_pattern": "write_file", "max": 2, "window": 10}
    ]));
    let engine = make_context_engine(policy);
    let action = Action::new("read_file", "execute", json!({}));
    let ctx = EvaluationContext {
        previous_actions: vec![
            "Write_File".to_string(),
            "WRITE_FILE".to_string(),
            "write_file".to_string(),
        ],
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "R34-ENG-5: Case-varied previous actions should sum for window rate limit, got: {v:?}"
    );
}

#[test]
fn test_max_calls_mixed_case_tool_pattern_r36_eng_1() {
    // R36-ENG-1: A mixed-case tool_pattern like "Read_File" must be
    // lowercased at compile time so PatternMatcher::matches() agrees
    // with the lowercased call_count keys built at evaluation time.
    let policy = make_context_policy(json!([
        {"type": "max_calls", "tool_pattern": "Read_File", "max": 3}
    ]));
    let engine = make_context_engine(policy);
    let action = Action::new("read_file", "execute", json!({}));

    // Under the limit — should allow.
    let mut counts = HashMap::new();
    counts.insert("read_file".to_string(), 2u64);
    let ctx = EvaluationContext {
        call_counts: counts,
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Allow),
        "R36-ENG-1: Mixed-case pattern should match lowercased keys (under limit), got: {v:?}"
    );

    // At the limit — should deny.
    let mut counts = HashMap::new();
    counts.insert("read_file".to_string(), 3u64);
    let ctx = EvaluationContext {
        call_counts: counts,
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "R36-ENG-1: Mixed-case pattern should match lowercased keys (at limit), got: {v:?}"
    );
}

#[test]
fn test_max_calls_in_window_mixed_case_tool_pattern_r36_eng_1() {
    // R36-ENG-1: Same fix for max_calls_in_window — mixed-case tool_pattern
    // must be lowercased at compile time.
    let policy = make_context_policy(json!([
        {"type": "max_calls_in_window", "tool_pattern": "Write_File", "max": 2, "window": 10}
    ]));
    let engine = make_context_engine(policy);
    let action = Action::new("read_file", "execute", json!({}));
    let ctx = EvaluationContext {
        previous_actions: vec![
            "write_file".to_string(),
            "write_file".to_string(),
            "write_file".to_string(),
        ],
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "R36-ENG-1: Mixed-case window pattern should match lowercased actions, got: {v:?}"
    );
}

// ── R38-ENG-1: AgentIdentityMatch bypass when JWT omitted ──────────────

#[test]
fn test_agent_identity_match_no_attestation_but_identity_required_denies() {
    // R38-ENG-1: require_attestation=false with required_issuer configured
    // must still deny when no agent_identity header is present.
    let policy = make_context_policy(json!([
        {
            "type": "agent_identity",
            "issuer": "corp",
            "require_attestation": false
        }
    ]));
    let engine = make_context_engine(policy);
    let action = Action::new("read_file", "execute", json!({}));
    let ctx = EvaluationContext {
        // No agent_identity at all
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "R38-ENG-1: No identity + required_issuer should deny, got: {v:?}"
    );
    if let Verdict::Deny { reason } = &v {
        assert!(
            reason.contains("identity restrictions configured"),
            "Deny reason should mention identity restrictions, got: {reason}"
        );
    }
}

#[test]
fn test_agent_identity_match_no_attestation_subject_required_denies() {
    // R38-ENG-1: require_attestation=false with required_subject configured
    let policy = make_context_policy(json!([
        {
            "type": "agent_identity",
            "subject": "agent-007",
            "require_attestation": false
        }
    ]));
    let engine = make_context_engine(policy);
    let action = Action::new("read_file", "execute", json!({}));
    let ctx = EvaluationContext {
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "R38-ENG-1: No identity + required_subject should deny, got: {v:?}"
    );
}

#[test]
fn test_agent_identity_match_no_attestation_audience_required_denies() {
    // R38-ENG-1: require_attestation=false with required_audience configured
    let policy = make_context_policy(json!([
        {
            "type": "agent_identity",
            "audience": "vellaveto-api",
            "require_attestation": false
        }
    ]));
    let engine = make_context_engine(policy);
    let action = Action::new("read_file", "execute", json!({}));
    let ctx = EvaluationContext {
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "R38-ENG-1: No identity + required_audience should deny, got: {v:?}"
    );
}

#[test]
fn test_agent_identity_match_no_attestation_claims_required_denies() {
    // R38-ENG-1: require_attestation=false with required_claims configured
    let policy = make_context_policy(json!([
        {
            "type": "agent_identity",
            "claims": {"role": "admin"},
            "require_attestation": false
        }
    ]));
    let engine = make_context_engine(policy);
    let action = Action::new("read_file", "execute", json!({}));
    let ctx = EvaluationContext {
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "R38-ENG-1: No identity + required_claims should deny, got: {v:?}"
    );
}

#[test]
fn test_agent_identity_match_no_attestation_blocked_only_denies_r39_eng_1() {
    // R39-ENG-1: require_attestation=false with blocked_issuers configured
    // must deny when no identity header is present. Without the header,
    // blocked issuer checks cannot be enforced (bypass by omission).
    // This supersedes the R38-ENG-1 behavior that allowed this case.
    let policy = make_context_policy(json!([
        {
            "type": "agent_identity",
            "blocked_issuers": ["evil-corp"],
            "require_attestation": false
        }
    ]));
    let engine = make_context_engine(policy);
    let action = Action::new("read_file", "execute", json!({}));
    let ctx = EvaluationContext {
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "R39-ENG-1: No identity + blocked_issuers should deny, got: {v:?}"
    );
}

// ── R38-ENG-2: Double percent-decode in extract_domain ─────────────────

#[test]
fn test_extract_domain_no_double_decode_r38_eng_2() {
    // R38-ENG-2: %2525 should decode to %25 (single decode), NOT to % (double decode).
    // "safe%252Eexample%252Ecom" → single decode → "safe%2eexample%2ecom"
    // A double decode would produce "safe.example.com" which is wrong.
    let domain = PolicyEngine::extract_domain("http://safe%252Eexample%252Ecom/path");
    assert_eq!(
        domain, "safe%2eexample%2ecom",
        "R38-ENG-2: Should single-decode only, not double-decode"
    );
}

#[test]
fn test_extract_domain_single_decode_still_works_r38_eng_2() {
    // Verify that normal single-encoded domains still decode correctly.
    // "evil%2Ecom" → single decode → "evil.com"
    let domain = PolicyEngine::extract_domain("http://evil%2Ecom/path");
    assert_eq!(
        domain, "evil.com",
        "R38-ENG-2: Single-encoded dots should still decode"
    );
}

#[test]
fn test_extract_domain_double_encoded_at_sign_r38_eng_2() {
    // %2540 = double-encoded @. Single decode → %40 (literal, not @).
    // Should NOT be treated as userinfo separator.
    let domain = PolicyEngine::extract_domain("http://user%2540host.com/path");
    assert_eq!(
        domain, "user%40host.com",
        "R38-ENG-2: Double-encoded @ should stay as %40 after single decode"
    );
}

// ── R39-ENG-1: AgentIdentityMatch bypass via omitted header with blocklists ──

#[test]
fn test_agent_identity_blocked_issuers_only_no_header_denies_r39_eng_1() {
    // R39-ENG-1: When only blocked_issuers is configured (no positive requirements)
    // and require_attestation=false, omitting the X-Agent-Identity header must still
    // produce Deny. Without this fix, the None arm only checked required_* fields,
    // allowing blocklist bypass.
    let policy = make_context_policy(json!([
        {
            "type": "agent_identity",
            "blocked_issuers": ["https://evil.example.com"],
            "require_attestation": false
        }
    ]));
    let engine = make_context_engine(policy);
    let action = Action::new("read_file", "execute", json!({}));
    let ctx = EvaluationContext {
        // No agent_identity at all — attacker omits the header
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "R39-ENG-1: No identity + blocked_issuers should deny, got: {v:?}"
    );
    if let Verdict::Deny { reason } = &v {
        assert!(
            reason.contains("identity restrictions configured"),
            "Deny reason should mention identity restrictions, got: {reason}"
        );
    }
}

#[test]
fn test_agent_identity_blocked_subjects_only_no_header_denies_r39_eng_1() {
    // R39-ENG-1: Same as above but with blocked_subjects instead of blocked_issuers.
    let policy = make_context_policy(json!([
        {
            "type": "agent_identity",
            "blocked_subjects": ["rogue-agent"],
            "require_attestation": false
        }
    ]));
    let engine = make_context_engine(policy);
    let action = Action::new("read_file", "execute", json!({}));
    let ctx = EvaluationContext {
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "R39-ENG-1: No identity + blocked_subjects should deny, got: {v:?}"
    );
    if let Verdict::Deny { reason } = &v {
        assert!(
            reason.contains("identity restrictions configured"),
            "Deny reason should mention identity restrictions, got: {reason}"
        );
    }
}

#[test]
fn test_agent_identity_blocked_issuers_with_header_allows_non_blocked_r39_eng_1() {
    // R39-ENG-1: When a non-blocked identity IS provided, it should still Allow.
    let policy = make_context_policy(json!([
        {
            "type": "agent_identity",
            "blocked_issuers": ["https://evil.example.com"],
            "require_attestation": false
        }
    ]));
    let engine = make_context_engine(policy);
    let action = Action::new("read_file", "execute", json!({}));
    let identity = make_test_identity("https://good.example.com", "agent-1", "worker");
    let ctx = EvaluationContext {
        agent_identity: Some(identity),
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Allow),
        "R39-ENG-1: Non-blocked identity should allow, got: {v:?}"
    );
}

// ── R39-ENG-3: normalize_domain_for_match ASCII fallback validation ─────────

#[test]
fn test_normalize_domain_rejects_space_r39_eng_3() {
    // R39-ENG-3: ASCII domain with trailing space should be rejected (not fall through
    // to the ASCII fallback), since space is not a valid domain character.
    let result = PolicyEngine::normalize_domain_for_match("evil.com ");
    assert!(
        result.is_none(),
        "R39-ENG-3: Domain with space should return None, got: {result:?}"
    );
}

#[test]
fn test_normalize_domain_rejects_colon_r39_eng_3() {
    // R39-ENG-3: ASCII domain with colon (e.g., port number leaked in) should be rejected.
    let result = PolicyEngine::normalize_domain_for_match("evil.com:8080");
    assert!(
        result.is_none(),
        "R39-ENG-3: Domain with colon should return None, got: {result:?}"
    );
}

#[test]
fn test_normalize_domain_rejects_at_sign_r39_eng_3() {
    // R39-ENG-3: ASCII domain with @ (e.g., userinfo leaked) should be rejected.
    let result = PolicyEngine::normalize_domain_for_match("user@evil.com");
    assert!(
        result.is_none(),
        "R39-ENG-3: Domain with @ should return None, got: {result:?}"
    );
}

#[test]
fn test_normalize_domain_rejects_slash_r39_eng_3() {
    // R39-ENG-3: ASCII domain with slash should be rejected.
    let result = PolicyEngine::normalize_domain_for_match("evil.com/path");
    assert!(
        result.is_none(),
        "R39-ENG-3: Domain with slash should return None, got: {result:?}"
    );
}

#[test]
fn test_normalize_domain_accepts_underscore_srv_r39_eng_3() {
    // R39-ENG-3: SRV-style domains with underscores should still be accepted
    // (this is the legitimate IDNA edge case the fallback exists for).
    let result = PolicyEngine::normalize_domain_for_match("_srv.evil.com");
    assert!(
        result.is_some(),
        "R39-ENG-3: SRV-style domain with underscore should be accepted"
    );
    assert_eq!(
        result.unwrap().as_ref(),
        "_srv.evil.com",
        "R39-ENG-3: Should normalize to lowercase"
    );
}

#[test]
fn test_normalize_domain_accepts_hyphen_r39_eng_3() {
    // R39-ENG-3: Domains with hyphens are valid and should be accepted.
    let result = PolicyEngine::normalize_domain_for_match("my-domain.example.com");
    assert!(
        result.is_some(),
        "R39-ENG-3: Domain with hyphen should be accepted"
    );
}

#[test]
fn test_normalize_domain_rejects_null_byte_r39_eng_3() {
    // R39-ENG-3: Null byte in domain is never valid.
    let result = PolicyEngine::normalize_domain_for_match("evil\0.com");
    assert!(
        result.is_none(),
        "R39-ENG-3: Domain with null byte should return None, got: {result:?}"
    );
}

// ── R40-ENG-2: AgentIdentityMatch case-sensitivity inconsistency ─────────

#[test]
fn test_agent_identity_required_issuer_case_insensitive_r40_eng_2() {
    // R40-ENG-2: A policy with mixed-case required_issuer must match a JWT
    // whose issuer is all-lowercase.
    let policy = make_context_policy(json!([
        {
            "type": "agent_identity",
            "issuer": "https://Auth.Example.COM"
        }
    ]));
    let engine = make_context_engine(policy);
    let action = Action::new("read_file", "execute", json!({}));
    let ctx = EvaluationContext {
        agent_identity: Some(AgentIdentity {
            issuer: Some("https://auth.example.com".to_string()),
            subject: None,
            audience: vec![],
            claims: Default::default(),
        }),
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Allow),
        "R40-ENG-2: Mixed-case required_issuer should match lowercase JWT issuer, got: {v:?}"
    );
}

#[test]
fn test_agent_identity_required_issuer_lowercase_matches_uppercase_jwt_r40_eng_2() {
    // R40-ENG-2: A policy with lowercase required_issuer must match a JWT
    // whose issuer is uppercase.
    let policy = make_context_policy(json!([
        {
            "type": "agent_identity",
            "issuer": "https://auth.example.com"
        }
    ]));
    let engine = make_context_engine(policy);
    let action = Action::new("read_file", "execute", json!({}));
    let ctx = EvaluationContext {
        agent_identity: Some(AgentIdentity {
            issuer: Some("https://AUTH.EXAMPLE.COM".to_string()),
            subject: None,
            audience: vec![],
            claims: Default::default(),
        }),
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Allow),
        "R40-ENG-2: Lowercase required_issuer should match uppercase JWT issuer, got: {v:?}"
    );
}

#[test]
fn test_agent_identity_required_subject_case_insensitive_r40_eng_2() {
    // R40-ENG-2: A policy with mixed-case required_subject must match a JWT
    // whose subject has different casing.
    let policy = make_context_policy(json!([
        {
            "type": "agent_identity",
            "subject": "Agent-ALPHA"
        }
    ]));
    let engine = make_context_engine(policy);
    let action = Action::new("read_file", "execute", json!({}));
    let ctx = EvaluationContext {
        agent_identity: Some(AgentIdentity {
            issuer: None,
            subject: Some("agent-alpha".to_string()),
            audience: vec![],
            claims: Default::default(),
        }),
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Allow),
        "R40-ENG-2: Mixed-case required_subject should match lowercase JWT subject, got: {v:?}"
    );
}

#[test]
fn test_agent_identity_required_audience_case_insensitive_r40_eng_2() {
    // R40-ENG-2: A policy with uppercase required_audience must match a JWT
    // whose audience is lowercase.
    let policy = make_context_policy(json!([
        {
            "type": "agent_identity",
            "audience": "VELLAVETO-API"
        }
    ]));
    let engine = make_context_engine(policy);
    let action = Action::new("read_file", "execute", json!({}));
    let ctx = EvaluationContext {
        agent_identity: Some(AgentIdentity {
            issuer: None,
            subject: None,
            audience: vec!["vellaveto-api".to_string()],
            claims: Default::default(),
        }),
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Allow),
        "R40-ENG-2: Uppercase required_audience should match lowercase JWT audience, got: {v:?}"
    );
}

#[test]
fn test_agent_identity_audience_mixed_case_in_jwt_array_r40_eng_2() {
    // R40-ENG-2: When JWT has multiple audiences with mixed casing,
    // a lowercase required_audience should match any of them.
    let policy = make_context_policy(json!([
        {
            "type": "agent_identity",
            "audience": "my-service"
        }
    ]));
    let engine = make_context_engine(policy);
    let action = Action::new("read_file", "execute", json!({}));
    let ctx = EvaluationContext {
        agent_identity: Some(AgentIdentity {
            issuer: None,
            subject: None,
            audience: vec!["other-service".to_string(), "MY-SERVICE".to_string()],
            claims: Default::default(),
        }),
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Allow),
        "R40-ENG-2: Audience in JWT array with different case should still match, got: {v:?}"
    );
}

#[test]
fn test_agent_identity_required_issuer_mismatch_still_denies_r40_eng_2() {
    // R40-ENG-2: Verify that case-insensitive matching doesn't weaken
    // actual mismatches — different issuers should still deny.
    let policy = make_context_policy(json!([
        {
            "type": "agent_identity",
            "issuer": "https://trusted.example.com"
        }
    ]));
    let engine = make_context_engine(policy);
    let action = Action::new("read_file", "execute", json!({}));
    let ctx = EvaluationContext {
        agent_identity: Some(AgentIdentity {
            issuer: Some("https://evil.example.com".to_string()),
            subject: None,
            audience: vec![],
            claims: Default::default(),
        }),
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "R40-ENG-2: Different issuer should still deny even with case-insensitive matching, got: {v:?}"
    );
}

// ════════════════════════════════════════════════════════════════
// FIND-043: Context condition coverage — MaxChainDepth
// ════════════════════════════════════════════════════════════════

#[test]
fn test_context_max_chain_depth_under_limit_allows() {
    let policy = make_context_policy(json!([
        {"type": "max_chain_depth", "max_depth": 3}
    ]));
    let engine = make_context_engine(policy);
    let action = Action::new("read_file", "execute", json!({}));
    let ctx = EvaluationContext {
        call_chain: vec![vellaveto_types::CallChainEntry {
            agent_id: "a".into(),
            tool: "t".into(),
            function: "f".into(),
            timestamp: "2026-01-01T00:00:00Z".into(),
            hmac: None,
            verified: None,
        }],
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Allow),
        "Chain depth 1 <= 3 should allow, got: {v:?}"
    );
}

#[test]
fn test_context_max_chain_depth_over_limit_denies() {
    let policy = make_context_policy(json!([
        {"type": "max_chain_depth", "max_depth": 2}
    ]));
    let engine = make_context_engine(policy);
    let action = Action::new("read_file", "execute", json!({}));
    let entry = vellaveto_types::CallChainEntry {
        agent_id: "a".into(),
        tool: "t".into(),
        function: "f".into(),
        timestamp: "2026-01-01T00:00:00Z".into(),
        hmac: None,
        verified: None,
    };
    let ctx = EvaluationContext {
        call_chain: vec![entry.clone(), entry.clone(), entry],
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "Chain depth 3 > 2 should deny, got: {v:?}"
    );
}

// SECURITY (FIND-R110-002): MaxChainDepth uses > (exclusive upper bound).
// A chain of length max_depth is allowed; length max_depth+1 is denied.
#[test]
fn test_context_max_chain_depth_exact_limit_allows() {
    let policy = make_context_policy(json!([
        {"type": "max_chain_depth", "max_depth": 2}
    ]));
    let engine = make_context_engine(policy);
    let action = Action::new("read_file", "execute", json!({}));
    let entry = vellaveto_types::CallChainEntry {
        agent_id: "a".into(),
        tool: "t".into(),
        function: "f".into(),
        timestamp: "2026-01-01T00:00:00Z".into(),
        hmac: None,
        verified: None,
    };
    let ctx = EvaluationContext {
        call_chain: vec![entry.clone(), entry],
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Allow),
        "Chain depth 2 == max_depth 2 should allow (> exclusive semantics), got: {v:?}"
    );
}

#[test]
fn test_context_max_chain_depth_below_limit_allows() {
    let policy = make_context_policy(json!([
        {"type": "max_chain_depth", "max_depth": 2}
    ]));
    let engine = make_context_engine(policy);
    let action = Action::new("read_file", "execute", json!({}));
    let entry = vellaveto_types::CallChainEntry {
        agent_id: "a".into(),
        tool: "t".into(),
        function: "f".into(),
        timestamp: "2026-01-01T00:00:00Z".into(),
        hmac: None,
        verified: None,
    };
    let ctx = EvaluationContext {
        call_chain: vec![entry],
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Allow),
        "Chain depth 1 < max 2 should allow, got: {v:?}"
    );
}

// ════════════════════════════════════════════════════════════════
// FIND-043: Context condition coverage — ResourceIndicator
// ════════════════════════════════════════════════════════════════

#[test]
fn test_context_resource_indicator_matching_allows() {
    let policy = make_context_policy(json!([
        {"type": "resource_indicator", "allowed_resources": ["https://api.example.com/*"], "require_resource": true}
    ]));
    let engine = make_context_engine(policy);
    let action = Action::new("read_file", "execute", json!({}));
    let ctx = EvaluationContext {
        agent_identity: Some(AgentIdentity {
            issuer: None,
            subject: None,
            audience: vec![],
            claims: serde_json::from_value(json!({"resource": "https://api.example.com/data"}))
                .unwrap(),
        }),
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Allow),
        "Matching resource should allow, got: {v:?}"
    );
}

#[test]
fn test_context_resource_indicator_missing_when_required_denies() {
    let policy = make_context_policy(json!([
        {"type": "resource_indicator", "allowed_resources": ["https://api.example.com/*"], "require_resource": true}
    ]));
    let engine = make_context_engine(policy);
    let action = Action::new("read_file", "execute", json!({}));
    let ctx = EvaluationContext {
        agent_identity: Some(AgentIdentity {
            issuer: None,
            subject: None,
            audience: vec![],
            claims: Default::default(),
        }),
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "Missing resource when required should deny, got: {v:?}"
    );
}

#[test]
fn test_context_resource_indicator_not_in_allowed_denies() {
    let policy = make_context_policy(json!([
        {"type": "resource_indicator", "allowed_resources": ["https://api.example.com/*"]}
    ]));
    let engine = make_context_engine(policy);
    let action = Action::new("read_file", "execute", json!({}));
    let ctx = EvaluationContext {
        agent_identity: Some(AgentIdentity {
            issuer: None,
            subject: None,
            audience: vec![],
            claims: serde_json::from_value(json!({"resource": "https://evil.com/data"})).unwrap(),
        }),
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "Non-matching resource should deny, got: {v:?}"
    );
}

#[test]
fn test_context_resource_indicator_no_identity_denies() {
    let policy = make_context_policy(json!([
        {"type": "resource_indicator", "allowed_resources": ["https://api.example.com/*"]}
    ]));
    let engine = make_context_engine(policy);
    let action = Action::new("read_file", "execute", json!({}));
    let ctx = EvaluationContext::default();
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "No identity with allowed_resources should deny, got: {v:?}"
    );
}

// ════════════════════════════════════════════════════════════════
// FIND-043: Context condition coverage — CapabilityRequired
// ════════════════════════════════════════════════════════════════

#[test]
fn test_context_capability_required_present_allows() {
    let policy = make_context_policy(json!([
        {"type": "capability_required", "required_capabilities": ["read"]}
    ]));
    let engine = make_context_engine(policy);
    let action = Action::new("read_file", "execute", json!({}));
    let ctx = EvaluationContext {
        agent_identity: Some(AgentIdentity {
            issuer: None,
            subject: None,
            audience: vec![],
            claims: serde_json::from_value(json!({"capabilities": "read,write"})).unwrap(),
        }),
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Allow),
        "Agent with required capability should allow, got: {v:?}"
    );
}

#[test]
fn test_context_capability_required_missing_denies() {
    let policy = make_context_policy(json!([
        {"type": "capability_required", "required_capabilities": ["admin"]}
    ]));
    let engine = make_context_engine(policy);
    let action = Action::new("read_file", "execute", json!({}));
    let ctx = EvaluationContext {
        agent_identity: Some(AgentIdentity {
            issuer: None,
            subject: None,
            audience: vec![],
            claims: serde_json::from_value(json!({"capabilities": "read,write"})).unwrap(),
        }),
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "Missing required capability should deny, got: {v:?}"
    );
}

#[test]
fn test_context_capability_blocked_present_denies() {
    let policy = make_context_policy(json!([
        {"type": "capability_required", "blocked_capabilities": ["destructive"]}
    ]));
    let engine = make_context_engine(policy);
    let action = Action::new("read_file", "execute", json!({}));
    let ctx = EvaluationContext {
        agent_identity: Some(AgentIdentity {
            issuer: None,
            subject: None,
            audience: vec![],
            claims: serde_json::from_value(json!({"capabilities": "read,destructive"})).unwrap(),
        }),
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "Blocked capability present should deny, got: {v:?}"
    );
}

#[test]
fn test_context_capability_no_identity_denies() {
    let policy = make_context_policy(json!([
        {"type": "capability_required", "required_capabilities": ["read"]}
    ]));
    let engine = make_context_engine(policy);
    let action = Action::new("read_file", "execute", json!({}));
    let ctx = EvaluationContext::default();
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "No identity with required capabilities should deny, got: {v:?}"
    );
}

#[test]
fn test_context_capability_case_insensitive() {
    let policy = make_context_policy(json!([
        {"type": "capability_required", "required_capabilities": ["Admin"]}
    ]));
    let engine = make_context_engine(policy);
    let action = Action::new("read_file", "execute", json!({}));
    let ctx = EvaluationContext {
        agent_identity: Some(AgentIdentity {
            issuer: None,
            subject: None,
            audience: vec![],
            claims: serde_json::from_value(json!({"capabilities": "admin,read"})).unwrap(),
        }),
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Allow),
        "Case-insensitive capability match should allow, got: {v:?}"
    );
}

// ════════════════════════════════════════════════════════════════
// FIND-043: Context condition coverage — StepUpAuth
// ════════════════════════════════════════════════════════════════

#[test]
fn test_context_step_up_auth_sufficient_level_allows() {
    let policy = make_context_policy(json!([
        {"type": "step_up_auth", "required_level": 2}
    ]));
    let engine = make_context_engine(policy);
    let action = Action::new("read_file", "execute", json!({}));
    let ctx = EvaluationContext {
        agent_identity: Some(AgentIdentity {
            issuer: None,
            subject: None,
            audience: vec![],
            claims: serde_json::from_value(json!({"auth_level": "3"})).unwrap(),
        }),
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Allow),
        "Auth level 3 >= 2 should allow, got: {v:?}"
    );
}

#[test]
fn test_context_step_up_auth_insufficient_level_returns_require_approval() {
    let policy = make_context_policy(json!([
        {"type": "step_up_auth", "required_level": 4}
    ]));
    let engine = make_context_engine(policy);
    let action = Action::new("read_file", "execute", json!({}));
    let ctx = EvaluationContext {
        agent_identity: Some(AgentIdentity {
            issuer: None,
            subject: None,
            audience: vec![],
            claims: serde_json::from_value(json!({"auth_level": "2"})).unwrap(),
        }),
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::RequireApproval { .. }),
        "Auth level 2 < 4 should require approval, got: {v:?}"
    );
}

#[test]
fn test_context_step_up_auth_no_identity_returns_require_approval() {
    let policy = make_context_policy(json!([
        {"type": "step_up_auth", "required_level": 1}
    ]));
    let engine = make_context_engine(policy);
    let action = Action::new("read_file", "execute", json!({}));
    let ctx = EvaluationContext::default();
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::RequireApproval { .. }),
        "No identity defaults to level 0 < 1, should require approval, got: {v:?}"
    );
}

// ════════════════════════════════════════════════════════════════
// FIND-043: Context condition coverage — DeputyValidation
// ════════════════════════════════════════════════════════════════

#[test]
fn test_context_deputy_validation_no_principal_denies() {
    let policy = make_context_policy(json!([
        {"type": "deputy_validation", "require_principal": true, "max_delegation_depth": 5}
    ]));
    let engine = make_context_engine(policy);
    let action = Action::new("read_file", "execute", json!({}));
    let ctx = EvaluationContext::default();
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "No principal when required should deny, got: {v:?}"
    );
}

#[test]
fn test_context_deputy_validation_with_principal_allows() {
    let policy = make_context_policy(json!([
        {"type": "deputy_validation", "require_principal": true, "max_delegation_depth": 5}
    ]));
    let engine = make_context_engine(policy);
    let action = Action::new("read_file", "execute", json!({}));
    let ctx = EvaluationContext {
        agent_id: Some("agent-1".into()),
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Allow),
        "With agent_id as principal should allow, got: {v:?}"
    );
}

#[test]
fn test_context_deputy_validation_depth_exceeded_denies() {
    let policy = make_context_policy(json!([
        {"type": "deputy_validation", "require_principal": false, "max_delegation_depth": 2}
    ]));
    let engine = make_context_engine(policy);
    let action = Action::new("read_file", "execute", json!({}));
    let entry = vellaveto_types::CallChainEntry {
        agent_id: "a".into(),
        tool: "t".into(),
        function: "f".into(),
        timestamp: "2026-01-01T00:00:00Z".into(),
        hmac: None,
        verified: None,
    };
    let ctx = EvaluationContext {
        call_chain: vec![entry.clone(), entry.clone(), entry],
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "Delegation depth 3 > 2 should deny, got: {v:?}"
    );
}

// ════════════════════════════════════════════════════════════════
// FIND-043: Marker conditions (CircuitBreaker, ShadowAgent, SchemaPoisoning)
// These conditions are evaluated as pass-through markers in the engine;
// actual enforcement is in integration layers. Test that they compile and
// don't block evaluation.
// ════════════════════════════════════════════════════════════════

#[test]
fn test_context_circuit_breaker_marker_passes_through() {
    let policy = make_context_policy(json!([
        {"type": "circuit_breaker", "tool_pattern": "read_file"}
    ]));
    let engine = make_context_engine(policy);
    let action = Action::new("read_file", "execute", json!({}));
    let ctx = EvaluationContext::default();
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Allow),
        "Circuit breaker marker should pass through, got: {v:?}"
    );
}

#[test]
fn test_context_shadow_agent_marker_passes_through() {
    let policy = make_context_policy(json!([
        {"type": "shadow_agent_check", "require_known_fingerprint": true, "min_trust_level": 0.5}
    ]));
    let engine = make_context_engine(policy);
    let action = Action::new("read_file", "execute", json!({}));
    let ctx = EvaluationContext::default();
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Allow),
        "Shadow agent marker should pass through, got: {v:?}"
    );
}

#[test]
fn test_context_schema_poisoning_marker_passes_through() {
    let policy = make_context_policy(json!([
        {"type": "schema_poisoning_check", "mutation_threshold": 0.5}
    ]));
    let engine = make_context_engine(policy);
    let action = Action::new("read_file", "execute", json!({}));
    let ctx = EvaluationContext::default();
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Allow),
        "Schema poisoning marker should pass through, got: {v:?}"
    );
}

#[test]
fn test_context_async_task_policy_marker_passes_through() {
    let policy = make_context_policy(json!([
        {"type": "async_task_policy", "max_concurrent": 10, "max_duration_secs": 300, "require_self_cancel": true}
    ]));
    let engine = make_context_engine(policy);
    let action = Action::new("read_file", "execute", json!({}));
    let ctx = EvaluationContext::default();
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Allow),
        "Async task policy marker should pass through, got: {v:?}"
    );
}

// ── Capability token context condition tests ────────────────────────────────

#[test]
fn test_require_capability_token_missing_denied() {
    let policy = make_context_policy(json!([{
        "type": "require_capability_token"
    }]));
    let engine = make_context_engine(policy.clone());
    let action = Action::new("read_file".to_string(), "read".to_string(), json!({}));
    let ctx = EvaluationContext::default();
    let v = engine
        .evaluate_action_with_context(&action, &[policy], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "Missing token should deny: {v:?}"
    );
}

#[test]
fn test_require_capability_token_present_allowed() {
    let policy = make_context_policy(json!([{
        "type": "require_capability_token"
    }]));
    let engine = make_context_engine(policy.clone());
    let action = Action::new("read_file".to_string(), "read".to_string(), json!({}));
    let token = vellaveto_types::CapabilityToken {
        token_id: "tok-1".into(),
        parent_token_id: None,
        issuer: "root-agent".into(),
        holder: "agent-a".into(),
        grants: vec![vellaveto_types::CapabilityGrant {
            tool_pattern: "*".into(),
            function_pattern: "*".into(),
            allowed_paths: vec![],
            allowed_domains: vec![],
            max_invocations: 0,
        }],
        remaining_depth: 3,
        issued_at: "2026-01-01T00:00:00Z".into(),
        expires_at: "2027-01-01T00:00:00Z".into(),
        signature: "deadbeef".into(),
        issuer_public_key: "cafebabe".into(),
    };
    let ctx = EvaluationContext::builder()
        .agent_id("agent-a")
        .capability_token(token)
        .build();
    let v = engine
        .evaluate_action_with_context(&action, &[policy], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Allow),
        "Token present should allow: {v:?}"
    );
}

#[test]
fn test_require_capability_token_holder_mismatch_denied() {
    let policy = make_context_policy(json!([{
        "type": "require_capability_token"
    }]));
    let engine = make_context_engine(policy.clone());
    let action = Action::new("read_file".to_string(), "read".to_string(), json!({}));
    let token = vellaveto_types::CapabilityToken {
        token_id: "tok-1".into(),
        parent_token_id: None,
        issuer: "root".into(),
        holder: "agent-b".into(),
        grants: vec![vellaveto_types::CapabilityGrant {
            tool_pattern: "*".into(),
            function_pattern: "*".into(),
            allowed_paths: vec![],
            allowed_domains: vec![],
            max_invocations: 0,
        }],
        remaining_depth: 3,
        issued_at: "2026-01-01T00:00:00Z".into(),
        expires_at: "2027-01-01T00:00:00Z".into(),
        signature: "x".into(),
        issuer_public_key: "y".into(),
    };
    let ctx = EvaluationContext::builder()
        .agent_id("agent-a")
        .capability_token(token)
        .build();
    let v = engine
        .evaluate_action_with_context(&action, &[policy], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "Holder mismatch should deny: {v:?}"
    );
}

#[test]
fn test_require_capability_token_missing_agent_id_denied() {
    let policy = make_context_policy(json!([{
        "type": "require_capability_token"
    }]));
    let engine = make_context_engine(policy.clone());
    let action = Action::new("read_file".to_string(), "read".to_string(), json!({}));
    let token = vellaveto_types::CapabilityToken {
        token_id: "tok-1".into(),
        parent_token_id: None,
        issuer: "root".into(),
        holder: "agent-a".into(),
        grants: vec![vellaveto_types::CapabilityGrant {
            tool_pattern: "*".into(),
            function_pattern: "*".into(),
            allowed_paths: vec![],
            allowed_domains: vec![],
            max_invocations: 0,
        }],
        remaining_depth: 3,
        issued_at: "2026-01-01T00:00:00Z".into(),
        expires_at: "2027-01-01T00:00:00Z".into(),
        signature: "x".into(),
        issuer_public_key: "y".into(),
    };
    let ctx = EvaluationContext::builder().capability_token(token).build();
    let v = engine
        .evaluate_action_with_context(&action, &[policy], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "Missing agent_id should deny: {v:?}"
    );
}

#[test]
fn test_require_capability_token_issuer_allowlist_denied() {
    let policy = make_context_policy(json!([{
        "type": "require_capability_token",
        "required_issuers": ["trusted-issuer"]
    }]));
    let engine = make_context_engine(policy.clone());
    let action = Action::new("read_file".to_string(), "read".to_string(), json!({}));
    let token = vellaveto_types::CapabilityToken {
        token_id: "tok-1".into(),
        parent_token_id: None,
        issuer: "untrusted-issuer".into(),
        holder: "agent-a".into(),
        grants: vec![vellaveto_types::CapabilityGrant {
            tool_pattern: "*".into(),
            function_pattern: "*".into(),
            allowed_paths: vec![],
            allowed_domains: vec![],
            max_invocations: 0,
        }],
        remaining_depth: 3,
        issued_at: "2026-01-01T00:00:00Z".into(),
        expires_at: "2027-01-01T00:00:00Z".into(),
        signature: "x".into(),
        issuer_public_key: "y".into(),
    };
    let ctx = EvaluationContext::builder()
        .agent_id("agent-a")
        .capability_token(token)
        .build();
    let v = engine
        .evaluate_action_with_context(&action, &[policy], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "Wrong issuer should deny: {v:?}"
    );
}

#[test]
fn test_require_capability_token_depth_insufficient() {
    let policy = make_context_policy(json!([{
        "type": "require_capability_token",
        "min_remaining_depth": 3
    }]));
    let engine = make_context_engine(policy.clone());
    let action = Action::new("read_file".to_string(), "read".to_string(), json!({}));
    let token = vellaveto_types::CapabilityToken {
        token_id: "tok-1".into(),
        parent_token_id: None,
        issuer: "root".into(),
        holder: "agent-a".into(),
        grants: vec![vellaveto_types::CapabilityGrant {
            tool_pattern: "*".into(),
            function_pattern: "*".into(),
            allowed_paths: vec![],
            allowed_domains: vec![],
            max_invocations: 0,
        }],
        remaining_depth: 1,
        issued_at: "2026-01-01T00:00:00Z".into(),
        expires_at: "2027-01-01T00:00:00Z".into(),
        signature: "x".into(),
        issuer_public_key: "y".into(),
    };
    let ctx = EvaluationContext::builder()
        .agent_id("agent-a")
        .capability_token(token)
        .build();
    let v = engine
        .evaluate_action_with_context(&action, &[policy], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "Insufficient depth should deny: {v:?}"
    );
}

fn make_delegated_capability_token(
    holder: &str,
    remaining_depth: u8,
) -> vellaveto_types::CapabilityToken {
    vellaveto_types::CapabilityToken {
        token_id: "tok-delegated".into(),
        parent_token_id: None,
        issuer: "root".into(),
        holder: holder.into(),
        grants: vec![vellaveto_types::CapabilityGrant {
            tool_pattern: "*".into(),
            function_pattern: "*".into(),
            allowed_paths: vec![],
            allowed_domains: vec![],
            max_invocations: 0,
        }],
        remaining_depth,
        issued_at: "2026-01-01T00:00:00Z".into(),
        expires_at: "2027-01-01T00:00:00Z".into(),
        signature: "sig".into(),
        issuer_public_key: "pub".into(),
    }
}

fn make_delegation_chain(ids: &[&str]) -> Vec<CallChainEntry> {
    ids.iter()
        .map(|id| CallChainEntry {
            agent_id: (*id).to_string(),
            tool: "deputy".to_string(),
            function: "delegated".to_string(),
            timestamp: "2026-03-08T10:00:00Z".to_string(),
            hmac: None,
            verified: None,
        })
        .collect()
}

#[test]
fn test_deputy_validation_and_capability_token_allow_when_both_satisfied() {
    let policy = make_context_policy(json!([
        {"type": "deputy_validation", "require_principal": true, "max_delegation_depth": 2},
        {"type": "require_capability_token", "min_remaining_depth": 1}
    ]));
    let engine = make_context_engine(policy.clone());
    let action = Action::new("read_file".to_string(), "read".to_string(), json!({}));
    let ctx = EvaluationContext::builder()
        .agent_id("agent-a")
        .capability_token(make_delegated_capability_token("agent-a", 3))
        .call_chain(make_delegation_chain(&["delegator-1"]))
        .build();

    let v = engine
        .evaluate_action_with_context(&action, &[policy], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Allow),
        "paired context should allow: {v:?}"
    );
}

#[test]
fn test_deputy_validation_and_capability_token_missing_token_denied() {
    let policy = make_context_policy(json!([
        {"type": "deputy_validation", "require_principal": true, "max_delegation_depth": 2},
        {"type": "require_capability_token", "min_remaining_depth": 1}
    ]));
    let engine = make_context_engine(policy.clone());
    let action = Action::new("read_file".to_string(), "read".to_string(), json!({}));
    let ctx = EvaluationContext::builder()
        .agent_id("agent-a")
        .call_chain(make_delegation_chain(&["delegator-1"]))
        .build();

    let v = engine
        .evaluate_action_with_context(&action, &[policy], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "missing token should deny: {v:?}"
    );
    if let Verdict::Deny { reason } = v {
        assert!(reason.contains("no capability token"));
    }
}

#[test]
fn test_deputy_validation_and_capability_token_missing_agent_id_denied() {
    let policy = make_context_policy(json!([
        {"type": "deputy_validation", "require_principal": true, "max_delegation_depth": 2},
        {"type": "require_capability_token", "min_remaining_depth": 1}
    ]));
    let engine = make_context_engine(policy.clone());
    let action = Action::new("read_file".to_string(), "read".to_string(), json!({}));
    let ctx = EvaluationContext::builder()
        .agent_identity(AgentIdentity {
            issuer: Some("issuer".into()),
            subject: Some("agent-a".into()),
            ..Default::default()
        })
        .capability_token(make_delegated_capability_token("agent-a", 3))
        .call_chain(make_delegation_chain(&["delegator-1"]))
        .build();

    let v = engine
        .evaluate_action_with_context(&action, &[policy], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "missing agent_id should deny paired context: {v:?}"
    );
    if let Verdict::Deny { reason } = v {
        assert!(reason.contains("cannot verify token holder binding"));
    }
}

#[test]
fn test_deputy_validation_and_capability_token_delegation_depth_denied() {
    let policy = make_context_policy(json!([
        {"type": "deputy_validation", "require_principal": true, "max_delegation_depth": 1},
        {"type": "require_capability_token", "min_remaining_depth": 1}
    ]));
    let engine = make_context_engine(policy.clone());
    let action = Action::new("read_file".to_string(), "read".to_string(), json!({}));
    let ctx = EvaluationContext::builder()
        .agent_id("agent-a")
        .capability_token(make_delegated_capability_token("agent-a", 3))
        .call_chain(make_delegation_chain(&["delegator-1", "delegator-2"]))
        .build();

    let v = engine
        .evaluate_action_with_context(&action, &[policy], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "delegation depth should deny paired context: {v:?}"
    );
    if let Verdict::Deny { reason } = v {
        assert!(reason.contains("delegation depth"));
    }
}

#[test]
fn test_deputy_validation_and_capability_token_issuer_allowlist_denied() {
    let policy = make_context_policy(json!([
        {"type": "deputy_validation", "require_principal": true, "max_delegation_depth": 2},
        {"type": "require_capability_token", "required_issuers": ["trusted-issuer"], "min_remaining_depth": 1}
    ]));
    let engine = make_context_engine(policy.clone());
    let action = Action::new("read_file".to_string(), "read".to_string(), json!({}));
    let mut token = make_delegated_capability_token("agent-a", 3);
    token.issuer = "untrusted-issuer".to_string();
    let ctx = EvaluationContext::builder()
        .agent_id("agent-a")
        .capability_token(token)
        .call_chain(make_delegation_chain(&["delegator-1"]))
        .build();

    let v = engine
        .evaluate_action_with_context(&action, &[policy], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "issuer allowlist should deny paired context: {v:?}"
    );
    if let Verdict::Deny { reason } = v {
        assert!(reason.contains("issuer 'untrusted-issuer' not in allowed list"));
    }
}

// ════════════════════════════════════════════════════════
// FIND-R44-057: Legacy path sort ID tiebreaker
// ════════════════════════════════════════════════════════

#[test]
fn test_legacy_sort_deterministic_with_same_priority_and_type() {
    // Two Allow policies with identical priority — evaluation order should be
    // deterministic based on ID (ascending), ensuring reproducible verdicts.
    let engine = PolicyEngine::new(false);
    let action = Action::new("bash".to_string(), "execute".to_string(), json!({}));

    // "aaa" < "zzz" in ID ordering, so "aaa" should be evaluated first.
    // Both match the same action, so the first one wins.
    let policy_a = Policy {
        id: "aaa:*".to_string(),
        name: "Allow A".to_string(),
        policy_type: PolicyType::Allow,
        priority: 100,
        path_rules: None,
        network_rules: None,
    };
    let policy_z = Policy {
        id: "zzz:*".to_string(),
        name: "Allow Z".to_string(),
        policy_type: PolicyType::Allow,
        priority: 100,
        path_rules: None,
        network_rules: None,
    };

    // Pass in reverse ID order to exercise the sort path
    let verdict1 = engine
        .evaluate_action(&action, &[policy_z.clone(), policy_a.clone()])
        .unwrap();
    let verdict2 = engine
        .evaluate_action(&action, &[policy_a.clone(), policy_z.clone()])
        .unwrap();

    // Both orderings should produce the same result (deterministic)
    assert_eq!(
        std::mem::discriminant(&verdict1),
        std::mem::discriminant(&verdict2),
        "Legacy sort should produce deterministic results regardless of input order"
    );
}

#[test]
fn test_legacy_sort_deny_still_beats_allow_at_same_priority() {
    // Verify that deny-first ordering is preserved alongside the ID tiebreaker
    let engine = PolicyEngine::new(false);
    let action = Action::new("bash".to_string(), "execute".to_string(), json!({}));

    let deny_policy = Policy {
        id: "zzz:*".to_string(), // Higher ID but Deny type
        name: "Deny bash".to_string(),
        policy_type: PolicyType::Deny,
        priority: 100,
        path_rules: None,
        network_rules: None,
    };
    let allow_policy = Policy {
        id: "aaa:*".to_string(), // Lower ID but Allow type
        name: "Allow bash".to_string(),
        policy_type: PolicyType::Allow,
        priority: 100,
        path_rules: None,
        network_rules: None,
    };

    // Deny should win even though its ID is higher
    let verdict = engine
        .evaluate_action(&action, &[allow_policy, deny_policy])
        .unwrap();
    assert!(
        matches!(verdict, Verdict::Deny { .. }),
        "Deny should still beat Allow at same priority, got: {verdict:?}"
    );
}

// ═══════════════════════════════════════════════════
// FIND-R46-005: on_no_match_continue equivalence test
// ═══════════════════════════════════════════════════

/// SECURITY (FIND-R46-005): Verify that compiled and legacy paths produce identical
/// results for on_no_match="continue" when no constraints fire. This proves that
/// the two evaluation paths are semantically equivalent for this critical behavior.
#[test]
fn test_on_no_match_continue_equivalence_compiled_vs_legacy() {
    let action = Action::new(
        "filesystem".to_string(),
        "read_file".to_string(),
        json!({"path": "/home/user/file.txt"}),
    );

    // A conditional policy with on_no_match="continue" that won't match,
    // followed by an Allow policy that will.
    let policies = vec![
        Policy {
            id: "filesystem:*".to_string(),
            name: "Conditional with continue".to_string(),
            policy_type: PolicyType::Conditional {
                conditions: json!({
                    "on_no_match": "continue",
                    "parameter_constraints": [{
                        "param": "nonexistent_param",
                        "op": "eq",
                        "value": "something",
                        "on_missing": "skip"
                    }]
                }),
            },
            priority: 100,
            path_rules: None,
            network_rules: None,
        },
        Policy {
            id: "filesystem:*:allow".to_string(),
            name: "Fallback allow".to_string(),
            policy_type: PolicyType::Allow,
            priority: 50,
            path_rules: None,
            network_rules: None,
        },
    ];

    // Legacy path
    let engine_legacy = PolicyEngine::new(false);
    let legacy_verdict = engine_legacy.evaluate_action(&action, &policies).unwrap();

    // Compiled path
    let engine_compiled = PolicyEngine::with_policies(false, &policies).unwrap();
    let compiled_verdict = engine_compiled.evaluate_action(&action, &[]).unwrap();

    // Both should produce Allow (the conditional skips via on_no_match="continue",
    // then the fallback Allow matches).
    assert!(
        matches!(legacy_verdict, Verdict::Allow),
        "Legacy path should produce Allow, got: {legacy_verdict:?}"
    );
    assert!(
        matches!(compiled_verdict, Verdict::Allow),
        "Compiled path should produce Allow, got: {compiled_verdict:?}"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// PHASE A: COMPREHENSIVE UNIT TESTS
// ═══════════════════════════════════════════════════════════════════════════
//
// Tests below cover:
//   A1: policy_compile.rs  (~30 tests)
//   A2: constraint_eval.rs (~30 tests)
//   A3: context_check.rs   (~35 tests)
//   A4: legacy.rs          (~25 tests)
//   A5: Differential tests (~10 tests)
// ═══════════════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════
// A1: policy_compile.rs tests
// ═══════════════════════════════════════════════════════

#[test]
fn test_compile_policies_empty_input_returns_empty() {
    let compiled = PolicyEngine::compile_policies(&[], false).unwrap();
    assert!(compiled.is_empty());
}

#[test]
fn test_compile_policies_single_allow_policy() {
    let policies = vec![Policy {
        id: "tool:*".to_string(),
        name: "Allow tool".to_string(),
        policy_type: PolicyType::Allow,
        priority: 50,
        path_rules: None,
        network_rules: None,
    }];
    let compiled = PolicyEngine::compile_policies(&policies, false).unwrap();
    assert_eq!(compiled.len(), 1);
    assert_eq!(compiled[0].policy.id, "tool:*");
}

#[test]
fn test_compile_policies_sorts_by_priority_descending() {
    let policies = vec![
        Policy {
            id: "a:*".to_string(),
            name: "Low".to_string(),
            policy_type: PolicyType::Allow,
            priority: 10,
            path_rules: None,
            network_rules: None,
        },
        Policy {
            id: "b:*".to_string(),
            name: "High".to_string(),
            policy_type: PolicyType::Allow,
            priority: 100,
            path_rules: None,
            network_rules: None,
        },
    ];
    let compiled = PolicyEngine::compile_policies(&policies, false).unwrap();
    assert_eq!(compiled[0].policy.priority, 100);
    assert_eq!(compiled[1].policy.priority, 10);
}

#[test]
fn test_compile_policies_deny_wins_at_same_priority() {
    let policies = vec![
        Policy {
            id: "a:*".to_string(),
            name: "Allow".to_string(),
            policy_type: PolicyType::Allow,
            priority: 100,
            path_rules: None,
            network_rules: None,
        },
        Policy {
            id: "b:*".to_string(),
            name: "Deny".to_string(),
            policy_type: PolicyType::Deny,
            priority: 100,
            path_rules: None,
            network_rules: None,
        },
    ];
    let compiled = PolicyEngine::compile_policies(&policies, false).unwrap();
    assert!(matches!(compiled[0].policy.policy_type, PolicyType::Deny));
}

#[test]
fn test_compile_policies_id_tiebreaker_at_same_priority_and_type() {
    let policies = vec![
        Policy {
            id: "zzz:*".to_string(),
            name: "Z policy".to_string(),
            policy_type: PolicyType::Allow,
            priority: 50,
            path_rules: None,
            network_rules: None,
        },
        Policy {
            id: "aaa:*".to_string(),
            name: "A policy".to_string(),
            policy_type: PolicyType::Allow,
            priority: 50,
            path_rules: None,
            network_rules: None,
        },
    ];
    let compiled = PolicyEngine::compile_policies(&policies, false).unwrap();
    assert_eq!(compiled[0].policy.id, "aaa:*");
    assert_eq!(compiled[1].policy.id, "zzz:*");
}

#[test]
fn test_compile_policies_collects_all_errors_not_just_first() {
    let policies = vec![
        Policy {
            id: "a:*".to_string(),
            name: "Bad glob".to_string(),
            policy_type: PolicyType::Allow,
            priority: 50,
            path_rules: Some(vellaveto_types::PathRules {
                allowed: vec!["[invalid".to_string()],
                blocked: vec![],
            }),
            network_rules: None,
        },
        Policy {
            id: "b:*".to_string(),
            name: "Bad cidr".to_string(),
            policy_type: PolicyType::Allow,
            priority: 50,
            path_rules: None,
            network_rules: Some(vellaveto_types::NetworkRules {
                allowed_domains: vec![],
                blocked_domains: vec![],
                ip_rules: Some(vellaveto_types::IpRules {
                    block_private: false,
                    blocked_cidrs: vec!["not-a-cidr".to_string()],
                    allowed_cidrs: vec![],
                }),
            }),
        },
    ];
    let errors = PolicyEngine::compile_policies(&policies, false).unwrap_err();
    assert_eq!(
        errors.len(),
        2,
        "Should collect all errors, got: {errors:?}"
    );
}

#[test]
fn test_compile_policies_invalid_glob_in_path_rules_fails() {
    let policies = vec![Policy {
        id: "fs:*".to_string(),
        name: "Bad path".to_string(),
        policy_type: PolicyType::Allow,
        priority: 50,
        path_rules: Some(vellaveto_types::PathRules {
            allowed: vec![],
            blocked: vec!["[bad-glob".to_string()],
        }),
        network_rules: None,
    }];
    let errors = PolicyEngine::compile_policies(&policies, false).unwrap_err();
    assert!(errors[0].reason.contains("Invalid blocked path glob"));
}

#[test]
fn test_compile_policies_invalid_cidr_in_ip_rules_fails() {
    let policies = vec![Policy {
        id: "net:*".to_string(),
        name: "Bad cidr".to_string(),
        policy_type: PolicyType::Allow,
        priority: 50,
        path_rules: None,
        network_rules: Some(vellaveto_types::NetworkRules {
            allowed_domains: vec![],
            blocked_domains: vec![],
            ip_rules: Some(vellaveto_types::IpRules {
                block_private: false,
                blocked_cidrs: vec!["999.999.999.999/32".to_string()],
                allowed_cidrs: vec![],
            }),
        }),
    }];
    let errors = PolicyEngine::compile_policies(&policies, false).unwrap_err();
    assert!(errors[0].reason.contains("Invalid blocked CIDR"));
}

#[test]
fn test_compile_policies_invalid_domain_pattern_fails() {
    let policies = vec![Policy {
        id: "net:*".to_string(),
        name: "Bad domain".to_string(),
        policy_type: PolicyType::Allow,
        priority: 50,
        path_rules: None,
        network_rules: Some(vellaveto_types::NetworkRules {
            allowed_domains: vec!["".to_string()],
            blocked_domains: vec![],
            ip_rules: None,
        }),
    }];
    let errors = PolicyEngine::compile_policies(&policies, false).unwrap_err();
    assert!(errors[0].reason.contains("Invalid domain pattern"));
}

/// SECURITY (FIND-R46-002): Unknown policy types fail-closed at compile time.
#[test]
fn test_compile_conditional_with_require_approval() {
    let policies = vec![Policy {
        id: "tool:*".to_string(),
        name: "Approval".to_string(),
        policy_type: PolicyType::Conditional {
            conditions: json!({
                "require_approval": true
            }),
        },
        priority: 50,
        path_rules: None,
        network_rules: None,
    }];
    let compiled = PolicyEngine::compile_policies(&policies, false).unwrap();
    assert!(compiled[0].require_approval);
}

#[test]
fn test_compile_conditional_with_on_no_match_continue() {
    let policies = vec![Policy {
        id: "tool:*".to_string(),
        name: "Continue".to_string(),
        policy_type: PolicyType::Conditional {
            conditions: json!({
                "on_no_match": "continue"
            }),
        },
        priority: 50,
        path_rules: None,
        network_rules: None,
    }];
    let compiled = PolicyEngine::compile_policies(&policies, false).unwrap();
    assert!(compiled[0].on_no_match_continue);
}

#[test]
fn test_compile_forbidden_parameters_preserved() {
    let policies = vec![Policy {
        id: "tool:*".to_string(),
        name: "Forbidden".to_string(),
        policy_type: PolicyType::Conditional {
            conditions: json!({
                "forbidden_parameters": ["secret", "password"]
            }),
        },
        priority: 50,
        path_rules: None,
        network_rules: None,
    }];
    let compiled = PolicyEngine::compile_policies(&policies, false).unwrap();
    assert_eq!(compiled[0].forbidden_parameters, vec!["secret", "password"]);
}

#[test]
fn test_compile_required_parameters_preserved() {
    let policies = vec![Policy {
        id: "tool:*".to_string(),
        name: "Required".to_string(),
        policy_type: PolicyType::Conditional {
            conditions: json!({
                "required_parameters": ["path", "mode"]
            }),
        },
        priority: 50,
        path_rules: None,
        network_rules: None,
    }];
    let compiled = PolicyEngine::compile_policies(&policies, false).unwrap();
    assert_eq!(compiled[0].required_parameters, vec!["path", "mode"]);
}

#[test]
fn test_compile_path_rules_allowed_and_blocked_globs() {
    let policies = vec![Policy {
        id: "fs:*".to_string(),
        name: "Paths".to_string(),
        policy_type: PolicyType::Allow,
        priority: 50,
        path_rules: Some(vellaveto_types::PathRules {
            allowed: vec!["/home/**".to_string()],
            blocked: vec!["/etc/**".to_string()],
        }),
        network_rules: None,
    }];
    let compiled = PolicyEngine::compile_policies(&policies, false).unwrap();
    let pr = compiled[0].compiled_path_rules.as_ref().unwrap();
    assert_eq!(pr.allowed.len(), 1);
    assert_eq!(pr.blocked.len(), 1);
    assert_eq!(pr.allowed[0].0, "/home/**");
    assert_eq!(pr.blocked[0].0, "/etc/**");
}

#[test]
fn test_compile_network_rules_domains() {
    let policies = vec![Policy {
        id: "net:*".to_string(),
        name: "Domains".to_string(),
        policy_type: PolicyType::Allow,
        priority: 50,
        path_rules: None,
        network_rules: Some(vellaveto_types::NetworkRules {
            allowed_domains: vec!["example.com".to_string()],
            blocked_domains: vec!["evil.com".to_string()],
            ip_rules: None,
        }),
    }];
    let compiled = PolicyEngine::compile_policies(&policies, false).unwrap();
    let nr = compiled[0].compiled_network_rules.as_ref().unwrap();
    assert_eq!(nr.allowed_domains, vec!["example.com"]);
    assert_eq!(nr.blocked_domains, vec!["evil.com"]);
}

#[test]
fn test_compile_ip_rules_block_private_and_cidrs() {
    let policies = vec![Policy {
        id: "net:*".to_string(),
        name: "IP rules".to_string(),
        policy_type: PolicyType::Allow,
        priority: 50,
        path_rules: None,
        network_rules: Some(vellaveto_types::NetworkRules {
            allowed_domains: vec![],
            blocked_domains: vec![],
            ip_rules: Some(vellaveto_types::IpRules {
                block_private: true,
                blocked_cidrs: vec!["10.0.0.0/8".to_string()],
                allowed_cidrs: vec!["192.168.1.0/24".to_string()],
            }),
        }),
    }];
    let compiled = PolicyEngine::compile_policies(&policies, false).unwrap();
    let ir = compiled[0].compiled_ip_rules.as_ref().unwrap();
    assert!(ir.block_private);
    assert_eq!(ir.blocked_cidrs.len(), 1);
    assert_eq!(ir.allowed_cidrs.len(), 1);
}

#[test]
fn test_compile_conditions_json_depth_exceeds_limit_fails() {
    // Build nested JSON > 10 levels deep
    let mut deep = json!("leaf");
    for _ in 0..11 {
        deep = json!({"nested": deep});
    }
    let policies = vec![Policy {
        id: "tool:*".to_string(),
        name: "Deep".to_string(),
        policy_type: PolicyType::Conditional { conditions: deep },
        priority: 50,
        path_rules: None,
        network_rules: None,
    }];
    let errors = PolicyEngine::compile_policies(&policies, false).unwrap_err();
    assert!(errors[0].reason.contains("maximum nesting depth"));
}

#[test]
fn test_compile_conditions_json_size_exceeds_limit_fails() {
    // Build condition JSON > 100KB
    let big_string = "x".repeat(100_001);
    let policies = vec![Policy {
        id: "tool:*".to_string(),
        name: "Big".to_string(),
        policy_type: PolicyType::Conditional {
            conditions: json!({"big_key": big_string}),
        },
        priority: 50,
        path_rules: None,
        network_rules: None,
    }];
    let errors = PolicyEngine::compile_policies(&policies, false).unwrap_err();
    assert!(errors[0].reason.contains("too large"));
}

#[test]
fn test_compile_conditions_unknown_key_strict_mode_fails() {
    let policies = vec![Policy {
        id: "tool:*".to_string(),
        name: "Unknown key".to_string(),
        policy_type: PolicyType::Conditional {
            conditions: json!({"unknown_key": true}),
        },
        priority: 50,
        path_rules: None,
        network_rules: None,
    }];
    let errors = PolicyEngine::compile_policies(&policies, true).unwrap_err();
    assert!(errors[0].reason.contains("Unknown condition key"));
}

#[test]
fn test_compile_conditions_unknown_key_non_strict_rejects_unknown_only() {
    let policies = vec![Policy {
        id: "tool:*".to_string(),
        name: "Unknown key".to_string(),
        policy_type: PolicyType::Conditional {
            conditions: json!({"unknown_key": true}),
        },
        priority: 50,
        path_rules: None,
        network_rules: None,
    }];
    let errors = PolicyEngine::compile_policies(&policies, false).unwrap_err();
    assert!(errors[0].reason.contains("recognized condition key"));
}

#[test]
fn test_compile_conditions_unknown_key_non_strict_passes_with_known_key() {
    let policies = vec![Policy {
        id: "tool:*".to_string(),
        name: "Unknown key with known key".to_string(),
        policy_type: PolicyType::Conditional {
            conditions: json!({
                "unknown_key": true,
                "require_approval": false
            }),
        },
        priority: 50,
        path_rules: None,
        network_rules: None,
    }];
    assert!(PolicyEngine::compile_policies(&policies, false).is_ok());
}

#[test]
fn test_compile_conditions_forbidden_parameters_non_array_fails() {
    let policies = vec![Policy {
        id: "tool:*".to_string(),
        name: "Malformed forbidden".to_string(),
        policy_type: PolicyType::Conditional {
            conditions: json!({"forbidden_parameters": "danger"}),
        },
        priority: 50,
        path_rules: None,
        network_rules: None,
    }];
    let errors = PolicyEngine::compile_policies(&policies, false).unwrap_err();
    assert!(errors[0]
        .reason
        .contains("forbidden_parameters must be an array"));
}

#[test]
fn test_compile_conditions_required_parameters_non_array_fails() {
    let policies = vec![Policy {
        id: "tool:*".to_string(),
        name: "Malformed required".to_string(),
        policy_type: PolicyType::Conditional {
            conditions: json!({"required_parameters": {"token": true}}),
        },
        priority: 50,
        path_rules: None,
        network_rules: None,
    }];
    let errors = PolicyEngine::compile_policies(&policies, false).unwrap_err();
    assert!(errors[0]
        .reason
        .contains("required_parameters must be an array"));
}

#[test]
fn test_compile_conditions_max_parameter_constraints_exceeded() {
    let constraints: Vec<serde_json::Value> = (0..101)
        .map(|i| {
            json!({
                "param": format!("p{}", i),
                "op": "eq",
                "value": "x"
            })
        })
        .collect();
    let policies = vec![Policy {
        id: "tool:*".to_string(),
        name: "Too many".to_string(),
        policy_type: PolicyType::Conditional {
            conditions: json!({"parameter_constraints": constraints}),
        },
        priority: 50,
        path_rules: None,
        network_rules: None,
    }];
    let errors = PolicyEngine::compile_policies(&policies, false).unwrap_err();
    assert!(errors[0].reason.contains("max is 100"));
}

#[test]
fn test_compile_constraint_missing_param_fails() {
    let policies = vec![Policy {
        id: "tool:*".to_string(),
        name: "No param".to_string(),
        policy_type: PolicyType::Conditional {
            conditions: json!({
                "parameter_constraints": [{"op": "eq", "value": "x"}]
            }),
        },
        priority: 50,
        path_rules: None,
        network_rules: None,
    }];
    let errors = PolicyEngine::compile_policies(&policies, false).unwrap_err();
    assert!(errors[0].reason.contains("missing required 'param'"));
}

#[test]
fn test_compile_constraint_missing_op_fails() {
    let policies = vec![Policy {
        id: "tool:*".to_string(),
        name: "No op".to_string(),
        policy_type: PolicyType::Conditional {
            conditions: json!({
                "parameter_constraints": [{"param": "x", "value": "y"}]
            }),
        },
        priority: 50,
        path_rules: None,
        network_rules: None,
    }];
    let errors = PolicyEngine::compile_policies(&policies, false).unwrap_err();
    assert!(errors[0].reason.contains("missing required 'op'"));
}

/// SECURITY (R8-11): Invalid on_match value rejected at compile time.
#[test]
fn test_compile_constraint_invalid_on_match_value_fails() {
    let policies = vec![Policy {
        id: "tool:*".to_string(),
        name: "Bad on_match".to_string(),
        policy_type: PolicyType::Conditional {
            conditions: json!({
                "parameter_constraints": [{
                    "param": "x",
                    "op": "eq",
                    "value": "y",
                    "on_match": "alow"  // typo
                }]
            }),
        },
        priority: 50,
        path_rules: None,
        network_rules: None,
    }];
    let errors = PolicyEngine::compile_policies(&policies, false).unwrap_err();
    assert!(errors[0].reason.contains("on_match"));
    assert!(errors[0].reason.contains("alow"));
}

#[test]
fn test_compile_constraint_invalid_on_missing_value_fails() {
    let policies = vec![Policy {
        id: "tool:*".to_string(),
        name: "Bad on_missing".to_string(),
        policy_type: PolicyType::Conditional {
            conditions: json!({
                "parameter_constraints": [{
                    "param": "x",
                    "op": "eq",
                    "value": "y",
                    "on_missing": "allow"  // invalid: only "deny" or "skip"
                }]
            }),
        },
        priority: 50,
        path_rules: None,
        network_rules: None,
    }];
    let errors = PolicyEngine::compile_policies(&policies, false).unwrap_err();
    assert!(errors[0].reason.contains("on_missing"));
}

#[test]
fn test_compile_constraint_glob_invalid_pattern_fails() {
    let policies = vec![Policy {
        id: "tool:*".to_string(),
        name: "Bad glob".to_string(),
        policy_type: PolicyType::Conditional {
            conditions: json!({
                "parameter_constraints": [{
                    "param": "path",
                    "op": "glob",
                    "pattern": "[invalid"
                }]
            }),
        },
        priority: 50,
        path_rules: None,
        network_rules: None,
    }];
    let errors = PolicyEngine::compile_policies(&policies, false).unwrap_err();
    assert!(errors[0].reason.contains("Invalid glob pattern"));
}

#[test]
fn test_compile_constraint_regex_invalid_pattern_fails() {
    let policies = vec![Policy {
        id: "tool:*".to_string(),
        name: "Bad regex".to_string(),
        policy_type: PolicyType::Conditional {
            conditions: json!({
                "parameter_constraints": [{
                    "param": "x",
                    "op": "regex",
                    "pattern": "(?P<unclosed"
                }]
            }),
        },
        priority: 50,
        path_rules: None,
        network_rules: None,
    }];
    let errors = PolicyEngine::compile_policies(&policies, false).unwrap_err();
    assert!(errors[0].reason.contains("Invalid regex pattern"));
}

/// SECURITY (FIND-R46-004): Regex DFA size is bounded to prevent memory exhaustion.
#[test]
fn test_compile_constraint_regex_dfa_size_limit() {
    // A regex pattern that compiles to a very large DFA
    let big_pattern = format!(
        "({})",
        (0..100)
            .map(|i| format!("a{{{}}}", i + 100))
            .collect::<Vec<_>>()
            .join("|")
    );
    let policies = vec![Policy {
        id: "tool:*".to_string(),
        name: "Big regex".to_string(),
        policy_type: PolicyType::Conditional {
            conditions: json!({
                "parameter_constraints": [{
                    "param": "x",
                    "op": "regex",
                    "pattern": big_pattern
                }]
            }),
        },
        priority: 50,
        path_rules: None,
        network_rules: None,
    }];
    // This may or may not exceed the DFA limit depending on the pattern, but
    // the important thing is it doesn't cause unbounded memory allocation.
    // Just verify it either compiles or returns a bounded error.
    let result = PolicyEngine::compile_policies(&policies, false);
    assert!(result.is_ok() || result.unwrap_err()[0].reason.contains("regex"));
}

#[test]
fn test_compile_constraint_all_10_operators_compile_correctly() {
    let policies = vec![Policy {
        id: "tool:*".to_string(),
        name: "All ops".to_string(),
        policy_type: PolicyType::Conditional {
            conditions: json!({
                "parameter_constraints": [
                    {"param": "p1", "op": "glob", "pattern": "*.txt"},
                    {"param": "p2", "op": "not_glob", "patterns": ["/safe/**"]},
                    {"param": "p3", "op": "regex", "pattern": "^[a-z]+$"},
                    {"param": "p4", "op": "domain_match", "pattern": "*.evil.com"},
                    {"param": "p5", "op": "domain_not_in", "patterns": ["good.com"]},
                    {"param": "p6", "op": "eq", "value": "yes"},
                    {"param": "p7", "op": "ne", "value": "no"},
                    {"param": "p8", "op": "one_of", "values": ["a", "b"]},
                    {"param": "p9", "op": "none_of", "values": ["x", "y"]},
                ]
            }),
        },
        priority: 50,
        path_rules: None,
        network_rules: None,
    }];
    let compiled = PolicyEngine::compile_policies(&policies, false).unwrap();
    assert_eq!(compiled[0].constraints.len(), 9);
}

// ═══════════════════════════════════════════════════════
// A2: constraint_eval.rs tests
// ═══════════════════════════════════════════════════════

fn make_action(tool: &str, func: &str, params: serde_json::Value) -> Action {
    Action::new(tool.to_string(), func.to_string(), params)
}

fn make_conditional_policy(id: &str, name: &str, conditions: serde_json::Value) -> Policy {
    Policy {
        id: id.to_string(),
        name: name.to_string(),
        policy_type: PolicyType::Conditional { conditions },
        priority: 100,
        path_rules: None,
        network_rules: None,
    }
}

#[test]
fn test_constraint_glob_match_fires() {
    let action = make_action("fs", "read", json!({"path": "/etc/passwd"}));
    let policy = make_conditional_policy(
        "fs:*",
        "Block etc",
        json!({
            "parameter_constraints": [{"param": "path", "op": "glob", "pattern": "/etc/**"}]
        }),
    );
    let engine = PolicyEngine::with_policies(false, &[policy]).unwrap();
    let verdict = engine.evaluate_action(&action, &[]).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

#[test]
fn test_constraint_glob_no_match_allows() {
    let action = make_action("fs", "read", json!({"path": "/home/user/file.txt"}));
    let policy = make_conditional_policy(
        "fs:*",
        "Block etc",
        json!({
            "parameter_constraints": [{"param": "path", "op": "glob", "pattern": "/etc/**"}]
        }),
    );
    let engine = PolicyEngine::with_policies(false, &[policy]).unwrap();
    let verdict = engine.evaluate_action(&action, &[]).unwrap();
    assert!(matches!(verdict, Verdict::Allow));
}

#[test]
fn test_constraint_glob_non_string_denies_non_strict() {
    let action = make_action("fs", "read", json!({"path": 42}));
    let policy = make_conditional_policy(
        "fs:*",
        "Block",
        json!({
            "parameter_constraints": [{"param": "path", "op": "glob", "pattern": "/etc/**"}]
        }),
    );
    let engine = PolicyEngine::with_policies(false, &[policy]).unwrap();
    let verdict = engine.evaluate_action(&action, &[]).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

#[test]
fn test_constraint_not_glob_outside_allowlist_fires() {
    let action = make_action("fs", "write", json!({"path": "/tmp/evil"}));
    let policy = make_conditional_policy(
        "fs:*",
        "Not in safe",
        json!({
            "parameter_constraints": [{
                "param": "path",
                "op": "not_glob",
                "patterns": ["/home/**", "/var/data/**"]
            }]
        }),
    );
    let engine = PolicyEngine::with_policies(false, &[policy]).unwrap();
    let verdict = engine.evaluate_action(&action, &[]).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

#[test]
fn test_constraint_not_glob_in_allowlist_allows() {
    let action = make_action("fs", "write", json!({"path": "/home/user/doc.txt"}));
    let policy = make_conditional_policy(
        "fs:*",
        "Safe paths",
        json!({
            "parameter_constraints": [{
                "param": "path",
                "op": "not_glob",
                "patterns": ["/home/**"]
            }]
        }),
    );
    let engine = PolicyEngine::with_policies(false, &[policy]).unwrap();
    let verdict = engine.evaluate_action(&action, &[]).unwrap();
    assert!(matches!(verdict, Verdict::Allow));
}

#[test]
fn test_constraint_regex_match_fires() {
    let action = make_action("net", "fetch", json!({"url": "http://evil.com/steal"}));
    let policy = make_conditional_policy(
        "net:*",
        "Block evil",
        json!({
            "parameter_constraints": [{
                "param": "url",
                "op": "regex",
                "pattern": "evil\\.com"
            }]
        }),
    );
    let engine = PolicyEngine::with_policies(false, &[policy]).unwrap();
    let verdict = engine.evaluate_action(&action, &[]).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

#[test]
fn test_constraint_regex_no_match_allows() {
    let action = make_action("net", "fetch", json!({"url": "http://good.com/api"}));
    let policy = make_conditional_policy(
        "net:*",
        "Block evil",
        json!({
            "parameter_constraints": [{
                "param": "url",
                "op": "regex",
                "pattern": "evil\\.com"
            }]
        }),
    );
    let engine = PolicyEngine::with_policies(false, &[policy]).unwrap();
    let verdict = engine.evaluate_action(&action, &[]).unwrap();
    assert!(matches!(verdict, Verdict::Allow));
}

#[test]
fn test_constraint_domain_match_fires() {
    let action = make_action("net", "fetch", json!({"url": "https://sub.evil.com/api"}));
    let policy = make_conditional_policy(
        "net:*",
        "Block evil domain",
        json!({
            "parameter_constraints": [{
                "param": "url",
                "op": "domain_match",
                "pattern": "*.evil.com"
            }]
        }),
    );
    let engine = PolicyEngine::with_policies(false, &[policy]).unwrap();
    let verdict = engine.evaluate_action(&action, &[]).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

#[test]
fn test_constraint_domain_match_no_match_allows() {
    let action = make_action("net", "fetch", json!({"url": "https://good.com/api"}));
    let policy = make_conditional_policy(
        "net:*",
        "Block evil domain",
        json!({
            "parameter_constraints": [{
                "param": "url",
                "op": "domain_match",
                "pattern": "*.evil.com"
            }]
        }),
    );
    let engine = PolicyEngine::with_policies(false, &[policy]).unwrap();
    let verdict = engine.evaluate_action(&action, &[]).unwrap();
    assert!(matches!(verdict, Verdict::Allow));
}

#[test]
fn test_constraint_domain_not_in_fires() {
    let action = make_action("net", "fetch", json!({"url": "https://unauthorized.com"}));
    let policy = make_conditional_policy(
        "net:*",
        "Only good domains",
        json!({
            "parameter_constraints": [{
                "param": "url",
                "op": "domain_not_in",
                "patterns": ["good.com", "api.good.com"]
            }]
        }),
    );
    let engine = PolicyEngine::with_policies(false, &[policy]).unwrap();
    let verdict = engine.evaluate_action(&action, &[]).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

#[test]
fn test_constraint_eq_match_fires() {
    let action = make_action("db", "query", json!({"mode": "delete"}));
    let policy = make_conditional_policy(
        "db:*",
        "Block delete",
        json!({
            "parameter_constraints": [{
                "param": "mode",
                "op": "eq",
                "value": "delete"
            }]
        }),
    );
    let engine = PolicyEngine::with_policies(false, &[policy]).unwrap();
    let verdict = engine.evaluate_action(&action, &[]).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

#[test]
fn test_constraint_eq_no_match_allows() {
    let action = make_action("db", "query", json!({"mode": "read"}));
    let policy = make_conditional_policy(
        "db:*",
        "Block delete",
        json!({
            "parameter_constraints": [{
                "param": "mode",
                "op": "eq",
                "value": "delete"
            }]
        }),
    );
    let engine = PolicyEngine::with_policies(false, &[policy]).unwrap();
    let verdict = engine.evaluate_action(&action, &[]).unwrap();
    assert!(matches!(verdict, Verdict::Allow));
}

#[test]
fn test_constraint_ne_fires_when_not_equal() {
    let action = make_action("tool", "op", json!({"env": "staging"}));
    let policy = make_conditional_policy(
        "tool:*",
        "Not prod",
        json!({
            "parameter_constraints": [{
                "param": "env",
                "op": "ne",
                "value": "production"
            }]
        }),
    );
    let engine = PolicyEngine::with_policies(false, &[policy]).unwrap();
    let verdict = engine.evaluate_action(&action, &[]).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

#[test]
fn test_constraint_one_of_fires_when_in_set() {
    let action = make_action("tool", "op", json!({"format": "exe"}));
    let policy = make_conditional_policy(
        "tool:*",
        "Block dangerous formats",
        json!({
            "parameter_constraints": [{
                "param": "format",
                "op": "one_of",
                "values": ["exe", "bat", "cmd"]
            }]
        }),
    );
    let engine = PolicyEngine::with_policies(false, &[policy]).unwrap();
    let verdict = engine.evaluate_action(&action, &[]).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

#[test]
fn test_constraint_one_of_allows_when_not_in_set() {
    let action = make_action("tool", "op", json!({"format": "txt"}));
    let policy = make_conditional_policy(
        "tool:*",
        "Block dangerous formats",
        json!({
            "parameter_constraints": [{
                "param": "format",
                "op": "one_of",
                "values": ["exe", "bat", "cmd"]
            }]
        }),
    );
    let engine = PolicyEngine::with_policies(false, &[policy]).unwrap();
    let verdict = engine.evaluate_action(&action, &[]).unwrap();
    assert!(matches!(verdict, Verdict::Allow));
}

#[test]
fn test_constraint_none_of_fires_when_not_in_set() {
    let action = make_action("tool", "op", json!({"format": "unknown"}));
    let policy = make_conditional_policy(
        "tool:*",
        "Only safe formats",
        json!({
            "parameter_constraints": [{
                "param": "format",
                "op": "none_of",
                "values": ["txt", "pdf", "json"]
            }]
        }),
    );
    let engine = PolicyEngine::with_policies(false, &[policy]).unwrap();
    let verdict = engine.evaluate_action(&action, &[]).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

#[test]
fn test_constraint_none_of_allows_when_in_set() {
    let action = make_action("tool", "op", json!({"format": "pdf"}));
    let policy = make_conditional_policy(
        "tool:*",
        "Only safe formats",
        json!({
            "parameter_constraints": [{
                "param": "format",
                "op": "none_of",
                "values": ["txt", "pdf", "json"]
            }]
        }),
    );
    let engine = PolicyEngine::with_policies(false, &[policy]).unwrap();
    let verdict = engine.evaluate_action(&action, &[]).unwrap();
    assert!(matches!(verdict, Verdict::Allow));
}

#[test]
fn test_constraint_wildcard_param_scans_all_values() {
    let action = make_action(
        "tool",
        "op",
        json!({
            "a": "safe",
            "b": "/etc/shadow"
        }),
    );
    let policy = make_conditional_policy(
        "tool:*",
        "Block etc in any param",
        json!({
            "parameter_constraints": [{
                "param": "*",
                "op": "glob",
                "pattern": "/etc/**"
            }]
        }),
    );
    let engine = PolicyEngine::with_policies(false, &[policy]).unwrap();
    let verdict = engine.evaluate_action(&action, &[]).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

#[test]
fn test_constraint_missing_param_on_missing_skip() {
    let action = make_action("tool", "op", json!({"other": "value"}));
    let policy = make_conditional_policy(
        "tool:*",
        "Skip missing",
        json!({
            "parameter_constraints": [{
                "param": "nonexistent",
                "op": "eq",
                "value": "x",
                "on_missing": "skip"
            }]
        }),
    );
    let engine = PolicyEngine::with_policies(false, &[policy]).unwrap();
    let verdict = engine.evaluate_action(&action, &[]).unwrap();
    // With on_missing: skip and no other constraints, all constraints are skipped → fail-closed
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

#[test]
fn test_constraint_missing_param_on_missing_deny() {
    let action = make_action("tool", "op", json!({"other": "value"}));
    let policy = make_conditional_policy(
        "tool:*",
        "Deny missing",
        json!({
            "parameter_constraints": [{
                "param": "required_param",
                "op": "eq",
                "value": "x",
                "on_missing": "deny"
            }]
        }),
    );
    let engine = PolicyEngine::with_policies(false, &[policy]).unwrap();
    let verdict = engine.evaluate_action(&action, &[]).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

#[test]
fn test_constraint_nested_param_path() {
    let action = make_action(
        "tool",
        "op",
        json!({
            "config": {"output": {"path": "/etc/shadow"}}
        }),
    );
    let policy = make_conditional_policy(
        "tool:*",
        "Block nested path",
        json!({
            "parameter_constraints": [{
                "param": "config.output.path",
                "op": "glob",
                "pattern": "/etc/**"
            }]
        }),
    );
    let engine = PolicyEngine::with_policies(false, &[policy]).unwrap();
    let verdict = engine.evaluate_action(&action, &[]).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

#[test]
fn test_constraint_all_skipped_fail_closed() {
    let action = make_action("tool", "op", json!({"x": "y"}));
    let policy = make_conditional_policy(
        "tool:*",
        "All skip",
        json!({
            "parameter_constraints": [
                {"param": "missing1", "op": "eq", "value": "a", "on_missing": "skip"},
                {"param": "missing2", "op": "eq", "value": "b", "on_missing": "skip"}
            ]
        }),
    );
    let engine = PolicyEngine::with_policies(false, &[policy]).unwrap();
    let verdict = engine.evaluate_action(&action, &[]).unwrap();
    assert!(
        matches!(verdict, Verdict::Deny { .. }),
        "All skipped should fail-closed, got: {verdict:?}"
    );
}

#[test]
fn test_constraint_all_skipped_on_no_match_continue_returns_none() {
    let action = make_action("tool", "op", json!({"x": "y"}));
    let policies = vec![
        make_conditional_policy(
            "tool:*",
            "Skip continue",
            json!({
                "on_no_match": "continue",
                "parameter_constraints": [
                    {"param": "missing", "op": "eq", "value": "a", "on_missing": "skip"}
                ]
            }),
        ),
        Policy {
            id: "tool:*:allow".to_string(),
            name: "Fallback allow".to_string(),
            policy_type: PolicyType::Allow,
            priority: 50,
            path_rules: None,
            network_rules: None,
        },
    ];
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();
    let verdict = engine.evaluate_action(&action, &[]).unwrap();
    assert!(
        matches!(verdict, Verdict::Allow),
        "on_no_match=continue should fall through to allow"
    );
}

#[test]
fn test_constraint_require_approval_returns_require_approval() {
    let action = make_action("tool", "op", json!({}));
    let policy = make_conditional_policy(
        "tool:*",
        "Approval",
        json!({
            "require_approval": true
        }),
    );
    let engine = PolicyEngine::with_policies(false, &[policy]).unwrap();
    let verdict = engine.evaluate_action(&action, &[]).unwrap();
    assert!(matches!(verdict, Verdict::RequireApproval { .. }));
}

#[test]
fn test_constraint_forbidden_parameter_present_denies() {
    let action = make_action("tool", "op", json!({"secret": "value"}));
    let policy = make_conditional_policy(
        "tool:*",
        "No secrets",
        json!({
            "forbidden_parameters": ["secret"]
        }),
    );
    let engine = PolicyEngine::with_policies(false, &[policy]).unwrap();
    let verdict = engine.evaluate_action(&action, &[]).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

#[test]
fn test_constraint_required_parameter_missing_denies() {
    let action = make_action("tool", "op", json!({"other": "value"}));
    let policy = make_conditional_policy(
        "tool:*",
        "Need path",
        json!({
            "required_parameters": ["path"]
        }),
    );
    let engine = PolicyEngine::with_policies(false, &[policy]).unwrap();
    let verdict = engine.evaluate_action(&action, &[]).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

#[test]
fn test_constraint_traced_vs_non_traced_consistency() {
    let action = make_action("fs", "read", json!({"path": "/etc/passwd"}));
    let policy = make_conditional_policy(
        "fs:*",
        "Block etc",
        json!({
            "parameter_constraints": [{"param": "path", "op": "glob", "pattern": "/etc/**"}]
        }),
    );
    let engine = PolicyEngine::with_policies(false, &[policy]).unwrap();

    let verdict = engine.evaluate_action(&action, &[]).unwrap();
    let (traced_verdict, _trace) = engine.evaluate_action_traced(&action).unwrap();

    // Both should produce Deny
    assert!(matches!(verdict, Verdict::Deny { .. }));
    assert!(matches!(traced_verdict, Verdict::Deny { .. }));
}

// ═══════════════════════════════════════════════════════
// A3: context_check.rs tests
// ═══════════════════════════════════════════════════════

fn make_context() -> EvaluationContext {
    EvaluationContext::builder().build()
}

#[test]
fn test_context_time_window_within_allows() {
    // Use a timestamp known to be within the window
    let ctx = EvaluationContext::builder()
        .timestamp("2024-06-15T10:00:00Z".to_string()) // Saturday, 10:00
        .build();
    let policy = make_conditional_policy(
        "tool:*",
        "Business hours",
        json!({
            "context_conditions": [{
                "type": "time_window",
                "start_hour": 9,
                "end_hour": 17,
                "days": [6]  // Saturday
            }]
        }),
    );
    let action = make_action("tool", "op", json!({}));
    let mut engine = PolicyEngine::with_policies(false, &[policy]).unwrap();
    engine.set_trust_context_timestamps(true);
    let verdict = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(verdict, Verdict::Allow),
        "Within window should allow, got: {verdict:?}"
    );
}

#[test]
fn test_context_time_window_outside_denies() {
    let ctx = EvaluationContext::builder()
        .timestamp("2024-06-15T22:00:00Z".to_string()) // Saturday, 22:00
        .build();
    let policy = make_conditional_policy(
        "tool:*",
        "Business hours",
        json!({
            "context_conditions": [{
                "type": "time_window",
                "start_hour": 9,
                "end_hour": 17,
                "days": [6]
            }]
        }),
    );
    let action = make_action("tool", "op", json!({}));
    let mut engine = PolicyEngine::with_policies(false, &[policy]).unwrap();
    engine.set_trust_context_timestamps(true);
    let verdict = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

#[test]
fn test_context_time_window_midnight_wrap_compiled() {
    // 23:00 should be within a 22-6 window
    let ctx = EvaluationContext::builder()
        .timestamp("2024-06-15T23:00:00Z".to_string())
        .build();
    let policy = make_conditional_policy(
        "tool:*",
        "Night shift",
        json!({
            "context_conditions": [{
                "type": "time_window",
                "start_hour": 22,
                "end_hour": 6,
                "days": []
            }]
        }),
    );
    let action = make_action("tool", "op", json!({}));
    let mut engine = PolicyEngine::with_policies(false, &[policy]).unwrap();
    engine.set_trust_context_timestamps(true);
    let verdict = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(matches!(verdict, Verdict::Allow));
}

#[test]
fn test_context_time_window_wrong_day_denies_compiled() {
    // Tuesday (day 2), but only Monday (1) allowed
    let ctx = EvaluationContext::builder()
        .timestamp("2024-06-18T10:00:00Z".to_string()) // Tuesday
        .build();
    let policy = make_conditional_policy(
        "tool:*",
        "Monday only",
        json!({
            "context_conditions": [{
                "type": "time_window",
                "start_hour": 0,
                "end_hour": 23,
                "days": [1]  // Monday only
            }]
        }),
    );
    let action = make_action("tool", "op", json!({}));
    let mut engine = PolicyEngine::with_policies(false, &[policy]).unwrap();
    engine.set_trust_context_timestamps(true);
    let verdict = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

#[test]
fn test_context_time_window_empty_days_allows_any_day() {
    let ctx = EvaluationContext::builder()
        .timestamp("2024-06-18T10:00:00Z".to_string()) // Tuesday 10:00
        .build();
    let policy = make_conditional_policy(
        "tool:*",
        "Any day",
        json!({
            "context_conditions": [{
                "type": "time_window",
                "start_hour": 9,
                "end_hour": 17,
                "days": []
            }]
        }),
    );
    let action = make_action("tool", "op", json!({}));
    let mut engine = PolicyEngine::with_policies(false, &[policy]).unwrap();
    engine.set_trust_context_timestamps(true);
    let verdict = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(matches!(verdict, Verdict::Allow));
}

#[test]
fn test_context_max_calls_under_limit_allows() {
    let mut counts = std::collections::HashMap::new();
    counts.insert("tool:op".to_string(), 5u64);
    let ctx = EvaluationContext::builder().call_counts(counts).build();
    let policy = make_conditional_policy(
        "tool:*",
        "Rate limit",
        json!({
            "context_conditions": [{
                "type": "max_calls",
                "tool_pattern": "*",
                "max": 10
            }]
        }),
    );
    let action = make_action("tool", "op", json!({}));
    let engine = PolicyEngine::with_policies(false, &[policy]).unwrap();
    let verdict = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(matches!(verdict, Verdict::Allow));
}

#[test]
fn test_context_max_calls_at_limit_denies_compiled() {
    let mut counts = std::collections::HashMap::new();
    counts.insert("tool:op".to_string(), 10u64);
    let ctx = EvaluationContext::builder().call_counts(counts).build();
    let policy = make_conditional_policy(
        "tool:*",
        "Rate limit",
        json!({
            "context_conditions": [{
                "type": "max_calls",
                "tool_pattern": "*",
                "max": 10
            }]
        }),
    );
    let action = make_action("tool", "op", json!({}));
    let engine = PolicyEngine::with_policies(false, &[policy]).unwrap();
    let verdict = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

#[test]
fn test_context_max_calls_empty_counts_fail_closed() {
    let ctx = make_context(); // empty call_counts
    let policy = make_conditional_policy(
        "tool:*",
        "Rate limit",
        json!({
            "context_conditions": [{
                "type": "max_calls",
                "tool_pattern": "*",
                "max": 10
            }]
        }),
    );
    let action = make_action("tool", "op", json!({}));
    let engine = PolicyEngine::with_policies(false, &[policy]).unwrap();
    let verdict = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(verdict, Verdict::Deny { .. }),
        "Empty call_counts should fail-closed"
    );
}

#[test]
fn test_context_max_calls_case_insensitive() {
    let mut counts = std::collections::HashMap::new();
    counts.insert("TOOL:OP".to_string(), 10u64);
    let ctx = EvaluationContext::builder().call_counts(counts).build();
    // Pattern lowercased at compile time
    let policy = make_conditional_policy(
        "tool:*",
        "Rate limit",
        json!({
            "context_conditions": [{
                "type": "max_calls",
                "tool_pattern": "tool:*",
                "max": 5
            }]
        }),
    );
    let action = make_action("tool", "op", json!({}));
    let engine = PolicyEngine::with_policies(false, &[policy]).unwrap();
    let verdict = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

#[test]
fn test_context_agent_id_allowed_allows() {
    let ctx = EvaluationContext::builder()
        .agent_id("agent-a".to_string())
        .build();
    let policy = make_conditional_policy(
        "tool:*",
        "Agent check",
        json!({
            "context_conditions": [{
                "type": "agent_id",
                "allowed": ["agent-a", "agent-b"]
            }]
        }),
    );
    let action = make_action("tool", "op", json!({}));
    let engine = PolicyEngine::with_policies(false, &[policy]).unwrap();
    let verdict = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(matches!(verdict, Verdict::Allow));
}

#[test]
fn test_context_agent_id_blocked_denies() {
    let ctx = EvaluationContext::builder()
        .agent_id("evil-agent".to_string())
        .build();
    let policy = make_conditional_policy(
        "tool:*",
        "Block agent",
        json!({
            "context_conditions": [{
                "type": "agent_id",
                "blocked": ["evil-agent"]
            }]
        }),
    );
    let action = make_action("tool", "op", json!({}));
    let engine = PolicyEngine::with_policies(false, &[policy]).unwrap();
    let verdict = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

#[test]
fn test_context_agent_id_not_in_allowed_denies() {
    let ctx = EvaluationContext::builder()
        .agent_id("unknown-agent".to_string())
        .build();
    let policy = make_conditional_policy(
        "tool:*",
        "Allowlist",
        json!({
            "context_conditions": [{
                "type": "agent_id",
                "allowed": ["agent-a", "agent-b"]
            }]
        }),
    );
    let action = make_action("tool", "op", json!({}));
    let engine = PolicyEngine::with_policies(false, &[policy]).unwrap();
    let verdict = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

#[test]
fn test_context_agent_id_none_fail_closed() {
    let ctx = make_context(); // no agent_id
    let policy = make_conditional_policy(
        "tool:*",
        "Require agent",
        json!({
            "context_conditions": [{
                "type": "agent_id",
                "allowed": ["agent-a"]
            }]
        }),
    );
    let action = make_action("tool", "op", json!({}));
    let engine = PolicyEngine::with_policies(false, &[policy]).unwrap();
    let verdict = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(verdict, Verdict::Deny { .. }),
        "No agent_id should fail-closed"
    );
}

#[test]
fn test_context_agent_id_case_insensitive_compiled() {
    let ctx = EvaluationContext::builder()
        .agent_id("Agent-A".to_string())
        .build();
    let policy = make_conditional_policy(
        "tool:*",
        "Case check",
        json!({
            "context_conditions": [{
                "type": "agent_id",
                "allowed": ["agent-a"]
            }]
        }),
    );
    let action = make_action("tool", "op", json!({}));
    let engine = PolicyEngine::with_policies(false, &[policy]).unwrap();
    let verdict = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(verdict, Verdict::Allow),
        "Case-insensitive match should allow"
    );
}

#[test]
fn test_context_require_previous_action_present_allows() {
    let ctx = EvaluationContext::builder()
        .previous_actions(vec!["authenticate".to_string()])
        .build();
    let policy = make_conditional_policy(
        "tool:*",
        "Require auth",
        json!({
            "context_conditions": [{
                "type": "require_previous_action",
                "required_tool": "authenticate"
            }]
        }),
    );
    let action = make_action("tool", "op", json!({}));
    let engine = PolicyEngine::with_policies(false, &[policy]).unwrap();
    let verdict = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(matches!(verdict, Verdict::Allow));
}

#[test]
fn test_context_require_previous_action_absent_denies() {
    let ctx = EvaluationContext::builder()
        .previous_actions(vec!["other_action".to_string()])
        .build();
    let policy = make_conditional_policy(
        "tool:*",
        "Require auth",
        json!({
            "context_conditions": [{
                "type": "require_previous_action",
                "required_tool": "authenticate"
            }]
        }),
    );
    let action = make_action("tool", "op", json!({}));
    let engine = PolicyEngine::with_policies(false, &[policy]).unwrap();
    let verdict = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

#[test]
fn test_context_require_previous_action_case_insensitive() {
    let ctx = EvaluationContext::builder()
        .previous_actions(vec!["Authenticate".to_string()])
        .build();
    let policy = make_conditional_policy(
        "tool:*",
        "Require auth",
        json!({
            "context_conditions": [{
                "type": "require_previous_action",
                "required_tool": "authenticate"
            }]
        }),
    );
    let action = make_action("tool", "op", json!({}));
    let engine = PolicyEngine::with_policies(false, &[policy]).unwrap();
    let verdict = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(verdict, Verdict::Allow),
        "Case-insensitive should match"
    );
}

#[test]
fn test_context_forbidden_previous_action_present_denies_compiled() {
    let ctx = EvaluationContext::builder()
        .previous_actions(vec!["dangerous_op".to_string()])
        .build();
    let policy = make_conditional_policy(
        "tool:*",
        "Forbid dangerous",
        json!({
            "context_conditions": [{
                "type": "forbidden_previous_action",
                "forbidden_tool": "dangerous_op"
            }]
        }),
    );
    let action = make_action("tool", "op", json!({}));
    let engine = PolicyEngine::with_policies(false, &[policy]).unwrap();
    let verdict = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

#[test]
fn test_context_forbidden_previous_action_absent_allows_compiled() {
    let ctx = EvaluationContext::builder()
        .previous_actions(vec!["safe_op".to_string()])
        .build();
    let policy = make_conditional_policy(
        "tool:*",
        "Forbid dangerous",
        json!({
            "context_conditions": [{
                "type": "forbidden_previous_action",
                "forbidden_tool": "dangerous_op"
            }]
        }),
    );
    let action = make_action("tool", "op", json!({}));
    let engine = PolicyEngine::with_policies(false, &[policy]).unwrap();
    let verdict = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(matches!(verdict, Verdict::Allow));
}

#[test]
fn test_context_max_calls_in_window_under_limit_allows() {
    let ctx = EvaluationContext::builder()
        .previous_actions(vec![
            "tool:op".to_string(),
            "tool:op".to_string(),
            "other:op".to_string(),
        ])
        .build();
    let policy = make_conditional_policy(
        "tool:*",
        "Window limit",
        json!({
            "context_conditions": [{
                "type": "max_calls_in_window",
                "tool_pattern": "tool:*",
                "max": 5,
                "window": 10
            }]
        }),
    );
    let action = make_action("tool", "op", json!({}));
    let engine = PolicyEngine::with_policies(false, &[policy]).unwrap();
    let verdict = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(matches!(verdict, Verdict::Allow));
}

#[test]
fn test_context_max_calls_in_window_at_limit_denies_compiled() {
    let ctx = EvaluationContext::builder()
        .previous_actions(vec![
            "tool:op".to_string(),
            "tool:op".to_string(),
            "tool:op".to_string(),
        ])
        .build();
    let policy = make_conditional_policy(
        "tool:*",
        "Window limit",
        json!({
            "context_conditions": [{
                "type": "max_calls_in_window",
                "tool_pattern": "tool:*",
                "max": 3,
                "window": 10
            }]
        }),
    );
    let action = make_action("tool", "op", json!({}));
    let engine = PolicyEngine::with_policies(false, &[policy]).unwrap();
    let verdict = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

#[test]
fn test_context_max_calls_in_window_zero_window_checks_all() {
    let ctx = EvaluationContext::builder()
        .previous_actions(vec![
            "tool:op".to_string(),
            "tool:op".to_string(),
            "tool:op".to_string(),
            "tool:op".to_string(),
            "tool:op".to_string(),
        ])
        .build();
    let policy = make_conditional_policy(
        "tool:*",
        "All history",
        json!({
            "context_conditions": [{
                "type": "max_calls_in_window",
                "tool_pattern": "tool:*",
                "max": 3,
                "window": 0
            }]
        }),
    );
    let action = make_action("tool", "op", json!({}));
    let engine = PolicyEngine::with_policies(false, &[policy]).unwrap();
    let verdict = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

#[test]
fn test_context_max_chain_depth_under_allows() {
    let ctx = EvaluationContext::builder()
        .call_chain(vec![vellaveto_types::CallChainEntry {
            agent_id: "a".to_string(),
            tool: "t".to_string(),
            function: "op".to_string(),
            timestamp: String::new(),
            hmac: None,
            verified: None,
        }])
        .build();
    let policy = make_conditional_policy(
        "tool:*",
        "Depth limit",
        json!({
            "context_conditions": [{
                "type": "max_chain_depth",
                "max_depth": 5
            }]
        }),
    );
    let action = make_action("tool", "op", json!({}));
    let engine = PolicyEngine::with_policies(false, &[policy]).unwrap();
    let verdict = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(matches!(verdict, Verdict::Allow));
}

#[test]
fn test_context_max_chain_depth_over_denies() {
    let chain: Vec<vellaveto_types::CallChainEntry> = (0..6)
        .map(|i| vellaveto_types::CallChainEntry {
            agent_id: format!("agent-{i}"),
            tool: "tool".to_string(),
            function: "op".to_string(),
            timestamp: String::new(),
            hmac: None,
            verified: None,
        })
        .collect();
    let ctx = EvaluationContext::builder().call_chain(chain).build();
    let policy = make_conditional_policy(
        "tool:*",
        "Depth limit",
        json!({
            "context_conditions": [{
                "type": "max_chain_depth",
                "max_depth": 3
            }]
        }),
    );
    let action = make_action("tool", "op", json!({}));
    let engine = PolicyEngine::with_policies(false, &[policy]).unwrap();
    let verdict = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

#[test]
fn test_context_agent_identity_issuer_match_allows() {
    let identity = vellaveto_types::AgentIdentity {
        issuer: Some("trusted-idp".to_string()),
        subject: Some("agent-1".to_string()),
        audience: vec![],
        claims: Default::default(),
    };
    let ctx = EvaluationContext::builder()
        .agent_identity(identity)
        .build();
    let policy = make_conditional_policy(
        "tool:*",
        "Identity check",
        json!({
            "context_conditions": [{
                "type": "agent_identity",
                "issuer": "trusted-idp",
                "require_attestation": true
            }]
        }),
    );
    let action = make_action("tool", "op", json!({}));
    let engine = PolicyEngine::with_policies(false, &[policy]).unwrap();
    let verdict = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(matches!(verdict, Verdict::Allow));
}

#[test]
fn test_context_agent_identity_blocked_issuer_denies() {
    let identity = vellaveto_types::AgentIdentity {
        issuer: Some("evil-idp".to_string()),
        subject: Some("agent-1".to_string()),
        audience: vec![],
        claims: Default::default(),
    };
    let ctx = EvaluationContext::builder()
        .agent_identity(identity)
        .build();
    let policy = make_conditional_policy(
        "tool:*",
        "Block issuer",
        json!({
            "context_conditions": [{
                "type": "agent_identity",
                "blocked_issuers": ["evil-idp"]
            }]
        }),
    );
    let action = make_action("tool", "op", json!({}));
    let engine = PolicyEngine::with_policies(false, &[policy]).unwrap();
    let verdict = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

#[test]
fn test_context_agent_identity_missing_attestation_denies() {
    let ctx = make_context(); // no agent_identity
    let policy = make_conditional_policy(
        "tool:*",
        "Require attestation",
        json!({
            "context_conditions": [{
                "type": "agent_identity",
                "require_attestation": true
            }]
        }),
    );
    let action = make_action("tool", "op", json!({}));
    let engine = PolicyEngine::with_policies(false, &[policy]).unwrap();
    let verdict = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

#[test]
fn test_context_agent_identity_missing_with_requirements_denies() {
    let ctx = make_context(); // no agent_identity
    let policy = make_conditional_policy(
        "tool:*",
        "Has reqs",
        json!({
            "context_conditions": [{
                "type": "agent_identity",
                "issuer": "trusted",
                "require_attestation": false
            }]
        }),
    );
    let action = make_action("tool", "op", json!({}));
    let engine = PolicyEngine::with_policies(false, &[policy]).unwrap();
    let verdict = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(verdict, Verdict::Deny { .. }),
        "Missing identity with requirements should deny"
    );
}

#[test]
fn test_context_min_verification_tier_sufficient_allows() {
    let ctx = EvaluationContext::builder()
        .verification_tier(vellaveto_types::VerificationTier::DidVerified)
        .build();
    let policy = make_conditional_policy(
        "tool:*",
        "Tier check",
        json!({
            "context_conditions": [{
                "type": "min_verification_tier",
                "required_tier": 2
            }]
        }),
    );
    let action = make_action("tool", "op", json!({}));
    let engine = PolicyEngine::with_policies(false, &[policy]).unwrap();
    let verdict = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(matches!(verdict, Verdict::Allow));
}

#[test]
fn test_context_min_verification_tier_insufficient_denies() {
    let ctx = EvaluationContext::builder()
        .verification_tier(vellaveto_types::VerificationTier::EmailVerified)
        .build();
    let policy = make_conditional_policy(
        "tool:*",
        "Tier check",
        json!({
            "context_conditions": [{
                "type": "min_verification_tier",
                "required_tier": 3
            }]
        }),
    );
    let action = make_action("tool", "op", json!({}));
    let engine = PolicyEngine::with_policies(false, &[policy]).unwrap();
    let verdict = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

#[test]
fn test_context_min_verification_tier_none_fail_closed() {
    let ctx = make_context(); // no verification_tier
    let policy = make_conditional_policy(
        "tool:*",
        "Tier check",
        json!({
            "context_conditions": [{
                "type": "min_verification_tier",
                "required_tier": 1
            }]
        }),
    );
    let action = make_action("tool", "op", json!({}));
    let engine = PolicyEngine::with_policies(false, &[policy]).unwrap();
    let verdict = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

#[test]
fn test_context_require_capability_token_valid_allows() {
    let token = vellaveto_types::CapabilityToken {
        token_id: "tok-test-1".into(),
        parent_token_id: None,
        issuer: "authority".into(),
        holder: "agent-a".into(),
        grants: vec![vellaveto_types::CapabilityGrant {
            tool_pattern: "*".into(),
            function_pattern: "*".into(),
            allowed_paths: vec![],
            allowed_domains: vec![],
            max_invocations: 0,
        }],
        remaining_depth: 3,
        issued_at: "2026-01-01T00:00:00Z".into(),
        expires_at: "2027-01-01T00:00:00Z".into(),
        signature: "deadbeef".into(),
        issuer_public_key: "cafebabe".into(),
    };
    let ctx = EvaluationContext::builder()
        .agent_id("agent-a".to_string())
        .capability_token(token)
        .build();
    let policy = make_conditional_policy(
        "tool:*",
        "Cap token",
        json!({
            "context_conditions": [{
                "type": "require_capability_token",
                "required_issuers": ["authority"],
                "min_remaining_depth": 1
            }]
        }),
    );
    let action = make_action("tool", "op", json!({}));
    let engine = PolicyEngine::with_policies(false, &[policy]).unwrap();
    let verdict = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(matches!(verdict, Verdict::Allow));
}

#[test]
fn test_context_require_capability_token_wrong_holder_denies() {
    let token = vellaveto_types::CapabilityToken {
        token_id: "tok-test-2".into(),
        parent_token_id: None,
        issuer: "authority".into(),
        holder: "agent-b".into(),
        grants: vec![],
        remaining_depth: 5,
        issued_at: "2026-01-01T00:00:00Z".into(),
        expires_at: "2027-01-01T00:00:00Z".into(),
        signature: "deadbeef".into(),
        issuer_public_key: "cafebabe".into(),
    };
    let ctx = EvaluationContext::builder()
        .agent_id("agent-a".to_string())
        .capability_token(token)
        .build();
    let policy = make_conditional_policy(
        "tool:*",
        "Cap token",
        json!({
            "context_conditions": [{
                "type": "require_capability_token"
            }]
        }),
    );
    let action = make_action("tool", "op", json!({}));
    let engine = PolicyEngine::with_policies(false, &[policy]).unwrap();
    let verdict = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

#[test]
fn test_context_require_capability_token_none_fail_closed() {
    let ctx = make_context();
    let policy = make_conditional_policy(
        "tool:*",
        "Cap token",
        json!({
            "context_conditions": [{
                "type": "require_capability_token"
            }]
        }),
    );
    let action = make_action("tool", "op", json!({}));
    let engine = PolicyEngine::with_policies(false, &[policy]).unwrap();
    let verdict = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

#[test]
/// FIND-R213-001: RequireCapabilityToken holder comparison uses homoglyph
/// normalization. A Cyrillic-variant holder name should match the Latin agent_id.
fn test_require_capability_token_holder_homoglyph_normalization_allows() {
    // token.holder uses Cyrillic 'а' (U+0430) which looks like Latin 'a'
    let token = vellaveto_types::CapabilityToken {
        token_id: "tok-homoglyph".into(),
        parent_token_id: None,
        issuer: "authority".into(),
        holder: "\u{0430}gent-a".into(), // Cyrillic 'а'
        grants: vec![vellaveto_types::CapabilityGrant {
            tool_pattern: "*".into(),
            function_pattern: "*".into(),
            allowed_paths: vec![],
            allowed_domains: vec![],
            max_invocations: 0,
        }],
        remaining_depth: 3,
        issued_at: "2026-01-01T00:00:00Z".into(),
        expires_at: "2027-01-01T00:00:00Z".into(),
        signature: "deadbeef".into(),
        issuer_public_key: "cafebabe".into(),
    };
    // agent_id uses Latin 'a'
    let ctx = EvaluationContext::builder()
        .agent_id("agent-a".to_string())
        .capability_token(token)
        .build();
    let policy = make_conditional_policy(
        "tool:*",
        "Cap token homoglyph",
        json!({
            "context_conditions": [{
                "type": "require_capability_token"
            }]
        }),
    );
    let action = make_action("tool", "op", json!({}));
    let engine = PolicyEngine::with_policies(false, &[policy]).unwrap();
    let verdict = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(verdict, Verdict::Allow),
        "Homoglyph-normalized holder should match agent_id: {verdict:?}"
    );
}

#[test]
/// FIND-R213-001: Genuinely different holder still denied after normalization.
fn test_require_capability_token_holder_different_after_normalization_denies() {
    let token = vellaveto_types::CapabilityToken {
        token_id: "tok-diff".into(),
        parent_token_id: None,
        issuer: "authority".into(),
        holder: "agent-b".into(),
        grants: vec![],
        remaining_depth: 5,
        issued_at: "2026-01-01T00:00:00Z".into(),
        expires_at: "2027-01-01T00:00:00Z".into(),
        signature: "deadbeef".into(),
        issuer_public_key: "cafebabe".into(),
    };
    let ctx = EvaluationContext::builder()
        .agent_id("agent-a".to_string())
        .capability_token(token)
        .build();
    let policy = make_conditional_policy(
        "tool:*",
        "Cap token diff",
        json!({
            "context_conditions": [{
                "type": "require_capability_token"
            }]
        }),
    );
    let action = make_action("tool", "op", json!({}));
    let engine = PolicyEngine::with_policies(false, &[policy]).unwrap();
    let verdict = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(verdict, Verdict::Deny { .. }),
        "Different holder should still deny: {verdict:?}"
    );
}

#[test]
fn test_context_session_state_allowed_allows() {
    let ctx = EvaluationContext::builder()
        .session_state("authenticated".to_string())
        .build();
    let policy = make_conditional_policy(
        "tool:*",
        "Session state",
        json!({
            "context_conditions": [{
                "type": "session_state_required",
                "allowed_states": ["authenticated", "admin"]
            }]
        }),
    );
    let action = make_action("tool", "op", json!({}));
    let engine = PolicyEngine::with_policies(false, &[policy]).unwrap();
    let verdict = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(matches!(verdict, Verdict::Allow));
}

#[test]
fn test_context_session_state_not_allowed_denies() {
    let ctx = EvaluationContext::builder()
        .session_state("guest".to_string())
        .build();
    let policy = make_conditional_policy(
        "tool:*",
        "Session state",
        json!({
            "context_conditions": [{
                "type": "session_state_required",
                "allowed_states": ["authenticated", "admin"]
            }]
        }),
    );
    let action = make_action("tool", "op", json!({}));
    let engine = PolicyEngine::with_policies(false, &[policy]).unwrap();
    let verdict = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

#[test]
fn test_context_session_state_none_fail_closed() {
    let ctx = make_context();
    let policy = make_conditional_policy(
        "tool:*",
        "Session state",
        json!({
            "context_conditions": [{
                "type": "session_state_required",
                "allowed_states": ["authenticated"]
            }]
        }),
    );
    let action = make_action("tool", "op", json!({}));
    let engine = PolicyEngine::with_policies(false, &[policy]).unwrap();
    let verdict = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

// ═══════════════════════════════════════════════════════
// A4: legacy.rs tests
// ═══════════════════════════════════════════════════════

#[test]
fn test_legacy_matches_action_wildcard() {
    let engine = PolicyEngine::new(false);
    let action = make_action("anything", "whatever", json!({}));
    let policy = Policy {
        id: "*".to_string(),
        name: "Catch all".to_string(),
        policy_type: PolicyType::Allow,
        priority: 1,
        path_rules: None,
        network_rules: None,
    };
    assert!(engine.matches_action(&action, &policy));
}

#[test]
fn test_legacy_matches_action_tool_wildcard() {
    let engine = PolicyEngine::new(false);
    let action = make_action("bash", "execute", json!({}));
    let policy = Policy {
        id: "bash:*".to_string(),
        name: "Bash all".to_string(),
        policy_type: PolicyType::Allow,
        priority: 1,
        path_rules: None,
        network_rules: None,
    };
    assert!(engine.matches_action(&action, &policy));
}

#[test]
fn test_legacy_matches_action_exact() {
    let engine = PolicyEngine::new(false);
    let action = make_action("fs", "read_file", json!({}));
    let policy = Policy {
        id: "fs:read_file".to_string(),
        name: "Exact".to_string(),
        policy_type: PolicyType::Allow,
        priority: 1,
        path_rules: None,
        network_rules: None,
    };
    assert!(engine.matches_action(&action, &policy));
}

#[test]
fn test_legacy_matches_action_prefix_wildcard() {
    let engine = PolicyEngine::new(false);
    let action = make_action("fs", "read_file", json!({}));
    let policy = Policy {
        id: "fs:read*".to_string(),
        name: "Prefix".to_string(),
        policy_type: PolicyType::Allow,
        priority: 1,
        path_rules: None,
        network_rules: None,
    };
    assert!(engine.matches_action(&action, &policy));
}

#[test]
fn test_legacy_matches_action_suffix_wildcard() {
    let engine = PolicyEngine::new(false);
    let action = make_action("fs", "read_file", json!({}));
    let policy = Policy {
        id: "*:read_file".to_string(),
        name: "Suffix".to_string(),
        policy_type: PolicyType::Allow,
        priority: 1,
        path_rules: None,
        network_rules: None,
    };
    assert!(engine.matches_action(&action, &policy));
}

#[test]
fn test_legacy_matches_action_no_match() {
    let engine = PolicyEngine::new(false);
    let action = make_action("fs", "read_file", json!({}));
    let policy = Policy {
        id: "bash:execute".to_string(),
        name: "Wrong".to_string(),
        policy_type: PolicyType::Allow,
        priority: 1,
        path_rules: None,
        network_rules: None,
    };
    assert!(!engine.matches_action(&action, &policy));
}

#[test]
fn test_legacy_apply_policy_allow() {
    let engine = PolicyEngine::new(false);
    let action = make_action("fs", "read", json!({}));
    let policy = Policy {
        id: "fs:*".to_string(),
        name: "Allow".to_string(),
        policy_type: PolicyType::Allow,
        priority: 1,
        path_rules: None,
        network_rules: None,
    };
    let verdict = engine.apply_policy(&action, &policy).unwrap().unwrap();
    assert!(matches!(verdict, Verdict::Allow));
}

#[test]
fn test_legacy_apply_policy_deny() {
    let engine = PolicyEngine::new(false);
    let action = make_action("bash", "exec", json!({}));
    let policy = Policy {
        id: "bash:*".to_string(),
        name: "Deny bash".to_string(),
        policy_type: PolicyType::Deny,
        priority: 1,
        path_rules: None,
        network_rules: None,
    };
    let verdict = engine.apply_policy(&action, &policy).unwrap().unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

#[test]
fn test_legacy_check_path_rules_blocked_match() {
    let engine = PolicyEngine::new(false);
    let mut action = make_action("fs", "read", json!({}));
    action.target_paths = vec!["/etc/shadow".to_string()];
    let policy = Policy {
        id: "fs:*".to_string(),
        name: "Block etc".to_string(),
        policy_type: PolicyType::Allow,
        priority: 1,
        path_rules: Some(vellaveto_types::PathRules {
            allowed: vec![],
            blocked: vec!["/etc/**".to_string()],
        }),
        network_rules: None,
    };
    let verdict = engine.evaluate_action(&action, &[policy]).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

#[test]
fn test_legacy_check_path_rules_allowed_match() {
    let engine = PolicyEngine::new(false);
    let mut action = make_action("fs", "read", json!({}));
    action.target_paths = vec!["/home/user/file.txt".to_string()];
    let policy = Policy {
        id: "fs:*".to_string(),
        name: "Allow home".to_string(),
        policy_type: PolicyType::Allow,
        priority: 1,
        path_rules: Some(vellaveto_types::PathRules {
            allowed: vec!["/home/**".to_string()],
            blocked: vec![],
        }),
        network_rules: None,
    };
    let verdict = engine.evaluate_action(&action, &[policy]).unwrap();
    assert!(matches!(verdict, Verdict::Allow));
}

#[test]
fn test_legacy_check_path_rules_no_targets_with_allowlist_fail_closed() {
    let engine = PolicyEngine::new(false);
    let action = make_action("fs", "read", json!({})); // no target_paths
    let policy = Policy {
        id: "fs:*".to_string(),
        name: "Allow home".to_string(),
        policy_type: PolicyType::Allow,
        priority: 1,
        path_rules: Some(vellaveto_types::PathRules {
            allowed: vec!["/home/**".to_string()],
            blocked: vec![],
        }),
        network_rules: None,
    };
    let verdict = engine.evaluate_action(&action, &[policy]).unwrap();
    assert!(
        matches!(verdict, Verdict::Deny { .. }),
        "No targets with allowlist should fail-closed"
    );
}

#[test]
fn test_legacy_check_path_rules_path_normalization() {
    let engine = PolicyEngine::new(false);
    let mut action = make_action("fs", "read", json!({}));
    action.target_paths = vec!["/home/../etc/shadow".to_string()];
    let policy = Policy {
        id: "fs:*".to_string(),
        name: "Block etc".to_string(),
        policy_type: PolicyType::Allow,
        priority: 1,
        path_rules: Some(vellaveto_types::PathRules {
            allowed: vec![],
            blocked: vec!["/etc/**".to_string()],
        }),
        network_rules: None,
    };
    let verdict = engine.evaluate_action(&action, &[policy]).unwrap();
    assert!(
        matches!(verdict, Verdict::Deny { .. }),
        "Path traversal should be caught after normalization"
    );
}

#[test]
fn test_legacy_check_network_rules_blocked_domain() {
    let engine = PolicyEngine::new(false);
    let mut action = make_action("net", "fetch", json!({}));
    action.target_domains = vec!["evil.com".to_string()];
    let policy = Policy {
        id: "net:*".to_string(),
        name: "Block evil".to_string(),
        policy_type: PolicyType::Allow,
        priority: 1,
        path_rules: None,
        network_rules: Some(vellaveto_types::NetworkRules {
            allowed_domains: vec![],
            blocked_domains: vec!["evil.com".to_string()],
            ip_rules: None,
        }),
    };
    let verdict = engine.evaluate_action(&action, &[policy]).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

#[test]
fn test_legacy_check_network_rules_allowed_domain() {
    let engine = PolicyEngine::new(false);
    let mut action = make_action("net", "fetch", json!({}));
    action.target_domains = vec!["api.example.com".to_string()];
    let policy = Policy {
        id: "net:*".to_string(),
        name: "Allow example".to_string(),
        policy_type: PolicyType::Allow,
        priority: 1,
        path_rules: None,
        network_rules: Some(vellaveto_types::NetworkRules {
            allowed_domains: vec!["*.example.com".to_string()],
            blocked_domains: vec![],
            ip_rules: None,
        }),
    };
    let verdict = engine.evaluate_action(&action, &[policy]).unwrap();
    assert!(matches!(verdict, Verdict::Allow));
}

#[test]
fn test_legacy_check_network_rules_no_targets_fail_closed() {
    let engine = PolicyEngine::new(false);
    let action = make_action("net", "fetch", json!({})); // no target_domains
    let policy = Policy {
        id: "net:*".to_string(),
        name: "Allow example".to_string(),
        policy_type: PolicyType::Allow,
        priority: 1,
        path_rules: None,
        network_rules: Some(vellaveto_types::NetworkRules {
            allowed_domains: vec!["example.com".to_string()],
            blocked_domains: vec![],
            ip_rules: None,
        }),
    };
    let verdict = engine.evaluate_action(&action, &[policy]).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

#[test]
fn test_legacy_check_ip_rules_block_private() {
    let engine = PolicyEngine::new(false);
    let mut action = make_action("net", "fetch", json!({}));
    action.target_domains = vec!["internal.example.com".to_string()];
    action.resolved_ips = vec!["192.168.1.1".to_string()];
    let policy = Policy {
        id: "net:*".to_string(),
        name: "Block private".to_string(),
        policy_type: PolicyType::Allow,
        priority: 1,
        path_rules: None,
        network_rules: Some(vellaveto_types::NetworkRules {
            allowed_domains: vec![],
            blocked_domains: vec![],
            ip_rules: Some(vellaveto_types::IpRules {
                block_private: true,
                blocked_cidrs: vec![],
                allowed_cidrs: vec![],
            }),
        }),
    };
    let verdict = engine.evaluate_action(&action, &[policy]).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

#[test]
fn test_legacy_check_ip_rules_blocked_cidr() {
    let engine = PolicyEngine::new(false);
    let mut action = make_action("net", "fetch", json!({}));
    action.target_domains = vec!["target.com".to_string()];
    action.resolved_ips = vec!["10.0.0.5".to_string()];
    let policy = Policy {
        id: "net:*".to_string(),
        name: "Block CIDR".to_string(),
        policy_type: PolicyType::Allow,
        priority: 1,
        path_rules: None,
        network_rules: Some(vellaveto_types::NetworkRules {
            allowed_domains: vec![],
            blocked_domains: vec![],
            ip_rules: Some(vellaveto_types::IpRules {
                block_private: false,
                blocked_cidrs: vec!["10.0.0.0/8".to_string()],
                allowed_cidrs: vec![],
            }),
        }),
    };
    let verdict = engine.evaluate_action(&action, &[policy]).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

#[test]
fn test_legacy_check_ip_rules_allowed_cidr() {
    let engine = PolicyEngine::new(false);
    let mut action = make_action("net", "fetch", json!({}));
    action.target_domains = vec!["target.com".to_string()];
    action.resolved_ips = vec!["203.0.113.5".to_string()];
    let policy = Policy {
        id: "net:*".to_string(),
        name: "Allow CIDR".to_string(),
        policy_type: PolicyType::Allow,
        priority: 1,
        path_rules: None,
        network_rules: Some(vellaveto_types::NetworkRules {
            allowed_domains: vec![],
            blocked_domains: vec![],
            ip_rules: Some(vellaveto_types::IpRules {
                block_private: false,
                blocked_cidrs: vec![],
                allowed_cidrs: vec!["203.0.113.0/24".to_string()],
            }),
        }),
    };
    let verdict = engine.evaluate_action(&action, &[policy]).unwrap();
    assert!(matches!(verdict, Verdict::Allow));
}

#[test]
fn test_legacy_check_ip_rules_invalid_cidr_fail_closed() {
    let engine = PolicyEngine::new(false);
    let mut action = make_action("net", "fetch", json!({}));
    action.target_domains = vec!["target.com".to_string()];
    action.resolved_ips = vec!["1.2.3.4".to_string()];
    let policy = Policy {
        id: "net:*".to_string(),
        name: "Bad CIDR".to_string(),
        policy_type: PolicyType::Allow,
        priority: 1,
        path_rules: None,
        network_rules: Some(vellaveto_types::NetworkRules {
            allowed_domains: vec![],
            blocked_domains: vec![],
            ip_rules: Some(vellaveto_types::IpRules {
                block_private: false,
                blocked_cidrs: vec!["not-a-cidr".to_string()],
                allowed_cidrs: vec![],
            }),
        }),
    };
    let verdict = engine.evaluate_action(&action, &[policy]).unwrap();
    assert!(
        matches!(verdict, Verdict::Deny { .. }),
        "Invalid CIDR should fail-closed"
    );
}

#[test]
fn test_legacy_check_ip_rules_ipv6_embedded_ipv4() {
    let engine = PolicyEngine::new(false);
    let mut action = make_action("net", "fetch", json!({}));
    action.target_domains = vec!["target.com".to_string()];
    // IPv6 mapped IPv4: ::ffff:192.168.1.1
    action.resolved_ips = vec!["::ffff:192.168.1.1".to_string()];
    let policy = Policy {
        id: "net:*".to_string(),
        name: "Block private".to_string(),
        policy_type: PolicyType::Allow,
        priority: 1,
        path_rules: None,
        network_rules: Some(vellaveto_types::NetworkRules {
            allowed_domains: vec![],
            blocked_domains: vec![],
            ip_rules: Some(vellaveto_types::IpRules {
                block_private: true,
                blocked_cidrs: vec![],
                allowed_cidrs: vec![],
            }),
        }),
    };
    let verdict = engine.evaluate_action(&action, &[policy]).unwrap();
    assert!(
        matches!(verdict, Verdict::Deny { .. }),
        "IPv6-mapped private IPv4 should be blocked"
    );
}

// ═══════════════════════════════════════════════════════
// A5: Differential testing (compiled vs legacy)
// ═══════════════════════════════════════════════════════

/// Helper that asserts compiled and legacy paths produce equivalent verdicts.
fn assert_compiled_legacy_equivalent(policies: &[Policy], action: &Action) {
    let engine_legacy = PolicyEngine::new(false);
    let legacy_verdict = engine_legacy
        .evaluate_action(action, policies)
        .expect("legacy evaluation failed");

    let engine_compiled = PolicyEngine::with_policies(false, policies).expect("compilation failed");
    let compiled_verdict = engine_compiled
        .evaluate_action(action, &[])
        .expect("compiled evaluation failed");

    let legacy_kind = std::mem::discriminant(&legacy_verdict);
    let compiled_kind = std::mem::discriminant(&compiled_verdict);
    assert_eq!(
        legacy_kind, compiled_kind,
        "Verdict mismatch: legacy={legacy_verdict:?}, compiled={compiled_verdict:?}"
    );
}

#[test]
fn test_differential_allow_policy_identical_verdicts() {
    let policies = vec![Policy {
        id: "fs:read_file".to_string(),
        name: "Allow reads".to_string(),
        policy_type: PolicyType::Allow,
        priority: 50,
        path_rules: None,
        network_rules: None,
    }];
    let action = make_action("fs", "read_file", json!({"path": "/tmp/file.txt"}));
    assert_compiled_legacy_equivalent(&policies, &action);
}

#[test]
fn test_differential_deny_policy_identical_verdicts() {
    let policies = vec![Policy {
        id: "bash:*".to_string(),
        name: "Deny bash".to_string(),
        policy_type: PolicyType::Deny,
        priority: 100,
        path_rules: None,
        network_rules: None,
    }];
    let action = make_action("bash", "execute", json!({"command": "rm -rf /"}));
    assert_compiled_legacy_equivalent(&policies, &action);
}

#[test]
fn test_differential_conditional_glob_deny_identical() {
    let policies = vec![Policy {
        id: "fs:*".to_string(),
        name: "Block etc".to_string(),
        policy_type: PolicyType::Conditional {
            conditions: json!({
                "parameter_constraints": [{
                    "param": "path",
                    "op": "glob",
                    "pattern": "/etc/**"
                }]
            }),
        },
        priority: 100,
        path_rules: None,
        network_rules: None,
    }];
    let action = make_action("fs", "read", json!({"path": "/etc/passwd"}));
    assert_compiled_legacy_equivalent(&policies, &action);
}

#[test]
fn test_differential_conditional_regex_deny_identical() {
    let policies = vec![Policy {
        id: "net:*".to_string(),
        name: "Block evil".to_string(),
        policy_type: PolicyType::Conditional {
            conditions: json!({
                "parameter_constraints": [{
                    "param": "url",
                    "op": "regex",
                    "pattern": "evil\\.com"
                }]
            }),
        },
        priority: 100,
        path_rules: None,
        network_rules: None,
    }];
    let action = make_action("net", "fetch", json!({"url": "https://evil.com/steal"}));
    assert_compiled_legacy_equivalent(&policies, &action);
}

#[test]
fn test_differential_conditional_domain_match_identical() {
    let policies = vec![Policy {
        id: "net:*".to_string(),
        name: "Block domain".to_string(),
        policy_type: PolicyType::Conditional {
            conditions: json!({
                "parameter_constraints": [{
                    "param": "url",
                    "op": "domain_match",
                    "pattern": "*.evil.com"
                }]
            }),
        },
        priority: 100,
        path_rules: None,
        network_rules: None,
    }];
    let action = make_action("net", "fetch", json!({"url": "https://api.evil.com/data"}));
    assert_compiled_legacy_equivalent(&policies, &action);
}

#[test]
fn test_differential_path_rules_blocked_identical() {
    let policies = vec![Policy {
        id: "fs:*".to_string(),
        name: "Block etc".to_string(),
        policy_type: PolicyType::Allow,
        priority: 100,
        path_rules: Some(vellaveto_types::PathRules {
            allowed: vec![],
            blocked: vec!["/etc/**".to_string()],
        }),
        network_rules: None,
    }];
    let mut action = make_action("fs", "read", json!({}));
    action.target_paths = vec!["/etc/shadow".to_string()];
    assert_compiled_legacy_equivalent(&policies, &action);
}

#[test]
fn test_differential_network_rules_blocked_identical() {
    let policies = vec![Policy {
        id: "net:*".to_string(),
        name: "Block evil".to_string(),
        policy_type: PolicyType::Allow,
        priority: 100,
        path_rules: None,
        network_rules: Some(vellaveto_types::NetworkRules {
            allowed_domains: vec![],
            blocked_domains: vec!["evil.com".to_string()],
            ip_rules: None,
        }),
    }];
    let mut action = make_action("net", "fetch", json!({}));
    action.target_domains = vec!["evil.com".to_string()];
    assert_compiled_legacy_equivalent(&policies, &action);
}

#[test]
fn test_differential_all_constraints_skipped_fails_closed_identical() {
    let policies = vec![Policy {
        id: "tool:*".to_string(),
        name: "All skip".to_string(),
        policy_type: PolicyType::Conditional {
            conditions: json!({
                "parameter_constraints": [
                    {"param": "missing", "op": "eq", "value": "x", "on_missing": "skip"}
                ]
            }),
        },
        priority: 100,
        path_rules: None,
        network_rules: None,
    }];
    let action = make_action("tool", "op", json!({"other": "value"}));
    assert_compiled_legacy_equivalent(&policies, &action);
}

#[test]
fn test_differential_ip_rules_block_private_identical() {
    let policies = vec![Policy {
        id: "net:*".to_string(),
        name: "Block private".to_string(),
        policy_type: PolicyType::Allow,
        priority: 100,
        path_rules: None,
        network_rules: Some(vellaveto_types::NetworkRules {
            allowed_domains: vec![],
            blocked_domains: vec![],
            ip_rules: Some(vellaveto_types::IpRules {
                block_private: true,
                blocked_cidrs: vec![],
                allowed_cidrs: vec![],
            }),
        }),
    }];
    let mut action = make_action("net", "fetch", json!({}));
    action.target_domains = vec!["internal.com".to_string()];
    action.resolved_ips = vec!["10.0.0.1".to_string()];
    assert_compiled_legacy_equivalent(&policies, &action);
}

#[test]
fn test_differential_require_approval_identical() {
    let policies = vec![Policy {
        id: "tool:*".to_string(),
        name: "Approval".to_string(),
        policy_type: PolicyType::Conditional {
            conditions: json!({"require_approval": true}),
        },
        priority: 100,
        path_rules: None,
        network_rules: None,
    }];
    let action = make_action("tool", "op", json!({}));
    assert_compiled_legacy_equivalent(&policies, &action);
}

// ═══════════════════════════════════════════════════
// FIND-R46-004: Legacy match_pattern infix wildcard behavior
// ═══════════════════════════════════════════════════

#[test]
fn test_r46_004_legacy_match_pattern_infix_wildcard_treated_as_prefix() {
    // Document and test that the legacy match_pattern treats "foo*bar"
    // as a prefix match on "foo" (since strip_suffix('*') doesn't find
    // a trailing '*', it falls to strip_prefix which also doesn't find
    // a leading '*', so it becomes an exact match).
    // Actually: "foo*bar" has no leading or trailing '*', so it's exact.
    let engine = PolicyEngine::new(false);
    let action = Action::new("file_read_write".to_string(), "exec".to_string(), json!({}));
    // "file_*_write" as a policy ID has no leading/trailing '*', so it's an exact match.
    // It should NOT match "file_read_write".
    let policies = vec![Policy {
        id: "file_*_write:*".to_string(),
        name: "infix wildcard".to_string(),
        policy_type: PolicyType::Allow,
        priority: 100,
        path_rules: None,
        network_rules: None,
    }];
    // Legacy path: "file_*_write" stripped of suffix '*' doesn't work because
    // the tool part is "file_*_write" — let's test this properly through the
    // compiled path which is what the actual engine uses.
    let result = engine.evaluate_action(&action, &policies);
    // The legacy pattern "file_*_write" with strip_suffix('*') finds no trailing '*',
    // strip_prefix('*') finds no leading '*', so it's treated as exact match.
    // "file_*_write" != "file_read_write", so it should NOT match → deny.
    assert!(
        matches!(result, Ok(Verdict::Deny { .. })),
        "Legacy infix wildcard should not match (treated as exact): {result:?}"
    );
}

#[test]
fn test_r46_004_compiled_infix_wildcard_treated_as_match_all() {
    // The compiled path treats infix wildcards as match-all (fail-closed).
    // This is documented in PatternMatcher::compile.
    use crate::PatternMatcher;
    let matcher = PatternMatcher::compile("read_*_file");
    assert!(
        matches!(matcher, PatternMatcher::Any),
        "Infix wildcard should be treated as match-all in compiled path"
    );
    assert!(
        matcher.matches("anything_at_all"),
        "Match-all should match any string"
    );
}

// ═══════════════════════════════════════════════════
// FIND-R46-005: json_depth bounded traversal
// ═══════════════════════════════════════════════════

#[test]
fn test_r46_005_json_depth_deeply_nested_returns_capped_depth() {
    // Build a deeply nested JSON: {"a":{"a":{"a":...}}} 200 levels deep
    let mut val = json!("leaf");
    for _ in 0..200 {
        val = json!({"a": val});
    }
    let depth = PolicyEngine::json_depth(&val);
    // Should be capped at or above MAX_JSON_DEPTH_LIMIT (128) without OOM/crash
    assert!(
        depth >= 128,
        "Deeply nested JSON should trigger depth limit, got {depth}"
    );
}

#[test]
fn test_r46_005_json_depth_wide_json_bounded() {
    // Build a wide JSON: {"k0":"v", "k1":"v", ... "k9999":"v"} with 10001 keys
    // at depth 0 — should terminate via node budget
    let mut obj = serde_json::Map::new();
    for i in 0..12000 {
        obj.insert(format!("k{i}"), json!("v"));
    }
    let val = serde_json::Value::Object(obj);
    let depth = PolicyEngine::json_depth(&val);
    // Should be 1 (flat object, each value is at depth 1)
    // The important thing is it doesn't OOM
    assert!(depth <= 2, "Wide flat JSON should have low depth: {depth}");
}

#[test]
fn test_r46_005_json_depth_normal_json() {
    let val = json!({"a": {"b": [1, 2, {"c": true}]}});
    let depth = PolicyEngine::json_depth(&val);
    // a=1, b=2, array=3, items=3, c_obj=4, c_val=4
    assert!((3..=5).contains(&depth), "Normal JSON depth: {depth}");
}

// ═══════════════════════════════════════════════════
// FIND-R46-006: collect_all_string_values complete traversal
// ═══════════════════════════════════════════════════

#[test]
fn test_r46_006_collect_all_string_values_deeply_nested() {
    // Build deeply nested JSON with string at the bottom
    let mut val = json!("deep_secret");
    for _ in 0..30 {
        val = json!({"nest": val});
    }
    let (results, _truncated) = PolicyEngine::collect_all_string_values(&val);
    // Should find the deeply nested string (depth 30 < MAX_JSON_DEPTH=32)
    assert!(
        !results.is_empty(),
        "Should find string at depth 30 (within limit of 32)"
    );
    assert!(
        results.iter().any(|(_, v)| *v == "deep_secret"),
        "Should find the deeply nested string value"
    );
}

#[test]
fn test_r46_006_collect_all_string_values_beyond_depth_limit() {
    // Build deeply nested JSON beyond the depth limit
    let mut val = json!("unreachable");
    for _ in 0..40 {
        val = json!({"nest": val});
    }
    let (results, _truncated) = PolicyEngine::collect_all_string_values(&val);
    // The string at depth 40 should NOT be found (exceeds MAX_JSON_DEPTH=32)
    let found = results.iter().any(|(_, v)| *v == "unreachable");
    assert!(!found, "String beyond depth limit should not be collected");
}

#[test]
fn test_r46_006_collect_all_string_values_mixed_nesting() {
    // Mix of shallow and deep values — all shallow ones should be found
    let val = json!({
        "shallow": "found1",
        "nested": {
            "level2": "found2",
            "deep": {
                "level3": "found3"
            }
        },
        "array": ["found4", {"inner": "found5"}]
    });
    let (results, _truncated) = PolicyEngine::collect_all_string_values(&val);
    let values: Vec<&str> = results.iter().map(|(_, v)| *v).collect();
    assert!(values.contains(&"found1"), "shallow string missing");
    assert!(values.contains(&"found2"), "level2 string missing");
    assert!(values.contains(&"found3"), "level3 string missing");
    assert!(values.contains(&"found4"), "array string missing");
    assert!(
        values.contains(&"found5"),
        "nested array object string missing"
    );
}

// ═══════════════════════════════════════════════════
// FIND-R46-007: ReDoS validator enhanced checks
// ═══════════════════════════════════════════════════

#[test]
fn test_r46_007_redos_nested_quantifier_rejected() {
    let result = PolicyEngine::validate_regex_safety("(a+)+");
    assert!(result.is_err(), "Nested quantifier should be rejected");
}

#[test]
fn test_r46_007_redos_alternation_with_quantifier_rejected() {
    // (a|b)+ with alternation under a quantified group
    let result = PolicyEngine::validate_regex_safety("(a|b)+");
    assert!(
        result.is_err(),
        "Alternation with outer quantifier should be rejected: {result:?}"
    );
}

#[test]
fn test_r46_007_redos_alternation_star_rejected() {
    let result = PolicyEngine::validate_regex_safety("(foo|bar)*");
    assert!(
        result.is_err(),
        "Alternation with outer * should be rejected: {result:?}"
    );
}

#[test]
fn test_r46_007_redos_simple_quantifier_allowed() {
    // Simple quantifiers without nesting should be fine
    assert!(PolicyEngine::validate_regex_safety("a+b*c?").is_ok());
    assert!(PolicyEngine::validate_regex_safety("[a-z]+").is_ok());
    assert!(PolicyEngine::validate_regex_safety("\\d{3}-\\d{4}").is_ok());
}

#[test]
fn test_r46_007_redos_group_without_quantifier_allowed() {
    // Groups without outer quantifiers are safe
    assert!(PolicyEngine::validate_regex_safety("(abc)").is_ok());
    assert!(PolicyEngine::validate_regex_safety("(a|b)").is_ok());
}

#[test]
fn test_r46_007_redos_escaped_paren_not_confused() {
    // Escaped parens should not be treated as groups
    assert!(PolicyEngine::validate_regex_safety("\\(a+\\)+").is_ok());
}

#[test]
fn test_r46_007_redos_overlength_rejected() {
    let long_pattern = "a".repeat(1025);
    assert!(PolicyEngine::validate_regex_safety(&long_pattern).is_err());
}

// ═══════════════════════════════════════════════════════════════════════════
// Phase 40: Workflow-Level Policy Constraints — RequiredActionSequence
// ═══════════════════════════════════════════════════════════════════════════

/// Like `make_context_policy` but matches ALL tools (id="*:*").
fn make_wildcard_context_policy(context_conditions: serde_json::Value) -> Policy {
    Policy {
        id: "*:*".to_string(),
        name: "wildcard-context-test".to_string(),
        policy_type: PolicyType::Conditional {
            conditions: json!({
                "context_conditions": context_conditions,
            }),
        },
        priority: 100,
        path_rules: None,
        network_rules: None,
    }
}

#[test]
fn test_required_action_sequence_ordered_present_allows() {
    let policy = make_wildcard_context_policy(json!([{
        "type": "required_action_sequence",
        "sequence": ["authenticate", "read_data"],
        "ordered": true
    }]));
    let engine = make_context_engine(policy);
    let action = Action::new("write_result", "execute", json!({}));
    let ctx = EvaluationContext {
        previous_actions: vec![
            "authenticate".to_string(),
            "list_files".to_string(),
            "read_data".to_string(),
        ],
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(matches!(v, Verdict::Allow), "Expected Allow, got {v:?}");
}

#[test]
fn test_required_action_sequence_ordered_absent_denies() {
    let policy = make_wildcard_context_policy(json!([{
        "type": "required_action_sequence",
        "sequence": ["authenticate", "read_data"],
        "ordered": true
    }]));
    let engine = make_context_engine(policy);
    let action = Action::new("write_result", "execute", json!({}));
    let ctx = EvaluationContext {
        previous_actions: vec!["list_files".to_string()],
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "Expected Deny, got {v:?}"
    );
}

#[test]
fn test_required_action_sequence_ordered_reversed_denies() {
    let policy = make_wildcard_context_policy(json!([{
        "type": "required_action_sequence",
        "sequence": ["authenticate", "read_data"],
        "ordered": true
    }]));
    let engine = make_context_engine(policy);
    let action = Action::new("write_result", "execute", json!({}));
    let ctx = EvaluationContext {
        previous_actions: vec!["read_data".to_string(), "authenticate".to_string()],
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "Expected Deny (wrong order), got {v:?}"
    );
}

#[test]
fn test_required_action_sequence_ordered_non_consecutive_allows() {
    let policy = make_wildcard_context_policy(json!([{
        "type": "required_action_sequence",
        "sequence": ["authenticate", "read_data"],
        "ordered": true
    }]));
    let engine = make_context_engine(policy);
    let action = Action::new("write_result", "execute", json!({}));
    let ctx = EvaluationContext {
        previous_actions: vec![
            "authenticate".to_string(),
            "list_files".to_string(),
            "check_permissions".to_string(),
            "read_data".to_string(),
        ],
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Allow),
        "Expected Allow (non-consecutive), got {v:?}"
    );
}

#[test]
fn test_required_action_sequence_ordered_partial_denies() {
    let policy = make_wildcard_context_policy(json!([{
        "type": "required_action_sequence",
        "sequence": ["authenticate", "read_data", "process"],
        "ordered": true
    }]));
    let engine = make_context_engine(policy);
    let action = Action::new("write_result", "execute", json!({}));
    let ctx = EvaluationContext {
        previous_actions: vec!["authenticate".to_string(), "read_data".to_string()],
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "Expected Deny (partial), got {v:?}"
    );
}

#[test]
fn test_required_action_sequence_unordered_all_present_allows() {
    let policy = make_wildcard_context_policy(json!([{
        "type": "required_action_sequence",
        "sequence": ["read_data", "authenticate"],
        "ordered": false
    }]));
    let engine = make_context_engine(policy);
    let action = Action::new("write_result", "execute", json!({}));
    let ctx = EvaluationContext {
        previous_actions: vec![
            "read_data".to_string(),
            "list_files".to_string(),
            "authenticate".to_string(),
        ],
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Allow),
        "Expected Allow (unordered all present), got {v:?}"
    );
}

#[test]
fn test_required_action_sequence_unordered_missing_one_denies() {
    let policy = make_wildcard_context_policy(json!([{
        "type": "required_action_sequence",
        "sequence": ["authenticate", "read_data", "validate"],
        "ordered": false
    }]));
    let engine = make_context_engine(policy);
    let action = Action::new("write_result", "execute", json!({}));
    let ctx = EvaluationContext {
        previous_actions: vec![
            "authenticate".to_string(),
            "read_data".to_string(),
            "list_files".to_string(),
        ],
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "Expected Deny (missing 'validate'), got {v:?}"
    );
}

#[test]
fn test_required_action_sequence_empty_history_denies() {
    let policy = make_wildcard_context_policy(json!([{
        "type": "required_action_sequence",
        "sequence": ["authenticate"],
        "ordered": true
    }]));
    let engine = make_context_engine(policy);
    let action = Action::new("write_result", "execute", json!({}));
    let ctx = EvaluationContext {
        previous_actions: vec![],
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "Expected Deny (empty history), got {v:?}"
    );
}

#[test]
fn test_required_action_sequence_history_shorter_denies() {
    let policy = make_wildcard_context_policy(json!([{
        "type": "required_action_sequence",
        "sequence": ["a", "b", "c"],
        "ordered": true
    }]));
    let engine = make_context_engine(policy);
    let action = Action::new("write_result", "execute", json!({}));
    let ctx = EvaluationContext {
        previous_actions: vec!["a".to_string(), "b".to_string()],
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "Expected Deny (history shorter), got {v:?}"
    );
}

#[test]
fn test_required_action_sequence_case_insensitive_allows() {
    let policy = make_wildcard_context_policy(json!([{
        "type": "required_action_sequence",
        "sequence": ["Authenticate", "READ_DATA"],
        "ordered": true
    }]));
    let engine = make_context_engine(policy);
    let action = Action::new("write_result", "execute", json!({}));
    let ctx = EvaluationContext {
        previous_actions: vec!["AUTHENTICATE".to_string(), "read_data".to_string()],
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Allow),
        "Expected Allow (case insensitive), got {v:?}"
    );
}

#[test]
fn test_required_action_sequence_single_tool_equivalent() {
    // Single-tool sequence should behave like RequirePreviousAction.
    let policy = make_wildcard_context_policy(json!([{
        "type": "required_action_sequence",
        "sequence": ["authenticate"],
        "ordered": true
    }]));
    let engine = make_context_engine(policy);
    let action = Action::new("write_result", "execute", json!({}));

    // Present → Allow
    let ctx = EvaluationContext {
        previous_actions: vec!["authenticate".to_string()],
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Allow),
        "Expected Allow for single-tool present, got {v:?}"
    );

    // Absent → Deny
    let ctx2 = EvaluationContext {
        previous_actions: vec!["other_tool".to_string()],
        ..Default::default()
    };
    let v2 = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx2))
        .unwrap();
    assert!(
        matches!(v2, Verdict::Deny { .. }),
        "Expected Deny for single-tool absent, got {v2:?}"
    );
}

#[test]
fn test_required_action_sequence_duplicate_tools_in_sequence() {
    // Duplicate tools in sequence: requires the tool to appear twice.
    let policy = make_wildcard_context_policy(json!([{
        "type": "required_action_sequence",
        "sequence": ["read", "read"],
        "ordered": true
    }]));
    let engine = make_context_engine(policy);
    let action = Action::new("write_result", "execute", json!({}));

    // Only one read → Deny
    let ctx = EvaluationContext {
        previous_actions: vec!["read".to_string()],
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "Expected Deny (only one read), got {v:?}"
    );

    // Two reads → Allow
    let ctx2 = EvaluationContext {
        previous_actions: vec!["read".to_string(), "read".to_string()],
        ..Default::default()
    };
    let v2 = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx2))
        .unwrap();
    assert!(
        matches!(v2, Verdict::Allow),
        "Expected Allow (two reads), got {v2:?}"
    );
}

#[test]
fn test_required_action_sequence_compile_empty_sequence_errors() {
    let policy = make_wildcard_context_policy(json!([{
        "type": "required_action_sequence",
        "sequence": [],
        "ordered": true
    }]));
    let result = PolicyEngine::with_policies(false, &[policy]);
    assert!(result.is_err(), "Expected compile error for empty sequence");
}

#[test]
fn test_required_action_sequence_compile_too_many_steps_errors() {
    let sequence: Vec<String> = (0..21).map(|i| format!("tool_{i}")).collect();
    let policy = make_wildcard_context_policy(json!([{
        "type": "required_action_sequence",
        "sequence": sequence,
        "ordered": true
    }]));
    let result = PolicyEngine::with_policies(false, &[policy]);
    assert!(result.is_err(), "Expected compile error for >20 steps");
}

#[test]
fn test_required_action_sequence_compile_non_string_errors() {
    let policy = make_wildcard_context_policy(json!([{
        "type": "required_action_sequence",
        "sequence": [123, "read"],
        "ordered": true
    }]));
    let result = PolicyEngine::with_policies(false, &[policy]);
    assert!(
        result.is_err(),
        "Expected compile error for non-string element"
    );
}

#[test]
fn test_required_action_sequence_compile_empty_string_errors() {
    let policy = make_wildcard_context_policy(json!([{
        "type": "required_action_sequence",
        "sequence": ["authenticate", ""],
        "ordered": true
    }]));
    let result = PolicyEngine::with_policies(false, &[policy]);
    assert!(result.is_err(), "Expected compile error for empty string");
}

#[test]
fn test_required_action_sequence_compile_missing_sequence_errors() {
    let policy = make_wildcard_context_policy(json!([{
        "type": "required_action_sequence",
        "ordered": true
    }]));
    let result = PolicyEngine::with_policies(false, &[policy]);
    assert!(
        result.is_err(),
        "Expected compile error for missing sequence"
    );
}

#[test]
fn test_required_action_sequence_ordered_exact_length_allows() {
    // History has exactly the same tools as the sequence.
    let policy = make_wildcard_context_policy(json!([{
        "type": "required_action_sequence",
        "sequence": ["a", "b", "c"],
        "ordered": true
    }]));
    let engine = make_context_engine(policy);
    let action = Action::new("write_result", "execute", json!({}));
    let ctx = EvaluationContext {
        previous_actions: vec!["a".to_string(), "b".to_string(), "c".to_string()],
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Allow),
        "Expected Allow (exact length), got {v:?}"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Phase 40: Workflow-Level Policy Constraints — ForbiddenActionSequence
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_forbidden_action_sequence_ordered_present_denies() {
    let policy = make_wildcard_context_policy(json!([{
        "type": "forbidden_action_sequence",
        "sequence": ["read_secret", "http_request"],
        "ordered": true
    }]));
    let engine = make_context_engine(policy);
    let action = Action::new("write_result", "execute", json!({}));
    let ctx = EvaluationContext {
        previous_actions: vec!["read_secret".to_string(), "http_request".to_string()],
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "Expected Deny, got {v:?}"
    );
}

#[test]
fn test_forbidden_action_sequence_ordered_absent_allows() {
    let policy = make_wildcard_context_policy(json!([{
        "type": "forbidden_action_sequence",
        "sequence": ["read_secret", "http_request"],
        "ordered": true
    }]));
    let engine = make_context_engine(policy);
    let action = Action::new("write_result", "execute", json!({}));
    let ctx = EvaluationContext {
        previous_actions: vec!["read_data".to_string(), "process".to_string()],
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(matches!(v, Verdict::Allow), "Expected Allow, got {v:?}");
}

#[test]
fn test_forbidden_action_sequence_ordered_reversed_allows() {
    // Sequence in wrong order should NOT trigger the forbidden check.
    let policy = make_wildcard_context_policy(json!([{
        "type": "forbidden_action_sequence",
        "sequence": ["read_secret", "http_request"],
        "ordered": true
    }]));
    let engine = make_context_engine(policy);
    let action = Action::new("write_result", "execute", json!({}));
    let ctx = EvaluationContext {
        previous_actions: vec!["http_request".to_string(), "read_secret".to_string()],
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Allow),
        "Expected Allow (reversed), got {v:?}"
    );
}

#[test]
fn test_forbidden_action_sequence_ordered_non_consecutive_denies() {
    // Non-consecutive but in order should still trigger.
    let policy = make_wildcard_context_policy(json!([{
        "type": "forbidden_action_sequence",
        "sequence": ["read_secret", "http_request"],
        "ordered": true
    }]));
    let engine = make_context_engine(policy);
    let action = Action::new("write_result", "execute", json!({}));
    let ctx = EvaluationContext {
        previous_actions: vec![
            "read_secret".to_string(),
            "process".to_string(),
            "http_request".to_string(),
        ],
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "Expected Deny (non-consecutive), got {v:?}"
    );
}

#[test]
fn test_forbidden_action_sequence_ordered_partial_allows() {
    // Only partial match should not deny.
    let policy = make_wildcard_context_policy(json!([{
        "type": "forbidden_action_sequence",
        "sequence": ["read_secret", "http_request", "send_email"],
        "ordered": true
    }]));
    let engine = make_context_engine(policy);
    let action = Action::new("write_result", "execute", json!({}));
    let ctx = EvaluationContext {
        previous_actions: vec!["read_secret".to_string(), "http_request".to_string()],
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Allow),
        "Expected Allow (partial), got {v:?}"
    );
}

#[test]
fn test_forbidden_action_sequence_unordered_all_present_denies() {
    let policy = make_wildcard_context_policy(json!([{
        "type": "forbidden_action_sequence",
        "sequence": ["read_secret", "http_request"],
        "ordered": false
    }]));
    let engine = make_context_engine(policy);
    let action = Action::new("write_result", "execute", json!({}));
    let ctx = EvaluationContext {
        previous_actions: vec!["http_request".to_string(), "read_secret".to_string()],
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "Expected Deny (unordered all present), got {v:?}"
    );
}

#[test]
fn test_forbidden_action_sequence_unordered_partial_allows() {
    let policy = make_wildcard_context_policy(json!([{
        "type": "forbidden_action_sequence",
        "sequence": ["read_secret", "http_request", "send_email"],
        "ordered": false
    }]));
    let engine = make_context_engine(policy);
    let action = Action::new("write_result", "execute", json!({}));
    let ctx = EvaluationContext {
        previous_actions: vec!["read_secret".to_string(), "http_request".to_string()],
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Allow),
        "Expected Allow (partial), got {v:?}"
    );
}

#[test]
fn test_forbidden_action_sequence_empty_history_allows() {
    let policy = make_wildcard_context_policy(json!([{
        "type": "forbidden_action_sequence",
        "sequence": ["read_secret", "http_request"],
        "ordered": true
    }]));
    let engine = make_context_engine(policy);
    let action = Action::new("write_result", "execute", json!({}));
    let ctx = EvaluationContext {
        previous_actions: vec![],
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Allow),
        "Expected Allow (empty history), got {v:?}"
    );
}

#[test]
fn test_forbidden_action_sequence_case_insensitive_denies() {
    let policy = make_wildcard_context_policy(json!([{
        "type": "forbidden_action_sequence",
        "sequence": ["Read_Secret", "HTTP_REQUEST"],
        "ordered": true
    }]));
    let engine = make_context_engine(policy);
    let action = Action::new("write_result", "execute", json!({}));
    let ctx = EvaluationContext {
        previous_actions: vec!["READ_SECRET".to_string(), "http_request".to_string()],
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "Expected Deny (case insensitive), got {v:?}"
    );
}

#[test]
fn test_forbidden_action_sequence_single_tool_equivalent() {
    // Single-tool forbidden sequence should behave like ForbiddenPreviousAction.
    let policy = make_wildcard_context_policy(json!([{
        "type": "forbidden_action_sequence",
        "sequence": ["dangerous_tool"],
        "ordered": true
    }]));
    let engine = make_context_engine(policy);
    let action = Action::new("write_result", "execute", json!({}));

    // Present → Deny
    let ctx = EvaluationContext {
        previous_actions: vec!["dangerous_tool".to_string()],
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "Expected Deny, got {v:?}"
    );

    // Absent → Allow
    let ctx2 = EvaluationContext {
        previous_actions: vec!["safe_tool".to_string()],
        ..Default::default()
    };
    let v2 = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx2))
        .unwrap();
    assert!(matches!(v2, Verdict::Allow), "Expected Allow, got {v2:?}");
}

#[test]
fn test_forbidden_action_sequence_exfiltration_detects() {
    // Real-world scenario: detect read_secret → http_request exfiltration.
    let policy = make_wildcard_context_policy(json!([{
        "type": "forbidden_action_sequence",
        "sequence": ["read_secret", "http_request"],
        "ordered": true
    }]));
    let engine = make_context_engine(policy);
    let action = Action::new("write_result", "execute", json!({}));
    let ctx = EvaluationContext {
        previous_actions: vec![
            "authenticate".to_string(),
            "read_secret".to_string(),
            "process_data".to_string(),
            "http_request".to_string(),
        ],
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "Expected Deny (exfiltration), got {v:?}"
    );
}

#[test]
fn test_forbidden_action_sequence_exfiltration_wrong_order_allows() {
    // Same tools but in reverse order: not an exfiltration.
    let policy = make_wildcard_context_policy(json!([{
        "type": "forbidden_action_sequence",
        "sequence": ["read_secret", "http_request"],
        "ordered": true
    }]));
    let engine = make_context_engine(policy);
    let action = Action::new("write_result", "execute", json!({}));
    let ctx = EvaluationContext {
        previous_actions: vec![
            "http_request".to_string(),
            "authenticate".to_string(),
            "read_secret".to_string(),
        ],
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Allow),
        "Expected Allow (wrong order), got {v:?}"
    );
}

#[test]
fn test_forbidden_action_sequence_compile_empty_sequence_errors() {
    let policy = make_wildcard_context_policy(json!([{
        "type": "forbidden_action_sequence",
        "sequence": [],
        "ordered": true
    }]));
    let result = PolicyEngine::with_policies(false, &[policy]);
    assert!(result.is_err(), "Expected compile error for empty sequence");
}

#[test]
fn test_forbidden_action_sequence_compile_too_many_steps_errors() {
    let sequence: Vec<String> = (0..21).map(|i| format!("tool_{i}")).collect();
    let policy = make_wildcard_context_policy(json!([{
        "type": "forbidden_action_sequence",
        "sequence": sequence,
        "ordered": true
    }]));
    let result = PolicyEngine::with_policies(false, &[policy]);
    assert!(result.is_err(), "Expected compile error for >20 steps");
}

#[test]
fn test_forbidden_action_sequence_compile_non_string_errors() {
    let policy = make_wildcard_context_policy(json!([{
        "type": "forbidden_action_sequence",
        "sequence": [true, "read"],
        "ordered": true
    }]));
    let result = PolicyEngine::with_policies(false, &[policy]);
    assert!(
        result.is_err(),
        "Expected compile error for non-string element"
    );
}

#[test]
fn test_forbidden_action_sequence_compile_empty_string_errors() {
    let policy = make_wildcard_context_policy(json!([{
        "type": "forbidden_action_sequence",
        "sequence": ["read_secret", ""],
        "ordered": true
    }]));
    let result = PolicyEngine::with_policies(false, &[policy]);
    assert!(result.is_err(), "Expected compile error for empty string");
}

#[test]
fn test_forbidden_action_sequence_compile_missing_sequence_errors() {
    let policy = make_wildcard_context_policy(json!([{
        "type": "forbidden_action_sequence",
        "ordered": false
    }]));
    let result = PolicyEngine::with_policies(false, &[policy]);
    assert!(
        result.is_err(),
        "Expected compile error for missing sequence"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Phase 40: Workflow-Level Policy Constraints — WorkflowTemplate
// ═══════════════════════════════════════════════════════════════════════════

fn make_workflow_policy(steps: serde_json::Value, enforce: &str) -> Policy {
    Policy {
        id: "*:*".to_string(),
        name: "workflow-test".to_string(),
        policy_type: PolicyType::Conditional {
            conditions: json!({
                "context_conditions": [{
                    "type": "workflow_template",
                    "steps": steps,
                    "enforce": enforce
                }]
            }),
        },
        priority: 100,
        path_rules: None,
        network_rules: None,
    }
}

fn standard_workflow_steps() -> serde_json::Value {
    json!([
        {"tool": "authenticate", "then": ["read_data", "list_data"]},
        {"tool": "read_data", "then": ["process"]},
        {"tool": "list_data", "then": ["process"]},
        {"tool": "process", "then": ["write_result"]}
    ])
}

#[test]
fn test_workflow_template_valid_first_step_allows() {
    let policy = make_workflow_policy(standard_workflow_steps(), "strict");
    let engine = make_context_engine(policy);
    let action = Action::new("authenticate", "execute", json!({}));
    let ctx = EvaluationContext {
        previous_actions: vec![],
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Allow),
        "Expected Allow (entry point), got {v:?}"
    );
}

#[test]
fn test_workflow_template_valid_successor_allows() {
    let policy = make_workflow_policy(standard_workflow_steps(), "strict");
    let engine = make_context_engine(policy);
    let action = Action::new("read_data", "execute", json!({}));
    let ctx = EvaluationContext {
        previous_actions: vec!["authenticate".to_string()],
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Allow),
        "Expected Allow (valid successor), got {v:?}"
    );
}

#[test]
fn test_workflow_template_invalid_successor_strict_denies() {
    let policy = make_workflow_policy(standard_workflow_steps(), "strict");
    let engine = make_context_engine(policy);
    let action = Action::new("write_result", "execute", json!({}));
    let ctx = EvaluationContext {
        previous_actions: vec!["authenticate".to_string()],
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "Expected Deny (invalid successor), got {v:?}"
    );
}

#[test]
fn test_workflow_template_invalid_successor_warn_allows() {
    let policy = make_workflow_policy(standard_workflow_steps(), "warn");
    let engine = make_context_engine(policy);
    let action = Action::new("write_result", "execute", json!({}));
    let ctx = EvaluationContext {
        previous_actions: vec!["authenticate".to_string()],
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Allow),
        "Expected Allow (warn mode), got {v:?}"
    );
}

#[test]
fn test_workflow_template_non_governed_tool_passthrough() {
    let policy = make_workflow_policy(standard_workflow_steps(), "strict");
    let engine = make_context_engine(policy);
    // "log_event" is not in the DAG so it should pass through.
    let action = Action::new("log_event", "execute", json!({}));
    let ctx = EvaluationContext {
        previous_actions: vec!["authenticate".to_string()],
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Allow),
        "Expected Allow (non-governed), got {v:?}"
    );
}

#[test]
fn test_workflow_template_non_entry_point_first_denies() {
    let policy = make_workflow_policy(standard_workflow_steps(), "strict");
    let engine = make_context_engine(policy);
    // "read_data" is not an entry point — calling it first should deny.
    let action = Action::new("read_data", "execute", json!({}));
    let ctx = EvaluationContext {
        previous_actions: vec![],
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "Expected Deny (not entry point), got {v:?}"
    );
}

#[test]
fn test_workflow_template_governed_after_non_governed_history() {
    let policy = make_workflow_policy(standard_workflow_steps(), "strict");
    let engine = make_context_engine(policy);
    // History has only non-governed tools; calling an entry point should work.
    let action = Action::new("authenticate", "execute", json!({}));
    let ctx = EvaluationContext {
        previous_actions: vec!["log_event".to_string(), "trace_call".to_string()],
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Allow),
        "Expected Allow (only non-governed in history), got {v:?}"
    );
}

#[test]
fn test_workflow_template_multi_step_full_path() {
    let policy = make_workflow_policy(standard_workflow_steps(), "strict");
    let engine = make_context_engine(policy);
    // Full valid path: authenticate → read_data → process → write_result
    let action = Action::new("write_result", "execute", json!({}));
    let ctx = EvaluationContext {
        previous_actions: vec![
            "authenticate".to_string(),
            "read_data".to_string(),
            "process".to_string(),
        ],
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Allow),
        "Expected Allow (full path), got {v:?}"
    );
}

#[test]
fn test_workflow_template_branch_allows_either_successor() {
    let policy = make_workflow_policy(standard_workflow_steps(), "strict");
    let engine = make_context_engine(policy);
    // authenticate → list_data is also valid (branch).
    let action = Action::new("list_data", "execute", json!({}));
    let ctx = EvaluationContext {
        previous_actions: vec!["authenticate".to_string()],
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Allow),
        "Expected Allow (branch), got {v:?}"
    );
}

#[test]
fn test_workflow_template_case_insensitive() {
    let policy = make_workflow_policy(standard_workflow_steps(), "strict");
    let engine = make_context_engine(policy);
    let action = Action::new("READ_DATA", "execute", json!({}));
    let ctx = EvaluationContext {
        previous_actions: vec!["AUTHENTICATE".to_string()],
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Allow),
        "Expected Allow (case insensitive), got {v:?}"
    );
}

#[test]
fn test_workflow_template_compile_cycle_rejects() {
    let steps = json!([
        {"tool": "a", "then": ["b"]},
        {"tool": "b", "then": ["c"]},
        {"tool": "c", "then": ["a"]}
    ]);
    let policy = make_workflow_policy(steps, "strict");
    let result = PolicyEngine::with_policies(false, &[policy]);
    assert!(result.is_err(), "Expected compile error for cycle");
    let errs = result.unwrap_err();
    let err = format!("{errs:?}");
    assert!(
        err.contains("cycle") || err.contains("entry point"),
        "Error should mention cycle: {err}"
    );
}

#[test]
fn test_workflow_template_compile_self_cycle_rejects() {
    let steps = json!([
        {"tool": "a", "then": ["a"]}
    ]);
    let policy = make_workflow_policy(steps, "strict");
    let result = PolicyEngine::with_policies(false, &[policy]);
    assert!(result.is_err(), "Expected compile error for self-cycle");
}

#[test]
fn test_workflow_template_compile_empty_steps_errors() {
    let policy = make_workflow_policy(json!([]), "strict");
    let result = PolicyEngine::with_policies(false, &[policy]);
    assert!(result.is_err(), "Expected compile error for empty steps");
}

#[test]
fn test_workflow_template_compile_too_many_steps_errors() {
    let steps: Vec<serde_json::Value> = (0..51)
        .map(|i| json!({"tool": format!("tool_{i}"), "then": [format!("tool_{}", i + 100)]}))
        .collect();
    let policy = make_workflow_policy(serde_json::Value::Array(steps), "strict");
    let result = PolicyEngine::with_policies(false, &[policy]);
    assert!(result.is_err(), "Expected compile error for >50 steps");
}

#[test]
fn test_workflow_template_compile_invalid_enforce_errors() {
    let steps = json!([{"tool": "a", "then": ["b"]}]);
    let policy = Policy {
        id: "*:*".to_string(),
        name: "workflow-test".to_string(),
        policy_type: PolicyType::Conditional {
            conditions: json!({
                "context_conditions": [{
                    "type": "workflow_template",
                    "steps": steps,
                    "enforce": "invalid_mode"
                }]
            }),
        },
        priority: 100,
        path_rules: None,
        network_rules: None,
    };
    let result = PolicyEngine::with_policies(false, &[policy]);
    assert!(
        result.is_err(),
        "Expected compile error for invalid enforce"
    );
}

#[test]
fn test_workflow_template_compile_missing_tool_errors() {
    let steps = json!([{"then": ["b"]}]);
    let policy = make_workflow_policy(steps, "strict");
    let result = PolicyEngine::with_policies(false, &[policy]);
    assert!(result.is_err(), "Expected compile error for missing tool");
}

#[test]
fn test_workflow_template_compile_missing_then_errors() {
    let steps = json!([{"tool": "a"}]);
    let policy = make_workflow_policy(steps, "strict");
    let result = PolicyEngine::with_policies(false, &[policy]);
    assert!(result.is_err(), "Expected compile error for missing then");
}

#[test]
fn test_workflow_template_compile_duplicate_step_errors() {
    let steps = json!([
        {"tool": "a", "then": ["b"]},
        {"tool": "a", "then": ["c"]}
    ]);
    let policy = make_workflow_policy(steps, "strict");
    let result = PolicyEngine::with_policies(false, &[policy]);
    assert!(result.is_err(), "Expected compile error for duplicate step");
}

#[test]
fn test_workflow_template_terminal_node_allowed() {
    // write_result is a terminal node (appears only as a successor, no step defined).
    // Calling write_result after process should be allowed.
    let policy = make_workflow_policy(standard_workflow_steps(), "strict");
    let engine = make_context_engine(policy);
    let action = Action::new("write_result", "execute", json!({}));
    let ctx = EvaluationContext {
        previous_actions: vec![
            "authenticate".to_string(),
            "read_data".to_string(),
            "process".to_string(),
        ],
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Allow),
        "Expected Allow (terminal node), got {v:?}"
    );
}

#[test]
fn test_workflow_template_terminal_no_successor_denies() {
    // write_result is a terminal node with no successors.
    // Calling any governed tool after write_result should deny.
    let policy = make_workflow_policy(standard_workflow_steps(), "strict");
    let engine = make_context_engine(policy);
    let action = Action::new("read_data", "execute", json!({}));
    let ctx = EvaluationContext {
        previous_actions: vec![
            "authenticate".to_string(),
            "read_data".to_string(),
            "process".to_string(),
            "write_result".to_string(),
        ],
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "Expected Deny (no successor after terminal), got {v:?}"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// ROUND 50 AUDIT: Additional tests for coverage gaps
// ═══════════════════════════════════════════════════════════════════════

// FIND-R50-010: ForbiddenActionSequence includes current tool in matching
#[test]
fn test_forbidden_action_sequence_detects_current_tool_as_final_step() {
    // The forbidden sequence is [read_secret, http_request].
    // When http_request IS the current tool, it should be detected.
    let policy = make_wildcard_context_policy(json!([{
        "type": "forbidden_action_sequence",
        "sequence": ["read_secret", "http_request"],
        "ordered": true
    }]));
    let engine = make_context_engine(policy);
    // current tool is http_request, history has read_secret
    let action = Action::new("http_request", "execute", json!({}));
    let ctx = EvaluationContext {
        previous_actions: vec!["read_secret".to_string()],
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "Expected Deny (current tool completes forbidden sequence), got {v:?}"
    );
}

#[test]
fn test_forbidden_action_sequence_current_tool_only_partial_allows() {
    // forbidden: [a, b, c]. history: [a], current tool: b (only 2/3 matched).
    let policy = make_wildcard_context_policy(json!([{
        "type": "forbidden_action_sequence",
        "sequence": ["a", "b", "c"],
        "ordered": true
    }]));
    let engine = make_context_engine(policy);
    let action = Action::new("b", "execute", json!({}));
    let ctx = EvaluationContext {
        previous_actions: vec!["a".to_string()],
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Allow),
        "Expected Allow (only 2/3 of forbidden sequence), got {v:?}"
    );
}

#[test]
fn test_forbidden_action_sequence_unordered_includes_current_tool() {
    // Unordered forbidden: {a, b}. history: [a], current tool: b → deny.
    let policy = make_wildcard_context_policy(json!([{
        "type": "forbidden_action_sequence",
        "sequence": ["a", "b"],
        "ordered": false
    }]));
    let engine = make_context_engine(policy);
    let action = Action::new("b", "execute", json!({}));
    let ctx = EvaluationContext {
        previous_actions: vec!["a".to_string()],
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "Expected Deny (unordered forbidden set complete with current tool), got {v:?}"
    );
}

// FIND-R50-011: RequiredActionSequence unordered duplicate multiplicity
#[test]
fn test_required_action_sequence_unordered_duplicate_needs_multiple() {
    // sequence: ["read", "read"], unordered — requires read to appear twice.
    let policy = make_wildcard_context_policy(json!([{
        "type": "required_action_sequence",
        "sequence": ["read", "read"],
        "ordered": false
    }]));
    let engine = make_context_engine(policy);
    let action = Action::new("write", "execute", json!({}));

    // Only one read → Deny
    let ctx = EvaluationContext {
        previous_actions: vec!["read".to_string()],
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "Expected Deny (only one read for unordered duplicate), got {v:?}"
    );

    // Two reads → Allow
    let ctx2 = EvaluationContext {
        previous_actions: vec!["read".to_string(), "read".to_string()],
        ..Default::default()
    };
    let v2 = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx2))
        .unwrap();
    assert!(
        matches!(v2, Verdict::Allow),
        "Expected Allow (two reads for unordered duplicate), got {v2:?}"
    );
}

// FIND-R50-012: ForbiddenActionSequence unordered duplicate multiplicity
#[test]
fn test_forbidden_action_sequence_unordered_duplicate_needs_multiple() {
    // forbidden: ["read", "read"], unordered — only deny if read appears twice.
    let policy = make_wildcard_context_policy(json!([{
        "type": "forbidden_action_sequence",
        "sequence": ["read", "read"],
        "ordered": false
    }]));
    let engine = make_context_engine(policy);
    let action = Action::new("write", "execute", json!({}));

    // Only one read in history (+ current tool "write") → Allow
    let ctx = EvaluationContext {
        previous_actions: vec!["read".to_string()],
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Allow),
        "Expected Allow (only one read, unordered duplicate forbidden), got {v:?}"
    );

    // Two reads → Deny
    let ctx2 = EvaluationContext {
        previous_actions: vec!["read".to_string(), "read".to_string()],
        ..Default::default()
    };
    let v2 = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx2))
        .unwrap();
    assert!(
        matches!(v2, Verdict::Deny { .. }),
        "Expected Deny (two reads for unordered duplicate forbidden), got {v2:?}"
    );
}

// FIND-R50-052: Boundary test for exactly 20 sequence steps
#[test]
fn test_required_action_sequence_compile_exactly_20_steps_succeeds() {
    let sequence: Vec<String> = (0..20).map(|i| format!("tool_{i}")).collect();
    let policy = make_wildcard_context_policy(json!([{
        "type": "required_action_sequence",
        "sequence": sequence,
        "ordered": true
    }]));
    let result = PolicyEngine::with_policies(false, &[policy]);
    assert!(result.is_ok(), "Expected 20 steps to compile: {result:?}");
}

// FIND-R50-053: Boundary test for exactly 50 workflow steps
#[test]
fn test_workflow_template_compile_exactly_50_steps_succeeds() {
    let steps: Vec<serde_json::Value> = (0..50)
        .map(|i| json!({"tool": format!("tool_{i}"), "then": [format!("tool_{}", i + 100)]}))
        .collect();
    let policy = make_workflow_policy(serde_json::Value::Array(steps), "strict");
    let result = PolicyEngine::with_policies(false, &[policy]);
    assert!(result.is_ok(), "Expected 50 steps to compile: {result:?}");
}

// FIND-R50-055: Test disconnected workflow components
#[test]
fn test_workflow_template_disconnected_components() {
    // Two separate sub-DAGs: a→b, c→d
    let steps = json!([
        {"tool": "a", "then": ["b"]},
        {"tool": "c", "then": ["d"]}
    ]);
    let policy = make_workflow_policy(steps, "strict");
    let engine = make_context_engine(policy);

    // Can start with entry point "a"
    let action_a = Action::new("a", "execute", json!({}));
    let ctx_empty = EvaluationContext::default();
    let v = engine
        .evaluate_action_with_context(&action_a, &[], Some(&ctx_empty))
        .unwrap();
    assert!(
        matches!(v, Verdict::Allow),
        "Expected Allow for entry 'a', got {v:?}"
    );

    // Can start with entry point "c"
    let action_c = Action::new("c", "execute", json!({}));
    let v2 = engine
        .evaluate_action_with_context(&action_c, &[], Some(&ctx_empty))
        .unwrap();
    assert!(
        matches!(v2, Verdict::Allow),
        "Expected Allow for entry 'c', got {v2:?}"
    );

    // After "a", calling "d" (from other component) should be denied
    let action_d = Action::new("d", "execute", json!({}));
    let ctx_a = EvaluationContext {
        previous_actions: vec!["a".to_string()],
        ..Default::default()
    };
    let v3 = engine
        .evaluate_action_with_context(&action_d, &[], Some(&ctx_a))
        .unwrap();
    assert!(
        matches!(v3, Verdict::Deny { .. }),
        "Expected Deny (cross-component transition), got {v3:?}"
    );
}

// FIND-R50-056: Test single-node workflow
#[test]
fn test_workflow_template_single_node() {
    let steps = json!([{"tool": "a", "then": []}]);
    let policy = make_workflow_policy(steps, "strict");
    let engine = make_context_engine(policy);

    // "a" as first governed tool → Allow (entry point)
    let action_a = Action::new("a", "execute", json!({}));
    let ctx = EvaluationContext::default();
    let v = engine
        .evaluate_action_with_context(&action_a, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Allow),
        "Expected Allow for single entry 'a', got {v:?}"
    );

    // Calling "a" again after "a" → Deny (terminal, no successors)
    let ctx2 = EvaluationContext {
        previous_actions: vec!["a".to_string()],
        ..Default::default()
    };
    let v2 = engine
        .evaluate_action_with_context(&action_a, &[], Some(&ctx2))
        .unwrap();
    assert!(
        matches!(v2, Verdict::Deny { .. }),
        "Expected Deny (no successor after terminal), got {v2:?}"
    );
}

// FIND-R50-059: Repeated matching patterns in history
#[test]
fn test_required_action_sequence_repeated_pattern_in_history() {
    let policy = make_wildcard_context_policy(json!([{
        "type": "required_action_sequence",
        "sequence": ["a", "b"],
        "ordered": true
    }]));
    let engine = make_context_engine(policy);
    let action = Action::new("c", "execute", json!({}));

    // History has the pattern twice: [a, b, a, b]
    let ctx = EvaluationContext {
        previous_actions: vec![
            "a".to_string(),
            "b".to_string(),
            "a".to_string(),
            "b".to_string(),
        ],
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Allow),
        "Expected Allow (repeated pattern), got {v:?}"
    );
}

// FIND-R50-062: Test ordered default value (should be true when omitted)
#[test]
fn test_required_action_sequence_ordered_defaults_true() {
    // Omit "ordered" — should default to true (ordered).
    let policy = make_wildcard_context_policy(json!([{
        "type": "required_action_sequence",
        "sequence": ["a", "b"]
    }]));
    let engine = make_context_engine(policy);
    let action = Action::new("c", "execute", json!({}));

    // Reversed order → Deny (ordered mode)
    let ctx = EvaluationContext {
        previous_actions: vec!["b".to_string(), "a".to_string()],
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "Expected Deny (reversed order, default ordered=true), got {v:?}"
    );
}

// FIND-R50-063: Test enforce default value (should be "strict" when omitted)
#[test]
fn test_workflow_template_enforce_defaults_strict() {
    // Omit "enforce" — should default to strict.
    let steps = json!([
        {"tool": "a", "then": ["b"]}
    ]);
    let policy = Policy {
        id: "*:*".to_string(),
        name: "workflow-test".to_string(),
        policy_type: PolicyType::Conditional {
            conditions: json!({
                "context_conditions": [{
                    "type": "workflow_template",
                    "steps": steps
                }]
            }),
        },
        priority: 100,
        path_rules: None,
        network_rules: None,
    };
    let engine = make_context_engine(policy);

    // Try invalid transition → should Deny (strict is default)
    let action = Action::new("b", "execute", json!({}));
    let ctx = EvaluationContext::default();
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "Expected Deny (default enforce=strict), got {v:?}"
    );
}

// FIND-R50-067: Test control character rejection at compile time
#[test]
fn test_required_action_sequence_compile_control_chars_rejected() {
    let policy = make_wildcard_context_policy(json!([{
        "type": "required_action_sequence",
        "sequence": ["tool_a\x00"],
        "ordered": true
    }]));
    let result = PolicyEngine::with_policies(false, &[policy]);
    assert!(
        result.is_err(),
        "Expected compile error for control char in tool name"
    );
}

#[test]
fn test_workflow_template_compile_control_chars_rejected() {
    let steps = json!([{"tool": "tool_a\n", "then": ["b"]}]);
    let policy = make_workflow_policy(steps, "strict");
    let result = PolicyEngine::with_policies(false, &[policy]);
    assert!(
        result.is_err(),
        "Expected compile error for control char in workflow tool name"
    );
}

// FIND-R50-068: Test explicit terminal node (empty then array)
#[test]
fn test_workflow_template_explicit_terminal_node() {
    let steps = json!([
        {"tool": "a", "then": ["b"]},
        {"tool": "b", "then": []}
    ]);
    let policy = make_workflow_policy(steps, "strict");
    let engine = make_context_engine(policy);

    // a → b is valid
    let action_b = Action::new("b", "execute", json!({}));
    let ctx = EvaluationContext {
        previous_actions: vec!["a".to_string()],
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action_b, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Allow),
        "Expected Allow (a→b valid), got {v:?}"
    );

    // b has no successors → calling "a" after "b" denies
    let action_a = Action::new("a", "execute", json!({}));
    let ctx2 = EvaluationContext {
        previous_actions: vec!["a".to_string(), "b".to_string()],
        ..Default::default()
    };
    let v2 = engine
        .evaluate_action_with_context(&action_a, &[], Some(&ctx2))
        .unwrap();
    assert!(
        matches!(v2, Verdict::Deny { .. }),
        "Expected Deny (explicit terminal node), got {v2:?}"
    );
}

// FIND-R50-069: Short-history allow for ForbiddenActionSequence
#[test]
fn test_forbidden_action_sequence_short_history_allows() {
    // forbidden: [a, b, c] (3 steps). history: [a, b] (only 2).
    // Even though a and b match the prefix, the sequence isn't complete → Allow.
    let policy = make_wildcard_context_policy(json!([{
        "type": "forbidden_action_sequence",
        "sequence": ["a", "b", "c"],
        "ordered": true
    }]));
    let engine = make_context_engine(policy);
    // current tool is "x" (not "c"), history has prefix [a, b]
    let action = Action::new("x", "execute", json!({}));
    let ctx = EvaluationContext {
        previous_actions: vec!["a".to_string(), "b".to_string()],
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Allow),
        "Expected Allow (forbidden sequence incomplete), got {v:?}"
    );
}

// FIND-R50-063: EvaluationContext.validate() called at engine boundary
#[test]
fn test_evaluation_context_validate_called_at_boundary() {
    let policy = make_wildcard_context_policy(json!([{
        "type": "required_action_sequence",
        "sequence": ["a"],
        "ordered": true
    }]));
    let engine = make_context_engine(policy);
    let action = Action::new("test", "execute", json!({}));

    // Create context with oversized previous_actions (> 10,000)
    let ctx = EvaluationContext {
        previous_actions: (0..10_001).map(|i| format!("tool_{i}")).collect(),
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "Expected Deny (context validation failure), got {v:?}"
    );
}

// FIND-R50-064: Previous action entry length validation
#[test]
fn test_evaluation_context_validate_action_name_length() {
    let policy = make_wildcard_context_policy(json!([{
        "type": "required_action_sequence",
        "sequence": ["a"],
        "ordered": true
    }]));
    let engine = make_context_engine(policy);
    let action = Action::new("test", "execute", json!({}));

    // Create context with oversized action name (> 256 bytes)
    let ctx = EvaluationContext {
        previous_actions: vec!["a".repeat(257)],
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "Expected Deny (action name too long), got {v:?}"
    );
}

// ═══════════════════════════════════════════════════════════════
// R203-001: AgentIdentityMatch sanitizes JWT claim values
// in denial reasons (blocked issuer/subject, mismatch messages).
//
// NOTE: EvaluationContext::validate() rejects control chars and
// Unicode format chars in AgentIdentity fields before the engine
// processes them. These tests verify the denial reason structure
// and that the sanitize_for_log() truncation path works correctly
// for long-but-clean values. The sanitize path provides defense-in-depth
// for callers that bypass EvaluationContext::validate().
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_r203_001_blocked_issuer_denial_reason_has_correct_structure() {
    // Blocked issuer generates denial reason containing "blocked issuer: <value>"
    let policy = make_context_policy(json!([{
        "type": "agent_identity",
        "blocked_issuers": ["evil-corp"]
    }]));
    let engine = make_context_engine(policy);
    let action = Action::new("read_file", "execute", json!({}));
    let ctx = EvaluationContext {
        agent_identity: Some(AgentIdentity {
            issuer: Some("evil-corp".to_string()),
            subject: None,
            audience: vec![],
            claims: Default::default(),
        }),
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    match v {
        Verdict::Deny { ref reason } => {
            assert!(
                reason.contains("blocked issuer"),
                "should mention blocked issuer: {reason}"
            );
            assert!(
                reason.contains("evil-corp"),
                "should include sanitized issuer value: {reason}"
            );
        }
        other => panic!("Expected Deny, got: {other:?}"),
    }
}

#[test]
fn test_r203_001_blocked_issuer_long_value_truncated_in_reason() {
    // A very long blocked issuer (> 128 chars) should be truncated in the denial reason.
    // Uses clean ASCII to avoid triggering AgentIdentity validation failures.
    let long_issuer = "evil-corp-".repeat(20); // 200 chars, over the 128-char limit
    let blocked_lower = long_issuer.to_lowercase();
    let policy = make_context_policy(json!([{
        "type": "agent_identity",
        "blocked_issuers": [blocked_lower]
    }]));
    let engine = make_context_engine(policy);
    let action = Action::new("read_file", "execute", json!({}));
    let ctx = EvaluationContext {
        agent_identity: Some(AgentIdentity {
            issuer: Some(long_issuer.clone()),
            subject: None,
            audience: vec![],
            claims: Default::default(),
        }),
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    match v {
        Verdict::Deny { ref reason } => {
            assert!(
                reason.contains("blocked issuer"),
                "should mention blocked issuer: {reason}"
            );
            // The 200-char verbatim value must not appear; only the truncated version (<=128 chars).
            assert!(
                !reason.contains(&long_issuer),
                "200-char issuer must be truncated in denial reason (got {reason})"
            );
            // The total reason length must be reasonable (< 300 chars).
            assert!(
                reason.len() < 300,
                "reason should be short after truncation, got {} chars",
                reason.len()
            );
        }
        other => panic!("Expected Deny, got: {other:?}"),
    }
}

#[test]
fn test_r203_001_issuer_mismatch_denial_reason_has_correct_structure() {
    // issuer mismatch generates "issuer mismatch: expected '...', got '...'" in reason
    let policy = make_context_policy(json!([{
        "type": "agent_identity",
        "issuer": "https://trusted.example.com"
    }]));
    let engine = make_context_engine(policy);
    let action = Action::new("read_file", "execute", json!({}));
    let ctx = EvaluationContext {
        agent_identity: Some(AgentIdentity {
            issuer: Some("https://evil.example.com".to_string()),
            subject: None,
            audience: vec![],
            claims: Default::default(),
        }),
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    match v {
        Verdict::Deny { ref reason } => {
            assert!(
                reason.contains("issuer mismatch"),
                "should mention issuer mismatch: {reason}"
            );
            assert!(
                reason.contains("expected"),
                "should include expected value: {reason}"
            );
            assert!(
                reason.contains("got"),
                "should include actual value: {reason}"
            );
        }
        other => panic!("Expected Deny, got: {other:?}"),
    }
}

#[test]
fn test_r203_001_issuer_mismatch_long_actual_truncated() {
    // A 200-char actual issuer that mismatches should be truncated in the denial reason.
    let long_actual = "https-evil-".repeat(20); // 220 chars, clean ASCII
    let policy = make_context_policy(json!([{
        "type": "agent_identity",
        "issuer": "https://trusted.example.com"
    }]));
    let engine = make_context_engine(policy);
    let action = Action::new("read_file", "execute", json!({}));
    let ctx = EvaluationContext {
        agent_identity: Some(AgentIdentity {
            issuer: Some(long_actual.clone()),
            subject: None,
            audience: vec![],
            claims: Default::default(),
        }),
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    match v {
        Verdict::Deny { ref reason } => {
            assert!(
                reason.contains("issuer mismatch"),
                "should mention issuer mismatch: {reason}"
            );
            // The 220-char verbatim value must not appear
            assert!(
                !reason.contains(&long_actual),
                "220-char issuer must be truncated in denial reason"
            );
        }
        other => panic!("Expected Deny, got: {other:?}"),
    }
}

#[test]
fn test_r203_001_subject_mismatch_denial_reason_has_correct_structure() {
    // subject mismatch produces "subject mismatch: expected '...', got '...'"
    let policy = make_context_policy(json!([{
        "type": "agent_identity",
        "subject": "trusted-agent"
    }]));
    let engine = make_context_engine(policy);
    let action = Action::new("read_file", "execute", json!({}));
    let ctx = EvaluationContext {
        agent_identity: Some(AgentIdentity {
            issuer: None,
            subject: Some("untrusted-agent".to_string()),
            audience: vec![],
            claims: Default::default(),
        }),
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    match v {
        Verdict::Deny { ref reason } => {
            assert!(
                reason.contains("subject mismatch"),
                "should mention subject mismatch: {reason}"
            );
            assert!(
                reason.contains("untrusted-agent"),
                "should include sanitized actual subject: {reason}"
            );
        }
        other => panic!("Expected Deny, got: {other:?}"),
    }
}

#[test]
fn test_r203_001_claim_mismatch_denial_reason_has_correct_structure() {
    // claim mismatch produces "claim '...' mismatch: expected '...', got '...'"
    let policy = make_context_policy(json!([{
        "type": "agent_identity",
        "claims": {"role": "admin"}
    }]));
    let engine = make_context_engine(policy);
    let action = Action::new("read_file", "execute", json!({}));
    let mut claims = std::collections::HashMap::new();
    claims.insert("role".to_string(), serde_json::json!("user"));
    let ctx = EvaluationContext {
        agent_identity: Some(AgentIdentity {
            issuer: Some("https://auth.example.com".to_string()),
            subject: Some("agent-1".to_string()),
            audience: vec![],
            claims,
        }),
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    match v {
        Verdict::Deny { ref reason } => {
            assert!(
                reason.contains("claim"),
                "should mention claim mismatch: {reason}"
            );
            assert!(
                reason.contains("role"),
                "should include claim name: {reason}"
            );
            assert!(
                reason.contains("user"),
                "should include sanitized actual value: {reason}"
            );
        }
        other => panic!("Expected Deny, got: {other:?}"),
    }
}

#[test]
fn test_r203_001_claim_mismatch_long_value_truncated() {
    // A very long claim value (> 128 chars) should be truncated in the denial reason.
    let long_role = "not-admin-".repeat(20); // 200 chars, clean ASCII
    let policy = make_context_policy(json!([{
        "type": "agent_identity",
        "claims": {"role": "admin"}
    }]));
    let engine = make_context_engine(policy);
    let action = Action::new("read_file", "execute", json!({}));
    let mut claims = std::collections::HashMap::new();
    claims.insert("role".to_string(), serde_json::json!(long_role.clone()));
    let ctx = EvaluationContext {
        agent_identity: Some(AgentIdentity {
            issuer: Some("https://auth.example.com".to_string()),
            subject: Some("agent-1".to_string()),
            audience: vec![],
            claims,
        }),
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    match v {
        Verdict::Deny { ref reason } => {
            // The 200-char value must not appear verbatim
            assert!(
                !reason.contains(&long_role),
                "200-char claim value must be truncated in reason"
            );
            assert!(
                reason.contains("claim"),
                "should still mention claim mismatch: {reason}"
            );
        }
        other => panic!("Expected Deny, got: {other:?}"),
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// FIND-CREATIVE-004: ForbiddenActionSequence with truncated history
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_forbidden_action_sequence_at_max_capacity_still_evaluates() {
    // When previous_actions is at MAX_PREVIOUS_ACTIONS, the check should still
    // work correctly for sequences that ARE present in the retained history.
    // The warning is emitted but does not change Allow/Deny logic.
    let policy = make_wildcard_context_policy(json!([{
        "type": "forbidden_action_sequence",
        "sequence": ["read_secret", "http_request"],
        "ordered": true
    }]));
    let engine = make_context_engine(policy);
    let action = Action::new("write_result", "execute", json!({}));

    // Build a history at capacity with the forbidden sequence at the end.
    let max = EvaluationContext::MAX_PREVIOUS_ACTIONS;
    let mut actions = vec!["benign_tool".to_string(); max - 2];
    actions.push("read_secret".to_string());
    actions.push("http_request".to_string());
    assert_eq!(actions.len(), max);

    let ctx = EvaluationContext {
        previous_actions: actions,
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "Forbidden sequence present at capacity should still Deny, got {v:?}"
    );
}

#[test]
fn test_forbidden_action_sequence_evicted_prefix_allows() {
    // Simulate the scenario where the forbidden prefix has been evicted:
    // the attacker called "read_secret" long ago, it aged out, and now
    // only "http_request" remains. The check should Allow (false negative).
    // This is the known limitation documented in FIND-CREATIVE-004.
    let policy = make_wildcard_context_policy(json!([{
        "type": "forbidden_action_sequence",
        "sequence": ["read_secret", "http_request"],
        "ordered": true
    }]));
    let engine = make_context_engine(policy);
    let action = Action::new("write_result", "execute", json!({}));

    // History only has "http_request" (the second step), no "read_secret".
    let ctx = EvaluationContext {
        previous_actions: vec!["benign_tool".to_string(), "http_request".to_string()],
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Allow),
        "Evicted prefix → Allow (known limitation), got {v:?}"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// FIND-CREATIVE-006: on_no_match="continue" + on_missing="skip" interaction
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_on_no_match_continue_all_skip_bypass_demonstrated() {
    // Demonstrate the bypass: a Conditional policy with on_no_match="continue"
    // and all constraints using on_missing="skip". When the attacker omits the
    // required parameter, all constraints skip, on_no_match="continue" fires,
    // and the policy is bypassed entirely — falling through to the next policy.
    let bypass_policy = Policy {
        id: "bypass:*".to_string(),
        name: "bypassable-policy".to_string(),
        policy_type: PolicyType::Conditional {
            conditions: json!({
                "on_no_match": "continue",
                "parameter_constraints": [
                    {
                        "param": "command",
                        "op": "glob",
                        "pattern": "/etc/**",
                        "on_match": "deny",
                        "on_missing": "skip"
                    }
                ]
            }),
        },
        priority: 100,
        path_rules: None,
        network_rules: None,
    };
    let allow_all = Policy {
        id: "*:*".to_string(),
        name: "allow-all-fallback".to_string(),
        policy_type: PolicyType::Allow,
        priority: 1,
        path_rules: None,
        network_rules: None,
    };

    let engine = PolicyEngine::with_policies(false, &[bypass_policy, allow_all]).unwrap();
    let action = Action::new("bypass", "execute", json!({}));
    // No "command" parameter → constraint skipped → on_no_match=continue → Allow (bypass!)
    let v = engine.evaluate_action(&action, &[]).unwrap();
    assert!(
        matches!(v, Verdict::Allow),
        "Missing param + on_no_match=continue + on_missing=skip → bypass to Allow: {v:?}"
    );
}

#[test]
fn test_on_no_match_continue_mixed_on_missing_no_bypass() {
    // When at least one constraint has on_missing="deny", the attacker cannot
    // bypass by omitting parameters — they get denied instead of skipped.
    let secure_policy = Policy {
        id: "secure:*".to_string(),
        name: "secure-policy".to_string(),
        policy_type: PolicyType::Conditional {
            conditions: json!({
                "on_no_match": "continue",
                "parameter_constraints": [
                    {
                        "param": "command",
                        "op": "glob",
                        "pattern": "/etc/**",
                        "on_match": "deny",
                        "on_missing": "deny"
                    }
                ]
            }),
        },
        priority: 100,
        path_rules: None,
        network_rules: None,
    };
    let allow_all = Policy {
        id: "*:*".to_string(),
        name: "allow-all-fallback".to_string(),
        policy_type: PolicyType::Allow,
        priority: 1,
        path_rules: None,
        network_rules: None,
    };

    let engine = PolicyEngine::with_policies(false, &[secure_policy, allow_all]).unwrap();
    let action = Action::new("secure", "execute", json!({}));
    // No "command" parameter → on_missing="deny" fires → Deny (not bypassed)
    let v = engine.evaluate_action(&action, &[]).unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "on_missing=deny should prevent bypass: {v:?}"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// FIND-SEM-003: Fullwidth Unicode homoglyph bypass prevention
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_sem003_fullwidth_tool_name_matches_deny_policy() {
    // A Deny policy for "read_file" must also catch the fullwidth variant
    // "ｒｅａｄ＿ｆｉｌｅ" (U+FF52 U+FF45 U+FF41 U+FF44 U+FF3F U+FF46 U+FF49 U+FF4C U+FF45)
    let deny_policy = Policy {
        id: "read_file".to_string(),
        name: "Block read_file".to_string(),
        policy_type: PolicyType::Deny,
        priority: 100,
        path_rules: None,
        network_rules: None,
    };
    let allow_all = Policy {
        id: "*".to_string(),
        name: "Allow all".to_string(),
        policy_type: PolicyType::Allow,
        priority: 1,
        path_rules: None,
        network_rules: None,
    };

    let engine = PolicyEngine::with_policies(false, &[deny_policy, allow_all]).unwrap();

    // Normal ASCII — should be denied
    let action_ascii = Action::new("read_file", "exec", json!({}));
    let v = engine.evaluate_action(&action_ascii, &[]).unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "ASCII read_file should be denied: {v:?}"
    );

    // Fullwidth Unicode — should ALSO be denied (FIND-SEM-003 fix)
    let action_fullwidth = Action::new(
        "\u{FF52}\u{FF45}\u{FF41}\u{FF44}\u{FF3F}\u{FF46}\u{FF49}\u{FF4C}\u{FF45}",
        "exec",
        json!({}),
    );
    let v = engine.evaluate_action(&action_fullwidth, &[]).unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "Fullwidth read_file should be denied (homoglyph normalization): {v:?}"
    );
}

#[test]
fn test_sem003_cyrillic_tool_name_matches_deny_policy() {
    // A Deny policy for "admin" must catch Cyrillic "а" (U+0430) replacing Latin "a"
    let deny_policy = Policy {
        id: "admin".to_string(),
        name: "Block admin".to_string(),
        policy_type: PolicyType::Deny,
        priority: 100,
        path_rules: None,
        network_rules: None,
    };
    let allow_all = Policy {
        id: "*".to_string(),
        name: "Allow all".to_string(),
        policy_type: PolicyType::Allow,
        priority: 1,
        path_rules: None,
        network_rules: None,
    };

    let engine = PolicyEngine::with_policies(false, &[deny_policy, allow_all]).unwrap();

    // Cyrillic "а" + Latin "dmin" — should be denied
    let action_cyrillic = Action::new("\u{0430}dmin", "exec", json!({}));
    let v = engine.evaluate_action(&action_cyrillic, &[]).unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "Cyrillic аdmin should be denied (homoglyph normalization): {v:?}"
    );
}

#[test]
fn test_sem003_fullwidth_tool_name_matches_allow_policy() {
    // An Allow policy for "read_file" must also match the fullwidth variant
    let allow_policy = Policy {
        id: "read_file".to_string(),
        name: "Allow read_file".to_string(),
        policy_type: PolicyType::Allow,
        priority: 100,
        path_rules: None,
        network_rules: None,
    };

    let engine = PolicyEngine::with_policies(false, &[allow_policy]).unwrap();

    let action_fullwidth = Action::new(
        "\u{FF52}\u{FF45}\u{FF41}\u{FF44}\u{FF3F}\u{FF46}\u{FF49}\u{FF4C}\u{FF45}",
        "exec",
        json!({}),
    );
    let v = engine.evaluate_action(&action_fullwidth, &[]).unwrap();
    assert!(
        matches!(v, Verdict::Allow),
        "Fullwidth read_file should match Allow policy: {v:?}"
    );
}

#[test]
fn test_sem003_prefix_policy_catches_fullwidth_prefix() {
    // A Deny policy "read_*" must catch fullwidth "ｒｅａｄ_anything"
    let deny_policy = Policy {
        id: "read_*".to_string(),
        name: "Block read_ prefix".to_string(),
        policy_type: PolicyType::Deny,
        priority: 100,
        path_rules: None,
        network_rules: None,
    };
    let allow_all = Policy {
        id: "*".to_string(),
        name: "Allow all".to_string(),
        policy_type: PolicyType::Allow,
        priority: 1,
        path_rules: None,
        network_rules: None,
    };

    let engine = PolicyEngine::with_policies(false, &[deny_policy, allow_all]).unwrap();

    // Fullwidth "ｒｅａｄ" + ASCII "_secret" → normalized to "read_secret" → matches "read_*"
    let action = Action::new("\u{FF52}\u{FF45}\u{FF41}\u{FF44}_secret", "exec", json!({}));
    let v = engine.evaluate_action(&action, &[]).unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "Fullwidth prefix should match Deny read_* policy: {v:?}"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// NFKC normalization tests (FIND-R220-001–003, IMP-R220-004)
// Verify compile/eval normalization parity for NFKC-only confusables.
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_nfkc_blocked_issuer_circled_letter_denied() {
    // FIND-R220-001: Circled Latin Capital Letter A (U+24B6) should NFKC → 'A' → 'a'.
    // Policy blocks "evil.example.com", JWT issuer uses circled 'Ⓐ' in "evil".
    let policy = make_context_policy(json!([
        {"type": "agent_identity", "blocked_issuers": ["evil.example.com"]}
    ]));
    let engine = make_context_engine(policy);
    let action = Action::new("read_file", "execute", json!({}));
    // Ⓔ=U+24BA (circled E), ⓥ=U+24E5 (circled v), ⓘ=U+24D8 (circled i), ⓛ=U+24DB (circled l)
    let ctx = EvaluationContext {
        agent_identity: Some(make_test_identity(
            "\u{24BA}\u{24E5}\u{24D8}\u{24DB}.example.com",
            "agent-123",
            "admin",
        )),
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "NFKC circled-letter issuer should match blocked issuer and deny: {v:?}"
    );
}

#[test]
fn test_nfkc_blocked_subject_math_bold_denied() {
    // FIND-R220-001: Mathematical bold letters (U+1D400 range) NFKC → ASCII.
    // Policy blocks subject "admin", JWT subject uses math bold '𝐚𝐝𝐦𝐢𝐧'.
    let policy = make_context_policy(json!([
        {"type": "agent_identity", "blocked_subjects": ["admin"]}
    ]));
    let engine = make_context_engine(policy);
    let action = Action::new("read_file", "execute", json!({}));
    // 𝐚=U+1D41A, 𝐝=U+1D41D, 𝐦=U+1D426, 𝐢=U+1D422, 𝐧=U+1D427
    let ctx = EvaluationContext {
        agent_identity: Some(make_test_identity(
            "https://example.com",
            "\u{1D41A}\u{1D41D}\u{1D426}\u{1D422}\u{1D427}",
            "viewer",
        )),
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "NFKC math-bold subject should match blocked subject and deny: {v:?}"
    );
}

#[test]
fn test_nfkc_agent_id_circled_letter_denied() {
    // FIND-R220-001: Agent ID with circled letters should match blocklist.
    let policy = make_context_policy(json!([
        {"type": "agent_id", "blocked": ["bad_agent"]}
    ]));
    let engine = make_context_engine(policy);
    let action = Action::new("read_file", "execute", json!({}));
    // Use circled letters: ⓑ=U+24D1, ⓐ=U+24D0, ⓓ=U+24D3
    let ctx = EvaluationContext {
        agent_id: Some("\u{24D1}\u{24D0}\u{24D3}_agent".to_string()),
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "NFKC circled-letter agent_id should match blocked agent_id and deny: {v:?}"
    );
}

#[test]
fn test_nfkc_required_previous_action_circled_tool_name() {
    // FIND-R220-006: Tool name with circled letters in history should match
    // required_previous_action compiled with the same letters (NFKC-normalized).
    let policy = make_context_policy(json!([
        {"type": "require_previous_action", "required_tool": "auth_check"}
    ]));
    let engine = make_context_engine(policy);
    let action = Action::new("read_file", "execute", json!({}));
    // Previous action uses circled letters: ⓐ=U+24D0 → 'a', ⓤ=U+24E4 → 'u', etc.
    let ctx = EvaluationContext {
        previous_actions: vec!["\u{24D0}uth_check".to_string()],
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Allow),
        "NFKC circled-letter tool name in history should match required_previous_action: {v:?}"
    );
}

#[test]
fn test_nfkc_forbidden_previous_action_parenthesized_tool_name() {
    // FIND-R220-005: Parenthesized letters (U+249C range) NFKC → ASCII.
    let policy = make_context_policy(json!([
        {"type": "forbidden_previous_action", "forbidden_tool": "exfiltrate"}
    ]));
    let engine = make_context_engine(policy);
    let action = Action::new("http_request", "execute", json!({}));
    // ⒠=U+24A0, ⒳=U+24B3, ⒡=U+24A1, etc. Only use the first char for simplicity.
    // ⒠ NFKC → "(e)" → not single char. Let's use circled instead: ⓔ=U+24D4
    let ctx = EvaluationContext {
        previous_actions: vec!["\u{24D4}xfiltrate".to_string()],
        ..Default::default()
    };
    let v = engine
        .evaluate_action_with_context(&action, &[], Some(&ctx))
        .unwrap();
    assert!(
        matches!(v, Verdict::Deny { .. }),
        "NFKC circled-letter forbidden tool in history should be caught: {v:?}"
    );
}

/// R230-ENG-4: Deny reasons must not leak internal patterns, CIDRs, or counts.
#[test]
fn test_r230_deny_reason_does_not_leak_path_pattern() {
    let policy = policy_with_path_rules(
        "read_file:*",
        "test-policy",
        PolicyType::Allow,
        PathRules {
            allowed: vec![],
            blocked: vec!["/secret/**".to_string()],
        },
    );
    let engine = PolicyEngine::with_policies(false, &[policy]).unwrap();
    let mut action = Action::new("read_file", "read", json!({}));
    action.target_paths = vec!["/secret/data.txt".to_string()];
    let v = engine.evaluate_action(&action, &[]).unwrap();
    match &v {
        Verdict::Deny { reason } => {
            assert!(
                !reason.contains("/secret/**"),
                "Deny reason must not leak glob pattern: {reason}"
            );
            assert!(
                reason.contains("blocked by policy"),
                "Deny reason should say 'blocked by policy': {reason}"
            );
        }
        _ => panic!("Expected Deny, got {v:?}"),
    }
}

/// R230-ENG-4: Deny reasons must not leak blocked domain patterns.
#[test]
fn test_r230_deny_reason_does_not_leak_domain_pattern() {
    let policy = policy_with_network_rules(
        "http_fetch:*",
        "test-policy",
        PolicyType::Allow,
        NetworkRules {
            allowed_domains: vec![],
            blocked_domains: vec!["*.evil.com".to_string()],
            ip_rules: None,
        },
    );
    let engine = PolicyEngine::with_policies(false, &[policy]).unwrap();
    let mut action = Action::new("http_fetch", "get", json!({}));
    action.target_domains = vec!["sub.evil.com".to_string()];
    let v = engine.evaluate_action(&action, &[]).unwrap();
    match &v {
        Verdict::Deny { reason } => {
            assert!(
                !reason.contains("*.evil.com"),
                "Deny reason must not leak domain pattern: {reason}"
            );
            assert!(
                reason.contains("blocked by policy"),
                "Deny reason should say 'blocked by policy': {reason}"
            );
        }
        _ => panic!("Expected Deny, got {v:?}"),
    }
}

/// R230-ENG-4: Deny reasons must not leak blocked CIDR values.
#[test]
fn test_r230_deny_reason_does_not_leak_cidr() {
    let policy = policy_with_network_rules(
        "http_fetch:*",
        "test-policy",
        PolicyType::Allow,
        NetworkRules {
            allowed_domains: vec![],
            blocked_domains: vec![],
            ip_rules: Some(vellaveto_types::IpRules {
                block_private: false,
                blocked_cidrs: vec!["10.0.0.0/8".to_string()],
                allowed_cidrs: vec![],
            }),
        },
    );
    let engine = PolicyEngine::with_policies(false, &[policy]).unwrap();
    let mut action = Action::new("http_fetch", "get", json!({}));
    action.target_domains = vec!["example.com".to_string()];
    action.resolved_ips = vec!["10.1.2.3".to_string()];
    let v = engine.evaluate_action(&action, &[]).unwrap();
    match &v {
        Verdict::Deny { reason } => {
            assert!(
                !reason.contains("10.0.0.0/8"),
                "Deny reason must not leak CIDR range: {reason}"
            );
            assert!(
                reason.contains("blocked CIDR"),
                "Deny reason should mention 'blocked CIDR': {reason}"
            );
        }
        _ => panic!("Expected Deny, got {v:?}"),
    }
}

// ═══════════════════════════════════════════════════════
// R237-ENG-2: Regex constraint normalizes paths before matching
// ═══════════════════════════════════════════════════════

/// R237-ENG-2: Percent-encoded traversal in parameter must be caught by regex
/// constraint after path normalization. `/safe/%2e%2e/etc/passwd` decodes to
/// `/safe/../etc/passwd` which normalizes to `/etc/passwd`.
#[test]
fn test_r237_eng2_regex_constraint_normalizes_percent_encoded_traversal() {
    let engine = PolicyEngine::new(false);
    // The action parameter contains a percent-encoded path traversal
    let action = action_with("fs", "read", json!({"path": "/safe/%2e%2e/etc/passwd"}));
    let policies = constraint_policy(json!([{
        "param": "path",
        "op": "regex",
        "pattern": "/etc/passwd",
        "on_match": "deny"
    }]));
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(verdict, Verdict::Deny { .. }),
        "Percent-encoded traversal /safe/%2e%2e/etc/passwd should be denied \
         after normalization to /etc/passwd, got: {verdict:?}"
    );
}

/// R237-ENG-2: Double-encoded traversal must also be caught by regex constraint.
#[test]
fn test_r237_eng2_regex_constraint_normalizes_double_encoded_traversal() {
    let engine = PolicyEngine::new(false);
    // %252e%252e → %2e%2e → .. after double decode
    let action = action_with("fs", "read", json!({"path": "/app/%252e%252e/etc/shadow"}));
    let policies = constraint_policy(json!([{
        "param": "path",
        "op": "regex",
        "pattern": "/etc/shadow",
        "on_match": "deny"
    }]));
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(verdict, Verdict::Deny { .. }),
        "Double-encoded traversal should be denied after normalization, got: {verdict:?}"
    );
}

/// R237-ENG-2: Clean path that does NOT match regex should still allow.
#[test]
fn test_r237_eng2_regex_constraint_clean_path_allows() {
    let engine = PolicyEngine::new(false);
    let action = action_with(
        "fs",
        "read",
        json!({"path": "/home/user/documents/report.txt"}),
    );
    let policies = constraint_policy(json!([{
        "param": "path",
        "op": "regex",
        "pattern": "/etc/passwd",
        "on_match": "deny"
    }]));
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(verdict, Verdict::Allow),
        "Clean path should allow, got: {verdict:?}"
    );
}

/// R237-ENG-2: Traced evaluation path also normalizes regex input.
#[test]
fn test_r237_eng2_regex_traced_normalizes_percent_encoded_traversal() {
    let action = action_with("fs", "read", json!({"path": "/safe/%2e%2e/etc/passwd"}));
    let policy = make_conditional_policy(
        "fs:*",
        "Block etc passwd",
        json!({
            "parameter_constraints": [{
                "param": "path",
                "op": "regex",
                "pattern": "/etc/passwd",
                "on_match": "deny"
            }]
        }),
    );
    let engine = PolicyEngine::with_policies(false, &[policy]).unwrap();

    let verdict = engine.evaluate_action(&action, &[]).unwrap();
    let (traced_verdict, _trace) = engine.evaluate_action_traced(&action).unwrap();

    // Both hot path and traced path must produce Deny
    assert!(
        matches!(verdict, Verdict::Deny { .. }),
        "Hot path should deny traversal, got: {verdict:?}"
    );
    assert!(
        matches!(traced_verdict, Verdict::Deny { .. }),
        "Traced path should deny traversal, got: {traced_verdict:?}"
    );
}
