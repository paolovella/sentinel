// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Tests for conditional policies where NO condition is triggered.
//! When a conditional policy matches an action but:
//! - require_approval is false or absent
//! - no forbidden_parameters match
//! - no required_parameters are missing
//!
//! The result should be Verdict::Allow (the fall-through default).
//! This documents a potentially surprising security behavior.

use serde_json::json;
use vellaveto_engine::PolicyEngine;
use vellaveto_types::{Action, Policy, PolicyType, Verdict};

fn make_action(tool: &str, function: &str, params: serde_json::Value) -> Action {
    Action::new(tool.to_string(), function.to_string(), params)
}

fn conditional_policy(id: &str, priority: i32, conditions: serde_json::Value) -> Policy {
    Policy {
        id: id.to_string(),
        name: format!("cond-{id}"),
        policy_type: PolicyType::Conditional { conditions },
        priority,
        path_rules: None,
        network_rules: None,
    }
}

fn deny_policy(id: &str, priority: i32) -> Policy {
    Policy {
        id: id.to_string(),
        name: format!("deny-{id}"),
        policy_type: PolicyType::Deny,
        priority,
        path_rules: None,
        network_rules: None,
    }
}

// ═══════════════════════════════════
// EMPTY CONDITIONS OBJECT → ALLOW
// ═══════════════════════════════════

/// A conditional policy with `{}` conditions has no rules to trigger.
/// Fall-through is Allow. This is arguably a security concern.
#[test]
fn empty_conditions_object_allows_action() {
    let engine = PolicyEngine::new(false);
    let action = make_action("bash", "rm_rf", json!({"target": "/"}));
    let policies = vec![conditional_policy("*", 100, json!({}))];
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(result, Verdict::Allow),
        "Empty conditions should fall through to Allow — SECURITY NOTE: this is permissive"
    );
}

/// Multiple empty conditional policies, all pass through to Allow.
#[test]
fn multiple_empty_conditionals_all_allow() {
    let engine = PolicyEngine::new(false);
    let action = make_action("bash", "exec", json!({}));
    let policies = vec![
        conditional_policy("*", 100, json!({})),
        conditional_policy("*", 50, json!({})),
        conditional_policy("*", 1, json!({})),
    ];
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(result, Verdict::Allow));
}

// ═══════════════════════════════════
// REQUIRE_APPROVAL = FALSE → ALLOW
// ═══════════════════════════════════

/// Explicit require_approval: false should not trigger RequireApproval.
#[test]
fn require_approval_false_allows() {
    let engine = PolicyEngine::new(false);
    let action = make_action("bash", "exec", json!({}));
    let policies = vec![conditional_policy(
        "*",
        100,
        json!({
            "require_approval": false
        }),
    )];
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(result, Verdict::Allow));
}

/// FIND-IMP-013: Non-boolean require_approval fails closed → RequireApproval.
/// The source uses `as_bool().unwrap_or(true)` (fail-closed).
#[test]
fn require_approval_string_true_fails_closed() {
    let engine = PolicyEngine::new(false);
    let action = make_action("bash", "exec", json!({}));
    let policies = vec![conditional_policy(
        "*",
        100,
        json!({
            "require_approval": "true"  // string, not boolean
        }),
    )];
    let result = engine.evaluate_action(&action, &policies).unwrap();
    // as_bool() on "true" returns None → unwrap_or(true) → fail-closed to RequireApproval
    assert!(
        matches!(result, Verdict::RequireApproval { .. }),
        "Non-boolean require_approval should fail-closed to RequireApproval, got {result:?}"
    );
}

/// FIND-IMP-013: Integer require_approval fails closed → RequireApproval.
#[test]
fn require_approval_integer_one_fails_closed() {
    let engine = PolicyEngine::new(false);
    let action = make_action("bash", "exec", json!({}));
    let policies = vec![conditional_policy(
        "*",
        100,
        json!({
            "require_approval": 1
        }),
    )];
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(result, Verdict::RequireApproval { .. }),
        "Non-boolean require_approval should fail-closed to RequireApproval, got {result:?}"
    );
}

// ═══════════════════════════════════
// FORBIDDEN_PARAMETERS: NONE PRESENT
// ═══════════════════════════════════

/// Forbidden params listed but action doesn't have any of them → Allow.
#[test]
fn forbidden_params_not_present_allows() {
    let engine = PolicyEngine::new(false);
    let action = make_action("tool", "func", json!({"safe_key": "value"}));
    let policies = vec![conditional_policy(
        "*",
        100,
        json!({
            "forbidden_parameters": ["danger", "evil", "bad"]
        }),
    )];
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(result, Verdict::Allow));
}

/// Forbidden params as empty array → nothing to check → Allow.
#[test]
fn empty_forbidden_params_array_allows() {
    let engine = PolicyEngine::new(false);
    let action = make_action("tool", "func", json!({"any": "param"}));
    let policies = vec![conditional_policy(
        "*",
        100,
        json!({
            "forbidden_parameters": []
        }),
    )];
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(result, Verdict::Allow));
}

// ═══════════════════════════════════
// REQUIRED_PARAMETERS: ALL PRESENT
// ═══════════════════════════════════

/// All required params present → Allow.
#[test]
fn all_required_params_present_allows() {
    let engine = PolicyEngine::new(false);
    let action = make_action(
        "tool",
        "func",
        json!({
            "token": "abc123",
            "user": "admin"
        }),
    );
    let policies = vec![conditional_policy(
        "*",
        100,
        json!({
            "required_parameters": ["token", "user"]
        }),
    )];
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(result, Verdict::Allow));
}

/// Empty required params array → nothing to check → Allow.
#[test]
fn empty_required_params_array_allows() {
    let engine = PolicyEngine::new(false);
    let action = make_action("tool", "func", json!({}));
    let policies = vec![conditional_policy(
        "*",
        100,
        json!({
            "required_parameters": []
        }),
    )];
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(matches!(result, Verdict::Allow));
}

// ═══════════════════════════════════
// UNKNOWN-ONLY CONDITION KEYS FAIL CLOSED
// ════════════════════════════════════

/// Conditions with only unrecognized keys are denied instead of silently
/// allowing everything.
#[test]
fn unknown_only_condition_keys_denied_fail_closed() {
    let engine = PolicyEngine::new(false);
    let action = make_action("bash", "rm_rf", json!({"target": "/"}));
    let policies = vec![conditional_policy(
        "*",
        1000,
        json!({
            "requir_approval": true,  // typo: missing 'e'
            "forbiden_parameters": ["target"]  // typo: missing 'd'
        }),
    )];
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(result, Verdict::Deny { .. }),
        "Typos in condition keys should fail closed, got {result:?}"
    );
}

/// Conditions with non-standard types for known keys.
/// forbidden_parameters as a string instead of array → silently skipped.
#[test]
fn forbidden_parameters_as_string_denied_fail_closed() {
    // R231-ENG-3: Non-array forbidden_parameters → fail-closed Deny
    let engine = PolicyEngine::new(false);
    let action = make_action("tool", "func", json!({"danger": true}));
    let policies = vec![conditional_policy(
        "*",
        100,
        json!({
            "forbidden_parameters": "danger"  // string, not array
        }),
    )];
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(result, Verdict::Deny { .. }),
        "String forbidden_parameters should fail-closed (Deny)"
    );
}

/// R231-ENG-3: required_parameters as an object instead of array → fail-closed Deny.
#[test]
fn required_parameters_as_object_denied_fail_closed() {
    let engine = PolicyEngine::new(false);
    let action = make_action("tool", "func", json!({})); // missing everything
    let policies = vec![conditional_policy(
        "*",
        100,
        json!({
            "required_parameters": {"token": true}  // object, not array
        }),
    )];
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(result, Verdict::Deny { .. }),
        "Object required_parameters should fail-closed (Deny)"
    );
}

// ═══════════════════════════════════
// CONDITIONAL PASSTHROUGH VS LOWER-PRIORITY DENY
// ═══════════════════════════════════

/// High-priority conditional that passes through to Allow
/// prevents a lower-priority Deny from ever being reached.
#[test]
fn conditional_passthrough_shadows_lower_deny() {
    let engine = PolicyEngine::new(false);
    let action = make_action("bash", "exec", json!({}));
    let policies = vec![
        conditional_policy("*", 100, json!({})), // passes through  Allow
        deny_policy("*", 50),                    // never reached
    ];
    let result = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(result, Verdict::Allow),
        "High-priority conditional passthrough should shadow lower-priority deny"
    );
}
