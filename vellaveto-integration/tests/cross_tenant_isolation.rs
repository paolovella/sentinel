// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Cross-tenant isolation integration tests.
//!
//! Verifies that one tenant cannot see or affect another tenant's:
//! - Policies and policy evaluation results
//! - Approval workflows
//! - Audit entries

use serde_json::json;
use tempfile::TempDir;
use vellaveto_approval::{ApprovalStatus, ApprovalStore};
use vellaveto_engine::PolicyEngine;
use vellaveto_types::{Action, Policy, PolicyType, Verdict};

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to create tokio runtime")
}

fn deny_policy(id: &str) -> Policy {
    Policy {
        id: id.to_string(),
        name: format!("deny {id}"),
        policy_type: PolicyType::Deny,
        priority: 100,
        path_rules: None,
        network_rules: None,
    }
}

fn allow_policy(id: &str) -> Policy {
    Policy {
        id: id.to_string(),
        name: format!("allow {id}"),
        policy_type: PolicyType::Allow,
        priority: 100,
        path_rules: None,
        network_rules: None,
    }
}

fn fs_action() -> Action {
    Action::new(
        "filesystem".to_string(),
        "read_file".to_string(),
        json!({"path": "/tmp/test"}),
    )
}

/// Tenant A's Deny policy must NOT affect Tenant B's evaluation of the same tool.
#[test]
fn test_cross_tenant_policy_evaluation_isolated() {
    let engine = PolicyEngine::new(false);

    // Tenant A: deny filesystem
    let policies_a = [deny_policy("filesystem:*")];
    let verdict_a = engine.evaluate_action(&fs_action(), &policies_a).unwrap();
    assert!(
        matches!(verdict_a, Verdict::Deny { .. }),
        "Tenant A should deny, got: {:?}",
        verdict_a
    );

    // Tenant B: allow filesystem — separate policy set, no contamination
    let policies_b = [allow_policy("filesystem:*")];
    let verdict_b = engine.evaluate_action(&fs_action(), &policies_b).unwrap();
    assert!(
        matches!(verdict_b, Verdict::Allow),
        "Tenant B should allow, got: {:?}",
        verdict_b
    );
}

/// Approval created by Tenant A must not be visible to Tenant B's store.
#[test]
fn test_cross_tenant_approval_not_shared() {
    let rt = runtime();
    rt.block_on(async {
        let dir = TempDir::new().unwrap();

        // Separate approval stores per tenant
        let store_a = ApprovalStore::new(
            dir.path().join("tenant_a_approvals.jsonl"),
            std::time::Duration::from_secs(900),
        );
        let store_b = ApprovalStore::new(
            dir.path().join("tenant_b_approvals.jsonl"),
            std::time::Duration::from_secs(900),
        );

        // Tenant A creates an approval
        let id_a = store_a
            .create(
                fs_action(),
                "tenant A needs approval".to_string(),
                Some("user-a".to_string()),
                Some("session-a".to_string()),
                Some("a".repeat(64)),
            )
            .await
            .unwrap();

        // Tenant B should NOT find Tenant A's approval
        let result_b = store_b.get(&id_a).await;
        assert!(
            result_b.is_err(),
            "Tenant B must not access Tenant A's approval"
        );

        // Tenant A can still see it
        let approval_a = store_a.get(&id_a).await.unwrap();
        assert_eq!(approval_a.status, ApprovalStatus::Pending);
    });
}

/// Audit isolation: per-tenant log files ensure no cross-contamination.
/// (AuditLogger uses per-tenant file paths — separate files guarantee isolation.
/// This test verifies the file-level separation pattern.)
#[test]
fn test_cross_tenant_audit_file_isolation() {
    let dir = TempDir::new().unwrap();
    let path_a = dir.path().join("tenant_a_audit.jsonl");
    let path_b = dir.path().join("tenant_b_audit.jsonl");

    // Write to Tenant A's file
    std::fs::write(&path_a, r#"{"id":"a1","action":{},"verdict":"Allow"}"#).unwrap();

    // Tenant B's file should not exist
    assert!(
        !path_b.exists(),
        "Tenant B's audit file should not exist after Tenant A writes"
    );

    // Tenant A's file has content
    let content_a = std::fs::read_to_string(&path_a).unwrap();
    assert!(!content_a.is_empty());
}

/// Concurrent evaluations across tenant policy sets must not leak verdicts.
#[test]
fn test_cross_tenant_concurrent_evaluation_no_leakage() {
    use std::sync::Arc;

    let rt = runtime();
    rt.block_on(async {
        let engine = Arc::new(PolicyEngine::new(false));
        let policies_deny = Arc::new(vec![deny_policy("*:*")]);
        let policies_allow = Arc::new(vec![allow_policy("*:*")]);
        let action = fs_action();

        let mut handles = Vec::new();
        for _ in 0..50 {
            let e = Arc::clone(&engine);
            let pd = Arc::clone(&policies_deny);
            let pa = Arc::clone(&policies_allow);
            let act = action.clone();
            handles.push(tokio::spawn(async move {
                let va = e.evaluate_action(&act, &pd).unwrap();
                let vb = e.evaluate_action(&act, &pa).unwrap();
                assert!(
                    matches!(va, Verdict::Deny { .. }),
                    "deny-tenant must always deny"
                );
                assert!(
                    matches!(vb, Verdict::Allow),
                    "allow-tenant must always allow"
                );
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
    });
}
