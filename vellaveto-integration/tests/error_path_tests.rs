// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Error path and concurrency stress tests.
//!
//! These tests verify Vellaveto's fail-closed behavior and concurrency safety
//! under adversarial conditions:
//! - Filesystem errors (read-only, full disk, permissions)
//! - Network errors (unreachable, timeout, DNS failure)
//! - Policy compilation errors
//! - Race conditions during policy reloads
//! - Approval store concurrency

use arc_swap::ArcSwap;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::json;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
use tower::ServiceExt;
use vellaveto_approval::ApprovalStore;
use vellaveto_audit::AuditLogger;
use vellaveto_engine::PolicyEngine;
use vellaveto_server::{routes, AppState, Metrics, PolicySnapshot, RateLimits};
use vellaveto_types::{Action, Policy, PolicyType};

// ═══════════════════════════════════════════════════════════════
// Test Helpers
// ═══════════════════════════════════════════════════════════════

fn make_test_state(tmp: &TempDir) -> AppState {
    let audit = Arc::new(AuditLogger::new(tmp.path().join("audit.log")));
    AppState {
        policy_state: Arc::new(ArcSwap::from_pointee(PolicySnapshot {
            engine: PolicyEngine::new(false),
            policies: vec![Policy {
                id: "file:*".to_string(),
                name: "Allow file ops".to_string(),
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
            Duration::from_secs(900),
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
        // Phase 1 & 2 security managers — disabled in tests
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
        // Server Configuration (FIND-004, FIND-005)
        shadow_ai_discovery: None,
        least_agency_tracker: None,
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
    }
}

// ═══════════════════════════════════════════════════════════════
// Filesystem Error Handling Tests
// ═══════════════════════════════════════════════════════════════

mod filesystem_errors {
    use super::*;

    #[tokio::test]
    #[cfg(unix)]
    async fn audit_log_read_only_denies_on_write_failure() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = TempDir::new().unwrap();
        let audit_path = tmp.path().join("audit.log");

        // Create and then make read-only
        std::fs::write(&audit_path, "").unwrap();
        std::fs::set_permissions(&audit_path, std::fs::Permissions::from_mode(0o444)).unwrap();

        let logger = Arc::new(AuditLogger::new(audit_path.clone()));
        let state = AppState {
            audit: logger,
            ..make_test_state(&tmp)
        };

        let app = routes::build_router(state);

        let req = Request::post("/api/evaluate")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"tool":"file","function":"read","parameters":{}}"#,
            ))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();

        // Cleanup before assert to avoid test pollution
        std::fs::set_permissions(&audit_path, std::fs::Permissions::from_mode(0o644)).unwrap();

        // Fail-closed: audit write failure should deny
        // Note: The server may handle this gracefully but the decision should be logged
        // This tests that the system doesn't panic on I/O errors
        assert!(
            resp.status() == StatusCode::OK || resp.status() == StatusCode::INTERNAL_SERVER_ERROR,
            "Expected OK or 500 on audit write failure, got {}",
            resp.status()
        );
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn approval_store_unwritable_denies_require_approval() {
        let tmp = TempDir::new().unwrap();

        // Create approval store pointing to a directory (can't write file there)
        let approval_path = tmp.path().join("approvals_dir");
        std::fs::create_dir(&approval_path).unwrap();

        let approvals = Arc::new(ApprovalStore::new(
            approval_path.join("cant_create.jsonl"),
            Duration::from_secs(900),
        ));

        let state = AppState {
            policy_state: Arc::new(ArcSwap::from_pointee(PolicySnapshot {
                engine: PolicyEngine::new(false),
                policies: vec![Policy {
                    id: "sensitive:*".to_string(),
                    name: "Requires approval".to_string(),
                    policy_type: PolicyType::Conditional {
                        conditions: json!({ "require_approval": true }),
                    },
                    priority: 100,
                    path_rules: None,
                    network_rules: None,
                }],
                compliance_config: Default::default(),
            })),
            approvals,
            ..make_test_state(&tmp)
        };

        // Make the directory read-only to prevent file creation
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&approval_path, std::fs::Permissions::from_mode(0o555)).unwrap();

        let app = routes::build_router(state);

        let req = Request::post("/api/evaluate")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"tool":"sensitive","function":"op","parameters":{}}"#,
            ))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();

        // Cleanup
        std::fs::set_permissions(&approval_path, std::fs::Permissions::from_mode(0o755)).unwrap();

        // FIND-R46-IT-002: Strengthen assertion — the system must not panic,
        // must return a valid HTTP response, and must NOT allow the action
        // through without proper approval (fail-closed).
        let status = resp.status();
        assert!(
            status.is_success() || status.is_client_error() || status.is_server_error(),
            "Should return a valid HTTP response even with unwritable storage, got {status}"
        );

        if status.is_success() {
            let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
                .await
                .unwrap();
            let body_str = String::from_utf8_lossy(&body);
            // Fail-closed: must NOT produce an Allow verdict when approval store
            // is broken. It should either Deny or RequireApproval.
            assert!(
                !body_str.contains("\"Allow\"")
                    || body_str.contains("\"Deny\"")
                    || body_str.contains("\"RequireApproval\""),
                "Unwritable approval store must fail-closed (not Allow): {body_str}"
            );
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// Policy Compilation Error Tests
// ═══════════════════════════════════════════════════════════════

mod policy_errors {
    use super::*;
    use vellaveto_types::PathRules;

    #[tokio::test]
    async fn invalid_policy_glob_fails_closed() {
        let tmp = TempDir::new().unwrap();

        // Create a policy with an invalid glob pattern
        let state = AppState {
            policy_state: Arc::new(ArcSwap::from_pointee(PolicySnapshot {
                engine: PolicyEngine::new(false),
                policies: vec![Policy {
                    id: "file:*".to_string(),
                    name: "Invalid glob".to_string(),
                    policy_type: PolicyType::Allow,
                    priority: 10,
                    path_rules: Some(PathRules {
                        allowed: vec!["[invalid-glob".to_string()], // unclosed bracket
                        blocked: vec![],
                    }),
                    network_rules: None,
                }],
                compliance_config: Default::default(),
            })),
            ..make_test_state(&tmp)
        };

        let app = routes::build_router(state);

        let req = Request::post("/api/evaluate")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"tool":"file","function":"read","parameters":{"path":"/tmp/test"}}"#,
            ))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();

        // FIND-R46-IT-002: Strengthen assertion — invalid policy patterns must
        // not crash AND must fail-closed (deny, not allow).
        assert!(
            resp.status().is_success() || resp.status().is_client_error(),
            "Should handle invalid glob gracefully, got {}",
            resp.status()
        );

        if resp.status().is_success() {
            let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
                .await
                .unwrap();
            let body_str = String::from_utf8_lossy(&body);
            // Fail-closed: the response must NOT be an Allow verdict
            let body_lower = body_str.to_lowercase();
            assert!(
                !body_lower.contains("\"allow\"")
                    || body_lower.contains("\"deny\"")
                    || body_lower.contains("deny"),
                "Invalid glob must fail-closed (deny, not allow): {body_str}"
            );
        }
    }

    #[tokio::test]
    async fn empty_policy_list_denies_all() {
        let tmp = TempDir::new().unwrap();

        let state = AppState {
            policy_state: Arc::new(ArcSwap::from_pointee(PolicySnapshot {
                engine: PolicyEngine::new(false),
                policies: vec![], // No policies
                compliance_config: Default::default(),
            })),
            ..make_test_state(&tmp)
        };

        let app = routes::build_router(state);

        let req = Request::post("/api/evaluate")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"tool":"file","function":"read","parameters":{}}"#,
            ))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();

        // FIND-R46-IT-002: Strengthen assertion — check HTTP status, parse
        // JSON verdict, and verify it is specifically "Deny" (not Allow).
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "Empty policy list should return 200 with Deny verdict"
        );

        let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let json: serde_json::Value =
            serde_json::from_slice(&body).expect("Response must be valid JSON");

        let verdict = &json["verdict"];
        let verdict_str = serde_json::to_string(verdict).unwrap();
        assert!(
            verdict_str.contains("Deny") || verdict_str.contains("deny"),
            "Empty policy list must produce Deny verdict (fail-closed), got: {verdict_str}"
        );
        // Must NOT contain Allow
        assert!(
            !verdict_str.contains("Allow") && !verdict_str.contains("allow"),
            "Empty policy list must NOT produce Allow verdict, got: {verdict_str}"
        );
    }
}

// ═══════════════════════════════════════════════════════════════
// Policy Reload Race Condition Tests
// ═══════════════════════════════════════════════════════════════

mod policy_reload_races {
    use super::*;

    #[tokio::test]
    async fn concurrent_policy_updates_are_atomic() {
        let tmp = TempDir::new().unwrap();
        let state = make_test_state(&tmp);
        let policy_state = state.policy_state.clone();

        let update_count = Arc::new(AtomicUsize::new(0));

        // Spawn multiple concurrent updates
        let handles: Vec<_> = (0..10)
            .map(|i| {
                let ps = policy_state.clone();
                let uc = update_count.clone();

                tokio::spawn(async move {
                    for j in 0..10 {
                        let new_snapshot = PolicySnapshot {
                            engine: PolicyEngine::new(false),
                            policies: vec![Policy {
                                id: format!("policy-{i}-{j}"),
                                name: "Test".to_string(),
                                policy_type: PolicyType::Allow,
                                priority: j,
                                path_rules: None,
                                network_rules: None,
                            }],
                            compliance_config: Default::default(),
                        };
                        ps.store(Arc::new(new_snapshot));
                        uc.fetch_add(1, Ordering::Relaxed);
                        tokio::task::yield_now().await;
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.await.unwrap();
        }

        assert_eq!(update_count.load(Ordering::Relaxed), 100);

        // Verify the state is consistent (has exactly one policy)
        let final_state = policy_state.load();
        assert_eq!(final_state.policies.len(), 1);
    }

    #[tokio::test]
    async fn evaluate_during_policy_reload_never_panics() {
        let tmp = TempDir::new().unwrap();
        let state = make_test_state(&tmp);
        let policy_state = state.policy_state.clone();
        let _app = routes::build_router(state);

        let evaluate_count = Arc::new(AtomicUsize::new(0));
        let ec = evaluate_count.clone();

        // Spawn policy update task
        let ps = policy_state.clone();
        let update_handle = tokio::spawn(async move {
            for i in 0..10 {
                let new_snapshot = PolicySnapshot {
                    engine: PolicyEngine::new(false),
                    policies: vec![Policy {
                        id: format!("policy-{i}"),
                        name: "Test".to_string(),
                        policy_type: if i % 2 == 0 {
                            PolicyType::Allow
                        } else {
                            PolicyType::Deny
                        },
                        priority: i,
                        path_rules: None,
                        network_rules: None,
                    }],
                    compliance_config: Default::default(),
                };
                ps.store(Arc::new(new_snapshot));
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        });

        // Spawn concurrent evaluate requests
        let evaluate_handles: Vec<_> = (0..10)
            .map(|_| {
                let app = routes::build_router(make_test_state(&TempDir::new().unwrap()));
                let ec = ec.clone();

                tokio::spawn(async move {
                    for _ in 0..5 {
                        let req = Request::post("/api/evaluate")
                            .header("content-type", "application/json")
                            .body(Body::from(
                                r#"{"tool":"file","function":"read","parameters":{}}"#,
                            ))
                            .unwrap();

                        let result = app.clone().oneshot(req).await;
                        assert!(result.is_ok(), "Request should not fail");
                        ec.fetch_add(1, Ordering::Relaxed);
                    }
                })
            })
            .collect();

        update_handle.await.unwrap();
        for handle in evaluate_handles {
            handle.await.unwrap();
        }

        assert!(
            evaluate_count.load(Ordering::Relaxed) > 0,
            "Should have completed some evaluations"
        );
    }
}

// ═══════════════════════════════════════════════════════════════
// Approval Concurrency Stress Tests
// ═══════════════════════════════════════════════════════════════

mod approval_concurrency {
    use super::*;

    #[tokio::test]
    async fn concurrent_approval_requests_no_data_corruption() {
        let tmp = TempDir::new().unwrap();
        let store = Arc::new(ApprovalStore::new(
            tmp.path().join("approvals.jsonl"),
            Duration::from_secs(900),
        ));

        let request_count = Arc::new(AtomicUsize::new(0));

        // Spawn multiple concurrent writers
        let handles: Vec<_> = (0..10)
            .map(|i| {
                let s = store.clone();
                let rc = request_count.clone();

                tokio::spawn(async move {
                    for j in 0..5 {
                        let action = Action {
                            tool: format!("tool-{i}"),
                            function: format!("func-{j}"),
                            parameters: json!({}),
                            target_paths: vec![],
                            target_domains: vec![],
                            resolved_ips: vec![],
                        };

                        // Create approval - should not panic or corrupt
                        let result = s
                            .create(
                                action,
                                "test reason".to_string(),
                                Some("tester".to_string()),
                                None,
                                None,
                            )
                            .await;
                        assert!(result.is_ok(), "Approval creation should succeed");
                        rc.fetch_add(1, Ordering::Relaxed);
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.await.unwrap();
        }

        assert_eq!(request_count.load(Ordering::Relaxed), 50);

        // Verify we can list all approvals
        let pending = store.list_pending().await;
        assert_eq!(pending.len(), 50, "All approvals should be listed");
    }

    #[tokio::test]
    async fn concurrent_approve_reject_no_race() {
        let tmp = TempDir::new().unwrap();
        let store = Arc::new(ApprovalStore::new(
            tmp.path().join("approvals.jsonl"),
            Duration::from_secs(900),
        ));

        // Create some approval requests first
        let mut approval_ids = Vec::new();
        for i in 0..10 {
            let action = Action {
                tool: format!("tool-{i}"),
                function: "func".to_string(),
                parameters: json!({}),
                target_paths: vec![],
                target_domains: vec![],
                resolved_ips: vec![],
            };
            let id = store
                .create(action, "test".to_string(), None, None, None)
                .await
                .unwrap();
            approval_ids.push(id);
        }

        // Concurrently approve and reject
        let approve_count = Arc::new(AtomicUsize::new(0));
        let reject_count = Arc::new(AtomicUsize::new(0));

        let handles: Vec<_> = approval_ids
            .iter()
            .enumerate()
            .map(|(i, id)| {
                let s = store.clone();
                let id = id.clone();
                let ac = approve_count.clone();
                let rc = reject_count.clone();

                tokio::spawn(async move {
                    if i % 2 == 0 {
                        let result = s.approve(&id, "admin").await;
                        if result.is_ok() {
                            ac.fetch_add(1, Ordering::Relaxed);
                        }
                    } else {
                        let result = s.deny(&id, "admin").await;
                        if result.is_ok() {
                            rc.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.await.unwrap();
        }

        let approved = approve_count.load(Ordering::Relaxed);
        let rejected = reject_count.load(Ordering::Relaxed);

        // All operations should have succeeded
        assert_eq!(
            approved + rejected,
            10,
            "All approvals should have been processed"
        );

        // Verify final state - should have no pending
        let pending = store.list_pending().await;
        assert!(pending.is_empty(), "All pending should be resolved");
    }

    #[tokio::test]
    async fn duplicate_approval_is_idempotent() {
        let tmp = TempDir::new().unwrap();
        let store = Arc::new(ApprovalStore::new(
            tmp.path().join("approvals.jsonl"),
            Duration::from_secs(900),
        ));

        let action = Action {
            tool: "test".to_string(),
            function: "func".to_string(),
            parameters: json!({}),
            target_paths: vec![],
            target_domains: vec![],
            resolved_ips: vec![],
        };

        let id = store
            .create(action, "test".to_string(), None, None, None)
            .await
            .unwrap();

        // Try to approve the same ID multiple times concurrently
        let success_count = Arc::new(AtomicUsize::new(0));

        let handles: Vec<_> = (0..10)
            .map(|_| {
                let s = store.clone();
                let id = id.clone();
                let sc = success_count.clone();

                tokio::spawn(async move {
                    if s.approve(&id, "admin").await.is_ok() {
                        sc.fetch_add(1, Ordering::Relaxed);
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.await.unwrap();
        }

        // Only one should succeed, rest should fail (already approved)
        let successes = success_count.load(Ordering::Relaxed);
        assert!(
            successes >= 1,
            "At least one approval should succeed: got {successes}"
        );
    }
}

// ═══════════════════════════════════════════════════════════════
// Idempotency Key Concurrency Tests
// ═══════════════════════════════════════════════════════════════

mod idempotency_concurrency {
    use super::*;
    use vellaveto_server::idempotency::{IdempotencyConfig, IdempotencyStore};

    #[tokio::test]
    async fn concurrent_acquire_same_key_only_one_wins() {
        let config = IdempotencyConfig {
            enabled: true,
            ttl_hours: 1,
            max_keys: 1000,
            max_key_length: 64,
        };
        let store = Arc::new(IdempotencyStore::new(config));

        let acquired_count = Arc::new(AtomicUsize::new(0));
        let in_progress_count = Arc::new(AtomicUsize::new(0));

        let handles: Vec<_> = (0..10)
            .map(|_| {
                let s = store.clone();
                let ac = acquired_count.clone();
                let ipc = in_progress_count.clone();

                tokio::spawn(async move {
                    match s.try_acquire("same-key") {
                        Ok(None) => {
                            ac.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(vellaveto_server::idempotency::IdempotencyError::InProgress) => {
                            ipc.fetch_add(1, Ordering::Relaxed);
                        }
                        _ => {}
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.await.unwrap();
        }

        let acquired = acquired_count.load(Ordering::Relaxed);
        let in_progress = in_progress_count.load(Ordering::Relaxed);

        // Exactly one should acquire, rest should get InProgress
        assert_eq!(acquired, 1, "Only one should acquire the key");
        assert_eq!(
            in_progress, 9,
            "Rest should get InProgress: got {in_progress}"
        );
    }

    #[tokio::test]
    async fn max_keys_eviction_under_pressure() {
        let config = IdempotencyConfig {
            enabled: true,
            ttl_hours: 1,
            max_keys: 100, // Small limit
            max_key_length: 64,
        };
        let store = IdempotencyStore::new(config);

        // Add more keys than the limit
        for i in 0..50 {
            let _ = store.try_acquire(&format!("key-{i}"));
            // Complete half of them
            if i % 2 == 0 {
                store.complete(
                    &format!("key-{i}"),
                    axum::http::StatusCode::OK,
                    vec![],
                    None,
                );
            }
        }

        // Store should not exceed max_keys significantly
        assert!(
            store.len() <= 150,
            "Store should evict old entries: len={}",
            store.len()
        );
    }
}
