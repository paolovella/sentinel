// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! OPA runtime tests isolated from general route unit tests.
//!
//! These tests mutate global OPA runtime configuration, so they run in a
//! dedicated test target to avoid cross-test interference.

use arc_swap::ArcSwap;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::json;
use std::sync::Arc;
use tempfile::TempDir;
use tower::ServiceExt;
use vellaveto_approval::ApprovalStore;
use vellaveto_audit::AuditLogger;
use vellaveto_config::OpaConfig;
use vellaveto_engine::PolicyEngine;
use vellaveto_server::{routes, AppState, Metrics, PolicySnapshot, RateLimits};
use vellaveto_types::{Policy, PolicyType};

static OPA_RUNTIME_TEST_LOCK: std::sync::LazyLock<tokio::sync::Mutex<()>> =
    std::sync::LazyLock::new(|| tokio::sync::Mutex::new(()));

struct OpaRuntimeResetGuard;

impl Drop for OpaRuntimeResetGuard {
    fn drop(&mut self) {
        let _ = vellaveto_server::opa::configure_runtime_client(&OpaConfig::default());
    }
}

fn test_state() -> (AppState, TempDir) {
    let tmp = TempDir::new().unwrap();
    let audit = Arc::new(AuditLogger::new(tmp.path().join("audit.log")));
    let state = AppState {
        policy_state: Arc::new(ArcSwap::from_pointee(PolicySnapshot {
            engine: PolicyEngine::new(false),
            policies: vec![
                Policy {
                    id: "file:read".to_string(),
                    name: "Allow file reads".to_string(),
                    policy_type: PolicyType::Allow,
                    priority: 10,
                    path_rules: None,
                    network_rules: None,
                },
                Policy {
                    id: "bash:*".to_string(),
                    name: "Block bash".to_string(),
                    policy_type: PolicyType::Deny,
                    priority: 100,
                    path_rules: None,
                    network_rules: None,
                },
            ],
            compliance_config: Default::default(),
        })),
        audit: Arc::clone(&audit),
        config_path: Arc::new("test-config.toml".to_string()),
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
        webhook_dedup: std::sync::Arc::new(vellaveto_server::routes::billing::WebhookDedup::new(
            std::time::Duration::from_secs(600),
        )),
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
                reason: "test".to_string(),
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
        staging_snapshot: std::sync::Arc::new(arc_swap::ArcSwap::from_pointee(None)),
        usage_tracker: None,
        topology_guard: None,
        topology_probe: None,
        recrawl_trigger: None,
    };
    (state, tmp)
}

async fn evaluate_file_read() -> (serde_json::Value, Arc<AuditLogger>, TempDir) {
    let (state, tmp) = test_state();
    let audit = state.audit.clone();
    let app = routes::build_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/evaluate")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_string(&json!({
                        "tool": "file",
                        "function": "read",
                        "parameters": {"path": "/tmp/test"}
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    (json, audit, tmp)
}

#[tokio::test]
async fn evaluate_opa_fail_closed_denies_on_unreachable_server() {
    let _lock = OPA_RUNTIME_TEST_LOCK.lock().await;
    let _reset = OpaRuntimeResetGuard;

    let cfg = OpaConfig {
        enabled: true,
        endpoint: Some("http://127.0.0.1:9".to_string()),
        require_https: false,
        decision_path: "vellaveto/allow".to_string(),
        cache_ttl_secs: 0,
        timeout_ms: 50,
        fail_open: false,
        fail_open_acknowledged: false,
        max_retries: 0,
        retry_backoff_ms: 10,
        headers: Default::default(),
        bundle_path: None,
        audit_decisions: false,
        cache_size: 1000,
    };
    vellaveto_server::opa::configure_runtime_client(&cfg).unwrap();

    let (json, audit, _tmp) = evaluate_file_read().await;
    assert_eq!(
        json["verdict"]["Deny"]["reason"],
        "OPA evaluation failed (fail-closed)"
    );

    let entries = audit.load_entries().await.unwrap();
    let entry = entries.last().expect("expected audit entry");
    assert_eq!(entry.metadata["opa"]["result"], "error");
    assert_eq!(entry.metadata["opa"]["fail_open"], false);
}

#[tokio::test]
async fn evaluate_opa_fail_open_allows_on_unreachable_server() {
    let _lock = OPA_RUNTIME_TEST_LOCK.lock().await;
    let _reset = OpaRuntimeResetGuard;

    let cfg = OpaConfig {
        enabled: true,
        endpoint: Some("http://127.0.0.1:9".to_string()),
        require_https: false,
        decision_path: "vellaveto/allow".to_string(),
        cache_ttl_secs: 0,
        timeout_ms: 50,
        fail_open: true,
        fail_open_acknowledged: true, // Required for fail_open=true
        max_retries: 0,
        retry_backoff_ms: 10,
        headers: Default::default(),
        bundle_path: None,
        audit_decisions: false,
        cache_size: 1000,
    };
    vellaveto_server::opa::configure_runtime_client(&cfg).unwrap();

    let (json, audit, _tmp) = evaluate_file_read().await;
    assert_eq!(json["verdict"], "Allow");

    let entries = audit.load_entries().await.unwrap();
    let entry = entries.last().expect("expected audit entry");
    assert_eq!(entry.metadata["opa"]["result"], "error");
    assert_eq!(entry.metadata["opa"]["fail_open"], true);
}
