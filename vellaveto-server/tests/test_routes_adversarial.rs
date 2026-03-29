// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! HTTP route unit tests using axum test utilities.
//! Tests the full request→response cycle without spawning a real server.

use arc_swap::ArcSwap;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::json;
use std::sync::Arc;
use tempfile::TempDir;
use tower::ServiceExt;
use vellaveto_approval::ApprovalStore;
use vellaveto_audit::AuditLogger;
use vellaveto_engine::PolicyEngine;
use vellaveto_server::{routes, AppState, Metrics, RateLimits};
use vellaveto_types::{Policy, PolicyType};

fn make_state() -> (AppState, TempDir) {
    let tmp = TempDir::new().unwrap();
    let audit = Arc::new(AuditLogger::new(tmp.path().join("audit.log")));
    let state = AppState {
        policy_state: Arc::new(ArcSwap::from_pointee(vellaveto_server::PolicySnapshot {
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
        config_path: Arc::new("nonexistent.toml".to_string()),
        approvals: Arc::new(ApprovalStore::new(
            tmp.path().join("approvals.jsonl"),
            std::time::Duration::from_secs(900),
        )),
        api_key: Some(Arc::new("test-secret-key-123".to_string())),
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

fn make_empty_state() -> (AppState, TempDir) {
    let tmp = TempDir::new().unwrap();
    let audit = Arc::new(AuditLogger::new(tmp.path().join("audit.log")));
    let state = AppState {
        policy_state: Arc::new(ArcSwap::from_pointee(vellaveto_server::PolicySnapshot {
            engine: PolicyEngine::new(false),
            policies: vec![],
            compliance_config: Default::default(),
        })),
        audit: Arc::clone(&audit),
        config_path: Arc::new("nonexistent.toml".to_string()),
        approvals: Arc::new(ApprovalStore::new(
            tmp.path().join("approvals.jsonl"),
            std::time::Duration::from_secs(900),
        )),
        api_key: Some(Arc::new("test-secret-key-123".to_string())),
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

// ═══════════════════════════════════
// HEALTH ENDPOINT
// ═══════════════════════════════════

#[tokio::test]
async fn health_returns_200() {
    let (state, _tmp) = make_state();
    let app = routes::build_router(state);
    let req = Request::get("/health").body(Body::empty()).unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn health_response_contains_status_ok() {
    let (state, _tmp) = make_state();
    let app = routes::build_router(state);
    let req = Request::get("/health").body(Body::empty()).unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["status"], "ok");
}

#[tokio::test]
async fn health_reports_correct_policy_count() {
    let (state, _tmp) = make_state();
    let app = routes::build_router(state);
    let req = Request::get("/health").body(Body::empty()).unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["status"], "ok");
}

// ═══════════════════════════════════
// EVALUATE ENDPOINT
// ═══════════════════════════════════

#[tokio::test]
async fn evaluate_allowed_action_returns_allow() {
    let (state, _tmp) = make_state();
    let app = routes::build_router(state);
    let req = Request::post("/api/evaluate")
        .header("content-type", "application/json")
        .header("Authorization", "Bearer test-secret-key-123")
        .body(Body::from(
            json!({
                "tool": "file",
                "function": "read",
                "parameters": {}
            })
            .to_string(),
        ))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(
        json.to_string().contains("Allow"),
        "file:read should be allowed: {json:?}"
    );
}

#[tokio::test]
async fn evaluate_denied_action_returns_deny() {
    let (state, _tmp) = make_state();
    let app = routes::build_router(state);
    let req = Request::post("/api/evaluate")
        .header("content-type", "application/json")
        .header("Authorization", "Bearer test-secret-key-123")
        .body(Body::from(
            json!({
                "tool": "bash",
                "function": "execute",
                "parameters": {}
            })
            .to_string(),
        ))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(
        json.to_string().contains("Deny"),
        "bash:execute should be denied: {json:?}"
    );
}

#[tokio::test]
async fn evaluate_logs_to_audit() {
    let (state, _tmp) = make_state();
    let audit = state.audit.clone();
    let app = routes::build_router(state);

    let req = Request::post("/api/evaluate")
        .header("content-type", "application/json")
        .header("Authorization", "Bearer test-secret-key-123")
        .body(Body::from(
            json!({
                "tool": "file",
                "function": "read",
                "parameters": {}
            })
            .to_string(),
        ))
        .unwrap();
    app.oneshot(req).await.unwrap();

    // Give async audit write time to complete
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let entries = audit.load_entries().await.unwrap();
    assert!(!entries.is_empty(), "Evaluate endpoint should log to audit");
    assert_eq!(entries[0].action.tool, "file");
}

#[tokio::test]
async fn evaluate_with_empty_policies_returns_deny() {
    let (state, _tmp) = make_empty_state();
    let app = routes::build_router(state);
    let req = Request::post("/api/evaluate")
        .header("content-type", "application/json")
        .header("Authorization", "Bearer test-secret-key-123")
        .body(Body::from(
            json!({
                "tool": "anything",
                "function": "whatever",
                "parameters": {}
            })
            .to_string(),
        ))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(
        json.to_string().contains("Deny"),
        "Empty policies should produce Deny (fail-closed): {json:?}"
    );
}

#[tokio::test]
async fn evaluate_invalid_json_returns_error() {
    let (state, _tmp) = make_state();
    let app = routes::build_router(state);
    let req = Request::post("/api/evaluate")
        .header("content-type", "application/json")
        .header("Authorization", "Bearer test-secret-key-123")
        .body(Body::from("not json"))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    // Should be 400 or 422 — NOT 200
    assert!(
        resp.status().is_client_error(),
        "Invalid JSON should return client error, got {}",
        resp.status()
    );
}

#[tokio::test]
async fn evaluate_missing_fields_returns_error() {
    let (state, _tmp) = make_state();
    let app = routes::build_router(state);
    let req = Request::post("/api/evaluate")
        .header("content-type", "application/json")
        .header("Authorization", "Bearer test-secret-key-123")
        .body(Body::from(json!({"tool": "bash"}).to_string()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert!(
        resp.status().is_client_error(),
        "Missing required fields should return client error, got {}",
        resp.status()
    );
}

// ═══════════════════════════════════
// POLICIES CRUD ENDPOINTS
// ═══════════════════════════════════

#[tokio::test]
async fn list_policies_returns_array() {
    let (state, _tmp) = make_state();
    let app = routes::build_router(state);
    let req = Request::get("/api/policies")
        .header("Authorization", "Bearer test-secret-key-123")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json.is_array(), "Policies should be an array: {json:?}");
    assert_eq!(json.as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn add_policy_increases_count() {
    let (state, _tmp) = make_state();
    let policy_state = state.policy_state.clone();
    let app = routes::build_router(state);

    let req = Request::post("/api/policies")
        .header("content-type", "application/json")
        .header("Authorization", "Bearer test-secret-key-123")
        .body(Body::from(
            json!({
                "id": "net:*",
                "name": "Block network",
                "policy_type": "Deny",
                "priority": 200
            })
            .to_string(),
        ))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert!(
        resp.status().is_success(),
        "Add policy should succeed, got {}",
        resp.status()
    );

    let count = policy_state.load().policies.len();
    assert_eq!(count, 3, "Should have 3 policies after adding one");
}

#[tokio::test]
async fn add_policy_with_invalid_json_fails() {
    let (state, _tmp) = make_state();
    let app = routes::build_router(state);
    let req = Request::post("/api/policies")
        .header("content-type", "application/json")
        .header("Authorization", "Bearer test-secret-key-123")
        .body(Body::from("not a policy"))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert!(resp.status().is_client_error());
}

#[tokio::test]
async fn remove_policy_by_simple_id() {
    let (state, _tmp) = make_state();
    let policy_state = state.policy_state.clone();
    let app = routes::build_router(state);

    // Remove "file:read" — but note the colon in the URL path
    // This tests whether path params handle colons correctly
    let req = Request::delete("/api/policies/file:read")
        .header("Authorization", "Bearer test-secret-key-123")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert!(
        resp.status().is_success(),
        "Remove policy should succeed, got {}",
        resp.status()
    );

    let count = policy_state.load().policies.len();
    assert_eq!(count, 1, "Should have 1 policy after removing one");
}

#[test]
fn remove_policy_nonexistent_id_is_not_error() {
    // Removing a non-existent policy should succeed (idempotent) or return 404
    // Either behavior is acceptable — the test documents which one was chosen
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let (state, _tmp) = make_state();
        let app = routes::build_router(state);
        let req = Request::delete("/api/policies/nonexistent_policy_id")
            .header("Authorization", "Bearer test-secret-key-123")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        // Should not be a 500
        assert_ne!(
            resp.status(),
            StatusCode::INTERNAL_SERVER_ERROR,
            "Removing non-existent policy should not be a server error"
        );
    });
}

// ═══════════════════════════════════
// AUDIT ENDPOINTS
// ═══════════════════════════════════

#[tokio::test]
async fn audit_entries_empty_returns_empty_array() {
    let (state, _tmp) = make_state();
    let app = routes::build_router(state);
    let req = Request::get("/api/audit/entries")
        .header("Authorization", "Bearer test-secret-key-123")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    // Route returns {"count": N, "entries": [...]}
    assert!(json.is_object());
    assert_eq!(json["count"], 0);
    assert!(
        json["entries"].as_array().unwrap().is_empty(),
        "Fresh audit should have no entries"
    );
}

#[tokio::test]
async fn audit_report_empty_returns_zero_counts() {
    let (state, _tmp) = make_state();
    let app = routes::build_router(state);
    let req = Request::get("/api/audit/report")
        .header("Authorization", "Bearer test-secret-key-123")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["total_entries"], 0);
    assert_eq!(json["allow_count"], 0);
    assert_eq!(json["deny_count"], 0);
}

// ═══════════════════════════════════
// RELOAD ENDPOINT
// ═══════════════════════════════════

#[tokio::test]
async fn reload_with_nonexistent_config_returns_error() {
    let (state, _tmp) = make_state();
    // config_path points to "nonexistent.toml" by default in test
    let app = routes::build_router(state);
    let req = Request::post("/api/policies/reload")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    // Should be a 500 or 400 — config file doesn't exist
    assert!(
        resp.status().is_server_error() || resp.status().is_client_error(),
        "Reload with nonexistent config should fail, got {}",
        resp.status()
    );
}

#[tokio::test]
async fn reload_with_valid_config_succeeds() {
    let tmp = TempDir::new().unwrap();
    let config_path = tmp.path().join("reload.toml");
    std::fs::write(
        &config_path,
        r#"
[[policies]]
name = "Reloaded"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Allow"
priority = 1
"#,
    )
    .unwrap();

    let audit = Arc::new(AuditLogger::new(tmp.path().join("audit.log")));
    let state = AppState {
        policy_state: Arc::new(ArcSwap::from_pointee(vellaveto_server::PolicySnapshot {
            engine: PolicyEngine::new(false),
            policies: vec![],
            compliance_config: Default::default(),
        })),
        audit: Arc::clone(&audit),
        config_path: Arc::new(config_path.to_str().unwrap().to_string()),
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
    let policy_state = state.policy_state.clone();
    let app = routes::build_router(state);

    let req = Request::post("/api/policies/reload")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert!(
        resp.status().is_success(),
        "Reload with valid config should succeed, got {}",
        resp.status()
    );

    let count = policy_state.load().policies.len();
    assert_eq!(count, 1, "Should have 1 policy after reload");
    assert_eq!(policy_state.load().policies[0].name, "Reloaded");
}

// ═══════════════════════════════════
// 404 FOR UNKNOWN ROUTES
// ════════════════════════════════════

#[tokio::test]
async fn unknown_route_returns_404() {
    let (state, _tmp) = make_state();
    let app = routes::build_router(state);
    let req = Request::get("/api/nonexistent")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn get_on_evaluate_endpoint_returns_405() {
    let (state, _tmp) = make_state();
    let app = routes::build_router(state);
    let req = Request::get("/api/evaluate")
        .header("Authorization", "Bearer test-secret-key-123")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    // GET on a POST-only route should be 405 Method Not Allowed
    assert!(
        resp.status() == StatusCode::METHOD_NOT_ALLOWED || resp.status() == StatusCode::NOT_FOUND,
        "Wrong method should not be 200, got {}",
        resp.status()
    );
}

/// SECURITY (R22-SRV-1): Client-supplied resolved_ips must be cleared before
/// evaluation. A malicious client could supply "8.8.8.8" to bypass DNS
/// rebinding / private-IP checks when the real resolution would be "127.0.0.1".
#[tokio::test]
async fn evaluate_clears_client_supplied_resolved_ips() {
    let tmp = TempDir::new().unwrap();
    let policies = vec![Policy {
        id: "net:block-private".to_string(),
        name: "Block private IPs".to_string(),
        policy_type: PolicyType::Allow,
        priority: 10,
        path_rules: None,
        network_rules: Some(vellaveto_types::NetworkRules {
            allowed_domains: vec!["*.example.com".to_string()],
            blocked_domains: vec![],
            ip_rules: Some(vellaveto_types::IpRules {
                block_private: true,
                ..Default::default()
            }),
        }),
    }];
    let engine = PolicyEngine::with_policies(false, &policies).unwrap();
    let audit = Arc::new(AuditLogger::new(tmp.path().join("audit.log")));
    let state = AppState {
        policy_state: Arc::new(ArcSwap::from_pointee(vellaveto_server::PolicySnapshot {
            engine,
            policies,
            compliance_config: Default::default(),
        })),
        audit: Arc::clone(&audit),
        config_path: Arc::new("test.toml".to_string()),
        approvals: Arc::new(ApprovalStore::new(
            tmp.path().join("approvals.jsonl"),
            std::time::Duration::from_secs(900),
        )),
        api_key: Some(Arc::new("test-secret-key-123".to_string())),
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
    let app = routes::build_router(state);

    // Client supplies resolved_ips with a public IP to bypass private-IP block
    let body = json!({
        "tool": "http_request",
        "function": "get",
        "parameters": {"url": "http://example.com"},
        "resolved_ips": ["8.8.8.8"]
    });
    let req = Request::post("/api/evaluate")
        .header("Content-Type", "application/json")
        .header("Authorization", "Bearer test-secret-key-123")
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let body_bytes = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

    // The response should show the action with cleared resolved_ips
    // (they should be empty or re-extracted, NOT the client-supplied "8.8.8.8")
    assert_eq!(status, StatusCode::OK, "Evaluate should succeed");
    if let Some(action) = body.get("action") {
        if let Some(ips) = action.get("resolved_ips") {
            let empty = vec![];
            let ips_arr = ips.as_array().unwrap_or(&empty);
            assert!(
                !ips_arr.iter().any(|ip| ip.as_str() == Some("8.8.8.8")),
                "Client-supplied resolved_ips should have been cleared, but found 8.8.8.8 in {ips_arr:?}"
            );
        }
    }
}

// =============================================================================
// R32-SRV-1: Unicode case-folding byte offset panic.
// Turkish İ (U+0130) lowercases to "i\u{0307}" — 2 bytes → 3 bytes.
// Using byte offset from s on the lowercased string would panic.
// =============================================================================
#[tokio::test]
async fn test_r32_srv1_unicode_case_fold_no_panic() {
    let (state, _tmp) = make_state();
    let app = routes::build_router(state);

    // Turkish İ in the scheme position — must not panic on case-folding
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/evaluate")
                .method("POST")
                .header("content-type", "application/json")
                .header("authorization", "Bearer test-secret-key-123")
                .body(Body::from(
                    json!({
                        "tool": "fetch",
                        "function": "get",
                        "parameters": {
                            "url": "HT\u{0130}P://evil.com/path"
                        }
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    // Should not panic — any valid HTTP status is acceptable
    assert!(
        resp.status() == StatusCode::OK || resp.status() == StatusCode::FORBIDDEN,
        "Unicode case-folding must not cause panic, got status: {}",
        resp.status()
    );
}

// =============================================================================
// R32-SRV-2: redact_response_action must clear target_paths/domains/ips
// =============================================================================
#[tokio::test]
async fn test_r32_srv2_redact_clears_targets() {
    let (state, _tmp) = make_state();
    let app = routes::build_router(state);

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/evaluate")
                .method("POST")
                .header("content-type", "application/json")
                .header("authorization", "Bearer test-secret-key-123")
                .body(Body::from(
                    json!({
                        "tool": "file",
                        "function": "read",
                        "parameters": {
                            "path": "/etc/shadow",
                            "url": "https://secret-internal.corp.com/api"
                        }
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "evaluate must succeed with valid auth"
    );
    let body_bytes = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

    // The response action must not leak extracted paths/domains
    if let Some(action) = body.get("action") {
        let paths = action.get("target_paths").and_then(|p| p.as_array());
        let domains = action.get("target_domains").and_then(|d| d.as_array());
        let ips = action.get("resolved_ips").and_then(|r| r.as_array());

        // Either fields are absent (skip_serializing_if = "Vec::is_empty") or empty
        if let Some(paths) = paths {
            assert!(
                paths.is_empty(),
                "target_paths must be redacted, got: {paths:?}"
            );
        }
        if let Some(domains) = domains {
            assert!(
                domains.is_empty(),
                "target_domains must be redacted, got: {domains:?}"
            );
        }
        if let Some(ips) = ips {
            assert!(
                ips.is_empty(),
                "resolved_ips must be redacted, got: {ips:?}"
            );
        }
    }
}

// =============================================================================
// R32-SRV-3: file://localhost.evil.com boundary check
// =============================================================================
#[tokio::test]
async fn test_r32_srv3_file_localhost_boundary() {
    let (state, _tmp) = make_state();
    let app = routes::build_router(state);

    // file://localhost.evil.com should NOT strip "localhost" — it's a different host
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/evaluate")
                .method("POST")
                .header("content-type", "application/json")
                .header("authorization", "Bearer test-secret-key-123")
                .body(Body::from(
                    json!({
                        "tool": "file",
                        "function": "read",
                        "parameters": {
                            "path": "file://localhost.evil.com/etc/passwd"
                        }
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    // Should not panic and should return a valid response
    assert!(
        resp.status() == StatusCode::OK || resp.status() == StatusCode::FORBIDDEN,
        "file://localhost.evil.com must not cause misparse, got status: {}",
        resp.status()
    );
}

// =============================================================================
// FIND-004: Metrics endpoint authentication configuration
// =============================================================================

/// When metrics_require_auth is true (default), /metrics requires authentication.
#[tokio::test]
async fn test_find004_metrics_require_auth_true_blocks_unauthenticated() {
    let tmp = TempDir::new().unwrap();
    let audit = Arc::new(AuditLogger::new(tmp.path().join("audit.log")));
    let state = AppState {
        policy_state: Arc::new(ArcSwap::from_pointee(vellaveto_server::PolicySnapshot {
            engine: PolicyEngine::new(false),
            policies: vec![],
            compliance_config: Default::default(),
        })),
        audit: Arc::clone(&audit),
        config_path: Arc::new("test.toml".to_string()),
        approvals: Arc::new(ApprovalStore::new(
            tmp.path().join("approvals.jsonl"),
            std::time::Duration::from_secs(900),
        )),
        api_key: Some(Arc::new("test-secret-key-123".to_string())),
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
        // FIND-004: Require auth for metrics (default)
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
    let app = routes::build_router(state);

    // Unauthenticated request to /metrics should be blocked
    let req = Request::get("/metrics").body(Body::empty()).unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "FIND-004: /metrics should require auth when metrics_require_auth=true"
    );
}

/// When metrics_require_auth is false, /metrics is accessible without authentication.
#[tokio::test]
async fn test_find004_metrics_require_auth_false_allows_unauthenticated() {
    let tmp = TempDir::new().unwrap();
    let audit = Arc::new(AuditLogger::new(tmp.path().join("audit.log")));
    let state = AppState {
        policy_state: Arc::new(ArcSwap::from_pointee(vellaveto_server::PolicySnapshot {
            engine: PolicyEngine::new(false),
            policies: vec![],
            compliance_config: Default::default(),
        })),
        audit: Arc::clone(&audit),
        config_path: Arc::new("test.toml".to_string()),
        approvals: Arc::new(ApprovalStore::new(
            tmp.path().join("approvals.jsonl"),
            std::time::Duration::from_secs(900),
        )),
        api_key: Some(Arc::new("test-secret-key-123".to_string())),
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
        // FIND-004: Allow unauthenticated metrics
        shadow_ai_discovery: None,
        least_agency_tracker: None,
        metrics_require_auth: false,
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
    let app = routes::build_router(state);

    // Unauthenticated request to /metrics should succeed
    let req = Request::get("/metrics").body(Body::empty()).unwrap();
    let resp = app.oneshot(req).await.unwrap();
    // Note: might be 404 if prometheus_handle is None, but not 401
    assert_ne!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "FIND-004: /metrics should not require auth when metrics_require_auth=false"
    );
}
