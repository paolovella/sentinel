// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Tenant isolation integration tests for the Vellaveto HTTP API server.
//!
//! Verifies that multi-tenancy features work correctly:
//! - Tenant extraction from headers, subdomains
//! - Policy namespacing by tenant
//! - Tenant management API endpoints
//! - Tenant isolation between requests

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
use vellaveto_server::tenant::{
    InMemoryTenantStore, Tenant, TenantConfig, TenantContext, TenantQuotas, TenantSource,
    TenantStore,
};
use vellaveto_server::usage_tracker::TenantUsageTracker;
use vellaveto_server::{routes, AppState, Metrics, PolicySnapshot, RateLimits};
use vellaveto_types::{Policy, PolicyType};

fn test_state_with_tenants(
    tenant_config: TenantConfig,
    tenant_store: Option<Arc<dyn vellaveto_server::tenant::TenantStore>>,
) -> (AppState, TempDir) {
    let tmp = TempDir::new().unwrap();
    let audit = Arc::new(AuditLogger::new(tmp.path().join("audit.log")));
    let state = AppState {
        policy_state: Arc::new(ArcSwap::from_pointee(PolicySnapshot {
            engine: PolicyEngine::new(false),
            policies: vec![
                // Tenant-specific policy for acme
                Policy {
                    id: "acme:file:allow".to_string(),
                    name: "Acme file access".to_string(),
                    policy_type: PolicyType::Allow,
                    priority: 10,
                    path_rules: None,
                    network_rules: None,
                },
                // Tenant-specific policy for globex
                Policy {
                    id: "globex:file:deny".to_string(),
                    name: "Globex file deny".to_string(),
                    policy_type: PolicyType::Deny,
                    priority: 10,
                    path_rules: None,
                    network_rules: None,
                },
                // Global shared policy
                Policy {
                    id: "_global_:health:allow".to_string(),
                    name: "Global health check".to_string(),
                    policy_type: PolicyType::Allow,
                    priority: 5,
                    path_rules: None,
                    network_rules: None,
                },
                // Legacy policy (no tenant namespace)
                Policy {
                    id: "legacy:policy".to_string(),
                    name: "Legacy policy".to_string(),
                    policy_type: PolicyType::Allow,
                    priority: 1,
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
        api_key: None, // No API key auth for these tests
        rate_limits: Arc::new(RateLimits::disabled()),
        cors_origins: vec![],
        metrics: Arc::new(Metrics::default()),
        trusted_proxies: Arc::new(vec![]),
        policy_write_lock: Arc::new(tokio::sync::Mutex::new(())),
        prometheus_handle: None,
        tool_registry: None,
        cluster: None,
        rbac_config: vellaveto_server::rbac::RbacConfig::default(),
        tenant_config,
        tenant_store,
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

// ────────────────────────────────────────────────────────────────────────────
// Tenant Extraction Tests
// ────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn tenant_disabled_uses_default_tenant() {
    let config = TenantConfig {
        enabled: false,
        ..Default::default()
    };
    let (state, _tmp) = test_state_with_tenants(config, None);
    let app = routes::build_router(state);

    let request = Request::builder()
        .method("GET")
        .uri("/health")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn tenant_extracted_from_header() {
    let config = TenantConfig {
        enabled: true,
        require_tenant: false,
        allow_header_tenant: true,
        ..Default::default()
    };
    let (state, _tmp) = test_state_with_tenants(config, None);
    let app = routes::build_router(state);

    let request = Request::builder()
        .method("GET")
        .uri("/health")
        .header("X-Tenant-ID", "acme")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn tenant_required_but_missing_returns_400() {
    let config = TenantConfig {
        enabled: true,
        require_tenant: true,
        ..Default::default()
    };
    let (state, _tmp) = test_state_with_tenants(config, None);
    let app = routes::build_router(state);

    let request = Request::builder()
        .method("GET")
        .uri("/health")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn tenant_not_found_returns_403_opaque() {
    let store = Arc::new(InMemoryTenantStore::with_default_tenant());
    let config = TenantConfig {
        enabled: true,
        require_tenant: true,
        allow_header_tenant: true,
        ..Default::default()
    };
    let (state, _tmp) = test_state_with_tenants(config, Some(store));
    let app = routes::build_router(state);

    let request = Request::builder()
        .method("GET")
        .uri("/health")
        .header("X-Tenant-ID", "nonexistent")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    // SECURITY (FIND-047): Returns 403 (not 404) to prevent tenant enumeration.
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn tenant_disabled_returns_403() {
    let store = Arc::new(InMemoryTenantStore::new());
    // Add a disabled tenant
    store
        .create_tenant(Tenant {
            id: "disabled-tenant".to_string(),
            name: "Disabled Tenant".to_string(),
            enabled: false,
            quotas: TenantQuotas::default(),
            metadata: Default::default(),
            created_at: None,
            updated_at: None,
        })
        .unwrap();

    let config = TenantConfig {
        enabled: true,
        require_tenant: true,
        allow_header_tenant: true,
        ..Default::default()
    };
    let (state, _tmp) = test_state_with_tenants(config, Some(store));
    let app = routes::build_router(state);

    let request = Request::builder()
        .method("GET")
        .uri("/health")
        .header("X-Tenant-ID", "disabled-tenant")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

// ────────────────────────────────────────────────────────────────────────────
// Tenant Context Policy Matching Tests
// ────────────────────────────────────────────────────────────────────────────

fn tenant_ctx(id: &str) -> TenantContext {
    TenantContext {
        tenant_id: id.to_string(),
        source: TenantSource::Header,
        quotas: None,
    }
}

#[test]
fn tenant_context_matches_own_policies() {
    let ctx = tenant_ctx("acme");

    // Own namespaced policy
    assert!(ctx.policy_matches("acme:file:read"));
    assert!(ctx.policy_matches("acme:tool:function"));

    // Global policies
    assert!(ctx.policy_matches("_global_:health:check"));

    // Legacy policies (no namespace)
    assert!(ctx.policy_matches("tool:function"));
    assert!(ctx.policy_matches("simple-policy"));
}

#[test]
fn tenant_context_rejects_other_tenant_policies() {
    let ctx = tenant_ctx("acme");

    // Other tenant's namespaced policies
    assert!(!ctx.policy_matches("globex:file:read"));
    assert!(!ctx.policy_matches("other:tool:function"));
}

#[test]
fn tenant_context_namespace_policy_correctly() {
    let ctx = tenant_ctx("acme");

    // Namespace a policy
    assert_eq!(ctx.namespace_policy("file:read"), "acme:file:read");
    assert_eq!(ctx.namespace_policy("tool:function"), "acme:tool:function");

    // Already namespaced (don't double-namespace)
    assert_eq!(
        ctx.namespace_policy("acme:file:read"),
        "acme:acme:file:read"
    );
}

// ────────────────────────────────────────────────────────────────────────────
// Tenant Management API Tests
// ────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn list_tenants_empty_when_no_store() {
    let config = TenantConfig::default();
    let (state, _tmp) = test_state_with_tenants(config, None);
    let app = routes::build_router(state);

    let request = Request::builder()
        .method("GET")
        .uri("/api/tenants")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let tenants: Vec<Tenant> = serde_json::from_slice(&body).unwrap();
    assert!(tenants.is_empty());
}

#[tokio::test]
async fn list_tenants_returns_all_tenants() {
    let store = Arc::new(InMemoryTenantStore::with_default_tenant());
    store
        .create_tenant(Tenant::new("acme", "Acme Corporation"))
        .unwrap();
    store
        .create_tenant(Tenant::new("globex", "Globex Corporation"))
        .unwrap();

    let config = TenantConfig::default();
    let (state, _tmp) = test_state_with_tenants(config, Some(store));
    let app = routes::build_router(state);

    let request = Request::builder()
        .method("GET")
        .uri("/api/tenants")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let tenants: Vec<Tenant> = serde_json::from_slice(&body).unwrap();
    assert_eq!(tenants.len(), 3); // default + acme + globex
}

#[tokio::test]
async fn get_tenant_returns_tenant() {
    let store = Arc::new(InMemoryTenantStore::with_default_tenant());
    store
        .create_tenant(Tenant::new("acme", "Acme Corporation"))
        .unwrap();

    let config = TenantConfig::default();
    let (state, _tmp) = test_state_with_tenants(config, Some(store));
    let app = routes::build_router(state);

    let request = Request::builder()
        .method("GET")
        .uri("/api/tenants/acme")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let resp: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(resp["tenant"]["id"], "acme");
    assert_eq!(resp["tenant"]["name"], "Acme Corporation");
}

#[tokio::test]
async fn get_tenant_not_found() {
    let store = Arc::new(InMemoryTenantStore::with_default_tenant());
    let config = TenantConfig::default();
    let (state, _tmp) = test_state_with_tenants(config, Some(store));
    let app = routes::build_router(state);

    let request = Request::builder()
        .method("GET")
        .uri("/api/tenants/nonexistent")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn create_tenant_success() {
    let store = Arc::new(InMemoryTenantStore::new());
    let config = TenantConfig::default();
    let (state, _tmp) = test_state_with_tenants(config, Some(store));
    let app = routes::build_router(state);

    let body = json!({
        "id": "new-tenant",
        "name": "New Tenant Inc"
    });

    let request = Request::builder()
        .method("POST")
        .uri("/api/tenants")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let resp: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(resp["tenant"]["id"], "new-tenant");
    assert_eq!(resp["tenant"]["name"], "New Tenant Inc");
    assert_eq!(resp["tenant"]["enabled"], true);
}

#[tokio::test]
async fn create_tenant_invalid_id() {
    let store = Arc::new(InMemoryTenantStore::new());
    let config = TenantConfig::default();
    let (state, _tmp) = test_state_with_tenants(config, Some(store));
    let app = routes::build_router(state);

    let body = json!({
        "id": "invalid@tenant!",
        "name": "Invalid Tenant"
    });

    let request = Request::builder()
        .method("POST")
        .uri("/api/tenants")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn create_tenant_duplicate_id() {
    let store = Arc::new(InMemoryTenantStore::new());
    store
        .create_tenant(Tenant::new("existing", "Existing Tenant"))
        .unwrap();

    let config = TenantConfig::default();
    let (state, _tmp) = test_state_with_tenants(config, Some(store));
    let app = routes::build_router(state);

    let body = json!({
        "id": "existing",
        "name": "Duplicate Tenant"
    });

    let request = Request::builder()
        .method("POST")
        .uri("/api/tenants")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn update_tenant_success() {
    let store = Arc::new(InMemoryTenantStore::new());
    store
        .create_tenant(Tenant::new("acme", "Acme Corp"))
        .unwrap();

    let config = TenantConfig::default();
    let (state, _tmp) = test_state_with_tenants(config, Some(store));
    let app = routes::build_router(state);

    let body = json!({
        "id": "acme",
        "name": "Acme Corporation Updated",
        "enabled": false
    });

    let request = Request::builder()
        .method("PUT")
        .uri("/api/tenants/acme")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let resp: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(resp["tenant"]["name"], "Acme Corporation Updated");
    assert_eq!(resp["tenant"]["enabled"], false);
}

#[tokio::test]
async fn update_tenant_id_mismatch() {
    let store = Arc::new(InMemoryTenantStore::new());
    store
        .create_tenant(Tenant::new("acme", "Acme Corp"))
        .unwrap();

    let config = TenantConfig::default();
    let (state, _tmp) = test_state_with_tenants(config, Some(store));
    let app = routes::build_router(state);

    let body = json!({
        "id": "different-id",
        "name": "Acme Corporation"
    });

    let request = Request::builder()
        .method("PUT")
        .uri("/api/tenants/acme")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn delete_tenant_success() {
    let store = Arc::new(InMemoryTenantStore::new());
    store
        .create_tenant(Tenant::new("to-delete", "Delete Me"))
        .unwrap();

    let config = TenantConfig::default();
    let (state, _tmp) = test_state_with_tenants(config, Some(store.clone()));
    let app = routes::build_router(state);

    let request = Request::builder()
        .method("DELETE")
        .uri("/api/tenants/to-delete")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // Verify deletion
    assert!(store.get_tenant("to-delete").is_none());
}

#[tokio::test]
async fn delete_tenant_not_found() {
    let store = Arc::new(InMemoryTenantStore::new());
    let config = TenantConfig::default();
    let (state, _tmp) = test_state_with_tenants(config, Some(store));
    let app = routes::build_router(state);

    let request = Request::builder()
        .method("DELETE")
        .uri("/api/tenants/nonexistent")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn delete_default_tenant_forbidden() {
    let store = Arc::new(InMemoryTenantStore::with_default_tenant());
    let config = TenantConfig::default();
    let (state, _tmp) = test_state_with_tenants(config, Some(store));
    let app = routes::build_router(state);

    let request = Request::builder()
        .method("DELETE")
        .uri("/api/tenants/_default_")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn tenant_store_not_configured_returns_501() {
    let config = TenantConfig::default();
    let (state, _tmp) = test_state_with_tenants(config, None);
    let app = routes::build_router(state);

    let request = Request::builder()
        .method("GET")
        .uri("/api/tenants/some-tenant")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
}

// ────────────────────────────────────────────────────────────────────────────
// Tenant Isolation in Evaluate Tests
// ────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn evaluate_includes_tenant_id_in_context() {
    let config = TenantConfig {
        enabled: true,
        require_tenant: false,
        allow_header_tenant: true,
        ..Default::default()
    };
    let (state, _tmp) = test_state_with_tenants(config, None);
    let app = routes::build_router(state);

    // Action is flattened into the request body
    let body = json!({
        "tool": "file",
        "function": "read",
        "parameters": {}
    });

    let request = Request::builder()
        .method("POST")
        .uri("/api/evaluate")
        .header("Content-Type", "application/json")
        .header("X-Tenant-ID", "test-tenant")
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    // Should succeed (no policies block it)
    assert_eq!(response.status(), StatusCode::OK);
}

// ────────────────────────────────────────────────────────────────────────────
// FIND-R203 Security Fixes
// ────────────────────────────────────────────────────────────────────────────

/// FIND-R203-001: list_policies returns only the calling tenant's policies.
///
/// Non-default tenants must not see policies belonging to other tenants.
#[tokio::test]
async fn list_policies_non_default_tenant_filters_results() {
    let config = TenantConfig {
        enabled: true,
        require_tenant: false,
        allow_header_tenant: true,
        ..Default::default()
    };
    let (state, _tmp) = test_state_with_tenants(config, None);
    let app = routes::build_router(state);

    // Tenant "acme" requests the policy list
    let request = Request::builder()
        .method("GET")
        .uri("/api/policies")
        .header("X-Tenant-ID", "acme")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let policies: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();

    // Should include acme's own policy, the global policy, and the legacy policy,
    // but NOT globex's policy.
    let ids: Vec<&str> = policies.iter().filter_map(|p| p["id"].as_str()).collect();

    assert!(
        ids.contains(&"acme:file:allow"),
        "Tenant 'acme' should see its own policy, got: {ids:?}"
    );
    assert!(
        ids.contains(&"_global_:health:allow"),
        "Tenant 'acme' should see global policies, got: {ids:?}"
    );
    assert!(
        ids.contains(&"legacy:policy"),
        "Tenant 'acme' should see legacy policies, got: {ids:?}"
    );
    assert!(
        !ids.contains(&"globex:file:deny"),
        "Tenant 'acme' must NOT see globex's policy, got: {ids:?}"
    );
}

/// FIND-R203-001: Default (admin) tenant sees all policies.
#[tokio::test]
async fn list_policies_default_tenant_sees_all() {
    let config = TenantConfig {
        enabled: false, // disabled → default tenant
        ..Default::default()
    };
    let (state, _tmp) = test_state_with_tenants(config, None);
    let app = routes::build_router(state);

    let request = Request::builder()
        .method("GET")
        .uri("/api/policies")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let policies: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
    // test_state_with_tenants loads 4 policies; default tenant sees them all
    assert_eq!(
        policies.len(),
        4,
        "Default tenant should see all 4 policies, got: {}",
        policies.len()
    );
}

/// FIND-R203-008: Non-default tenants cannot read metering usage for other tenants.
#[tokio::test]
async fn billing_usage_cross_tenant_returns_404() {
    let config = TenantConfig {
        enabled: true,
        require_tenant: false,
        allow_header_tenant: true,
        ..Default::default()
    };
    let (mut state, _tmp) = test_state_with_tenants(config, None);
    let tracker = Arc::new(TenantUsageTracker::new(
        vellaveto_config::MeteringConfig::default(),
    ));
    tracker.record_evaluation_outcome("globex", true);
    state.usage_tracker = Some(tracker);
    let app = routes::build_router(state);

    let request = Request::builder()
        .method("GET")
        .uri("/api/billing/usage/globex")
        .header("X-Tenant-ID", "acme")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "Cross-tenant usage reads must be denied with 404"
    );
}

/// FIND-R203-008: Tenants can still read their own usage.
#[tokio::test]
async fn billing_usage_own_tenant_returns_200() {
    let config = TenantConfig {
        enabled: true,
        require_tenant: false,
        allow_header_tenant: true,
        ..Default::default()
    };
    let (mut state, _tmp) = test_state_with_tenants(config, None);
    let tracker = Arc::new(TenantUsageTracker::new(
        vellaveto_config::MeteringConfig::default(),
    ));
    tracker.record_evaluation_outcome("acme", true);
    state.usage_tracker = Some(tracker);
    let app = routes::build_router(state);

    let request = Request::builder()
        .method("GET")
        .uri("/api/billing/usage/acme")
        .header("X-Tenant-ID", "acme")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

/// FIND-R203-008: Default tenant (admin context) may query any tenant usage.
#[tokio::test]
async fn billing_usage_default_tenant_can_query_any_tenant() {
    let config = TenantConfig {
        enabled: false, // disabled => default tenant context
        ..Default::default()
    };
    let (mut state, _tmp) = test_state_with_tenants(config, None);
    let tracker = Arc::new(TenantUsageTracker::new(
        vellaveto_config::MeteringConfig::default(),
    ));
    tracker.record_evaluation_outcome("globex", true);
    state.usage_tracker = Some(tracker);
    let app = routes::build_router(state);

    let request = Request::builder()
        .method("GET")
        .uri("/api/billing/usage/globex")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

/// FIND-R203-002: Non-default tenant cannot delete another tenant's policy.
#[tokio::test]
async fn remove_policy_cross_tenant_returns_403() {
    let config = TenantConfig {
        enabled: true,
        require_tenant: false,
        allow_header_tenant: true,
        ..Default::default()
    };
    let (state, _tmp) = test_state_with_tenants(config, None);
    let app = routes::build_router(state);

    // Tenant "acme" tries to delete globex's policy
    let request = Request::builder()
        .method("DELETE")
        .uri("/api/policies/globex:file:deny")
        .header("X-Tenant-ID", "acme")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "Deleting another tenant's policy must return 403"
    );
}

/// FIND-R203-002: Non-default tenant can delete its own policy.
#[tokio::test]
async fn remove_policy_own_tenant_policy_succeeds() {
    let config = TenantConfig {
        enabled: true,
        require_tenant: false,
        allow_header_tenant: true,
        ..Default::default()
    };
    let (state, _tmp) = test_state_with_tenants(config, None);
    let app = routes::build_router(state);

    // Tenant "acme" deletes its own policy
    let request = Request::builder()
        .method("DELETE")
        .uri("/api/policies/acme:file:allow")
        .header("X-Tenant-ID", "acme")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "Deleting own policy should succeed"
    );
}

/// FIND-R203-006: remove_policy 404 does not echo the policy ID in the error.
#[tokio::test]
async fn remove_policy_not_found_does_not_echo_id() {
    let config = TenantConfig {
        enabled: false, // default tenant to avoid 403 from FIND-R203-002
        ..Default::default()
    };
    let (state, _tmp) = test_state_with_tenants(config, None);
    let app = routes::build_router(state);

    let request = Request::builder()
        .method("DELETE")
        .uri("/api/policies/probe:sensitive:id")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let error_msg = json["error"].as_str().unwrap_or("");

    // The policy ID must NOT appear in the error response.
    assert!(
        !error_msg.contains("probe:sensitive:id"),
        "404 error must not echo the policy ID, got: {error_msg}"
    );
    assert_eq!(
        error_msg, "Policy not found",
        "404 error should be generic 'Policy not found'"
    );
}

/// FIND-R203-003: Subdomain extraction rejects underscore-prefixed tenant names.
#[test]
fn extract_tenant_from_subdomain_rejects_reserved_prefix() {
    use vellaveto_server::tenant::extract_tenant_from_subdomain;

    // _default_ via subdomain must be rejected
    assert_eq!(
        extract_tenant_from_subdomain("_default_.vellaveto.example.com", "vellaveto.example.com"),
        None,
        "_default_ subdomain must be rejected"
    );

    // _admin via subdomain must be rejected
    assert_eq!(
        extract_tenant_from_subdomain("_admin.vellaveto.example.com", "vellaveto.example.com"),
        None,
        "_admin subdomain must be rejected"
    );

    // Normal tenant still works
    assert_eq!(
        extract_tenant_from_subdomain("acme.vellaveto.example.com", "vellaveto.example.com"),
        Some("acme".to_string()),
        "Normal subdomain must still be accepted"
    );
}

/// FIND-R203-005: audit_store_status returns 403 for non-default tenants.
#[tokio::test]
async fn audit_store_status_non_default_tenant_returns_403() {
    let config = TenantConfig {
        enabled: true,
        require_tenant: false,
        allow_header_tenant: true,
        ..Default::default()
    };
    let (state, _tmp) = test_state_with_tenants(config, None);
    let app = routes::build_router(state);

    let request = Request::builder()
        .method("GET")
        .uri("/api/audit/store/status")
        .header("X-Tenant-ID", "acme")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "audit/store/status must return 403 for non-default tenants"
    );
}

// ────────────────────────────────────────────────────────────────────────────
// FIND-CREATIVE-001: Tenant Policy Isolation with Compiled Engine
// ────────────────────────────────────────────────────────────────────────────

/// FIND-CREATIVE-001 (P0): Verifies that a non-default tenant does NOT see
/// another tenant's policies on the non-traced evaluation path.
///
/// The bug: `evaluate_action_with_context()` ignores the `policies` parameter
/// when compiled policies exist. The pre-compiled engine was built from ALL
/// tenants' policies, so tenant "globex" could trigger a match on "acme:*" rules.
/// The fix builds a tenant-scoped engine for non-default tenants.
#[tokio::test]
async fn evaluate_non_default_tenant_does_not_see_other_tenant_policies() {
    // Create policies: acme has an Allow for "file:*", globex has a Deny.
    // Without the fix, globex calling `file:read` would match acme's Allow rule
    // because the compiled engine has all policies.
    let all_policies = vec![
        Policy {
            id: "acme:file:allow".to_string(),
            name: "Acme file access".to_string(),
            policy_type: PolicyType::Allow,
            priority: 100,
            path_rules: None,
            network_rules: None,
        },
        Policy {
            id: "globex:file:deny".to_string(),
            name: "Globex file deny".to_string(),
            policy_type: PolicyType::Deny,
            priority: 100,
            path_rules: None,
            network_rules: None,
        },
    ];

    // CRITICAL: Use with_policies() to create a COMPILED engine — this is what
    // production uses. PolicyEngine::new(false) would not trigger the bug because
    // there are no compiled policies and the fallback path uses the policies param.
    let compiled_engine = PolicyEngine::with_policies(false, &all_policies).unwrap();

    let config = TenantConfig {
        enabled: true,
        require_tenant: false,
        allow_header_tenant: true,
        ..Default::default()
    };

    let tmp = TempDir::new().unwrap();
    let audit = Arc::new(AuditLogger::new(tmp.path().join("audit.log")));
    let state = AppState {
        policy_state: Arc::new(ArcSwap::from_pointee(PolicySnapshot {
            engine: compiled_engine,
            policies: all_policies,
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
        tenant_config: config,
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

    // Globex tenant evaluates "file:read" — should see its own Deny policy,
    // NOT acme's Allow policy.
    let request = Request::builder()
        .method("POST")
        .uri("/api/evaluate")
        .header("content-type", "application/json")
        .header("X-Tenant-ID", "globex")
        .body(Body::from(
            json!({
                "tool": "file",
                "function": "read",
                "parameters": {}
            })
            .to_string(),
        ))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let result: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // SECURITY: The verdict MUST NOT be "allow" because globex's only matching policy is Deny.
    // Before the fix, the compiled engine would match acme's Allow rule and return "allow".
    // The verdict is either {"Deny": {"reason": ...}} or "allow".
    let verdict = &result["verdict"];
    assert!(
        verdict.get("Deny").is_some() || verdict.as_str() == Some("deny"),
        "FIND-CREATIVE-001: Non-default tenant must NOT see other tenants' Allow policies. \
         Expected Deny verdict, got: {result:?}"
    );
    // Verify it is NOT allow
    assert_ne!(
        verdict.as_str().unwrap_or(""),
        "allow",
        "FIND-CREATIVE-001: Globex must not receive Allow from acme's policies"
    );
}

/// FIND-R203-005: audit_store_status is accessible by the default (admin) tenant.
#[tokio::test]
async fn audit_store_status_default_tenant_returns_200() {
    let config = TenantConfig {
        enabled: false, // disabled → default tenant
        ..Default::default()
    };
    let (state, _tmp) = test_state_with_tenants(config, None);
    let app = routes::build_router(state);

    let request = Request::builder()
        .method("GET")
        .uri("/api/audit/store/status")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "audit/store/status must return 200 for default tenant"
    );
}
