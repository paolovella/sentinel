// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! RBAC integration tests for the Vellaveto HTTP API server.
//!
//! Verifies that role-based access control enforces the permission matrix
//! correctly for all endpoints.

use arc_swap::ArcSwap;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde::Serialize;
use std::sync::Arc;
use tempfile::TempDir;
use tower::ServiceExt;
use vellaveto_approval::ApprovalStore;
use vellaveto_audit::AuditLogger;
use vellaveto_engine::PolicyEngine;
use vellaveto_server::rbac::{JwtConfig, JwtKey, RbacConfig, Role};
use vellaveto_server::{routes, AppState, Metrics, PolicySnapshot, RateLimits};
use vellaveto_types::{Policy, PolicyType};

/// Test JWT claims with expiry
#[derive(Serialize)]
struct TestClaims {
    sub: String,
    role: String,
    exp: u64,
}

fn future_exp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3600
}

fn create_jwt(role: &str, secret: &str) -> String {
    use jsonwebtoken::{encode, EncodingKey, Header};

    let claims = TestClaims {
        sub: format!("test-user-{role}"),
        role: role.to_string(),
        exp: future_exp(),
    };

    encode(
        &Header::new(jsonwebtoken::Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .unwrap()
}

fn test_state_with_rbac(rbac_config: RbacConfig) -> (AppState, TempDir) {
    let tmp = TempDir::new().unwrap();
    let audit = Arc::new(AuditLogger::new(tmp.path().join("audit.log")));
    let state = AppState {
        policy_state: Arc::new(ArcSwap::from_pointee(PolicySnapshot {
            engine: PolicyEngine::new(false),
            policies: vec![Policy {
                id: "test:allow".to_string(),
                name: "Test policy".to_string(),
                policy_type: PolicyType::Allow,
                priority: 10,
                path_rules: None,
                network_rules: None,
            }],
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
        rbac_config,
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

fn test_state_with_rbac_and_api_key(
    rbac_config: RbacConfig,
    api_key: Option<&str>,
) -> (AppState, TempDir) {
    let (mut state, tmp) = test_state_with_rbac(rbac_config);
    state.api_key = api_key.map(|key| Arc::new(key.to_string()));
    (state, tmp)
}

// ────────────────────────────────
// RBAC Disabled Tests
// ────────────────────────────────

#[tokio::test]
async fn rbac_disabled_allows_all_requests() {
    let config = RbacConfig {
        enabled: false,
        ..Default::default()
    };
    let (state, _tmp) = test_state_with_rbac(config);
    let app = routes::build_router(state);

    // Should be able to access admin endpoints without auth
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/policies")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

// ────────────────────────────────
// Header-Based Role Tests
// ────────────────────────────────

#[tokio::test]
async fn header_role_admin_can_access_all() {
    let config = RbacConfig {
        enabled: true,
        allow_header_role: true,
        default_role: Role::Viewer,
        jwt_config: None,
    };
    let (state, _tmp) = test_state_with_rbac(config);
    let app = routes::build_router(state);

    // Admin can access policy write endpoint
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/policies")
                .header("x-vellaveto-role", "admin")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"id":"new","name":"New","policy_type":"allow","priority":1}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    // Should succeed (or at least not be 403)
    assert_ne!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn header_role_viewer_denied_write() {
    let config = RbacConfig {
        enabled: true,
        allow_header_role: true,
        default_role: Role::Viewer,
        jwt_config: None,
    };
    let (state, _tmp) = test_state_with_rbac(config);
    let app = routes::build_router(state);

    // Viewer cannot access policy write endpoint
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/policies")
                .header("x-vellaveto-role", "viewer")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"id":"new","name":"New","policy_type":"allow","priority":1}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn header_role_viewer_can_read() {
    let config = RbacConfig {
        enabled: true,
        allow_header_role: true,
        default_role: Role::Viewer,
        jwt_config: None,
    };
    let (state, _tmp) = test_state_with_rbac(config);
    let app = routes::build_router(state);

    // Viewer can read policies
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/policies")
                .header("x-vellaveto-role", "viewer")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn header_role_operator_can_reload() {
    let config = RbacConfig {
        enabled: true,
        allow_header_role: true,
        default_role: Role::Viewer,
        jwt_config: None,
    };
    let (state, _tmp) = test_state_with_rbac(config);
    let app = routes::build_router(state);

    // Operator can reload policies (will fail because config doesn't exist, but not 403)
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/policies/reload")
                .header("x-vellaveto-role", "operator")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Should not be forbidden (may be 500 due to missing config file)
    assert_ne!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn header_role_auditor_can_export() {
    let config = RbacConfig {
        enabled: true,
        allow_header_role: true,
        default_role: Role::Viewer,
        jwt_config: None,
    };
    let (state, _tmp) = test_state_with_rbac(config);
    let app = routes::build_router(state);

    // Auditor can access audit export
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/audit/export")
                .header("x-vellaveto-role", "auditor")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn header_role_auditor_denied_evaluate() {
    let config = RbacConfig {
        enabled: true,
        allow_header_role: true,
        default_role: Role::Viewer,
        jwt_config: None,
    };
    let (state, _tmp) = test_state_with_rbac(config);
    let app = routes::build_router(state);

    // Auditor cannot evaluate actions
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/evaluate")
                .header("x-vellaveto-role", "auditor")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"tool":"test","function":"test","parameters":{}}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

// ────────────────────────────────
// Default Role Tests
// ────────────────────────────────

#[tokio::test]
async fn default_role_applied_when_no_header() {
    let config = RbacConfig {
        enabled: true,
        allow_header_role: true,
        default_role: Role::Viewer,
        jwt_config: None,
    };
    let (state, _tmp) = test_state_with_rbac(config);
    let app = routes::build_router(state);

    // No role header - should get default (Viewer) and be denied write
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/policies")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"id":"new","name":"New","policy_type":"allow","priority":1}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn default_role_can_read_policies() {
    let config = RbacConfig {
        enabled: true,
        allow_header_role: false, // Header role disabled
        default_role: Role::Viewer,
        jwt_config: None,
    };
    let (state, _tmp) = test_state_with_rbac(config);
    let app = routes::build_router(state);

    // Default role (Viewer) can read policies
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/policies")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

// ────────────────────────────────
// JWT-Based Role Tests
// ────────────────────────────────

const TEST_SECRET: &str = "test-secret-for-jwt-validation-256bit";

#[tokio::test]
async fn jwt_admin_role_can_write() {
    let config = RbacConfig {
        enabled: true,
        allow_header_role: false,
        default_role: Role::Viewer,
        jwt_config: Some(JwtConfig {
            key: JwtKey::Secret(TEST_SECRET.to_string()),
            algorithms: vec![jsonwebtoken::Algorithm::HS256],
            issuer: None,
            audience: None,
            leeway_seconds: 60,
        }),
    };
    let (state, _tmp) = test_state_with_rbac(config);
    let app = routes::build_router(state);

    let token = create_jwt("admin", TEST_SECRET);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/policies")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"id":"new","name":"New","policy_type":"allow","priority":1}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    // Should not be forbidden
    assert_ne!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn jwt_viewer_role_denied_write() {
    let config = RbacConfig {
        enabled: true,
        allow_header_role: false,
        default_role: Role::Viewer,
        jwt_config: Some(JwtConfig {
            key: JwtKey::Secret(TEST_SECRET.to_string()),
            algorithms: vec![jsonwebtoken::Algorithm::HS256],
            issuer: None,
            audience: None,
            leeway_seconds: 60,
        }),
    };
    let (state, _tmp) = test_state_with_rbac(config);
    let app = routes::build_router(state);

    let token = create_jwt("viewer", TEST_SECRET);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/policies")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"id":"new","name":"New","policy_type":"allow","priority":1}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn jwt_operator_can_evaluate() {
    let config = RbacConfig {
        enabled: true,
        allow_header_role: false,
        default_role: Role::Viewer,
        jwt_config: Some(JwtConfig {
            key: JwtKey::Secret(TEST_SECRET.to_string()),
            algorithms: vec![jsonwebtoken::Algorithm::HS256],
            issuer: None,
            audience: None,
            leeway_seconds: 60,
        }),
    };
    let (state, _tmp) = test_state_with_rbac(config);
    let app = routes::build_router(state);

    let token = create_jwt("operator", TEST_SECRET);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/evaluate")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"tool":"test","function":"test","parameters":{}}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    // Should not be forbidden (operator has Evaluate permission)
    assert_ne!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn jwt_operator_can_evaluate_when_api_key_is_configured() {
    let config = RbacConfig {
        enabled: true,
        allow_header_role: false,
        default_role: Role::Viewer,
        jwt_config: Some(JwtConfig {
            key: JwtKey::Secret(TEST_SECRET.to_string()),
            algorithms: vec![jsonwebtoken::Algorithm::HS256],
            issuer: None,
            audience: None,
            leeway_seconds: 60,
        }),
    };
    let (state, _tmp) = test_state_with_rbac_and_api_key(config, Some("legacy-api-key"));
    let app = routes::build_router(state);

    let token = create_jwt("operator", TEST_SECRET);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/evaluate")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"tool":"test","function":"test","parameters":{}}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    // JWT-authenticated requests should not be blocked by API key middleware.
    assert_ne!(response.status(), StatusCode::UNAUTHORIZED);
    assert_ne!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn jwt_mode_with_api_key_still_requires_auth_header() {
    let config = RbacConfig {
        enabled: true,
        allow_header_role: false,
        default_role: Role::Viewer,
        jwt_config: Some(JwtConfig {
            key: JwtKey::Secret(TEST_SECRET.to_string()),
            algorithms: vec![jsonwebtoken::Algorithm::HS256],
            issuer: None,
            audience: None,
            leeway_seconds: 60,
        }),
    };
    let (state, _tmp) = test_state_with_rbac_and_api_key(config, Some("legacy-api-key"));
    let app = routes::build_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/policies")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // With API key configured, missing Authorization must still be rejected.
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn jwt_mode_without_api_key_still_requires_auth_header() {
    let config = RbacConfig {
        enabled: true,
        allow_header_role: false,
        default_role: Role::Viewer,
        jwt_config: Some(JwtConfig {
            key: JwtKey::Secret(TEST_SECRET.to_string()),
            algorithms: vec![jsonwebtoken::Algorithm::HS256],
            issuer: None,
            audience: None,
            leeway_seconds: 60,
        }),
    };
    let (state, _tmp) = test_state_with_rbac(config);
    let app = routes::build_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/policies")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // In JWT mode, protected endpoints must not fall back to the default role.
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn jwt_mode_with_header_role_enabled_still_requires_explicit_auth_material() {
    let config = RbacConfig {
        enabled: true,
        allow_header_role: true,
        default_role: Role::Viewer,
        jwt_config: Some(JwtConfig {
            key: JwtKey::Secret(TEST_SECRET.to_string()),
            algorithms: vec![jsonwebtoken::Algorithm::HS256],
            issuer: None,
            audience: None,
            leeway_seconds: 60,
        }),
    };
    let (state, _tmp) = test_state_with_rbac(config);
    let app = routes::build_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/policies")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn jwt_mode_with_header_role_enabled_accepts_role_header_path() {
    let config = RbacConfig {
        enabled: true,
        allow_header_role: true,
        default_role: Role::Viewer,
        jwt_config: Some(JwtConfig {
            key: JwtKey::Secret(TEST_SECRET.to_string()),
            algorithms: vec![jsonwebtoken::Algorithm::HS256],
            issuer: None,
            audience: None,
            leeway_seconds: 60,
        }),
    };
    let (state, _tmp) = test_state_with_rbac(config);
    let app = routes::build_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/policies")
                .header("x-vellaveto-role", "viewer")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn jwt_mode_with_header_role_enabled_rejects_invalid_role_header() {
    let config = RbacConfig {
        enabled: true,
        allow_header_role: true,
        default_role: Role::Viewer,
        jwt_config: Some(JwtConfig {
            key: JwtKey::Secret(TEST_SECRET.to_string()),
            algorithms: vec![jsonwebtoken::Algorithm::HS256],
            issuer: None,
            audience: None,
            leeway_seconds: 60,
        }),
    };
    let (state, _tmp) = test_state_with_rbac(config);
    let app = routes::build_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/policies")
                .header("x-vellaveto-role", "not-a-role")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn jwt_invalid_token_is_rejected() {
    let config = RbacConfig {
        enabled: true,
        allow_header_role: false,
        default_role: Role::Viewer,
        jwt_config: Some(JwtConfig {
            key: JwtKey::Secret(TEST_SECRET.to_string()),
            algorithms: vec![jsonwebtoken::Algorithm::HS256],
            issuer: None,
            audience: None,
            leeway_seconds: 60,
        }),
    };
    let (state, _tmp) = test_state_with_rbac(config);
    let app = routes::build_router(state);

    // Use wrong secret - token won't validate
    let token = create_jwt("admin", "wrong-secret");

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/policies")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"id":"new","name":"New","policy_type":"allow","priority":1}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    // Invalid JWT is rejected fail-closed; it must not fall back to default role.
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

// ────────────────────────────────
// Health Endpoint Tests
// ────────────────────────────────

#[tokio::test]
async fn health_always_accessible() {
    let config = RbacConfig {
        enabled: true,
        allow_header_role: false,
        default_role: Role::Viewer,
        jwt_config: None,
    };
    let (state, _tmp) = test_state_with_rbac(config);
    let app = routes::build_router(state);

    // Health endpoint should always be accessible
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn health_accessible_even_with_invalid_jwt_header() {
    let config = RbacConfig {
        enabled: true,
        allow_header_role: false,
        default_role: Role::Viewer,
        jwt_config: Some(JwtConfig {
            key: JwtKey::Secret(TEST_SECRET.to_string()),
            algorithms: vec![jsonwebtoken::Algorithm::HS256],
            issuer: None,
            audience: None,
            leeway_seconds: 60,
        }),
    };
    let (state, _tmp) = test_state_with_rbac(config);
    let app = routes::build_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/health")
                .header("authorization", "Bearer invalid.jwt.token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

// ────────────────────────────────
// Permission Matrix Tests
// ────────────────────────────────

/// Test that the permission matrix is correctly enforced for each role
#[tokio::test]
async fn permission_matrix_viewer() {
    let config = RbacConfig {
        enabled: true,
        allow_header_role: true,
        default_role: Role::Viewer,
        jwt_config: None,
    };
    let (state, _tmp) = test_state_with_rbac(config);

    // Viewer permissions: PolicyRead, AuditRead, DashboardAccess
    let tests = vec![
        ("GET", "/api/policies", true),      // PolicyRead - allowed
        ("POST", "/api/policies", false),    // PolicyWrite - denied
        ("GET", "/api/audit/entries", true), // AuditRead - allowed
        ("GET", "/api/audit/export", false), // AuditExport - denied
        ("POST", "/api/evaluate", false),    // Evaluate - denied
        ("GET", "/dashboard", true),         // DashboardAccess - allowed
    ];

    for (method, path, should_succeed) in tests {
        let app = routes::build_router(state.clone());
        let response = app
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .header("x-vellaveto-role", "viewer")
                    .header("content-type", "application/json")
                    .body(if method == "POST" {
                        Body::from(r#"{"tool":"t","function":"f","parameters":{}}"#)
                    } else {
                        Body::empty()
                    })
                    .unwrap(),
            )
            .await
            .unwrap();

        if should_succeed {
            assert_ne!(
                response.status(),
                StatusCode::FORBIDDEN,
                "Viewer should have access to {method} {path}"
            );
        } else {
            assert_eq!(
                response.status(),
                StatusCode::FORBIDDEN,
                "Viewer should NOT have access to {method} {path}"
            );
        }
    }
}

#[tokio::test]
async fn permission_matrix_operator() {
    let config = RbacConfig {
        enabled: true,
        allow_header_role: true,
        default_role: Role::Viewer,
        jwt_config: None,
    };
    let (state, _tmp) = test_state_with_rbac(config);

    // Operator permissions: PolicyRead, PolicyReload, ApprovalRead, ApprovalResolve,
    // AuditRead, MetricsRead, DashboardAccess, Evaluate, ToolRegistryRead
    let tests = vec![
        ("GET", "/api/policies", true),          // PolicyRead - allowed
        ("POST", "/api/policies", false),        // PolicyWrite - denied
        ("GET", "/api/audit/entries", true),     // AuditRead - allowed
        ("GET", "/api/audit/export", false),     // AuditExport - denied
        ("POST", "/api/evaluate", true),         // Evaluate - allowed
        ("GET", "/api/approvals/pending", true), // ApprovalRead - allowed
        ("GET", "/metrics", true),               // MetricsRead - allowed
    ];

    for (method, path, should_succeed) in tests {
        let app = routes::build_router(state.clone());
        let response = app
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .header("x-vellaveto-role", "operator")
                    .header("content-type", "application/json")
                    .body(if method == "POST" {
                        Body::from(r#"{"tool":"t","function":"f","parameters":{}}"#)
                    } else {
                        Body::empty()
                    })
                    .unwrap(),
            )
            .await
            .unwrap();

        if should_succeed {
            assert_ne!(
                response.status(),
                StatusCode::FORBIDDEN,
                "Operator should have access to {method} {path}"
            );
        } else {
            assert_eq!(
                response.status(),
                StatusCode::FORBIDDEN,
                "Operator should NOT have access to {method} {path}"
            );
        }
    }
}
