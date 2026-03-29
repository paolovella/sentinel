// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Security regression tests for per-IP rate limiting.
//!
//! Originally written as adversary exploit demonstrations (Phase 6).
//! Now converted to regression tests that verify the fixes remain in place.
//!
//! Findings addressed:
//! - #18 (HIGH): XFF spoofing bypass → Fixed: proxy headers ignored without trusted_proxies
//! - #19 (MEDIUM): Unbounded DashMap → Fixed: max_capacity with fail-closed
//! - #20 (LOW): Localhost collapse → Fixed: ConnectInfo used instead of header fallback
//! - #21 (HIGH): IP impersonation → Fixed: proxy headers ignored without trusted_proxies
//! - #22 (LOW): Verify exits 0 on duplicates → Fixed: exit code 2 on duplicate IDs
//! - #23 (LOW): XFF leftmost attacker-controlled → Fixed: rightmost-untrusted with trusted_proxies
//! - #24 (LOW): Error leaks rate limit type → Fixed: unified error message

use arc_swap::ArcSwap;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use std::sync::Arc;
use tempfile::TempDir;
use tower::ServiceExt;
use vellaveto_approval::ApprovalStore;
use vellaveto_audit::AuditLogger;
use vellaveto_engine::PolicyEngine;
use vellaveto_server::{routes, AppState, Metrics, PerIpRateLimiter, RateLimits};
use vellaveto_types::{Policy, PolicyType};

fn per_ip_state(rps: u32) -> (AppState, TempDir) {
    let tmp = TempDir::new().unwrap();
    let audit = Arc::new(AuditLogger::new(tmp.path().join("audit.log")));
    let state = AppState {
        policy_state: Arc::new(ArcSwap::from_pointee(vellaveto_server::PolicySnapshot {
            engine: PolicyEngine::new(false),
            policies: vec![Policy {
                id: "file:read".to_string(),
                name: "Allow".to_string(),
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
        api_key: None,
        rate_limits: Arc::new(
            RateLimits::new(None, None, None).with_per_ip(std::num::NonZeroU32::new(rps).unwrap()),
        ),
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

// =============================================================================
// Finding #18 FIXED: XFF spoofing no longer bypasses rate limiting.
//
// With trusted_proxies empty (default), proxy headers are ignored entirely.
// All requests are attributed to the connection IP (127.0.0.1 in tests),
// so spoofing X-Forwarded-For has no effect on rate limiting.
// =============================================================================

#[tokio::test]
async fn regression_18_xff_spoofing_blocked_without_trusted_proxies() {
    // Per-IP limit of 1 req/s, no trusted proxies
    let (state, _tmp) = per_ip_state(1);
    let body_str = r#"{"tool":"file","function":"read","parameters":{}}"#;

    // First request succeeds (new bucket for connection IP)
    let app = routes::build_router(state.clone());
    let resp = app
        .oneshot(
            Request::post("/api/evaluate")
                .header("content-type", "application/json")
                .header("x-forwarded-for", "10.0.0.1")
                .body(Body::from(body_str))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(resp.status().is_success(), "First request should succeed");

    // Second request with DIFFERENT spoofed XFF — still rate-limited because
    // without trusted_proxies, the XFF header is ignored. Both requests use
    // the same connection IP (127.0.0.1).
    let app = routes::build_router(state.clone());
    let resp = app
        .oneshot(
            Request::post("/api/evaluate")
                .header("content-type", "application/json")
                .header("x-forwarded-for", "10.0.0.2")
                .body(Body::from(body_str))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "XFF spoofing must not bypass rate limiting when trusted_proxies is empty"
    );
}

#[tokio::test]
async fn regression_18_xri_spoofing_blocked_without_trusted_proxies() {
    let (state, _tmp) = per_ip_state(1);
    let body_str = r#"{"tool":"file","function":"read","parameters":{}}"#;

    // First request succeeds
    let app = routes::build_router(state.clone());
    let resp = app
        .oneshot(
            Request::post("/api/evaluate")
                .header("content-type", "application/json")
                .header("x-real-ip", "192.168.1.1")
                .body(Body::from(body_str))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(resp.status().is_success());

    // Second request with different X-Real-IP — still rate-limited
    let app = routes::build_router(state.clone());
    let resp = app
        .oneshot(
            Request::post("/api/evaluate")
                .header("content-type", "application/json")
                .header("x-real-ip", "192.168.1.2")
                .body(Body::from(body_str))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "X-Real-IP spoofing must not bypass rate limiting when trusted_proxies is empty"
    );
}

// =============================================================================
// Finding #19 FIXED: DashMap growth is bounded by max_capacity.
//
// When the limiter reaches max_capacity, new IPs are denied (fail-closed)
// instead of creating unbounded entries.
// =============================================================================

#[test]
fn regression_19_dashmap_growth_bounded() {
    // Create limiter with a small max capacity for testing
    let limiter = PerIpRateLimiter::with_max_capacity(std::num::NonZeroU32::new(10).unwrap(), 100);

    // Fill to capacity
    for i in 0..100u32 {
        let ip: std::net::IpAddr = std::net::Ipv4Addr::from(i.wrapping_add(167_772_160)).into();
        let _ = limiter.check(ip);
    }
    assert_eq!(limiter.len(), 100, "Should have 100 entries at capacity");

    // Attempt to add more — should be denied, not inserted
    let new_ip: std::net::IpAddr = std::net::Ipv4Addr::from(200_000_000u32).into();
    let result = limiter.check(new_ip);
    assert!(
        result.is_some(),
        "New IPs must be denied when at max capacity (fail-closed)"
    );
    assert_eq!(
        limiter.len(),
        100,
        "No new entries should be inserted when at max capacity"
    );

    // Existing IPs still work (not locked out)
    let existing_ip: std::net::IpAddr = std::net::Ipv4Addr::from(167_772_160u32).into();
    let result = limiter.check(existing_ip);
    assert!(
        result.is_none(),
        "Existing IPs should still be allowed when at capacity"
    );
}

#[test]
fn regression_19_cleanup_frees_capacity() {
    let limiter = PerIpRateLimiter::with_max_capacity(std::num::NonZeroU32::new(10).unwrap(), 50);

    // Fill to capacity
    for i in 0..50u32 {
        let ip: std::net::IpAddr = std::net::Ipv4Addr::from(i.wrapping_add(167_772_160)).into();
        let _ = limiter.check(ip);
    }
    assert_eq!(limiter.len(), 50);

    // Cleanup with 0 duration removes all entries
    limiter.cleanup(std::time::Duration::from_secs(0));
    assert_eq!(limiter.len(), 0, "Cleanup should free all entries");

    // New IPs can now be admitted
    let new_ip: std::net::IpAddr = std::net::Ipv4Addr::from(200_000_000u32).into();
    let result = limiter.check(new_ip);
    assert!(
        result.is_none(),
        "New IPs should be allowed after cleanup frees capacity"
    );
}

// =============================================================================
// Finding #20 FIXED: Without proxy headers, connection IP is used.
//
// In test environments without real TCP connections, ConnectInfo isn't set
// so the fallback is 127.0.0.1. This is correct behavior — all test
// requests from the same process share one bucket, as they should.
// In production with real connections, each TCP connection has its own IP.
// =============================================================================

#[tokio::test]
async fn regression_20_direct_clients_use_connection_ip() {
    let (state, _tmp) = per_ip_state(1);
    let body_str = r#"{"tool":"file","function":"read","parameters":{}}"#;

    // First request succeeds — uses connection IP (127.0.0.1 in test)
    let app = routes::build_router(state.clone());
    let resp = app
        .oneshot(
            Request::post("/api/evaluate")
                .header("content-type", "application/json")
                .body(Body::from(body_str))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(resp.status().is_success(), "First direct request succeeds");

    // Second request is properly rate-limited on the same connection IP.
    // This is correct behavior — in production, different clients have
    // different connection IPs via ConnectInfo<SocketAddr>.
    let app = routes::build_router(state.clone());
    let resp = app
        .oneshot(
            Request::post("/api/evaluate")
                .header("content-type", "application/json")
                .body(Body::from(body_str))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "Second request from same connection IP is properly rate-limited"
    );
}

// =============================================================================
// Finding #21 FIXED: IP impersonation blocked.
//
// Without trusted_proxies, X-Forwarded-For is ignored. An attacker cannot
// consume another user's rate limit bucket by spoofing their IP.
// =============================================================================

#[tokio::test]
async fn regression_21_ip_impersonation_blocked() {
    let (state, _tmp) = per_ip_state(1);
    let body_str = r#"{"tool":"file","function":"read","parameters":{}}"#;

    let victim_ip = "203.0.113.42";

    // Attacker tries to impersonate victim via X-Forwarded-For
    let app = routes::build_router(state.clone());
    let resp = app
        .oneshot(
            Request::post("/api/evaluate")
                .header("content-type", "application/json")
                .header("x-forwarded-for", victim_ip)
                .body(Body::from(body_str))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(resp.status().is_success(), "First request succeeds");

    // Attacker's second request is rate-limited on THEIR connection IP (127.0.0.1),
    // not on the victim's IP. The spoofed header is ignored.
    let app = routes::build_router(state.clone());
    let resp = app
        .oneshot(
            Request::post("/api/evaluate")
                .header("content-type", "application/json")
                .header("x-forwarded-for", victim_ip)
                .body(Body::from(body_str))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "Attacker is rate-limited on their own connection IP, not the victim's"
    );
}

// =============================================================================
// Finding #23 FIXED: XFF leftmost entry is ignored without trusted_proxies.
//
// With the empty trusted_proxies default, ALL proxy headers are ignored.
// When trusted_proxies is configured, the rightmost untrusted entry is used.
// =============================================================================

#[tokio::test]
async fn regression_23_xff_ignored_without_trusted_proxies() {
    let (state, _tmp) = per_ip_state(1);
    let body_str = r#"{"tool":"file","function":"read","parameters":{}}"#;

    // First request with crafted XFF chain — succeeds
    let app = routes::build_router(state.clone());
    let resp = app
        .oneshot(
            Request::post("/api/evaluate")
                .header("content-type", "application/json")
                .header("x-forwarded-for", "1.2.3.4, 10.0.0.1")
                .body(Body::from(body_str))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(resp.status().is_success());

    // Second request with DIFFERENT leftmost XFF entry — still rate-limited
    // because XFF is completely ignored without trusted_proxies
    let app = routes::build_router(state.clone());
    let resp = app
        .oneshot(
            Request::post("/api/evaluate")
                .header("content-type", "application/json")
                .header("x-forwarded-for", "5.6.7.8, 10.0.0.1")
                .body(Body::from(body_str))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "Changing leftmost XFF entry must not bypass rate limiting"
    );
}

// =============================================================================
// Finding #24 FIXED: Error responses use the same generic message.
//
// Both per-IP and global rate limit responses now say:
//   "Rate limit exceeded. Try again later."
// No architectural details are leaked.
// =============================================================================

#[tokio::test]
async fn regression_24_error_message_does_not_leak_architecture() {
    let tmp = TempDir::new().unwrap();
    let audit = Arc::new(AuditLogger::new(tmp.path().join("audit.log")));
    let state = AppState {
        policy_state: Arc::new(ArcSwap::from_pointee(vellaveto_server::PolicySnapshot {
            engine: PolicyEngine::new(false),
            policies: vec![Policy {
                id: "file:read".to_string(),
                name: "Allow".to_string(),
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
        api_key: None,
        rate_limits: Arc::new(
            RateLimits::new(Some(100), None, None)
                .with_per_ip(std::num::NonZeroU32::new(1).unwrap()),
        ),
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

    let body_str = r#"{"tool":"file","function":"read","parameters":{}}"#;

    // First request succeeds
    let app = routes::build_router(state.clone());
    let _ = app
        .oneshot(
            Request::post("/api/evaluate")
                .header("content-type", "application/json")
                .body(Body::from(body_str))
                .unwrap(),
        )
        .await
        .unwrap();

    // Second request triggers rate limit
    let app = routes::build_router(state.clone());
    let resp = app
        .oneshot(
            Request::post("/api/evaluate")
                .header("content-type", "application/json")
                .body(Body::from(body_str))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let body_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let error_msg = body_json["error"].as_str().unwrap();

    // Must NOT contain "Per-IP" or any architecture-revealing text
    assert!(
        !error_msg.contains("Per-IP") && !error_msg.contains("per-ip"),
        "Error message '{error_msg}' must not reveal which rate limiter triggered"
    );
    assert_eq!(
        error_msg, "Rate limit exceeded. Try again later.",
        "Error message should be generic"
    );
}

// =============================================================================
// Additional regression: max_capacity accessor works correctly
// =============================================================================

#[test]
fn regression_max_capacity_accessor() {
    let limiter = PerIpRateLimiter::new(std::num::NonZeroU32::new(10).unwrap());
    assert_eq!(
        limiter.max_capacity(),
        vellaveto_server::DEFAULT_MAX_IP_CAPACITY
    );

    let custom = PerIpRateLimiter::with_max_capacity(std::num::NonZeroU32::new(10).unwrap(), 500);
    assert_eq!(custom.max_capacity(), 500);
}
