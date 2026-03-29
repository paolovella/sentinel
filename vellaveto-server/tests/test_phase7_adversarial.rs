// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Phase 7 adversarial exploit tests.
//!
//! Findings:
//! - #25 (HIGH): GET endpoints bypass API key authentication — audit logs,
//!   policies, pending approvals all readable without authorization
//! - #26 (MEDIUM): Unbounded approval creation — no max capacity on pending
//!   approvals HashMap, enables memory exhaustion DoS
//! - #27 (MEDIUM): ApprovalStore create() persist-before-lock race —
//!   approval is on disk but not yet in memory between persist and insert
//! - #28 (LOW): Silent malformed JSONL drop in load_from_file — data loss
//!   with no logging or error on restart
//! - #29 (LOW): persist_approval uses flush() without fsync() — durability
//!   gap on power loss

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
use vellaveto_types::{Action, Policy, PolicyType};

/// Helper to create AppState with an API key configured.
fn state_with_api_key(tmp: &TempDir) -> AppState {
    let audit = Arc::new(AuditLogger::new(tmp.path().join("audit.log")));
    AppState {
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
        api_key: Some(Arc::new("secret-api-key-12345".to_string())),
        rate_limits: Arc::new(RateLimits::new(None, None, None)),
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
        staging_snapshot: Arc::new(arc_swap::ArcSwap::from_pointee(None)),
        usage_tracker: None,
        topology_guard: None,
        topology_probe: None,
        recrawl_trigger: None,
    }
}

// =============================================================================
// Regression tests for Finding #25: GET endpoints previously bypassed API key
// authentication.
//
// FIXED: All sensitive GET endpoints now require auth when an API key is
// configured. Only /health remains public. /api/metrics and /metrics were
// moved behind auth in R38-SRV-1.
// =============================================================================

#[tokio::test]
async fn regression_25_policies_not_readable_without_auth() {
    let tmp = TempDir::new().unwrap();
    let state = state_with_api_key(&tmp);

    // Verify POST is still protected
    let app = routes::build_router(state.clone());
    let resp = app
        .oneshot(
            Request::post("/api/evaluate")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"tool":"file","function":"read","parameters":{}}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "POST without API key should be rejected"
    );

    // GET /api/policies without auth must now be rejected (fix for #25)
    let app = routes::build_router(state.clone());
    let resp = app
        .oneshot(Request::get("/api/policies").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "GET /api/policies without auth must return 401 (regression #25)"
    );
}

#[tokio::test]
async fn regression_25_audit_entries_not_readable_without_auth() {
    let tmp = TempDir::new().unwrap();
    let state = state_with_api_key(&tmp);

    // First, create an audit entry via authenticated evaluate
    let app = routes::build_router(state.clone());
    let resp = app
        .oneshot(
            Request::post("/api/evaluate")
                .header("content-type", "application/json")
                .header("authorization", "Bearer secret-api-key-12345")
                .body(Body::from(
                    r#"{"tool":"file","function":"read","parameters":{"path":"/etc/shadow"}}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "Authenticated evaluate should work"
    );

    // GET /api/audit/entries without auth must now be rejected (fix for #25)
    let app = routes::build_router(state.clone());
    let resp = app
        .oneshot(
            Request::get("/api/audit/entries")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "GET /api/audit/entries without auth must return 401 (regression #25)"
    );
}

#[tokio::test]
async fn regression_25_pending_approvals_not_readable_without_auth() {
    let tmp = TempDir::new().unwrap();
    let state = state_with_api_key(&tmp);

    // Create a pending approval directly in the store
    state
        .approvals
        .create(
            Action::new(
                "admin".to_string(),
                "delete_user".to_string(),
                json!({"user": "admin", "secret_token": "tok_live_abc123"}),
            ),
            "needs review".to_string(),
            None,
            None,
            None,
        )
        .await
        .unwrap();

    // GET /api/approvals/pending without auth must now be rejected (fix for #25)
    let app = routes::build_router(state.clone());
    let resp = app
        .oneshot(
            Request::get("/api/approvals/pending")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "GET /api/approvals/pending without auth must return 401 (regression #25)"
    );
}

/// R38-SRV-1: /api/metrics now requires auth because it exposes policy count
/// and pending approval count (security-sensitive per R26-SRV-6).
#[tokio::test]
async fn regression_38_metrics_requires_auth() {
    let tmp = TempDir::new().unwrap();
    let state = state_with_api_key(&tmp);

    // /api/metrics is now protected — must return 401 without API key
    let app = routes::build_router(state.clone());
    let resp = app
        .oneshot(Request::get("/api/metrics").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "GET /api/metrics must require auth (R38-SRV-1)"
    );

    // With valid API key, /api/metrics should return 200
    let app = routes::build_router(state.clone());
    let resp = app
        .oneshot(
            Request::get("/api/metrics")
                .header("authorization", "Bearer secret-api-key-12345")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "GET /api/metrics should succeed with valid auth"
    );
}

/// R38-SRV-1: /metrics (Prometheus) also requires auth — exposes
/// vellaveto_policies_loaded and vellaveto_active_sessions gauges.
#[tokio::test]
async fn regression_38_prometheus_metrics_requires_auth() {
    let tmp = TempDir::new().unwrap();
    let state = state_with_api_key(&tmp);

    // /metrics without API key must return 401
    let app = routes::build_router(state.clone());
    let resp = app
        .oneshot(Request::get("/metrics").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "GET /metrics must require auth (R38-SRV-1)"
    );
}

/// R38-SRV-2: /metrics (Prometheus) is rate-limited — prevents scraper DoS.
#[tokio::test]
async fn regression_38_prometheus_metrics_rate_limited() {
    let tmp = TempDir::new().unwrap();
    let audit = Arc::new(AuditLogger::new(tmp.path().join("audit.log")));
    // Create state with API key and tight rate limits to test rate limiting
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
        api_key: Some(Arc::new("secret-api-key-12345".to_string())),
        // Very tight rate limit: 1 request per second on readonly (GET) endpoints
        rate_limits: Arc::new(RateLimits::new(None, None, Some(1))),
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

    // First request should succeed
    let app = routes::build_router(state.clone());
    let resp = app
        .oneshot(
            Request::get("/metrics")
                .header("authorization", "Bearer secret-api-key-12345")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    // May be 404 (no prometheus_handle) or 200 — but NOT 429 on first request
    assert_ne!(
        resp.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "First /metrics request should not be rate-limited"
    );

    // Rapid subsequent requests should eventually hit rate limit
    let mut hit_rate_limit = false;
    for _ in 0..20 {
        let app = routes::build_router(state.clone());
        let resp = app
            .oneshot(
                Request::get("/metrics")
                    .header("authorization", "Bearer secret-api-key-12345")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        if resp.status() == StatusCode::TOO_MANY_REQUESTS {
            hit_rate_limit = true;
            break;
        }
    }
    assert!(hit_rate_limit, "/metrics must be rate-limited (R38-SRV-2)");
}

// =============================================================================
// Finding #26: Unbounded approval creation — memory exhaustion DoS.
//
// ApprovalStore.pending is a HashMap<String, PendingApproval> with no max
// capacity. Each PendingApproval contains the full Action (including arbitrary
// JSON parameters). An attacker who can trigger RequireApproval verdicts (or
// directly call create()) floods the store with entries.
//
// expire_stale() runs periodically but only removes entries past their TTL.
// With a 15-minute default TTL, an attacker creating 1000 entries/second
// accumulates 900,000 entries before the first cleanup. Each entry with a
// 1KB parameter payload = ~900MB of memory.
// =============================================================================

#[tokio::test]
async fn exploit_26_unbounded_approval_creation() {
    let tmp = TempDir::new().unwrap();
    let store = ApprovalStore::new(
        tmp.path().join("approvals.jsonl"),
        std::time::Duration::from_secs(3600), // 1 hour TTL — entries stick around
    );

    // Create 1000 approvals with non-trivial parameters
    for i in 0..1000 {
        let action = Action::new(
            "admin".to_string(),
            "delete".to_string(),
            json!({
                "target": format!("user_{}", i),
                "padding": "x".repeat(512), // ~512 bytes per entry
            }),
        );
        store
            .create(action, format!("reason_{i}"), None, None, None)
            .await
            .unwrap();
    }

    // All 1000 are pending — no limit enforced
    let pending = store.list_pending().await;
    assert_eq!(
        pending.len(),
        1000,
        "All 1000 approvals created — no capacity limit exists"
    );

    // expire_stale won't help — entries are within TTL
    let expired = store.expire_stale().await;
    assert_eq!(expired, 0, "No entries expired — all within 1-hour TTL");
    let still_pending = store.list_pending().await;
    assert_eq!(
        still_pending.len(),
        1000,
        "All 1000 still in memory after expire_stale — unbounded growth confirmed"
    );
}

// =============================================================================
// Finding #27: ApprovalStore create() persist-before-lock race.
//
// create() calls persist_approval() BEFORE acquiring the write lock and
// inserting into the HashMap. Between persist and insert, the approval exists
// on disk but not in memory. A concurrent reader (get, list_pending) won't
// see it. If the server crashes between persist and insert, restart recovers
// it from disk — but during normal operation there's a visibility gap.
// =============================================================================

#[tokio::test]
async fn exploit_27_create_persist_before_lock_ordering() {
    let tmp = TempDir::new().unwrap();
    let log_path = tmp.path().join("approvals.jsonl");
    let store = Arc::new(ApprovalStore::new(
        log_path.clone(),
        std::time::Duration::from_secs(900),
    ));

    // Demonstrate the ordering: after create() returns, the entry is in
    // both disk and memory. But the code path is:
    //   1. persist_approval() — writes to disk (no lock)
    //   2. pending.write().await — acquires lock
    //   3. pending.insert() — adds to memory
    //
    // The vulnerability window is between steps 1 and 3. We can't easily
    // observe it in a single-threaded test, but we can verify the ordering
    // by checking that the file has more entries than the memory store after
    // concurrent creates with controlled timing.

    let store_clone = store.clone();
    let (tx, rx) = tokio::sync::oneshot::channel::<String>();

    // Create an approval
    let id = store
        .create(
            Action::new("file".to_string(), "read".to_string(), json!({})),
            "test".to_string(),
            None,
            None,
            None,
        )
        .await
        .unwrap();

    // After create() returns, entry should be in memory
    let approval = store.get(&id).await;
    assert!(
        approval.is_ok(),
        "Entry must be in memory after create returns"
    );

    // Also verify it's on disk
    let content = tokio::fs::read_to_string(&log_path).await.unwrap();
    assert!(
        content.contains(&id),
        "Entry must be on disk after create returns"
    );

    // The risk: if we could intercept between persist and lock-acquire,
    // a concurrent get() would return NotFound. This test documents the
    // ordering issue even though we can't reliably trigger the race here.
    //
    // Fix: acquire the write lock BEFORE persisting, or persist inside the
    // lock scope (like approve() and deny() already do).
    let _ = (tx, rx, store_clone); // suppress unused warnings
}

// =============================================================================
// Finding #28: Silent malformed JSONL drop in load_from_file.
//
// When load_from_file() encounters a malformed JSON line, it silently skips
// it via `if let Ok(...)`. No error is logged, no count of skipped lines
// is returned. An attacker who corrupts the JSONL file (partial write,
// disk error, or deliberate tampering) causes approvals to silently
// disappear on restart.
// =============================================================================

#[tokio::test]
async fn exploit_28_silent_malformed_jsonl_drop() {
    let tmp = TempDir::new().unwrap();
    let log_path = tmp.path().join("approvals.jsonl");

    // Create a store with a valid entry
    let store1 = ApprovalStore::new(log_path.clone(), std::time::Duration::from_secs(900));
    let id = store1
        .create(
            Action::new("file".to_string(), "read".to_string(), json!({})),
            "important approval".to_string(),
            None,
            None,
            None,
        )
        .await
        .unwrap();

    // Verify it's on disk
    let content = tokio::fs::read_to_string(&log_path).await.unwrap();
    assert!(content.contains(&id));

    // Corrupt the file by inserting a malformed line BEFORE the valid entry
    let corrupted =
        format!("{{\"id\":\"corrupt\",\"status\":\"INVALID_VALUE\",\"malformed\n{content}");
    tokio::fs::write(&log_path, corrupted).await.unwrap();

    // Load into a new store
    let store2 = ApprovalStore::new(log_path.clone(), std::time::Duration::from_secs(900));
    let loaded = store2.load_from_file().await.unwrap();

    // The valid entry survived, but the corrupted line was SILENTLY dropped.
    // load_from_file returns Ok(1), not Err — no indication of corruption.
    assert_eq!(
        loaded, 1,
        "Only 1 entry loaded — corrupted line silently dropped with no error"
    );

    // The malformed line is gone without a trace. No error, no warning,
    // no count of skipped lines. If the corrupted line had been a VALID
    // entry that was partially truncated, it would also be silently lost.
    let result = store2.get("corrupt").await;
    assert!(
        result.is_err(),
        "Corrupted entry silently skipped — no error surfaced to caller"
    );
}

#[tokio::test]
async fn exploit_28_truncated_entry_silently_lost() {
    let tmp = TempDir::new().unwrap();
    let log_path = tmp.path().join("approvals.jsonl");

    // Create two valid entries
    let store1 = ApprovalStore::new(log_path.clone(), std::time::Duration::from_secs(900));
    let id1 = store1
        .create(
            Action::new(
                "admin".to_string(),
                "approve_transfer".to_string(),
                json!({"amount": 50000}),
            ),
            "high-value transfer".to_string(),
            None,
            None,
            None,
        )
        .await
        .unwrap();
    let id2 = store1
        .create(
            Action::new("file".to_string(), "delete".to_string(), json!({})),
            "file deletion".to_string(),
            None,
            None,
            None,
        )
        .await
        .unwrap();

    // Simulate a power loss that truncates the second entry mid-write
    let content = tokio::fs::read_to_string(&log_path).await.unwrap();
    let lines: Vec<&str> = content.lines().collect();
    assert_eq!(lines.len(), 2);

    // Truncate the second line to 20 chars (invalid JSON)
    let truncated = format!("{}\n{}\n", lines[0], &lines[1][..20]);
    tokio::fs::write(&log_path, truncated).await.unwrap();

    // Load from corrupted file
    let store2 = ApprovalStore::new(log_path, std::time::Duration::from_secs(900));
    let loaded = store2.load_from_file().await.unwrap();

    // Only 1 entry loaded — the truncated one is silently lost
    assert_eq!(loaded, 1, "Only first entry survived truncation");
    assert!(store2.get(&id1).await.is_ok(), "First entry survives");
    assert!(
        store2.get(&id2).await.is_err(),
        "Second entry silently lost due to truncation — no error reported"
    );
}

// =============================================================================
// Finding #29: persist_approval calls flush() but not fsync().
//
// On line 256, the code calls file.flush().await? which pushes data from
// the userspace buffer to the kernel, but doesn't call file.sync_all() or
// file.sync_data() which would force the kernel to flush to stable storage.
// This means a power loss after flush() but before the kernel writes to
// disk can lose approval state changes (approved actions revert to pending
// on restart).
//
// This is documented here but not exploitable in a unit test — it requires
// actual power loss or OS-level fsync behavior testing.
// =============================================================================

// (Finding #29 is not testable in unit tests — requires power failure simulation)
// Documented in the findings report for manual verification.

// =============================================================================
// Bonus: Approval endpoints don't validate resolved_by field length.
//
// The ResolveRequest.resolved_by field has no length limit. An attacker
// can send a multi-megabyte resolved_by string, which gets stored in memory
// and persisted to disk.
// =============================================================================

#[tokio::test]
async fn exploit_bonus_resolved_by_unbounded_length() {
    let tmp = TempDir::new().unwrap();
    let store = ApprovalStore::new(
        tmp.path().join("approvals.jsonl"),
        std::time::Duration::from_secs(900),
    );

    let id = store
        .create(
            Action::new("file".to_string(), "read".to_string(), json!({})),
            "test".to_string(),
            None,
            None,
            None,
        )
        .await
        .unwrap();

    // SECURITY (R39-SUP-6): resolved_by length is now bounded at store level.
    // A ridiculously long resolved_by string should be rejected.
    let huge_name = "A".repeat(100_000); // 100KB
    let result = store.approve(&id, &huge_name).await;
    assert!(
        result.is_err(),
        "Store should reject overly long resolved_by"
    );

    // Verify that a reasonable-length identity is accepted
    let ok_name = "A".repeat(512); // At the limit
    let result = store.approve(&id, &ok_name).await;
    assert!(result.is_ok(), "512-byte identity should be accepted");
}
