// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Security Regression Tests for CRITICAL/HIGH Findings 1-14
//!
//! These tests verify that each vulnerability identified in the Controller's
//! external security audit is properly fixed. Each test attempts the attack
//! described in the audit report and confirms the fix blocks it.
//!
//! Reference: `.collab/orchestrator/issues/external-audit-report.md`

use arc_swap::ArcSwap;
use axum::body::Body;
use axum::http::Request;
use serde_json::json;
use std::io::Cursor;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::io::BufReader;
use tower::ServiceExt;
use vellaveto_approval::ApprovalStore;
use vellaveto_audit::AuditLogger;
use vellaveto_engine::PolicyEngine;
use vellaveto_mcp::extractor::{classify_message, MessageType};
use vellaveto_mcp::framing::{read_message, FramingError};
use vellaveto_server::{routes, AppState, Metrics, RateLimits};
use vellaveto_types::{Action, Policy, PolicyType, Verdict};

// ═══════════════════════════════════════════════════
// FINDING #1 — Hash chain bypass (CRITICAL)
//
// Attack: Insert a hashless entry after the chain has started.
// The old code accepted it silently, letting an attacker splice
// entries into the audit log undetected.
// Fix: verify_chain() rejects hashless entries after the first hashed one.
// ═══════════════════════════════════════════════════

#[tokio::test]
async fn finding_1_hashless_entry_after_chain_start_rejected() {
    let tmp = TempDir::new().unwrap();
    let log_path = tmp.path().join("audit.log");

    // Phase 1: Create a valid hashed chain with 2 entries
    let logger = AuditLogger::new(log_path.clone());
    let action = Action::new(
        "file".to_string(),
        "read".to_string(),
        json!({"path": "/tmp/test"}),
    );
    logger
        .log_entry(&action, &Verdict::Allow, json!({}))
        .await
        .unwrap();
    logger
        .log_entry(
            &action,
            &Verdict::Deny {
                reason: "blocked".to_string(),
            },
            json!({}),
        )
        .await
        .unwrap();

    // Verify chain is valid
    let verification = logger.verify_chain().await.unwrap();
    assert!(verification.valid, "Initial chain should be valid");

    // Phase 2: Tamper — inject a hashless entry into the log file
    let entries = logger.load_entries().await.unwrap();
    assert!(
        entries[0].entry_hash.is_some(),
        "Entries should have hashes"
    );

    // Create a fake entry without hashes and append it
    let fake_entry = json!({
        "id": "injected-fake",
        "action": {"tool": "bash", "function": "exec", "parameters": {"cmd": "rm -rf /"}},
        "verdict": "Allow",
        "timestamp": "2026-01-01T00:00:00Z",
        "metadata": {}
        // No entry_hash or prev_hash — this is the attack
    });
    let mut log_content = tokio::fs::read_to_string(&log_path).await.unwrap();
    log_content.push_str(&serde_json::to_string(&fake_entry).unwrap());
    log_content.push('\n');
    tokio::fs::write(&log_path, log_content).await.unwrap();

    // Phase 3: Verify that the chain is now invalid
    let logger2 = AuditLogger::new(log_path);
    let verification = logger2.verify_chain().await.unwrap();
    assert!(
        !verification.valid,
        "Chain with injected hashless entry must be detected as invalid"
    );
}

// ═══════════════════════════════════════════════════
// FINDING #2 — Hash chain field separators (CRITICAL)
//
// Attack: Two entries with boundary-shifted fields produce the same hash.
// e.g., tool="ab", function="cd" vs tool="abc", function="d"
// Fix: Length-prefixed encoding prevents field boundary collisions.
// ═══════════════════════════════════════════════════

#[tokio::test]
async fn finding_2_boundary_shifted_fields_produce_different_hashes() {
    let tmp = TempDir::new().unwrap();

    // Entry A: tool="ab", function="cd"
    let logger_a = AuditLogger::new(tmp.path().join("a.log"));
    let action_a = Action::new("ab".to_string(), "cd".to_string(), json!({}));
    logger_a
        .log_entry(&action_a, &Verdict::Allow, json!({}))
        .await
        .unwrap();

    // Entry B: tool="abc", function="d"
    let logger_b = AuditLogger::new(tmp.path().join("b.log"));
    let action_b = Action::new("abc".to_string(), "d".to_string(), json!({}));
    logger_b
        .log_entry(&action_b, &Verdict::Allow, json!({}))
        .await
        .unwrap();

    let entries_a = logger_a.load_entries().await.unwrap();
    let entries_b = logger_b.load_entries().await.unwrap();

    let hash_a = entries_a[0].entry_hash.as_ref().unwrap();
    let hash_b = entries_b[0].entry_hash.as_ref().unwrap();

    assert_ne!(
        hash_a, hash_b,
        "Boundary-shifted fields must produce different hashes (length-prefix encoding)"
    );
}

// ═══════════════════════════════════════════════════
// FINDING #3 — initialize_chain trusts file (CRITICAL)
//
// Attack: Tamper with the log file, then restart the logger.
// The old code would trust the last entry's hash and chain from it.
// Fix: initialize_chain() verifies the chain before trusting it.
// ═══════════════════════════════════════════════════

#[tokio::test]
async fn finding_3_initialize_chain_detects_tampered_file() {
    let tmp = TempDir::new().unwrap();
    let log_path = tmp.path().join("audit.log");

    // Create a valid chain
    let logger = AuditLogger::new(log_path.clone());
    let action = Action::new(
        "file".to_string(),
        "read".to_string(),
        json!({"path": "/tmp/safe"}),
    );
    logger
        .log_entry(&action, &Verdict::Allow, json!({}))
        .await
        .unwrap();
    logger
        .log_entry(
            &action,
            &Verdict::Deny {
                reason: "blocked".to_string(),
            },
            json!({}),
        )
        .await
        .unwrap();

    // Tamper: modify the entry_hash of the first entry (preserving valid JSON)
    let content = tokio::fs::read_to_string(&log_path).await.unwrap();
    let mut lines: Vec<String> = content.lines().map(|l| l.to_string()).collect();
    assert_eq!(lines.len(), 2, "Should have 2 entries");

    // Parse first entry, corrupt its hash, write back
    let mut entry: serde_json::Value = serde_json::from_str(&lines[0]).unwrap();
    entry["entry_hash"] = json!("0000000000000000000000000000000000000000000000000000000000000000");
    lines[0] = serde_json::to_string(&entry).unwrap();
    let tampered = lines.join("\n") + "\n";
    tokio::fs::write(&log_path, tampered).await.unwrap();

    // Restart logger — initialize_chain should detect the corruption
    let logger2 = AuditLogger::new(log_path.clone());
    // initialize_chain calls verify_chain internally; it may warn and start fresh
    let _ = logger2.initialize_chain().await;

    // New entry after detecting corruption starts a fresh chain segment
    logger2
        .log_entry(&action, &Verdict::Allow, json!({}))
        .await
        .unwrap();

    // The full chain (including tampered entries) should be detected as invalid
    let entries = logger2.load_entries().await.unwrap();
    assert!(
        entries.len() >= 3,
        "Should have original entries plus new one"
    );

    // Verify the chain detects the tampering
    let verification = logger2.verify_chain().await.unwrap();
    assert!(
        !verification.valid,
        "Chain with tampered entry hash must be detected as invalid"
    );
}

// ═══════════════════════════════════════════════════
// FINDING #5 — Empty tool name bypass (CRITICAL)
//
// Attack: Send a tools/call with no name or empty name.
// The old code created a ToolCall with empty string that evaded
// specific deny policies (deny rules match on tool name).
// Fix: classify_message returns Invalid for missing/empty names.
// ═══════════════════════════════════════════════════

#[test]
fn finding_5_empty_tool_name_returns_invalid_not_toolcall() {
    // Attack 1: No params at all
    let msg_no_params = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call"
    });
    assert!(
        matches!(
            classify_message(&msg_no_params),
            MessageType::Invalid { .. }
        ),
        "tools/call without params must be Invalid"
    );

    // Attack 2: Empty tool name
    let msg_empty_name = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {"name": "", "arguments": {}}
    });
    assert!(
        matches!(
            classify_message(&msg_empty_name),
            MessageType::Invalid { .. }
        ),
        "tools/call with empty name must be Invalid"
    );

    // Attack 3: Non-string tool name
    let msg_numeric_name = json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {"name": 42, "arguments": {}}
    });
    assert!(
        matches!(
            classify_message(&msg_numeric_name),
            MessageType::Invalid { .. }
        ),
        "tools/call with non-string name must be Invalid"
    );

    // Attack 4: Name is null
    let msg_null_name = json!({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": {"name": null, "arguments": {}}
    });
    assert!(
        matches!(
            classify_message(&msg_null_name),
            MessageType::Invalid { .. }
        ),
        "tools/call with null name must be Invalid"
    );
}

#[test]
fn finding_5_valid_tool_name_still_works() {
    let msg = json!({
        "jsonrpc": "2.0",
        "id": 10,
        "method": "tools/call",
        "params": {"name": "read_file", "arguments": {"path": "/tmp/test"}}
    });
    match classify_message(&msg) {
        MessageType::ToolCall { tool_name, .. } => {
            assert_eq!(tool_name, "read_file");
        }
        other => panic!("Expected ToolCall, got {other:?}"),
    }
}

// ═══════════════════════════════════════════════════
// FINDING #6 — Unbounded read_line OOM (CRITICAL)
//
// Attack: Send a line without a newline that's > 1MB.
// The old code would buffer the entire line into memory.
// Fix: MAX_LINE_LENGTH (1MB) enforced; returns LineTooLong error.
// ═══════════════════════════════════════════════════

#[tokio::test]
async fn finding_6_oversized_line_rejected() {
    // Create a line that exceeds 1MB
    let oversized = format!("{}\n", "A".repeat(1_048_577));
    let cursor = Cursor::new(oversized.into_bytes());
    let mut reader = BufReader::new(cursor);
    let result = read_message(&mut reader).await;
    assert!(result.is_err(), "Oversized line must be rejected");
    assert!(
        matches!(result.unwrap_err(), FramingError::LineTooLong(_)),
        "Error must be LineTooLong"
    );
}

#[tokio::test]
async fn finding_6_normal_sized_line_accepted() {
    let msg = json!({"jsonrpc": "2.0", "id": 1, "method": "ping"});
    let data = format!("{}\n", serde_json::to_string(&msg).unwrap());
    let cursor = Cursor::new(data.into_bytes());
    let mut reader = BufReader::new(cursor);
    let result = read_message(&mut reader).await.unwrap();
    assert!(result.is_some(), "Normal-sized line must be accepted");
}

// ═══════════════════════════════════════════════════
// FINDING #7 — No authentication on server endpoints (CRITICAL)
//
// Attack: Anyone can POST to /api/policies to add permissive policies,
// or POST to /api/evaluate to test what's allowed, without any auth.
// Fix: Bearer token auth middleware on all mutating (non-GET) endpoints.
// ═══════════════════════════════════════════════════

mod server_auth {
    use arc_swap::ArcSwap;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use std::sync::Arc;
    use tempfile::TempDir;
    use tower::ServiceExt;
    use vellaveto_approval::ApprovalStore;
    use vellaveto_audit::AuditLogger;
    use vellaveto_engine::PolicyEngine;
    use vellaveto_server::{routes, AppState, Metrics, RateLimits};
    use vellaveto_types::{Policy, PolicyType};

    fn make_authed_state(api_key: &str) -> (AppState, TempDir) {
        let tmp = TempDir::new().unwrap();
        let audit = Arc::new(AuditLogger::new(tmp.path().join("audit.log")));
        let state = AppState {
            policy_state: Arc::new(ArcSwap::from_pointee(vellaveto_server::PolicySnapshot {
                engine: PolicyEngine::new(false),
                policies: vec![Policy {
                    id: "file:read".to_string(),
                    name: "Allow file reads".to_string(),
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
            api_key: Some(Arc::new(api_key.to_string())),
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
            webhook_dedup: std::sync::Arc::new(
                vellaveto_server::routes::billing::WebhookDedup::new(
                    std::time::Duration::from_secs(600),
                ),
            ),
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
        };
        (state, tmp)
    }

    #[tokio::test]
    async fn post_without_auth_returns_401() {
        let (state, _tmp) = make_authed_state("secret-key-123");
        let app = routes::build_router(state);

        let req = Request::post("/api/evaluate")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"tool":"file","function":"read","parameters":{}}"#,
            ))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "POST without Bearer token must be 401"
        );
    }

    #[tokio::test]
    async fn post_with_wrong_key_returns_401() {
        let (state, _tmp) = make_authed_state("secret-key-123");
        let app = routes::build_router(state);

        let req = Request::post("/api/evaluate")
            .header("content-type", "application/json")
            .header("authorization", "Bearer wrong-key")
            .body(Body::from(
                r#"{"tool":"file","function":"read","parameters":{}}"#,
            ))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "POST with wrong Bearer token must be 401"
        );
    }

    #[tokio::test]
    async fn post_with_correct_key_returns_200() {
        let (state, _tmp) = make_authed_state("secret-key-123");
        let app = routes::build_router(state);

        let req = Request::post("/api/evaluate")
            .header("content-type", "application/json")
            .header("authorization", "Bearer secret-key-123")
            .body(Body::from(
                r#"{"tool":"file","function":"read","parameters":{}}"#,
            ))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert!(
            resp.status().is_success(),
            "POST with correct Bearer token must succeed, got {}",
            resp.status()
        );
    }

    #[tokio::test]
    async fn get_without_auth_still_works() {
        let (state, _tmp) = make_authed_state("secret-key-123");
        let app = routes::build_router(state);

        let req = Request::get("/health").body(Body::empty()).unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert!(
            resp.status().is_success(),
            "GET endpoints must work without auth"
        );
    }

    #[tokio::test]
    async fn delete_without_auth_returns_401() {
        let (state, _tmp) = make_authed_state("secret-key-123");
        let app = routes::build_router(state);

        let req = Request::delete("/api/policies/some-id")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "DELETE without auth must be 401"
        );
    }

    #[tokio::test]
    async fn no_api_key_configured_allows_all() {
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
            api_key: None, // No key configured
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
            webhook_dedup: std::sync::Arc::new(
                vellaveto_server::routes::billing::WebhookDedup::new(
                    std::time::Duration::from_secs(600),
                ),
            ),
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
        };
        let app = routes::build_router(state);

        let req = Request::post("/api/evaluate")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"tool":"file","function":"read","parameters":{}}"#,
            ))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert!(
            resp.status().is_success(),
            "When no API key configured, POST should succeed without auth"
        );
    }

    #[tokio::test]
    async fn policy_add_requires_auth() {
        let (state, _tmp) = make_authed_state("test-key");
        let app = routes::build_router(state);

        let policy_json = r#"{
            "id": "evil:*",
            "name": "Attacker policy",
            "policy_type": "Allow",
            "priority": 1000
        }"#;

        let req = Request::post("/api/policies")
            .header("content-type", "application/json")
            .body(Body::from(policy_json))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "Adding policies without auth must be blocked"
        );
    }

    #[tokio::test]
    async fn approval_endpoints_require_auth() {
        let (state, _tmp) = make_authed_state("test-key");
        let app = routes::build_router(state);

        let req = Request::post("/api/approvals/fake-id/approve")
            .header("content-type", "application/json")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "Approving without auth must be blocked"
        );
    }
}

// ═══════════════════════════════════════════════════
// FINDING #8 — extract_domain `@` bypass (HIGH)
//
// Attack: URL like `https://evil.com/path?email=user@safe.com`
// The old code searched for `@` in the entire URL, finding it in the
// query string and extracting `safe.com` as the domain instead of `evil.com`.
// Fix: Only search for `@` in the authority portion.
// ═══════════════════════════════════════════════════

#[test]
fn finding_8_at_sign_in_query_does_not_poison_domain() {
    // The attack: query param contains @safe.com
    let domain = PolicyEngine::extract_domain("https://evil.com/path?email=user@safe.com");
    assert_eq!(
        domain, "evil.com",
        "@ in query string must not affect domain extraction"
    );
}

#[test]
fn finding_8_at_sign_in_fragment_does_not_poison_domain() {
    let domain = PolicyEngine::extract_domain("https://evil.com/page#user@safe.com");
    assert_eq!(
        domain, "evil.com",
        "@ in fragment must not affect domain extraction"
    );
}

#[test]
fn finding_8_legitimate_userinfo_still_works() {
    // user@host is valid in the authority section
    let domain = PolicyEngine::extract_domain("https://user@real-host.com/path");
    assert_eq!(
        domain, "real-host.com",
        "Legitimate userinfo@ must still extract the correct host"
    );
}

#[test]
fn finding_8_at_in_both_authority_and_query() {
    let domain =
        PolicyEngine::extract_domain("https://admin@legit.com/path?redirect=user@evil.com");
    assert_eq!(
        domain, "legit.com",
        "Authority @ takes precedence over query @"
    );
}

#[test]
fn finding_8_domain_policy_blocks_evil_despite_at_bypass_attempt() {
    let engine = PolicyEngine::new(false);

    let policy = Policy {
        id: "http:*".to_string(),
        name: "Block evil.com".to_string(),
        policy_type: PolicyType::Conditional {
            conditions: json!({
                "parameter_constraints": [{
                    "param": "url",
                    "op": "domain_match",
                    "pattern": "evil.com"
                }]
            }),
        },
        priority: 100,
        path_rules: None,
        network_rules: None,
    };

    // The attack URL with @ in query trying to evade the policy
    let action = Action::new(
        "http".to_string(),
        "request".to_string(),
        json!({"url": "https://evil.com/steal?callback=user@safe.com"}),
    );

    let verdict = engine.evaluate_action(&action, &[policy]).unwrap();
    assert!(
        matches!(verdict, Verdict::Deny { .. }),
        "evil.com must be blocked even with @ in query: got {verdict:?}"
    );
}

// ═══════════════════════════════════════════════════
// FINDING #9 — normalize_path empty fallback (HIGH)
//
// Attack: Path that normalizes to empty string (null bytes, etc.)
// The old code returned the RAW INPUT, which still contained the
// dangerous traversal sequences normalization was meant to remove.
// Fix: Return "/" (root) when normalization produces empty string.
// ═══════════════════════════════════════════════════

#[test]
fn finding_9_null_byte_path_normalizes_to_err() {
    assert!(
        PolicyEngine::normalize_path("/a/b\0/c").is_err(),
        "Path with null bytes must return Err (fail-closed), not raw input"
    );
}

#[test]
fn finding_9_empty_path_normalizes_to_err() {
    // Path that resolves to nothing after normalization
    assert!(
        PolicyEngine::normalize_path("").is_err(),
        "Empty path must return Err (fail-closed)"
    );
}

#[test]
fn finding_9_normal_paths_still_work() {
    assert_eq!(
        PolicyEngine::normalize_path("/etc/passwd").unwrap(),
        "/etc/passwd"
    );
    assert_eq!(
        PolicyEngine::normalize_path("/a/../b").unwrap(),
        "/b",
        "Normal traversal should resolve correctly"
    );
    assert_eq!(
        PolicyEngine::normalize_path("/a/./b/./c").unwrap(),
        "/a/b/c",
        "Dot segments should be removed"
    );
}

#[test]
fn finding_9_traversal_at_root_absorbed() {
    // Traversal beyond root should be absorbed, not preserved
    let result = PolicyEngine::normalize_path("/a/../../etc/passwd").unwrap();
    assert_eq!(
        result, "/etc/passwd",
        "Traversal beyond root must be absorbed"
    );
}

// ═══════════════════════════════════════════════════
// FINDING #10 — Approval store persistence (HIGH)
//
// Verify that approvals survive a logger restart by reading
// from the persistence file.
// ═══════════════════════════════════════════════════

#[tokio::test]
async fn finding_10_approvals_survive_restart() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("approvals.jsonl");

    // Create store and add an approval
    let store =
        vellaveto_approval::ApprovalStore::new(path.clone(), std::time::Duration::from_secs(900));
    let action = Action::new("dangerous".to_string(), "exec".to_string(), json!({}));
    let id = store
        .create(action.clone(), "needs review".to_string(), None, None, None)
        .await
        .unwrap();

    // Verify the persistence file exists and has content
    let file_content = tokio::fs::read_to_string(&path).await.unwrap();
    assert!(
        !file_content.is_empty(),
        "Approval store must persist to file"
    );

    // "Restart" — create new store from same path and reload from file
    let store2 = vellaveto_approval::ApprovalStore::new(path, std::time::Duration::from_secs(900));
    store2
        .load_from_file()
        .await
        .expect("load_from_file must succeed");

    // The pending approval should be visible after restart + reload
    let pending = store2.list_pending().await;
    assert!(
        pending.iter().any(|a| a.id == id),
        "Approval '{}' must survive store restart (Finding #10). Got: {:?}",
        id,
        pending.iter().map(|a| &a.id).collect::<Vec<_>>()
    );
}

// ═══════════════════════════════════════════════════
// FINDING #13 — Audit records wrong verdict for RequireApproval (HIGH)
//
// The old code logged RequireApproval verdicts as Deny in the audit trail.
// Fix: The audit entry should record the actual verdict.
// ═══════════════════════════════════════════════════

#[tokio::test]
async fn finding_13_require_approval_verdict_recorded_correctly() {
    let tmp = TempDir::new().unwrap();
    let logger = AuditLogger::new(tmp.path().join("audit.log"));

    let action = Action::new("dangerous".to_string(), "exec".to_string(), json!({}));
    let verdict = Verdict::RequireApproval {
        reason: "needs human review".to_string(),
    };

    logger
        .log_entry(&action, &verdict, json!({"source": "test"}))
        .await
        .unwrap();

    let entries = logger.load_entries().await.unwrap();
    assert_eq!(entries.len(), 1);

    // The verdict in the audit entry must be RequireApproval, not Deny
    match &entries[0].verdict {
        Verdict::RequireApproval { reason } => {
            assert!(
                reason.contains("human review"),
                "Reason should be preserved"
            );
        }
        other => {
            panic!(
                "Expected RequireApproval in audit log, got {other:?}. \
                 This means the audit is recording the wrong verdict."
            );
        }
    }
}

// ═══════════════════════════════════════════════════
// FINDING #14 — Empty line terminates proxy (HIGH)
//
// Attack: A blank newline from the child process terminates the proxy.
// Fix: Empty lines are skipped; only true EOF terminates.
// ═══════════════════════════════════════════════════

#[tokio::test]
async fn finding_14_empty_lines_skipped_not_eof() {
    // Multiple empty lines followed by a valid message
    let data = b"\n\n\n{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n";
    let cursor = Cursor::new(data.to_vec());
    let mut reader = BufReader::new(cursor);
    let msg = read_message(&mut reader).await.unwrap();
    assert!(
        msg.is_some(),
        "Empty lines must be skipped, not treated as EOF"
    );
    assert_eq!(msg.unwrap()["method"], "ping");
}

#[tokio::test]
async fn finding_14_only_empty_lines_followed_by_eof() {
    // Only empty lines followed by actual EOF → should return None
    let data = b"\n\n\n";
    let cursor = Cursor::new(data.to_vec());
    let mut reader = BufReader::new(cursor);
    let msg = read_message(&mut reader).await.unwrap();
    assert!(
        msg.is_none(),
        "Only empty lines followed by EOF should return None"
    );
}

#[tokio::test]
async fn finding_14_interleaved_empty_lines_between_messages() {
    let data = b"{\"id\":1,\"method\":\"a\"}\n\n\n{\"id\":2,\"method\":\"b\"}\n";
    let cursor = Cursor::new(data.to_vec());
    let mut reader = BufReader::new(cursor);

    let msg1 = read_message(&mut reader).await.unwrap().unwrap();
    assert_eq!(msg1["id"], 1);

    let msg2 = read_message(&mut reader).await.unwrap().unwrap();
    assert_eq!(msg2["id"], 2);

    let msg3 = read_message(&mut reader).await.unwrap();
    assert!(msg3.is_none(), "Should be EOF after last message");
}

// ═══════════════════════════════════════════════════
// COMBINED ATTACK SCENARIOS
//
// Tests that combine multiple findings to verify defense in depth.
// ═══════════════════════════════════════════════════

#[test]
fn combined_domain_bypass_with_path_traversal() {
    // Attacker tries both @ bypass and path traversal simultaneously
    let engine = PolicyEngine::new(false);

    let deny_policy = Policy {
        id: "http:*".to_string(),
        name: "Block evil.com".to_string(),
        policy_type: PolicyType::Conditional {
            conditions: json!({
                "parameter_constraints": [{
                    "param": "url",
                    "op": "domain_match",
                    "pattern": "evil.com"
                }]
            }),
        },
        priority: 100,
        path_rules: None,
        network_rules: None,
    };

    // Attack: evil.com with @ bypass attempt
    let action = Action::new(
        "http".to_string(),
        "request".to_string(),
        json!({
            "url": "https://evil.com/data?user@safe.com",
            "path": "/a/../../etc/shadow"
        }),
    );

    let verdict = engine.evaluate_action(&action, &[deny_policy]).unwrap();
    assert!(
        matches!(verdict, Verdict::Deny { .. }),
        "Combined attack must be blocked: got {verdict:?}"
    );
}

#[test]
fn combined_empty_tool_name_with_deny_policy() {
    // Verify that empty tool name is caught at the MCP layer,
    // not forwarded to the engine where it could evade policies
    let msg = json!({
        "jsonrpc": "2.0",
        "id": 99,
        "method": "tools/call",
        "params": {"name": "", "arguments": {"path": "/etc/shadow"}}
    });

    match classify_message(&msg) {
        MessageType::Invalid { reason, .. } => {
            assert!(
                reason.contains("missing or empty"),
                "Should explain why it's invalid"
            );
        }
        other => panic!(
            "Empty tool name must be caught as Invalid before reaching engine: got {other:?}"
        ),
    }
}

#[tokio::test]
async fn combined_audit_integrity_full_lifecycle() {
    let tmp = TempDir::new().unwrap();
    let log_path = tmp.path().join("audit.log");

    // Create logger and log several entries
    let logger = Arc::new(AuditLogger::new(log_path.clone()));

    let actions = vec![
        ("file", "read", Verdict::Allow),
        (
            "bash",
            "exec",
            Verdict::Deny {
                reason: "blocked".to_string(),
            },
        ),
        (
            "deploy",
            "push",
            Verdict::RequireApproval {
                reason: "needs sign-off".to_string(),
            },
        ),
    ];

    for (tool, func, verdict) in &actions {
        let action = Action::new(tool.to_string(), func.to_string(), json!({}));
        logger.log_entry(&action, verdict, json!({})).await.unwrap();
    }

    // Verify chain is valid
    let verification = logger.verify_chain().await.unwrap();
    assert!(verification.valid, "Chain must be valid after normal usage");
    assert_eq!(verification.entries_checked, 3);

    // Verify all verdicts are recorded correctly (finding #13)
    let entries = logger.load_entries().await.unwrap();
    assert!(matches!(entries[0].verdict, Verdict::Allow));
    assert!(matches!(entries[1].verdict, Verdict::Deny { .. }));
    assert!(matches!(
        entries[2].verdict,
        Verdict::RequireApproval { .. }
    ));

    // Verify all entries have hashes (finding #1)
    for entry in &entries {
        assert!(entry.entry_hash.is_some(), "All entries must have hashes");
    }
}

// ═══════════════════════════════════════════════════
// CROSS-REVIEW FINDING #4 — Hash chain write ordering
//
// The audit log must update last_hash ONLY AFTER the file write
// succeeds. If last_hash were updated before the write, a failed
// write would leave an orphaned hash pointing to a non-existent
// entry on disk, breaking the chain.
//
// This test verifies that after multiple writes, the chain is valid
// and each entry's prev_hash correctly references the previous entry.
// ═══════════════════════════════════════════════════

#[tokio::test]
async fn finding_4_hash_chain_ordering_consistent_after_writes() {
    let tmp = TempDir::new().unwrap();
    let log_path = tmp.path().join("audit.log");

    let logger = AuditLogger::new(log_path.clone());
    logger.initialize_chain().await.unwrap();

    let action = Action::new("test".to_string(), "op".to_string(), json!({}));

    // Write 5 entries in sequence
    for i in 0..5 {
        logger
            .log_entry(
                &action,
                &Verdict::Deny {
                    reason: format!("entry {i}"),
                },
                json!({"seq": i}),
            )
            .await
            .unwrap();
    }

    // Verify the chain is valid
    let verification = logger.verify_chain().await.unwrap();
    assert!(
        verification.valid,
        "Chain must be valid: first_broken_at={:?}",
        verification.first_broken_at
    );
    assert_eq!(verification.entries_checked, 5);

    // Verify prev_hash linkage: entry[i].prev_hash == entry[i-1].entry_hash
    let entries = logger.load_entries().await.unwrap();
    assert_eq!(entries.len(), 5);

    // First entry has no prev_hash (or it's None)
    assert!(
        entries[0].prev_hash.is_none(),
        "First entry should have no prev_hash"
    );

    for i in 1..entries.len() {
        assert_eq!(
            entries[i].prev_hash.as_deref(),
            entries[i - 1].entry_hash.as_deref(),
            "Entry {}'s prev_hash must equal entry {}'s entry_hash",
            i,
            i - 1
        );
    }
}

// ═══════════════════════════════════════════════════
// CROSS-REVIEW FINDING #11 — Error propagation in evaluate
//
// When audit logging or approval creation encounters an error,
// the server must not panic or silently return incorrect results.
// Audit log failures are fire-and-forget (logged, don't fail the request).
// Approval failures are fail-closed (converted to Deny).
//
// This test verifies evaluate works correctly even when the audit
// logger points to a valid path but the approval store is unwritable.
// ═══════════════════════════════════════════════════

#[tokio::test]
async fn finding_11_evaluate_succeeds_even_when_audit_fails_to_write() {
    let tmp = TempDir::new().unwrap();

    // Create audit logger pointing to a file we make read-only
    let audit_path = tmp.path().join("audit.log");
    let logger = Arc::new(AuditLogger::new(audit_path.clone()));

    // Write one valid entry first
    let action = Action::new("file".to_string(), "read".to_string(), json!({}));
    logger
        .log_entry(&action, &Verdict::Allow, json!({}))
        .await
        .unwrap();

    // Now make the audit file read-only to force write failures
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o444);
        std::fs::set_permissions(&audit_path, perms).unwrap();
    }

    let state = AppState {
        policy_state: Arc::new(ArcSwap::from_pointee(vellaveto_server::PolicySnapshot {
            engine: PolicyEngine::new(false),
            policies: vec![Policy {
                id: "file:read".to_string(),
                name: "Allow reads".to_string(),
                policy_type: PolicyType::Allow,
                priority: 10,
                path_rules: None,
                network_rules: None,
            }],
            compliance_config: Default::default(),
        })),
        audit: Arc::clone(&logger),
        config_path: Arc::new("test.toml".to_string()),
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
                reason: "test default".to_string(),
            },
        }),
        setup_completed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        wizard_sessions: Arc::new(dashmap::DashMap::new()),
        audit_query: Arc::new(vellaveto_audit::query::file::FileAuditQuery::new(
            Arc::clone(&logger),
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
    };

    let app = routes::build_router(state);

    let body = serde_json::to_string(&json!({
        "tool": "file",
        "function": "read",
        "parameters": {"path": "/tmp/test"}
    }))
    .unwrap();

    let resp = app
        .oneshot(
            Request::post("/api/evaluate")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    // The request should succeed (200 OK) even though audit write fails
    // because audit is fire-and-forget
    assert_eq!(
        resp.status(),
        axum::http::StatusCode::OK,
        "Evaluate must succeed even when audit write fails"
    );

    let body_bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(json["verdict"], "Allow");
}

// ═══════════════════════════════════════════════════
// CROSS-REVIEW FINDING #12 — Fail-closed on approval creation failure
//
// When a policy evaluates to RequireApproval but ApprovalStore::create()
// fails, the server MUST deny the request (fail-closed), NOT allow it
// through without an approval_id.
//
// This test creates an unwritable approval store, evaluates an action
// against a RequireApproval policy, and verifies the response is Deny.
// ═══════════════════════════════════════════════════

#[tokio::test]
async fn finding_12_approval_creation_failure_denies_request() {
    let tmp = TempDir::new().unwrap();

    // Create an approval store pointing to an unwritable path.
    // /dev/null/impossible cannot be created as a file because /dev/null is not a directory.
    let approvals = Arc::new(ApprovalStore::new(
        std::path::PathBuf::from("/dev/null/impossible.jsonl"),
        std::time::Duration::from_secs(900),
    ));

    let audit = Arc::new(AuditLogger::new(tmp.path().join("audit.log")));
    let state = AppState {
        policy_state: Arc::new(ArcSwap::from_pointee(vellaveto_server::PolicySnapshot {
            engine: PolicyEngine::new(false),
            policies: vec![Policy {
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
            }],
            compliance_config: Default::default(),
        })),
        audit: Arc::clone(&audit),
        config_path: Arc::new("test.toml".to_string()),
        approvals,
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
    };

    let app = routes::build_router(state);

    let body = serde_json::to_string(&json!({
        "tool": "network",
        "function": "connect",
        "parameters": {"host": "example.com"}
    }))
    .unwrap();

    let resp = app
        .oneshot(
            Request::post("/api/evaluate")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    // The request should return 200 OK with Deny verdict (fail-closed)
    assert_eq!(resp.status(), axum::http::StatusCode::OK);

    let body_bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

    // Verdict must be Deny (not RequireApproval, not Allow)
    let verdict = &json["verdict"];
    assert!(
        verdict.is_object() || verdict.is_string(),
        "Expected verdict in response"
    );

    // Check for Deny verdict — it should contain the reason about approval failure
    let verdict_str = serde_json::to_string(verdict).unwrap();
    assert!(
        verdict_str.contains("Deny") || verdict_str.contains("deny"),
        "Verdict must be Deny when approval creation fails, got: {verdict_str}"
    );

    // approval_id must be null/absent since creation failed
    let approval_id = json.get("approval_id");
    assert!(
        approval_id.is_none() || approval_id.unwrap().is_null(),
        "approval_id must be null when creation fails"
    );
}

// ═══════════════════════════════════════════════════
// R19 SECURITY FIXES — Path Normalization Strictness
// ═══════════════════════════════════════════════════

/// R19-PATH-1: Null bytes in paths must be denied, not normalized to "/"
#[test]
fn r19_path_null_bytes_denied() {
    use vellaveto_engine::PolicyEngine;

    let result = PolicyEngine::normalize_path_bounded("/etc/\x00passwd", 20);
    assert!(
        result.is_err(),
        "Null bytes in path must return error, not normalize to '/'"
    );

    let err = result.unwrap_err();
    let err_str = err.to_string();
    assert!(
        err_str.contains("null byte"),
        "Error message should mention null byte: {err_str}"
    );
}

/// R19-PATH-2: Percent-decode iteration exhaustion must be denied
#[test]
fn r19_path_iteration_exhaustion_denied() {
    use vellaveto_engine::PolicyEngine;

    // Create a deeply nested percent-encoded path that requires many iterations.
    // Each layer of %25 adds one decode iteration:
    // %252565 → %2565 → %65 → 'e' (3 iterations)
    // %25252565 → %252565 → %2565 → %65 → 'e' (4 iterations)
    // We need to exceed max_iterations (e.g., 5) to trigger the error.
    //
    // Build: start with 'e' (%65), then wrap with %25 repeatedly
    // 6 wraps = %25252525252565 requires 6 decode iterations
    let mut encoded = String::from("%65"); // 'e'
    for _ in 0..6 {
        // Each wrap: %XX becomes %25XX
        encoded = encoded.replace('%', "%25");
    }
    let deeply_encoded = format!("/etc/passwd{encoded}");

    // With max_iterations=5, this should fail
    let result = PolicyEngine::normalize_path_bounded(&deeply_encoded, 5);
    assert!(
        result.is_err(),
        "Iteration exhaustion must return error, not normalize to '/'. Got: {result:?}"
    );

    let err = result.unwrap_err();
    let err_str = err.to_string();
    assert!(
        err_str.contains("iteration") || err_str.contains("limit"),
        "Error message should mention iteration limit: {err_str}"
    );
}

/// R19-PATH-3: Invalid percent sequences must be denied
#[test]
fn r19_path_invalid_percent_sequence_denied() {
    use vellaveto_engine::PolicyEngine;

    // %ZZ is not a valid hex sequence
    let result = PolicyEngine::normalize_path_bounded("/etc/%ZZpasswd", 20);

    // This may either:
    // 1. Return an error (strictest)
    // 2. Leave the %ZZ intact but still normalize the path
    // Either way, it must NOT collapse to "/" or bypass path matching

    match result {
        Ok(normalized) => {
            // If it doesn't error, it should preserve the invalid sequence
            // and NOT collapse to "/"
            assert_ne!(
                normalized, "/",
                "Invalid percent sequence must not collapse to '/'"
            );
            assert!(
                normalized.contains("etc"),
                "Path should still contain meaningful components"
            );
        }
        Err(_) => {
            // Erroring is also acceptable (stricter behavior)
        }
    }
}

/// R19-PATH-4: Empty path after normalization must be denied
#[test]
fn r19_path_empty_after_normalization_denied() {
    use vellaveto_engine::PolicyEngine;

    // Paths that might normalize to empty string
    let test_cases = ["", ".", "..", "../..", "/..", "/./.."];

    for path in test_cases {
        let result = PolicyEngine::normalize_path_bounded(path, 20);
        match result {
            Ok(normalized) => {
                // If it succeeds, the result must be "/" or a meaningful path, not empty
                assert!(
                    !normalized.is_empty(),
                    "Path '{path}' normalized to empty string, which is invalid"
                );
            }
            Err(_) => {
                // Erroring is acceptable for pathological inputs
            }
        }
    }
}

// ═══════════════════════════════════════════════════
// R19 SECURITY FIXES — Audit Rotation Strictness
// ═══════════════════════════════════════════════════

/// R19-AUDIT-1: Audit rotation with corrupted log must skip (not write empty manifest)
#[tokio::test]
async fn r19_audit_rotation_corrupted_log_skipped() {
    let tmp = TempDir::new().unwrap();
    let log_path = tmp.path().join("audit.log");

    // Create a corrupted log file (invalid JSON)
    tokio::fs::write(&log_path, "this is not valid JSON\n{also broken}\n")
        .await
        .unwrap();

    // Create logger with small max size to trigger rotation attempt
    let logger = AuditLogger::new(log_path.clone()).with_max_file_size(10); // 10 bytes = force rotation

    // Log an entry — this should try to rotate but fail to parse existing log
    let action = Action::new(
        "test".to_string(),
        "test".to_string(),
        json!({"test": true}),
    );
    let _result = logger.log_entry(&action, &Verdict::Allow, json!({})).await;

    // The log entry itself should succeed (we don't fail the whole operation)
    // But rotation should have been skipped

    // Check that no manifest was created with empty/incorrect data
    let manifest_path = tmp.path().join("audit.rotation_manifest.jsonl");
    if manifest_path.exists() {
        let manifest_content = tokio::fs::read_to_string(&manifest_path).await.unwrap();
        // If a manifest entry exists, it must have a valid tail_hash (not empty)
        for line in manifest_content.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let entry: serde_json::Value = serde_json::from_str(line).unwrap();
            let tail_hash = entry.get("tail_hash").and_then(|v| v.as_str());
            // First rotation with corrupted log should have been skipped entirely
            // So either: no manifest, or manifest has valid hashes from other rotations
            if let Some(hash) = tail_hash {
                // Empty string would indicate the bug
                assert!(
                    !hash.is_empty() || entry.get("entry_count") == Some(&json!(0)),
                    "Manifest entry has empty tail_hash but non-zero entry count: {line}"
                );
            }
        }
    }
    // Test passes if no corrupt manifest was created
}

/// R19-AUDIT-2: Audit rotation when last entry has no hash must skip
#[tokio::test]
async fn r19_audit_rotation_missing_hash_skipped() {
    let tmp = TempDir::new().unwrap();
    let log_path = tmp.path().join("audit.log");

    // Create a log with an entry that has no entry_hash (simulating corruption)
    let corrupt_entry = json!({
        "id": "no-hash-entry",
        "action": {"tool": "test", "function": "test", "parameters": {}},
        "verdict": "Allow",
        "timestamp": "2026-01-01T00:00:00Z",
        "metadata": {}
        // Deliberately missing entry_hash and prev_hash
    });
    let mut content = serde_json::to_string(&corrupt_entry).unwrap();
    content.push('\n');
    tokio::fs::write(&log_path, &content).await.unwrap();

    // Create logger with small max size
    let logger = AuditLogger::new(log_path.clone()).with_max_file_size(10);

    // Try to log — should attempt rotation but skip due to missing hash
    let action = Action::new("x".to_string(), "x".to_string(), json!({}));
    let _ = logger.log_entry(&action, &Verdict::Allow, json!({})).await;

    // Check manifest wasn't created with empty tail_hash
    let manifest_path = tmp.path().join("audit.rotation_manifest.jsonl");
    if manifest_path.exists() {
        let manifest_content = tokio::fs::read_to_string(&manifest_path).await.unwrap();
        for line in manifest_content.lines().filter(|l| !l.trim().is_empty()) {
            let entry: serde_json::Value = serde_json::from_str(line).unwrap();
            if let Some(count) = entry.get("entry_count").and_then(|v| v.as_u64()) {
                if count > 0 {
                    let tail_hash = entry
                        .get("tail_hash")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    assert!(
                        !tail_hash.is_empty(),
                        "Manifest has entry_count={count} but empty tail_hash"
                    );
                }
            }
        }
    }
}

// ═══════════════════════════════════════════════════
// R19 SECURITY FIXES — Policy Mutation Atomicity
// ═══════════════════════════════════════════════════

/// R19-MCP-1: add_policy with invalid policy must return error and not change state
#[tokio::test]
async fn r19_add_policy_compile_failure_no_state_change() {
    use vellaveto_mcp::McpServer;

    // Create a server
    let server = McpServer::new(false); // strict_mode = false

    // First add a valid policy
    // Note: McpRequest.id is a String, so JSON-RPC id must be a string
    let valid_add = r#"{
        "jsonrpc": "2.0",
        "id": "1",
        "method": "add_policy",
        "params": {
            "id": "initial",
            "name": "Initial Policy",
            "policy_type": "Allow",
            "priority": 10
        }
    }"#;
    let result = server.handle_request(valid_add).await.unwrap();
    let response: serde_json::Value = serde_json::from_str(&result).unwrap();
    // Check error is absent or null
    let has_error = response.get("error").map(|e| !e.is_null()).unwrap_or(false);
    assert!(!has_error, "Valid policy add should succeed: {result}");

    // List policies to verify one exists
    let list_req = r#"{"jsonrpc": "2.0", "id": "2", "method": "list_policies", "params": {}}"#;
    let result = server.handle_request(list_req).await.unwrap();
    let response: serde_json::Value = serde_json::from_str(&result).unwrap();
    let policies_before: Vec<serde_json::Value> =
        serde_json::from_value(response.get("result").cloned().unwrap_or(json!([])))
            .unwrap_or_default();
    assert_eq!(
        policies_before.len(),
        1,
        "Should have 1 policy before invalid add"
    );

    // Try to add an invalid policy (invalid regex pattern)
    let invalid_add = r#"{
        "jsonrpc": "2.0",
        "id": "3",
        "method": "add_policy",
        "params": {
            "id": "invalid",
            "name": "Invalid Policy",
            "policy_type": {
                "Conditional": {
                    "conditions": {
                        "parameter_constraints": [{
                            "param": "test",
                            "op": "regex",
                            "pattern": "(((unclosed"
                        }]
                    }
                }
            },
            "priority": 100
        }
    }"#;

    let result = server.handle_request(invalid_add).await.unwrap();
    let response: serde_json::Value = serde_json::from_str(&result).unwrap();

    // The response should contain a non-null error
    let has_error = response.get("error").map(|e| !e.is_null()).unwrap_or(false);
    assert!(
        has_error,
        "Invalid policy add should return error response: {result}"
    );

    // List policies again - should still have only 1
    let result = server.handle_request(list_req).await.unwrap();
    let response: serde_json::Value = serde_json::from_str(&result).unwrap();
    let policies_after: Vec<serde_json::Value> =
        serde_json::from_value(response.get("result").cloned().unwrap_or(json!([])))
            .unwrap_or_default();

    assert_eq!(
        policies_after.len(),
        policies_before.len(),
        "Policy count should not change after failed add"
    );
}

// ═══════════════════════════════════════════════════
// R19 SECURITY FIXES — Config Priority Safety
// ═══════════════════════════════════════════════════

/// R19-CFG-1: Default priority is 0 (lowest), not 100
#[test]
fn r19_config_priority_defaults_to_zero() {
    use vellaveto_config::PolicyConfig;

    let toml = r#"
[[policies]]
name = "No explicit priority"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Allow"
"#;

    let config = PolicyConfig::from_toml(toml).unwrap();
    let policies = config.to_policies();

    assert_eq!(
        policies[0].priority, 0,
        "Default priority should be 0 (lowest), not 100"
    );
}

// ═══════════════════════════════════════════════════
// FIND-R46-IT-003 — Malformed server responses produce Deny
//
// When the policy engine receives malformed input or the evaluate
// endpoint receives invalid JSON, the system must fail-closed.
// ═══════════════════════════════════════════════════

#[tokio::test]
async fn find_r46_it003_malformed_json_request_body_rejected() {
    let tmp = TempDir::new().unwrap();
    let audit = Arc::new(AuditLogger::new(tmp.path().join("audit.log")));
    let state = AppState {
        policy_state: Arc::new(ArcSwap::from_pointee(vellaveto_server::PolicySnapshot {
            engine: PolicyEngine::new(false),
            policies: vec![Policy {
                id: "file:*".to_string(),
                name: "Allow files".to_string(),
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
    };

    // Test 1: Completely invalid JSON
    let app = routes::build_router(state.clone());
    let req = Request::post("/api/evaluate")
        .header("content-type", "application/json")
        .body(Body::from("this is not json at all"))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert!(
        resp.status().is_client_error() || resp.status().is_server_error(),
        "Malformed JSON must be rejected, got status {}",
        resp.status()
    );

    // Test 2: Valid JSON but missing required 'tool' field
    let app = routes::build_router(state.clone());
    let req = Request::post("/api/evaluate")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"function":"read","parameters":{}}"#))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    // Should either reject (4xx) or produce a Deny verdict
    if resp.status().is_success() {
        let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let body_str = String::from_utf8_lossy(&body);
        let body_lower = body_str.to_lowercase();
        assert!(
            body_lower.contains("deny"),
            "Missing 'tool' field must fail-closed to Deny: {body_str}"
        );
    }

    // Test 3: Empty JSON object
    let app = routes::build_router(state.clone());
    let req = Request::post("/api/evaluate")
        .header("content-type", "application/json")
        .body(Body::from("{}"))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    // Should either reject or produce Deny
    if resp.status().is_success() {
        let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let body_str = String::from_utf8_lossy(&body);
        let body_lower = body_str.to_lowercase();
        assert!(
            body_lower.contains("deny"),
            "Empty JSON object must fail-closed to Deny: {body_str}"
        );
    }

    // Test 4: JSON array instead of object
    let app = routes::build_router(state.clone());
    let req = Request::post("/api/evaluate")
        .header("content-type", "application/json")
        .body(Body::from("[1,2,3]"))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert!(
        resp.status().is_client_error() || resp.status().is_server_error(),
        "JSON array must be rejected for evaluate endpoint, got status {}",
        resp.status()
    );
}

// ═══════════════════════════════════════════════════
// FIND-R46-IT-004 — SSRF regression tests for resolved_ips
//
// Verify that private IP ranges in resolved_ips are blocked
// when IP rules with block_private are configured.
// ═══════════════════════════════════════════════════

#[test]
fn find_r46_it004_ssrf_private_ip_10_blocked() {
    use vellaveto_types::{IpRules, NetworkRules};

    let engine = PolicyEngine::new(false);
    let policies = vec![Policy {
        id: "http:*".to_string(),
        name: "Block private IPs".to_string(),
        policy_type: PolicyType::Allow,
        priority: 100,
        path_rules: None,
        network_rules: Some(NetworkRules {
            allowed_domains: vec![],
            blocked_domains: vec![],
            ip_rules: Some(IpRules {
                block_private: true,
                blocked_cidrs: vec![],
                allowed_cidrs: vec![],
            }),
        }),
    }];

    // RFC 1918 10.0.0.0/8 range
    let private_ips = vec!["10.0.0.1", "10.255.255.255", "10.0.0.0", "10.128.64.32"];

    for ip in private_ips {
        let action = Action {
            tool: "http".to_string(),
            function: "request".to_string(),
            parameters: json!({"url": "http://internal.service"}),
            target_paths: vec![],
            target_domains: vec!["internal.service".to_string()],
            resolved_ips: vec![ip.to_string()],
        };
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(
            matches!(verdict, Verdict::Deny { .. }),
            "Private IP {ip} (10.0.0.0/8) must be blocked by SSRF protection: got {verdict:?}"
        );
    }
}

#[test]
fn find_r46_it004_ssrf_private_ip_172_16_blocked() {
    use vellaveto_types::{IpRules, NetworkRules};

    let engine = PolicyEngine::new(false);
    let policies = vec![Policy {
        id: "http:*".to_string(),
        name: "Block private IPs".to_string(),
        policy_type: PolicyType::Allow,
        priority: 100,
        path_rules: None,
        network_rules: Some(NetworkRules {
            allowed_domains: vec![],
            blocked_domains: vec![],
            ip_rules: Some(IpRules {
                block_private: true,
                blocked_cidrs: vec![],
                allowed_cidrs: vec![],
            }),
        }),
    }];

    // RFC 1918 172.16.0.0/12 range
    let private_ips = vec!["172.16.0.1", "172.31.255.255", "172.20.10.5"];

    for ip in private_ips {
        let action = Action {
            tool: "http".to_string(),
            function: "request".to_string(),
            parameters: json!({"url": "http://internal.service"}),
            target_paths: vec![],
            target_domains: vec!["internal.service".to_string()],
            resolved_ips: vec![ip.to_string()],
        };
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(
            matches!(verdict, Verdict::Deny { .. }),
            "Private IP {ip} (172.16.0.0/12) must be blocked by SSRF protection: got {verdict:?}"
        );
    }
}

#[test]
fn find_r46_it004_ssrf_private_ip_192_168_blocked() {
    use vellaveto_types::{IpRules, NetworkRules};

    let engine = PolicyEngine::new(false);
    let policies = vec![Policy {
        id: "http:*".to_string(),
        name: "Block private IPs".to_string(),
        policy_type: PolicyType::Allow,
        priority: 100,
        path_rules: None,
        network_rules: Some(NetworkRules {
            allowed_domains: vec![],
            blocked_domains: vec![],
            ip_rules: Some(IpRules {
                block_private: true,
                blocked_cidrs: vec![],
                allowed_cidrs: vec![],
            }),
        }),
    }];

    // RFC 1918 192.168.0.0/16 range
    let private_ips = vec!["192.168.0.1", "192.168.1.1", "192.168.255.255"];

    for ip in private_ips {
        let action = Action {
            tool: "http".to_string(),
            function: "request".to_string(),
            parameters: json!({"url": "http://internal.service"}),
            target_paths: vec![],
            target_domains: vec!["internal.service".to_string()],
            resolved_ips: vec![ip.to_string()],
        };
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(
            matches!(verdict, Verdict::Deny { .. }),
            "Private IP {ip} (192.168.0.0/16) must be blocked by SSRF protection: got {verdict:?}"
        );
    }
}

#[test]
fn find_r46_it004_ssrf_loopback_blocked() {
    use vellaveto_types::{IpRules, NetworkRules};

    let engine = PolicyEngine::new(false);
    let policies = vec![Policy {
        id: "http:*".to_string(),
        name: "Block private IPs".to_string(),
        policy_type: PolicyType::Allow,
        priority: 100,
        path_rules: None,
        network_rules: Some(NetworkRules {
            allowed_domains: vec![],
            blocked_domains: vec![],
            ip_rules: Some(IpRules {
                block_private: true,
                blocked_cidrs: vec![],
                allowed_cidrs: vec![],
            }),
        }),
    }];

    // Loopback and link-local addresses
    let loopback_ips = vec![
        "127.0.0.1",
        "127.0.0.2",
        "169.254.169.254", // AWS metadata endpoint (link-local)
        "0.0.0.0",
    ];

    for ip in loopback_ips {
        let action = Action {
            tool: "http".to_string(),
            function: "request".to_string(),
            parameters: json!({"url": "http://metadata.internal"}),
            target_paths: vec![],
            target_domains: vec!["metadata.internal".to_string()],
            resolved_ips: vec![ip.to_string()],
        };
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(
            matches!(verdict, Verdict::Deny { .. }),
            "Loopback/link-local IP {ip} must be blocked by SSRF protection: got {verdict:?}"
        );
    }
}

#[test]
fn find_r46_it004_ssrf_public_ip_allowed() {
    use vellaveto_types::{IpRules, NetworkRules};

    let engine = PolicyEngine::new(false);
    let policies = vec![Policy {
        id: "http:*".to_string(),
        name: "Block private IPs".to_string(),
        policy_type: PolicyType::Allow,
        priority: 100,
        path_rules: None,
        network_rules: Some(NetworkRules {
            allowed_domains: vec![],
            blocked_domains: vec![],
            ip_rules: Some(IpRules {
                block_private: true,
                blocked_cidrs: vec![],
                allowed_cidrs: vec![],
            }),
        }),
    }];

    // Public IPs should still be allowed
    let public_ips = vec![
        "8.8.8.8",       // Google DNS
        "1.1.1.1",       // Cloudflare DNS
        "93.184.216.34", // example.com
    ];

    for ip in public_ips {
        let action = Action {
            tool: "http".to_string(),
            function: "request".to_string(),
            parameters: json!({"url": "http://example.com"}),
            target_paths: vec![],
            target_domains: vec!["example.com".to_string()],
            resolved_ips: vec![ip.to_string()],
        };
        let verdict = engine.evaluate_action(&action, &policies).unwrap();
        assert!(
            matches!(verdict, Verdict::Allow),
            "Public IP {ip} should be allowed: got {verdict:?}"
        );
    }
}

#[test]
fn find_r46_it004_ssrf_no_resolved_ips_with_domain_denied() {
    use vellaveto_types::{IpRules, NetworkRules};

    let engine = PolicyEngine::new(false);
    let policies = vec![Policy {
        id: "http:*".to_string(),
        name: "Block private IPs".to_string(),
        policy_type: PolicyType::Allow,
        priority: 100,
        path_rules: None,
        network_rules: Some(NetworkRules {
            allowed_domains: vec![],
            blocked_domains: vec![],
            ip_rules: Some(IpRules {
                block_private: true,
                blocked_cidrs: vec![],
                allowed_cidrs: vec![],
            }),
        }),
    }];

    // IP rules configured but no resolved IPs provided (DNS resolution not performed)
    // with target_domains present — must fail-closed
    let action = Action {
        tool: "http".to_string(),
        function: "request".to_string(),
        parameters: json!({"url": "http://evil.internal"}),
        target_paths: vec![],
        target_domains: vec!["evil.internal".to_string()],
        resolved_ips: vec![], // No DNS resolution performed
    };
    let verdict = engine.evaluate_action(&action, &policies).unwrap();
    assert!(
        matches!(verdict, Verdict::Deny { .. }),
        "Missing resolved_ips with target_domains must fail-closed: got {verdict:?}"
    );
}
