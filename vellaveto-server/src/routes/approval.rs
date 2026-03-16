// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Approval workflow route handlers.
//!
//! This module provides REST API endpoints for human-in-the-loop
//! approval management.
//!
//! Endpoints:
//! - `GET /api/approvals/pending` - List pending approvals
//! - `GET /api/approvals/{id}` - Get a specific approval
//! - `POST /api/approvals/{id}/approve` - Approve an approval request
//! - `POST /api/approvals/{id}/deny` - Deny an approval request

use axum::{
    extract::{Path, State},
    http::{header, HeaderMap, StatusCode},
    Json,
};
use serde::Deserialize;
use serde_json::json;
use vellaveto_mcp::mediation::build_secondary_acis_envelope_with_security_context;
use vellaveto_types::acis::DecisionOrigin;
use vellaveto_types::{Action, Verdict};

use crate::routes::ErrorResponse;
use crate::AppState;

/// Maximum length for the `resolved_by` field (Finding B1: prevents multi-MB strings).
const MAX_RESOLVED_BY_LEN: usize = 1024;

/// SECURITY (FIND-R67-001): Maximum entries returned by pending approvals list.
const MAX_PENDING_LIST: usize = 1000;

/// Validate an approval ID from a URL path parameter.
/// SECURITY (R16-APPR-1): Reject oversized or malformed IDs to prevent
/// log bloat and provide clean error messages.
pub(crate) fn validate_approval_id(id: &str) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    let length_valid = crate::verified_approval_id::server_approval_id_length_valid(id.len());
    if !length_valid {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!(
                    "Approval ID must be 1-{} characters",
                    crate::verified_approval_id::MAX_SERVER_APPROVAL_ID_LEN
                ),
            }),
        ));
    }
    if !crate::verified_approval_id::server_approval_id_value_accepted(
        length_valid,
        id.chars().any(crate::routes::is_unsafe_char),
    ) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Approval ID contains invalid characters".to_string(),
            }),
        ));
    }
    Ok(())
}

/// Sanitize the resolved_by field: strip control characters.
/// SECURITY (R16-APPR-2): Prevents stored XSS via audit trail if
/// rendered in a web UI, and prevents log injection with newlines/tabs.
fn sanitize_resolved_by(value: &str) -> String {
    value
        .chars()
        .filter(|c| !crate::routes::is_unsafe_char(*c))
        .collect()
}

/// Derive the resolver identity from the authenticated principal.
///
/// SECURITY (R11-APPR-4): The resolver identity is derived from the Bearer
/// token hash rather than trusting client-supplied values. This creates a
/// cryptographic binding between the authentication and the audit trail.
///
/// The client-supplied `resolved_by` value is preserved as a note but the
/// token hash is the authoritative identity.
pub fn derive_resolver_identity(headers: &HeaderMap, client_value: &str) -> String {
    if let Some(auth) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    {
        if auth.len() > 7 && auth[..7].eq_ignore_ascii_case("bearer ") {
            let token = &auth[7..];
            if !token.is_empty() {
                use sha2::{Digest, Sha256};
                let hash = Sha256::digest(token.as_bytes());
                let principal = format!("bearer:{}", hex::encode(&hash[..16]));
                if client_value != "anonymous" {
                    // SECURITY (R34-SRV-7): Strip control characters from client value
                    // to prevent log injection via approval requested_by field.
                    let sanitized: String = client_value
                        .chars()
                        .filter(|c| !crate::routes::is_unsafe_char(*c))
                        .take(256)
                        .collect();
                    return format!("{principal} (note: {sanitized})");
                }
                return principal;
            }
        }
    }
    client_value.to_string()
}

/// Request body for resolving an approval.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolveRequest {
    #[serde(default = "default_resolver")]
    pub resolved_by: String,
    /// Optional reason for the approval/denial decision (audit trail).
    /// SECURITY (IMP-R212-002): Python SDK sends `reason` in the body;
    /// without this field `deny_unknown_fields` would reject the request.
    #[serde(default)]
    pub reason: Option<String>,
}

fn default_resolver() -> String {
    "anonymous".to_string()
}

/// List all pending approvals.
///
/// GET /api/approvals/pending
///
/// Returns a JSON object with:
/// - `count`: number of pending approvals
/// - `approvals`: array of approval objects (parameters redacted)
pub async fn list_pending_approvals(State(state): State<AppState>) -> Json<serde_json::Value> {
    let pending = match state.list_pending_approvals().await {
        Ok(p) => p,
        Err(e) => {
            tracing::error!("Failed to list pending approvals: {:?}", e);
            return Json(json!({"count": 0, "approvals": [], "error": "Backend unavailable"}));
        }
    };
    // SECURITY (R11-APPR-10): Redact sensitive parameters before returning.
    // The approval listing may contain API keys, credentials, or PII in the
    // action parameters. Apply the same redaction used by the audit logger.
    // SECURITY (FIND-R67-001): Cap response to prevent unbounded serialization.
    let total = pending.len();
    let redacted: Vec<serde_json::Value> = pending
        .iter()
        .take(MAX_PENDING_LIST)
        .filter_map(|a| {
            // SECURITY (FIND-R67-005): Handle serialization failure instead of
            // silently producing empty objects via unwrap_or_default().
            match serde_json::to_value(a) {
                Ok(mut val) => {
                    if let Some(action) = val.get_mut("action") {
                        if let Some(params) = action.get("parameters") {
                            let redacted_params = vellaveto_audit::redact_keys_and_patterns(params);
                            action["parameters"] = redacted_params;
                        }
                    }
                    Some(val)
                }
                Err(e) => {
                    tracing::warn!("Failed to serialize approval entry: {}", e);
                    None
                }
            }
        })
        .collect();

    Json(
        json!({"count": redacted.len(), "total": total, "truncated": total > MAX_PENDING_LIST, "approvals": redacted}),
    )
}

/// Get a specific approval by ID.
///
/// GET /api/approvals/{id}
///
/// Returns the approval object with parameters redacted.
pub async fn get_approval(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    validate_approval_id(&id)?;

    let approval = state.get_approval(&id).await.map_err(|e| {
        tracing::debug!("Approval lookup failed for '{}': {:?}", id, e);
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Approval not found".to_string(),
            }),
        )
    })?;

    // Phase 2: Generate fact summary before approval is moved into JSON.
    let fact_summary = approval.fact_summary();

    let mut value = serde_json::to_value(approval).map_err(|e| {
        tracing::error!("Approval serialization error: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Internal server error".to_string(),
            }),
        )
    })?;
    // SECURITY (R11-APPR-10): Redact parameters before returning
    if let Some(action) = value.get_mut("action") {
        if let Some(params) = action.get("parameters") {
            let redacted = vellaveto_audit::redact_keys_and_patterns(params);
            action["parameters"] = redacted;
        }
    }
    // Phase 2: Include fact summary for human reviewers.
    if let Ok(summary_json) = serde_json::to_value(&fact_summary) {
        value["fact_summary"] = summary_json;
    }
    Ok(Json(value))
}

/// Approve an approval request.
///
/// POST /api/approvals/{id}/approve
///
/// # Security
///
/// - Derives resolver identity from authenticated principal (Bearer token hash)
/// - Validates approval ID for length and control characters
/// - Creates audit trail for the approval decision
/// - Returns 403 Forbidden for self-approval attempts
pub async fn approve_approval(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Option<Json<ResolveRequest>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    validate_approval_id(&id)?;

    // SECURITY (R11-APPR-4): Derive resolver identity from the authenticated
    // principal (Bearer token hash) rather than trusting the client-supplied
    // resolved_by field. The client value is kept as a note but the auth
    // identity is the authoritative record.
    // SECURITY (IMP-R212-002): Extract both resolved_by and optional reason
    // from the body before consuming it.
    let (client_resolved_by, reason) = match body {
        Some(b) => {
            let reason = b.reason.clone();
            (b.resolved_by.clone(), reason)
        }
        None => ("anonymous".to_string(), None),
    };
    let resolved_by =
        sanitize_resolved_by(&derive_resolver_identity(&headers, &client_resolved_by));

    if resolved_by.len() > MAX_RESOLVED_BY_LEN {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("resolved_by exceeds maximum length of {MAX_RESOLVED_BY_LEN} bytes"),
            }),
        ));
    }
    // Validate reason if present
    if let Some(ref r) = reason {
        if r.len() > 4096 {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "reason exceeds maximum length (4096)".to_string(),
                }),
            ));
        }
        if r.chars().any(super::is_unsafe_char) {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "reason contains invalid characters".to_string(),
                }),
            ));
        }
    }

    let approval = state
        .approve_approval(&id, &resolved_by)
        .await
        .map_err(|e| {
            let (status, msg) = match &e {
                crate::ApprovalOpError::NotFound(_) => {
                    (StatusCode::NOT_FOUND, "Approval not found")
                }
                crate::ApprovalOpError::AlreadyResolved(_) => {
                    (StatusCode::CONFLICT, "Approval already resolved")
                }
                crate::ApprovalOpError::Expired(_) => (StatusCode::GONE, "Approval expired"),
                crate::ApprovalOpError::Validation(ref msg) => {
                    // SECURITY (R9-2): Self-approval attempts return 403 Forbidden
                    tracing::warn!("Approval validation failed for '{}': {}", id, msg);
                    (StatusCode::FORBIDDEN, "Self-approval denied")
                }
                _ => {
                    tracing::error!("Approval approve error for '{}': {:?}", id, e);
                    (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
                }
            };
            (
                status,
                Json(ErrorResponse {
                    error: msg.to_string(),
                }),
            )
        })?;

    // M7: Audit trail for approval decisions
    {
        let audit_action = Action::new(
            "vellaveto",
            "approval_resolved",
            json!({
                "approval_id": &id,
                "original_tool": &approval.action.tool,
                "original_function": &approval.action.function,
            }),
        );
        let mut meta = json!({
            "source": "api",
            "event": "approval_approved",
            "resolved_by": &resolved_by,
        });
        if let Some(ref r) = reason {
            meta["reason"] = json!(r);
        }
        if approval
            .containment_context
            .as_ref()
            .is_some_and(|context| context.counterfactual_review_required)
        {
            meta["counterfactual_review_required"] = json!(true);
        }
        let approval_security_context = approval
            .containment_context
            .as_ref()
            .and_then(|context| context.to_runtime_security_context());
        let acis_envelope = build_secondary_acis_envelope_with_security_context(
            &audit_action,
            &Verdict::Allow,
            DecisionOrigin::ApprovalGate,
            "http",
            approval.session_id.as_deref(),
            approval_security_context.as_ref(),
        );
        if let Err(e) = state
            .audit
            .log_entry_with_acis(&audit_action, &Verdict::Allow, meta, acis_envelope)
            .await
        {
            tracing::warn!("Failed to audit approval resolution for {}: {}", id, e);
        } else {
            crate::metrics::increment_audit_entries();
        }
    }

    // Phase 50: Record approval in usage tracker.
    if let Some(ref tracker) = state.usage_tracker {
        tracker.record_approval(crate::tenant::DEFAULT_TENANT_ID);
    }

    let mut value = serde_json::to_value(approval).map_err(|e| {
        tracing::error!("Approval serialization error: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Internal server error".to_string(),
            }),
        )
    })?;
    // SECURITY (R29-SRV-1): Redact parameters before returning (same as get_approval)
    if let Some(action) = value.get_mut("action") {
        if let Some(params) = action.get("parameters") {
            let redacted = vellaveto_audit::redact_keys_and_patterns(params);
            action["parameters"] = redacted;
        }
    }
    Ok(Json(value))
}

/// Deny an approval request.
///
/// POST /api/approvals/{id}/deny
///
/// # Security
///
/// - Derives resolver identity from authenticated principal (Bearer token hash)
/// - Validates approval ID for length and control characters
/// - Creates audit trail for the denial decision
pub async fn deny_approval(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Option<Json<ResolveRequest>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    validate_approval_id(&id)?;

    // SECURITY (IMP-R212-002): Extract both resolved_by and optional reason.
    let (client_resolved_by, reason) = match body {
        Some(b) => {
            let reason = b.reason.clone();
            (b.resolved_by.clone(), reason)
        }
        None => ("anonymous".to_string(), None),
    };
    let resolved_by =
        sanitize_resolved_by(&derive_resolver_identity(&headers, &client_resolved_by));

    if resolved_by.len() > MAX_RESOLVED_BY_LEN {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("resolved_by exceeds maximum length of {MAX_RESOLVED_BY_LEN} bytes"),
            }),
        ));
    }
    if let Some(ref r) = reason {
        if r.len() > 4096 {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "reason exceeds maximum length (4096)".to_string(),
                }),
            ));
        }
        if r.chars().any(super::is_unsafe_char) {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "reason contains invalid characters".to_string(),
                }),
            ));
        }
    }

    let approval = state.deny_approval(&id, &resolved_by).await.map_err(|e| {
        let (status, msg) = match &e {
            crate::ApprovalOpError::NotFound(_) => (StatusCode::NOT_FOUND, "Approval not found"),
            crate::ApprovalOpError::AlreadyResolved(_) => {
                (StatusCode::CONFLICT, "Approval already resolved")
            }
            crate::ApprovalOpError::Expired(_) => (StatusCode::GONE, "Approval expired"),
            crate::ApprovalOpError::Validation(ref msg) => {
                // SECURITY (FIND-R170-001): Self-denial validation returns 403,
                // mirroring approve_approval handler (R9-2 parity).
                tracing::warn!("Approval denial validation failed for '{}': {}", id, msg);
                (StatusCode::FORBIDDEN, "Self-denial denied")
            }
            _ => {
                tracing::error!("Approval deny error for '{}': {:?}", id, e);
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
            }
        };
        (
            status,
            Json(ErrorResponse {
                error: msg.to_string(),
            }),
        )
    })?;

    // M7: Audit trail for approval decisions
    {
        let audit_action = Action::new(
            "vellaveto",
            "approval_resolved",
            json!({
                "approval_id": &id,
                "original_tool": &approval.action.tool,
                "original_function": &approval.action.function,
            }),
        );
        let mut meta = json!({
            "source": "api",
            "event": "approval_denied",
            "resolved_by": &resolved_by,
        });
        if let Some(ref r) = reason {
            meta["reason"] = json!(r);
        }
        let deny_verdict = Verdict::Deny {
            reason: "approval_denied".to_string(),
        };
        if approval
            .containment_context
            .as_ref()
            .is_some_and(|context| context.counterfactual_review_required)
        {
            meta["counterfactual_review_required"] = json!(true);
        }
        let approval_security_context = approval
            .containment_context
            .as_ref()
            .and_then(|context| context.to_runtime_security_context());
        let acis_envelope = build_secondary_acis_envelope_with_security_context(
            &audit_action,
            &deny_verdict,
            DecisionOrigin::ApprovalGate,
            "http",
            approval.session_id.as_deref(),
            approval_security_context.as_ref(),
        );
        if let Err(e) = state
            .audit
            .log_entry_with_acis(&audit_action, &deny_verdict, meta, acis_envelope)
            .await
        {
            tracing::warn!("Failed to audit approval denial for {}: {}", id, e);
        } else {
            crate::metrics::increment_audit_entries();
        }
    }

    let mut value = serde_json::to_value(approval).map_err(|e| {
        tracing::error!("Approval serialization error: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Internal server error".to_string(),
            }),
        )
    })?;
    // SECURITY (R29-SRV-1): Redact parameters before returning (same as get_approval)
    if let Some(action) = value.get_mut("action") {
        if let Some(params) = action.get("parameters") {
            let redacted = vellaveto_audit::redact_keys_and_patterns(params);
            action["parameters"] = redacted;
        }
    }
    Ok(Json(value))
}

#[cfg(test)]
#[allow(clippy::assertions_on_constants)]
mod tests {
    use super::*;

    // ── validate_approval_id tests ───────────────────────────────────────

    #[test]
    fn test_validate_approval_id_valid_uuid() {
        assert!(validate_approval_id("550e8400-e29b-41d4-a716-446655440000").is_ok());
    }

    #[test]
    fn test_validate_approval_id_valid_short() {
        assert!(validate_approval_id("abc-123").is_ok());
    }

    #[test]
    fn test_validate_approval_id_single_char() {
        assert!(validate_approval_id("x").is_ok());
    }

    #[test]
    fn test_validate_approval_id_empty_rejected() {
        let err = validate_approval_id("").unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert!(err.1 .0.error.contains("1-128"));
    }

    #[test]
    fn test_validate_approval_id_too_long_rejected() {
        let long_id = "a".repeat(129);
        let err = validate_approval_id(&long_id).unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_validate_approval_id_at_max_length() {
        let id = "a".repeat(128);
        assert!(validate_approval_id(&id).is_ok());
    }

    #[test]
    fn test_validate_approval_id_control_chars_rejected() {
        let err = validate_approval_id("id\x00inject").unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert!(err.1 .0.error.contains("invalid characters"));
    }

    #[test]
    fn test_validate_approval_id_newline_rejected() {
        let err = validate_approval_id("id\nline2").unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_validate_approval_id_tab_rejected() {
        let err = validate_approval_id("id\there").unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }

    // ── sanitize_resolved_by tests ───────────────────────────────────────

    #[test]
    fn test_sanitize_resolved_by_clean_input() {
        assert_eq!(sanitize_resolved_by("admin-user"), "admin-user");
    }

    #[test]
    fn test_sanitize_resolved_by_strips_control_chars() {
        assert_eq!(sanitize_resolved_by("admin\x00user"), "adminuser");
    }

    #[test]
    fn test_sanitize_resolved_by_strips_newlines() {
        assert_eq!(
            sanitize_resolved_by("admin\ninjected\rlog"),
            "admininjectedlog"
        );
    }

    #[test]
    fn test_sanitize_resolved_by_strips_tabs() {
        assert_eq!(sanitize_resolved_by("admin\tuser"), "adminuser");
    }

    #[test]
    fn test_sanitize_resolved_by_empty_string() {
        assert_eq!(sanitize_resolved_by(""), "");
    }

    #[test]
    fn test_sanitize_resolved_by_preserves_unicode_letters() {
        assert_eq!(sanitize_resolved_by("Hallgrimur"), "Hallgrimur");
    }

    // ── derive_resolver_identity tests ───────────────────────────────────

    #[test]
    fn test_derive_resolver_identity_no_auth_header() {
        let headers = HeaderMap::new();
        let result = derive_resolver_identity(&headers, "admin");
        assert_eq!(result, "admin");
    }

    #[test]
    fn test_derive_resolver_identity_non_bearer_header() {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, "Basic dXNlcjpwYXNz".parse().unwrap());
        let result = derive_resolver_identity(&headers, "admin");
        assert_eq!(result, "admin");
    }

    #[test]
    fn test_derive_resolver_identity_bearer_token_binds_hash() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            "Bearer test-token-value".parse().unwrap(),
        );
        let result = derive_resolver_identity(&headers, "user1");
        assert!(result.starts_with("bearer:"));
        assert!(result.contains("(note: user1)"));
    }

    #[test]
    fn test_derive_resolver_identity_bearer_anonymous_no_note() {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, "Bearer my-api-key".parse().unwrap());
        let result = derive_resolver_identity(&headers, "anonymous");
        assert!(result.starts_with("bearer:"));
        assert!(!result.contains("(note:"));
    }

    #[test]
    fn test_derive_resolver_identity_bearer_case_insensitive() {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, "BEARER my-api-key".parse().unwrap());
        let result = derive_resolver_identity(&headers, "anonymous");
        assert!(result.starts_with("bearer:"));
    }

    #[test]
    fn test_derive_resolver_identity_empty_bearer_token() {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, "Bearer ".parse().unwrap());
        let result = derive_resolver_identity(&headers, "admin");
        // Empty token: falls through to client value
        assert_eq!(result, "admin");
    }

    #[test]
    fn test_derive_resolver_identity_client_value_control_chars_stripped() {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, "Bearer test-token".parse().unwrap());
        let result = derive_resolver_identity(&headers, "user\x00inject\nlog");
        assert!(!result.contains('\x00'));
        assert!(!result.contains('\n'));
        assert!(result.contains("userinjectlog"));
    }

    #[test]
    fn test_derive_resolver_identity_client_value_truncated_at_256() {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, "Bearer test-token".parse().unwrap());
        let long_name = "x".repeat(500);
        let result = derive_resolver_identity(&headers, &long_name);
        // The note should be truncated to 256 chars
        let note_content = result
            .split("(note: ")
            .nth(1)
            .unwrap()
            .trim_end_matches(')');
        assert!(note_content.len() <= 256);
    }

    #[test]
    fn test_derive_resolver_identity_same_token_same_hash() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            "Bearer deterministic-token".parse().unwrap(),
        );
        let result1 = derive_resolver_identity(&headers, "anonymous");
        let result2 = derive_resolver_identity(&headers, "anonymous");
        assert_eq!(result1, result2);
    }

    #[test]
    fn test_derive_resolver_identity_different_tokens_different_hashes() {
        let mut h1 = HeaderMap::new();
        h1.insert(header::AUTHORIZATION, "Bearer token-aaa".parse().unwrap());
        let mut h2 = HeaderMap::new();
        h2.insert(header::AUTHORIZATION, "Bearer token-bbb".parse().unwrap());
        let r1 = derive_resolver_identity(&h1, "anonymous");
        let r2 = derive_resolver_identity(&h2, "anonymous");
        assert_ne!(r1, r2);
    }

    // ── default_resolver tests ───────────────────────────────────────────

    #[test]
    fn test_default_resolver_returns_anonymous() {
        assert_eq!(default_resolver(), "anonymous");
    }

    // ── ResolveRequest serde tests ───────────────────────────────────────

    #[test]
    fn test_resolve_request_defaults() {
        let req: ResolveRequest = serde_json::from_str("{}").unwrap();
        assert_eq!(req.resolved_by, "anonymous");
        assert!(req.reason.is_none());
    }

    #[test]
    fn test_resolve_request_with_fields() {
        let req: ResolveRequest =
            serde_json::from_str(r#"{"resolved_by":"admin","reason":"policy review"}"#).unwrap();
        assert_eq!(req.resolved_by, "admin");
        assert_eq!(req.reason.as_deref(), Some("policy review"));
    }

    #[test]
    fn test_resolve_request_denies_unknown_fields() {
        let result: Result<ResolveRequest, _> =
            serde_json::from_str(r#"{"resolved_by":"admin","extra":true}"#);
        assert!(result.is_err());
    }

    // ── Constants sanity checks ──────────────────────────────────────────

    #[test]
    fn test_max_resolved_by_len_reasonable() {
        assert!(MAX_RESOLVED_BY_LEN > 0);
        assert!(MAX_RESOLVED_BY_LEN <= 8192);
    }

    #[test]
    fn test_max_approval_id_len_reasonable() {
        assert!(crate::verified_approval_id::MAX_SERVER_APPROVAL_ID_LEN >= 36); // UUID length
        assert!(crate::verified_approval_id::MAX_SERVER_APPROVAL_ID_LEN <= 256);
    }

    #[test]
    fn test_max_pending_list_reasonable() {
        assert!(MAX_PENDING_LIST > 0);
        assert!(MAX_PENDING_LIST <= 10_000);
    }
}
