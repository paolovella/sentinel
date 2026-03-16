// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Audit log route handlers.
//!
//! This module provides REST API endpoints for audit log access,
//! verification, and checkpoint management.
//!
//! Endpoints:
//! - `GET /api/audit` - List audit entries (paginated)
//! - `GET /api/audit/export` - Export audit entries in SIEM formats
//! - `GET /api/audit/report` - Get audit summary report
//! - `GET /api/audit/verify` - Verify audit chain integrity
//! - `GET /api/audit/checkpoints` - List checkpoints
//! - `GET /api/audit/checkpoints/verify` - Verify checkpoint signatures
//! - `POST /api/audit/checkpoints` - Create a new checkpoint

use axum::{
    extract::{Query, State},
    http::{header, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use serde_json::json;

use crate::routes::ErrorResponse;
use crate::AppState;

/// Default number of audit entries per page.
const DEFAULT_AUDIT_PAGE_SIZE: usize = 100;
/// Maximum number of audit entries per page.
const MAX_AUDIT_PAGE_SIZE: usize = 1000;
/// Maximum number of entries that can be loaded before returning an error.
const MAX_LOADED_ENTRIES: usize = 500_000;
/// SECURITY (FIND-R67-004-001): Maximum number of checkpoints returned by list endpoint.
const MAX_CHECKPOINTS_LIST: usize = 1000;

/// Query parameters for paginated audit entry listing.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditEntriesQuery {
    /// Maximum number of entries to return (default 100, max 1000).
    #[serde(default)]
    pub limit: Option<usize>,
    /// Number of entries to skip from the end (most recent first).
    #[serde(default)]
    pub offset: Option<usize>,
}

/// List audit entries with pagination.
///
/// GET /api/audit
#[tracing::instrument(name = "vellaveto.audit_entries", skip(state, params))]
pub async fn audit_entries(
    State(state): State<AppState>,
    Query(params): Query<AuditEntriesQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let entries = state.audit.load_entries().await.map_err(|e| {
        tracing::error!("Failed to load audit entries: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to load audit entries".to_string(),
            }),
        )
    })?;

    if entries.len() > MAX_LOADED_ENTRIES {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                error: "Audit log exceeds capacity limit. Rotate or archive the audit log."
                    .to_string(),
            }),
        ));
    }

    let total = entries.len();
    let limit = params
        .limit
        .unwrap_or(DEFAULT_AUDIT_PAGE_SIZE)
        .min(MAX_AUDIT_PAGE_SIZE);
    // SECURITY (FIND-R58-SRV-AUDIT-001): Cap offset at total to prevent
    // nonsensical skip values that waste iterator cycles.
    let offset = params.offset.unwrap_or(0).min(total);

    // Return the most recent entries (tail of the list), paginated.
    let page: Vec<_> = entries.into_iter().rev().skip(offset).take(limit).collect();

    Ok(Json(
        json!({"total": total, "count": page.len(), "offset": offset, "limit": limit, "entries": page}),
    ))
}

/// Query parameters for the audit export endpoint.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditExportQuery {
    /// Export format: "cef" or "jsonl". Default: "jsonl".
    pub format: Option<String>,
    /// Only include entries with timestamp >= this value (ISO 8601 string comparison).
    pub since: Option<String>,
    /// Maximum number of entries to export. Default: 100, max: 1000.
    pub limit: Option<usize>,
}

/// Export audit entries in SIEM-compatible formats (CEF or JSON Lines).
///
/// GET /api/audit/export
///
/// Query parameters:
/// - `format`: "cef" or "jsonl" (default: "jsonl")
/// - `since`: ISO 8601 timestamp filter (entries >= this value)
/// - `limit`: Maximum entries (default: 100, max: 1000)
///
/// Returns `text/plain` for CEF, `application/x-ndjson` for JSON Lines.
pub async fn audit_export(
    State(state): State<AppState>,
    Query(query): Query<AuditExportQuery>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    // SECURITY (FIND-R49-005): Validate `since` and `format` query parameters
    if let Some(ref since) = query.since {
        if since.len() > 64 || since.chars().any(crate::routes::is_unsafe_char) {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "Invalid 'since' parameter".to_string(),
                }),
            ));
        }
        // SECURITY (P3, Trap 17): Validate basic ISO 8601 format — must start with
        // a 4-digit year. Rejects arbitrary strings used as lexicographic filters
        // that could never match valid timestamps, preventing logic confusion.
        let year_digits = since.chars().take(4).filter(|c| c.is_ascii_digit()).count();
        if year_digits != 4 {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "Invalid 'since' parameter: must be an ISO 8601 timestamp".to_string(),
                }),
            ));
        }
    }
    if let Some(ref fmt) = query.format {
        if fmt.len() > 16 || fmt.chars().any(crate::routes::is_unsafe_char) {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "Invalid 'format' parameter".to_string(),
                }),
            ));
        }
    }

    let format = query
        .format
        .as_deref()
        .and_then(vellaveto_audit::export::ExportFormat::parse_format)
        .unwrap_or(vellaveto_audit::export::ExportFormat::JsonLines);

    let limit = query.limit.unwrap_or(100).min(1000); // Cap at 1000

    let entries = state.audit.load_entries().await.map_err(|e| {
        tracing::error!("Failed to load audit entries for export: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to load audit entries".to_string(),
            }),
        )
    })?;

    if entries.len() > MAX_LOADED_ENTRIES {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                error: "Audit log exceeds capacity limit. Rotate or archive the audit log."
                    .to_string(),
            }),
        ));
    }

    // Filter by `since` timestamp if provided (lexicographic comparison on ISO 8601)
    let filtered: Vec<_> = if let Some(ref since) = query.since {
        entries
            .into_iter()
            .filter(|e| e.timestamp.as_str() >= since.as_str())
            .take(limit)
            .collect()
    } else {
        entries.into_iter().take(limit).collect()
    };

    let body = vellaveto_audit::export::format_entries(&filtered, format);

    let content_type = match format {
        vellaveto_audit::export::ExportFormat::Cef => "text/plain",
        vellaveto_audit::export::ExportFormat::JsonLines => "application/x-ndjson",
        vellaveto_audit::export::ExportFormat::Ocsf => "application/json",
    };

    Ok(([(header::CONTENT_TYPE, content_type)], body))
}

/// Generate an audit summary report.
///
/// GET /api/audit/report
pub async fn audit_report(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let report = state.audit.generate_report().await.map_err(|e| {
        tracing::error!("Failed to generate audit report: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to generate audit report".to_string(),
            }),
        )
    })?;

    // SECURITY (R16-AUDIT-5): Return summary statistics only, not the full
    // entry list. The entries endpoint provides paginated access to individual
    // entries. Embedding all entries in the report response could exhaust
    // server memory with a large audit log.
    Ok(Json(json!({
        "total_entries": report.total_entries,
        "allow_count": report.allow_count,
        "deny_count": report.deny_count,
        "require_approval_count": report.require_approval_count,
    })))
}

/// Verify audit chain integrity.
///
/// GET /api/audit/verify
pub async fn audit_verify(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let verification = state.audit.verify_chain().await.map_err(|e| {
        tracing::error!("Failed to verify audit chain: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to verify audit chain".to_string(),
            }),
        )
    })?;

    let value = serde_json::to_value(verification).map_err(|e| {
        tracing::error!("Audit verification serialization error: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Internal server error".to_string(),
            }),
        )
    })?;
    Ok(Json(value))
}

/// List all checkpoints.
///
/// GET /api/audit/checkpoints
pub async fn list_checkpoints(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let checkpoints = state.audit.load_checkpoints().await.map_err(|e| {
        tracing::error!("Failed to load checkpoints: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to load checkpoints".to_string(),
            }),
        )
    })?;

    // SECURITY (FIND-R67-004-001): Cap response to prevent unbounded serialization.
    let total = checkpoints.len();
    let bounded: Vec<_> = checkpoints.into_iter().take(MAX_CHECKPOINTS_LIST).collect();
    Ok(Json(
        json!({"count": bounded.len(), "total": total, "truncated": total > MAX_CHECKPOINTS_LIST, "checkpoints": bounded}),
    ))
}

/// Verify all checkpoint signatures.
///
/// GET /api/audit/checkpoints/verify
pub async fn verify_checkpoints(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let verification = state.audit.verify_checkpoints().await.map_err(|e| {
        tracing::error!("Failed to verify checkpoints: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to verify checkpoints".to_string(),
            }),
        )
    })?;

    let value = serde_json::to_value(verification).map_err(|e| {
        tracing::error!("Checkpoint verification serialization error: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Internal server error".to_string(),
            }),
        )
    })?;
    Ok(Json(value))
}

/// Create a new checkpoint.
///
/// POST /api/audit/checkpoints
pub async fn create_checkpoint(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let checkpoint = state.audit.create_checkpoint().await.map_err(|e| {
        tracing::error!("Failed to create checkpoint: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to create checkpoint".to_string(),
            }),
        )
    })?;

    let value = serde_json::to_value(&checkpoint).map_err(|e| {
        tracing::error!("Checkpoint serialization error: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Internal server error".to_string(),
            }),
        )
    })?;
    Ok(Json(value))
}

#[cfg(test)]
#[allow(clippy::assertions_on_constants, clippy::unnecessary_literal_unwrap)]
mod tests {
    use super::*;

    // ── AuditEntriesQuery serde tests ────────────────────────────────────

    #[test]
    fn test_audit_entries_query_defaults() {
        let q: AuditEntriesQuery = serde_json::from_str("{}").unwrap();
        assert!(q.limit.is_none());
        assert!(q.offset.is_none());
    }

    #[test]
    fn test_audit_entries_query_with_values() {
        let q: AuditEntriesQuery = serde_json::from_str(r#"{"limit":50,"offset":10}"#).unwrap();
        assert_eq!(q.limit, Some(50));
        assert_eq!(q.offset, Some(10));
    }

    #[test]
    fn test_audit_entries_query_denies_unknown_fields() {
        let result: Result<AuditEntriesQuery, _> =
            serde_json::from_str(r#"{"limit":50,"bogus":true}"#);
        assert!(result.is_err());
    }

    // ── AuditExportQuery serde tests ─────────────────────────────────────

    #[test]
    fn test_audit_export_query_defaults() {
        let q: AuditExportQuery = serde_json::from_str("{}").unwrap();
        assert!(q.format.is_none());
        assert!(q.since.is_none());
        assert!(q.limit.is_none());
    }

    #[test]
    fn test_audit_export_query_with_all_fields() {
        let q: AuditExportQuery =
            serde_json::from_str(r#"{"format":"cef","since":"2026-01-01T00:00:00Z","limit":500}"#)
                .unwrap();
        assert_eq!(q.format.as_deref(), Some("cef"));
        assert_eq!(q.since.as_deref(), Some("2026-01-01T00:00:00Z"));
        assert_eq!(q.limit, Some(500));
    }

    #[test]
    fn test_audit_export_query_denies_unknown_fields() {
        let result: Result<AuditExportQuery, _> =
            serde_json::from_str(r#"{"format":"jsonl","extra":"bad"}"#);
        assert!(result.is_err());
    }

    // ── Constants sanity checks ──────────────────────────────────────────

    #[test]
    fn test_default_audit_page_size_reasonable() {
        assert!(DEFAULT_AUDIT_PAGE_SIZE > 0);
        assert!(DEFAULT_AUDIT_PAGE_SIZE <= MAX_AUDIT_PAGE_SIZE);
    }

    #[test]
    fn test_max_audit_page_size_bounded() {
        assert!(MAX_AUDIT_PAGE_SIZE > 0);
        assert!(MAX_AUDIT_PAGE_SIZE <= 10_000);
    }

    #[test]
    fn test_max_loaded_entries_bounded() {
        assert!(MAX_LOADED_ENTRIES > 0);
        assert!(MAX_LOADED_ENTRIES <= 1_000_000);
    }

    #[test]
    fn test_max_checkpoints_list_bounded() {
        assert!(MAX_CHECKPOINTS_LIST > 0);
        assert!(MAX_CHECKPOINTS_LIST <= 10_000);
    }

    // ── Pagination logic tests ───────────────────────────────────────────
    // These test the pagination clamping logic extracted from the handler.

    #[test]
    fn test_pagination_limit_defaults_to_100() {
        let limit = None::<usize>
            .unwrap_or(DEFAULT_AUDIT_PAGE_SIZE)
            .min(MAX_AUDIT_PAGE_SIZE);
        assert_eq!(limit, 100);
    }

    #[test]
    fn test_pagination_limit_capped_at_max() {
        let limit = Some(5000_usize)
            .unwrap_or(DEFAULT_AUDIT_PAGE_SIZE)
            .min(MAX_AUDIT_PAGE_SIZE);
        assert_eq!(limit, MAX_AUDIT_PAGE_SIZE);
    }

    #[test]
    fn test_pagination_limit_explicit_value() {
        let limit = Some(50_usize)
            .unwrap_or(DEFAULT_AUDIT_PAGE_SIZE)
            .min(MAX_AUDIT_PAGE_SIZE);
        assert_eq!(limit, 50);
    }

    #[test]
    fn test_pagination_offset_capped_at_total() {
        let total: usize = 100;
        let offset = Some(200_usize).unwrap_or(0).min(total);
        assert_eq!(offset, 100);
    }

    #[test]
    fn test_pagination_offset_defaults_to_zero() {
        let total: usize = 100;
        let offset = None::<usize>.unwrap_or(0).min(total);
        assert_eq!(offset, 0);
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Phase 2: OpenTelemetry span export
// ═══════════════════════════════════════════════════════════════════════════════

/// Export recent audit entries as OTel-compatible spans.
///
/// GET /api/audit/otel-spans?limit=100
///
/// Converts audit entries to structured span records that can be
/// forwarded to Jaeger, Grafana Tempo, or other OTel backends.
pub async fn otel_spans(
    State(_state): State<super::super::AppState>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> axum::Json<serde_json::Value> {
    let limit = params
        .get("limit")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(100)
        .min(1000);

    // OTel span export endpoint. The build_evaluation_span() converter exists
    // in vellaveto_audit::otel_spans — this endpoint will wire to the audit
    // query layer once file/PostgreSQL querying is integrated.
    axum::Json(serde_json::json!({
        "spans": [],
        "count": 0,
        "limit": limit,
        "note": "OTel span export available — connect to audit query backend for live data"
    }))
}
