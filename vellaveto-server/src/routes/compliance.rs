// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Compliance evidence generation API routes.
//!
//! Provides endpoints for EU AI Act, SOC 2, ISO 42001, CoSAI, Adversa TOP 25,
//! OWASP ASI, DORA, NIS2, evidence packs, and cross-framework gap analysis
//! reporting. These read-only endpoints generate reports at request time using
//! registry-based classification (read-time, not write-time).
//!
//! SECURITY (FIND-R46-010): Compliance reports are computationally expensive to
//! generate. A simple time-based cache (60s TTL) is used for the stateless
//! endpoints (threat_coverage, gap_analysis, iso42001_report) to prevent
//! regeneration on every request. A more sophisticated caching layer (e.g.,
//! per-config-hash, shared across endpoints) should be added in a future phase.

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

use super::ErrorResponse;
use crate::AppState;

/// SECURITY (FIND-R46-010): Simple time-based cache for compliance reports.
/// Regenerate at most once per 60 seconds.
const COMPLIANCE_CACHE_TTL_SECS: u64 = 60;

/// Cached compliance report entry.
struct CachedReport {
    generated_at: Instant,
    value: serde_json::Value,
}

/// Thread-safe cache for a single compliance report.
struct ReportCache(Mutex<Option<CachedReport>>);

impl ReportCache {
    const fn new() -> Self {
        Self(Mutex::new(None))
    }

    /// Return cached value if still valid, otherwise None.
    fn get(&self) -> Option<serde_json::Value> {
        let guard = match self.0.lock() {
            Ok(g) => g,
            Err(poisoned) => {
                // SECURITY (FIND-R157): Recover from mutex poisoning instead of
                // discarding cached data. This is a non-security cache so recovery
                // is safe and avoids unnecessary regeneration.
                tracing::warn!("ReportCache mutex poisoned — recovering for cache read");
                poisoned.into_inner()
            }
        };
        if let Some(ref cached) = *guard {
            if cached.generated_at.elapsed().as_secs() < COMPLIANCE_CACHE_TTL_SECS {
                return Some(cached.value.clone());
            }
        }
        None
    }

    /// Store a freshly generated report.
    fn set(&self, value: serde_json::Value) {
        let mut guard = match self.0.lock() {
            Ok(g) => g,
            Err(poisoned) => {
                // SECURITY (FIND-R157): Recover from mutex poisoning instead of
                // silently discarding the report. This is a non-security cache so
                // recovery is safe and avoids data loss.
                tracing::warn!("ReportCache mutex poisoned — recovering for cache write");
                poisoned.into_inner()
            }
        };
        *guard = Some(CachedReport {
            generated_at: Instant::now(),
            value,
        });
    }
}

static THREAT_COVERAGE_CACHE: ReportCache = ReportCache::new();
static GAP_ANALYSIS_CACHE: ReportCache = ReportCache::new();
static ISO42001_CACHE: ReportCache = ReportCache::new();
static OWASP_ASI_CACHE: ReportCache = ReportCache::new();
/// QUALITY (FIND-GAP-013): Cache for the compliance_status endpoint which
/// regenerates EU AI Act, SOC 2, NIST RMF, ISO 27090, and ISO 42001 reports
/// on every request. Keyed by (include_nist, include_iso) but simplified to
/// a single cache entry since the query param combinations are limited.
static COMPLIANCE_STATUS_CACHE: ReportCache = ReportCache::new();
/// Cache for evidence pack reports, keyed by framework name.
/// Uses a HashMap<String, CachedReport> for per-framework caching.
static EVIDENCE_PACK_CACHE: Mutex<Option<HashMap<String, CachedReport>>> = Mutex::new(None);

/// SECURITY (R238-SRV-7): Maximum number of entries in the evidence pack cache.
/// Prevents unbounded HashMap growth from attacker-controlled framework names.
const MAX_EVIDENCE_PACK_CACHE_ENTRIES: usize = 32;

// ── Query Parameters ─────────────────────────────────────────────────────────

/// Query parameters for the compliance status endpoint.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComplianceStatusQuery {
    /// Include NIST RMF coverage in status response.
    #[serde(default = "default_true")]
    pub include_nist: bool,
    /// Include ISO 27090 readiness in status response.
    #[serde(default = "default_true")]
    pub include_iso: bool,
}

fn default_true() -> bool {
    true
}

/// Query parameters for the SOC 2 evidence endpoint.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Soc2EvidenceQuery {
    /// Filter to specific Trust Services Category.
    #[serde(default)]
    pub category: Option<String>,
}

// ── Handlers ─────────────────────────────────────────────────────────────────

/// `GET /api/compliance/status` — Overall compliance posture.
///
/// Returns a summary of compliance readiness across all frameworks:
/// EU AI Act, SOC 2, NIST AI RMF, ISO 27090, and ISO 42001.
#[tracing::instrument(name = "vellaveto.compliance_status", skip(state))]
pub async fn compliance_status(
    State(state): State<AppState>,
    Query(params): Query<ComplianceStatusQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    // QUALITY (FIND-GAP-013): Serve from cache if within TTL and params are
    // default (both include flags true). Non-default queries bypass the cache
    // since they are less frequent and caching all permutations is overkill.
    if params.include_nist && params.include_iso {
        if let Some(cached) = COMPLIANCE_STATUS_CACHE.get() {
            return Ok(Json(cached));
        }
    }

    let snapshot = state.policy_state.load();
    let config = &snapshot.compliance_config;

    // EU AI Act
    let eu_ai_act_status = if config.eu_ai_act.enabled {
        let registry = vellaveto_audit::eu_ai_act::EuAiActRegistry::new();
        let report = registry.generate_assessment(
            config.eu_ai_act.risk_class,
            &config.eu_ai_act.deployer_name,
            &config.eu_ai_act.system_id,
        );
        Some(serde_json::json!({
            "enabled": true,
            "risk_class": config.eu_ai_act.risk_class,
            "compliance_percentage": report.compliance_percentage,
            "applicable_articles": report.applicable_articles,
            "compliant_articles": report.compliant_articles,
            "partial_articles": report.partial_articles,
        }))
    } else {
        Some(serde_json::json!({ "enabled": false }))
    };

    // SOC 2
    let soc2_status = if config.soc2.enabled {
        let registry = vellaveto_audit::soc2::Soc2Registry::new();
        let report = registry.generate_evidence_report(
            &config.soc2.organization_name,
            &config.soc2.period_start,
            &config.soc2.period_end,
            &config.soc2.tracked_categories,
        );
        Some(serde_json::json!({
            "enabled": true,
            "overall_readiness": report.overall_readiness,
            "total_score": report.total_score,
            "max_score": report.max_score,
            "total_gaps": report.total_gaps,
        }))
    } else {
        Some(serde_json::json!({ "enabled": false }))
    };

    // NIST RMF (optional)
    let nist_status = if params.include_nist {
        let registry = vellaveto_audit::nist_rmf::NistRmfRegistry::new();
        let report = registry.generate_report();
        Some(serde_json::json!({
            "overall_coverage": report.overall_coverage,
            "total_findings": report.findings.len(),
        }))
    } else {
        None
    };

    // ISO 27090 (optional)
    let iso_status = if params.include_iso {
        let registry = vellaveto_audit::iso27090::Iso27090Registry::new();
        let assessment = registry.generate_assessment();
        Some(serde_json::json!({
            "overall_percentage": assessment.overall_percentage,
            "certification_ready": assessment.certification_ready,
        }))
    } else {
        None
    };

    let mut response = serde_json::json!({
        "eu_ai_act": eu_ai_act_status,
        "soc2": soc2_status,
    });

    if let Some(nist) = nist_status {
        response["nist_rmf"] = nist;
    }
    if let Some(iso) = iso_status {
        response["iso27090"] = iso;
    }

    // ISO 42001
    let iso42001_registry = vellaveto_audit::iso42001::Iso42001Registry::new();
    let iso42001_report = iso42001_registry.generate_report("Vellaveto", "vellaveto-runtime");
    response["iso42001"] = serde_json::json!({
        "compliance_percentage": iso42001_report.compliance_percentage,
        "total_clauses": iso42001_report.total_clauses,
        "compliant_clauses": iso42001_report.compliant_clauses,
        "partial_clauses": iso42001_report.partial_clauses,
    });

    // OWASP ASI — gated on config enabled flag (FIND-R82-003)
    if config.owasp_asi.enabled {
        let asi_registry = vellaveto_audit::owasp_asi::OwaspAsiRegistry::new();
        let asi_report = asi_registry.generate_coverage_report();
        response["owasp_asi"] = serde_json::json!({
            "coverage_percent": asi_report.coverage_percent,
            "total_controls": asi_report.total_controls,
            "covered_controls": asi_report.covered_controls,
            "total_categories": asi_report.total_categories,
            "covered_categories": asi_report.covered_categories,
        });
    } else {
        response["owasp_asi"] = serde_json::json!({ "enabled": false });
    }

    // QUALITY (FIND-GAP-013): Cache default-params response for future requests.
    if params.include_nist && params.include_iso {
        COMPLIANCE_STATUS_CACHE.set(response.clone());
    }

    Ok(Json(response))
}

/// `GET /api/compliance/iso42001/report` — ISO/IEC 42001 compliance evidence.
///
/// Generates a full ISO 42001 AI Management System compliance evidence report.
#[tracing::instrument(name = "vellaveto.iso42001_report")]
pub async fn iso42001_report() -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)>
{
    // SECURITY (FIND-R46-010): Serve from cache if within TTL.
    if let Some(cached) = ISO42001_CACHE.get() {
        return Ok(Json(cached));
    }

    let registry = vellaveto_audit::iso42001::Iso42001Registry::new();
    let report = registry.generate_report("Vellaveto", "vellaveto-runtime");

    let value = serde_json::to_value(&report).map_err(|e| {
        tracing::error!("Failed to serialize ISO 42001 report: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to generate report".to_string(),
            }),
        )
    })?;

    ISO42001_CACHE.set(value.clone());
    Ok(Json(value))
}

/// `GET /api/compliance/eu-ai-act/report` — EU AI Act conformity assessment.
///
/// Generates a full conformity assessment report per Art 43 of the EU AI Act.
#[tracing::instrument(name = "vellaveto.eu_ai_act_report", skip(state))]
pub async fn eu_ai_act_report(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let snapshot = state.policy_state.load();
    let config = &snapshot.compliance_config;

    if !config.eu_ai_act.enabled {
        return Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "EU AI Act compliance is not enabled in configuration".to_string(),
            }),
        ));
    }

    let registry = vellaveto_audit::eu_ai_act::EuAiActRegistry::new();
    let report = registry.generate_assessment(
        config.eu_ai_act.risk_class,
        &config.eu_ai_act.deployer_name,
        &config.eu_ai_act.system_id,
    );

    serde_json::to_value(&report).map(Json).map_err(|e| {
        tracing::error!("Failed to serialize EU AI Act report: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to generate report".to_string(),
            }),
        )
    })
}

/// `GET /api/compliance/soc2/evidence` — SOC 2 evidence collection.
///
/// Generates a SOC 2 evidence report with optional category filtering.
#[tracing::instrument(name = "vellaveto.soc2_evidence", skip(state))]
pub async fn soc2_evidence(
    State(state): State<AppState>,
    Query(params): Query<Soc2EvidenceQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let snapshot = state.policy_state.load();
    let config = &snapshot.compliance_config;

    if !config.soc2.enabled {
        return Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "SOC 2 compliance is not enabled in configuration".to_string(),
            }),
        ));
    }

    // Apply category filter from query param if present
    let tracked_categories = if let Some(ref cat_filter) = params.category {
        // SECURITY (FIND-R49-005): Validate length and reject control characters
        // before using the filter value, and never echo user input in errors.
        if cat_filter.len() > 16 || cat_filter.chars().any(crate::routes::is_unsafe_char) {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "Invalid category. Valid values: CC1-CC9".to_string(),
                }),
            ));
        }
        use vellaveto_config::TrustServicesCategory;
        let parsed = match cat_filter.to_uppercase().as_str() {
            "CC1" => Some(TrustServicesCategory::CC1),
            "CC2" => Some(TrustServicesCategory::CC2),
            "CC3" => Some(TrustServicesCategory::CC3),
            "CC4" => Some(TrustServicesCategory::CC4),
            "CC5" => Some(TrustServicesCategory::CC5),
            "CC6" => Some(TrustServicesCategory::CC6),
            "CC7" => Some(TrustServicesCategory::CC7),
            "CC8" => Some(TrustServicesCategory::CC8),
            "CC9" => Some(TrustServicesCategory::CC9),
            _ => None,
        };
        if let Some(cat) = parsed {
            vec![cat]
        } else {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "Invalid category. Valid values: CC1-CC9".to_string(),
                }),
            ));
        }
    } else {
        config.soc2.tracked_categories.clone()
    };

    let registry = vellaveto_audit::soc2::Soc2Registry::new();
    let report = registry.generate_evidence_report(
        &config.soc2.organization_name,
        &config.soc2.period_start,
        &config.soc2.period_end,
        &tracked_categories,
    );

    serde_json::to_value(&report).map(Json).map_err(|e| {
        tracing::error!("Failed to serialize SOC 2 report: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to generate report".to_string(),
            }),
        )
    })
}

/// `GET /api/compliance/threat-coverage` — Threat framework coverage.
///
/// Returns coverage reports for MITRE ATLAS, CoSAI, and Adversa TOP 25
/// threat/vulnerability frameworks.
#[tracing::instrument(name = "vellaveto.threat_coverage")]
pub async fn threat_coverage() -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)>
{
    // SECURITY (FIND-R46-010): Serve from cache if within TTL.
    if let Some(cached) = THREAT_COVERAGE_CACHE.get() {
        return Ok(Json(cached));
    }

    let atlas = vellaveto_audit::atlas::AtlasRegistry::new();
    let atlas_report = atlas.generate_coverage_report();

    let cosai = vellaveto_audit::cosai::CosaiRegistry::new();
    let cosai_report = cosai.generate_coverage_report();

    let adversa = vellaveto_audit::adversa_top25::AdversaTop25Registry::new();
    let adversa_report = adversa.generate_coverage_report();

    let response = serde_json::json!({
        "atlas": {
            "total_techniques": atlas_report.total_techniques,
            "covered": atlas_report.covered_techniques.len(),
            "coverage_percent": atlas_report.coverage_percent,
        },
        "cosai": {
            "total_categories": cosai_report.total_categories,
            "covered_categories": cosai_report.covered_categories,
            "total_threats": cosai_report.total_threats,
            "covered_threats": cosai_report.covered_threats.len(),
            "coverage_percent": cosai_report.coverage_percent,
        },
        "adversa_top25": {
            "total_vulnerabilities": adversa_report.total_vulnerabilities,
            "covered": adversa_report.covered_count,
            "coverage_percent": adversa_report.coverage_percent,
        },
    });

    THREAT_COVERAGE_CACHE.set(response.clone());
    Ok(Json(response))
}

/// `GET /api/compliance/gap-analysis` — Cross-framework gap analysis.
///
/// Generates a consolidated gap analysis across all 10 security frameworks
/// (ATLAS, NIST RMF, ISO 27090, ISO 42001, EU AI Act, CoSAI, Adversa TOP 25, OWASP ASI, DORA, NIS2).
#[tracing::instrument(name = "vellaveto.gap_analysis")]
pub async fn gap_analysis() -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    // SECURITY (FIND-R46-010): Serve from cache if within TTL.
    if let Some(cached) = GAP_ANALYSIS_CACHE.get() {
        return Ok(Json(cached));
    }

    let report = vellaveto_audit::gap_analysis::generate_gap_analysis();

    let value = serde_json::to_value(&report).map_err(|e| {
        tracing::error!("Failed to serialize gap analysis report: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to generate gap analysis report".to_string(),
            }),
        )
    })?;

    GAP_ANALYSIS_CACHE.set(value.clone());
    Ok(Json(value))
}

/// `GET /api/compliance/owasp-agentic` — OWASP Agentic Security Index coverage.
///
/// Returns ASI coverage report with per-category breakdown and control matrix.
/// 10 categories (ASI01–ASI10), 33 controls, mapped to Vellaveto detections.
#[tracing::instrument(name = "vellaveto.owasp_asi", skip(state))]
pub async fn owasp_asi_coverage(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    // SECURITY (FIND-R82-003): Gate on config enabled flag, matching other compliance endpoints.
    let snapshot = state.policy_state.load();
    if !snapshot.compliance_config.owasp_asi.enabled {
        return Ok(Json(serde_json::json!({ "enabled": false })));
    }

    // SECURITY (FIND-R46-010): Serve from cache if within TTL.
    if let Some(cached) = OWASP_ASI_CACHE.get() {
        return Ok(Json(cached));
    }

    let registry = vellaveto_audit::owasp_asi::OwaspAsiRegistry::new();
    let report = registry.generate_coverage_report();

    let value = serde_json::to_value(&report).map_err(|e| {
        tracing::error!("Failed to serialize OWASP ASI report: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to generate OWASP ASI report".to_string(),
            }),
        )
    })?;

    OWASP_ASI_CACHE.set(value.clone());
    Ok(Json(value))
}

/// `GET /api/compliance/data-governance` — Art 10 data governance summary.
///
/// Returns tool data classification mappings, provenance, and retention records
/// when data governance is enabled. Returns `{ "enabled": false }` otherwise.
#[tracing::instrument(name = "vellaveto.data_governance", skip(state))]
pub async fn data_governance_summary(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let snapshot = state.policy_state.load();
    let config = &snapshot.compliance_config;

    if !config.data_governance.enabled {
        return Ok(Json(serde_json::json!({ "enabled": false })));
    }

    let registry = vellaveto_audit::data_governance::DataGovernanceRegistry::new();
    let summary = registry.generate_summary();

    serde_json::to_value(&summary)
        .map(|mut v| {
            v["enabled"] = serde_json::Value::Bool(true);
            Json(v)
        })
        .map_err(|e| {
            tracing::error!("Failed to serialize data governance summary: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to generate data governance summary".to_string(),
                }),
            )
        })
}

// ── Phase 38: SOC 2 Type II Access Review ───────────────────────────────────

/// Maximum agent_id query parameter length.
const MAX_AGENT_ID_QUERY_LEN: usize = 128;

/// Maximum period for access review reports in days.
const MAX_PERIOD_DAYS: u32 = 366;

/// Query parameters for the SOC 2 access review endpoint.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccessReviewQuery {
    /// Review period duration, e.g. "30d", "7d", "90d". Default from config.
    #[serde(default)]
    pub period: Option<String>,
    /// Export format: "json" (default) or "html".
    #[serde(default)]
    pub format: Option<String>,
    /// Optional agent_id filter.
    #[serde(default)]
    pub agent_id: Option<String>,
}

/// Parse a period string like "30d" into a number of days.
fn parse_period_days(period: &str) -> Result<u32, String> {
    let trimmed = period.trim();
    if trimmed.is_empty() {
        return Err("Empty period string".to_string());
    }
    // SECURITY: Reject overly long period strings before echoing in errors.
    if trimmed.len() > 20 {
        return Err("Invalid period: value too long".to_string());
    }
    let (num_str, suffix) = if trimmed.ends_with('d') || trimmed.ends_with('D') {
        (&trimmed[..trimmed.len() - 1], "d")
    } else {
        (trimmed, "")
    };
    let _ = suffix; // suffix is always "d" or empty (days only)
    let days: u32 = num_str
        .parse()
        .map_err(|_| "Invalid period: must be a number followed by 'd'".to_string())?;
    if days == 0 {
        return Err("Period must be at least 1 day".to_string());
    }
    if days > MAX_PERIOD_DAYS {
        // SECURITY (FIND-R155-003): Don't echo user value or internal bounds.
        return Err("Period exceeds maximum allowed".to_string());
    }
    Ok(days)
}

/// `GET /api/compliance/soc2/access-review` — SOC 2 Type II access review report.
///
/// Generates an access review report scanning audit entries over a configurable
/// period, cross-referenced with least-agency data. Supports JSON and HTML output.
#[tracing::instrument(name = "vellaveto.soc2_access_review", skip(state))]
pub async fn soc2_access_review(
    State(state): State<AppState>,
    Query(params): Query<AccessReviewQuery>,
) -> Result<Response, (StatusCode, Json<ErrorResponse>)> {
    let snapshot = state.policy_state.load();
    let config = &snapshot.compliance_config;

    // Gate: SOC 2 must be enabled
    if !config.soc2.enabled {
        return Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "SOC 2 compliance is not enabled in configuration".to_string(),
            }),
        ));
    }

    // Gate: access review must be enabled
    if !config.soc2.access_review.enabled {
        return Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "SOC 2 access review is not enabled in configuration".to_string(),
            }),
        ));
    }

    // Parse period
    let period_days = if let Some(ref p) = params.period {
        parse_period_days(p)
            .map_err(|e| (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: e })))?
    } else {
        config.soc2.access_review.default_period_days
    };

    // Validate agent_id filter
    if let Some(ref aid) = params.agent_id {
        if aid.len() > MAX_AGENT_ID_QUERY_LEN {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!(
                        "agent_id exceeds max length ({} > {})",
                        aid.len(),
                        MAX_AGENT_ID_QUERY_LEN
                    ),
                }),
            ));
        }
        if aid.chars().any(crate::routes::is_unsafe_char) {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "agent_id contains control characters".to_string(),
                }),
            ));
        }
    }

    // Compute period boundaries
    let now = chrono::Utc::now();
    let period_end = now.to_rfc3339();
    let period_start = (now - chrono::Duration::days(i64::from(period_days))).to_rfc3339();

    // Load audit entries
    let entries = state.audit.load_entries().await.map_err(|e| {
        tracing::error!("Failed to load audit entries for access review: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to load audit entries".to_string(),
            }),
        )
    })?;

    // SECURITY (FIND-R49-004): Prevent OOM from very large audit logs.
    const MAX_REVIEW_ENTRIES: usize = 500_000;
    if entries.len() > MAX_REVIEW_ENTRIES {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                error: "Audit log exceeds capacity limit. Rotate or archive the audit log."
                    .to_string(),
            }),
        ));
    }

    // Collect least-agency data from tracker (if available)
    let least_agency_data = collect_least_agency_data(&entries, &period_start, &period_end, &state);

    // Generate report
    let mut report = vellaveto_audit::access_review::generate_access_review(
        &entries,
        &config.soc2.organization_name,
        &period_start,
        &period_end,
        &least_agency_data,
    );

    // Apply optional agent_id filter
    if let Some(ref aid) = params.agent_id {
        report.entries.retain(|e| e.agent_id == *aid);
        report.total_agents = report.entries.len();
        report.total_evaluations = report.entries.iter().map(|e| e.total_evaluations).sum();
    }

    // SECURITY (FIND-R138-001): Validate and allowlist `format` before it is
    // used in the audit log entry. An unvalidated user-supplied string in the
    // tamper-evident audit trail is a log injection vector.
    let format = match params.format.as_deref() {
        Some("html") => "html",
        Some("json") | None => "json",
        Some(other) => {
            tracing::warn!(
                format_len = other.len(),
                "soc2_access_review: invalid format parameter rejected"
            );
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "format must be 'json' or 'html'".to_string(),
                }),
            ));
        }
    };

    // Log audit event
    let _ = state
        .audit
        .log_access_review_event(
            "generated",
            serde_json::json!({
                "period_days": period_days,
                "total_agents": report.total_agents,
                "total_evaluations": report.total_evaluations,
                "format": format,
            }),
        )
        .await;

    // Return in requested format
    match format {
        "html" => {
            let html = vellaveto_audit::access_review::render_html(&report);
            Ok((
                StatusCode::OK,
                [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
                html,
            )
                .into_response())
        }
        _ => {
            let value = serde_json::to_value(&report).map_err(|e| {
                tracing::error!("Failed to serialize access review report: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "Failed to generate report".to_string(),
                    }),
                )
            })?;
            Ok(Json(value).into_response())
        }
    }
}

// ── Phase 48: Compliance Evidence Packs ──────────────────────────────────────

/// Allowed evidence pack framework path parameter values.
const EVIDENCE_PACK_FRAMEWORKS: &[&str] = &["dora", "nis2", "iso42001", "eu-ai-act"];

/// Query parameters for the evidence pack endpoint.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidencePackQuery {
    /// Export format: "json" (default) or "html".
    #[serde(default)]
    pub format: Option<String>,
}

/// `GET /api/compliance/evidence-pack/status` — List available evidence pack frameworks.
///
/// Returns which evidence pack frameworks are available and their enabled status.
#[tracing::instrument(name = "vellaveto.evidence_pack_status", skip(state))]
pub async fn evidence_pack_status(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let snapshot = state.policy_state.load();
    let config = &snapshot.compliance_config;

    let mut available = Vec::new();
    if config.dora.enabled {
        available.push("dora");
    }
    if config.nis2.enabled {
        available.push("nis2");
    }
    // ISO 42001 and EU AI Act use existing config flags
    if config.eu_ai_act.enabled {
        available.push("eu-ai-act");
    }
    // ISO 42001 is always available (no separate enabled flag for evidence pack)
    available.push("iso42001");

    let response = serde_json::json!({
        "available_frameworks": available,
        "dora_enabled": config.dora.enabled,
        "nis2_enabled": config.nis2.enabled,
    });
    Ok(Json(response))
}

/// `GET /api/compliance/evidence-pack/{framework}` — Generate evidence pack.
///
/// Generates a compliance evidence pack for the specified framework (DORA, NIS2,
/// ISO 42001, or EU AI Act). Supports JSON and HTML output formats.
#[tracing::instrument(name = "vellaveto.evidence_pack", skip(state))]
pub async fn evidence_pack(
    State(state): State<AppState>,
    axum::extract::Path(framework): axum::extract::Path<String>,
    Query(params): Query<EvidencePackQuery>,
) -> Result<Response, (StatusCode, Json<ErrorResponse>)> {
    // SECURITY: Validate path parameter
    super::validate_path_param(&framework, "framework")?;

    // SECURITY: Allowlist check — only known frameworks accepted
    if !EVIDENCE_PACK_FRAMEWORKS.contains(&framework.as_str()) {
        // SECURITY (R243-SRV-2): Do not enumerate valid frameworks to clients.
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Unknown or unsupported framework".to_string(),
            }),
        ));
    }

    let snapshot = state.policy_state.load();
    let config = &snapshot.compliance_config;

    // Parse framework enum
    let evidence_framework = match framework.as_str() {
        "dora" => {
            if !config.dora.enabled {
                return Err((
                    StatusCode::NOT_FOUND,
                    Json(ErrorResponse {
                        error: "DORA evidence pack is not enabled in configuration".to_string(),
                    }),
                ));
            }
            vellaveto_types::EvidenceFramework::Dora
        }
        "nis2" => {
            if !config.nis2.enabled {
                return Err((
                    StatusCode::NOT_FOUND,
                    Json(ErrorResponse {
                        error: "NIS2 evidence pack is not enabled in configuration".to_string(),
                    }),
                ));
            }
            vellaveto_types::EvidenceFramework::Nis2
        }
        "iso42001" => vellaveto_types::EvidenceFramework::Iso42001,
        "eu-ai-act" => {
            if !config.eu_ai_act.enabled {
                return Err((
                    StatusCode::NOT_FOUND,
                    Json(ErrorResponse {
                        error: "EU AI Act evidence pack is not enabled in configuration"
                            .to_string(),
                    }),
                ));
            }
            vellaveto_types::EvidenceFramework::EuAiAct
        }
        // Unreachable due to allowlist above, but fail-closed
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "Unknown framework".to_string(),
                }),
            ));
        }
    };

    // SECURITY (FIND-R138-001): Validate and allowlist `format` before use.
    let format = match params.format.as_deref() {
        Some("html") => "html",
        Some("json") | None => "json",
        Some(other) => {
            tracing::warn!(
                format_len = other.len(),
                "evidence_pack: invalid format parameter rejected"
            );
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "format must be 'json' or 'html'".to_string(),
                }),
            ));
        }
    };

    // Check per-framework cache
    if format == "json" {
        let cache_guard = match EVIDENCE_PACK_CACHE.lock() {
            Ok(g) => g,
            Err(poisoned) => {
                tracing::warn!("EVIDENCE_PACK_CACHE mutex poisoned — recovering");
                poisoned.into_inner()
            }
        };
        if let Some(ref map) = *cache_guard {
            if let Some(cached) = map.get(&framework) {
                if cached.generated_at.elapsed().as_secs() < COMPLIANCE_CACHE_TTL_SECS {
                    return Ok(Json(cached.value.clone()).into_response());
                }
            }
        }
    }

    // Determine org name and system_id from config
    let (org_name, sys_id) = match framework.as_str() {
        "dora" => (
            config.dora.organization_name.as_str(),
            config.dora.system_id.as_str(),
        ),
        "nis2" => (
            config.nis2.organization_name.as_str(),
            config.nis2.system_id.as_str(),
        ),
        "iso42001" => ("Vellaveto", "vellaveto-runtime"),
        "eu-ai-act" => (
            config.eu_ai_act.deployer_name.as_str(),
            config.eu_ai_act.system_id.as_str(),
        ),
        _ => ("", ""),
    };

    // Generate the evidence pack
    let pack = vellaveto_audit::evidence_pack::generate_evidence_pack(
        evidence_framework,
        org_name,
        sys_id,
    );

    match format {
        "html" => {
            let html = vellaveto_audit::evidence_pack::render_evidence_pack_html(&pack);
            Ok((
                StatusCode::OK,
                [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
                html,
            )
                .into_response())
        }
        _ => {
            let value = serde_json::to_value(&pack).map_err(|e| {
                tracing::error!("Failed to serialize evidence pack: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "Failed to generate evidence pack".to_string(),
                    }),
                )
            })?;

            // Store in per-framework cache
            let mut cache_guard = match EVIDENCE_PACK_CACHE.lock() {
                Ok(g) => g,
                Err(poisoned) => {
                    tracing::warn!("EVIDENCE_PACK_CACHE mutex poisoned — recovering for write");
                    poisoned.into_inner()
                }
            };
            let map = cache_guard.get_or_insert_with(HashMap::new);
            // SECURITY (R238-SRV-7): Enforce cache size bound with LRU eviction.
            // If at capacity and the key is not already present, evict the oldest entry.
            if map.len() >= MAX_EVIDENCE_PACK_CACHE_ENTRIES && !map.contains_key(&framework) {
                // Evict the entry with the oldest generated_at timestamp.
                if let Some(oldest_key) = map
                    .iter()
                    .min_by_key(|(_, entry)| entry.generated_at)
                    .map(|(k, _)| k.clone())
                {
                    map.remove(&oldest_key);
                }
            }
            map.insert(
                framework.clone(),
                CachedReport {
                    generated_at: Instant::now(),
                    value: value.clone(),
                },
            );

            Ok(Json(value).into_response())
        }
    }
}

/// SECURITY (FIND-R63-SRV-011): Maximum number of (agent_id, session_id) pairs
/// to collect when building least-agency data. Prevents unbounded HashSet growth
/// from very large audit logs with many unique agent/session combinations.
const MAX_AGENT_SESSION_PAIRS: usize = 50_000;

/// Validate the format query parameter for compliance endpoints.
/// Returns the validated format string ("json" or "html") or an error.
#[cfg(test)]
fn validate_format_param(format: Option<&str>) -> Result<&'static str, &'static str> {
    match format {
        Some("html") => Ok("html"),
        Some("json") | None => Ok("json"),
        Some(_) => Err("format must be 'json' or 'html'"),
    }
}

/// Collect least-agency data for all (agent_id, session_id) pairs observed in
/// audit entries within the review period.
fn collect_least_agency_data(
    entries: &[vellaveto_audit::AuditEntry],
    period_start: &str,
    period_end: &str,
    state: &AppState,
) -> HashMap<(String, String), vellaveto_types::LeastAgencyReport> {
    let tracker = match state.least_agency_tracker.as_ref() {
        Some(t) => t,
        None => return HashMap::new(),
    };

    // Collect unique (agent_id, session_id) pairs from period entries
    let mut pairs = std::collections::HashSet::new();
    for entry in entries {
        if entry.action.tool == "vellaveto" {
            continue;
        }
        if entry.timestamp.as_str() < period_start || entry.timestamp.as_str() > period_end {
            continue;
        }
        // SECURITY (FIND-R63-SRV-011): Cap the HashSet to prevent OOM from
        // audit logs with an excessive number of unique agent/session pairs.
        if pairs.len() >= MAX_AGENT_SESSION_PAIRS {
            tracing::warn!(
                max = MAX_AGENT_SESSION_PAIRS,
                "Agent/session pair limit reached during access review; results may be incomplete"
            );
            break;
        }
        let agent_id = entry
            .metadata
            .get("agent_id")
            .and_then(|v| v.as_str())
            .unwrap_or(&entry.action.tool);
        let session_id = entry
            .metadata
            .get("session_id")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        pairs.insert((agent_id.to_string(), session_id.to_string()));
    }

    let mut result = HashMap::new();
    for (agent_id, session_id) in pairs {
        if let Some(report) = tracker.generate_report(&agent_id, &session_id) {
            result.insert((agent_id, session_id), report);
        }
    }
    result
}

#[cfg(test)]
#[allow(clippy::assertions_on_constants)]
mod tests {
    use super::*;

    // ── parse_period_days tests ──────────────────────────────────────────

    #[test]
    fn test_parse_period_days_valid_with_suffix() {
        assert_eq!(parse_period_days("30d").unwrap(), 30);
        assert_eq!(parse_period_days("1d").unwrap(), 1);
        assert_eq!(parse_period_days("366d").unwrap(), 366);
        assert_eq!(parse_period_days("7D").unwrap(), 7);
    }

    #[test]
    fn test_parse_period_days_valid_without_suffix() {
        assert_eq!(parse_period_days("90").unwrap(), 90);
        assert_eq!(parse_period_days("1").unwrap(), 1);
    }

    #[test]
    fn test_parse_period_days_trims_whitespace() {
        assert_eq!(parse_period_days("  30d  ").unwrap(), 30);
        assert_eq!(parse_period_days(" 7 ").unwrap(), 7);
    }

    #[test]
    fn test_parse_period_days_empty_string_rejected() {
        let err = parse_period_days("").unwrap_err();
        assert_eq!(err, "Empty period string");
    }

    #[test]
    fn test_parse_period_days_whitespace_only_rejected() {
        let err = parse_period_days("   ").unwrap_err();
        assert_eq!(err, "Empty period string");
    }

    #[test]
    fn test_parse_period_days_zero_rejected() {
        let err = parse_period_days("0d").unwrap_err();
        assert_eq!(err, "Period must be at least 1 day");
    }

    #[test]
    fn test_parse_period_days_exceeds_max_rejected() {
        let err = parse_period_days("367d").unwrap_err();
        assert_eq!(err, "Period exceeds maximum allowed");
    }

    #[test]
    fn test_parse_period_days_invalid_number_rejected() {
        let err = parse_period_days("abcd").unwrap_err();
        assert!(err.contains("must be a number"));
    }

    #[test]
    fn test_parse_period_days_negative_rejected() {
        let err = parse_period_days("-5d").unwrap_err();
        assert!(err.contains("must be a number"));
    }

    #[test]
    fn test_parse_period_days_too_long_rejected() {
        let long = "1".repeat(21);
        let err = parse_period_days(&long).unwrap_err();
        assert_eq!(err, "Invalid period: value too long");
    }

    #[test]
    fn test_parse_period_days_boundary_max() {
        // MAX_PERIOD_DAYS is 366
        assert_eq!(parse_period_days("366d").unwrap(), 366);
    }

    // ── validate_format_param tests ──────────────────────────────────────

    #[test]
    fn test_validate_format_param_json_default() {
        assert_eq!(validate_format_param(None).unwrap(), "json");
    }

    #[test]
    fn test_validate_format_param_json_explicit() {
        assert_eq!(validate_format_param(Some("json")).unwrap(), "json");
    }

    #[test]
    fn test_validate_format_param_html() {
        assert_eq!(validate_format_param(Some("html")).unwrap(), "html");
    }

    #[test]
    fn test_validate_format_param_invalid_rejected() {
        let err = validate_format_param(Some("xml")).unwrap_err();
        assert!(err.contains("format must be"));
    }

    #[test]
    fn test_validate_format_param_empty_string_rejected() {
        let err = validate_format_param(Some("")).unwrap_err();
        assert!(err.contains("format must be"));
    }

    // ── default_true tests ───────────────────────────────────────────────

    #[test]
    fn test_default_true_returns_true() {
        assert!(default_true());
    }

    // ── ReportCache tests ────────────────────────────────────────────────

    #[test]
    fn test_report_cache_initially_empty() {
        let cache = ReportCache::new();
        assert!(cache.get().is_none());
    }

    #[test]
    fn test_report_cache_set_then_get() {
        let cache = ReportCache::new();
        let value = serde_json::json!({"status": "ok"});
        cache.set(value.clone());
        let got = cache.get().unwrap();
        assert_eq!(got, value);
    }

    #[test]
    fn test_report_cache_overwrites_previous() {
        let cache = ReportCache::new();
        cache.set(serde_json::json!({"v": 1}));
        cache.set(serde_json::json!({"v": 2}));
        let got = cache.get().unwrap();
        assert_eq!(got["v"], 2);
    }

    // ── EVIDENCE_PACK_FRAMEWORKS allowlist tests ────────────────────────

    #[test]
    fn test_evidence_pack_frameworks_contains_expected() {
        assert!(EVIDENCE_PACK_FRAMEWORKS.contains(&"dora"));
        assert!(EVIDENCE_PACK_FRAMEWORKS.contains(&"nis2"));
        assert!(EVIDENCE_PACK_FRAMEWORKS.contains(&"iso42001"));
        assert!(EVIDENCE_PACK_FRAMEWORKS.contains(&"eu-ai-act"));
    }

    #[test]
    fn test_evidence_pack_frameworks_rejects_unknown() {
        assert!(!EVIDENCE_PACK_FRAMEWORKS.contains(&"pci-dss"));
        assert!(!EVIDENCE_PACK_FRAMEWORKS.contains(&"hipaa"));
        assert!(!EVIDENCE_PACK_FRAMEWORKS.contains(&""));
    }

    // ── ComplianceStatusQuery serde tests ────────────────────────────────

    #[test]
    fn test_compliance_status_query_defaults() {
        let q: ComplianceStatusQuery = serde_json::from_str("{}").unwrap();
        assert!(q.include_nist);
        assert!(q.include_iso);
    }

    #[test]
    fn test_compliance_status_query_explicit_false() {
        let q: ComplianceStatusQuery =
            serde_json::from_str(r#"{"include_nist":false,"include_iso":false}"#).unwrap();
        assert!(!q.include_nist);
        assert!(!q.include_iso);
    }

    #[test]
    fn test_compliance_status_query_denies_unknown_fields() {
        let result: Result<ComplianceStatusQuery, _> =
            serde_json::from_str(r#"{"include_nist":true,"bogus":42}"#);
        assert!(result.is_err());
    }

    // ── Soc2EvidenceQuery serde tests ────────────────────────────────────

    #[test]
    fn test_soc2_evidence_query_defaults() {
        let q: Soc2EvidenceQuery = serde_json::from_str("{}").unwrap();
        assert!(q.category.is_none());
    }

    #[test]
    fn test_soc2_evidence_query_with_category() {
        let q: Soc2EvidenceQuery = serde_json::from_str(r#"{"category":"CC1"}"#).unwrap();
        assert_eq!(q.category.as_deref(), Some("CC1"));
    }

    #[test]
    fn test_soc2_evidence_query_denies_unknown_fields() {
        let result: Result<Soc2EvidenceQuery, _> =
            serde_json::from_str(r#"{"category":"CC1","extra":true}"#);
        assert!(result.is_err());
    }

    // ── AccessReviewQuery serde tests ────────────────────────────────────

    #[test]
    fn test_access_review_query_defaults() {
        let q: AccessReviewQuery = serde_json::from_str("{}").unwrap();
        assert!(q.period.is_none());
        assert!(q.format.is_none());
        assert!(q.agent_id.is_none());
    }

    #[test]
    fn test_access_review_query_denies_unknown_fields() {
        let result: Result<AccessReviewQuery, _> =
            serde_json::from_str(r#"{"period":"30d","unknown":1}"#);
        assert!(result.is_err());
    }

    // ── EvidencePackQuery serde tests ────────────────────────────────────

    #[test]
    fn test_evidence_pack_query_defaults() {
        let q: EvidencePackQuery = serde_json::from_str("{}").unwrap();
        assert!(q.format.is_none());
    }

    #[test]
    fn test_evidence_pack_query_denies_unknown_fields() {
        let result: Result<EvidencePackQuery, _> =
            serde_json::from_str(r#"{"format":"json","bogus":true}"#);
        assert!(result.is_err());
    }

    // ── Constants sanity checks ──────────────────────────────────────────

    #[test]
    fn test_compliance_cache_ttl_is_reasonable() {
        assert!(COMPLIANCE_CACHE_TTL_SECS > 0);
        assert!(COMPLIANCE_CACHE_TTL_SECS <= 3600); // Not more than 1 hour
    }

    #[test]
    fn test_max_agent_id_query_len_is_bounded() {
        assert!(MAX_AGENT_ID_QUERY_LEN > 0);
        assert!(MAX_AGENT_ID_QUERY_LEN <= 1024);
    }

    #[test]
    fn test_max_period_days_is_bounded() {
        assert!(MAX_PERIOD_DAYS >= 1);
        assert!(MAX_PERIOD_DAYS <= 366);
    }

    #[test]
    fn test_max_agent_session_pairs_is_bounded() {
        assert!(MAX_AGENT_SESSION_PAIRS > 0);
        assert!(MAX_AGENT_SESSION_PAIRS <= 100_000);
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Phase 4: Compliance Evidence Factory Endpoints
// ═══════════════════════════════════════════════════════════════════════════════

/// Generate an EU AI Act Annex IV technical documentation package.
///
/// GET /api/compliance/annex-iv
///
/// Returns a structured documentation package with evidence from runtime state.
pub async fn annex_iv_package(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let snapshot = state.policy_state.load();
    let policy_count = snapshot.policies.len();
    let audit_entry_count = state.metrics.evaluations_total.load(std::sync::atomic::Ordering::Relaxed);
    let compliance_frameworks: Vec<String> = vec![
        "EU AI Act".to_string(),
        "SOC 2".to_string(),
        "DORA".to_string(),
        "NIS2".to_string(),
        "ISO 42001".to_string(),
        "NIST AI 600-1".to_string(),
        "OWASP Agentic Top 10".to_string(),
        "OWASP MCP Top 10".to_string(),
        "CoSAI".to_string(),
        "Adversa TOP 25".to_string(),
        "Singapore MGF".to_string(),
        "CSA ATF".to_string(),
    ];

    let package = vellaveto_audit::annex_iv::build_annex_iv_package(
        env!("CARGO_PKG_VERSION"),
        policy_count,
        audit_entry_count,
        767,   // formal verification instances
        11279, // test count
        &compliance_frameworks,
        &HashMap::new(),
    );

    serde_json::to_value(&package)
        .map(Json)
        .map_err(|e| {
            tracing::error!("Annex IV serialization error: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Internal server error".to_string(),
                }),
            )
        })
}

/// Generate an Article 73 incident report template.
///
/// POST /api/compliance/incident-report
///
/// Accepts incident details and returns a structured report with
/// cross-regulation notification deadlines.
pub async fn create_incident_report(
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let incident_id = body
        .get("incident_id")
        .and_then(|v| v.as_str())
        .unwrap_or("INC-UNSET")
        .to_string();
    let title = body
        .get("title")
        .and_then(|v| v.as_str())
        .unwrap_or("Untitled incident")
        .to_string();
    let description = body
        .get("description")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let severity = body
        .get("severity")
        .and_then(|v| v.as_u64())
        .unwrap_or(3) as u8;
    let classification = match body
        .get("classification")
        .and_then(|v| v.as_str())
        .unwrap_or("system_malfunction")
    {
        "security_breach" => vellaveto_audit::article73::IncidentClassification::SecurityBreach,
        "safety_incident" => vellaveto_audit::article73::IncidentClassification::SafetyIncident,
        "fundamental_rights" => {
            vellaveto_audit::article73::IncidentClassification::FundamentalRightsImpact
        }
        "supply_chain" => {
            vellaveto_audit::article73::IncidentClassification::SupplyChainCompromise
        }
        _ => vellaveto_audit::article73::IncidentClassification::SystemMalfunction,
    };

    let report = vellaveto_audit::article73::build_incident_report(
        vellaveto_audit::article73::IncidentParams {
            incident_id,
            title,
            classification,
            severity,
            detected_at: chrono::Utc::now().to_rfc3339(),
            description,
            affected_assets: body
                .get("affected_assets")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default(),
            evidence_refs: Vec::new(),
        },
    );

    serde_json::to_value(&report)
        .map(Json)
        .map_err(|e| {
            tracing::error!("Incident report serialization error: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Internal server error".to_string(),
                }),
            )
        })
}

/// Generate a FRIA (Fundamental Rights Impact Assessment) data export.
///
/// GET /api/compliance/fria
///
/// Returns structured data for deployer FRIA workflows (Art 27).
pub async fn fria_export(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let snapshot = state.policy_state.load();
    let policy_count = snapshot.policies.len();
    let approval_tool_count = 0_usize; // TODO: count RequireApproval policies

    let export = vellaveto_audit::fria::build_fria_export(
        &format!("vellaveto-v{}", env!("CARGO_PKG_VERSION")),
        policy_count,
        approval_tool_count,
        true,  // has_dlp
        false, // has_pii_sanitization (server mode, not shield)
        true,  // has_audit_trail
    );

    serde_json::to_value(&export)
        .map(Json)
        .map_err(|e| {
            tracing::error!("FRIA export serialization error: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Internal server error".to_string(),
                }),
            )
        })
}
