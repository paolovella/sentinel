// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Route handlers for the Vellaveto HTTP API.
//!
//! This module provides all HTTP route handlers for the Vellaveto server API.
//! The main router is built by `build_router()`.
//!
//! Submodules:
//! - `approval` - Human-in-the-loop approval workflow handlers
//! - `audit` - Audit log and checkpoint handlers
//! - `auth_level` - Step-up authentication level handlers
//! - `billing` - Billing webhook handlers
//! - `circuit_breaker` - Circuit breaker handlers (OWASP ASI08)
//! - `compliance` - Compliance framework handlers (EU AI Act, SOC 2, etc.)
//! - `deployment` - Deployment info and leader status handlers (Phase 27)
//! - `deputy` - Deputy validation handlers (OWASP ASI02)
//! - `discovery` - Tool discovery API handlers (Phase 34)
//! - `etdi` - ETDI cryptographic tool security handlers
//! - `exec_graph` - Execution graph export handlers (Phase 6)
//! - `federation` - Agent identity federation handlers (Phase 39)
//! - `governance` - Shadow AI governance handlers (Phase 26)
//! - `main` - Core evaluate/health/status handlers
//! - `memory` - Memory Injection Defense (MINJA) handlers
//! - `nhi` - Non-Human Identity (NHI) lifecycle handlers
//! - `observability` - AI observability platform handlers (Phase 15)
//! - `policy` - Policy CRUD and hot-reload handlers
//! - `policy_lifecycle` - Policy versioning, approval, staging, and rollback handlers (Phase 47)
//! - `projector` - Model projector API handlers (Phase 35)
//! - `registry` - Tool registry management handlers
//! - `sampling` - Sampling detection handlers
//! - `schema_lineage` - Schema lineage tracking handlers (OWASP ASI05)
//! - `shadow_agent` - Shadow agent detection handlers
//! - `signup` - Self-service tenant signup (Phase 53)
//! - `simulator` - Policy simulator API handlers (Phase 22)
//! - `task_state` - MCP async task state handlers
//! - `tenant` - Tenant management handlers (Phase 3)
//! - `zk_audit` - Zero-knowledge audit trail handlers (Phase 37)

pub mod approval;
pub mod audit;
pub mod audit_store;
pub mod auth_level;
pub mod billing;
pub mod circuit_breaker;
pub mod compliance;
pub mod deployment;
pub mod deputy;
pub mod discovery;
pub mod etdi;
pub mod exec_graph;
pub mod federation;
pub mod governance;
pub mod inventory;
#[cfg(test)]
mod kani_webhook_dedup_differential;
mod main;
pub mod memory;
pub mod nhi;
pub mod observability;
pub mod policy;
pub mod policy_lifecycle;
pub mod projector;
pub mod registry;
pub mod sampling;
pub mod schema_lineage;
pub mod shadow_agent;
pub mod signup;
pub mod simulator;
pub mod task_state;
pub mod tenant;
pub mod topology;
pub mod zk_audit;

pub use main::*;

/// Maximum length for path parameters (IDs, tool names, session IDs).
const MAX_PATH_PARAM_LEN: usize = 256;

/// SECURITY (FIND-R51-005, IMP-R126-003): Detect control characters AND Unicode
/// format characters. Delegates to canonical `is_unicode_format_char()` from
/// vellaveto-types, fixing the U+2065 gap that existed in the previous inline
/// range implementation.
pub(crate) fn is_unsafe_char(c: char) -> bool {
    c.is_control() || vellaveto_types::is_unicode_format_char(c)
}

/// Core path parameter validation: rejects values that are too long or
/// contain control/format characters.  Returns `Ok(())` on success or
/// `Err(error_message)` on failure.
///
/// SECURITY (FIND-R51-005): All path parameters from external input must
/// pass through this check before use.
fn validate_path_param_core(value: &str, field_name: &str) -> Result<(), String> {
    if value.len() > MAX_PATH_PARAM_LEN {
        return Err(format!("{field_name} exceeds maximum length"));
    }
    if value.chars().any(is_unsafe_char) {
        return Err(format!("{field_name} contains invalid characters"));
    }
    Ok(())
}

/// SECURITY (FIND-R51-005): Validate a path parameter — reject if too long
/// or contains control/format characters. Returns a `BAD_REQUEST` error
/// compatible with `(StatusCode, Json<ErrorResponse>)`.
pub fn validate_path_param(
    value: &str,
    field_name: &str,
) -> Result<(), (axum::http::StatusCode, axum::Json<ErrorResponse>)> {
    validate_path_param_core(value, field_name).map_err(|msg| {
        (
            axum::http::StatusCode::BAD_REQUEST,
            axum::Json(ErrorResponse { error: msg }),
        )
    })
}

/// SECURITY (FIND-R51-005): Validate a path parameter — same logic but
/// returns `(StatusCode, Json<serde_json::Value>)` for handlers that use
/// that error type instead of `ErrorResponse`.
pub fn validate_path_param_json(
    value: &str,
    field_name: &str,
) -> Result<(), (axum::http::StatusCode, axum::Json<serde_json::Value>)> {
    validate_path_param_core(value, field_name).map_err(|msg| {
        (
            axum::http::StatusCode::BAD_REQUEST,
            axum::Json(serde_json::json!({ "error": msg })),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── is_unsafe_char tests ──────────────────────────────────────────

    #[test]
    fn test_is_unsafe_char_ascii_control_chars_detected() {
        // NUL, BEL, ESC, DEL
        assert!(is_unsafe_char('\x00'));
        assert!(is_unsafe_char('\x07'));
        assert!(is_unsafe_char('\x1B'));
        assert!(is_unsafe_char('\x7F'));
    }

    #[test]
    fn test_is_unsafe_char_newline_and_tab_detected() {
        assert!(is_unsafe_char('\n'));
        assert!(is_unsafe_char('\r'));
        assert!(is_unsafe_char('\t'));
    }

    #[test]
    fn test_is_unsafe_char_unicode_format_chars_detected() {
        // Zero-width space (U+200B)
        assert!(is_unsafe_char('\u{200B}'));
        // Zero-width non-joiner (U+200C)
        assert!(is_unsafe_char('\u{200C}'));
        // Zero-width joiner (U+200D)
        assert!(is_unsafe_char('\u{200D}'));
        // Bidi override (U+202E)
        assert!(is_unsafe_char('\u{202E}'));
        // Bidi isolate (U+2066)
        assert!(is_unsafe_char('\u{2066}'));
    }

    #[test]
    fn test_is_unsafe_char_normal_ascii_not_detected() {
        assert!(!is_unsafe_char('a'));
        assert!(!is_unsafe_char('Z'));
        assert!(!is_unsafe_char('0'));
        assert!(!is_unsafe_char('-'));
        assert!(!is_unsafe_char('_'));
        assert!(!is_unsafe_char(' '));
        assert!(!is_unsafe_char('/'));
    }

    #[test]
    fn test_is_unsafe_char_unicode_text_not_detected() {
        assert!(!is_unsafe_char('ñ'));
        assert!(!is_unsafe_char('ü'));
        assert!(!is_unsafe_char('日'));
        assert!(!is_unsafe_char('🔒'));
    }

    // ── validate_path_param_core tests ────────────────────────────────

    #[test]
    fn test_validate_path_param_core_valid_input() {
        assert!(validate_path_param_core("my-tool-123", "tool").is_ok());
        assert!(validate_path_param_core("abc_DEF_456", "id").is_ok());
        assert!(validate_path_param_core("a", "field").is_ok());
    }

    #[test]
    fn test_validate_path_param_core_empty_string_ok() {
        // Empty string is valid (no length limit minimum, no unsafe chars)
        assert!(validate_path_param_core("", "field").is_ok());
    }

    #[test]
    fn test_validate_path_param_core_max_length_ok() {
        let value = "a".repeat(MAX_PATH_PARAM_LEN);
        assert!(validate_path_param_core(&value, "field").is_ok());
    }

    #[test]
    fn test_validate_path_param_core_exceeds_max_length() {
        let value = "a".repeat(MAX_PATH_PARAM_LEN + 1);
        let err = validate_path_param_core(&value, "tool_name").unwrap_err();
        assert!(err.contains("exceeds maximum length"));
        assert!(err.contains("tool_name"));
    }

    #[test]
    fn test_validate_path_param_core_control_char_rejected() {
        let err = validate_path_param_core("tool\x00name", "tool").unwrap_err();
        assert!(err.contains("invalid characters"));
    }

    #[test]
    fn test_validate_path_param_core_newline_rejected() {
        let err = validate_path_param_core("line1\nline2", "field").unwrap_err();
        assert!(err.contains("invalid characters"));
    }

    #[test]
    fn test_validate_path_param_core_unicode_format_char_rejected() {
        // Zero-width space
        let err = validate_path_param_core("tool\u{200B}name", "tool").unwrap_err();
        assert!(err.contains("invalid characters"));
    }

    #[test]
    fn test_validate_path_param_core_bidi_override_rejected() {
        let err = validate_path_param_core("tool\u{202E}name", "field").unwrap_err();
        assert!(err.contains("invalid characters"));
    }

    // ── validate_path_param tests ─────────────────────────────────────

    #[test]
    fn test_validate_path_param_valid_returns_ok() {
        assert!(validate_path_param("valid-id", "id").is_ok());
    }

    #[test]
    fn test_validate_path_param_invalid_returns_bad_request() {
        let err = validate_path_param("id\x00bad", "id").unwrap_err();
        assert_eq!(err.0, axum::http::StatusCode::BAD_REQUEST);
        assert!(err.1 .0.error.contains("invalid characters"));
    }

    // ── validate_path_param_json tests ────────────────────────────────

    #[test]
    fn test_validate_path_param_json_valid_returns_ok() {
        assert!(validate_path_param_json("valid-tool", "tool").is_ok());
    }

    #[test]
    fn test_validate_path_param_json_too_long_returns_bad_request() {
        let long_val = "x".repeat(MAX_PATH_PARAM_LEN + 1);
        let err = validate_path_param_json(&long_val, "tool").unwrap_err();
        assert_eq!(err.0, axum::http::StatusCode::BAD_REQUEST);
    }
}
