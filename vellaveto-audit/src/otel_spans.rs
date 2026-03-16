// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Phase 2: OpenTelemetry-compatible span generation from audit entries.
//!
//! Converts VellaVeto audit entries into structured span-like records that
//! can be exported to OTel-compatible backends (Jaeger, Grafana Tempo, etc.)
//! via the OTLP exporter. This bridges the existing audit trail with the
//! observability ecosystem without requiring the full OpenTelemetry SDK.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use vellaveto_types::{Action, Verdict};

/// A lightweight OTel-compatible span record derived from an audit entry.
///
/// Not a full OTel SDK span — this is a structured record that can be
/// serialized to OTLP JSON format by the exporter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditSpan {
    /// Trace ID (hex, 32 chars). Derived from session scope binding.
    pub trace_id: String,
    /// Span ID (hex, 16 chars). Derived from audit entry ID.
    pub span_id: String,
    /// Parent span ID if this is a nested evaluation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_span_id: Option<String>,
    /// Span name (e.g., "vellaveto.evaluate", "vellaveto.inject_scan").
    pub name: String,
    /// Start time as Unix nanoseconds.
    pub start_time_unix_nano: u64,
    /// End time as Unix nanoseconds.
    pub end_time_unix_nano: u64,
    /// Span kind: SERVER for incoming evaluations, INTERNAL for sub-checks.
    pub kind: SpanKind,
    /// Status: OK for Allow, ERROR for Deny.
    pub status: SpanStatus,
    /// Structured attributes.
    pub attributes: HashMap<String, SpanAttributeValue>,
}

/// OTel span kind.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SpanKind {
    Server,
    Internal,
}

/// OTel span status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpanStatus {
    pub code: SpanStatusCode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// OTel status codes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SpanStatusCode {
    Unset,
    Ok,
    Error,
}

/// Typed attribute value (OTel AnyValue equivalent).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum SpanAttributeValue {
    String(String),
    Int(i64),
    Bool(bool),
}

/// Build an audit span from an action and verdict.
///
/// This is the primary entry point for converting audit entries to spans.
/// The caller provides timing and context; this function maps VellaVeto
/// concepts to OTel attributes.
/// Context for building an evaluation span.
pub struct SpanContext<'a> {
    pub trace_id: &'a str,
    pub span_id: &'a str,
    pub start_ns: u64,
    pub end_ns: u64,
    pub session_id: Option<&'a str>,
    pub agent_id: Option<&'a str>,
    pub transport: Option<&'a str>,
}

pub fn build_evaluation_span(
    action: &Action,
    verdict: &Verdict,
    ctx: &SpanContext<'_>,
) -> AuditSpan {
    let SpanContext {
        trace_id,
        span_id,
        start_ns,
        end_ns,
        session_id,
        agent_id,
        transport,
    } = ctx;
    let mut attrs = HashMap::new();

    // Vellaveto-specific attributes
    attrs.insert(
        "vellaveto.tool".to_string(),
        SpanAttributeValue::String(action.tool.clone()),
    );
    attrs.insert(
        "vellaveto.function".to_string(),
        SpanAttributeValue::String(action.function.clone()),
    );
    attrs.insert(
        "vellaveto.verdict".to_string(),
        SpanAttributeValue::String(match verdict {
            Verdict::Allow => "allow".to_string(),
            Verdict::Deny { .. } => "deny".to_string(),
            Verdict::RequireApproval { .. } => "require_approval".to_string(),
            _ => "unknown".to_string(),
        }),
    );

    if let Verdict::Deny { reason } = verdict {
        attrs.insert(
            "vellaveto.deny_reason".to_string(),
            SpanAttributeValue::String(reason[..reason.len().min(256)].to_string()),
        );
    }

    if !action.target_paths.is_empty() {
        attrs.insert(
            "vellaveto.target_path_count".to_string(),
            SpanAttributeValue::Int(action.target_paths.len() as i64),
        );
    }
    if !action.target_domains.is_empty() {
        attrs.insert(
            "vellaveto.target_domain_count".to_string(),
            SpanAttributeValue::Int(action.target_domains.len() as i64),
        );
    }

    if let Some(sid) = session_id {
        attrs.insert(
            "vellaveto.session_id".to_string(),
            SpanAttributeValue::String(sid[..sid.len().min(64)].to_string()),
        );
    }
    if let Some(aid) = agent_id {
        attrs.insert(
            "vellaveto.agent_id".to_string(),
            SpanAttributeValue::String(aid[..aid.len().min(64)].to_string()),
        );
    }
    if let Some(t) = transport {
        attrs.insert(
            "vellaveto.transport".to_string(),
            SpanAttributeValue::String(t.to_string()),
        );
    }

    let status = match verdict {
        Verdict::Allow => SpanStatus {
            code: SpanStatusCode::Ok,
            message: None,
        },
        Verdict::Deny { .. } => SpanStatus {
            code: SpanStatusCode::Error,
            message: Some("denied by policy".to_string()),
        },
        Verdict::RequireApproval { .. } => SpanStatus {
            code: SpanStatusCode::Unset,
            message: Some("approval required".to_string()),
        },
        _ => SpanStatus {
            code: SpanStatusCode::Unset,
            message: Some("unknown verdict".to_string()),
        },
    };

    AuditSpan {
        trace_id: trace_id.to_string(),
        span_id: span_id.to_string(),
        parent_span_id: None,
        name: format!("vellaveto.evaluate.{}", action.tool),
        start_time_unix_nano: *start_ns,
        end_time_unix_nano: *end_ns,
        kind: SpanKind::Server,
        status,
        attributes: attrs,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_action() -> Action {
        Action::new("read_file", "*", serde_json::json!({"path": "/tmp/test"}))
    }

    #[test]
    fn test_build_evaluation_span_allow() {
        let span = build_evaluation_span(
            &test_action(),
            &Verdict::Allow,
            &SpanContext {
                trace_id: "0123456789abcdef0123456789abcdef",
                span_id: "0123456789abcdef",
                start_ns: 1000000,
                end_ns: 2000000,
                session_id: Some("session-1"),
                agent_id: Some("agent-1"),
                transport: Some("stdio"),
            },
        );
        assert_eq!(span.name, "vellaveto.evaluate.read_file");
        assert!(matches!(span.status.code, SpanStatusCode::Ok));
        assert_eq!(
            span.attributes.get("vellaveto.verdict"),
            Some(&SpanAttributeValue::String("allow".to_string()))
        );
        assert_eq!(
            span.attributes.get("vellaveto.transport"),
            Some(&SpanAttributeValue::String("stdio".to_string()))
        );
    }

    #[test]
    fn test_build_evaluation_span_deny() {
        let span = build_evaluation_span(
            &test_action(),
            &Verdict::Deny {
                reason: "blocked by policy".to_string(),
            },
            &SpanContext {
                trace_id: "abcdef",
                span_id: "123456",
                start_ns: 0,
                end_ns: 100,
                session_id: None,
                agent_id: None,
                transport: None,
            },
        );
        assert!(matches!(span.status.code, SpanStatusCode::Error));
        assert!(span.attributes.contains_key("vellaveto.deny_reason"));
    }

    #[test]
    fn test_build_evaluation_span_require_approval() {
        let span = build_evaluation_span(
            &test_action(),
            &Verdict::RequireApproval {
                reason: "needs human review".to_string(),
            },
            &SpanContext {
                trace_id: "trace",
                span_id: "span",
                start_ns: 0,
                end_ns: 0,
                session_id: None,
                agent_id: None,
                transport: None,
            },
        );
        assert!(matches!(span.status.code, SpanStatusCode::Unset));
        assert_eq!(
            span.attributes.get("vellaveto.verdict"),
            Some(&SpanAttributeValue::String("require_approval".to_string()))
        );
    }
}
