// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.

//! Guardrails for server-initiated JSON-RPC requests.

use serde_json::{json, Value};
use vellaveto_mcp::extractor::normalize_method;
use vellaveto_mcp::mediation::build_secondary_acis_envelope_with_security_context;
use vellaveto_types::acis::DecisionOrigin;
use vellaveto_types::{Action, Verdict};

use super::helpers::protocol_rejection_security_context;
use super::ProxyState;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ServerRequestInfo {
    pub method: String,
    pub id: Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum SseServerRequestScanError {
    OversizedEvent,
}

/// Return metadata for a JSON-RPC request object (`method` + `id`).
///
/// Notifications intentionally do not match: SEP-2260's active-processing rule
/// governs server requests, and JSON-RPC requests are the messages that require
/// responses.
pub(super) fn json_rpc_request_info(message: &Value) -> Option<ServerRequestInfo> {
    if !message.is_object() || message.get("result").is_some() || message.get("error").is_some() {
        return None;
    }

    let method = message.get("method").and_then(Value::as_str)?;
    let id = message.get("id")?.clone();
    Some(ServerRequestInfo {
        method: normalize_method(method),
        id,
    })
}

/// True for a JSON-RPC response or error response.
pub(super) fn is_json_rpc_response(message: &Value) -> bool {
    message.is_object()
        && message.get("id").is_some()
        && (message.get("result").is_some() || message.get("error").is_some())
}

/// Scan SSE data payloads for JSON-RPC server requests.
pub(super) fn find_server_request_in_sse(
    sse_bytes: &[u8],
    max_event_bytes: usize,
) -> Result<Option<ServerRequestInfo>, SseServerRequestScanError> {
    let sse_text = String::from_utf8_lossy(sse_bytes);
    let normalized = sse_text.replace("\r\n", "\n").replace('\r', "\n");

    for event in normalized.split("\n\n") {
        let mut data_parts = Vec::new();
        for line in event.lines() {
            let trimmed = line.trim_start_matches(|c: char| c.is_whitespace());
            if let Some(rest) = trimmed.strip_prefix("data:") {
                data_parts.push(rest.trim_start());
            }
        }
        if data_parts.is_empty() {
            continue;
        }

        let data_payload = data_parts.join("\n");
        if data_payload.trim().is_empty() {
            continue;
        }
        if data_payload.len() > max_event_bytes {
            return Err(SseServerRequestScanError::OversizedEvent);
        }

        let Ok(json_val) = serde_json::from_str::<Value>(&data_payload) else {
            continue;
        };
        if let Some(info) = json_rpc_request_info(&json_val) {
            return Ok(Some(info));
        }
    }

    Ok(None)
}

pub(super) async fn audit_unsolicited_server_request(
    state: &ProxyState,
    session_id: &str,
    transport: &'static str,
    method: &str,
    source: &'static str,
) {
    let action = Action::new(
        "vellaveto",
        "unsolicited_server_request",
        json!({
            "method": method,
            "session": session_id,
            "transport": transport,
        }),
    );
    let verdict = Verdict::Deny {
        reason: "Unsolicited server request".to_string(),
    };
    let security_context = protocol_rejection_security_context("unsolicited_server_request");
    let envelope = build_secondary_acis_envelope_with_security_context(
        &action,
        &verdict,
        DecisionOrigin::PolicyEngine,
        transport,
        Some(session_id),
        Some(&security_context),
    );

    if let Err(error) = state
        .audit
        .log_entry_with_acis(
            &action,
            &verdict,
            json!({
                "source": source,
                "event": "unsolicited_server_request_blocked",
                "method": method,
                "transport": transport,
            }),
            envelope,
        )
        .await
    {
        tracing::warn!(
            session_id = %session_id,
            "Failed to audit unsolicited server request block: {}",
            error
        );
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn detects_json_rpc_request_but_not_notification_or_response() {
        let request = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "elicitation/create",
            "params": {}
        });
        let info = json_rpc_request_info(&request).expect("request info");
        assert_eq!(info.method, "elicitation/create");
        assert_eq!(info.id, json!(1));

        let notification = json!({
            "jsonrpc": "2.0",
            "method": "notifications/progress",
            "params": {}
        });
        assert!(json_rpc_request_info(&notification).is_none());

        let response = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {}
        });
        assert!(json_rpc_request_info(&response).is_none());
        assert!(is_json_rpc_response(&response));
    }

    #[test]
    fn detects_server_request_in_sse_data_payload() {
        let sse = b"event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":\"srv-1\",\"method\":\"sampling/createMessage\",\"params\":{}}\n\n";
        let info = find_server_request_in_sse(sse, 4096)
            .expect("scan")
            .expect("server request");
        assert_eq!(info.method, "sampling/createmessage");
        assert_eq!(info.id, json!("srv-1"));
    }

    #[test]
    fn rejects_oversized_sse_payloads_fail_closed() {
        let sse = b"data: {\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"elicitation/create\"}\n\n";
        assert_eq!(
            find_server_request_in_sse(sse, 8),
            Err(SseServerRequestScanError::OversizedEvent)
        );
    }
}
