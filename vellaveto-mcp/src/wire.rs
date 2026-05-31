// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Version-gated MCP wire normalization.
//!
//! This module is the adapter boundary between version-specific MCP JSON-RPC
//! shapes and Vellaveto's internal policy/audit model.

use serde_json::Value;
use vellaveto_types::{has_dangerous_chars, McpProtocolVersion};

use crate::extractor::{classify_message, normalize_method, MessageType};

const META_CLIENT_INFO: &str = "io.modelcontextprotocol/clientInfo";
const META_CAPABILITIES: &str = "io.modelcontextprotocol/capabilities";
const META_PROTOCOL_VERSION: &str = "io.modelcontextprotocol/protocolVersion";
const META_TRACEPARENT: &str = "traceparent";
const META_TRACESTATE: &str = "tracestate";
const META_BAGGAGE: &str = "baggage";

const MAX_META_BYTES: usize = 16 * 1024;
const MAX_TRACESTATE_BYTES: usize = 512;
const MAX_BAGGAGE_BYTES: usize = 8 * 1024;

/// Internal canonical representation of an inbound MCP JSON-RPC message.
#[derive(Debug, Clone, PartialEq)]
pub struct CanonicalRequest {
    pub protocol_version: McpProtocolVersion,
    pub kind: CanonicalMessageKind,
    pub id: Option<Value>,
    pub method: String,
    pub name: Option<String>,
    pub principal: Option<String>,
    pub correlation_id: Option<String>,
    pub args: Value,
    pub meta: TypedMeta,
    pub handles: Vec<CanonicalHandle>,
}

/// Coarse JSON-RPC message kind after normalization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanonicalMessageKind {
    Request,
    Notification,
    Response,
}

/// Server-minted capability handle observed in normalized arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalHandle {
    pub field: String,
    pub value: String,
}

/// Parsed `_meta` fields that are allowed to influence security logic.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct TypedMeta {
    pub client_info: Option<Value>,
    pub capabilities: Option<Value>,
    pub protocol_version: Option<McpProtocolVersion>,
    pub trace_context: TraceContextMeta,
    pub quarantined_keys: Vec<String>,
}

/// W3C trace context values carried in MCP `_meta`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TraceContextMeta {
    pub traceparent: Option<String>,
    pub tracestate: Option<String>,
    pub baggage: Option<String>,
}

/// A fail-closed adapter denial.
#[derive(Debug, Clone, PartialEq)]
pub struct AdapterDeny {
    pub kind: AdapterDenyKind,
    pub code: i64,
    pub message: String,
    pub id: Option<Value>,
}

impl AdapterDeny {
    fn invalid_request(message: impl Into<String>, id: Option<Value>) -> Self {
        Self {
            kind: AdapterDenyKind::InvalidRequest,
            code: -32600,
            message: message.into(),
            id,
        }
    }

    fn meta_violation(message: impl Into<String>, id: Option<Value>) -> Self {
        Self {
            kind: AdapterDenyKind::MetaViolation,
            code: -32600,
            message: message.into(),
            id,
        }
    }

    fn batch() -> Self {
        Self {
            kind: AdapterDenyKind::Batch,
            code: vellaveto_types::json_rpc::BATCH_NOT_ALLOWED,
            message: "JSON-RPC batching is not supported".to_string(),
            id: None,
        }
    }
}

/// Adapter denial category.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdapterDenyKind {
    Batch,
    InvalidRequest,
    MetaViolation,
}

impl AdapterDenyKind {
    /// Whether the HTTP proxy should enforce this denial before legacy handler
    /// paths run. Structural invalid requests still flow to existing audit paths
    /// until the handler is fully migrated to this adapter.
    pub fn enforce_immediately(self) -> bool {
        matches!(self, Self::MetaViolation)
    }
}

/// Adapter from one MCP wire version into Vellaveto's canonical request model.
pub trait WireAdapter {
    fn protocol_version(&self) -> McpProtocolVersion;

    fn normalize_inbound(&self, msg: &Value) -> Result<CanonicalRequest, AdapterDeny> {
        normalize_common(self.protocol_version(), msg)
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct Adapter2025_03_26;

#[derive(Debug, Clone, Copy, Default)]
pub struct Adapter2025_06_18;

#[derive(Debug, Clone, Copy, Default)]
pub struct Adapter2025_11_25;

#[derive(Debug, Clone, Copy, Default)]
pub struct Adapter2026_07_28;

impl WireAdapter for Adapter2025_03_26 {
    fn protocol_version(&self) -> McpProtocolVersion {
        McpProtocolVersion::V2025_03_26
    }
}

impl WireAdapter for Adapter2025_06_18 {
    fn protocol_version(&self) -> McpProtocolVersion {
        McpProtocolVersion::V2025_06_18
    }
}

impl WireAdapter for Adapter2025_11_25 {
    fn protocol_version(&self) -> McpProtocolVersion {
        McpProtocolVersion::V2025_11_25
    }
}

impl WireAdapter for Adapter2026_07_28 {
    fn protocol_version(&self) -> McpProtocolVersion {
        McpProtocolVersion::V2026_07_28
    }
}

/// Normalize an inbound MCP message using the adapter for `protocol_version`.
pub fn normalize_inbound(
    protocol_version: McpProtocolVersion,
    msg: &Value,
) -> Result<CanonicalRequest, AdapterDeny> {
    match protocol_version {
        McpProtocolVersion::V2025_03_26 => Adapter2025_03_26.normalize_inbound(msg),
        McpProtocolVersion::V2025_06_18 => Adapter2025_06_18.normalize_inbound(msg),
        McpProtocolVersion::V2025_11_25 => Adapter2025_11_25.normalize_inbound(msg),
        McpProtocolVersion::V2026_07_28 => Adapter2026_07_28.normalize_inbound(msg),
    }
}

fn normalize_common(
    protocol_version: McpProtocolVersion,
    msg: &Value,
) -> Result<CanonicalRequest, AdapterDeny> {
    if msg.is_array() {
        return Err(AdapterDeny::batch());
    }

    let id = msg.get("id").cloned();
    let meta = parse_typed_meta(protocol_version, msg, id.clone())?;
    let correlation_id = meta
        .trace_context
        .traceparent
        .clone()
        .or_else(|| id.as_ref().map(correlation_from_id));

    match classify_message(msg) {
        MessageType::ToolCall {
            id,
            tool_name,
            arguments,
        } => Ok(CanonicalRequest {
            protocol_version,
            kind: CanonicalMessageKind::Request,
            id: Some(id),
            method: "tools/call".to_string(),
            name: Some(tool_name),
            principal: None,
            correlation_id,
            args: arguments,
            meta,
            handles: Vec::new(),
        }),
        MessageType::ResourceRead { id, uri } => Ok(CanonicalRequest {
            protocol_version,
            kind: CanonicalMessageKind::Request,
            id: Some(id),
            method: "resources/read".to_string(),
            name: Some(uri.clone()),
            principal: None,
            correlation_id,
            args: serde_json::json!({ "uri": uri }),
            meta,
            handles: Vec::new(),
        }),
        MessageType::SamplingRequest { id } => Ok(CanonicalRequest {
            protocol_version,
            kind: CanonicalMessageKind::Request,
            id: Some(id),
            method: "sampling/createMessage".to_string(),
            name: None,
            principal: None,
            correlation_id,
            args: params_or_empty_object(msg),
            meta,
            handles: Vec::new(),
        }),
        MessageType::ElicitationRequest { id } => Ok(CanonicalRequest {
            protocol_version,
            kind: CanonicalMessageKind::Request,
            id: Some(id),
            method: "elicitation/create".to_string(),
            name: None,
            principal: None,
            correlation_id,
            args: params_or_empty_object(msg),
            meta,
            handles: Vec::new(),
        }),
        MessageType::TaskRequest {
            id,
            task_method,
            task_id,
        } => Ok(CanonicalRequest {
            protocol_version,
            kind: CanonicalMessageKind::Request,
            id: Some(id),
            method: task_method,
            name: task_id,
            principal: None,
            correlation_id,
            args: params_or_empty_object(msg),
            meta,
            handles: Vec::new(),
        }),
        MessageType::ExtensionMethod {
            id,
            extension_id,
            method,
        } => Ok(CanonicalRequest {
            protocol_version,
            kind: CanonicalMessageKind::Request,
            id: Some(id),
            method,
            name: Some(extension_id),
            principal: None,
            correlation_id,
            args: params_or_empty_object(msg),
            meta,
            handles: Vec::new(),
        }),
        MessageType::ProgressNotification { progress_token, .. } => Ok(CanonicalRequest {
            protocol_version,
            kind: CanonicalMessageKind::Notification,
            id: None,
            method: "notifications/progress".to_string(),
            name: Some(progress_token),
            principal: None,
            correlation_id,
            args: params_or_empty_object(msg),
            meta,
            handles: Vec::new(),
        }),
        MessageType::PassThrough => normalize_passthrough(protocol_version, msg, meta),
        MessageType::Invalid { id, reason } => Err(AdapterDeny::invalid_request(reason, Some(id))),
        MessageType::Batch => Err(AdapterDeny::batch()),
    }
}

fn normalize_passthrough(
    protocol_version: McpProtocolVersion,
    msg: &Value,
    meta: TypedMeta,
) -> Result<CanonicalRequest, AdapterDeny> {
    if msg.get("result").is_some() || msg.get("error").is_some() {
        let id = msg.get("id").cloned();
        let correlation_id = id.as_ref().map(correlation_from_id);
        return Ok(CanonicalRequest {
            protocol_version,
            kind: CanonicalMessageKind::Response,
            id,
            method: "__response__".to_string(),
            name: None,
            principal: None,
            correlation_id,
            args: msg.clone(),
            meta,
            handles: Vec::new(),
        });
    }

    let Some(method) = msg.get("method").and_then(Value::as_str) else {
        return Err(AdapterDeny::invalid_request(
            "Missing method field",
            msg.get("id").cloned(),
        ));
    };

    let id = msg.get("id").cloned();
    let kind = if id.is_some() {
        CanonicalMessageKind::Request
    } else {
        CanonicalMessageKind::Notification
    };

    Ok(CanonicalRequest {
        protocol_version,
        kind,
        id: id.clone(),
        method: normalize_method(method),
        name: None,
        principal: None,
        correlation_id: id.as_ref().map(correlation_from_id),
        args: params_or_empty_object(msg),
        meta,
        handles: Vec::new(),
    })
}

fn params_or_empty_object(msg: &Value) -> Value {
    msg.get("params")
        .filter(|params| params.is_object())
        .cloned()
        .unwrap_or_else(|| Value::Object(serde_json::Map::new()))
}

fn correlation_from_id(id: &Value) -> String {
    match id {
        Value::String(value) => value.clone(),
        _ => id.to_string(),
    }
}

fn parse_typed_meta(
    protocol_version: McpProtocolVersion,
    msg: &Value,
    id: Option<Value>,
) -> Result<TypedMeta, AdapterDeny> {
    let meta = match raw_meta(msg, id.clone())? {
        Some(meta) => meta,
        None => return Ok(TypedMeta::default()),
    };

    let meta_bytes = serde_json::to_vec(meta)
        .map_err(|_| AdapterDeny::meta_violation("_meta serialization failed", id.clone()))?;
    if meta_bytes.len() > MAX_META_BYTES {
        return Err(AdapterDeny::meta_violation("_meta exceeds size limit", id));
    }

    let object = meta
        .as_object()
        .ok_or_else(|| AdapterDeny::meta_violation("_meta must be a JSON object", id.clone()))?;

    let mut typed = TypedMeta::default();
    for (key, value) in object {
        match key.as_str() {
            META_CLIENT_INFO | "clientInfo" => typed.client_info = Some(value.clone()),
            META_CAPABILITIES | "capabilities" => typed.capabilities = Some(value.clone()),
            META_PROTOCOL_VERSION | "protocolVersion" => {
                let Some(version) = value.as_str() else {
                    return Err(AdapterDeny::meta_violation(
                        "_meta protocol version must be a string",
                        id.clone(),
                    ));
                };
                let parsed = version.parse::<McpProtocolVersion>().map_err(|_| {
                    AdapterDeny::meta_violation(
                        "_meta protocol version is not supported",
                        id.clone(),
                    )
                })?;
                if parsed != protocol_version {
                    return Err(AdapterDeny::meta_violation(
                        "_meta protocol version disagrees with transport",
                        id.clone(),
                    ));
                }
                typed.protocol_version = Some(parsed);
            }
            META_TRACEPARENT => {
                typed.trace_context.traceparent =
                    Some(parse_traceparent(value, id.clone())?.to_string());
            }
            META_TRACESTATE => {
                typed.trace_context.tracestate = Some(parse_bounded_text(
                    value,
                    MAX_TRACESTATE_BYTES,
                    "tracestate",
                    id.clone(),
                )?);
            }
            META_BAGGAGE => {
                typed.trace_context.baggage = Some(parse_bounded_text(
                    value,
                    MAX_BAGGAGE_BYTES,
                    "baggage",
                    id.clone(),
                )?);
            }
            _ => typed.quarantined_keys.push(key.clone()),
        }
    }
    typed.quarantined_keys.sort();
    Ok(typed)
}

fn raw_meta(msg: &Value, id: Option<Value>) -> Result<Option<&Value>, AdapterDeny> {
    let top_level = msg.get("_meta");
    let params_meta = msg.get("params").and_then(|params| params.get("_meta"));
    match (top_level, params_meta) {
        (Some(left), Some(right)) if left != right => Err(AdapterDeny::meta_violation(
            "conflicting top-level and params _meta",
            id,
        )),
        (Some(meta), _) | (_, Some(meta)) => Ok(Some(meta)),
        (None, None) => Ok(None),
    }
}

fn parse_traceparent(value: &Value, id: Option<Value>) -> Result<&str, AdapterDeny> {
    let Some(traceparent) = value.as_str() else {
        return Err(AdapterDeny::meta_violation(
            "traceparent must be a string",
            id,
        ));
    };
    if !is_valid_traceparent(traceparent) {
        return Err(AdapterDeny::meta_violation("traceparent is malformed", id));
    }
    Ok(traceparent)
}

fn parse_bounded_text(
    value: &Value,
    max_bytes: usize,
    field: &str,
    id: Option<Value>,
) -> Result<String, AdapterDeny> {
    let Some(text) = value.as_str() else {
        return Err(AdapterDeny::meta_violation(
            format!("{field} must be a string"),
            id,
        ));
    };
    if text.len() > max_bytes {
        return Err(AdapterDeny::meta_violation(
            format!("{field} exceeds size limit"),
            id,
        ));
    }
    if has_dangerous_chars(text) {
        return Err(AdapterDeny::meta_violation(
            format!("{field} contains control or format characters"),
            id,
        ));
    }
    Ok(text.to_string())
}

fn is_valid_traceparent(traceparent: &str) -> bool {
    let parts: Vec<&str> = traceparent.split('-').collect();
    if parts.len() != 4 {
        return false;
    }
    let [version, trace_id, parent_id, flags] = [parts[0], parts[1], parts[2], parts[3]];
    version.len() == 2
        && version != "ff"
        && trace_id.len() == 32
        && trace_id != "00000000000000000000000000000000"
        && parent_id.len() == 16
        && parent_id != "0000000000000000"
        && flags.len() == 2
        && [version, trace_id, parent_id, flags]
            .iter()
            .all(|part| part.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn adapter_normalizes_tool_call() {
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {
                "name": "read_file",
                "arguments": {"path": "/tmp/a"},
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
                }
            }
        });

        let canonical =
            normalize_inbound(McpProtocolVersion::V2026_07_28, &msg).expect("canonical request");
        assert_eq!(canonical.protocol_version, McpProtocolVersion::V2026_07_28);
        assert_eq!(canonical.kind, CanonicalMessageKind::Request);
        assert_eq!(canonical.method, "tools/call");
        assert_eq!(canonical.name.as_deref(), Some("read_file"));
        assert_eq!(canonical.args, json!({"path": "/tmp/a"}));
        assert_eq!(
            canonical.correlation_id.as_deref(),
            Some("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
        );
    }

    #[test]
    fn adapter_denies_meta_protocol_mismatch() {
        let msg = json!({
            "jsonrpc": "2.0",
            "id": "abc",
            "method": "tools/list",
            "params": {
                "_meta": {"io.modelcontextprotocol/protocolVersion": "2025-11-25"}
            }
        });

        let err = normalize_inbound(McpProtocolVersion::V2026_07_28, &msg).unwrap_err();
        assert_eq!(err.kind, AdapterDenyKind::MetaViolation);
    }

    #[test]
    fn adapter_denies_malformed_traceparent() {
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {"_meta": {"traceparent": "not-a-trace"}}
        });

        let err = normalize_inbound(McpProtocolVersion::V2026_07_28, &msg).unwrap_err();
        assert_eq!(err.kind, AdapterDenyKind::MetaViolation);
    }

    #[test]
    fn adapter_quarantines_unknown_meta_keys() {
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {
                "_meta": {
                    "approval_id": "abc",
                    "custom": "value"
                }
            }
        });

        let canonical =
            normalize_inbound(McpProtocolVersion::V2025_11_25, &msg).expect("canonical request");
        assert_eq!(
            canonical.meta.quarantined_keys,
            vec!["approval_id", "custom"]
        );
    }

    #[test]
    fn adapter_denies_batch() {
        let err = normalize_inbound(McpProtocolVersion::V2025_11_25, &json!([])).unwrap_err();
        assert_eq!(err.kind, AdapterDenyKind::Batch);
    }

    #[test]
    fn adapter_normalizes_unknown_method_instead_of_passing_through() {
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 9,
            "method": "custom/doThing",
            "params": {"x": true}
        });

        let canonical =
            normalize_inbound(McpProtocolVersion::V2025_11_25, &msg).expect("canonical request");
        assert_eq!(canonical.kind, CanonicalMessageKind::Request);
        assert_eq!(canonical.method, "custom/dothing");
        assert_eq!(canonical.args, json!({"x": true}));
    }

    #[test]
    fn adapter_normalizes_response_as_canonical_message() {
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 3,
            "result": {"ok": true}
        });

        let canonical =
            normalize_inbound(McpProtocolVersion::V2025_11_25, &msg).expect("canonical response");
        assert_eq!(canonical.kind, CanonicalMessageKind::Response);
        assert_eq!(canonical.method, "__response__");
        assert_eq!(canonical.correlation_id.as_deref(), Some("3"));
    }
}
