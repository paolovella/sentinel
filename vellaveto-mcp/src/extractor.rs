// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Extract [`Action`] from MCP JSON-RPC tool call messages.
//!
//! MCP `tools/call` messages have this shape:
//! ```json
//! {
//!     "jsonrpc": "2.0",
//!     "id": 1,
//!     "method": "tools/call",
//!     "params": {
//!         "name": "read_file",
//!         "arguments": { "path": "/etc/passwd" }
//!     }
//! }
//! ```
//!
//! This module classifies messages and extracts the tool name + arguments
//! into a [`vellaveto_types::Action`] for policy evaluation.

use serde_json::Value;
use vellaveto_types::Action;

/// Standard parameter key for file system paths (extracted from tool arguments or URIs).
///
/// Both the extractor and the policy engine reference this key:
/// - Extractor populates `action.parameters["path"]` for `file://` URIs
/// - Engine's `ParameterConstraint` matches against `parameters.path`
pub const PARAM_PATH: &str = "path";

/// Standard parameter key for network URLs (extracted from tool arguments or URIs).
///
/// Both the extractor and the policy engine reference this key:
/// - Extractor populates `action.parameters["url"]` for `http(s)://` URIs
/// - Engine's `ParameterConstraint` matches against `parameters.url`
pub const PARAM_URL: &str = "url";

/// Standard parameter key for raw URIs (always populated for `resources/read`).
pub const PARAM_URI: &str = "uri";

/// Classification of an MCP JSON-RPC message.
#[derive(Debug, Clone, PartialEq)]
pub enum MessageType {
    /// A `tools/call` request that should be policy-checked.
    ToolCall {
        id: Value,
        tool_name: String,
        arguments: Value,
    },
    /// A `resources/read` request that should be policy-checked.
    ResourceRead { id: Value, uri: String },
    /// A `sampling/createMessage` request — blocked unconditionally as an exfiltration vector.
    SamplingRequest { id: Value },
    /// An `elicitation/create` request (MCP 2025-06-18) — server-initiated user prompt.
    ElicitationRequest { id: Value },
    /// A `tasks/*` request (MCP 2025-11-25) — async task management (get, cancel, list, resubscribe, create).
    TaskRequest {
        id: Value,
        task_method: String,
        task_id: Option<String>,
    },
    /// A JSON-RPC batch (array of requests) — rejected per MCP 2025-06-18.
    Batch,
    /// An invalid request that should be rejected with an error response.
    Invalid { id: Value, reason: String },
    /// A `notifications/progress` notification (upstream → client).
    ProgressNotification {
        progress_token: String,
        progress: f64,
        total: Option<f64>,
    },
    /// An extension method call (method starts with `x-` prefix).
    ExtensionMethod {
        id: Value,
        extension_id: String,
        method: String,
    },
    /// Any other message (notifications, responses, other methods).
    PassThrough,
}

/// Normalize an MCP method name for matching.
///
/// Strips trailing slashes, null bytes, and whitespace to prevent
/// bypass via `"tools/call/"`, `"tools/call\0"`, or `"tools/call "`.
/// Returns the normalized lowercase form for case-insensitive comparison.
pub fn normalize_method(method: &str) -> String {
    // SECURITY (R33-MCP-6): Strip ALL invisible/format Unicode characters that the
    // injection scanner also strips, not just a subset. A mismatch allows bypass:
    // e.g. "tools/\u{202A}call" passes method matching (→ "tools/call") but the
    // original string with the bidi override might evade injection scanning.
    method
        .trim()
        .chars()
        .filter(|c| {
            let cp = *c as u32;
            // SECURITY (FIND-R107-001): Also strip C0 (0x00-0x1F) and C1
            // (0x7F-0x9F) control characters to prevent log injection via
            // embedded newlines/carriage returns in method names.
            !(cp <= 0x1F                                  // C0 control chars (NUL..US)
                || (0x7F..=0x9F).contains(&cp)            // DEL + C1 control chars
                || (0x200B..=0x200F).contains(&cp)        // zero-width chars
                || (0x202A..=0x202E).contains(&cp)        // bidi overrides
                || (0xFE00..=0xFE0F).contains(&cp)        // variation selectors
                || cp == 0xFEFF                            // BOM / ZWNBSP
                || (0x2060..=0x2064).contains(&cp)        // word joiners / invisible operators
                || (0xFFF9..=0xFFFB).contains(&cp)        // interlinear annotation
                || cp == 0x180E                            // Mongolian vowel separator
                || cp == 0x00AD                            // soft hyphen
                || (0x2066..=0x2069).contains(&cp)        // bidi isolate (LRI, RLI, FSI, PDI)
                || (0xE0000..=0xE007F).contains(&cp)) // tag characters
        })
        .collect::<String>()
        .trim_end_matches('/')
        .to_lowercase()
}

/// Classify a JSON-RPC message.
///
/// Returns `ToolCall` for `"method": "tools/call"` requests with valid params.
/// Returns `ResourceRead` for `"method": "resources/read"` requests with a URI.
/// Returns `Invalid` for messages with no method AND no result/error fields.
/// Returns `PassThrough` for responses and other recognized methods.
///
/// Method names are normalized before matching: trailing slashes, null bytes,
/// and whitespace are stripped, and comparison is case-insensitive. This prevents
/// bypass attacks like `"tools/call/"` or `"Tools/Call"`.
pub fn classify_message(msg: &Value) -> MessageType {
    // MCP 2025-06-18 removed JSON-RPC batching. Reject arrays early.
    if msg.is_array() {
        return MessageType::Batch;
    }

    let method = match msg.get("method").and_then(|v| v.as_str()) {
        Some(m) => m,
        None => {
            // No method field — check if it's a JSON-RPC response or truly invalid
            if msg.get("result").is_some() || msg.get("error").is_some() {
                return MessageType::PassThrough; // It's a response
            }
            let id = msg.get("id").cloned().unwrap_or(Value::Null);
            return MessageType::Invalid {
                id,
                reason: "Missing method field".to_string(),
            };
        }
    };

    let id = msg.get("id").cloned().unwrap_or(Value::Null);
    let params = msg.get("params");
    let normalized = normalize_method(method);

    match normalized.as_str() {
        "tools/call" => {
            let tool_name = params.and_then(|p| p.get("name")).and_then(|n| n.as_str());

            match tool_name {
                Some(name) if !name.is_empty() => {
                    // SECURITY (FIND-R82-001): Validate that arguments is an object
                    // (or absent). Non-object types (array, string, number) are rejected
                    // early for clarity rather than relying on fail-closed .get() semantics.
                    let raw_args = params.and_then(|p| p.get("arguments"));
                    if let Some(args) = raw_args {
                        if !args.is_object() && !args.is_null() {
                            return MessageType::Invalid {
                                id,
                                reason: "tools/call arguments must be a JSON object".to_string(),
                            };
                        }
                    }
                    let arguments = raw_args
                        .filter(|a| a.is_object())
                        .cloned()
                        .unwrap_or_else(|| Value::Object(serde_json::Map::new()));

                    // SECURITY (R8-MCP-10): Normalize tool name same as method
                    // names — strip zero-width chars and trim whitespace to prevent
                    // policy bypass via "bash\u{200B}" not matching "bash" policy.
                    let normalized_name = normalize_method(name);
                    if normalized_name.is_empty() {
                        return MessageType::Invalid {
                            id,
                            reason: "tools/call tool name is empty after normalization".to_string(),
                        };
                    }

                    MessageType::ToolCall {
                        id,
                        tool_name: normalized_name,
                        arguments,
                    }
                }
                _ => MessageType::Invalid {
                    id,
                    reason: "tools/call missing or empty tool name".to_string(),
                },
            }
        }
        "resources/read" => {
            // SECURITY (R17-URI-1): Reject empty/missing URI to prevent policy bypass.
            // An empty URI produces an Action with empty target_paths and target_domains,
            // which causes the engine to skip all path and network rule checks.
            match params.and_then(|p| p.get("uri")).and_then(|u| u.as_str()) {
                Some(uri) if !uri.is_empty() => MessageType::ResourceRead {
                    id,
                    uri: uri.to_string(),
                },
                _ => MessageType::Invalid {
                    id,
                    reason: "resources/read missing or empty uri parameter".to_string(),
                },
            }
        }
        "sampling/createmessage" => MessageType::SamplingRequest { id },
        "elicitation/create" => MessageType::ElicitationRequest { id },
        method @ ("tasks/get" | "tasks/cancel" | "tasks/list" | "tasks/resubscribe"
        | "tasks/create") => {
            let task_id = params
                .and_then(|p| p.get("id"))
                .and_then(|t| t.as_str())
                .map(|s| s.to_string());
            MessageType::TaskRequest {
                id,
                task_method: method.to_string(),
                task_id,
            }
        }
        "notifications/progress" => {
            let progress_token = params
                .and_then(|p| p.get("progressToken"))
                .and_then(|t| t.as_str())
                .unwrap_or("")
                .to_string();
            let progress = params
                .and_then(|p| p.get("progress"))
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0);
            let total = params.and_then(|p| p.get("total")).and_then(|v| v.as_f64());
            MessageType::ProgressNotification {
                progress_token,
                progress,
                total,
            }
        }
        _ if normalized.starts_with("x-") => {
            let extension_id = normalized
                .split('/')
                .next()
                .unwrap_or(&normalized)
                .to_string();
            MessageType::ExtensionMethod {
                id,
                extension_id,
                method: normalized,
            }
        }
        _ => MessageType::PassThrough,
    }
}

/// Extract an [`Action`] from a classified tool call.
///
/// The `tool` field is set to the MCP tool name.
/// The `function` field is set to `"*"` (MCP tools don't have sub-functions).
/// The `parameters` field is the tool's arguments object.
///
/// Automatically populates `target_paths` from parameters containing file-like paths
/// and `target_domains` from parameters containing URLs.
///
/// Validates tool name at the trust boundary. Returns a fail-closed action
/// (tool `"<invalid>"`) if the name is invalid, ensuring downstream policy
/// evaluation denies the call rather than processing garbage input.
pub fn extract_action(tool_name: &str, arguments: &Value) -> Action {
    // Validate at the trust boundary (M2: reject empty, null bytes, overlength)
    match Action::validated(tool_name, "*", arguments.clone()) {
        Ok(mut action) => {
            extract_targets_from_params(
                arguments,
                &mut action.target_paths,
                &mut action.target_domains,
            );
            action
        }
        Err(e) => {
            tracing::warn!(
                "Invalid tool name rejected at extraction: {} (tool={:?})",
                e,
                &tool_name[..tool_name.len().min(64)]
            );
            // Fail-closed: return an action that no Allow policy will match
            Action::new("<invalid>", "<invalid>", arguments.clone())
        }
    }
}

/// Maximum recursion depth for parameter scanning (defense-in-depth against stack overflow).
const MAX_PARAM_SCAN_DEPTH: usize = 32;

/// Maximum number of extracted paths + domains to prevent OOM from large parameter arrays.
/// Matches the server-side limit in vellaveto-server/src/routes.rs.
const MAX_EXTRACTED_TARGETS: usize = 256;

/// Scan parameter values for file paths and URLs, populating target_paths and target_domains.
fn extract_targets_from_params(value: &Value, paths: &mut Vec<String>, domains: &mut Vec<String>) {
    extract_targets_from_params_inner(value, paths, domains, 0);
}

fn extract_targets_from_params_inner(
    value: &Value,
    paths: &mut Vec<String>,
    domains: &mut Vec<String>,
    depth: usize,
) {
    if depth >= MAX_PARAM_SCAN_DEPTH {
        return;
    }
    // SECURITY (R11-PATH-4): Cap extracted targets to prevent OOM.
    if paths.len() + domains.len() >= MAX_EXTRACTED_TARGETS {
        return;
    }
    match value {
        Value::String(s) => {
            // Only lowercase the scheme for comparison, preserve original path case
            let lower = s.to_lowercase();
            if let Some(lower_after_scheme) = lower.strip_prefix("file://") {
                // Extract path from file:// URI, preserving original case.
                // Find the scheme end in the original string.
                let after_scheme = &s[7..]; // skip "file://"
                let path_original = if lower_after_scheme.starts_with("localhost") {
                    &after_scheme["localhost".len()..]
                } else if after_scheme.starts_with('/') {
                    after_scheme
                } else {
                    after_scheme
                        .find('/')
                        .map(|i| &after_scheme[i..])
                        .unwrap_or("")
                };
                // Strip query strings and fragments before adding
                let file_path = strip_query_and_fragment(path_original);
                // SECURITY (R12-EXT-1): Percent-decode file:// paths.
                // Without this, file:///etc/%70asswd bypasses blocked-path
                // rules for /etc/passwd because the engine sees encoded chars.
                // SECURITY (R245-SRV-4): Strict UTF-8 — skip malformed sequences.
                if let Ok(decoded) = percent_encoding::percent_decode_str(file_path).decode_utf8() {
                    if !decoded.is_empty() {
                        paths.push(decoded.into_owned());
                    }
                }
            } else if lower.starts_with("http://") || lower.starts_with("https://") {
                // Extract domain from HTTP(S) URL
                if let Some(authority) = s.find("://").map(|i| &s[i + 3..]) {
                    let host_raw = authority.split('/').next().unwrap_or(authority);
                    // SECURITY (R12-EXT-2): Percent-decode authority before splitting on '@'.
                    // Without this, http://evil.com%40blocked.com bypasses domain matching
                    // because the encoded '@' hides the userinfo/host boundary.
                    // SECURITY (R245-SRV-4): Strict UTF-8 — skip malformed authority.
                    if let Ok(decoded) =
                        percent_encoding::percent_decode_str(host_raw).decode_utf8()
                    {
                        let host = decoded.as_ref();
                        let host = host.split(':').next().unwrap_or(host);
                        let host = host.split('?').next().unwrap_or(host);
                        let host = host.split('#').next().unwrap_or(host);
                        let host = if let Some(pos) = host.rfind('@') {
                            &host[pos + 1..]
                        } else {
                            host
                        };
                        if !host.is_empty() {
                            domains.push(host.to_lowercase());
                        }
                    }
                }
            } else if s.starts_with('/') && !s.contains(' ') {
                // Looks like an absolute file path — strip query/fragments
                let clean = strip_query_and_fragment(s);
                if !clean.is_empty() {
                    paths.push(clean.to_string());
                }
            } else if looks_like_relative_path(s) {
                // SECURITY (R11-PATH-3): Catch relative paths containing ..
                // or starting with ~/ that bypass the absolute-path check.
                let clean = strip_query_and_fragment(s);
                if !clean.is_empty() {
                    paths.push(format!("/{clean}"));
                }
            }
        }
        Value::Object(map) => {
            for val in map.values() {
                extract_targets_from_params_inner(val, paths, domains, depth + 1);
            }
        }
        Value::Array(arr) => {
            for val in arr {
                extract_targets_from_params_inner(val, paths, domains, depth + 1);
            }
        }
        _ => {}
    }
}

/// Strip query string (`?...`) and fragment (`#...`) from a path.
fn strip_query_and_fragment(path: &str) -> &str {
    let path = path.split('?').next().unwrap_or(path);
    path.split('#').next().unwrap_or(path)
}

/// Detect relative paths that could bypass the absolute-path check.
fn looks_like_relative_path(s: &str) -> bool {
    if s.contains(' ') {
        return false;
    }
    s.starts_with("../")
        || s.starts_with("./")
        || s.starts_with("~/")
        || s.contains("/../")
        || s == ".."
        || s == "~"
}

/// Extract an [`Action`] from a `resources/read` URI.
///
/// The `tool` field is `"resources"`, `function` is `"read"`.
/// The `parameters` field contains:
/// - `uri`: the raw URI string
/// - `path`: extracted file path for `file://` URIs (for path constraint evaluation)
/// - `url`: the full URI for `http://`/`https://` URIs (for domain constraint evaluation)
pub fn extract_resource_action(uri: &str) -> Action {
    let mut params = serde_json::Map::new();
    params.insert(PARAM_URI.to_string(), Value::String(uri.to_string()));

    let mut target_paths = Vec::new();
    let mut target_domains = Vec::new();

    // Lowercase the scheme for comparison (RFC 3986 §3.1: schemes are case-insensitive)
    let uri_lower = uri.to_lowercase();
    if let Some(lower_after_scheme) = uri_lower.strip_prefix("file://") {
        // Preserve original path case for case-sensitive filesystems.
        let after_scheme = &uri[7..]; // skip "file://"
        let file_path = if lower_after_scheme.starts_with("localhost") {
            &after_scheme["localhost".len()..]
        } else if after_scheme.starts_with('/') {
            after_scheme
        } else {
            // file://host/path — extract path after host
            after_scheme
                .find('/')
                .map(|i| &after_scheme[i..])
                .unwrap_or(after_scheme)
        };
        // Strip query strings and fragments
        let file_path = strip_query_and_fragment(file_path);
        // SECURITY (R12-EXT-1): Percent-decode file:// paths before use.
        // SECURITY (R245-SRV-4): Strict UTF-8 — skip malformed sequences.
        if let Ok(decoded) = percent_encoding::percent_decode_str(file_path).decode_utf8() {
            params.insert(PARAM_PATH.to_string(), Value::String(decoded.to_string()));
            target_paths.push(decoded.into_owned());
        }
    } else if uri_lower.starts_with("http://") || uri_lower.starts_with("https://") {
        params.insert(PARAM_URL.to_string(), Value::String(uri.to_string()));
        // Extract domain for target_domains
        if let Some(authority) = uri.find("://").map(|i| &uri[i + 3..]) {
            let host_raw = authority.split('/').next().unwrap_or(authority);
            // SECURITY (R12-EXT-2): Percent-decode authority before splitting.
            // SECURITY (R245-SRV-4): Strict UTF-8 — skip malformed authority.
            if let Ok(decoded) = percent_encoding::percent_decode_str(host_raw).decode_utf8() {
                let host = decoded.as_ref();
                let host = host.split(':').next().unwrap_or(host);
                let host = host.split('?').next().unwrap_or(host);
                let host = host.split('#').next().unwrap_or(host);
                let host = if let Some(pos) = host.rfind('@') {
                    &host[pos + 1..]
                } else {
                    host
                };
                if !host.is_empty() {
                    target_domains.push(host.to_lowercase());
                }
            }
        }
    }

    let mut action = Action::new("resources", "read", Value::Object(params));
    action.target_paths = target_paths;
    action.target_domains = target_domains;
    action
}

/// Extract an [`Action`] from a classified task request.
///
/// The `tool` field is `"tasks"`, `function` is the task method (e.g., `"get"`, `"cancel"`).
/// The `parameters` field contains the task_id (if present) and the original method name.
///
/// This allows policies to target task operations:
/// - `tasks:get` — retrieving async task results (may contain sensitive tool output)
/// - `tasks:cancel` — cancelling running tasks (may disrupt workflows)
pub fn extract_task_action(task_method: &str, task_id: Option<&str>) -> Action {
    let function = task_method.strip_prefix("tasks/").unwrap_or(task_method);
    let mut params = serde_json::Map::new();
    params.insert("method".to_string(), Value::String(task_method.to_string()));
    if let Some(tid) = task_id {
        params.insert("task_id".to_string(), Value::String(tid.to_string()));
    }
    Action::new("tasks", function, Value::Object(params))
}

/// Extract an [`Action`] from a classified extension method call.
///
/// The `tool` field is the extension prefix (e.g., `"x-vellaveto-audit"`).
/// The `function` field is the full normalized method name.
/// The `parameters` field is forwarded from the original message params.
pub fn extract_extension_action(extension_id: &str, method: &str, params: &Value) -> Action {
    Action::new(extension_id, method, params.clone())
}

/// Build a JSON-RPC error response for a rejected batch request.
///
/// Per MCP 2025-06-18, JSON-RPC batching is no longer supported.
/// Uses `id: null` since batch messages don't have a single ID.
pub fn make_batch_error_response() -> Value {
    use vellaveto_types::json_rpc;
    // SECURITY (FIND-R92-001): Use BATCH_NOT_ALLOWED (-32010) instead of
    // INVALID_REQUEST (-32600). Batch rejection is a policy decision, not a
    // malformed request — using the correct code prevents fingerprinting.
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": null,
        "error": {
            "code": json_rpc::BATCH_NOT_ALLOWED,
            "message": "JSON-RPC batching is not supported (MCP 2025-06-18)"
        }
    })
}

/// Build a JSON-RPC error response for an invalid request.
pub fn make_invalid_response(id: &Value, reason: &str) -> Value {
    use vellaveto_types::json_rpc;
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": json_rpc::INVALID_REQUEST,
            "message": format!("Invalid request: {}", reason)
        }
    })
}

/// Build a JSON-RPC error response for a denied tool call.
///
/// Uses [`vellaveto_types::json_rpc::POLICY_DENIED`] error code.
/// Per JSON-RPC 2.0, -32000 to -32099 are reserved for application-defined errors.
/// Includes structured `data` field for client diagnostics.
pub fn make_denial_response(id: &Value, reason: &str) -> Value {
    use vellaveto_types::json_rpc;
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": json_rpc::POLICY_DENIED,
            "message": format!("Denied by policy: {}", reason),
            "data": {
                "type": "policy_denial",
                "reason": reason
            }
        }
    })
}

/// Build a JSON-RPC error response for a tool call that requires approval.
///
/// Uses [`vellaveto_types::json_rpc::APPROVAL_REQUIRED`] error code.
/// Includes structured `data` field for client diagnostics.
pub fn make_approval_response(id: &Value, reason: &str) -> Value {
    use vellaveto_types::json_rpc;
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": json_rpc::APPROVAL_REQUIRED,
            "message": format!("Approval required: {}", reason),
            "data": {
                "type": "approval_required",
                "reason": reason
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_classify_tool_call() {
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "read_file",
                "arguments": {"path": "/etc/passwd"}
            }
        });
        let mt = classify_message(&msg);
        match mt {
            MessageType::ToolCall {
                id,
                tool_name,
                arguments,
            } => {
                assert_eq!(id, json!(1));
                assert_eq!(tool_name, "read_file");
                assert_eq!(arguments["path"], "/etc/passwd");
            }
            _ => panic!("Expected ToolCall"),
        }
    }

    #[test]
    fn test_classify_non_tool_call() {
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "resources/list",
            "params": {}
        });
        assert_eq!(classify_message(&msg), MessageType::PassThrough);
    }

    #[test]
    fn test_classify_response() {
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 3,
            "result": {"content": []}
        });
        assert_eq!(classify_message(&msg), MessageType::PassThrough);
    }

    #[test]
    fn test_classify_error_response() {
        // JSON-RPC error responses (no method, has error) should be PassThrough
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 30,
            "error": {"code": -32600, "message": "Invalid request"}
        });
        assert_eq!(classify_message(&msg), MessageType::PassThrough);
    }

    #[test]
    fn test_classify_no_method_no_result_is_invalid() {
        // A message with no method and no result/error is truly invalid
        let msg = json!({"jsonrpc": "2.0", "id": 31});
        match classify_message(&msg) {
            MessageType::Invalid { id, reason } => {
                assert_eq!(id, json!(31));
                assert!(reason.contains("Missing method"));
            }
            other => panic!("Expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn test_classify_notification() {
        // Non-progress notifications are still PassThrough
        let msg = json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {}
        });
        assert_eq!(classify_message(&msg), MessageType::PassThrough);
    }

    #[test]
    fn test_classify_tool_call_missing_params_returns_invalid() {
        // Fix #5: Missing tool name must return Invalid, not ToolCall with empty name
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call"
        });
        let mt = classify_message(&msg);
        match mt {
            MessageType::Invalid { id, reason } => {
                assert_eq!(id, json!(4));
                assert!(reason.contains("missing or empty tool name"));
            }
            _ => panic!("Expected Invalid, got {mt:?}"),
        }
    }

    #[test]
    fn test_classify_tool_call_empty_name_returns_invalid() {
        // Fix #5: Empty string tool name must also return Invalid
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {"name": "", "arguments": {}}
        });
        let mt = classify_message(&msg);
        assert!(matches!(mt, MessageType::Invalid { .. }));
    }

    #[test]
    fn test_classify_tool_call_non_string_name_returns_invalid() {
        // Fix #5: Non-string name (e.g., integer) must return Invalid
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 6,
            "method": "tools/call",
            "params": {"name": 42, "arguments": {}}
        });
        let mt = classify_message(&msg);
        assert!(matches!(mt, MessageType::Invalid { .. }));
    }

    #[test]
    fn test_classify_tool_call_non_object_arguments_returns_invalid() {
        // FIND-R82-001: Non-object arguments must be rejected early.
        let array_args = json!({
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {"name": "bash", "arguments": ["cmd", "arg"]}
        });
        let mt = classify_message(&array_args);
        assert!(
            matches!(mt, MessageType::Invalid { .. }),
            "array arguments should be rejected"
        );

        let string_args = json!({
            "jsonrpc": "2.0",
            "id": 8,
            "method": "tools/call",
            "params": {"name": "bash", "arguments": "a string"}
        });
        let mt = classify_message(&string_args);
        assert!(
            matches!(mt, MessageType::Invalid { .. }),
            "string arguments should be rejected"
        );

        let number_args = json!({
            "jsonrpc": "2.0",
            "id": 9,
            "method": "tools/call",
            "params": {"name": "bash", "arguments": 42}
        });
        let mt = classify_message(&number_args);
        assert!(
            matches!(mt, MessageType::Invalid { .. }),
            "number arguments should be rejected"
        );

        // Null and absent arguments are fine (default to empty object)
        let null_args = json!({
            "jsonrpc": "2.0",
            "id": 10,
            "method": "tools/call",
            "params": {"name": "bash", "arguments": null}
        });
        let mt = classify_message(&null_args);
        assert!(
            matches!(mt, MessageType::ToolCall { .. }),
            "null arguments should be accepted"
        );

        let absent_args = json!({
            "jsonrpc": "2.0",
            "id": 11,
            "method": "tools/call",
            "params": {"name": "bash"}
        });
        let mt = classify_message(&absent_args);
        assert!(
            matches!(mt, MessageType::ToolCall { .. }),
            "absent arguments should be accepted"
        );
    }

    #[test]
    fn test_extract_action() {
        let args = json!({"path": "/tmp/file.txt", "encoding": "utf-8"});
        let action = extract_action("read_file", &args);
        assert_eq!(action.tool, "read_file");
        assert_eq!(action.function, "*");
        assert_eq!(action.parameters["path"], "/tmp/file.txt");
    }

    #[test]
    fn test_make_denial_response() {
        let resp = make_denial_response(&json!(5), "blocked by policy");
        assert_eq!(resp["jsonrpc"], "2.0");
        assert_eq!(resp["id"], 5);
        assert_eq!(resp["error"]["code"], -32001);
        assert!(resp["error"]["message"]
            .as_str()
            .unwrap()
            .contains("Denied by policy"));
    }

    #[test]
    fn test_make_approval_response() {
        let resp = make_approval_response(&json!(6), "needs review");
        assert_eq!(resp["error"]["code"], -32002);
        assert!(resp["error"]["message"]
            .as_str()
            .unwrap()
            .contains("Approval required"));
    }

    // --- resources/read classification tests ---

    #[test]
    fn test_classify_resource_read() {
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 10,
            "method": "resources/read",
            "params": {
                "uri": "file:///etc/passwd"
            }
        });
        let mt = classify_message(&msg);
        match mt {
            MessageType::ResourceRead { id, uri } => {
                assert_eq!(id, json!(10));
                assert_eq!(uri, "file:///etc/passwd");
            }
            _ => panic!("Expected ResourceRead, got {mt:?}"),
        }
    }

    #[test]
    fn test_classify_resource_read_http_uri() {
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 11,
            "method": "resources/read",
            "params": {
                "uri": "https://evil.com/exfil"
            }
        });
        let mt = classify_message(&msg);
        match mt {
            MessageType::ResourceRead { id, uri } => {
                assert_eq!(id, json!(11));
                assert_eq!(uri, "https://evil.com/exfil");
            }
            _ => panic!("Expected ResourceRead"),
        }
    }

    #[test]
    fn test_classify_resource_read_missing_params() {
        // R17-URI-1: Missing URI must be rejected as Invalid (not accepted as empty)
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 12,
            "method": "resources/read"
        });
        let mt = classify_message(&msg);
        match mt {
            MessageType::Invalid { reason, .. } => {
                assert!(
                    reason.contains("empty uri") || reason.contains("missing"),
                    "Expected rejection for missing URI, got: {reason}"
                );
            }
            _ => panic!("Expected Invalid for missing URI, got: {mt:?}"),
        }
    }

    #[test]
    fn test_classify_resource_read_empty_uri_rejected() {
        // R17-URI-1: Empty string URI must also be rejected
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 13,
            "method": "resources/read",
            "params": {"uri": ""}
        });
        let mt = classify_message(&msg);
        match mt {
            MessageType::Invalid { reason, .. } => {
                assert!(
                    reason.contains("empty"),
                    "Expected rejection for empty URI, got: {reason}"
                );
            }
            _ => panic!("Expected Invalid for empty URI, got: {mt:?}"),
        }
    }

    #[test]
    fn test_classify_resources_list_is_passthrough() {
        // resources/list is NOT intercepted (only resources/read)
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 13,
            "method": "resources/list",
            "params": {}
        });
        assert_eq!(classify_message(&msg), MessageType::PassThrough);
    }

    // --- extract_resource_action tests ---

    #[test]
    fn test_extract_resource_action_file_uri() {
        let action = extract_resource_action("file:///etc/shadow");
        assert_eq!(action.tool, "resources");
        assert_eq!(action.function, "read");
        assert_eq!(action.parameters["uri"], "file:///etc/shadow");
        assert_eq!(action.parameters["path"], "/etc/shadow");
        // No url field for file:// URIs
        assert!(action.parameters.get("url").is_none());
    }

    #[test]
    fn test_extract_resource_action_file_uri_with_localhost() {
        let action = extract_resource_action("file://localhost/home/user/.ssh/id_rsa");
        assert_eq!(action.parameters["path"], "/home/user/.ssh/id_rsa");
    }

    #[test]
    fn test_extract_resource_action_http_uri() {
        let action = extract_resource_action("https://evil.com/data");
        assert_eq!(action.tool, "resources");
        assert_eq!(action.function, "read");
        assert_eq!(action.parameters["uri"], "https://evil.com/data");
        assert_eq!(action.parameters["url"], "https://evil.com/data");
        // No path field for http URIs
        assert!(action.parameters.get("path").is_none());
    }

    #[test]
    fn test_extract_resource_action_unknown_scheme() {
        // Unknown schemes get uri only, no path or url extraction
        let action = extract_resource_action("custom://something");
        assert_eq!(action.parameters["uri"], "custom://something");
        assert!(action.parameters.get("path").is_none());
        assert!(action.parameters.get("url").is_none());
    }

    // --- Exploit #1: Method name normalization bypass tests ---

    #[test]
    fn test_classify_trailing_slash_tools_call() {
        // Adversary bypass: "tools/call/" must still be recognized as ToolCall
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 100,
            "method": "tools/call/",
            "params": {"name": "bash", "arguments": {"command": "cat /etc/shadow"}}
        });
        match classify_message(&msg) {
            MessageType::ToolCall { tool_name, .. } => {
                assert_eq!(tool_name, "bash");
            }
            other => panic!("Expected ToolCall, got {other:?}"),
        }
    }

    #[test]
    fn test_classify_trailing_space_tools_call() {
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 101,
            "method": "tools/call ",
            "params": {"name": "bash", "arguments": {}}
        });
        assert!(matches!(
            classify_message(&msg),
            MessageType::ToolCall { .. }
        ));
    }

    #[test]
    fn test_classify_case_variation_tools_call() {
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 102,
            "method": "Tools/Call",
            "params": {"name": "bash", "arguments": {}}
        });
        assert!(matches!(
            classify_message(&msg),
            MessageType::ToolCall { .. }
        ));
    }

    #[test]
    fn test_classify_null_byte_suffix_tools_call() {
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 103,
            "method": "tools/call\u{0000}",
            "params": {"name": "bash", "arguments": {}}
        });
        assert!(matches!(
            classify_message(&msg),
            MessageType::ToolCall { .. }
        ));
    }

    #[test]
    fn test_classify_trailing_slash_sampling() {
        // sampling/createMessage/ must still be blocked
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 104,
            "method": "sampling/createMessage/",
            "params": {"messages": []}
        });
        assert!(matches!(
            classify_message(&msg),
            MessageType::SamplingRequest { .. }
        ));
    }

    #[test]
    fn test_classify_case_variation_sampling() {
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 105,
            "method": "Sampling/CreateMessage",
            "params": {"messages": []}
        });
        assert!(matches!(
            classify_message(&msg),
            MessageType::SamplingRequest { .. }
        ));
    }

    // --- Exploit #1 residual: Zero-width Unicode bypass tests ---

    #[test]
    fn test_classify_zero_width_space_tools_call() {
        // U+200B zero-width space must be stripped
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 110,
            "method": "tools/call\u{200B}",
            "params": {"name": "bash", "arguments": {"command": "id"}}
        });
        assert!(matches!(
            classify_message(&msg),
            MessageType::ToolCall { .. }
        ));
    }

    #[test]
    fn test_classify_zero_width_joiner_tools_call() {
        // U+200D zero-width joiner must be stripped
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 111,
            "method": "tools\u{200D}/call",
            "params": {"name": "bash", "arguments": {}}
        });
        assert!(matches!(
            classify_message(&msg),
            MessageType::ToolCall { .. }
        ));
    }

    #[test]
    fn test_classify_rtl_mark_tools_call() {
        // U+200F right-to-left mark must be stripped
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 112,
            "method": "tools/call\u{200F}",
            "params": {"name": "bash", "arguments": {}}
        });
        assert!(matches!(
            classify_message(&msg),
            MessageType::ToolCall { .. }
        ));
    }

    #[test]
    fn test_classify_bom_tools_call() {
        // U+FEFF BOM / zero-width no-break space must be stripped
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 113,
            "method": "\u{FEFF}tools/call",
            "params": {"name": "bash", "arguments": {}}
        });
        assert!(matches!(
            classify_message(&msg),
            MessageType::ToolCall { .. }
        ));
    }

    #[test]
    fn test_classify_multiple_zero_width_chars_tools_call() {
        // Multiple zero-width chars embedded throughout
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 114,
            "method": "\u{200B}t\u{200C}ools/\u{200E}call\u{200F}",
            "params": {"name": "bash", "arguments": {}}
        });
        assert!(matches!(
            classify_message(&msg),
            MessageType::ToolCall { .. }
        ));
    }

    #[test]
    fn test_classify_zero_width_sampling_bypass() {
        // Zero-width chars in sampling/createMessage must still be caught
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 115,
            "method": "sampling/create\u{200B}Message",
            "params": {"messages": []}
        });
        assert!(matches!(
            classify_message(&msg),
            MessageType::SamplingRequest { .. }
        ));
    }

    #[test]
    fn test_classify_trailing_slash_resources_read() {
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 106,
            "method": "resources/read/",
            "params": {"uri": "file:///etc/shadow"}
        });
        match classify_message(&msg) {
            MessageType::ResourceRead { uri, .. } => {
                assert_eq!(uri, "file:///etc/shadow");
            }
            other => panic!("Expected ResourceRead, got {other:?}"),
        }
    }

    // --- Exploit #3: URI scheme case sensitivity tests ---

    #[test]
    fn test_extract_resource_action_uppercase_file_scheme() {
        // RFC 3986 §3.1: schemes are case-insensitive
        let action = extract_resource_action("FILE:///etc/shadow");
        assert_eq!(action.parameters["path"], "/etc/shadow");
    }

    #[test]
    fn test_extract_resource_action_mixed_case_file_scheme() {
        let action = extract_resource_action("File:///etc/passwd");
        assert_eq!(action.parameters["path"], "/etc/passwd");
    }

    #[test]
    fn test_extract_resource_action_uppercase_http_scheme() {
        let action = extract_resource_action("HTTPS://evil.com/data");
        assert_eq!(action.parameters["url"], "HTTPS://evil.com/data");
    }

    #[test]
    fn test_extract_resource_action_file_localhost_case_insensitive() {
        let action = extract_resource_action("FILE://localhost/etc/shadow");
        assert_eq!(action.parameters["path"], "/etc/shadow");
    }

    // --- target_paths / target_domains extraction tests ---

    #[test]
    fn test_extract_action_populates_target_paths() {
        let args = json!({"path": "/etc/passwd", "encoding": "utf-8"});
        let action = extract_action("read_file", &args);
        assert!(
            action.target_paths.contains(&"/etc/passwd".to_string()),
            "target_paths should contain /etc/passwd, got: {:?}",
            action.target_paths
        );
    }

    #[test]
    fn test_extract_action_populates_target_domains_from_url() {
        let args = json!({"url": "https://evil.com/data", "method": "GET"});
        let action = extract_action("http_request", &args);
        assert!(
            action.target_domains.contains(&"evil.com".to_string()),
            "target_domains should contain evil.com, got: {:?}",
            action.target_domains
        );
    }

    #[test]
    fn test_extract_action_file_uri_populates_target_paths() {
        let args = json!({"resource": "file:///home/user/.aws/credentials"});
        let action = extract_action("read_resource", &args);
        assert!(
            action
                .target_paths
                .contains(&"/home/user/.aws/credentials".to_string()),
            "target_paths should contain the extracted file path, got: {:?}",
            action.target_paths
        );
    }

    #[test]
    fn test_extract_action_no_targets_for_plain_values() {
        let args = json!({"command": "ls -la", "timeout": 30});
        let action = extract_action("bash", &args);
        assert!(action.target_paths.is_empty());
        assert!(action.target_domains.is_empty());
    }

    #[test]
    fn test_extract_resource_action_file_populates_target_paths() {
        let action = extract_resource_action("file:///etc/shadow");
        assert!(action.target_paths.contains(&"/etc/shadow".to_string()));
        assert!(action.target_domains.is_empty());
    }

    #[test]
    fn test_extract_resource_action_http_populates_target_domains() {
        let action = extract_resource_action("https://evil.com/data");
        assert!(action.target_domains.contains(&"evil.com".to_string()));
        assert!(action.target_paths.is_empty());
    }

    // --- JSON-RPC batch rejection tests (MCP 2025-06-18) ---

    #[test]
    fn test_classify_batch_request_returns_batch() {
        let msg = json!([
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "bash", "arguments": {}}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "read_file", "arguments": {}}}
        ]);
        assert_eq!(classify_message(&msg), MessageType::Batch);
    }

    #[test]
    fn test_classify_empty_batch_returns_batch() {
        let msg = json!([]);
        assert_eq!(classify_message(&msg), MessageType::Batch);
    }

    #[test]
    fn test_classify_single_element_batch_returns_batch() {
        let msg = json!([{"jsonrpc": "2.0", "id": 1, "method": "ping"}]);
        assert_eq!(classify_message(&msg), MessageType::Batch);
    }

    #[test]
    fn test_make_batch_error_response_format() {
        let resp = make_batch_error_response();
        assert_eq!(resp["jsonrpc"], "2.0");
        assert!(resp["id"].is_null());
        // FIND-R92-001: Updated from -32600 (INVALID_REQUEST) to -32010 (BATCH_NOT_ALLOWED)
        assert_eq!(resp["error"]["code"], -32010);
        assert!(resp["error"]["message"]
            .as_str()
            .is_some_and(|m| m.contains("batching")));
    }

    // --- Elicitation classification tests (MCP 2025-06-18) ---

    #[test]
    fn test_classify_elicitation_create() {
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 20,
            "method": "elicitation/create",
            "params": {
                "message": "Please enter your API key",
                "requestedSchema": {"type": "object", "properties": {"api_key": {"type": "string"}}}
            }
        });
        match classify_message(&msg) {
            MessageType::ElicitationRequest { id } => {
                assert_eq!(id, json!(20));
            }
            other => panic!("Expected ElicitationRequest, got {other:?}"),
        }
    }

    #[test]
    fn test_classify_elicitation_case_insensitive() {
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 21,
            "method": "Elicitation/Create",
            "params": {}
        });
        assert!(matches!(
            classify_message(&msg),
            MessageType::ElicitationRequest { .. }
        ));
    }

    #[test]
    fn test_classify_elicitation_trailing_slash() {
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 22,
            "method": "elicitation/create/",
            "params": {}
        });
        assert!(matches!(
            classify_message(&msg),
            MessageType::ElicitationRequest { .. }
        ));
    }

    // --- MCP Tasks classification tests (MCP 2025-11-25) ---

    #[test]
    fn test_classify_tasks_get() {
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 30,
            "method": "tasks/get",
            "params": {"id": "task-abc-123"}
        });
        match classify_message(&msg) {
            MessageType::TaskRequest {
                id,
                task_method,
                task_id,
            } => {
                assert_eq!(id, json!(30));
                assert_eq!(task_method, "tasks/get");
                assert_eq!(task_id, Some("task-abc-123".to_string()));
            }
            other => panic!("Expected TaskRequest, got {other:?}"),
        }
    }

    #[test]
    fn test_classify_tasks_cancel() {
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 31,
            "method": "tasks/cancel",
            "params": {"id": "task-def-456"}
        });
        match classify_message(&msg) {
            MessageType::TaskRequest {
                task_method,
                task_id,
                ..
            } => {
                assert_eq!(task_method, "tasks/cancel");
                assert_eq!(task_id, Some("task-def-456".to_string()));
            }
            other => panic!("Expected TaskRequest, got {other:?}"),
        }
    }

    #[test]
    fn test_classify_tasks_get_no_task_id() {
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 32,
            "method": "tasks/get",
            "params": {}
        });
        match classify_message(&msg) {
            MessageType::TaskRequest { task_id, .. } => {
                assert_eq!(task_id, None);
            }
            other => panic!("Expected TaskRequest, got {other:?}"),
        }
    }

    #[test]
    fn test_classify_tasks_case_insensitive() {
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 33,
            "method": "Tasks/Get",
            "params": {"id": "t1"}
        });
        assert!(matches!(
            classify_message(&msg),
            MessageType::TaskRequest { .. }
        ));
    }

    #[test]
    fn test_classify_tasks_trailing_slash() {
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 34,
            "method": "tasks/cancel/",
            "params": {"id": "t2"}
        });
        assert!(matches!(
            classify_message(&msg),
            MessageType::TaskRequest { .. }
        ));
    }

    // --- extract_task_action tests (R4-1 fix) ---

    #[test]
    fn test_extract_task_action_get() {
        let action = extract_task_action("tasks/get", Some("task-abc-123"));
        assert_eq!(action.tool, "tasks");
        assert_eq!(action.function, "get");
        assert_eq!(action.parameters["method"], "tasks/get");
        assert_eq!(action.parameters["task_id"], "task-abc-123");
    }

    #[test]
    fn test_extract_task_action_cancel() {
        let action = extract_task_action("tasks/cancel", Some("task-def-456"));
        assert_eq!(action.tool, "tasks");
        assert_eq!(action.function, "cancel");
        assert_eq!(action.parameters["method"], "tasks/cancel");
        assert_eq!(action.parameters["task_id"], "task-def-456");
    }

    #[test]
    fn test_extract_task_action_no_task_id() {
        let action = extract_task_action("tasks/get", None);
        assert_eq!(action.tool, "tasks");
        assert_eq!(action.function, "get");
        assert_eq!(action.parameters["method"], "tasks/get");
        assert!(action.parameters.get("task_id").is_none());
    }

    #[test]
    fn test_extract_task_action_unknown_method() {
        // If a new task method is added, function extracts the suffix
        let action = extract_task_action("tasks/list", None);
        assert_eq!(action.tool, "tasks");
        assert_eq!(action.function, "list");
    }

    // --- ProgressNotification classification tests ---

    #[test]
    fn test_classify_progress_notification() {
        let msg = json!({
            "jsonrpc": "2.0",
            "method": "notifications/progress",
            "params": {
                "progressToken": "tok-123",
                "progress": 50.0,
                "total": 100.0
            }
        });
        match classify_message(&msg) {
            MessageType::ProgressNotification {
                progress_token,
                progress,
                total,
            } => {
                assert_eq!(progress_token, "tok-123");
                assert!((progress - 50.0).abs() < f64::EPSILON);
                assert!((total.unwrap() - 100.0).abs() < f64::EPSILON);
            }
            other => panic!("Expected ProgressNotification, got {other:?}"),
        }
    }

    #[test]
    fn test_classify_progress_notification_missing_params() {
        let msg = json!({
            "jsonrpc": "2.0",
            "method": "notifications/progress"
        });
        match classify_message(&msg) {
            MessageType::ProgressNotification {
                progress_token,
                progress,
                total,
            } => {
                assert_eq!(progress_token, "");
                assert!((progress - 0.0).abs() < f64::EPSILON);
                assert!(total.is_none());
            }
            other => panic!("Expected ProgressNotification, got {other:?}"),
        }
    }

    // --- Extension method classification tests ---

    #[test]
    fn test_classify_extension_method() {
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 50,
            "method": "x-vellaveto-audit/stats",
            "params": {}
        });
        match classify_message(&msg) {
            MessageType::ExtensionMethod {
                id,
                extension_id,
                method,
            } => {
                assert_eq!(id, json!(50));
                assert_eq!(extension_id, "x-vellaveto-audit");
                assert_eq!(method, "x-vellaveto-audit/stats");
            }
            other => panic!("Expected ExtensionMethod, got {other:?}"),
        }
    }

    #[test]
    fn test_classify_extension_with_subpath() {
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 51,
            "method": "x-my-ext/deep/path",
            "params": {}
        });
        match classify_message(&msg) {
            MessageType::ExtensionMethod {
                extension_id,
                method,
                ..
            } => {
                assert_eq!(extension_id, "x-my-ext");
                assert_eq!(method, "x-my-ext/deep/path");
            }
            other => panic!("Expected ExtensionMethod, got {other:?}"),
        }
    }

    #[test]
    fn test_non_extension_passthrough() {
        // Method not starting with "x-" should be PassThrough
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 52,
            "method": "some/other/method",
            "params": {}
        });
        assert_eq!(classify_message(&msg), MessageType::PassThrough);
    }

    #[test]
    fn test_extract_extension_action() {
        let params = json!({"query": "SELECT count(*)"});
        let action =
            extract_extension_action("x-vellaveto-audit", "x-vellaveto-audit/query", &params);
        assert_eq!(action.tool, "x-vellaveto-audit");
        assert_eq!(action.function, "x-vellaveto-audit/query");
        assert_eq!(action.parameters["query"], "SELECT count(*)");
    }

    #[test]
    fn test_normalize_method_strips_control_characters() {
        // SECURITY (FIND-R107-001): Control characters must be stripped to
        // prevent log injection via embedded newlines in method names.
        assert_eq!(
            normalize_method("tools/call\nFAKE_LOG"),
            "tools/callfake_log"
        );
        assert_eq!(
            normalize_method("tasks/get\r\n[CRITICAL] breach"),
            "tasks/get[critical] breach"
        );
        assert_eq!(normalize_method("foo\tbar"), "foobar");
        // C1 control characters (0x7F-0x9F)
        assert_eq!(normalize_method("foo\x7Fbar"), "foobar");
        assert_eq!(normalize_method("foo\u{0085}bar"), "foobar");
        assert_eq!(normalize_method("foo\u{009F}bar"), "foobar");
    }
}
