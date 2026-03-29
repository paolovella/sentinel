// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! A2A message types and classification.
//!
//! This module defines the A2A (Agent-to-Agent) protocol message types and
//! provides classification logic for JSON-RPC messages, following the same
//! pattern as MCP message classification.
//!
//! # A2A Protocol Methods
//!
//! - `message/send` — Send a message to an agent
//! - `message/stream` — Send a message with streaming response (SSE)
//! - `tasks/get` — Get task status
//! - `tasks/cancel` — Cancel a running task
//! - `tasks/resubscribe` — Resubscribe to task events

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

/// Maximum number of parts in an A2A message.
const MAX_A2A_MESSAGE_PARTS: usize = 1000;

/// Maximum number of metadata entries per message or part.
const MAX_A2A_METADATA_ENTRIES: usize = 100;

/// Maximum length of inline base64 file content (16 MB).
const MAX_A2A_FILE_BYTES_LEN: usize = 16 * 1024 * 1024;

/// Maximum length of an A2A task_id.
///
/// Matches vellaveto-types `SecureTask::MAX_TASK_ID_LEN` (256).
const MAX_A2A_TASK_ID_LEN: usize = 256;

/// SECURITY (FIND-R188-002): Validate A2A task_id for length and dangerous chars.
///
/// Returns `None` for valid task IDs, `Some(reason)` for invalid ones.
/// Prevents log injection, oversized allocation, and control character attacks.
fn validate_a2a_task_id(tid: &str) -> Option<String> {
    if tid.is_empty() {
        return Some("task_id must not be empty".to_string());
    }
    if tid.len() > MAX_A2A_TASK_ID_LEN {
        return Some(format!(
            "task_id length {} exceeds maximum {}",
            tid.len(),
            MAX_A2A_TASK_ID_LEN
        ));
    }
    if vellaveto_types::has_dangerous_chars(tid) {
        return Some("task_id contains control or format characters".to_string());
    }
    None
}

/// A2A Task state (from A2A specification).
///
/// Represents the lifecycle states of an A2A task.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskState {
    /// Task has been submitted but not yet started.
    Submitted,
    /// Task is currently being processed.
    Working,
    /// Task requires additional input from the caller.
    InputRequired,
    /// Task has completed successfully.
    Completed,
    /// Task has failed with an error.
    Failed,
    /// Task was explicitly canceled.
    Canceled,
}

impl std::fmt::Display for TaskState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TaskState::Submitted => write!(f, "submitted"),
            TaskState::Working => write!(f, "working"),
            TaskState::InputRequired => write!(f, "input_required"),
            TaskState::Completed => write!(f, "completed"),
            TaskState::Failed => write!(f, "failed"),
            TaskState::Canceled => write!(f, "canceled"),
        }
    }
}

/// A2A message part content types.
///
/// Represents the different content types that can appear in an A2A message part.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PartContent {
    /// Text content.
    Text { text: String },
    /// File content (inline or by URI reference).
    File { file: FileContent },
    /// Structured data content.
    Data { data: Value },
}

/// File content in an A2A message.
///
/// Files can be provided inline (base64-encoded bytes) or by URI reference.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileContent {
    /// Optional file name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// MIME type of the file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    /// Base64-encoded file content (inline).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes: Option<String>,
    /// URI reference to the file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
}

/// A2A message part.
///
/// A message consists of one or more parts, each with content and metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessagePart {
    /// Part content (text, file, or data).
    #[serde(flatten)]
    pub content: PartContent,
    /// Optional metadata for this part.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<HashMap<String, Value>>,
}

impl FileContent {
    /// Validate file content bounds.
    pub fn validate(&self) -> Result<(), String> {
        if let Some(ref bytes) = self.bytes {
            if bytes.len() > MAX_A2A_FILE_BYTES_LEN {
                return Err(format!(
                    "file.bytes length {} exceeds maximum {}",
                    bytes.len(),
                    MAX_A2A_FILE_BYTES_LEN
                ));
            }
        }
        Ok(())
    }
}

/// A2A message structure.
///
/// Represents a message exchanged between agents.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct A2aMessage {
    /// Role of the message sender ("user" or "agent").
    pub role: String,
    /// Message parts.
    pub parts: Vec<MessagePart>,
    /// Optional metadata for the message.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<HashMap<String, Value>>,
}

impl A2aMessage {
    /// Validate A2A message bounds.
    pub fn validate(&self) -> Result<(), String> {
        // R262-A2A-1: Validate role for dangerous characters (bidi, zero-width, etc.).
        if vellaveto_types::has_dangerous_chars(&self.role) {
            return Err("message.role contains dangerous characters".to_string());
        }
        if self.parts.len() > MAX_A2A_MESSAGE_PARTS {
            return Err(format!(
                "message.parts count {} exceeds maximum {}",
                self.parts.len(),
                MAX_A2A_MESSAGE_PARTS
            ));
        }
        if let Some(ref meta) = self.metadata {
            if meta.len() > MAX_A2A_METADATA_ENTRIES {
                return Err(format!(
                    "message.metadata count {} exceeds maximum {}",
                    meta.len(),
                    MAX_A2A_METADATA_ENTRIES
                ));
            }
        }
        for part in &self.parts {
            if let Some(ref meta) = part.metadata {
                if meta.len() > MAX_A2A_METADATA_ENTRIES {
                    return Err(format!(
                        "part.metadata count {} exceeds maximum {}",
                        meta.len(),
                        MAX_A2A_METADATA_ENTRIES
                    ));
                }
            }
            // R262-A2A-1: Validate part content for dangerous characters.
            match &part.content {
                PartContent::File { ref file } => {
                    file.validate()?;
                    if let Some(ref name) = file.name {
                        if vellaveto_types::has_dangerous_chars(name) {
                            return Err("file.name contains dangerous characters".to_string());
                        }
                    }
                    if let Some(ref mime) = file.mime_type {
                        if vellaveto_types::has_dangerous_chars(mime) {
                            return Err("file.mime_type contains dangerous characters".to_string());
                        }
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }
}

/// A2A message classification (mirrors MCP MessageType pattern).
///
/// Used to route incoming A2A JSON-RPC messages to appropriate handlers.
#[derive(Debug, Clone, PartialEq)]
pub enum A2aMessageType {
    /// `message/send` request — primary interaction method.
    MessageSend {
        id: Value,
        task_id: Option<String>,
        message: Value,
    },
    /// `message/stream` request — streaming response (SSE).
    MessageStream {
        id: Value,
        task_id: Option<String>,
        message: Value,
    },
    /// `tasks/get` request — retrieve task status.
    TaskGet { id: Value, task_id: String },
    /// `tasks/cancel` request — cancel a running task.
    TaskCancel { id: Value, task_id: String },
    /// `tasks/resubscribe` request — resubscribe to task events.
    TaskResubscribe { id: Value, task_id: String },
    /// JSON-RPC batch (array) — rejected for security.
    Batch,
    /// Invalid request that should be rejected with an error response.
    Invalid { id: Value, reason: String },
    /// Passthrough (responses, notifications, or other methods).
    PassThrough,
}

/// Normalize an A2A method name for matching.
///
/// Strips trailing slashes, null bytes, and invisible Unicode characters
/// to prevent bypass via `"message/send/"`, `"message/send\0"`, etc.
/// Returns the normalized lowercase form for case-insensitive comparison.
pub fn normalize_a2a_method(method: &str) -> String {
    // SECURITY: Strip ALL invisible/format Unicode characters (same as MCP)
    // to prevent bypass via zero-width characters, bidi overrides, etc.
    method
        .trim()
        .chars()
        .filter(|c| {
            let cp = *c as u32;
            // SECURITY (FIND-R110-001): Also strip C0 (0x00-0x1F) and C1
            // (0x7F-0x9F) control characters to prevent log injection via
            // embedded newlines/carriage returns in method names.
            // Parity with MCP normalize_method() fix FIND-R107-001.
            !(cp <= 0x1F                               // C0 control chars (NUL..US)
                || (0x7F..=0x9F).contains(&cp)         // DEL + C1 control chars
                || (0x200B..=0x200F).contains(&cp)     // zero-width chars
                || (0x202A..=0x202E).contains(&cp)     // bidi overrides
                || (0xFE00..=0xFE0F).contains(&cp)     // variation selectors
                || cp == 0xFEFF                        // BOM / ZWNBSP
                || (0x2060..=0x2064).contains(&cp)     // word joiners / invisible operators
                || (0xFFF9..=0xFFFB).contains(&cp)     // interlinear annotation
                || cp == 0x180E                        // Mongolian vowel separator
                || cp == 0x00AD                        // soft hyphen
                || (0x2066..=0x2069).contains(&cp)     // bidi isolate (LRI, RLI, FSI, PDI)
                || (0xE0000..=0xE007F).contains(&cp)) // tag characters
        })
        .collect::<String>()
        .trim_end_matches('/')
        .to_lowercase()
}

/// Classify an A2A JSON-RPC message.
///
/// Returns the appropriate `A2aMessageType` variant based on the message content.
/// Method names are normalized before matching to prevent bypass attacks.
///
/// # Security
///
/// - Batch requests (JSON arrays) are rejected to prevent TOCTOU attacks
/// - Method names are normalized to prevent bypass via invisible characters
/// - Missing required fields result in `Invalid` rather than silent failures
pub fn classify_a2a_message(msg: &Value) -> A2aMessageType {
    // Reject JSON-RPC batch requests (security hardening)
    if msg.is_array() {
        return A2aMessageType::Batch;
    }

    // Extract method field
    let method = match msg.get("method").and_then(|v| v.as_str()) {
        Some(m) => m,
        None => {
            // No method field — check if it's a JSON-RPC response
            if msg.get("result").is_some() || msg.get("error").is_some() {
                return A2aMessageType::PassThrough;
            }
            let id = msg.get("id").cloned().unwrap_or(Value::Null);
            return A2aMessageType::Invalid {
                id,
                reason: "Missing method field".to_string(),
            };
        }
    };

    let id = msg.get("id").cloned().unwrap_or(Value::Null);
    let params = msg.get("params");
    let normalized = normalize_a2a_method(method);

    match normalized.as_str() {
        "message/send" => {
            let message = params.and_then(|p| p.get("message")).cloned();
            match message {
                Some(m) => {
                    let task_id = params.and_then(|p| p.get("id")).and_then(|v| v.as_str());
                    // SECURITY (FIND-R188-002): Validate task_id when present.
                    if let Some(tid) = task_id {
                        if let Some(reason) = validate_a2a_task_id(tid) {
                            return A2aMessageType::Invalid {
                                id,
                                reason: format!("message/send: {}", reason),
                            };
                        }
                    }
                    A2aMessageType::MessageSend {
                        id,
                        task_id: task_id.map(|s| s.to_string()),
                        message: m,
                    }
                }
                None => A2aMessageType::Invalid {
                    id,
                    reason: "message/send requires message in params".to_string(),
                },
            }
        }
        "message/stream" => {
            let message = params.and_then(|p| p.get("message")).cloned();
            match message {
                Some(m) => {
                    let task_id = params.and_then(|p| p.get("id")).and_then(|v| v.as_str());
                    // SECURITY (FIND-R188-002): Validate task_id when present.
                    if let Some(tid) = task_id {
                        if let Some(reason) = validate_a2a_task_id(tid) {
                            return A2aMessageType::Invalid {
                                id,
                                reason: format!("message/stream: {}", reason),
                            };
                        }
                    }
                    A2aMessageType::MessageStream {
                        id,
                        task_id: task_id.map(|s| s.to_string()),
                        message: m,
                    }
                }
                None => A2aMessageType::Invalid {
                    id,
                    reason: "message/stream requires message in params".to_string(),
                },
            }
        }
        "tasks/get" => {
            let task_id = params.and_then(|p| p.get("id")).and_then(|v| v.as_str());
            match task_id {
                Some(tid) => {
                    // SECURITY (FIND-R188-002): Validate task_id.
                    if let Some(reason) = validate_a2a_task_id(tid) {
                        return A2aMessageType::Invalid {
                            id,
                            reason: format!("tasks/get: {}", reason),
                        };
                    }
                    A2aMessageType::TaskGet {
                        id,
                        task_id: tid.to_string(),
                    }
                }
                None => A2aMessageType::Invalid {
                    id,
                    reason: "tasks/get requires id in params".to_string(),
                },
            }
        }
        "tasks/cancel" => {
            let task_id = params.and_then(|p| p.get("id")).and_then(|v| v.as_str());
            match task_id {
                Some(tid) => {
                    // SECURITY (FIND-R188-002): Validate task_id.
                    if let Some(reason) = validate_a2a_task_id(tid) {
                        return A2aMessageType::Invalid {
                            id,
                            reason: format!("tasks/cancel: {}", reason),
                        };
                    }
                    A2aMessageType::TaskCancel {
                        id,
                        task_id: tid.to_string(),
                    }
                }
                None => A2aMessageType::Invalid {
                    id,
                    reason: "tasks/cancel requires id in params".to_string(),
                },
            }
        }
        "tasks/resubscribe" => {
            let task_id = params.and_then(|p| p.get("id")).and_then(|v| v.as_str());
            match task_id {
                Some(tid) => {
                    // SECURITY (FIND-R188-002): Validate task_id.
                    if let Some(reason) = validate_a2a_task_id(tid) {
                        return A2aMessageType::Invalid {
                            id,
                            reason: format!("tasks/resubscribe: {}", reason),
                        };
                    }
                    A2aMessageType::TaskResubscribe {
                        id,
                        task_id: tid.to_string(),
                    }
                }
                None => A2aMessageType::Invalid {
                    id,
                    reason: "tasks/resubscribe requires id in params".to_string(),
                },
            }
        }
        _ => {
            // Unknown method — pass through (could be notifications, etc.)
            A2aMessageType::PassThrough
        }
    }
}

/// Extract text content from an A2A message for DLP/injection scanning.
///
/// Concatenates all text parts from the message for content inspection.
pub fn extract_text_content(message: &Value) -> Vec<String> {
    let mut texts = Vec::new();

    if let Some(parts) = message.get("parts").and_then(|p| p.as_array()) {
        // SECURITY (IMP-R110-004): Bound iteration to prevent OOM from huge parts arrays.
        for part in parts.iter().take(MAX_A2A_MESSAGE_PARTS) {
            // Check for text type
            if let Some(text_type) = part.get("type").and_then(|t| t.as_str()) {
                if text_type == "text" {
                    if let Some(text) = part.get("text").and_then(|t| t.as_str()) {
                        texts.push(text.to_string());
                    }
                }
            }
        }
    }

    texts
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_task_state_display() {
        assert_eq!(TaskState::Submitted.to_string(), "submitted");
        assert_eq!(TaskState::Working.to_string(), "working");
        assert_eq!(TaskState::InputRequired.to_string(), "input_required");
        assert_eq!(TaskState::Completed.to_string(), "completed");
        assert_eq!(TaskState::Failed.to_string(), "failed");
        assert_eq!(TaskState::Canceled.to_string(), "canceled");
    }

    #[test]
    fn test_task_state_serde() {
        let state = TaskState::Working;
        let json = serde_json::to_string(&state).unwrap();
        assert_eq!(json, "\"working\"");

        let parsed: TaskState = serde_json::from_str("\"input_required\"").unwrap();
        assert_eq!(parsed, TaskState::InputRequired);
    }

    #[test]
    fn test_normalize_method_basic() {
        assert_eq!(normalize_a2a_method("message/send"), "message/send");
        assert_eq!(normalize_a2a_method("MESSAGE/SEND"), "message/send");
        assert_eq!(normalize_a2a_method("message/send/"), "message/send");
        assert_eq!(normalize_a2a_method("  message/send  "), "message/send");
    }

    #[test]
    fn test_normalize_method_invisible_chars() {
        // Zero-width space (U+200B)
        assert_eq!(normalize_a2a_method("message\u{200B}/send"), "message/send");
        // BOM (U+FEFF)
        assert_eq!(normalize_a2a_method("\u{FEFF}message/send"), "message/send");
        // Null byte
        assert_eq!(normalize_a2a_method("message/send\0"), "message/send");
    }

    #[test]
    fn test_classify_message_send() {
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "message/send",
            "params": {
                "message": {
                    "role": "user",
                    "parts": [{"type": "text", "text": "Hello"}]
                }
            }
        });

        match classify_a2a_message(&msg) {
            A2aMessageType::MessageSend {
                id,
                task_id,
                message,
            } => {
                assert_eq!(id, json!(1));
                assert!(task_id.is_none());
                assert!(message.get("role").is_some());
            }
            _ => panic!("Expected MessageSend"),
        }
    }

    #[test]
    fn test_classify_message_send_with_task_id() {
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "message/send",
            "params": {
                "id": "task-123",
                "message": {
                    "role": "user",
                    "parts": [{"type": "text", "text": "Continue"}]
                }
            }
        });

        match classify_a2a_message(&msg) {
            A2aMessageType::MessageSend { task_id, .. } => {
                assert_eq!(task_id, Some("task-123".to_string()));
            }
            _ => panic!("Expected MessageSend"),
        }
    }

    #[test]
    fn test_classify_message_stream() {
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "message/stream",
            "params": {
                "message": {
                    "role": "user",
                    "parts": [{"type": "text", "text": "Stream this"}]
                }
            }
        });

        assert!(matches!(
            classify_a2a_message(&msg),
            A2aMessageType::MessageStream { .. }
        ));
    }

    #[test]
    fn test_classify_tasks_get() {
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tasks/get",
            "params": {
                "id": "task-456"
            }
        });

        match classify_a2a_message(&msg) {
            A2aMessageType::TaskGet { id, task_id } => {
                assert_eq!(id, json!(1));
                assert_eq!(task_id, "task-456");
            }
            _ => panic!("Expected TaskGet"),
        }
    }

    #[test]
    fn test_classify_tasks_cancel() {
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tasks/cancel",
            "params": {
                "id": "task-789"
            }
        });

        assert!(matches!(
            classify_a2a_message(&msg),
            A2aMessageType::TaskCancel { .. }
        ));
    }

    #[test]
    fn test_classify_tasks_resubscribe() {
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tasks/resubscribe",
            "params": {
                "id": "task-abc"
            }
        });

        assert!(matches!(
            classify_a2a_message(&msg),
            A2aMessageType::TaskResubscribe { .. }
        ));
    }

    #[test]
    fn test_classify_batch_rejected() {
        let msg = json!([
            {"jsonrpc": "2.0", "id": 1, "method": "message/send", "params": {}},
            {"jsonrpc": "2.0", "id": 2, "method": "tasks/get", "params": {}}
        ]);

        assert!(matches!(classify_a2a_message(&msg), A2aMessageType::Batch));
    }

    #[test]
    fn test_classify_invalid_missing_method() {
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "params": {}
        });

        assert!(matches!(
            classify_a2a_message(&msg),
            A2aMessageType::Invalid { .. }
        ));
    }

    #[test]
    fn test_classify_invalid_missing_message() {
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "message/send",
            "params": {}
        });

        match classify_a2a_message(&msg) {
            A2aMessageType::Invalid { reason, .. } => {
                assert!(reason.contains("message"));
            }
            _ => panic!("Expected Invalid"),
        }
    }

    #[test]
    fn test_classify_response_passthrough() {
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"status": "ok"}
        });

        assert!(matches!(
            classify_a2a_message(&msg),
            A2aMessageType::PassThrough
        ));
    }

    #[test]
    fn test_classify_error_passthrough() {
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "error": {"code": -32600, "message": "Invalid Request"}
        });

        assert!(matches!(
            classify_a2a_message(&msg),
            A2aMessageType::PassThrough
        ));
    }

    #[test]
    fn test_classify_unknown_method_passthrough() {
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "custom/method",
            "params": {}
        });

        assert!(matches!(
            classify_a2a_message(&msg),
            A2aMessageType::PassThrough
        ));
    }

    #[test]
    fn test_extract_text_content() {
        let message = json!({
            "role": "user",
            "parts": [
                {"type": "text", "text": "Hello"},
                {"type": "file", "file": {"name": "test.txt"}},
                {"type": "text", "text": "World"}
            ]
        });

        let texts = extract_text_content(&message);
        assert_eq!(texts, vec!["Hello", "World"]);
    }

    #[test]
    fn test_extract_text_content_empty() {
        let message = json!({
            "role": "agent",
            "parts": [
                {"type": "file", "file": {"uri": "file:///test.txt"}}
            ]
        });

        let texts = extract_text_content(&message);
        assert!(texts.is_empty());
    }

    /// SECURITY (FIND-R110-001): C0/C1 control chars stripped from A2A methods.
    #[test]
    fn test_normalize_a2a_method_strips_control_characters() {
        // C0: newline, carriage return, tab
        assert_eq!(
            normalize_a2a_method("message/send\nFAKE_LOG"),
            "message/sendfake_log"
        );
        assert_eq!(
            normalize_a2a_method("tasks/get\r\n[CRITICAL]"),
            "tasks/get[critical]"
        );
        assert_eq!(normalize_a2a_method("foo\tbar"), "foobar");
        // DEL (0x7F) and C1 control chars (0x80-0x9F)
        assert_eq!(normalize_a2a_method("foo\x7Fbar"), "foobar");
        assert_eq!(normalize_a2a_method("foo\u{0085}bar"), "foobar"); // NEL
        assert_eq!(normalize_a2a_method("foo\u{009F}bar"), "foobar"); // APC
    }

    // ═══════════════════════════════════════════════════
    // A2A Validation Tests (IMP-R110-004)
    // ═══════════════════════════════════════════════════

    #[test]
    fn test_a2a_message_validate_too_many_parts() {
        let parts: Vec<MessagePart> = (0..1001)
            .map(|i| MessagePart {
                content: PartContent::Text {
                    text: format!("part {}", i),
                },
                metadata: None,
            })
            .collect();
        let msg = A2aMessage {
            role: "user".to_string(),
            parts,
            metadata: None,
        };
        let err = msg.validate().unwrap_err();
        assert!(err.contains("parts count"));
    }

    #[test]
    fn test_a2a_message_validate_too_many_metadata() {
        let mut meta = HashMap::new();
        for i in 0..101 {
            meta.insert(format!("key{}", i), Value::Null);
        }
        let msg = A2aMessage {
            role: "user".to_string(),
            parts: vec![],
            metadata: Some(meta),
        };
        let err = msg.validate().unwrap_err();
        assert!(err.contains("metadata count"));
    }

    #[test]
    fn test_a2a_message_validate_file_bytes_too_large() {
        let big_bytes = "A".repeat(MAX_A2A_FILE_BYTES_LEN + 1);
        let msg = A2aMessage {
            role: "user".to_string(),
            parts: vec![MessagePart {
                content: PartContent::File {
                    file: FileContent {
                        name: None,
                        mime_type: None,
                        bytes: Some(big_bytes),
                        uri: None,
                    },
                },
                metadata: None,
            }],
            metadata: None,
        };
        let err = msg.validate().unwrap_err();
        assert!(err.contains("file.bytes length"));
    }

    #[test]
    fn test_a2a_message_validate_ok() {
        let msg = A2aMessage {
            role: "user".to_string(),
            parts: vec![MessagePart {
                content: PartContent::Text {
                    text: "hello".to_string(),
                },
                metadata: None,
            }],
            metadata: None,
        };
        assert!(msg.validate().is_ok());
    }

    // R262-A2A-1: Dangerous chars in role must be rejected
    #[test]
    fn test_r262_a2a_message_rejects_dangerous_role() {
        let msg = A2aMessage {
            role: "user\u{200B}".to_string(), // zero-width space
            parts: vec![],
            metadata: None,
        };
        let err = msg.validate().unwrap_err();
        assert!(
            err.contains("role") && err.contains("dangerous"),
            "Error: {err}"
        );
    }

    // R262-A2A-1: Dangerous chars in file name must be rejected
    #[test]
    fn test_r262_a2a_message_rejects_dangerous_file_name() {
        let msg = A2aMessage {
            role: "user".to_string(),
            parts: vec![MessagePart {
                content: PartContent::File {
                    file: FileContent {
                        name: Some("test\x00.txt".to_string()),
                        mime_type: None,
                        bytes: None,
                        uri: None,
                    },
                },
                metadata: None,
            }],
            metadata: None,
        };
        assert!(msg.validate().is_err());
    }

    #[test]
    fn test_a2a_message_deny_unknown_fields() {
        let json = r#"{"role":"user","parts":[],"unknown_field":"bad"}"#;
        let result: Result<A2aMessage, _> = serde_json::from_str(json);
        assert!(
            result.is_err(),
            "deny_unknown_fields should reject unknown fields"
        );
    }

    #[test]
    fn test_file_content_deny_unknown_fields() {
        let json = r#"{"name":"test","extra":"bad"}"#;
        let result: Result<FileContent, _> = serde_json::from_str(json);
        assert!(
            result.is_err(),
            "deny_unknown_fields should reject unknown fields"
        );
    }

    #[test]
    fn test_classify_a2a_rejects_oversized_task_id() {
        let long_id = "x".repeat(300);
        let msg = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "tasks/get",
            "id": 1,
            "params": { "id": long_id }
        });
        let result = classify_a2a_message(&msg);
        match result {
            A2aMessageType::Invalid { reason, .. } => {
                assert!(reason.contains("exceeds maximum"), "reason: {reason}");
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn test_classify_a2a_rejects_control_chars_in_task_id() {
        let msg = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "tasks/cancel",
            "id": 1,
            "params": { "id": "task\x00injected" }
        });
        let result = classify_a2a_message(&msg);
        match result {
            A2aMessageType::Invalid { reason, .. } => {
                assert!(reason.contains("control or format"), "reason: {reason}");
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn test_classify_a2a_message_send_valid_task_id() {
        let msg = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "message/send",
            "id": 1,
            "params": {
                "id": "valid-task-123",
                "message": { "role": "user", "parts": [] }
            }
        });
        let result = classify_a2a_message(&msg);
        match result {
            A2aMessageType::MessageSend { task_id, .. } => {
                assert_eq!(task_id.as_deref(), Some("valid-task-123"));
            }
            other => panic!("expected MessageSend, got {other:?}"),
        }
    }

    #[test]
    fn test_classify_a2a_message_send_rejects_bad_task_id() {
        let msg = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "message/send",
            "id": 1,
            "params": {
                "id": "task\u{200B}invisible",
                "message": { "role": "user", "parts": [] }
            }
        });
        let result = classify_a2a_message(&msg);
        match result {
            A2aMessageType::Invalid { reason, .. } => {
                assert!(reason.contains("control or format"), "reason: {reason}");
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn test_part_content_serde() {
        let text = PartContent::Text {
            text: "hello".to_string(),
        };
        let json = serde_json::to_string(&text).unwrap();
        assert!(json.contains("\"type\":\"text\""));
        assert!(json.contains("\"text\":\"hello\""));

        let file = PartContent::File {
            file: FileContent {
                name: Some("test.txt".to_string()),
                mime_type: Some("text/plain".to_string()),
                bytes: None,
                uri: Some("file:///test.txt".to_string()),
            },
        };
        let json = serde_json::to_string(&file).unwrap();
        assert!(json.contains("\"type\":\"file\""));
    }
}
