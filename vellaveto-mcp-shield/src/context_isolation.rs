// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella

//! Context window isolation — prevents cross-session context leakage.
//!
//! Each session starts with a clean context. If the user wants continuity,
//! the Shield provides it locally: relevant context from LOCAL history is
//! injected into the new session's prompt. The provider sees a fresh user
//! every session.
//!
//! Local context is stored using the encrypted audit store and is never
//! sent to the provider in linkable form.

use crate::error::ShieldError;
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

/// Maximum number of context entries per session.
const MAX_CONTEXT_ENTRIES: usize = 1_000;

/// Maximum total sessions tracked for context isolation.
const MAX_CONTEXT_SESSIONS: usize = 10_000;

/// Maximum length of a single context entry text (64 KB).
const MAX_CONTEXT_ENTRY_LEN: usize = 65_536;

/// Maximum total context bytes across all entries in a session (1 MB).
const MAX_CONTEXT_TOTAL_BYTES: usize = 1_048_576;

/// A single piece of conversation context.
struct ContextEntry {
    /// The role: "user" or "assistant".
    role: String,
    /// The text content (sanitized — no PII).
    text: String,
    /// Monotonic sequence number within the session.
    #[allow(dead_code)]
    sequence: u64,
}

/// Per-session context state.
struct SessionContext {
    entries: VecDeque<ContextEntry>,
    total_bytes: usize,
    next_sequence: u64,
}

impl SessionContext {
    fn new() -> Self {
        Self {
            entries: VecDeque::new(),
            total_bytes: 0,
            next_sequence: 0,
        }
    }
}

/// Manages per-session context isolation.
///
/// Ensures that:
/// 1. Each session has an independent context window
/// 2. Context is never shared between sessions at the provider level
/// 3. Local context history is maintained for user convenience
/// 4. All stored context is PII-sanitized (should be run AFTER QuerySanitizer)
pub struct ContextIsolator {
    sessions: Mutex<HashMap<String, SessionContext>>,
    max_entries: usize,
    max_sessions: usize,
}

impl ContextIsolator {
    /// Create a new context isolator with default bounds.
    pub fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            max_entries: MAX_CONTEXT_ENTRIES,
            max_sessions: MAX_CONTEXT_SESSIONS,
        }
    }

    /// Create with custom limits.
    pub fn with_limits(max_entries: usize, max_sessions: usize) -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            max_entries: max_entries.min(MAX_CONTEXT_ENTRIES),
            max_sessions: max_sessions.min(MAX_CONTEXT_SESSIONS),
        }
    }

    /// Record a context entry for a session (e.g., a user message or assistant response).
    ///
    /// Text should already be PII-sanitized before calling this.
    pub fn record(&self, session_id: &str, role: &str, text: &str) -> Result<(), ShieldError> {
        if text.len() > MAX_CONTEXT_ENTRY_LEN {
            return Err(ShieldError::Config(format!(
                "context entry too large ({} bytes, max {})",
                text.len(),
                MAX_CONTEXT_ENTRY_LEN
            )));
        }

        let mut sessions = self
            .sessions
            .lock()
            .map_err(|e| ShieldError::SessionIsolation(format!("context lock poisoned: {e}")))?;

        // Create session if needed
        if !sessions.contains_key(session_id) {
            if sessions.len() >= self.max_sessions {
                return Err(ShieldError::SessionIsolation(
                    "context session capacity exhausted (fail-closed)".to_string(),
                ));
            }
            sessions.insert(session_id.to_string(), SessionContext::new());
        }

        let ctx = sessions.get_mut(session_id).ok_or_else(|| {
            ShieldError::SessionIsolation("session not found after insert".to_string())
        })?;

        // Check total bytes limit
        if ctx.total_bytes.saturating_add(text.len()) > MAX_CONTEXT_TOTAL_BYTES {
            // Evict oldest entries to make room
            while ctx.total_bytes.saturating_add(text.len()) > MAX_CONTEXT_TOTAL_BYTES {
                if let Some(old) = ctx.entries.pop_front() {
                    ctx.total_bytes = ctx.total_bytes.saturating_sub(old.text.len());
                } else {
                    break;
                }
            }
        }

        // Enforce entry count limit
        while ctx.entries.len() >= self.max_entries {
            if let Some(old) = ctx.entries.pop_front() {
                ctx.total_bytes = ctx.total_bytes.saturating_sub(old.text.len());
            }
        }

        let seq = ctx.next_sequence;
        ctx.next_sequence = ctx.next_sequence.saturating_add(1);
        ctx.total_bytes = ctx.total_bytes.saturating_add(text.len());

        ctx.entries.push_back(ContextEntry {
            role: role.to_string(),
            text: text.to_string(),
            sequence: seq,
        });

        Ok(())
    }

    /// Get the last N context entries for a session (for local context injection).
    ///
    /// Returns entries in chronological order. These can be injected into
    /// a new session's system prompt so the user gets continuity without
    /// the provider linking sessions.
    pub fn get_recent_context(
        &self,
        session_id: &str,
        max_entries: usize,
    ) -> Result<Vec<(String, String)>, ShieldError> {
        let sessions = self
            .sessions
            .lock()
            .map_err(|e| ShieldError::SessionIsolation(format!("context lock poisoned: {e}")))?;

        let ctx = sessions.get(session_id).ok_or_else(|| {
            ShieldError::SessionIsolation(format!("unknown context session: {session_id}"))
        })?;

        let entries: Vec<(String, String)> = ctx
            .entries
            .iter()
            .rev()
            .take(max_entries)
            .map(|e| (e.role.clone(), e.text.clone()))
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();

        Ok(entries)
    }

    /// Get the total number of context entries in a session.
    pub fn entry_count(&self, session_id: &str) -> usize {
        self.sessions
            .lock()
            .ok()
            .and_then(|s| s.get(session_id).map(|ctx| ctx.entries.len()))
            .unwrap_or(0)
    }

    /// End a session's context, clearing all stored entries.
    pub fn end_session(&self, session_id: &str) {
        if let Ok(mut sessions) = self.sessions.lock() {
            sessions.remove(session_id);
        }
    }

    /// Get the number of active context sessions.
    pub fn session_count(&self) -> usize {
        self.sessions.lock().map(|s| s.len()).unwrap_or(0)
    }

    /// Record context from a JSON-RPC response message.
    ///
    /// Extracts text content from the response result/error and records it.
    /// Only processes responses with `result` or `error` fields.
    pub fn record_json_response(
        &self,
        session_id: &str,
        msg: &serde_json::Value,
    ) -> Result<(), ShieldError> {
        // Extract text from result.content[].text or error.message
        let text = if let Some(result) = msg.get("result") {
            extract_text_from_result(result)
        } else if let Some(error) = msg.get("error") {
            error
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("")
                .to_string()
        } else {
            return Ok(());
        };

        if text.is_empty() {
            return Ok(());
        }

        self.record(session_id, "assistant", &text)
    }

    /// Record context from a JSON-RPC request message (user side).
    ///
    /// Extracts the tool name and arguments as context.
    pub fn record_json_request(
        &self,
        session_id: &str,
        msg: &serde_json::Value,
    ) -> Result<(), ShieldError> {
        let method = msg
            .get("method")
            .and_then(|m| m.as_str())
            .unwrap_or("unknown");
        let params = msg
            .get("params")
            .and_then(|p| serde_json::to_string(p).ok())
            .unwrap_or_default();

        // Truncate params to avoid huge context entries
        let truncated: String = params.chars().take(4096).collect();
        let text = format!("[{method}] {truncated}");

        self.record(session_id, "user", &text)
    }
}

/// Extract text content from a JSON-RPC result value.
///
/// Handles common MCP response formats:
/// - `result.content[].text` (tool call results)
/// - `result.text` (simple text responses)
/// - `result` as string directly
fn extract_text_from_result(result: &serde_json::Value) -> String {
    // Try result.content[].text (MCP tool result format)
    if let Some(content) = result.get("content").and_then(|c| c.as_array()) {
        let texts: Vec<&str> = content
            .iter()
            .filter_map(|item| item.get("text").and_then(|t| t.as_str()))
            .collect();
        if !texts.is_empty() {
            return texts.join("\n");
        }
    }

    // Try result.text
    if let Some(text) = result.get("text").and_then(|t| t.as_str()) {
        return text.to_string();
    }

    // Try result as string directly
    if let Some(s) = result.as_str() {
        return s.to_string();
    }

    String::new()
}

impl Default for ContextIsolator {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for ContextIsolator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ContextIsolator")
            .field("session_count", &self.session_count())
            .field("max_entries", &self.max_entries)
            .finish()
    }
}
