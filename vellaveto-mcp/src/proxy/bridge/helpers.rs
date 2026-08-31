// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Helper methods for `ProxyBridge`.
//!
//! Agent identity extraction, flagged tool persistence/loading,
//! and tool annotation extraction with rug-pull detection.

use super::ProxyBridge;
use super::ToolAnnotations;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use vellaveto_audit::AuditLogger;
use vellaveto_types::{Action, AgentFingerprint, RuntimeSecurityContext, SinkClass};

impl ProxyBridge {
    fn rpc_meta(msg: &Value) -> Option<&Value> {
        msg.get("_meta")
            .or_else(|| msg.get("params").and_then(|p| p.get("_meta")))
    }

    /// Extract agent fingerprint from MCP message `_meta` field.
    ///
    /// MCP 2025-11-25 allows clients to include identity information in `_meta`.
    /// This extracts fingerprint components if present.
    pub(super) fn extract_fingerprint_from_meta(msg: &Value) -> AgentFingerprint {
        let meta = Self::rpc_meta(msg);

        AgentFingerprint {
            jwt_sub: meta
                .and_then(|m| m.get("agent_id"))
                .or_else(|| meta.and_then(|m| m.get("agentId")))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            jwt_iss: meta
                .and_then(|m| m.get("issuer"))
                .or_else(|| meta.and_then(|m| m.get("iss")))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            client_id: meta
                .and_then(|m| m.get("client_id"))
                .or_else(|| meta.and_then(|m| m.get("clientId")))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            ip_hash: None, // Not available in stdio proxy
        }
    }

    /// Extract claimed agent ID from MCP message.
    ///
    /// SECURITY (FIND-R136-004): Length-capped and control-char-filtered to
    /// prevent log injection and unbounded memory from malicious `_meta.agent_id`.
    pub(super) fn extract_agent_id(msg: &Value) -> Option<String> {
        /// Maximum length for a claimed agent ID from `_meta`.
        /// Matches `MAX_ENV_AGENT_ID_LENGTH` in relay.rs.
        const MAX_CLAIMED_AGENT_ID_LEN: usize = 256;

        let meta = Self::rpc_meta(msg)?;
        let raw = meta
            .get("agent_id")
            .or_else(|| meta.get("agentId"))
            .and_then(|v| v.as_str())?;

        if raw.len() > MAX_CLAIMED_AGENT_ID_LEN {
            tracing::warn!(
                len = raw.len(),
                max = MAX_CLAIMED_AGENT_ID_LEN,
                "claimed agent_id in _meta exceeds maximum length — ignoring"
            );
            return None;
        }
        if vellaveto_types::has_dangerous_chars(raw) {
            tracing::warn!(
                "claimed agent_id in _meta contains control or Unicode format characters — ignoring"
            );
            return None;
        }
        Some(raw.to_string())
    }

    /// Extract a transport-supplied runtime security context from MCP message
    /// metadata and fill in conservative sink classification when missing.
    pub(super) fn build_runtime_security_context(
        msg: &Value,
        action: &Action,
        annotations: Option<&ToolAnnotations>,
    ) -> Option<RuntimeSecurityContext> {
        let mut security_context = Self::extract_runtime_security_context(msg).unwrap_or_default();
        if security_context.sink_class.is_none() {
            security_context.sink_class = Self::infer_sink_class(action, annotations);
        }
        if security_context == RuntimeSecurityContext::default() {
            None
        } else {
            Some(security_context)
        }
    }

    fn extract_runtime_security_context(msg: &Value) -> Option<RuntimeSecurityContext> {
        let meta = Self::rpc_meta(msg)?;
        let candidate = meta
            .get("vellaveto_security_context")
            .or_else(|| meta.get("vellavetoSecurityContext"))?
            .clone();
        match serde_json::from_value::<RuntimeSecurityContext>(candidate) {
            Ok(security_context) => match security_context.validate() {
                Ok(()) => Some(security_context),
                Err(error) => {
                    tracing::warn!(
                        error = %error,
                        "Ignoring invalid vellaveto security context from MCP metadata"
                    );
                    None
                }
            },
            Err(error) => {
                tracing::warn!(
                    error = %error,
                    "Ignoring malformed vellaveto security context from MCP metadata"
                );
                None
            }
        }
    }

    pub(super) fn infer_sink_class(
        action: &Action,
        annotations: Option<&ToolAnnotations>,
    ) -> Option<SinkClass> {
        let tool = action.tool.to_ascii_lowercase();
        let function = action.function.to_ascii_lowercase();
        let destructive_hint = annotations.is_some_and(|ann| ann.destructive_hint);
        let read_only_hint =
            annotations.is_some_and(|ann| ann.read_only_hint && !ann.destructive_hint);

        if action.tool == "resources" && action.function == "read" {
            return Some(SinkClass::ReadOnly);
        }
        if read_only_hint {
            return Some(SinkClass::ReadOnly);
        }
        if Self::contains_security_keyword(&tool, &function, &["approval", "consent", "prompt"]) {
            return Some(SinkClass::ApprovalUi);
        }
        if Self::contains_security_keyword(
            &tool,
            &function,
            &[
                "secret",
                "credential",
                "token",
                "password",
                "apikey",
                "api_key",
                "auth",
            ],
        ) {
            return Some(SinkClass::CredentialAccess);
        }
        if Self::contains_security_keyword(
            &tool,
            &function,
            &["policy", "config", "rule", "governance"],
        ) {
            return Some(SinkClass::PolicyMutation);
        }
        if Self::contains_security_keyword(&tool, &function, &["memory", "memo", "cache", "store"])
        {
            return Some(SinkClass::MemoryWrite);
        }
        if Self::contains_security_keyword(
            &tool,
            &function,
            &[
                "exec", "execute", "run", "shell", "bash", "python", "node", "script", "command",
                "spawn", "terminal",
            ],
        ) {
            return Some(SinkClass::CodeExecution);
        }
        if !action.target_domains.is_empty() {
            return Some(SinkClass::NetworkEgress);
        }
        if !action.target_paths.is_empty() {
            if destructive_hint || Self::looks_like_mutating_action(&tool, &function) {
                return Some(SinkClass::FilesystemWrite);
            }
            return Some(SinkClass::ReadOnly);
        }
        if destructive_hint || Self::looks_like_mutating_action(&tool, &function) {
            return Some(SinkClass::LowRiskWrite);
        }
        if Self::looks_like_read_only_action(&tool, &function) {
            return Some(SinkClass::ReadOnly);
        }
        Some(SinkClass::LowRiskWrite)
    }

    fn contains_security_keyword(tool: &str, function: &str, keywords: &[&str]) -> bool {
        keywords
            .iter()
            .any(|keyword| tool.contains(keyword) || function.contains(keyword))
    }

    fn looks_like_mutating_action(tool: &str, function: &str) -> bool {
        Self::contains_security_keyword(
            tool,
            function,
            &[
                "write", "edit", "update", "delete", "remove", "create", "append", "save", "set",
            ],
        )
    }

    fn looks_like_read_only_action(tool: &str, function: &str) -> bool {
        Self::contains_security_keyword(
            tool,
            function,
            &[
                "read", "get", "list", "fetch", "view", "show", "search", "query",
            ],
        )
    }

    /// Extract a presented approval ID from MCP message `_meta`.
    ///
    /// Accepts both top-level `_meta` and nested `params._meta`, matching the
    /// existing agent-id extraction rules. Length-capped and control-char
    /// filtered so malformed approval IDs fail closed before store lookup.
    pub(super) fn extract_approval_id_from_meta(msg: &Value) -> Option<String> {
        vellaveto_approval::extract_presented_approval_id_from_rpc_meta(msg)
    }

    /// Persist a flagged tool to the JSONL file.
    ///
    /// Appends a single line: `{"tool":"<name>","flagged_at":"<ISO8601>","reason":"<reason>"}`
    /// Does nothing if `flagged_tools_path` is not configured.
    pub(super) async fn persist_flagged_tool(&self, tool_name: &str, reason: &str) {
        let path = match &self.flagged_tools_path {
            Some(p) => p,
            None => return,
        };
        let now = chrono::Utc::now().to_rfc3339();
        let entry = json!({
            "tool": tool_name,
            "flagged_at": now,
            "reason": reason,
        });
        let line = match serde_json::to_string(&entry) {
            Ok(s) => format!("{s}\n"),
            Err(e) => {
                tracing::warn!("Failed to serialize flagged tool entry: {}", e);
                return;
            }
        };
        match tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .await
        {
            Ok(mut file) => {
                use tokio::io::AsyncWriteExt;
                if let Err(e) = file.write_all(line.as_bytes()).await {
                    tracing::warn!("Failed to persist flagged tool '{}': {}", tool_name, e);
                } else if let Err(e) = file.flush().await {
                    tracing::warn!("Failed to flush flagged tool '{}': {}", tool_name, e);
                }
            }
            Err(e) => {
                tracing::warn!("Failed to open flagged tools file: {}", e);
            }
        }
    }

    /// Load previously flagged tools from the JSONL persistence file.
    ///
    /// Returns an empty set if the file does not exist or `flagged_tools_path` is not configured.
    pub(super) async fn load_flagged_tools(&self) -> std::collections::HashSet<String> {
        let path = match &self.flagged_tools_path {
            Some(p) => p,
            None => return std::collections::HashSet::new(),
        };

        // SECURITY (FIND-R80-001): Check file size before reading to prevent OOM
        // from a maliciously large flagged-tools file. Cap at 10 MB which is generous
        // for 10,000 JSONL entries (~100 bytes each ≈ 1 MB).
        const MAX_FLAGGED_FILE_SIZE: u64 = 10 * 1024 * 1024;
        match tokio::fs::metadata(path).await {
            Ok(meta) => {
                if meta.len() > MAX_FLAGGED_FILE_SIZE {
                    tracing::error!(
                        "Flagged tools file {:?} exceeds max size ({} > {} bytes); skipping load",
                        path,
                        meta.len(),
                        MAX_FLAGGED_FILE_SIZE
                    );
                    return std::collections::HashSet::new();
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return std::collections::HashSet::new();
            }
            Err(e) => {
                tracing::warn!("Failed to stat flagged tools file: {}", e);
                return std::collections::HashSet::new();
            }
        }

        let contents = match tokio::fs::read_to_string(path).await {
            Ok(c) => c,
            Err(e) => {
                if e.kind() != std::io::ErrorKind::NotFound {
                    tracing::warn!("Failed to read flagged tools file: {}", e);
                }
                return std::collections::HashSet::new();
            }
        };
        let mut tools = std::collections::HashSet::new();
        for line in contents.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            // SECURITY (FIND-R80-001): Cap loaded entries at MAX_FLAGGED_TOOLS
            // for parity with runtime flag_tool() insertion bounds.
            if tools.len() >= super::relay::MAX_FLAGGED_TOOLS {
                tracing::warn!(
                    "Flagged tools file has more than {} entries; truncating load",
                    super::relay::MAX_FLAGGED_TOOLS
                );
                break;
            }
            match serde_json::from_str::<Value>(line) {
                Ok(entry) => {
                    if let Some(tool) = entry.get("tool").and_then(|t| t.as_str()) {
                        tools.insert(tool.to_string());
                    }
                }
                Err(e) => {
                    tracing::warn!("Skipping malformed flagged-tools line: {}", e);
                }
            }
        }
        if !tools.is_empty() {
            tracing::info!(
                "Loaded {} previously flagged tools from {:?}",
                tools.len(),
                path
            );
        }
        tools
    }

    /// Extract tool annotations from a `tools/list` response.
    ///
    /// Parses the response result, extracts annotations per tool, and detects
    /// rug-pull attacks (tool definitions changing between calls).
    ///
    /// When rug-pull is detected (annotation changes or new tools added after
    /// the initial `tools/list`), affected tool names are inserted into
    /// `flagged_tools` so the proxy can block subsequent calls to them.
    pub(super) async fn extract_tool_annotations(
        response: &Value,
        known: &mut HashMap<String, ToolAnnotations>,
        flagged_tools: &mut std::collections::HashSet<String>,
        audit: &AuditLogger,
        known_tools: &HashSet<String>,
    ) {
        let is_first_list = known.is_empty();
        let result = crate::rug_pull::detect_rug_pull_and_squatting(
            response,
            known,
            is_first_list,
            known_tools,
        );

        // Flag detected tools for blocking
        // SECURITY (FIND-R46-007): Bounded insertion.
        for name in result.flagged_tool_names() {
            if flagged_tools.len() < super::relay::MAX_FLAGGED_TOOLS {
                flagged_tools.insert(name.to_string());
            } else {
                tracing::warn!(
                    "flagged_tools at capacity ({}); cannot flag tool '{}'",
                    super::relay::MAX_FLAGGED_TOOLS,
                    name
                );
                break;
            }
        }

        // Audit any detected events
        crate::rug_pull::audit_rug_pull_events(&result, audit, "proxy").await;

        // Update known annotations from detection result.
        // SECURITY (FIND-R46-007): Cap known_tool_annotations to prevent OOM.
        // If the updated set exceeds the cap, keep only the first N entries
        // (insertion order is not guaranteed for HashMap, but we bound the size).
        *known = result.updated_known;
        if known.len() > super::relay::MAX_KNOWN_TOOL_ANNOTATIONS {
            let excess = known.len() - super::relay::MAX_KNOWN_TOOL_ANNOTATIONS;
            let keys_to_remove: Vec<String> = known.keys().take(excess).cloned().collect();
            for key in keys_to_remove {
                known.remove(&key);
            }
            tracing::warn!(
                "known_tool_annotations exceeded cap ({}); evicted {} entries",
                super::relay::MAX_KNOWN_TOOL_ANNOTATIONS,
                excess
            );
        }
    }
}
