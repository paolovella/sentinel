// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Bidirectional relay loop for `ProxyBridge`.
//!
//! Contains the `run()` method and its handler methods for each message type.
//! The relay sits between agent stdin/stdout and child MCP server,
//! evaluating every tool call, resource read, and task request against policies.

use super::ProxyBridge;
use super::ToolAnnotations;
use crate::extractor::{
    classify_message, extract_action, extract_extension_action, extract_resource_action,
    extract_task_action, make_batch_error_response, make_denial_response, make_invalid_response,
    MessageType,
};
use crate::framing::{read_message, write_message};
use crate::inspection::{
    scan_notification_for_injection, scan_notification_for_secrets, scan_parameters_for_secrets,
    scan_response_for_injection, scan_response_for_secrets, scan_tool_descriptions,
    scan_tool_descriptions_with_scanner,
};
use crate::output_validation::ValidationResult;
use crate::proxy::types::{ProxyDecision, ProxyError};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};
use tokio::io::BufReader;
use tokio::process::{ChildStdin, ChildStdout};
use vellaveto_config::ToolManifest;
use vellaveto_types::{Action, EvaluationContext, EvaluationTrace, Verdict};

/// Resolve target domains to IP addresses for DNS rebinding protection.
///
/// Populates `action.resolved_ips` with the IP addresses that each target domain
/// resolves to. If DNS resolution fails for a domain, no IPs are added for it —
/// the engine will deny the action fail-closed if IP rules are configured.
///
/// SECURITY (FIND-R78-001): Parity with HTTP/WS/gRPC proxy handlers.
async fn resolve_domains(action: &mut Action) {
    if action.target_domains.is_empty() {
        return;
    }
    let mut resolved = Vec::new();
    for domain in &action.target_domains {
        // SECURITY (FIND-R80-004): Stop resolving if we've hit the cap.
        if resolved.len() >= MAX_RESOLVED_IPS {
            tracing::warn!(
                "Resolved IPs capped at {} — skipping remaining domains",
                MAX_RESOLVED_IPS
            );
            break;
        }
        // Strip port if present (domain might be "example.com:8080")
        let host = domain.split(':').next().unwrap_or(domain);
        match tokio::net::lookup_host((host, 0)).await {
            Ok(addrs) => {
                for addr in addrs {
                    if resolved.len() >= MAX_RESOLVED_IPS {
                        tracing::warn!(
                            domain = %domain,
                            cap = MAX_RESOLVED_IPS,
                            "Resolved IPs cap reached during DNS lookup — truncating"
                        );
                        break;
                    }
                    resolved.push(addr.ip().to_string());
                }
            }
            Err(e) => {
                tracing::warn!(
                    domain = %domain,
                    error = %e,
                    "DNS resolution failed — resolved_ips will be empty for this domain"
                );
                // Fail-closed: engine will deny if ip_rules configured but no IPs resolved
            }
        }
    }
    action.resolved_ips = resolved;
}

/// SECURITY (FIND-R80-004): Maximum number of resolved IPs from DNS lookups.
/// A domain with many A/AAAA records could return hundreds of IPs. Cap to
/// prevent unbounded memory growth.
const MAX_RESOLVED_IPS: usize = 100;

/// SECURITY (R8-MCP-8): Maximum number of pending (in-flight) requests.
/// Prevents OOM if an agent sends requests faster than the server responds.
const MAX_PENDING_REQUESTS: usize = 1000;

/// Maximum action history entries for context-aware evaluation.
const MAX_ACTION_HISTORY: usize = 100;

/// Initial capacity for pending request tracking.
const INITIAL_PENDING_REQUEST_CAPACITY: usize = 256;

/// Initial capacity for tool state tracking.
const INITIAL_TOOL_STATE_CAPACITY: usize = 128;

/// Initial capacity for call count tracking.
const INITIAL_CALL_COUNTS_CAPACITY: usize = 128;

/// SECURITY (FIND-R46-003): Maximum entries for tools_list_request_ids and
/// initialize_request_ids tracking sets. Prevents unbounded growth / OOM.
const MAX_REQUEST_TRACKING_IDS: usize = 1000;

/// SECURITY (FIND-R46-007): Maximum entries for known_tool_annotations.
pub(super) const MAX_KNOWN_TOOL_ANNOTATIONS: usize = 10_000;

/// SECURITY (FIND-R46-007): Maximum entries for flagged_tools.
pub(super) const MAX_FLAGGED_TOOLS: usize = 10_000;

/// SECURITY (FIND-R46-010): Maximum entries for call_counts.
const MAX_CALL_COUNTS: usize = 10_000;

/// SECURITY (FIND-R80-003): Maximum length for VELLAVETO_AGENT_ID env var.
/// Matches vellaveto-config/src/governance.rs::MAX_AGENT_ID_LENGTH.
const MAX_ENV_AGENT_ID_LENGTH: usize = 256;

/// SECURITY (FIND-R46-011): Maximum channel buffer for child→agent relay.
/// Each buffered message can be up to ~1MB; keeping the buffer small
/// bounds worst-case memory to ~4MB instead of ~256MB.
const RELAY_CHANNEL_BUFFER: usize = 64;

/// SECURITY (FIND-R46-011): Maximum size (in bytes) of a single serialized
/// JSON-RPC message accepted from the child server. Messages exceeding
/// this limit are dropped with a warning.
const MAX_RELAY_MESSAGE_SIZE: usize = 4 * 1024 * 1024; // 4 MB

/// SECURITY (FIND-R212-012): Interval between pending-request timeout sweeps.
/// Named constant (was hard-coded 5s) so it can be tuned for latency-sensitive
/// deployments without code changes.
const SWEEP_TIMEOUT_INTERVAL_SECS: u64 = 5;

/// Bundled mutable I/O handles for the relay loop.
///
/// Groups agent-side and child-side writers to reduce handler argument counts.
struct IoWriters<'a> {
    agent: &'a mut tokio::io::Stdout,
    child: &'a mut ChildStdin,
}

/// Tracks a pending (in-flight) request for timeout, circuit breaker,
/// and decision explanation plumbing.
struct PendingRequest {
    /// When the request was sent to the child server.
    sent_at: Instant,
    /// Tool or method name.
    tool_name: String,
    /// Evaluation trace (when tracing enabled), for Art 50(2) explanation injection.
    trace: Option<EvaluationTrace>,
}

/// Mutable session state for the relay loop.
///
/// Groups all per-session mutable variables that are threaded through
/// the handler methods during the bidirectional message relay.
pub(super) struct RelayState {
    /// Pending request IDs for timeout detection and circuit breaker recording.
    /// Key: serialized JSON-RPC id, Value: PendingRequest.
    pending_requests: HashMap<String, PendingRequest>,
    /// Track tools/list request IDs so we can intercept responses.
    tools_list_request_ids: HashSet<String>,
    /// Known tool annotations for rug-pull detection.
    known_tool_annotations: HashMap<String, ToolAnnotations>,
    /// Track initialize request IDs for protocol version negotiation.
    initialize_request_ids: HashSet<String>,
    /// Negotiated MCP protocol version.
    negotiated_protocol_version: Option<String>,
    /// Rug-pulled tools flagged for blocking.
    flagged_tools: HashSet<String>,
    /// Pinned tool manifest for schema verification.
    pinned_manifest: Option<ToolManifest>,
    /// Memory poisoning defense tracker.
    memory_tracker: crate::memory_tracking::MemoryTracker,
    /// Context-aware evaluation call counts.
    call_counts: HashMap<String, u64>,
    /// Context-aware evaluation action history.
    action_history: VecDeque<String>,
    /// Elicitation rate limiting counter (per session/proxy lifetime).
    elicitation_count: u32,
    /// Sampling rate limiting counter (per session/proxy lifetime).
    /// SECURITY (FIND-R125-001): Parity with elicitation rate limiting.
    sampling_count: u32,
    /// SECURITY (FIND-R46-013): Cached agent_id from environment variable.
    /// Set once at relay start from `VELLAVETO_AGENT_ID` env var.
    agent_id: Option<String>,
    /// R227: Server name from initialize response for discovery engine.
    server_name: Option<String>,
    /// R227: Per-tool sampling call timestamps for rate limiting.
    /// Key: tool name, Value: timestamps of sampling calls within the window.
    sampling_per_tool: HashMap<String, VecDeque<Instant>>,
}

impl RelayState {
    pub(super) fn new(flagged_tools: HashSet<String>) -> Self {
        // SECURITY (FIND-R46-013): Read agent_id from environment variable.
        // In stdio proxy mode, there is no OAuth/HTTP header to extract an agent_id
        // from, so we allow operators to set it via VELLAVETO_AGENT_ID.
        let agent_id = std::env::var("VELLAVETO_AGENT_ID").ok().and_then(|v| {
            let trimmed = v.trim().to_string();
            if trimmed.is_empty() {
                return None;
            }
            // SECURITY (FIND-R80-003): Validate the env var for length, control chars,
            // and Unicode format chars. If invalid, log a warning and fall back to None.
            if trimmed.len() > MAX_ENV_AGENT_ID_LENGTH {
                tracing::warn!(
                    len = trimmed.len(),
                    max = MAX_ENV_AGENT_ID_LENGTH,
                    "VELLAVETO_AGENT_ID exceeds maximum length — ignoring"
                );
                return None;
            }
            if vellaveto_types::has_dangerous_chars(&trimmed) {
                tracing::warn!(
                    "VELLAVETO_AGENT_ID contains control or Unicode format characters — ignoring"
                );
                return None;
            }
            Some(trimmed)
        });
        if agent_id.is_none() {
            tracing::warn!(
                "SECURITY (FIND-R46-013): agent_id is None in stdio proxy. \
                 Set VELLAVETO_AGENT_ID environment variable to identify the agent \
                 for context-aware policy evaluation."
            );
        } else {
            tracing::info!(
                agent_id = agent_id.as_deref().unwrap_or(""),
                "Stdio proxy agent_id set from VELLAVETO_AGENT_ID"
            );
        }

        Self {
            pending_requests: HashMap::with_capacity(INITIAL_PENDING_REQUEST_CAPACITY),
            tools_list_request_ids: HashSet::with_capacity(INITIAL_PENDING_REQUEST_CAPACITY),
            known_tool_annotations: HashMap::with_capacity(INITIAL_TOOL_STATE_CAPACITY),
            initialize_request_ids: HashSet::with_capacity(INITIAL_PENDING_REQUEST_CAPACITY),
            negotiated_protocol_version: None,
            flagged_tools,
            pinned_manifest: None,
            memory_tracker: crate::memory_tracking::MemoryTracker::new(),
            call_counts: HashMap::with_capacity(INITIAL_CALL_COUNTS_CAPACITY),
            action_history: VecDeque::with_capacity(MAX_ACTION_HISTORY),
            elicitation_count: 0,
            sampling_count: 0,
            agent_id,
            server_name: None,
            sampling_per_tool: HashMap::new(),
        }
    }

    /// R227: Get the most recently dispatched tool name from pending requests.
    /// Used to attribute sampling/elicitation calls to the tool that triggered them.
    fn current_tool_name(&self) -> Option<&str> {
        self.pending_requests
            .values()
            .max_by_key(|pr| pr.sent_at)
            .map(|pr| pr.tool_name.as_str())
    }

    /// Maximum number of distinct tool names tracked for per-tool sampling limits.
    /// Prevents unbounded HashMap growth from attacker-supplied unique tool names.
    const MAX_SAMPLING_PER_TOOL_ENTRIES: usize = 10_000;

    /// R227: Check per-tool sampling rate limit. Returns Ok(()) if allowed,
    /// Err(reason) if the tool has exceeded its sampling budget.
    pub(super) fn check_per_tool_sampling_limit(
        &mut self,
        tool_name: &str,
        max_per_tool: u32,
        window_secs: u64,
    ) -> Result<(), String> {
        if max_per_tool == 0 {
            return Ok(()); // Per-tool limiting disabled
        }

        // R228-PROXY-1: Bound the per-tool tracking HashMap to prevent memory
        // exhaustion from attacker-supplied unique tool names.
        if self.sampling_per_tool.len() >= Self::MAX_SAMPLING_PER_TOOL_ENTRIES
            && !self.sampling_per_tool.contains_key(tool_name)
        {
            return Err("per-tool sampling tracking at capacity".to_string());
        }

        let now = Instant::now();
        let window = Duration::from_secs(window_secs);
        let entry = self
            .sampling_per_tool
            .entry(tool_name.to_string())
            .or_default();

        // Prune expired entries
        while entry
            .front()
            .is_some_and(|&t| now.duration_since(t) > window)
        {
            entry.pop_front();
        }

        if entry.len() >= max_per_tool as usize {
            return Err(format!(
                "per-tool sampling rate limit exceeded for '{}' ({}/{} in {}s window)",
                vellaveto_types::sanitize_for_log(tool_name, 64),
                entry.len(),
                max_per_tool,
                window_secs
            ));
        }

        entry.push_back(now);
        Ok(())
    }

    /// Build an EvaluationContext from the current session state.
    fn evaluation_context(&self) -> EvaluationContext {
        EvaluationContext {
            timestamp: None,
            agent_id: self.agent_id.clone(),
            agent_identity: None,
            call_counts: self.call_counts.clone(),
            previous_actions: self.action_history.iter().cloned().collect(),
            call_chain: Vec::new(),
            tenant_id: None,
            verification_tier: None,
            capability_token: None,
            session_state: None,
        }
    }

    /// SECURITY (FIND-R46-007): Insert into flagged_tools with capacity check.
    fn flag_tool(&mut self, name: String) {
        if self.flagged_tools.len() < MAX_FLAGGED_TOOLS {
            self.flagged_tools.insert(name);
        } else {
            tracing::warn!(
                "flagged_tools at capacity ({}); cannot flag tool '{}'",
                MAX_FLAGGED_TOOLS,
                name
            );
        }
    }

    /// Record a successful forward for context tracking.
    fn record_forwarded_action(&mut self, action_name: &str) {
        // SECURITY (FIND-R180-004): Truncate per-key to prevent unbounded string
        // memory in call_counts HashMap keys and action_history entries.
        const MAX_ACTION_NAME_LEN: usize = 256;
        let bounded_name: String = action_name.chars().take(MAX_ACTION_NAME_LEN).collect();

        // SECURITY (FIND-R46-010): Cap call_counts to prevent OOM from
        // unbounded unique tool/method names.
        if let Some(count) = self.call_counts.get_mut(bounded_name.as_str()) {
            *count = count.saturating_add(1);
        } else if self.call_counts.len() < MAX_CALL_COUNTS {
            self.call_counts.insert(bounded_name.clone(), 1);
        } else {
            tracing::warn!(
                "call_counts at capacity ({}); not tracking '{}'",
                MAX_CALL_COUNTS,
                vellaveto_types::sanitize_for_log(action_name, 64),
            );
        }
        if self.action_history.len() >= MAX_ACTION_HISTORY {
            self.action_history.pop_front();
        }
        self.action_history.push_back(bounded_name);
    }

    /// Track a pending request for timeout detection.
    fn track_pending_request(
        &mut self,
        id: &Value,
        tool_name: String,
        trace: Option<EvaluationTrace>,
    ) {
        /// SECURITY (FIND-R112-003): Maximum length for a pending request ID key.
        /// Prevents memory exhaustion from oversized JSON-RPC request IDs.
        const MAX_REQUEST_ID_KEY_LEN: usize = 1024;

        if !id.is_null() {
            let id_key = id.to_string();
            if id_key.len() > MAX_REQUEST_ID_KEY_LEN {
                tracing::warn!("dropping oversized request id key ({} bytes)", id_key.len());
                return;
            }
            // SECURITY (FIND-R210-001): Reject duplicate in-flight request IDs.
            // A silent HashMap::insert overwrite would corrupt the pending entry,
            // causing response attribution to the wrong tool and circuit breaker
            // state corruption.
            if self.pending_requests.contains_key(&id_key) {
                tracing::warn!(
                    "SECURITY: duplicate in-flight request ID detected (tool={}); keeping original entry",
                    tool_name
                );
                return;
            }
            if self.pending_requests.len() < MAX_PENDING_REQUESTS {
                self.pending_requests.insert(
                    id_key,
                    PendingRequest {
                        sent_at: Instant::now(),
                        tool_name,
                        trace,
                    },
                );
            } else {
                tracing::warn!(
                    "Pending request limit reached ({}), not tracking request",
                    MAX_PENDING_REQUESTS
                );
            }
        }
    }
}

impl ProxyBridge {
    /// Run the bidirectional proxy loop.
    ///
    /// Reads messages from `agent_reader` (the agent's stdout, our stdin),
    /// evaluates tool calls, forwards allowed messages to `child_stdin`,
    /// and relays responses from `child_stdout` back to `agent_writer` (our stdout).
    ///
    /// Tracks forwarded request IDs and times them out if the child doesn't
    /// respond within `request_timeout`.
    pub async fn run(
        &self,
        agent_reader: tokio::io::Stdin,
        mut agent_writer: tokio::io::Stdout,
        mut child_stdin: ChildStdin,
        child_stdout: ChildStdout,
    ) -> Result<(), ProxyError> {
        let mut agent_reader = BufReader::new(agent_reader);
        let mut child_reader = BufReader::new(child_stdout);

        // Phase 4B: Load previously persisted flagged tools on startup.
        let mut state = RelayState::new(self.load_flagged_tools().await);
        let mut io = IoWriters {
            agent: &mut agent_writer,
            child: &mut child_stdin,
        };

        // Spawn a task to relay child → agent responses
        // SECURITY (FIND-R46-011): Reduced buffer from 256 to RELAY_CHANNEL_BUFFER (64)
        // to bound worst-case memory. Each message is also size-checked before sending.
        let (response_tx, mut response_rx) =
            tokio::sync::mpsc::channel::<Value>(RELAY_CHANNEL_BUFFER);

        let relay_handle = tokio::spawn(async move {
            loop {
                match read_message(&mut child_reader).await {
                    Ok(Some(msg)) => {
                        // SECURITY (FIND-R46-011): Drop oversized messages from child
                        // to prevent memory exhaustion via large responses filling the
                        // channel buffer.
                        let estimated_size = msg.to_string().len();
                        if estimated_size > MAX_RELAY_MESSAGE_SIZE {
                            tracing::warn!(
                                "SECURITY: Dropping oversized child response ({} bytes, max {})",
                                estimated_size,
                                MAX_RELAY_MESSAGE_SIZE,
                            );
                            continue;
                        }
                        if response_tx.send(msg).await.is_err() {
                            break;
                        }
                    }
                    Ok(None) => break, // Child closed stdout
                    Err(e) => {
                        tracing::error!("Error reading from child: {}", e);
                        break;
                    }
                }
            }
        });

        // Timer for periodic timeout sweeps
        let mut timeout_interval =
            tokio::time::interval(Duration::from_secs(SWEEP_TIMEOUT_INTERVAL_SECS));
        timeout_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        // Main loop: read from agent, evaluate, forward or block
        loop {
            tokio::select! {
                // Message from agent
                agent_msg = read_message(&mut agent_reader) => {
                    match agent_msg {
                        Ok(Some(msg)) => {
                            self.handle_agent_message(
                                msg, &mut state, &mut io,
                            ).await?;
                        }
                        Ok(None) => {
                            tracing::info!("Agent closed connection");
                            break;
                        }
                        Err(e) => {
                            tracing::error!("Error reading from agent: {}", e);
                            break;
                        }
                    }
                }
                // Response from child
                child_msg = response_rx.recv() => {
                    match child_msg {
                        Some(msg) => {
                            self.handle_child_response(
                                msg, &mut state, &mut io,
                            ).await?;
                        }
                        None => {
                            self.handle_child_terminated(
                                &mut state, io.agent,
                            ).await?;
                            break;
                        }
                    }
                }
                // Periodic timeout sweep
                _ = timeout_interval.tick() => {
                    self.sweep_timeouts(&mut state, io.agent).await;
                }
            }
        }

        relay_handle.abort();
        Ok(())
    }

    /// Handle a message received from the agent.
    async fn handle_agent_message(
        &self,
        msg: Value,
        state: &mut RelayState,
        io: &mut IoWriters<'_>,
    ) -> Result<(), ProxyError> {
        match classify_message(&msg) {
            MessageType::ToolCall {
                id,
                tool_name,
                arguments,
            } => {
                self.handle_tool_call(msg, id, tool_name, arguments, state, io)
                    .await
            }
            MessageType::ResourceRead { id, uri } => {
                self.handle_resource_read(msg, id, uri, state, io).await
            }
            MessageType::SamplingRequest { id } => {
                self.handle_sampling_request(&msg, id, state, io.agent)
                    .await
            }
            MessageType::ElicitationRequest { id } => {
                self.handle_elicitation_request(&msg, id, state, io.agent)
                    .await
            }
            MessageType::TaskRequest {
                id,
                task_method,
                task_id,
            } => {
                self.handle_task_request(msg, id, task_method, task_id, state, io)
                    .await
            }
            MessageType::Batch => {
                // MCP 2025-06-18: batching removed from spec.
                let response = make_batch_error_response();
                tracing::warn!("Rejected JSON-RPC batch request");
                // SECURITY (FIND-R92-002): Audit batch rejection for parity with
                // HTTP proxy (handlers.rs:2331-2351).
                let batch_action = extract_action("vellaveto", &json!({"event": "batch_rejected"}));
                if let Err(e) = self
                    .audit
                    .log_entry(
                        &batch_action,
                        &Verdict::Deny {
                            reason: "JSON-RPC batching not supported".to_string(),
                        },
                        json!({"source": "proxy", "event": "batch_rejected"}),
                    )
                    .await
                {
                    tracing::warn!("Failed to audit batch rejection: {}", e);
                }
                write_message(io.agent, &response)
                    .await
                    .map_err(ProxyError::Framing)
            }
            MessageType::Invalid { id, reason } => {
                let response = make_invalid_response(&id, &reason);
                tracing::warn!("Invalid MCP request: {}", reason);
                write_message(io.agent, &response)
                    .await
                    .map_err(ProxyError::Framing)
            }
            MessageType::ProgressNotification { .. } => {
                // SECURITY (FIND-R46-005): Progress notifications may carry arbitrary
                // data in their `params` (including a `data` sub-field). Route through
                // handle_passthrough which applies DLP + injection scanning before
                // forwarding to the child server.
                self.handle_passthrough(&msg, state, io).await
            }
            MessageType::ExtensionMethod {
                id,
                extension_id,
                method,
            } => {
                self.handle_extension_method(msg, id, extension_id, method, state, io)
                    .await
            }
            MessageType::PassThrough => self.handle_passthrough(&msg, state, io).await,
        }
    }

    /// Handle a `tools/call` request from the agent.
    async fn handle_tool_call(
        &self,
        msg: Value,
        id: Value,
        tool_name: String,
        arguments: Value,
        state: &mut RelayState,
        io: &mut IoWriters<'_>,
    ) -> Result<(), ProxyError> {
        let IoWriters {
            agent: agent_writer,
            child: child_stdin,
        } = io;
        // SECURITY (FIND-R78-001): MCP 2025-11-25 tool name validation.
        // Parity with HTTP/WebSocket/gRPC proxy modes.
        if self.strict_tool_name_validation {
            if let Err(e) = vellaveto_types::validate_mcp_tool_name(&tool_name) {
                tracing::warn!(
                    "SECURITY: Rejecting invalid tool name in stdio proxy: {}",
                    e
                );
                let action = extract_action(&tool_name, &arguments);
                let reason = "Invalid tool name".to_string();
                let verdict = Verdict::Deny {
                    reason: reason.clone(),
                };
                if let Err(audit_err) = self
                    .audit
                    .log_entry(
                        &action,
                        &verdict,
                        json!({"source": "proxy", "event": "invalid_tool_name"}),
                    )
                    .await
                {
                    tracing::warn!("Failed to audit invalid tool name: {}", audit_err);
                }
                let response = make_denial_response(&id, &reason);
                write_message(agent_writer, &response)
                    .await
                    .map_err(ProxyError::Framing)?;
                return Ok(());
            }
        }

        // C-15 Exploit #9: Block calls to rug-pulled tools
        if state.flagged_tools.contains(&tool_name) {
            let action = extract_action(&tool_name, &arguments);
            let reason = format!(
                "Tool '{}' blocked: annotations changed since initial tools/list (rug-pull detected)",
                tool_name
            );
            let verdict = Verdict::Deny {
                reason: reason.clone(),
            };
            if let Err(e) = self
                .audit
                .log_entry(
                    &action,
                    &verdict,
                    json!({"source": "proxy", "tool": tool_name, "event": "rug_pull_tool_blocked"}),
                )
                .await
            {
                tracing::warn!("Failed to audit rug-pull block: {}", e);
            }
            let response = make_denial_response(&id, &reason);
            write_message(agent_writer, &response)
                .await
                .map_err(ProxyError::Framing)?;
            return Ok(());
        }

        // ═══════════════════════════════════════════════════════════════════
        // Phase 3.1: Pre-evaluation security checks
        // ═══════════════════════════════════════════════════════════════════

        // Phase 3.1: Circuit breaker check (OWASP ASI08)
        if let Some(ref cb) = self.circuit_breaker {
            if let Err(reason) = cb.can_proceed(&tool_name) {
                tracing::warn!(
                    "SECURITY: Circuit breaker blocking tool '{}': {}",
                    tool_name,
                    reason
                );
                let action = extract_action(&tool_name, &arguments);
                let verdict = Verdict::Deny {
                    reason: reason.clone(),
                };
                if let Err(e) = self
                    .audit
                    .log_entry(
                        &action,
                        &verdict,
                        json!({
                            "source": "proxy",
                            "event": "circuit_breaker_blocked",
                            "tool": tool_name,
                        }),
                    )
                    .await
                {
                    tracing::warn!("Failed to audit circuit breaker block: {}", e);
                }
                let response = make_denial_response(&id, &reason);
                write_message(agent_writer, &response)
                    .await
                    .map_err(ProxyError::Framing)?;
                return Ok(());
            }
        }

        // Phase 3.1: Shadow agent detection
        if let Some(ref detector) = self.shadow_agent {
            let fingerprint = Self::extract_fingerprint_from_meta(&msg);
            if fingerprint.is_populated() {
                if let Some(claimed_id) = Self::extract_agent_id(&msg) {
                    if let Err(alert) = detector.detect_shadow(&claimed_id, &fingerprint) {
                        tracing::warn!(
                            "SECURITY: Shadow agent detected - claimed '{}' but fingerprint mismatch",
                            claimed_id
                        );
                        let action = extract_action(&tool_name, &arguments);
                        let reason = format!(
                            "Shadow agent detected: claimed identity '{}' does not match fingerprint",
                            claimed_id
                        );
                        let verdict = Verdict::Deny {
                            reason: reason.clone(),
                        };
                        if let Err(e) = self
                            .audit
                            .log_entry(
                                &action,
                                &verdict,
                                json!({
                                    "source": "proxy",
                                    "event": "shadow_agent_detected",
                                    "claimed_id": claimed_id,
                                    "expected_summary": alert.expected_fingerprint.summary(),
                                    "actual_summary": alert.actual_fingerprint.summary(),
                                    "severity": format!("{:?}", alert.severity),
                                }),
                            )
                            .await
                        {
                            tracing::warn!("Failed to audit shadow agent: {}", e);
                        }
                        let response = make_denial_response(&id, &reason);
                        write_message(agent_writer, &response)
                            .await
                            .map_err(ProxyError::Framing)?;
                        return Ok(());
                    }
                    // Ok(()) means no shadow detected - proceed
                }
            }
        }

        // Phase 3.1: Deputy validation (OWASP ASI02)
        if let Some(ref deputy) = self.deputy {
            let session_id = "stdio-session";
            if let Some(claimed_id) = Self::extract_agent_id(&msg) {
                if let Err(err) = deputy.validate_action(session_id, &tool_name, &claimed_id) {
                    let reason = err.to_string();
                    tracing::warn!(
                        "SECURITY: Deputy validation failed for '{}' -> '{}': {}",
                        claimed_id,
                        tool_name,
                        reason
                    );
                    let action = extract_action(&tool_name, &arguments);
                    let verdict = Verdict::Deny {
                        reason: reason.clone(),
                    };
                    if let Err(e) = self
                        .audit
                        .log_entry(
                            &action,
                            &verdict,
                            json!({
                                "source": "proxy",
                                "event": "deputy_validation_failed",
                                "session": session_id,
                                "principal": claimed_id,
                                "tool": tool_name,
                            }),
                        )
                        .await
                    {
                        tracing::warn!("Failed to audit deputy validation: {}", e);
                    }
                    let response = make_denial_response(&id, &reason);
                    write_message(agent_writer, &response)
                        .await
                        .map_err(ProxyError::Framing)?;
                    return Ok(());
                }
            }
        }

        // P2: DLP scan parameters for secret exfiltration.
        let dlp_findings = scan_parameters_for_secrets(&arguments);
        if !dlp_findings.is_empty() {
            tracing::warn!(
                "SECURITY: DLP alert for tool '{}': {:?}",
                tool_name,
                dlp_findings
                    .iter()
                    .map(|f| &f.pattern_name)
                    .collect::<Vec<_>>()
            );
            let action = extract_action(&tool_name, &arguments);
            let patterns: Vec<String> = dlp_findings
                .iter()
                .map(|f| format!("{} at {}", f.pattern_name, f.location))
                .collect();
            let audit_reason = format!("DLP: secrets detected in parameters: {:?}", patterns);
            if let Err(e) = self
                .audit
                .log_entry(
                    &action,
                    &Verdict::Deny {
                        reason: audit_reason.clone(),
                    },
                    json!({
                        "source": "proxy",
                        "event": "dlp_secret_blocked",
                        "tool": tool_name,
                        "findings": patterns,
                    }),
                )
                .await
            {
                tracing::warn!("Failed to audit DLP finding: {}", e);
            }
            // SECURITY (R28-MCP-5): Generic error to agent — do not
            // leak which DLP patterns matched or their locations.
            let response = json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {
                    "code": -32001,
                    "message": "Request blocked: security policy violation",
                }
            });
            write_message(agent_writer, &response)
                .await
                .map_err(ProxyError::Framing)?;
            return Ok(());
        }

        // SECURITY (FIND-040): Injection scan tool call parameters.
        // Transport parity with HTTP/WS/gRPC handlers — the stdio relay
        // must scan outbound tool call arguments for injection patterns.
        if !self.injection_disabled {
            let synthetic_msg = json!({
                "method": tool_name,
                "params": arguments,
            });
            let injection_matches: Vec<String> = if let Some(ref scanner) = self.injection_scanner {
                scanner
                    .scan_notification(&synthetic_msg)
                    .into_iter()
                    .map(|s| s.to_string())
                    .collect()
            } else {
                scan_notification_for_injection(&synthetic_msg)
                    .into_iter()
                    .map(|s| s.to_string())
                    .collect()
            };
            if !injection_matches.is_empty() {
                tracing::warn!(
                    "SECURITY: Injection in tool call params '{}': {:?}",
                    tool_name,
                    injection_matches
                );
                let action = extract_action(&tool_name, &arguments);
                let verdict = if self.injection_blocking {
                    Verdict::Deny {
                        reason: format!(
                            "Tool call blocked: injection detected in parameters ({:?})",
                            injection_matches
                        ),
                    }
                } else {
                    Verdict::Allow
                };
                if let Err(e) = self
                    .audit
                    .log_entry(
                        &action,
                        &verdict,
                        json!({
                            "source": "proxy",
                            "event": "tool_call_injection_detected",
                            "tool": tool_name,
                            "patterns": injection_matches,
                            "blocked": self.injection_blocking,
                        }),
                    )
                    .await
                {
                    tracing::warn!("Failed to audit tool call injection finding: {}", e);
                }
                if self.injection_blocking {
                    let response = json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": {
                            "code": -32001,
                            "message": "Request blocked: security policy violation",
                        }
                    });
                    write_message(agent_writer, &response)
                        .await
                        .map_err(ProxyError::Framing)?;
                    return Ok(());
                }
            }
        }

        // OWASP ASI06: Check for memory poisoning
        let poisoning_matches = state.memory_tracker.check_parameters(&arguments);
        if !poisoning_matches.is_empty() {
            for m in &poisoning_matches {
                tracing::warn!(
                    "SECURITY: Memory poisoning detected in tool call '{}': \
                     param '{}' contains replayed data (fingerprint: {})",
                    tool_name,
                    m.param_location,
                    m.fingerprint
                );
            }
            let action = extract_action(&tool_name, &arguments);
            let deny_reason = format!(
                "Memory poisoning detected: {} replayed data fragment(s) in tool '{}'",
                poisoning_matches.len(),
                tool_name
            );
            if let Err(e) = self
                .audit
                .log_entry(
                    &action,
                    &Verdict::Deny {
                        reason: deny_reason.clone(),
                    },
                    json!({
                        "source": "proxy",
                        "event": "memory_poisoning_detected",
                        "matches": poisoning_matches.len(),
                        "tool": tool_name,
                    }),
                )
                .await
            {
                tracing::error!(
                    error = %e,
                    tool = %tool_name,
                    "Failed to log audit entry for memory poisoning detection"
                );
            }
            let response = json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {
                    "code": -32001,
                    "message": "Request blocked: security policy violation",
                }
            });
            write_message(agent_writer, &response)
                .await
                .map_err(ProxyError::Framing)?;
            return Ok(());
        }

        // Tool registry check
        if let Some(ref registry) = self.tool_registry {
            let trust = registry.check_trust_level(&tool_name).await;
            match trust {
                crate::tool_registry::TrustLevel::Unknown => {
                    registry.register_unknown(&tool_name).await;
                    let action = extract_action(&tool_name, &arguments);
                    let reason = format!(
                        "Tool '{}' is not in the registry — requires approval before use",
                        tool_name
                    );
                    let verdict = Verdict::RequireApproval {
                        reason: reason.clone(),
                    };
                    if let Err(e) = self
                        .audit
                        .log_entry(
                            &action,
                            &verdict,
                            json!({"source": "proxy", "registry": "unknown_tool", "tool": tool_name}),
                        )
                        .await
                    {
                        tracing::error!("AUDIT FAILURE: {}", e);
                    }
                    // SECURITY (SE-005): Log approval creation errors instead of silently swallowing.
                    let approval_id = if let Some(ref store) = self.approval_store {
                        match store.create(action, reason.clone(), None).await {
                            Ok(id) => Some(id),
                            Err(e) => {
                                tracing::error!("APPROVAL CREATION FAILURE (unknown_tool): {}", e);
                                None
                            }
                        }
                    } else {
                        None
                    };
                    let error_data = json!({"verdict": "require_approval", "reason": reason, "approval_id": approval_id});
                    let response = make_denial_response(&id, &error_data.to_string());
                    write_message(agent_writer, &response)
                        .await
                        .map_err(ProxyError::Framing)?;
                    return Ok(());
                }
                crate::tool_registry::TrustLevel::Untrusted { score } => {
                    let action = extract_action(&tool_name, &arguments);
                    let reason = format!(
                        "Tool '{}' trust score ({:.2}) is below threshold — requires approval",
                        tool_name, score
                    );
                    let verdict = Verdict::RequireApproval {
                        reason: reason.clone(),
                    };
                    if let Err(e) = self
                        .audit
                        .log_entry(
                            &action,
                            &verdict,
                            json!({"source": "proxy", "registry": "untrusted_tool", "tool": tool_name}),
                        )
                        .await
                    {
                        tracing::error!("AUDIT FAILURE: {}", e);
                    }
                    // SECURITY (SE-005): Log approval creation errors instead of silently swallowing.
                    let approval_id = if let Some(ref store) = self.approval_store {
                        match store.create(action, reason.clone(), None).await {
                            Ok(id) => Some(id),
                            Err(e) => {
                                tracing::error!(
                                    "APPROVAL CREATION FAILURE (untrusted_tool): {}",
                                    e
                                );
                                None
                            }
                        }
                    } else {
                        None
                    };
                    let error_data = json!({"verdict": "require_approval", "reason": reason, "approval_id": approval_id});
                    let response = make_denial_response(&id, &error_data.to_string());
                    write_message(agent_writer, &response)
                        .await
                        .map_err(ProxyError::Framing)?;
                    return Ok(());
                }
                crate::tool_registry::TrustLevel::Trusted => {
                    // Trusted — proceed to engine evaluation
                }
            }
        }

        // SECURITY (FIND-R78-001): Build action early so we can resolve domains
        // before policy evaluation, achieving parity with HTTP/WS/gRPC handlers.
        let mut action = extract_action(&tool_name, &arguments);

        // DNS rebinding protection: resolve target domains to IPs when any
        // policy has ip_rules configured.
        if self.engine.has_ip_rules() {
            resolve_domains(&mut action).await;
        }

        let ann = state.known_tool_annotations.get(&tool_name);
        let eval_ctx = state.evaluation_context();
        let (decision, eval_trace) =
            self.evaluate_tool_call_with_action(&id, &action, &tool_name, ann, Some(&eval_ctx));
        match decision {
            ProxyDecision::Forward => {
                // SECURITY (FIND-R78-002): ABAC refinement — only runs when ABAC
                // engine is configured. If the PolicyEngine allowed the action,
                // ABAC may still deny it based on principal/action/resource/condition
                // constraints. Parity with HTTP/WS/gRPC proxy handlers.
                if let Some(ref abac) = self.abac_engine {
                    let principal_id = eval_ctx.agent_id.as_deref().unwrap_or("anonymous");
                    let principal_type = eval_ctx.principal_type();
                    let abac_ctx = vellaveto_engine::abac::AbacEvalContext {
                        eval_ctx: &eval_ctx,
                        principal_type,
                        principal_id,
                        risk_score: None, // No session risk score in stdio mode
                    };

                    match abac.evaluate(&action, &abac_ctx) {
                        vellaveto_engine::abac::AbacDecision::Deny { policy_id, reason } => {
                            let verdict = Verdict::Deny {
                                reason: reason.clone(),
                            };
                            if let Err(e) = self
                                .audit
                                .log_entry(
                                    &action,
                                    &verdict,
                                    json!({
                                        "source": "proxy",
                                        "event": "abac_deny",
                                        "abac_policy": policy_id,
                                        "tool": tool_name,
                                    }),
                                )
                                .await
                            {
                                tracing::warn!("Audit log failed for ABAC deny: {}", e);
                            }
                            let response = make_denial_response(&id, &reason);
                            write_message(agent_writer, &response)
                                .await
                                .map_err(ProxyError::Framing)?;
                            return Ok(());
                        }
                        vellaveto_engine::abac::AbacDecision::Allow { .. } => {
                            // ABAC explicitly allowed — proceed.
                            // NOTE: record_usage not called here because ProxyBridge
                            // does not hold a LeastAgencyTracker (stdio mode).
                        }
                        vellaveto_engine::abac::AbacDecision::NoMatch => {
                            // No ABAC rule matched — existing Allow verdict stands
                        }
                        #[allow(unreachable_patterns)] // AbacDecision is #[non_exhaustive]
                        _ => {
                            // SECURITY: Future variants — fail-closed (deny).
                            tracing::warn!("Unknown AbacDecision variant — fail-closed");
                            let reason =
                                "Access denied by policy (unknown ABAC decision)".to_string();
                            let verdict = Verdict::Deny {
                                reason: reason.clone(),
                            };
                            if let Err(e) = self
                                .audit
                                .log_entry(
                                    &action,
                                    &verdict,
                                    json!({
                                        "source": "proxy",
                                        "event": "abac_unknown_variant_deny",
                                        "tool": tool_name,
                                    }),
                                )
                                .await
                            {
                                tracing::warn!("Audit log failed for ABAC deny: {}", e);
                            }
                            let response = make_denial_response(&id, &reason);
                            write_message(agent_writer, &response)
                                .await
                                .map_err(ProxyError::Framing)?;
                            return Ok(());
                        }
                    }
                }

                // SECURITY (FIND-R52-009): Audit allowed tool calls for full observability.
                // Compliance frameworks (EU AI Act Art 50, SOC 2) require tracking all
                // decisions, not just denials.
                let meta = Self::tool_call_audit_metadata(&tool_name, ann);
                if let Err(e) = self.audit.log_entry(&action, &Verdict::Allow, meta).await {
                    tracing::warn!("Audit log failed for allowed tool call: {}", e);
                }
                // Record tool call in registry on Allow
                if let Some(ref registry) = self.tool_registry {
                    registry.record_call(&tool_name).await;
                }
                state.record_forwarded_action(&tool_name);
                // SECURITY (FIND-R150-003): Truncate tool_name before storing in
                // PendingRequest — parity with passthrough handler (line ~2057).
                let truncated_tool: String = tool_name.chars().take(256).collect();
                state.track_pending_request(&id, truncated_tool, eval_trace);

                // Consumer shield: record outbound context BEFORE sanitization
                // (so the user's local context preserves original text, not PII placeholders)
                #[cfg(feature = "consumer-shield")]
                if let Some(ref isolator) = self.shield_context_isolator {
                    let session_id = state.agent_id.as_deref().unwrap_or("default");
                    if let Err(e) = isolator.record_json_request(session_id, &msg) {
                        tracing::debug!("Shield context record (outbound) failed: {}", e);
                    }
                }

                // Consumer shield: sanitize outbound request parameters
                // SECURITY: Fail-closed — if sanitization fails, PII must not leak to provider.
                #[cfg(feature = "consumer-shield")]
                let msg = if let Some(ref sanitizer) = self.shield_sanitizer {
                    match sanitizer.sanitize_json(&msg) {
                        Ok(sanitized) => sanitized,
                        Err(e) => {
                            tracing::error!(
                                "Shield sanitize FAILED (fail-closed): {} — blocking request",
                                e
                            );
                            let error_response = make_denial_response(
                                &id,
                                "Shield PII sanitization failed — request blocked to prevent data leakage",
                            );
                            write_message(agent_writer, &error_response)
                                .await
                                .map_err(ProxyError::Framing)?;
                            return Ok(());
                        }
                    }
                } else {
                    msg
                };

                // Consumer shield: stylometric normalization (after PII sanitization)
                // Advisory: normalization failure is not a privacy risk, forward original
                #[cfg(feature = "consumer-shield")]
                let msg = if let Some(ref normalizer) = self.shield_stylometric {
                    match normalizer.normalize_json(&msg) {
                        Ok(normalized) => normalized,
                        Err(e) => {
                            tracing::warn!(
                                "Shield stylometric normalize failed: {} — forwarding sanitized",
                                e
                            );
                            msg
                        }
                    }
                } else {
                    msg
                };

                // Consumer shield: consume credential on first tool call per session
                #[cfg(feature = "consumer-shield")]
                if let Some(ref unlinker) = self.shield_session_unlinker {
                    let session_id = state.agent_id.as_deref().unwrap_or("default").to_string();
                    let unlinker_guard = unlinker.lock().await;
                    if unlinker_guard.get_session_credential(&session_id).is_err() {
                        match unlinker_guard.start_session(&session_id) {
                            Ok(_credential) => {
                                tracing::debug!(
                                    "Shield session started with fresh credential: {}",
                                    session_id
                                );
                            }
                            Err(e) => {
                                tracing::warn!("Shield session start failed: {} — continuing without credential", e);
                            }
                        }
                    }
                }

                write_message(child_stdin, &msg)
                    .await
                    .map_err(ProxyError::Framing)?;
            }
            ProxyDecision::Block(mut response, verdict) => {
                // If RequireApproval and we have an approval store,
                // create a pending approval and inject the ID into
                // the JSON-RPC error data.
                if let Verdict::RequireApproval { ref reason } = verdict {
                    if let Some(ref store) = self.approval_store {
                        match store.create(action.clone(), reason.clone(), None).await {
                            Ok(approval_id) => {
                                if let Some(data) =
                                    response.get_mut("error").and_then(|e| e.get_mut("data"))
                                {
                                    data["approval_id"] = Value::String(approval_id.clone());
                                }
                                tracing::info!(
                                    "Created pending approval {} for tool '{}'",
                                    approval_id,
                                    tool_name
                                );
                            }
                            Err(e) => {
                                tracing::error!("Failed to create approval (fail-closed): {}", e);
                            }
                        }
                    }
                }
                let meta = Self::tool_call_audit_metadata(&tool_name, ann);
                if let Err(e) = self.audit.log_entry(&action, &verdict, meta).await {
                    tracing::warn!("Audit log failed: {}", e);
                }
                write_message(agent_writer, &response)
                    .await
                    .map_err(ProxyError::Framing)?;
            }
        }
        Ok(())
    }

    /// Handle a `resources/read` request from the agent.
    async fn handle_resource_read(
        &self,
        msg: Value,
        id: Value,
        uri: String,
        state: &mut RelayState,
        io: &mut IoWriters<'_>,
    ) -> Result<(), ProxyError> {
        let IoWriters {
            agent: agent_writer,
            child: child_stdin,
        } = io;
        // SECURITY: DLP scan the resource URI for embedded secrets.
        let uri_as_json = json!({"uri": uri});
        let dlp_findings = scan_parameters_for_secrets(&uri_as_json);
        if !dlp_findings.is_empty() {
            // SECURITY (FIND-R136-003): Sanitize URI before logging.
            let safe_uri = vellaveto_types::sanitize_for_log(&uri, 512);
            tracing::warn!(
                "SECURITY: DLP alert in resource URI '{}': {:?}",
                safe_uri,
                dlp_findings
                    .iter()
                    .map(|f| &f.pattern_name)
                    .collect::<Vec<_>>()
            );
            let action = extract_resource_action(&uri);
            let patterns: Vec<String> = dlp_findings
                .iter()
                .map(|f| format!("{} at {}", f.pattern_name, f.location))
                .collect();
            let audit_reason = format!("DLP: secrets detected in resource URI: {:?}", patterns);
            if let Err(e) = self
                .audit
                .log_entry(
                    &action,
                    &Verdict::Deny {
                        reason: audit_reason.clone(),
                    },
                    json!({
                        "source": "proxy",
                        "event": "dlp_resource_blocked",
                        "uri": uri,
                        "findings": patterns,
                    }),
                )
                .await
            {
                tracing::warn!("Failed to audit resource DLP: {}", e);
            }
            // SECURITY (R28-MCP-5): Generic error to agent.
            let response = json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {
                    "code": -32001,
                    "message": "Request blocked: security policy violation",
                }
            });
            write_message(agent_writer, &response)
                .await
                .map_err(ProxyError::Framing)?;
            return Ok(());
        }

        // SECURITY (R37-MCP-1): Memory poisoning check for ResourceRead.
        let uri_params = json!({"uri": &uri});
        let poisoning_matches = state.memory_tracker.check_parameters(&uri_params);
        if !poisoning_matches.is_empty() {
            for m in &poisoning_matches {
                tracing::warn!(
                    "SECURITY: Memory poisoning detected in resource read '{}': \
                     param '{}' contains replayed data (fingerprint: {})",
                    uri,
                    m.param_location,
                    m.fingerprint
                );
            }
            let action = extract_resource_action(&uri);
            let deny_reason = format!(
                "Memory poisoning detected: {} replayed data fragment(s) in resource read '{}'",
                poisoning_matches.len(),
                uri
            );
            if let Err(e) = self
                .audit
                .log_entry(
                    &action,
                    &Verdict::Deny {
                        reason: deny_reason.clone(),
                    },
                    json!({
                        "source": "proxy",
                        "event": "memory_poisoning_detected",
                        "matches": poisoning_matches.len(),
                        "uri": uri,
                    }),
                )
                .await
            {
                tracing::error!(
                    error = %e,
                    uri = %uri,
                    "Failed to log audit entry for memory poisoning detection"
                );
            }
            let response = json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {
                    "code": -32001,
                    "message": "Request blocked: security policy violation",
                }
            });
            write_message(agent_writer, &response)
                .await
                .map_err(ProxyError::Framing)?;
            return Ok(());
        }

        // SECURITY (R230-RELAY-4): Injection scan resource read URI.
        // Parity with handle_tool_call (line 869).
        if !self.injection_disabled {
            let synthetic_msg = json!({"method": "resources/read", "params": {"uri": &uri}});
            let injection_matches: Vec<String> = if let Some(ref scanner) = self.injection_scanner {
                scanner
                    .scan_notification(&synthetic_msg)
                    .into_iter()
                    .map(|s| s.to_string())
                    .collect()
            } else {
                scan_notification_for_injection(&synthetic_msg)
                    .into_iter()
                    .map(|s| s.to_string())
                    .collect()
            };
            if !injection_matches.is_empty() {
                let safe_uri = vellaveto_types::sanitize_for_log(&uri, 512);
                tracing::warn!(
                    "SECURITY: Injection in resource URI '{}': {:?}",
                    safe_uri,
                    injection_matches
                );
                let res_action = extract_resource_action(&uri);
                let verdict = if self.injection_blocking {
                    Verdict::Deny {
                        reason: format!(
                            "Resource read blocked: injection detected in URI ({:?})",
                            injection_matches
                        ),
                    }
                } else {
                    Verdict::Allow
                };
                if let Err(e) = self
                    .audit
                    .log_entry(
                        &res_action,
                        &verdict,
                        json!({
                            "source": "proxy",
                            "event": "resource_injection_detected",
                            "patterns": injection_matches,
                            "blocked": self.injection_blocking,
                        }),
                    )
                    .await
                {
                    tracing::warn!("Failed to audit resource injection finding: {}", e);
                }
                if self.injection_blocking {
                    let response = json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": {
                            "code": -32001,
                            "message": "Request blocked: security policy violation",
                        }
                    });
                    write_message(agent_writer, &response)
                        .await
                        .map_err(ProxyError::Framing)?;
                    return Ok(());
                }
            }
        }

        // SECURITY (FIND-R78-001): Build action early for DNS resolution.
        let mut action = extract_resource_action(&uri);
        if self.engine.has_ip_rules() {
            resolve_domains(&mut action).await;
        }

        let eval_ctx = state.evaluation_context();
        match self.evaluate_resource_read_with_action(&id, &action, &uri, Some(&eval_ctx)) {
            ProxyDecision::Forward => {
                // SECURITY (FIND-R52-009): Audit allowed resource reads for full observability.
                if let Err(e) = self
                    .audit
                    .log_entry(
                        &action,
                        &Verdict::Allow,
                        json!({"source": "proxy", "resource_uri": uri}),
                    )
                    .await
                {
                    tracing::warn!("Audit log failed for allowed resource read: {}", e);
                }
                // SECURITY (R38-MCP-2): Update call_counts and action_history for ResourceRead.
                state.record_forwarded_action("resources/read");
                state.track_pending_request(&id, "resources/read".to_string(), None);
                write_message(child_stdin, &msg)
                    .await
                    .map_err(ProxyError::Framing)?;
            }
            ProxyDecision::Block(mut response, verdict) => {
                if let Verdict::RequireApproval { ref reason } = verdict {
                    if let Some(ref store) = self.approval_store {
                        match store.create(action.clone(), reason.clone(), None).await {
                            Ok(approval_id) => {
                                if let Some(data) =
                                    response.get_mut("error").and_then(|e| e.get_mut("data"))
                                {
                                    data["approval_id"] = Value::String(approval_id.clone());
                                }
                                tracing::info!(
                                    "Created pending approval {} for resource '{}'",
                                    approval_id,
                                    uri
                                );
                            }
                            Err(e) => {
                                tracing::error!("Failed to create approval for resource: {}", e);
                            }
                        }
                    }
                }
                if let Err(e) = self
                    .audit
                    .log_entry(
                        &action,
                        &verdict,
                        json!({"source": "proxy", "resource_uri": uri}),
                    )
                    .await
                {
                    tracing::warn!("Audit log failed: {}", e);
                }
                write_message(agent_writer, &response)
                    .await
                    .map_err(ProxyError::Framing)?;
            }
        }
        Ok(())
    }

    /// Handle a `sampling/createMessage` request from the child server.
    async fn handle_sampling_request(
        &self,
        msg: &Value,
        id: Value,
        state: &mut RelayState,
        agent_writer: &mut tokio::io::Stdout,
    ) -> Result<(), ProxyError> {
        let params = msg.get("params").cloned().unwrap_or(json!({}));
        let verdict = crate::elicitation::inspect_sampling(
            &params,
            &self.sampling_config,
            state.sampling_count,
        );
        match verdict {
            crate::elicitation::SamplingVerdict::Allow => {
                // R227: Per-tool sampling rate limit check.
                // Attribute sampling to the most recently dispatched tool.
                let tool_name = state.current_tool_name().unwrap_or("unknown").to_string();
                if let Err(reason) = state.check_per_tool_sampling_limit(
                    &tool_name,
                    self.sampling_config.max_per_tool,
                    self.sampling_config.per_tool_window_secs,
                ) {
                    let response = make_denial_response(&id, &reason);
                    let action = vellaveto_types::Action::new(
                        "vellaveto",
                        "sampling_blocked",
                        json!({"reason": &reason, "tool": &tool_name}),
                    );
                    if let Err(e) = self
                        .audit
                        .log_entry(
                            &action,
                            &Verdict::Deny {
                                reason: reason.clone(),
                            },
                            json!({"source": "proxy", "event": "sampling_per_tool_rate_limit"}),
                        )
                        .await
                    {
                        tracing::warn!("Audit log failed: {}", e);
                    }
                    tracing::warn!("Blocked sampling/createMessage: {}", reason);
                    write_message(agent_writer, &response)
                        .await
                        .map_err(ProxyError::Framing)?;
                    return Ok(());
                }

                // SECURITY (R231-MCP-2): DLP scan sampling request parameters
                // before forwarding. Sampling messages must not leak secrets.
                let dlp_findings = scan_parameters_for_secrets(&params);
                if !dlp_findings.is_empty() {
                    let patterns: Vec<String> = dlp_findings
                        .iter()
                        .map(|f| format!("{} at {}", f.pattern_name, f.location))
                        .collect();
                    tracing::warn!("SECURITY: DLP alert in sampling request: {:?}", patterns);
                    let dlp_action = vellaveto_types::Action::new(
                        "vellaveto",
                        "sampling_dlp_blocked",
                        json!({"findings": patterns, "tool": &tool_name}),
                    );
                    if let Err(e) = self
                        .audit
                        .log_entry(
                            &dlp_action,
                            &Verdict::Deny {
                                reason: format!(
                                    "Sampling blocked: secrets detected in request ({:?})",
                                    patterns
                                ),
                            },
                            json!({"source": "proxy", "event": "sampling_dlp_blocked"}),
                        )
                        .await
                    {
                        tracing::warn!("Failed to audit sampling DLP finding: {}", e);
                    }
                    let response =
                        make_denial_response(&id, "Request blocked: security policy violation");
                    write_message(agent_writer, &response)
                        .await
                        .map_err(ProxyError::Framing)?;
                    return Ok(());
                }

                // SECURITY (TI-2026-002): Injection scan sampling system prompt
                // and messages. A malicious MCP server can inject hidden instructions
                // via sampling/createMessage to hijack the LLM or exfiltrate data.
                if !self.injection_disabled {
                    let synthetic_msg = json!({
                        "method": "sampling/createMessage",
                        "params": params,
                    });
                    let injection_matches: Vec<String> =
                        if let Some(ref scanner) = self.injection_scanner {
                            scanner
                                .scan_notification(&synthetic_msg)
                                .into_iter()
                                .map(|s| s.to_string())
                                .collect()
                        } else {
                            scan_notification_for_injection(&synthetic_msg)
                                .into_iter()
                                .map(|s| s.to_string())
                                .collect()
                        };
                    if !injection_matches.is_empty() {
                        tracing::warn!(
                            "SECURITY: Injection in sampling/createMessage from tool '{}': {:?}",
                            tool_name,
                            injection_matches
                        );
                        if self.injection_blocking {
                            let deny_action = vellaveto_types::Action::new(
                                "vellaveto",
                                "sampling_injection_blocked",
                                json!({
                                    "tool": &tool_name,
                                    "patterns": injection_matches,
                                }),
                            );
                            if let Err(e) = self
                                .audit
                                .log_entry(
                                    &deny_action,
                                    &Verdict::Deny {
                                        reason: format!(
                                            "Sampling blocked: injection in system prompt/messages ({:?})",
                                            injection_matches
                                        ),
                                    },
                                    json!({
                                        "source": "proxy",
                                        "event": "sampling_injection_blocked",
                                        "tool": &tool_name,
                                    }),
                                )
                                .await
                            {
                                tracing::warn!(
                                    "Failed to audit sampling injection: {}",
                                    e
                                );
                            }
                            let response = make_denial_response(
                                &id,
                                "Request blocked: security policy violation",
                            );
                            write_message(agent_writer, &response)
                                .await
                                .map_err(ProxyError::Framing)?;
                            return Ok(());
                        }
                    }
                }

                // SECURITY (FIND-R125-001): Saturating add prevents
                // panic from overflow-checks in release profile.
                state.sampling_count = state.sampling_count.saturating_add(1);
                // SECURITY (FIND-R46-008): Audit allowed sampling decisions.
                let action = vellaveto_types::Action::new(
                    "vellaveto",
                    "sampling_allowed",
                    json!({"source": "proxy", "count": state.sampling_count, "tool": &tool_name}),
                );
                if let Err(e) = self
                    .audit
                    .log_entry(
                        &action,
                        &Verdict::Allow,
                        json!({"source": "proxy", "event": "sampling_allowed"}),
                    )
                    .await
                {
                    tracing::warn!("Audit log failed for sampling allow: {}", e);
                }
                write_message(agent_writer, msg)
                    .await
                    .map_err(ProxyError::Framing)?;
            }
            crate::elicitation::SamplingVerdict::Deny { reason } => {
                let response = make_denial_response(&id, &reason);
                let action = vellaveto_types::Action::new(
                    "vellaveto",
                    "sampling_blocked",
                    json!({"reason": &reason}),
                );
                if let Err(e) = self
                    .audit
                    .log_entry(
                        &action,
                        &Verdict::Deny {
                            reason: reason.clone(),
                        },
                        json!({"source": "proxy", "event": "sampling_blocked"}),
                    )
                    .await
                {
                    tracing::warn!("Audit log failed: {}", e);
                }
                tracing::warn!("Blocked sampling/createMessage: {}", reason);
                write_message(agent_writer, &response)
                    .await
                    .map_err(ProxyError::Framing)?;
            }
        }
        Ok(())
    }

    /// Handle an `elicitation/create` request from the child server.
    async fn handle_elicitation_request(
        &self,
        msg: &Value,
        id: Value,
        state: &mut RelayState,
        agent_writer: &mut tokio::io::Stdout,
    ) -> Result<(), ProxyError> {
        let params = msg.get("params").cloned().unwrap_or(json!({}));
        let verdict = crate::elicitation::inspect_elicitation(
            &params,
            &self.elicitation_config,
            state.elicitation_count,
        );
        match verdict {
            crate::elicitation::ElicitationVerdict::Allow => {
                // SECURITY (R231-MCP-3): DLP scan elicitation request parameters
                // before forwarding. Elicitations must not leak secrets via
                // title, message, or schema default values.
                let dlp_findings = scan_parameters_for_secrets(&params);
                if !dlp_findings.is_empty() {
                    let patterns: Vec<String> = dlp_findings
                        .iter()
                        .map(|f| format!("{} at {}", f.pattern_name, f.location))
                        .collect();
                    tracing::warn!("SECURITY: DLP alert in elicitation request: {:?}", patterns);
                    let dlp_action = vellaveto_types::Action::new(
                        "vellaveto",
                        "elicitation_dlp_blocked",
                        json!({"findings": patterns}),
                    );
                    if let Err(e) = self
                        .audit
                        .log_entry(
                            &dlp_action,
                            &Verdict::Deny {
                                reason: format!(
                                    "Elicitation blocked: secrets detected ({:?})",
                                    patterns
                                ),
                            },
                            json!({"source": "proxy", "event": "elicitation_dlp_blocked"}),
                        )
                        .await
                    {
                        tracing::warn!("Failed to audit elicitation DLP: {}", e);
                    }
                    let response =
                        make_denial_response(&id, "Request blocked: security policy violation");
                    write_message(agent_writer, &response)
                        .await
                        .map_err(ProxyError::Framing)?;
                    return Ok(());
                }

                // SECURITY (R28-MCP-8): Saturating add prevents
                // panic from overflow-checks in release profile.
                state.elicitation_count = state.elicitation_count.saturating_add(1);
                // SECURITY (FIND-R46-008): Audit allowed elicitation decisions.
                let action = vellaveto_types::Action::new(
                    "vellaveto",
                    "elicitation_allowed",
                    json!({"source": "proxy", "count": state.elicitation_count}),
                );
                if let Err(e) = self
                    .audit
                    .log_entry(
                        &action,
                        &Verdict::Allow,
                        json!({"source": "proxy", "event": "elicitation_allowed"}),
                    )
                    .await
                {
                    tracing::warn!("Audit log failed for elicitation allow: {}", e);
                }
                write_message(agent_writer, msg)
                    .await
                    .map_err(ProxyError::Framing)?;
            }
            crate::elicitation::ElicitationVerdict::Deny { reason } => {
                let action = vellaveto_types::Action::new(
                    "vellaveto",
                    "elicitation_intercepted",
                    json!({"reason": &reason}),
                );
                if let Err(e) = self
                    .audit
                    .log_entry(
                        &action,
                        &Verdict::Deny {
                            reason: reason.clone(),
                        },
                        json!({"source": "proxy", "event": "elicitation_intercepted"}),
                    )
                    .await
                {
                    tracing::warn!("Audit log failed: {}", e);
                }
                tracing::warn!("Blocked elicitation/create: {}", reason);
                let response = make_denial_response(&id, &reason);
                write_message(agent_writer, &response)
                    .await
                    .map_err(ProxyError::Framing)?;
            }
        }
        Ok(())
    }

    /// Handle a task request (`tasks/get`, `tasks/cancel`, etc.) from the agent.
    async fn handle_task_request(
        &self,
        msg: Value,
        id: Value,
        task_method: String,
        task_id: Option<String>,
        state: &mut RelayState,
        io: &mut IoWriters<'_>,
    ) -> Result<(), ProxyError> {
        let IoWriters {
            agent: agent_writer,
            child: child_stdin,
        } = io;
        // SECURITY (FIND-R136-003): Sanitize agent-sourced task_method/task_id
        // before logging to prevent log injection via control/format characters.
        let safe_task_method = vellaveto_types::sanitize_for_log(&task_method, 256);
        let safe_task_id: Option<String> = task_id
            .as_ref()
            .map(|id| vellaveto_types::sanitize_for_log(id, 256));
        tracing::debug!(
            "Task request: {} (task_id: {:?})",
            safe_task_method,
            safe_task_id
        );

        // R4-1: DLP scan task request parameters for secret exfiltration.
        let task_params = msg.get("params").cloned().unwrap_or(json!({}));
        let dlp_findings = scan_parameters_for_secrets(&task_params);
        if !dlp_findings.is_empty() {
            tracing::warn!(
                "SECURITY: DLP alert for task '{}': {:?}",
                safe_task_method,
                dlp_findings
                    .iter()
                    .map(|f| &f.pattern_name)
                    .collect::<Vec<_>>()
            );
            let dlp_action = extract_task_action(&task_method, task_id.as_deref());
            let patterns: Vec<String> = dlp_findings
                .iter()
                .map(|f| format!("{} at {}", f.pattern_name, f.location))
                .collect();
            let audit_reason = format!("DLP: secrets detected in task request: {:?}", patterns);
            if let Err(e) = self
                .audit
                .log_entry(
                    &dlp_action,
                    &Verdict::Deny {
                        reason: audit_reason.clone(),
                    },
                    json!({
                        "source": "proxy",
                        "event": "dlp_secret_blocked_task",
                        "task_method": safe_task_method,
                        "findings": patterns,
                    }),
                )
                .await
            {
                tracing::warn!("Failed to audit DLP finding: {}", e);
            }
            let response = json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {
                    "code": -32001,
                    "message": "Request blocked: security policy violation",
                }
            });
            write_message(agent_writer, &response)
                .await
                .map_err(ProxyError::Framing)?;
            return Ok(());
        }

        // SECURITY (R37-MCP-1): Memory poisoning check for TaskRequest.
        let poisoning_matches = state.memory_tracker.check_parameters(&task_params);
        if !poisoning_matches.is_empty() {
            for m in &poisoning_matches {
                tracing::warn!(
                    "SECURITY: Memory poisoning detected in task request '{}': \
                     param '{}' contains replayed data (fingerprint: {})",
                    safe_task_method,
                    m.param_location,
                    m.fingerprint
                );
            }
            let action = extract_task_action(&task_method, task_id.as_deref());
            let deny_reason = format!(
                "Memory poisoning detected: {} replayed data fragment(s) in task '{}'",
                poisoning_matches.len(),
                task_method
            );
            if let Err(e) = self
                .audit
                .log_entry(
                    &action,
                    &Verdict::Deny {
                        reason: deny_reason.clone(),
                    },
                    json!({
                        "source": "proxy",
                        "event": "memory_poisoning_detected",
                        "matches": poisoning_matches.len(),
                        "task_method": safe_task_method,
                    }),
                )
                .await
            {
                tracing::error!(
                    error = %e,
                    task_method = %task_method,
                    "Failed to log audit entry for memory poisoning detection"
                );
            }
            let response = json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {
                    "code": -32001,
                    "message": "Request blocked: security policy violation",
                }
            });
            write_message(agent_writer, &response)
                .await
                .map_err(ProxyError::Framing)?;
            return Ok(());
        }

        // SECURITY (R230-RELAY-3): Injection scan task request parameters.
        // Parity with handle_tool_call (line 869).
        if !self.injection_disabled {
            let synthetic_msg = json!({
                "method": task_method,
                "params": task_params,
            });
            let injection_matches: Vec<String> = if let Some(ref scanner) = self.injection_scanner {
                scanner
                    .scan_notification(&synthetic_msg)
                    .into_iter()
                    .map(|s| s.to_string())
                    .collect()
            } else {
                scan_notification_for_injection(&synthetic_msg)
                    .into_iter()
                    .map(|s| s.to_string())
                    .collect()
            };
            if !injection_matches.is_empty() {
                let task_action = extract_task_action(&task_method, task_id.as_deref());
                tracing::warn!(
                    "SECURITY: Injection in task request '{}': {:?}",
                    safe_task_method,
                    injection_matches
                );
                let verdict = if self.injection_blocking {
                    Verdict::Deny {
                        reason: format!(
                            "Task request blocked: injection detected in parameters ({:?})",
                            injection_matches
                        ),
                    }
                } else {
                    Verdict::Allow
                };
                if let Err(e) = self
                    .audit
                    .log_entry(
                        &task_action,
                        &verdict,
                        json!({
                            "source": "proxy",
                            "event": "task_injection_detected",
                            "task_method": safe_task_method,
                            "patterns": injection_matches,
                            "blocked": self.injection_blocking,
                        }),
                    )
                    .await
                {
                    tracing::warn!("Failed to audit task injection finding: {}", e);
                }
                if self.injection_blocking {
                    let response = json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": {
                            "code": -32001,
                            "message": "Request blocked: security policy violation",
                        }
                    });
                    write_message(agent_writer, &response)
                        .await
                        .map_err(ProxyError::Framing)?;
                    return Ok(());
                }
            }
        }

        let action = extract_task_action(&task_method, task_id.as_deref());
        let eval_ctx = state.evaluation_context();
        match self.evaluate_action_inner(&action, Some(&eval_ctx)) {
            Ok((Verdict::Allow, _trace)) => {
                // SECURITY (FIND-R80-006): ABAC refinement — only runs when ABAC
                // engine is configured. If the PolicyEngine allowed the action,
                // ABAC may still deny it based on principal/action/resource/condition
                // constraints. Parity with tool call handler.
                if let Some(ref abac) = self.abac_engine {
                    let principal_id = eval_ctx.agent_id.as_deref().unwrap_or("anonymous");
                    let principal_type = eval_ctx.principal_type();
                    let abac_ctx = vellaveto_engine::abac::AbacEvalContext {
                        eval_ctx: &eval_ctx,
                        principal_type,
                        principal_id,
                        risk_score: None,
                    };

                    match abac.evaluate(&action, &abac_ctx) {
                        vellaveto_engine::abac::AbacDecision::Deny { policy_id, reason } => {
                            let verdict = Verdict::Deny {
                                reason: reason.clone(),
                            };
                            if let Err(e) = self
                                .audit
                                .log_entry(
                                    &action,
                                    &verdict,
                                    json!({
                                        "source": "proxy",
                                        "event": "abac_deny_task",
                                        "abac_policy": policy_id,
                                        "task_method": safe_task_method,
                                        "task_id": safe_task_id,
                                    }),
                                )
                                .await
                            {
                                tracing::warn!("Audit log failed for ABAC deny: {}", e);
                            }
                            let response = make_denial_response(&id, &reason);
                            write_message(agent_writer, &response)
                                .await
                                .map_err(ProxyError::Framing)?;
                            return Ok(());
                        }
                        vellaveto_engine::abac::AbacDecision::Allow { .. } => {
                            // ABAC explicitly allowed — proceed.
                            // NOTE: record_usage not called here because ProxyBridge
                            // does not hold a LeastAgencyTracker (stdio mode).
                        }
                        vellaveto_engine::abac::AbacDecision::NoMatch => {
                            // No ABAC rule matched — existing Allow verdict stands
                        }
                        #[allow(unreachable_patterns)] // AbacDecision is #[non_exhaustive]
                        _ => {
                            // SECURITY: Future variants — fail-closed (deny).
                            tracing::warn!(
                                "Unknown AbacDecision variant in task request — fail-closed"
                            );
                            let reason =
                                "Access denied by policy (unknown ABAC decision)".to_string();
                            let verdict = Verdict::Deny {
                                reason: reason.clone(),
                            };
                            if let Err(e) = self
                                .audit
                                .log_entry(
                                    &action,
                                    &verdict,
                                    json!({
                                        "source": "proxy",
                                        "event": "abac_unknown_variant_deny_task",
                                        "task_method": safe_task_method,
                                    }),
                                )
                                .await
                            {
                                tracing::warn!("Audit log failed for ABAC deny: {}", e);
                            }
                            let response = make_denial_response(&id, &reason);
                            write_message(agent_writer, &response)
                                .await
                                .map_err(ProxyError::Framing)?;
                            return Ok(());
                        }
                    }
                }

                if let Err(e) = self
                    .audit
                    .log_entry(
                        &action,
                        &Verdict::Allow,
                        json!({
                            "source": "proxy",
                            "event": "task_request_forwarded",
                            "task_method": safe_task_method,
                            "task_id": safe_task_id,
                        }),
                    )
                    .await
                {
                    tracing::warn!("Audit log failed: {}", e);
                }
                // SECURITY (R38-MCP-2): Update call_counts and action_history.
                state.record_forwarded_action(&task_method);
                // SECURITY (FIND-R150-002): Truncate before PendingRequest storage.
                let truncated_task: String = task_method.chars().take(256).collect();
                state.track_pending_request(&id, truncated_task, None);
                write_message(child_stdin, &msg)
                    .await
                    .map_err(ProxyError::Framing)?;
            }
            Ok((verdict @ Verdict::Deny { .. }, _))
            | Ok((verdict @ Verdict::RequireApproval { .. }, _)) => {
                // SECURITY (FIND-R166-001/002): Extract reason without unreachable!().
                // Verdict is #[non_exhaustive] — future variants must not panic.
                let reason = match &verdict {
                    Verdict::Deny { reason } => reason.clone(),
                    Verdict::RequireApproval { reason } => reason.clone(),
                    other => format!("Denied by policy: {:?}", other),
                };
                let response = make_denial_response(&id, &reason);
                if let Err(e) = self
                    .audit
                    .log_entry(
                        &action,
                        &verdict,
                        json!({
                            "source": "proxy",
                            "event": "task_request_denied",
                            "task_method": safe_task_method,
                            "task_id": safe_task_id,
                        }),
                    )
                    .await
                {
                    tracing::warn!("Audit log failed: {}", e);
                }
                write_message(agent_writer, &response)
                    .await
                    .map_err(ProxyError::Framing)?;
            }
            // Handle future Verdict variants - fail closed (deny)
            Ok((_, _)) => {
                let reason = "Unknown verdict type - failing closed".to_string();
                let verdict = Verdict::Deny {
                    reason: reason.clone(),
                };
                if let Err(e) = self
                    .audit
                    .log_entry(
                        &action,
                        &verdict,
                        json!({
                            "source": "proxy",
                            "event": "task_request_unknown_verdict",
                            "task_method": safe_task_method,
                        }),
                    )
                    .await
                {
                    tracing::warn!("Audit log failed: {}", e);
                }
                let response = make_denial_response(&id, &reason);
                write_message(agent_writer, &response)
                    .await
                    .map_err(ProxyError::Framing)?;
            }
            Err(e) => {
                tracing::error!("Policy evaluation error for task '{}': {}", task_method, e);
                let reason = "Policy evaluation failed".to_string();
                let verdict = Verdict::Deny {
                    reason: reason.clone(),
                };
                if let Err(e) = self
                    .audit
                    .log_entry(
                        &action,
                        &verdict,
                        json!({
                            "source": "proxy",
                            "event": "task_request_eval_error",
                            "task_method": safe_task_method,
                        }),
                    )
                    .await
                {
                    tracing::warn!("Audit log failed: {}", e);
                }
                let response = make_denial_response(&id, &reason);
                write_message(agent_writer, &response)
                    .await
                    .map_err(ProxyError::Framing)?;
            }
        }
        Ok(())
    }

    /// Handle an extension method call (`x-` prefixed methods) from the agent.
    async fn handle_extension_method(
        &self,
        msg: Value,
        id: Value,
        extension_id: String,
        method: String,
        state: &mut RelayState,
        io: &mut IoWriters<'_>,
    ) -> Result<(), ProxyError> {
        let IoWriters {
            agent: agent_writer,
            child: child_stdin,
        } = io;
        // SECURITY (FIND-R136-003): Sanitize agent-sourced extension_id and method
        // before logging to prevent log injection via control/format characters.
        let safe_extension_id = vellaveto_types::sanitize_for_log(&extension_id, 256);
        let safe_ext_method = vellaveto_types::sanitize_for_log(&method, 256);
        tracing::debug!(
            "Extension method: {} (extension: {})",
            safe_ext_method,
            safe_extension_id
        );

        let params = msg.get("params").cloned().unwrap_or(json!({}));
        let action = extract_extension_action(&extension_id, &method, &params);

        // SECURITY (R230-RELAY-2): Circuit breaker check for extension methods.
        // Parity with handle_tool_call (line 692).
        if let Some(ref cb) = self.circuit_breaker {
            let cb_key = format!("ext:{}:{}", extension_id, method);
            if let Err(reason) = cb.can_proceed(&cb_key) {
                tracing::warn!(
                    "SECURITY: Circuit breaker blocking extension '{}:{}': {}",
                    safe_extension_id,
                    safe_ext_method,
                    reason
                );
                let verdict = Verdict::Deny {
                    reason: reason.clone(),
                };
                if let Err(e) = self
                    .audit
                    .log_entry(
                        &action,
                        &verdict,
                        json!({
                            "source": "proxy",
                            "event": "circuit_breaker_blocked_extension",
                            "extension_id": safe_extension_id,
                            "method": safe_ext_method,
                        }),
                    )
                    .await
                {
                    tracing::warn!("Failed to audit circuit breaker block: {}", e);
                }
                let response = make_denial_response(&id, &reason);
                write_message(agent_writer, &response)
                    .await
                    .map_err(ProxyError::Framing)?;
                return Ok(());
            }
        }

        // SECURITY (R230-RELAY-5): Shadow agent detection for extension methods.
        // Parity with handle_tool_call (line 727).
        if let Some(ref detector) = self.shadow_agent {
            let fingerprint = Self::extract_fingerprint_from_meta(&msg);
            if fingerprint.is_populated() {
                if let Some(claimed_id) = Self::extract_agent_id(&msg) {
                    if let Err(alert) = detector.detect_shadow(&claimed_id, &fingerprint) {
                        tracing::warn!(
                            "SECURITY: Shadow agent detected in extension '{}:{}' - claimed '{}'",
                            safe_extension_id,
                            safe_ext_method,
                            claimed_id
                        );
                        let reason = format!(
                            "Shadow agent detected: claimed identity '{}' does not match fingerprint",
                            claimed_id
                        );
                        let verdict = Verdict::Deny {
                            reason: reason.clone(),
                        };
                        if let Err(e) = self
                            .audit
                            .log_entry(
                                &action,
                                &verdict,
                                json!({
                                    "source": "proxy",
                                    "event": "shadow_agent_detected_extension",
                                    "claimed_id": claimed_id,
                                    "expected_summary": alert.expected_fingerprint.summary(),
                                    "actual_summary": alert.actual_fingerprint.summary(),
                                    "extension_id": safe_extension_id,
                                    "method": safe_ext_method,
                                }),
                            )
                            .await
                        {
                            tracing::warn!("Failed to audit shadow agent: {}", e);
                        }
                        let response = make_denial_response(&id, &reason);
                        write_message(agent_writer, &response)
                            .await
                            .map_err(ProxyError::Framing)?;
                        return Ok(());
                    }
                }
            }
        }

        let eval_ctx = state.evaluation_context();

        match self.evaluate_action_inner(&action, Some(&eval_ctx)) {
            Ok((Verdict::Allow, _trace)) => {
                // SECURITY (FIND-R80-007): ABAC refinement — only runs when ABAC
                // engine is configured. If the PolicyEngine allowed the action,
                // ABAC may still deny it based on principal/action/resource/condition
                // constraints. Parity with tool call handler.
                if let Some(ref abac) = self.abac_engine {
                    let principal_id = eval_ctx.agent_id.as_deref().unwrap_or("anonymous");
                    let principal_type = eval_ctx.principal_type();
                    let abac_ctx = vellaveto_engine::abac::AbacEvalContext {
                        eval_ctx: &eval_ctx,
                        principal_type,
                        principal_id,
                        risk_score: None,
                    };

                    match abac.evaluate(&action, &abac_ctx) {
                        vellaveto_engine::abac::AbacDecision::Deny { policy_id, reason } => {
                            let verdict = Verdict::Deny {
                                reason: reason.clone(),
                            };
                            if let Err(e) = self
                                .audit
                                .log_entry(
                                    &action,
                                    &verdict,
                                    json!({
                                        "source": "proxy",
                                        "event": "abac_deny_extension",
                                        "abac_policy": policy_id,
                                        "extension_id": safe_extension_id,
                                        "method": safe_ext_method,
                                    }),
                                )
                                .await
                            {
                                tracing::warn!("Audit log failed for ABAC deny: {}", e);
                            }
                            let response = make_denial_response(&id, &reason);
                            write_message(agent_writer, &response)
                                .await
                                .map_err(ProxyError::Framing)?;
                            return Ok(());
                        }
                        vellaveto_engine::abac::AbacDecision::Allow { .. } => {
                            // ABAC explicitly allowed — proceed.
                            // NOTE: record_usage not called here because ProxyBridge
                            // does not hold a LeastAgencyTracker (stdio mode).
                        }
                        vellaveto_engine::abac::AbacDecision::NoMatch => {
                            // No ABAC rule matched — existing Allow verdict stands
                        }
                        #[allow(unreachable_patterns)] // AbacDecision is #[non_exhaustive]
                        _ => {
                            // SECURITY: Future variants — fail-closed (deny).
                            tracing::warn!(
                                "Unknown AbacDecision variant in extension method — fail-closed"
                            );
                            let reason =
                                "Access denied by policy (unknown ABAC decision)".to_string();
                            let verdict = Verdict::Deny {
                                reason: reason.clone(),
                            };
                            if let Err(e) = self
                                .audit
                                .log_entry(
                                    &action,
                                    &verdict,
                                    json!({
                                        "source": "proxy",
                                        "event": "abac_unknown_variant_deny_extension",
                                        "extension_id": safe_extension_id,
                                    }),
                                )
                                .await
                            {
                                tracing::warn!("Audit log failed for ABAC deny: {}", e);
                            }
                            let response = make_denial_response(&id, &reason);
                            write_message(agent_writer, &response)
                                .await
                                .map_err(ProxyError::Framing)?;
                            return Ok(());
                        }
                    }
                }

                // SECURITY (FIND-R46-004): DLP scan extension method parameters
                // before forwarding. Extension methods must not bypass DLP.
                let dlp_findings = scan_parameters_for_secrets(&params);
                if !dlp_findings.is_empty() {
                    let patterns: Vec<String> = dlp_findings
                        .iter()
                        .map(|f| format!("{} at {}", f.pattern_name, f.location))
                        .collect();
                    tracing::warn!(
                        "SECURITY: DLP alert in extension method '{}': {:?}",
                        safe_ext_method,
                        patterns
                    );
                    let dlp_action = vellaveto_types::Action::new(
                        "vellaveto",
                        "extension_dlp_blocked",
                        json!({
                            "extension_id": safe_extension_id,
                            "method": safe_ext_method,
                            "findings": patterns,
                        }),
                    );
                    if let Err(e) = self
                        .audit
                        .log_entry(
                            &dlp_action,
                            &Verdict::Deny {
                                reason: format!(
                                    "Extension method blocked: secrets detected in parameters ({:?})",
                                    patterns
                                ),
                            },
                            json!({
                                "source": "proxy",
                                "event": "extension_dlp_blocked",
                                "extension_id": safe_extension_id,
                                "method": safe_ext_method,
                            }),
                        )
                        .await
                    {
                        tracing::warn!("Failed to audit extension DLP finding: {}", e);
                    }
                    let response =
                        make_denial_response(&id, "Request blocked: security policy violation");
                    write_message(agent_writer, &response)
                        .await
                        .map_err(ProxyError::Framing)?;
                    return Ok(());
                }

                // SECURITY (R231-MCP-1): Injection scanning for extension method
                // parameters — parity with tool calls, passthrough, and notifications.
                if !self.injection_disabled {
                    let synthetic_msg = json!({
                        "method": safe_ext_method,
                        "params": params.clone(),
                    });
                    let injection_matches: Vec<String> =
                        if let Some(ref scanner) = self.injection_scanner {
                            scanner
                                .scan_notification(&synthetic_msg)
                                .into_iter()
                                .map(|s| s.to_string())
                                .collect()
                        } else {
                            scan_notification_for_injection(&synthetic_msg)
                                .into_iter()
                                .map(|s| s.to_string())
                                .collect()
                        };
                    if !injection_matches.is_empty() {
                        tracing::warn!(
                            "SECURITY: Injection in extension method '{}:{}': {:?}",
                            safe_extension_id,
                            safe_ext_method,
                            injection_matches
                        );
                        let verdict = if self.injection_blocking {
                            Verdict::Deny {
                                reason: format!(
                                    "Extension method blocked: injection detected in parameters ({:?})",
                                    injection_matches
                                ),
                            }
                        } else {
                            Verdict::Allow
                        };
                        if let Err(e) = self
                            .audit
                            .log_entry(
                                &action,
                                &verdict,
                                json!({
                                    "source": "proxy",
                                    "event": "extension_injection_detected",
                                    "extension_id": safe_extension_id,
                                    "method": safe_ext_method,
                                    "patterns": injection_matches,
                                    "blocked": self.injection_blocking,
                                }),
                            )
                            .await
                        {
                            tracing::warn!("Failed to audit extension injection finding: {}", e);
                        }
                        if self.injection_blocking {
                            let response = make_denial_response(
                                &id,
                                "Request blocked: security policy violation",
                            );
                            write_message(agent_writer, &response)
                                .await
                                .map_err(ProxyError::Framing)?;
                            return Ok(());
                        }
                    }
                }

                // SECURITY (FIND-R180-001): Memory poisoning CHECK for extension
                // method parameters — parity with tool calls, resource reads, and tasks.
                let poisoning_matches = state.memory_tracker.check_parameters(&params);
                if !poisoning_matches.is_empty() {
                    for m in &poisoning_matches {
                        tracing::warn!(
                            "SECURITY: Memory poisoning detected in extension method '{}': \
                             param '{}' contains replayed data (fingerprint: {})",
                            safe_ext_method,
                            m.param_location,
                            m.fingerprint
                        );
                    }
                    let deny_reason = format!(
                        "Memory poisoning detected: {} replayed data fragment(s) in extension '{}'",
                        poisoning_matches.len(),
                        safe_ext_method
                    );
                    if let Err(e) = self
                        .audit
                        .log_entry(
                            &action,
                            &Verdict::Deny {
                                reason: deny_reason.clone(),
                            },
                            json!({
                                "source": "proxy",
                                "event": "memory_poisoning_detected",
                                "matches": poisoning_matches.len(),
                                "extension_id": safe_extension_id,
                                "method": safe_ext_method,
                            }),
                        )
                        .await
                    {
                        tracing::error!(
                            error = %e,
                            method = %safe_ext_method,
                            "Failed to log audit entry for extension memory poisoning detection"
                        );
                    }
                    let response =
                        make_denial_response(&id, "Request blocked: security policy violation");
                    write_message(agent_writer, &response)
                        .await
                        .map_err(ProxyError::Framing)?;
                    return Ok(());
                }

                // SECURITY (FIND-R46-004): Fingerprint extension method parameters
                // for future memory poisoning detection in downstream calls.
                state.memory_tracker.extract_from_value(&params);

                if let Err(e) = self
                    .audit
                    .log_entry(
                        &action,
                        &Verdict::Allow,
                        json!({
                            "source": "proxy",
                            "event": "extension_method_forwarded",
                            "extension_id": safe_extension_id,
                            "method": safe_ext_method,
                        }),
                    )
                    .await
                {
                    tracing::warn!("Audit log failed: {}", e);
                }
                state.record_forwarded_action(&method);
                // SECURITY (FIND-R150-002): Truncate before PendingRequest storage.
                let truncated_ext: String = method.chars().take(256).collect();
                state.track_pending_request(&id, truncated_ext, None);
                write_message(child_stdin, &msg)
                    .await
                    .map_err(ProxyError::Framing)?;
            }
            Ok((verdict @ Verdict::Deny { .. }, _))
            | Ok((verdict @ Verdict::RequireApproval { .. }, _)) => {
                // SECURITY (FIND-R166-001/002): Extract reason without unreachable!().
                // Verdict is #[non_exhaustive] — future variants must not panic.
                let reason = match &verdict {
                    Verdict::Deny { reason } => reason.clone(),
                    Verdict::RequireApproval { reason } => reason.clone(),
                    other => format!("Denied by policy: {:?}", other),
                };
                let response = make_denial_response(&id, &reason);
                if let Err(e) = self
                    .audit
                    .log_entry(
                        &action,
                        &verdict,
                        json!({
                            "source": "proxy",
                            "event": "extension_method_denied",
                            "extension_id": safe_extension_id,
                            "method": safe_ext_method,
                        }),
                    )
                    .await
                {
                    tracing::warn!("Audit log failed: {}", e);
                }
                write_message(agent_writer, &response)
                    .await
                    .map_err(ProxyError::Framing)?;
            }
            Ok((_, _)) => {
                let reason = "Unknown verdict type - failing closed".to_string();
                let verdict = Verdict::Deny {
                    reason: reason.clone(),
                };
                if let Err(e) = self
                    .audit
                    .log_entry(
                        &action,
                        &verdict,
                        json!({
                            "source": "proxy",
                            "event": "extension_method_unknown_verdict",
                            "extension_id": safe_extension_id,
                        }),
                    )
                    .await
                {
                    tracing::warn!("Audit log failed: {}", e);
                }
                let response = make_denial_response(&id, &reason);
                write_message(agent_writer, &response)
                    .await
                    .map_err(ProxyError::Framing)?;
            }
            Err(e) => {
                tracing::error!(
                    "Policy evaluation error for extension '{}': {}",
                    safe_extension_id,
                    e
                );
                let reason = "Policy evaluation failed".to_string();
                let verdict = Verdict::Deny {
                    reason: reason.clone(),
                };
                if let Err(e) = self
                    .audit
                    .log_entry(
                        &action,
                        &verdict,
                        json!({
                            "source": "proxy",
                            "event": "extension_method_eval_error",
                            "extension_id": safe_extension_id,
                        }),
                    )
                    .await
                {
                    tracing::warn!("Audit log failed: {}", e);
                }
                let response = make_denial_response(&id, &reason);
                write_message(agent_writer, &response)
                    .await
                    .map_err(ProxyError::Framing)?;
            }
        }
        Ok(())
    }

    /// Handle a passthrough message (not a tool call, resource read, or task request).
    async fn handle_passthrough(
        &self,
        msg: &Value,
        state: &mut RelayState,
        io: &mut IoWriters<'_>,
    ) -> Result<(), ProxyError> {
        let IoWriters {
            agent: agent_writer,
            child: child_stdin,
        } = io;
        // Track passthrough requests that have an id
        if let Some(id) = msg.get("id") {
            if !id.is_null() {
                // SECURITY (R33-MCP-1): Enforce MAX_PENDING_REQUESTS on PassThrough.
                if state.pending_requests.len() >= MAX_PENDING_REQUESTS {
                    let response = make_invalid_response(id, "Too many pending requests");
                    tracing::warn!("PassThrough request rejected: pending request limit reached");
                    write_message(agent_writer, &response)
                        .await
                        .map_err(ProxyError::Framing)?;
                    return Ok(());
                }
                let id_key = id.to_string();
                // SECURITY (FIND-R136-001): Apply same key-length guard as
                // track_pending_request() (FIND-R112-003). Without this, a
                // pathologically large JSON-RPC `id` bypasses the size check.
                let method = msg.get("method").and_then(|m| m.as_str());
                if id_key.len() > 1024 {
                    tracing::warn!(
                        "dropping oversized passthrough request id key ({} bytes)",
                        id_key.len()
                    );
                    // Still forward the message but don't track it
                } else {
                    // SECURITY (FIND-R210-002): Check for duplicate in-flight IDs
                    // before inserting passthrough tracking entry.  A collision
                    // between a tools/call entry and a passthrough entry would
                    // corrupt circuit breaker attribution.
                    if state.pending_requests.contains_key(&id_key) {
                        tracing::warn!(
                            "SECURITY: duplicate in-flight request ID in passthrough (method={:?}); keeping original entry",
                            method
                        );
                    } else {
                        // SECURITY (FIND-R136-001): Truncate method name to prevent
                        // unbounded strings stored in PendingRequest.
                        let method_name: String =
                            method.unwrap_or("unknown").chars().take(256).collect();
                        state.pending_requests.insert(
                            id_key.clone(),
                            PendingRequest {
                                sent_at: Instant::now(),
                                tool_name: method_name,
                                trace: None,
                            },
                        );
                    }
                }
                // SECURITY (R29-MCP-1): Normalize method before tracking.
                let normalized_method = method.map(crate::extractor::normalize_method);

                // C-8.2: Track tools/list requests for annotation extraction
                // SECURITY (FIND-R46-003): Cap set size to prevent OOM.
                if normalized_method.as_deref() == Some("tools/list") {
                    if state.tools_list_request_ids.len() < MAX_REQUEST_TRACKING_IDS {
                        state.tools_list_request_ids.insert(id_key.clone());
                    } else {
                        tracing::warn!(
                            "tools_list_request_ids at capacity ({}); dropping tracking for {}",
                            MAX_REQUEST_TRACKING_IDS,
                            id_key
                        );
                    }
                }

                // C-8.4: Track initialize requests for protocol version
                // SECURITY (FIND-R46-003): Cap set size to prevent OOM.
                if normalized_method.as_deref() == Some("initialize") {
                    if state.initialize_request_ids.len() < MAX_REQUEST_TRACKING_IDS {
                        state.initialize_request_ids.insert(id_key);
                    } else {
                        tracing::warn!(
                            "initialize_request_ids at capacity ({}); dropping tracking for {}",
                            MAX_REQUEST_TRACKING_IDS,
                            id_key
                        );
                    }
                    if let Some(ver) = msg
                        .get("params")
                        .and_then(|p| p.get("protocolVersion"))
                        .and_then(|v| v.as_str())
                    {
                        tracing::info!("MCP initialize: client requested protocol version {}", ver);
                    }
                }
            }
        }
        // SECURITY (FIND-R46-RLY-001): DLP scan passthrough message parameters
        // before forwarding. MCP is extensible — any unrecognized method could
        // carry secrets in its parameters, making passthrough a wide-open
        // exfiltration path without scanning.
        let params_to_scan = msg.get("params").cloned().unwrap_or(json!({}));
        let mut dlp_findings = scan_parameters_for_secrets(&params_to_scan);
        // SECURITY (FIND-R96-001): Also scan `result` field for JSON-RPC responses.
        // Agent responses to server-initiated requests (sampling/elicitation) carry
        // data in `result`, not `params`. Without this, secrets in sampling/elicitation
        // responses bypass DLP scanning entirely.
        if let Some(result_val) = msg.get("result") {
            dlp_findings.extend(scan_parameters_for_secrets(result_val));
        }
        if !dlp_findings.is_empty() {
            let method_name = msg
                .get("method")
                .and_then(|m| m.as_str())
                .unwrap_or("unknown");
            let patterns: Vec<String> = dlp_findings
                .iter()
                .map(|f| format!("{} at {}", f.pattern_name, f.location))
                .collect();
            tracing::warn!(
                "SECURITY: DLP alert in passthrough '{}': {:?}",
                method_name,
                patterns
            );
            let action = vellaveto_types::Action::new(
                "vellaveto",
                "passthrough_dlp_blocked",
                json!({
                    "method": method_name,
                    "findings": patterns,
                }),
            );
            if let Err(e) = self
                .audit
                .log_entry(
                    &action,
                    &Verdict::Deny {
                        reason: format!(
                            "PassThrough blocked: secrets detected in parameters ({:?})",
                            patterns
                        ),
                    },
                    json!({
                        "source": "proxy",
                        "event": "passthrough_dlp_blocked",
                        "method": method_name,
                        "findings": patterns,
                    }),
                )
                .await
            {
                tracing::warn!("Failed to audit passthrough DLP finding: {}", e);
            }
            // Fail-closed: deny the message. Return generic error to agent
            // to avoid leaking which DLP patterns matched.
            if let Some(id) = msg.get("id") {
                if !id.is_null() {
                    // SECURITY (FIND-R52-008): Remove orphaned pending_request entry
                    // to prevent resource leak when DLP scanning blocks the message.
                    let id_key = id.to_string();
                    state.pending_requests.remove(&id_key);
                    state.tools_list_request_ids.remove(&id_key);
                    state.initialize_request_ids.remove(&id_key);
                    let response = json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": {
                            "code": -32001,
                            "message": "Request blocked: security policy violation",
                        }
                    });
                    write_message(agent_writer, &response)
                        .await
                        .map_err(ProxyError::Framing)?;
                }
            }
            return Ok(());
        }

        // SECURITY (FIND-R46-RLY-001): Injection scan passthrough messages.
        // Same rationale — extensible methods must not bypass injection detection.
        if !self.injection_disabled {
            let injection_matches: Vec<String> = if let Some(ref scanner) = self.injection_scanner {
                scanner
                    .scan_notification(msg)
                    .into_iter()
                    .map(|s| s.to_string())
                    .collect()
            } else {
                scan_notification_for_injection(msg)
                    .into_iter()
                    .map(|s| s.to_string())
                    .collect()
            };
            if !injection_matches.is_empty() {
                let method_name = msg
                    .get("method")
                    .and_then(|m| m.as_str())
                    .unwrap_or("unknown");
                tracing::warn!(
                    "SECURITY: Injection detected in passthrough '{}': {:?}",
                    method_name,
                    injection_matches
                );
                let action = vellaveto_types::Action::new(
                    "vellaveto",
                    "passthrough_injection_detected",
                    json!({
                        "method": method_name,
                        "patterns": injection_matches,
                    }),
                );
                let verdict = if self.injection_blocking {
                    Verdict::Deny {
                        reason: format!(
                            "PassThrough blocked: injection detected ({:?})",
                            injection_matches
                        ),
                    }
                } else {
                    Verdict::Allow
                };
                if let Err(e) = self
                    .audit
                    .log_entry(
                        &action,
                        &verdict,
                        json!({
                            "source": "proxy",
                            "event": "passthrough_injection_detected",
                            "method": method_name,
                            "patterns": injection_matches,
                            "blocked": self.injection_blocking,
                        }),
                    )
                    .await
                {
                    tracing::warn!("Failed to audit passthrough injection finding: {}", e);
                }
                if self.injection_blocking {
                    if let Some(id) = msg.get("id") {
                        if !id.is_null() {
                            // SECURITY (FIND-R52-008): Remove orphaned pending_request entry
                            // to prevent resource leak when injection scanning blocks the message.
                            let id_key = id.to_string();
                            state.pending_requests.remove(&id_key);
                            state.tools_list_request_ids.remove(&id_key);
                            state.initialize_request_ids.remove(&id_key);
                            let response = json!({
                                "jsonrpc": "2.0",
                                "id": id,
                                "error": {
                                    "code": -32005,
                                    "message": "Request blocked: injection detected",
                                }
                            });
                            write_message(agent_writer, &response)
                                .await
                                .map_err(ProxyError::Framing)?;
                        }
                    }
                    return Ok(());
                }
            }
        }

        // SECURITY (IMP-R182-008): Memory poisoning check — parity with tool calls,
        // resource reads, tasks, and extension methods.
        // SECURITY (IMP-R184-010): Also scan `result` field — parity with DLP scan
        // which scans both params and result (FIND-R96-001).
        let mut poisoning_matches = state.memory_tracker.check_parameters(&params_to_scan);
        if let Some(result_val) = msg.get("result") {
            poisoning_matches.extend(state.memory_tracker.check_parameters(result_val));
        }
        if !poisoning_matches.is_empty() {
            let method_name = msg
                .get("method")
                .and_then(|m| m.as_str())
                .unwrap_or("unknown");
            for m in &poisoning_matches {
                tracing::warn!(
                    "SECURITY: Memory poisoning detected in passthrough '{}': \
                     param '{}' contains replayed data (fingerprint: {})",
                    method_name,
                    m.param_location,
                    m.fingerprint
                );
            }
            let action = vellaveto_types::Action::new(
                "vellaveto",
                "passthrough_memory_poisoning",
                json!({
                    "method": method_name,
                    "matches": poisoning_matches.len(),
                }),
            );
            if let Err(e) = self
                .audit
                .log_entry(
                    &action,
                    &Verdict::Deny {
                        reason: format!(
                            "PassThrough blocked: memory poisoning detected ({} matches)",
                            poisoning_matches.len()
                        ),
                    },
                    json!({
                        "source": "proxy",
                        "event": "passthrough_memory_poisoning",
                        "method": method_name,
                    }),
                )
                .await
            {
                tracing::warn!("Failed to audit passthrough memory poisoning: {}", e);
            }
            if let Some(id) = msg.get("id") {
                if !id.is_null() {
                    let id_key = id.to_string();
                    state.pending_requests.remove(&id_key);
                    state.tools_list_request_ids.remove(&id_key);
                    state.initialize_request_ids.remove(&id_key);
                    let response = json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": {
                            "code": -32005,
                            "message": "Request blocked: security policy violation",
                        }
                    });
                    write_message(agent_writer, &response)
                        .await
                        .map_err(ProxyError::Framing)?;
                }
            }
            return Ok(());
        }
        // Fingerprint passthrough params+result for future poisoning detection.
        state.memory_tracker.extract_from_value(&params_to_scan);
        if let Some(result_val) = msg.get("result") {
            state.memory_tracker.extract_from_value(result_val);
        }

        // Forward the message after security scanning passes
        write_message(child_stdin, msg)
            .await
            .map_err(ProxyError::Framing)
    }

    /// Handle a response received from the child MCP server.
    async fn handle_child_response(
        &self,
        mut msg: Value,
        state: &mut RelayState,
        io: &mut IoWriters<'_>,
    ) -> Result<(), ProxyError> {
        let IoWriters {
            agent: agent_writer,
            child: child_stdin,
        } = io;
        // C-8.5 / R8-MCP-1: Block server-initiated requests, except for
        // MCP-specified server→client requests (sampling, elicitation).
        if let Some(method) = msg.get("method").and_then(|m| m.as_str()) {
            // SECURITY (R23-MCP-3): Treat `"id": null` as a notification.
            let is_request = msg.get("id").is_some_and(|v| !v.is_null());
            if is_request {
                // SECURITY (FIND-R46-RLY-002): Per the MCP specification,
                // `sampling/createMessage` and `elicitation/create` are
                // server→client requests: the MCP server asks the client/LLM
                // to perform sampling or prompt the user. These MUST be
                // forwarded to the agent (through their respective security
                // handlers) rather than blocked by the server-side-request
                // guard. Blocking them renders MCP sampling non-functional.
                let normalized = crate::extractor::normalize_method(method);
                match normalized.as_str() {
                    "sampling/createmessage" => {
                        let id = msg.get("id").cloned().unwrap_or(Value::Null);
                        tracing::debug!(
                            "Server→client sampling/createMessage request (id: {}) — routing to sampling handler",
                            id
                        );
                        return self
                            .handle_sampling_request(&msg, id, state, agent_writer)
                            .await;
                    }
                    "elicitation/create" => {
                        let id = msg.get("id").cloned().unwrap_or(Value::Null);
                        tracing::debug!(
                            "Server→client elicitation/create request (id: {}) — routing to elicitation handler",
                            id
                        );
                        return self
                            .handle_elicitation_request(&msg, id, state, agent_writer)
                            .await;
                    }
                    _ => {}
                }

                // All other server-initiated requests are blocked.
                // SECURITY (FIND-R110-004): Sanitize method name before logging/echoing
                // to prevent log injection and information leakage from child server.
                let safe_method = vellaveto_types::sanitize_for_log(method, 128);
                tracing::warn!(
                    "SECURITY: Server sent request '{}' — blocked (only notifications and sampling/elicitation allowed from server)",
                    safe_method
                );
                let action = vellaveto_types::Action::new(
                    "vellaveto",
                    "server_request_blocked",
                    json!({
                        "method": safe_method,
                        "request_id": msg.get("id"),
                    }),
                );
                let verdict = Verdict::Deny {
                    reason: "Server-initiated request blocked by Vellaveto".to_string(),
                };
                if let Err(e) = self
                    .audit
                    .log_entry(
                        &action,
                        &verdict,
                        json!({"source": "proxy", "event": "server_request_blocked"}),
                    )
                    .await
                {
                    tracing::warn!("Failed to audit server request block: {}", e);
                }
                let error_response = json!({
                    "jsonrpc": "2.0",
                    "id": msg.get("id").cloned().unwrap_or(Value::Null),
                    "error": {
                        "code": -32001,
                        "message": "Server-initiated request blocked by Vellaveto proxy"
                    }
                });
                write_message(child_stdin, &error_response)
                    .await
                    .map_err(ProxyError::Framing)?;
                return Ok(());
            }

            // Notifications: forwarded through with DLP + injection scanning
            if self.response_dlp_enabled {
                let dlp_findings = scan_notification_for_secrets(&msg);
                if !dlp_findings.is_empty() {
                    let patterns: Vec<String> = dlp_findings
                        .iter()
                        .map(|f| format!("{} at {}", f.pattern_name, f.location))
                        .collect();
                    tracing::warn!("SECURITY: DLP alert in server notification: {:?}", patterns);
                    let action = vellaveto_types::Action::new(
                        "vellaveto",
                        "notification_dlp_secret_detected",
                        json!({
                            "findings": patterns,
                            "method": msg.get("method"),
                        }),
                    );
                    let verdict = if self.response_dlp_blocking {
                        Verdict::Deny {
                            reason: format!(
                                "Notification blocked: secrets detected ({:?})",
                                patterns
                            ),
                        }
                    } else {
                        Verdict::Allow
                    };
                    if let Err(e) = self
                        .audit
                        .log_entry(
                            &action,
                            &verdict,
                            json!({
                                "source": "proxy",
                                "event": "notification_dlp_secret_detected",
                                "findings": patterns,
                                "blocked": self.response_dlp_blocking,
                            }),
                        )
                        .await
                    {
                        tracing::warn!("Failed to audit notification DLP: {}", e);
                    }
                    if self.response_dlp_blocking {
                        return Ok(());
                    }
                }
            }

            // SECURITY (R21-MCP-1): Scan notification params for injection patterns.
            if !self.injection_disabled {
                let injection_matches: Vec<String> =
                    if let Some(ref scanner) = self.injection_scanner {
                        scanner
                            .scan_notification(&msg)
                            .into_iter()
                            .map(|s| s.to_string())
                            .collect()
                    } else {
                        scan_notification_for_injection(&msg)
                            .into_iter()
                            .map(|s| s.to_string())
                            .collect()
                    };
                if !injection_matches.is_empty() {
                    tracing::warn!(
                        "SECURITY: Injection detected in server notification: {:?}",
                        injection_matches
                    );
                    let action = vellaveto_types::Action::new(
                        "vellaveto",
                        "notification_injection_detected",
                        json!({
                            "patterns": injection_matches,
                            "method": msg.get("method"),
                        }),
                    );
                    let verdict = if self.injection_blocking {
                        Verdict::Deny {
                            reason: format!(
                                "Notification blocked: injection detected ({:?})",
                                injection_matches
                            ),
                        }
                    } else {
                        Verdict::Allow
                    };
                    if let Err(e) = self
                        .audit
                        .log_entry(
                            &action,
                            &verdict,
                            json!({
                                "source": "proxy",
                                "event": "notification_injection_detected",
                                "patterns": injection_matches,
                                "blocked": self.injection_blocking,
                            }),
                        )
                        .await
                    {
                        tracing::warn!("Failed to audit notification injection: {}", e);
                    }
                    if self.injection_blocking {
                        return Ok(());
                    }
                }
            }

            // SECURITY (R38-MCP-1 + FIND-052): Fingerprint notification data.
            if let Some(method) = msg.get("method") {
                state.memory_tracker.extract_from_value(method);
            }
            if let Some(params) = msg.get("params") {
                state.memory_tracker.extract_from_value(params);
            }

            // SECURITY (FIND-R46-009): Notifications (messages with method but no
            // non-null id) are fully handled above. Return early to prevent
            // fall-through into response-processing logic (which would perform
            // redundant scanning and incorrect pending-request bookkeeping).
            let is_notification = msg.get("id").is_none_or(|v| v.is_null());
            if is_notification {
                return write_message(agent_writer, &msg)
                    .await
                    .map_err(ProxyError::Framing);
            }
        }

        // Consumer shield: desanitize inbound response content
        #[cfg(feature = "consumer-shield")]
        if let Some(ref sanitizer) = self.shield_sanitizer {
            if msg.get("result").is_some() || msg.get("error").is_some() {
                match sanitizer.desanitize_json(&msg) {
                    Ok(desanitized) => msg = desanitized,
                    Err(e) => {
                        tracing::warn!("Shield desanitize failed: {} — forwarding original", e);
                    }
                }
            }
        }

        // Consumer shield: record inbound context for session isolation (after desanitize)
        #[cfg(feature = "consumer-shield")]
        if let Some(ref isolator) = self.shield_context_isolator {
            let session_id = state.agent_id.as_deref().unwrap_or("default");
            if let Err(e) = isolator.record_json_response(session_id, &msg) {
                tracing::debug!("Shield context record (inbound) failed: {}", e);
            }
        }

        // Remove from pending requests on response
        let mut response_tool_name: Option<String> = None;
        let mut response_trace: Option<EvaluationTrace> = None;
        if let Some(id) = msg.get("id") {
            if !id.is_null() {
                let id_key = id.to_string();
                // Phase 3.1: Circuit breaker recording on response
                if let Some(pending) = state.pending_requests.remove(&id_key) {
                    response_tool_name = Some(pending.tool_name.clone());
                    response_trace = pending.trace;
                    if let Some(ref cb) = self.circuit_breaker {
                        if msg.get("error").is_some() {
                            cb.record_failure(&pending.tool_name);
                        } else {
                            cb.record_success(&pending.tool_name);
                        }
                    }
                }

                // C-8.2: If this is a tools/list response, extract annotations.
                // SECURITY (FIND-R46-006): The tools/list response is evaluated and
                // forwarded using the same parsed `serde_json::Value`. `write_message`
                // re-serializes this Value to canonical JSON, eliminating any TOCTOU
                // gap between evaluation and forwarding (no raw wire bytes are reused).
                if state.tools_list_request_ids.remove(&id_key) {
                    self.handle_tools_list_response(&msg, state).await;
                }

                // C-8.4: If this is an initialize response, extract protocol version
                if state.initialize_request_ids.remove(&id_key) {
                    if let Some(ver) = msg
                        .get("result")
                        .and_then(|r| r.get("protocolVersion"))
                        .and_then(|v| v.as_str())
                    {
                        // SECURITY (FIND-R136-002): Cap + sanitize protocol version
                        // from child server to prevent unbounded storage and log injection.
                        const MAX_PROTOCOL_VERSION_LEN: usize = 64;
                        let safe_ver =
                            vellaveto_types::sanitize_for_log(ver, MAX_PROTOCOL_VERSION_LEN);
                        tracing::info!(
                            "MCP initialize: server negotiated protocol version {}",
                            safe_ver
                        );
                        state.negotiated_protocol_version = Some(safe_ver.clone());

                        // R227: Capture server name for discovery engine indexing.
                        if let Some(name) = msg
                            .get("result")
                            .and_then(|r| r.get("serverInfo"))
                            .and_then(|s| s.get("name"))
                            .and_then(|n| n.as_str())
                        {
                            const MAX_SERVER_NAME_LEN: usize = 128;
                            let safe_name =
                                vellaveto_types::sanitize_for_log(name, MAX_SERVER_NAME_LEN);
                            state.server_name = Some(safe_name);
                        }

                        let action = vellaveto_types::Action::new(
                            "vellaveto",
                            "protocol_version",
                            json!({
                                "server_protocol_version": safe_ver,
                                "server_name": msg.get("result")
                                    .and_then(|r| r.get("serverInfo"))
                                    .and_then(|s| s.get("name"))
                                    .and_then(|n| n.as_str()),
                                "server_version": msg.get("result")
                                    .and_then(|r| r.get("serverInfo"))
                                    .and_then(|s| s.get("version"))
                                    .and_then(|v| v.as_str()),
                                "capabilities": msg.get("result")
                                    .and_then(|r| r.get("capabilities")),
                            }),
                        );
                        let verdict = Verdict::Allow;
                        if let Err(e) = self
                            .audit
                            .log_entry(
                                &action,
                                &verdict,
                                json!({"source": "proxy", "event": "protocol_negotiation"}),
                            )
                            .await
                        {
                            tracing::warn!("Failed to audit protocol version: {}", e);
                        }
                    }
                }
            }
        }

        // SECURITY (FIND-R79-001): Track whether injection, schema violation, or DLP
        // was detected (even in log-only mode) to gate memory_tracker.record_response().
        // Recording fingerprints from tainted responses would poison the tracker.
        // Parity with HTTP (inspection.rs:638), WS (mod.rs:2659), gRPC (service.rs:1115).
        let mut injection_found = false;
        let mut schema_violation_found = false;
        let mut dlp_found = false;

        // C-8.3: Inspect response for prompt injection (OWASP MCP06)
        let injection_matches: Vec<String> = if self.injection_disabled {
            Vec::new()
        } else if let Some(ref scanner) = self.injection_scanner {
            scanner
                .scan_response(&msg)
                .into_iter()
                .map(|s| s.to_string())
                .collect()
        } else {
            scan_response_for_injection(&msg)
                .into_iter()
                .map(|s| s.to_string())
                .collect()
        };
        if !injection_matches.is_empty() {
            injection_found = true;
            tracing::warn!(
                "SECURITY: Potential prompt injection in tool response! \
                 Matched patterns: {:?}",
                injection_matches
            );
            let (verdict, should_block) = if self.injection_blocking {
                (
                    Verdict::Deny {
                        reason: format!(
                            "Response blocked: prompt injection detected ({})",
                            injection_matches.join(", ")
                        ),
                    },
                    true,
                )
            } else {
                (Verdict::Allow, false)
            };
            let action = vellaveto_types::Action::new(
                "vellaveto",
                "response_inspection",
                json!({
                    "matched_patterns": injection_matches,
                    "response_id": msg.get("id"),
                    "blocked": should_block,
                }),
            );
            if let Err(e) = self
                .audit
                .log_entry(
                    &action,
                    &verdict,
                    json!({
                        "source": "proxy",
                        "event": "prompt_injection_detected",
                        "patterns": injection_matches,
                        "protocol_version": state.negotiated_protocol_version,
                        "blocked": should_block,
                    }),
                )
                .await
            {
                tracing::warn!("Failed to audit injection detection: {}", e);
            }

            if should_block {
                let blocked_response = json!({
                    "jsonrpc": "2.0",
                    "id": msg.get("id").cloned().unwrap_or(Value::Null),
                    "error": {
                        "code": -32005,
                        "message": "Response blocked: prompt injection detected"
                    }
                });
                write_message(agent_writer, &blocked_response)
                    .await
                    .map_err(ProxyError::Framing)?;
                return Ok(());
            }
        }

        // MCP 2025-06-18: Validate structuredContent against output schemas
        if let Some(result) = msg.get("result") {
            if let Some(structured) = result.get("structuredContent") {
                if let Some(tool_name) = response_tool_name.as_deref() {
                    match self.output_schema_registry.validate(tool_name, structured) {
                        ValidationResult::Valid => {
                            tracing::debug!("structuredContent validated for tool '{}'", tool_name);
                        }
                        ValidationResult::NoSchema => {
                            // Note: NoSchema in non-blocking mode is not a tainted response,
                            // so we do NOT set schema_violation_found here. In blocking mode,
                            // the code returns early below, making the flag moot.
                            if self.output_schema_blocking {
                                tracing::warn!(
                                    "SECURITY: No output schema registered for tool '{}' \
                                     while output_schema_blocking=true; blocking response",
                                    tool_name
                                );
                                let action = vellaveto_types::Action::new(
                                    "vellaveto",
                                    "output_schema_violation",
                                    json!({
                                        "tool": tool_name,
                                        "violations": ["no output schema registered for tool"],
                                        "response_id": msg.get("id"),
                                    }),
                                );
                                if let Err(e) = self
                                    .audit
                                    .log_entry(
                                        &action,
                                        &Verdict::Deny {
                                            reason: format!(
                                                "structuredContent schema validation blocked: no schema registered for tool '{}'",
                                                tool_name
                                            ),
                                        },
                                        json!({"source": "proxy", "event": "output_schema_violation"}),
                                    )
                                    .await
                                {
                                    tracing::warn!(
                                        "Failed to audit output schema missing-schema violation: {}",
                                        e
                                    );
                                }

                                let blocked_response = json!({
                                    "jsonrpc": "2.0",
                                    "id": msg.get("id").cloned().unwrap_or(Value::Null),
                                    "error": {
                                        "code": -32005,
                                        "message": "Response blocked: no output schema registered for structuredContent validation"
                                    }
                                });
                                write_message(agent_writer, &blocked_response)
                                    .await
                                    .map_err(ProxyError::Framing)?;
                                return Ok(());
                            } else {
                                tracing::debug!(
                                    "No output schema registered for tool '{}', skipping validation",
                                    tool_name
                                );
                            }
                        }
                        ValidationResult::Invalid { violations } => {
                            tracing::warn!(
                                "SECURITY: structuredContent validation failed for tool '{}': {:?}",
                                tool_name,
                                violations
                            );
                            let action = vellaveto_types::Action::new(
                                "vellaveto",
                                "output_schema_violation",
                                json!({
                                    "tool": tool_name,
                                    "violations": violations,
                                    "response_id": msg.get("id"),
                                }),
                            );
                            if let Err(e) = self
                                .audit
                                .log_entry(
                                    &action,
                                    &Verdict::Deny {
                                        reason: format!(
                                            "structuredContent validation failed: {:?}",
                                            violations
                                        ),
                                    },
                                    json!({"source": "proxy", "event": "output_schema_violation"}),
                                )
                                .await
                            {
                                tracing::warn!("Failed to audit output schema violation: {}", e);
                            }

                            if self.output_schema_blocking {
                                let blocked_response = json!({
                                    "jsonrpc": "2.0",
                                    "id": msg.get("id").cloned().unwrap_or(Value::Null),
                                    "error": {
                                        "code": -32005,
                                        "message": "Response blocked: structuredContent schema validation failed"
                                    }
                                });
                                write_message(agent_writer, &blocked_response)
                                    .await
                                    .map_err(ProxyError::Framing)?;
                                return Ok(());
                            }
                            // Set after early-return so the flag is only
                            // read when execution continues to the
                            // record_response guard below.
                            schema_violation_found = true;
                        }
                    }
                } else if self.output_schema_blocking {
                    // Note: no need to set schema_violation_found here because
                    // this branch returns early via `return Ok(())` below.
                    tracing::warn!(
                        "SECURITY: structuredContent present but tool context unavailable \
                         while output_schema_blocking=true; blocking response"
                    );
                    let action = vellaveto_types::Action::new(
                        "vellaveto",
                        "output_schema_violation",
                        json!({
                            "tool": Value::Null,
                            "violations": ["tool context unavailable for structuredContent schema validation"],
                            "response_id": msg.get("id"),
                        }),
                    );
                    if let Err(e) = self
                        .audit
                        .log_entry(
                            &action,
                            &Verdict::Deny {
                                reason: "structuredContent schema validation blocked: tool context unavailable".to_string(),
                            },
                            json!({"source": "proxy", "event": "output_schema_violation"}),
                        )
                        .await
                    {
                        tracing::warn!(
                            "Failed to audit output schema context violation: {}",
                            e
                        );
                    }

                    let blocked_response = json!({
                        "jsonrpc": "2.0",
                        "id": msg.get("id").cloned().unwrap_or(Value::Null),
                        "error": {
                            "code": -32005,
                            "message": "Response blocked: structuredContent schema validation unavailable (missing tool context)"
                        }
                    });
                    write_message(agent_writer, &blocked_response)
                        .await
                        .map_err(ProxyError::Framing)?;
                    return Ok(());
                } else {
                    tracing::debug!(
                        "structuredContent present but tool context unavailable; skipping schema validation"
                    );
                }
            }
        }

        // DLP response scanning: detect secrets in tool response content
        if self.response_dlp_enabled {
            let dlp_findings = scan_response_for_secrets(&msg);
            if !dlp_findings.is_empty() {
                dlp_found = true;
                let patterns: Vec<String> = dlp_findings
                    .iter()
                    .map(|f| format!("{} at {}", f.pattern_name, f.location))
                    .collect();
                tracing::warn!("SECURITY: DLP alert in tool response: {:?}", patterns);
                let action = vellaveto_types::Action::new(
                    "vellaveto",
                    "response_dlp_secret_detected",
                    json!({
                        "findings": patterns,
                        "response_id": msg.get("id"),
                    }),
                );
                let verdict = if self.response_dlp_blocking {
                    Verdict::Deny {
                        reason: format!("Response blocked: secrets detected ({:?})", patterns),
                    }
                } else {
                    Verdict::Allow // Log-only
                };
                if let Err(e) = self
                    .audit
                    .log_entry(
                        &action,
                        &verdict,
                        json!({
                            "source": "proxy",
                            "event": "response_dlp_secret_detected",
                            "findings": patterns,
                            "blocked": self.response_dlp_blocking,
                        }),
                    )
                    .await
                {
                    tracing::warn!("Failed to audit response DLP finding: {}", e);
                }

                if self.response_dlp_blocking {
                    let blocked_response = json!({
                        "jsonrpc": "2.0",
                        "id": msg.get("id").cloned().unwrap_or(Value::Null),
                        "error": {
                            "code": -32006,
                            "message": "Response blocked: secrets detected in tool output"
                        }
                    });
                    write_message(agent_writer, &blocked_response)
                        .await
                        .map_err(ProxyError::Framing)?;
                    return Ok(());
                }
            }
        }

        // OWASP ASI06: Record response data for poisoning detection.
        // SECURITY (FIND-R79-001): Skip recording when injection, DLP, or schema
        // violation was detected (even in log-only mode) to avoid poisoning the
        // tracker with tainted data. Parity with HTTP/WS/gRPC handlers.
        if !injection_found && !dlp_found && !schema_violation_found {
            state.memory_tracker.record_response(&msg);
        }

        // Phase 19: Art 50(1) transparency marking
        if self.transparency_marking {
            crate::transparency::mark_ai_mediated(&mut msg);
        }

        // Phase 24: Art 50(2) decision explanation injection
        crate::transparency::inject_decision_explanation(
            &mut msg,
            response_trace.as_ref(),
            self.explanation_verbosity,
        );

        // Phase 19: Art 14 human oversight audit event
        if let Some(tool_name) = response_tool_name.as_deref() {
            if crate::transparency::requires_human_oversight(tool_name, &self.human_oversight_tools)
            {
                let oversight_action = vellaveto_types::Action::new(
                    "vellaveto",
                    "human_oversight_triggered",
                    json!({"tool": tool_name}),
                );
                if let Err(e) = self
                    .audit
                    .log_entry(
                        &oversight_action,
                        &Verdict::Allow,
                        json!({
                            "source": "proxy",
                            "event": "human_oversight_triggered",
                            "tool": tool_name,
                        }),
                    )
                    .await
                {
                    tracing::warn!("Failed to audit human oversight event: {}", e);
                }
            }
        }

        // Relay child response to agent
        write_message(agent_writer, &msg)
            .await
            .map_err(ProxyError::Framing)
    }

    /// Handle tools/list response processing.
    ///
    /// Extracts tool annotations, detects rug-pulls, scans descriptions for
    /// injection, verifies manifests, registers output schemas, and detects
    /// schema poisoning.
    async fn handle_tools_list_response(&self, msg: &Value, state: &mut RelayState) {
        // Phase 4B: Snapshot flagged tools before detection to identify new ones
        let flagged_before: HashSet<String> = state.flagged_tools.clone();

        Self::extract_tool_annotations(
            msg,
            &mut state.known_tool_annotations,
            &mut state.flagged_tools,
            &self.audit,
            &self.known_tools,
        )
        .await;

        // Phase 4B: Persist any newly flagged tools
        for name in state.flagged_tools.difference(&flagged_before) {
            let reason = "annotation_change_or_new_tool";
            self.persist_flagged_tool(name, reason).await;
        }

        // P2: Scan tool descriptions for embedded injection
        if !self.injection_disabled {
            let desc_findings = if let Some(ref scanner) = self.injection_scanner {
                scan_tool_descriptions_with_scanner(msg, scanner)
            } else {
                scan_tool_descriptions(msg)
            };
            for finding in &desc_findings {
                // SECURITY (FIND-R150-001): Sanitize child-provided tool_name before
                // logging to prevent log injection via control/format characters.
                let safe_desc_tool = vellaveto_types::sanitize_for_log(&finding.tool_name, 256);
                tracing::warn!(
                    "SECURITY: Injection detected in tool '{}' description! Patterns: {:?}",
                    safe_desc_tool,
                    finding.matched_patterns
                );
                let action = vellaveto_types::Action::new(
                    "vellaveto",
                    "tool_description_injection",
                    json!({
                        "tool": safe_desc_tool,
                        "matched_patterns": finding.matched_patterns,
                    }),
                );
                if let Err(e) = self
                    .audit
                    .log_entry(
                        &action,
                        &Verdict::Deny {
                            reason: format!(
                                "Tool '{}' description contains injection patterns: {:?}",
                                safe_desc_tool, finding.matched_patterns
                            ),
                        },
                        json!({"source": "proxy", "event": "tool_description_injection"}),
                    )
                    .await
                {
                    tracing::warn!("Failed to audit tool description injection: {}", e);
                }
                // SECURITY (R29-MCP-2): Flag tools with injection in descriptions.
                // SECURITY (FIND-R46-007): Bounded insertion.
                state.flag_tool(finding.tool_name.clone());
                self.persist_flagged_tool(&finding.tool_name, "description_injection")
                    .await;
            }
        }

        // Phase 5: Manifest verification on tools/list responses
        if let Some(ref manifest_cfg) = self.manifest_config {
            if manifest_cfg.enabled {
                match &state.pinned_manifest {
                    None => {
                        if let Some(m) = ToolManifest::from_tools_list(msg) {
                            tracing::info!("Pinned tool manifest: {} tools", m.tools.len());
                            state.pinned_manifest = Some(m);
                        }
                    }
                    Some(pinned) => {
                        if let Err(discrepancies) = manifest_cfg.verify_manifest(pinned, msg) {
                            tracing::warn!(
                                "SECURITY: Tool manifest verification FAILED: {:?}",
                                discrepancies
                            );
                            let action = vellaveto_types::Action::new(
                                "vellaveto",
                                "manifest_verification",
                                json!({
                                    "discrepancies": discrepancies,
                                    "pinned_tool_count": pinned.tools.len(),
                                }),
                            );
                            if let Err(e) = self
                                .audit
                                .log_entry(
                                    &action,
                                    &Verdict::Deny {
                                        reason: format!(
                                            "Manifest verification failed: {:?}",
                                            discrepancies
                                        ),
                                    },
                                    json!({"source": "proxy", "event": "manifest_verification_failed"}),
                                )
                                .await
                            {
                                tracing::warn!("Failed to audit manifest failure: {}", e);
                            }
                        }
                    }
                }
            }
        }

        // MCP 2025-06-18: Register output schemas for structuredContent validation
        self.output_schema_registry.register_from_tools_list(msg);
        tracing::debug!(
            "Output schema registry: {} schemas registered",
            self.output_schema_registry.len()
        );

        // Phase 3.1: Schema poisoning detection (OWASP ASI05)
        if let Some(ref tracker) = self.schema_lineage {
            if let Some(tools) = msg
                .get("result")
                .and_then(|r| r.get("tools"))
                .and_then(|t| t.as_array())
            {
                for tool in tools {
                    if let Some(name) = tool.get("name").and_then(|n| n.as_str()) {
                        let schema = tool.get("inputSchema").cloned().unwrap_or(json!({}));
                        match tracker.observe_schema(name, &schema) {
                            crate::schema_poisoning::ObservationResult::MajorChange {
                                similarity,
                                alert,
                            } => {
                                tracing::warn!(
                                    "SECURITY: Schema poisoning detected for tool '{}': similarity={:.2}",
                                    name, similarity
                                );
                                let action = vellaveto_types::Action::new(
                                    "vellaveto",
                                    "schema_poisoning_detected",
                                    json!({
                                        "tool": name,
                                        "similarity": similarity,
                                        "alert": format!("{:?}", alert),
                                    }),
                                );
                                if let Err(e) = self
                                    .audit
                                    .log_entry(
                                        &action,
                                        &Verdict::Deny {
                                            reason: format!(
                                                "Schema poisoning detected: tool '{}' schema changed (similarity={:.2})",
                                                name, similarity
                                            ),
                                        },
                                        json!({
                                            "source": "proxy",
                                            "event": "schema_poisoning_detected",
                                            "tool": name,
                                        }),
                                    )
                                    .await
                                {
                                    tracing::warn!("Failed to audit schema poisoning: {}", e);
                                }
                                // SECURITY (FIND-R46-007): Bounded insertion.
                                state.flag_tool(name.to_string());
                                self.persist_flagged_tool(name, "schema_poisoning").await;
                            }
                            crate::schema_poisoning::ObservationResult::MinorChange {
                                similarity,
                            } => {
                                tracing::debug!(
                                    "Schema minor change for tool '{}': similarity={:.2}",
                                    name,
                                    similarity
                                );
                                // R227: When block_tool_drift is enabled, ANY schema change
                                // (even minor) blocks the tool. This defends against gradual
                                // capability expansion where a tool incrementally adds
                                // parameters or broadens descriptions.
                                if self.block_tool_drift {
                                    tracing::warn!(
                                        "SECURITY: Tool drift blocked for '{}': schema changed (similarity={:.2})",
                                        name, similarity
                                    );
                                    let action = vellaveto_types::Action::new(
                                        "vellaveto",
                                        "tool_drift_blocked",
                                        json!({
                                            "tool": name,
                                            "similarity": similarity,
                                        }),
                                    );
                                    if let Err(e) = self
                                        .audit
                                        .log_entry(
                                            &action,
                                            &Verdict::Deny {
                                                reason: format!(
                                                    "Tool '{}' schema drifted (similarity={:.2})",
                                                    name, similarity
                                                ),
                                            },
                                            json!({
                                                "source": "proxy",
                                                "event": "tool_drift_blocked",
                                            }),
                                        )
                                        .await
                                    {
                                        tracing::warn!("Failed to audit tool drift: {}", e);
                                    }
                                    state.flag_tool(name.to_string());
                                    self.persist_flagged_tool(name, "tool_drift").await;
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
        }

        // R227 (R24-MCP-1): Ingest tools into discovery engine for intent-based search.
        // This runs after all security checks (injection, manifest, schema poisoning)
        // to avoid indexing tools that were flagged by earlier phases.
        #[cfg(feature = "discovery")]
        if let Some(ref discovery_engine) = self.discovery_engine {
            let server_id = state.server_name.as_deref().unwrap_or("stdio");
            if let Some(result_value) = msg.get("result") {
                match discovery_engine.ingest_tools_list(server_id, result_value) {
                    Ok(count) => {
                        tracing::debug!(
                            server_id = server_id,
                            count = count,
                            "Discovery engine ingested tools from tools/list response"
                        );
                    }
                    Err(e) => {
                        // Advisory only — don't block the response on indexing failure.
                        tracing::warn!(
                            server_id = server_id,
                            error = %e,
                            "Discovery engine failed to ingest tools/list response"
                        );
                    }
                }
            }
        }

        // Topology guard: upsert server from tools/list response for live topology updates.
        // Advisory only — upsert failures don't block the response.
        #[cfg(feature = "discovery")]
        if let Some(ref topology_guard) = self.topology_guard {
            if let Some(result_value) = msg.get("result") {
                let server_id = state.server_name.as_deref().unwrap_or("stdio");
                match build_server_decl_from_tools_list(server_id, result_value) {
                    Ok(decl) => {
                        if let Err(e) = topology_guard.upsert_server(decl) {
                            tracing::warn!(
                                server_id = server_id,
                                error = %e,
                                "Failed to upsert server into topology guard"
                            );
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            server_id = server_id,
                            error = %e,
                            "Failed to parse tools/list for topology"
                        );
                    }
                }
            }
        }
    }

    /// Handle child process termination, flushing pending requests with errors.
    async fn handle_child_terminated(
        &self,
        state: &mut RelayState,
        agent_writer: &mut tokio::io::Stdout,
    ) -> Result<(), ProxyError> {
        if !state.pending_requests.is_empty() {
            tracing::error!(
                "Child MCP server terminated with {} pending requests",
                state.pending_requests.len()
            );
            let crash_ids: Vec<String> = state.pending_requests.keys().cloned().collect();
            let pending_count = crash_ids.len();
            for id_key in &crash_ids {
                // Phase 3.1: Circuit breaker - record crash as failure
                if let Some(pending) = state.pending_requests.remove(id_key) {
                    if let Some(ref cb) = self.circuit_breaker {
                        cb.record_failure(&pending.tool_name);
                    }
                }
                let id: Value = serde_json::from_str(id_key).unwrap_or(Value::Null);
                let response = json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": {
                        "code": -32003,
                        "message": "Child MCP server terminated unexpectedly"
                    }
                });
                if let Err(e) = write_message(agent_writer, &response).await {
                    tracing::error!("Failed to send crash response: {}", e);
                }
            }
            let action = vellaveto_types::Action::new("vellaveto", "child_crash", json!({}));
            if let Err(e) = self
                .audit
                .log_entry(
                    &action,
                    &Verdict::Deny {
                        reason: "Child MCP server terminated unexpectedly".to_string(),
                    },
                    json!({"source": "proxy", "event": "child_crash", "pending_requests": pending_count}),
                )
                .await
            {
                tracing::warn!("Failed to audit child crash: {}", e);
            }
        } else {
            tracing::info!("Child process closed");
        }
        Ok(())
    }

    /// Sweep timed-out pending requests and send error responses.
    async fn sweep_timeouts(&self, state: &mut RelayState, agent_writer: &mut tokio::io::Stdout) {
        let now = Instant::now();
        let timed_out: Vec<String> = state
            .pending_requests
            .iter()
            .filter(|(_, req)| now.duration_since(req.sent_at) > self.request_timeout)
            .map(|(id_key, _)| id_key.clone())
            .collect();

        for id_key in timed_out {
            // Phase 3.1: Circuit breaker - record timeout as failure
            if let Some(pending) = state.pending_requests.remove(&id_key) {
                if let Some(ref cb) = self.circuit_breaker {
                    cb.record_failure(&pending.tool_name);
                }
            }
            let id: Value = serde_json::from_str(&id_key).unwrap_or(Value::Null);
            tracing::warn!("Request timed out: id={}", id_key);
            let response = json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {
                    "code": -32003,
                    "message": "Request timed out: child MCP server did not respond"
                }
            });
            if let Err(e) = write_message(agent_writer, &response).await {
                tracing::error!("Failed to send timeout response: {}", e);
            }
        }
    }
}

/// Build a [`StaticServerDecl`](vellaveto_discovery::topology::StaticServerDecl) from an MCP
/// `tools/list` response JSON. Parses the `tools` array from the result object.
#[cfg(feature = "discovery")]
fn build_server_decl_from_tools_list(
    server_id: &str,
    result_value: &serde_json::Value,
) -> Result<vellaveto_discovery::topology::StaticServerDecl, String> {
    let tools_array = result_value
        .get("tools")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "tools/list result missing 'tools' array".to_string())?;

    // SECURITY (R230-DISC-2): Validate tool count, name length, description length,
    // and input_schema size against topology constants to prevent untrusted data
    // from consuming unbounded memory.
    const MAX_INPUT_SCHEMA_SIZE: usize = 1_048_576; // 1 MB

    if tools_array.len() > vellaveto_discovery::topology::MAX_TOOLS_PER_SERVER {
        return Err(format!(
            "tools/list returned {} tools, exceeds max {}",
            tools_array.len(),
            vellaveto_discovery::topology::MAX_TOOLS_PER_SERVER
        ));
    }

    let mut tools = Vec::with_capacity(tools_array.len());
    for tool_value in tools_array {
        let name = tool_value
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if name.is_empty() {
            continue; // Skip tools with missing/empty names
        }
        if name.len() > vellaveto_discovery::topology::MAX_TOOL_NAME_LEN {
            tracing::warn!(
                tool = %name.chars().take(64).collect::<String>(),
                "Skipping tool with name exceeding max length"
            );
            continue;
        }
        let description = tool_value
            .get("description")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        // R230-DISC-2: Truncate oversized descriptions
        let description =
            if description.len() > vellaveto_discovery::topology::MAX_TOOL_DESCRIPTION_LEN {
                tracing::warn!(tool = %name, "Truncating oversized tool description");
                description
                    .chars()
                    .take(vellaveto_discovery::topology::MAX_TOOL_DESCRIPTION_LEN)
                    .collect()
            } else {
                description
            };
        let input_schema = tool_value
            .get("inputSchema")
            .cloned()
            .unwrap_or(serde_json::json!({}));
        // R230-DISC-8: Reject oversized input schemas
        if let Ok(schema_json) = serde_json::to_string(&input_schema) {
            if schema_json.len() > MAX_INPUT_SCHEMA_SIZE {
                tracing::warn!(tool = %name, size = schema_json.len(), "Skipping tool with oversized inputSchema");
                continue;
            }
        }

        tools.push(vellaveto_discovery::topology::StaticToolDecl {
            name,
            description,
            input_schema,
        });
    }

    Ok(vellaveto_discovery::topology::StaticServerDecl {
        name: server_id.to_string(),
        tools,
        resources: Vec::new(), // tools/list doesn't include resources
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_relay_state_new_initializes_empty() {
        let state = RelayState::new(HashSet::new());
        assert!(state.pending_requests.is_empty());
        assert!(state.tools_list_request_ids.is_empty());
        assert!(state.known_tool_annotations.is_empty());
        assert!(state.initialize_request_ids.is_empty());
        assert!(state.negotiated_protocol_version.is_none());
        assert!(state.flagged_tools.is_empty());
        assert!(state.pinned_manifest.is_none());
        assert!(state.call_counts.is_empty());
        assert!(state.action_history.is_empty());
        assert_eq!(state.elicitation_count, 0);
    }

    #[test]
    fn test_relay_state_flag_tool_succeeds_under_capacity() {
        let mut state = RelayState::new(HashSet::new());
        state.flag_tool("evil_tool".to_string());
        assert!(state.flagged_tools.contains("evil_tool"));
        assert_eq!(state.flagged_tools.len(), 1);
    }

    #[test]
    fn test_relay_state_flag_tool_rejects_at_capacity() {
        let mut initial: HashSet<String> = HashSet::with_capacity(MAX_FLAGGED_TOOLS);
        for i in 0..MAX_FLAGGED_TOOLS {
            initial.insert(format!("tool_{}", i));
        }
        let mut state = RelayState::new(initial);
        assert_eq!(state.flagged_tools.len(), MAX_FLAGGED_TOOLS);

        // Attempting to flag one more should be silently ignored.
        state.flag_tool("overflow_tool".to_string());
        assert!(!state.flagged_tools.contains("overflow_tool"));
        assert_eq!(state.flagged_tools.len(), MAX_FLAGGED_TOOLS);
    }

    #[test]
    fn test_relay_state_record_forwarded_action_increments_count() {
        let mut state = RelayState::new(HashSet::new());
        state.record_forwarded_action("read_file");
        state.record_forwarded_action("read_file");
        assert_eq!(state.call_counts.get("read_file"), Some(&2));
    }

    #[test]
    fn test_relay_state_record_forwarded_action_caps_at_max_call_counts() {
        let mut state = RelayState::new(HashSet::new());
        // Fill call_counts to capacity with unique action names.
        for i in 0..MAX_CALL_COUNTS {
            state.record_forwarded_action(&format!("action_{}", i));
        }
        assert_eq!(state.call_counts.len(), MAX_CALL_COUNTS);

        // The next unique action should be ignored (not inserted).
        state.record_forwarded_action("overflow_action");
        assert!(!state.call_counts.contains_key("overflow_action"));
        assert_eq!(state.call_counts.len(), MAX_CALL_COUNTS);
    }

    #[test]
    fn test_relay_state_record_forwarded_action_evicts_oldest_history() {
        let mut state = RelayState::new(HashSet::new());
        // Record 101 actions: action_0 through action_100.
        for i in 0..=MAX_ACTION_HISTORY {
            state.record_forwarded_action(&format!("action_{}", i));
        }
        // History should be capped at MAX_ACTION_HISTORY (100).
        assert_eq!(state.action_history.len(), MAX_ACTION_HISTORY);
        // The oldest entry (action_0) should have been evicted.
        assert_eq!(state.action_history.front(), Some(&"action_1".to_string()));
        // The newest entry should be present.
        assert_eq!(
            state.action_history.back(),
            Some(&format!("action_{}", MAX_ACTION_HISTORY))
        );
    }

    #[test]
    fn test_relay_state_track_pending_request_succeeds_under_limit() {
        let mut state = RelayState::new(HashSet::new());
        let id = json!(42);
        state.track_pending_request(&id, "read_file".to_string(), None);
        assert_eq!(state.pending_requests.len(), 1);
        let id_key = id.to_string();
        assert!(state.pending_requests.contains_key(&id_key));
        let pending = state.pending_requests.get(&id_key).unwrap();
        assert_eq!(pending.tool_name, "read_file");
        assert!(pending.trace.is_none());
    }

    #[test]
    fn test_relay_state_track_pending_request_rejects_at_limit() {
        let mut state = RelayState::new(HashSet::new());
        // Fill pending_requests to capacity.
        for i in 0..MAX_PENDING_REQUESTS {
            let id = json!(i);
            state.track_pending_request(&id, format!("tool_{}", i), None);
        }
        assert_eq!(state.pending_requests.len(), MAX_PENDING_REQUESTS);

        // The next request should be silently ignored.
        let overflow_id = json!(MAX_PENDING_REQUESTS + 1);
        state.track_pending_request(&overflow_id, "overflow_tool".to_string(), None);
        assert_eq!(state.pending_requests.len(), MAX_PENDING_REQUESTS);
        assert!(!state
            .pending_requests
            .contains_key(&overflow_id.to_string()));
    }

    #[test]
    fn test_relay_state_track_pending_request_ignores_null_id() {
        let mut state = RelayState::new(HashSet::new());
        state.track_pending_request(&Value::Null, "read_file".to_string(), None);
        assert!(state.pending_requests.is_empty());
    }

    #[test]
    fn test_relay_state_evaluation_context_includes_call_counts() {
        let mut state = RelayState::new(HashSet::new());
        state.record_forwarded_action("read_file");
        state.record_forwarded_action("read_file");
        state.record_forwarded_action("write_file");

        let ctx = state.evaluation_context();
        assert_eq!(ctx.call_counts.get("read_file"), Some(&2));
        assert_eq!(ctx.call_counts.get("write_file"), Some(&1));
        assert_eq!(ctx.call_counts.len(), 2);
    }

    #[test]
    fn test_relay_state_evaluation_context_includes_action_history() {
        let mut state = RelayState::new(HashSet::new());
        state.record_forwarded_action("read_file");
        state.record_forwarded_action("write_file");
        state.record_forwarded_action("exec_command");

        let ctx = state.evaluation_context();
        assert_eq!(
            ctx.previous_actions,
            vec![
                "read_file".to_string(),
                "write_file".to_string(),
                "exec_command".to_string()
            ]
        );
    }
}
