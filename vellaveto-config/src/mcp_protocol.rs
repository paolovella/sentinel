// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

use serde::{Deserialize, Serialize};

use crate::default_true;

/// Elicitation interception configuration (MCP 2025-06-18, P2.2).
///
/// Controls whether server-initiated user prompts (`elicitation/create`)
/// are allowed, and what constraints apply. Elicitation can be used for
/// social engineering — servers may request passwords, API keys, or other
/// sensitive data via user prompts.
///
/// # TOML Example
///
/// ```toml
/// [elicitation]
/// enabled = true
/// blocked_field_types = ["password", "ssn", "secret"]
/// max_per_session = 5
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ElicitationConfig {
    /// Master toggle. Default: false (block all elicitation requests).
    #[serde(default)]
    pub enabled: bool,
    /// Field types that should be blocked (e.g. "password", "ssn").
    /// Matched case-insensitively against `type` and `format` fields
    /// in the elicitation schema.
    #[serde(default)]
    pub blocked_field_types: Vec<String>,
    /// Maximum elicitation requests per session. Default: 5.
    #[serde(default = "default_max_elicitation")]
    pub max_per_session: u32,
    /// Phase 1: Blocked URL domains in elicitation content.
    /// Elicitation schemas can include `format: "uri"` fields or embed URLs
    /// in descriptions/defaults that direct users to phishing sites. URLs
    /// with domains matching these patterns are denied.
    /// Supports wildcard prefix: `*.evil.com` matches `phish.evil.com`.
    #[serde(default)]
    pub blocked_url_domains: Vec<String>,
    /// Phase 1: Allowed URL domains in elicitation content.
    /// When non-empty, only URLs with domains matching these patterns are
    /// permitted. All other URL domains are denied.
    #[serde(default)]
    pub allowed_url_domains: Vec<String>,
}

fn default_max_elicitation() -> u32 {
    5
}

impl Default for ElicitationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            blocked_field_types: Vec::new(),
            max_per_session: default_max_elicitation(),
            blocked_url_domains: Vec::new(),
            allowed_url_domains: Vec::new(),
        }
    }
}

/// Maximum number of blocked field types for elicitation config.
pub const MAX_BLOCKED_FIELD_TYPES: usize = 100;

/// Maximum length of a single blocked field type entry.
///
/// SECURITY (FIND-R125-002): Unbounded entries could waste memory during
/// case-insensitive matching in `schema_contains_field_type()`.
pub const MAX_BLOCKED_FIELD_TYPE_LENGTH: usize = 128;

/// Maximum number of URL domain entries for elicitation config.
pub const MAX_ELICITATION_URL_DOMAINS: usize = 256;

/// Maximum length of a single URL domain entry.
pub const MAX_ELICITATION_URL_DOMAIN_LENGTH: usize = 256;

impl ElicitationConfig {
    /// Validate configuration bounds.
    pub fn validate(&self) -> Result<(), String> {
        if self.blocked_field_types.len() > MAX_BLOCKED_FIELD_TYPES {
            return Err(format!(
                "elicitation.blocked_field_types exceeds {MAX_BLOCKED_FIELD_TYPES} entries"
            ));
        }
        // SECURITY (FIND-R125-002): Validate individual entry content.
        for (i, entry) in self.blocked_field_types.iter().enumerate() {
            if entry.is_empty() {
                return Err(format!("elicitation.blocked_field_types[{i}] is empty"));
            }
            if entry.len() > MAX_BLOCKED_FIELD_TYPE_LENGTH {
                return Err(format!(
                    "elicitation.blocked_field_types[{}] length {} exceeds max {}",
                    i,
                    entry.len(),
                    MAX_BLOCKED_FIELD_TYPE_LENGTH
                ));
            }
            // SECURITY (FIND-R158-001): Use canonical has_dangerous_chars() to reject
            // both control chars AND Unicode format chars (zero-width, bidi, BOM).
            if vellaveto_types::has_dangerous_chars(entry) {
                return Err(format!(
                    "elicitation.blocked_field_types[{i}] contains control or format characters"
                ));
            }
        }
        // Phase 1: Validate URL domain lists.
        for (list_name, list) in [
            ("blocked_url_domains", &self.blocked_url_domains),
            ("allowed_url_domains", &self.allowed_url_domains),
        ] {
            if list.len() > MAX_ELICITATION_URL_DOMAINS {
                return Err(format!(
                    "elicitation.{list_name} exceeds {MAX_ELICITATION_URL_DOMAINS} entries"
                ));
            }
            for (i, entry) in list.iter().enumerate() {
                if entry.is_empty() {
                    return Err(format!("elicitation.{list_name}[{i}] is empty"));
                }
                if entry.len() > MAX_ELICITATION_URL_DOMAIN_LENGTH {
                    return Err(format!(
                        "elicitation.{list_name}[{i}] length {} exceeds max {MAX_ELICITATION_URL_DOMAIN_LENGTH}",
                        entry.len()
                    ));
                }
                if vellaveto_types::has_dangerous_chars(entry) {
                    return Err(format!(
                        "elicitation.{list_name}[{i}] contains control or format characters"
                    ));
                }
            }
        }
        Ok(())
    }
}

/// Sampling request policy configuration (P2.3).
///
/// Controls whether `sampling/createMessage` requests are allowed and
/// what constraints apply. Sampling allows MCP servers to request the
/// LLM to generate text, which can be an exfiltration vector if tool
/// output is included in the prompt.
///
/// # TOML Example
///
/// ```toml
/// [sampling]
/// enabled = true
/// allowed_models = ["claude-3-opus", "claude-3-sonnet"]
/// block_if_contains_tool_output = true
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SamplingConfig {
    /// Master toggle. Default: false (block all sampling requests).
    #[serde(default)]
    pub enabled: bool,
    /// Allowed model name prefixes. Empty = any model allowed.
    #[serde(default)]
    pub allowed_models: Vec<String>,
    /// Block if the prompt contains tool output. Default: true.
    /// This prevents data laundering where a malicious tool response
    /// plants instructions that get fed back to the LLM via sampling.
    #[serde(default = "default_true")]
    pub block_if_contains_tool_output: bool,
    /// Maximum sampling requests per session. Default: 10.
    ///
    /// SECURITY (FIND-R125-001): Without per-session rate limiting, a malicious
    /// MCP server can issue unlimited `sampling/createMessage` requests, unlike
    /// elicitation which has `max_per_session`.
    #[serde(default = "default_max_sampling")]
    pub max_per_session: u32,
    /// R227: Maximum sampling requests per tool within the rate window.
    /// Prevents a single tool from draining compute via repeated sampling.
    /// Default: 50. Set to 0 to disable per-tool rate limiting.
    #[serde(default = "default_max_sampling_per_tool")]
    pub max_per_tool: u32,
    /// R227: Time window (seconds) for per-tool sampling rate limiting.
    /// Default: 60.
    #[serde(default = "default_sampling_per_tool_window")]
    pub per_tool_window_secs: u64,
    /// R232/TI-2026-030: Allowed `includeContext` values for sampling requests.
    /// Controls what conversation context a server can request via sampling.
    /// Default: `["none"]` (most restrictive). Valid values: "none", "thisServer", "allServers".
    /// SECURITY: `allServers` allows cross-server data exfiltration — only enable if trusted.
    #[serde(default = "default_allowed_include_context")]
    pub allowed_include_context: Vec<String>,
    /// R232/TI-2026-030: Maximum tokens allowed in a sampling request.
    /// Caps `maxTokens` to prevent compute resource draining.
    /// Default: 4096. Set to 0 to disable the cap.
    #[serde(default = "default_max_sampling_tokens")]
    pub max_tokens: u32,
    /// Phase 1: Tool allowlist for sampling requests (glob patterns).
    /// When non-empty, `sampling/createMessage` requests that reference tools
    /// not in this list are denied. Prevents servers from using sampling to
    /// trick the LLM into invoking tools the server is not allowed to call.
    /// Default: empty (all tools allowed when sampling is enabled).
    #[serde(default)]
    pub allowed_tools_in_sampling: Vec<String>,
}

fn default_max_sampling() -> u32 {
    10
}

fn default_max_sampling_per_tool() -> u32 {
    50
}

fn default_sampling_per_tool_window() -> u64 {
    60
}

fn default_allowed_include_context() -> Vec<String> {
    vec!["none".to_string()]
}

fn default_max_sampling_tokens() -> u32 {
    4096
}

impl Default for SamplingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            allowed_models: Vec::new(),
            block_if_contains_tool_output: true,
            max_per_session: default_max_sampling(),
            max_per_tool: default_max_sampling_per_tool(),
            per_tool_window_secs: default_sampling_per_tool_window(),
            allowed_include_context: default_allowed_include_context(),
            max_tokens: default_max_sampling_tokens(),
            allowed_tools_in_sampling: Vec::new(),
        }
    }
}

/// Maximum number of allowed models for sampling config.
pub const MAX_ALLOWED_MODELS: usize = 100;

/// Maximum length of a single allowed model entry.
///
/// SECURITY (FIND-R125-003): Unbounded entries could waste memory during
/// model name matching in `inspect_sampling()`.
pub const MAX_ALLOWED_MODEL_LENGTH: usize = 256;

/// Maximum number of tool patterns in `allowed_tools_in_sampling`.
pub const MAX_ALLOWED_TOOLS_IN_SAMPLING: usize = 256;

/// Maximum length of a single tool pattern entry.
pub const MAX_TOOL_PATTERN_LENGTH: usize = 256;

impl SamplingConfig {
    /// Validate configuration bounds.
    pub fn validate(&self) -> Result<(), String> {
        if self.allowed_models.len() > MAX_ALLOWED_MODELS {
            return Err(format!(
                "sampling.allowed_models exceeds {MAX_ALLOWED_MODELS} entries"
            ));
        }
        // SECURITY (FIND-R125-003): Validate individual entry content.
        for (i, entry) in self.allowed_models.iter().enumerate() {
            if entry.is_empty() {
                return Err(format!("sampling.allowed_models[{i}] is empty"));
            }
            if entry.len() > MAX_ALLOWED_MODEL_LENGTH {
                return Err(format!(
                    "sampling.allowed_models[{}] length {} exceeds max {}",
                    i,
                    entry.len(),
                    MAX_ALLOWED_MODEL_LENGTH
                ));
            }
            // SECURITY (FIND-R158-001): Canonical check for control + format chars.
            if vellaveto_types::has_dangerous_chars(entry) {
                return Err(format!(
                    "sampling.allowed_models[{i}] contains control or format characters"
                ));
            }
        }
        // R227: Validate per-tool window is reasonable (max 1 hour).
        if self.per_tool_window_secs > 3600 {
            return Err(format!(
                "sampling.per_tool_window_secs {} exceeds max 3600",
                self.per_tool_window_secs
            ));
        }
        // R232/TI-2026-030: Validate allowed_include_context values.
        const VALID_INCLUDE_CONTEXT: &[&str] = &["none", "thisServer", "allServers"];
        if self.allowed_include_context.is_empty() {
            return Err(
                "sampling.allowed_include_context must have at least one entry".to_string(),
            );
        }
        if self.allowed_include_context.len() > 3 {
            return Err(format!(
                "sampling.allowed_include_context has {} entries, max is 3",
                self.allowed_include_context.len()
            ));
        }
        for (i, val) in self.allowed_include_context.iter().enumerate() {
            if !VALID_INCLUDE_CONTEXT.contains(&val.as_str()) {
                return Err(format!(
                    "sampling.allowed_include_context[{i}] '{val}' is not valid (must be one of: none, thisServer, allServers)"
                ));
            }
        }
        // Phase 1: Validate allowed_tools_in_sampling.
        if self.allowed_tools_in_sampling.len() > MAX_ALLOWED_TOOLS_IN_SAMPLING {
            return Err(format!(
                "sampling.allowed_tools_in_sampling exceeds {MAX_ALLOWED_TOOLS_IN_SAMPLING} entries"
            ));
        }
        for (i, entry) in self.allowed_tools_in_sampling.iter().enumerate() {
            if entry.is_empty() {
                return Err(format!(
                    "sampling.allowed_tools_in_sampling[{i}] is empty"
                ));
            }
            if entry.len() > MAX_TOOL_PATTERN_LENGTH {
                return Err(format!(
                    "sampling.allowed_tools_in_sampling[{i}] length {} exceeds max {MAX_TOOL_PATTERN_LENGTH}",
                    entry.len()
                ));
            }
            if vellaveto_types::has_dangerous_chars(entry) {
                return Err(format!(
                    "sampling.allowed_tools_in_sampling[{i}] contains control or format characters"
                ));
            }
        }
        Ok(())
    }
}

// ═══════════════════════════════════════════════════
// MCP 2025-11-25 CONFIGURATION
// ═══════════════════════════════════════════════════

/// Default maximum concurrent async tasks.
fn default_max_concurrent_tasks() -> usize {
    100
}

/// Default maximum task duration (1 hour in seconds).
fn default_max_task_duration_secs() -> u64 {
    3600
}

/// Async task lifecycle configuration (MCP 2025-11-25).
///
/// Controls policies for async task creation, duration limits, and cancellation.
///
/// # TOML Example
///
/// ```toml
/// [async_tasks]
/// enabled = true
/// max_concurrent_tasks = 100
/// max_task_duration_secs = 3600
/// require_self_cancel = true
/// allow_cancellation = ["admin", "operator"]
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AsyncTaskConfig {
    /// Master toggle for async task policies. Default: true.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Maximum concurrent active tasks per session. Default: 100.
    /// Set to 0 for unlimited.
    #[serde(default = "default_max_concurrent_tasks")]
    pub max_concurrent_tasks: usize,

    /// Maximum task duration in seconds. Default: 3600 (1 hour).
    /// Set to 0 for unlimited.
    #[serde(default = "default_max_task_duration_secs")]
    pub max_task_duration_secs: u64,

    /// When true, only the agent that created a task can cancel it.
    /// When false, any agent in allow_cancellation can cancel.
    /// Default: true.
    #[serde(default = "default_true")]
    pub require_self_cancel: bool,

    /// Agent IDs or roles allowed to cancel any task.
    /// Only applies when require_self_cancel is false.
    #[serde(default)]
    pub allow_cancellation: Vec<String>,

    // ═══════════════════════════════════════════════════
    // Phase 11: Task Security Configuration
    // ═══════════════════════════════════════════════════
    /// Enable task state encryption (ChaCha20-Poly1305). Default: true.
    #[serde(default = "default_true")]
    pub encrypt_state: bool,

    /// Enable hash chain integrity tracking. Default: true.
    #[serde(default = "default_true")]
    pub enable_hash_chain: bool,

    /// Enable resume token authentication. Default: true.
    #[serde(default = "default_true")]
    pub require_resume_token: bool,

    /// Enable replay protection via nonce tracking. Default: true.
    #[serde(default = "default_true")]
    pub replay_protection: bool,

    /// Maximum nonces to track per task (FIFO eviction). Default: 1000.
    #[serde(default = "default_max_nonces")]
    pub max_nonces: usize,

    /// Enable checkpoint creation for long-running tasks. Default: false.
    #[serde(default)]
    pub enable_checkpoints: bool,

    /// Create checkpoint after this many state transitions. Default: 10.
    #[serde(default = "default_checkpoint_interval")]
    pub checkpoint_interval: usize,

    /// Retention period for completed tasks in seconds. Default: 3600.
    #[serde(default = "default_task_retention_secs")]
    pub task_retention_secs: u64,
}

fn default_max_nonces() -> usize {
    1000
}

fn default_checkpoint_interval() -> usize {
    10
}

fn default_task_retention_secs() -> u64 {
    3600
}

impl Default for AsyncTaskConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_concurrent_tasks: default_max_concurrent_tasks(),
            max_task_duration_secs: default_max_task_duration_secs(),
            require_self_cancel: true,
            allow_cancellation: Vec::new(),
            encrypt_state: true,
            enable_hash_chain: true,
            require_resume_token: true,
            replay_protection: true,
            max_nonces: default_max_nonces(),
            enable_checkpoints: false,
            checkpoint_interval: default_checkpoint_interval(),
            task_retention_secs: default_task_retention_secs(),
        }
    }
}

/// Maximum number of allow_cancellation entries.
pub const MAX_ALLOW_CANCELLATION: usize = 100;

impl AsyncTaskConfig {
    /// Validate configuration bounds.
    pub fn validate(&self) -> Result<(), String> {
        if self.allow_cancellation.len() > MAX_ALLOW_CANCELLATION {
            return Err(format!(
                "async_tasks.allow_cancellation exceeds {MAX_ALLOW_CANCELLATION} entries"
            ));
        }
        // SECURITY (FIND-R60-006, FIND-R158-001): Reject control + Unicode format
        // characters in allow_cancellation entries to prevent log injection and
        // policy bypass via invisible chars.
        for (i, entry) in self.allow_cancellation.iter().enumerate() {
            if vellaveto_types::has_dangerous_chars(entry) {
                return Err(format!(
                    "async_tasks.allow_cancellation[{i}] contains control or format characters"
                ));
            }
            if entry.is_empty() {
                return Err(format!("async_tasks.allow_cancellation[{i}] is empty"));
            }
        }
        // SECURITY (FIND-R137-006): Reject max_nonces=0 when replay_protection
        // is enabled — a zero-capacity nonce FIFO silently disables replay defense.
        if self.replay_protection && self.max_nonces == 0 {
            return Err(
                "async_tasks.max_nonces must be > 0 when replay_protection is enabled".to_string(),
            );
        }
        Ok(())
    }
}

/// RFC 8707 Resource Indicator configuration.
///
/// Validates OAuth tokens include the expected resource indicators.
/// Resource indicators bind tokens to specific API endpoints.
///
/// # TOML Example
///
/// ```toml
/// [resource_indicator]
/// enabled = true
/// allowed_resources = ["urn:vellaveto:*", "https://api.example.com/*"]
/// require_resource = false
/// ```
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ResourceIndicatorConfig {
    /// Enable resource indicator validation. Default: false.
    #[serde(default)]
    pub enabled: bool,

    /// Patterns for allowed resource URIs (glob patterns supported).
    /// If non-empty, at least one pattern must match the token's resource.
    #[serde(default)]
    pub allowed_resources: Vec<String>,

    /// When true, deny if the token has no resource indicator.
    /// Default: false.
    #[serde(default)]
    pub require_resource: bool,
}

/// Maximum number of allowed resource patterns.
pub const MAX_ALLOWED_RESOURCES: usize = 100;

/// Maximum per-entry length for resource indicator patterns.
pub const MAX_RESOURCE_ENTRY_LENGTH: usize = 256;

impl ResourceIndicatorConfig {
    /// Validate configuration bounds.
    pub fn validate(&self) -> Result<(), String> {
        if self.allowed_resources.len() > MAX_ALLOWED_RESOURCES {
            return Err(format!(
                "resource_indicator.allowed_resources exceeds {MAX_ALLOWED_RESOURCES} entries"
            ));
        }
        // SECURITY (FIND-R137-003): Per-entry validation — empty string matches
        // everything, effectively disabling resource indicator enforcement.
        for (i, entry) in self.allowed_resources.iter().enumerate() {
            if entry.is_empty() {
                return Err(format!(
                    "resource_indicator.allowed_resources[{i}] is empty"
                ));
            }
            if entry.len() > MAX_RESOURCE_ENTRY_LENGTH {
                return Err(format!(
                    "resource_indicator.allowed_resources[{}] length {} exceeds max {}",
                    i,
                    entry.len(),
                    MAX_RESOURCE_ENTRY_LENGTH
                ));
            }
            // SECURITY (FIND-R158-001): Canonical check for control + format chars.
            if vellaveto_types::has_dangerous_chars(entry) {
                return Err(format!(
                    "resource_indicator.allowed_resources[{i}] contains control or format characters"
                ));
            }
        }
        Ok(())
    }
}

/// CIMD (Capability-Indexed Message Dispatch) configuration.
///
/// Controls capability requirements for MCP 2025-11-25 sessions.
///
/// # TOML Example
///
/// ```toml
/// [cimd]
/// enabled = true
/// required_capabilities = ["tools"]
/// blocked_capabilities = ["admin.dangerous"]
/// ```
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CimdConfig {
    /// Enable capability-based routing. Default: false.
    #[serde(default)]
    pub enabled: bool,

    /// Capabilities that must be declared by the client.
    #[serde(default)]
    pub required_capabilities: Vec<String>,

    /// Capabilities that must NOT be declared by the client.
    #[serde(default)]
    pub blocked_capabilities: Vec<String>,
}

/// Maximum number of capability entries per list.
pub const MAX_CAPABILITIES: usize = 100;

/// Maximum per-entry length for capability strings.
pub const MAX_CAPABILITY_ENTRY_LENGTH: usize = 128;

impl CimdConfig {
    /// Validate configuration bounds.
    pub fn validate(&self) -> Result<(), String> {
        if self.required_capabilities.len() > MAX_CAPABILITIES {
            return Err(format!(
                "cimd.required_capabilities exceeds {MAX_CAPABILITIES} entries"
            ));
        }
        if self.blocked_capabilities.len() > MAX_CAPABILITIES {
            return Err(format!(
                "cimd.blocked_capabilities exceeds {MAX_CAPABILITIES} entries"
            ));
        }
        // SECURITY (FIND-R137-004): Per-entry validation — empty required
        // capability always matches; empty blocked capability blocks all.
        for (i, entry) in self.required_capabilities.iter().enumerate() {
            if entry.is_empty() {
                return Err(format!("cimd.required_capabilities[{i}] is empty"));
            }
            if entry.len() > MAX_CAPABILITY_ENTRY_LENGTH {
                return Err(format!(
                    "cimd.required_capabilities[{}] length {} exceeds max {}",
                    i,
                    entry.len(),
                    MAX_CAPABILITY_ENTRY_LENGTH
                ));
            }
            // SECURITY (FIND-R158-001): Canonical check for control + format chars.
            if vellaveto_types::has_dangerous_chars(entry) {
                return Err(format!(
                    "cimd.required_capabilities[{i}] contains control or format characters"
                ));
            }
        }
        for (i, entry) in self.blocked_capabilities.iter().enumerate() {
            if entry.is_empty() {
                return Err(format!("cimd.blocked_capabilities[{i}] is empty"));
            }
            if entry.len() > MAX_CAPABILITY_ENTRY_LENGTH {
                return Err(format!(
                    "cimd.blocked_capabilities[{}] length {} exceeds max {}",
                    i,
                    entry.len(),
                    MAX_CAPABILITY_ENTRY_LENGTH
                ));
            }
            // SECURITY (FIND-R158-001): Canonical check for control + format chars.
            if vellaveto_types::has_dangerous_chars(entry) {
                return Err(format!(
                    "cimd.blocked_capabilities[{i}] contains control or format characters"
                ));
            }
        }
        Ok(())
    }
}

// ═══════════════════════════════════════════════════
// MCP 2025-11-25 STREAMABLE HTTP CONFIGURATION (Phase 30)
// ═══════════════════════════════════════════════════

/// Default maximum event ID length (bytes).
fn default_max_event_id_length() -> usize {
    128
}

/// Streamable HTTP configuration for MCP 2025-11-25 compliance.
///
/// Controls SSE resumability (GET /mcp + Last-Event-ID), strict tool name
/// validation, and retry directive overrides.
///
/// # TOML Example
///
/// ```toml
/// [streamable_http]
/// resumability_enabled = true
/// strict_tool_name_validation = false
/// max_event_id_length = 128
/// sse_retry_ms = 3000
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct StreamableHttpConfig {
    /// Enable SSE resumability (GET /mcp with Last-Event-ID). Default: false.
    #[serde(default)]
    pub resumability_enabled: bool,

    /// Enable strict MCP 2025-11-25 tool name validation. Default: false.
    /// When true, tool names must match `[a-zA-Z0-9_\-./]{1,64}` with no
    /// leading/trailing dots/slashes and no consecutive dots.
    #[serde(default)]
    pub strict_tool_name_validation: bool,

    /// Maximum length for SSE event IDs (bytes). Default: 128, max: 512.
    /// Event IDs exceeding this length are rejected (fail-closed).
    #[serde(default = "default_max_event_id_length")]
    pub max_event_id_length: usize,

    /// Override SSE `retry:` directive (milliseconds). Default: None.
    /// When Some, the proxy injects a `retry:` field on SSE responses.
    /// Range: 100–60000 ms.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sse_retry_ms: Option<u64>,
}

impl Default for StreamableHttpConfig {
    fn default() -> Self {
        Self {
            resumability_enabled: false,
            strict_tool_name_validation: false,
            max_event_id_length: default_max_event_id_length(),
            sse_retry_ms: None,
        }
    }
}

impl StreamableHttpConfig {
    /// Validate configuration values.
    ///
    /// - `max_event_id_length` must be in [1, 512]
    /// - `sse_retry_ms` must be in [100, 60000] when Some
    pub fn validate(&self) -> Result<(), String> {
        if self.max_event_id_length == 0 || self.max_event_id_length > 512 {
            return Err(format!(
                "max_event_id_length must be in [1, 512], got {}",
                self.max_event_id_length
            ));
        }
        if let Some(retry) = self.sse_retry_ms {
            if !(100..=60_000).contains(&retry) {
                return Err(format!("sse_retry_ms must be in [100, 60000], got {retry}"));
            }
        }
        Ok(())
    }
}

/// Default step-up auth expiry (30 minutes in seconds).
fn default_step_up_expiry_secs() -> u64 {
    1800
}

/// Step-up authentication configuration.
///
/// Allows policies to require stronger authentication for sensitive operations.
///
/// # TOML Example
///
/// ```toml
/// [step_up_auth]
/// enabled = true
/// step_up_expiry_secs = 1800
/// trigger_tools = ["delete_*", "transfer_*", "admin_*"]
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct StepUpAuthConfig {
    /// Enable step-up authentication. Default: false.
    #[serde(default)]
    pub enabled: bool,

    /// How long a step-up auth session is valid in seconds. Default: 1800 (30 min).
    #[serde(default = "default_step_up_expiry_secs")]
    pub step_up_expiry_secs: u64,

    /// Tool patterns that trigger step-up auth challenges.
    /// Supports glob patterns like "delete_*".
    #[serde(default)]
    pub trigger_tools: Vec<String>,

    /// Required auth level for triggered tools. Default: 3 (OAuthMfa).
    /// 0=None, 1=Basic, 2=OAuth, 3=OAuthMfa, 4=HardwareKey
    #[serde(default = "default_step_up_level")]
    pub required_level: u8,
}

fn default_step_up_level() -> u8 {
    3 // OAuthMfa
}

impl Default for StepUpAuthConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            step_up_expiry_secs: default_step_up_expiry_secs(),
            trigger_tools: Vec::new(),
            required_level: default_step_up_level(),
        }
    }
}

/// Maximum number of trigger tools for step-up auth.
pub const MAX_TRIGGER_TOOLS: usize = 100;

/// Maximum per-entry length for trigger tool patterns.
pub const MAX_TRIGGER_TOOL_LENGTH: usize = 256;

impl StepUpAuthConfig {
    /// Validate configuration bounds.
    pub fn validate(&self) -> Result<(), String> {
        if self.trigger_tools.len() > MAX_TRIGGER_TOOLS {
            return Err(format!(
                "step_up_auth.trigger_tools exceeds {MAX_TRIGGER_TOOLS} entries"
            ));
        }
        if self.required_level > 4 {
            return Err(format!(
                "step_up_auth.required_level must be 0-4, got {}",
                self.required_level
            ));
        }
        // SECURITY (FIND-R137-005): Per-entry validation on trigger_tools.
        for (i, entry) in self.trigger_tools.iter().enumerate() {
            if entry.is_empty() {
                return Err(format!("step_up_auth.trigger_tools[{i}] is empty"));
            }
            if entry.len() > MAX_TRIGGER_TOOL_LENGTH {
                return Err(format!(
                    "step_up_auth.trigger_tools[{}] length {} exceeds max {}",
                    i,
                    entry.len(),
                    MAX_TRIGGER_TOOL_LENGTH
                ));
            }
            // SECURITY (FIND-R158-001): Canonical check for control + format chars.
            if vellaveto_types::has_dangerous_chars(entry) {
                return Err(format!(
                    "step_up_auth.trigger_tools[{i}] contains control or format characters"
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::field_reassign_with_default)]
mod tests {
    use super::*;

    // ═══════════════════════════════════════════════════
    // ElicitationConfig validate() tests
    // ═══════════════════════════════════════════════════

    #[test]
    fn test_elicitation_validate_default_ok() {
        let config = ElicitationConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_elicitation_validate_too_many_blocked_field_types_rejected() {
        let mut config = ElicitationConfig::default();
        config.blocked_field_types = (0..=MAX_BLOCKED_FIELD_TYPES)
            .map(|i| format!("type_{i}"))
            .collect();
        let err = config.validate().unwrap_err();
        assert!(err.contains("blocked_field_types"));
    }

    #[test]
    fn test_elicitation_validate_empty_blocked_field_type_rejected() {
        let mut config = ElicitationConfig::default();
        config.blocked_field_types = vec!["".to_string()];
        let err = config.validate().unwrap_err();
        assert!(err.contains("is empty"));
    }

    #[test]
    fn test_elicitation_validate_blocked_field_type_too_long_rejected() {
        let mut config = ElicitationConfig::default();
        config.blocked_field_types = vec!["x".repeat(MAX_BLOCKED_FIELD_TYPE_LENGTH + 1)];
        let err = config.validate().unwrap_err();
        assert!(err.contains("exceeds max"));
    }

    #[test]
    fn test_elicitation_validate_blocked_field_type_control_chars_rejected() {
        let mut config = ElicitationConfig::default();
        config.blocked_field_types = vec!["password\x00".to_string()];
        let err = config.validate().unwrap_err();
        assert!(err.contains("control or format characters"));
    }

    // ═══════════════════════════════════════════════════
    // SamplingConfig validate() tests
    // ═══════════════════════════════════════════════════

    #[test]
    fn test_sampling_validate_default_ok() {
        let config = SamplingConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_sampling_validate_too_many_allowed_models_rejected() {
        let mut config = SamplingConfig::default();
        config.allowed_models = (0..=MAX_ALLOWED_MODELS)
            .map(|i| format!("model_{i}"))
            .collect();
        let err = config.validate().unwrap_err();
        assert!(err.contains("allowed_models"));
    }

    #[test]
    fn test_sampling_validate_empty_model_rejected() {
        let mut config = SamplingConfig::default();
        config.allowed_models = vec!["".to_string()];
        let err = config.validate().unwrap_err();
        assert!(err.contains("is empty"));
    }

    #[test]
    fn test_sampling_validate_model_too_long_rejected() {
        let mut config = SamplingConfig::default();
        config.allowed_models = vec!["m".repeat(MAX_ALLOWED_MODEL_LENGTH + 1)];
        let err = config.validate().unwrap_err();
        assert!(err.contains("exceeds max"));
    }

    #[test]
    fn test_sampling_validate_model_control_chars_rejected() {
        let mut config = SamplingConfig::default();
        config.allowed_models = vec!["claude\x01bad".to_string()];
        let err = config.validate().unwrap_err();
        assert!(err.contains("control or format characters"));
    }

    #[test]
    fn test_sampling_validate_per_tool_window_over_3600_rejected() {
        let mut config = SamplingConfig::default();
        config.per_tool_window_secs = 3601;
        let err = config.validate().unwrap_err();
        assert!(err.contains("per_tool_window_secs"));
    }

    #[test]
    fn test_sampling_validate_empty_include_context_rejected() {
        let mut config = SamplingConfig::default();
        config.allowed_include_context = Vec::new();
        let err = config.validate().unwrap_err();
        assert!(err.contains("at least one entry"));
    }

    #[test]
    fn test_sampling_validate_too_many_include_context_rejected() {
        let mut config = SamplingConfig::default();
        config.allowed_include_context = vec![
            "none".to_string(),
            "thisServer".to_string(),
            "allServers".to_string(),
            "extra".to_string(),
        ];
        let err = config.validate().unwrap_err();
        assert!(err.contains("max is 3"));
    }

    #[test]
    fn test_sampling_validate_invalid_include_context_rejected() {
        let mut config = SamplingConfig::default();
        config.allowed_include_context = vec!["invalid".to_string()];
        let err = config.validate().unwrap_err();
        assert!(err.contains("is not valid"));
    }

    #[test]
    fn test_sampling_validate_all_valid_include_context_ok() {
        let mut config = SamplingConfig::default();
        config.allowed_include_context = vec![
            "none".to_string(),
            "thisServer".to_string(),
            "allServers".to_string(),
        ];
        assert!(config.validate().is_ok());
    }

    // ═══════════════════════════════════════════════════
    // AsyncTaskConfig validate() tests
    // ═══════════════════════════════════════════════════

    #[test]
    fn test_async_task_validate_default_ok() {
        let config = AsyncTaskConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_async_task_validate_too_many_cancellation_entries_rejected() {
        let mut config = AsyncTaskConfig::default();
        config.allow_cancellation = (0..=MAX_ALLOW_CANCELLATION)
            .map(|i| format!("agent_{i}"))
            .collect();
        let err = config.validate().unwrap_err();
        assert!(err.contains("allow_cancellation"));
    }

    #[test]
    fn test_async_task_validate_empty_cancellation_entry_rejected() {
        let mut config = AsyncTaskConfig::default();
        config.allow_cancellation = vec!["".to_string()];
        let err = config.validate().unwrap_err();
        assert!(err.contains("is empty"));
    }

    #[test]
    fn test_async_task_validate_cancellation_control_chars_rejected() {
        let mut config = AsyncTaskConfig::default();
        config.allow_cancellation = vec!["admin\x07".to_string()];
        let err = config.validate().unwrap_err();
        assert!(err.contains("control or format characters"));
    }

    #[test]
    fn test_async_task_validate_zero_nonces_with_replay_protection_rejected() {
        let mut config = AsyncTaskConfig::default();
        config.replay_protection = true;
        config.max_nonces = 0;
        let err = config.validate().unwrap_err();
        assert!(err.contains("max_nonces must be > 0"));
    }

    #[test]
    fn test_async_task_validate_zero_nonces_without_replay_protection_ok() {
        let mut config = AsyncTaskConfig::default();
        config.replay_protection = false;
        config.max_nonces = 0;
        assert!(config.validate().is_ok());
    }

    // ═══════════════════════════════════════════════════
    // ResourceIndicatorConfig validate() tests
    // ═══════════════════════════════════════════════════

    #[test]
    fn test_resource_indicator_validate_default_ok() {
        let config = ResourceIndicatorConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_resource_indicator_validate_too_many_resources_rejected() {
        let mut config = ResourceIndicatorConfig::default();
        config.allowed_resources = (0..=MAX_ALLOWED_RESOURCES)
            .map(|i| format!("urn:res:{i}"))
            .collect();
        let err = config.validate().unwrap_err();
        assert!(err.contains("allowed_resources"));
    }

    #[test]
    fn test_resource_indicator_validate_empty_resource_rejected() {
        let mut config = ResourceIndicatorConfig::default();
        config.allowed_resources = vec!["".to_string()];
        let err = config.validate().unwrap_err();
        assert!(err.contains("is empty"));
    }

    #[test]
    fn test_resource_indicator_validate_resource_too_long_rejected() {
        let mut config = ResourceIndicatorConfig::default();
        config.allowed_resources = vec!["x".repeat(MAX_RESOURCE_ENTRY_LENGTH + 1)];
        let err = config.validate().unwrap_err();
        assert!(err.contains("exceeds max"));
    }

    #[test]
    fn test_resource_indicator_validate_resource_control_chars_rejected() {
        let mut config = ResourceIndicatorConfig::default();
        config.allowed_resources = vec!["urn:test\x00".to_string()];
        let err = config.validate().unwrap_err();
        assert!(err.contains("control or format characters"));
    }

    // ═══════════════════════════════════════════════════
    // CimdConfig validate() tests
    // ═══════════════════════════════════════════════════

    #[test]
    fn test_cimd_validate_default_ok() {
        let config = CimdConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_cimd_validate_too_many_required_capabilities_rejected() {
        let mut config = CimdConfig::default();
        config.required_capabilities = (0..=MAX_CAPABILITIES).map(|i| format!("cap_{i}")).collect();
        let err = config.validate().unwrap_err();
        assert!(err.contains("required_capabilities"));
    }

    #[test]
    fn test_cimd_validate_too_many_blocked_capabilities_rejected() {
        let mut config = CimdConfig::default();
        config.blocked_capabilities = (0..=MAX_CAPABILITIES).map(|i| format!("cap_{i}")).collect();
        let err = config.validate().unwrap_err();
        assert!(err.contains("blocked_capabilities"));
    }

    #[test]
    fn test_cimd_validate_empty_required_capability_rejected() {
        let mut config = CimdConfig::default();
        config.required_capabilities = vec!["".to_string()];
        let err = config.validate().unwrap_err();
        assert!(err.contains("required_capabilities[0] is empty"));
    }

    #[test]
    fn test_cimd_validate_empty_blocked_capability_rejected() {
        let mut config = CimdConfig::default();
        config.blocked_capabilities = vec!["".to_string()];
        let err = config.validate().unwrap_err();
        assert!(err.contains("blocked_capabilities[0] is empty"));
    }

    #[test]
    fn test_cimd_validate_required_capability_too_long_rejected() {
        let mut config = CimdConfig::default();
        config.required_capabilities = vec!["c".repeat(MAX_CAPABILITY_ENTRY_LENGTH + 1)];
        let err = config.validate().unwrap_err();
        assert!(err.contains("exceeds max"));
    }

    #[test]
    fn test_cimd_validate_capability_control_chars_rejected() {
        let mut config = CimdConfig::default();
        config.required_capabilities = vec!["tools\x00".to_string()];
        let err = config.validate().unwrap_err();
        assert!(err.contains("control or format characters"));
    }

    // ═══════════════════════════════════════════════════
    // StreamableHttpConfig validate() tests
    // ═══════════════════════════════════════════════════

    #[test]
    fn test_streamable_http_validate_default_ok() {
        let config = StreamableHttpConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_streamable_http_validate_event_id_length_zero_rejected() {
        let mut config = StreamableHttpConfig::default();
        config.max_event_id_length = 0;
        let err = config.validate().unwrap_err();
        assert!(err.contains("max_event_id_length"));
    }

    #[test]
    fn test_streamable_http_validate_event_id_length_over_512_rejected() {
        let mut config = StreamableHttpConfig::default();
        config.max_event_id_length = 513;
        let err = config.validate().unwrap_err();
        assert!(err.contains("max_event_id_length"));
    }

    #[test]
    fn test_streamable_http_validate_sse_retry_below_100_rejected() {
        let mut config = StreamableHttpConfig::default();
        config.sse_retry_ms = Some(99);
        let err = config.validate().unwrap_err();
        assert!(err.contains("sse_retry_ms"));
    }

    #[test]
    fn test_streamable_http_validate_sse_retry_above_60000_rejected() {
        let mut config = StreamableHttpConfig::default();
        config.sse_retry_ms = Some(60_001);
        let err = config.validate().unwrap_err();
        assert!(err.contains("sse_retry_ms"));
    }

    #[test]
    fn test_streamable_http_validate_sse_retry_none_ok() {
        let mut config = StreamableHttpConfig::default();
        config.sse_retry_ms = None;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_streamable_http_validate_sse_retry_boundary_100_ok() {
        let mut config = StreamableHttpConfig::default();
        config.sse_retry_ms = Some(100);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_streamable_http_validate_sse_retry_boundary_60000_ok() {
        let mut config = StreamableHttpConfig::default();
        config.sse_retry_ms = Some(60_000);
        assert!(config.validate().is_ok());
    }

    // ═══════════════════════════════════════════════════
    // StepUpAuthConfig validate() tests
    // ═══════════════════════════════════════════════════

    #[test]
    fn test_step_up_auth_validate_default_ok() {
        let config = StepUpAuthConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_step_up_auth_validate_too_many_trigger_tools_rejected() {
        let mut config = StepUpAuthConfig::default();
        config.trigger_tools = (0..=MAX_TRIGGER_TOOLS)
            .map(|i| format!("tool_{i}"))
            .collect();
        let err = config.validate().unwrap_err();
        assert!(err.contains("trigger_tools"));
    }

    #[test]
    fn test_step_up_auth_validate_required_level_above_4_rejected() {
        let mut config = StepUpAuthConfig::default();
        config.required_level = 5;
        let err = config.validate().unwrap_err();
        assert!(err.contains("required_level"));
    }

    #[test]
    fn test_step_up_auth_validate_required_level_4_ok() {
        let mut config = StepUpAuthConfig::default();
        config.required_level = 4;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_step_up_auth_validate_empty_trigger_tool_rejected() {
        let mut config = StepUpAuthConfig::default();
        config.trigger_tools = vec!["".to_string()];
        let err = config.validate().unwrap_err();
        assert!(err.contains("is empty"));
    }

    #[test]
    fn test_step_up_auth_validate_trigger_tool_too_long_rejected() {
        let mut config = StepUpAuthConfig::default();
        config.trigger_tools = vec!["t".repeat(MAX_TRIGGER_TOOL_LENGTH + 1)];
        let err = config.validate().unwrap_err();
        assert!(err.contains("exceeds max"));
    }

    #[test]
    fn test_step_up_auth_validate_trigger_tool_control_chars_rejected() {
        let mut config = StepUpAuthConfig::default();
        config.trigger_tools = vec!["delete_\x00all".to_string()];
        let err = config.validate().unwrap_err();
        assert!(err.contains("control or format characters"));
    }
}
