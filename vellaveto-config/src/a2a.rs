// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! A2A (Agent-to-Agent) protocol security configuration.

use crate::default_true;
use serde::{Deserialize, Serialize};

/// A2A (Agent-to-Agent) protocol security configuration.
///
/// Controls Vellaveto's A2A proxy behavior including message interception,
/// policy evaluation, agent card verification, and security feature integration.
///
/// # TOML Example
///
/// ```toml
/// [a2a]
/// enabled = true
/// upstream_url = "https://agent.example.com"
/// listen_addr = "0.0.0.0:8082"
/// require_agent_card = true
/// agent_card_cache_secs = 3600
/// allowed_auth_methods = ["bearer", "oauth2"]
/// enable_circuit_breaker = true
/// enable_shadow_agent_detection = true
/// enable_dlp_scanning = true
/// enable_injection_detection = true
/// max_message_size = 10485760
/// request_timeout_ms = 30000
/// allowed_task_operations = []
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct A2aConfig {
    /// Enable A2A protocol support. Default: false.
    #[serde(default)]
    pub enabled: bool,

    /// Upstream A2A server URL (when acting as proxy).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_url: Option<String>,

    /// Listen address for A2A proxy (e.g., "0.0.0.0:8082").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen_addr: Option<String>,

    /// Require agent card verification before allowing requests. Default: false.
    #[serde(default)]
    pub require_agent_card: bool,

    /// Cache agent cards for this duration in seconds. Default: 3600 (1 hour).
    #[serde(default = "default_a2a_card_cache_secs")]
    pub agent_card_cache_secs: u64,

    /// Allowed authentication methods. Default: ["apikey", "bearer"].
    /// Valid values: "apikey", "bearer", "oauth2", "mtls"
    #[serde(default = "default_a2a_auth_methods")]
    pub allowed_auth_methods: Vec<String>,

    /// Apply circuit breaker to upstream A2A servers. Default: true.
    #[serde(default = "default_true")]
    pub enable_circuit_breaker: bool,

    /// Enable shadow agent detection for A2A traffic. Default: true.
    #[serde(default = "default_true")]
    pub enable_shadow_agent_detection: bool,

    /// Enable DLP scanning on A2A message content. Default: true.
    #[serde(default = "default_true")]
    pub enable_dlp_scanning: bool,

    /// Enable injection detection on A2A text content. Default: true.
    #[serde(default = "default_true")]
    pub enable_injection_detection: bool,

    /// Maximum message size in bytes. Default: 10 MB.
    #[serde(default = "default_a2a_max_message_size")]
    pub max_message_size: usize,

    /// Request timeout in milliseconds. Default: 30000 (30 seconds).
    #[serde(default = "default_a2a_timeout")]
    pub request_timeout_ms: u64,

    /// Allowed task operations (empty = all allowed). Default: [].
    /// Valid values: "get", "cancel", "resubscribe"
    #[serde(default)]
    pub allowed_task_operations: Vec<String>,
}

fn default_a2a_card_cache_secs() -> u64 {
    3600 // 1 hour
}

fn default_a2a_auth_methods() -> Vec<String> {
    vec!["apikey".to_string(), "bearer".to_string()]
}

fn default_a2a_max_message_size() -> usize {
    10 * 1024 * 1024 // 10 MB
}

fn default_a2a_timeout() -> u64 {
    30000 // 30 seconds
}

/// Maximum URL length for A2A upstream/listen addresses.
const MAX_A2A_URL_LENGTH: usize = 2048;

/// Maximum listen address length.
const MAX_A2A_LISTEN_ADDR_LENGTH: usize = 256;

/// Maximum A2A card cache duration (7 days).
const MAX_A2A_CARD_CACHE_SECS: u64 = 604_800;

/// Maximum auth methods / task operations entries.
const MAX_A2A_LIST_ENTRIES: usize = 20;

/// Maximum per-entry string length for auth methods / task operations.
const MAX_A2A_ENTRY_LENGTH: usize = 64;

/// Maximum message size (100 MB).
const MAX_A2A_MESSAGE_SIZE: usize = 100 * 1024 * 1024;

/// Maximum request timeout (5 minutes).
const MAX_A2A_TIMEOUT_MS: u64 = 300_000;

/// Valid A2A auth methods.
const VALID_A2A_AUTH_METHODS: &[&str] = &["apikey", "bearer", "oauth2", "mtls"];

/// Valid A2A task operations.
const VALID_A2A_TASK_OPERATIONS: &[&str] = &["get", "cancel", "resubscribe"];

impl A2aConfig {
    /// Validate A2A configuration fields.
    pub fn validate(&self) -> Result<(), String> {
        // Validate upstream_url
        if let Some(ref url) = self.upstream_url {
            if url.len() > MAX_A2A_URL_LENGTH {
                return Err(format!(
                    "a2a.upstream_url length {} exceeds maximum {}",
                    url.len(),
                    MAX_A2A_URL_LENGTH
                ));
            }
            if vellaveto_types::has_dangerous_chars(url) {
                return Err("a2a.upstream_url contains control or format characters".to_string());
            }
            if !url.starts_with("http://") && !url.starts_with("https://") {
                return Err("a2a.upstream_url must start with http:// or https://".to_string());
            }
        }

        // Validate listen_addr
        if let Some(ref addr) = self.listen_addr {
            if addr.len() > MAX_A2A_LISTEN_ADDR_LENGTH {
                return Err(format!(
                    "a2a.listen_addr length {} exceeds maximum {}",
                    addr.len(),
                    MAX_A2A_LISTEN_ADDR_LENGTH
                ));
            }
            if vellaveto_types::has_dangerous_chars(addr) {
                return Err("a2a.listen_addr contains control or format characters".to_string());
            }
        }

        // Validate agent_card_cache_secs
        // SECURITY (FIND-R86-004): Reject zero cache TTL — it disables caching entirely,
        // causing every request to re-fetch the agent card (performance DoS vector).
        if self.agent_card_cache_secs == 0 {
            return Err("a2a.agent_card_cache_secs must be > 0".to_string());
        }
        if self.agent_card_cache_secs > MAX_A2A_CARD_CACHE_SECS {
            return Err(format!(
                "a2a.agent_card_cache_secs {} exceeds maximum {} (7 days)",
                self.agent_card_cache_secs, MAX_A2A_CARD_CACHE_SECS
            ));
        }

        // Validate allowed_auth_methods
        if self.allowed_auth_methods.len() > MAX_A2A_LIST_ENTRIES {
            return Err(format!(
                "a2a.allowed_auth_methods count {} exceeds maximum {}",
                self.allowed_auth_methods.len(),
                MAX_A2A_LIST_ENTRIES
            ));
        }
        for method in &self.allowed_auth_methods {
            if method.is_empty() {
                return Err("a2a.allowed_auth_methods contains an empty string".to_string());
            }
            if method.len() > MAX_A2A_ENTRY_LENGTH {
                return Err(format!(
                    "a2a.allowed_auth_methods entry length {} exceeds maximum {}",
                    method.len(),
                    MAX_A2A_ENTRY_LENGTH
                ));
            }
            if vellaveto_types::has_dangerous_chars(method) {
                return Err(format!(
                    "a2a.allowed_auth_methods entry '{method}' contains control or format characters"
                ));
            }
            if !VALID_A2A_AUTH_METHODS.contains(&method.as_str()) {
                return Err(format!(
                    "a2a.allowed_auth_methods contains invalid value '{method}'. \
                     Valid values: {VALID_A2A_AUTH_METHODS:?}"
                ));
            }
        }

        // Validate max_message_size
        if self.max_message_size == 0 {
            return Err("a2a.max_message_size must be > 0".to_string());
        }
        if self.max_message_size > MAX_A2A_MESSAGE_SIZE {
            return Err(format!(
                "a2a.max_message_size {} exceeds maximum {} (100 MB)",
                self.max_message_size, MAX_A2A_MESSAGE_SIZE
            ));
        }

        // Validate request_timeout_ms
        if self.request_timeout_ms == 0 {
            return Err("a2a.request_timeout_ms must be > 0".to_string());
        }
        if self.request_timeout_ms > MAX_A2A_TIMEOUT_MS {
            return Err(format!(
                "a2a.request_timeout_ms {} exceeds maximum {} (5 minutes)",
                self.request_timeout_ms, MAX_A2A_TIMEOUT_MS
            ));
        }

        // Validate allowed_task_operations
        if self.allowed_task_operations.len() > MAX_A2A_LIST_ENTRIES {
            return Err(format!(
                "a2a.allowed_task_operations count {} exceeds maximum {}",
                self.allowed_task_operations.len(),
                MAX_A2A_LIST_ENTRIES
            ));
        }
        for op in &self.allowed_task_operations {
            if op.is_empty() {
                return Err("a2a.allowed_task_operations contains an empty string".to_string());
            }
            if op.len() > MAX_A2A_ENTRY_LENGTH {
                return Err(format!(
                    "a2a.allowed_task_operations entry length {} exceeds maximum {}",
                    op.len(),
                    MAX_A2A_ENTRY_LENGTH
                ));
            }
            if vellaveto_types::has_dangerous_chars(op) {
                return Err(format!(
                    "a2a.allowed_task_operations entry '{op}' contains control or format characters"
                ));
            }
            if !VALID_A2A_TASK_OPERATIONS.contains(&op.as_str()) {
                return Err(format!(
                    "a2a.allowed_task_operations contains invalid value '{op}'. \
                     Valid values: {VALID_A2A_TASK_OPERATIONS:?}"
                ));
            }
        }

        Ok(())
    }
}

impl Default for A2aConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            upstream_url: None,
            listen_addr: None,
            // SECURITY: Fail-closed — require agent card verification by default.
            require_agent_card: true,
            agent_card_cache_secs: default_a2a_card_cache_secs(),
            allowed_auth_methods: default_a2a_auth_methods(),
            enable_circuit_breaker: true,
            enable_shadow_agent_detection: true,
            enable_dlp_scanning: true,
            enable_injection_detection: true,
            max_message_size: default_a2a_max_message_size(),
            request_timeout_ms: default_a2a_timeout(),
            // SECURITY: Fail-closed — only allow safe read-only task operations by default.
            allowed_task_operations: vec!["get".into(), "cancel".into(), "resubscribe".into()],
        }
    }
}
