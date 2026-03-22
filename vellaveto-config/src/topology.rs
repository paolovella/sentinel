// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Topology crawling configuration (ActionEngine-inspired live discovery).
//!
//! Controls the MCP server topology crawler: recrawl intervals, timeouts,
//! concurrency limits, data flow inference, and failure fallback behavior.
//! Distinct from `DiscoveryConfig` (Phase 34 tool search index).

use serde::{Deserialize, Serialize};

/// Maximum recrawl interval (24 hours).
pub const MAX_RECRAWL_INTERVAL_SECS: u64 = 86_400;

/// Maximum server timeout (5 minutes).
pub const MAX_SERVER_TIMEOUT_SECS: u64 = 300;

/// Maximum concurrent probes.
pub const MAX_CONCURRENT_PROBES: usize = 64;

/// Maximum consecutive failures before fallback.
pub const MAX_CONSECUTIVE_FAILURES: u32 = 100;

/// Topology crawling configuration.
///
/// When enabled, the server periodically probes connected MCP servers
/// to build a live topology graph (servers → tools → resources).
/// The graph is used by `TopologyGuard` (from `vellaveto-discovery`)
/// to pre-filter tool calls before policy evaluation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TopologyConfig {
    /// Enable topology crawling.
    /// Default: false (opt-in).
    #[serde(default)]
    pub enabled: bool,

    /// Interval (seconds) between periodic re-crawls.
    /// Default: 300 (5 minutes).
    #[serde(default = "default_recrawl_interval_secs")]
    pub recrawl_interval_secs: u64,

    /// Per-server probe timeout (seconds).
    /// Default: 10.
    #[serde(default = "default_server_timeout_secs")]
    pub server_timeout_secs: u64,

    /// Continue crawling remaining servers if one fails.
    /// Default: true (resilient mode).
    #[serde(default = "super::default_true")]
    pub continue_on_error: bool,

    /// Maximum number of servers probed concurrently.
    /// Default: 8.
    #[serde(default = "default_max_concurrent")]
    pub max_concurrent: usize,

    /// Infer data flow edges between tools using schema analysis.
    /// Default: false (opt-in — adds CPU overhead during crawl).
    #[serde(default)]
    pub infer_data_flow: bool,

    /// Minimum confidence threshold [0.0, 1.0] for inferred data flow edges.
    /// Default: 0.5.
    #[serde(default = "default_inference_threshold")]
    pub inference_threshold: f32,

    /// Trigger an immediate re-crawl when an unknown tool is encountered.
    /// Default: false.
    #[serde(default)]
    pub on_unknown_tool_recrawl: bool,

    /// Maximum consecutive crawl failures before switching to fallback mode.
    /// Default: 3.
    #[serde(default = "default_max_consecutive_failures")]
    pub max_consecutive_failures: u32,

    /// Behavior when topology is unavailable (crawl failures exceed threshold).
    /// - "deny": Deny all tool calls until topology is restored (default, fail-closed).
    /// - "bypass": Skip topology check, let policy engine decide.
    ///
    /// SECURITY (R237-CFG-5): Default changed from "bypass" to "deny" to enforce
    /// fail-closed behavior. Operators who want fail-open must explicitly opt in.
    #[serde(default = "default_fallback_mode")]
    pub fallback_mode: String,
}

fn default_recrawl_interval_secs() -> u64 {
    300
}

fn default_server_timeout_secs() -> u64 {
    10
}

fn default_max_concurrent() -> usize {
    8
}

fn default_inference_threshold() -> f32 {
    0.5
}

fn default_max_consecutive_failures() -> u32 {
    3
}

fn default_fallback_mode() -> String {
    "deny".to_string()
}

impl Default for TopologyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            recrawl_interval_secs: default_recrawl_interval_secs(),
            server_timeout_secs: default_server_timeout_secs(),
            continue_on_error: true,
            max_concurrent: default_max_concurrent(),
            infer_data_flow: false,
            inference_threshold: default_inference_threshold(),
            on_unknown_tool_recrawl: false,
            max_consecutive_failures: default_max_consecutive_failures(),
            fallback_mode: default_fallback_mode(),
        }
    }
}

impl TopologyConfig {
    /// Validate topology configuration bounds.
    pub fn validate(&self) -> Result<(), String> {
        if self.recrawl_interval_secs == 0 {
            return Err("topology.recrawl_interval_secs must be > 0".to_string());
        }
        if self.recrawl_interval_secs > MAX_RECRAWL_INTERVAL_SECS {
            return Err(format!(
                "topology.recrawl_interval_secs must be <= {} (24h), got {}",
                MAX_RECRAWL_INTERVAL_SECS, self.recrawl_interval_secs
            ));
        }
        if self.server_timeout_secs == 0 {
            return Err("topology.server_timeout_secs must be > 0".to_string());
        }
        if self.server_timeout_secs > MAX_SERVER_TIMEOUT_SECS {
            return Err(format!(
                "topology.server_timeout_secs must be <= {} (5m), got {}",
                MAX_SERVER_TIMEOUT_SECS, self.server_timeout_secs
            ));
        }
        if self.max_concurrent == 0 {
            return Err("topology.max_concurrent must be > 0".to_string());
        }
        if self.max_concurrent > MAX_CONCURRENT_PROBES {
            return Err(format!(
                "topology.max_concurrent must be <= {}, got {}",
                MAX_CONCURRENT_PROBES, self.max_concurrent
            ));
        }
        if !self.inference_threshold.is_finite() {
            return Err(format!(
                "topology.inference_threshold must be finite, got {}",
                self.inference_threshold
            ));
        }
        if self.inference_threshold < 0.0 || self.inference_threshold > 1.0 {
            return Err(format!(
                "topology.inference_threshold must be in [0.0, 1.0], got {}",
                self.inference_threshold
            ));
        }
        if self.max_consecutive_failures == 0 {
            return Err("topology.max_consecutive_failures must be > 0".to_string());
        }
        if self.max_consecutive_failures > MAX_CONSECUTIVE_FAILURES {
            return Err(format!(
                "topology.max_consecutive_failures must be <= {}, got {}",
                MAX_CONSECUTIVE_FAILURES, self.max_consecutive_failures
            ));
        }
        // SECURITY (R250-CFG-3): Validate dangerous chars before enum matching
        // to prevent control character injection in config error messages.
        if vellaveto_types::has_dangerous_chars(&self.fallback_mode) {
            return Err("topology.fallback_mode contains control or format characters".to_string());
        }
        match self.fallback_mode.as_str() {
            "bypass" | "deny" => {}
            other => {
                return Err(format!(
                    "topology.fallback_mode must be 'bypass' or 'deny', got '{other}'"
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── R237-CFG-5: Default fallback_mode is fail-closed ("deny") ──

    #[test]
    fn test_topology_default_fallback_mode_deny() {
        let config = TopologyConfig::default();
        assert_eq!(
            config.fallback_mode, "deny",
            "TopologyConfig default fallback_mode must be 'deny' (fail-closed)"
        );
    }
}
