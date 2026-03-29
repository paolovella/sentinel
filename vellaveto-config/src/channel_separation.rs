// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Phase 6: Control/Data Channel Separation configuration.
//!
//! Three-phase structural defense against MCP channel conflation:
//! 1. Source-class tainting — untrusted tool responses auto-taint regardless of detection
//! 2. Intent scope declarations — constrain what tools/sinks an agent can use
//! 3. Behavioral sequence analysis — detect anomalous patterns after taint

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use vellaveto_types::TrustTier;

// ═══════════════════════════════════════════════════
// Phase 6.1: Source Trust Classification
// ═══════════════════════════════════════════════════

/// Per-tool and per-server trust classification.
/// Tools/servers not listed default to `default_tool_trust`.
///
/// # TOML Example
///
/// ```toml
/// [source_trust]
/// default_tool_trust = "unknown"
/// untrusted_tools = ["fetch_url", "browse_*", "search_*"]
/// verified_tools = ["internal_api_*"]
///
/// [source_trust.server_trust]
/// "filesystem-server" = "low"
/// "github-mcp" = "medium"
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SourceTrustConfig {
    /// Tools that return untrusted content by nature (web fetch, user uploads, etc.)
    #[serde(default)]
    pub untrusted_tools: Vec<String>,
    /// Tools that return verified content (internal APIs, signed data, etc.)
    #[serde(default)]
    pub verified_tools: Vec<String>,
    /// Per-server trust overrides.
    #[serde(default)]
    pub server_trust: HashMap<String, TrustTier>,
    /// Default trust tier for tools not in any list.
    #[serde(default = "default_tool_trust")]
    pub default_tool_trust: TrustTier,
}

fn default_tool_trust() -> TrustTier {
    TrustTier::Unknown
}

impl Default for SourceTrustConfig {
    fn default() -> Self {
        Self {
            untrusted_tools: Vec::new(),
            verified_tools: Vec::new(),
            server_trust: HashMap::new(),
            default_tool_trust: default_tool_trust(),
        }
    }
}

/// Maximum entries per trust list.
const MAX_TRUST_ENTRIES: usize = 256;

impl SourceTrustConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.untrusted_tools.len() > MAX_TRUST_ENTRIES {
            return Err(format!(
                "source_trust.untrusted_tools exceeds {MAX_TRUST_ENTRIES} entries"
            ));
        }
        if self.verified_tools.len() > MAX_TRUST_ENTRIES {
            return Err(format!(
                "source_trust.verified_tools exceeds {MAX_TRUST_ENTRIES} entries"
            ));
        }
        if self.server_trust.len() > MAX_TRUST_ENTRIES {
            return Err(format!(
                "source_trust.server_trust exceeds {MAX_TRUST_ENTRIES} entries"
            ));
        }
        for (i, entry) in self.untrusted_tools.iter().enumerate() {
            if entry.is_empty() || entry.len() > 256 {
                return Err(format!(
                    "source_trust.untrusted_tools[{i}] must be 1-256 chars"
                ));
            }
            if vellaveto_types::has_dangerous_chars(entry) {
                return Err(format!(
                    "source_trust.untrusted_tools[{i}] contains dangerous characters"
                ));
            }
        }
        for (i, entry) in self.verified_tools.iter().enumerate() {
            if entry.is_empty() || entry.len() > 256 {
                return Err(format!(
                    "source_trust.verified_tools[{i}] must be 1-256 chars"
                ));
            }
            if vellaveto_types::has_dangerous_chars(entry) {
                return Err(format!(
                    "source_trust.verified_tools[{i}] contains dangerous characters"
                ));
            }
        }
        Ok(())
    }

    /// Resolve the trust tier for a tool, checking untrusted/verified lists
    /// then server overrides, then falling back to default.
    pub fn resolve_tool_trust(&self, tool_name: &str, server_name: Option<&str>) -> TrustTier {
        // Check untrusted list first (most restrictive)
        if self
            .untrusted_tools
            .iter()
            .any(|p| glob_match(p, tool_name))
        {
            return TrustTier::Untrusted;
        }
        // Check verified list
        if self.verified_tools.iter().any(|p| glob_match(p, tool_name)) {
            return TrustTier::Verified;
        }
        // Check server trust override
        if let Some(server) = server_name {
            if let Some(&tier) = self.server_trust.get(server) {
                return tier;
            }
        }
        self.default_tool_trust
    }
}

// ═══════════════════════════════════════════════════
// Phase 6.1C: Sink Classification
// ═══════════════════════════════════════════════════

/// Policy-driven sink class inference.
///
/// # TOML Example
///
/// ```toml
/// [[sink_classification.rules]]
/// tool_pattern = "execute_*"
/// sink_class = "CodeExecution"
///
/// [[sink_classification.rules]]
/// tool_pattern = "write_file"
/// sink_class = "FilesystemWrite"
/// ```
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SinkClassificationConfig {
    /// Per-tool sink class overrides. Glob patterns supported.
    #[serde(default)]
    pub rules: Vec<SinkClassRule>,
    /// Fallback to heuristic when no rule matches.
    #[serde(default = "default_true")]
    pub fallback_to_heuristic: bool,
}

fn default_true() -> bool {
    true
}

/// A rule mapping a tool pattern to a sink class.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SinkClassRule {
    /// Tool name or glob pattern.
    pub tool_pattern: String,
    /// Sink class for matching tools.
    pub sink_class: vellaveto_types::provenance::SinkClass,
}

impl SinkClassificationConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.rules.len() > MAX_TRUST_ENTRIES {
            return Err(format!(
                "sink_classification.rules exceeds {MAX_TRUST_ENTRIES} entries"
            ));
        }
        for (i, rule) in self.rules.iter().enumerate() {
            if rule.tool_pattern.is_empty() || rule.tool_pattern.len() > 256 {
                return Err(format!(
                    "sink_classification.rules[{i}].tool_pattern must be 1-256 chars"
                ));
            }
        }
        Ok(())
    }

    /// Resolve sink class for a tool. Returns None if no rule matches
    /// and fallback_to_heuristic is false.
    pub fn resolve_sink_class(
        &self,
        tool_name: &str,
    ) -> Option<vellaveto_types::provenance::SinkClass> {
        for rule in &self.rules {
            if glob_match(&rule.tool_pattern, tool_name) {
                return Some(rule.sink_class);
            }
        }
        if self.fallback_to_heuristic {
            Some(heuristic_sink_class(tool_name))
        } else {
            None
        }
    }
}

/// The existing heuristic sink class inference (extracted from relay.rs).
fn heuristic_sink_class(tool_name: &str) -> vellaveto_types::provenance::SinkClass {
    use vellaveto_types::provenance::SinkClass;
    if tool_name.contains("execute") || tool_name.contains("run") {
        SinkClass::CodeExecution
    } else if tool_name.contains("write") || tool_name.contains("delete") {
        SinkClass::FilesystemWrite
    } else {
        SinkClass::ReadOnly
    }
}

// ═══════════════════════════════════════════════════
// Phase 6.2: Intent Scope Declaration
// ═══════════════════════════════════════════════════

/// Declared intent scope for a session.
/// Constrains what the agent is authorized to do.
///
/// # TOML Example
///
/// ```toml
/// [intent_scope]
/// allowed_sink_classes = ["ReadOnly", "LowRiskWrite", "FilesystemWrite"]
/// allowed_tools = ["read_*", "write_*", "list_*"]
/// denied_tools = ["execute_*"]
/// out_of_scope_action = "RequireApproval"
/// max_distinct_tools = 10
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct IntentScopeConfig {
    /// Allowed sink classes for this session.
    #[serde(default)]
    pub allowed_sink_classes: Vec<vellaveto_types::provenance::SinkClass>,
    /// Explicitly allowed tool name patterns.
    #[serde(default)]
    pub allowed_tools: Vec<String>,
    /// Explicitly denied tool name patterns (takes precedence).
    #[serde(default)]
    pub denied_tools: Vec<String>,
    /// Action for out-of-scope calls.
    #[serde(default)]
    pub out_of_scope_action: OutOfScopeAction,
    /// Maximum distinct tools per session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_distinct_tools: Option<u32>,
    /// Whether scope can be widened mid-session.
    #[serde(default)]
    pub allow_scope_expansion: bool,
}

/// What to do when a call is out of scope.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum OutOfScopeAction {
    Deny,
    RequireApproval,
    #[default]
    AuditOnly,
}

impl Default for IntentScopeConfig {
    fn default() -> Self {
        Self {
            allowed_sink_classes: Vec::new(), // empty = all allowed
            allowed_tools: Vec::new(),
            denied_tools: Vec::new(),
            // SECURITY (R261-CFG-2): Default to Deny (fail-closed).
            // Previously AuditOnly, which silently passed out-of-scope calls.
            out_of_scope_action: OutOfScopeAction::Deny,
            max_distinct_tools: None,
            // SECURITY (R261-CFG-2): Default to false (fail-closed).
            // Previously true, allowing privilege escalation via scope expansion.
            allow_scope_expansion: false,
        }
    }
}

impl IntentScopeConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.allowed_tools.len() > MAX_TRUST_ENTRIES {
            return Err(format!(
                "intent_scope.allowed_tools exceeds {MAX_TRUST_ENTRIES}"
            ));
        }
        if self.denied_tools.len() > MAX_TRUST_ENTRIES {
            return Err(format!(
                "intent_scope.denied_tools exceeds {MAX_TRUST_ENTRIES}"
            ));
        }
        for (i, t) in self.allowed_tools.iter().enumerate() {
            if t.is_empty() || t.len() > 256 || vellaveto_types::has_dangerous_chars(t) {
                return Err(format!("intent_scope.allowed_tools[{i}] invalid"));
            }
        }
        for (i, t) in self.denied_tools.iter().enumerate() {
            if t.is_empty() || t.len() > 256 || vellaveto_types::has_dangerous_chars(t) {
                return Err(format!("intent_scope.denied_tools[{i}] invalid"));
            }
        }
        Ok(())
    }

    /// Check if a tool call is within scope.
    pub fn check_in_scope(
        &self,
        tool_name: &str,
        sink_class: vellaveto_types::provenance::SinkClass,
    ) -> ScopeCheckResult {
        // Denied tools take precedence
        if self.denied_tools.iter().any(|p| glob_match(p, tool_name)) {
            return ScopeCheckResult::OutOfScope {
                reason: "tool in denied_tools list".to_string(),
            };
        }
        // Check allowed tools (if non-empty, must match)
        if !self.allowed_tools.is_empty()
            && !self.allowed_tools.iter().any(|p| glob_match(p, tool_name))
        {
            return ScopeCheckResult::OutOfScope {
                reason: "tool not in allowed_tools list".to_string(),
            };
        }
        // Check allowed sink classes (if non-empty, must match)
        if !self.allowed_sink_classes.is_empty() && !self.allowed_sink_classes.contains(&sink_class)
        {
            return ScopeCheckResult::OutOfScope {
                reason: format!("sink class {:?} not in allowed_sink_classes", sink_class),
            };
        }
        ScopeCheckResult::InScope
    }

    /// Restrict scope to what the trust floor allows.
    /// Used when source-class taint fires to narrow the session's scope.
    pub fn restrict_to_trust_floor(&self, trust_floor: TrustTier) -> Self {
        use vellaveto_types::provenance::minimum_trust_tier_for_sink;
        let restricted_sinks: Vec<vellaveto_types::provenance::SinkClass> = self
            .allowed_sink_classes
            .iter()
            .copied()
            .filter(|sink| minimum_trust_tier_for_sink(*sink).rank() <= trust_floor.rank())
            .collect();

        Self {
            allowed_sink_classes: restricted_sinks,
            max_distinct_tools: self.max_distinct_tools.map(|n| n.min(3)),
            allow_scope_expansion: false,
            ..self.clone()
        }
    }
}

/// Result of an intent scope check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeCheckResult {
    InScope,
    OutOfScope { reason: String },
}

/// Simple glob matching (consistent with the rest of the codebase).
fn glob_match(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(star_pos) = pattern.find('*') {
        let prefix = &pattern[..star_pos];
        let suffix = &pattern[star_pos + 1..];
        value.starts_with(prefix) && value.ends_with(suffix)
    } else {
        pattern == value
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vellaveto_types::provenance::SinkClass;

    // ═══════════════════════════════════════════════════
    // Source trust tests
    // ═══════════════════════════════════════════════════

    #[test]
    fn test_resolve_untrusted_tool() {
        let config = SourceTrustConfig {
            untrusted_tools: vec!["fetch_*".to_string(), "browse_*".to_string()],
            ..Default::default()
        };
        assert_eq!(
            config.resolve_tool_trust("fetch_url", None),
            TrustTier::Untrusted
        );
        assert_eq!(
            config.resolve_tool_trust("read_file", None),
            TrustTier::Unknown
        );
    }

    #[test]
    fn test_resolve_verified_tool() {
        let config = SourceTrustConfig {
            verified_tools: vec!["internal_api_*".to_string()],
            ..Default::default()
        };
        assert_eq!(
            config.resolve_tool_trust("internal_api_users", None),
            TrustTier::Verified
        );
    }

    #[test]
    fn test_resolve_server_trust() {
        let mut server_trust = HashMap::new();
        server_trust.insert("github-mcp".to_string(), TrustTier::Medium);
        let config = SourceTrustConfig {
            server_trust,
            ..Default::default()
        };
        assert_eq!(
            config.resolve_tool_trust("any_tool", Some("github-mcp")),
            TrustTier::Medium
        );
        assert_eq!(
            config.resolve_tool_trust("any_tool", Some("unknown-server")),
            TrustTier::Unknown
        );
    }

    #[test]
    fn test_untrusted_takes_precedence_over_server() {
        let mut server_trust = HashMap::new();
        server_trust.insert("server".to_string(), TrustTier::High);
        let config = SourceTrustConfig {
            untrusted_tools: vec!["fetch_*".to_string()],
            server_trust,
            ..Default::default()
        };
        // fetch_url is untrusted even though server is High
        assert_eq!(
            config.resolve_tool_trust("fetch_url", Some("server")),
            TrustTier::Untrusted
        );
    }

    // ═══════════════════════════════════════════════════
    // Sink classification tests
    // ═══════════════════════════════════════════════════

    #[test]
    fn test_sink_classification_rule_match() {
        let config = SinkClassificationConfig {
            rules: vec![SinkClassRule {
                tool_pattern: "execute_*".to_string(),
                sink_class: SinkClass::CodeExecution,
            }],
            fallback_to_heuristic: true,
        };
        assert_eq!(
            config.resolve_sink_class("execute_command"),
            Some(SinkClass::CodeExecution)
        );
        // write_file falls through to heuristic
        assert_eq!(
            config.resolve_sink_class("write_file"),
            Some(SinkClass::FilesystemWrite)
        );
    }

    #[test]
    fn test_sink_classification_no_fallback() {
        let config = SinkClassificationConfig {
            rules: vec![],
            fallback_to_heuristic: false,
        };
        assert_eq!(config.resolve_sink_class("anything"), None);
    }

    // ═══════════════════════════════════════════════════
    // Intent scope tests
    // ═══════════════════════════════════════════════════

    #[test]
    fn test_intent_scope_in_scope() {
        let scope = IntentScopeConfig {
            allowed_tools: vec!["read_*".to_string(), "write_*".to_string()],
            allowed_sink_classes: vec![SinkClass::ReadOnly, SinkClass::FilesystemWrite],
            ..Default::default()
        };
        assert_eq!(
            scope.check_in_scope("read_file", SinkClass::ReadOnly),
            ScopeCheckResult::InScope
        );
    }

    #[test]
    fn test_intent_scope_denied_tool() {
        let scope = IntentScopeConfig {
            denied_tools: vec!["execute_*".to_string()],
            ..Default::default()
        };
        assert!(matches!(
            scope.check_in_scope("execute_command", SinkClass::CodeExecution),
            ScopeCheckResult::OutOfScope { .. }
        ));
    }

    #[test]
    fn test_intent_scope_sink_class_out_of_scope() {
        let scope = IntentScopeConfig {
            allowed_sink_classes: vec![SinkClass::ReadOnly],
            ..Default::default()
        };
        assert!(matches!(
            scope.check_in_scope("write_file", SinkClass::FilesystemWrite),
            ScopeCheckResult::OutOfScope { .. }
        ));
    }

    #[test]
    fn test_intent_scope_restrict_to_trust_floor() {
        let scope = IntentScopeConfig {
            allowed_sink_classes: vec![
                SinkClass::ReadOnly,
                SinkClass::FilesystemWrite,
                SinkClass::CodeExecution,
            ],
            max_distinct_tools: Some(20),
            allow_scope_expansion: true,
            ..Default::default()
        };
        // Trust floor = Low → only sinks requiring Low or less trust
        let restricted = scope.restrict_to_trust_floor(TrustTier::Low);
        // ReadOnly requires Unknown (rank 1), LowRiskWrite requires Low (rank 3)
        // FilesystemWrite requires Medium (rank 4) > Low (rank 3) → excluded
        // CodeExecution requires Verified (rank 6) > Low → excluded
        assert!(!restricted
            .allowed_sink_classes
            .contains(&SinkClass::CodeExecution));
        assert!(!restricted
            .allowed_sink_classes
            .contains(&SinkClass::FilesystemWrite));
        assert!(restricted
            .allowed_sink_classes
            .contains(&SinkClass::ReadOnly));
        assert_eq!(restricted.max_distinct_tools, Some(3));
        assert!(!restricted.allow_scope_expansion);
    }

    #[test]
    fn test_intent_scope_empty_lists_allow_all() {
        let scope = IntentScopeConfig::default();
        assert_eq!(
            scope.check_in_scope("anything", SinkClass::PolicyMutation),
            ScopeCheckResult::InScope
        );
    }
}
