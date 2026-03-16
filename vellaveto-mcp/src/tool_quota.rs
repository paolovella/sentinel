// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Phase 2: Per-tool rate limiting and quota enforcement.
//!
//! Enforces `[[tool_quotas]]` from the policy config at runtime.
//! Each quota entry specifies a tool pattern (glob), max calls per window,
//! and the action on exceed (deny or require_approval).

use std::collections::HashMap;
use std::time::Instant;
use vellaveto_config::ToolQuota;

/// Maximum number of call timestamps to retain per tool (prevents OOM).
const MAX_CALL_TIMESTAMPS: usize = 10_000;

/// Runtime tracker for per-tool rate limits.
pub struct ToolQuotaTracker {
    quotas: Vec<ToolQuota>,
    /// Per-tool call timestamps. Key: tool name, Value: timestamps.
    calls: HashMap<String, Vec<Instant>>,
}

impl ToolQuotaTracker {
    /// Create a new tracker from configured quotas.
    pub fn new(quotas: Vec<ToolQuota>) -> Self {
        Self {
            quotas,
            calls: HashMap::new(),
        }
    }

    /// Check if a tool call is permitted under the configured quotas.
    ///
    /// Returns `Ok(())` if allowed, `Err(QuotaExceeded)` if any quota is exceeded.
    /// The caller should record the call with `record_call()` after forwarding.
    pub fn check_quota(&mut self, tool_name: &str) -> Result<(), QuotaExceeded> {
        let now = Instant::now();

        for quota in &self.quotas {
            if !tool_matches_pattern(tool_name, &quota.tool_pattern) {
                continue;
            }

            let window = std::time::Duration::from_secs(quota.window_secs);
            let cutoff = now.checked_sub(window).unwrap_or(now);

            let calls = self.calls.entry(tool_name.to_string()).or_default();

            // Prune old entries
            calls.retain(|t| *t >= cutoff);

            if calls.len() >= quota.max_calls as usize {
                return Err(QuotaExceeded {
                    tool: tool_name.to_string(),
                    pattern: quota.tool_pattern.clone(),
                    max_calls: quota.max_calls,
                    window_secs: quota.window_secs,
                    on_exceed: quota.on_exceed.clone(),
                });
            }
        }

        Ok(())
    }

    /// Record a tool call after it has been forwarded.
    pub fn record_call(&mut self, tool_name: &str) {
        let calls = self.calls.entry(tool_name.to_string()).or_default();
        if calls.len() < MAX_CALL_TIMESTAMPS {
            calls.push(Instant::now());
        }
    }

    /// Returns true if any quotas are configured.
    pub fn has_quotas(&self) -> bool {
        !self.quotas.is_empty()
    }
}

/// Quota exceeded result with details for audit/deny.
#[derive(Debug)]
pub struct QuotaExceeded {
    pub tool: String,
    pub pattern: String,
    pub max_calls: u32,
    pub window_secs: u64,
    pub on_exceed: String,
}

impl std::fmt::Display for QuotaExceeded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "tool quota exceeded: '{}' matched pattern '{}' ({}/{} calls in {}s window)",
            &self.tool[..self.tool.len().min(64)],
            &self.pattern[..self.pattern.len().min(64)],
            self.max_calls,
            self.max_calls,
            self.window_secs
        )
    }
}

/// Simple glob matching (consistent with policy engine tool_pattern).
fn tool_matches_pattern(tool_name: &str, pattern: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(star_pos) = pattern.find('*') {
        let prefix = &pattern[..star_pos];
        let suffix = &pattern[star_pos + 1..];
        tool_name.starts_with(prefix) && tool_name.ends_with(suffix)
    } else {
        pattern == tool_name
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_quota(pattern: &str, max_calls: u32, window_secs: u64) -> ToolQuota {
        ToolQuota {
            tool_pattern: pattern.to_string(),
            max_calls,
            window_secs,
            on_exceed: "deny".to_string(),
        }
    }

    #[test]
    fn test_quota_allows_under_limit() {
        let mut tracker = ToolQuotaTracker::new(vec![make_quota("execute_command", 3, 60)]);
        assert!(tracker.check_quota("execute_command").is_ok());
        tracker.record_call("execute_command");
        assert!(tracker.check_quota("execute_command").is_ok());
        tracker.record_call("execute_command");
        assert!(tracker.check_quota("execute_command").is_ok());
    }

    #[test]
    fn test_quota_denies_at_limit() {
        let mut tracker = ToolQuotaTracker::new(vec![make_quota("execute_command", 2, 60)]);
        tracker.record_call("execute_command");
        tracker.record_call("execute_command");
        let result = tracker.check_quota("execute_command");
        assert!(result.is_err());
        let exceeded = result.unwrap_err();
        assert_eq!(exceeded.max_calls, 2);
        assert_eq!(exceeded.tool, "execute_command");
    }

    #[test]
    fn test_quota_glob_pattern() {
        let mut tracker = ToolQuotaTracker::new(vec![make_quota("write_*", 1, 60)]);
        tracker.record_call("write_file");
        // write_file matches write_* so should be denied
        assert!(tracker.check_quota("write_file").is_err());
        // read_file does NOT match write_*
        assert!(tracker.check_quota("read_file").is_ok());
    }

    #[test]
    fn test_quota_unmatched_tool_allowed() {
        let mut tracker = ToolQuotaTracker::new(vec![make_quota("execute_command", 1, 60)]);
        tracker.record_call("read_file");
        tracker.record_call("read_file");
        tracker.record_call("read_file");
        // read_file has no quota — always allowed
        assert!(tracker.check_quota("read_file").is_ok());
    }

    #[test]
    fn test_quota_require_approval_on_exceed() {
        let mut tracker = ToolQuotaTracker::new(vec![ToolQuota {
            tool_pattern: "delete_*".to_string(),
            max_calls: 1,
            window_secs: 60,
            on_exceed: "require_approval".to_string(),
        }]);
        tracker.record_call("delete_file");
        let exceeded = tracker.check_quota("delete_file").unwrap_err();
        assert_eq!(exceeded.on_exceed, "require_approval");
    }

    #[test]
    fn test_quota_no_quotas_always_allows() {
        let mut tracker = ToolQuotaTracker::new(Vec::new());
        assert!(!tracker.has_quotas());
        assert!(tracker.check_quota("anything").is_ok());
    }
}
