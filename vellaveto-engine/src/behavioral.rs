// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Behavioral anomaly detection for agent tool call patterns (P4.1 / OWASP ASI).
//!
//! Tracks per-agent tool call frequency using exponential moving average (EMA)
//! and flags deviations from established baselines. Deterministic and auditable —
//! no ML, no randomness.
//!
//! # Design
//!
//! - **EMA**: `new_ema = alpha * current + (1 - alpha) * old_ema`
//! - **Anomaly**: flagged when `current_count / baseline_ema >= threshold`
//! - **Cold start**: no alerts until `min_sessions` sessions are recorded
//! - **Bounded memory**: max agents and max tools per agent with LRU eviction
//! - **Decay**: tools unused in a session have their EMA decayed toward zero

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

// ═══════════════════════════════════════════════════
// CONFIGURATION
// ═══════════════════════════════════════════════════

/// Configuration for behavioral anomaly detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BehavioralConfig {
    /// EMA smoothing factor in (0.0, 1.0]. Higher values weight recent data more.
    /// Default: 0.2
    #[serde(default = "default_alpha")]
    pub alpha: f64,

    /// Deviation threshold multiplier. Anomaly flagged when
    /// `current_count / baseline_ema >= threshold`.
    /// Default: 10.0
    #[serde(default = "default_threshold")]
    pub threshold: f64,

    /// Minimum sessions before baselines are actionable (cold start protection).
    /// No anomalies are flagged until both the agent and the specific tool have
    /// at least this many recorded sessions.
    /// Default: 3
    #[serde(default = "default_min_sessions")]
    pub min_sessions: u32,

    /// Maximum tool entries tracked per agent. Oldest (by last active use) evicted first.
    /// Default: 500
    #[serde(default = "default_max_tools")]
    pub max_tools_per_agent: usize,

    /// Maximum agents tracked. Agent with fewest total sessions evicted first.
    /// Default: 10_000
    #[serde(default = "default_max_agents")]
    pub max_agents: usize,

    /// Absolute ceiling for tool call count per session (FIND-080).
    /// When set, any session with a tool call count exceeding this value
    /// triggers a Critical alert regardless of EMA baseline.
    /// Prevents gradual ramp evasion where EMA adapts to slow increases.
    /// Default: None (no absolute ceiling)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub absolute_ceiling: Option<u64>,

    /// Maximum initial EMA value for cold-start protection (FIND-081).
    /// When set, the first observation's EMA is capped at this value,
    /// preventing attackers from setting an artificially high baseline
    /// by flooding calls during the first session.
    /// Default: None (no cap)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_initial_ema: Option<f64>,
}

fn default_alpha() -> f64 {
    0.2
}
fn default_threshold() -> f64 {
    10.0
}
fn default_min_sessions() -> u32 {
    3
}
fn default_max_tools() -> usize {
    500
}
fn default_max_agents() -> usize {
    10_000
}

impl Default for BehavioralConfig {
    fn default() -> Self {
        Self {
            alpha: default_alpha(),
            threshold: default_threshold(),
            min_sessions: default_min_sessions(),
            max_tools_per_agent: default_max_tools(),
            max_agents: default_max_agents(),
            absolute_ceiling: None,
            max_initial_ema: None,
        }
    }
}

// ═══════════════════════════════════════════════════
// ERRORS
// ═══════════════════════════════════════════════════

/// Errors from behavioral tracking operations.
#[derive(Debug, Clone, PartialEq)]
pub enum BehavioralError {
    /// Alpha must be in (0.0, 1.0].
    InvalidAlpha(f64),
    /// Threshold must be positive and finite.
    InvalidThreshold(f64),
    /// max_tools_per_agent must be > 0.
    InvalidMaxTools,
    /// max_agents must be > 0.
    InvalidMaxAgents,
    /// Snapshot contains invalid data.
    InvalidSnapshot(String),
}

impl std::fmt::Display for BehavioralError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BehavioralError::InvalidAlpha(a) => {
                write!(f, "alpha must be in (0.0, 1.0], got {a}")
            }
            BehavioralError::InvalidThreshold(t) => {
                write!(f, "threshold must be positive and finite, got {t}")
            }
            BehavioralError::InvalidMaxTools => write!(f, "max_tools_per_agent must be > 0"),
            BehavioralError::InvalidMaxAgents => write!(f, "max_agents must be > 0"),
            BehavioralError::InvalidSnapshot(msg) => write!(f, "invalid snapshot: {msg}"),
        }
    }
}

impl std::error::Error for BehavioralError {}

impl BehavioralConfig {
    /// Validate configuration values.
    pub fn validate(&self) -> Result<(), BehavioralError> {
        if self.alpha <= 0.0 || self.alpha > 1.0 || self.alpha.is_nan() {
            return Err(BehavioralError::InvalidAlpha(self.alpha));
        }
        if self.threshold <= 0.0 || self.threshold.is_nan() || self.threshold.is_infinite() {
            return Err(BehavioralError::InvalidThreshold(self.threshold));
        }
        // SECURITY (R240-ENG-3): Upper-bound max_tools_per_agent and max_agents to
        // prevent unbounded HashMap growth from attacker-controlled configuration.
        const MAX_BEHAVIORAL_AGENTS: usize = 1_000_000;
        const MAX_TOOLS_PER_AGENT_LIMIT: usize = 100_000;
        if self.max_tools_per_agent == 0 || self.max_tools_per_agent > MAX_TOOLS_PER_AGENT_LIMIT {
            return Err(BehavioralError::InvalidMaxTools);
        }
        if self.max_agents == 0 || self.max_agents > MAX_BEHAVIORAL_AGENTS {
            return Err(BehavioralError::InvalidMaxAgents);
        }
        // SECURITY (FIND-R113-P3): Validate max_initial_ema is positive and finite.
        if let Some(max_ema) = self.max_initial_ema {
            if max_ema <= 0.0 || max_ema.is_nan() || max_ema.is_infinite() {
                return Err(BehavioralError::InvalidThreshold(max_ema));
            }
        }
        Ok(())
    }
}

// ═══════════════════════════════════════════════════
// BASELINE & ALERT TYPES
// ═══════════════════════════════════════════════════

/// Per-tool statistics tracked across sessions.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolBaseline {
    /// Exponential moving average of call count.
    pub ema: f64,
    /// Number of sessions where this tool was observed or decayed.
    pub session_count: u32,
    /// Monotonic counter from last *active* use (non-zero call count).
    /// Used for eviction: tools only passively decaying have stale values.
    pub last_active: u64,
}

/// Severity of a detected anomaly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AnomalySeverity {
    /// Current count exceeds `threshold * baseline` (but below 2x threshold).
    Warning,
    /// Current count exceeds `2 * threshold * baseline`.
    Critical,
}

/// An anomaly detected in tool call behavior.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnomalyAlert {
    /// Agent that triggered the anomaly.
    pub agent_id: String,
    /// Tool name with anomalous frequency.
    pub tool: String,
    /// Current session's call count for this tool.
    pub current_count: u64,
    /// Historical EMA baseline.
    pub baseline_ema: f64,
    /// Deviation ratio (`current_count / baseline_ema`).
    pub deviation_ratio: f64,
    /// Severity level.
    pub severity: AnomalySeverity,
}

impl std::fmt::Display for AnomalyAlert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[{:?}] Agent '{}' tool '{}': {} calls (baseline {:.1}, ratio {:.1}x)",
            self.severity,
            self.agent_id,
            self.tool,
            self.current_count,
            self.baseline_ema,
            self.deviation_ratio,
        )
    }
}

// ═══════════════════════════════════════════════════
// SNAPSHOT (PERSISTENCE)
// ═══════════════════════════════════════════════════

/// Serializable snapshot of all behavioral tracking state.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BehavioralSnapshot {
    /// Per-agent state.
    pub agents: HashMap<String, AgentSnapshotEntry>,
    /// Global update counter at time of snapshot.
    pub update_counter: u64,
}

/// Snapshot entry for a single agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSnapshotEntry {
    pub tools: HashMap<String, ToolBaseline>,
    pub total_sessions: u32,
}

// ═══════════════════════════════════════════════════
// INTERNAL STATE
// ═══════════════════════════════════════════════════

/// Per-agent tracking state.
#[derive(Debug, Clone)]
struct AgentState {
    tools: HashMap<String, ToolBaseline>,
    total_sessions: u32,
}

// ═══════════════════════════════════════════════════
// TRACKER
// ═══════════════════════════════════════════════════

/// Tracks per-agent tool call frequency patterns and detects anomalies.
///
/// Uses exponential moving average (EMA) — deterministic, auditable, no ML.
/// Designed to detect behavioral shifts like an agent suddenly making 500
/// `read_file` calls when the historical average is 5.
pub struct BehavioralTracker {
    config: BehavioralConfig,
    agents: HashMap<String, AgentState>,
    /// Monotonic counter incremented on each `record_session` call.
    update_counter: u64,
}

impl BehavioralTracker {
    /// Create a new tracker. Returns an error if the configuration is invalid.
    pub fn new(config: BehavioralConfig) -> Result<Self, BehavioralError> {
        config.validate()?;
        Ok(Self {
            config,
            agents: HashMap::new(),
            update_counter: 0,
        })
    }

    /// Check current session's call counts against historical baselines.
    ///
    /// Returns detected anomalies (may be empty). Does **not** modify state.
    /// Call [`record_session`](Self::record_session) after the session completes
    /// to update baselines.
    /// SECURITY (FIND-R139-001): Maximum number of entries in a caller-supplied
    /// call_counts map. Prevents O(n) iteration DoS from pathologically large maps.
    const MAX_CALL_COUNT_ENTRIES: usize = 10_000;

    /// SECURITY (FIND-R139-002): Maximum length for agent_id on the live path,
    /// matching the validation applied in `from_snapshot`.
    const MAX_AGENT_ID_LEN: usize = 512;

    /// SECURITY (FIND-R116-TE-003): Maximum length for tool keys in call_counts,
    /// matching the canonical MAX_NAME_LEN (256) used for tool names in vellaveto-types.
    const MAX_TOOL_KEY_LEN: usize = 256;

    #[must_use = "behavioral anomaly alerts must not be discarded"]
    pub fn check_session(
        &self,
        agent_id: &str,
        call_counts: &HashMap<String, u64>,
    ) -> Vec<AnomalyAlert> {
        let mut alerts = Vec::new();

        // SECURITY (FIND-R139-002): Validate agent_id on the live path.
        if agent_id.len() > Self::MAX_AGENT_ID_LEN
            || agent_id
                .chars()
                .any(|c| c.is_control() || vellaveto_types::is_unicode_format_char(c))
        {
            tracing::warn!(
                len = agent_id.len(),
                "check_session: rejecting invalid agent_id"
            );
            return alerts;
        }

        // SECURITY (R239-ENG-1): Normalize agent_id through NFKC + lowercase + homoglyph
        // mapping so that homoglyph variants map to the same baseline.
        let agent_id = crate::normalize::normalize_full(agent_id);

        // SECURITY (FIND-R139-001): Cap call_counts iteration.
        if call_counts.len() > Self::MAX_CALL_COUNT_ENTRIES {
            tracing::warn!(
                count = call_counts.len(),
                max = Self::MAX_CALL_COUNT_ENTRIES,
                "check_session: call_counts exceeds cap, skipping"
            );
            return alerts;
        }

        let agent = match self.agents.get(&agent_id) {
            Some(a) => a,
            None => return alerts, // No history for this agent
        };

        // Cold start: don't flag until the agent has enough sessions
        if agent.total_sessions < self.config.min_sessions {
            tracing::debug!(
                agent_id = %agent_id,
                sessions = %agent.total_sessions,
                min_required = %self.config.min_sessions,
                "Agent in cold-start phase, anomaly detection deferred"
            );
            return alerts;
        }

        for (tool, &count) in call_counts {
            if count == 0 {
                continue;
            }

            // SECURITY (FIND-R116-TE-003): Validate tool keys for length and
            // control/format characters, matching the validation in from_snapshot().
            if tool.len() > Self::MAX_TOOL_KEY_LEN {
                tracing::warn!("check_session: skipping oversized tool key");
                continue;
            }
            if tool
                .chars()
                .any(|c| c.is_control() || vellaveto_types::is_unicode_format_char(c))
            {
                tracing::warn!("check_session: skipping tool key with control/format chars");
                continue;
            }

            // SECURITY (FIND-080): Check absolute ceiling before EMA-based detection.
            // This catches gradual ramp attacks where EMA adapts to slow increases.
            if let Some(ceiling) = self.config.absolute_ceiling {
                if count > ceiling {
                    // SECURITY (FIND-R114-001): Guard against ceiling=0 producing
                    // Infinity in deviation_ratio, which bypasses threshold comparisons.
                    // When ceiling is 0, any non-zero count is maximally anomalous.
                    let deviation_ratio = if ceiling == 0 {
                        f64::MAX
                    } else {
                        count as f64 / ceiling as f64
                    };
                    let alert = AnomalyAlert {
                        severity: AnomalySeverity::Critical,
                        tool: tool.clone(),
                        current_count: count,
                        baseline_ema: self
                            .agents
                            .get(&agent_id)
                            .and_then(|a| a.tools.get(tool))
                            .map_or(0.0, |b| b.ema),
                        deviation_ratio,
                        agent_id: agent_id.clone(),
                    };

                    metrics::counter!(
                        "vellaveto_anomaly_detections_total",
                        "severity" => "critical"
                    )
                    .increment(1);

                    tracing::warn!(
                        agent_id = %agent_id,
                        tool = %tool,
                        current_count = %count,
                        ceiling = %ceiling,
                        "CRITICAL: Tool call count exceeds absolute ceiling"
                    );

                    alerts.push(alert);
                    continue; // Already flagged — skip EMA check for this tool
                }
            }

            let baseline = match agent.tools.get(tool) {
                Some(b) => b,
                None => continue, // New tool — no baseline yet
            };

            // Per-tool cold start: need enough observations for this specific tool
            if baseline.session_count < self.config.min_sessions {
                tracing::trace!(
                    agent_id = %agent_id,
                    tool = %tool,
                    tool_sessions = %baseline.session_count,
                    min_required = %self.config.min_sessions,
                    "Tool in cold-start phase, skipping anomaly check"
                );
                continue;
            }

            // Compute deviation ratio. If baseline EMA is zero (edge case:
            // tool was recorded but EMA decayed to exactly 0.0), treat any
            // non-zero count as anomalous with a high synthetic ratio.
            let ratio = if baseline.ema <= f64::EPSILON {
                count as f64 // effectively infinite deviation
            } else {
                count as f64 / baseline.ema
            };

            if ratio >= self.config.threshold {
                let severity = if ratio >= self.config.threshold * 2.0 {
                    AnomalySeverity::Critical
                } else {
                    AnomalySeverity::Warning
                };

                let alert = AnomalyAlert {
                    agent_id: agent_id.clone(),
                    tool: tool.clone(),
                    current_count: count,
                    baseline_ema: baseline.ema,
                    deviation_ratio: ratio,
                    severity,
                };

                // IMPROVEMENT_PLAN 1.2: Record anomaly detection metrics
                let severity_label = match severity {
                    AnomalySeverity::Critical => "critical",
                    AnomalySeverity::Warning => "warning",
                };
                metrics::counter!(
                    "vellaveto_anomaly_detections_total",
                    "severity" => severity_label.to_string()
                )
                .increment(1);

                // Log anomaly detection for observability
                match severity {
                    AnomalySeverity::Critical => {
                        tracing::warn!(
                            agent_id = %agent_id,
                            tool = %tool,
                            current_count = %count,
                            baseline_ema = %baseline.ema,
                            deviation_ratio = %ratio,
                            "CRITICAL behavioral anomaly detected: tool call frequency {:.1}x above baseline",
                            ratio
                        );
                    }
                    AnomalySeverity::Warning => {
                        tracing::warn!(
                            agent_id = %agent_id,
                            tool = %tool,
                            current_count = %count,
                            baseline_ema = %baseline.ema,
                            deviation_ratio = %ratio,
                            "Behavioral anomaly detected: tool call frequency {:.1}x above baseline",
                            ratio
                        );
                    }
                }

                alerts.push(alert);
            }
        }

        alerts
    }

    /// Update baselines after a session completes.
    ///
    /// Call this with the final call counts when a session ends.
    /// Tools with zero counts are ignored for recording but existing baselines
    /// for tools **not present** in `call_counts` are decayed toward zero.
    pub fn record_session(&mut self, agent_id: &str, call_counts: &HashMap<String, u64>) {
        // SECURITY (FIND-R139-002): Validate agent_id on the live path.
        if agent_id.len() > Self::MAX_AGENT_ID_LEN
            || agent_id
                .chars()
                .any(|c| c.is_control() || vellaveto_types::is_unicode_format_char(c))
        {
            tracing::warn!(
                len = agent_id.len(),
                "record_session: rejecting invalid agent_id"
            );
            return;
        }

        // SECURITY (R239-ENG-1): Normalize agent_id through NFKC + lowercase + homoglyph
        // mapping so that homoglyph variants map to the same baseline.
        let agent_id = crate::normalize::normalize_full(agent_id);

        // SECURITY (FIND-R139-001): Cap call_counts iteration.
        if call_counts.len() > Self::MAX_CALL_COUNT_ENTRIES {
            tracing::warn!(
                count = call_counts.len(),
                max = Self::MAX_CALL_COUNT_ENTRIES,
                "record_session: call_counts exceeds cap, skipping"
            );
            return;
        }

        self.update_counter = self.update_counter.saturating_add(1);

        // Enforce agent limit via eviction before inserting a new agent
        if !self.agents.contains_key(agent_id.as_str())
            && self.agents.len() >= self.config.max_agents
        {
            self.evict_agent();
        }

        let agent = self
            .agents
            .entry(agent_id.to_string())
            .or_insert_with(|| AgentState {
                tools: HashMap::new(),
                total_sessions: 0,
            });

        agent.total_sessions = agent.total_sessions.saturating_add(1);

        // Collect which tools were actively called (non-zero count)
        let called_tools: HashSet<&String> = call_counts
            .iter()
            .filter(|(_, &c)| c > 0)
            .map(|(k, _)| k)
            .collect();

        // Update baselines for actively called tools
        for (tool, &count) in call_counts {
            if count == 0 {
                continue;
            }

            // SECURITY (FIND-R116-TE-003): Validate tool keys for length and
            // control/format characters, matching the validation in from_snapshot()
            // and check_session(). Skip entries with invalid tool keys.
            if tool.len() > Self::MAX_TOOL_KEY_LEN {
                tracing::warn!("record_session: skipping oversized tool key");
                continue;
            }
            if tool
                .chars()
                .any(|c| c.is_control() || vellaveto_types::is_unicode_format_char(c))
            {
                tracing::warn!("record_session: skipping tool key with control/format chars");
                continue;
            }

            // Enforce per-agent tool limit
            if !agent.tools.contains_key(tool)
                && agent.tools.len() >= self.config.max_tools_per_agent
            {
                Self::evict_tool(&mut agent.tools);
            }

            let baseline = agent
                .tools
                .entry(tool.clone())
                .or_insert_with(|| ToolBaseline {
                    ema: 0.0,
                    session_count: 0,
                    last_active: 0,
                });

            // EMA update
            if baseline.session_count == 0 {
                // First observation: initialize EMA directly
                // SECURITY (FIND-081): Cap initial EMA to prevent cold-start poisoning.
                baseline.ema = if let Some(cap) = self.config.max_initial_ema {
                    (count as f64).min(cap)
                } else {
                    count as f64
                };
            } else {
                baseline.ema =
                    self.config.alpha * count as f64 + (1.0 - self.config.alpha) * baseline.ema;
                // SECURITY (FIND-R139-003): Clamp non-finite EMA to fail-closed.
                // If EMA becomes +Infinity, all ratios become 0.0, silently
                // disabling anomaly detection for this tool/agent.
                if !baseline.ema.is_finite() {
                    tracing::error!(
                        "EMA overflow detected — resetting to current count for fail-closed behavior"
                    );
                    baseline.ema = count as f64;
                }
            }

            baseline.session_count = baseline.session_count.saturating_add(1);
            baseline.last_active = self.update_counter;
        }

        // Decay baselines for tools that were NOT called this session.
        // Their effective count is 0 → EMA trends toward zero.
        // Note: we intentionally do NOT update `last_active` here so that
        // passively decaying tools are evicted before actively used ones.
        // SECURITY (FIND-R49-002): Evict stale near-zero EMA tools after prolonged decay.
        // Without this, tools that are never called again accumulate indefinitely in memory,
        // with EMA asymptotically approaching zero but never being cleaned up.
        const MAX_DECAY_SESSIONS: u32 = 200;
        let mut evict_keys: Vec<String> = Vec::new();

        let existing_tools: Vec<String> = agent.tools.keys().cloned().collect();
        for tool_name in &existing_tools {
            if !called_tools.contains(tool_name) {
                if let Some(baseline) = agent.tools.get_mut(tool_name) {
                    baseline.ema *= 1.0 - self.config.alpha;
                    baseline.session_count = baseline.session_count.saturating_add(1);

                    // Track tools to evict (stale near-zero EMA after prolonged decay)
                    if baseline.session_count > MAX_DECAY_SESSIONS && baseline.ema < 0.01 {
                        evict_keys.push(tool_name.clone());
                    }
                }
            }
        }

        // Remove stale entries outside the borrow of agent.tools
        for key in &evict_keys {
            agent.tools.remove(key);
        }
    }

    /// Get the baseline for a specific agent and tool.
    pub fn get_baseline(&self, agent_id: &str, tool: &str) -> Option<&ToolBaseline> {
        self.agents.get(agent_id)?.tools.get(tool)
    }

    /// Get the total sessions recorded for an agent.
    pub fn agent_sessions(&self, agent_id: &str) -> Option<u32> {
        self.agents.get(agent_id).map(|a| a.total_sessions)
    }

    /// Number of agents being tracked.
    pub fn agent_count(&self) -> usize {
        self.agents.len()
    }

    /// Number of tools tracked for a specific agent.
    pub fn tool_count(&self, agent_id: &str) -> usize {
        self.agents.get(agent_id).map_or(0, |a| a.tools.len())
    }

    /// Access the current configuration.
    pub fn config(&self) -> &BehavioralConfig {
        &self.config
    }

    /// Create a serializable snapshot of all tracking state.
    pub fn snapshot(&self) -> BehavioralSnapshot {
        let agents = self
            .agents
            .iter()
            .map(|(id, state)| {
                (
                    id.clone(),
                    AgentSnapshotEntry {
                        tools: state.tools.clone(),
                        total_sessions: state.total_sessions,
                    },
                )
            })
            .collect();

        BehavioralSnapshot {
            agents,
            update_counter: self.update_counter,
        }
    }

    /// Restore from a persisted snapshot.
    ///
    /// Validates that all EMA values are finite and non-negative.
    pub fn from_snapshot(
        config: BehavioralConfig,
        snapshot: BehavioralSnapshot,
    ) -> Result<Self, BehavioralError> {
        config.validate()?;

        // SECURITY (FIND-R58-ENG-001): Enforce max_agents/max_tools_per_agent bounds
        // on deserialized snapshots to prevent OOM from oversized snapshot files.
        if snapshot.agents.len() > config.max_agents {
            return Err(BehavioralError::InvalidSnapshot(format!(
                "snapshot has {} agents, exceeds max_agents {}",
                snapshot.agents.len(),
                config.max_agents
            )));
        }
        for (agent_id, entry) in &snapshot.agents {
            // SECURITY (R256-ENG-1): Reject oversized agent_id keys from snapshots.
            // Parity with the live-path check in check_session()/record_session().
            if agent_id.len() > Self::MAX_AGENT_ID_LEN {
                return Err(BehavioralError::InvalidSnapshot(format!(
                    "agent_id length {} exceeds maximum {}",
                    agent_id.len(),
                    Self::MAX_AGENT_ID_LEN
                )));
            }
            // SECURITY (FIND-R114-002): Reject agent_id keys with control or
            // Unicode format characters to prevent bidi override injection in
            // pattern matching and log confusion.
            if agent_id
                .chars()
                .any(|c| c.is_control() || vellaveto_types::is_unicode_format_char(c))
            {
                return Err(BehavioralError::InvalidSnapshot(
                    "agent_id contains control or Unicode format characters".to_string(),
                ));
            }
            if entry.tools.len() > config.max_tools_per_agent {
                return Err(BehavioralError::InvalidSnapshot(format!(
                    "agent '{}' has {} tools, exceeds max_tools_per_agent {}",
                    agent_id,
                    entry.tools.len(),
                    config.max_tools_per_agent
                )));
            }
            for (tool, baseline) in &entry.tools {
                // SECURITY (R256-ENG-1): Reject oversized tool keys from snapshots.
                // Parity with the live-path check in check_session()/record_session().
                if tool.len() > Self::MAX_TOOL_KEY_LEN {
                    return Err(BehavioralError::InvalidSnapshot(format!(
                        "tool key length {} exceeds maximum {}",
                        tool.len(),
                        Self::MAX_TOOL_KEY_LEN
                    )));
                }
                // SECURITY (FIND-R114-002): Reject tool keys with control or
                // Unicode format characters.
                if tool
                    .chars()
                    .any(|c| c.is_control() || vellaveto_types::is_unicode_format_char(c))
                {
                    return Err(BehavioralError::InvalidSnapshot(
                        "tool key contains control or Unicode format characters".to_string(),
                    ));
                }
                if baseline.ema.is_nan() || baseline.ema.is_infinite() {
                    return Err(BehavioralError::InvalidSnapshot(format!(
                        "agent '{}' tool '{}' has invalid EMA: {}",
                        agent_id, tool, baseline.ema
                    )));
                }
                if baseline.ema < 0.0 {
                    return Err(BehavioralError::InvalidSnapshot(format!(
                        "agent '{}' tool '{}' has negative EMA: {}",
                        agent_id, tool, baseline.ema
                    )));
                }
            }
        }

        let agents = snapshot
            .agents
            .into_iter()
            .map(|(id, entry)| {
                (
                    id,
                    AgentState {
                        tools: entry.tools,
                        total_sessions: entry.total_sessions,
                    },
                )
            })
            .collect();

        Ok(Self {
            config,
            agents,
            update_counter: snapshot.update_counter,
        })
    }

    /// Evict the agent with the fewest total sessions.
    fn evict_agent(&mut self) {
        if let Some(victim) = self
            .agents
            .iter()
            .min_by_key(|(_, state)| state.total_sessions)
            .map(|(id, _)| id.clone())
        {
            self.agents.remove(&victim);
        }
    }

    /// Evict the tool with the oldest `last_active` timestamp.
    fn evict_tool(tools: &mut HashMap<String, ToolBaseline>) {
        if let Some(victim) = tools
            .iter()
            .min_by_key(|(_, baseline)| baseline.last_active)
            .map(|(name, _)| name.clone())
        {
            tools.remove(&victim);
        }
    }
}

// ═══════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to build call count maps concisely.
    fn counts(data: &[(&str, u64)]) -> HashMap<String, u64> {
        data.iter().map(|(k, v)| (k.to_string(), *v)).collect()
    }

    // ── Config validation ─────────────────────────

    #[test]
    fn test_new_tracker_default_config() {
        let tracker = BehavioralTracker::new(BehavioralConfig::default());
        assert!(tracker.is_ok());
        assert_eq!(tracker.as_ref().map(|t| t.agent_count()).unwrap_or(0), 0);
    }

    #[test]
    fn test_config_validate_valid() {
        assert!(BehavioralConfig::default().validate().is_ok());
        let edge = BehavioralConfig {
            alpha: 1.0, // upper bound inclusive
            ..Default::default()
        };
        assert!(edge.validate().is_ok());
    }

    #[test]
    #[allow(clippy::field_reassign_with_default)]
    fn test_config_validate_invalid_alpha() {
        for bad in [0.0, -0.1, 1.1, f64::NAN] {
            let mut c = BehavioralConfig::default();
            c.alpha = bad;
            assert!(
                matches!(c.validate(), Err(BehavioralError::InvalidAlpha(_))),
                "alpha={bad} should fail"
            );
        }
    }

    #[test]
    #[allow(clippy::field_reassign_with_default)]
    fn test_config_validate_invalid_threshold() {
        for bad in [0.0, -1.0, f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            let mut c = BehavioralConfig::default();
            c.threshold = bad;
            assert!(
                matches!(c.validate(), Err(BehavioralError::InvalidThreshold(_))),
                "threshold={bad} should fail"
            );
        }
    }

    #[test]
    fn test_config_validate_invalid_max_tools() {
        let c = BehavioralConfig {
            max_tools_per_agent: 0,
            ..Default::default()
        };
        assert!(matches!(
            c.validate(),
            Err(BehavioralError::InvalidMaxTools)
        ));
    }

    #[test]
    fn test_config_validate_invalid_max_agents() {
        let c = BehavioralConfig {
            max_agents: 0,
            ..Default::default()
        };
        assert!(matches!(
            c.validate(),
            Err(BehavioralError::InvalidMaxAgents)
        ));
    }

    // ── Cold start ────────────────────────────────

    #[test]
    fn test_no_anomaly_during_agent_cold_start() {
        let config = BehavioralConfig {
            min_sessions: 3,
            ..Default::default()
        };
        let mut tracker = BehavioralTracker::new(config).expect("valid config");

        let c = counts(&[("read_file", 5)]);
        tracker.record_session("agent-1", &c);
        tracker.record_session("agent-1", &c);
        // Only 2 sessions — below min_sessions of 3

        let high = counts(&[("read_file", 5000)]);
        let alerts = tracker.check_session("agent-1", &high);
        assert!(alerts.is_empty(), "Should not flag during cold start");
    }

    #[test]
    fn test_no_anomaly_during_tool_cold_start() {
        let config = BehavioralConfig {
            min_sessions: 3,
            threshold: 2.0,
            ..Default::default()
        };
        let mut tracker = BehavioralTracker::new(config).expect("valid config");

        // 5 sessions with tool-a, establishing agent-level history
        for _ in 0..5 {
            tracker.record_session("agent-1", &counts(&[("tool-a", 10)]));
        }

        // Now introduce tool-b for only 1 session
        tracker.record_session("agent-1", &counts(&[("tool-b", 5)]));

        // tool-b has only 1 session of history — should not alert
        let check = counts(&[("tool-b", 500)]);
        let alerts = tracker.check_session("agent-1", &check);
        assert!(
            alerts.is_empty(),
            "Tool with insufficient history should not alert"
        );
    }

    // ── Anomaly detection ─────────────────────────

    #[test]
    fn test_anomaly_after_baseline_established() {
        let config = BehavioralConfig {
            min_sessions: 3,
            threshold: 10.0,
            alpha: 0.2,
            ..Default::default()
        };
        let mut tracker = BehavioralTracker::new(config).expect("valid config");

        let normal = counts(&[("read_file", 5)]);
        for _ in 0..5 {
            tracker.record_session("agent-1", &normal);
        }

        let anomalous = counts(&[("read_file", 500)]);
        let alerts = tracker.check_session("agent-1", &anomalous);
        assert!(!alerts.is_empty(), "Should detect anomaly");
        assert_eq!(alerts[0].tool, "read_file");
        assert_eq!(alerts[0].current_count, 500);
        assert!(alerts[0].deviation_ratio >= 10.0);
    }

    #[test]
    fn test_no_anomaly_for_normal_usage() {
        let config = BehavioralConfig {
            min_sessions: 3,
            threshold: 10.0,
            alpha: 0.2,
            ..Default::default()
        };
        let mut tracker = BehavioralTracker::new(config).expect("valid config");

        let normal = counts(&[("read_file", 5)]);
        for _ in 0..5 {
            tracker.record_session("agent-1", &normal);
        }

        // 7 is ~1.4x baseline — well below 10x threshold
        let still_normal = counts(&[("read_file", 7)]);
        let alerts = tracker.check_session("agent-1", &still_normal);
        assert!(
            alerts.is_empty(),
            "Normal variation should not trigger alert"
        );
    }

    #[test]
    fn test_new_tool_no_alert() {
        let config = BehavioralConfig {
            min_sessions: 3,
            ..Default::default()
        };
        let mut tracker = BehavioralTracker::new(config).expect("valid config");

        let normal = counts(&[("read_file", 5)]);
        for _ in 0..5 {
            tracker.record_session("agent-1", &normal);
        }

        // write_file never seen — no baseline, no alert
        let new_tool = counts(&[("write_file", 1000)]);
        let alerts = tracker.check_session("agent-1", &new_tool);
        assert!(
            alerts.is_empty(),
            "New tool with no baseline should not alert"
        );
    }

    // ── Severity ──────────────────────────────────

    #[test]
    fn test_critical_severity() {
        let config = BehavioralConfig {
            min_sessions: 3,
            threshold: 5.0,
            alpha: 0.5,
            ..Default::default()
        };
        let mut tracker = BehavioralTracker::new(config).expect("valid config");

        let normal = counts(&[("read_file", 10)]);
        for _ in 0..5 {
            tracker.record_session("agent-1", &normal);
        }

        // With alpha=0.5 over 5 sessions of count=10, EMA ≈ 10.0
        // 1000 / 10 = 100x → well above 2 * threshold(5) = 10x → Critical
        let critical = counts(&[("read_file", 1000)]);
        let alerts = tracker.check_session("agent-1", &critical);
        assert!(!alerts.is_empty());
        assert_eq!(alerts[0].severity, AnomalySeverity::Critical);
    }

    #[test]
    fn test_warning_severity() {
        let config = BehavioralConfig {
            min_sessions: 3,
            threshold: 5.0,
            alpha: 0.5,
            ..Default::default()
        };
        let mut tracker = BehavioralTracker::new(config).expect("valid config");

        let normal = counts(&[("read_file", 10)]);
        for _ in 0..5 {
            tracker.record_session("agent-1", &normal);
        }

        // 60 / 10 = 6x → above threshold(5) but below 2*threshold(10) → Warning
        let warning = counts(&[("read_file", 60)]);
        let alerts = tracker.check_session("agent-1", &warning);
        assert!(!alerts.is_empty());
        assert_eq!(alerts[0].severity, AnomalySeverity::Warning);
    }

    // ── EMA behavior ──────────────────────────────

    #[test]
    fn test_ema_first_observation_initializes() {
        let config = BehavioralConfig {
            min_sessions: 1,
            ..Default::default()
        };
        let mut tracker = BehavioralTracker::new(config).expect("valid config");

        tracker.record_session("agent-1", &counts(&[("read_file", 42)]));

        let baseline = tracker
            .get_baseline("agent-1", "read_file")
            .expect("baseline should exist");
        assert!(
            (baseline.ema - 42.0).abs() < f64::EPSILON,
            "First observation should set EMA directly"
        );
        assert_eq!(baseline.session_count, 1);
    }

    #[test]
    fn test_ema_update_formula() {
        let config = BehavioralConfig {
            min_sessions: 1,
            alpha: 0.5,
            ..Default::default()
        };
        let mut tracker = BehavioralTracker::new(config).expect("valid config");

        // Session 1: EMA = 100
        tracker.record_session("agent-1", &counts(&[("tool", 100)]));
        let ema1 = tracker.get_baseline("agent-1", "tool").expect("exists").ema;
        assert!((ema1 - 100.0).abs() < f64::EPSILON);

        // Session 2: EMA = 0.5 * 200 + 0.5 * 100 = 150
        tracker.record_session("agent-1", &counts(&[("tool", 200)]));
        let ema2 = tracker.get_baseline("agent-1", "tool").expect("exists").ema;
        assert!((ema2 - 150.0).abs() < f64::EPSILON);

        // Session 3: EMA = 0.5 * 100 + 0.5 * 150 = 125
        tracker.record_session("agent-1", &counts(&[("tool", 100)]));
        let ema3 = tracker.get_baseline("agent-1", "tool").expect("exists").ema;
        assert!((ema3 - 125.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_ema_decay_unused_tools() {
        let config = BehavioralConfig {
            min_sessions: 1,
            alpha: 0.5,
            ..Default::default()
        };
        let mut tracker = BehavioralTracker::new(config).expect("valid config");

        // Establish baseline
        tracker.record_session("agent-1", &counts(&[("read_file", 100)]));
        assert!(
            (tracker
                .get_baseline("agent-1", "read_file")
                .expect("exists")
                .ema
                - 100.0)
                .abs()
                < f64::EPSILON
        );

        // Session without read_file — EMA should decay
        tracker.record_session("agent-1", &counts(&[("other_tool", 1)]));
        let ema = tracker
            .get_baseline("agent-1", "read_file")
            .expect("exists")
            .ema;
        // Decay: ema = (1 - 0.5) * 100 = 50
        assert!(
            (ema - 50.0).abs() < 0.01,
            "EMA should decay to 50.0, got {ema}"
        );
    }

    #[test]
    fn test_ema_decay_does_not_update_last_active() {
        let config = BehavioralConfig {
            min_sessions: 1,
            alpha: 0.5,
            ..Default::default()
        };
        let mut tracker = BehavioralTracker::new(config).expect("valid config");

        tracker.record_session("agent-1", &counts(&[("read_file", 100)]));
        let active_before = tracker
            .get_baseline("agent-1", "read_file")
            .expect("exists")
            .last_active;

        // Decay-only session
        tracker.record_session("agent-1", &counts(&[("other_tool", 1)]));
        let active_after = tracker
            .get_baseline("agent-1", "read_file")
            .expect("exists")
            .last_active;

        assert_eq!(
            active_before, active_after,
            "Passive decay should not update last_active"
        );
    }

    // ── Agent/tool isolation ──────────────────────

    #[test]
    fn test_multiple_agents_independent() {
        let config = BehavioralConfig {
            min_sessions: 3,
            threshold: 10.0,
            alpha: 0.2,
            ..Default::default()
        };
        let mut tracker = BehavioralTracker::new(config).expect("valid config");

        // Agent-1: low baseline (~5)
        let low = counts(&[("read_file", 5)]);
        for _ in 0..5 {
            tracker.record_session("agent-1", &low);
        }

        // Agent-2: high baseline (~500)
        let high = counts(&[("read_file", 500)]);
        for _ in 0..5 {
            tracker.record_session("agent-2", &high);
        }

        // 50 calls: anomalous for agent-1, normal for agent-2
        let check = counts(&[("read_file", 50)]);
        let alerts_1 = tracker.check_session("agent-1", &check);
        assert!(!alerts_1.is_empty(), "50 should be anomalous for agent-1");

        let alerts_2 = tracker.check_session("agent-2", &check);
        assert!(alerts_2.is_empty(), "50 should be normal for agent-2");
    }

    #[test]
    fn test_unknown_agent_no_alerts() {
        let tracker = BehavioralTracker::new(BehavioralConfig::default()).expect("valid config");
        let alerts = tracker.check_session("unknown", &counts(&[("tool", 1000)]));
        assert!(alerts.is_empty());
    }

    // ── Eviction ──────────────────────────────────

    #[test]
    fn test_agent_eviction_by_session_count() {
        let config = BehavioralConfig {
            max_agents: 2,
            ..Default::default()
        };
        let mut tracker = BehavioralTracker::new(config).expect("valid config");

        let c = counts(&[("tool", 1)]);
        tracker.record_session("agent-1", &c);
        tracker.record_session("agent-2", &c);
        tracker.record_session("agent-2", &c); // agent-2 has more sessions

        // Adding agent-3 should evict agent-1 (fewest sessions)
        tracker.record_session("agent-3", &c);

        assert_eq!(tracker.agent_count(), 2);
        assert!(
            tracker.get_baseline("agent-1", "tool").is_none(),
            "agent-1 should be evicted"
        );
        assert!(tracker.get_baseline("agent-2", "tool").is_some());
        assert!(tracker.get_baseline("agent-3", "tool").is_some());
    }

    #[test]
    fn test_tool_eviction_by_last_active() {
        let config = BehavioralConfig {
            max_tools_per_agent: 2,
            ..Default::default()
        };
        let mut tracker = BehavioralTracker::new(config).expect("valid config");

        // Record tool-a first (update_counter=1)
        tracker.record_session("agent-1", &counts(&[("tool-a", 1)]));
        // Record tool-b second (update_counter=2)
        tracker.record_session("agent-1", &counts(&[("tool-b", 1)]));

        // Adding tool-c should evict tool-a (oldest last_active)
        tracker.record_session("agent-1", &counts(&[("tool-c", 1)]));

        assert_eq!(tracker.tool_count("agent-1"), 2);
        assert!(
            tracker.get_baseline("agent-1", "tool-a").is_none(),
            "tool-a should be evicted"
        );
    }

    // ── Zero/empty handling ───────────────────────

    #[test]
    fn test_zero_counts_not_recorded() {
        let config = BehavioralConfig {
            min_sessions: 1,
            ..Default::default()
        };
        let mut tracker = BehavioralTracker::new(config).expect("valid config");

        tracker.record_session("agent-1", &counts(&[("read_file", 0)]));
        assert!(
            tracker.get_baseline("agent-1", "read_file").is_none(),
            "Zero-count tool should not create a baseline"
        );
    }

    #[test]
    fn test_empty_call_counts_no_panic() {
        let mut tracker =
            BehavioralTracker::new(BehavioralConfig::default()).expect("valid config");
        let empty = HashMap::new();
        tracker.record_session("agent-1", &empty);
        let alerts = tracker.check_session("agent-1", &empty);
        assert!(alerts.is_empty());
    }

    #[test]
    fn test_check_with_zero_count_skipped() {
        let config = BehavioralConfig {
            min_sessions: 1,
            threshold: 2.0,
            ..Default::default()
        };
        let mut tracker = BehavioralTracker::new(config).expect("valid config");

        let c = counts(&[("tool", 10)]);
        for _ in 0..3 {
            tracker.record_session("agent-1", &c);
        }

        // Zero-count entry should be skipped in check
        let zero = counts(&[("tool", 0)]);
        let alerts = tracker.check_session("agent-1", &zero);
        assert!(alerts.is_empty());
    }

    // ── Snapshot persistence ──────────────────────

    #[test]
    fn test_snapshot_roundtrip() {
        let config = BehavioralConfig {
            min_sessions: 2,
            ..Default::default()
        };
        let mut tracker = BehavioralTracker::new(config.clone()).expect("valid config");

        let c = counts(&[("read_file", 10), ("write_file", 3)]);
        tracker.record_session("agent-1", &c);
        tracker.record_session("agent-1", &c);

        let snapshot = tracker.snapshot();

        // Serialize and deserialize (simulating persistence)
        let json = serde_json::to_string(&snapshot).expect("serialize");
        let restored_snap: BehavioralSnapshot = serde_json::from_str(&json).expect("deserialize");

        let restored =
            BehavioralTracker::from_snapshot(config, restored_snap).expect("valid snapshot");
        assert_eq!(restored.agent_count(), 1);
        assert_eq!(restored.agent_sessions("agent-1"), Some(2));
        assert!(restored.get_baseline("agent-1", "read_file").is_some());
        assert!(restored.get_baseline("agent-1", "write_file").is_some());
    }

    #[test]
    fn test_snapshot_rejects_nan_ema() {
        let config = BehavioralConfig::default();
        let mut tools = HashMap::new();
        tools.insert(
            "bad_tool".to_string(),
            ToolBaseline {
                ema: f64::NAN,
                session_count: 1,
                last_active: 0,
            },
        );
        let mut agents = HashMap::new();
        agents.insert(
            "agent-1".to_string(),
            AgentSnapshotEntry {
                tools,
                total_sessions: 1,
            },
        );
        let snapshot = BehavioralSnapshot {
            agents,
            update_counter: 0,
        };

        assert!(matches!(
            BehavioralTracker::from_snapshot(config, snapshot),
            Err(BehavioralError::InvalidSnapshot(_))
        ));
    }

    #[test]
    fn test_snapshot_rejects_negative_ema() {
        let config = BehavioralConfig::default();
        let mut tools = HashMap::new();
        tools.insert(
            "bad_tool".to_string(),
            ToolBaseline {
                ema: -1.0,
                session_count: 1,
                last_active: 0,
            },
        );
        let mut agents = HashMap::new();
        agents.insert(
            "agent-1".to_string(),
            AgentSnapshotEntry {
                tools,
                total_sessions: 1,
            },
        );
        let snapshot = BehavioralSnapshot {
            agents,
            update_counter: 0,
        };

        assert!(matches!(
            BehavioralTracker::from_snapshot(config, snapshot),
            Err(BehavioralError::InvalidSnapshot(_))
        ));
    }

    #[test]
    fn test_snapshot_rejects_infinite_ema() {
        let config = BehavioralConfig::default();
        let mut tools = HashMap::new();
        tools.insert(
            "bad_tool".to_string(),
            ToolBaseline {
                ema: f64::INFINITY,
                session_count: 1,
                last_active: 0,
            },
        );
        let mut agents = HashMap::new();
        agents.insert(
            "agent-1".to_string(),
            AgentSnapshotEntry {
                tools,
                total_sessions: 1,
            },
        );
        let snapshot = BehavioralSnapshot {
            agents,
            update_counter: 0,
        };

        assert!(matches!(
            BehavioralTracker::from_snapshot(config, snapshot),
            Err(BehavioralError::InvalidSnapshot(_))
        ));
    }

    // ── GAP-012: Persistence Integration Tests ────

    /// GAP-012: Multi-agent snapshot roundtrip ensures all agents and their
    /// tools are correctly persisted and restored.
    #[test]
    fn test_snapshot_multi_agent_roundtrip() {
        let config = BehavioralConfig {
            min_sessions: 2,
            ..Default::default()
        };
        let mut tracker = BehavioralTracker::new(config.clone()).expect("valid config");

        // Record sessions for multiple agents with different tool patterns
        let agent1_tools = counts(&[("read_file", 10), ("write_file", 3)]);
        let agent2_tools = counts(&[("list_dir", 50), ("delete_file", 2), ("chmod", 5)]);
        let agent3_tools = counts(&[("network_call", 100)]);

        for _ in 0..3 {
            tracker.record_session("agent-1", &agent1_tools);
            tracker.record_session("agent-2", &agent2_tools);
            tracker.record_session("agent-3", &agent3_tools);
        }

        let snapshot = tracker.snapshot();

        // Persist and restore
        let json = serde_json::to_string(&snapshot).expect("serialize");
        let restored_snap: BehavioralSnapshot = serde_json::from_str(&json).expect("deserialize");
        let restored =
            BehavioralTracker::from_snapshot(config, restored_snap).expect("valid snapshot");

        // Verify all agents restored
        assert_eq!(restored.agent_count(), 3);
        assert_eq!(restored.agent_sessions("agent-1"), Some(3));
        assert_eq!(restored.agent_sessions("agent-2"), Some(3));
        assert_eq!(restored.agent_sessions("agent-3"), Some(3));

        // Verify tool counts
        assert_eq!(restored.tool_count("agent-1"), 2);
        assert_eq!(restored.tool_count("agent-2"), 3);
        assert_eq!(restored.tool_count("agent-3"), 1);

        // Verify specific baselines exist
        assert!(restored.get_baseline("agent-1", "read_file").is_some());
        assert!(restored.get_baseline("agent-2", "list_dir").is_some());
        assert!(restored.get_baseline("agent-3", "network_call").is_some());
    }

    /// GAP-012: Restored tracker produces identical anomaly detection results
    /// as the original tracker.
    #[test]
    fn test_snapshot_restored_produces_same_alerts() {
        let config = BehavioralConfig {
            min_sessions: 3,
            threshold: 10.0,
            alpha: 0.3,
            ..Default::default()
        };
        let mut tracker = BehavioralTracker::new(config.clone()).expect("valid config");

        // Build up baseline
        let normal = counts(&[("tool_a", 10), ("tool_b", 20)]);
        for _ in 0..5 {
            tracker.record_session("agent-1", &normal);
        }

        // Create anomalous input
        let anomalous = counts(&[("tool_a", 500), ("tool_b", 20)]);

        // Check alerts on original
        let original_alerts = tracker.check_session("agent-1", &anomalous);

        // Snapshot and restore
        let snapshot = tracker.snapshot();
        let json = serde_json::to_string(&snapshot).expect("serialize");
        let restored_snap: BehavioralSnapshot = serde_json::from_str(&json).expect("deserialize");
        let restored =
            BehavioralTracker::from_snapshot(config, restored_snap).expect("valid snapshot");

        // Check alerts on restored tracker
        let restored_alerts = restored.check_session("agent-1", &anomalous);

        // Should produce identical alerts
        assert_eq!(original_alerts.len(), restored_alerts.len());
        for (orig, rest) in original_alerts.iter().zip(restored_alerts.iter()) {
            assert_eq!(orig.agent_id, rest.agent_id);
            assert_eq!(orig.tool, rest.tool);
            assert_eq!(orig.current_count, rest.current_count);
            // EMA values should be identical
            assert!(
                (orig.baseline_ema - rest.baseline_ema).abs() < f64::EPSILON,
                "EMA mismatch: {} vs {}",
                orig.baseline_ema,
                rest.baseline_ema
            );
        }
    }

    /// GAP-012: Large-scale snapshot handles many agents and tools efficiently.
    #[test]
    fn test_snapshot_large_scale() {
        let config = BehavioralConfig {
            min_sessions: 1,
            max_agents: 100,
            max_tools_per_agent: 50,
            ..Default::default()
        };
        let mut tracker = BehavioralTracker::new(config.clone()).expect("valid config");

        // Create 50 agents, each with 20 tools
        for agent_id in 0..50 {
            let tools: HashMap<String, u64> = (0..20)
                .map(|tool_id| (format!("tool_{tool_id}"), (agent_id + tool_id + 1) as u64))
                .collect();
            for _ in 0..3 {
                tracker.record_session(&format!("agent-{agent_id}"), &tools);
            }
        }

        let snapshot = tracker.snapshot();

        // Verify snapshot size is reasonable
        let json = serde_json::to_string(&snapshot).expect("serialize");
        assert!(
            json.len() > 1000,
            "Snapshot should contain substantial data"
        );
        assert!(
            json.len() < 1_000_000,
            "Snapshot should be reasonably sized"
        );

        // Restore and verify counts
        let restored_snap: BehavioralSnapshot = serde_json::from_str(&json).expect("deserialize");
        let restored =
            BehavioralTracker::from_snapshot(config, restored_snap).expect("valid snapshot");

        assert_eq!(restored.agent_count(), 50);
        assert_eq!(restored.tool_count("agent-0"), 20);
        assert_eq!(restored.agent_sessions("agent-49"), Some(3));
    }

    /// GAP-012: Update counter is preserved through persistence roundtrip.
    #[test]
    fn test_snapshot_preserves_update_counter() {
        let config = BehavioralConfig::default();
        let mut tracker = BehavioralTracker::new(config.clone()).expect("valid config");

        // Record many sessions to increment update counter
        for i in 0..10 {
            tracker.record_session(&format!("agent-{}", i % 3), &counts(&[("tool", 5)]));
        }

        let snapshot = tracker.snapshot();
        let original_counter = snapshot.update_counter;
        assert!(original_counter >= 10, "Counter should track updates");

        // Roundtrip
        let json = serde_json::to_string(&snapshot).expect("serialize");
        let restored_snap: BehavioralSnapshot = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(
            restored_snap.update_counter, original_counter,
            "Update counter must survive roundtrip"
        );

        let restored =
            BehavioralTracker::from_snapshot(config, restored_snap).expect("valid snapshot");
        let new_snapshot = restored.snapshot();
        assert_eq!(
            new_snapshot.update_counter, original_counter,
            "Restored tracker preserves counter value"
        );
    }

    // ── Accessors ─────────────────────────────────

    #[test]
    fn test_agent_sessions_none_for_unknown() {
        let tracker = BehavioralTracker::new(BehavioralConfig::default()).expect("valid config");
        assert_eq!(tracker.agent_sessions("nonexistent"), None);
    }

    #[test]
    fn test_tool_count_zero_for_unknown() {
        let tracker = BehavioralTracker::new(BehavioralConfig::default()).expect("valid config");
        assert_eq!(tracker.tool_count("nonexistent"), 0);
    }

    #[test]
    fn test_config_accessor() {
        let config = BehavioralConfig {
            alpha: 0.3,
            threshold: 8.0,
            ..Default::default()
        };
        let tracker = BehavioralTracker::new(config).expect("valid config");
        assert!((tracker.config().alpha - 0.3).abs() < f64::EPSILON);
        assert!((tracker.config().threshold - 8.0).abs() < f64::EPSILON);
    }

    // ── Display ───────────────────────────────────

    #[test]
    fn test_anomaly_alert_display() {
        let alert = AnomalyAlert {
            agent_id: "agent-1".to_string(),
            tool: "read_file".to_string(),
            current_count: 500,
            baseline_ema: 5.0,
            deviation_ratio: 100.0,
            severity: AnomalySeverity::Critical,
        };
        let display = format!("{alert}");
        assert!(display.contains("Critical"));
        assert!(display.contains("agent-1"));
        assert!(display.contains("read_file"));
        assert!(display.contains("500"));
    }

    #[test]
    fn test_behavioral_error_display() {
        let e = BehavioralError::InvalidAlpha(0.0);
        assert!(format!("{e}").contains("alpha"));
        let e = BehavioralError::InvalidThreshold(-1.0);
        assert!(format!("{e}").contains("threshold"));
        let e = BehavioralError::InvalidMaxTools;
        assert!(format!("{e}").contains("max_tools"));
        let e = BehavioralError::InvalidMaxAgents;
        assert!(format!("{e}").contains("max_agents"));
        let e = BehavioralError::InvalidSnapshot("test".to_string());
        assert!(format!("{e}").contains("test"));
    }

    // ── Saturating arithmetic ─────────────────────

    #[test]
    fn test_saturating_session_count() {
        let config = BehavioralConfig {
            min_sessions: 1,
            ..Default::default()
        };
        let mut tracker = BehavioralTracker::new(config).expect("valid config");

        let c = counts(&[("tool", 1)]);
        for _ in 0..100 {
            tracker.record_session("agent-1", &c);
        }
        assert_eq!(tracker.agent_sessions("agent-1"), Some(100));
    }

    // ── Multiple tools in one session ─────────────

    #[test]
    fn test_multiple_tools_single_session() {
        let config = BehavioralConfig {
            min_sessions: 3,
            threshold: 10.0,
            alpha: 0.5,
            ..Default::default()
        };
        let mut tracker = BehavioralTracker::new(config).expect("valid config");

        let normal = counts(&[("read_file", 5), ("write_file", 2), ("list_dir", 10)]);
        for _ in 0..5 {
            tracker.record_session("agent-1", &normal);
        }

        // read_file anomalous, write_file normal, list_dir normal
        let mixed = counts(&[("read_file", 500), ("write_file", 3), ("list_dir", 12)]);
        let alerts = tracker.check_session("agent-1", &mixed);
        assert_eq!(alerts.len(), 1, "Only read_file should trigger");
        assert_eq!(alerts[0].tool, "read_file");
    }

    // ── Gradual increase adapts baseline ──────────

    #[test]
    fn test_gradual_increase_adapts() {
        let config = BehavioralConfig {
            min_sessions: 3,
            threshold: 5.0,
            alpha: 0.5,
            ..Default::default()
        };
        let mut tracker = BehavioralTracker::new(config).expect("valid config");

        // Start with baseline of 10
        for _ in 0..3 {
            tracker.record_session("agent-1", &counts(&[("tool", 10)]));
        }

        // Gradually increase — EMA adapts, so 20 shouldn't alert after adaptation
        for _ in 0..10 {
            tracker.record_session("agent-1", &counts(&[("tool", 20)]));
        }

        // After many sessions at 20, EMA is close to 20. 20 should not alert.
        let alerts = tracker.check_session("agent-1", &counts(&[("tool", 20)]));
        assert!(
            alerts.is_empty(),
            "Gradual increase should adapt the baseline"
        );
    }

    // ════════════════════════════════════════════════════════
    // FIND-052: EMA epsilon and extreme numeric edge cases
    // ════════════════════════════════════════════════════════

    #[test]
    fn test_behavioral_epsilon_ema_triggers_anomaly() {
        // When EMA is at or below f64::EPSILON, any non-zero count should
        // use the synthetic high-deviation path (line 306-307)
        let config = BehavioralConfig {
            min_sessions: 1,
            threshold: 2.0,
            alpha: 0.99, // High alpha — EMA will closely track current value
            ..Default::default()
        };
        let mut tracker = BehavioralTracker::new(config).expect("valid config");

        // Record very small values to get EMA close to zero,
        // then decay further by recording sessions without the tool
        tracker.record_session("agent-1", &counts(&[("tool", 1)]));
        // Decay the tool's EMA by running many sessions without it
        for _ in 0..100 {
            tracker.record_session("agent-1", &counts(&[("other", 1)]));
        }

        let baseline = tracker
            .get_baseline("agent-1", "tool")
            .expect("baseline should exist");
        // After 100 decay rounds with alpha=0.99, EMA should be extremely small
        assert!(
            baseline.ema < 0.01,
            "EMA should have decayed to near zero, got: {}",
            baseline.ema
        );

        // Now check: with near-zero EMA, the epsilon guard uses count as the ratio.
        // A count >= threshold should trigger anomaly.
        let alerts = tracker.check_session("agent-1", &counts(&[("tool", 3)]));
        // The tool has enough sessions and the agent has enough sessions
        // so the cold start guard won't block this.
        // ratio = count as f64 = 3.0 >= threshold(2.0)
        assert!(
            !alerts.is_empty(),
            "Near-zero EMA with count >= threshold should flag as anomalous"
        );
    }

    #[test]
    fn test_behavioral_u64_max_count_does_not_panic() {
        let config = BehavioralConfig {
            min_sessions: 1,
            threshold: 2.0,
            alpha: 0.5,
            ..Default::default()
        };
        let mut tracker = BehavioralTracker::new(config).expect("valid config");

        // Establish baseline
        let normal = counts(&[("tool", 10)]);
        for _ in 0..3 {
            tracker.record_session("agent-1", &normal);
        }

        // Check session with u64::MAX — should not panic
        let extreme = counts(&[("tool", u64::MAX)]);
        let alerts = tracker.check_session("agent-1", &extreme);
        // Should definitely detect anomaly
        assert!(!alerts.is_empty(), "u64::MAX count should trigger anomaly");

        // Recording u64::MAX should also not panic
        tracker.record_session("agent-1", &extreme);
        let baseline = tracker
            .get_baseline("agent-1", "tool")
            .expect("baseline exists");
        assert!(
            baseline.ema.is_finite(),
            "EMA should remain finite after u64::MAX, got: {}",
            baseline.ema
        );
    }

    #[test]
    fn test_behavioral_large_ema_large_count_no_overflow() {
        let config = BehavioralConfig {
            min_sessions: 1,
            threshold: 2.0,
            alpha: 0.5,
            ..Default::default()
        };
        let mut tracker = BehavioralTracker::new(config).expect("valid config");

        // Record sessions with very large counts
        let large = counts(&[("tool", u64::MAX / 2)]);
        for _ in 0..5 {
            tracker.record_session("agent-1", &large);
        }

        let baseline = tracker
            .get_baseline("agent-1", "tool")
            .expect("baseline exists");
        assert!(
            baseline.ema.is_finite(),
            "EMA should remain finite with large counts"
        );

        // Check with even larger count
        let larger = counts(&[("tool", u64::MAX)]);
        let alerts = tracker.check_session("agent-1", &larger);
        // With EMA ~ u64::MAX/2 and count ~ u64::MAX, ratio ~ 2.0 >= threshold(2.0)
        assert!(!alerts.is_empty(), "u64::MAX vs large EMA should trigger");
        // Verify ratio is finite
        assert!(
            alerts[0].deviation_ratio.is_finite(),
            "Deviation ratio should be finite, got: {}",
            alerts[0].deviation_ratio
        );
    }

    #[test]
    fn test_behavioral_update_counter_saturates() {
        let config = BehavioralConfig {
            min_sessions: 1,
            ..Default::default()
        };
        let mut tracker = BehavioralTracker::new(config).expect("valid config");

        // Record many sessions — update_counter uses saturating_add
        for i in 0..100 {
            tracker.record_session(&format!("agent-{}", i % 5), &counts(&[("tool", 1)]));
        }

        let snapshot = tracker.snapshot();
        assert_eq!(
            snapshot.update_counter, 100,
            "Update counter should track session count"
        );
    }

    // ════════════════════════════════════════════════════════
    // FIND-R114-001: absolute_ceiling=0 must not produce Infinity
    // ════════════════════════════════════════════════════════

    #[test]
    fn test_absolute_ceiling_zero_does_not_produce_infinity() {
        let config = BehavioralConfig {
            min_sessions: 1,
            absolute_ceiling: Some(0),
            ..Default::default()
        };
        let mut tracker = BehavioralTracker::new(config).expect("valid config");

        // Establish some baseline
        let normal = counts(&[("tool", 5)]);
        for _ in 0..3 {
            tracker.record_session("agent-1", &normal);
        }

        // Any non-zero count exceeds ceiling=0
        let check = counts(&[("tool", 1)]);
        let alerts = tracker.check_session("agent-1", &check);
        assert!(!alerts.is_empty(), "count > 0 should exceed ceiling of 0");
        assert_eq!(alerts[0].severity, AnomalySeverity::Critical);
        // The critical check: deviation_ratio must be finite (not Infinity)
        assert!(
            alerts[0].deviation_ratio.is_finite(),
            "deviation_ratio must be finite when ceiling=0, got: {}",
            alerts[0].deviation_ratio
        );
        assert!(
            alerts[0].deviation_ratio > 0.0,
            "deviation_ratio should be positive"
        );
    }

    // ════════════════════════════════════════════════════════
    // FIND-R114-002: from_snapshot rejects control/format chars in keys
    // ════════════════════════════════════════════════════════

    #[test]
    fn test_from_snapshot_rejects_control_char_agent_id() {
        let config = BehavioralConfig::default();
        let mut agents = HashMap::new();
        agents.insert(
            "agent\x01bad".to_string(),
            AgentSnapshotEntry {
                tools: HashMap::new(),
                total_sessions: 1,
            },
        );
        let snapshot = BehavioralSnapshot {
            agents,
            update_counter: 0,
        };
        let result = BehavioralTracker::from_snapshot(config, snapshot);
        assert!(
            matches!(result, Err(BehavioralError::InvalidSnapshot(_))),
            "expected InvalidSnapshot for control char agent_id"
        );
    }

    #[test]
    fn test_from_snapshot_rejects_unicode_format_char_agent_id() {
        let config = BehavioralConfig::default();
        let mut agents = HashMap::new();
        // Zero-width space in agent ID
        agents.insert(
            "agent\u{200B}id".to_string(),
            AgentSnapshotEntry {
                tools: HashMap::new(),
                total_sessions: 1,
            },
        );
        let snapshot = BehavioralSnapshot {
            agents,
            update_counter: 0,
        };
        let result = BehavioralTracker::from_snapshot(config, snapshot);
        assert!(
            matches!(result, Err(BehavioralError::InvalidSnapshot(_))),
            "expected InvalidSnapshot for Unicode format char agent_id"
        );
    }

    #[test]
    fn test_from_snapshot_rejects_control_char_tool_key() {
        let config = BehavioralConfig::default();
        let mut tools = HashMap::new();
        tools.insert(
            "tool\nnewline".to_string(),
            ToolBaseline {
                ema: 5.0,
                session_count: 1,
                last_active: 0,
            },
        );
        let mut agents = HashMap::new();
        agents.insert(
            "agent-1".to_string(),
            AgentSnapshotEntry {
                tools,
                total_sessions: 1,
            },
        );
        let snapshot = BehavioralSnapshot {
            agents,
            update_counter: 0,
        };
        let result = BehavioralTracker::from_snapshot(config, snapshot);
        assert!(
            matches!(result, Err(BehavioralError::InvalidSnapshot(_))),
            "expected InvalidSnapshot for control char tool key"
        );
    }

    #[test]
    fn test_from_snapshot_rejects_bidi_override_tool_key() {
        let config = BehavioralConfig::default();
        let mut tools = HashMap::new();
        // Right-to-left override in tool name
        tools.insert(
            "tool\u{202E}malicious".to_string(),
            ToolBaseline {
                ema: 5.0,
                session_count: 1,
                last_active: 0,
            },
        );
        let mut agents = HashMap::new();
        agents.insert(
            "agent-1".to_string(),
            AgentSnapshotEntry {
                tools,
                total_sessions: 1,
            },
        );
        let snapshot = BehavioralSnapshot {
            agents,
            update_counter: 0,
        };
        let result = BehavioralTracker::from_snapshot(config, snapshot);
        assert!(
            matches!(result, Err(BehavioralError::InvalidSnapshot(_))),
            "expected InvalidSnapshot for bidi override tool key"
        );
    }

    #[test]
    fn test_from_snapshot_accepts_clean_keys() {
        let config = BehavioralConfig::default();
        let mut tools = HashMap::new();
        tools.insert(
            "read_file".to_string(),
            ToolBaseline {
                ema: 5.0,
                session_count: 1,
                last_active: 0,
            },
        );
        let mut agents = HashMap::new();
        agents.insert(
            "agent-1".to_string(),
            AgentSnapshotEntry {
                tools,
                total_sessions: 1,
            },
        );
        let snapshot = BehavioralSnapshot {
            agents,
            update_counter: 0,
        };
        assert!(BehavioralTracker::from_snapshot(config, snapshot).is_ok());
    }

    // ── FIND-R139: Live-path validation tests ──────────

    #[test]
    fn test_record_session_rejects_oversized_agent_id() {
        let mut tracker = BehavioralTracker::new(BehavioralConfig::default()).unwrap();
        let long_id = "a".repeat(513);
        let counts: HashMap<String, u64> = [("tool1".to_string(), 5u64)].into_iter().collect();
        tracker.record_session(&long_id, &counts);
        assert!(
            tracker.agents.is_empty(),
            "oversized agent_id should be rejected"
        );
    }

    #[test]
    fn test_record_session_rejects_control_char_agent_id() {
        let mut tracker = BehavioralTracker::new(BehavioralConfig::default()).unwrap();
        let counts: HashMap<String, u64> = [("tool1".to_string(), 5u64)].into_iter().collect();
        tracker.record_session("agent\x1b[31m", &counts);
        assert!(
            tracker.agents.is_empty(),
            "control-char agent_id should be rejected"
        );
    }

    #[test]
    fn test_check_session_rejects_oversized_call_counts() {
        let tracker = BehavioralTracker::new(BehavioralConfig::default()).unwrap();
        let mut counts: HashMap<String, u64> = HashMap::new();
        for i in 0..10_001 {
            counts.insert(format!("tool_{i}"), 1);
        }
        let alerts = tracker.check_session("agent-1", &counts);
        assert!(
            alerts.is_empty(),
            "oversized call_counts should be rejected with empty alerts"
        );
    }

    #[test]
    fn test_ema_non_finite_clamp() {
        let mut tracker = BehavioralTracker::new(BehavioralConfig {
            alpha: 0.5,
            ..BehavioralConfig::default()
        })
        .unwrap();
        let agent_id = "agent-ema-test";
        // First session to establish baseline
        let counts: HashMap<String, u64> = [("tool1".to_string(), u64::MAX)].into_iter().collect();
        tracker.record_session(agent_id, &counts);
        let agent = tracker.agents.get(agent_id).unwrap();
        let ema = agent.tools.get("tool1").unwrap().ema;
        assert!(
            ema.is_finite(),
            "EMA should remain finite even with u64::MAX count"
        );
    }

    // ═══════════════════════════════════════════════════
    // FIND-R116-TE-003: Tool key validation in record_session / check_session
    // ═══════════════════════════════════════════════════

    #[test]
    fn test_record_session_skips_oversized_tool_key() {
        let mut tracker = BehavioralTracker::new(BehavioralConfig::default()).unwrap();
        let long_tool = "a".repeat(257); // exceeds MAX_TOOL_KEY_LEN = 256
        let c: HashMap<String, u64> = [(long_tool.clone(), 5u64)].into_iter().collect();
        tracker.record_session("agent-1", &c);
        // The oversized tool key should have been skipped
        assert!(
            tracker.get_baseline("agent-1", &long_tool).is_none(),
            "oversized tool key should not be recorded"
        );
    }

    #[test]
    fn test_record_session_skips_control_char_tool_key() {
        let mut tracker = BehavioralTracker::new(BehavioralConfig::default()).unwrap();
        let bad_tool = "tool\nnewline".to_string();
        let c: HashMap<String, u64> = [(bad_tool.clone(), 5u64)].into_iter().collect();
        tracker.record_session("agent-1", &c);
        assert!(
            tracker.get_baseline("agent-1", &bad_tool).is_none(),
            "control char tool key should not be recorded"
        );
    }

    #[test]
    fn test_record_session_skips_unicode_format_char_tool_key() {
        let mut tracker = BehavioralTracker::new(BehavioralConfig::default()).unwrap();
        // Zero-width space in tool name
        let bad_tool = "tool\u{200B}name".to_string();
        let c: HashMap<String, u64> = [(bad_tool.clone(), 5u64)].into_iter().collect();
        tracker.record_session("agent-1", &c);
        assert!(
            tracker.get_baseline("agent-1", &bad_tool).is_none(),
            "Unicode format char tool key should not be recorded"
        );
    }

    #[test]
    fn test_record_session_accepts_valid_tool_key_alongside_invalid() {
        let mut tracker = BehavioralTracker::new(BehavioralConfig::default()).unwrap();
        let mut c = HashMap::new();
        c.insert("valid_tool".to_string(), 5u64);
        c.insert("bad\x01tool".to_string(), 10u64);
        tracker.record_session("agent-1", &c);
        // Valid tool should be recorded, invalid should be skipped
        assert!(
            tracker.get_baseline("agent-1", "valid_tool").is_some(),
            "valid tool key should be recorded"
        );
        assert!(
            tracker.get_baseline("agent-1", "bad\x01tool").is_none(),
            "invalid tool key should not be recorded"
        );
    }

    #[test]
    fn test_record_session_tool_key_at_max_len_accepted() {
        let mut tracker = BehavioralTracker::new(BehavioralConfig::default()).unwrap();
        let tool_at_limit = "a".repeat(256); // exactly at MAX_TOOL_KEY_LEN
        let c: HashMap<String, u64> = [(tool_at_limit.clone(), 5u64)].into_iter().collect();
        tracker.record_session("agent-1", &c);
        assert!(
            tracker.get_baseline("agent-1", &tool_at_limit).is_some(),
            "tool key at exactly MAX_TOOL_KEY_LEN should be accepted"
        );
    }

    #[test]
    fn test_check_session_skips_oversized_tool_key() {
        let config = BehavioralConfig {
            min_sessions: 1,
            threshold: 2.0,
            ..Default::default()
        };
        let mut tracker = BehavioralTracker::new(config).unwrap();

        // Build baseline with a valid tool
        let normal = counts(&[("valid_tool", 5)]);
        for _ in 0..3 {
            tracker.record_session("agent-1", &normal);
        }

        // Check session with oversized tool key — should be silently skipped
        let long_tool = "a".repeat(257);
        let mut check: HashMap<String, u64> = HashMap::new();
        check.insert(long_tool, 1000);
        let alerts = tracker.check_session("agent-1", &check);
        assert!(
            alerts.is_empty(),
            "oversized tool key should be skipped in check_session"
        );
    }

    #[test]
    fn test_check_session_skips_control_char_tool_key() {
        let config = BehavioralConfig {
            min_sessions: 1,
            threshold: 2.0,
            absolute_ceiling: Some(10),
            ..Default::default()
        };
        let mut tracker = BehavioralTracker::new(config).unwrap();

        let normal = counts(&[("valid_tool", 5)]);
        for _ in 0..3 {
            tracker.record_session("agent-1", &normal);
        }

        // Check session with control char in tool key — should be silently skipped
        // even with absolute_ceiling which would normally trigger Critical
        let mut check: HashMap<String, u64> = HashMap::new();
        check.insert("tool\x1bnewline".to_string(), 1000);
        let alerts = tracker.check_session("agent-1", &check);
        assert!(
            alerts.is_empty(),
            "control char tool key should be skipped in check_session"
        );
    }

    #[test]
    fn test_check_session_skips_bidi_override_tool_key() {
        let config = BehavioralConfig {
            min_sessions: 1,
            threshold: 2.0,
            absolute_ceiling: Some(10),
            ..Default::default()
        };
        let mut tracker = BehavioralTracker::new(config).unwrap();

        let normal = counts(&[("valid_tool", 5)]);
        for _ in 0..3 {
            tracker.record_session("agent-1", &normal);
        }

        // Bidi override in tool key — should be silently skipped
        let mut check: HashMap<String, u64> = HashMap::new();
        check.insert("tool\u{202E}evil".to_string(), 1000);
        let alerts = tracker.check_session("agent-1", &check);
        assert!(
            alerts.is_empty(),
            "bidi override tool key should be skipped in check_session"
        );
    }
}
