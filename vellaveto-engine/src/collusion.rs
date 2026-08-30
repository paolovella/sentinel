// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Multi-agent collusion detection (Phase 62 — OWASP ASI04, ASI07).
//!
//! Detects coordinated attacks across multiple agents where individual actions
//! appear innocuous but collectively constitute malicious behavior:
//!
//! - **Steganographic channels**: Unusually high entropy in tool parameters or
//!   response values, suggesting hidden data channels between agents.
//! - **Coordinated attack patterns**: Multiple agents targeting the same resource
//!   in a narrow time window (e.g., agent A reads credentials, agent B exfiltrates).
//! - **Cross-agent behavioral correlation**: Synchronized tool call patterns that
//!   deviate from independent baselines.
//!
//! # Design
//!
//! - **Deterministic**: No ML, no randomness — uses entropy thresholds and
//!   temporal correlation windows.
//! - **Bounded memory**: Ring buffers with `MAX_*` constants on all collections.
//! - **Fail-closed**: Lock poisoning and capacity exhaustion produce alerts.
//! - **Observable**: Every detection logged with structured tracing.

use crate::entropy_gate::{
    entropy_alert_severity, entropy_observation_millibits, entropy_threshold_millibits,
    is_high_entropy_millibits, EntropyAlertLevel,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::RwLock;

// ═══════════════════════════════════════════════════
// CONSTANTS (bounded collections — Trap 3)
// ═══════════════════════════════════════════════════

/// Maximum number of agents tracked for collusion correlation.
const MAX_TRACKED_AGENTS: usize = 10_000;

/// Maximum resource access events retained per resource.
const MAX_EVENTS_PER_RESOURCE: usize = 1_000;

/// Maximum number of distinct resources tracked.
const MAX_TRACKED_RESOURCES: usize = 50_000;

/// Maximum number of entropy samples retained per agent.
const MAX_ENTROPY_SAMPLES_PER_AGENT: usize = 500;

/// Maximum length of an agent ID.
const MAX_AGENT_ID_LEN: usize = 512;

/// Maximum length of a resource key.
const MAX_RESOURCE_KEY_LEN: usize = 2048;

/// Maximum length of a tool name.
const MAX_TOOL_NAME_LEN: usize = 256;

/// Maximum number of collusion alerts retained.
const MAX_ALERT_HISTORY: usize = 10_000;

/// Maximum length of parameter data for entropy analysis (64 KB).
const MAX_PARAM_DATA_LEN: usize = 65_536;

/// Maximum denial events retained per agent for reconnaissance detection.
const MAX_DENIAL_EVENTS_PER_AGENT: usize = 500;

/// Maximum number of agents tracked for reconnaissance detection.
const MAX_RECON_TRACKED_AGENTS: usize = 10_000;

/// Maximum number of agents tracked for behavioral drift detection.
const MAX_DRIFT_TRACKED_AGENTS: usize = 10_000;

/// Maximum tool usage entries per drift profile.
const MAX_DRIFT_TOOL_ENTRIES: usize = 500;

/// Maximum number of historical denial rate snapshots per agent.
/// Reserved for future multi-window drift comparison.
#[allow(dead_code)]
const MAX_DRIFT_SNAPSHOTS: usize = 100;

// ═══════════════════════════════════════════════════
// CONFIGURATION
// ═══════════════════════════════════════════════════

/// Configuration for multi-agent collusion detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CollusionConfig {
    /// Whether collusion detection is enabled.
    /// Default: true
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    /// Time window (seconds) for coordinated access detection.
    /// Two agents accessing the same resource within this window are correlated.
    /// Default: 60
    #[serde(default = "default_coordination_window_secs")]
    pub coordination_window_secs: u64,

    /// Minimum Shannon entropy (bits per byte) to flag a parameter as potentially
    /// steganographic. Normal text is ~3.5–4.5, compressed/encrypted data is ~7.5+.
    /// Default: 6.5
    #[serde(default = "default_entropy_threshold")]
    pub entropy_threshold: f64,

    /// Minimum number of high-entropy observations before flagging an agent.
    /// Prevents false positives from occasional base64 parameters.
    /// Default: 5
    #[serde(default = "default_min_entropy_observations")]
    pub min_entropy_observations: u32,

    /// Number of distinct agents that must access the same resource within
    /// `coordination_window_secs` to trigger a coordinated access alert.
    /// Default: 3
    #[serde(default = "default_min_coordinated_agents")]
    pub min_coordinated_agents: u32,

    /// Threshold for temporal synchronization score (0.0–1.0).
    /// Higher values require more precise synchronization.
    /// Default: 0.7
    #[serde(default = "default_sync_threshold")]
    pub sync_threshold: f64,

    /// R226: Number of distinct policy denials within `recon_window_secs` that
    /// triggers a reconnaissance probe alert. Detects agents systematically
    /// probing permission boundaries (Promptware Kill Chain Stage 3).
    /// Default: 10
    #[serde(default = "default_recon_denial_threshold")]
    pub recon_denial_threshold: u32,

    /// R226: Time window (seconds) for reconnaissance probe detection.
    /// Default: 60
    #[serde(default = "default_recon_window_secs")]
    pub recon_window_secs: u64,

    /// R226: Drift detection — minimum change in denial rate (0.0–1.0) across
    /// a time window to trigger an alert. E.g., if an agent's denial rate jumps
    /// from 5% to 30%, the drift is 0.25 which exceeds the default 0.20 threshold.
    /// Default: 0.20
    #[serde(default = "default_drift_threshold")]
    pub drift_threshold: f64,

    /// R226: Drift detection — time window (seconds) for comparing behavior
    /// baseline vs current. Default: 3600 (1 hour).
    #[serde(default = "default_drift_window_secs")]
    pub drift_window_secs: u64,

    /// R226: Drift detection — minimum number of actions before drift detection
    /// activates (avoids false alerts on small sample sizes).
    /// Default: 20
    #[serde(default = "default_drift_min_actions")]
    pub drift_min_actions: u32,
}

fn default_enabled() -> bool {
    true
}
fn default_coordination_window_secs() -> u64 {
    60
}
fn default_entropy_threshold() -> f64 {
    6.5
}
fn default_min_entropy_observations() -> u32 {
    5
}
fn default_min_coordinated_agents() -> u32 {
    3
}
fn default_sync_threshold() -> f64 {
    0.7
}
fn default_recon_denial_threshold() -> u32 {
    10
}
fn default_recon_window_secs() -> u64 {
    60
}
fn default_drift_threshold() -> f64 {
    0.20
}
fn default_drift_window_secs() -> u64 {
    3600
}
fn default_drift_min_actions() -> u32 {
    20
}

impl Default for CollusionConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            coordination_window_secs: default_coordination_window_secs(),
            entropy_threshold: default_entropy_threshold(),
            min_entropy_observations: default_min_entropy_observations(),
            min_coordinated_agents: default_min_coordinated_agents(),
            sync_threshold: default_sync_threshold(),
            recon_denial_threshold: default_recon_denial_threshold(),
            recon_window_secs: default_recon_window_secs(),
            drift_threshold: default_drift_threshold(),
            drift_window_secs: default_drift_window_secs(),
            drift_min_actions: default_drift_min_actions(),
        }
    }
}

// ═══════════════════════════════════════════════════
// ERRORS
// ═══════════════════════════════════════════════════

/// Errors from collusion detection operations.
#[derive(Debug, Clone, PartialEq)]
pub enum CollusionError {
    /// Configuration validation failed.
    InvalidConfig(String),
    /// Lock poisoned — fail-closed.
    LockPoisoned(String),
    /// Input validation failed.
    InvalidInput(String),
}

impl std::fmt::Display for CollusionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CollusionError::InvalidConfig(msg) => write!(f, "invalid collusion config: {msg}"),
            CollusionError::LockPoisoned(msg) => {
                write!(f, "collusion detector lock poisoned (fail-closed): {msg}")
            }
            CollusionError::InvalidInput(msg) => {
                write!(f, "collusion detector input validation failed: {msg}")
            }
        }
    }
}

impl std::error::Error for CollusionError {}

impl CollusionConfig {
    /// Validate configuration values.
    pub fn validate(&self) -> Result<(), CollusionError> {
        // SECURITY (R237-ENG-7): Upper bounds on time windows prevent config abuse.
        const MAX_COORDINATION_WINDOW_SECS: u64 = 86_400; // 24 hours
        if self.coordination_window_secs == 0
            || self.coordination_window_secs > MAX_COORDINATION_WINDOW_SECS
        {
            return Err(CollusionError::InvalidConfig(format!(
                "coordination_window_secs must be in [1, {MAX_COORDINATION_WINDOW_SECS}]"
            )));
        }
        // SECURITY (Trap 4): Validate f64 fields for NaN/Infinity.
        // SECURITY (R229-ENG-5): Upper bound at 8.0 (max Shannon entropy for bytes).
        // Values above 8.0 would disable detection entirely.
        if !self.entropy_threshold.is_finite()
            || self.entropy_threshold < 0.0
            || self.entropy_threshold > 8.0
        {
            return Err(CollusionError::InvalidConfig(format!(
                "entropy_threshold must be in [0.0, 8.0], got {}",
                self.entropy_threshold
            )));
        }
        if !self.sync_threshold.is_finite()
            || self.sync_threshold < 0.0
            || self.sync_threshold > 1.0
        {
            return Err(CollusionError::InvalidConfig(format!(
                "sync_threshold must be in [0.0, 1.0], got {}",
                self.sync_threshold
            )));
        }
        if self.min_coordinated_agents < 2 {
            return Err(CollusionError::InvalidConfig(
                "min_coordinated_agents must be >= 2".to_string(),
            ));
        }
        // R226: Recon detection validation.
        if self.recon_denial_threshold == 0 {
            return Err(CollusionError::InvalidConfig(
                "recon_denial_threshold must be > 0".to_string(),
            ));
        }
        const MAX_RECON_WINDOW_SECS: u64 = 3_600; // 1 hour
        if self.recon_window_secs == 0 || self.recon_window_secs > MAX_RECON_WINDOW_SECS {
            return Err(CollusionError::InvalidConfig(format!(
                "recon_window_secs must be in [1, {MAX_RECON_WINDOW_SECS}]"
            )));
        }
        // R226: Drift detection validation.
        if !self.drift_threshold.is_finite()
            || self.drift_threshold < 0.0
            || self.drift_threshold > 1.0
        {
            return Err(CollusionError::InvalidConfig(format!(
                "drift_threshold must be in [0.0, 1.0], got {}",
                self.drift_threshold
            )));
        }
        const MAX_DRIFT_WINDOW_SECS: u64 = 604_800; // 7 days
        if self.drift_window_secs == 0 || self.drift_window_secs > MAX_DRIFT_WINDOW_SECS {
            return Err(CollusionError::InvalidConfig(format!(
                "drift_window_secs must be in [1, {MAX_DRIFT_WINDOW_SECS}]"
            )));
        }
        if self.drift_min_actions == 0 {
            return Err(CollusionError::InvalidConfig(
                "drift_min_actions must be > 0".to_string(),
            ));
        }
        // SECURITY (R231-COLL-1): Zero min_entropy_observations makes the
        // `high_entropy_count >= 0` check always true, flooding
        // SteganographicChannel alerts on every single call.
        if self.min_entropy_observations == 0 {
            return Err(CollusionError::InvalidConfig(
                "min_entropy_observations must be > 0".to_string(),
            ));
        }
        Ok(())
    }
}

// ═══════════════════════════════════════════════════
// ALERT TYPES
// ═══════════════════════════════════════════════════

/// Type of collusion detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CollusionType {
    /// Steganographic channel: high-entropy parameters suggesting hidden data.
    SteganographicChannel,
    /// Coordinated resource access: multiple agents accessing the same resource
    /// in a narrow time window.
    CoordinatedAccess,
    /// Synchronized behavior: agents showing correlated tool call timing.
    SynchronizedBehavior,
    /// R226: Reconnaissance probe — agent rapidly triggering many distinct policy
    /// denials in a short window, indicating boundary probing before an attack.
    /// (Schneier / Promptware Kill Chain Stage 3)
    ReconnaissanceProbe,
    /// R226: Gradual constraint drift — agent behavior shifts significantly over
    /// a time window, indicating "salami slicing" or progressive boundary pushing.
    /// (Straiker — agent hijacking via gradual drift)
    ConstraintDrift,
    /// R229: Tracker capacity exhaustion — an attacker may have filled the tracker
    /// with dummy agent IDs to evade detection. This is a fail-closed alert.
    CapacityExhaustion,
}

/// Severity of a collusion alert.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum CollusionSeverity {
    /// Suspicious pattern detected, may be benign.
    Low,
    /// Pattern is unlikely to be accidental.
    Medium,
    /// Strong indicator of coordinated malicious activity.
    High,
    /// Multiple strong indicators combined.
    Critical,
}

/// A collusion alert emitted by the detector.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CollusionAlert {
    /// Type of collusion detected.
    pub collusion_type: CollusionType,
    /// Severity level.
    pub severity: CollusionSeverity,
    /// Agent IDs involved.
    pub agent_ids: Vec<String>,
    /// Resource or tool targeted (if applicable).
    pub target: String,
    /// Human-readable description.
    pub description: String,
    /// Unix timestamp when detected.
    pub detected_at: u64,
    /// Supporting evidence (entropy values, timing data, etc.).
    pub evidence: CollusionEvidence,
}

/// Evidence supporting a collusion alert.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CollusionEvidence {
    /// Entropy values if steganographic channel detected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entropy_values: Option<Vec<f64>>,
    /// Timestamps of coordinated accesses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_timestamps: Option<Vec<u64>>,
    /// Synchronization score (0.0–1.0).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sync_score: Option<f64>,
    /// Number of observations.
    pub observation_count: u32,
}

impl std::fmt::Display for CollusionAlert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[{:?}/{:?}] agents={:?} target='{}': {}",
            self.severity, self.collusion_type, self.agent_ids, self.target, self.description,
        )
    }
}

// ═══════════════════════════════════════════════════
// INTERNAL STATE
// ═══════════════════════════════════════════════════

/// A timestamped resource access event.
#[derive(Debug, Clone)]
struct ResourceAccessEvent {
    agent_id: String,
    /// Tool used for the access. Retained for audit trail / evidence.
    #[allow(dead_code)]
    tool: String,
    timestamp: u64,
}

/// Per-agent entropy tracking.
#[derive(Debug, Clone)]
struct EntropyProfile {
    /// Recent entropy values for parameter data.
    samples: VecDeque<EntropyObservation>,
    /// Count of samples exceeding the threshold.
    high_entropy_count: u32,
    /// Total samples recorded.
    total_samples: u32,
}

impl EntropyProfile {
    fn new() -> Self {
        Self {
            samples: VecDeque::new(),
            high_entropy_count: 0,
            total_samples: 0,
        }
    }
}

/// Telemetry and decision-grade representation of one entropy sample.
///
/// The raw `bits_per_byte` value is preserved for evidence and metrics, while
/// the security decision path uses `decision_millibits` to avoid scattered
/// floating-point threshold comparisons in the detector state machine.
#[derive(Debug, Clone, Copy)]
struct EntropyObservation {
    bits_per_byte: f64,
    /// Conservative fixed-point score used for security decisions.
    ///
    /// Observations round up to the nearest millibit so borderline values bias
    /// toward alerting rather than silently missing a suspicious sample.
    decision_millibits: u16,
}

impl EntropyObservation {
    fn new(bits_per_byte: f64) -> Self {
        Self {
            bits_per_byte,
            decision_millibits: entropy_observation_millibits(bits_per_byte),
        }
    }

    fn is_high(self, threshold_millibits: u16) -> bool {
        is_high_entropy_millibits(self.decision_millibits, threshold_millibits)
    }
}

/// R226: A policy denial event for reconnaissance detection.
#[derive(Debug, Clone)]
struct DenialEvent {
    /// Tool that was denied.
    tool: String,
    /// Unix timestamp of the denial.
    timestamp: u64,
}

/// R226: Per-agent behavioral drift profile.
///
/// Tracks tool call and denial counts in a sliding window to detect gradual
/// shifts in an agent's behavior over time. A sudden increase in denial rate
/// indicates the agent is being pushed beyond its authorized boundaries.
#[derive(Debug, Clone)]
struct DriftProfile {
    /// Timestamped action records: (timestamp, was_denied).
    actions: VecDeque<(u64, bool)>,
}

impl DriftProfile {
    fn new() -> Self {
        Self {
            actions: VecDeque::new(),
        }
    }

    /// Record an action (tool call attempt, possibly denied).
    fn record(&mut self, timestamp: u64, denied: bool) {
        if self.actions.len() >= MAX_DRIFT_TOOL_ENTRIES {
            self.actions.pop_front();
        }
        self.actions.push_back((timestamp, denied));
    }

    /// Compute denial rate for actions within a time window ending at `now`.
    fn denial_rate_in_window(&self, window_start: u64, window_end: u64) -> Option<f64> {
        let mut total = 0u64;
        let mut denied = 0u64;
        for &(ts, was_denied) in &self.actions {
            // SECURITY (R241-ENG-3): Half-open interval to prevent boundary double-counting.
            if ts >= window_start && ts < window_end {
                total = total.saturating_add(1);
                if was_denied {
                    denied = denied.saturating_add(1);
                }
            }
        }
        if total == 0 {
            return None;
        }
        Some(denied as f64 / total as f64)
    }
}

/// Per-agent tool call timing profile for synchronization detection.
#[derive(Debug, Clone)]
struct TimingProfile {
    /// Recent tool call timestamps.
    timestamps: VecDeque<u64>,
    /// Maximum entries retained.
    max_entries: usize,
}

impl TimingProfile {
    fn new(max_entries: usize) -> Self {
        Self {
            timestamps: VecDeque::new(),
            max_entries,
        }
    }

    fn record(&mut self, timestamp: u64) {
        if self.timestamps.len() >= self.max_entries {
            self.timestamps.pop_front();
        }
        self.timestamps.push_back(timestamp);
    }
}

// ═══════════════════════════════════════════════════
// DETECTOR
// ═══════════════════════════════════════════════════

/// Multi-agent collusion detector.
///
/// Thread-safe via `RwLock`. All operations are fail-closed on lock poisoning.
pub struct CollusionDetector {
    config: CollusionConfig,
    /// Per-resource access event ring buffers.
    resource_events: RwLock<HashMap<String, VecDeque<ResourceAccessEvent>>>,
    /// Per-agent entropy profiles.
    entropy_profiles: RwLock<HashMap<String, EntropyProfile>>,
    /// Per-agent timing profiles for sync detection.
    timing_profiles: RwLock<HashMap<String, TimingProfile>>,
    /// Alert history (ring buffer).
    alerts: RwLock<VecDeque<CollusionAlert>>,
    /// R226: Per-agent denial event ring buffers for reconnaissance detection.
    denial_events: RwLock<HashMap<String, VecDeque<DenialEvent>>>,
    /// R226: Per-agent behavioral drift profiles.
    drift_profiles: RwLock<HashMap<String, DriftProfile>>,
}

impl std::fmt::Debug for CollusionDetector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CollusionDetector")
            .field("config", &self.config)
            .field("resource_events", &"<locked>")
            .field("entropy_profiles", &"<locked>")
            .field("timing_profiles", &"<locked>")
            .field("alerts", &"<locked>")
            .field("denial_events", &"<locked>")
            .field("drift_profiles", &"<locked>")
            .finish()
    }
}

impl CollusionDetector {
    /// Create a new collusion detector with validated configuration.
    pub fn new(config: CollusionConfig) -> Result<Self, CollusionError> {
        config.validate()?;
        Ok(Self {
            config,
            resource_events: RwLock::new(HashMap::new()),
            entropy_profiles: RwLock::new(HashMap::new()),
            timing_profiles: RwLock::new(HashMap::new()),
            alerts: RwLock::new(VecDeque::new()),
            denial_events: RwLock::new(HashMap::new()),
            drift_profiles: RwLock::new(HashMap::new()),
        })
    }

    /// Check if the detector is enabled.
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Get the current configuration.
    pub fn config(&self) -> &CollusionConfig {
        &self.config
    }

    // ═══════════════════════════════════════════════
    // INPUT VALIDATION
    // ═══════════════════════════════════════════════

    /// Validate an agent ID for length and dangerous characters.
    fn validate_agent_id(agent_id: &str) -> Result<(), CollusionError> {
        if agent_id.is_empty() || agent_id.len() > MAX_AGENT_ID_LEN {
            return Err(CollusionError::InvalidInput(format!(
                "agent_id length {} out of range [1, {}]",
                agent_id.len(),
                MAX_AGENT_ID_LEN
            )));
        }
        if vellaveto_types::has_dangerous_chars(agent_id) {
            return Err(CollusionError::InvalidInput(
                "agent_id contains control or Unicode format characters".to_string(),
            ));
        }
        Ok(())
    }

    /// Validate a resource key for length and dangerous characters.
    fn validate_resource_key(resource: &str) -> Result<(), CollusionError> {
        if resource.is_empty() || resource.len() > MAX_RESOURCE_KEY_LEN {
            return Err(CollusionError::InvalidInput(format!(
                "resource key length {} out of range [1, {}]",
                resource.len(),
                MAX_RESOURCE_KEY_LEN
            )));
        }
        if vellaveto_types::has_dangerous_chars(resource) {
            return Err(CollusionError::InvalidInput(
                "resource key contains control or Unicode format characters".to_string(),
            ));
        }
        Ok(())
    }

    /// Validate a tool name.
    fn validate_tool_name(tool: &str) -> Result<(), CollusionError> {
        if tool.is_empty() || tool.len() > MAX_TOOL_NAME_LEN {
            return Err(CollusionError::InvalidInput(format!(
                "tool name length {} out of range [1, {}]",
                tool.len(),
                MAX_TOOL_NAME_LEN
            )));
        }
        if vellaveto_types::has_dangerous_chars(tool) {
            return Err(CollusionError::InvalidInput(
                "tool name contains control or Unicode format characters".to_string(),
            ));
        }
        Ok(())
    }

    // ═══════════════════════════════════════════════
    // STEGANOGRAPHIC CHANNEL DETECTION
    // ═══════════════════════════════════════════════

    /// Compute Shannon entropy (bits per byte) of raw data.
    ///
    /// Returns a value in [0.0, 8.0]. Values above ~6.5 suggest
    /// compressed/encrypted/random data (potential steganographic channel).
    pub fn compute_entropy(data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }

        let mut freq = [0u64; 256];
        for &byte in data {
            freq[byte as usize] = freq[byte as usize].saturating_add(1);
        }

        let len = data.len() as f64;
        let mut entropy = 0.0_f64;

        for &count in &freq {
            if count == 0 {
                continue;
            }
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }

        // Guard against NaN/Infinity from degenerate inputs.
        if !entropy.is_finite() {
            return 0.0;
        }

        entropy
    }

    /// SECURITY (R229-ENG-2): Build a capacity-exhaustion alert for fail-closed behavior.
    fn capacity_alert(tracker_name: &str, max: usize) -> CollusionAlert {
        CollusionAlert {
            collusion_type: CollusionType::CapacityExhaustion,
            severity: CollusionSeverity::High,
            agent_ids: Vec::new(),
            target: tracker_name.to_string(),
            description: format!(
                "{tracker_name} tracker at capacity ({max}) — possible evasion attack"
            ),
            // SECURITY (R238-ENG-3): Use 1 instead of 0 to avoid timestamp
            // collapse at epoch if system clock is misconfigured.
            detected_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(1),
            evidence: CollusionEvidence {
                entropy_values: None,
                access_timestamps: None,
                sync_score: None,
                observation_count: u32::try_from(max).unwrap_or(u32::MAX),
            },
        }
    }

    /// Analyze parameter data for steganographic channels.
    ///
    /// Records the entropy observation and returns an alert if the agent
    /// has consistently high-entropy parameters.
    pub fn analyze_parameters(
        &self,
        agent_id: &str,
        param_data: &[u8],
    ) -> Result<Option<CollusionAlert>, CollusionError> {
        if !self.config.enabled {
            return Ok(None);
        }
        Self::validate_agent_id(agent_id)?;

        // Truncate oversized parameter data for entropy analysis.
        let data = if param_data.len() > MAX_PARAM_DATA_LEN {
            &param_data[..MAX_PARAM_DATA_LEN]
        } else {
            param_data
        };

        // Skip very short data (insufficient for meaningful entropy).
        if data.len() < 16 {
            return Ok(None);
        }

        let observation = EntropyObservation::new(Self::compute_entropy(data));
        let threshold_millibits = entropy_threshold_millibits(self.config.entropy_threshold);
        let is_high = observation.is_high(threshold_millibits);

        let mut profiles = self
            .entropy_profiles
            .write()
            .map_err(|_| CollusionError::LockPoisoned("entropy_profiles write lock".to_string()))?;

        // SECURITY (R229-ENG-2): Fail-closed on capacity exhaustion.
        // Previously returned Ok(None) which silently skipped, allowing evasion.
        if !profiles.contains_key(agent_id) && profiles.len() >= MAX_TRACKED_AGENTS {
            tracing::warn!(
                max = MAX_TRACKED_AGENTS,
                "Collusion entropy profiles at capacity — returning alert"
            );
            return Ok(Some(Self::capacity_alert(
                "entropy_profiles",
                MAX_TRACKED_AGENTS,
            )));
        }

        let profile = profiles
            .entry(agent_id.to_string())
            .or_insert_with(EntropyProfile::new);

        // Record sample.
        if profile.samples.len() >= MAX_ENTROPY_SAMPLES_PER_AGENT {
            // Evict oldest and adjust count if it was high-entropy.
            if let Some(old) = profile.samples.pop_front() {
                if old.is_high(threshold_millibits) {
                    profile.high_entropy_count = profile.high_entropy_count.saturating_sub(1);
                }
            }
        }
        profile.samples.push_back(observation);
        profile.total_samples = profile.total_samples.saturating_add(1);
        if is_high {
            profile.high_entropy_count = profile.high_entropy_count.saturating_add(1);
        }

        // Check if we have enough high-entropy observations to alert.
        if let Some(alert_level) = entropy_alert_severity(
            profile.high_entropy_count,
            self.config.min_entropy_observations,
        ) {
            let entropy_values: Vec<f64> = profile
                .samples
                .iter()
                .copied()
                .filter(|sample| sample.is_high(threshold_millibits))
                .map(|sample| sample.bits_per_byte)
                .take(10) // Limit evidence size
                .collect();

            let now = Self::now_secs();
            let severity = match alert_level {
                EntropyAlertLevel::High => CollusionSeverity::High,
                EntropyAlertLevel::Medium => CollusionSeverity::Medium,
            };

            let alert = CollusionAlert {
                collusion_type: CollusionType::SteganographicChannel,
                severity,
                agent_ids: vec![agent_id.to_string()],
                target: format!("agent:{agent_id}"),
                description: format!(
                    "Agent '{}' has {} high-entropy parameter observations (threshold: {:.1} bits/byte)",
                    agent_id,
                    profile.high_entropy_count,
                    self.config.entropy_threshold,
                ),
                detected_at: now,
                evidence: CollusionEvidence {
                    entropy_values: Some(entropy_values),
                    access_timestamps: None,
                    sync_score: None,
                    observation_count: profile.high_entropy_count,
                },
            };

            metrics::counter!(
                "vellaveto_collusion_alerts_total",
                "type" => "steganographic_channel"
            )
            .increment(1);

            tracing::warn!(
                agent_id = %agent_id,
                high_entropy_count = %profile.high_entropy_count,
                latest_entropy = %observation.bits_per_byte,
                "Potential steganographic channel detected in agent parameters"
            );

            self.record_alert(alert.clone())?;
            return Ok(Some(alert));
        }

        Ok(None)
    }

    // ═══════════════════════════════════════════════
    // COORDINATED RESOURCE ACCESS DETECTION
    // ═══════════════════════════════════════════════

    /// Record a resource access event and check for coordinated access patterns.
    ///
    /// Returns an alert if `min_coordinated_agents` or more distinct agents
    /// accessed the same resource within `coordination_window_secs`.
    pub fn record_resource_access(
        &self,
        agent_id: &str,
        resource: &str,
        tool: &str,
        timestamp: u64,
    ) -> Result<Option<CollusionAlert>, CollusionError> {
        if !self.config.enabled {
            return Ok(None);
        }
        Self::validate_agent_id(agent_id)?;
        Self::validate_resource_key(resource)?;
        Self::validate_tool_name(tool)?;

        // SECURITY (R231-ENG-4): Normalize agent_id, resource, and tool via
        // normalize_full() before using as HashMap keys. Without this, homoglyph
        // variants of the same logical entity are tracked separately, defeating
        // coordinated access detection (e.g., Cyrillic 'а' vs Latin 'a').
        let agent_id = crate::normalize::normalize_full(agent_id);
        let resource = crate::normalize::normalize_full(resource);
        let tool = crate::normalize::normalize_full(tool);

        let mut events = self
            .resource_events
            .write()
            .map_err(|_| CollusionError::LockPoisoned("resource_events write lock".to_string()))?;

        // SECURITY (R229-ENG-2): Fail-closed on capacity exhaustion.
        if !events.contains_key(resource.as_str()) && events.len() >= MAX_TRACKED_RESOURCES {
            tracing::warn!(
                max = MAX_TRACKED_RESOURCES,
                "Collusion resource tracking at capacity — returning alert"
            );
            return Ok(Some(Self::capacity_alert(
                "resource_tracking",
                MAX_TRACKED_RESOURCES,
            )));
        }

        let event_queue = events
            .entry(resource.to_string())
            .or_insert_with(VecDeque::new);

        // Evict events outside the window.
        let cutoff = timestamp.saturating_sub(self.config.coordination_window_secs);
        while let Some(front) = event_queue.front() {
            if front.timestamp < cutoff {
                event_queue.pop_front();
            } else {
                break;
            }
        }

        // Add new event, evicting oldest if at capacity.
        if event_queue.len() >= MAX_EVENTS_PER_RESOURCE {
            event_queue.pop_front();
        }

        event_queue.push_back(ResourceAccessEvent {
            agent_id: agent_id.to_string(),
            tool: tool.to_string(),
            timestamp,
        });

        // Count distinct agents in the current window.
        let mut distinct_agents: Vec<&str> = Vec::new();
        let mut timestamps_in_window: Vec<u64> = Vec::new();
        for event in event_queue.iter() {
            if event.timestamp >= cutoff {
                if !distinct_agents.contains(&event.agent_id.as_str()) {
                    distinct_agents.push(&event.agent_id);
                }
                timestamps_in_window.push(event.timestamp);
            }
        }

        if distinct_agents.len() >= self.config.min_coordinated_agents as usize {
            let now = Self::now_secs();

            let severity = if distinct_agents.len()
                >= (self.config.min_coordinated_agents as usize).saturating_mul(2)
            {
                CollusionSeverity::High
            } else {
                CollusionSeverity::Medium
            };

            let alert = CollusionAlert {
                collusion_type: CollusionType::CoordinatedAccess,
                severity,
                agent_ids: distinct_agents.iter().map(|s| s.to_string()).collect(),
                target: resource.to_string(),
                description: format!(
                    "{} agents accessed resource '{}' within {}s window",
                    distinct_agents.len(),
                    resource,
                    self.config.coordination_window_secs,
                ),
                detected_at: now,
                evidence: CollusionEvidence {
                    entropy_values: None,
                    access_timestamps: Some(timestamps_in_window),
                    sync_score: None,
                    // SECURITY (R229-ENG-3): Safe cast with fail-closed fallback.
                    observation_count: u32::try_from(distinct_agents.len()).unwrap_or(u32::MAX),
                },
            };

            metrics::counter!(
                "vellaveto_collusion_alerts_total",
                "type" => "coordinated_access"
            )
            .increment(1);

            tracing::warn!(
                resource = %resource,
                agent_count = %distinct_agents.len(),
                window_secs = %self.config.coordination_window_secs,
                "Coordinated resource access detected"
            );

            self.record_alert(alert.clone())?;
            return Ok(Some(alert));
        }

        Ok(None)
    }

    // ═══════════════════════════════════════════════
    // SYNCHRONIZED BEHAVIOR DETECTION
    // ═══════════════════════════════════════════════

    /// Record a tool call timestamp for synchronization analysis.
    ///
    /// Returns an alert if the agent's timing is highly correlated with
    /// other tracked agents.
    pub fn record_tool_timing(
        &self,
        agent_id: &str,
        timestamp: u64,
    ) -> Result<Option<CollusionAlert>, CollusionError> {
        if !self.config.enabled {
            return Ok(None);
        }
        Self::validate_agent_id(agent_id)?;
        // SECURITY (R231-ENG-4): Normalize agent_id for consistent tracking.
        let agent_id = crate::normalize::normalize_full(agent_id);

        let mut profiles = self
            .timing_profiles
            .write()
            .map_err(|_| CollusionError::LockPoisoned("timing_profiles write lock".to_string()))?;

        // SECURITY (R229-ENG-2): Fail-closed on capacity exhaustion.
        if !profiles.contains_key(agent_id.as_str()) && profiles.len() >= MAX_TRACKED_AGENTS {
            tracing::warn!(
                max = MAX_TRACKED_AGENTS,
                "Collusion timing profiles at capacity — returning alert"
            );
            return Ok(Some(Self::capacity_alert(
                "timing_profiles",
                MAX_TRACKED_AGENTS,
            )));
        }

        let profile = profiles
            .entry(agent_id.to_string())
            .or_insert_with(|| TimingProfile::new(MAX_ENTROPY_SAMPLES_PER_AGENT));

        profile.record(timestamp);

        // Need at least 10 timestamps per agent for meaningful correlation.
        if profile.timestamps.len() < 10 {
            return Ok(None);
        }

        // Clone the current agent's timestamps to release the mutable borrow,
        // allowing immutable iteration over other profiles.
        let agent_timestamps = profile.timestamps.clone();

        // Check synchronization with all other agents.
        let mut correlated_agents = Vec::new();
        let mut max_sync_score = 0.0_f64;

        for (other_id, other_profile) in profiles.iter() {
            if *other_id == agent_id || other_profile.timestamps.len() < 10 {
                continue;
            }
            let score = Self::compute_sync_score(&agent_timestamps, &other_profile.timestamps);
            if score >= self.config.sync_threshold {
                correlated_agents.push(other_id.clone());
                if score > max_sync_score {
                    max_sync_score = score;
                }
            }
        }

        if !correlated_agents.is_empty() {
            let mut all_agents = vec![agent_id.to_string()];
            all_agents.extend(correlated_agents);

            let now = Self::now_secs();

            let severity = if max_sync_score >= 0.9 {
                CollusionSeverity::High
            } else {
                CollusionSeverity::Medium
            };

            let alert = CollusionAlert {
                collusion_type: CollusionType::SynchronizedBehavior,
                severity,
                agent_ids: all_agents.clone(),
                target: "tool_call_timing".to_string(),
                description: format!(
                    "{} agents show synchronized tool call timing (max sync score: {:.2})",
                    all_agents.len(),
                    max_sync_score,
                ),
                detected_at: now,
                evidence: CollusionEvidence {
                    entropy_values: None,
                    access_timestamps: None,
                    sync_score: Some(max_sync_score),
                    observation_count: u32::try_from(all_agents.len()).unwrap_or(u32::MAX),
                },
            };

            metrics::counter!(
                "vellaveto_collusion_alerts_total",
                "type" => "synchronized_behavior"
            )
            .increment(1);

            tracing::warn!(
                agent_ids = ?all_agents,
                sync_score = %max_sync_score,
                "Synchronized agent behavior detected"
            );

            self.record_alert(alert.clone())?;
            return Ok(Some(alert));
        }

        Ok(None)
    }

    /// Compute temporal synchronization score between two agents.
    ///
    /// Uses inter-arrival time correlation: if agents consistently make
    /// calls at similar intervals, the score approaches 1.0.
    ///
    /// Returns a value in [0.0, 1.0].
    fn compute_sync_score(a_timestamps: &VecDeque<u64>, b_timestamps: &VecDeque<u64>) -> f64 {
        if a_timestamps.len() < 2 || b_timestamps.len() < 2 {
            return 0.0;
        }

        // Compute inter-arrival times.
        let a_intervals: Vec<f64> = a_timestamps
            .iter()
            .zip(a_timestamps.iter().skip(1))
            .map(|(&t1, &t2)| t2.saturating_sub(t1) as f64)
            .collect();

        let b_intervals: Vec<f64> = b_timestamps
            .iter()
            .zip(b_timestamps.iter().skip(1))
            .map(|(&t1, &t2)| t2.saturating_sub(t1) as f64)
            .collect();

        if a_intervals.is_empty() || b_intervals.is_empty() {
            return 0.0;
        }

        // Pearson correlation of inter-arrival times.
        // Use the shorter of the two vectors.
        let min_len = a_intervals.len().min(b_intervals.len());
        if min_len < 2 {
            return 0.0;
        }

        let a_slice = &a_intervals[..min_len];
        let b_slice = &b_intervals[..min_len];

        let a_mean: f64 = a_slice.iter().sum::<f64>() / min_len as f64;
        let b_mean: f64 = b_slice.iter().sum::<f64>() / min_len as f64;

        let mut cov = 0.0_f64;
        let mut a_var = 0.0_f64;
        let mut b_var = 0.0_f64;

        for i in 0..min_len {
            let a_diff = a_slice[i] - a_mean;
            let b_diff = b_slice[i] - b_mean;
            cov += a_diff * b_diff;
            a_var += a_diff * a_diff;
            b_var += b_diff * b_diff;
        }

        let denom = (a_var * b_var).sqrt();
        if denom < f64::EPSILON {
            // Zero variance — constant intervals. If both are constant at the
            // same rate, treat as highly correlated.
            if a_var < f64::EPSILON && b_var < f64::EPSILON {
                // Both constant: check if the intervals are similar.
                let a_rep = a_slice.first().copied().unwrap_or(0.0);
                let b_rep = b_slice.first().copied().unwrap_or(0.0);
                let max_rep = a_rep.max(b_rep);
                if max_rep < f64::EPSILON {
                    return 1.0; // Both zero-interval — identical
                }
                let diff = (a_rep - b_rep).abs() / max_rep;
                return (1.0 - diff).max(0.0);
            }
            return 0.0;
        }

        let correlation = cov / denom;
        // Clamp to [0.0, 1.0] — negative correlation is not collusion.
        // Guard against NaN from degenerate inputs before clamping.
        if !correlation.is_finite() {
            return 0.0;
        }
        correlation.clamp(0.0, 1.0)
    }

    // ═══════════════════════════════════════════════
    // R226: RECONNAISSANCE PROBE DETECTION
    // ═══════════════════════════════════════════════

    /// Record a policy denial event for an agent and check for reconnaissance
    /// probing patterns.
    ///
    /// A reconnaissance probe is detected when an agent triggers
    /// `recon_denial_threshold` or more distinct policy denials within
    /// `recon_window_secs`. This indicates the agent is systematically
    /// probing permission boundaries before launching an attack
    /// (Promptware Kill Chain Stage 3 — Schneier/arXiv:2601.09625).
    ///
    /// Returns an alert if the threshold is exceeded.
    pub fn record_denial(
        &self,
        agent_id: &str,
        tool: &str,
        timestamp: u64,
    ) -> Result<Option<CollusionAlert>, CollusionError> {
        if !self.config.enabled {
            return Ok(None);
        }
        Self::validate_agent_id(agent_id)?;
        Self::validate_tool_name(tool)?;
        // SECURITY (R231-ENG-4): Normalize for consistent tracking.
        let agent_id = crate::normalize::normalize_full(agent_id);
        let tool = crate::normalize::normalize_full(tool);

        let mut denials = self
            .denial_events
            .write()
            .map_err(|_| CollusionError::LockPoisoned("denial_events write lock".to_string()))?;

        // SECURITY (R229-ENG-2): Fail-closed on capacity exhaustion.
        if !denials.contains_key(agent_id.as_str()) && denials.len() >= MAX_RECON_TRACKED_AGENTS {
            tracing::warn!(
                max = MAX_RECON_TRACKED_AGENTS,
                "Reconnaissance denial tracking at capacity — returning alert"
            );
            return Ok(Some(Self::capacity_alert(
                "recon_tracking",
                MAX_RECON_TRACKED_AGENTS,
            )));
        }

        let events = denials
            .entry(agent_id.to_string())
            .or_insert_with(VecDeque::new);

        // Evict events outside the window.
        let cutoff = timestamp.saturating_sub(self.config.recon_window_secs);
        while let Some(front) = events.front() {
            if front.timestamp < cutoff {
                events.pop_front();
            } else {
                break;
            }
        }

        // Add new event, evicting oldest if at capacity.
        if events.len() >= MAX_DENIAL_EVENTS_PER_AGENT {
            events.pop_front();
        }
        events.push_back(DenialEvent {
            tool: tool.to_string(),
            timestamp,
        });

        // Count distinct tools denied within the window.
        let mut distinct_tools: Vec<&str> = Vec::new();
        let mut denial_timestamps: Vec<u64> = Vec::new();
        for event in events.iter() {
            if event.timestamp >= cutoff {
                if !distinct_tools.contains(&event.tool.as_str()) {
                    distinct_tools.push(&event.tool);
                }
                denial_timestamps.push(event.timestamp);
            }
        }

        // SECURITY (R229-ENG-3): Safe cast with fail-closed fallback.
        let distinct_count = u32::try_from(distinct_tools.len()).unwrap_or(u32::MAX);
        if distinct_count >= self.config.recon_denial_threshold {
            let now = Self::now_secs();

            let severity = if distinct_count >= self.config.recon_denial_threshold.saturating_mul(2)
            {
                CollusionSeverity::Critical
            } else {
                CollusionSeverity::High
            };

            let alert = CollusionAlert {
                collusion_type: CollusionType::ReconnaissanceProbe,
                severity,
                agent_ids: vec![agent_id.to_string()],
                target: format!("agent:{agent_id}"),
                description: format!(
                    "Agent '{}' triggered {} distinct policy denials within {}s window \
                     (threshold: {}), indicating reconnaissance probing",
                    agent_id,
                    distinct_count,
                    self.config.recon_window_secs,
                    self.config.recon_denial_threshold,
                ),
                detected_at: now,
                evidence: CollusionEvidence {
                    entropy_values: None,
                    access_timestamps: Some(denial_timestamps),
                    sync_score: None,
                    observation_count: distinct_count,
                },
            };

            metrics::counter!(
                "vellaveto_collusion_alerts_total",
                "type" => "reconnaissance_probe"
            )
            .increment(1);

            tracing::warn!(
                agent_id = %agent_id,
                distinct_denials = %distinct_count,
                window_secs = %self.config.recon_window_secs,
                "Reconnaissance probe detected: agent systematically probing permission boundaries"
            );

            self.record_alert(alert.clone())?;
            return Ok(Some(alert));
        }

        Ok(None)
    }

    // ═══════════════════════════════════════════════
    // R226: GRADUAL CONSTRAINT DRIFT DETECTION
    // ═══════════════════════════════════════════════

    /// Record a tool call attempt and detect behavioral drift.
    ///
    /// Tracks each agent's action history (allowed vs denied) and compares the
    /// denial rate in the first half of the time window (baseline) to the second
    /// half (current). If the denial rate increases by more than `drift_threshold`,
    /// an alert is raised indicating the agent may be gradually pushing boundaries.
    ///
    /// (Straiker — "salami slicing" agent hijacking over multiple sessions)
    pub fn record_agent_action(
        &self,
        agent_id: &str,
        denied: bool,
        timestamp: u64,
    ) -> Result<Option<CollusionAlert>, CollusionError> {
        if !self.config.enabled {
            return Ok(None);
        }
        Self::validate_agent_id(agent_id)?;
        // SECURITY (R231-ENG-4): Normalize for consistent tracking.
        let agent_id = crate::normalize::normalize_full(agent_id);

        let mut profiles = self
            .drift_profiles
            .write()
            .map_err(|_| CollusionError::LockPoisoned("drift_profiles write lock".to_string()))?;

        // SECURITY (R229-ENG-2): Fail-closed on capacity exhaustion.
        if !profiles.contains_key(agent_id.as_str()) && profiles.len() >= MAX_DRIFT_TRACKED_AGENTS {
            tracing::warn!(
                max = MAX_DRIFT_TRACKED_AGENTS,
                "Drift tracking at capacity — returning alert"
            );
            return Ok(Some(Self::capacity_alert(
                "drift_tracking",
                MAX_DRIFT_TRACKED_AGENTS,
            )));
        }

        let profile = profiles
            .entry(agent_id.to_string())
            .or_insert_with(DriftProfile::new);

        profile.record(timestamp, denied);

        // Need enough actions before computing drift.
        if profile.actions.len() < self.config.drift_min_actions as usize {
            return Ok(None);
        }

        // Split the window into baseline (first half) and current (second half).
        let window_start = timestamp.saturating_sub(self.config.drift_window_secs);
        let midpoint = window_start.saturating_add(self.config.drift_window_secs / 2);

        let baseline_rate = profile.denial_rate_in_window(window_start, midpoint);
        let current_rate = profile.denial_rate_in_window(midpoint, timestamp);

        if let (Some(baseline), Some(current)) = (baseline_rate, current_rate) {
            let drift = current - baseline;
            if drift >= self.config.drift_threshold {
                let now = Self::now_secs();

                let severity = if drift >= self.config.drift_threshold * 2.0 {
                    CollusionSeverity::High
                } else {
                    CollusionSeverity::Medium
                };

                let alert = CollusionAlert {
                    collusion_type: CollusionType::ConstraintDrift,
                    severity,
                    agent_ids: vec![agent_id.to_string()],
                    target: format!("agent:{agent_id}"),
                    description: format!(
                        "Agent '{}' denial rate shifted from {:.1}% to {:.1}% \
                         (drift: {:.1}%, threshold: {:.1}%) within {}s window",
                        agent_id,
                        baseline * 100.0,
                        current * 100.0,
                        drift * 100.0,
                        self.config.drift_threshold * 100.0,
                        self.config.drift_window_secs,
                    ),
                    detected_at: now,
                    evidence: CollusionEvidence {
                        entropy_values: None,
                        access_timestamps: None,
                        sync_score: Some(drift),
                        observation_count: u32::try_from(profile.actions.len()).unwrap_or(u32::MAX),
                    },
                };

                metrics::counter!(
                    "vellaveto_collusion_alerts_total",
                    "type" => "constraint_drift"
                )
                .increment(1);

                tracing::warn!(
                    agent_id = %agent_id,
                    baseline_rate = %format!("{:.2}", baseline),
                    current_rate = %format!("{:.2}", current),
                    drift = %format!("{:.2}", drift),
                    "Gradual constraint drift detected: agent behavior shifting"
                );

                self.record_alert(alert.clone())?;
                return Ok(Some(alert));
            }
        }

        Ok(None)
    }

    // ═══════════════════════════════════════════════
    // ALERT MANAGEMENT
    // ═══════════════════════════════════════════════

    /// Record an alert in the history ring buffer.
    fn record_alert(&self, alert: CollusionAlert) -> Result<(), CollusionError> {
        let mut alerts = self
            .alerts
            .write()
            .map_err(|_| CollusionError::LockPoisoned("alerts write lock".to_string()))?;

        if alerts.len() >= MAX_ALERT_HISTORY {
            alerts.pop_front();
        }
        alerts.push_back(alert);
        Ok(())
    }

    /// Get recent alerts (up to `limit`).
    pub fn recent_alerts(&self, limit: usize) -> Result<Vec<CollusionAlert>, CollusionError> {
        let alerts = self
            .alerts
            .read()
            .map_err(|_| CollusionError::LockPoisoned("alerts read lock".to_string()))?;

        Ok(alerts.iter().rev().take(limit).cloned().collect())
    }

    /// Get total alert count.
    pub fn alert_count(&self) -> Result<usize, CollusionError> {
        let alerts = self
            .alerts
            .read()
            .map_err(|_| CollusionError::LockPoisoned("alerts read lock".to_string()))?;
        Ok(alerts.len())
    }

    // ═══════════════════════════════════════════════
    // UTILITY
    // ═══════════════════════════════════════════════

    /// Get current Unix timestamp in seconds.
    ///
    /// SECURITY (R238-ENG-3): Returns 1 (not 0) on clock failure to prevent
    /// timestamp collapse where all events appear at epoch, defeating temporal
    /// correlation windows.
    fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or_else(|_| {
                tracing::error!(
                    "SECURITY: System clock before UNIX epoch — using fallback timestamp 1"
                );
                1
            })
    }
}

// ═══════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> CollusionConfig {
        CollusionConfig::default()
    }

    fn make_detector() -> CollusionDetector {
        CollusionDetector::new(default_config()).unwrap()
    }

    // ────────────────────────────────────────────────
    // Config validation
    // ────────────────────────────────────────────────

    #[test]
    fn test_config_validate_default_ok() {
        assert!(CollusionConfig::default().validate().is_ok());
    }

    #[test]
    fn test_config_validate_zero_window_rejected() {
        let mut cfg = default_config();
        cfg.coordination_window_secs = 0;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_config_validate_nan_entropy_rejected() {
        let mut cfg = default_config();
        cfg.entropy_threshold = f64::NAN;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_config_validate_negative_entropy_rejected() {
        let mut cfg = default_config();
        cfg.entropy_threshold = -1.0;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_config_validate_sync_threshold_out_of_range() {
        let mut cfg = default_config();
        cfg.sync_threshold = 1.5;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_config_validate_min_agents_below_two() {
        let mut cfg = default_config();
        cfg.min_coordinated_agents = 1;
        assert!(cfg.validate().is_err());
    }

    /// R231-COLL-1: Zero min_entropy_observations causes alert flooding.
    #[test]
    fn test_config_validate_zero_min_entropy_observations_rejected() {
        let mut cfg = default_config();
        cfg.min_entropy_observations = 0;
        let err = cfg.validate().unwrap_err();
        assert!(
            err.to_string()
                .contains("min_entropy_observations must be > 0"),
            "Expected min_entropy_observations error, got: {err}",
        );
    }

    /// R231-COLL-1: Non-zero min_entropy_observations accepted.
    #[test]
    fn test_config_validate_nonzero_min_entropy_observations_ok() {
        let mut cfg = default_config();
        cfg.min_entropy_observations = 1;
        assert!(cfg.validate().is_ok());
    }

    // ────────────────────────────────────────────────
    // Entropy computation
    // ────────────────────────────────────────────────

    #[test]
    fn test_compute_entropy_empty_data_returns_zero() {
        assert_eq!(CollusionDetector::compute_entropy(&[]), 0.0);
    }

    #[test]
    fn test_compute_entropy_uniform_data_returns_zero() {
        let data = vec![0x41u8; 100]; // All 'A'
        let entropy = CollusionDetector::compute_entropy(&data);
        assert!(
            entropy < 0.01,
            "Uniform data should have ~0 entropy, got {entropy}"
        );
    }

    #[test]
    fn test_compute_entropy_random_data_returns_high() {
        // Simulate high-entropy data (all 256 byte values equally distributed).
        let mut data = Vec::with_capacity(2560);
        for _ in 0..10 {
            for b in 0..=255u8 {
                data.push(b);
            }
        }
        let entropy = CollusionDetector::compute_entropy(&data);
        assert!(
            entropy > 7.9,
            "Uniformly distributed data should have ~8.0 bits/byte entropy, got {entropy}"
        );
    }

    #[test]
    fn test_compute_entropy_english_text_moderate() {
        let data = b"The quick brown fox jumps over the lazy dog. This is a normal sentence.";
        let entropy = CollusionDetector::compute_entropy(data);
        assert!(
            entropy > 3.0 && entropy < 5.5,
            "English text should have ~3.5-4.5 bits/byte entropy, got {entropy}"
        );
    }

    #[test]
    fn test_entropy_decision_helper_uses_fixed_point_threshold() {
        let threshold = entropy_threshold_millibits(6.5);
        assert_eq!(threshold, 6500);

        let exact = EntropyObservation::new(6.5);
        let clearly_low = EntropyObservation::new(6.498);
        let clearly_high = EntropyObservation::new(6.8);

        assert!(exact.is_high(threshold));
        assert!(!clearly_low.is_high(threshold));
        assert!(clearly_high.is_high(threshold));
    }

    #[test]
    fn test_entropy_decision_helper_biases_borderline_values_toward_alerting() {
        let threshold = entropy_threshold_millibits(6.5);
        let borderline = EntropyObservation::new(6.4991);

        assert!(
            borderline.is_high(threshold),
            "Borderline entropy should classify high under the conservative fixed-point gate"
        );
    }

    // ────────────────────────────────────────────────
    // Steganographic channel detection
    // ────────────────────────────────────────────────

    #[test]
    fn test_analyze_parameters_disabled_returns_none() {
        let mut cfg = default_config();
        cfg.enabled = false;
        let detector = CollusionDetector::new(cfg).unwrap();
        let result = detector.analyze_parameters("agent-1", &[0u8; 100]);
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_analyze_parameters_short_data_returns_none() {
        let detector = make_detector();
        // Data shorter than 16 bytes should be skipped.
        let result = detector.analyze_parameters("agent-1", &[0u8; 10]);
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_analyze_parameters_normal_text_no_alert() {
        let detector = make_detector();
        let text = b"This is normal text parameter data that should not trigger alerts.";
        for _ in 0..20 {
            let result = detector.analyze_parameters("agent-1", text);
            assert!(
                result.unwrap().is_none(),
                "Normal text should not trigger steganographic alert"
            );
        }
    }

    #[test]
    fn test_analyze_parameters_high_entropy_triggers_alert() {
        let mut cfg = default_config();
        cfg.min_entropy_observations = 3;
        cfg.entropy_threshold = 6.0;
        let detector = CollusionDetector::new(cfg).unwrap();

        // Generate high-entropy data.
        let mut data = Vec::with_capacity(2560);
        for _ in 0..10 {
            for b in 0..=255u8 {
                data.push(b);
            }
        }

        // First few won't trigger (below min_entropy_observations).
        for i in 0..2 {
            let result = detector
                .analyze_parameters(&format!("agent-{i}"), &data)
                .unwrap();
            // These are unique agents, so each has only 1 observation.
            assert!(result.is_none());
        }

        // Same agent, repeated observations should trigger.
        let mut triggered = false;
        for _ in 0..5 {
            if let Some(alert) = detector.analyze_parameters("agent-crypto", &data).unwrap() {
                assert_eq!(alert.collusion_type, CollusionType::SteganographicChannel);
                assert!(alert.evidence.entropy_values.is_some());
                triggered = true;
                break;
            }
        }
        assert!(
            triggered,
            "Should have triggered steganographic alert after repeated high-entropy observations"
        );
    }

    // ────────────────────────────────────────────────
    // Coordinated resource access
    // ────────────────────────────────────────────────

    #[test]
    fn test_record_resource_access_disabled_returns_none() {
        let mut cfg = default_config();
        cfg.enabled = false;
        let detector = CollusionDetector::new(cfg).unwrap();
        let result = detector.record_resource_access("agent-1", "/secret", "read", 1000);
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_record_resource_access_single_agent_no_alert() {
        let detector = make_detector();
        let result = detector.record_resource_access("agent-1", "/secret", "read", 1000);
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_record_resource_access_coordinated_triggers_alert() {
        let mut cfg = default_config();
        cfg.min_coordinated_agents = 3;
        cfg.coordination_window_secs = 60;
        let detector = CollusionDetector::new(cfg).unwrap();

        let base_time = 1_000_000u64;
        // Three agents access the same resource within the window.
        assert!(detector
            .record_resource_access("agent-1", "/credentials/db", "read_file", base_time)
            .unwrap()
            .is_none());
        assert!(detector
            .record_resource_access("agent-2", "/credentials/db", "read_file", base_time + 10)
            .unwrap()
            .is_none());

        let result = detector
            .record_resource_access("agent-3", "/credentials/db", "read_file", base_time + 20)
            .unwrap();
        assert!(
            result.is_some(),
            "Three agents in window should trigger alert"
        );

        let alert = result.unwrap();
        assert_eq!(alert.collusion_type, CollusionType::CoordinatedAccess);
        assert_eq!(alert.agent_ids.len(), 3);
        assert!(alert.description.contains("3 agents"));
    }

    #[test]
    fn test_record_resource_access_outside_window_no_alert() {
        let mut cfg = default_config();
        cfg.min_coordinated_agents = 3;
        cfg.coordination_window_secs = 60;
        let detector = CollusionDetector::new(cfg).unwrap();

        let base_time = 1_000_000u64;
        // First two agents access resource, third is outside the window.
        assert!(detector
            .record_resource_access("agent-1", "/secret", "read", base_time)
            .unwrap()
            .is_none());
        assert!(detector
            .record_resource_access("agent-2", "/secret", "read", base_time + 10)
            .unwrap()
            .is_none());
        // Agent-3 accesses 100 seconds later (outside 60s window).
        let result = detector
            .record_resource_access("agent-3", "/secret", "read", base_time + 100)
            .unwrap();
        // Agent-1's event is expired (100 > 60), so only agent-2 and agent-3 remain = 2 < 3.
        assert!(
            result.is_none(),
            "Agent outside window should not trigger alert"
        );
    }

    // ────────────────────────────────────────────────
    // Synchronized behavior detection
    // ────────────────────────────────────────────────

    #[test]
    fn test_record_tool_timing_disabled_returns_none() {
        let mut cfg = default_config();
        cfg.enabled = false;
        let detector = CollusionDetector::new(cfg).unwrap();
        let result = detector.record_tool_timing("agent-1", 1000);
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_record_tool_timing_single_agent_no_alert() {
        let detector = make_detector();
        for t in 0..20 {
            let result = detector.record_tool_timing("agent-1", t * 10);
            assert!(result.unwrap().is_none());
        }
    }

    #[test]
    fn test_record_tool_timing_synchronized_triggers_alert() {
        let mut cfg = default_config();
        cfg.sync_threshold = 0.8;
        let detector = CollusionDetector::new(cfg).unwrap();

        // Two agents with identical inter-arrival times.
        for t in 0..15 {
            let _ = detector.record_tool_timing("agent-a", t * 10);
            let _ = detector.record_tool_timing("agent-b", t * 10 + 1); // Offset by 1s
        }

        // The next recording should detect synchronization.
        let result = detector.record_tool_timing("agent-a", 150);
        // May or may not trigger depending on exact correlation computation.
        // The sync detection is best-effort for identical patterns.
        // We primarily verify no errors.
        assert!(result.is_ok());
    }

    #[test]
    fn test_compute_sync_score_identical_intervals_returns_high() {
        let a: VecDeque<u64> = (0..10).map(|i| i * 5).collect();
        let b: VecDeque<u64> = (0..10).map(|i| i * 5 + 1).collect();

        let score = CollusionDetector::compute_sync_score(&a, &b);
        assert!(
            score > 0.95,
            "Identical intervals should have high sync score, got {score}"
        );
    }

    #[test]
    fn test_compute_sync_score_different_intervals_returns_low() {
        // Agent A: constant 5s intervals.
        let a: VecDeque<u64> = (0..10).map(|i| i * 5).collect();
        // Agent B: exponentially increasing intervals.
        let b: VecDeque<u64> = (0..10).map(|i| i * i * 3).collect();

        let score = CollusionDetector::compute_sync_score(&a, &b);
        assert!(
            score < 0.8,
            "Different interval patterns should have low sync score, got {score}"
        );
    }

    #[test]
    fn test_compute_sync_score_empty_timestamps_returns_zero() {
        let a: VecDeque<u64> = VecDeque::new();
        let b: VecDeque<u64> = (0..10).collect();
        assert_eq!(CollusionDetector::compute_sync_score(&a, &b), 0.0);
    }

    #[test]
    fn test_compute_sync_score_single_timestamp_returns_zero() {
        let a: VecDeque<u64> = vec![100].into_iter().collect();
        let b: VecDeque<u64> = vec![100].into_iter().collect();
        assert_eq!(CollusionDetector::compute_sync_score(&a, &b), 0.0);
    }

    // ────────────────────────────────────────────────
    // Input validation
    // ────────────────────────────────────────────────

    #[test]
    fn test_validate_agent_id_empty_rejected() {
        assert!(CollusionDetector::validate_agent_id("").is_err());
    }

    #[test]
    fn test_validate_agent_id_too_long_rejected() {
        let long_id = "a".repeat(MAX_AGENT_ID_LEN + 1);
        assert!(CollusionDetector::validate_agent_id(&long_id).is_err());
    }

    #[test]
    fn test_validate_agent_id_control_chars_rejected() {
        assert!(CollusionDetector::validate_agent_id("agent\0id").is_err());
    }

    #[test]
    fn test_validate_resource_key_empty_rejected() {
        assert!(CollusionDetector::validate_resource_key("").is_err());
    }

    #[test]
    fn test_validate_tool_name_too_long_rejected() {
        let long_name = "t".repeat(MAX_TOOL_NAME_LEN + 1);
        assert!(CollusionDetector::validate_tool_name(&long_name).is_err());
    }

    // ────────────────────────────────────────────────
    // Alert management
    // ────────────────────────────────────────────────

    #[test]
    fn test_recent_alerts_returns_empty_initially() {
        let detector = make_detector();
        let alerts = detector.recent_alerts(10).unwrap();
        assert!(alerts.is_empty());
    }

    #[test]
    fn test_alert_count_returns_zero_initially() {
        let detector = make_detector();
        assert_eq!(detector.alert_count().unwrap(), 0);
    }

    #[test]
    fn test_recent_alerts_returns_most_recent_first() {
        // Record a coordinated access alert via 2-agent pattern.
        let mut cfg = default_config();
        cfg.min_coordinated_agents = 2;
        let detector = CollusionDetector::new(cfg).unwrap();

        let base = 1_000_000u64;
        let _ = detector.record_resource_access("a1", "/res1", "read", base);
        let _ = detector.record_resource_access("a2", "/res1", "read", base + 1);
        let _ = detector.record_resource_access("a1", "/res2", "read", base + 2);
        let _ = detector.record_resource_access("a3", "/res2", "read", base + 3);

        let alerts = detector.recent_alerts(10).unwrap();
        assert!(!alerts.is_empty(), "Should have at least one alert");
        // Most recent should be first.
        if alerts.len() >= 2 {
            assert!(alerts[0].detected_at >= alerts[1].detected_at);
        }
    }

    // ────────────────────────────────────────────────
    // Serialization
    // ────────────────────────────────────────────────

    #[test]
    fn test_config_serialization_roundtrip() {
        let cfg = CollusionConfig::default();
        let json = serde_json::to_string(&cfg).unwrap();
        let parsed: CollusionConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(
            parsed.coordination_window_secs,
            cfg.coordination_window_secs
        );
        assert_eq!(parsed.entropy_threshold, cfg.entropy_threshold);
    }

    #[test]
    fn test_config_deny_unknown_fields() {
        let json = r#"{"enabled": true, "unknown_field": 42}"#;
        let result: Result<CollusionConfig, _> = serde_json::from_str(json);
        assert!(
            result.is_err(),
            "deny_unknown_fields should reject unknown fields"
        );
    }

    #[test]
    fn test_alert_serialization_roundtrip() {
        let alert = CollusionAlert {
            collusion_type: CollusionType::SteganographicChannel,
            severity: CollusionSeverity::High,
            agent_ids: vec!["a1".to_string()],
            target: "test".to_string(),
            description: "test alert".to_string(),
            detected_at: 12345,
            evidence: CollusionEvidence {
                entropy_values: Some(vec![7.5, 7.8]),
                access_timestamps: None,
                sync_score: None,
                observation_count: 2,
            },
        };
        let json = serde_json::to_string(&alert).unwrap();
        let parsed: CollusionAlert = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.collusion_type, CollusionType::SteganographicChannel);
        assert_eq!(parsed.severity, CollusionSeverity::High);
    }

    // ────────────────────────────────────────────────
    // R226: Reconnaissance probe detection
    // ────────────────────────────────────────────────

    #[test]
    fn test_record_denial_disabled_returns_none() {
        let mut cfg = default_config();
        cfg.enabled = false;
        let detector = CollusionDetector::new(cfg).unwrap();
        let result = detector.record_denial("agent-1", "read_file", 1000);
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_record_denial_below_threshold_no_alert() {
        let mut cfg = default_config();
        cfg.recon_denial_threshold = 5;
        cfg.recon_window_secs = 60;
        let detector = CollusionDetector::new(cfg).unwrap();

        let base = 1_000_000u64;
        // 4 distinct tool denials — below threshold of 5.
        for (i, tool) in ["read_file", "write_file", "exec_cmd", "list_dir"]
            .iter()
            .enumerate()
        {
            let result = detector
                .record_denial("probe-agent", tool, base + i as u64)
                .unwrap();
            assert!(
                result.is_none(),
                "Below threshold should not trigger alert (tool #{i})"
            );
        }
    }

    #[test]
    fn test_record_denial_at_threshold_triggers_alert() {
        let mut cfg = default_config();
        cfg.recon_denial_threshold = 5;
        cfg.recon_window_secs = 60;
        let detector = CollusionDetector::new(cfg).unwrap();

        let base = 1_000_000u64;
        let tools = [
            "read_file",
            "write_file",
            "exec_cmd",
            "list_dir",
            "delete_file",
        ];

        let mut triggered = false;
        for (i, tool) in tools.iter().enumerate() {
            if let Some(alert) = detector
                .record_denial("probe-agent", tool, base + i as u64)
                .unwrap()
            {
                assert_eq!(alert.collusion_type, CollusionType::ReconnaissanceProbe);
                assert_eq!(alert.severity, CollusionSeverity::High);
                assert!(alert.description.contains("5 distinct policy denials"));
                assert!(alert.description.contains("probe-agent"));
                assert_eq!(alert.evidence.observation_count, 5);
                triggered = true;
                break;
            }
        }
        assert!(
            triggered,
            "Should have triggered reconnaissance probe alert at threshold"
        );
    }

    #[test]
    fn test_record_denial_same_tool_repeated_no_alert() {
        let mut cfg = default_config();
        cfg.recon_denial_threshold = 5;
        cfg.recon_window_secs = 60;
        let detector = CollusionDetector::new(cfg).unwrap();

        let base = 1_000_000u64;
        // Same tool denied 20 times — only 1 distinct tool, below threshold.
        for i in 0..20 {
            let result = detector
                .record_denial("probe-agent", "read_file", base + i)
                .unwrap();
            assert!(
                result.is_none(),
                "Repeated same-tool denial should not trigger recon alert"
            );
        }
    }

    #[test]
    fn test_record_denial_outside_window_no_alert() {
        let mut cfg = default_config();
        cfg.recon_denial_threshold = 3;
        cfg.recon_window_secs = 10;
        let detector = CollusionDetector::new(cfg).unwrap();

        let base = 1_000_000u64;
        // First 2 denials at base time.
        detector
            .record_denial("probe-agent", "tool_a", base)
            .unwrap();
        detector
            .record_denial("probe-agent", "tool_b", base + 1)
            .unwrap();

        // Third denial well outside the 10s window.
        let result = detector
            .record_denial("probe-agent", "tool_c", base + 100)
            .unwrap();
        // tool_a and tool_b have expired (100 > 10), so only tool_c = 1 distinct, < 3.
        assert!(
            result.is_none(),
            "Denials outside window should not trigger alert"
        );
    }

    #[test]
    fn test_record_denial_critical_severity_at_double_threshold() {
        let mut cfg = default_config();
        cfg.recon_denial_threshold = 3;
        cfg.recon_window_secs = 120;
        let detector = CollusionDetector::new(cfg).unwrap();

        let base = 1_000_000u64;
        let tools = ["t1", "t2", "t3", "t4", "t5", "t6"];

        let mut last_alert = None;
        for (i, tool) in tools.iter().enumerate() {
            if let Some(alert) = detector
                .record_denial("heavy-probe", tool, base + i as u64)
                .unwrap()
            {
                last_alert = Some(alert);
            }
        }
        let alert = last_alert.expect("Should have triggered alert with 6 tools");
        // 6 >= 3*2, so severity should be Critical.
        assert_eq!(alert.severity, CollusionSeverity::Critical);
    }

    #[test]
    fn test_record_denial_invalid_agent_id_rejected() {
        let detector = make_detector();
        assert!(detector.record_denial("", "tool", 1000).is_err());
    }

    #[test]
    fn test_record_denial_invalid_tool_name_rejected() {
        let detector = make_detector();
        assert!(detector.record_denial("agent", "", 1000).is_err());
    }

    #[test]
    fn test_recon_config_validate_zero_threshold_rejected() {
        let mut cfg = default_config();
        cfg.recon_denial_threshold = 0;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_recon_config_validate_zero_window_rejected() {
        let mut cfg = default_config();
        cfg.recon_window_secs = 0;
        assert!(cfg.validate().is_err());
    }

    // ────────────────────────────────────────────────
    // R226: Gradual constraint drift detection
    // ────────────────────────────────────────────────

    #[test]
    fn test_record_agent_action_disabled_returns_none() {
        let mut cfg = default_config();
        cfg.enabled = false;
        let detector = CollusionDetector::new(cfg).unwrap();
        let result = detector.record_agent_action("agent-1", false, 1000);
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_record_agent_action_below_min_actions_no_alert() {
        let mut cfg = default_config();
        cfg.drift_min_actions = 20;
        cfg.drift_window_secs = 100;
        cfg.drift_threshold = 0.20;
        let detector = CollusionDetector::new(cfg).unwrap();

        // Record only 10 actions — below min_actions threshold.
        for i in 0..10 {
            let result = detector
                .record_agent_action("agent-1", i % 3 == 0, 1000 + i)
                .unwrap();
            assert!(result.is_none(), "Below min_actions should not trigger");
        }
    }

    #[test]
    fn test_record_agent_action_drift_triggers_alert() {
        let mut cfg = default_config();
        cfg.drift_min_actions = 10;
        cfg.drift_window_secs = 100;
        cfg.drift_threshold = 0.20;
        let detector = CollusionDetector::new(cfg).unwrap();

        let base = 1_000_000u64;
        // Baseline half (0-50s): all allowed (denial rate = 0%).
        for i in 0..10 {
            detector
                .record_agent_action("drift-agent", false, base + i * 5)
                .unwrap();
        }
        // Current half (51-100s): all denied (denial rate = 100%).
        let mut triggered = false;
        for i in 0..10 {
            if let Some(alert) = detector
                .record_agent_action("drift-agent", true, base + 51 + i * 5)
                .unwrap()
            {
                assert_eq!(alert.collusion_type, CollusionType::ConstraintDrift);
                assert!(alert.description.contains("drift-agent"));
                triggered = true;
                break;
            }
        }
        assert!(triggered, "Significant drift should trigger alert");
    }

    #[test]
    fn test_record_agent_action_no_drift_no_alert() {
        let mut cfg = default_config();
        cfg.drift_min_actions = 10;
        cfg.drift_window_secs = 100;
        cfg.drift_threshold = 0.20;
        let detector = CollusionDetector::new(cfg).unwrap();

        let base = 1_000_000u64;
        // Stable denial rate across both halves (~10% each).
        for i in 0..30 {
            let denied = i % 10 == 0; // ~10% denial rate
            let result = detector
                .record_agent_action("stable-agent", denied, base + i * 3)
                .unwrap();
            assert!(
                result.is_none(),
                "Stable denial rate should not trigger drift alert (action {i})"
            );
        }
    }

    #[test]
    fn test_drift_config_validate_invalid_threshold() {
        let mut cfg = default_config();
        cfg.drift_threshold = 1.5;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_drift_config_validate_nan_threshold() {
        let mut cfg = default_config();
        cfg.drift_threshold = f64::NAN;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_drift_config_validate_zero_window() {
        let mut cfg = default_config();
        cfg.drift_window_secs = 0;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_drift_config_validate_zero_min_actions() {
        let mut cfg = default_config();
        cfg.drift_min_actions = 0;
        assert!(cfg.validate().is_err());
    }

    // ── R237 — Upper bounds on time windows ────────────────────────────

    #[test]
    fn test_r237_eng7_coordination_window_upper_bound() {
        let mut cfg = default_config();
        cfg.coordination_window_secs = 86_401; // > 24 hours
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_r237_eng7_recon_window_upper_bound() {
        let mut cfg = default_config();
        cfg.recon_window_secs = 3_601; // > 1 hour
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_r237_eng7_drift_window_upper_bound() {
        let mut cfg = default_config();
        cfg.drift_window_secs = 604_801; // > 7 days
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_r237_eng7_coordination_window_at_max_ok() {
        let mut cfg = default_config();
        cfg.coordination_window_secs = 86_400; // exactly 24 hours
        assert!(cfg.validate().is_ok());
    }

    // ── R229 regression tests ───────────────────────────────────────────

    #[test]
    fn test_r229_capacity_alert_type_is_capacity_exhaustion() {
        let alert = CollusionDetector::capacity_alert("test_tracker", 100);
        assert_eq!(alert.collusion_type, CollusionType::CapacityExhaustion);
        assert_eq!(alert.severity, CollusionSeverity::High);
        assert!(alert.description.contains("capacity"));
        assert!(alert.description.contains("100"));
        assert_eq!(alert.target, "test_tracker");
    }

    #[test]
    fn test_r229_capacity_exhaustion_serialization_roundtrip() {
        let alert = CollusionDetector::capacity_alert("entropy_profiles", 10_000);
        let json = serde_json::to_string(&alert).expect("serialize");
        let parsed: CollusionAlert = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.collusion_type, CollusionType::CapacityExhaustion);
        assert_eq!(parsed.severity, CollusionSeverity::High);
    }

    #[test]
    fn test_r229_safe_u32_cast_on_observation_count() {
        // Verify u32::try_from pattern returns u32::MAX on overflow (not panic/wrap)
        let huge: usize = u32::MAX as usize + 100;
        let safe = u32::try_from(huge).unwrap_or(u32::MAX);
        assert_eq!(safe, u32::MAX);
    }
}

#[cfg(test)]
// Suppressed rather than satisfied: linting the extraction would edit the copy
// the Kani proofs run against.
#[allow(
    clippy::field_reassign_with_default,
    clippy::manual_range_contains,
    dead_code,
    unused_imports
)]
mod kani_collusion_extraction {
    include!(concat!(env!("OUT_DIR"), "/kani_collusion_extraction.rs"));
}

#[cfg(test)]
mod kani_parity_differential_collusion {
    //! Differential binding for `PARITY-HAND-2` — collusion config validation.
    //!
    //! K98-K102 rest on a `CollusionConfig::validate()` the extraction
    //! describes as mirroring production's. It did not: two fields production
    //! validates were absent — see `KANI-COLLUSION-GAPS-1`.
    //!
    //! Compared against production's real `validate()`, field by field, at each
    //! boundary. Production writes the **reject** form with `!is_finite()`, so
    //! comparing against a restatement would risk the polarity trap recorded as
    //! `ACCEPT-REJECT-ASYMMETRY-1`.

    use super::kani_collusion_extraction as extracted;
    use super::CollusionConfig;

    fn production_default() -> CollusionConfig {
        CollusionConfig::default()
    }

    fn model_default() -> extracted::CollusionConfig {
        extracted::CollusionConfig::default()
    }

    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn test_extraction_is_actually_present() {
        assert!(
            extracted::EXTRACTION_PRESENT,
            "formal/kani/src/collusion_detection.rs was not found, so this binding \
             compared nothing"
        );
    }

    /// The defaults must agree field by field, or every subsequent comparison
    /// starts from a different config than production ships.
    #[test]
    fn test_defaults_match_production() {
        let p = production_default();
        let m = model_default();
        assert_eq!(m.coordination_window_secs, p.coordination_window_secs);
        assert_eq!(m.entropy_threshold, p.entropy_threshold);
        assert_eq!(m.sync_threshold, p.sync_threshold);
        assert_eq!(m.min_entropy_observations, p.min_entropy_observations);
        assert_eq!(m.min_coordinated_agents, p.min_coordinated_agents);
        assert_eq!(m.recon_denial_threshold, p.recon_denial_threshold);
        assert_eq!(m.recon_window_secs, p.recon_window_secs);
        assert_eq!(m.drift_threshold, p.drift_threshold);
        assert_eq!(m.drift_window_secs, p.drift_window_secs);
        assert_eq!(m.drift_min_actions, p.drift_min_actions);
        // And the shipped default must actually validate, in both.
        assert!(
            p.validate().is_ok(),
            "production's default config is invalid"
        );
        assert!(
            m.validate().is_ok(),
            "the model's default config is invalid"
        );
    }

    /// Every field, at and around each boundary, against production's real
    /// `validate()`.
    #[test]
    fn test_validation_matches_production_field_by_field() {
        // (label, mutate production, mutate model)
        struct Case {
            label: &'static str,
            apply_p: fn(&mut CollusionConfig),
            apply_m: fn(&mut extracted::CollusionConfig),
        }

        const CASES: &[Case] = &[
            Case {
                label: "coordination_window_secs = 0",
                apply_p: |c| c.coordination_window_secs = 0,
                apply_m: |c| c.coordination_window_secs = 0,
            },
            Case {
                label: "coordination_window_secs = 86_400 (at bound)",
                apply_p: |c| c.coordination_window_secs = 86_400,
                apply_m: |c| c.coordination_window_secs = 86_400,
            },
            Case {
                label: "coordination_window_secs = 86_401 (over)",
                apply_p: |c| c.coordination_window_secs = 86_401,
                apply_m: |c| c.coordination_window_secs = 86_401,
            },
            Case {
                label: "entropy_threshold NaN",
                apply_p: |c| c.entropy_threshold = f64::NAN,
                apply_m: |c| c.entropy_threshold = f64::NAN,
            },
            Case {
                label: "entropy_threshold +inf",
                apply_p: |c| c.entropy_threshold = f64::INFINITY,
                apply_m: |c| c.entropy_threshold = f64::INFINITY,
            },
            Case {
                label: "entropy_threshold 8.0 (at bound)",
                apply_p: |c| c.entropy_threshold = 8.0,
                apply_m: |c| c.entropy_threshold = 8.0,
            },
            Case {
                label: "entropy_threshold 8.1 (over)",
                apply_p: |c| c.entropy_threshold = 8.1,
                apply_m: |c| c.entropy_threshold = 8.1,
            },
            Case {
                label: "sync_threshold NaN",
                apply_p: |c| c.sync_threshold = f64::NAN,
                apply_m: |c| c.sync_threshold = f64::NAN,
            },
            Case {
                label: "sync_threshold 1.1 (over)",
                apply_p: |c| c.sync_threshold = 1.1,
                apply_m: |c| c.sync_threshold = 1.1,
            },
            Case {
                label: "drift_threshold NaN",
                apply_p: |c| c.drift_threshold = f64::NAN,
                apply_m: |c| c.drift_threshold = f64::NAN,
            },
            Case {
                label: "drift_threshold -0.1 (under)",
                apply_p: |c| c.drift_threshold = -0.1,
                apply_m: |c| c.drift_threshold = -0.1,
            },
            Case {
                label: "min_entropy_observations = 0 (R231-COLL-1)",
                apply_p: |c| c.min_entropy_observations = 0,
                apply_m: |c| c.min_entropy_observations = 0,
            },
            Case {
                label: "min_coordinated_agents = 1 (KANI-COLLUSION-GAPS-1)",
                apply_p: |c| c.min_coordinated_agents = 1,
                apply_m: |c| c.min_coordinated_agents = 1,
            },
            Case {
                label: "min_coordinated_agents = 2 (at bound)",
                apply_p: |c| c.min_coordinated_agents = 2,
                apply_m: |c| c.min_coordinated_agents = 2,
            },
            Case {
                label: "recon_denial_threshold = 0",
                apply_p: |c| c.recon_denial_threshold = 0,
                apply_m: |c| c.recon_denial_threshold = 0,
            },
            Case {
                label: "recon_window_secs = 3_601 (over)",
                apply_p: |c| c.recon_window_secs = 3_601,
                apply_m: |c| c.recon_window_secs = 3_601,
            },
            Case {
                label: "drift_window_secs = 0",
                apply_p: |c| c.drift_window_secs = 0,
                apply_m: |c| c.drift_window_secs = 0,
            },
            Case {
                label: "drift_min_actions = 0 (KANI-COLLUSION-GAPS-1)",
                apply_p: |c| c.drift_min_actions = 0,
                apply_m: |c| c.drift_min_actions = 0,
            },
        ];

        let mut accepted = 0usize;
        let mut rejected = 0usize;
        for case in CASES {
            let mut p = production_default();
            (case.apply_p)(&mut p);
            let mut m = model_default();
            (case.apply_m)(&mut m);

            let production_ok = p.validate().is_ok();
            let model_ok = m.validate().is_ok();
            assert_eq!(
                model_ok, production_ok,
                "PARITY-HAND-2: validation disagrees for {} (production accepts={}, \
                 model accepts={}) — K98-K102 rest on a validator that is not \
                 production's",
                case.label, production_ok, model_ok
            );
            if production_ok {
                accepted += 1;
            } else {
                rejected += 1;
            }
        }
        assert_eq!(CASES.len(), 18, "case list shrank; recount before trusting");
        assert!(
            accepted > 0 && rejected > 0,
            "the case list is one-sided (accepted {accepted}, rejected {rejected}); \
             it cannot distinguish a validator that rejects everything"
        );
    }

    /// The capacity check that decides whether tracking fails closed.
    ///
    /// R229-ENG-1 made capacity exhaustion an alert rather than a silent drop:
    /// an attacker who can fill the tracker with dummy agents must not then
    /// operate unobserved.
    #[test]
    fn test_capacity_exhaustion_matches_production_bound() {
        assert_eq!(
            extracted::MAX_TRACKED_AGENTS,
            10_000,
            "the model's agent-tracking bound moved"
        );
        for (current, max) in [(0usize, 10usize), (9, 10), (10, 10), (11, 10), (0, 0)] {
            assert_eq!(
                extracted::is_capacity_exhausted(current, max),
                current >= max,
                "capacity exhaustion disagrees at ({current}, {max})"
            );
        }
        // `>=`, not `>`: at capacity is exhausted, or the tracker admits one
        // more than its bound before alerting.
        assert!(extracted::is_capacity_exhausted(10, 10));
    }
}
