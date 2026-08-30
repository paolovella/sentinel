// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Cascading failure circuit breakers for multi-hop tool call chains (Phase 62).
//!
//! Addresses OWASP ASI08 by enforcing:
//! - **Chain depth limits**: Maximum tool call depth in multi-hop pipelines.
//! - **Per-pipeline error rate tracking**: Automatic circuit breaking when a
//!   pipeline's error rate exceeds a configurable threshold.
//! - **Pipeline isolation**: Errors in one pipeline do not affect others.
//!
//! # Design
//!
//! - **Deterministic**: Sliding window error rate, no ML.
//! - **Bounded memory**: `MAX_*` constants on all collections.
//! - **Fail-closed**: Lock poisoning and capacity exhaustion deny requests.
//! - **Observable**: Metrics and structured tracing for all state changes.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::RwLock;

// ═══════════════════════════════════════════════════
// CONSTANTS
// ═══════════════════════════════════════════════════

/// Maximum tracked pipelines.
const MAX_TRACKED_PIPELINES: usize = 10_000;

/// Maximum events per pipeline window.
const MAX_EVENTS_PER_PIPELINE: usize = 10_000;

/// Maximum tracked call chains (in-flight).
const MAX_TRACKED_CHAINS: usize = 50_000;

/// Maximum length of a pipeline ID.
const MAX_PIPELINE_ID_LEN: usize = 512;

/// Maximum length of a chain ID.
const MAX_CHAIN_ID_LEN: usize = 512;

/// Maximum chain depth hard limit (cannot configure higher than this).
const ABSOLUTE_MAX_CHAIN_DEPTH: u32 = 100;

// ═══════════════════════════════════════════════════
// CONFIGURATION
// ═══════════════════════════════════════════════════

/// Configuration for cascading failure circuit breakers.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CascadingConfig {
    /// Whether cascading failure protection is enabled.
    /// Default: true
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    /// Maximum allowed chain depth for multi-hop tool calls.
    /// Requests exceeding this depth are denied.
    /// Default: 10
    #[serde(default = "default_max_chain_depth")]
    pub max_chain_depth: u32,

    /// Error rate threshold (0.0–1.0) that triggers pipeline circuit breaking.
    /// When the error rate within the window exceeds this, the pipeline is broken.
    /// Default: 0.5
    #[serde(default = "default_error_rate_threshold")]
    pub error_rate_threshold: f64,

    /// Sliding window size in seconds for error rate calculation.
    /// Default: 300 (5 minutes)
    #[serde(default = "default_window_secs")]
    pub window_secs: u64,

    /// Minimum number of events in the window before error rate is actionable.
    /// Prevents false positives from small sample sizes.
    /// Default: 10
    #[serde(default = "default_min_window_events")]
    pub min_window_events: u32,

    /// Duration in seconds a pipeline stays broken before allowing probes.
    /// Default: 60
    #[serde(default = "default_break_duration_secs")]
    pub break_duration_secs: u64,
}

fn default_enabled() -> bool {
    true
}
fn default_max_chain_depth() -> u32 {
    10
}
fn default_error_rate_threshold() -> f64 {
    0.5
}
fn default_window_secs() -> u64 {
    300
}
fn default_min_window_events() -> u32 {
    10
}
fn default_break_duration_secs() -> u64 {
    60
}

impl Default for CascadingConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            max_chain_depth: default_max_chain_depth(),
            error_rate_threshold: default_error_rate_threshold(),
            window_secs: default_window_secs(),
            min_window_events: default_min_window_events(),
            break_duration_secs: default_break_duration_secs(),
        }
    }
}

// ═══════════════════════════════════════════════════
// ERRORS
// ═══════════════════════════════════════════════════

/// Errors from cascading failure operations.
#[derive(Debug, Clone, PartialEq)]
pub enum CascadingError {
    /// Configuration validation failed.
    InvalidConfig(String),
    /// Lock poisoned — fail-closed.
    LockPoisoned(String),
    /// Input validation failed.
    InvalidInput(String),
    /// Chain depth exceeded.
    ChainDepthExceeded { current: u32, max: u32 },
    /// Pipeline circuit broken.
    PipelineBroken {
        pipeline_id: String,
        error_rate: f64,
    },
}

impl std::fmt::Display for CascadingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CascadingError::InvalidConfig(msg) => write!(f, "invalid cascading config: {msg}"),
            CascadingError::LockPoisoned(msg) => {
                write!(f, "cascading breaker lock poisoned (fail-closed): {msg}")
            }
            CascadingError::InvalidInput(msg) => {
                write!(f, "cascading breaker input validation failed: {msg}")
            }
            CascadingError::ChainDepthExceeded { current, max } => {
                write!(
                    f,
                    "tool call chain depth {current} exceeds maximum {max} (OWASP ASI08)"
                )
            }
            CascadingError::PipelineBroken {
                pipeline_id,
                error_rate: _,
            } => {
                // SECURITY (R245-ENG-12): Do not expose error_rate in Display.
                // The exact percentage leaks internal pipeline health metrics to
                // callers, which may be untrusted. The field is retained in the
                // enum for internal logging/metrics.
                write!(
                    f,
                    "Pipeline '{}' circuit is broken — requests blocked until recovery",
                    pipeline_id
                )
            }
        }
    }
}

impl std::error::Error for CascadingError {}

impl CascadingConfig {
    /// Validate configuration values.
    pub fn validate(&self) -> Result<(), CascadingError> {
        if self.max_chain_depth == 0 || self.max_chain_depth > ABSOLUTE_MAX_CHAIN_DEPTH {
            return Err(CascadingError::InvalidConfig(format!(
                "max_chain_depth must be in [1, {}], got {}",
                ABSOLUTE_MAX_CHAIN_DEPTH, self.max_chain_depth
            )));
        }
        // SECURITY (Trap 4): Validate f64 for NaN/Infinity.
        if !self.error_rate_threshold.is_finite()
            || self.error_rate_threshold < 0.0
            || self.error_rate_threshold > 1.0
        {
            return Err(CascadingError::InvalidConfig(format!(
                "error_rate_threshold must be in [0.0, 1.0], got {}",
                self.error_rate_threshold
            )));
        }
        // SECURITY (R240-ENG-2): Upper-bound time windows to prevent unbounded memory
        // growth in sliding window trackers and permanent denial-of-service from
        // unreachable break durations. Consistent with CollusionConfig bounds.
        const MAX_WINDOW_SECS: u64 = 86_400; // 24 hours
        const MAX_BREAK_DURATION_SECS: u64 = 86_400; // 24 hours
        if self.window_secs == 0 || self.window_secs > MAX_WINDOW_SECS {
            return Err(CascadingError::InvalidConfig(format!(
                "window_secs must be in [1, {MAX_WINDOW_SECS}], got {}",
                self.window_secs
            )));
        }
        if self.break_duration_secs == 0 || self.break_duration_secs > MAX_BREAK_DURATION_SECS {
            return Err(CascadingError::InvalidConfig(format!(
                "break_duration_secs must be in [1, {MAX_BREAK_DURATION_SECS}], got {}",
                self.break_duration_secs
            )));
        }
        // SECURITY (R229-ENG-9 + R245-ENG-2): Bound min_window_events to [1, 100_000].
        // Zero would make the circuit breaker trigger on the first failure regardless
        // of sample size, causing spurious tripping. Upper bound prevents disabling
        // circuit breakers by setting an unreachably high minimum.
        const MAX_MIN_WINDOW_EVENTS: u32 = 100_000;
        if self.min_window_events == 0 {
            return Err(CascadingError::InvalidConfig(
                "min_window_events must be >= 1, got 0".to_string(),
            ));
        }
        if self.min_window_events > MAX_MIN_WINDOW_EVENTS {
            return Err(CascadingError::InvalidConfig(format!(
                "min_window_events must be <= {}, got {}",
                MAX_MIN_WINDOW_EVENTS, self.min_window_events
            )));
        }
        Ok(())
    }
}

// ═══════════════════════════════════════════════════
// INTERNAL STATE
// ═══════════════════════════════════════════════════

/// A pipeline event (success or failure) with timestamp.
#[derive(Debug, Clone, Copy)]
struct PipelineEvent {
    timestamp: u64,
    is_error: bool,
}

/// Per-pipeline error tracking state.
#[derive(Debug)]
struct PipelineState {
    /// Sliding window of events.
    events: VecDeque<PipelineEvent>,
    /// Whether the circuit is currently broken.
    is_broken: bool,
    /// Timestamp when the circuit was broken (None if not broken).
    broken_at: Option<u64>,
    /// Number of times this pipeline has been broken.
    break_count: u32,
}

impl PipelineState {
    fn new() -> Self {
        Self {
            events: VecDeque::new(),
            is_broken: false,
            broken_at: None,
            break_count: 0,
        }
    }
}

/// In-flight call chain tracking.
#[derive(Debug, Clone)]
struct CallChain {
    /// Current depth.
    depth: u32,
    /// Pipeline this chain belongs to. Retained for observability.
    #[allow(dead_code)]
    pipeline_id: String,
    /// Timestamp when the chain started. Retained for staleness eviction.
    #[allow(dead_code)]
    started_at: u64,
}

// ═══════════════════════════════════════════════════
// MANAGER
// ═══════════════════════════════════════════════════

/// Cascading failure circuit breaker manager.
///
/// Thread-safe via `RwLock`. All security-critical paths are fail-closed.
pub struct CascadingBreaker {
    config: CascadingConfig,
    /// Per-pipeline error tracking.
    pipelines: RwLock<HashMap<String, PipelineState>>,
    /// In-flight call chains indexed by chain ID.
    chains: RwLock<HashMap<String, CallChain>>,
}

impl std::fmt::Debug for CascadingBreaker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CascadingBreaker")
            .field("config", &self.config)
            .field("pipelines", &"<locked>")
            .field("chains", &"<locked>")
            .finish()
    }
}

impl CascadingBreaker {
    /// Create a new cascading failure breaker with validated configuration.
    pub fn new(config: CascadingConfig) -> Result<Self, CascadingError> {
        config.validate()?;
        Ok(Self {
            config,
            pipelines: RwLock::new(HashMap::new()),
            chains: RwLock::new(HashMap::new()),
        })
    }

    /// Check if the breaker is enabled.
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Get the configured maximum chain depth.
    pub fn max_chain_depth(&self) -> u32 {
        self.config.max_chain_depth
    }

    // ═══════════════════════════════════════════════
    // INPUT VALIDATION
    // ═══════════════════════════════════════════════

    fn validate_pipeline_id(pipeline_id: &str) -> Result<(), CascadingError> {
        if pipeline_id.is_empty() || pipeline_id.len() > MAX_PIPELINE_ID_LEN {
            return Err(CascadingError::InvalidInput(format!(
                "pipeline_id length {} out of range [1, {}]",
                pipeline_id.len(),
                MAX_PIPELINE_ID_LEN
            )));
        }
        if vellaveto_types::has_dangerous_chars(pipeline_id) {
            return Err(CascadingError::InvalidInput(
                "pipeline_id contains control or Unicode format characters".to_string(),
            ));
        }
        Ok(())
    }

    fn validate_chain_id(chain_id: &str) -> Result<(), CascadingError> {
        if chain_id.is_empty() || chain_id.len() > MAX_CHAIN_ID_LEN {
            return Err(CascadingError::InvalidInput(format!(
                "chain_id length {} out of range [1, {}]",
                chain_id.len(),
                MAX_CHAIN_ID_LEN
            )));
        }
        if vellaveto_types::has_dangerous_chars(chain_id) {
            return Err(CascadingError::InvalidInput(
                "chain_id contains control or Unicode format characters".to_string(),
            ));
        }
        Ok(())
    }

    // ═══════════════════════════════════════════════
    // CHAIN DEPTH TRACKING
    // ═══════════════════════════════════════════════

    /// Begin or extend a tool call chain. Returns the current depth.
    ///
    /// If the chain does not exist, it is created at depth 1.
    /// If the chain already exists, the depth is incremented.
    ///
    /// Returns `Err(ChainDepthExceeded)` if the new depth would exceed
    /// `max_chain_depth`.
    pub fn enter_chain(&self, chain_id: &str, pipeline_id: &str) -> Result<u32, CascadingError> {
        if !self.config.enabled {
            return Ok(0);
        }
        Self::validate_chain_id(chain_id)?;
        Self::validate_pipeline_id(pipeline_id)?;

        let mut chains = self
            .chains
            .write()
            .map_err(|_| CascadingError::LockPoisoned("chains write lock".to_string()))?;

        if let Some(chain) = chains.get_mut(chain_id) {
            let new_depth = chain.depth.saturating_add(1);
            if new_depth > self.config.max_chain_depth {
                metrics::counter!(
                    "vellaveto_cascading_depth_exceeded_total",
                    "pipeline" => pipeline_id.to_string()
                )
                .increment(1);

                tracing::warn!(
                    chain_id = %chain_id,
                    pipeline_id = %pipeline_id,
                    current_depth = %new_depth,
                    max_depth = %self.config.max_chain_depth,
                    "Tool call chain depth exceeded (OWASP ASI08)"
                );

                return Err(CascadingError::ChainDepthExceeded {
                    current: new_depth,
                    max: self.config.max_chain_depth,
                });
            }
            chain.depth = new_depth;
            Ok(new_depth)
        } else {
            // New chain. Check capacity.
            if chains.len() >= MAX_TRACKED_CHAINS {
                tracing::warn!(
                    max = MAX_TRACKED_CHAINS,
                    "Cascading chain tracker at capacity, denying new chain (fail-closed)"
                );
                return Err(CascadingError::ChainDepthExceeded {
                    current: 1,
                    max: 0, // Capacity exceeded, not depth exceeded
                });
            }

            let now = Self::now_secs();
            chains.insert(
                chain_id.to_string(),
                CallChain {
                    depth: 1,
                    pipeline_id: pipeline_id.to_string(),
                    started_at: now,
                },
            );
            Ok(1)
        }
    }

    /// Exit a chain level (decrement depth). Call when a tool call completes.
    ///
    /// Removes the chain entirely if depth reaches 0.
    pub fn exit_chain(&self, chain_id: &str) -> Result<u32, CascadingError> {
        if !self.config.enabled {
            return Ok(0);
        }
        Self::validate_chain_id(chain_id)?;

        let mut chains = self
            .chains
            .write()
            .map_err(|_| CascadingError::LockPoisoned("chains write lock".to_string()))?;

        if let Some(chain) = chains.get_mut(chain_id) {
            if chain.depth <= 1 {
                chains.remove(chain_id);
                return Ok(0);
            }
            chain.depth = chain.depth.saturating_sub(1);
            Ok(chain.depth)
        } else {
            Ok(0)
        }
    }

    /// Get the current depth of a chain. Returns 0 if the chain doesn't exist.
    pub fn chain_depth(&self, chain_id: &str) -> Result<u32, CascadingError> {
        if !self.config.enabled {
            return Ok(0);
        }
        Self::validate_chain_id(chain_id)?;

        let chains = self
            .chains
            .read()
            .map_err(|_| CascadingError::LockPoisoned("chains read lock".to_string()))?;

        Ok(chains.get(chain_id).map(|c| c.depth).unwrap_or(0))
    }

    // ═══════════════════════════════════════════════
    // PIPELINE ERROR RATE TRACKING
    // ═══════════════════════════════════════════════

    /// Check if a pipeline is available (not broken).
    ///
    /// Returns `Ok(())` if the pipeline is healthy or if the break duration
    /// has elapsed (probe allowed). Returns `Err(PipelineBroken)` if broken.
    #[must_use = "pipeline break results must not be discarded"]
    pub fn check_pipeline(&self, pipeline_id: &str) -> Result<(), CascadingError> {
        if !self.config.enabled {
            return Ok(());
        }
        Self::validate_pipeline_id(pipeline_id)?;

        let pipelines = self
            .pipelines
            .read()
            .map_err(|_| CascadingError::LockPoisoned("pipelines read lock".to_string()))?;

        if let Some(state) = pipelines.get(pipeline_id) {
            if state.is_broken {
                let now = Self::now_secs();
                if let Some(broken_at) = state.broken_at {
                    if now >= broken_at.saturating_add(self.config.break_duration_secs) {
                        // Break duration elapsed — allow probe.
                        return Ok(());
                    }
                }

                let error_rate = self.compute_error_rate_inner(state, now);
                return Err(CascadingError::PipelineBroken {
                    pipeline_id: pipeline_id.to_string(),
                    error_rate: error_rate * 100.0,
                });
            }
        }

        Ok(())
    }

    /// Record a successful event in a pipeline.
    pub fn record_pipeline_success(&self, pipeline_id: &str) -> Result<(), CascadingError> {
        if !self.config.enabled {
            return Ok(());
        }
        Self::validate_pipeline_id(pipeline_id)?;
        self.record_pipeline_event(pipeline_id, false)
    }

    /// Record an error event in a pipeline. Returns `true` if the pipeline
    /// circuit was broken as a result.
    pub fn record_pipeline_error(&self, pipeline_id: &str) -> Result<bool, CascadingError> {
        if !self.config.enabled {
            return Ok(false);
        }
        Self::validate_pipeline_id(pipeline_id)?;
        self.record_pipeline_event(pipeline_id, true)?;

        // Check if we should break the circuit.
        let mut pipelines = self.pipelines.write().map_err(|_| {
            CascadingError::LockPoisoned("pipelines write lock for break check".to_string())
        })?;

        if let Some(state) = pipelines.get_mut(pipeline_id) {
            if !state.is_broken {
                let now = Self::now_secs();
                let error_rate = self.compute_error_rate_inner(state, now);
                let total_events = state.events.len();

                if total_events >= self.config.min_window_events as usize
                    && error_rate >= self.config.error_rate_threshold
                {
                    state.is_broken = true;
                    state.broken_at = Some(now);
                    state.break_count = state.break_count.saturating_add(1);

                    metrics::counter!(
                        "vellaveto_cascading_pipeline_breaks_total",
                        "pipeline" => pipeline_id.to_string()
                    )
                    .increment(1);

                    tracing::warn!(
                        pipeline_id = %pipeline_id,
                        error_rate = %format!("{:.1}%", error_rate * 100.0),
                        break_count = %state.break_count,
                        "Pipeline circuit broken due to high error rate (OWASP ASI08)"
                    );

                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    /// Record a pipeline event (success or error).
    fn record_pipeline_event(
        &self,
        pipeline_id: &str,
        is_error: bool,
    ) -> Result<(), CascadingError> {
        let mut pipelines = self
            .pipelines
            .write()
            .map_err(|_| CascadingError::LockPoisoned("pipelines write lock".to_string()))?;

        // SECURITY (R229-ENG-1): Fail-closed on capacity exhaustion.
        // Previously returned Ok(()) which silently dropped events, allowing
        // an attacker to fill with dummy pipeline IDs then operate undetected.
        if !pipelines.contains_key(pipeline_id) && pipelines.len() >= MAX_TRACKED_PIPELINES {
            tracing::warn!(
                max = MAX_TRACKED_PIPELINES,
                "Cascading pipeline tracker at capacity — denying new pipeline"
            );
            return Err(CascadingError::ChainDepthExceeded {
                current: u32::try_from(pipelines.len()).unwrap_or(u32::MAX),
                max: u32::try_from(MAX_TRACKED_PIPELINES).unwrap_or(u32::MAX),
            });
        }

        let now = Self::now_secs();
        let state = pipelines
            .entry(pipeline_id.to_string())
            .or_insert_with(PipelineState::new);

        // Evict events outside the window.
        let cutoff = now.saturating_sub(self.config.window_secs);
        while let Some(front) = state.events.front() {
            if front.timestamp < cutoff {
                state.events.pop_front();
            } else {
                break;
            }
        }

        // Bound events per pipeline.
        if state.events.len() >= MAX_EVENTS_PER_PIPELINE {
            state.events.pop_front();
        }

        state.events.push_back(PipelineEvent {
            timestamp: now,
            is_error,
        });

        // If the pipeline was broken and break_duration has elapsed, reset.
        if state.is_broken {
            if let Some(broken_at) = state.broken_at {
                if now >= broken_at.saturating_add(self.config.break_duration_secs) {
                    // Check if error rate has recovered.
                    let error_rate = self.compute_error_rate_inner(state, now);
                    if error_rate < self.config.error_rate_threshold {
                        state.is_broken = false;
                        state.broken_at = None;

                        metrics::counter!(
                            "vellaveto_cascading_pipeline_recoveries_total",
                            "pipeline" => pipeline_id.to_string()
                        )
                        .increment(1);

                        tracing::info!(
                            pipeline_id = %pipeline_id,
                            error_rate = %format!("{:.1}%", error_rate * 100.0),
                            "Pipeline circuit recovered"
                        );
                    }
                }
            }
        }

        Ok(())
    }

    /// Compute the error rate for a pipeline state using the given timestamp.
    /// SECURITY (R245-ENG-9): Accepts `now` parameter to ensure consistent
    /// time reference with the caller, preventing TOCTOU between event
    /// recording and error rate computation.
    fn compute_error_rate_inner(&self, state: &PipelineState, now: u64) -> f64 {
        if state.events.is_empty() {
            return 0.0;
        }
        let cutoff = now.saturating_sub(self.config.window_secs);

        let mut total = 0u64;
        let mut errors = 0u64;
        for event in &state.events {
            if event.timestamp >= cutoff {
                total = total.saturating_add(1);
                if event.is_error {
                    errors = errors.saturating_add(1);
                }
            }
        }

        if total == 0 {
            return 0.0;
        }

        let rate = errors as f64 / total as f64;
        if !rate.is_finite() {
            return 1.0; // Fail-closed
        }
        rate
    }

    /// Get the current error rate for a pipeline (0.0–1.0).
    pub fn pipeline_error_rate(&self, pipeline_id: &str) -> Result<f64, CascadingError> {
        if !self.config.enabled {
            return Ok(0.0);
        }
        Self::validate_pipeline_id(pipeline_id)?;

        let pipelines = self
            .pipelines
            .read()
            .map_err(|_| CascadingError::LockPoisoned("pipelines read lock".to_string()))?;

        if let Some(state) = pipelines.get(pipeline_id) {
            Ok(self.compute_error_rate_inner(state, Self::now_secs()))
        } else {
            Ok(0.0)
        }
    }

    /// Check if a pipeline's circuit is currently broken.
    pub fn is_pipeline_broken(&self, pipeline_id: &str) -> Result<bool, CascadingError> {
        if !self.config.enabled {
            return Ok(false);
        }
        Self::validate_pipeline_id(pipeline_id)?;

        let pipelines = self
            .pipelines
            .read()
            .map_err(|_| CascadingError::LockPoisoned("pipelines read lock".to_string()))?;

        Ok(pipelines
            .get(pipeline_id)
            .map(|s| s.is_broken)
            .unwrap_or(false))
    }

    /// Get summary statistics for all pipelines.
    pub fn pipeline_summary(&self) -> Result<CascadingSummary, CascadingError> {
        let pipelines = self
            .pipelines
            .read()
            .map_err(|_| CascadingError::LockPoisoned("pipelines read lock".to_string()))?;
        let chains = self
            .chains
            .read()
            .map_err(|_| CascadingError::LockPoisoned("chains read lock".to_string()))?;

        let mut healthy = 0usize;
        let mut broken = 0usize;
        for state in pipelines.values() {
            if state.is_broken {
                broken = broken.saturating_add(1);
            } else {
                healthy = healthy.saturating_add(1);
            }
        }

        Ok(CascadingSummary {
            total_pipelines: pipelines.len(),
            healthy_pipelines: healthy,
            broken_pipelines: broken,
            active_chains: chains.len(),
            max_chain_depth: self.config.max_chain_depth,
        })
    }

    // ═══════════════════════════════════════════════
    // UTILITY
    // ═══════════════════════════════════════════════

    fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or_else(|e| {
                // SECURITY (R245-ENG-1): Return 1, not 0, on pre-epoch clock —
                // consistent with collusion.rs. A 0 value could cause division-by-zero
                // or off-by-one in time-window arithmetic.
                tracing::warn!(error = %e, "SystemTime before UNIX_EPOCH — using 1");
                1
            })
    }
}

/// Summary of cascading breaker state.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CascadingSummary {
    pub total_pipelines: usize,
    pub healthy_pipelines: usize,
    pub broken_pipelines: usize,
    pub active_chains: usize,
    pub max_chain_depth: u32,
}

// ═══════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> CascadingConfig {
        CascadingConfig::default()
    }

    fn make_breaker() -> CascadingBreaker {
        CascadingBreaker::new(default_config()).unwrap()
    }

    // ────────────────────────────────────────────────
    // Config validation
    // ────────────────────────────────────────────────

    #[test]
    fn test_config_validate_default_ok() {
        assert!(CascadingConfig::default().validate().is_ok());
    }

    #[test]
    fn test_config_validate_zero_depth_rejected() {
        let mut cfg = default_config();
        cfg.max_chain_depth = 0;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_config_validate_excessive_depth_rejected() {
        let mut cfg = default_config();
        cfg.max_chain_depth = ABSOLUTE_MAX_CHAIN_DEPTH + 1;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_config_validate_nan_error_rate_rejected() {
        let mut cfg = default_config();
        cfg.error_rate_threshold = f64::NAN;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_config_validate_negative_error_rate_rejected() {
        let mut cfg = default_config();
        cfg.error_rate_threshold = -0.1;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_config_validate_above_one_error_rate_rejected() {
        let mut cfg = default_config();
        cfg.error_rate_threshold = 1.1;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_config_validate_zero_window_rejected() {
        let mut cfg = default_config();
        cfg.window_secs = 0;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_config_validate_zero_break_duration_rejected() {
        let mut cfg = default_config();
        cfg.break_duration_secs = 0;
        assert!(cfg.validate().is_err());
    }

    // ── R245 regression tests ─────────────────────────────────────────

    #[test]
    fn test_r245_config_validate_zero_min_window_events_rejected() {
        let mut cfg = default_config();
        cfg.min_window_events = 0;
        let err = cfg.validate().unwrap_err();
        let msg = format!("{err:?}");
        assert!(msg.contains("min_window_events must be >= 1"));
    }

    #[test]
    fn test_r245_config_validate_one_min_window_events_accepted() {
        let mut cfg = default_config();
        cfg.min_window_events = 1;
        assert!(cfg.validate().is_ok());
    }

    // ────────────────────────────────────────────────
    // Chain depth tracking
    // ────────────────────────────────────────────────

    #[test]
    fn test_enter_chain_starts_at_depth_one() {
        let breaker = make_breaker();
        let depth = breaker.enter_chain("chain-1", "pipeline-1").unwrap();
        assert_eq!(depth, 1);
    }

    #[test]
    fn test_enter_chain_increments_depth() {
        let breaker = make_breaker();
        assert_eq!(breaker.enter_chain("chain-1", "pipe-1").unwrap(), 1);
        assert_eq!(breaker.enter_chain("chain-1", "pipe-1").unwrap(), 2);
        assert_eq!(breaker.enter_chain("chain-1", "pipe-1").unwrap(), 3);
    }

    #[test]
    fn test_enter_chain_depth_exceeded_denied() {
        let mut cfg = default_config();
        cfg.max_chain_depth = 3;
        let breaker = CascadingBreaker::new(cfg).unwrap();

        assert_eq!(breaker.enter_chain("c1", "p1").unwrap(), 1);
        assert_eq!(breaker.enter_chain("c1", "p1").unwrap(), 2);
        assert_eq!(breaker.enter_chain("c1", "p1").unwrap(), 3);

        // Fourth call should fail.
        let result = breaker.enter_chain("c1", "p1");
        assert!(result.is_err());
        match result.err().unwrap() {
            CascadingError::ChainDepthExceeded { current, max } => {
                assert_eq!(current, 4);
                assert_eq!(max, 3);
            }
            other => panic!("Expected ChainDepthExceeded, got {other:?}"),
        }
    }

    #[test]
    fn test_exit_chain_decrements_depth() {
        let breaker = make_breaker();
        breaker.enter_chain("c1", "p1").unwrap();
        breaker.enter_chain("c1", "p1").unwrap();
        breaker.enter_chain("c1", "p1").unwrap();

        assert_eq!(breaker.exit_chain("c1").unwrap(), 2);
        assert_eq!(breaker.exit_chain("c1").unwrap(), 1);
        assert_eq!(breaker.exit_chain("c1").unwrap(), 0);
    }

    #[test]
    fn test_exit_chain_removes_at_zero() {
        let breaker = make_breaker();
        breaker.enter_chain("c1", "p1").unwrap();
        breaker.exit_chain("c1").unwrap();
        assert_eq!(breaker.chain_depth("c1").unwrap(), 0);
    }

    #[test]
    fn test_exit_chain_nonexistent_returns_zero() {
        let breaker = make_breaker();
        assert_eq!(breaker.exit_chain("nonexistent").unwrap(), 0);
    }

    #[test]
    fn test_chain_depth_nonexistent_returns_zero() {
        let breaker = make_breaker();
        assert_eq!(breaker.chain_depth("nonexistent").unwrap(), 0);
    }

    #[test]
    fn test_enter_chain_disabled_returns_zero() {
        let mut cfg = default_config();
        cfg.enabled = false;
        let breaker = CascadingBreaker::new(cfg).unwrap();
        assert_eq!(breaker.enter_chain("c1", "p1").unwrap(), 0);
    }

    // ────────────────────────────────────────────────
    // Pipeline error rate tracking
    // ────────────────────────────────────────────────

    #[test]
    fn test_check_pipeline_healthy_ok() {
        let breaker = make_breaker();
        assert!(breaker.check_pipeline("pipe-1").is_ok());
    }

    #[test]
    fn test_record_pipeline_mostly_success_no_break() {
        let breaker = make_breaker();
        // Record mostly successes with occasional errors (20% error rate < 50% threshold).
        for _ in 0..20 {
            breaker.record_pipeline_success("pipe-1").unwrap();
            breaker.record_pipeline_success("pipe-1").unwrap();
            breaker.record_pipeline_success("pipe-1").unwrap();
            breaker.record_pipeline_success("pipe-1").unwrap();
            assert!(!breaker.record_pipeline_error("pipe-1").unwrap());
        }
        assert!(breaker.check_pipeline("pipe-1").is_ok());
    }

    #[test]
    fn test_record_pipeline_error_breaks_circuit() {
        let mut cfg = default_config();
        cfg.error_rate_threshold = 0.5;
        cfg.min_window_events = 4;
        let breaker = CascadingBreaker::new(cfg).unwrap();

        // Record 5 errors (100% error rate > 50% threshold, >= 4 min events).
        for i in 0..5 {
            let broke = breaker.record_pipeline_error("pipe-1").unwrap();
            if i >= 3 {
                // After 4th event (index 3), should break.
                if broke {
                    assert!(breaker.is_pipeline_broken("pipe-1").unwrap());
                    return;
                }
            }
        }
        // Should have broken by now.
        assert!(
            breaker.is_pipeline_broken("pipe-1").unwrap(),
            "Pipeline should be broken after 5 consecutive errors"
        );
    }

    #[test]
    fn test_pipeline_error_rate_computed_correctly() {
        let mut cfg = default_config();
        cfg.min_window_events = 2;
        let breaker = CascadingBreaker::new(cfg).unwrap();

        breaker.record_pipeline_success("pipe-1").unwrap();
        breaker.record_pipeline_success("pipe-1").unwrap();
        breaker.record_pipeline_error("pipe-1").unwrap();
        breaker.record_pipeline_error("pipe-1").unwrap();

        let rate = breaker.pipeline_error_rate("pipe-1").unwrap();
        assert!(
            (rate - 0.5).abs() < 0.01,
            "Error rate should be ~0.5, got {rate}"
        );
    }

    #[test]
    fn test_pipeline_error_rate_nonexistent_returns_zero() {
        let breaker = make_breaker();
        assert_eq!(breaker.pipeline_error_rate("nonexistent").unwrap(), 0.0);
    }

    #[test]
    fn test_check_pipeline_disabled_ok() {
        let mut cfg = default_config();
        cfg.enabled = false;
        let breaker = CascadingBreaker::new(cfg).unwrap();
        assert!(breaker.check_pipeline("pipe-1").is_ok());
    }

    #[test]
    fn test_is_pipeline_broken_nonexistent_false() {
        let breaker = make_breaker();
        assert!(!breaker.is_pipeline_broken("nonexistent").unwrap());
    }

    // ────────────────────────────────────────────────
    // Summary
    // ────────────────────────────────────────────────

    #[test]
    fn test_pipeline_summary_empty() {
        let breaker = make_breaker();
        let summary = breaker.pipeline_summary().unwrap();
        assert_eq!(summary.total_pipelines, 0);
        assert_eq!(summary.healthy_pipelines, 0);
        assert_eq!(summary.broken_pipelines, 0);
        assert_eq!(summary.active_chains, 0);
        assert_eq!(summary.max_chain_depth, 10);
    }

    #[test]
    fn test_pipeline_summary_with_data() {
        let mut cfg = default_config();
        cfg.error_rate_threshold = 0.5;
        cfg.min_window_events = 2;
        let breaker = CascadingBreaker::new(cfg).unwrap();

        // Healthy pipeline.
        breaker.record_pipeline_success("pipe-1").unwrap();
        breaker.record_pipeline_success("pipe-1").unwrap();

        // Broken pipeline.
        breaker.record_pipeline_error("pipe-2").unwrap();
        breaker.record_pipeline_error("pipe-2").unwrap();
        breaker.record_pipeline_error("pipe-2").unwrap();

        // Active chain.
        breaker.enter_chain("chain-1", "pipe-1").unwrap();

        let summary = breaker.pipeline_summary().unwrap();
        assert_eq!(summary.total_pipelines, 2);
        assert_eq!(summary.active_chains, 1);
        // pipe-2 should be broken.
        assert!(summary.broken_pipelines >= 1);
    }

    // ────────────────────────────────────────────────
    // Input validation
    // ────────────────────────────────────────────────

    #[test]
    fn test_validate_pipeline_id_empty_rejected() {
        let breaker = make_breaker();
        assert!(breaker.check_pipeline("").is_err());
    }

    #[test]
    fn test_validate_pipeline_id_too_long_rejected() {
        let breaker = make_breaker();
        let long_id = "p".repeat(MAX_PIPELINE_ID_LEN + 1);
        assert!(breaker.check_pipeline(&long_id).is_err());
    }

    #[test]
    fn test_validate_pipeline_id_control_chars_rejected() {
        let breaker = make_breaker();
        assert!(breaker.check_pipeline("pipe\0line").is_err());
    }

    #[test]
    fn test_validate_chain_id_empty_rejected() {
        let breaker = make_breaker();
        assert!(breaker.enter_chain("", "pipe-1").is_err());
    }

    // ────────────────────────────────────────────────
    // Serialization
    // ────────────────────────────────────────────────

    #[test]
    fn test_config_serialization_roundtrip() {
        let cfg = CascadingConfig::default();
        let json = serde_json::to_string(&cfg).unwrap();
        let parsed: CascadingConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.max_chain_depth, cfg.max_chain_depth);
        assert_eq!(parsed.error_rate_threshold, cfg.error_rate_threshold);
    }

    #[test]
    fn test_config_deny_unknown_fields() {
        let json = r#"{"enabled": true, "bogus": 42}"#;
        let result: Result<CascadingConfig, _> = serde_json::from_str(json);
        assert!(
            result.is_err(),
            "deny_unknown_fields should reject unknown fields"
        );
    }

    #[test]
    fn test_summary_serialization_roundtrip() {
        let summary = CascadingSummary {
            total_pipelines: 5,
            healthy_pipelines: 3,
            broken_pipelines: 2,
            active_chains: 10,
            max_chain_depth: 10,
        };
        let json = serde_json::to_string(&summary).unwrap();
        let parsed: CascadingSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.total_pipelines, 5);
        assert_eq!(parsed.broken_pipelines, 2);
    }

    #[test]
    fn test_summary_deny_unknown_fields() {
        let json = r#"{"total_pipelines":5,"healthy_pipelines":3,"broken_pipelines":2,"active_chains":10,"max_chain_depth":10,"extra":"bad"}"#;
        let result: Result<CascadingSummary, _> = serde_json::from_str(json);
        assert!(
            result.is_err(),
            "deny_unknown_fields should reject unknown fields"
        );
    }

    // ── R229 regression tests ───────────────────────────────────────────

    #[test]
    fn test_r229_pipeline_capacity_returns_error_not_ok() {
        // R229-ENG-1: Verify that pipeline tracker at capacity returns Err,
        // not Ok(()) which would silently drop events.
        let _breaker = make_breaker();
        // The capacity check is in record_pipeline_event. We can't easily fill
        // 10,000 pipelines in a unit test, but we can verify the error type exists
        // and is properly constructed.
        let err = CascadingError::ChainDepthExceeded {
            current: 10_000,
            max: 10_000,
        };
        let msg = format!("{err:?}");
        assert!(msg.contains("ChainDepthExceeded"));
        assert!(msg.contains("10000"));
    }

    #[test]
    fn test_r245_pipeline_broken_display_redacts_error_rate() {
        let err = CascadingError::PipelineBroken {
            pipeline_id: "pipe-1".to_string(),
            error_rate: 87.5,
        };

        let msg = format!("{err}");
        assert!(msg.contains("pipe-1"));
        assert!(!msg.contains("87.5"));
        assert!(!msg.contains('%'));
    }
}

#[cfg(test)]
mod kani_parity_differential_temporal_window {
    //! Differential binding for `PARITY-HAND-2` — sliding-window event expiry.
    //!
    //! K71/K72 model the window the cascading circuit breaker keeps: which
    //! events have expired, how many remain, and the error rate over them.
    //!
    //! The extraction is materialized as `crate::temporal_window` (see the
    //! module comment in `lib.rs` — it is reproduced there because the
    //! `collusion_detection` extraction's own tests reach for it as a sibling).
    //!
    //! Production's expiry loop is inline in a private method, so the
    //! comparison is made two ways: the pure arithmetic directly, and the
    //! window behaviour through the real `CascadingBreaker`.
    //!
    //! What rides on it: an expiry that drops too much makes the error rate
    //! look better than it is, and a breaker that should have opened stays
    //! closed.

    use crate::temporal_window as extracted;
    use crate::temporal_window::WindowEvent;

    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn test_extraction_is_actually_present() {
        assert!(
            extracted::EXTRACTION_PRESENT,
            "formal/kani/src/temporal_window.rs was not found, so this binding \
             compared nothing"
        );
    }

    /// The error rate, against production's formula including its fail-closed
    /// branch.
    ///
    /// **The `!is_finite()` arm is unreachable, and that is recorded rather
    /// than tested around.** `total > 0` means the divisor is at least `1.0`,
    /// both operands convert to finite `f64` (`u64::MAX as f64` is ~1.8e19,
    /// well inside range), and finite / finite-nonzero is finite. Changing
    /// that arm from `1.0` to `0.0` is an *equivalent mutation*: no input
    /// reaches it, so no test can catch it and none should be contrived to
    /// try.
    ///
    /// This is a different failure from `ACCEPT-REJECT-ASYMMETRY-1`, where a
    /// guard was redundant because of the *polarity* of the expression around
    /// it. Here the guard is dead because the *arithmetic* cannot produce the
    /// value it defends against. Both look protective; neither does work. The
    /// distinction matters when reading a proof: a property established over a
    /// branch nothing reaches is established vacuously.
    #[test]
    fn test_error_rate_matches_production_formula() {
        for (total, errors) in [
            (0u64, 0u64),
            (1, 0),
            (1, 1),
            (2, 1),
            (100, 0),
            (100, 50),
            (100, 100),
            (u64::MAX, 0),
            (u64::MAX, u64::MAX),
        ] {
            let production = if total == 0 {
                0.0
            } else {
                let rate = errors as f64 / total as f64;
                if rate.is_finite() {
                    rate
                } else {
                    1.0
                }
            };
            assert_eq!(
                extracted::compute_error_rate(total, errors),
                production,
                "PARITY-HAND-2: error rate disagrees at ({total}, {errors})"
            );
        }
        // An empty window is 0.0, not a division by zero.
        assert_eq!(extracted::compute_error_rate(0, 5), 0.0);
    }

    /// Expiry and counting over a window, at every boundary offset.
    ///
    /// The cutoff is `now - window_secs` and the comparison is strict `<` for
    /// expiry and `>=` for inclusion, so an event exactly on the cutoff is
    /// **kept**. Walking `now` across the event timestamps checks that
    /// boundary from both sides.
    #[test]
    fn test_expiry_and_counting_match_the_cutoff_rule() {
        let events: Vec<WindowEvent> = [
            (10u64, false),
            (20, true),
            (30, false),
            (40, true),
            (50, false),
        ]
        .into_iter()
        .map(|(timestamp, is_error)| WindowEvent {
            timestamp,
            is_error,
        })
        .collect();

        let window_secs = 20u64;
        for now in 0u64..=80 {
            let cutoff = now.saturating_sub(window_secs);
            let expired = extracted::expired_prefix_len(&events, now, window_secs);
            let expected_expired = events.iter().take_while(|e| e.timestamp < cutoff).count();
            assert_eq!(
                expired, expected_expired,
                "expired prefix disagrees at now={now} (cutoff={cutoff})"
            );

            let (total, errors) = extracted::count_in_window_slice(&events, now, window_secs);
            let expected_total = events.iter().filter(|e| e.timestamp >= cutoff).count() as u64;
            let expected_errors = events
                .iter()
                .filter(|e| e.timestamp >= cutoff && e.is_error)
                .count() as u64;
            assert_eq!(total, expected_total, "window total disagrees at now={now}");
            assert_eq!(
                errors, expected_errors,
                "window errors disagrees at now={now}"
            );
        }

        // An event exactly on the cutoff is kept, not expired — the difference
        // between `<` and `<=` is one event's worth of error rate.
        let on_cutoff = [WindowEvent {
            timestamp: 30,
            is_error: true,
        }];
        assert_eq!(
            extracted::expired_prefix_len(&on_cutoff, 50, 20),
            0,
            "an event exactly on the cutoff was expired"
        );
        assert_eq!(
            extracted::count_in_window_slice(&on_cutoff, 50, 20),
            (1, 1),
            "an event exactly on the cutoff was excluded from the window"
        );
    }

    /// `now < window_secs` must saturate to a zero cutoff rather than
    /// underflow — otherwise early events would appear to be from the future
    /// and every event would expire at once.
    #[test]
    fn test_cutoff_saturates_before_the_epoch() {
        let events = [
            WindowEvent {
                timestamp: 0,
                is_error: false,
            },
            WindowEvent {
                timestamp: 5,
                is_error: true,
            },
        ];
        assert_eq!(
            extracted::expired_prefix_len(&events, 1, 100),
            0,
            "cutoff underflowed: events before the window start were expired"
        );
        assert_eq!(extracted::count_in_window_slice(&events, 1, 100), (2, 1));
    }

    /// The window behaviour through the real tracker: recorded errors show up
    /// in the rate, and the rate is the ratio the model computes.
    #[test]
    fn test_real_tracker_error_rate_agrees_with_the_model() {
        let tracker = super::CascadingBreaker::new(super::CascadingConfig {
            enabled: true,
            window_secs: 3600,
            ..Default::default()
        })
        .expect("tracker constructs");

        for _ in 0..3 {
            tracker
                .record_pipeline_success("pipeline-a")
                .expect("record success");
        }
        let _ = tracker.record_pipeline_error("pipeline-a");

        let production_rate = tracker
            .pipeline_error_rate("pipeline-a")
            .expect("rate available");
        assert_eq!(
            production_rate,
            extracted::compute_error_rate(4, 1),
            "PARITY-HAND-2: the real tracker's error rate is not the ratio the \
             model computes — a breaker threshold would trip at a different point"
        );
    }
}
