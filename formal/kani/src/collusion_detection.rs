// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Collusion detection invariant verification.
//!
//! Extracts and verifies security-critical properties of the collusion
//! detection subsystem from `vellaveto-engine/src/collusion.rs`.
//!
//! # Verified Properties (K98-K102)
//!
//! | ID   | Property |
//! |------|----------|
//! | K98  | Configuration validation rejects NaN/Infinity on all f64 fields |
//! | K99  | Configuration validation rejects out-of-range values |
//! | K100 | Capacity exhaustion produces alert (never silent skip) |
//! | K101 | Error rate computation is always in [0.0, 1.0] and fail-closed |
//! | K102 | Denial rate half-open interval: no double-counting at boundaries |
//!
//! # Production Correspondence
//!
//! - Configuration validation ↔ `collusion.rs:CollusionConfig::validate()`
//! - Capacity exhaustion ↔ `collusion.rs:analyze_parameters()`, `record_resource_access()`
//! - Error rate ↔ `temporal_window.rs:compute_error_rate()`
//! - Denial rate ↔ `collusion.rs:check_agent_drift()` half-open window

/// Maximum tracked agents before capacity alert.
pub const MAX_TRACKED_AGENTS: usize = 10_000;

/// Configuration for collusion detection (mirrors production).
#[derive(Debug, Clone)]
pub struct CollusionConfig {
    pub coordination_window_secs: u64,
    pub entropy_threshold: f64,
    pub sync_threshold: f64,
    pub min_entropy_observations: u32,
    pub min_coordinated_agents: u32,
    pub recon_denial_threshold: u32,
    pub recon_window_secs: u64,
    pub drift_threshold: f64,
    pub drift_window_secs: u64,
    pub drift_min_actions: u32,
}

impl Default for CollusionConfig {
    fn default() -> Self {
        Self {
            coordination_window_secs: 60,
            entropy_threshold: 6.5,
            sync_threshold: 0.7,
            min_entropy_observations: 5,
            min_coordinated_agents: 3,
            recon_denial_threshold: 10,
            recon_window_secs: 60,
            drift_threshold: 0.20,
            drift_window_secs: 3600,
            drift_min_actions: 20,
        }
    }
}

/// Validation errors.
#[derive(Debug)]
pub enum ConfigError {
    InvalidField(String),
}

impl CollusionConfig {
    /// Validate configuration fields.
    /// Mirrors production `CollusionConfig::validate()`.
    pub fn validate(&self) -> Result<(), ConfigError> {
        // R231-COLL-1: min_entropy_observations must be > 0
        if self.min_entropy_observations == 0 {
            return Err(ConfigError::InvalidField(
                "min_entropy_observations must be > 0".into(),
            ));
        }

        // Trap #4: NaN/Infinity on f64 fields
        if !self.entropy_threshold.is_finite() {
            return Err(ConfigError::InvalidField("entropy_threshold not finite".into()));
        }
        if !self.sync_threshold.is_finite() {
            return Err(ConfigError::InvalidField("sync_threshold not finite".into()));
        }
        if !self.drift_threshold.is_finite() {
            return Err(ConfigError::InvalidField("drift_threshold not finite".into()));
        }

        // Range bounds
        if self.entropy_threshold < 0.0 || self.entropy_threshold > 8.0 {
            return Err(ConfigError::InvalidField("entropy_threshold out of [0, 8]".into()));
        }
        if self.sync_threshold < 0.0 || self.sync_threshold > 1.0 {
            return Err(ConfigError::InvalidField("sync_threshold out of [0, 1]".into()));
        }
        if self.drift_threshold < 0.0 || self.drift_threshold > 1.0 {
            return Err(ConfigError::InvalidField("drift_threshold out of [0, 1]".into()));
        }

        // Window bounds
        if self.coordination_window_secs < 1 || self.coordination_window_secs > 86_400 {
            return Err(ConfigError::InvalidField(
                "coordination_window_secs out of [1, 86400]".into(),
            ));
        }
        if self.recon_window_secs < 1 || self.recon_window_secs > 3_600 {
            return Err(ConfigError::InvalidField(
                "recon_window_secs out of [1, 3600]".into(),
            ));
        }
        if self.drift_window_secs < 1 || self.drift_window_secs > 604_800 {
            return Err(ConfigError::InvalidField(
                "drift_window_secs out of [1, 604800]".into(),
            ));
        }

        if self.recon_denial_threshold == 0 {
            return Err(ConfigError::InvalidField(
                "recon_denial_threshold must be > 0".into(),
            ));
        }

        // KANI-COLLUSION-GAPS-1: these two were missing from the model while it
        // claimed to mirror production's validate(). Collusion by definition
        // needs at least two agents — `min_coordinated_agents < 2` would make
        // a single agent "coordinated" with itself — and a zero
        // `drift_min_actions` divides detection by an empty action set.
        if self.min_coordinated_agents < 2 {
            return Err(ConfigError::InvalidField(
                "min_coordinated_agents must be >= 2".into(),
            ));
        }
        if self.drift_min_actions == 0 {
            return Err(ConfigError::InvalidField(
                "drift_min_actions must be > 0".into(),
            ));
        }

        Ok(())
    }
}

/// Capacity check: returns true if capacity exhausted (should alert).
/// Mirrors the fail-closed check in analyze_parameters/record_resource_access.
pub fn is_capacity_exhausted(current_count: usize, max_count: usize) -> bool {
    current_count >= max_count
}

/// Denial rate computation using half-open interval.
/// Mirrors production: `ts >= window_start && ts < window_end`.
pub fn denial_rate_half_open(
    actions: &[(u64, bool)], // (timestamp, is_denial)
    window_start: u64,
    window_end: u64,
) -> Option<f64> {
    let mut total = 0u64;
    let mut denials = 0u64;

    for &(ts, denied) in actions {
        if ts >= window_start && ts < window_end {
            total = total.saturating_add(1);
            if denied {
                denials = denials.saturating_add(1);
            }
        }
    }

    if total == 0 {
        return None; // Not enough data
    }

    let rate = denials as f64 / total as f64;
    if !rate.is_finite() {
        Some(1.0) // Fail-closed
    } else {
        Some(rate)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── K98: NaN/Infinity rejection ────────────────────────────────────

    #[test]
    fn test_k98_nan_rejected() {
        let mut config = CollusionConfig::default();

        config.entropy_threshold = f64::NAN;
        assert!(config.validate().is_err(), "NaN entropy_threshold");

        config.entropy_threshold = 6.5; // reset
        config.sync_threshold = f64::NAN;
        assert!(config.validate().is_err(), "NaN sync_threshold");

        config.sync_threshold = 0.7; // reset
        config.drift_threshold = f64::NAN;
        assert!(config.validate().is_err(), "NaN drift_threshold");
    }

    #[test]
    fn test_k98_infinity_rejected() {
        let mut config = CollusionConfig::default();

        config.entropy_threshold = f64::INFINITY;
        assert!(config.validate().is_err(), "Inf entropy_threshold");

        config.entropy_threshold = f64::NEG_INFINITY;
        assert!(config.validate().is_err(), "NegInf entropy_threshold");

        config.entropy_threshold = 6.5;
        config.sync_threshold = f64::INFINITY;
        assert!(config.validate().is_err(), "Inf sync_threshold");

        config.sync_threshold = 0.7;
        config.drift_threshold = f64::INFINITY;
        assert!(config.validate().is_err(), "Inf drift_threshold");
    }

    // ── K99: Out-of-range rejection ────────────────────────────────────

    #[test]
    fn test_k99_entropy_range() {
        let mut config = CollusionConfig::default();

        config.entropy_threshold = -0.1;
        assert!(config.validate().is_err(), "entropy < 0");

        config.entropy_threshold = 8.1;
        assert!(config.validate().is_err(), "entropy > 8");

        config.entropy_threshold = 0.0;
        assert!(config.validate().is_ok(), "entropy = 0 valid");

        config.entropy_threshold = 8.0;
        assert!(config.validate().is_ok(), "entropy = 8 valid");
    }

    #[test]
    fn test_k99_score_range() {
        let mut config = CollusionConfig::default();

        config.sync_threshold = -0.1;
        assert!(config.validate().is_err(), "sync < 0");

        config.sync_threshold = 1.1;
        assert!(config.validate().is_err(), "sync > 1");

        config.sync_threshold = 0.7;
        config.drift_threshold = -0.1;
        assert!(config.validate().is_err(), "drift < 0");

        config.drift_threshold = 1.1;
        assert!(config.validate().is_err(), "drift > 1");
    }

    #[test]
    fn test_k99_window_bounds() {
        let mut config = CollusionConfig::default();

        config.coordination_window_secs = 0;
        assert!(config.validate().is_err(), "coordination = 0");

        config.coordination_window_secs = 86_401;
        assert!(config.validate().is_err(), "coordination > 86400");

        config.coordination_window_secs = 60;
        config.recon_window_secs = 0;
        assert!(config.validate().is_err(), "recon = 0");

        config.recon_window_secs = 60;
        config.drift_window_secs = 0;
        assert!(config.validate().is_err(), "drift = 0");
    }

    #[test]
    fn test_k99_min_entropy_observations_zero() {
        let mut config = CollusionConfig::default();
        config.min_entropy_observations = 0;
        assert!(config.validate().is_err(), "R231-COLL-1: 0 observations rejected");
    }

    #[test]
    fn test_k99_recon_threshold_zero() {
        let mut config = CollusionConfig::default();
        config.recon_denial_threshold = 0;
        assert!(config.validate().is_err(), "0 recon threshold rejected");
    }

    #[test]
    fn test_k99_valid_default() {
        let config = CollusionConfig::default();
        assert!(config.validate().is_ok(), "default config should be valid");
    }

    // ── K100: Capacity exhaustion produces alert ───────────────────────

    #[test]
    fn test_k100_capacity_exhausted() {
        assert!(is_capacity_exhausted(MAX_TRACKED_AGENTS, MAX_TRACKED_AGENTS));
        assert!(is_capacity_exhausted(MAX_TRACKED_AGENTS + 1, MAX_TRACKED_AGENTS));
    }

    #[test]
    fn test_k100_capacity_not_exhausted() {
        assert!(!is_capacity_exhausted(0, MAX_TRACKED_AGENTS));
        assert!(!is_capacity_exhausted(MAX_TRACKED_AGENTS - 1, MAX_TRACKED_AGENTS));
    }

    // ── K101: Error rate always [0, 1] and fail-closed ─────────────────

    #[test]
    fn test_k101_error_rate_bounded() {
        use crate::temporal_window::compute_error_rate;

        // Exhaustive for small values
        for total in 0..=50u64 {
            for errors in 0..=total {
                let rate = compute_error_rate(total, errors);
                assert!(rate >= 0.0, "rate < 0 for total={total}, errors={errors}");
                assert!(rate <= 1.0, "rate > 1 for total={total}, errors={errors}");
                assert!(rate.is_finite(), "rate not finite for total={total}, errors={errors}");
            }
        }
    }

    #[test]
    fn test_k101_error_rate_fail_closed_zero_total() {
        use crate::temporal_window::compute_error_rate;
        // Zero total returns 0.0 (no events = no error)
        assert_eq!(compute_error_rate(0, 0), 0.0);
    }

    // ── K102: Denial rate half-open interval ───────────────────────────

    #[test]
    fn test_k102_boundary_included() {
        let actions = vec![(100, true)]; // Action at exactly window_start
        let rate = denial_rate_half_open(&actions, 100, 200);
        assert_eq!(rate, Some(1.0), "Event at window_start should be included");
    }

    #[test]
    fn test_k102_boundary_excluded() {
        let actions = vec![(200, true)]; // Action at exactly window_end
        let rate = denial_rate_half_open(&actions, 100, 200);
        assert_eq!(rate, None, "Event at window_end should be excluded (half-open)");
    }

    #[test]
    fn test_k102_no_double_counting() {
        // Events at boundaries of adjacent windows
        let actions = vec![
            (99, true),  // Before window
            (100, true), // Start of window (included)
            (150, false), // Middle (included)
            (199, true), // End - 1 (included)
            (200, true), // End (excluded)
        ];
        let rate = denial_rate_half_open(&actions, 100, 200);
        // Included: 100 (denial), 150 (not denial), 199 (denial) = 3 total, 2 denials
        assert_eq!(rate, Some(2.0 / 3.0));
    }

    #[test]
    fn test_k102_empty_window() {
        let actions: Vec<(u64, bool)> = vec![];
        let rate = denial_rate_half_open(&actions, 100, 200);
        assert_eq!(rate, None, "Empty window should return None");
    }

    #[test]
    fn test_k102_all_outside_window() {
        let actions = vec![(50, true), (250, true)];
        let rate = denial_rate_half_open(&actions, 100, 200);
        assert_eq!(rate, None, "All events outside window should return None");
    }
}
