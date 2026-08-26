// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verified fixed-point entropy alert kernel.
//!
//! This module contains the integer-only decision logic used after the
//! float-to-fixed conversion in `entropy_gate.rs`. It is the intended Verus
//! proof boundary for the steganographic alert gate in `collusion.rs`.

/// Severity tier for repeated high-entropy observations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EntropyAlertLevel {
    Medium,
    High,
}

/// Return true when a fixed-point entropy observation is at or above the
/// configured fixed-point threshold.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn is_high_entropy_millibits(
    observation_millibits: u16,
    threshold_millibits: u16,
) -> bool {
    observation_millibits >= threshold_millibits
}

/// Return true when the high-entropy sample count reaches the configured alert
/// threshold.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn should_alert_on_high_entropy_count(
    high_entropy_count: u32,
    min_entropy_observations: u32,
) -> bool {
    high_entropy_count >= min_entropy_observations
}

/// Saturating double of the minimum alert threshold used for high severity.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn high_severity_entropy_threshold(min_entropy_observations: u32) -> u32 {
    if min_entropy_observations > u32::MAX / 2 {
        u32::MAX
    } else {
        min_entropy_observations * 2
    }
}

/// Compute the severity tier once the alert threshold has been reached.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn entropy_alert_level(
    high_entropy_count: u32,
    min_entropy_observations: u32,
) -> EntropyAlertLevel {
    if high_entropy_count >= high_severity_entropy_threshold(min_entropy_observations) {
        EntropyAlertLevel::High
    } else {
        EntropyAlertLevel::Medium
    }
}

/// Return the alert severity for the current high-entropy count, or `None`
/// when the alert threshold has not been reached.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn entropy_alert_severity(
    high_entropy_count: u32,
    min_entropy_observations: u32,
) -> Option<EntropyAlertLevel> {
    if should_alert_on_high_entropy_count(high_entropy_count, min_entropy_observations) {
        Some(entropy_alert_level(
            high_entropy_count,
            min_entropy_observations,
        ))
    } else {
        None
    }
}

#[cfg(test)]
mod verus_spec_differential {
    //! Differential binding for `PARITY-HAND-1` (see
    //! `formal/ASSUMPTION_REGISTRY.md`).
    //!
    //! Verus proves `exec == spec` for `formal/verus/verified_entropy_gate.rs`.
    //! The transcriptions below restate that `spec` and assert it agrees with
    //! the shipped function. Symbol parity cannot see this:
    //! `check-verus-parity.sh` greps for names.
    //!
    //! BOUNDED: operands are `u16` and `u32`. The boundary sets are built
    //! around the saturation point of the high-severity threshold
    //! (`min_entropy_observations * 2`, which the spec clamps rather than
    //! overflowing) and around zero, where a threshold of zero would make
    //! every observation alert.
    //!
    //! Keep each transcription in step with the kernel; if it drifts, the
    //! assumption returns silently.

    use super::*;

    fn spec_is_high_entropy_millibits(
        observation_millibits: u16,
        threshold_millibits: u16,
    ) -> bool {
        observation_millibits >= threshold_millibits
    }

    fn spec_should_alert_on_high_entropy_count(
        high_entropy_count: u32,
        min_entropy_observations: u32,
    ) -> bool {
        high_entropy_count >= min_entropy_observations
    }

    fn spec_high_severity_entropy_threshold(min_entropy_observations: u32) -> u32 {
        if min_entropy_observations > u32::MAX / 2 {
            u32::MAX
        } else {
            min_entropy_observations * 2
        }
    }

    fn spec_entropy_alert_level(
        high_entropy_count: u32,
        min_entropy_observations: u32,
    ) -> EntropyAlertLevel {
        if high_entropy_count >= spec_high_severity_entropy_threshold(min_entropy_observations) {
            EntropyAlertLevel::High
        } else {
            EntropyAlertLevel::Medium
        }
    }

    fn spec_entropy_alert_severity(
        high_entropy_count: u32,
        min_entropy_observations: u32,
    ) -> Option<EntropyAlertLevel> {
        if spec_should_alert_on_high_entropy_count(high_entropy_count, min_entropy_observations) {
            Some(spec_entropy_alert_level(
                high_entropy_count,
                min_entropy_observations,
            ))
        } else {
            None
        }
    }

    #[test]
    fn test_production_matches_verus_spec() {
        let bits = [0u16, 1, 2, 4_000, 8_000, u16::MAX - 1, u16::MAX];
        for &observation in &bits {
            for &threshold in &bits {
                assert_eq!(
                    is_high_entropy_millibits(observation, threshold),
                    spec_is_high_entropy_millibits(observation, threshold),
                    "PARITY-HAND-1: is_high_entropy_millibits disagrees at \
                     ({observation}, {threshold})"
                );
            }
        }

        let counts = [
            0u32,
            1,
            2,
            10,
            u32::MAX / 2 - 1,
            u32::MAX / 2,
            u32::MAX / 2 + 1,
            u32::MAX - 1,
            u32::MAX,
        ];
        for &count in &counts {
            assert_eq!(
                high_severity_entropy_threshold(count),
                spec_high_severity_entropy_threshold(count),
                "PARITY-HAND-1: high_severity_entropy_threshold disagrees at {count}"
            );
            for &min_obs in &counts {
                assert_eq!(
                    should_alert_on_high_entropy_count(count, min_obs),
                    spec_should_alert_on_high_entropy_count(count, min_obs),
                    "PARITY-HAND-1: should_alert_on_high_entropy_count disagrees at \
                     ({count}, {min_obs})"
                );
                assert_eq!(
                    entropy_alert_level(count, min_obs),
                    spec_entropy_alert_level(count, min_obs),
                    "PARITY-HAND-1: entropy_alert_level disagrees at ({count}, {min_obs})"
                );
                assert_eq!(
                    entropy_alert_severity(count, min_obs),
                    spec_entropy_alert_severity(count, min_obs),
                    "PARITY-HAND-1: entropy_alert_severity disagrees at ({count}, {min_obs})"
                );
            }
        }
    }

    // ── verified_entropy_pipeline ─────────────────────────────────────────
    //
    // A second kernel, `formal/verus/verified_entropy_pipeline.rs`, composes
    // these predicates into an alerting pipeline. Its `spec_should_alert` and
    // `spec_alert_severity` both carry a `min_observations > 0` guard that the
    // predicates in this module do NOT have — production enforces it earlier,
    // in `CollusionConfig::validate()`. See ENTROPY-CONFIG-1 in
    // `formal/ASSUMPTION_REGISTRY.md`.

    fn spec_pipeline_should_alert(count: u32, min_observations: u32) -> bool {
        min_observations > 0 && count >= min_observations
    }

    // The kernel keeps "config invalid" and "below the floor" as two branches
    // even though both yield no alert, because they are different reasons and
    // only the first is what ENTROPY-CONFIG-1 is about. Collapsing them, which
    // is what clippy suggests, would blur exactly the distinction being pinned.
    #[allow(clippy::if_same_then_else)]
    fn spec_pipeline_alert_severity(
        count: u32,
        min_observations: u32,
    ) -> Option<EntropyAlertLevel> {
        if min_observations == 0 {
            None
        } else if count < min_observations {
            None
        } else if count >= spec_high_severity_entropy_threshold(min_observations) {
            Some(EntropyAlertLevel::High)
        } else {
            Some(EntropyAlertLevel::Medium)
        }
    }

    /// For every validated configuration — `min_observations > 0` — the
    /// pipeline kernel and the shipped predicates agree.
    #[test]
    fn test_pipeline_matches_production_for_validated_configs() {
        let counts = [0u32, 1, 2, 3, 4, 10, u32::MAX / 2, u32::MAX - 1, u32::MAX];
        for &count in &counts {
            for &min_obs in &counts {
                if min_obs == 0 {
                    continue;
                }
                assert_eq!(
                    should_alert_on_high_entropy_count(count, min_obs),
                    spec_pipeline_should_alert(count, min_obs),
                    "PARITY-HAND-1: should_alert disagrees with the pipeline kernel at ({count}, {min_obs})"
                );
                assert_eq!(
                    entropy_alert_severity(count, min_obs),
                    spec_pipeline_alert_severity(count, min_obs),
                    "PARITY-HAND-1: entropy_alert_severity disagrees with the pipeline kernel at ({count}, {min_obs})"
                );
            }
        }
    }

    /// ENTROPY-CONFIG-1: pinned record of where the two diverge, and of the
    /// validation that makes the divergence unreachable.
    ///
    /// At `min_observations == 0` the pipeline kernel returns no alert, while
    /// the shipped predicates alert on every call — the flood R231-COLL-1
    /// fixed. Production closes it in `CollusionConfig::validate()`, not in the
    /// predicate, so the kernel's guarantee holds only for validated configs.
    /// Both halves are asserted here: the divergence, and the validation that
    /// makes it unreachable.
    #[test]
    fn test_pinned_zero_observation_divergence_and_its_guard() {
        // The divergence itself.
        assert!(
            should_alert_on_high_entropy_count(0, 0),
            "ENTROPY-CONFIG-1: the shipped predicate is expected to alert at zero"
        );
        assert!(
            !spec_pipeline_should_alert(0, 0),
            "ENTROPY-CONFIG-1: the pipeline kernel is expected to refuse at zero"
        );
        assert_eq!(
            spec_pipeline_alert_severity(5, 0),
            None,
            "ENTROPY-CONFIG-1: the pipeline kernel must produce no severity at zero"
        );
        assert!(
            entropy_alert_severity(5, 0).is_some(),
            "ENTROPY-CONFIG-1: the shipped predicate is expected to produce a severity at zero"
        );

        // The guard that makes it unreachable. If this stops rejecting zero,
        // the kernel's precondition is no longer established anywhere.
        let config = crate::collusion::CollusionConfig {
            min_entropy_observations: 0,
            ..Default::default()
        };
        let err = config
            .validate()
            .expect_err("ENTROPY-CONFIG-1: validate() must reject zero min_entropy_observations");
        assert!(
            format!("{err:?}").contains("min_entropy_observations"),
            "ENTROPY-CONFIG-1: validate() rejected zero but not for this reason: {err:?}"
        );
    }

    #[test]
    fn test_spec_oracle_can_reject() {
        // The doubled threshold must clamp rather than overflow.
        assert_eq!(spec_high_severity_entropy_threshold(u32::MAX), u32::MAX);
        assert_eq!(spec_high_severity_entropy_threshold(2), 4);
        // Below the observation floor there is no alert at all.
        assert_eq!(spec_entropy_alert_severity(1, 2), None);
        assert_eq!(
            spec_entropy_alert_severity(2, 2),
            Some(EntropyAlertLevel::Medium)
        );
        assert_eq!(
            spec_entropy_alert_severity(4, 2),
            Some(EntropyAlertLevel::High)
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_high_entropy_millibits() {
        assert!(is_high_entropy_millibits(6500, 6500));
        assert!(!is_high_entropy_millibits(6499, 6500));
    }

    #[test]
    fn test_should_alert_on_high_entropy_count() {
        assert!(!should_alert_on_high_entropy_count(2, 3));
        assert!(should_alert_on_high_entropy_count(3, 3));
    }

    #[test]
    fn test_high_severity_entropy_threshold() {
        assert_eq!(high_severity_entropy_threshold(3), 6);
        assert_eq!(high_severity_entropy_threshold(u32::MAX), u32::MAX);
    }

    #[test]
    fn test_entropy_alert_level() {
        assert_eq!(entropy_alert_level(3, 3), EntropyAlertLevel::Medium);
        assert_eq!(entropy_alert_level(6, 3), EntropyAlertLevel::High);
    }

    #[test]
    fn test_entropy_alert_severity() {
        assert_eq!(entropy_alert_severity(2, 3), None);
        assert_eq!(
            entropy_alert_severity(3, 3),
            Some(EntropyAlertLevel::Medium)
        );
        assert_eq!(entropy_alert_severity(6, 3), Some(EntropyAlertLevel::High));
    }
}
