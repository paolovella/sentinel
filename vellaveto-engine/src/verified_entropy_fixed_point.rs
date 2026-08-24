// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verified float-to-millibit conversion for entropy alert decisions.
//!
//! Extracted verbatim from `entropy_gate.rs` so that
//! `formal/verus/verified_entropy_fixed_point.rs` has a named production
//! counterpart to bind against. `entropy_gate` re-exports these, so callers are
//! unchanged.
//!
//! The kernel here proves *properties* (FP-WRAP-1..5) rather than an algorithm,
//! and those properties rest on the trusted float axioms FLOAT-CONV-1..4 in
//! `formal/ASSUMPTION_REGISTRY.md`. The binding below is correspondingly a
//! property discharge, not a spec transcription.

/// Fixed-point scale for entropy alert decisions (1/1000 bit precision).
pub(crate) const ENTROPY_DECISION_SCALE: u16 = 1000;
/// Maximum Shannon entropy for byte data, scaled to millibits.
pub(crate) const MAX_ENTROPY_DECISION_MILLIBITS: u16 = 8 * ENTROPY_DECISION_SCALE;

/// Convert an entropy value in bits/byte to a millibit decision score.
///
/// Non-finite input yields 0, the fail-safe default. `round_up` selects the
/// conservative direction: observations round up, thresholds round down, so the
/// integer comparison never produces a false negative.
pub(crate) fn entropy_fixed_point(bits_per_byte: f64, round_up: bool) -> u16 {
    if !bits_per_byte.is_finite() {
        return 0;
    }

    let clamped = bits_per_byte.clamp(0.0, 8.0);
    let scaled = clamped * f64::from(ENTROPY_DECISION_SCALE);
    let rounded = if round_up {
        scaled.ceil()
    } else {
        scaled.floor()
    };

    if rounded <= 0.0 {
        0
    } else if rounded >= f64::from(MAX_ENTROPY_DECISION_MILLIBITS) {
        MAX_ENTROPY_DECISION_MILLIBITS
    } else {
        rounded as u16
    }
}

/// Convert a configured entropy threshold into the conservative decision score.
pub(crate) fn entropy_threshold_millibits(threshold_bits: f64) -> u16 {
    entropy_fixed_point(threshold_bits, false)
}

/// Convert an observed entropy value into the conservative decision score.
pub(crate) fn entropy_observation_millibits(bits_per_byte: f64) -> u16 {
    entropy_fixed_point(bits_per_byte, true)
}

#[cfg(test)]
mod verus_spec_differential {
    //! Differential binding for `PARITY-HAND-1` (see
    //! `formal/ASSUMPTION_REGISTRY.md`).
    //!
    //! PROPERTY discharge, not a spec transcription. The kernel
    //! `formal/verus/verified_entropy_fixed_point.rs` proves five properties of
    //! this conversion rather than an algorithm it equals, so there is no
    //! `spec` function to restate. Each property below is checked directly
    //! against the shipped function over a float sample chosen to reach every
    //! branch: non-finite inputs, both clamp edges, the rounding boundary, and
    //! ordinary values in between.
    //!
    //! This binds the properties to shipped behaviour. It does **not** discharge
    //! the trusted float axioms FLOAT-CONV-1..4 those proofs rest on; those
    //! remain in the registry.

    use super::*;

    /// Values chosen against the branches: non-finite, below and at the lower
    /// clamp, either side of the rounding boundary, at and above the upper
    /// clamp, and subnormals.
    fn sample() -> Vec<f64> {
        vec![
            f64::NAN,
            f64::INFINITY,
            f64::NEG_INFINITY,
            f64::MIN,
            -1.0e12,
            -1.0,
            -f64::MIN_POSITIVE,
            -0.0,
            0.0,
            f64::MIN_POSITIVE,
            0.0004,
            0.0005,
            0.001,
            1.0,
            6.4991,
            6.5,
            6.9999,
            7.0,
            7.9995,
            7.9999,
            8.0,
            8.0001,
            1.0e12,
            f64::MAX,
        ]
    }

    /// FP-WRAP-1: both conversions land in `[0, MAX_ENTROPY_DECISION_MILLIBITS]`.
    ///
    /// Two guards enforce this jointly — the `clamp(0.0, 8.0)` and the
    /// `rounded >= MAX` branch — and removing *either alone* is an equivalent
    /// mutant, not a defect: with the clamp in place `rounded` never exceeds
    /// 8000.0, so the branch only fires where the cast would give 8000 anyway.
    /// Mutation-testing this property therefore has to remove both; doing so
    /// fails here at `8.0001 -> 8001`.
    #[test]
    fn test_output_is_always_within_millibit_bounds() {
        for value in sample() {
            for round_up in [false, true] {
                let out = entropy_fixed_point(value, round_up);
                assert!(
                    out <= MAX_ENTROPY_DECISION_MILLIBITS,
                    "PARITY-HAND-1 (FP-WRAP-1): {value} round_up={round_up} produced {out}, \
                     above MAX_ENTROPY_DECISION_MILLIBITS"
                );
            }
        }
    }

    /// FP-WRAP-2: non-finite input is the fail-safe zero.
    #[test]
    fn test_non_finite_input_is_zero() {
        for value in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            for round_up in [false, true] {
                assert_eq!(
                    entropy_fixed_point(value, round_up),
                    0,
                    "PARITY-HAND-1 (FP-WRAP-2): non-finite {value} must convert to 0"
                );
            }
        }
    }

    /// FP-WRAP-3: for the same input, the threshold (floor) never exceeds the
    /// observation (ceil).
    #[test]
    fn test_threshold_never_exceeds_observation_for_same_input() {
        for value in sample() {
            let threshold = entropy_fixed_point(value, false);
            let observation = entropy_fixed_point(value, true);
            assert!(
                threshold <= observation,
                "PARITY-HAND-1 (FP-WRAP-3): {value} gave threshold={threshold} > \
                 observation={observation}"
            );
        }
    }

    /// FP-WRAP-4: no false negatives. If the float comparison says the actual
    /// entropy is at or above the threshold, the millibit comparison must agree.
    #[test]
    fn test_no_false_negative_across_the_sample() {
        for actual in sample() {
            for threshold in sample() {
                if !actual.is_finite() || !threshold.is_finite() || actual < threshold {
                    continue;
                }
                let observation = entropy_observation_millibits(actual);
                let threshold_mb = entropy_threshold_millibits(threshold);
                assert!(
                    observation >= threshold_mb,
                    "PARITY-HAND-1 (FP-WRAP-4): actual={actual} >= threshold={threshold} in the \
                     float domain, but observation={observation} < threshold={threshold_mb} in \
                     millibits — a false negative"
                );
            }
        }
    }

    /// FP-WRAP-5: observations satisfy the millibit-valid precondition the
    /// entropy pipeline (EPIPE-1) depends on.
    #[test]
    fn test_observations_satisfy_millibit_valid_precondition() {
        for value in sample() {
            let observation = entropy_observation_millibits(value);
            assert!(
                observation <= MAX_ENTROPY_DECISION_MILLIBITS,
                "PARITY-HAND-1 (FP-WRAP-5): observation {observation} for {value} breaks the \
                 EPIPE-1 precondition"
            );
        }
    }

    #[test]
    fn test_properties_can_reject() {
        // The properties are only meaningful if the rounding directions are
        // genuinely different and the clamps genuinely bite.
        assert_eq!(entropy_threshold_millibits(6.4991), 6499);
        assert_eq!(entropy_observation_millibits(6.4991), 6500);
        assert_eq!(
            entropy_observation_millibits(1.0e12),
            MAX_ENTROPY_DECISION_MILLIBITS
        );
        assert_eq!(entropy_observation_millibits(-1.0), 0);
    }
}
