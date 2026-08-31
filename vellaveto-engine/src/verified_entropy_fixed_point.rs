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

#[cfg(test)]
// Suppressed rather than satisfied: linting the extraction would edit the copy
// the Kani proofs run against.
#[allow(
    clippy::approx_constant,
    clippy::manual_range_contains,
    dead_code,
    unused_imports
)]
mod kani_entropy_wrapper_extraction {
    include!(concat!(
        env!("OUT_DIR"),
        "/kani_entropy_wrapper_extraction.rs"
    ));
}

#[cfg(test)]
mod kani_parity_differential_entropy_wrapper {
    //! Differential binding for `PARITY-HAND-2` — entropy float-to-fixed-point.
    //!
    //! The **third closed triangle**. This mirror was extracted during the
    //! Verus campaign so `verified_entropy_pipeline` could be bound to
    //! something reachable; the Kani extraction (K86-K88) proved its own copy
    //! of the same conversion and was connected to nothing. Both now meet on
    //! this function.
    //!
    //! What rides on it: the Verus kernel proves the alert gate over *integers*
    //! and assumes a faithful float-to-fixed conversion feeding it. If this
    //! conversion disagrees between the two, the integer proof is about
    //! observations that never occur — a threshold comparison off by a
    //! millibit decides whether an entropy alert fires.

    use super::kani_entropy_wrapper_extraction as extracted;
    use super::{entropy_fixed_point, entropy_observation_millibits, entropy_threshold_millibits};

    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn test_extraction_is_actually_present() {
        assert!(
            extracted::EXTRACTION_PRESENT,
            "formal/kani/src/entropy_wrapper.rs was not found, so this binding \
             compared nothing"
        );
    }

    /// The scale constants, pinned on both sides independently.
    #[test]
    fn test_scale_constants_match() {
        assert_eq!(extracted::ENTROPY_DECISION_SCALE, 1000);
        assert_eq!(extracted::MAX_ENTROPY_DECISION_MILLIBITS, 8000);
        // Production's bound, reached through the function rather than the
        // constant, so a change to either side is visible.
        assert_eq!(entropy_fixed_point(8.0, false), 8000);
        assert_eq!(entropy_fixed_point(0.0, false), 0);
    }

    /// A dense sweep across the whole representable range plus the values that
    /// break naive conversions.
    ///
    /// The rounding boundary is where a millibit is won or lost, so the sweep
    /// steps finely enough to land on and between them, in **both** rounding
    /// directions.
    #[test]
    fn test_conversion_matches_production_across_the_range() {
        let mut checked = 0usize;
        // 0.000 to 8.100 in thousandths — past the clamp on purpose.
        for milli in 0..=8_100u32 {
            let bits = f64::from(milli) / 1000.0;
            for round_up in [false, true] {
                assert_eq!(
                    extracted::entropy_fixed_point(bits, round_up),
                    entropy_fixed_point(bits, round_up),
                    "PARITY-HAND-2: fixed-point conversion disagrees at \
                     {bits} bits/byte (round_up={round_up})"
                );
                checked += 1;
            }
        }
        assert_eq!(checked, 8_101 * 2, "sweep collapsed");
    }

    /// The values a float conversion is most likely to mishandle.
    #[test]
    fn test_non_finite_and_out_of_range_match_production() {
        const HOSTILE: [f64; 10] = [
            f64::NAN,
            f64::INFINITY,
            f64::NEG_INFINITY,
            -0.0,
            -1.0,
            -1e300,
            8.0,
            8.000_1,
            1e300,
            f64::MIN_POSITIVE,
        ];
        for bits in HOSTILE {
            for round_up in [false, true] {
                assert_eq!(
                    extracted::entropy_fixed_point(bits, round_up),
                    entropy_fixed_point(bits, round_up),
                    "PARITY-HAND-2: conversion disagrees for {bits:?} \
                     (round_up={round_up})"
                );
            }
        }
        // K87: non-finite input converts to 0, never to a large value that
        // would clear an entropy threshold.
        for bad in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            assert_eq!(
                entropy_fixed_point(bad, false),
                0,
                "K87: a non-finite entropy observation did not convert to 0"
            );
            assert_eq!(entropy_fixed_point(bad, true), 0);
        }
        // K86: the output is bounded, so no observation can exceed the maximum
        // the integer gate is proved over.
        for bits in HOSTILE {
            assert!(
                entropy_fixed_point(bits, true) <= 8000,
                "K86: conversion of {bits:?} exceeded MAX_ENTROPY_DECISION_MILLIBITS"
            );
        }
    }

    /// Two mutations of this conversion are **equivalent**, verified rather
    /// than assumed, and recorded so nobody writes a contrived test chasing
    /// them.
    ///
    /// The upper bound is enforced *twice* — by `clamp(0.0, 8.0)` on the input
    /// and by the `rounded >= MAX` branch on the output — so removing either
    /// alone changes no result. Widening the clamp to `9.0` still hits the
    /// output branch; weakening `>=` to `>` is unreachable because
    /// `scaled <= 8.0 * 1000` means `rounded` never exceeds `MAX`.
    ///
    /// This is `FP-WRAP-1`, predicted earlier in this campaign: a value bounded
    /// by two independent mechanisms cannot be mutation-tested one mechanism at
    /// a time. Removing *both* is caught; that is the test worth having, and it
    /// is what `test_non_finite_and_out_of_range_match_production` performs by
    /// asserting the output bound directly.
    #[test]
    fn test_the_upper_bound_is_enforced_twice() {
        // Neither mechanism alone is observable, so assert the property they
        // jointly guarantee instead of either mechanism.
        for bits in [8.0, 8.000_1, 8.5, 9.0, 1e300, f64::INFINITY] {
            for round_up in [false, true] {
                assert!(
                    entropy_fixed_point(bits, round_up) <= 8000,
                    "the output bound was exceeded for {bits:?}"
                );
            }
        }
        // And the bound is actually reached, so the assertion is not vacuous.
        assert_eq!(entropy_fixed_point(8.0, false), 8000);
        assert_eq!(entropy_fixed_point(9.0, true), 8000);
    }

    /// The two directional wrappers, which decide the *side* of a threshold
    /// comparison an observation lands on.
    ///
    /// The rounding runs the way a **detector** needs, which is the opposite of
    /// what "conservative" suggests if you read it as an access decision: the
    /// threshold rounds **down** (`round_up = false`) and the observation
    /// rounds **up** (`round_up = true`). So a borderline observation *does*
    /// clear a borderline threshold, and the gate errs toward firing.
    ///
    /// That is fail-closed here — a missed high-entropy observation is missed
    /// exfiltration, so the safe error is a false alert rather than a false
    /// silence. Swapping the two directions would flip that, and the resulting
    /// off-by-one-millibit is exactly the gap an exfiltration payload sits in.
    #[test]
    fn test_directional_wrappers_match_production() {
        for milli in 0..=8_100u32 {
            let bits = f64::from(milli) / 1000.0;
            assert_eq!(
                extracted::entropy_threshold_millibits(bits),
                entropy_threshold_millibits(bits),
                "PARITY-HAND-2: threshold conversion disagrees at {bits}"
            );
            assert_eq!(
                extracted::entropy_observation_millibits(bits),
                entropy_observation_millibits(bits),
                "PARITY-HAND-2: observation conversion disagrees at {bits}"
            );
        }
        // The asymmetry itself, at a value that is not exactly representable:
        // 6.5005 bits scales to 6500.5 millibits, so the threshold floors to
        // 6500 and the observation ceils to 6501.
        let borderline = 6.500_5;
        assert_eq!(entropy_threshold_millibits(borderline), 6500);
        assert_eq!(entropy_observation_millibits(borderline), 6501);
        assert!(
            entropy_observation_millibits(borderline) >= entropy_threshold_millibits(borderline),
            "the observation must never round below the threshold, or a \
             high-entropy payload sitting between two millibits goes undetected"
        );
        // And the direction holds across the range, not just at one point.
        for milli in 0..=8_000u32 {
            let bits = f64::from(milli) / 1000.0 + 0.000_5;
            assert!(
                entropy_observation_millibits(bits) >= entropy_threshold_millibits(bits),
                "rounding direction inverted at {bits} bits/byte"
            );
        }
    }
}
