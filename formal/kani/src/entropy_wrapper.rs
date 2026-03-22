// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Entropy float-to-fixed-point wrapper verification.
//!
//! Extracts and verifies the `entropy_fixed_point()` conversion from
//! `vellaveto-engine/src/entropy_gate.rs`. The Verus kernel proves the
//! integer-only alert gating; this module proves the float-to-fixed
//! wrapper that feeds it.
//!
//! # Verified Properties (K86-K90)
//!
//! | ID  | Property |
//! |-----|----------|
//! | K86 | Output always in [0, 8000] (no u16 overflow) |
//! | K87 | NaN and Infinity map to 0 (fail-safe) |
//! | K88 | Negative values map to 0 (clamped) |
//! | K89 | Monotonicity: a <= b implies f(a) <= f(b) for finite a, b in [0, 8] |
//! | K90 | Ceil >= Floor for same input (conservative direction) |
//!
//! # Production Correspondence
//!
//! - `entropy_fixed_point()` ↔ `vellaveto-engine/src/entropy_gate.rs:24-44`
//! - `entropy_threshold_millibits()` ↔ `entropy_gate.rs:47-49` (floor)
//! - `entropy_observation_millibits()` ↔ `entropy_gate.rs:52-54` (ceil)

/// Fixed-point scale: 1/1000 bit precision.
pub const ENTROPY_DECISION_SCALE: u16 = 1000;
/// Maximum: 8 bits per byte * 1000 = 8000 millibits.
pub const MAX_ENTROPY_DECISION_MILLIBITS: u16 = 8 * ENTROPY_DECISION_SCALE;

/// Convert floating-point entropy (bits/byte) to fixed-point millibits.
///
/// Verbatim from `vellaveto-engine/src/entropy_gate.rs:24-44`.
pub fn entropy_fixed_point(bits_per_byte: f64, round_up: bool) -> u16 {
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

/// Threshold conversion (floor — conservative for thresholds).
pub fn entropy_threshold_millibits(threshold_bits: f64) -> u16 {
    entropy_fixed_point(threshold_bits, false)
}

/// Observation conversion (ceil — conservative for observations).
pub fn entropy_observation_millibits(bits_per_byte: f64) -> u16 {
    entropy_fixed_point(bits_per_byte, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    // K86: Output always in [0, 8000]
    #[test]
    fn test_k86_output_bounded() {
        let test_values = [
            0.0, 0.001, 0.5, 1.0, 3.14159, 6.5, 7.999, 8.0, 8.001,
            100.0, -1.0, -100.0, f64::NAN, f64::INFINITY, f64::NEG_INFINITY,
            f64::MIN, f64::MAX, f64::MIN_POSITIVE,
        ];
        for &v in &test_values {
            let floor = entropy_fixed_point(v, false);
            let ceil = entropy_fixed_point(v, true);
            assert!(floor <= MAX_ENTROPY_DECISION_MILLIBITS,
                "floor({v}) = {floor} exceeds max");
            assert!(ceil <= MAX_ENTROPY_DECISION_MILLIBITS,
                "ceil({v}) = {ceil} exceeds max");
        }
    }

    // K87: NaN and Infinity map to 0
    #[test]
    fn test_k87_nan_infinity_to_zero() {
        assert_eq!(entropy_fixed_point(f64::NAN, false), 0);
        assert_eq!(entropy_fixed_point(f64::NAN, true), 0);
        assert_eq!(entropy_fixed_point(f64::INFINITY, false), 0);
        assert_eq!(entropy_fixed_point(f64::INFINITY, true), 0);
        assert_eq!(entropy_fixed_point(f64::NEG_INFINITY, false), 0);
        assert_eq!(entropy_fixed_point(f64::NEG_INFINITY, true), 0);
    }

    // K88: Negative values map to 0
    #[test]
    fn test_k88_negative_to_zero() {
        assert_eq!(entropy_fixed_point(-1.0, false), 0);
        assert_eq!(entropy_fixed_point(-1.0, true), 0);
        assert_eq!(entropy_fixed_point(-0.001, false), 0);
        assert_eq!(entropy_fixed_point(-100.0, false), 0);
        assert_eq!(entropy_fixed_point(f64::MIN, false), 0);
    }

    // K89: Monotonicity for finite values in [0, 8]
    #[test]
    fn test_k89_monotonicity() {
        let values = [0.0, 0.001, 0.5, 1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 6.5, 7.0, 7.5, 7.999, 8.0];
        for i in 0..values.len() - 1 {
            let a = values[i];
            let b = values[i + 1];
            assert!(a <= b);
            // Floor monotonic
            let fa = entropy_fixed_point(a, false);
            let fb = entropy_fixed_point(b, false);
            assert!(fa <= fb, "floor not monotonic: f({a})={fa} > f({b})={fb}");
            // Ceil monotonic
            let ca = entropy_fixed_point(a, true);
            let cb = entropy_fixed_point(b, true);
            assert!(ca <= cb, "ceil not monotonic: f({a})={ca} > f({b})={cb}");
        }
    }

    // K90: Ceil >= Floor for same input
    #[test]
    fn test_k90_ceil_ge_floor() {
        let values = [
            0.0, 0.001, 0.5, 1.0, 2.5, 3.14159, 4.999, 5.0, 6.4991, 6.5, 7.0, 7.999, 8.0,
            f64::NAN, f64::INFINITY, f64::NEG_INFINITY, -1.0, 100.0,
        ];
        for &v in &values {
            let floor = entropy_fixed_point(v, false);
            let ceil = entropy_fixed_point(v, true);
            assert!(ceil >= floor,
                "ceil({v})={ceil} < floor({v})={floor}");
        }
    }

    // Bridge test: verified kernel receives valid u16 from wrapper
    #[test]
    fn test_wrapper_to_kernel_bridge() {
        // Threshold at 6.5 bits → floor → 6500 millibits
        let threshold = entropy_threshold_millibits(6.5);
        assert_eq!(threshold, 6500);

        // Observation at 6.5 bits → ceil → 6500 millibits (exact)
        let obs_exact = entropy_observation_millibits(6.5);
        assert_eq!(obs_exact, 6500);

        // Observation at 6.4991 → ceil → 6500 (rounds up)
        let obs_round = entropy_observation_millibits(6.4991);
        assert_eq!(obs_round, 6500);

        // Observation at 6.498 → ceil(6498.0) = 6498 (below 6500 threshold)
        let obs_below = entropy_observation_millibits(6.498);
        assert_eq!(obs_below, 6498);
        assert!(obs_below < threshold, "6.498 observation should be below 6.5 threshold");
    }

    // Exact boundary values
    #[test]
    fn test_boundary_values() {
        assert_eq!(entropy_fixed_point(0.0, false), 0);
        assert_eq!(entropy_fixed_point(0.0, true), 0);
        assert_eq!(entropy_fixed_point(8.0, false), 8000);
        assert_eq!(entropy_fixed_point(8.0, true), 8000);
        // Just above 8.0 should clamp
        assert_eq!(entropy_fixed_point(8.001, false), 8000);
        assert_eq!(entropy_fixed_point(8.001, true), 8000);
    }
}
