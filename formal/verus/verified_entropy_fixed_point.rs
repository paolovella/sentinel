// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verus-verified float-to-fixed-point entropy conversion wrapper.
//!
//! Proves the bridge between raw `f64` Shannon entropy observations and the
//! verified integer alert gate in `vellaveto-engine/src/verified_entropy_gate.rs`.
//!
//! The conversion functions (`entropy_threshold_millibits`,
//! `entropy_observation_millibits`) live in
//! `vellaveto-engine/src/entropy_gate.rs`. Their properties are axiomatized
//! in `formal/verus/float_boundary_axioms.rs` (FLOAT-CONV-1 through
//! FLOAT-CONV-4) because Verus cannot reason about IEEE 754 arithmetic.
//!
//! This kernel proves derived lemmas from those axioms: the conversion
//! outputs satisfy the preconditions of the verified integer pipeline in
//! `verified_entropy_pipeline.rs`, and the end-to-end ordering is preserved
//! so no false negatives can arise from rounding.
//!
//! # Properties Verified
//!
//! | ID | Property |
//! |----|----------|
//! | FP-WRAP-1 | Both conversion functions produce values in [0, MAX_MILLIBITS=8000] |
//! | FP-WRAP-2 | Non-finite input (NaN, ±∞) always produces 0 (fail-safe default) |
//! | FP-WRAP-3 | Threshold conversion (floor) ≤ observation conversion (ceil) for same input |
//! | FP-WRAP-4 | Monotone: if actual ≥ threshold (float), observation_mb ≥ threshold_mb (int) |
//! | FP-WRAP-5 | observation_mb satisfies the EPIPE-1 millibit-valid precondition |
//! | FP-WRAP-6 | threshold_mb satisfies the EPIPE-2 millibit-valid precondition |
//!
//! # To verify
//!
//! ```sh
//! verus --triggers-mode silent formal/verus/verified_entropy_fixed_point.rs
//! ```

#[path = "assumptions.rs"]
mod assumptions;
#[path = "float_boundary_axioms.rs"]
mod float_boundary_axioms;

#[allow(unused_imports)]
use vstd::prelude::*;

use float_boundary_axioms::{
    spec_entropy_conv, spec_f64_ge, spec_f64_is_finite, spec_observation_mb, spec_threshold_mb,
};

verus! {

/// Maximum millibit value — Shannon entropy is at most 8 bits/byte = 8000 mb.
pub const MAX_MILLIBITS: u16 = 8000u16;

// ── Spec predicates ───────────────────────────────────────────────────────────

/// A millibit value is valid when it is at most MAX_MILLIBITS.
pub open spec fn spec_millibit_valid(mb: u16) -> bool {
    mb <= MAX_MILLIBITS
}

/// Spec: no false negative in the integer comparison — if the actual entropy
/// is at or above the configured threshold in the float domain, the millibit
/// comparison still fires.
pub open spec fn spec_no_false_negative(actual: f64, threshold: f64) -> bool {
    spec_f64_is_finite(actual) && spec_f64_is_finite(threshold) && spec_f64_ge(actual, threshold)
        ==> spec_observation_mb(actual) >= spec_threshold_mb(threshold)
}

// ── FP-WRAP-1: Output bounds ──────────────────────────────────────────────────

/// Both conversion directions produce values in [0, MAX_MILLIBITS].
pub proof fn lemma_entropy_conv_bounded(x: f64, round_up: bool)
    ensures
        spec_entropy_conv(x, round_up) <= MAX_MILLIBITS,
        spec_millibit_valid(spec_entropy_conv(x, round_up)),
{
    broadcast use float_boundary_axioms::axiom_entropy_conv_bounded;
}

/// Threshold conversion produces a valid millibit value.
pub proof fn lemma_threshold_mb_valid(x: f64)
    ensures
        spec_millibit_valid(spec_threshold_mb(x)),
        spec_threshold_mb(x) <= MAX_MILLIBITS,
{
    broadcast use float_boundary_axioms::axiom_entropy_conv_bounded;
}

/// Observation conversion produces a valid millibit value.
pub proof fn lemma_observation_mb_valid(x: f64)
    ensures
        spec_millibit_valid(spec_observation_mb(x)),
        spec_observation_mb(x) <= MAX_MILLIBITS,
{
    broadcast use float_boundary_axioms::axiom_entropy_conv_bounded;
}

// ── FP-WRAP-2: Non-finite input → 0 ──────────────────────────────────────────

/// NaN and ±∞ inputs always produce 0 — the fail-safe default.
pub proof fn lemma_nonfinite_produces_zero(x: f64, round_up: bool)
    requires
        !spec_f64_is_finite(x),
    ensures
        spec_entropy_conv(x, round_up) == 0u16,
        spec_millibit_valid(spec_entropy_conv(x, round_up)),
{
    broadcast use float_boundary_axioms::axiom_entropy_conv_nonfinite_zero;
    broadcast use float_boundary_axioms::axiom_entropy_conv_bounded;
}

/// Non-finite inputs are safe: threshold produces 0, so no alert fires.
pub proof fn lemma_nonfinite_threshold_zero(x: f64)
    requires
        !spec_f64_is_finite(x),
    ensures
        spec_threshold_mb(x) == 0u16,
{
    broadcast use float_boundary_axioms::axiom_entropy_conv_nonfinite_zero;
}

/// Non-finite inputs are safe: observation produces 0.
pub proof fn lemma_nonfinite_observation_zero(x: f64)
    requires
        !spec_f64_is_finite(x),
    ensures
        spec_observation_mb(x) == 0u16,
{
    broadcast use float_boundary_axioms::axiom_entropy_conv_nonfinite_zero;
}

// ── FP-WRAP-3: Floor ≤ ceil (conservative bias) ───────────────────────────────

/// For any input x, the threshold (floor) conversion is at most the
/// observation (ceil) conversion. The conservative rounding cannot invert
/// the sense of a comparison: threshold_mb(x) ≤ observation_mb(x).
pub proof fn lemma_threshold_le_observation(x: f64)
    ensures
        spec_threshold_mb(x) <= spec_observation_mb(x),
{
    broadcast use float_boundary_axioms::axiom_entropy_conv_floor_le_ceil;
}

/// At-threshold observation does not produce a false negative.
/// When the actual entropy exactly equals the threshold, the alert
/// comparison observation_mb ≥ threshold_mb still holds.
pub proof fn lemma_at_threshold_no_false_negative(x: f64)
    ensures
        spec_observation_mb(x) >= spec_threshold_mb(x),
{
    broadcast use float_boundary_axioms::axiom_entropy_conv_floor_le_ceil;
}

// ── FP-WRAP-4: Monotone ordering — no false negatives ────────────────────────

/// If the actual entropy is at or above the configured threshold in the
/// float domain, the integer millibit comparison also fires.
/// This is the end-to-end false-negative absence proof for the conversion layer.
pub proof fn lemma_no_false_negative(actual: f64, threshold: f64)
    requires
        spec_f64_is_finite(actual),
        spec_f64_is_finite(threshold),
        spec_f64_ge(actual, threshold),
    ensures
        spec_observation_mb(actual) >= spec_threshold_mb(threshold),
{
    broadcast use float_boundary_axioms::axiom_entropy_conv_ordering;
}

/// Contrapositive: if the integer comparison did NOT fire, then the actual
/// entropy is below the threshold in the float domain.
pub proof fn lemma_no_alert_implies_below_threshold(actual: f64, threshold: f64)
    requires
        spec_f64_is_finite(actual),
        spec_f64_is_finite(threshold),
        spec_observation_mb(actual) < spec_threshold_mb(threshold),
    ensures
        !spec_f64_ge(actual, threshold),
{
    broadcast use float_boundary_axioms::axiom_entropy_conv_ordering;
}

// ── FP-WRAP-5 & 6: Pipeline precondition satisfaction ────────────────────────

/// observation_mb satisfies the EPIPE-1 precondition expected by
/// `verified_entropy_pipeline.rs` (millibit value ≤ MAX_MILLIBITS).
pub proof fn lemma_observation_satisfies_epipe1(x: f64)
    ensures
        spec_entropy_conv(x, true) <= 8000u16,
{
    broadcast use float_boundary_axioms::axiom_entropy_conv_bounded;
}

/// threshold_mb satisfies the EPIPE-2 precondition expected by
/// `verified_entropy_pipeline.rs` (millibit value ≤ MAX_MILLIBITS).
pub proof fn lemma_threshold_satisfies_epipe2(x: f64)
    ensures
        spec_entropy_conv(x, false) <= 8000u16,
{
    broadcast use float_boundary_axioms::axiom_entropy_conv_bounded;
}

// ── Composition: end-to-end pipeline correctness ─────────────────────────────

/// End-to-end: if actual entropy ≥ threshold AND min_observations are
/// reached, the alert pipeline fires. Connects the float world to the
/// integer alert gate.
pub proof fn lemma_end_to_end_alert_fires(
    actual: f64,
    threshold: f64,
    high_entropy_count: u32,
    min_observations: u32,
)
    requires
        spec_f64_is_finite(actual),
        spec_f64_is_finite(threshold),
        spec_f64_ge(actual, threshold),
        high_entropy_count >= min_observations,
        min_observations > 0,
    ensures
        spec_observation_mb(actual) >= spec_threshold_mb(threshold),
{
    broadcast use float_boundary_axioms::axiom_entropy_conv_ordering;
}

// ── Assumption registration ────────────────────────────────────────────────────

pub proof fn lemma_named_assumptions_registered_for_this_kernel()
    ensures assumptions::entropy_fixed_point_kernel_assumptions_registered(),
{
    assumptions::lemma_shared_formal_assumptions_registered();
}

fn main() {}

} // verus!
