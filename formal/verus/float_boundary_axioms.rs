// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Trusted float-to-fixed-point conversion boundary.
//!
//! These axioms model the security-critical properties of the
//! `entropy_fixed_point` conversion in `vellaveto-engine/src/entropy_gate.rs`.
//! They are the proof-facing mirror of the `FLOAT-CONV-*` entries in
//! `formal/ASSUMPTION_REGISTRY.md`.
//!
//! ## Why these are axioms, not theorems
//!
//! Verus does not support IEEE 754 arithmetic reasoning in spec mode. The
//! `f64` type is opaque to the SMT backend, so properties like `clamp`,
//! `floor`, and `ceil` cannot be derived algebraically. These four axioms
//! assert only what standard IEEE 754 and `libm` guarantee; they are
//! audited against the production implementation in `entropy_gate.rs`.
//!
//! ## Audit notes (for assumption review)
//!
//! - `axiom_entropy_conv_bounded`: follows from the explicit three-way
//!   branch at the end of `entropy_fixed_point`:
//!   `if rounded <= 0.0 { 0 } else if rounded >= 8000.0 { 8000 } else { rounded as u16 }`.
//!   The `as u16` cast is safe because `rounded ∈ (0.0, 8000.0)` and 8000 < u16::MAX.
//!
//! - `axiom_entropy_conv_nonfinite_zero`: follows from the unconditional
//!   `if !bits_per_byte.is_finite() { return 0; }` guard at function entry.
//!   `f64::is_finite()` returns false for NaN, +∞, and −∞ per IEEE 754.
//!
//! - `axiom_entropy_conv_floor_le_ceil`: `floor(y) ≤ y ≤ ceil(y)` for any
//!   finite `y` is a standard IEEE 754 / libm guarantee. Since both share
//!   the same `scaled` intermediate, `floor(scaled) ≤ ceil(scaled)`.
//!
//! - `axiom_entropy_conv_ordering`: if `a ≥ b ≥ 0.0` in the float domain,
//!   then `a * 1000 ≥ b * 1000`, and `ceil(a*1000) ≥ a*1000 ≥ b*1000 ≥ floor(b*1000)`.
//!   Floating-point multiplication is monotone for non-negative finite values.

#[allow(unused_imports)]
use vstd::prelude::*;

verus! {

// ── Abstract spec model ───────────────────────────────────────────────────────

/// Abstract: is `x` a finite f64 value (not NaN, not ±∞)?
pub uninterp spec fn spec_f64_is_finite(x: f64) -> bool;

/// Abstract: is `a ≥ b` in the IEEE 754 total order for non-NaN values?
pub uninterp spec fn spec_f64_ge(a: f64, b: f64) -> bool;

/// Abstract: the result that `entropy_fixed_point(x, round_up)` returns.
/// This models the conversion output as an abstract function of the
/// (float, direction) pair, decoupled from Verus's inability to reason
/// about `f64` arithmetic.
pub uninterp spec fn spec_entropy_conv(x: f64, round_up: bool) -> u16;

// ── Convenience aliases ───────────────────────────────────────────────────────

/// Spec: result of `entropy_threshold_millibits(x)` (floor / round-down).
pub open spec fn spec_threshold_mb(x: f64) -> u16 {
    spec_entropy_conv(x, false)
}

/// Spec: result of `entropy_observation_millibits(x)` (ceil / round-up).
pub open spec fn spec_observation_mb(x: f64) -> u16 {
    spec_entropy_conv(x, true)
}

// ── FLOAT-CONV-1: output always bounded in [0, MAX_MILLIBITS] ─────────────────

pub broadcast axiom fn axiom_entropy_conv_bounded(x: f64, round_up: bool)
    ensures
        #[trigger] spec_entropy_conv(x, round_up) <= 8000u16,
;

// ── FLOAT-CONV-2: non-finite input maps to 0 (fail-safe) ─────────────────────

pub broadcast axiom fn axiom_entropy_conv_nonfinite_zero(x: f64, round_up: bool)
    requires
        !spec_f64_is_finite(x),
    ensures
        #[trigger] spec_entropy_conv(x, round_up) == 0u16,
;

// ── FLOAT-CONV-3: floor ≤ ceil for the same input ────────────────────────────
//
// `entropy_threshold_millibits(x) ≤ entropy_observation_millibits(x)` for
// any x: the threshold conversion is always at most the observation
// conversion for the same raw entropy value.

pub broadcast axiom fn axiom_entropy_conv_floor_le_ceil(x: f64)
    ensures
        #![trigger spec_entropy_conv(x, false), spec_entropy_conv(x, true)]
        spec_entropy_conv(x, false) <= spec_entropy_conv(x, true),
;

// ── FLOAT-CONV-4: monotone ordering (no false negatives) ─────────────────────
//
// If the actual entropy `actual` is at least as large as the configured
// threshold `threshold` (both finite, in the float ordering), then
// the observation millibit (ceil) is at least the threshold millibit (floor).
// This ensures the integer alert gate never produces a false negative when
// the true entropy equals or exceeds the configured threshold.

pub broadcast axiom fn axiom_entropy_conv_ordering(actual: f64, threshold: f64)
    requires
        spec_f64_is_finite(actual),
        spec_f64_is_finite(threshold),
        spec_f64_ge(actual, threshold),
    ensures
        #![trigger spec_entropy_conv(actual, true), spec_entropy_conv(threshold, false)]
        spec_entropy_conv(actual, true) >= spec_entropy_conv(threshold, false),
;

// ── Broadcast group ───────────────────────────────────────────────────────────

pub broadcast group group_float_boundary_axioms {
    axiom_entropy_conv_bounded,
    axiom_entropy_conv_nonfinite_zero,
    axiom_entropy_conv_floor_le_ceil,
    axiom_entropy_conv_ordering,
}

// ── Summary predicate ─────────────────────────────────────────────────────────

pub open spec fn float_boundary_axioms_hold() -> bool {
    &&& forall|x: f64, round_up: bool|
        #[trigger] spec_entropy_conv(x, round_up) <= 8000u16
    &&& forall|x: f64, round_up: bool|
        !spec_f64_is_finite(x) ==> #[trigger] spec_entropy_conv(x, round_up) == 0u16
    &&& forall|x: f64|
        #![trigger spec_entropy_conv(x, false), spec_entropy_conv(x, true)]
        spec_entropy_conv(x, false) <= spec_entropy_conv(x, true)
    &&& forall|actual: f64, threshold: f64|
        #![trigger spec_entropy_conv(actual, true), spec_entropy_conv(threshold, false)]
        spec_f64_is_finite(actual) && spec_f64_is_finite(threshold) && spec_f64_ge(actual, threshold)
            ==> spec_entropy_conv(actual, true) >= spec_entropy_conv(threshold, false)
}

} // verus!
