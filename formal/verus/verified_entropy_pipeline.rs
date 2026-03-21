// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verus-verified entropy alert pipeline composition.
//!
//! Proves end-to-end properties of the entropy detection pipeline:
//! float observation → millibit conversion → threshold comparison →
//! alert gating → severity classification.
//!
//! This kernel composes the integer-only alert gate (verified_entropy_gate.rs)
//! with millibit conversion properties (Kani K86-K90) and the alert
//! severity decision.
//!
//! Properties verified:
//! - EPIPE-1: Millibit observation bounded [0, 8000]
//! - EPIPE-2: Millibit threshold bounded [0, 8000]
//! - EPIPE-3: Below-threshold observation produces no alert
//! - EPIPE-4: At-threshold observation produces alert (conservative)
//! - EPIPE-5: Alert severity monotonic with observation count
//! - EPIPE-6: Zero min_observations is structurally rejected
//!
//! To verify:
//!   `verus --triggers-mode silent formal/verus/verified_entropy_pipeline.rs`

#[path = "assumptions.rs"]
mod assumptions;

#[allow(unused_imports)]
use vstd::prelude::*;

verus! {

pub const MAX_MILLIBITS: u16 = 8000;

#[derive(Structural, PartialEq, Eq, Clone, Copy)]
pub enum AlertSeverity {
    None,
    Medium,
    High,
}

/// Saturating multiply by 2 for u32.
pub open spec fn spec_saturating_double(v: u32) -> u32 {
    if v > 0x7FFF_FFFFu32 { 0xFFFF_FFFFu32 } else { (v * 2) as u32 }
}

pub fn saturating_double(v: u32) -> (result: u32)
    ensures result == spec_saturating_double(v),
{
    if v > u32::MAX / 2 { u32::MAX } else { v * 2 }
}

// ── Pipeline spec functions ────────────────────────────────────────

/// Spec: millibit value is valid (bounded by MAX_MILLIBITS).
pub open spec fn spec_millibit_valid(mb: u16) -> bool {
    mb <= MAX_MILLIBITS
}

/// Spec: observation exceeds threshold.
pub open spec fn spec_is_high_entropy(obs_mb: u16, threshold_mb: u16) -> bool {
    obs_mb >= threshold_mb
}

/// Spec: should alert fire given observation count and minimum.
pub open spec fn spec_should_alert(count: u32, min_observations: u32) -> bool {
    min_observations > 0 && count >= min_observations
}

/// Spec: alert severity based on count vs doubled threshold.
pub open spec fn spec_alert_severity(
    count: u32,
    min_observations: u32,
) -> AlertSeverity {
    if min_observations == 0 {
        AlertSeverity::None  // Config invalid — no alert
    } else if count < min_observations {
        AlertSeverity::None
    } else if count >= spec_saturating_double(min_observations) {
        AlertSeverity::High
    } else {
        AlertSeverity::Medium
    }
}

// ── Exec functions ─────────────────────────────────────────────────

pub fn millibit_valid(mb: u16) -> (result: bool)
    ensures result == spec_millibit_valid(mb),
{
    mb <= MAX_MILLIBITS
}

pub fn is_high_entropy(obs_mb: u16, threshold_mb: u16) -> (result: bool)
    ensures
        result == spec_is_high_entropy(obs_mb, threshold_mb),
        result ==> obs_mb >= threshold_mb,
        !result ==> obs_mb < threshold_mb,
{
    obs_mb >= threshold_mb
}

pub fn should_alert(count: u32, min_observations: u32) -> (result: bool)
    ensures
        result == spec_should_alert(count, min_observations),
        result ==> count >= min_observations,
        result ==> min_observations > 0,
{
    min_observations > 0 && count >= min_observations
}

pub fn alert_severity(count: u32, min_observations: u32) -> (result: AlertSeverity)
    ensures
        result == spec_alert_severity(count, min_observations),
{
    if min_observations == 0 {
        AlertSeverity::None
    } else if count < min_observations {
        AlertSeverity::None
    } else if count >= saturating_double(min_observations) {
        AlertSeverity::High
    } else {
        AlertSeverity::Medium
    }
}

// ── EPIPE-1: Millibit observation bounded ─────────────────────────

pub proof fn lemma_millibit_bounded()
    ensures
        spec_millibit_valid(0),
        spec_millibit_valid(MAX_MILLIBITS),
        !spec_millibit_valid(8001u16),
{
}

// ── EPIPE-2: Millibit threshold bounded ───────────────────────────

pub proof fn lemma_threshold_within_entropy_range(threshold_mb: u16)
    requires spec_millibit_valid(threshold_mb),
    ensures threshold_mb <= 8000,
{
}

// ── EPIPE-3: Below threshold → no alert ───────────────────────────

pub proof fn lemma_below_threshold_no_detection(obs_mb: u16, threshold_mb: u16)
    requires obs_mb < threshold_mb,
    ensures !spec_is_high_entropy(obs_mb, threshold_mb),
{
}

/// If every observation is below threshold, count stays at 0, no alert.
pub proof fn lemma_zero_count_no_alert(min_observations: u32)
    requires min_observations > 0,
    ensures !spec_should_alert(0, min_observations),
{
}

// ── EPIPE-4: At threshold → detected (conservative) ──────────────

pub proof fn lemma_at_threshold_detected(threshold_mb: u16)
    ensures spec_is_high_entropy(threshold_mb, threshold_mb),
{
}

/// Enough detections → alert fires.
pub proof fn lemma_sufficient_count_alerts(min_observations: u32)
    requires min_observations > 0,
    ensures spec_should_alert(min_observations, min_observations),
{
}

// ── EPIPE-5: Severity monotonic with count ────────────────────────

pub proof fn lemma_severity_at_min_is_medium(min_observations: u32)
    requires
        min_observations > 0,
        min_observations <= u32::MAX / 2,
    ensures
        spec_alert_severity(min_observations, min_observations)
            == AlertSeverity::Medium,
{
}

pub proof fn lemma_severity_at_double_is_high(min_observations: u32)
    requires
        min_observations > 0,
        min_observations <= u32::MAX / 2,
    ensures
        spec_alert_severity(
            spec_saturating_double(min_observations),
            min_observations,
        ) == AlertSeverity::High,
{
}

/// Severity never goes from High back to Medium.
pub proof fn lemma_severity_monotonic(
    count1: u32,
    count2: u32,
    min_observations: u32,
)
    requires
        min_observations > 0,
        count2 >= count1,
        spec_alert_severity(count1, min_observations) == AlertSeverity::High,
    ensures
        spec_alert_severity(count2, min_observations) == AlertSeverity::High,
{
}

// ── EPIPE-6: Zero min_observations → no alert (structural) ───────

pub proof fn lemma_zero_min_observations_never_alerts(count: u32)
    ensures
        !spec_should_alert(count, 0),
        spec_alert_severity(count, 0) == AlertSeverity::None,
{
}

// ── End-to-end composition ────────────────────────────────────────

/// Full pipeline: if all observations are below threshold, severity is None.
pub proof fn lemma_end_to_end_below_threshold(min_observations: u32)
    requires min_observations > 0,
    ensures
        // Zero high-entropy observations → no alert → None severity
        spec_alert_severity(0, min_observations) == AlertSeverity::None,
{
}

/// Full pipeline: min_observations high-entropy hits → Medium alert.
pub proof fn lemma_end_to_end_threshold_hit(min_observations: u32)
    requires
        min_observations > 0,
        min_observations <= u32::MAX / 2,
    ensures
        spec_alert_severity(min_observations, min_observations)
            == AlertSeverity::Medium,
{
}

// ── Assumption registration ────────────────────────────────────────

pub proof fn lemma_named_assumptions_registered_for_this_kernel()
    ensures assumptions::entropy_pipeline_kernel_assumptions_registered(),
{
    assumptions::lemma_shared_formal_assumptions_registered();
}

fn main() {}

} // verus!
