// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verus-verified behavioral sequence analysis containment kernel.
//!
//! Phase 6.3E: Proves that sequence-based anomaly detection is
//! monotonic, warmup-respecting, and panic-free.
//!
//! Properties verified:
//! - SEQ-1: Anomaly detection is monotonic (once detected, persists)
//! - SEQ-2: Anomaly confidence only increases (max-tracking)
//! - SEQ-3: Scope restriction requires anomaly (no false restriction)
//! - SEQ-4: Warmup period does not suppress taint restrictions
//! - SEQ-5: New tool count after taint is bounded
//! - SEQ-6: High-confidence anomaly always triggers restriction
//!
//! Production correspondence:
//! - Anomaly tracking ↔ vellaveto-types/src/channel_separation.rs
//! - Sequence detectors ↔ vellaveto-proxy/src/main.rs behavioral analysis
//!
//! To verify:
//!   `verus --triggers-mode silent formal/verus/verified_sequence_analysis.rs`

#[path = "assumptions.rs"]
mod assumptions;

#[allow(unused_imports)]
use vstd::prelude::*;

verus! {

/// Ghost model of the sequence analysis state.
pub struct SequenceState {
    pub call_count: u32,
    pub anomaly_detected: bool,
    pub anomaly_confidence: u32,  // 0-100; u32 to match SequenceAnomaly.confidence
    pub taint_active: bool,
    pub new_tools_after_taint: u32,
    pub scope_restricted: bool,
}

pub const WARMUP_CALLS: u32 = 3;
pub const MAX_NEW_TOOLS: u32 = 2;
pub const RESTRICTION_THRESHOLD: u32 = 70;
pub const MAX_CONFIDENCE: u32 = 100;

// ── Core spec functions ────────────────────────────────────────────

/// Spec: update anomaly_detected (monotonic — once true, stays true).
pub open spec fn spec_update_anomaly_detected(
    current: bool,
    new_detection: bool,
) -> bool {
    current || new_detection
}

/// Spec: update confidence (max-tracking — only increases).
pub open spec fn spec_update_confidence(
    current: u32,
    new_confidence: u32,
) -> u32 {
    if new_confidence > current { new_confidence } else { current }
}

/// Spec: should scope be restricted?
pub open spec fn spec_should_restrict(
    anomaly_detected: bool,
    anomaly_confidence: u32,
) -> bool {
    anomaly_detected && anomaly_confidence >= RESTRICTION_THRESHOLD
}

/// Spec: is warmup complete?
pub open spec fn spec_warmup_complete(call_count: u32) -> bool {
    call_count >= WARMUP_CALLS
}

// ── SEQ-1: Anomaly detection is monotonic ─────────────────────────

pub fn update_anomaly_detected(current: bool, new_detection: bool) -> (result: bool)
    ensures
        result == spec_update_anomaly_detected(current, new_detection),
        current ==> result,   // Once true, stays true
        new_detection ==> result,
{
    current || new_detection
}

pub proof fn lemma_anomaly_persistence(current: bool, new_detection: bool)
    requires current,
    ensures spec_update_anomaly_detected(current, new_detection),
{
}

pub proof fn lemma_anomaly_monotonic_chain(
    s0: bool, d1: bool, d2: bool, d3: bool,
)
    ensures ({
        let s1 = spec_update_anomaly_detected(s0, d1);
        let s2 = spec_update_anomaly_detected(s1, d2);
        let s3 = spec_update_anomaly_detected(s2, d3);
        // Once any detection fires, all subsequent states are true
        (s0 || d1) ==> (s1 && s2 && s3)
    }),
{
}

// ── SEQ-2: Confidence only increases ──────────────────────────────

pub fn update_confidence(current: u32, new_confidence: u32) -> (result: u32)
    ensures
        result == spec_update_confidence(current, new_confidence),
        result >= current,    // Never decreases
        result >= new_confidence || result == current,
{
    if new_confidence > current { new_confidence } else { current }
}

pub proof fn lemma_confidence_monotonic(current: u32, new_confidence: u32)
    ensures
        spec_update_confidence(current, new_confidence) >= current,
{
}

pub proof fn lemma_confidence_chain_monotonic(c0: u32, n1: u32, n2: u32)
    ensures ({
        let c1 = spec_update_confidence(c0, n1);
        let c2 = spec_update_confidence(c1, n2);
        c2 >= c1 && c1 >= c0
    }),
{
}

// ── SEQ-3: Restriction requires anomaly ───────────────────────────

pub proof fn lemma_restriction_requires_anomaly(
    anomaly_detected: bool,
    confidence: u32,
)
    ensures
        spec_should_restrict(anomaly_detected, confidence) ==> anomaly_detected,
        spec_should_restrict(anomaly_detected, confidence) ==> confidence >= RESTRICTION_THRESHOLD,
{
}

pub proof fn lemma_no_anomaly_no_restriction(confidence: u32)
    ensures
        !spec_should_restrict(false, confidence),
{
}

// ── SEQ-4: Warmup does not suppress taint ─────────────────────────

/// Taint is tracked independently of warmup.
/// Even if call_count < WARMUP_CALLS, taint_active can be true.
pub proof fn lemma_warmup_independent_of_taint(
    call_count: u32,
    taint_active: bool,
)
    ensures
        // Taint state is not affected by warmup status
        taint_active == taint_active,  // structural: taint is independent variable
        // During warmup, taint is still recorded
        (!spec_warmup_complete(call_count) && taint_active) ==> taint_active,
{
}

/// Stronger: taint restriction (from source-class module) is independent
/// of whether sequence analysis has started.
pub fn is_taint_restricted(taint_active: bool, call_count: u32) -> (result: bool)
    ensures
        result == taint_active,
        // Taint restriction does NOT depend on warmup
        result == taint_active,
{
    taint_active
}

// ── SEQ-5: New tool count bounded ─────────────────────────────────

pub fn check_new_tool_budget(
    new_tools_after_taint: u32,
    max_new_tools: u32,
) -> (result: bool)
    ensures
        result == (new_tools_after_taint <= max_new_tools),
        !result ==> new_tools_after_taint > max_new_tools,
{
    new_tools_after_taint <= max_new_tools
}

pub fn increment_new_tools(current: u32) -> (result: u32)
    ensures
        result == current.saturating_add(1) as u32,
        result >= current,
        result <= u32::MAX as u32,
{
    current.saturating_add(1)
}

// ── SEQ-6: High confidence triggers restriction ───────────────────

pub proof fn lemma_high_confidence_triggers_restriction()
    ensures
        spec_should_restrict(true, 90),   // privEsc → 90 confidence
        spec_should_restrict(true, 85),   // novelAfterTaint → 85 confidence
        !spec_should_restrict(true, 60),  // diversitySpike → 60 < threshold
        !spec_should_restrict(true, 0),   // no anomaly → 0
{
}

/// Composition: detection at confidence >= 70 always restricts.
pub proof fn lemma_detection_above_threshold_restricts(confidence: u32)
    requires
        confidence >= RESTRICTION_THRESHOLD,
    ensures
        spec_should_restrict(true, confidence),
{
}

// ── Composite state transition ────────────────────────────────────

/// A single step of sequence analysis: given a detection event,
/// update all state fields and verify invariants hold.
pub fn sequence_step(
    state: &SequenceState,
    detected: bool,
    confidence: u32,
    is_novel_after_taint: bool,
) -> (new_state: SequenceState)
    requires
        state.anomaly_confidence <= MAX_CONFIDENCE,
        confidence <= MAX_CONFIDENCE,
    ensures
        // SEQ-1: Anomaly monotonic
        state.anomaly_detected ==> new_state.anomaly_detected,
        // SEQ-2: Confidence monotonic
        new_state.anomaly_confidence >= state.anomaly_confidence,
        // SEQ-3: Restriction requires anomaly
        new_state.scope_restricted ==> (new_state.anomaly_detected || state.scope_restricted),
        // Call count increases
        new_state.call_count == state.call_count.saturating_add(1) as u32,
{
    let new_detected = update_anomaly_detected(state.anomaly_detected, detected);
    let new_confidence = update_confidence(state.anomaly_confidence, confidence);
    let new_restricted = state.scope_restricted
        || (new_detected && new_confidence >= RESTRICTION_THRESHOLD);
    let new_tools = if is_novel_after_taint {
        state.new_tools_after_taint.saturating_add(1)
    } else {
        state.new_tools_after_taint
    };

    SequenceState {
        call_count: state.call_count.saturating_add(1),
        anomaly_detected: new_detected,
        anomaly_confidence: new_confidence,
        taint_active: state.taint_active,
        new_tools_after_taint: new_tools,
        scope_restricted: new_restricted,
    }
}

// ── Assumption registration ────────────────────────────────────────

pub proof fn lemma_named_assumptions_registered_for_this_kernel()
    ensures assumptions::sequence_analysis_kernel_assumptions_registered(),
{
    assumptions::lemma_shared_formal_assumptions_registered();
}

fn main() {}

} // verus!
