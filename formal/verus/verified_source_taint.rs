// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verus-verified source-class taint containment kernel.
//!
//! Phase 6.1D: Proves that the source-class trust floor computation
//! is panic-free and correctly enforces trust-tier ordering.
//!
//! Properties verified:
//! - TAINT-1: Trust floor only decreases (monotonic degradation)
//! - TAINT-2: Untrusted source always produces floor <= Untrusted
//! - TAINT-3: Verified source never lowers the floor
//! - TAINT-4: Sink gate is fail-closed (insufficient trust → blocked)
//! - TAINT-5: No sink accessible when floor == 0 (Quarantined)
//!
//! Production correspondence:
//! - Trust tier ranks ↔ vellaveto-types/src/provenance.rs TrustTier
//! - Sink gate ↔ vellaveto-proxy/src/main.rs taint-based enforcement
//!
//! To verify:
//!   `verus --triggers-mode silent formal/verus/verified_source_taint.rs`

#[path = "assumptions.rs"]
mod assumptions;

#[allow(unused_imports)]
use vstd::prelude::*;

verus! {

// ── Trust tier ranks (mirrors production) ───────────────────────────

pub const QUARANTINED: u8 = 0;
pub const UNKNOWN: u8 = 1;
pub const UNTRUSTED: u8 = 2;
pub const LOW: u8 = 3;
pub const MEDIUM: u8 = 4;
pub const HIGH: u8 = 5;
pub const VERIFIED: u8 = 6;

// ── Sink trust requirements ────────────────────────────────────────

pub open spec fn spec_min_trust_for_sink(sink_class: u8) -> u8 {
    if sink_class == 0 { UNKNOWN }       // ReadOnly
    else if sink_class == 1 { LOW }       // LowRiskWrite
    else if sink_class == 2 { MEDIUM }    // FilesystemWrite
    else if sink_class == 3 { MEDIUM }    // NetworkEgress
    else if sink_class == 4 { VERIFIED }  // CodeExecution
    else if sink_class == 5 { VERIFIED }  // PolicyMutation
    else { UNKNOWN }                      // Unknown → fail-safe
}

pub fn min_trust_for_sink(sink_class: u8) -> (result: u8)
    ensures result == spec_min_trust_for_sink(sink_class),
{
    if sink_class == 0 { UNKNOWN }
    else if sink_class == 1 { LOW }
    else if sink_class == 2 { MEDIUM }
    else if sink_class == 3 { MEDIUM }
    else if sink_class == 4 { VERIFIED }
    else if sink_class == 5 { VERIFIED }
    else { UNKNOWN }
}

// ── Trust floor computation ────────────────────────────────────────

/// Compute new trust floor after observing a source with given trust rank.
/// Floor only decreases (monotonic degradation).
pub open spec fn spec_update_trust_floor(current_floor: u8, source_trust: u8) -> u8 {
    if source_trust < current_floor {
        source_trust
    } else {
        current_floor
    }
}

pub fn update_trust_floor(current_floor: u8, source_trust: u8) -> (result: u8)
    ensures
        result == spec_update_trust_floor(current_floor, source_trust),
        result <= current_floor,
        result <= source_trust || result == current_floor,
{
    if source_trust < current_floor {
        source_trust
    } else {
        current_floor
    }
}

// ── Sink gate ──────────────────────────────────────────────────────

/// Check if a sink is accessible given the current trust floor.
/// Fail-closed: insufficient trust → blocked.
pub open spec fn spec_sink_accessible(trust_floor: u8, sink_class: u8) -> bool {
    trust_floor >= spec_min_trust_for_sink(sink_class)
}

pub fn sink_accessible(trust_floor: u8, sink_class: u8) -> (result: bool)
    ensures
        result == spec_sink_accessible(trust_floor, sink_class),
        result ==> trust_floor >= spec_min_trust_for_sink(sink_class),
        !result ==> trust_floor < spec_min_trust_for_sink(sink_class),
{
    trust_floor >= min_trust_for_sink(sink_class)
}

// ── TAINT-1: Trust floor only decreases ────────────────────────────

pub proof fn lemma_trust_floor_monotonic_decrease(
    current_floor: u8,
    source_trust: u8,
)
    ensures
        spec_update_trust_floor(current_floor, source_trust) <= current_floor,
{
}

/// Sequence of updates only decreases the floor.
pub proof fn lemma_trust_floor_chain_monotonic(
    floor0: u8,
    source1: u8,
    source2: u8,
)
    ensures ({
        let floor1 = spec_update_trust_floor(floor0, source1);
        let floor2 = spec_update_trust_floor(floor1, source2);
        floor2 <= floor1 && floor1 <= floor0
    }),
{
}

// ── TAINT-2: Untrusted source always produces floor <= Untrusted ──

pub proof fn lemma_untrusted_source_lowers_floor(current_floor: u8)
    requires
        current_floor >= UNTRUSTED,
    ensures
        spec_update_trust_floor(current_floor, UNTRUSTED) <= UNTRUSTED,
{
}

// ── TAINT-3: Verified source never lowers the floor ───────────────

pub proof fn lemma_verified_source_preserves_floor(current_floor: u8)
    requires
        current_floor <= VERIFIED,
    ensures
        spec_update_trust_floor(current_floor, VERIFIED) == current_floor,
{
}

// ── TAINT-4: Sink gate fail-closed ────────────────────────────────

pub proof fn lemma_sink_gate_fail_closed(trust_floor: u8, sink_class: u8)
    requires
        trust_floor < spec_min_trust_for_sink(sink_class),
    ensures
        !spec_sink_accessible(trust_floor, sink_class),
{
}

/// Privileged sinks always blocked at untrusted floor.
pub proof fn lemma_privileged_sinks_blocked_when_untrusted()
    ensures
        !spec_sink_accessible(UNTRUSTED, 4),  // CodeExecution
        !spec_sink_accessible(UNTRUSTED, 5),  // PolicyMutation
        !spec_sink_accessible(UNTRUSTED, 2),  // FilesystemWrite
        !spec_sink_accessible(UNTRUSTED, 3),  // NetworkEgress
{
}

// ── TAINT-5: Quarantined blocks everything except ReadOnly ────────

pub proof fn lemma_quarantined_blocks_all_but_readonly()
    ensures
        !spec_sink_accessible(QUARANTINED, 1),  // LowRiskWrite
        !spec_sink_accessible(QUARANTINED, 2),  // FilesystemWrite
        !spec_sink_accessible(QUARANTINED, 3),  // NetworkEgress
        !spec_sink_accessible(QUARANTINED, 4),  // CodeExecution
        !spec_sink_accessible(QUARANTINED, 5),  // PolicyMutation
        !spec_sink_accessible(QUARANTINED, 0),  // ReadOnly needs UNKNOWN=1
{
}

// ── Composition: taint then gate ──────────────────────────────────

/// After processing an untrusted source, privileged sinks are blocked.
pub proof fn lemma_untrusted_source_blocks_privileged_sinks(initial_floor: u8)
    requires
        initial_floor >= UNTRUSTED,
    ensures ({
        let new_floor = spec_update_trust_floor(initial_floor, UNTRUSTED);
        !spec_sink_accessible(new_floor, 4)  // CodeExecution blocked
        && !spec_sink_accessible(new_floor, 5)  // PolicyMutation blocked
    }),
{
}

// ── Assumption registration ───────────────────────────────────────

pub proof fn lemma_named_assumptions_registered_for_this_kernel()
    ensures assumptions::source_taint_kernel_assumptions_registered(),
{
    assumptions::lemma_shared_formal_assumptions_registered();
}

fn main() {}

} // verus!
