// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verus-verified approval lineage drift guards (DRIFT-1–4).
//!
//! Proves the extracted predicates for approval drift detection
//! and fail-closed enforcement in the MCP relay hot path.
//!
//! Production code: `vellaveto-approval/src/lib.rs:330-360`,
//! `vellaveto-mcp/src/proxy/bridge/relay.rs:2941-3014`
//!
//! To verify:
//!   `verus --triggers-mode silent formal/verus/verified_approval_drift.rs`

#[path = "assumptions.rs"]
mod assumptions;

#[allow(unused_imports)]
use vstd::prelude::*;

verus! {

// ═══════════════════════════════════════════════════════════════════
// DRIFT-1: Trust downgrade detection
// ═══════════════════════════════════════════════════════════════════

/// A trust downgrade occurs when the current session trust rank
/// is strictly lower than the trust rank at approval creation time.
pub open spec fn spec_trust_downgraded(
    approval_rank: u32,
    current_rank: u32,
) -> bool {
    current_rank < approval_rank
}

pub fn trust_downgraded(approval_rank: u32, current_rank: u32) -> (result: bool)
    ensures
        result == spec_trust_downgraded(approval_rank, current_rank),
        // Key safety property: lower rank means degraded trust
        result ==> current_rank < approval_rank,
        !result ==> current_rank >= approval_rank,
{
    current_rank < approval_rank
}

// ═══════════════════════════════════════════════════════════════════
// DRIFT-2: Taint accumulation detection
// ═══════════════════════════════════════════════════════════════════

/// Taint accumulation occurs when the session has acquired more
/// semantic taint entries since the approval was created.
pub open spec fn spec_taint_accumulated(
    approval_taint_count: usize,
    current_taint_count: usize,
) -> bool {
    current_taint_count > approval_taint_count
}

pub fn taint_accumulated(
    approval_taint_count: usize,
    current_taint_count: usize,
) -> (result: bool)
    ensures
        result == spec_taint_accumulated(approval_taint_count, current_taint_count),
        result ==> current_taint_count > approval_taint_count,
        !result ==> current_taint_count <= approval_taint_count,
{
    current_taint_count > approval_taint_count
}

// ═══════════════════════════════════════════════════════════════════
// DRIFT-3: Combined drift detection → decision is Block
// ═══════════════════════════════════════════════════════════════════

/// Either trust downgrade OR taint accumulation constitutes drift.
pub open spec fn spec_drift_detected(
    trust_down: bool,
    taint_up: bool,
) -> bool {
    trust_down || taint_up
}

pub fn drift_detected(trust_down: bool, taint_up: bool) -> (result: bool)
    ensures
        result == spec_drift_detected(trust_down, taint_up),
        result ==> trust_down || taint_up,
{
    trust_down || taint_up
}

/// When drift is detected via the combined gate, the result is always true.
/// This proves that ANY cause of drift (trust OR taint OR store error)
/// produces a true result from fail_closed_drift.
pub proof fn lemma_any_drift_cause_triggers_gate(
    trust_down: bool,
    taint_up: bool,
    store_error: bool,
)
    requires trust_down || taint_up || store_error,
    ensures spec_fail_closed_drift(store_error, trust_down, taint_up),
{
    // spec_fail_closed_drift = store_error || trust_down || taint_up
    // With at least one true input, the disjunction is true.
}

// ═══════════════════════════════════════════════════════════════════
// DRIFT-4: Store error → fail-closed (drift_detected = true)
// ═══════════════════════════════════════════════════════════════════

/// When the approval store returns an error, the combined drift gate
/// MUST return true regardless of trust/taint state. This is the
/// fail-closed property: store unavailability cannot bypass drift
/// enforcement.
pub proof fn lemma_store_error_alone_triggers_drift()
    ensures spec_fail_closed_drift(true, false, false),
{
    // spec_fail_closed_drift(true, false, false)
    //   = true || false || false
    //   = true
}

/// Prove: the combined decision gate is fail-closed.
/// If store_error OR trust_down OR taint_up, drift_detected = true.
pub open spec fn spec_fail_closed_drift(
    store_error: bool,
    trust_down: bool,
    taint_up: bool,
) -> bool {
    store_error || trust_down || taint_up
}

pub fn fail_closed_drift(
    store_error: bool,
    trust_down: bool,
    taint_up: bool,
) -> (result: bool)
    ensures
        result == spec_fail_closed_drift(store_error, trust_down, taint_up),
        store_error ==> result,
        trust_down ==> result,
        taint_up ==> result,
        !store_error && !trust_down && !taint_up ==> !result,
{
    store_error || trust_down || taint_up
}

pub proof fn lemma_named_assumptions_registered_for_this_kernel()
    ensures assumptions::approval_drift_kernel_assumptions_registered(),
{
    assumptions::lemma_shared_formal_assumptions_registered();
}

} // verus!
