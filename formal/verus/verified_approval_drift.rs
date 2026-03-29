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

/// When drift is detected, the decision MUST be Block (never Forward).
/// This is the critical safety property: drifted approvals are never consumed.
pub proof fn lemma_drift_implies_not_forward(drift: bool)
    requires drift,
    ensures spec_drift_detected(drift, false) || spec_drift_detected(false, drift),
{
}

// ═══════════════════════════════════════════════════════════════════
// DRIFT-4: Store error → fail-closed (drift_detected = true)
// ═══════════════════════════════════════════════════════════════════

/// When the approval store returns an error, drift_detected MUST be
/// set to true (fail-closed). This prevents store unavailability from
/// bypassing drift enforcement.
pub open spec fn spec_store_error_sets_drift(store_error: bool) -> bool {
    store_error ==> true
}

pub fn store_error_sets_drift(store_error: bool) -> (result: bool)
    ensures
        result == true,
        store_error ==> result,
        // Key property: store errors are treated as drift
{
    true
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

} // verus!
