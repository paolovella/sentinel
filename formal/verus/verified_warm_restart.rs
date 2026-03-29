// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verus-verified session warm restart guards (WARM-1–3).
//!
//! Proves the extracted predicates for selective session restoration
//! from a persistent backend: only security-critical states are restored,
//! max_sessions bound is respected, and counter arithmetic is safe.
//!
//! Production code: `vellaveto-mcp/src/session_guard.rs:634-671`
//!
//! To verify:
//!   `verus --triggers-mode silent formal/verus/verified_warm_restart.rs`

#[path = "assumptions.rs"]
mod assumptions;

#[allow(unused_imports)]
use vstd::prelude::*;

verus! {

#[derive(Structural, PartialEq, Eq, Clone, Copy)]
pub enum SessionState {
    Init,
    Active,
    Suspicious,
    Locked,
    Ended,
}

// ═══════════════════════════════════════════════════════════════════
// WARM-1: Selective restoration — only Locked and Suspicious
// ═══════════════════════════════════════════════════════════════════

/// Only security-critical session states should be restored on warm
/// restart. Init and Active are transient; Ended is terminal.
pub open spec fn spec_should_restore(state: SessionState) -> bool {
    state == SessionState::Locked || state == SessionState::Suspicious
}

pub fn should_restore(state: SessionState) -> (result: bool)
    ensures
        result == spec_should_restore(state),
        // Locked sessions are restored (attacker-blocked sessions survive restart)
        state == SessionState::Locked ==> result,
        // Suspicious sessions are restored (anomaly evidence survives restart)
        state == SessionState::Suspicious ==> result,
        // Init sessions are NOT restored (transient, no security state)
        state == SessionState::Init ==> !result,
        // Active sessions are NOT restored (transient, no violation history)
        state == SessionState::Active ==> !result,
        // Ended sessions are NOT restored (terminal, no further transitions)
        state == SessionState::Ended ==> !result,
{
    matches!(state, SessionState::Locked | SessionState::Suspicious)
}

/// Prove: each non-restorable state is explicitly excluded.
/// This is stronger than an exhaustive disjunction — it proves the
/// negative cases individually, not just that all states are covered.
pub proof fn lemma_init_not_restored()
    ensures !spec_should_restore(SessionState::Init),
{
}

pub proof fn lemma_active_not_restored()
    ensures !spec_should_restore(SessionState::Active),
{
}

pub proof fn lemma_ended_not_restored()
    ensures !spec_should_restore(SessionState::Ended),
{
}

pub proof fn lemma_locked_is_restored()
    ensures spec_should_restore(SessionState::Locked),
{
}

pub proof fn lemma_suspicious_is_restored()
    ensures spec_should_restore(SessionState::Suspicious),
{
}

// ═══════════════════════════════════════════════════════════════════
// WARM-2: max_sessions bound enforcement
// ═══════════════════════════════════════════════════════════════════

/// The restoration loop must stop before exceeding max_sessions.
pub open spec fn spec_can_insert(current_count: usize, max_sessions: usize) -> bool {
    current_count < max_sessions
}

pub fn can_insert(current_count: usize, max_sessions: usize) -> (result: bool)
    ensures
        result == spec_can_insert(current_count, max_sessions),
        result ==> current_count < max_sessions,
        !result ==> current_count >= max_sessions,
{
    current_count < max_sessions
}

/// Prove: after insertion, the session count is still within bounds.
pub proof fn lemma_insert_preserves_bound(
    count_before: usize,
    max_sessions: usize,
)
    requires
        count_before < max_sessions,
        count_before < usize::MAX,
    ensures
        count_before + 1 <= max_sessions,
{
}

// ═══════════════════════════════════════════════════════════════════
// WARM-3: Saturating arithmetic on restored counter
// ═══════════════════════════════════════════════════════════════════

/// The restored counter uses saturating_add to prevent overflow.
/// Even at usize::MAX, adding 1 produces usize::MAX (not 0).
pub open spec fn spec_saturating_add(a: usize, b: usize) -> usize {
    if a + b > usize::MAX as int {
        usize::MAX as usize
    } else {
        (a + b) as usize
    }
}

/// Prove: saturating_add never wraps to zero.
/// (Verus auto-discharges this from the spec definition, but we
/// include the reasoning for documentation.)
pub proof fn lemma_saturating_add_never_zero(a: usize, b: usize)
    requires a > 0 || b > 0,
    ensures spec_saturating_add(a, b) > 0,
{
    // Case 1: a + b <= usize::MAX → result = a + b > 0 (since a>0 or b>0)
    // Case 2: a + b > usize::MAX → result = usize::MAX > 0
}

/// Prove: saturating_add never exceeds usize::MAX.
/// (Trivially true from the spec definition's cap.)
pub proof fn lemma_saturating_add_bounded(a: usize, b: usize)
    ensures spec_saturating_add(a, b) <= usize::MAX as usize,
{
    // Both branches of spec_saturating_add return <= usize::MAX by construction.
}

pub proof fn lemma_named_assumptions_registered_for_this_kernel()
    ensures assumptions::warm_restart_kernel_assumptions_registered(),
{
    assumptions::lemma_shared_formal_assumptions_registered();
}

} // verus!
