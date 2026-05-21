// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verus-verified replay non-admission and fail-closed unknown-provenance guards.
//!
//! Proves the algebraic properties of `ReplayStatus` merging and the
//! end-to-end connection from a detected replay to privileged-sink denial.
//!
//! This kernel is the machine-checked version of the cross-cutting verification
//! track requirement:
//! > "Add focused formal invariants for replay non-admission [...] and
//! > fail-closed unknown-provenance handling"
//!
//! # Production correspondence
//!
//! - `vellaveto-types/src/provenance.rs` — `ReplayStatus` enum
//! - `vellaveto-http-proxy/src/proxy/helpers.rs::merge_replay_status` — absorbing merge
//! - `vellaveto-http-proxy/src/proxy/helpers.rs` (lines 920–923) — replay → Quarantined clamp
//! - `vellaveto-types/src/provenance.rs::TrustTier::rank` — Quarantined = 0
//!
//! # Composition
//!
//! This kernel bridges `verified_trust_lattice.rs` (flow admissibility) with
//! the transport-level replay detection: the chain is
//!
//!   `ReplayDetected → TrustTier::Quarantined (rank 0) → flow denied to privileged sinks`
//!
//! # Properties Verified
//!
//! | ID | Property |
//! |----|----------|
//! | REPLAY-MERGE-1 | Merge is symmetric: merge(a, b) == merge(b, a) |
//! | REPLAY-MERGE-2 | ReplayDetected is absorbing: merge(ReplayDetected, _) == ReplayDetected |
//! | REPLAY-MERGE-3 | Fresh is second-highest: merge(Fresh, NotChecked) == Fresh |
//! | REPLAY-MERGE-4 | Merge is associative: merge(a, merge(b, c)) == merge(merge(a, b), c) |
//! | REPLAY-MERGE-5 | Merge is monotone: if a is worse-or-equal to a2, merge(a, b) is worse-or-equal to merge(a2, b) |
//! | REPLAY-ADMIT-1 | ReplayDetected clamps effective trust to Quarantined (rank 0) |
//! | REPLAY-ADMIT-2 | NotChecked ≠ Fresh — unknown replay status is not equivalent to verified fresh |
//! | REPLAY-ADMIT-3 | Quarantined rank 0 → privileged sink flow denied without declassification |
//! | REPLAY-ADMIT-4 | End-to-end: ReplayDetected → Quarantined trust → privileged sink denied |
//! | REPLAY-ADMIT-5 | Positive: Fresh + sufficient trust → privileged sink admissible |
//!
//! # To verify
//!
//! ```sh
//! verus --triggers-mode silent formal/verus/verified_replay_provenance.rs
//! ```

#[path = "assumptions.rs"]
mod assumptions;

#[allow(unused_imports)]
use vstd::prelude::*;

verus! {

// ── Abstract ReplayStatus model ────────────────────────────────────────────────

/// Abstract replay status — matches `vellaveto-types/src/provenance.rs::ReplayStatus`.
/// The integer rank encodes severity (higher = more restrictive):
/// - NotChecked = 0: replay was not verified (unknown)
/// - Fresh     = 1: verified non-replay
/// - ReplayDetected = 2: confirmed replay attempt
#[derive(Structural, PartialEq, Eq, Clone, Copy)]
pub enum ReplayStatus {
    NotChecked,
    Fresh,
    ReplayDetected,
}

pub open spec fn spec_replay_rank(s: ReplayStatus) -> nat {
    match s {
        ReplayStatus::NotChecked   => 0,
        ReplayStatus::Fresh        => 1,
        ReplayStatus::ReplayDetected => 2,
    }
}

/// Spec: the merge of two replay statuses — absorbing join (max-rank wins).
/// Mirrors `merge_replay_status` in `vellaveto-http-proxy/src/proxy/helpers.rs`.
pub open spec fn spec_merge_replay(a: ReplayStatus, b: ReplayStatus) -> ReplayStatus {
    match (a, b) {
        (ReplayStatus::ReplayDetected, _) | (_, ReplayStatus::ReplayDetected)
            => ReplayStatus::ReplayDetected,
        (ReplayStatus::Fresh, _) | (_, ReplayStatus::Fresh)
            => ReplayStatus::Fresh,
        _ => ReplayStatus::NotChecked,
    }
}

pub fn merge_replay_status(a: ReplayStatus, b: ReplayStatus) -> (result: ReplayStatus)
    ensures result == spec_merge_replay(a, b),
{
    match (a, b) {
        (ReplayStatus::ReplayDetected, _) | (_, ReplayStatus::ReplayDetected)
            => ReplayStatus::ReplayDetected,
        (ReplayStatus::Fresh, _) | (_, ReplayStatus::Fresh)
            => ReplayStatus::Fresh,
        _ => ReplayStatus::NotChecked,
    }
}

// ── REPLAY-MERGE-1: Symmetry ───────────────────────────────────────────────────

pub proof fn lemma_replay_merge_symmetric(a: ReplayStatus, b: ReplayStatus)
    ensures spec_merge_replay(a, b) == spec_merge_replay(b, a),
{
    // Case analysis on all 9 combinations: symmetric by the definition.
    match (a, b) {
        (ReplayStatus::ReplayDetected, _) => {},
        (_, ReplayStatus::ReplayDetected) => {},
        (ReplayStatus::Fresh, _)          => {},
        (_, ReplayStatus::Fresh)          => {},
        _                                 => {},
    }
}

// ── REPLAY-MERGE-2: ReplayDetected is absorbing ────────────────────────────────

pub proof fn lemma_replay_detected_absorbs(b: ReplayStatus)
    ensures
        spec_merge_replay(ReplayStatus::ReplayDetected, b) == ReplayStatus::ReplayDetected,
        spec_merge_replay(b, ReplayStatus::ReplayDetected) == ReplayStatus::ReplayDetected,
{
    // From the definition: first branch fires on ReplayDetected.
}

/// ReplayDetected cannot be washed out by any subsequent merge.
pub proof fn lemma_replay_detected_is_permanent(b: ReplayStatus, c: ReplayStatus)
    ensures
        spec_merge_replay(spec_merge_replay(ReplayStatus::ReplayDetected, b), c)
            == ReplayStatus::ReplayDetected,
{
    // merge(merge(ReplayDetected, b), c) = merge(ReplayDetected, c) = ReplayDetected.
    assert(spec_merge_replay(ReplayStatus::ReplayDetected, b) == ReplayStatus::ReplayDetected);
}

// ── REPLAY-MERGE-3: Fresh is second-priority ──────────────────────────────────

pub proof fn lemma_fresh_beats_not_checked()
    ensures
        spec_merge_replay(ReplayStatus::Fresh, ReplayStatus::NotChecked)
            == ReplayStatus::Fresh,
        spec_merge_replay(ReplayStatus::NotChecked, ReplayStatus::Fresh)
            == ReplayStatus::Fresh,
{
    // From the definition: ReplayDetected branch doesn't fire, Fresh branch fires.
}

// ── REPLAY-MERGE-4: Associativity ─────────────────────────────────────────────

pub proof fn lemma_replay_merge_associative(a: ReplayStatus, b: ReplayStatus, c: ReplayStatus)
    ensures
        spec_merge_replay(a, spec_merge_replay(b, c))
            == spec_merge_replay(spec_merge_replay(a, b), c),
{
    // Full case analysis on all 27 combinations.
    match (a, b, c) {
        (ReplayStatus::ReplayDetected, _, _) => {},
        (_, ReplayStatus::ReplayDetected, _) => {},
        (_, _, ReplayStatus::ReplayDetected) => {},
        (ReplayStatus::Fresh, _, _)          => {},
        (_, ReplayStatus::Fresh, _)          => {},
        (_, _, ReplayStatus::Fresh)          => {},
        _                                    => {},
    }
}

// ── REPLAY-MERGE-5: Rank monotonicity ─────────────────────────────────────────

/// If `a` has a higher or equal rank than `a2`, the merged result is also
/// higher or equal — replay status merges are monotone in severity.
pub proof fn lemma_replay_merge_rank_monotone(
    a: ReplayStatus,
    a2: ReplayStatus,
    b: ReplayStatus,
)
    requires spec_replay_rank(a) >= spec_replay_rank(a2),
    ensures
        spec_replay_rank(spec_merge_replay(a, b))
            >= spec_replay_rank(spec_merge_replay(a2, b)),
{
    // If a is worse-or-equal to a2, merging with b can't make the result better.
    match (a, a2, b) {
        (ReplayStatus::ReplayDetected, _, _) => {
            // merge(ReplayDetected, b) = ReplayDetected (rank 2), always >= anything.
        },
        (ReplayStatus::Fresh, ReplayStatus::NotChecked, _) => {
            // merge(Fresh, b) ∈ {Fresh, ReplayDetected} (rank >= 1)
            // merge(NotChecked, b) ∈ {NotChecked, Fresh, ReplayDetected}
            // max rank of merge(Fresh, b) >= max rank of merge(NotChecked, b) in all cases
        },
        (ReplayStatus::Fresh, ReplayStatus::Fresh, _) => {},
        (ReplayStatus::NotChecked, ReplayStatus::NotChecked, _) => {},
        _ => {
            // remaining cases: a has same rank as a2
        },
    }
}

// ── REPLAY-ADMIT-1: ReplayDetected → Quarantined trust (rank 0) ───────────────

/// Spec: the effective trust rank given a replay status.
/// `ReplayDetected` clamps to Quarantined (rank 0).
/// `NotChecked` clamps to Unknown (rank 1) — conservative.
/// `Fresh` does not modify trust (returns the provided base rank).
pub open spec fn spec_effective_trust_rank(
    replay_status: ReplayStatus,
    base_trust_rank: nat,
) -> nat {
    match replay_status {
        ReplayStatus::ReplayDetected => 0,  // Quarantined
        ReplayStatus::NotChecked     => if base_trust_rank > 1 { 1 } else { base_trust_rank },  // capped at Unknown
        ReplayStatus::Fresh          => base_trust_rank,
    }
}

/// If replay is detected, effective trust is exactly Quarantined (rank 0).
pub proof fn lemma_replay_admit_detected_clamps_to_quarantined(base_trust_rank: nat)
    ensures spec_effective_trust_rank(ReplayStatus::ReplayDetected, base_trust_rank) == 0,
{
    // Direct from the spec function.
}

// ── REPLAY-ADMIT-2: NotChecked ≠ Fresh ────────────────────────────────────────

/// An unchecked replay status is not equivalent to a verified fresh status —
/// "unknown" is treated conservatively, not optimistically.
pub proof fn lemma_replay_admit_not_checked_ne_fresh()
    ensures ReplayStatus::NotChecked != ReplayStatus::Fresh,
{
    // The two enum variants are distinct.
}

/// NotChecked caps trust at Unknown (rank 1), while Fresh preserves base trust.
/// This means unchecked provenance cannot access anything requiring rank > 1.
pub proof fn lemma_replay_admit_not_checked_is_conservative(base_trust_rank: nat)
    requires base_trust_rank > 1,
    ensures
        spec_effective_trust_rank(ReplayStatus::NotChecked, base_trust_rank) == 1,
        spec_effective_trust_rank(ReplayStatus::Fresh, base_trust_rank) == base_trust_rank,
        spec_effective_trust_rank(ReplayStatus::Fresh, base_trust_rank)
            > spec_effective_trust_rank(ReplayStatus::NotChecked, base_trust_rank),
{
    // From the spec function: NotChecked returns min(base, 1) = 1 when base > 1.
}

// ── REPLAY-ADMIT-3: Quarantined rank 0 → flow denied without declassification ──

/// Spec: min trust required for a privileged sink (rank >= 1).
/// Mirrors `spec_min_trust_for_sink` from `verified_trust_lattice.rs`.
pub open spec fn spec_sink_requires_trust(sink_rank: nat) -> bool {
    sink_rank >= 1  // any non-ReadOnly sink requires at least Unknown trust
}

/// Quarantined (rank 0) cannot flow to any sink requiring trust rank >= 1.
pub proof fn lemma_replay_admit_quarantined_flow_denied(sink_rank: nat)
    requires sink_rank >= 1,
    ensures
        // Effective trust rank 0 < sink requirement rank 1 → denied without declassification.
        !(0 >= sink_rank as nat),
{
    // 0 < sink_rank (since sink_rank >= 1) → 0 does not satisfy >= sink_rank.
    assert(0 < sink_rank as nat);
}

// ── REPLAY-ADMIT-4: End-to-end chain ─────────────────────────────────────────

/// End-to-end: ReplayDetected → effective trust = Quarantined (rank 0) →
/// cannot flow to any privileged sink (rank >= 1) without declassification.
///
/// This is the machine-checked version of the cross-cutting requirement:
/// "replay non-admission" — replayed requests cannot silently drive
/// privileged actions.
pub proof fn lemma_replay_admit_end_to_end_denied(
    base_trust_rank: nat,
    privileged_sink_rank: nat,
)
    requires privileged_sink_rank >= 1,
    ensures
        // (1) ReplayDetected clamps to rank 0.
        spec_effective_trust_rank(ReplayStatus::ReplayDetected, base_trust_rank) == 0,
        // (2) Rank 0 cannot flow to sink requiring >= 1.
        !(spec_effective_trust_rank(ReplayStatus::ReplayDetected, base_trust_rank)
            >= privileged_sink_rank as nat),
{
    lemma_replay_admit_detected_clamps_to_quarantined(base_trust_rank);
    assert(spec_effective_trust_rank(ReplayStatus::ReplayDetected, base_trust_rank) == 0);
    assert(0 < privileged_sink_rank as nat);
}

/// Replay cannot be "undone" by a later fresh transport: once ReplayDetected
/// is merged into the session status, the combined result remains ReplayDetected.
pub proof fn lemma_replay_detected_survives_fresh_merge(
    prior_status: ReplayStatus,
    later_fresh: ReplayStatus,
)
    requires
        prior_status == ReplayStatus::ReplayDetected,
        later_fresh == ReplayStatus::Fresh,
    ensures
        spec_merge_replay(prior_status, later_fresh) == ReplayStatus::ReplayDetected,
{
    // From REPLAY-MERGE-2: ReplayDetected is absorbing.
    lemma_replay_detected_absorbs(later_fresh);
}

// ── REPLAY-ADMIT-5: Positive — Fresh + sufficient trust → admissible ──────────

/// A fresh (non-replayed) request with sufficient trust can access privileged sinks.
/// This confirms the gate is not over-restrictive.
pub proof fn lemma_replay_admit_fresh_with_trust_admitted(
    base_trust_rank: nat,
    required_sink_rank: nat,
)
    requires
        base_trust_rank >= required_sink_rank,
        required_sink_rank <= 6,  // within valid trust range
    ensures
        // Fresh preserves the base trust rank.
        spec_effective_trust_rank(ReplayStatus::Fresh, base_trust_rank) == base_trust_rank,
        // And that rank is sufficient for the sink.
        spec_effective_trust_rank(ReplayStatus::Fresh, base_trust_rank) >= required_sink_rank,
{
    // From the spec function: Fresh returns base_trust_rank unchanged.
}

// ── Fail-closed unknown-provenance composition ────────────────────────────────

/// A request where replay was not checked AND whose base trust would be high
/// is still capped at Unknown (rank 1), preventing privileged access.
pub proof fn lemma_fail_closed_not_checked_caps_access(
    base_trust_rank: nat,
    privileged_sink_rank: nat,
)
    requires
        base_trust_rank >= 3,   // would be Low or higher without replay check
        privileged_sink_rank >= 3,  // FilesystemWrite or higher
    ensures
        // Effective trust is capped at Unknown (rank 1).
        spec_effective_trust_rank(ReplayStatus::NotChecked, base_trust_rank) == 1,
        // Rank 1 < rank 3 → cannot flow to FilesystemWrite+ without declassification.
        spec_effective_trust_rank(ReplayStatus::NotChecked, base_trust_rank)
            < privileged_sink_rank as nat,
{
    lemma_replay_admit_not_checked_is_conservative(base_trust_rank);
}

/// Full unknown-provenance chain: NotChecked → capped at Unknown → denied to
/// high-privilege sinks. This is the machine-checked version of the cross-cutting
/// requirement: "fail-closed unknown-provenance handling".
pub proof fn lemma_unknown_provenance_fail_closed_end_to_end(
    base_trust_rank: nat,
    privileged_sink_rank: nat,
)
    requires
        base_trust_rank > 1,
        privileged_sink_rank > 1,
    ensures
        !(spec_effective_trust_rank(ReplayStatus::NotChecked, base_trust_rank)
            >= privileged_sink_rank as nat),
{
    // spec_effective_trust_rank(NotChecked, base) = 1
    // privileged_sink_rank > 1 → 1 < privileged_sink_rank → denied.
    assert(spec_effective_trust_rank(ReplayStatus::NotChecked, base_trust_rank) == 1);
    assert(1 < privileged_sink_rank as nat);
}

// ── Assumption registration ────────────────────────────────────────────────────

pub proof fn lemma_named_assumptions_registered_for_this_kernel()
    ensures assumptions::replay_provenance_kernel_assumptions_registered(),
{
    assumptions::lemma_shared_formal_assumptions_registered();
}

fn main() {}

} // verus!
