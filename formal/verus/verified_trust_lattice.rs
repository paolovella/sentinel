// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verus-verified algebraic laws for the `TrustTier × SinkClass` product lattice.
//!
//! Proves the lattice laws and flow-admissibility invariants on the rank-based
//! total-order implementations of `TrustTier` and `SinkClass` from
//! `vellaveto-types/src/provenance.rs`.
//!
//! This is the formal backing for ROADMAP Work Package 3A (formal trust lattice
//! for MCP servers) and the cross-cutting verification track requirement:
//! "Add formal lattice, noninterference, and flow-admissibility specs for
//! `TrustTier × SinkClass` enforcement".
//!
//! # Production correspondence
//!
//! - `vellaveto-types/src/provenance.rs` — `TrustTier`, `SinkClass`, `FlowPoint`
//! - `TrustTier::rank()`, `TrustTier::join()`, `TrustTier::meet()`, `TrustTier::can_flow_to()`
//! - `SinkClass::rank()`, `SinkClass::join()`, `SinkClass::meet()`
//! - `FlowPoint::is_admissible()`, `FlowPoint::compose()`, `FlowPoint::trust_deficit()`
//!
//! # Properties Verified
//!
//! ## TrustTier lattice laws (TRUST-LAT-1–6)
//! | ID | Property |
//! |----|----------|
//! | TRUST-LAT-1 | Join is commutative: join(a,b) rank == join(b,a) rank |
//! | TRUST-LAT-2 | Join is idempotent: join(a,a) rank == a.rank() |
//! | TRUST-LAT-3 | Join is the least upper bound: join(a,b).rank() == max(a.rank(), b.rank()) |
//! | TRUST-LAT-4 | Meet is commutative: meet(a,b) rank == meet(b,a) rank |
//! | TRUST-LAT-5 | Meet is idempotent: meet(a,a) rank == a.rank() |
//! | TRUST-LAT-6 | Meet is the greatest lower bound: meet(a,b).rank() == min(a.rank(), b.rank()) |
//!
//! ## Flow admissibility (FLOW-ADM-1–5)
//! | ID | Property |
//! |----|----------|
//! | FLOW-ADM-1 | Fail-closed: if src.rank() < required.rank() and not declassified → denied |
//! | FLOW-ADM-2 | Declassification always opens flow |
//! | FLOW-ADM-3 | Monotone source: more trusted source admits at least as many flows |
//! | FLOW-ADM-4 | Quarantined (rank 0) cannot flow to anything without declassification |
//! | FLOW-ADM-5 | Verified (rank 6) can flow anywhere without declassification |
//!
//! ## FlowPoint product lattice (FLOW-PROD-1–4)
//! | ID | Property |
//! |----|----------|
//! | FLOW-PROD-1 | Composition lowers trust (meet) |
//! | FLOW-PROD-2 | Composition raises sink privilege (join) |
//! | FLOW-PROD-3 | Composition cannot produce an inadmissible flow from two admissible ones if trust is sufficient |
//! | FLOW-PROD-4 | Trust deficit is 0 iff admissible |
//!
//! # To verify
//!
//! ```sh
//! verus --triggers-mode silent formal/verus/verified_trust_lattice.rs
//! ```

#[path = "assumptions.rs"]
mod assumptions;

#[allow(unused_imports)]
use vstd::prelude::*;

verus! {

// ── Spec model ────────────────────────────────────────────────────────────────

/// Max rank for TrustTier (Verified = 6).
pub open spec fn spec_trust_tier_max_rank() -> nat {
    6
}

/// Max rank for SinkClass (PolicyMutation = 8).
pub open spec fn spec_sink_class_max_rank() -> nat {
    8
}

/// Spec: a valid TrustTier rank is in the supported trust-tier range.
pub open spec fn spec_valid_trust_rank(r: nat) -> bool {
    r <= spec_trust_tier_max_rank()
}

/// Spec: a valid SinkClass rank is in the supported sink-class range.
pub open spec fn spec_valid_sink_rank(r: nat) -> bool {
    r <= spec_sink_class_max_rank()
}

/// Spec: join on ranks is max.
pub open spec fn spec_join_rank(a: nat, b: nat) -> nat {
    if a >= b { a } else { b }
}

/// Spec: meet on ranks is min.
pub open spec fn spec_meet_rank(a: nat, b: nat) -> nat {
    if a <= b { a } else { b }
}

// ── TRUST-LAT-1: Join is commutative ─────────────────────────────────────────

pub proof fn lemma_trust_join_commutative(a: nat, b: nat)
    ensures spec_join_rank(a, b) == spec_join_rank(b, a),
{
    // max(a, b) == max(b, a) — direct from the definition.
}

// ── TRUST-LAT-2: Join is idempotent ──────────────────────────────────────────

pub proof fn lemma_trust_join_idempotent(a: nat)
    ensures spec_join_rank(a, a) == a,
{
    // max(a, a) == a.
}

// ── TRUST-LAT-3: Join is the least upper bound ────────────────────────────────

/// join(a, b) >= a and join(a, b) >= b.
pub proof fn lemma_trust_join_upper_bound(a: nat, b: nat)
    ensures
        spec_join_rank(a, b) >= a,
        spec_join_rank(a, b) >= b,
{
    // max(a, b) >= a and max(a, b) >= b by the definition of max.
}

/// join(a, b) is the LEAST upper bound: any upper bound c >= a and c >= b
/// implies c >= join(a, b).
pub proof fn lemma_trust_join_is_lub(a: nat, b: nat, c: nat)
    requires c >= a && c >= b,
    ensures c >= spec_join_rank(a, b),
{
    // If c >= a and c >= b, then c >= max(a, b).
}

/// join is associative: join(a, join(b, c)) == join(join(a, b), c).
pub proof fn lemma_trust_join_associative(a: nat, b: nat, c: nat)
    ensures spec_join_rank(a, spec_join_rank(b, c)) == spec_join_rank(spec_join_rank(a, b), c),
{
    // max(a, max(b, c)) == max(max(a, b), c) — both equal max(a, b, c).
}

// ── TRUST-LAT-4: Meet is commutative ─────────────────────────────────────────

pub proof fn lemma_trust_meet_commutative(a: nat, b: nat)
    ensures spec_meet_rank(a, b) == spec_meet_rank(b, a),
{
    // min(a, b) == min(b, a).
}

// ── TRUST-LAT-5: Meet is idempotent ──────────────────────────────────────────

pub proof fn lemma_trust_meet_idempotent(a: nat)
    ensures spec_meet_rank(a, a) == a,
{
    // min(a, a) == a.
}

// ── TRUST-LAT-6: Meet is the greatest lower bound ─────────────────────────────

/// meet(a, b) <= a and meet(a, b) <= b.
pub proof fn lemma_trust_meet_lower_bound(a: nat, b: nat)
    ensures
        spec_meet_rank(a, b) <= a,
        spec_meet_rank(a, b) <= b,
{
    // min(a, b) <= a and min(a, b) <= b.
}

/// meet(a, b) is the GREATEST lower bound.
pub proof fn lemma_trust_meet_is_glb(a: nat, b: nat, c: nat)
    requires c <= a && c <= b,
    ensures c <= spec_meet_rank(a, b),
{
    // If c <= a and c <= b, then c <= min(a, b).
}

/// meet is associative: meet(a, meet(b, c)) == meet(meet(a, b), c).
pub proof fn lemma_trust_meet_associative(a: nat, b: nat, c: nat)
    ensures spec_meet_rank(a, spec_meet_rank(b, c)) == spec_meet_rank(spec_meet_rank(a, b), c),
{
    // min(a, min(b, c)) == min(min(a, b), c).
}

// ── Absorption laws ────────────────────────────────────────────────────────────

/// join(a, meet(a, b)) == a.
pub proof fn lemma_trust_absorption_join(a: nat, b: nat)
    ensures spec_join_rank(a, spec_meet_rank(a, b)) == a,
{
    // max(a, min(a, b)) == a since min(a, b) <= a.
}

/// meet(a, join(a, b)) == a.
pub proof fn lemma_trust_absorption_meet(a: nat, b: nat)
    ensures spec_meet_rank(a, spec_join_rank(a, b)) == a,
{
    // min(a, max(a, b)) == a since max(a, b) >= a.
}

// ── FLOW-ADM-1: Fail-closed flow admissibility ────────────────────────────────

/// Spec: `can_flow_to` on rank values.
pub open spec fn spec_can_flow_to(src_rank: nat, required_rank: nat, declassified: bool) -> bool {
    declassified || src_rank >= required_rank
}

/// If source rank is below required and not declassified, flow is denied.
pub proof fn lemma_flow_adm_fail_closed(src_rank: nat, required_rank: nat)
    requires src_rank < required_rank,
    ensures !spec_can_flow_to(src_rank, required_rank, false),
{
    // declassified = false AND src_rank < required_rank → denied.
}

// ── FLOW-ADM-2: Declassification always opens flow ────────────────────────────

pub proof fn lemma_flow_adm_declassification_opens(src_rank: nat, required_rank: nat)
    ensures spec_can_flow_to(src_rank, required_rank, true),
{
    // declassified = true → always admitted.
}

// ── FLOW-ADM-3: Monotone source ───────────────────────────────────────────────

/// More trusted source admits at least as many flows (without declassification).
pub proof fn lemma_flow_adm_monotone_source(
    src_high: nat,
    src_low: nat,
    required_rank: nat,
)
    requires
        src_high >= src_low,
        spec_can_flow_to(src_low, required_rank, false),
    ensures
        spec_can_flow_to(src_high, required_rank, false),
{
    // src_low >= required, src_high >= src_low → src_high >= required.
}

/// The set of flows admitted by a higher trust source is a superset.
pub proof fn lemma_flow_adm_superset(src_high: nat, src_low: nat, required: nat)
    requires src_high >= src_low,
    ensures
        spec_can_flow_to(src_low, required, false)
            ==> spec_can_flow_to(src_high, required, false),
{
    // If src_low >= required (admits flow), then src_high >= required (also admits).
    // If src_low < required (denies flow), then trivially >= (false >= false = 0 >= 0).
}

// ── FLOW-ADM-4: Quarantined cannot flow without declassification ──────────────

/// Quarantined rank = 0. It cannot flow to anything requiring rank >= 1.
pub proof fn lemma_flow_adm_quarantined_fail_closed(required_rank: nat)
    requires required_rank >= 1,
    ensures !spec_can_flow_to(0, required_rank, false),
{
    // 0 < required_rank → denied (without declassification).
}

// ── FLOW-ADM-5: Verified (max rank) can flow anywhere without declassification ─

/// Verified rank is the maximum trust tier. It can flow to any required rank <= 6.
pub proof fn lemma_flow_adm_verified_admits_all(required_rank: nat)
    requires required_rank <= spec_trust_tier_max_rank(),
    ensures spec_can_flow_to(spec_trust_tier_max_rank(), required_rank, false),
{
    // The maximum trust tier is >= required_rank, so the flow is admitted.
}

// ── Privileged sink threshold monotonicity ────────────────────────────────────

/// Spec: minimum trust rank required for a given sink class rank.
/// Higher sink privilege → higher minimum trust required.
/// Mirrors `minimum_trust_tier_for_sink()` in production.
pub open spec fn spec_min_trust_for_sink(sink_rank: nat) -> nat {
    // Based on the production mapping in vellaveto-types/src/provenance.rs:
    // ReadOnly(0) → Unknown(1), LowRiskWrite(1) → Untrusted(2),
    // FilesystemWrite(2) → Low(3), NetworkEgress(3) → Low(3),
    // MemoryWrite(4) → Medium(4), ApprovalUi(5) → Medium(4),
    // CodeExecution(6) → High(5), CredentialAccess(7) → High(5),
    // PolicyMutation(8) → Verified(6).
    if sink_rank == 0 { 1 }       // ReadOnly: Unknown (rank 1)
    else if sink_rank == 1 { 2 }  // LowRiskWrite: Untrusted (rank 2)
    else if sink_rank <= 3 { 3 }  // FilesystemWrite/NetworkEgress: Low (rank 3)
    else if sink_rank <= 5 { 4 }  // MemoryWrite/ApprovalUi: Medium (rank 4)
    else if sink_rank <= 7 { 5 }  // CodeExecution/CredentialAccess: High (rank 5)
    else { 6 }                    // PolicyMutation: Verified (rank 6)
}

/// TC6 (mirrors TrustContainment.tla): more privileged sinks require at least
/// as much trust.
pub proof fn lemma_sink_threshold_monotone(s1: nat, s2: nat)
    requires
        spec_valid_sink_rank(s1),
        spec_valid_sink_rank(s2),
        s1 <= s2,
    ensures
        spec_min_trust_for_sink(s1) <= spec_min_trust_for_sink(s2),
{
    // The spec function is non-decreasing in sink_rank — verified by case analysis.
    // s1 <= s2, both in [0..8], and spec_min_trust_for_sink is piecewise non-decreasing.
    assert(s1 <= 8 && s2 <= 8);
    // Case-split on s1 and s2 ranges: since s1 <= s2 and both <= 8,
    // the threshold for s2 is at least the threshold for s1.
}

// ── FLOW-PROD-1: Composition lowers trust ─────────────────────────────────────

/// Sequential composition of two flow points: trust can only decrease (meet = min).
pub proof fn lemma_flow_prod_compose_lowers_trust(t1: nat, t2: nat)
    requires
        spec_valid_trust_rank(t1),
        spec_valid_trust_rank(t2),
    ensures
        spec_meet_rank(t1, t2) <= t1,
        spec_meet_rank(t1, t2) <= t2,
{
    lemma_trust_meet_lower_bound(t1, t2);
}

// ── FLOW-PROD-2: Composition raises sink privilege ────────────────────────────

/// Sequential composition of two flow points: sink privilege can only increase (join = max).
pub proof fn lemma_flow_prod_compose_raises_sink(s1: nat, s2: nat)
    requires
        spec_valid_sink_rank(s1),
        spec_valid_sink_rank(s2),
    ensures
        spec_join_rank(s1, s2) >= s1,
        spec_join_rank(s1, s2) >= s2,
{
    lemma_trust_join_upper_bound(s1, s2);
}

// ── FLOW-PROD-3: Admissibility after composition ──────────────────────────────

/// If both flow points are individually admissible and the composed trust is
/// sufficient for the composed sink, the composition is also admissible.
pub proof fn lemma_flow_prod_compose_admissible(t1: nat, t2: nat, s1: nat, s2: nat)
    requires
        spec_valid_trust_rank(t1),
        spec_valid_trust_rank(t2),
        spec_valid_sink_rank(s1),
        spec_valid_sink_rank(s2),
        // The composed trust meets the composed sink's threshold.
        spec_meet_rank(t1, t2) >= spec_min_trust_for_sink(spec_join_rank(s1, s2)),
    ensures
        spec_can_flow_to(
            spec_meet_rank(t1, t2),
            spec_min_trust_for_sink(spec_join_rank(s1, s2)),
            false,
        ),
{
    // meet(t1,t2) >= min_trust_for_sink(join(s1,s2)) → admissible without declassification.
}

/// Negative: an individually admissible flow may become inadmissible after
/// composition when trust decreases but sink privilege increases.
///
/// This formalizes the key security insight: composing an untrusted flow
/// (low trust) with a privileged sink (high sink class) can create an
/// escalation that neither flow individually represents.
pub proof fn lemma_flow_prod_compose_can_escalate(t1: nat, t2: nat, s1: nat, s2: nat)
    requires
        spec_valid_trust_rank(t1),
        spec_valid_trust_rank(t2),
        spec_valid_sink_rank(s1),
        spec_valid_sink_rank(s2),
        // First flow is admissible.
        t1 >= spec_min_trust_for_sink(s1),
        // After composition, the combined trust may be below the combined sink threshold.
        spec_meet_rank(t1, t2) < spec_min_trust_for_sink(spec_join_rank(s1, s2)),
    ensures
        // The composition is NOT admissible (without declassification).
        !spec_can_flow_to(
            spec_meet_rank(t1, t2),
            spec_min_trust_for_sink(spec_join_rank(s1, s2)),
            false,
        ),
{
    lemma_flow_adm_fail_closed(
        spec_meet_rank(t1, t2),
        spec_min_trust_for_sink(spec_join_rank(s1, s2)),
    );
}

// ── FLOW-PROD-4: Trust deficit is 0 iff admissible ────────────────────────────

/// Spec: trust deficit for a flow point.
pub open spec fn spec_trust_deficit(trust_rank: nat, sink_rank: nat) -> nat {
    let required = spec_min_trust_for_sink(sink_rank);
    if required > trust_rank { (required - trust_rank) as nat } else { 0 }
}

/// Trust deficit is 0 iff the flow is admissible (without declassification).
pub proof fn lemma_flow_deficit_zero_iff_admissible(trust_rank: nat, sink_rank: nat)
    requires
        spec_valid_trust_rank(trust_rank),
        spec_valid_sink_rank(sink_rank),
    ensures
        (spec_trust_deficit(trust_rank, sink_rank) == 0)
            <==> spec_can_flow_to(trust_rank, spec_min_trust_for_sink(sink_rank), false),
{
    let required = spec_min_trust_for_sink(sink_rank);
    if trust_rank >= required {
        // Admissible → deficit = 0.
        assert(spec_trust_deficit(trust_rank, sink_rank) == 0);
        assert(spec_can_flow_to(trust_rank, required, false));
    } else {
        // Not admissible → deficit > 0.
        assert(required > trust_rank);
        assert(spec_trust_deficit(trust_rank, sink_rank) == (required - trust_rank) as nat);
        assert(!spec_can_flow_to(trust_rank, required, false));
    }
}

// ── Cross-cutting: WP 3A flow admissibility composition ───────────────────────

/// End-to-end: if tainted content (low trust) flows into a privileged sink
/// (high privilege) without declassification, the flow is denied.
/// This is the machine-checked version of TrustContainment.tla TC1-TC3.
pub proof fn lemma_tainted_privileged_flow_denied(
    source_trust_rank: nat,
    sink_class_rank: nat,
)
    requires
        spec_valid_trust_rank(source_trust_rank),
        spec_valid_sink_rank(sink_class_rank),
        source_trust_rank < spec_min_trust_for_sink(sink_class_rank),
    ensures
        !spec_can_flow_to(source_trust_rank, spec_min_trust_for_sink(sink_class_rank), false),
        spec_trust_deficit(source_trust_rank, sink_class_rank) > 0,
{
    lemma_flow_adm_fail_closed(source_trust_rank, spec_min_trust_for_sink(sink_class_rank));
    // deficit = required - trust_rank > 0 since required > trust_rank.
    assert(spec_min_trust_for_sink(sink_class_rank) > source_trust_rank);
    assert(spec_trust_deficit(source_trust_rank, sink_class_rank) > 0);
}

/// Declassification is the ONLY way for low-trust content to reach privileged sinks.
pub proof fn lemma_only_declassification_opens_privileged_flow(
    source_trust_rank: nat,
    sink_class_rank: nat,
)
    requires
        spec_valid_trust_rank(source_trust_rank),
        spec_valid_sink_rank(sink_class_rank),
        source_trust_rank < spec_min_trust_for_sink(sink_class_rank),
    ensures
        // Without declassification: denied.
        !spec_can_flow_to(source_trust_rank, spec_min_trust_for_sink(sink_class_rank), false),
        // With declassification: admitted.
        spec_can_flow_to(source_trust_rank, spec_min_trust_for_sink(sink_class_rank), true),
{
    lemma_flow_adm_fail_closed(source_trust_rank, spec_min_trust_for_sink(sink_class_rank));
    lemma_flow_adm_declassification_opens(source_trust_rank, spec_min_trust_for_sink(sink_class_rank));
}

// ── Assumption registration ────────────────────────────────────────────────────

pub proof fn lemma_named_assumptions_registered_for_this_kernel()
    ensures assumptions::trust_lattice_kernel_assumptions_registered(),
{
    assumptions::lemma_shared_formal_assumptions_registered();
}

fn main() {}

} // verus!
