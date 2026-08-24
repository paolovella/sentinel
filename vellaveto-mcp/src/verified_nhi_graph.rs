// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verified NHI delegation graph guards.
//!
//! This module extracts the pure graph predicates used by `nhi.rs` when
//! deciding whether an existing delegation link is live for forward traversal
//! and whether inserting a new delegation edge preserves acyclicity.

/// Return true when a delegation link can be followed from the current agent to
/// its successor during forward graph traversal.
///
/// The expiry parse boundary is fail-closed: an unparseable timestamp is not a
/// live edge.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn delegation_link_effective_for_successor(
    from_agent_matches_current: bool,
    link_active: bool,
    expiry_parsed: bool,
    now_before_expiry: bool,
) -> bool {
    from_agent_matches_current && link_active && expiry_parsed && now_before_expiry
}

/// Return true when inserting a new delegation edge preserves acyclicity.
///
/// Callers compute `path_from_delegatee_to_delegator_exists` over the currently
/// live delegation graph. If such a path exists, adding `delegator ->
/// delegatee` would close a cycle and must be rejected.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn delegation_edge_preserves_acyclicity(
    path_from_delegatee_to_delegator_exists: bool,
) -> bool {
    !path_from_delegatee_to_delegator_exists
}

#[cfg(test)]
mod verus_spec_differential {
    //! Differential binding for `PARITY-HAND-1` (see
    //! `formal/ASSUMPTION_REGISTRY.md`).
    //!
    //! Verus proves `exec == spec` for `formal/verus/verified_nhi_graph.rs`.
    //! The transcriptions below restate that `spec` and assert it agrees with
    //! the shipped function. Symbol parity cannot see this:
    //! `check-verus-parity.sh` greps for names.
    //!
    //! TOTAL discharge for both predicates: 2⁴ and 2¹.
    //!
    //! The successor-traversal spec folds a `Seq` of links and is not bound
    //! here; that obligation stays under `PARITY-HAND-1`.
    //!
    //! Keep each transcription in step with the kernel; if it drifts, the
    //! assumption returns silently.

    use super::*;

    fn spec_delegation_link_effective_for_successor(
        from_agent_matches_current: bool,
        link_active: bool,
        expiry_parsed: bool,
        now_before_expiry: bool,
    ) -> bool {
        from_agent_matches_current && link_active && expiry_parsed && now_before_expiry
    }

    fn spec_delegation_edge_preserves_acyclicity(
        path_from_delegatee_to_delegator_exists: bool,
    ) -> bool {
        !path_from_delegatee_to_delegator_exists
    }

    #[test]
    fn test_production_matches_verus_spec_total_domain() {
        for bits in 0u8..16 {
            let f = |i: u8| bits & (1 << i) != 0;
            let (a, b, c, d) = (f(0), f(1), f(2), f(3));
            assert_eq!(
                delegation_link_effective_for_successor(a, b, c, d),
                spec_delegation_link_effective_for_successor(a, b, c, d),
                "PARITY-HAND-1: delegation_link_effective_for_successor disagrees at \
                 bits {bits:#06b}"
            );
            assert_eq!(
                delegation_edge_preserves_acyclicity(a),
                spec_delegation_edge_preserves_acyclicity(a),
                "PARITY-HAND-1: delegation_edge_preserves_acyclicity disagrees at ({a})"
            );
        }
    }

    #[test]
    fn test_spec_oracle_can_reject() {
        // An edge that closes a cycle back to the delegator is refused — this
        // is what stops a delegation graph looping into unbounded authority.
        assert!(!spec_delegation_edge_preserves_acyclicity(true));
        assert!(spec_delegation_edge_preserves_acyclicity(false));
        // Every link condition is load-bearing.
        assert!(!spec_delegation_link_effective_for_successor(
            true, true, true, false
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_delegation_link_effective_for_successor_requires_all_guards() {
        assert!(delegation_link_effective_for_successor(
            true, true, true, true
        ));
        assert!(!delegation_link_effective_for_successor(
            false, true, true, true
        ));
        assert!(!delegation_link_effective_for_successor(
            true, false, true, true
        ));
        assert!(!delegation_link_effective_for_successor(
            true, true, false, false
        ));
    }

    #[test]
    fn test_delegation_edge_preserves_acyclicity_rejects_live_back_path() {
        assert!(delegation_edge_preserves_acyclicity(false));
        assert!(!delegation_edge_preserves_acyclicity(true));
    }
}
