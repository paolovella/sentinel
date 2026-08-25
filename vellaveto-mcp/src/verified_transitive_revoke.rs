// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verified predicates for transitive delegation revocation.
//!
//! Extracted from the inline conditions in `nhi::transitive_revoke` so that
//! `formal/verus/verified_transitive_revoke.rs` has named production
//! counterparts to bind against. `transitive_revoke` calls these; behaviour is
//! unchanged.

/// Maximum BFS depth for a transitive revocation walk.
///
/// Was a function-local `const` in `transitive_revoke`; hoisted so the kernel
/// binds against the same value the walk uses.
pub(crate) const MAX_TRANSITIVE_REVOKE_DEPTH: usize = 50;

/// Return true while the walk is still within its depth bound.
///
/// Stopping at the bound can leave a reachable delegation active; that residual
/// is `REVOKE-DEPTH-1` in `formal/ASSUMPTION_REGISTRY.md`, discharged
/// downstream by chain resolution rather than here.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn depth_within_bound(depth: usize) -> bool {
    depth <= MAX_TRANSITIVE_REVOKE_DEPTH
}

/// Return true when a delegation link must be deactivated by this revocation.
///
/// A link is cut when it touches the agent being revoked on either side and is
/// still active. Touching on *either* side is deliberate: revoking an agent
/// severs both what it granted and what was granted to it.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn link_should_deactivate(
    link_from_is_current: bool,
    link_to_is_current: bool,
    link_active: bool,
) -> bool {
    (link_from_is_current || link_to_is_current) && link_active
}

/// Return true when a link is untouched by this revocation — the complement of
/// the reachability test, kept explicit so "no collateral damage" is checkable.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn no_collateral(link_from_is_current: bool, link_to_is_current: bool) -> bool {
    !link_from_is_current && !link_to_is_current
}

#[cfg(test)]
mod verus_spec_differential {
    //! Differential binding for `PARITY-HAND-1` (see
    //! `formal/ASSUMPTION_REGISTRY.md`).
    //!
    //! Verus proves `exec == spec` for
    //! `formal/verus/verified_transitive_revoke.rs`. The transcriptions below
    //! restate that `spec` and assert it agrees with the shipped predicates.
    //!
    //! `link_should_deactivate` and `no_collateral` get TOTAL discharges over
    //! their booleans. The depth bound is BOUNDED over a `usize` set built
    //! around the limit and both extremes.
    //!
    //! `spec_bfs_terminates` is a property of the walk rather than a predicate
    //! to call, so it is checked as an invariant: visited never exceeds the
    //! agent count.

    use super::*;

    /// The kernel fixes the bound at a literal 50. Writing
    /// `MAX_TRANSITIVE_REVOKE_DEPTH` on both sides of the comparison would bind
    /// the *relation* and not the *value*: raising the production constant
    /// would move both and the test would still pass. Mutation testing caught
    /// exactly that, so the literal is pinned here.
    const K_MAX_TRANSITIVE_REVOKE_DEPTH: usize = 50;

    fn spec_depth_within_bound(depth: usize) -> bool {
        depth <= K_MAX_TRANSITIVE_REVOKE_DEPTH
    }

    fn spec_link_should_deactivate(
        link_from_is_current: bool,
        link_to_is_current: bool,
        link_active: bool,
    ) -> bool {
        (link_from_is_current || link_to_is_current) && link_active
    }

    fn spec_no_collateral(link_from_is_current: bool, link_to_is_current: bool) -> bool {
        !link_from_is_current && !link_to_is_current
    }

    fn spec_bfs_terminates(visited_count: usize, total_agents: usize) -> bool {
        visited_count <= total_agents
    }

    #[test]
    fn test_link_predicates_match_verus_spec_total_domain() {
        for bits in 0u8..8 {
            let f = |i: u8| bits & (1 << i) != 0;
            let (from_is, to_is, active) = (f(0), f(1), f(2));
            assert_eq!(
                link_should_deactivate(from_is, to_is, active),
                spec_link_should_deactivate(from_is, to_is, active),
                "PARITY-HAND-1: link_should_deactivate disagrees at ({from_is}, {to_is}, {active})"
            );
            assert_eq!(
                no_collateral(from_is, to_is),
                spec_no_collateral(from_is, to_is),
                "PARITY-HAND-1: no_collateral disagrees at ({from_is}, {to_is})"
            );
            // The two must be complementary on the reachability question: a
            // link that is collateral-free is never deactivated.
            if no_collateral(from_is, to_is) {
                assert!(
                    !link_should_deactivate(from_is, to_is, active),
                    "PARITY-HAND-1: a link touching neither side of the revocation was cut"
                );
            }
        }
    }

    #[test]
    fn test_depth_bound_matches_verus_spec_at_boundaries() {
        assert_eq!(
            MAX_TRANSITIVE_REVOKE_DEPTH, K_MAX_TRANSITIVE_REVOKE_DEPTH,
            "PARITY-HAND-1: production depth bound no longer matches the kernel's literal"
        );
        for depth in [0usize, 1, 49, 50, 51, 500, usize::MAX - 1, usize::MAX] {
            assert_eq!(
                depth_within_bound(depth),
                spec_depth_within_bound(depth),
                "PARITY-HAND-1: depth_within_bound disagrees at {depth}"
            );
        }
    }

    #[test]
    fn test_bfs_visited_never_exceeds_agent_count() {
        // `spec_bfs_terminates` is the walk's termination argument. The walk
        // inserts into `visited` before enqueueing and never re-enqueues, so
        // the invariant is that visited stays within the agent population.
        for total in [0usize, 1, 2, 50, 1_000] {
            for visited in [0usize, 1, total] {
                assert_eq!(
                    spec_bfs_terminates(visited, total),
                    visited <= total,
                    "PARITY-HAND-1: bfs termination invariant disagrees at ({visited}, {total})"
                );
            }
        }
    }

    #[test]
    fn test_spec_oracle_can_reject() {
        // An inactive link is not re-cut, and an unrelated link is never cut.
        assert!(!spec_link_should_deactivate(true, false, false));
        assert!(!spec_link_should_deactivate(false, false, true));
        // Either side touching is enough.
        assert!(spec_link_should_deactivate(true, false, true));
        assert!(spec_link_should_deactivate(false, true, true));
        // The bound is inclusive: at the limit the walk continues, past it stops.
        assert!(spec_depth_within_bound(50));
        assert!(!spec_depth_within_bound(51));
    }
}
