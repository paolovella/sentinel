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

#[cfg(test)]
// Suppressed rather than satisfied: linting the extraction would edit the copy
// the Kani proofs run against.
#[allow(clippy::manual_range_contains, dead_code, unused_imports)]
mod kani_transitive_revoke_extraction {
    include!(concat!(
        env!("OUT_DIR"),
        "/kani_transitive_revoke_extraction.rs"
    ));
}

#[cfg(test)]
mod kani_parity_differential_transitive_revoke {
    //! Differential binding for `PARITY-HAND-2` — transitive NHI revocation.
    //!
    //! This module is unusual: it is the first place where **all three** meet.
    //! The Verus kernel `verified_transitive_revoke.rs` proves its specs against
    //! this mirror (bound above in `verus_spec_differential`), and
    //! `formal/kani/src/transitive_revoke.rs` proves K136/K137 against its own
    //! copy of the same predicates. Nothing connected the Kani copy to anything
    //! until now.
    //!
    //! So this binding closes the triangle: Kani copy ↔ production mirror, over
    //! the total domain of each predicate. With the Verus binding already in
    //! place, agreement here means all three descriptions are of one function.
    //!
    //! What rides on it: revoking an NHI must sever every delegation reachable
    //! from it. `link_should_deactivate` decides which links are cut, and
    //! cutting on *either* side is deliberate — revoking an agent severs both
    //! what it granted and what was granted to it.

    use super::kani_transitive_revoke_extraction as extracted;
    use super::MAX_TRANSITIVE_REVOKE_DEPTH;
    use super::{depth_within_bound, link_should_deactivate, no_collateral};

    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn test_extraction_is_actually_present() {
        assert!(
            extracted::EXTRACTION_PRESENT,
            "formal/kani/src/transitive_revoke.rs was not found, so this binding \
             compared nothing"
        );
    }

    /// K137, TOTAL over 2³: a link is cut when it touches the revoked agent on
    /// either side and is still active.
    #[test]
    fn test_link_deactivation_matches_production_total_domain() {
        for from_is_revoked in [false, true] {
            for to_is_revoked in [false, true] {
                for active in [false, true] {
                    assert_eq!(
                        extracted::should_deactivate(from_is_revoked, to_is_revoked, active),
                        link_should_deactivate(from_is_revoked, to_is_revoked, active),
                        "PARITY-HAND-2: the Kani copy and production disagree on \
                         cutting a link at (from={from_is_revoked}, \
                         to={to_is_revoked}, active={active}) — K137 is about a \
                         different revocation rule than the one running"
                    );
                }
            }
        }
        // The property stated: touching on either side is enough.
        assert!(link_should_deactivate(true, false, true));
        assert!(link_should_deactivate(false, true, true));
        assert!(!link_should_deactivate(false, false, true));
        // An already-inactive link is not "cut" again.
        assert!(!link_should_deactivate(true, true, false));
    }

    /// K136: the depth bound, at and around it, and pinned on both sides
    /// independently rather than compared to itself.
    #[test]
    fn test_depth_bound_matches_production_at_the_boundary() {
        assert_eq!(
            MAX_TRANSITIVE_REVOKE_DEPTH, 50,
            "production's transitive revoke depth bound moved"
        );

        for depth in 0..=(MAX_TRANSITIVE_REVOKE_DEPTH + 5) {
            assert_eq!(
                extracted::depth_bounded(depth),
                depth_within_bound(depth),
                "PARITY-HAND-2: depth bound disagrees at {depth}"
            );
        }
        // The boundary itself, from both sides.
        assert!(extracted::depth_bounded(50) && depth_within_bound(50));
        assert!(!extracted::depth_bounded(51) && !depth_within_bound(51));
    }

    /// The visited-set predicate and the no-collateral predicate are
    /// complements of different things, and are checked as such.
    ///
    /// The Kani copy models BFS progress (`visited_insert_new`); production
    /// models reachability (`no_collateral`). They are not the same predicate,
    /// so they are not compared to each other — asserting an accidental
    /// agreement between two unrelated booleans would be exactly the kind of
    /// vacuous check this campaign exists to remove.
    #[test]
    fn test_visited_and_collateral_predicates_hold_separately() {
        // BFS makes progress only on genuinely new nodes, or K136's
        // termination argument fails.
        assert!(extracted::visited_insert_new(false));
        assert!(!extracted::visited_insert_new(true));

        // A link touching neither endpoint is untouched, over the total 2²
        // domain.
        for from_is_current in [false, true] {
            for to_is_current in [false, true] {
                assert_eq!(
                    no_collateral(from_is_current, to_is_current),
                    !from_is_current && !to_is_current,
                    "no_collateral disagrees at ({from_is_current}, {to_is_current})"
                );
                // And it is exactly the complement of "would be cut if active".
                assert_ne!(
                    no_collateral(from_is_current, to_is_current),
                    link_should_deactivate(from_is_current, to_is_current, true),
                    "an untouched link was also cut, or a touched link was not"
                );
            }
        }
    }
}
