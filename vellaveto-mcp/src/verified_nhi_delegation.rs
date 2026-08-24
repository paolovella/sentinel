// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verified NHI delegation terminal-state and chain guards.
//!
//! This module extracts the fail-closed predicates around delegation
//! participants, active/unexpired chain links, and depth bounding from
//! `nhi.rs` so they can be mirrored in Verus.

/// Return true when an identity is in a delegation-blocking terminal state.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn identity_is_terminal(status_is_revoked: bool, status_is_expired: bool) -> bool {
    status_is_revoked || status_is_expired
}

/// Return true when an identity is allowed to participate in delegation.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn delegation_participant_allowed(
    status_is_revoked: bool,
    status_is_expired: bool,
) -> bool {
    !identity_is_terminal(status_is_revoked, status_is_expired)
}

/// Return true when a delegation link is still effective for chain traversal.
///
/// The expiry parse boundary is fail-closed: an unparseable timestamp is not an
/// effective link.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn delegation_link_effective_for_chain(
    to_agent_matches_current: bool,
    link_active: bool,
    expiry_parsed: bool,
    now_before_expiry: bool,
) -> bool {
    to_agent_matches_current && link_active && expiry_parsed && now_before_expiry
}

/// Return true when the current chain depth has exceeded the configured bound.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn delegation_chain_depth_exceeded(chain_len: usize, max_depth: usize) -> bool {
    chain_len > max_depth
}

#[cfg(test)]
mod verus_spec_differential {
    //! Differential binding for `PARITY-HAND-1` (see
    //! `formal/ASSUMPTION_REGISTRY.md`).
    //!
    //! Verus proves `exec == spec` for `formal/verus/verified_nhi_delegation.rs`.
    //! The transcriptions below restate that `spec` and assert it agrees with
    //! the shipped function. Symbol parity cannot see this:
    //! `check-verus-parity.sh` greps for names.
    //!
    //! MIXED: the status and link predicates are enumerated TOTALLY over their
    //! booleans (2² and 2⁴). The chain-depth comparison carries `usize`
    //! operands and uses a boundary set including both extremes, since it is
    //! strict and an off-by-one there admits one extra delegation hop.
    //!
    //! The chain-traversal spec (`spec_chain_traversable_to`) folds a `Seq` of
    //! links and is not bound here; that obligation stays under
    //! `PARITY-HAND-1`.
    //!
    //! Keep each transcription in step with the kernel; if it drifts, the
    //! assumption returns silently.

    use super::*;

    fn spec_identity_is_terminal(status_is_revoked: bool, status_is_expired: bool) -> bool {
        status_is_revoked || status_is_expired
    }

    fn spec_delegation_participant_allowed(
        status_is_revoked: bool,
        status_is_expired: bool,
    ) -> bool {
        !spec_identity_is_terminal(status_is_revoked, status_is_expired)
    }

    fn spec_delegation_link_effective_for_chain(
        to_agent_matches_current: bool,
        link_active: bool,
        expiry_parsed: bool,
        now_before_expiry: bool,
    ) -> bool {
        to_agent_matches_current && link_active && expiry_parsed && now_before_expiry
    }

    fn spec_delegation_chain_depth_exceeded(chain_len: usize, max_depth: usize) -> bool {
        chain_len > max_depth
    }

    #[test]
    fn test_production_matches_verus_spec() {
        for bits in 0u8..16 {
            let f = |i: u8| bits & (1 << i) != 0;
            let (a, b, c, d) = (f(0), f(1), f(2), f(3));
            assert_eq!(
                identity_is_terminal(a, b),
                spec_identity_is_terminal(a, b),
                "PARITY-HAND-1: identity_is_terminal disagrees at ({a}, {b})"
            );
            assert_eq!(
                delegation_participant_allowed(a, b),
                spec_delegation_participant_allowed(a, b),
                "PARITY-HAND-1: delegation_participant_allowed disagrees at ({a}, {b})"
            );
            assert_eq!(
                delegation_link_effective_for_chain(a, b, c, d),
                spec_delegation_link_effective_for_chain(a, b, c, d),
                "PARITY-HAND-1: delegation_link_effective_for_chain disagrees at bits {bits:#06b}"
            );
        }

        let values = [0usize, 1, 2, 8, 64, usize::MAX - 1, usize::MAX];
        for &chain_len in &values {
            for &max_depth in &values {
                assert_eq!(
                    delegation_chain_depth_exceeded(chain_len, max_depth),
                    spec_delegation_chain_depth_exceeded(chain_len, max_depth),
                    "PARITY-HAND-1: delegation_chain_depth_exceeded disagrees at \
                     ({chain_len}, {max_depth})"
                );
            }
        }
    }

    #[test]
    fn test_spec_oracle_can_reject() {
        // A revoked or expired identity may not participate at all.
        assert!(!spec_delegation_participant_allowed(true, false));
        assert!(!spec_delegation_participant_allowed(false, true));
        // Every one of the four link conditions is load-bearing.
        assert!(!spec_delegation_link_effective_for_chain(
            false, true, true, true
        ));
        assert!(!spec_delegation_link_effective_for_chain(
            true, false, true, true
        ));
        assert!(!spec_delegation_link_effective_for_chain(
            true, true, false, true
        ));
        assert!(!spec_delegation_link_effective_for_chain(
            true, true, true, false
        ));
        // The depth check is strict: at the cap is fine, one past is not.
        assert!(!spec_delegation_chain_depth_exceeded(8, 8));
        assert!(spec_delegation_chain_depth_exceeded(9, 8));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_is_terminal_matches_revoked_or_expired() {
        assert!(identity_is_terminal(true, false));
        assert!(identity_is_terminal(false, true));
        assert!(!identity_is_terminal(false, false));
    }

    #[test]
    fn test_delegation_participant_allowed_rejects_terminal_states() {
        assert!(!delegation_participant_allowed(true, false));
        assert!(!delegation_participant_allowed(false, true));
        assert!(delegation_participant_allowed(false, false));
    }

    #[test]
    fn test_delegation_link_effective_for_chain_requires_all_guards() {
        assert!(delegation_link_effective_for_chain(true, true, true, true));
        assert!(!delegation_link_effective_for_chain(
            false, true, true, true
        ));
        assert!(!delegation_link_effective_for_chain(
            true, false, true, true
        ));
        assert!(!delegation_link_effective_for_chain(
            true, true, false, false
        ));
    }

    #[test]
    fn test_delegation_chain_depth_exceeded_is_strict() {
        assert!(!delegation_chain_depth_exceeded(3, 3));
        assert!(delegation_chain_depth_exceeded(4, 3));
    }
}
