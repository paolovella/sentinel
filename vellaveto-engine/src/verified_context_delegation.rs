// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verified engine-side delegation and call-chain context guards.
//!
//! This module extracts the pure predicates from `context_check.rs` that
//! consume `EvaluationContext.call_chain.len()` and the presence of a principal.

/// Return true when either an attested agent identity or a legacy `agent_id`
/// is present in the evaluation context.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn identified_principal_present(
    agent_identity_present: bool,
    agent_id_present: bool,
) -> bool {
    agent_identity_present || agent_id_present
}

/// Return true when the policy's principal requirement is satisfied.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn principal_requirement_satisfied(
    require_principal: bool,
    principal_present: bool,
) -> bool {
    !require_principal || principal_present
}

/// Return true when the current call-chain depth is within the policy limit.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn chain_depth_within_limit(chain_depth: usize, max_depth: usize) -> bool {
    chain_depth <= max_depth
}

/// Return true when the delegated call depth is within the policy limit.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn delegation_depth_within_limit(
    delegation_depth: usize,
    max_delegation_depth: u8,
) -> bool {
    delegation_depth <= max_delegation_depth as usize
}

#[cfg(test)]
mod verus_spec_differential {
    //! Differential binding for `PARITY-HAND-1` (see
    //! `formal/ASSUMPTION_REGISTRY.md`).
    //!
    //! Verus proves `exec == spec` for `formal/verus/verified_context_delegation.rs`.
    //! The transcriptions below restate that `spec` and assert it agrees with
    //! the shipped function. Symbol parity cannot see this:
    //! `check-verus-parity.sh` greps for names.
    //!
    //! MIXED: the two presence predicates are enumerated TOTALLY. The depth
    //! limits carry `usize` operands and use a boundary set including both
    //! extremes, since the comparison is inclusive and an off-by-one there
    //! widens the delegation chain.
    //!
    //! Keep each transcription in step with the kernel; if it drifts, the
    //! assumption returns silently.

    use super::*;

    fn spec_identified_principal_present(
        agent_identity_present: bool,
        agent_id_present: bool,
    ) -> bool {
        agent_identity_present || agent_id_present
    }

    fn spec_principal_requirement_satisfied(
        require_principal: bool,
        principal_present: bool,
    ) -> bool {
        !require_principal || principal_present
    }

    fn spec_chain_depth_within_limit(chain_depth: usize, max_depth: usize) -> bool {
        chain_depth <= max_depth
    }

    /// The kernel states both operands as `nat`. Production narrows the cap to
    /// `u8` and widens it back at the comparison, so the transcription follows
    /// production's types while keeping the kernel's inclusive comparison.
    fn spec_delegation_depth_within_limit(
        delegation_depth: usize,
        max_delegation_depth: u8,
    ) -> bool {
        delegation_depth <= max_delegation_depth as usize
    }

    #[test]
    fn test_production_matches_verus_spec() {
        for a in [false, true] {
            for b in [false, true] {
                assert_eq!(
                    identified_principal_present(a, b),
                    spec_identified_principal_present(a, b),
                    "PARITY-HAND-1: identified_principal_present disagrees at ({a}, {b})"
                );
                assert_eq!(
                    principal_requirement_satisfied(a, b),
                    spec_principal_requirement_satisfied(a, b),
                    "PARITY-HAND-1: principal_requirement_satisfied disagrees at ({a}, {b})"
                );
            }
        }

        let values = [0usize, 1, 2, 8, 64, usize::MAX - 1, usize::MAX];
        for &depth in &values {
            for &max in &values {
                assert_eq!(
                    chain_depth_within_limit(depth, max),
                    spec_chain_depth_within_limit(depth, max),
                    "PARITY-HAND-1: chain_depth_within_limit disagrees at ({depth}, {max})"
                );
            }
            for &max8 in &[0u8, 1, 2, 8, 64, u8::MAX - 1, u8::MAX] {
                assert_eq!(
                    delegation_depth_within_limit(depth, max8),
                    spec_delegation_depth_within_limit(depth, max8),
                    "PARITY-HAND-1: delegation_depth_within_limit disagrees at ({depth}, {max8})"
                );
            }
        }
    }

    #[test]
    fn test_spec_oracle_can_reject() {
        // Requiring a principal is not satisfied by its absence.
        assert!(!spec_principal_requirement_satisfied(true, false));
        // The limits are inclusive: at the cap is fine, one past is not.
        assert!(spec_chain_depth_within_limit(8, 8));
        assert!(!spec_chain_depth_within_limit(9, 8));
        assert!(!spec_delegation_depth_within_limit(9, 8u8));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identified_principal_present_accepts_either_identity_source() {
        assert!(!identified_principal_present(false, false));
        assert!(identified_principal_present(true, false));
        assert!(identified_principal_present(false, true));
        assert!(identified_principal_present(true, true));
    }

    #[test]
    fn test_principal_requirement_satisfied_fails_closed_when_required() {
        assert!(!principal_requirement_satisfied(true, false));
        assert!(principal_requirement_satisfied(true, true));
        assert!(principal_requirement_satisfied(false, false));
    }

    #[test]
    fn test_chain_depth_within_limit_is_inclusive() {
        assert!(chain_depth_within_limit(0, 0));
        assert!(chain_depth_within_limit(2, 2));
        assert!(!chain_depth_within_limit(3, 2));
    }

    #[test]
    fn test_delegation_depth_within_limit_is_inclusive() {
        assert!(delegation_depth_within_limit(0, 0));
        assert!(delegation_depth_within_limit(2, 2));
        assert!(!delegation_depth_within_limit(3, 2));
    }
}
