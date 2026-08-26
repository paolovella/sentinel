// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verified combined deputy/capability context guards.
//!
//! This module extracts the pure conjunction used when a policy requires both
//! deputy validation and a capability token in the same engine evaluation.

use crate::verified_capability_context;
use crate::verified_context_delegation;

/// Return true when a delegated request has a bound principal and capability
/// token holder for a policy that requires both checks.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn delegated_capability_principal_and_holder_valid(
    require_principal: bool,
    agent_identity_present: bool,
    agent_id_present: bool,
    capability_token_present: bool,
    normalized_holder_equals_agent: bool,
) -> bool {
    let principal_present = verified_context_delegation::identified_principal_present(
        agent_identity_present,
        agent_id_present,
    );

    verified_context_delegation::principal_requirement_satisfied(
        require_principal,
        principal_present,
    ) && capability_token_present
        && verified_capability_context::capability_holder_binding_valid(
            agent_id_present,
            normalized_holder_equals_agent,
        )
}

/// Return true when both delegated call depth and capability-token depth satisfy
/// the policy's fail-closed bounds.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn delegated_capability_depths_valid(
    delegation_depth: usize,
    max_delegation_depth: u8,
    capability_token_present: bool,
    remaining_depth: u8,
    min_remaining_depth: u8,
) -> bool {
    verified_context_delegation::delegation_depth_within_limit(
        delegation_depth,
        max_delegation_depth,
    ) && capability_token_present
        && verified_capability_context::capability_remaining_depth_sufficient(
            remaining_depth,
            min_remaining_depth,
        )
}

/// Return true when the token issuer satisfies the configured allowlist in the
/// combined delegated-capability path.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn delegated_capability_issuer_valid(
    required_issuers_empty: bool,
    issuer_allowed: bool,
) -> bool {
    verified_capability_context::capability_issuer_allowed(required_issuers_empty, issuer_allowed)
}

/// Return true when the evaluation context satisfies the combined fail-closed
/// deputy/capability boundary.
#[inline]
#[must_use = "security decisions must not be discarded"]
#[allow(clippy::too_many_arguments)]
pub(crate) const fn delegated_capability_context_valid(
    require_principal: bool,
    agent_identity_present: bool,
    agent_id_present: bool,
    capability_token_present: bool,
    normalized_holder_equals_agent: bool,
    required_issuers_empty: bool,
    issuer_allowed: bool,
    delegation_depth: usize,
    max_delegation_depth: u8,
    remaining_depth: u8,
    min_remaining_depth: u8,
) -> bool {
    delegated_capability_principal_and_holder_valid(
        require_principal,
        agent_identity_present,
        agent_id_present,
        capability_token_present,
        normalized_holder_equals_agent,
    ) && delegated_capability_issuer_valid(required_issuers_empty, issuer_allowed)
        && delegated_capability_depths_valid(
            delegation_depth,
            max_delegation_depth,
            capability_token_present,
            remaining_depth,
            min_remaining_depth,
        )
}

#[cfg(test)]
mod verus_spec_differential {
    //! Differential binding for `PARITY-HAND-1` (see
    //! `formal/ASSUMPTION_REGISTRY.md`).
    //!
    //! Verus proves `exec == spec` for `formal/verus/verified_capability_delegation_context.rs`.
    //! The transcriptions below restate that `spec` and assert it agrees with
    //! the shipped function. Symbol parity cannot see this:
    //! `check-verus-parity.sh` greps for names.
    //!
    //! MIXED: the seven booleans are enumerated TOTALLY (2⁷ = 128) and the
    //! composite predicate is checked against every one of them, crossed with
    //! a boundary set for the three depth operands.
    //!
    //! Keep each transcription in step with the kernel; if it drifts, the
    //! assumption returns silently.

    use super::*;

    fn spec_delegated_capability_principal_and_holder_valid(
        require_principal: bool,
        agent_identity_present: bool,
        agent_id_present: bool,
        capability_token_present: bool,
        normalized_holder_equals_agent: bool,
    ) -> bool {
        let principal_present = agent_identity_present || agent_id_present;
        (!require_principal || principal_present)
            && capability_token_present
            && agent_id_present
            && normalized_holder_equals_agent
    }

    fn spec_delegated_capability_depths_valid(
        delegation_depth: usize,
        max_delegation_depth: u8,
        capability_token_present: bool,
        remaining_depth: u8,
        min_remaining_depth: u8,
    ) -> bool {
        delegation_depth <= max_delegation_depth as usize
            && capability_token_present
            && remaining_depth >= min_remaining_depth
    }

    fn spec_delegated_capability_issuer_valid(
        required_issuers_empty: bool,
        issuer_allowed: bool,
    ) -> bool {
        required_issuers_empty || issuer_allowed
    }

    #[allow(clippy::too_many_arguments)]
    fn spec_delegated_capability_context_valid(
        require_principal: bool,
        agent_identity_present: bool,
        agent_id_present: bool,
        capability_token_present: bool,
        normalized_holder_equals_agent: bool,
        required_issuers_empty: bool,
        issuer_allowed: bool,
        delegation_depth: usize,
        max_delegation_depth: u8,
        remaining_depth: u8,
        min_remaining_depth: u8,
    ) -> bool {
        spec_delegated_capability_principal_and_holder_valid(
            require_principal,
            agent_identity_present,
            agent_id_present,
            capability_token_present,
            normalized_holder_equals_agent,
        ) && spec_delegated_capability_issuer_valid(required_issuers_empty, issuer_allowed)
            && spec_delegated_capability_depths_valid(
                delegation_depth,
                max_delegation_depth,
                capability_token_present,
                remaining_depth,
                min_remaining_depth,
            )
    }

    #[test]
    fn test_production_matches_verus_spec() {
        let depths: [usize; 4] = [0, 1, 2, 255];
        let caps: [u8; 4] = [0, 1, 2, u8::MAX];
        let mut checked = 0usize;

        for bits in 0u8..128 {
            let f = |i: u8| bits & (1 << i) != 0;
            let (rp, aip, idp, ctp, hol, rie, ia) = (f(0), f(1), f(2), f(3), f(4), f(5), f(6));

            assert_eq!(
                delegated_capability_principal_and_holder_valid(rp, aip, idp, ctp, hol),
                spec_delegated_capability_principal_and_holder_valid(rp, aip, idp, ctp, hol),
                "PARITY-HAND-1: principal_and_holder_valid disagrees at bits {bits:#09b}"
            );
            assert_eq!(
                delegated_capability_issuer_valid(rie, ia),
                spec_delegated_capability_issuer_valid(rie, ia),
                "PARITY-HAND-1: issuer_valid disagrees at ({rie}, {ia})"
            );

            for &delegation_depth in &depths {
                for &max_delegation_depth in &caps {
                    for &remaining in &caps {
                        for &min_remaining in &caps {
                            assert_eq!(
                                delegated_capability_depths_valid(
                                    delegation_depth,
                                    max_delegation_depth,
                                    ctp,
                                    remaining,
                                    min_remaining
                                ),
                                spec_delegated_capability_depths_valid(
                                    delegation_depth,
                                    max_delegation_depth,
                                    ctp,
                                    remaining,
                                    min_remaining
                                ),
                                "PARITY-HAND-1: depths_valid disagrees"
                            );
                            assert_eq!(
                                delegated_capability_context_valid(
                                    rp,
                                    aip,
                                    idp,
                                    ctp,
                                    hol,
                                    rie,
                                    ia,
                                    delegation_depth,
                                    max_delegation_depth,
                                    remaining,
                                    min_remaining
                                ),
                                spec_delegated_capability_context_valid(
                                    rp,
                                    aip,
                                    idp,
                                    ctp,
                                    hol,
                                    rie,
                                    ia,
                                    delegation_depth,
                                    max_delegation_depth,
                                    remaining,
                                    min_remaining
                                ),
                                "PARITY-HAND-1: context_valid disagrees"
                            );
                            checked += 1;
                        }
                    }
                }
            }
        }
        assert_eq!(checked, 128 * 4 * 4 * 4 * 4, "enumeration collapsed");
    }

    #[test]
    fn test_spec_oracle_can_reject() {
        // A delegated capability always needs a token and a holder bound to
        // the acting agent, regardless of whether a principal is required.
        assert!(!spec_delegated_capability_principal_and_holder_valid(
            false, true, true, false, true
        ));
        assert!(!spec_delegated_capability_principal_and_holder_valid(
            false, true, true, true, false
        ));
        // Requiring a principal is not satisfied by an absent one.
        assert!(!spec_delegated_capability_principal_and_holder_valid(
            true, false, false, true, true
        ));
        // Depth must be within the cap and above the floor.
        assert!(!spec_delegated_capability_depths_valid(3, 2, true, 5, 1));
        assert!(!spec_delegated_capability_depths_valid(1, 2, true, 0, 1));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_delegated_capability_principal_and_holder_valid_requires_token_and_binding() {
        assert!(delegated_capability_principal_and_holder_valid(
            true, true, true, true, true
        ));
        assert!(!delegated_capability_principal_and_holder_valid(
            true, true, true, false, true
        ));
        assert!(!delegated_capability_principal_and_holder_valid(
            true, true, false, true, false
        ));
    }

    #[test]
    fn test_delegated_capability_depths_valid_requires_both_bounds() {
        assert!(delegated_capability_depths_valid(1, 2, true, 3, 1));
        assert!(!delegated_capability_depths_valid(3, 2, true, 3, 1));
        assert!(!delegated_capability_depths_valid(1, 2, true, 0, 1));
        assert!(!delegated_capability_depths_valid(1, 2, false, 3, 1));
    }

    #[test]
    fn test_delegated_capability_issuer_valid_respects_allowlist() {
        assert!(delegated_capability_issuer_valid(true, false));
        assert!(delegated_capability_issuer_valid(false, true));
        assert!(!delegated_capability_issuer_valid(false, false));
    }

    #[test]
    fn test_delegated_capability_context_valid_conjoins_principal_and_depth() {
        assert!(delegated_capability_context_valid(
            true, true, true, true, true, true, true, 1, 2, 3, 1
        ));
        assert!(!delegated_capability_context_valid(
            true, true, true, true, true, true, true, 3, 2, 3, 1
        ));
        assert!(!delegated_capability_context_valid(
            true, true, true, true, false, true, true, 1, 2, 3, 1
        ));
        assert!(!delegated_capability_context_valid(
            true, true, true, true, true, false, false, 1, 2, 3, 1
        ));
    }
}
