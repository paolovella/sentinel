// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verified capability-token context guards.
//!
//! This module extracts the pure predicates from the engine's
//! `require_capability_token` condition so the runtime authorization boundary
//! can be mirrored in Verus without pulling in the full policy engine.

/// Return true when the evaluation context includes an identified agent and the
/// normalized capability-token holder matches that agent.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn capability_holder_binding_valid(
    agent_present: bool,
    normalized_holder_equals_agent: bool,
) -> bool {
    agent_present && normalized_holder_equals_agent
}

/// Return true when the token issuer is allowed by the configured issuer
/// allowlist.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn capability_issuer_allowed(
    required_issuers_empty: bool,
    issuer_allowed: bool,
) -> bool {
    required_issuers_empty || issuer_allowed
}

/// Return true when the token retains enough delegation depth for the policy.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn capability_remaining_depth_sufficient(
    remaining_depth: u8,
    min_remaining_depth: u8,
) -> bool {
    remaining_depth >= min_remaining_depth
}

#[cfg(test)]
mod verus_spec_differential {
    //! Differential binding for `PARITY-HAND-1` (see
    //! `formal/ASSUMPTION_REGISTRY.md`).
    //!
    //! Verus proves `exec == spec` for `formal/verus/verified_capability_context.rs`.
    //! The transcriptions below restate that `spec` and assert it agrees with
    //! the shipped function. Symbol parity cannot see this:
    //! `check-verus-parity.sh` greps for names.
    //!
    //! MIXED: the two binding predicates are enumerated TOTALLY over their
    //! booleans. The depth comparison carries integer operands and uses a
    //! boundary set including both extremes.
    //!
    //! Keep each transcription in step with the kernel; if it drifts, the
    //! assumption returns silently.

    use super::*;

    fn spec_capability_holder_binding_valid(
        agent_present: bool,
        normalized_holder_equals_agent: bool,
    ) -> bool {
        agent_present && normalized_holder_equals_agent
    }

    fn spec_capability_issuer_allowed(required_issuers_empty: bool, issuer_allowed: bool) -> bool {
        required_issuers_empty || issuer_allowed
    }

    fn spec_capability_remaining_depth_sufficient(
        remaining_depth: u8,
        min_remaining_depth: u8,
    ) -> bool {
        remaining_depth >= min_remaining_depth
    }

    #[test]
    fn test_production_matches_verus_spec() {
        for a in [false, true] {
            for b in [false, true] {
                assert_eq!(
                    capability_holder_binding_valid(a, b),
                    spec_capability_holder_binding_valid(a, b),
                    "PARITY-HAND-1: capability_holder_binding_valid disagrees at ({a}, {b})"
                );
                assert_eq!(
                    capability_issuer_allowed(a, b),
                    spec_capability_issuer_allowed(a, b),
                    "PARITY-HAND-1: capability_issuer_allowed disagrees at ({a}, {b})"
                );
            }
        }
        // u8 depths are small enough to enumerate completely.
        for remaining in 0u8..=u8::MAX {
            for min in [0u8, 1, 2, 127, 254, 255] {
                assert_eq!(
                    capability_remaining_depth_sufficient(remaining, min),
                    spec_capability_remaining_depth_sufficient(remaining, min),
                    "PARITY-HAND-1: capability_remaining_depth_sufficient disagrees at \
                     ({remaining}, {min})"
                );
            }
        }
    }

    #[test]
    fn test_spec_oracle_can_reject() {
        // A capability with no bound agent must not validate.
        assert!(!spec_capability_holder_binding_valid(false, true));
        assert!(!spec_capability_holder_binding_valid(true, false));
        // A non-empty issuer allowlist must actually be satisfied.
        assert!(!spec_capability_issuer_allowed(false, false));
        // Depth must reach the floor, not merely approach it.
        assert!(!spec_capability_remaining_depth_sufficient(1, 2));
        assert!(spec_capability_remaining_depth_sufficient(2, 2));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capability_holder_binding_valid_fails_closed_without_agent() {
        assert!(!capability_holder_binding_valid(false, false));
        assert!(!capability_holder_binding_valid(false, true));
        assert!(!capability_holder_binding_valid(true, false));
        assert!(capability_holder_binding_valid(true, true));
    }

    #[test]
    fn test_capability_issuer_allowed_respects_allowlist() {
        assert!(capability_issuer_allowed(true, false));
        assert!(capability_issuer_allowed(false, true));
        assert!(!capability_issuer_allowed(false, false));
    }

    #[test]
    fn test_capability_remaining_depth_sufficient_is_inclusive() {
        assert!(capability_remaining_depth_sufficient(3, 3));
        assert!(capability_remaining_depth_sufficient(4, 3));
        assert!(!capability_remaining_depth_sufficient(2, 3));
    }
}
