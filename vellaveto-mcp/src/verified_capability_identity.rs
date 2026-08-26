// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verified capability identity-chain boundary.
//!
//! This module extracts the normalized holder/issuer checks from
//! `capability_token.rs` so they can be mirrored in Verus without pulling full
//! Unicode normalization into the proof boundary.

/// Return true when a delegated child holder remains distinct from the parent
/// holder after the caller's normalization pipeline.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn delegation_holder_distinct(
    normalized_new_equals_parent_holder_ignore_ascii_case: bool,
) -> bool {
    !normalized_new_equals_parent_holder_ignore_ascii_case
}

/// Return true when the delegated child issuer is valid for the parent link.
///
/// Root tokens (`child_has_parent == false`) have no parent-holder chain
/// obligation. Delegated children must carry the parent holder as issuer.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn delegated_child_issuer_valid(
    child_has_parent: bool,
    child_issuer_equals_parent_holder: bool,
) -> bool {
    !child_has_parent || child_issuer_equals_parent_holder
}

/// Return true when the normalized holder value satisfies the expected holder
/// check during verification.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn holder_expectation_satisfied(normalized_holder_equals_expected: bool) -> bool {
    normalized_holder_equals_expected
}

#[cfg(test)]
mod verus_spec_differential {
    //! Differential binding for `PARITY-HAND-1` (see
    //! `formal/ASSUMPTION_REGISTRY.md`).
    //!
    //! Verus proves `exec == spec` for the kernel in
    //! `formal/verus/verified_capability_identity.rs`. The transcriptions below restate that
    //! `spec` and assert it agrees with the function this crate actually ships,
    //! which is the step that carries the proof to production. Symbol-level
    //! parity cannot do this: `check-verus-parity.sh` greps for names and
    //! reported success against a tree with a security check replaced by
    //! `return true`.
    //!
    //! TOTAL discharge: all three predicates range over booleans only.
    //!
    //! Keep each transcription in step with the kernel. If it drifts, the
    //! assumption returns silently.

    use super::*;

    fn spec_delegation_holder_distinct(
        normalized_new_equals_parent_holder_ignore_ascii_case: bool,
    ) -> bool {
        !normalized_new_equals_parent_holder_ignore_ascii_case
    }

    fn spec_delegated_child_issuer_valid(
        child_has_parent: bool,
        child_issuer_equals_parent_holder: bool,
    ) -> bool {
        !child_has_parent || child_issuer_equals_parent_holder
    }

    fn spec_holder_expectation_satisfied(normalized_holder_equals_expected: bool) -> bool {
        normalized_holder_equals_expected
    }

    #[test]
    fn test_production_matches_verus_spec_total_domain() {
        for a in [false, true] {
            assert_eq!(
                delegation_holder_distinct(a),
                spec_delegation_holder_distinct(a),
                "PARITY-HAND-1: delegation_holder_distinct disagrees at ({a})"
            );
            assert_eq!(
                holder_expectation_satisfied(a),
                spec_holder_expectation_satisfied(a),
                "PARITY-HAND-1: holder_expectation_satisfied disagrees at ({a})"
            );
            for b in [false, true] {
                assert_eq!(
                    delegated_child_issuer_valid(a, b),
                    spec_delegated_child_issuer_valid(a, b),
                    "PARITY-HAND-1: delegated_child_issuer_valid disagrees at ({a}, {b})"
                );
            }
        }
    }

    #[test]
    fn test_spec_oracle_can_reject() {
        // Self-delegation must be refused, and a child claiming a parent must
        // carry that parent's holder as its issuer.
        assert!(!spec_delegation_holder_distinct(true));
        assert!(!spec_delegated_child_issuer_valid(true, false));
        assert!(spec_delegated_child_issuer_valid(false, false));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_delegation_holder_distinct_rejects_self_delegation() {
        assert!(!delegation_holder_distinct(true));
        assert!(delegation_holder_distinct(false));
    }

    #[test]
    fn test_delegated_child_issuer_valid_accepts_root_tokens() {
        assert!(delegated_child_issuer_valid(false, false));
    }

    #[test]
    fn test_delegated_child_issuer_valid_requires_parent_holder_link() {
        assert!(delegated_child_issuer_valid(true, true));
        assert!(!delegated_child_issuer_valid(true, false));
    }

    #[test]
    fn test_holder_expectation_satisfied_is_identity() {
        assert!(holder_expectation_satisfied(true));
        assert!(!holder_expectation_satisfied(false));
    }
}
