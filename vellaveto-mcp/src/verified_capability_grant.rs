// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verified capability grant attenuation kernel.
//!
//! This module extracts the pure restriction-shape and `max_invocations`
//! attenuation checks from `capability_token.rs::grant_is_subset()` so they can
//! be proved in Verus without pulling pattern language containment into the
//! proof boundary.

/// Return true when a child grant preserves the parent's mandatory restriction
/// shapes and does not widen the invocation bound.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn grant_restrictions_attenuated(
    parent_has_allowed_paths: bool,
    child_has_allowed_paths: bool,
    parent_has_allowed_domains: bool,
    child_has_allowed_domains: bool,
    parent_max_invocations: u64,
    child_max_invocations: u64,
) -> bool {
    (!parent_has_allowed_paths || child_has_allowed_paths)
        && (!parent_has_allowed_domains || child_has_allowed_domains)
        && (parent_max_invocations == 0
            || (child_max_invocations > 0 && child_max_invocations <= parent_max_invocations))
}

#[cfg(test)]
mod verus_spec_differential {
    //! Differential binding for `PARITY-HAND-1` (see
    //! `formal/ASSUMPTION_REGISTRY.md`).
    //!
    //! Verus proves `exec == spec` for `formal/verus/verified_capability_grant.rs`.
    //! The transcriptions below restate that `spec` and assert it agrees with
    //! the function this crate ships, which is the step that carries the proof
    //! to production. Symbol parity cannot see this: `check-verus-parity.sh`
    //! greps for names.
    //!
    //! MIXED: the four restriction booleans are enumerated TOTALLY. The
    //! invocation counts are `u64`, so they use a boundary set around zero
    //! (which the spec treats as unlimited), equality, and `u64::MAX`.
    //!
    //! Keep each transcription in step with the kernel; if it drifts, the
    //! assumption returns silently.

    use super::*;

    fn spec_required_restrictions_preserved(
        parent_has_allowed_paths: bool,
        child_has_allowed_paths: bool,
        parent_has_allowed_domains: bool,
        child_has_allowed_domains: bool,
    ) -> bool {
        (!parent_has_allowed_paths || child_has_allowed_paths)
            && (!parent_has_allowed_domains || child_has_allowed_domains)
    }

    fn spec_max_invocations_attenuated(
        parent_max_invocations: u64,
        child_max_invocations: u64,
    ) -> bool {
        parent_max_invocations == 0
            || (child_max_invocations > 0 && child_max_invocations <= parent_max_invocations)
    }

    fn spec_grant_restrictions_attenuated(
        parent_has_allowed_paths: bool,
        child_has_allowed_paths: bool,
        parent_has_allowed_domains: bool,
        child_has_allowed_domains: bool,
        parent_max_invocations: u64,
        child_max_invocations: u64,
    ) -> bool {
        spec_required_restrictions_preserved(
            parent_has_allowed_paths,
            child_has_allowed_paths,
            parent_has_allowed_domains,
            child_has_allowed_domains,
        ) && spec_max_invocations_attenuated(parent_max_invocations, child_max_invocations)
    }

    #[test]
    fn test_production_matches_verus_spec() {
        let counts = [0u64, 1, 2, 5, u64::MAX];
        let mut checked = 0usize;
        for bits in 0u8..16 {
            let f = |i: u8| bits & (1 << i) != 0;
            let (pp, cp, pd, cd) = (f(0), f(1), f(2), f(3));
            for &parent_max in &counts {
                for &child_max in &counts {
                    assert_eq!(
                        grant_restrictions_attenuated(pp, cp, pd, cd, parent_max, child_max),
                        spec_grant_restrictions_attenuated(pp, cp, pd, cd, parent_max, child_max),
                        "PARITY-HAND-1: grant_restrictions_attenuated disagrees at \
                         ({pp}, {cp}, {pd}, {cd}, {parent_max}, {child_max})"
                    );
                    checked += 1;
                }
            }
        }
        assert_eq!(checked, 16 * 25, "enumeration collapsed");
    }

    #[test]
    fn test_spec_oracle_can_reject() {
        // A parent that restricts paths must not delegate to an unrestricted
        // child — the widening this kernel exists to forbid.
        assert!(!spec_required_restrictions_preserved(
            true, false, false, false
        ));
        // Unlimited parent (0) permits any child budget.
        assert!(spec_max_invocations_attenuated(0, u64::MAX));
        // A bounded parent must not be widened, and 0 means unlimited so a
        // child may not claim it.
        assert!(!spec_max_invocations_attenuated(5, 6));
        assert!(!spec_max_invocations_attenuated(5, 0));
        assert!(spec_max_invocations_attenuated(5, 5));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_path_restrictions_cannot_be_dropped() {
        assert!(!grant_restrictions_attenuated(
            true, false, false, false, 0, 0
        ));
    }

    #[test]
    fn test_domain_restrictions_cannot_be_dropped() {
        assert!(!grant_restrictions_attenuated(
            false, false, true, false, 0, 0
        ));
    }

    #[test]
    fn test_limited_parent_rejects_unlimited_child() {
        assert!(!grant_restrictions_attenuated(
            false, false, false, false, 10, 0
        ));
    }

    #[test]
    fn test_limited_parent_rejects_larger_child_limit() {
        assert!(!grant_restrictions_attenuated(
            false, false, false, false, 10, 11
        ));
    }

    #[test]
    fn test_limited_parent_accepts_smaller_child_limit() {
        assert!(grant_restrictions_attenuated(true, true, true, true, 10, 5));
    }

    #[test]
    fn test_unlimited_parent_leaves_only_shape_checks() {
        assert!(grant_restrictions_attenuated(
            false, false, false, false, 0, 0
        ));
        assert!(grant_restrictions_attenuated(
            true, true, false, false, 0, 99
        ));
    }
}
