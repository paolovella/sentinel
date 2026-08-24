// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verified capability grant-coverage gate.
//!
//! This module extracts the fail-closed path/domain restriction gate from
//! `capability_token.rs::grant_covers_action()` so it can be mirrored in Verus
//! without pulling path normalization or glob matching into the proof boundary.

/// Return true when a restricted grant is satisfied by the action's extracted
/// target paths/domains.
///
/// If a grant restricts paths or domains, the corresponding action target set
/// must be present and every supplied target must already have been checked as
/// covered by the caller's normalization and pattern-matching pipeline.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn grant_restrictions_cover_action(
    grant_has_allowed_paths: bool,
    action_has_target_paths: bool,
    all_target_paths_covered: bool,
    grant_has_allowed_domains: bool,
    action_has_target_domains: bool,
    all_target_domains_covered: bool,
) -> bool {
    (!grant_has_allowed_paths || (action_has_target_paths && all_target_paths_covered))
        && (!grant_has_allowed_domains || (action_has_target_domains && all_target_domains_covered))
}

#[cfg(test)]
mod verus_spec_differential {
    //! Differential binding for `PARITY-HAND-1` (see
    //! `formal/ASSUMPTION_REGISTRY.md`).
    //!
    //! Verus proves `exec == spec` for the kernel in
    //! `formal/verus/verified_capability_coverage.rs`. The transcriptions below restate that
    //! `spec` and assert it agrees with the function this crate actually ships,
    //! which is the step that carries the proof to production. Symbol-level
    //! parity cannot do this: `check-verus-parity.sh` greps for names and
    //! reported success against a tree with a security check replaced by
    //! `return true`.
    //!
    //! TOTAL discharge: six booleans, all 64 combinations enumerated.
    //!
    //! Keep each transcription in step with the kernel. If it drifts, the
    //! assumption returns silently.

    use super::*;

    fn spec_grant_restrictions_cover_action(
        grant_has_allowed_paths: bool,
        action_has_target_paths: bool,
        all_target_paths_covered: bool,
        grant_has_allowed_domains: bool,
        action_has_target_domains: bool,
        all_target_domains_covered: bool,
    ) -> bool {
        (!grant_has_allowed_paths || (action_has_target_paths && all_target_paths_covered))
            && (!grant_has_allowed_domains
                || (action_has_target_domains && all_target_domains_covered))
    }

    #[test]
    fn test_production_matches_verus_spec_total_domain() {
        let mut checked = 0usize;
        for bits in 0u8..64 {
            let f = |i: u8| bits & (1 << i) != 0;
            let (a, b, c, d, e, g) = (f(0), f(1), f(2), f(3), f(4), f(5));
            assert_eq!(
                grant_restrictions_cover_action(a, b, c, d, e, g),
                spec_grant_restrictions_cover_action(a, b, c, d, e, g),
                "PARITY-HAND-1: grant_restrictions_cover_action disagrees at bits {bits:#08b}"
            );
            checked += 1;
        }
        assert_eq!(checked, 64, "total domain is 2^6; enumeration collapsed");
    }

    #[test]
    fn test_spec_oracle_can_reject() {
        // A grant that restricts paths must not cover an action whose paths are
        // uncovered — the fail-closed direction this kernel exists to pin.
        assert!(!spec_grant_restrictions_cover_action(
            true, true, false, false, false, false
        ));
        assert!(!spec_grant_restrictions_cover_action(
            true, false, true, false, false, false
        ));
        assert!(spec_grant_restrictions_cover_action(
            false, false, false, false, false, false
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_grant_restrictions_cover_action_rejects_missing_paths() {
        assert!(!grant_restrictions_cover_action(
            true, false, false, false, false, false
        ));
    }

    #[test]
    fn test_grant_restrictions_cover_action_rejects_uncovered_paths() {
        assert!(!grant_restrictions_cover_action(
            true, true, false, false, false, false
        ));
    }

    #[test]
    fn test_grant_restrictions_cover_action_rejects_missing_domains() {
        assert!(!grant_restrictions_cover_action(
            false, false, false, true, false, false
        ));
    }

    #[test]
    fn test_grant_restrictions_cover_action_rejects_uncovered_domains() {
        assert!(!grant_restrictions_cover_action(
            false, false, false, true, true, false
        ));
    }

    #[test]
    fn test_grant_restrictions_cover_action_accepts_satisfied_restrictions() {
        assert!(grant_restrictions_cover_action(
            true, true, true, true, true, true
        ));
    }

    #[test]
    fn test_grant_restrictions_cover_action_ignores_absent_restrictions() {
        assert!(grant_restrictions_cover_action(
            false, false, false, false, false, false
        ));
        assert!(grant_restrictions_cover_action(
            false, false, false, true, true, true
        ));
        assert!(grant_restrictions_cover_action(
            true, true, true, false, false, false
        ));
    }
}
