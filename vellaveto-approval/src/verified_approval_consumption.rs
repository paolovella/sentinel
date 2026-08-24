// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verified approval-consumption guards.
//!
//! Approved approvals are single-use. Consumption is allowed only when the
//! approval is still in `Approved`, retains an `action_fingerprint` binding,
//! and the presented request scope matches that binding. All other cases fail
//! closed.

/// Return true when the approval is in the only status that permits consumption.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub const fn approval_status_allows_consumption(approval_is_approved: bool) -> bool {
    approval_is_approved
}

/// Return true when the approval's binding state permits consumption.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub const fn approval_binding_allows_consumption(
    approval_has_action_fingerprint_binding: bool,
    request_scope_matches_binding: bool,
) -> bool {
    approval_has_action_fingerprint_binding && request_scope_matches_binding
}

/// Return true when the approval may be consumed for this request.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub const fn approval_consumption_permitted(
    approval_is_approved: bool,
    approval_has_action_fingerprint_binding: bool,
    request_scope_matches_binding: bool,
) -> bool {
    approval_status_allows_consumption(approval_is_approved)
        && approval_binding_allows_consumption(
            approval_has_action_fingerprint_binding,
            request_scope_matches_binding,
        )
}

#[cfg(test)]
mod verus_spec_differential {
    //! Differential binding for `PARITY-HAND-1` (see
    //! `formal/ASSUMPTION_REGISTRY.md`).
    //!
    //! Verus proves `exec == spec` for `formal/verus/verified_approval_consumption.rs`.
    //! The transcriptions below restate that `spec` and assert it agrees with
    //! the shipped function, which is the step that carries the proof to
    //! production. Symbol parity cannot see this: `check-verus-parity.sh`
    //! greps for names.
    //!
    //! TOTAL discharge: every predicate ranges over booleans only, so the
    //! enumeration below is the whole input domain.
    //!
    //! Keep each transcription in step with the kernel; if it drifts, the
    //! assumption returns silently.

    use super::*;

    fn spec_approval_status_allows_consumption(approval_is_approved: bool) -> bool {
        approval_is_approved
    }

    fn spec_approval_binding_allows_consumption(
        approval_has_action_fingerprint_binding: bool,
        request_scope_matches_binding: bool,
    ) -> bool {
        approval_has_action_fingerprint_binding && request_scope_matches_binding
    }

    fn spec_approval_consumption_permitted(
        approval_is_approved: bool,
        approval_has_action_fingerprint_binding: bool,
        request_scope_matches_binding: bool,
    ) -> bool {
        spec_approval_status_allows_consumption(approval_is_approved)
            && spec_approval_binding_allows_consumption(
                approval_has_action_fingerprint_binding,
                request_scope_matches_binding,
            )
    }

    #[test]
    fn test_production_matches_verus_spec_total_domain() {
        for bits in 0u8..8 {
            let f = |i: u8| bits & (1 << i) != 0;
            let (a, b, c) = (f(0), f(1), f(2));
            assert_eq!(
                approval_status_allows_consumption(a),
                spec_approval_status_allows_consumption(a),
                "PARITY-HAND-1: approval_status_allows_consumption disagrees at ({a})"
            );
            assert_eq!(
                approval_binding_allows_consumption(a, b),
                spec_approval_binding_allows_consumption(a, b),
                "PARITY-HAND-1: approval_binding_allows_consumption disagrees at ({a}, {b})"
            );
            assert_eq!(
                approval_consumption_permitted(a, b, c),
                spec_approval_consumption_permitted(a, b, c),
                "PARITY-HAND-1: approval_consumption_permitted disagrees at ({a}, {b}, {c})"
            );
        }
    }

    #[test]
    fn test_spec_oracle_can_reject() {
        // An unapproved approval is never consumable, and consumption requires
        // a fingerprint binding that the request actually matches.
        assert!(!spec_approval_consumption_permitted(false, true, true));
        assert!(!spec_approval_consumption_permitted(true, false, true));
        assert!(!spec_approval_consumption_permitted(true, true, false));
        assert!(spec_approval_consumption_permitted(true, true, true));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_only_approved_status_allows_consumption() {
        assert!(!approval_status_allows_consumption(false));
        assert!(approval_status_allows_consumption(true));
    }

    #[test]
    fn test_binding_guard_requires_fingerprint_and_scope_match() {
        assert!(!approval_binding_allows_consumption(false, false));
        assert!(!approval_binding_allows_consumption(false, true));
        assert!(!approval_binding_allows_consumption(true, false));
        assert!(approval_binding_allows_consumption(true, true));
    }

    #[test]
    fn test_consumption_permitted_requires_approved_bound_matching_scope() {
        assert!(!approval_consumption_permitted(false, true, true));
        assert!(!approval_consumption_permitted(true, false, true));
        assert!(!approval_consumption_permitted(true, true, false));
        assert!(approval_consumption_permitted(true, true, true));
    }
}
