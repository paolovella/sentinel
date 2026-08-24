// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verified approval-scope binding guards.
//!
//! Approvals may optionally be bound to a `session_id` and an
//! `action_fingerprint`. When a binding is present, any future use of that
//! approval must present the same bound value. Missing or mismatched bound
//! values fail closed.

/// Return true when a request satisfies the approval's session binding.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub const fn approval_session_binding_satisfied(
    approval_has_session_binding: bool,
    request_has_session: bool,
    request_matches_bound_session: bool,
) -> bool {
    !approval_has_session_binding || (request_has_session && request_matches_bound_session)
}

/// Return true when a request satisfies the approval's action-fingerprint binding.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub const fn approval_fingerprint_binding_satisfied(
    approval_has_action_fingerprint_binding: bool,
    request_has_action_fingerprint: bool,
    request_matches_bound_fingerprint: bool,
) -> bool {
    !approval_has_action_fingerprint_binding
        || (request_has_action_fingerprint && request_matches_bound_fingerprint)
}

/// Return true when a request satisfies all approval scope bindings.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub const fn approval_scope_binding_satisfied(
    approval_has_session_binding: bool,
    request_has_session: bool,
    request_matches_bound_session: bool,
    approval_has_action_fingerprint_binding: bool,
    request_has_action_fingerprint: bool,
    request_matches_bound_fingerprint: bool,
) -> bool {
    approval_session_binding_satisfied(
        approval_has_session_binding,
        request_has_session,
        request_matches_bound_session,
    ) && approval_fingerprint_binding_satisfied(
        approval_has_action_fingerprint_binding,
        request_has_action_fingerprint,
        request_matches_bound_fingerprint,
    )
}

#[cfg(test)]
mod verus_spec_differential {
    //! Differential binding for `PARITY-HAND-1` (see
    //! `formal/ASSUMPTION_REGISTRY.md`).
    //!
    //! Verus proves `exec == spec` for `formal/verus/verified_approval_scope.rs`.
    //! The transcriptions below restate that `spec` and assert it agrees with
    //! the shipped function, which is the step that carries the proof to
    //! production. Symbol parity cannot see this: `check-verus-parity.sh`
    //! greps for names.
    //!
    //! TOTAL discharge: six booleans, all 64 combinations enumerated.
    //!
    //! Keep each transcription in step with the kernel; if it drifts, the
    //! assumption returns silently.

    use super::*;

    fn spec_approval_session_binding_satisfied(
        approval_has_session_binding: bool,
        request_has_session: bool,
        request_matches_bound_session: bool,
    ) -> bool {
        !approval_has_session_binding || (request_has_session && request_matches_bound_session)
    }

    fn spec_approval_fingerprint_binding_satisfied(
        approval_has_action_fingerprint_binding: bool,
        request_has_action_fingerprint: bool,
        request_matches_bound_fingerprint: bool,
    ) -> bool {
        !approval_has_action_fingerprint_binding
            || (request_has_action_fingerprint && request_matches_bound_fingerprint)
    }

    fn spec_approval_scope_binding_satisfied(
        approval_has_session_binding: bool,
        request_has_session: bool,
        request_matches_bound_session: bool,
        approval_has_action_fingerprint_binding: bool,
        request_has_action_fingerprint: bool,
        request_matches_bound_fingerprint: bool,
    ) -> bool {
        spec_approval_session_binding_satisfied(
            approval_has_session_binding,
            request_has_session,
            request_matches_bound_session,
        ) && spec_approval_fingerprint_binding_satisfied(
            approval_has_action_fingerprint_binding,
            request_has_action_fingerprint,
            request_matches_bound_fingerprint,
        )
    }

    #[test]
    fn test_production_matches_verus_spec_total_domain() {
        let mut checked = 0usize;
        for bits in 0u8..64 {
            let f = |i: u8| bits & (1 << i) != 0;
            let (a, b, c, d, e, g) = (f(0), f(1), f(2), f(3), f(4), f(5));
            assert_eq!(
                approval_session_binding_satisfied(a, b, c),
                spec_approval_session_binding_satisfied(a, b, c),
                "PARITY-HAND-1: approval_session_binding_satisfied disagrees at ({a}, {b}, {c})"
            );
            assert_eq!(
                approval_fingerprint_binding_satisfied(d, e, g),
                spec_approval_fingerprint_binding_satisfied(d, e, g),
                "PARITY-HAND-1: approval_fingerprint_binding_satisfied disagrees at \
                 ({d}, {e}, {g})"
            );
            assert_eq!(
                approval_scope_binding_satisfied(a, b, c, d, e, g),
                spec_approval_scope_binding_satisfied(a, b, c, d, e, g),
                "PARITY-HAND-1: approval_scope_binding_satisfied disagrees at bits {bits:#08b}"
            );
            checked += 1;
        }
        assert_eq!(checked, 64, "total domain is 2^6; enumeration collapsed");
    }

    #[test]
    fn test_spec_oracle_can_reject() {
        // A session-bound approval must not be replayed on a request that has
        // no session, or one bound to a different session.
        assert!(!spec_approval_session_binding_satisfied(true, false, true));
        assert!(!spec_approval_session_binding_satisfied(true, true, false));
        // An unbound approval imposes no session requirement.
        assert!(spec_approval_session_binding_satisfied(false, false, false));
        // The same shape holds for the action-fingerprint binding.
        assert!(!spec_approval_fingerprint_binding_satisfied(
            true, true, false
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unbound_session_binding_always_succeeds() {
        assert!(approval_session_binding_satisfied(false, false, false));
        assert!(approval_session_binding_satisfied(false, true, false));
        assert!(approval_session_binding_satisfied(false, true, true));
    }

    #[test]
    fn test_bound_session_binding_requires_present_match() {
        assert!(!approval_session_binding_satisfied(true, false, false));
        assert!(!approval_session_binding_satisfied(true, true, false));
        assert!(approval_session_binding_satisfied(true, true, true));
    }

    #[test]
    fn test_unbound_fingerprint_binding_always_succeeds() {
        assert!(approval_fingerprint_binding_satisfied(false, false, false));
        assert!(approval_fingerprint_binding_satisfied(false, true, false));
        assert!(approval_fingerprint_binding_satisfied(false, true, true));
    }

    #[test]
    fn test_bound_fingerprint_binding_requires_present_match() {
        assert!(!approval_fingerprint_binding_satisfied(true, false, false));
        assert!(!approval_fingerprint_binding_satisfied(true, true, false));
        assert!(approval_fingerprint_binding_satisfied(true, true, true));
    }

    #[test]
    fn test_combined_scope_binding_requires_all_bound_dimensions() {
        assert!(approval_scope_binding_satisfied(
            false, false, false, false, false, false
        ));
        assert!(approval_scope_binding_satisfied(
            true, true, true, true, true, true
        ));
        assert!(!approval_scope_binding_satisfied(
            true, false, false, false, false, false
        ));
        assert!(!approval_scope_binding_satisfied(
            false, false, false, true, false, false
        ));
        assert!(!approval_scope_binding_satisfied(
            true, true, true, true, true, false
        ));
    }
}
