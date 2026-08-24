// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verified predicates for warm-restart session restoration.
//!
//! Extracted from the inline conditions in `SessionGuard::warm_restart` so that
//! `formal/verus/verified_warm_restart.rs` has named production counterparts to
//! bind against. `warm_restart` calls these; behaviour is unchanged.

use crate::session_guard::SessionState;

/// Return true when a persisted session is security-critical and must survive a
/// restart.
///
/// Restoring only these states is what stops a restart from clearing a lock an
/// attacker earned — the whole point of warm restart.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) fn should_restore(state: SessionState) -> bool {
    matches!(state, SessionState::Locked | SessionState::Suspicious)
}

/// Return true when another session fits within the configured bound.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn can_insert(current_count: usize, max_sessions: usize) -> bool {
    current_count < max_sessions
}

/// Saturating restoration counter.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn next_restored(restored: usize) -> usize {
    restored.saturating_add(1)
}

#[cfg(test)]
mod verus_spec_differential {
    //! Differential binding for `PARITY-HAND-1` (see
    //! `formal/ASSUMPTION_REGISTRY.md`).
    //!
    //! Verus proves `exec == spec` for
    //! `formal/verus/verified_warm_restart.rs`. The transcriptions below
    //! restate that `spec` and assert it agrees with the shipped predicates.
    //!
    //! `should_restore` gets a TOTAL discharge over every `SessionState`
    //! variant, which is the property that matters: adding a state without
    //! deciding whether it survives a restart is the failure mode, and this
    //! test forces that decision.
    //!
    //! `can_insert` and the counter are BOUNDED over a `usize` set including
    //! both extremes, since the counter must saturate rather than wrap.

    use super::*;

    /// Every `SessionState` the crate defines. If a variant is added and not
    /// listed here, `test_every_session_state_is_covered` fails.
    const ALL_STATES: [SessionState; 5] = [
        SessionState::Init,
        SessionState::Active,
        SessionState::Suspicious,
        SessionState::Locked,
        SessionState::Ended,
    ];

    fn spec_should_restore(state: SessionState) -> bool {
        state == SessionState::Locked || state == SessionState::Suspicious
    }

    fn spec_can_insert(current_count: usize, max_sessions: usize) -> bool {
        current_count < max_sessions
    }

    fn spec_saturating_add(a: usize, b: usize) -> usize {
        match a.checked_add(b) {
            // The kernel writes this as `a + b > usize::MAX` over unbounded
            // `int`, which in `usize` is exactly "the addition wrapped".
            Some(total) => total,
            None => usize::MAX,
        }
    }

    #[test]
    fn test_should_restore_matches_verus_spec_total_domain() {
        for state in ALL_STATES {
            assert_eq!(
                should_restore(state),
                spec_should_restore(state),
                "PARITY-HAND-1: should_restore disagrees for {state:?}"
            );
        }
    }

    /// A new `SessionState` variant must be classified deliberately, not
    /// inherit "do not restore" by falling through a `matches!`.
    #[test]
    fn test_every_session_state_is_covered() {
        for state in ALL_STATES {
            let restored = should_restore(state);
            match state {
                SessionState::Locked | SessionState::Suspicious => assert!(
                    restored,
                    "PARITY-HAND-1: {state:?} is security-critical and must survive a restart"
                ),
                SessionState::Init | SessionState::Active | SessionState::Ended => {
                    assert!(!restored, "PARITY-HAND-1: {state:?} must not be restored")
                }
            }
        }
    }

    #[test]
    fn test_capacity_and_counter_match_verus_spec_at_boundaries() {
        let values = [0usize, 1, 2, 64, usize::MAX - 1, usize::MAX];
        for &current in &values {
            for &max in &values {
                assert_eq!(
                    can_insert(current, max),
                    spec_can_insert(current, max),
                    "PARITY-HAND-1: can_insert disagrees at ({current}, {max})"
                );
            }
            assert_eq!(
                next_restored(current),
                spec_saturating_add(current, 1),
                "PARITY-HAND-1: next_restored disagrees at {current}"
            );
        }
    }

    #[test]
    fn test_spec_oracle_can_reject() {
        // Only the two security-critical states survive.
        assert!(!spec_should_restore(SessionState::Init));
        assert!(!spec_should_restore(SessionState::Active));
        assert!(!spec_should_restore(SessionState::Ended));
        assert!(spec_should_restore(SessionState::Locked));
        // The bound is exclusive: at capacity nothing more is inserted.
        assert!(!spec_can_insert(4, 4));
        assert!(spec_can_insert(3, 4));
        // The counter saturates rather than wrapping to zero.
        assert_eq!(spec_saturating_add(usize::MAX, 1), usize::MAX);
    }
}
