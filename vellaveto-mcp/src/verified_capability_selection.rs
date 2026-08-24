// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verified capability grant-selection kernel.
//!
//! This module extracts the first-match selection rule from
//! `capability_token.rs::check_grant_coverage()` so it can be mirrored in
//! Verus without pulling the full grant matcher into the proof boundary.

/// Return the first matching grant index seen so far.
///
/// Once a matching index is selected, later matching grants cannot replace it.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn next_covering_grant_index(
    selected_index: Option<usize>,
    current_index: usize,
    current_grant_covers: bool,
) -> Option<usize> {
    match selected_index {
        Some(existing_index) => Some(existing_index),
        None => {
            if current_grant_covers {
                Some(current_index)
            } else {
                None
            }
        }
    }
}

#[cfg(test)]
mod verus_spec_differential {
    //! Differential binding for `PARITY-HAND-1` (see
    //! `formal/ASSUMPTION_REGISTRY.md`).
    //!
    //! Verus proves `exec == spec` for the kernel in
    //! `formal/verus/verified_capability_selection.rs`. The transcriptions below restate that
    //! `spec` and assert it agrees with the function this crate actually ships,
    //! which is the step that carries the proof to production. Symbol-level
    //! parity cannot do this: `check-verus-parity.sh` greps for names and
    //! reported success against a tree with a security check replaced by
    //! `return true`.
    //!
    //! BOUNDED discharge: `current_index` ranges over `usize`, so the
    //! enumeration uses a representative set including both extremes rather
    //! than the whole domain. The first-match-wins branch structure is fully
    //! covered.
    //!
    //! Keep each transcription in step with the kernel. If it drifts, the
    //! assumption returns silently.

    use super::*;

    fn spec_next_covering_grant_index(
        selected_index: Option<usize>,
        current_index: usize,
        current_grant_covers: bool,
    ) -> Option<usize> {
        match selected_index {
            Some(existing_index) => Some(existing_index),
            None => {
                if current_grant_covers {
                    Some(current_index)
                } else {
                    None
                }
            }
        }
    }

    #[test]
    fn test_production_matches_verus_spec_bounded() {
        let selected = [None, Some(0usize), Some(1), Some(usize::MAX)];
        let currents = [0usize, 1, 2, usize::MAX];
        let mut checked = 0usize;
        for &s in &selected {
            for &current in &currents {
                for covers in [false, true] {
                    assert_eq!(
                        next_covering_grant_index(s, current, covers),
                        spec_next_covering_grant_index(s, current, covers),
                        "PARITY-HAND-1: next_covering_grant_index disagrees at \
                         ({s:?}, {current}, {covers})"
                    );
                    checked += 1;
                }
            }
        }
        assert_eq!(checked, 32, "enumeration collapsed");
    }

    #[test]
    fn test_spec_oracle_can_reject() {
        // First match wins: a later covering grant must not displace it.
        assert_eq!(spec_next_covering_grant_index(Some(3), 9, true), Some(3));
        assert_eq!(spec_next_covering_grant_index(None, 9, false), None);
        assert_eq!(spec_next_covering_grant_index(None, 9, true), Some(9));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_next_covering_grant_index_selects_first_match() {
        assert_eq!(next_covering_grant_index(None, 3, true), Some(3));
    }

    #[test]
    fn test_next_covering_grant_index_skips_non_match() {
        assert_eq!(next_covering_grant_index(None, 3, false), None);
    }

    #[test]
    fn test_next_covering_grant_index_preserves_existing_selection() {
        assert_eq!(next_covering_grant_index(Some(1), 4, false), Some(1));
        assert_eq!(next_covering_grant_index(Some(1), 4, true), Some(1));
    }
}
