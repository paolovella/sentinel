// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verified capability literal matching kernel.
//!
//! This module extracts the literal-only fast paths from
//! `capability_token.rs::pattern_matches()` and
//! `capability_token.rs::grant_is_subset()` so they can be mirrored in Verus
//! without pulling full glob-language containment into the proof boundary.

/// Return true when a pattern with no glob metacharacters matches a value via
/// ASCII-case-insensitive equality.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn literal_pattern_matches(
    pattern_has_metacharacters: bool,
    pattern_equals_value_ignore_ascii_case: bool,
) -> bool {
    !pattern_has_metacharacters && pattern_equals_value_ignore_ascii_case
}

/// Return true when a literal child pattern is safely contained by the parent
/// pattern according to the runtime matcher result.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn literal_child_pattern_subset(
    child_has_metacharacters: bool,
    parent_matches_child_literal: bool,
) -> bool {
    !child_has_metacharacters && parent_matches_child_literal
}

#[cfg(test)]
mod verus_spec_differential {
    //! Differential binding for `PARITY-HAND-1` (see
    //! `formal/ASSUMPTION_REGISTRY.md`).
    //!
    //! Verus proves `exec == spec` for the kernel in
    //! `formal/verus/verified_capability_literal.rs`. The transcriptions below restate that
    //! `spec` and assert it agrees with the function this crate actually ships,
    //! which is the step that carries the proof to production. Symbol-level
    //! parity cannot do this: `check-verus-parity.sh` greps for names and
    //! reported success against a tree with a security check replaced by
    //! `return true`.
    //!
    //! TOTAL discharge: both predicates range over two booleans, so
    //! the enumeration below is the entire input domain, not a sample.
    //!
    //! Keep each transcription in step with the kernel. If it drifts, the
    //! assumption returns silently.

    use super::*;

    fn spec_literal_pattern_matches(
        pattern_has_metacharacters: bool,
        pattern_equals_value_ignore_ascii_case: bool,
    ) -> bool {
        !pattern_has_metacharacters && pattern_equals_value_ignore_ascii_case
    }

    fn spec_literal_child_pattern_subset(
        child_has_metacharacters: bool,
        parent_matches_child_literal: bool,
    ) -> bool {
        !child_has_metacharacters && parent_matches_child_literal
    }

    #[test]
    fn test_production_matches_verus_spec_total_domain() {
        let mut checked = 0usize;
        for a in [false, true] {
            for b in [false, true] {
                assert_eq!(
                    literal_pattern_matches(a, b),
                    spec_literal_pattern_matches(a, b),
                    "PARITY-HAND-1: literal_pattern_matches disagrees at ({a}, {b})"
                );
                assert_eq!(
                    literal_child_pattern_subset(a, b),
                    spec_literal_child_pattern_subset(a, b),
                    "PARITY-HAND-1: literal_child_pattern_subset disagrees at ({a}, {b})"
                );
                checked += 1;
            }
        }
        assert_eq!(checked, 4, "total domain is 2^2; enumeration collapsed");
    }

    #[test]
    fn test_spec_oracle_can_reject() {
        // A discharge that cannot fail reinstates the assumption while
        // appearing to remove it.
        assert!(!spec_literal_pattern_matches(true, true));
        assert!(!spec_literal_pattern_matches(false, false));
        assert!(spec_literal_pattern_matches(false, true));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_literal_pattern_matches_accepts_equal_literal() {
        assert!(literal_pattern_matches(false, true));
    }

    #[test]
    fn test_literal_pattern_matches_rejects_literal_mismatch() {
        assert!(!literal_pattern_matches(false, false));
    }

    #[test]
    fn test_literal_pattern_matches_rejects_metacharacter_pattern() {
        assert!(!literal_pattern_matches(true, true));
    }

    #[test]
    fn test_literal_child_pattern_subset_accepts_matching_literal_child() {
        assert!(literal_child_pattern_subset(false, true));
    }

    #[test]
    fn test_literal_child_pattern_subset_rejects_mismatching_literal_child() {
        assert!(!literal_child_pattern_subset(false, false));
    }

    #[test]
    fn test_literal_child_pattern_subset_rejects_child_glob() {
        assert!(!literal_child_pattern_subset(true, true));
    }
}
