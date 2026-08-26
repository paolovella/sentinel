// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verified presented-approval-id validation guards.
//!
//! JSON-RPC transport surfaces may present an approval identifier through
//! `_meta.approval_id`. The value is only accepted when it fits within the
//! transport-specific length cap and contains no dangerous characters.

/// Maximum length accepted for a presented approval ID in transport `_meta`.
pub const MAX_PRESENTED_APPROVAL_ID_LEN: usize = 256;

/// Return true when the presented approval ID length fits within the cap.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub const fn presented_approval_id_length_valid(len: usize) -> bool {
    len <= MAX_PRESENTED_APPROVAL_ID_LEN
}

/// Return true when a presented approval ID should be accepted.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub const fn presented_approval_id_value_accepted(
    length_valid: bool,
    contains_dangerous_chars: bool,
) -> bool {
    length_valid && !contains_dangerous_chars
}

#[cfg(test)]
mod verus_spec_differential {
    //! Differential binding for `PARITY-HAND-1` (see
    //! `formal/ASSUMPTION_REGISTRY.md`).
    //!
    //! Verus proves `exec == spec` for `formal/verus/verified_presented_approval_id.rs`.
    //! The transcriptions below restate that `spec` and assert it agrees with
    //! the shipped function, which is the step that carries the proof to
    //! production. Symbol parity cannot see this: `check-verus-parity.sh`
    //! greps for names.
    //!
    //! MIXED: the acceptance predicate is enumerated TOTALLY over its two
    //! booleans. The length predicate is exhaustive over `0..=512`, which
    //! brackets the 256-byte cap on both sides, plus `usize::MAX`.
    //!
    //! The kernel fixes the cap at a literal 256 while production reads
    //! `MAX_PRESENTED_APPROVAL_ID_LEN`, so this also binds that constant.
    //!
    //! Keep each transcription in step with the kernel; if it drifts, the
    //! assumption returns silently.

    use super::*;

    fn spec_max_presented_approval_id_len() -> usize {
        256
    }

    fn spec_presented_approval_id_length_valid(len: usize) -> bool {
        len <= spec_max_presented_approval_id_len()
    }

    fn spec_presented_approval_id_value_accepted(
        length_valid: bool,
        contains_dangerous_chars: bool,
    ) -> bool {
        length_valid && !contains_dangerous_chars
    }

    #[test]
    fn test_production_matches_verus_spec() {
        for len in 0usize..=512 {
            assert_eq!(
                presented_approval_id_length_valid(len),
                spec_presented_approval_id_length_valid(len),
                "PARITY-HAND-1: presented_approval_id_length_valid disagrees at {len}"
            );
        }
        assert_eq!(
            presented_approval_id_length_valid(usize::MAX),
            spec_presented_approval_id_length_valid(usize::MAX),
            "PARITY-HAND-1: presented_approval_id_length_valid disagrees at usize::MAX"
        );
        for a in [false, true] {
            for b in [false, true] {
                assert_eq!(
                    presented_approval_id_value_accepted(a, b),
                    spec_presented_approval_id_value_accepted(a, b),
                    "PARITY-HAND-1: presented_approval_id_value_accepted disagrees at ({a}, {b})"
                );
            }
        }
    }

    #[test]
    fn test_spec_oracle_can_reject() {
        // The cap is inclusive at 256 and rejects 257.
        assert!(spec_presented_approval_id_length_valid(256));
        assert!(!spec_presented_approval_id_length_valid(257));
        // Dangerous characters are refused regardless of length.
        assert!(!spec_presented_approval_id_value_accepted(true, true));
        assert!(!spec_presented_approval_id_value_accepted(false, false));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_presented_approval_id_length_valid_accepts_within_cap() {
        assert!(presented_approval_id_length_valid(0));
        assert!(presented_approval_id_length_valid(1));
        assert!(presented_approval_id_length_valid(
            MAX_PRESENTED_APPROVAL_ID_LEN
        ));
    }

    #[test]
    fn test_presented_approval_id_length_valid_rejects_above_cap() {
        assert!(!presented_approval_id_length_valid(
            MAX_PRESENTED_APPROVAL_ID_LEN + 1
        ));
    }

    #[test]
    fn test_presented_approval_id_value_accepted_requires_safe_bounded_value() {
        assert!(presented_approval_id_value_accepted(true, false));
        assert!(!presented_approval_id_value_accepted(false, false));
        assert!(!presented_approval_id_value_accepted(true, true));
        assert!(!presented_approval_id_value_accepted(false, true));
    }
}
