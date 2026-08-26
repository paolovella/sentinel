// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Verified server approval-id validation guards.
//!
//! The HTTP API accepts approval IDs through URL path parameters and the
//! `x-vellaveto-approval-id` header. These values are only accepted when they
//! are non-empty, fit within the server's public contract length cap, and
//! contain no unsafe characters.

/// Maximum length for approval IDs accepted by the HTTP API.
pub const MAX_SERVER_APPROVAL_ID_LEN: usize = 128;

/// Return true when the server-visible approval ID length is valid.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub const fn server_approval_id_length_valid(len: usize) -> bool {
    len > 0 && len <= MAX_SERVER_APPROVAL_ID_LEN
}

/// Return true when the server should accept this approval ID value.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub const fn server_approval_id_value_accepted(
    length_valid: bool,
    contains_unsafe_chars: bool,
) -> bool {
    length_valid && !contains_unsafe_chars
}

#[cfg(test)]
mod verus_spec_differential {
    //! Differential binding for `PARITY-HAND-1` (see
    //! `formal/ASSUMPTION_REGISTRY.md`).
    //!
    //! Verus proves `exec == spec` for `formal/verus/verified_server_approval_id.rs`.
    //! The transcriptions below restate that `spec` and assert it agrees with
    //! the shipped function. Symbol parity cannot see this:
    //! `check-verus-parity.sh` greps for names.
    //!
    //! MIXED: the acceptance predicate is enumerated TOTALLY over its two
    //! booleans; the length predicate is exhaustive over `0..=256`, which
    //! brackets the 128-byte cap on both sides, plus `usize::MAX`.
    //!
    //! The kernel fixes the cap at a literal 128 while production reads
    //! `MAX_SERVER_APPROVAL_ID_LEN`, so this also binds that constant. Note it
    //! differs from the 256-byte cap on the *presented* approval id — using
    //! one where the other belongs is a documented trap in this codebase.
    //!
    //! Keep each transcription in step with the kernel; if it drifts, the
    //! assumption returns silently.

    use super::*;

    fn spec_max_server_approval_id_len() -> usize {
        128
    }

    fn spec_server_approval_id_length_valid(len: usize) -> bool {
        len > 0 && len <= spec_max_server_approval_id_len()
    }

    fn spec_server_approval_id_value_accepted(
        length_valid: bool,
        contains_unsafe_chars: bool,
    ) -> bool {
        length_valid && !contains_unsafe_chars
    }

    #[test]
    fn test_production_matches_verus_spec() {
        for len in 0usize..=256 {
            assert_eq!(
                server_approval_id_length_valid(len),
                spec_server_approval_id_length_valid(len),
                "PARITY-HAND-1: server_approval_id_length_valid disagrees at {len}"
            );
        }
        assert_eq!(
            server_approval_id_length_valid(usize::MAX),
            spec_server_approval_id_length_valid(usize::MAX),
            "PARITY-HAND-1: server_approval_id_length_valid disagrees at usize::MAX"
        );
        for a in [false, true] {
            for b in [false, true] {
                assert_eq!(
                    server_approval_id_value_accepted(a, b),
                    spec_server_approval_id_value_accepted(a, b),
                    "PARITY-HAND-1: server_approval_id_value_accepted disagrees at ({a}, {b})"
                );
            }
        }
    }

    #[test]
    fn test_spec_oracle_can_reject() {
        // Empty is refused and the cap is inclusive at 128.
        assert!(!spec_server_approval_id_length_valid(0));
        assert!(spec_server_approval_id_length_valid(128));
        assert!(!spec_server_approval_id_length_valid(129));
        // Unsafe characters are refused regardless of length.
        assert!(!spec_server_approval_id_value_accepted(true, true));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_approval_id_length_valid_accepts_non_empty_within_cap() {
        assert!(server_approval_id_length_valid(1));
        assert!(server_approval_id_length_valid(MAX_SERVER_APPROVAL_ID_LEN));
    }

    #[test]
    fn test_server_approval_id_length_valid_rejects_empty_or_too_long() {
        assert!(!server_approval_id_length_valid(0));
        assert!(!server_approval_id_length_valid(
            MAX_SERVER_APPROVAL_ID_LEN + 1
        ));
    }

    #[test]
    fn test_server_approval_id_value_accepted_requires_safe_bounded_value() {
        assert!(server_approval_id_value_accepted(true, false));
        assert!(!server_approval_id_value_accepted(false, false));
        assert!(!server_approval_id_value_accepted(true, true));
        assert!(!server_approval_id_value_accepted(false, true));
    }
}
