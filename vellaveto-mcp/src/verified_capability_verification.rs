// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verified capability-token verification precheck boundary.
//!
//! This module extracts the pure fail-closed guards from
//! `capability_token.rs::verify_capability_token()` so they can be mirrored in
//! Verus without pulling Ed25519 or hashing into the proof boundary.

/// Exact decoded Ed25519 public-key length in bytes.
pub(crate) const CAPABILITY_PUBLIC_KEY_LEN: usize = 32;

/// Exact decoded Ed25519 signature length in bytes.
pub(crate) const CAPABILITY_SIGNATURE_LEN: usize = 64;

/// Return true when the current time remains strictly before expiry.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn capability_not_expired(now_before_expires: bool) -> bool {
    now_before_expires
}

/// Return true when `issued_at` does not exceed the allowed future skew.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn capability_issued_at_within_skew(
    issued_at_skew_secs: i64,
    max_issued_at_skew_secs: i64,
) -> bool {
    issued_at_skew_secs <= max_issued_at_skew_secs
}

/// Return true when an expected issuer public key matches the token key.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn capability_expected_public_key_matches(
    expected_key_equals_token_key: bool,
) -> bool {
    expected_key_equals_token_key
}

/// Return true when the decoded issuer public key has the required length.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn capability_public_key_length_valid(public_key_len: usize) -> bool {
    public_key_len == CAPABILITY_PUBLIC_KEY_LEN
}

/// Return true when the decoded signature has the required length.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn capability_signature_length_valid(signature_len: usize) -> bool {
    signature_len == CAPABILITY_SIGNATURE_LEN
}

#[cfg(test)]
mod verus_spec_differential {
    //! Differential binding for `PARITY-HAND-1` (see
    //! `formal/ASSUMPTION_REGISTRY.md`).
    //!
    //! Verus proves `exec == spec` for the kernel in
    //! `formal/verus/verified_capability_verification.rs`. The transcriptions below restate that
    //! `spec` and assert it agrees with the function this crate actually ships,
    //! which is the step that carries the proof to production. Symbol-level
    //! parity cannot do this: `check-verus-parity.sh` greps for names and
    //! reported success against a tree with a security check replaced by
    //! `return true`.
    //!
    //! MIXED: the boolean predicates get a TOTAL discharge. The length
    //! predicates are enumerated exhaustively over `0..=128`, which brackets
    //! both accepted lengths. The skew comparison is bounded to a boundary set
    //! around equality and both `i64` extremes.
    //!
    //! The spec fixes the accepted lengths at 32 and 64 literally, while
    //! production reads named constants — so this also binds those constants.
    //!
    //! Keep each transcription in step with the kernel. If it drifts, the
    //! assumption returns silently.

    use super::*;

    fn spec_capability_not_expired(now_before_expires: bool) -> bool {
        now_before_expires
    }

    fn spec_capability_issued_at_within_skew(
        issued_at_skew_secs: i64,
        max_issued_at_skew_secs: i64,
    ) -> bool {
        issued_at_skew_secs <= max_issued_at_skew_secs
    }

    fn spec_capability_expected_public_key_matches(expected_key_equals_token_key: bool) -> bool {
        expected_key_equals_token_key
    }

    fn spec_capability_public_key_length_valid(public_key_len: usize) -> bool {
        public_key_len == 32
    }

    fn spec_capability_signature_length_valid(signature_len: usize) -> bool {
        signature_len == 64
    }

    #[test]
    fn test_boolean_predicates_match_verus_spec_total_domain() {
        for a in [false, true] {
            assert_eq!(
                capability_not_expired(a),
                spec_capability_not_expired(a),
                "PARITY-HAND-1: capability_not_expired disagrees at ({a})"
            );
            assert_eq!(
                capability_expected_public_key_matches(a),
                spec_capability_expected_public_key_matches(a),
                "PARITY-HAND-1: capability_expected_public_key_matches disagrees at ({a})"
            );
        }
    }

    #[test]
    fn test_length_predicates_match_verus_spec_exhaustive_to_128() {
        for len in 0usize..=128 {
            assert_eq!(
                capability_public_key_length_valid(len),
                spec_capability_public_key_length_valid(len),
                "PARITY-HAND-1: capability_public_key_length_valid disagrees at {len}"
            );
            assert_eq!(
                capability_signature_length_valid(len),
                spec_capability_signature_length_valid(len),
                "PARITY-HAND-1: capability_signature_length_valid disagrees at {len}"
            );
        }
    }

    #[test]
    fn test_skew_predicate_matches_verus_spec_at_boundaries() {
        let values = [
            i64::MIN,
            -1_000_000,
            -1,
            0,
            1,
            299,
            300,
            301,
            1_000_000,
            i64::MAX,
        ];
        for &skew in &values {
            for &max in &values {
                assert_eq!(
                    capability_issued_at_within_skew(skew, max),
                    spec_capability_issued_at_within_skew(skew, max),
                    "PARITY-HAND-1: capability_issued_at_within_skew disagrees at ({skew}, {max})"
                );
            }
        }
    }

    #[test]
    fn test_spec_oracle_can_reject() {
        assert!(!spec_capability_not_expired(false));
        assert!(!spec_capability_public_key_length_valid(31));
        assert!(!spec_capability_public_key_length_valid(33));
        assert!(!spec_capability_signature_length_valid(63));
        assert!(!spec_capability_signature_length_valid(65));
        assert!(!spec_capability_issued_at_within_skew(301, 300));
        assert!(spec_capability_issued_at_within_skew(300, 300));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capability_not_expired_rejects_elapsed_window() {
        assert!(capability_not_expired(true));
        assert!(!capability_not_expired(false));
    }

    #[test]
    fn test_capability_issued_at_within_skew_rejects_future_drift() {
        assert!(capability_issued_at_within_skew(30, 60));
        assert!(capability_issued_at_within_skew(60, 60));
        assert!(!capability_issued_at_within_skew(61, 60));
    }

    #[test]
    fn test_capability_expected_public_key_matches_is_identity() {
        assert!(capability_expected_public_key_matches(true));
        assert!(!capability_expected_public_key_matches(false));
    }

    #[test]
    fn test_capability_public_key_length_valid_requires_exact_length() {
        assert!(capability_public_key_length_valid(
            CAPABILITY_PUBLIC_KEY_LEN
        ));
        assert!(!capability_public_key_length_valid(
            CAPABILITY_PUBLIC_KEY_LEN - 1
        ));
        assert!(!capability_public_key_length_valid(
            CAPABILITY_PUBLIC_KEY_LEN + 1
        ));
    }

    #[test]
    fn test_capability_signature_length_valid_requires_exact_length() {
        assert!(capability_signature_length_valid(CAPABILITY_SIGNATURE_LEN));
        assert!(!capability_signature_length_valid(
            CAPABILITY_SIGNATURE_LEN - 1
        ));
        assert!(!capability_signature_length_valid(
            CAPABILITY_SIGNATURE_LEN + 1
        ));
    }
}
