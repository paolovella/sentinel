// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verified audit-chain verification kernel.
//!
//! This module extracts the pure fail-closed guards from
//! `verification.rs::verify_chain()`. It does not prove cryptographic hash
//! soundness or filesystem semantics; it formalizes the control-flow boundary
//! that decides when audit verification must reject an entry.

/// Return true when the timestamp guard passes:
/// - the timestamp is in UTC form
/// - the timestamp is non-decreasing relative to the previous entry
#[inline]
#[must_use = "audit verification decisions must not be discarded"]
pub(crate) const fn timestamp_guard(is_utc: bool, timestamps_nondecreasing: bool) -> bool {
    is_utc && timestamps_nondecreasing
}

/// Return true when the sequence monotonicity rule passes.
///
/// `has_prev_sequence` indicates whether `prev_sequence` is meaningful. A
/// current sequence of `0` is accepted as a legacy entry and does not
/// participate in monotonicity tracking.
#[inline]
#[must_use = "audit verification decisions must not be discarded"]
pub(crate) const fn sequence_monotonic(
    has_prev_sequence: bool,
    prev_sequence: u64,
    current_sequence: u64,
) -> bool {
    current_sequence == 0 || !has_prev_sequence || current_sequence > prev_sequence
}

/// Return true when the hash-presence transition is allowed.
///
/// Legacy entries without hashes are only permitted before the first hashed
/// entry. Once a hashed entry has been seen, all subsequent entries must also
/// carry hashes.
#[inline]
#[must_use = "audit verification decisions must not be discarded"]
pub(crate) const fn hash_presence_valid(seen_hashed_entry: bool, entry_has_hash: bool) -> bool {
    entry_has_hash || !seen_hashed_entry
}

/// Return true when the full per-entry chain-verification step passes.
///
/// If the entry has no hash, the link/hash booleans are ignored and only the
/// timestamp, sequence, and hash-presence guards matter. If the entry has a
/// hash, both the `prev_hash` link and the recomputed `entry_hash` must match.
#[inline]
#[must_use = "audit verification decisions must not be discarded"]
pub(crate) const fn audit_chain_step_valid(
    timestamp_guard_ok: bool,
    sequence_guard_ok: bool,
    hash_presence_guard_ok: bool,
    entry_has_hash: bool,
    prev_hash_matches: bool,
    entry_hash_matches: bool,
) -> bool {
    timestamp_guard_ok
        && sequence_guard_ok
        && hash_presence_guard_ok
        && (!entry_has_hash || (prev_hash_matches && entry_hash_matches))
}

/// Return the next `seen_hashed_entry` state after processing one entry.
#[inline]
#[must_use = "audit verifier state updates must not be discarded"]
pub(crate) const fn next_seen_hashed_entry(seen_hashed_entry: bool, entry_has_hash: bool) -> bool {
    seen_hashed_entry || entry_has_hash
}

/// Return the next tracked non-zero sequence value.
///
/// Legacy zero-sequence entries leave the tracked value unchanged.
#[inline]
#[must_use = "audit verifier state updates must not be discarded"]
pub(crate) const fn next_prev_sequence(prev_sequence: u64, current_sequence: u64) -> u64 {
    if current_sequence > 0 {
        current_sequence
    } else {
        prev_sequence
    }
}

#[cfg(test)]
mod verus_spec_differential {
    //! Differential binding for `PARITY-HAND-1` (see
    //! `formal/ASSUMPTION_REGISTRY.md`).
    //!
    //! Verus proves `exec == spec` for `formal/verus/verified_audit_chain.rs`.
    //! The transcriptions below restate that `spec` and assert it agrees with
    //! the function this crate ships, which is the step that carries the proof
    //! to production. Symbol parity cannot see this: `check-verus-parity.sh`
    //! greps for names.
    //!
    //! MIXED: the guard predicates are enumerated TOTALLY over their booleans.
    //! The sequence predicates carry `u64` operands and use a boundary set
    //! including both extremes.
    //!
    //! Keep each transcription in step with the kernel; if it drifts, the
    //! assumption returns silently.

    use super::*;

    fn spec_timestamp_guard(is_utc: bool, timestamps_nondecreasing: bool) -> bool {
        is_utc && timestamps_nondecreasing
    }

    fn spec_sequence_monotonic(
        has_prev_sequence: bool,
        prev_sequence: u64,
        current_sequence: u64,
    ) -> bool {
        current_sequence == 0 || !has_prev_sequence || current_sequence > prev_sequence
    }

    fn spec_hash_presence_valid(seen_hashed_entry: bool, entry_has_hash: bool) -> bool {
        entry_has_hash || !seen_hashed_entry
    }

    fn spec_audit_chain_step_valid(
        timestamp_guard_ok: bool,
        sequence_guard_ok: bool,
        hash_presence_guard_ok: bool,
        entry_has_hash: bool,
        prev_hash_matches: bool,
        entry_hash_matches: bool,
    ) -> bool {
        timestamp_guard_ok
            && sequence_guard_ok
            && hash_presence_guard_ok
            && (!entry_has_hash || (prev_hash_matches && entry_hash_matches))
    }

    fn spec_next_seen_hashed_entry(seen_hashed_entry: bool, entry_has_hash: bool) -> bool {
        seen_hashed_entry || entry_has_hash
    }

    fn spec_next_prev_sequence(prev_sequence: u64, current_sequence: u64) -> u64 {
        if current_sequence > 0 {
            current_sequence
        } else {
            prev_sequence
        }
    }

    #[test]
    fn test_boolean_predicates_match_verus_spec_total_domain() {
        for bits in 0u8..64 {
            let f = |i: u8| bits & (1 << i) != 0;
            let (a, b, c, d, e, g) = (f(0), f(1), f(2), f(3), f(4), f(5));

            assert_eq!(
                timestamp_guard(a, b),
                spec_timestamp_guard(a, b),
                "PARITY-HAND-1: timestamp_guard disagrees at ({a}, {b})"
            );
            assert_eq!(
                hash_presence_valid(a, b),
                spec_hash_presence_valid(a, b),
                "PARITY-HAND-1: hash_presence_valid disagrees at ({a}, {b})"
            );
            assert_eq!(
                next_seen_hashed_entry(a, b),
                spec_next_seen_hashed_entry(a, b),
                "PARITY-HAND-1: next_seen_hashed_entry disagrees at ({a}, {b})"
            );
            assert_eq!(
                audit_chain_step_valid(a, b, c, d, e, g),
                spec_audit_chain_step_valid(a, b, c, d, e, g),
                "PARITY-HAND-1: audit_chain_step_valid disagrees at bits {bits:#08b}"
            );
        }
    }

    #[test]
    fn test_sequence_predicates_match_verus_spec_at_boundaries() {
        let values = [0u64, 1, 2, 7, u64::MAX - 1, u64::MAX];
        for &prev in &values {
            for &current in &values {
                for has_prev in [false, true] {
                    assert_eq!(
                        sequence_monotonic(has_prev, prev, current),
                        spec_sequence_monotonic(has_prev, prev, current),
                        "PARITY-HAND-1: sequence_monotonic disagrees at \
                         ({has_prev}, {prev}, {current})"
                    );
                }
                assert_eq!(
                    next_prev_sequence(prev, current),
                    spec_next_prev_sequence(prev, current),
                    "PARITY-HAND-1: next_prev_sequence disagrees at ({prev}, {current})"
                );
            }
        }
    }

    #[test]
    fn test_spec_oracle_can_reject() {
        // A non-UTC timestamp breaks the chain guard.
        assert!(!spec_timestamp_guard(false, true));
        // Sequence numbers must strictly increase once a predecessor exists.
        assert!(!spec_sequence_monotonic(true, 5, 5));
        assert!(!spec_sequence_monotonic(true, 5, 4));
        // Once a hashed entry has been seen, later entries may not drop hashes.
        assert!(!spec_hash_presence_valid(true, false));
        // A hashed entry with a mismatching link is refused.
        assert!(!spec_audit_chain_step_valid(
            true, true, true, true, false, true
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timestamp_guard_rejects_non_utc() {
        assert!(!timestamp_guard(false, true));
    }

    #[test]
    fn test_timestamp_guard_rejects_regression() {
        assert!(!timestamp_guard(true, false));
    }

    #[test]
    fn test_timestamp_guard_accepts_utc_nondecreasing() {
        assert!(timestamp_guard(true, true));
    }

    #[test]
    fn test_sequence_monotonic_accepts_legacy_zero() {
        assert!(sequence_monotonic(true, 10, 0));
    }

    #[test]
    fn test_sequence_monotonic_rejects_regression() {
        assert!(!sequence_monotonic(true, 10, 10));
        assert!(!sequence_monotonic(true, 10, 9));
    }

    #[test]
    fn test_hash_presence_valid_rejects_unhashed_after_hashed() {
        assert!(!hash_presence_valid(true, false));
    }

    #[test]
    fn test_hash_presence_valid_accepts_legacy_prefix() {
        assert!(hash_presence_valid(false, false));
    }

    #[test]
    fn test_audit_chain_step_valid_rejects_hashed_link_mismatch() {
        assert!(!audit_chain_step_valid(true, true, true, true, false, true));
    }

    #[test]
    fn test_audit_chain_step_valid_rejects_hashed_self_hash_mismatch() {
        assert!(!audit_chain_step_valid(true, true, true, true, true, false));
    }

    #[test]
    fn test_audit_chain_step_valid_accepts_unhashed_legacy_entry() {
        assert!(audit_chain_step_valid(
            true, true, true, false, false, false
        ));
    }

    #[test]
    fn test_next_seen_hashed_entry_latches_true() {
        assert!(next_seen_hashed_entry(false, true));
        assert!(next_seen_hashed_entry(true, false));
    }

    #[test]
    fn test_next_prev_sequence_preserves_legacy_zero() {
        assert_eq!(next_prev_sequence(7, 0), 7);
        assert_eq!(next_prev_sequence(7, 8), 8);
    }
}
