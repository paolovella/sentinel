// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verified audit append/recovery counter kernel.
//!
//! This module extracts the pure counter transitions that govern audit append
//! state across normal writes, rotation resets, and restart recovery.

/// Return the per-file entry count immediately after a rotation reset.
#[inline]
#[must_use = "audit append state updates must not be discarded"]
pub(crate) const fn entry_count_after_rotation() -> u64 {
    0
}

/// Return the sequence value assigned to the entry being written.
#[inline]
#[must_use = "audit append state updates must not be discarded"]
pub(crate) const fn assigned_sequence(global_sequence: u64) -> u64 {
    global_sequence
}

/// Return the per-file entry count after one successful append.
#[inline]
#[must_use = "audit append state updates must not be discarded"]
pub(crate) const fn next_entry_count(current_entry_count: u64) -> u64 {
    current_entry_count.saturating_add(1)
}

/// Return the global sequence counter after one successful append.
#[inline]
#[must_use = "audit append state updates must not be discarded"]
pub(crate) const fn next_global_sequence(current_global_sequence: u64) -> u64 {
    current_global_sequence.saturating_add(1)
}

/// Return the next global sequence value after recovering the highest observed
/// sequence from disk.
#[inline]
#[must_use = "audit append state updates must not be discarded"]
pub(crate) const fn next_sequence_after_recovery(max_observed_sequence: u64) -> u64 {
    max_observed_sequence.saturating_add(1)
}

#[cfg(test)]
mod verus_spec_differential {
    //! Differential binding for `PARITY-HAND-1` (see
    //! `formal/ASSUMPTION_REGISTRY.md`).
    //!
    //! Verus proves `exec == spec` for `formal/verus/verified_audit_append.rs`.
    //! The transcriptions below restate that `spec` and assert it agrees with
    //! the function this crate ships, which is the step that carries the proof
    //! to production. Symbol parity cannot see this: `check-verus-parity.sh`
    //! greps for names.
    //!
    //! BOUNDED: every counter is `u64`, so the enumeration is a boundary set
    //! built around zero and the saturation point. Saturation is the property
    //! that matters here — a wrapping counter resets a sequence number and
    //! breaks chain monotonicity, so `u64::MAX` and its neighbours are
    //! included explicitly.
    //!
    //! Keep each transcription in step with the kernel; if it drifts, the
    //! assumption returns silently.

    use super::*;

    const U64_MAX_VALUE: u64 = u64::MAX;

    fn spec_entry_count_after_rotation() -> u64 {
        0
    }

    fn spec_assigned_sequence(global_sequence: u64) -> u64 {
        global_sequence
    }

    /// The kernel states this over unbounded `nat`, where `current >=
    /// U64_MAX_VALUE` is a genuine comparison. Transcribed into `u64` the
    /// `>` half is unreachable, so it collapses to `==`. The reasoning is
    /// recorded here because the collapse is a property of the domain change
    /// and not a liberty taken with the spec.
    fn spec_saturating_next(current: u64) -> u64 {
        if current == U64_MAX_VALUE {
            U64_MAX_VALUE
        } else {
            current + 1
        }
    }

    const BOUNDARY: [u64; 8] = [
        0,
        1,
        2,
        1_000,
        u64::MAX / 2,
        u64::MAX - 2,
        u64::MAX - 1,
        u64::MAX,
    ];

    #[test]
    fn test_production_matches_verus_spec_at_boundaries() {
        assert_eq!(
            entry_count_after_rotation(),
            spec_entry_count_after_rotation(),
            "PARITY-HAND-1: entry_count_after_rotation disagrees"
        );
        for &v in &BOUNDARY {
            assert_eq!(
                assigned_sequence(v),
                spec_assigned_sequence(v),
                "PARITY-HAND-1: assigned_sequence disagrees at {v}"
            );
            assert_eq!(
                next_entry_count(v),
                spec_saturating_next(v),
                "PARITY-HAND-1: next_entry_count disagrees at {v}"
            );
            assert_eq!(
                next_global_sequence(v),
                spec_saturating_next(v),
                "PARITY-HAND-1: next_global_sequence disagrees at {v}"
            );
            assert_eq!(
                next_sequence_after_recovery(v),
                spec_saturating_next(v),
                "PARITY-HAND-1: next_sequence_after_recovery disagrees at {v}"
            );
        }
    }

    #[test]
    fn test_spec_oracle_can_reject() {
        // The counters must saturate rather than wrap. A wrapping sequence
        // number restarts the audit chain at zero.
        assert_eq!(spec_saturating_next(u64::MAX), u64::MAX);
        assert_eq!(spec_saturating_next(0), 1);
        assert_eq!(spec_entry_count_after_rotation(), 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entry_count_after_rotation_resets_to_zero() {
        assert_eq!(entry_count_after_rotation(), 0);
    }

    #[test]
    fn test_assigned_sequence_is_identity() {
        assert_eq!(assigned_sequence(7), 7);
    }

    #[test]
    fn test_next_entry_count_increments_when_not_saturated() {
        assert_eq!(next_entry_count(7), 8);
    }

    #[test]
    fn test_next_entry_count_saturates_at_u64_max() {
        assert_eq!(next_entry_count(u64::MAX), u64::MAX);
    }

    #[test]
    fn test_next_global_sequence_increments_when_not_saturated() {
        assert_eq!(next_global_sequence(7), 8);
    }

    #[test]
    fn test_next_global_sequence_saturates_at_u64_max() {
        assert_eq!(next_global_sequence(u64::MAX), u64::MAX);
    }

    #[test]
    fn test_next_sequence_after_recovery_increments_when_not_saturated() {
        assert_eq!(next_sequence_after_recovery(7), 8);
    }

    #[test]
    fn test_next_sequence_after_recovery_saturates_at_u64_max() {
        assert_eq!(next_sequence_after_recovery(u64::MAX), u64::MAX);
    }
}
