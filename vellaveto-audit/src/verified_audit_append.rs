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
mod verus_composition_differential {
    //! Differential binding for `PARITY-HAND-1`, composition kernel
    //! `formal/verus/verified_audit_integrity.rs` (AUDIT-INT-1..4).
    //!
    //! This kernel does not model a new function. It **restates** primitives
    //! that `verified_audit_append` and `verified_audit_chain` already model,
    //! then proves properties of composing them n times. That makes it
    //! vulnerable to a failure the per-primitive bindings cannot catch: the
    //! composition reasoning about a *different* primitive than the one that
    //! ships, because it carries its own copy of the definition.
    //!
    //! So the binding has two halves. First the restated primitives are checked
    //! against the shipped ones. Then the n-step compositions are checked
    //! against iterating the shipped functions.
    //!
    //! BOUNDED: primitives over a `u64` boundary set around the saturation
    //! point; compositions over step counts 0..=64 from several starting
    //! points including two steps below `u64::MAX`, where saturation bites.

    use super::*;
    use crate::verified_audit_chain::{audit_chain_step_valid, next_seen_hashed_entry};

    const U64_MAX: u64 = u64::MAX;

    /// Restated in the composition kernel — must equal the bound primitive.
    ///
    /// The kernel states saturation over unbounded `nat`, where `n >= U64_MAX`
    /// is a genuine comparison. In `u64` the `>` half is unreachable and it
    /// collapses to `==`; that is a property of the domain change, not a
    /// liberty taken with the spec.
    fn spec_next_entry_count(n: u64) -> u64 {
        if n == U64_MAX {
            U64_MAX
        } else {
            n + 1
        }
    }

    fn spec_next_global_sequence(n: u64) -> u64 {
        if n == U64_MAX {
            U64_MAX
        } else {
            n + 1
        }
    }

    fn spec_assigned_sequence(global_seq: u64) -> u64 {
        global_seq
    }

    fn spec_entry_count_after_rotation() -> u64 {
        0
    }

    /// Transcription of the composition kernel's own `spec_chain_step_valid`,
    /// which takes raw inputs where `verified_audit_chain` takes pre-computed
    /// guard results.
    #[allow(clippy::too_many_arguments)]
    fn spec_chain_step_valid(
        is_utc: bool,
        timestamps_nondecreasing: bool,
        prev_seq: u64,
        current_seq: u64,
        seen_hashed: bool,
        entry_has_hash: bool,
        prev_hash_present: bool,
        current_hash_present: bool,
    ) -> bool {
        is_utc
            && timestamps_nondecreasing
            && (prev_seq == 0 || current_seq > prev_seq)
            && (!seen_hashed || entry_has_hash)
            && (!entry_has_hash || (prev_hash_present && current_hash_present))
    }

    fn spec_next_seen_hashed(seen_hashed: bool, entry_has_hash: bool) -> bool {
        seen_hashed || entry_has_hash
    }

    const BOUNDARY: [u64; 8] = [
        0,
        1,
        2,
        1_000,
        U64_MAX / 2,
        U64_MAX - 2,
        U64_MAX - 1,
        U64_MAX,
    ];

    #[test]
    fn test_restated_primitives_equal_the_shipped_ones() {
        assert_eq!(
            entry_count_after_rotation(),
            spec_entry_count_after_rotation(),
            "PARITY-HAND-1: the composition kernel restates entry_count_after_rotation differently"
        );
        for &v in &BOUNDARY {
            assert_eq!(
                next_entry_count(v),
                spec_next_entry_count(v),
                "PARITY-HAND-1: the composition kernel restates next_entry_count differently at {v}"
            );
            assert_eq!(
                next_global_sequence(v),
                spec_next_global_sequence(v),
                "PARITY-HAND-1: the composition kernel restates next_global_sequence differently at {v}"
            );
            assert_eq!(
                assigned_sequence(v),
                spec_assigned_sequence(v),
                "PARITY-HAND-1: the composition kernel restates assigned_sequence differently at {v}"
            );
        }
    }

    /// AUDIT-INT-1: n appends from `initial` give `initial + n`, saturating.
    #[test]
    fn test_global_sequence_after_n_appends_matches_iterating_the_shipped_fn() {
        for &initial in &BOUNDARY {
            let mut shipped = initial;
            let mut spec = initial;
            for n in 0..=64u64 {
                assert_eq!(
                    shipped, spec,
                    "PARITY-HAND-1: global sequence diverges after {n} appends from {initial}"
                );
                // Below saturation the closed form must also hold.
                if initial < U64_MAX - 64 {
                    assert_eq!(
                        shipped,
                        initial + n,
                        "AUDIT-INT-1: {n} appends from {initial} did not give initial + n"
                    );
                }
                shipped = next_global_sequence(shipped);
                spec = spec_next_global_sequence(spec);
            }
        }
    }

    /// AUDIT-INT-2: entry count after a rotation then n appends is n, saturating.
    #[test]
    fn test_entry_count_after_rotation_and_n_matches_iterating_the_shipped_fn() {
        let mut shipped = entry_count_after_rotation();
        let mut spec = spec_entry_count_after_rotation();
        for n in 0..=64u64 {
            assert_eq!(
                shipped, spec,
                "PARITY-HAND-1: entry count diverges after rotation and {n} appends"
            );
            assert_eq!(
                shipped, n,
                "AUDIT-INT-2: rotation then {n} appends did not give n"
            );
            shipped = next_entry_count(shipped);
            spec = spec_next_entry_count(spec);
        }
    }

    /// AUDIT-INT-3: `seen_hashed` latches — once true it never returns false.
    #[test]
    fn test_seen_hashed_latches_across_n_steps() {
        for start in [false, true] {
            for mask in 0u16..256 {
                let mut shipped = start;
                let mut spec = start;
                let mut ever_hashed = start;
                for step in 0..8u16 {
                    let entry_has_hash = mask & (1 << step) != 0;
                    shipped = next_seen_hashed_entry(shipped, entry_has_hash);
                    spec = spec_next_seen_hashed(spec, entry_has_hash);
                    ever_hashed |= entry_has_hash;
                    assert_eq!(
                        shipped, spec,
                        "PARITY-HAND-1: seen_hashed diverges at step {step} of mask {mask:#010b}"
                    );
                    assert_eq!(
                        shipped, ever_hashed,
                        "AUDIT-INT-3: seen_hashed did not latch at step {step} of mask {mask:#010b}"
                    );
                }
            }
        }
    }

    /// AUDIT-INT-4: the composition kernel's chain step must accept exactly
    /// what the shipped guards accept, once the guards are computed the way
    /// production computes them.
    #[test]
    fn test_chain_step_matches_the_shipped_guards() {
        let sequences = [
            (0u64, 0u64),
            (0, 5),
            (5, 5),
            (5, 4),
            (5, 6),
            (U64_MAX - 1, U64_MAX),
        ];
        let mut checked = 0usize;
        for bits in 0u8..64 {
            let f = |i: u8| bits & (1 << i) != 0;
            let (is_utc, ts_ok, seen_hashed, entry_has_hash, prev_hash, cur_hash) =
                (f(0), f(1), f(2), f(3), f(4), f(5));
            for (prev_seq, current_seq) in sequences {
                // Production computes the guards first, then combines them.
                let shipped = audit_chain_step_valid(
                    is_utc && ts_ok,
                    current_seq == 0 || prev_seq == 0 || current_seq > prev_seq,
                    entry_has_hash || !seen_hashed,
                    entry_has_hash,
                    prev_hash,
                    cur_hash,
                );
                let composition = spec_chain_step_valid(
                    is_utc,
                    ts_ok,
                    prev_seq,
                    current_seq,
                    seen_hashed,
                    entry_has_hash,
                    prev_hash,
                    cur_hash,
                );
                // AUDIT-LEGACY-1: the one place they differ. Production
                // treats `current_seq == 0` as a legacy entry and skips the
                // monotonicity check; the composition kernel only skips on
                // `prev_seq == 0`, so it rejects what production accepts.
                // Asserted rather than skipped, so the gap cannot widen
                // quietly — and so it fails if the two ever converge.
                if current_seq == 0 && prev_seq != 0 {
                    if is_utc && ts_ok && (entry_has_hash || !seen_hashed) {
                        assert!(
                            !composition,
                            "AUDIT-LEGACY-1: the composition kernel now accepts a legacy \
                             zero-sequence entry at ({prev_seq}, {current_seq}); if the kernel \
                             was updated, remove this carve-out"
                        );
                        assert_eq!(
                            shipped,
                            !entry_has_hash || (prev_hash && cur_hash),
                            "AUDIT-LEGACY-1: production stopped accepting legacy zero-sequence \
                             entries at ({prev_seq}, {current_seq})"
                        );
                    }
                    continue;
                }
                assert_eq!(
                    shipped, composition,
                    "PARITY-HAND-1: chain step disagrees at bits {bits:#08b}, seq ({prev_seq}, {current_seq})"
                );
                checked += 1;
            }
        }
        assert!(checked > 300, "enumeration collapsed to {checked}");
    }

    #[test]
    fn test_spec_oracle_can_reject() {
        // Saturation, not wrap.
        assert_eq!(spec_next_global_sequence(U64_MAX), U64_MAX);
        // The latch is one-way.
        assert!(spec_next_seen_hashed(true, false));
        // A hashed entry without both links is refused.
        assert!(!spec_chain_step_valid(
            true, true, 1, 2, false, true, true, false
        ));
        assert!(!spec_chain_step_valid(
            true, true, 1, 2, false, true, false, true
        ));
        // Once hashed has been seen, an unhashed entry is refused.
        assert!(!spec_chain_step_valid(
            true, true, 1, 2, true, false, true, true
        ));
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
