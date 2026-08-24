// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Verified cross-call DLP tracker state kernel.
//!
//! This module extracts the pure field-capacity/update decisions from
//! `cross_call_dlp.rs` so they can be proved in Verus without pulling HashMap,
//! VecDeque, UTF-8 decoding, or regex scanning into the proof boundary.

use super::verified_dlp_core;

/// Return true when a new field at capacity must emit a synthetic finding so
/// the caller can fail closed instead of silently losing cross-call coverage.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) const fn should_emit_capacity_exhausted_finding(
    field_exists: bool,
    tracked_fields: usize,
    max_fields: usize,
) -> bool {
    !field_exists && tracked_fields >= max_fields
}

/// Return true when the tracker should update the overlap buffer for this
/// field. Existing fields always update; new fields must satisfy the verified
/// DLP core capacity check.
#[inline]
#[must_use = "security decisions must not be discarded"]
pub(crate) fn should_update_buffer(
    field_exists: bool,
    tracked_fields: usize,
    max_fields: usize,
    current_bytes: usize,
    new_buffer_bytes: usize,
    max_total_bytes: usize,
) -> bool {
    field_exists
        || verified_dlp_core::can_track_field(
            tracked_fields,
            max_fields,
            current_bytes,
            new_buffer_bytes,
            max_total_bytes,
        )
}

#[cfg(test)]
mod verus_spec_differential {
    //! Differential binding for `PARITY-HAND-1` (see
    //! `formal/ASSUMPTION_REGISTRY.md`).
    //!
    //! Verus proves `exec == spec` for `formal/verus/verified_cross_call_dlp.rs`.
    //! The transcriptions below restate that `spec` and assert it agrees with
    //! the shipped function. Symbol parity cannot see this:
    //! `check-verus-parity.sh` greps for names.
    //!
    //! BOUNDED: `field_exists` is enumerated totally; the four `usize` counters
    //! use a boundary set built around the field cap, the byte cap and the
    //! addition overflow the spec forbids.
    //!
    //! Keep each transcription in step with the kernel; if it drifts, the
    //! assumption returns silently.

    use super::*;

    fn spec_should_emit_capacity_exhausted_finding(
        field_exists: bool,
        tracked_fields: usize,
        max_fields: usize,
    ) -> bool {
        !field_exists && tracked_fields >= max_fields
    }

    fn spec_should_update_buffer(
        field_exists: bool,
        tracked_fields: usize,
        max_fields: usize,
        current_bytes: usize,
        new_buffer_bytes: usize,
        max_total_bytes: usize,
    ) -> bool {
        field_exists
            || (tracked_fields < max_fields
                && match current_bytes.checked_add(new_buffer_bytes) {
                    Some(total) => total <= max_total_bytes,
                    None => false,
                })
    }

    #[test]
    fn test_production_matches_verus_spec_at_boundaries() {
        let values = [0usize, 1, 2, 16, usize::MAX - 1, usize::MAX];
        for field_exists in [false, true] {
            for &tracked in &values {
                for &max_fields in &values {
                    assert_eq!(
                        should_emit_capacity_exhausted_finding(field_exists, tracked, max_fields),
                        spec_should_emit_capacity_exhausted_finding(
                            field_exists,
                            tracked,
                            max_fields
                        ),
                        "PARITY-HAND-1: should_emit_capacity_exhausted_finding disagrees at \
                         ({field_exists}, {tracked}, {max_fields})"
                    );
                    for &current_bytes in &values {
                        for &new_bytes in &values {
                            for &max_total in &values {
                                assert_eq!(
                                    should_update_buffer(
                                        field_exists,
                                        tracked,
                                        max_fields,
                                        current_bytes,
                                        new_bytes,
                                        max_total
                                    ),
                                    spec_should_update_buffer(
                                        field_exists,
                                        tracked,
                                        max_fields,
                                        current_bytes,
                                        new_bytes,
                                        max_total
                                    ),
                                    "PARITY-HAND-1: should_update_buffer disagrees"
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn test_spec_oracle_can_reject() {
        // An already-tracked field always updates; a new one at capacity does
        // not, and that is what raises the capacity finding.
        assert!(spec_should_update_buffer(true, 9, 1, 0, 0, 0));
        assert!(!spec_should_update_buffer(false, 1, 1, 0, 0, 0));
        assert!(spec_should_emit_capacity_exhausted_finding(false, 1, 1));
        assert!(!spec_should_emit_capacity_exhausted_finding(true, 1, 1));
        // Overflowing byte budgets fail closed.
        assert!(!spec_should_update_buffer(
            false,
            0,
            1,
            usize::MAX,
            1,
            usize::MAX
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_field_at_capacity_emits_capacity_finding() {
        assert!(should_emit_capacity_exhausted_finding(false, 4, 4));
        assert!(!should_emit_capacity_exhausted_finding(true, 4, 4));
        assert!(!should_emit_capacity_exhausted_finding(false, 3, 4));
    }

    #[test]
    fn test_existing_field_updates_even_at_capacity() {
        assert!(should_update_buffer(true, 4, 4, 600, 150, 600));
    }

    #[test]
    fn test_new_field_updates_below_capacity() {
        assert!(should_update_buffer(false, 3, 4, 450, 150, 600));
    }

    #[test]
    fn test_new_field_rejected_at_capacity() {
        assert!(!should_update_buffer(false, 4, 4, 450, 150, 600));
    }

    #[test]
    fn test_new_field_rejected_on_byte_budget() {
        assert!(!should_update_buffer(false, 3, 4, 580, 50, 600));
    }
}
