// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verified cross-rotation manifest guard kernel.
//!
//! This module extracts the pure linkage and path-safety predicates used while
//! verifying rotation manifests.

/// Return true when the claimed `start_hash` is consistent with the previous
/// segment tail.
#[inline]
#[must_use = "rotation-manifest linkage decisions must not be discarded"]
pub(crate) const fn rotation_start_hash_link_valid(
    claimed_start_hash_is_empty: bool,
    has_previous_tail_hash: bool,
    claimed_start_hash_matches_previous_tail: bool,
) -> bool {
    claimed_start_hash_is_empty
        || !has_previous_tail_hash
        || claimed_start_hash_matches_previous_tail
}

/// Return true when a rotated-file manifest reference is safe to resolve
/// relative to the audit-log directory.
#[inline]
#[must_use = "rotation-manifest path-safety decisions must not be discarded"]
pub(crate) const fn rotated_file_reference_valid(
    has_traversal: bool,
    is_absolute: bool,
    is_bare_filename: bool,
    is_empty: bool,
) -> bool {
    !has_traversal && !is_absolute && is_bare_filename && !is_empty
}

/// Return true when a missing rotated file may still be treated as a benign
/// prune.
#[inline]
#[must_use = "rotation-manifest prune-boundary decisions must not be discarded"]
pub(crate) const fn missing_rotated_file_allowed(files_checked: usize) -> bool {
    files_checked == 0
}

#[cfg(test)]
mod verus_spec_differential {
    //! Differential binding for `PARITY-HAND-1` (see
    //! `formal/ASSUMPTION_REGISTRY.md`).
    //!
    //! Verus proves `exec == spec` for `formal/verus/verified_rotation_manifest.rs`.
    //! The transcriptions below restate that `spec` and assert it agrees with
    //! the function this crate ships, which is the step that carries the proof
    //! to production. Symbol parity cannot see this: `check-verus-parity.sh`
    //! greps for names.
    //!
    //! MIXED: the two reference predicates are enumerated TOTALLY over their
    //! booleans (2^3 and 2^4). The file counter is `usize` and uses a small
    //! boundary set around zero, which is the only value the spec treats
    //! specially.
    //!
    //! Keep each transcription in step with the kernel; if it drifts, the
    //! assumption returns silently.

    use super::*;

    fn spec_rotation_start_hash_link_valid(
        claimed_start_hash_is_empty: bool,
        has_previous_tail_hash: bool,
        claimed_start_hash_matches_previous_tail: bool,
    ) -> bool {
        claimed_start_hash_is_empty
            || !has_previous_tail_hash
            || claimed_start_hash_matches_previous_tail
    }

    fn spec_rotated_file_reference_valid(
        has_traversal: bool,
        is_absolute: bool,
        is_bare_filename: bool,
        is_empty: bool,
    ) -> bool {
        !has_traversal && !is_absolute && is_bare_filename && !is_empty
    }

    fn spec_missing_rotated_file_allowed(files_checked: usize) -> bool {
        files_checked == 0
    }

    #[test]
    fn test_production_matches_verus_spec_total_domain() {
        for bits in 0u8..16 {
            let f = |i: u8| bits & (1 << i) != 0;
            let (a, b, c, d) = (f(0), f(1), f(2), f(3));
            assert_eq!(
                rotation_start_hash_link_valid(a, b, c),
                spec_rotation_start_hash_link_valid(a, b, c),
                "PARITY-HAND-1: rotation_start_hash_link_valid disagrees at ({a}, {b}, {c})"
            );
            assert_eq!(
                rotated_file_reference_valid(a, b, c, d),
                spec_rotated_file_reference_valid(a, b, c, d),
                "PARITY-HAND-1: rotated_file_reference_valid disagrees at ({a}, {b}, {c}, {d})"
            );
        }
        for files_checked in [0usize, 1, 2, 100, usize::MAX] {
            assert_eq!(
                missing_rotated_file_allowed(files_checked),
                spec_missing_rotated_file_allowed(files_checked),
                "PARITY-HAND-1: missing_rotated_file_allowed disagrees at {files_checked}"
            );
        }
    }

    #[test]
    fn test_spec_oracle_can_reject() {
        // A claimed start hash that contradicts the previous segment's tail
        // breaks cross-rotation continuity.
        assert!(!spec_rotation_start_hash_link_valid(false, true, false));
        // Path traversal, absolute paths and empty names are all refused.
        assert!(!spec_rotated_file_reference_valid(true, false, true, false));
        assert!(!spec_rotated_file_reference_valid(false, true, true, false));
        assert!(!spec_rotated_file_reference_valid(false, false, true, true));
        assert!(!spec_rotated_file_reference_valid(
            false, false, false, false
        ));
        // A missing rotated file is only tolerable before anything was checked.
        assert!(!spec_missing_rotated_file_allowed(1));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rotation_start_hash_link_valid_allows_empty_start_hash() {
        assert!(rotation_start_hash_link_valid(true, true, false));
    }

    #[test]
    fn test_rotation_start_hash_link_valid_allows_first_segment_without_previous_tail() {
        assert!(rotation_start_hash_link_valid(false, false, false));
    }

    #[test]
    fn test_rotation_start_hash_link_valid_rejects_mismatch_after_previous_tail() {
        assert!(!rotation_start_hash_link_valid(false, true, false));
    }

    #[test]
    fn test_rotated_file_reference_valid_accepts_bare_filename() {
        assert!(rotated_file_reference_valid(false, false, true, false));
    }

    #[test]
    fn test_rotated_file_reference_valid_rejects_unsafe_paths() {
        assert!(!rotated_file_reference_valid(true, false, true, false));
        assert!(!rotated_file_reference_valid(false, true, true, false));
        assert!(!rotated_file_reference_valid(false, false, false, false));
        assert!(!rotated_file_reference_valid(false, false, true, true));
    }

    #[test]
    fn test_missing_rotated_file_allowed_only_before_existing_segment() {
        assert!(missing_rotated_file_allowed(0));
        assert!(!missing_rotated_file_allowed(1));
        assert!(!missing_rotated_file_allowed(2));
    }
}
