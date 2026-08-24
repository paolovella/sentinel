// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verified Merkle proof-path kernel.
//!
//! This module extracts the pure structural rules shared by
//! `merkle.rs::compute_siblings()` and `merkle.rs::verify_proof()`: which
//! levels emit a sibling step, which sibling index is chosen, how the left/right
//! direction bit is encoded, and how the leaf index advances to the parent.

/// Return the sibling index paired with `node_index` at the current tree level.
#[inline]
#[must_use = "Merkle proof-path decisions must not be discarded"]
pub(crate) const fn proof_sibling_index(node_index: usize) -> usize {
    if node_index.is_multiple_of(2) {
        node_index + 1
    } else {
        node_index - 1
    }
}

/// Return true when the encoded proof step places the sibling hash on the left
/// side of the verifier's concatenation order.
#[inline]
#[must_use = "Merkle proof-path decisions must not be discarded"]
pub(crate) const fn proof_step_is_left(node_index: usize) -> bool {
    node_index % 2 == 1
}

/// Return true when the current node has a sibling at this level and therefore
/// emits a proof step instead of being promoted unchanged.
#[inline]
#[must_use = "Merkle proof-path decisions must not be discarded"]
pub(crate) const fn proof_level_has_sibling(node_index: usize, level_len: usize) -> bool {
    proof_sibling_index(node_index) < level_len
}

/// Return the parent index reached after ascending one Merkle level.
#[inline]
#[must_use = "Merkle proof-path decisions must not be discarded"]
pub(crate) const fn proof_parent_index(node_index: usize) -> usize {
    node_index / 2
}

/// Return true when the verifier must hash `sibling || current` for this proof
/// step instead of `current || sibling`.
#[inline]
#[must_use = "Merkle proof-path decisions must not be discarded"]
pub(crate) const fn proof_step_places_sibling_left(step_is_left: bool) -> bool {
    step_is_left
}

#[cfg(test)]
mod verus_spec_differential {
    //! Differential binding for `PARITY-HAND-1` (see
    //! `formal/ASSUMPTION_REGISTRY.md`).
    //!
    //! Verus proves `exec == spec` for `formal/verus/verified_merkle_path.rs`.
    //! The transcriptions below restate that `spec` and assert it agrees with
    //! the function this crate ships, which is the step that carries the proof
    //! to production. Symbol parity cannot see this: `check-verus-parity.sh`
    //! greps for names.
    //!
    //! BOUNDED: index arithmetic over `usize`, enumerated exhaustively across
    //! `0..=256` where every parity and pairing case occurs, plus the top of
    //! the range. `usize::MAX` is odd, so the even branch never has to add
    //! past the maximum; the enumeration covers both parities at the top
    //! anyway so a changed parity rule is caught rather than assumed safe.
    //!
    //! Keep each transcription in step with the kernel; if it drifts, the
    //! assumption returns silently.

    use super::*;

    // Production writes `.is_multiple_of(2)` where the kernel writes
    // `% 2 == 0`. Keeping the kernel's form here is the point: the differential
    // test is what establishes the two agree, so the transcription must not be
    // rewritten into production's idiom.
    #[allow(clippy::manual_is_multiple_of)]
    fn spec_proof_sibling_index(node_index: usize) -> usize {
        if node_index % 2 == 0 {
            node_index + 1
        } else {
            node_index - 1
        }
    }

    #[allow(clippy::manual_is_multiple_of)]
    fn spec_proof_step_is_left(node_index: usize) -> bool {
        node_index % 2 == 1
    }

    fn spec_proof_level_has_sibling(node_index: usize, level_len: usize) -> bool {
        spec_proof_sibling_index(node_index) < level_len
    }

    fn spec_proof_parent_index(node_index: usize) -> usize {
        node_index / 2
    }

    fn spec_proof_step_places_sibling_left(step_is_left: bool) -> bool {
        step_is_left
    }

    #[test]
    fn test_production_matches_verus_spec_exhaustive_small_and_top() {
        let mut indices: Vec<usize> = (0usize..=256).collect();
        // usize::MAX is odd, so its sibling is MAX - 1 and no overflow occurs.
        indices.extend([usize::MAX - 2, usize::MAX - 1, usize::MAX]);

        for &node_index in &indices {
            assert_eq!(
                proof_sibling_index(node_index),
                spec_proof_sibling_index(node_index),
                "PARITY-HAND-1: proof_sibling_index disagrees at {node_index}"
            );
            assert_eq!(
                proof_step_is_left(node_index),
                spec_proof_step_is_left(node_index),
                "PARITY-HAND-1: proof_step_is_left disagrees at {node_index}"
            );
            assert_eq!(
                proof_parent_index(node_index),
                spec_proof_parent_index(node_index),
                "PARITY-HAND-1: proof_parent_index disagrees at {node_index}"
            );
        }

        for node_index in 0usize..=64 {
            for level_len in 0usize..=64 {
                assert_eq!(
                    proof_level_has_sibling(node_index, level_len),
                    spec_proof_level_has_sibling(node_index, level_len),
                    "PARITY-HAND-1: proof_level_has_sibling disagrees at \
                     ({node_index}, {level_len})"
                );
            }
        }

        for step_is_left in [false, true] {
            assert_eq!(
                proof_step_places_sibling_left(step_is_left),
                spec_proof_step_places_sibling_left(step_is_left),
                "PARITY-HAND-1: proof_step_places_sibling_left disagrees at ({step_is_left})"
            );
        }
    }

    #[test]
    fn test_spec_oracle_can_reject() {
        // Pairing and parity: even nodes sit left of their sibling, odd right.
        assert_eq!(spec_proof_sibling_index(0), 1);
        assert_eq!(spec_proof_sibling_index(1), 0);
        assert!(!spec_proof_step_is_left(0));
        assert!(spec_proof_step_is_left(1));
        // A trailing odd node has no sibling in its level.
        assert!(!spec_proof_level_has_sibling(2, 3));
        assert!(spec_proof_level_has_sibling(0, 2));
        assert_eq!(spec_proof_parent_index(5), 2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proof_sibling_index_even_uses_right_neighbor() {
        assert_eq!(proof_sibling_index(0), 1);
        assert_eq!(proof_sibling_index(2), 3);
    }

    #[test]
    fn test_proof_sibling_index_odd_uses_left_neighbor() {
        assert_eq!(proof_sibling_index(1), 0);
        assert_eq!(proof_sibling_index(3), 2);
    }

    #[test]
    fn test_proof_step_is_left_matches_odd_indices() {
        assert!(!proof_step_is_left(0));
        assert!(proof_step_is_left(1));
        assert!(!proof_step_is_left(2));
        assert!(proof_step_is_left(3));
    }

    #[test]
    fn test_proof_level_has_sibling_rejects_promoted_tail() {
        assert!(!proof_level_has_sibling(2, 3));
    }

    #[test]
    fn test_proof_level_has_sibling_accepts_paired_nodes() {
        assert!(proof_level_has_sibling(0, 2));
        assert!(proof_level_has_sibling(1, 2));
        assert!(proof_level_has_sibling(2, 4));
    }

    #[test]
    fn test_proof_parent_index_halves_node_index() {
        assert_eq!(proof_parent_index(0), 0);
        assert_eq!(proof_parent_index(1), 0);
        assert_eq!(proof_parent_index(5), 2);
    }

    #[test]
    fn test_proof_step_places_sibling_left_is_identity() {
        assert!(!proof_step_places_sibling_left(false));
        assert!(proof_step_places_sibling_left(true));
    }
}
