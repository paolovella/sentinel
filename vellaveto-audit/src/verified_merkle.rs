// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verified Merkle fail-closed guard kernel.
//!
//! This module extracts the pure capacity and proof-shape guards from
//! `merkle.rs`. It does not verify cryptographic collision resistance or the
//! hash-computation internals; it formalizes the control-flow boundary that
//! decides when Merkle append / initialization / proof verification must reject
//! inputs.

/// Maximum allowed proof depth.
///
/// A Merkle tree with more than `2^64` leaves is physically unrealistic, so a
/// proof with more siblings than this is treated as malformed.
pub(crate) const MAX_PROOF_SIBLINGS: usize = 64;

/// Return true when a new leaf may be appended without exceeding the maximum
/// leaf count.
#[inline]
#[must_use = "Merkle capacity decisions must not be discarded"]
pub(crate) const fn append_allowed(leaf_count: u64, max_leaf_count: u64) -> bool {
    leaf_count < max_leaf_count
}

/// Return true when a persisted leaf file / replayed state contains at most the
/// configured maximum number of leaves.
#[inline]
#[must_use = "Merkle initialization decisions must not be discarded"]
pub(crate) const fn stored_leaf_count_valid(leaf_count: u64, max_leaf_count: u64) -> bool {
    leaf_count <= max_leaf_count
}

/// Return true when the proof tree size is non-zero.
#[inline]
#[must_use = "Merkle proof validation decisions must not be discarded"]
pub(crate) const fn proof_tree_size_valid(tree_size: u64) -> bool {
    tree_size > 0
}

/// Return true when the proof leaf index lies within the claimed tree size.
#[inline]
#[must_use = "Merkle proof validation decisions must not be discarded"]
pub(crate) const fn proof_leaf_index_valid(leaf_index: u64, tree_size: u64) -> bool {
    leaf_index < tree_size
}

/// Return true when the proof sibling count stays within the configured bound.
#[inline]
#[must_use = "Merkle proof validation decisions must not be discarded"]
pub(crate) const fn proof_sibling_count_valid(sibling_count: usize) -> bool {
    sibling_count <= MAX_PROOF_SIBLINGS
}

/// Return true when a decoded sibling hash has the expected SHA-256 byte length.
#[inline]
#[must_use = "Merkle proof validation decisions must not be discarded"]
pub(crate) const fn sibling_hash_len_valid(sibling_len: usize) -> bool {
    sibling_len == 32
}

#[cfg(test)]
mod verus_spec_differential {
    //! Differential binding for `PARITY-HAND-1` (see
    //! `formal/ASSUMPTION_REGISTRY.md`).
    //!
    //! Verus proves `exec == spec` for `formal/verus/verified_merkle.rs`.
    //! The transcriptions below restate that `spec` and assert it agrees with
    //! the function this crate ships, which is the step that carries the proof
    //! to production. Symbol parity cannot see this: `check-verus-parity.sh`
    //! greps for names.
    //!
    //! BOUNDED: the operands are `u64` and `usize`. Counts and indices are
    //! enumerated over a boundary set around zero, the configured caps
    //! (`MAX_PROOF_SIBLINGS`, `HASH_SIZE`) and both integer extremes, since
    //! those caps are exactly where the predicates change answer.
    //!
    //! The kernel writes `HASH_SIZE` and `MAX_PROOF_SIBLINGS` symbolically
    //! while production compares against a literal `32` and the crate
    //! constant, so this also binds those values.
    //!
    //! Keep each transcription in step with the kernel; if it drifts, the
    //! assumption returns silently.

    use super::*;

    // The kernel fixes both bounds as literals. Writing production's
    // `MAX_PROOF_SIBLINGS` on both sides of the comparison would bind the
    // relation and not the value — raising the cap would move both sides and
    // the test would still pass. Verified: a mutation from 64 to 4096 escaped
    // before these literals were pinned.
    const K_HASH_SIZE: usize = 32;
    const K_MAX_PROOF_SIBLINGS: usize = 64;

    fn spec_append_allowed(leaf_count: u64, max_leaf_count: u64) -> bool {
        leaf_count < max_leaf_count
    }

    fn spec_stored_leaf_count_valid(leaf_count: u64, max_leaf_count: u64) -> bool {
        leaf_count <= max_leaf_count
    }

    fn spec_proof_tree_size_valid(tree_size: u64) -> bool {
        tree_size > 0
    }

    fn spec_proof_leaf_index_valid(leaf_index: u64, tree_size: u64) -> bool {
        leaf_index < tree_size
    }

    fn spec_proof_sibling_count_valid(sibling_count: usize) -> bool {
        sibling_count <= K_MAX_PROOF_SIBLINGS
    }

    fn spec_sibling_hash_len_valid(sibling_len: usize) -> bool {
        sibling_len == K_HASH_SIZE
    }

    #[test]
    fn test_count_predicates_match_verus_spec_at_boundaries() {
        let values = [0u64, 1, 2, 1_000, u64::MAX - 1, u64::MAX];
        for &a in &values {
            for &b in &values {
                assert_eq!(
                    append_allowed(a, b),
                    spec_append_allowed(a, b),
                    "PARITY-HAND-1: append_allowed disagrees at ({a}, {b})"
                );
                assert_eq!(
                    stored_leaf_count_valid(a, b),
                    spec_stored_leaf_count_valid(a, b),
                    "PARITY-HAND-1: stored_leaf_count_valid disagrees at ({a}, {b})"
                );
                assert_eq!(
                    proof_leaf_index_valid(a, b),
                    spec_proof_leaf_index_valid(a, b),
                    "PARITY-HAND-1: proof_leaf_index_valid disagrees at ({a}, {b})"
                );
            }
            assert_eq!(
                proof_tree_size_valid(a),
                spec_proof_tree_size_valid(a),
                "PARITY-HAND-1: proof_tree_size_valid disagrees at {a}"
            );
        }
    }

    #[test]
    fn test_size_predicates_match_verus_spec_exhaustive_around_caps() {
        assert_eq!(
            MAX_PROOF_SIBLINGS, K_MAX_PROOF_SIBLINGS,
            "PARITY-HAND-1: production MAX_PROOF_SIBLINGS no longer matches the kernel's literal"
        );
        // Exhaustive across both caps with headroom on either side.
        for n in 0usize..=128 {
            assert_eq!(
                proof_sibling_count_valid(n),
                spec_proof_sibling_count_valid(n),
                "PARITY-HAND-1: proof_sibling_count_valid disagrees at {n}"
            );
            assert_eq!(
                sibling_hash_len_valid(n),
                spec_sibling_hash_len_valid(n),
                "PARITY-HAND-1: sibling_hash_len_valid disagrees at {n}"
            );
        }
        assert_eq!(
            proof_sibling_count_valid(usize::MAX),
            spec_proof_sibling_count_valid(usize::MAX),
            "PARITY-HAND-1: proof_sibling_count_valid disagrees at usize::MAX"
        );
    }

    #[test]
    fn test_spec_oracle_can_reject() {
        // An empty tree admits no proof, and an index must fall inside it.
        assert!(!spec_proof_tree_size_valid(0));
        assert!(!spec_proof_leaf_index_valid(4, 4));
        // Appending at capacity is refused; storing exactly at capacity is not.
        assert!(!spec_append_allowed(4, 4));
        assert!(spec_stored_leaf_count_valid(4, 4));
        // Both caps are exact.
        assert!(spec_proof_sibling_count_valid(64));
        assert!(!spec_proof_sibling_count_valid(65));
        assert!(!spec_sibling_hash_len_valid(31));
        assert!(!spec_sibling_hash_len_valid(33));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_append_allowed_rejects_at_limit() {
        assert!(!append_allowed(2, 2));
    }

    #[test]
    fn test_append_allowed_accepts_below_limit() {
        assert!(append_allowed(1, 2));
    }

    #[test]
    fn test_stored_leaf_count_valid_accepts_equal_limit() {
        assert!(stored_leaf_count_valid(2, 2));
    }

    #[test]
    fn test_stored_leaf_count_valid_rejects_over_limit() {
        assert!(!stored_leaf_count_valid(3, 2));
    }

    #[test]
    fn test_proof_tree_size_valid_rejects_zero() {
        assert!(!proof_tree_size_valid(0));
    }

    #[test]
    fn test_proof_leaf_index_valid_rejects_out_of_range() {
        assert!(!proof_leaf_index_valid(5, 3));
    }

    #[test]
    fn test_proof_sibling_count_valid_rejects_too_many_siblings() {
        assert!(!proof_sibling_count_valid(MAX_PROOF_SIBLINGS + 1));
    }

    #[test]
    fn test_sibling_hash_len_valid_requires_32_bytes() {
        assert!(sibling_hash_len_valid(32));
        assert!(!sibling_hash_len_valid(31));
        assert!(!sibling_hash_len_valid(33));
    }
}
