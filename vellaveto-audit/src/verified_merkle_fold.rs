// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Verified Merkle fold kernel.
//!
//! This module extracts the pure Merkle fold steps shared by `merkle.rs`:
//! building the next level from adjacent nodes, folding one proof step using
//! the encoded direction bit, and folding peaks low-to-high when computing the
//! current root.

use crate::merkle::hash_internal;

/// Return the number of nodes in the next Merkle level.
#[inline]
#[must_use = "Merkle level-shape decisions must not be discarded"]
pub(crate) const fn next_level_len(level_len: usize) -> usize {
    (level_len / 2) + (level_len % 2)
}

/// Build the next Merkle level from the current one.
///
/// Adjacent pairs are combined with `hash_internal(left, right)`. A trailing
/// odd node is promoted unchanged.
#[must_use = "Merkle next-level computation must not be discarded"]
pub(crate) fn next_level_hashes(current: &[[u8; 32]]) -> Vec<[u8; 32]> {
    let mut next = Vec::with_capacity(next_level_len(current.len()));
    let mut i = 0usize;
    while i + 1 < current.len() {
        next.push(hash_internal(&current[i], &current[i + 1]));
        i += 2;
    }
    if i < current.len() {
        next.push(current[i]);
    }
    next
}

/// Fold one proof step into the running verifier accumulator.
#[inline]
#[must_use = "Merkle proof folding decisions must not be discarded"]
pub(crate) fn fold_proof_step(
    current: [u8; 32],
    sibling: [u8; 32],
    sibling_on_left: bool,
) -> [u8; 32] {
    if sibling_on_left {
        hash_internal(&sibling, &current)
    } else {
        hash_internal(&current, &sibling)
    }
}

/// Fold one higher Merkle peak into the running root accumulator.
#[inline]
#[must_use = "Merkle root-folding decisions must not be discarded"]
pub(crate) fn fold_peak_into_root(peak: [u8; 32], acc: [u8; 32]) -> [u8; 32] {
    hash_internal(&peak, &acc)
}

#[cfg(test)]
mod verus_spec_differential {
    //! **Partial** differential binding for `PARITY-HAND-1` (see
    //! `formal/ASSUMPTION_REGISTRY.md`).
    //!
    //! Only `next_level_len` is bound here. The rest of
    //! `formal/verus/verified_merkle_fold.rs` states its specs over abstract
    //! hash sequences (`Seq<Seq<int>>`), so a differential test would have to
    //! supply a hash model rather than transcribe a pure function — and a
    //! binding against a *modelled* hash establishes less than it appears to.
    //! Those obligations stay under `PARITY-HAND-1`, and the registry counts
    //! this kernel as partial rather than discharged.

    use super::*;

    fn spec_next_level_len(level_len: usize) -> usize {
        level_len / 2 + level_len % 2
    }

    #[test]
    fn test_next_level_len_matches_verus_spec_exhaustive_small_and_top() {
        // Level lengths are bounded by leaf count in practice; 0..=1024 covers
        // every parity and halving case, and the top of the range is included
        // because `level_len / 2 + level_len % 2` must not overflow there.
        for level_len in 0usize..=1024 {
            assert_eq!(
                next_level_len(level_len),
                spec_next_level_len(level_len),
                "PARITY-HAND-1: next_level_len disagrees at {level_len}"
            );
        }
        for &level_len in &[usize::MAX - 1, usize::MAX] {
            assert_eq!(
                next_level_len(level_len),
                spec_next_level_len(level_len),
                "PARITY-HAND-1: next_level_len disagrees at {level_len}"
            );
        }
    }

    #[test]
    fn test_spec_oracle_can_reject() {
        // A trailing odd node is promoted, so an odd level rounds up.
        assert_eq!(spec_next_level_len(0), 0);
        assert_eq!(spec_next_level_len(1), 1);
        assert_eq!(spec_next_level_len(2), 1);
        assert_eq!(spec_next_level_len(3), 2);
        assert_eq!(spec_next_level_len(4), 2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_next_level_len_rounds_up_odd_width() {
        assert_eq!(next_level_len(0), 0);
        assert_eq!(next_level_len(1), 1);
        assert_eq!(next_level_len(2), 1);
        assert_eq!(next_level_len(3), 2);
        assert_eq!(next_level_len(5), 3);
    }

    #[test]
    fn test_next_level_hashes_pairs_two_nodes() {
        let left = [0x01u8; 32];
        let right = [0x02u8; 32];
        let next = next_level_hashes(&[left, right]);
        assert_eq!(next, vec![hash_internal(&left, &right)]);
    }

    #[test]
    fn test_next_level_hashes_promotes_odd_tail() {
        let left = [0x01u8; 32];
        let right = [0x02u8; 32];
        let tail = [0x03u8; 32];
        let next = next_level_hashes(&[left, right, tail]);
        assert_eq!(next.len(), 2);
        assert_eq!(next[0], hash_internal(&left, &right));
        assert_eq!(next[1], tail);
    }

    #[test]
    fn test_fold_proof_step_respects_left_flag() {
        let current = [0x11u8; 32];
        let sibling = [0x22u8; 32];
        assert_eq!(
            fold_proof_step(current, sibling, false),
            hash_internal(&current, &sibling)
        );
        assert_eq!(
            fold_proof_step(current, sibling, true),
            hash_internal(&sibling, &current)
        );
    }

    #[test]
    fn test_fold_peak_into_root_places_peak_on_left() {
        let peak = [0x33u8; 32];
        let acc = [0x44u8; 32];
        assert_eq!(fold_peak_into_root(peak, acc), hash_internal(&peak, &acc));
    }
}
