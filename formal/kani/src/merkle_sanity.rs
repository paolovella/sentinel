// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Merkle hash property sanity checks.
//!
//! Bridges the Verus axiomatized Merkle trust boundary with runtime
//! SHA-256 properties. These are NOT cryptographic proofs — they verify
//! that the SHA-256 implementation satisfies the structural properties
//! assumed by the Verus Merkle proofs.
//!
//! # Verified Properties (K121-K125)
//!
//! | ID   | Property |
//! |------|----------|
//! | K121 | SHA-256 output is always 32 bytes (bridges MERKLE-HASH-1 axiom) |
//! | K122 | SHA-256 is deterministic: same input → same output |
//! | K123 | RFC 6962 domain separation: leaf prefix (0x00) ≠ internal prefix (0x01) |
//! | K124 | Hex encoding of 32-byte hash is always 64 chars |
//! | K125 | Different inputs produce different hashes (collision sanity, not proof) |
//!
//! # Trust Boundary
//!
//! These sanity checks strengthen the Verus axioms in
//! `formal/verus/merkle_boundary_axioms.rs` by testing them against
//! the actual sha2 crate implementation. The axioms remain trusted
//! (SHA-256 collision resistance is a cryptographic assumption), but
//! these checks verify that the implementation behaves as axiomatized.

use sha2::{Digest, Sha256};

/// Compute SHA-256 hash of input bytes.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// RFC 6962 leaf hash: H(0x00 || data).
pub fn merkle_leaf_hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(&[0x00]); // Leaf prefix
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// RFC 6962 internal hash: H(0x01 || left || right).
pub fn merkle_internal_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(&[0x01]); // Internal prefix
    hasher.update(left);
    hasher.update(right);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Hex-encode a 32-byte hash.
pub fn hex_encode(hash: &[u8; 32]) -> String {
    hash.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── K121: SHA-256 always produces 32 bytes ──────────────────────

    #[test]
    fn test_k121_sha256_output_length() {
        let test_inputs: Vec<&[u8]> = vec![
            b"",
            b"hello",
            b"a]b\x00c",
            &[0xFF; 1000],
            &[0x00; 0],
            b"The quick brown fox jumps over the lazy dog",
        ];
        for input in &test_inputs {
            let hash = sha256(input);
            assert_eq!(hash.len(), 32, "SHA-256 must always produce 32 bytes");
        }
    }

    #[test]
    fn test_k121_leaf_hash_length() {
        assert_eq!(merkle_leaf_hash(b"data").len(), 32);
        assert_eq!(merkle_leaf_hash(b"").len(), 32);
    }

    #[test]
    fn test_k121_internal_hash_length() {
        let left = sha256(b"left");
        let right = sha256(b"right");
        assert_eq!(merkle_internal_hash(&left, &right).len(), 32);
    }

    // ── K122: SHA-256 is deterministic ──────────────────────────────

    #[test]
    fn test_k122_sha256_deterministic() {
        let inputs = [b"test1".as_slice(), b"test2", b"", b"\x00\xFF"];
        for input in &inputs {
            let hash1 = sha256(input);
            let hash2 = sha256(input);
            assert_eq!(hash1, hash2, "SHA-256 must be deterministic for {:?}", input);
        }
    }

    #[test]
    fn test_k122_leaf_hash_deterministic() {
        let h1 = merkle_leaf_hash(b"data");
        let h2 = merkle_leaf_hash(b"data");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_k122_internal_hash_deterministic() {
        let left = sha256(b"l");
        let right = sha256(b"r");
        let h1 = merkle_internal_hash(&left, &right);
        let h2 = merkle_internal_hash(&left, &right);
        assert_eq!(h1, h2);
    }

    // ── K123: RFC 6962 domain separation ────────────────────────────

    #[test]
    fn test_k123_leaf_ne_internal() {
        // For the same data, leaf hash ≠ internal hash
        // (because leaf uses 0x00 prefix, internal uses 0x01 prefix)
        let data = sha256(b"some data"); // 32 bytes, valid as both leaf data and child hash
        let leaf = merkle_leaf_hash(&data);
        let internal = merkle_internal_hash(&data, &data);
        assert_ne!(
            leaf, internal,
            "Leaf and internal hashes must differ (domain separation)"
        );
    }

    #[test]
    fn test_k123_prefix_difference() {
        // Directly verify that different prefixes produce different hashes
        let data = b"identical content";
        let with_00 = sha256(&[&[0x00], data.as_slice()].concat());
        let with_01 = sha256(&[&[0x01], data.as_slice()].concat());
        assert_ne!(with_00, with_01, "Different prefixes must produce different hashes");
    }

    // ── K124: Hex encoding of 32 bytes is 64 chars ──────────────────

    #[test]
    fn test_k124_hex_encode_length() {
        let hashes = [
            sha256(b""),
            sha256(b"test"),
            sha256(&[0xFF; 100]),
            merkle_leaf_hash(b"leaf"),
        ];
        for hash in &hashes {
            let hex = hex_encode(hash);
            assert_eq!(hex.len(), 64, "Hex encoding of 32 bytes must be 64 chars");
            assert!(
                hex.chars().all(|c| c.is_ascii_hexdigit()),
                "Hex must only contain hex digits"
            );
        }
    }

    // ── K125: Different inputs → different hashes (sanity) ──────────

    #[test]
    fn test_k125_collision_sanity() {
        // This is NOT a proof of collision resistance — just a sanity check
        // that the SHA-256 implementation doesn't have obvious flaws
        let inputs: Vec<&[u8]> = vec![
            b"a", b"b", b"c", b"ab", b"ba", b"abc", b"", b"\x00", b"\x01",
        ];
        for i in 0..inputs.len() {
            for j in (i + 1)..inputs.len() {
                let h1 = sha256(inputs[i]);
                let h2 = sha256(inputs[j]);
                assert_ne!(
                    h1, h2,
                    "Different inputs {:?} and {:?} produced same hash",
                    inputs[i], inputs[j]
                );
            }
        }
    }

    #[test]
    fn test_k125_leaf_collision_sanity() {
        let h1 = merkle_leaf_hash(b"entry1");
        let h2 = merkle_leaf_hash(b"entry2");
        assert_ne!(h1, h2);
    }
}
